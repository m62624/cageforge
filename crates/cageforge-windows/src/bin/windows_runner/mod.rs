// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::fs::File;
use std::process::ExitCode;

use crate::runner_protocol::{
    RunnerBootstrapStage, RunnerMessage, WindowsRunnerFailure, WindowsRunnerFailureCode,
    WindowsRunnerFailureStage, WindowsRunnerProtocolError, read_frame, write_frame,
};

mod identity;
mod process;
mod token;

struct RunnerArguments {
    request_pipe: String,
    response_pipe: String,
}

struct AuthenticatedTransport {
    request: File,
    response: File,
    account: identity::AuthenticatedRunnerAccount,
}

impl RunnerArguments {
    fn parse() -> Result<Self, identity::RunnerAuthenticationError> {
        let mut arguments = std::env::args_os();
        let _program = arguments.next();
        let request_pipe = arguments
            .next()
            .ok_or(identity::RunnerAuthenticationError::MissingPipeArguments)?;
        let response_pipe = arguments
            .next()
            .ok_or(identity::RunnerAuthenticationError::MissingPipeArguments)?;
        if arguments.next().is_some() {
            return Err(identity::RunnerAuthenticationError::UnexpectedArgument);
        }
        let request_pipe = request_pipe
            .into_string()
            .map_err(|_| identity::RunnerAuthenticationError::NonUnicodePipeName)?;
        let response_pipe = response_pipe
            .into_string()
            .map_err(|_| identity::RunnerAuthenticationError::NonUnicodePipeName)?;
        Ok(Self {
            request_pipe,
            response_pipe,
        })
    }
}

impl AuthenticatedTransport {
    fn open_pipes(
        arguments: &RunnerArguments,
    ) -> Result<(File, File), identity::RunnerAuthenticationError> {
        let request = identity::open_pipe(&arguments.request_pipe, identity::PipeDirection::Read)?;
        let response =
            identity::open_pipe(&arguments.response_pipe, identity::PipeDirection::Write)?;
        Ok((request, response))
    }

    fn authenticate(
        installed: &identity::InstalledRunnerIdentity,
        request: &File,
        response: &File,
        parent_process_handle: u64,
        parent_token_handle: u64,
    ) -> Result<identity::AuthenticatedRunnerAccount, identity::RunnerAuthenticationError> {
        identity::authenticate_transport(
            installed,
            request,
            response,
            parent_process_handle,
            parent_token_handle,
        )
    }

    fn fail(&mut self, failure: WindowsRunnerFailure) -> ExitCode {
        let stage = failure.stage();
        let code = failure.code();
        let native_code = failure.native_code();
        let detail = failure.detail().to_string();
        if let Err(error) = write_frame(&mut self.response, RunnerMessage::Failed { failure }) {
            eprintln!(
                "cageforge-windows-command-runner: failed to report {stage:?}/{code:?} ({native_code:?}): {detail}: {error}"
            );
        }
        ExitCode::from(125)
    }
}

pub(super) fn run() -> ExitCode {
    let arguments = match RunnerArguments::parse() {
        Ok(arguments) => arguments,
        Err(error) => {
            eprintln!("cageforge-windows-command-runner: {error}");
            return ExitCode::from(RunnerBootstrapStage::Arguments as u8);
        }
    };
    let (mut request, mut response) = match AuthenticatedTransport::open_pipes(&arguments) {
        Ok(pipes) => pipes,
        Err(error) => {
            eprintln!("cageforge-windows-command-runner: {error}");
            std::process::exit(bootstrap_exit_code(&error) as i32);
        }
    };
    let installed = match identity::InstalledRunnerIdentity::verify() {
        Ok(installed) => installed,
        Err(error) => return report_bootstrap_failure(&mut response, &error),
    };
    let parent_process_handle = match read_frame(&mut request) {
        Ok(RunnerMessage::ParentIdentity {
            process_handle,
            token_handle,
        }) => (process_handle, token_handle),
        Ok(message) => {
            return report_bootstrap_failure(
                &mut response,
                &identity::RunnerAuthenticationError::ParentIdentityMessage {
                    actual: message.kind(),
                },
            );
        }
        Err(source) => {
            return report_bootstrap_failure(
                &mut response,
                &identity::RunnerAuthenticationError::ParentIdentityFrame { source },
            );
        }
    };
    let account = match AuthenticatedTransport::authenticate(
        &installed,
        &request,
        &response,
        parent_process_handle.0,
        parent_process_handle.1,
    ) {
        Ok(account) => account,
        Err(error) => return report_bootstrap_failure(&mut response, &error),
    };
    let mut transport = AuthenticatedTransport {
        request,
        response,
        account,
    };
    if let Err(error) = write_frame(&mut transport.response, RunnerMessage::Ready) {
        eprintln!(
            "cageforge-windows-command-runner: failed to report authenticated readiness: {error}"
        );
        return ExitCode::from(125);
    }
    let message = match read_frame(&mut transport.request) {
        Ok(message) => message,
        Err(error) => {
            let failure = runner_failure(
                WindowsRunnerFailureStage::Request,
                WindowsRunnerFailureCode::RequestFrame,
                error
                    .source()
                    .and_then(|source| source.downcast_ref::<std::io::Error>())
                    .and_then(std::io::Error::raw_os_error)
                    .and_then(|code| u32::try_from(code).ok()),
                error.to_string(),
            );
            return transport.fail(failure);
        }
    };
    let RunnerMessage::Spawn { request } = message else {
        let protocol_error = WindowsRunnerProtocolError::UnexpectedMessage {
            phase: "initial spawn request",
            actual: message.kind(),
        };
        let failure = runner_failure(
            WindowsRunnerFailureStage::Request,
            WindowsRunnerFailureCode::RequestFrame,
            None,
            protocol_error.to_string(),
        );
        return transport.fail(failure);
    };
    if !transport.account.matches(request.account) {
        let failure = runner_failure(
            WindowsRunnerFailureStage::Request,
            WindowsRunnerFailureCode::RequestedAccountMismatch,
            None,
            "spawn request selected a different provisioned account",
        );
        return transport.fail(failure);
    }
    let token = match token::RestrictedPrimaryToken::create(
        &request.capability_sids,
        request.route_sid.as_deref(),
        transport.account.sid(),
    ) {
        Ok(token) => token,
        Err(error) => {
            let failure = runner_failure(
                error.stage(),
                error.failure_code(),
                error.native_code(),
                error.to_string(),
            );
            return transport.fail(failure);
        }
    };
    let mut process = match process::SpawnedProcess::start(&token, request) {
        Ok(process) => process,
        Err(error) => {
            let failure = runner_failure(
                error.stage(),
                error.failure_code(),
                error.native_code(),
                error.to_string(),
            );
            return transport.fail(failure);
        }
    };
    if let Err(error) = write_frame(
        &mut transport.response,
        RunnerMessage::Spawned {
            process_id: process.id(),
        },
    ) {
        let failure = runner_failure(
            WindowsRunnerFailureStage::Process,
            WindowsRunnerFailureCode::ResponseFrame,
            None,
            error.to_string(),
        );
        return transport.fail(failure);
    }
    let exit_code = match process.wait() {
        Ok(exit_code) => exit_code,
        Err(error) => {
            let failure = runner_failure(
                error.stage(),
                error.failure_code(),
                error.native_code(),
                error.to_string(),
            );
            return transport.fail(failure);
        }
    };
    match write_frame(&mut transport.response, RunnerMessage::Exited { exit_code }) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("cageforge-windows-command-runner: failed to report process exit: {error}");
            ExitCode::from(125)
        }
    }
}

fn runner_failure(
    stage: WindowsRunnerFailureStage,
    code: WindowsRunnerFailureCode,
    native_code: Option<u32>,
    detail: impl Into<String>,
) -> WindowsRunnerFailure {
    WindowsRunnerFailure {
        stage,
        code,
        native_code,
        detail: detail.into(),
    }
}

fn bootstrap_exit_code(error: &identity::RunnerAuthenticationError) -> u32 {
    const BOOTSTRAP_STATUS_PREFIX: u32 = 0xcf00_0000;

    match error.native_code() {
        Some(native_code) if native_code <= u16::MAX as u32 => {
            BOOTSTRAP_STATUS_PREFIX | ((error.bootstrap_stage() as u32) << 16) | native_code
        }
        Some(_) | None => error.bootstrap_stage() as u32,
    }
}

fn report_bootstrap_failure(
    response: &mut File,
    error: &identity::RunnerAuthenticationError,
) -> ExitCode {
    let failure = authentication_failure(error);
    if let Err(write_error) = write_frame(response, RunnerMessage::Failed { failure }) {
        eprintln!(
            "cageforge-windows-command-runner: failed to report bootstrap failure {error}: {write_error}"
        );
        return ExitCode::from(error.bootstrap_stage() as u8);
    }
    ExitCode::from(125)
}

fn authentication_failure(error: &identity::RunnerAuthenticationError) -> WindowsRunnerFailure {
    let code = match error {
        identity::RunnerAuthenticationError::CurrentExecutable { .. }
        | identity::RunnerAuthenticationError::MissingInstallDirectory => {
            WindowsRunnerFailureCode::ManifestPath
        }
        identity::RunnerAuthenticationError::ManifestLocationMismatch => {
            WindowsRunnerFailureCode::InstalledResourceSecurity
        }
        identity::RunnerAuthenticationError::ManifestRead { .. }
        | identity::RunnerAuthenticationError::ExecutableRead { .. } => {
            WindowsRunnerFailureCode::InstalledResourceRead
        }
        identity::RunnerAuthenticationError::ManifestDecode { .. }
        | identity::RunnerAuthenticationError::ManifestVersion
        | identity::RunnerAuthenticationError::ManifestAccountBinding => {
            WindowsRunnerFailureCode::ManifestDecode
        }
        identity::RunnerAuthenticationError::InstalledResourceSecurity { .. } => {
            WindowsRunnerFailureCode::InstalledResourceSecurity
        }
        identity::RunnerAuthenticationError::RunnerDigestMismatch => {
            WindowsRunnerFailureCode::RunnerDigestMismatch
        }
        identity::RunnerAuthenticationError::PipeOpen { .. } => WindowsRunnerFailureCode::PipeOpen,
        identity::RunnerAuthenticationError::PipeServerPidRead { .. }
        | identity::RunnerAuthenticationError::PipeServerMismatch
        | identity::RunnerAuthenticationError::InvalidPipeServerPid => {
            WindowsRunnerFailureCode::PipeServerMismatch
        }
        identity::RunnerAuthenticationError::ParentIdentityFrame { .. }
        | identity::RunnerAuthenticationError::ParentIdentityMessage { .. } => {
            WindowsRunnerFailureCode::ParentIdentityFrame
        }
        identity::RunnerAuthenticationError::ParentIdentityHandle { .. }
        | identity::RunnerAuthenticationError::ParentIdentityPidMismatch { .. } => {
            WindowsRunnerFailureCode::ParentIdentityHandle
        }
        identity::RunnerAuthenticationError::ParentIdentityToken { .. } => {
            WindowsRunnerFailureCode::ParentIdentityToken
        }
        identity::RunnerAuthenticationError::RunnerTokenOpen { .. }
        | identity::RunnerAuthenticationError::TokenUserRead { .. }
        | identity::RunnerAuthenticationError::InvalidTokenUser
        | identity::RunnerAuthenticationError::TokenUserFormat { .. } => {
            WindowsRunnerFailureCode::RunnerTokenOpen
        }
        identity::RunnerAuthenticationError::RunnerAccountMismatch => {
            WindowsRunnerFailureCode::RunnerAccountMismatch
        }
        identity::RunnerAuthenticationError::ServerOwnerMismatch => {
            WindowsRunnerFailureCode::ServerOwnerMismatch
        }
        identity::RunnerAuthenticationError::MissingPipeArguments
        | identity::RunnerAuthenticationError::UnexpectedArgument
        | identity::RunnerAuthenticationError::NonUnicodePipeName
        | identity::RunnerAuthenticationError::InvalidPipeName => {
            WindowsRunnerFailureCode::RequestFrame
        }
    };
    runner_failure(
        WindowsRunnerFailureStage::Authentication,
        code,
        error.native_code(),
        error.to_string(),
    )
}
