// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::fs::File;
use std::process::ExitCode;

use crate::runner_protocol::{
    RunnerMessage, WindowsRunnerFailure, WindowsRunnerFailureCode, WindowsRunnerFailureStage,
    WindowsRunnerProtocolError, read_frame, write_frame,
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
    fn connect(arguments: RunnerArguments) -> Result<Self, identity::RunnerAuthenticationError> {
        let installed = identity::InstalledRunnerIdentity::verify()?;
        let request = identity::open_pipe(&arguments.request_pipe, identity::PipeDirection::Read)?;
        let response =
            identity::open_pipe(&arguments.response_pipe, identity::PipeDirection::Write)?;
        let account = identity::authenticate_transport(&installed, &request, &response)?;
        Ok(Self {
            request,
            response,
            account,
        })
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
            return ExitCode::from(125);
        }
    };
    let mut transport = match AuthenticatedTransport::connect(arguments) {
        Ok(transport) => transport,
        Err(error) => {
            eprintln!("cageforge-windows-command-runner: {error}");
            return ExitCode::from(125);
        }
    };
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
