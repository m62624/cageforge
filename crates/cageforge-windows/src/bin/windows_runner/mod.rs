// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::fs::File;
use std::io::{Read, Write};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

use crate::runner_protocol::{
    MAX_RUNNER_OUTPUT_CHUNK_BYTES, RunnerMessage, RunnerOutputStream, WindowsRunnerFailure,
    WindowsRunnerFailureCode, WindowsRunnerFailureStage, WindowsRunnerProtocolError, read_frame,
    write_frame,
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

fn spawn_output_reader(
    mut reader: File,
    response: Arc<Mutex<File>>,
    stream: RunnerOutputStream,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut buffer = vec![0u8; MAX_RUNNER_OUTPUT_CHUNK_BYTES];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(length) => {
                    let message = RunnerMessage::Output {
                        stream,
                        bytes: buffer[..length].to_vec(),
                    };
                    let Ok(mut response) = response.lock() else {
                        break;
                    };
                    if write_frame(&mut *response, message).is_err() {
                        break;
                    }
                }
                Err(error) => {
                    report_async_failure(
                        &response,
                        WindowsRunnerFailure::new(
                            WindowsRunnerFailureStage::Wait,
                            WindowsRunnerFailureCode::ResponseFrame,
                            error
                                .raw_os_error()
                                .and_then(|code| u32::try_from(code).ok()),
                            format!("failed to read restricted process {stream:?}: {error}"),
                        ),
                    );
                    break;
                }
            }
        }
    })
}

fn spawn_control_reader(mut request: File, response: Arc<Mutex<File>>, mut stdin: Option<File>) {
    std::thread::spawn(move || {
        loop {
            let message = match read_frame(&mut request) {
                Ok(message) => message,
                Err(error) => {
                    if error
                        .source()
                        .and_then(|source| source.downcast_ref::<std::io::Error>())
                        .is_some_and(|source| source.kind() == std::io::ErrorKind::UnexpectedEof)
                    {
                        break;
                    }
                    report_async_failure(
                        &response,
                        WindowsRunnerFailure::new(
                            WindowsRunnerFailureStage::Request,
                            WindowsRunnerFailureCode::RequestFrame,
                            None,
                            error.to_string(),
                        ),
                    );
                    break;
                }
            };
            match message {
                RunnerMessage::Stdin { bytes } if bytes.len() <= MAX_RUNNER_OUTPUT_CHUNK_BYTES => {
                    let Some(writer) = stdin.as_mut() else {
                        report_async_failure(
                            &response,
                            WindowsRunnerFailure::new(
                                WindowsRunnerFailureStage::Request,
                                WindowsRunnerFailureCode::RequestField,
                                None,
                                "stdin data received for a closed or null stream",
                            ),
                        );
                        break;
                    };
                    if let Err(error) = writer.write_all(&bytes) {
                        report_async_failure(
                            &response,
                            WindowsRunnerFailure::new(
                                WindowsRunnerFailureStage::Wait,
                                WindowsRunnerFailureCode::StandardStreamPrepare,
                                error
                                    .raw_os_error()
                                    .and_then(|code| u32::try_from(code).ok()),
                                format!("failed to write restricted process stdin: {error}"),
                            ),
                        );
                        break;
                    }
                }
                RunnerMessage::CloseStdin => {
                    stdin = None;
                }
                other => {
                    report_async_failure(
                        &response,
                        WindowsRunnerFailure::new(
                            WindowsRunnerFailureStage::Request,
                            WindowsRunnerFailureCode::RequestFrame,
                            None,
                            format!(
                                "unexpected {} message during process lifecycle",
                                other.kind()
                            ),
                        ),
                    );
                    break;
                }
            }
        }
    });
}

fn report_async_failure(response: &Mutex<File>, failure: WindowsRunnerFailure) {
    if let Ok(mut response) = response.lock() {
        let _ = write_frame(&mut *response, RunnerMessage::Failed { failure });
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
            let failure = WindowsRunnerFailure::new(
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
        let failure = WindowsRunnerFailure::new(
            WindowsRunnerFailureStage::Request,
            WindowsRunnerFailureCode::RequestFrame,
            None,
            protocol_error.to_string(),
        );
        return transport.fail(failure);
    };
    if !transport.account.matches(request.account) {
        let failure = WindowsRunnerFailure::new(
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
            let failure = WindowsRunnerFailure::new(
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
            let failure = WindowsRunnerFailure::new(
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
        let failure = WindowsRunnerFailure::new(
            WindowsRunnerFailureStage::Process,
            WindowsRunnerFailureCode::ResponseFrame,
            None,
            error.to_string(),
        );
        return transport.fail(failure);
    }
    let response = Arc::new(Mutex::new(transport.response));
    let stdout = process.take_stdout().map(|reader| {
        spawn_output_reader(reader, Arc::clone(&response), RunnerOutputStream::Stdout)
    });
    let stderr = process.take_stderr().map(|reader| {
        spawn_output_reader(reader, Arc::clone(&response), RunnerOutputStream::Stderr)
    });
    spawn_control_reader(
        transport.request,
        Arc::clone(&response),
        process.take_stdin(),
    );
    let exit_code = match process.wait() {
        Ok(exit_code) => exit_code,
        Err(error) => {
            report_async_failure(
                &response,
                WindowsRunnerFailure::new(
                    error.stage(),
                    error.failure_code(),
                    error.native_code(),
                    error.to_string(),
                ),
            );
            return ExitCode::from(125);
        }
    };
    for reader in [stdout, stderr].into_iter().flatten() {
        if reader.join().is_err() {
            report_async_failure(
                &response,
                WindowsRunnerFailure::new(
                    WindowsRunnerFailureStage::Wait,
                    WindowsRunnerFailureCode::ResponseFrame,
                    None,
                    "restricted process output reader panicked",
                ),
            );
            return ExitCode::from(125);
        }
    }
    let Ok(mut response) = response.lock() else {
        return ExitCode::from(125);
    };
    match write_frame(&mut *response, RunnerMessage::Exited { exit_code }) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("cageforge-windows-command-runner: failed to report process exit: {error}");
            ExitCode::from(125)
        }
    }
}
