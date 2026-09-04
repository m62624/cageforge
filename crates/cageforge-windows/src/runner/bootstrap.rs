// SPDX-License-Identifier: Apache-2.0

//! Clean current-user bootstrap for a runner that must use `CreateProcessWithLogonW`.

use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::path::Path;
use std::time::Duration;

use thiserror::Error;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, CreateProcessW, GetExitCodeProcess,
    PROCESS_INFORMATION, STARTUPINFOW, TerminateProcess, WaitForSingleObject,
};

use crate::runner::pipe::{ParentRunnerPipe, ParentRunnerPipeError, RunnerPipeNames};
use crate::runner::protocol::{RunnerMessage, WindowsRunnerProtocolError, read_frame};

const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(15);
const BOOTSTRAP_EXIT_TIMEOUT: Duration = Duration::from_secs(5);
const BOOTSTRAP_MODE: &str = "--cageforge-bootstrap";

pub(crate) struct BootstrapResult {
    pub(crate) process: OwnedHandle,
    pub(crate) thread: OwnedHandle,
    pub(crate) process_id: u32,
    pub(crate) logon_sid: String,
}

struct BootstrapProcess {
    process: OwnedHandle,
    process_id: u32,
    completed: bool,
}

#[derive(Debug, Error)]
pub(crate) enum BootstrapError {
    #[error(transparent)]
    Pipe(#[from] ParentRunnerPipeError),
    #[error(transparent)]
    Protocol(#[from] WindowsRunnerProtocolError),
    #[error(
        "clean bootstrap rejected runner preparation during {stage:?}/{code:?} (Windows error {native_code:?})"
    )]
    RemoteFailure {
        stage: crate::runner::protocol::WindowsRunnerFailureStage,
        code: crate::runner::protocol::WindowsRunnerFailureCode,
        native_code: Option<u32>,
    },
    #[error("failed to start the clean Windows runner bootstrap: Windows error {code}")]
    ProcessStart { code: u32 },
    #[error("Windows returned invalid clean-bootstrap process information")]
    InvalidProcessInformation,
    #[error(
        "the clean bootstrap exited with code {exit_code} before reporting its suspended runner"
    )]
    ExitedBeforeReport { exit_code: u32 },
    #[error("failed to read the clean-bootstrap exit code: Windows error {code}")]
    ExitCodeRead { code: u32 },
    #[error("clean bootstrap reported an unexpected {actual} message")]
    UnexpectedMessage { actual: &'static str },
    #[error("clean bootstrap reported invalid suspended-runner metadata")]
    InvalidReport,
    #[error("clean bootstrap did not exit after transferring the suspended-runner handles")]
    ExitTimeout,
    #[error("waiting for clean bootstrap termination failed: Windows error {code}")]
    ExitWait { code: u32 },
    #[error("clean bootstrap wait returned unexpected status {result:#x}")]
    ExitWaitUnexpected { result: u32 },
}

impl BootstrapResult {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn start(
        runner_path: &Path,
        working_directory: &Path,
        credential_path: &Path,
        credential_sha256: &str,
        account_name: &str,
        names: &RunnerPipeNames,
        report_name: &str,
        report_pipe: ParentRunnerPipe,
    ) -> Result<Self, BootstrapError> {
        let bootstrap = BootstrapProcess::start(
            runner_path,
            working_directory,
            credential_path,
            credential_sha256,
            account_name,
            names,
            report_name,
        )?;
        let (ready_sender, _ready_receiver) = std::sync::mpsc::sync_channel(1);
        report_pipe.connect(bootstrap.process_id, BOOTSTRAP_TIMEOUT, ready_sender)?;
        let mut report = report_pipe.into_file();
        let message = read_frame(&mut report);
        let result = match message {
            Ok(RunnerMessage::BootstrapRunner {
                process_id,
                process_handle,
                thread_handle,
                logon_sid,
            }) => bootstrap_result(process_id, process_handle, thread_handle, logon_sid),
            Ok(RunnerMessage::Failed { failure }) => Err(BootstrapError::RemoteFailure {
                stage: failure.stage(),
                code: failure.code(),
                native_code: failure.native_code(),
            }),
            Ok(message) => Err(BootstrapError::UnexpectedMessage {
                actual: message.kind(),
            }),
            Err(error) => match bootstrap.exit_code()? {
                Some(exit_code) => Err(BootstrapError::ExitedBeforeReport { exit_code }),
                None => Err(error.into()),
            },
        };
        bootstrap.finish()?;
        result
    }
}

impl BootstrapProcess {
    #[allow(clippy::too_many_arguments, unsafe_code)]
    fn start(
        runner_path: &Path,
        working_directory: &Path,
        credential_path: &Path,
        credential_sha256: &str,
        account_name: &str,
        names: &RunnerPipeNames,
        report_name: &str,
    ) -> Result<Self, BootstrapError> {
        let runner = runner_path.to_str().ok_or(BootstrapError::InvalidReport)?;
        let cwd = working_directory
            .to_str()
            .ok_or(BootstrapError::InvalidReport)?;
        let credential_path = credential_path
            .to_str()
            .ok_or(BootstrapError::InvalidReport)?;
        let command_line = [
            runner.to_string(),
            BOOTSTRAP_MODE.to_string(),
            report_name.to_string(),
            std::process::id().to_string(),
            credential_path.to_string(),
            credential_sha256.to_string(),
            account_name.to_string(),
            names.request.clone(),
            names.response.clone(),
            cwd.to_string(),
        ]
        .iter()
        .map(|argument| crate::win::quote_argument(argument))
        .collect::<Vec<_>>()
        .join(" ");
        let application = crate::win::to_wide(runner);
        let mut command_line = crate::win::to_wide(&command_line);
        let cwd = crate::win::to_wide(cwd);
        let startup = STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOW>() as u32,
            ..Default::default()
        };
        let mut process = PROCESS_INFORMATION::default();
        if unsafe {
            CreateProcessW(
                application.as_ptr(),
                command_line.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
                std::ptr::null(),
                cwd.as_ptr(),
                &startup,
                &mut process,
            )
        } == 0
        {
            return Err(BootstrapError::ProcessStart {
                code: unsafe { GetLastError() },
            });
        }
        if process.hProcess.is_null() || process.hThread.is_null() || process.dwProcessId == 0 {
            if !process.hProcess.is_null() {
                unsafe { windows_sys::Win32::Foundation::CloseHandle(process.hProcess) };
            }
            if !process.hThread.is_null() {
                unsafe { windows_sys::Win32::Foundation::CloseHandle(process.hThread) };
            }
            return Err(BootstrapError::InvalidProcessInformation);
        }
        Ok(Self {
            process: unsafe { OwnedHandle::from_raw_handle(process.hProcess as RawHandle) },
            process_id: process.dwProcessId,
            completed: false,
        })
    }

    #[allow(unsafe_code)]
    fn exit_code(&self) -> Result<Option<u32>, BootstrapError> {
        let result = unsafe { WaitForSingleObject(self.process.as_raw_handle() as _, 0) };
        match result {
            windows_sys::Win32::Foundation::WAIT_TIMEOUT => Ok(None),
            windows_sys::Win32::Foundation::WAIT_OBJECT_0 => {
                let mut exit_code = 0;
                if unsafe { GetExitCodeProcess(self.process.as_raw_handle() as _, &mut exit_code) }
                    == 0
                {
                    Err(BootstrapError::ExitCodeRead {
                        code: unsafe { GetLastError() },
                    })
                } else {
                    Ok(Some(exit_code))
                }
            }
            windows_sys::Win32::Foundation::WAIT_FAILED => Err(BootstrapError::ExitWait {
                code: unsafe { GetLastError() },
            }),
            result => Err(BootstrapError::ExitWaitUnexpected { result }),
        }
    }

    #[allow(unsafe_code)]
    fn finish(mut self) -> Result<(), BootstrapError> {
        let timeout = BOOTSTRAP_EXIT_TIMEOUT.as_millis() as u32;
        let result = unsafe { WaitForSingleObject(self.process.as_raw_handle() as _, timeout) };
        match result {
            windows_sys::Win32::Foundation::WAIT_OBJECT_0 => {
                self.completed = true;
                Ok(())
            }
            windows_sys::Win32::Foundation::WAIT_TIMEOUT => Err(BootstrapError::ExitTimeout),
            windows_sys::Win32::Foundation::WAIT_FAILED => Err(BootstrapError::ExitWait {
                code: unsafe { GetLastError() },
            }),
            result => Err(BootstrapError::ExitWaitUnexpected { result }),
        }
    }
}

#[allow(unsafe_code)]
impl Drop for BootstrapProcess {
    fn drop(&mut self) {
        if !self.completed {
            unsafe {
                let _ = TerminateProcess(self.process.as_raw_handle() as _, 125);
                let _ = WaitForSingleObject(self.process.as_raw_handle() as _, 5_000);
            }
        }
    }
}

#[allow(unsafe_code)]
fn bootstrap_result(
    process_id: u32,
    process_handle: u64,
    thread_handle: u64,
    logon_sid: String,
) -> Result<BootstrapResult, BootstrapError> {
    let process = usize::try_from(process_handle).map_err(|_| BootstrapError::InvalidReport)?;
    let thread = usize::try_from(thread_handle).map_err(|_| BootstrapError::InvalidReport)?;
    if process_id == 0
        || process == 0
        || thread == 0
        || logon_sid.is_empty()
        || logon_sid.contains('\0')
    {
        return Err(BootstrapError::InvalidReport);
    }
    Ok(BootstrapResult {
        process: unsafe { OwnedHandle::from_raw_handle(process as RawHandle) },
        thread: unsafe { OwnedHandle::from_raw_handle(thread as RawHandle) },
        process_id,
        logon_sid,
    })
}
