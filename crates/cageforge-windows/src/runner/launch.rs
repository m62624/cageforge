// SPDX-License-Identifier: Apache-2.0

//! Suspended dedicated-account runner launch and pre-resume hardening.

use std::ffi::c_void;
use std::fs::File;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use thiserror::Error;
use windows_sys::Win32::Foundation::{
    DuplicateHandle, ERROR_INVALID_DATA, GetLastError, HLOCAL, LocalFree, WAIT_FAILED,
    WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
    SE_KERNEL_OBJECT, SetSecurityInfo,
};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner,
    OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    TOKEN_QUERY,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetExitCodeProcess, OpenProcessToken, PROCESS_ALL_ACCESS,
    PROCESS_QUERY_LIMITED_INFORMATION, ResumeThread, THREAD_ALL_ACCESS, TerminateProcess,
    WaitForSingleObject,
};

use crate::native_strings::local_wide_string_with_length;
use crate::runner::bootstrap::{BootstrapError, BootstrapResult};
use crate::runner::parent::{BoundaryTerminator, ParentBoundaryError, ParentJob, ParentJobError};
use crate::runner::pipe::{
    ParentPipeDirection, ParentRunnerPipe, ParentRunnerPipeError, RunnerPipeNames,
};
use crate::runner::protocol::{
    RunnerAccount, RunnerBootstrapStage, RunnerMessage, WindowsRunnerProtocolError, write_frame,
};
use crate::setup::WindowsSetupDetails;
use crate::setup::verification::PinnedRunnerResources;
use crate::setup::verification::open_verified_credentials;

const RUNNER_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

pub(crate) struct RunnerLaunch {
    request: Option<File>,
    response: Option<File>,
    pub(crate) job_handle: u64,
    boundary: Arc<BoundaryTerminator>,
}

struct SuspendedRunner {
    process: OwnedHandle,
    thread: OwnedHandle,
    process_id: u32,
    released: bool,
}

struct LocalSecurityDescriptor(PSECURITY_DESCRIPTOR);

struct LocalWideString(*mut u16);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RunnerBootstrapStatus {
    pub(crate) stage: RunnerBootstrapStage,
    pub(crate) native_code: Option<u32>,
}

#[derive(Debug, Error)]
pub(crate) enum RunnerLaunchError {
    #[error(transparent)]
    Bootstrap(#[from] BootstrapError),
    #[error(transparent)]
    Job(#[from] ParentJobError),
    #[error(transparent)]
    Pipe(#[from] ParentRunnerPipeError),
    #[error(transparent)]
    Boundary(#[from] ParentBoundaryError),
    #[error(transparent)]
    RunnerResource(#[from] crate::error::WindowsSetupVerificationError),
    #[error("failed to parse the protected runner process descriptor: Windows error {code}")]
    ProcessDescriptorParse { code: u32 },
    #[error("failed to inspect the protected runner process descriptor: Windows error {code}")]
    ProcessDescriptorInspect { code: u32 },
    #[error("failed to apply the protected {object} descriptor: Windows error {code}")]
    ProcessDescriptorApply { object: &'static str, code: u32 },
    #[error("failed to read back the protected {object} descriptor: Windows error {code}")]
    ProcessDescriptorReadBack { object: &'static str, code: u32 },
    #[error("protected {object} descriptor differs after Windows read-back")]
    ProcessDescriptorMismatch { object: &'static str },
    #[error("failed to resume the hardened command runner: Windows error {code}")]
    Resume { code: u32 },
    #[error(
        "failed to duplicate the query-only parent process handle into the runner: Windows error {code}"
    )]
    ParentIdentityProcessHandle { code: u32 },
    #[error(
        "failed to open the parent token for query-only runner authentication: Windows error {code}"
    )]
    ParentIdentityTokenOpen { code: u32 },
    #[error(
        "failed to duplicate the query-only parent token handle into the runner: Windows error {code}"
    )]
    ParentIdentityTokenHandle { code: u32 },
    #[error(transparent)]
    ParentIdentityFrame(#[from] WindowsRunnerProtocolError),
    #[error("the {direction:?} runner-pipe accept worker stopped before becoming ready")]
    PipeAcceptWorkerMissing { direction: ParentPipeDirection },
    #[error("the {direction:?} runner-pipe accept worker panicked")]
    PipeAcceptWorkerPanic { direction: ParentPipeDirection },
    #[error(
        "waiting for the command runner before {direction:?} pipe connection failed: Windows error {code}"
    )]
    RunnerConnectWait {
        direction: ParentPipeDirection,
        code: u32,
    },
    #[error(
        "waiting for the command runner before {direction:?} pipe connection returned unexpected status {result:#x}"
    )]
    RunnerConnectWaitUnexpected {
        direction: ParentPipeDirection,
        result: u32,
    },
    #[error(
        "failed to read command-runner exit code before {direction:?} pipe connection: Windows error {code}"
    )]
    RunnerConnectExitCode {
        direction: ParentPipeDirection,
        code: u32,
    },
    #[error(
        "command runner failed during {stage:?} before {direction:?} pipe connection (Windows error {native_code:?})"
    )]
    RunnerBootstrapFailure {
        direction: ParentPipeDirection,
        stage: RunnerBootstrapStage,
        native_code: Option<u32>,
    },
    #[error(
        "command runner exited with unexpected code {exit_code} before {direction:?} pipe connection"
    )]
    RunnerExitedBeforePipeConnect {
        direction: ParentPipeDirection,
        exit_code: u32,
    },
    #[error("authenticated runner request pipe is no longer available")]
    RequestPipeUnavailable,
    #[error("authenticated runner response pipe is no longer available")]
    ResponsePipeUnavailable,
}

#[allow(unsafe_code)]
impl Drop for SuspendedRunner {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        unsafe {
            TerminateProcess(self.process.as_raw_handle() as _, 125);
            WaitForSingleObject(self.process.as_raw_handle() as _, 5_000);
        }
    }
}

#[allow(unsafe_code)]
impl Drop for LocalSecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { LocalFree(self.0 as HLOCAL) };
        }
    }
}

#[allow(unsafe_code)]
impl Drop for LocalWideString {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { LocalFree(self.0 as HLOCAL) };
        }
    }
}

impl RunnerLaunch {
    pub(crate) fn start(
        runner_resources: &PinnedRunnerResources,
        setup: &WindowsSetupDetails,
        working_directory: &Path,
        account: RunnerAccount,
    ) -> Result<Self, RunnerLaunchError> {
        runner_resources.verify_launch_security(setup.owner_sid(), setup.accounts().group_sid())?;
        let names = RunnerPipeNames::generate()?;
        let job = ParentJob::new()?;
        let _credentials = open_verified_credentials(setup)?;
        let credential_path = setup.state_directory().join("credentials.json.dpapi");
        let report_name = RunnerPipeNames::bootstrap_report()?;
        let report = ParentRunnerPipe::create(
            &report_name,
            setup.owner_sid(),
            setup.owner_sid(),
            ParentPipeDirection::Response,
        )?;
        let account_name = match account {
            RunnerAccount::Offline => setup.accounts().offline_name(),
            RunnerAccount::Online => setup.accounts().online_name(),
        };
        let bootstrap = BootstrapResult::start(
            runner_resources.command_runner_path(),
            working_directory,
            &credential_path,
            setup.credential_sha256(),
            account_name,
            &names,
            &report_name,
            report,
        )?;
        let logon_sid = bootstrap.logon_sid.clone();
        let mut runner = SuspendedRunner::from_bootstrap(bootstrap);
        let request = ParentRunnerPipe::create(
            &names.request,
            setup.owner_sid(),
            &logon_sid,
            ParentPipeDirection::Request,
        )?;
        let response = ParentRunnerPipe::create(
            &names.response,
            setup.owner_sid(),
            &logon_sid,
            ParentPipeDirection::Response,
        )?;
        protect_kernel_object(
            runner.process.as_raw_handle() as _,
            setup.owner_sid(),
            "runner process",
            PROCESS_ALL_ACCESS,
        )?;
        protect_kernel_object(
            runner.thread.as_raw_handle() as _,
            setup.owner_sid(),
            "runner primary thread",
            THREAD_ALL_ACCESS,
        )?;
        let job_handle = job.duplicate_assign_only_into(runner.process.as_raw_handle() as _)?;
        connect_runner_pipes(&mut runner, &request, &response)?;
        let mut request = request.into_file();
        let (process_handle, token_handle) = runner.duplicate_parent_identity_handles()?;
        write_frame(
            &mut request,
            RunnerMessage::ParentIdentity {
                process_handle,
                token_handle,
            },
        )?;
        let boundary = Arc::new(BoundaryTerminator::new(job, &runner.process)?);
        runner.released = true;
        Ok(Self {
            request: Some(request),
            response: Some(response.into_file()),
            job_handle,
            boundary,
        })
    }

    pub(crate) fn boundary(&self) -> Arc<BoundaryTerminator> {
        Arc::clone(&self.boundary)
    }

    pub(crate) fn take_request(&mut self) -> Result<File, RunnerLaunchError> {
        self.request
            .take()
            .ok_or(RunnerLaunchError::RequestPipeUnavailable)
    }

    pub(crate) fn take_response(&mut self) -> Result<File, RunnerLaunchError> {
        self.response
            .take()
            .ok_or(RunnerLaunchError::ResponsePipeUnavailable)
    }
}

impl Drop for RunnerLaunch {
    fn drop(&mut self) {
        let _ = self.boundary.terminate(125);
    }
}

impl SuspendedRunner {
    fn from_bootstrap(bootstrap: BootstrapResult) -> Self {
        Self {
            process: bootstrap.process,
            thread: bootstrap.thread,
            process_id: bootstrap.process_id,
            released: false,
        }
    }

    #[allow(unsafe_code)]
    fn resume(&mut self) -> Result<(), RunnerLaunchError> {
        let previous = unsafe { ResumeThread(self.thread.as_raw_handle() as _) };
        if previous == u32::MAX {
            return Err(RunnerLaunchError::Resume {
                code: unsafe { GetLastError() },
            });
        }
        Ok(())
    }

    #[allow(unsafe_code)]
    fn duplicate_parent_identity_handles(&self) -> Result<(u64, u64), RunnerLaunchError> {
        let mut process_duplicate = std::ptr::null_mut();
        if unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                GetCurrentProcess(),
                self.process.as_raw_handle() as _,
                &mut process_duplicate,
                PROCESS_QUERY_LIMITED_INFORMATION,
                0,
                0,
            )
        } == 0
        {
            return Err(RunnerLaunchError::ParentIdentityProcessHandle {
                code: unsafe { GetLastError() },
            });
        }
        let mut source_token = std::ptr::null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut source_token) } == 0 {
            return Err(RunnerLaunchError::ParentIdentityTokenOpen {
                code: unsafe { GetLastError() },
            });
        }
        let source_token = unsafe { OwnedHandle::from_raw_handle(source_token as RawHandle) };
        let mut token_duplicate = std::ptr::null_mut();
        if unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                source_token.as_raw_handle() as _,
                self.process.as_raw_handle() as _,
                &mut token_duplicate,
                TOKEN_QUERY,
                0,
                0,
            )
        } == 0
        {
            return Err(RunnerLaunchError::ParentIdentityTokenHandle {
                code: unsafe { GetLastError() },
            });
        }
        Ok((
            process_duplicate as usize as u64,
            token_duplicate as usize as u64,
        ))
    }

    #[allow(unsafe_code)]
    fn exited_before_pipe_connect(
        &self,
        direction: ParentPipeDirection,
    ) -> Result<Option<u32>, RunnerLaunchError> {
        let result = unsafe { WaitForSingleObject(self.process.as_raw_handle() as _, 0) };
        if result == WAIT_TIMEOUT {
            return Ok(None);
        }
        if result == WAIT_FAILED {
            return Err(RunnerLaunchError::RunnerConnectWait {
                direction,
                code: unsafe { GetLastError() },
            });
        }
        if result != WAIT_OBJECT_0 {
            return Err(RunnerLaunchError::RunnerConnectWaitUnexpected { direction, result });
        }
        let mut exit_code = 0;
        if unsafe { GetExitCodeProcess(self.process.as_raw_handle() as _, &mut exit_code) } == 0 {
            return Err(RunnerLaunchError::RunnerConnectExitCode {
                direction,
                code: unsafe { GetLastError() },
            });
        }
        Ok(Some(exit_code))
    }
}

fn connect_runner_pipes(
    runner: &mut SuspendedRunner,
    request: &ParentRunnerPipe,
    response: &ParentRunnerPipe,
) -> Result<(), RunnerLaunchError> {
    let process_id = runner.process_id;
    let (request_ready_sender, request_ready_receiver) = std::sync::mpsc::sync_channel(1);
    let (response_ready_sender, response_ready_receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::scope(|scope| {
        let request_worker = scope
            .spawn(|| request.connect(process_id, RUNNER_CONNECT_TIMEOUT, request_ready_sender));
        let response_worker = scope
            .spawn(|| response.connect(process_id, RUNNER_CONNECT_TIMEOUT, response_ready_sender));
        request_ready_receiver
            .recv()
            .map_err(|_| RunnerLaunchError::PipeAcceptWorkerMissing {
                direction: ParentPipeDirection::Request,
            })?;
        response_ready_receiver
            .recv()
            .map_err(|_| RunnerLaunchError::PipeAcceptWorkerMissing {
                direction: ParentPipeDirection::Response,
            })?;
        runner.resume()?;
        let request_result =
            request_worker
                .join()
                .map_err(|_| RunnerLaunchError::PipeAcceptWorkerPanic {
                    direction: ParentPipeDirection::Request,
                })?;
        let response_result =
            response_worker
                .join()
                .map_err(|_| RunnerLaunchError::PipeAcceptWorkerPanic {
                    direction: ParentPipeDirection::Response,
                })?;
        connect_runner_pipe_result(runner, request_result, ParentPipeDirection::Request)?;
        connect_runner_pipe_result(runner, response_result, ParentPipeDirection::Response)
    })
}

fn connect_runner_pipe_result(
    runner: &SuspendedRunner,
    result: Result<(), ParentRunnerPipeError>,
    direction: ParentPipeDirection,
) -> Result<(), RunnerLaunchError> {
    match result {
        Ok(()) => Ok(()),
        Err(error) => match runner.exited_before_pipe_connect(direction)? {
            Some(exit_code) => match decode_runner_bootstrap_status(exit_code) {
                Some(status) => Err(RunnerLaunchError::RunnerBootstrapFailure {
                    direction,
                    stage: status.stage,
                    native_code: status.native_code,
                }),
                None => Err(RunnerLaunchError::RunnerExitedBeforePipeConnect {
                    direction,
                    exit_code,
                }),
            },
            None => Err(error.into()),
        },
    }
}

pub(crate) fn decode_runner_bootstrap_status(exit_code: u32) -> Option<RunnerBootstrapStatus> {
    const PREFIX: u32 = 0xcf00_0000;

    let (stage_code, native_code) = if exit_code & 0xff00_0000 == PREFIX {
        (
            (exit_code >> 16) & 0xff,
            Some((exit_code & u16::MAX as u32) as u16),
        )
    } else {
        (exit_code, None)
    };
    let stage = match stage_code {
        125 => RunnerBootstrapStage::Arguments,
        126 => RunnerBootstrapStage::InstalledIdentity,
        127 => RunnerBootstrapStage::RequestPipe,
        128 => RunnerBootstrapStage::ResponsePipe,
        129 => RunnerBootstrapStage::TransportAuthentication,
        _ => return None,
    };
    Some(RunnerBootstrapStatus {
        stage,
        native_code: native_code.map(u32::from),
    })
}

#[allow(unsafe_code)]
fn protect_kernel_object(
    handle: *mut c_void,
    owner_sid: &str,
    object: &'static str,
    canonical_full_access: u32,
) -> Result<(), RunnerLaunchError> {
    let sddl = crate::win::to_wide(&format!(
        "O:{owner_sid}D:P(A;;0x{:08x};;;SY)(A;;0x{:08x};;;BA)(A;;0x{:08x};;;{owner_sid})",
        canonical_full_access, canonical_full_access, canonical_full_access,
    ));
    let mut expected = std::ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut expected,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(RunnerLaunchError::ProcessDescriptorParse {
            code: unsafe { GetLastError() },
        });
    }
    let expected = LocalSecurityDescriptor(expected);
    let mut owner = std::ptr::null_mut();
    let mut owner_defaulted = 0;
    let mut dacl = std::ptr::null_mut();
    let mut dacl_present = 0;
    let mut dacl_defaulted = 0;
    if unsafe { GetSecurityDescriptorOwner(expected.0, &mut owner, &mut owner_defaulted) } == 0
        || unsafe {
            GetSecurityDescriptorDacl(
                expected.0,
                &mut dacl_present,
                &mut dacl,
                &mut dacl_defaulted,
            )
        } == 0
        || owner.is_null()
        || dacl_present == 0
        || dacl.is_null()
    {
        return Err(RunnerLaunchError::ProcessDescriptorInspect {
            code: unsafe { GetLastError() },
        });
    }
    let status = unsafe {
        SetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION,
            owner,
            std::ptr::null_mut(),
            dacl,
            std::ptr::null(),
        )
    };
    if status != 0 {
        return Err(RunnerLaunchError::ProcessDescriptorApply {
            object,
            code: status,
        });
    }
    let mut actual = std::ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut actual,
        )
    };
    if status != 0 {
        return Err(RunnerLaunchError::ProcessDescriptorReadBack {
            object,
            code: status,
        });
    }
    let actual = LocalSecurityDescriptor(actual);
    if descriptor_string(expected.0)? != descriptor_string(actual.0)? {
        return Err(RunnerLaunchError::ProcessDescriptorMismatch { object });
    }
    Ok(())
}

#[allow(unsafe_code)]
fn descriptor_string(descriptor: PSECURITY_DESCRIPTOR) -> Result<String, RunnerLaunchError> {
    let mut value = std::ptr::null_mut();
    let mut value_length = 0u32;
    if unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            SDDL_REVISION_1,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut value,
            &mut value_length,
        )
    } == 0
    {
        return Err(RunnerLaunchError::ProcessDescriptorInspect {
            code: unsafe { GetLastError() },
        });
    }
    let value = LocalWideString(value);
    local_wide_string_with_length(value.0, value_length).ok_or(
        RunnerLaunchError::ProcessDescriptorInspect {
            code: ERROR_INVALID_DATA,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::{RunnerBootstrapStatus, decode_runner_bootstrap_status};
    use crate::runner::protocol::RunnerBootstrapStage;

    #[test]
    fn bootstrap_status_accepts_only_reserved_stages() {
        assert_eq!(
            decode_runner_bootstrap_status(0xcf7f_0005),
            Some(RunnerBootstrapStatus {
                stage: RunnerBootstrapStage::RequestPipe,
                native_code: Some(5),
            })
        );
        assert_eq!(decode_runner_bootstrap_status(0xcf7a_0005), None);
        assert_eq!(decode_runner_bootstrap_status(124), None);
        assert_eq!(decode_runner_bootstrap_status(130), None);
    }
}
