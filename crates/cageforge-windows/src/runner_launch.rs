// SPDX-License-Identifier: Apache-2.0

//! Suspended dedicated-account runner launch and pre-resume hardening.

use std::ffi::c_void;
use std::fs::File;
use std::mem::{offset_of, size_of};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use thiserror::Error;
use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, GetLastError, HLOCAL, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
    SE_KERNEL_OBJECT, SetSecurityInfo,
};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner,
    GetTokenInformation, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, SID_AND_ATTRIBUTES, TOKEN_GROUPS, TOKEN_QUERY, TokenGroups,
};
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessWithLogonW,
    OpenProcessToken, PROCESS_INFORMATION, ResumeThread, STARTUPINFOW, TerminateProcess,
    WaitForSingleObject,
};

use crate::runner_desktop::{ParentDesktop, ParentDesktopError};
use crate::runner_parent::{BoundaryTerminator, ParentBoundaryError, ParentJob, ParentJobError};
use crate::runner_pipe::{
    ParentPipeDirection, ParentRunnerPipe, ParentRunnerPipeError, RunnerPipeNames,
};
use crate::setup_verification::credentials::AccountCredential;

const RUNNER_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const SE_GROUP_LOGON_ID: u32 = 0xc000_0000;

pub(crate) struct RunnerLaunch {
    request: Option<File>,
    response: Option<File>,
    pub(crate) job_handle: u64,
    desktop: ParentDesktop,
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

struct TokenBuffer(Vec<u8>);

#[derive(Debug, Error)]
pub(crate) enum RunnerLaunchError {
    #[error(transparent)]
    Job(#[from] ParentJobError),
    #[error(transparent)]
    Pipe(#[from] ParentRunnerPipeError),
    #[error(transparent)]
    Desktop(#[from] ParentDesktopError),
    #[error(transparent)]
    Boundary(#[from] ParentBoundaryError),
    #[error("command-runner path is not valid Unicode")]
    RunnerPathEncoding,
    #[error("command-runner working directory is not valid Unicode")]
    WorkingDirectoryEncoding,
    #[error(
        "CreateProcessWithLogonW failed for the {account} sandbox account: Windows error {code}"
    )]
    Logon { account: String, code: u32 },
    #[error("Windows returned invalid runner process information")]
    InvalidProcessInformation,
    #[error("failed to open the runner process token: Windows error {code}")]
    RunnerTokenOpen { code: u32 },
    #[error("failed to read runner token groups: Windows error {code}")]
    TokenGroupsRead { code: u32 },
    #[error("Windows returned a truncated runner token group record")]
    TokenGroupsTruncated,
    #[error("runner token has no unique logon SID")]
    MissingLogonSid,
    #[error("runner token has more than one logon SID")]
    DuplicateLogonSid,
    #[error("failed to format the runner logon SID: Windows error {code}")]
    LogonSidFormat { code: u32 },
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
        runner_path: &Path,
        working_directory: &Path,
        credential: &AccountCredential,
        owner_sid: &str,
    ) -> Result<Self, RunnerLaunchError> {
        let names = RunnerPipeNames::generate()?;
        let job = ParentJob::new()?;
        let mut runner =
            SuspendedRunner::start(runner_path, working_directory, credential, &names)?;
        let logon_sid = runner.logon_sid()?;
        let request = ParentRunnerPipe::create(
            &names.request,
            owner_sid,
            &logon_sid,
            ParentPipeDirection::Request,
        )?;
        let response = ParentRunnerPipe::create(
            &names.response,
            owner_sid,
            &logon_sid,
            ParentPipeDirection::Response,
        )?;
        let desktop = ParentDesktop::create(owner_sid, &logon_sid)?;
        protect_kernel_object(
            runner.process.as_raw_handle() as _,
            owner_sid,
            "runner process",
        )?;
        protect_kernel_object(
            runner.thread.as_raw_handle() as _,
            owner_sid,
            "runner primary thread",
        )?;
        let job_handle = job.duplicate_assign_only_into(runner.process.as_raw_handle() as _)?;
        runner.resume()?;
        request.connect(runner.process_id, RUNNER_CONNECT_TIMEOUT)?;
        response.connect(runner.process_id, RUNNER_CONNECT_TIMEOUT)?;
        let boundary = Arc::new(BoundaryTerminator::new(job, &runner.process)?);
        runner.released = true;
        Ok(Self {
            request: Some(request.into_file()),
            response: Some(response.into_file()),
            job_handle,
            desktop,
            boundary,
        })
    }

    pub(crate) fn desktop_name(&self) -> &[u16] {
        self.desktop.startup_name()
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
    #[allow(unsafe_code)]
    fn start(
        runner_path: &Path,
        working_directory: &Path,
        credential: &AccountCredential,
        names: &RunnerPipeNames,
    ) -> Result<Self, RunnerLaunchError> {
        let runner = runner_path
            .to_str()
            .ok_or(RunnerLaunchError::RunnerPathEncoding)?;
        let cwd = working_directory
            .to_str()
            .ok_or(RunnerLaunchError::WorkingDirectoryEncoding)?;
        let command_line = [runner, &names.request, &names.response]
            .into_iter()
            .map(crate::win::quote_argument)
            .collect::<Vec<_>>()
            .join(" ");
        let application = crate::win::to_wide(runner);
        let mut command_line = crate::win::to_wide(&command_line);
        let cwd = crate::win::to_wide(cwd);
        let username = crate::win::to_wide(credential.name());
        let domain = crate::win::to_wide(".");
        let startup = STARTUPINFOW {
            cb: size_of::<STARTUPINFOW>() as u32,
            ..Default::default()
        };
        let mut process = PROCESS_INFORMATION::default();
        if unsafe {
            CreateProcessWithLogonW(
                username.as_ptr(),
                domain.as_ptr(),
                credential.password_wide().as_ptr(),
                0,
                application.as_ptr(),
                command_line.as_mut_ptr(),
                CREATE_NO_WINDOW | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
                std::ptr::null(),
                cwd.as_ptr(),
                &startup,
                &mut process,
            )
        } == 0
        {
            return Err(RunnerLaunchError::Logon {
                account: credential.name().to_string(),
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
            return Err(RunnerLaunchError::InvalidProcessInformation);
        }
        Ok(Self {
            process: unsafe { OwnedHandle::from_raw_handle(process.hProcess as RawHandle) },
            thread: unsafe { OwnedHandle::from_raw_handle(process.hThread as RawHandle) },
            process_id: process.dwProcessId,
            released: false,
        })
    }

    #[allow(unsafe_code)]
    fn logon_sid(&self) -> Result<String, RunnerLaunchError> {
        let mut token = std::ptr::null_mut();
        if unsafe { OpenProcessToken(self.process.as_raw_handle() as _, TOKEN_QUERY, &mut token) }
            == 0
        {
            return Err(RunnerLaunchError::RunnerTokenOpen {
                code: unsafe { GetLastError() },
            });
        }
        let token = unsafe { OwnedHandle::from_raw_handle(token as RawHandle) };
        let buffer = token_groups(token.as_raw_handle() as _)?;
        let groups = group_entries(&buffer)?;
        let mut logon = groups
            .into_iter()
            .filter(|entry| entry.Attributes & SE_GROUP_LOGON_ID == SE_GROUP_LOGON_ID)
            .map(|entry| sid_string(entry.Sid));
        let Some(sid) = logon.next() else {
            return Err(RunnerLaunchError::MissingLogonSid);
        };
        if logon.next().is_some() {
            return Err(RunnerLaunchError::DuplicateLogonSid);
        }
        sid
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
}

#[allow(unsafe_code)]
fn token_groups(token: *mut c_void) -> Result<TokenBuffer, RunnerLaunchError> {
    let mut length = 0;
    let first =
        unsafe { GetTokenInformation(token, TokenGroups, std::ptr::null_mut(), 0, &mut length) };
    if first != 0 || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER || length == 0 {
        return Err(RunnerLaunchError::TokenGroupsRead {
            code: unsafe { GetLastError() },
        });
    }
    let mut buffer = vec![0u8; length as usize];
    if unsafe {
        GetTokenInformation(
            token,
            TokenGroups,
            buffer.as_mut_ptr().cast(),
            length,
            &mut length,
        )
    } == 0
    {
        return Err(RunnerLaunchError::TokenGroupsRead {
            code: unsafe { GetLastError() },
        });
    }
    buffer.truncate(length as usize);
    Ok(TokenBuffer(buffer))
}

#[allow(unsafe_code)]
fn group_entries(buffer: &TokenBuffer) -> Result<Vec<SID_AND_ATTRIBUTES>, RunnerLaunchError> {
    let offset = offset_of!(TOKEN_GROUPS, Groups);
    if buffer.0.len() < offset {
        return Err(RunnerLaunchError::TokenGroupsTruncated);
    }
    let count = unsafe { std::ptr::read_unaligned(buffer.0.as_ptr().cast::<u32>()) } as usize;
    if count > (buffer.0.len() - offset) / size_of::<SID_AND_ATTRIBUTES>() {
        return Err(RunnerLaunchError::TokenGroupsTruncated);
    }
    let entries = unsafe { buffer.0.as_ptr().add(offset).cast::<SID_AND_ATTRIBUTES>() };
    Ok((0..count)
        .map(|index| unsafe { std::ptr::read_unaligned(entries.add(index)) })
        .collect())
}

#[allow(unsafe_code)]
fn sid_string(sid: *mut c_void) -> Result<String, RunnerLaunchError> {
    let mut value = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut value) } == 0 {
        return Err(RunnerLaunchError::LogonSidFormat {
            code: unsafe { GetLastError() },
        });
    }
    let value = LocalWideString(value);
    Ok(wide_string(value.0))
}

#[allow(unsafe_code)]
fn protect_kernel_object(
    handle: *mut c_void,
    owner_sid: &str,
    object: &'static str,
) -> Result<(), RunnerLaunchError> {
    let sddl = crate::win::to_wide(&format!(
        "O:{owner_sid}D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{owner_sid})"
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
    if unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            SDDL_REVISION_1,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut value,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(RunnerLaunchError::ProcessDescriptorInspect {
            code: unsafe { GetLastError() },
        });
    }
    let value = LocalWideString(value);
    Ok(wide_string(value.0))
}

#[allow(unsafe_code)]
fn wide_string(value: *const u16) -> String {
    unsafe {
        let mut length = 0;
        while *value.add(length) != 0 {
            length += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(value, length))
    }
}
