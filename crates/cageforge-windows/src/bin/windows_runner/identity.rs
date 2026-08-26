// SPDX-License-Identifier: Apache-2.0

use std::ffi::c_void;
use std::fs::{self, File};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};

use sha2::{Digest, Sha256};
use thiserror::Error;
use windows_sys::Win32::Foundation::{GetLastError, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_GENERIC_READ, FILE_GENERIC_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

use crate::account_identity::ManagedAccountNames;
use crate::runner_manifest::{RUNNER_MANIFEST_NAME, RUNNER_MANIFEST_VERSION, RunnerManifest};
use crate::runner_protocol::RunnerAccount;
use crate::runner_resource_security::{
    RunnerResourceKind, RunnerResourceSecurityError, verify_runner_resource,
};

pub(super) struct InstalledRunnerIdentity {
    manifest: RunnerManifest,
}

pub(super) struct AuthenticatedRunnerAccount {
    kind: RunnerAccountKind,
    sid: String,
}

#[derive(PartialEq, Eq)]
enum RunnerAccountKind {
    Offline,
    Online,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PipeDirection {
    Read,
    Write,
}

struct ProcessTokenIdentity {
    user_sid: String,
}

#[derive(Debug, Error)]
pub(super) enum RunnerAuthenticationError {
    #[error("authenticated request and response pipe arguments are required")]
    MissingPipeArguments,
    #[error("unexpected command-runner argument")]
    UnexpectedArgument,
    #[error("named-pipe argument is not valid Unicode")]
    NonUnicodePipeName,
    #[error("named-pipe argument is outside the Cageforge runner namespace")]
    InvalidPipeName,
    #[error("failed to locate the running command-runner executable: {source}")]
    CurrentExecutable {
        #[source]
        source: std::io::Error,
    },
    #[error("running command-runner executable has no parent directory")]
    MissingInstallDirectory,
    #[error("failed to read the protected command-runner manifest: {source}")]
    ManifestRead {
        #[source]
        source: std::io::Error,
    },
    #[error("failed to read the installed command-runner executable: {source}")]
    ExecutableRead {
        #[source]
        source: std::io::Error,
    },
    #[error("failed to decode the protected command-runner manifest: {source}")]
    ManifestDecode {
        #[source]
        source: serde_json::Error,
    },
    #[error("command-runner manifest version mismatch")]
    ManifestVersion,
    #[error("command-runner manifest account names are not derived from its setup owner")]
    ManifestAccountBinding,
    #[error("installed command-runner resource security verification failed: {source}")]
    InstalledResourceSecurity {
        #[source]
        source: RunnerResourceSecurityError,
    },
    #[error("running command-runner executable digest differs from its protected manifest")]
    RunnerDigestMismatch,
    #[error("failed to open the {direction:?} command-runner pipe: Windows error {code}")]
    PipeOpen { direction: PipeDirection, code: u32 },
    #[error("failed to query the {direction:?} pipe server PID: Windows error {code}")]
    PipeServerPidRead { direction: PipeDirection, code: u32 },
    #[error("request and response pipes belong to different server processes")]
    PipeServerMismatch,
    #[error("Windows returned an invalid zero pipe-server PID")]
    InvalidPipeServerPid,
    #[error("failed to open the pipe server process: Windows error {code}")]
    ServerProcessOpen { code: u32 },
    #[error("failed to open a process token for identity verification: Windows error {code}")]
    ProcessTokenOpen { code: u32 },
    #[error("failed to read a process token user SID: Windows error {code}")]
    TokenUserRead { code: u32 },
    #[error("Windows returned an invalid process token user record")]
    InvalidTokenUser,
    #[error("failed to format a process token user SID: Windows error {code}")]
    TokenUserFormat { code: u32 },
    #[error("command runner is not executing as a provisioned sandbox account")]
    RunnerAccountMismatch,
    #[error("pipe server process is not executing as the setup owner")]
    ServerOwnerMismatch,
}

impl InstalledRunnerIdentity {
    pub(super) fn verify() -> Result<Self, RunnerAuthenticationError> {
        let executable = std::env::current_exe()
            .map_err(|source| RunnerAuthenticationError::CurrentExecutable { source })?;
        let directory = executable
            .parent()
            .ok_or(RunnerAuthenticationError::MissingInstallDirectory)?;
        let manifest_path = directory.join(RUNNER_MANIFEST_NAME);
        let encoded = fs::read(&manifest_path)
            .map_err(|source| RunnerAuthenticationError::ManifestRead { source })?;
        let manifest: RunnerManifest = serde_json::from_slice(&encoded)
            .map_err(|source| RunnerAuthenticationError::ManifestDecode { source })?;
        if manifest.version != RUNNER_MANIFEST_VERSION {
            return Err(RunnerAuthenticationError::ManifestVersion);
        }
        let names = ManagedAccountNames::for_owner(&manifest.owner_sid);
        if !manifest.offline_name.eq_ignore_ascii_case(&names.offline)
            || !manifest.online_name.eq_ignore_ascii_case(&names.online)
            || !manifest.group_name.eq_ignore_ascii_case(&names.group)
        {
            return Err(RunnerAuthenticationError::ManifestAccountBinding);
        }
        verify_runner_resource(
            &executable,
            &manifest.owner_sid,
            &manifest.group_sid,
            RunnerResourceKind::Executable,
        )
        .map_err(|source| RunnerAuthenticationError::InstalledResourceSecurity { source })?;
        verify_runner_resource(
            &manifest_path,
            &manifest.owner_sid,
            &manifest.group_sid,
            RunnerResourceKind::Manifest,
        )
        .map_err(|source| RunnerAuthenticationError::InstalledResourceSecurity { source })?;
        let executable_bytes = fs::read(&executable)
            .map_err(|source| RunnerAuthenticationError::ExecutableRead { source })?;
        let actual_digest = hex_digest(&executable_bytes);
        if !actual_digest.eq_ignore_ascii_case(&manifest.command_runner_sha256) {
            return Err(RunnerAuthenticationError::RunnerDigestMismatch);
        }
        Ok(Self { manifest })
    }
}

impl AuthenticatedRunnerAccount {
    pub(super) const fn matches(&self, requested: RunnerAccount) -> bool {
        matches!(
            (&self.kind, requested),
            (RunnerAccountKind::Offline, RunnerAccount::Offline)
                | (RunnerAccountKind::Online, RunnerAccount::Online)
        )
    }

    pub(super) fn sid(&self) -> &str {
        &self.sid
    }
}

#[allow(unsafe_code)]
pub(super) fn open_pipe(
    name: &str,
    direction: PipeDirection,
) -> Result<File, RunnerAuthenticationError> {
    if !name.starts_with(r"\\.\pipe\Cageforge-runner-") || name.contains('\0') {
        return Err(RunnerAuthenticationError::InvalidPipeName);
    }
    let access = match direction {
        PipeDirection::Read => FILE_GENERIC_READ,
        PipeDirection::Write => FILE_GENERIC_WRITE,
    };
    let wide = name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            access,
            0,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(RunnerAuthenticationError::PipeOpen {
            direction,
            code: unsafe { GetLastError() },
        });
    }
    Ok(unsafe { File::from_raw_handle(handle as RawHandle) })
}

pub(super) fn authenticate_transport(
    installed: &InstalledRunnerIdentity,
    request: &File,
    response: &File,
) -> Result<AuthenticatedRunnerAccount, RunnerAuthenticationError> {
    let request_pid = pipe_server_pid(request, PipeDirection::Read)?;
    let response_pid = pipe_server_pid(response, PipeDirection::Write)?;
    if request_pid != response_pid {
        return Err(RunnerAuthenticationError::PipeServerMismatch);
    }
    let server = process_token_identity(request_pid)?;
    if !server
        .user_sid
        .eq_ignore_ascii_case(&installed.manifest.owner_sid)
    {
        return Err(RunnerAuthenticationError::ServerOwnerMismatch);
    }
    let runner = current_process_token_identity()?;
    if runner
        .user_sid
        .eq_ignore_ascii_case(&installed.manifest.offline_sid)
    {
        Ok(AuthenticatedRunnerAccount {
            kind: RunnerAccountKind::Offline,
            sid: installed.manifest.offline_sid.clone(),
        })
    } else if runner
        .user_sid
        .eq_ignore_ascii_case(&installed.manifest.online_sid)
    {
        Ok(AuthenticatedRunnerAccount {
            kind: RunnerAccountKind::Online,
            sid: installed.manifest.online_sid.clone(),
        })
    } else {
        Err(RunnerAuthenticationError::RunnerAccountMismatch)
    }
}

#[allow(unsafe_code)]
fn pipe_server_pid(
    pipe: &File,
    direction: PipeDirection,
) -> Result<u32, RunnerAuthenticationError> {
    let mut process_id = 0;
    if unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle() as _, &mut process_id) } == 0 {
        return Err(RunnerAuthenticationError::PipeServerPidRead {
            direction,
            code: unsafe { GetLastError() },
        });
    }
    if process_id == 0 {
        return Err(RunnerAuthenticationError::InvalidPipeServerPid);
    }
    Ok(process_id)
}

#[allow(unsafe_code)]
fn process_token_identity(
    process_id: u32,
) -> Result<ProcessTokenIdentity, RunnerAuthenticationError> {
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if process.is_null() {
        return Err(RunnerAuthenticationError::ServerProcessOpen {
            code: unsafe { GetLastError() },
        });
    }
    let process = unsafe { OwnedHandle::from_raw_handle(process as RawHandle) };
    token_identity_for_process(process.as_raw_handle() as _)
}

#[allow(unsafe_code)]
fn current_process_token_identity() -> Result<ProcessTokenIdentity, RunnerAuthenticationError> {
    token_identity_for_process(unsafe { GetCurrentProcess() })
}

#[allow(unsafe_code)]
fn token_identity_for_process(
    process: *mut c_void,
) -> Result<ProcessTokenIdentity, RunnerAuthenticationError> {
    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
        return Err(RunnerAuthenticationError::ProcessTokenOpen {
            code: unsafe { GetLastError() },
        });
    }
    let token = unsafe { OwnedHandle::from_raw_handle(token as RawHandle) };
    let user_sid = token_user_sid(token.as_raw_handle() as _)?;
    Ok(ProcessTokenIdentity { user_sid })
}

#[allow(unsafe_code)]
fn token_user_sid(token: *mut c_void) -> Result<String, RunnerAuthenticationError> {
    let mut length = 0u32;
    unsafe {
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut length);
    }
    if length < std::mem::size_of::<TOKEN_USER>() as u32 {
        return Err(RunnerAuthenticationError::TokenUserRead {
            code: unsafe { GetLastError() },
        });
    }
    let mut buffer = vec![0u8; length as usize];
    if unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            length,
            &mut length,
        )
    } == 0
    {
        return Err(RunnerAuthenticationError::TokenUserRead {
            code: unsafe { GetLastError() },
        });
    }
    let token_user = unsafe { std::ptr::read_unaligned(buffer.as_ptr().cast::<TOKEN_USER>()) };
    if token_user.User.Sid.is_null() {
        return Err(RunnerAuthenticationError::InvalidTokenUser);
    }
    let mut value = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(token_user.User.Sid, &mut value) } == 0 {
        return Err(RunnerAuthenticationError::TokenUserFormat {
            code: unsafe { GetLastError() },
        });
    }
    let sid = wide_pointer_to_string(value);
    unsafe {
        windows_sys::Win32::Foundation::LocalFree(value as _);
    }
    Ok(sid)
}

fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[allow(unsafe_code)]
fn wide_pointer_to_string(value: *const u16) -> String {
    unsafe {
        let mut length = 0usize;
        while *value.add(length) != 0 {
            length += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(value, length))
    }
}
