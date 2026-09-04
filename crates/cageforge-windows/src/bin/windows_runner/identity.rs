// SPDX-License-Identifier: Apache-2.0

use std::ffi::c_void;
use std::fs::File;
use std::io::Read;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::path::Path;

use cageforge_path::paths_equal;
use sha2::{Digest, Sha256};
use thiserror::Error;
use windows_sys::Win32::Foundation::{GetLastError, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_APPEND_DATA, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES,
    OPEN_EXISTING,
};
use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessId, OpenProcessToken};

use crate::account_identity::ManagedAccountNames;
use crate::runner_manifest::{RUNNER_MANIFEST_NAME, RUNNER_MANIFEST_VERSION, RunnerManifest};
use crate::runner_protocol::{RunnerAccount, RunnerBootstrapStage};
use crate::runner_resource_security::{
    RunnerResourceKind, RunnerResourceSecurityError, verify_open_runner_resource,
};

use crate::native_strings::local_sid_string;

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
    #[error("protected command-runner manifest is not adjacent to the running executable")]
    ManifestLocationMismatch,
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
    #[error("the parent identity bootstrap frame could not be read: {source}")]
    ParentIdentityFrame {
        #[source]
        source: crate::runner_protocol::WindowsRunnerProtocolError,
    },
    #[error("expected a parent identity bootstrap frame, received {actual}")]
    ParentIdentityMessage { actual: &'static str },
    #[error(
        "the parent identity bootstrap frame contains an invalid process handle: Windows error {code}"
    )]
    ParentIdentityHandle { code: u32 },
    #[error("the parent identity handle PID {actual} differs from pipe server PID {expected}")]
    ParentIdentityPidMismatch { expected: u32, actual: u32 },
    #[error(
        "the parent identity bootstrap frame contains an unreadable token handle: Windows error {code}"
    )]
    ParentIdentityToken { code: u32 },
    #[error("Windows returned an invalid zero pipe-server PID")]
    InvalidPipeServerPid,
    #[error(
        "failed to open the command-runner token for identity verification: Windows error {code}"
    )]
    RunnerTokenOpen { code: u32 },
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
        let mut manifest_file = crate::setup_pinned_file::open_for_readback(&manifest_path, false)
            .map_err(
                |error| RunnerAuthenticationError::InstalledResourceSecurity {
                    source: RunnerResourceSecurityError::Unsafe {
                        path: manifest_path.clone(),
                        detail: error.to_string(),
                    },
                },
            )?;
        let manifest_path = crate::setup_pinned_file::final_path_for_open_handle(
            &manifest_path,
            manifest_file.as_raw_handle() as _,
        )
        .map_err(
            |error| RunnerAuthenticationError::InstalledResourceSecurity {
                source: RunnerResourceSecurityError::Unsafe {
                    path: manifest_path.clone(),
                    detail: error.to_string(),
                },
            },
        )?;
        let mut executable_file = crate::setup_pinned_file::open_for_readback(&executable, false)
            .map_err(|error| {
            RunnerAuthenticationError::InstalledResourceSecurity {
                source: RunnerResourceSecurityError::Unsafe {
                    path: executable.clone(),
                    detail: error.to_string(),
                },
            }
        })?;
        let executable_path = crate::setup_pinned_file::final_path_for_open_handle(
            &executable,
            executable_file.as_raw_handle() as _,
        )
        .map_err(
            |error| RunnerAuthenticationError::InstalledResourceSecurity {
                source: RunnerResourceSecurityError::Unsafe {
                    path: executable.clone(),
                    detail: error.to_string(),
                },
            },
        )?;
        if !runner_resources_are_adjacent(&executable_path, &manifest_path) {
            return Err(RunnerAuthenticationError::ManifestLocationMismatch);
        }
        let mut encoded = Vec::new();
        manifest_file
            .read_to_end(&mut encoded)
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
        verify_open_runner_resource(
            &executable_file,
            &executable_path,
            &manifest.owner_sid,
            &manifest.group_sid,
            RunnerResourceKind::Executable,
        )
        .map_err(|source| RunnerAuthenticationError::InstalledResourceSecurity { source })?;
        verify_open_runner_resource(
            &manifest_file,
            &manifest_path,
            &manifest.owner_sid,
            &manifest.group_sid,
            RunnerResourceKind::Manifest,
        )
        .map_err(|source| RunnerAuthenticationError::InstalledResourceSecurity { source })?;
        let mut executable_bytes = Vec::new();
        executable_file
            .read_to_end(&mut executable_bytes)
            .map_err(|source| RunnerAuthenticationError::ExecutableRead { source })?;
        let actual_digest = hex_digest(&executable_bytes);
        if !actual_digest.eq_ignore_ascii_case(&manifest.command_runner_sha256) {
            return Err(RunnerAuthenticationError::RunnerDigestMismatch);
        }
        Ok(Self { manifest })
    }
}

fn runner_resources_are_adjacent(executable: &Path, manifest: &Path) -> bool {
    let Some(executable_directory) = executable.parent() else {
        return false;
    };
    let Some(manifest_directory) = manifest.parent() else {
        return false;
    };
    let Some(manifest_name) = manifest.file_name() else {
        return false;
    };
    paths_equal(executable_directory, manifest_directory)
        && paths_equal(Path::new(manifest_name), Path::new(RUNNER_MANIFEST_NAME))
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

impl RunnerAuthenticationError {
    pub(super) const fn bootstrap_stage(&self) -> RunnerBootstrapStage {
        match self {
            Self::CurrentExecutable { .. }
            | Self::MissingInstallDirectory
            | Self::ManifestLocationMismatch
            | Self::ManifestRead { .. }
            | Self::ExecutableRead { .. }
            | Self::ManifestDecode { .. }
            | Self::ManifestVersion
            | Self::ManifestAccountBinding
            | Self::InstalledResourceSecurity { .. }
            | Self::RunnerDigestMismatch => RunnerBootstrapStage::InstalledIdentity,
            Self::PipeOpen {
                direction: PipeDirection::Read,
                ..
            } => RunnerBootstrapStage::RequestPipe,
            Self::PipeOpen {
                direction: PipeDirection::Write,
                ..
            } => RunnerBootstrapStage::ResponsePipe,
            Self::MissingPipeArguments
            | Self::UnexpectedArgument
            | Self::NonUnicodePipeName
            | Self::InvalidPipeName => RunnerBootstrapStage::Arguments,
            Self::PipeServerPidRead { .. }
            | Self::PipeServerMismatch
            | Self::ParentIdentityFrame { .. }
            | Self::ParentIdentityMessage { .. }
            | Self::ParentIdentityHandle { .. }
            | Self::ParentIdentityPidMismatch { .. }
            | Self::ParentIdentityToken { .. }
            | Self::InvalidPipeServerPid
            | Self::RunnerTokenOpen { .. }
            | Self::TokenUserRead { .. }
            | Self::InvalidTokenUser
            | Self::TokenUserFormat { .. }
            | Self::RunnerAccountMismatch
            | Self::ServerOwnerMismatch => RunnerBootstrapStage::TransportAuthentication,
        }
    }

    pub(super) const fn native_code(&self) -> Option<u32> {
        match self {
            Self::PipeOpen { code, .. }
            | Self::PipeServerPidRead { code, .. }
            | Self::ParentIdentityHandle { code }
            | Self::ParentIdentityToken { code }
            | Self::RunnerTokenOpen { code }
            | Self::TokenUserRead { code }
            | Self::TokenUserFormat { code } => Some(*code),
            Self::MissingPipeArguments
            | Self::UnexpectedArgument
            | Self::NonUnicodePipeName
            | Self::InvalidPipeName
            | Self::CurrentExecutable { .. }
            | Self::MissingInstallDirectory
            | Self::ManifestLocationMismatch
            | Self::ManifestRead { .. }
            | Self::ExecutableRead { .. }
            | Self::ManifestDecode { .. }
            | Self::ManifestVersion
            | Self::ManifestAccountBinding
            | Self::InstalledResourceSecurity { .. }
            | Self::RunnerDigestMismatch
            | Self::PipeServerMismatch
            | Self::ParentIdentityFrame { .. }
            | Self::ParentIdentityMessage { .. }
            | Self::ParentIdentityPidMismatch { .. }
            | Self::InvalidPipeServerPid
            | Self::InvalidTokenUser
            | Self::RunnerAccountMismatch
            | Self::ServerOwnerMismatch => None,
        }
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
    let access = client_pipe_access(direction);
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
    parent_process_handle: u64,
    parent_token_handle: u64,
) -> Result<AuthenticatedRunnerAccount, RunnerAuthenticationError> {
    let request_pid = pipe_server_pid(request, PipeDirection::Read)?;
    let response_pid = pipe_server_pid(response, PipeDirection::Write)?;
    if request_pid != response_pid {
        return Err(RunnerAuthenticationError::PipeServerMismatch);
    }
    let server =
        parent_process_token_identity(parent_process_handle, parent_token_handle, request_pid)?;
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
fn parent_process_token_identity(
    process_value: u64,
    token_value: u64,
    expected_process_id: u32,
) -> Result<ProcessTokenIdentity, RunnerAuthenticationError> {
    let process_handle = usize::try_from(process_value).map_err(|_| {
        RunnerAuthenticationError::ParentIdentityHandle {
            code: windows_sys::Win32::Foundation::ERROR_INVALID_HANDLE,
        }
    })? as *mut c_void;
    let process_id = unsafe { GetProcessId(process_handle) };
    if process_id == 0 {
        return Err(RunnerAuthenticationError::ParentIdentityHandle {
            code: unsafe { GetLastError() },
        });
    }
    if process_id != expected_process_id {
        return Err(RunnerAuthenticationError::ParentIdentityPidMismatch {
            expected: expected_process_id,
            actual: process_id,
        });
    }
    let token_handle = usize::try_from(token_value).map_err(|_| {
        RunnerAuthenticationError::ParentIdentityToken {
            code: windows_sys::Win32::Foundation::ERROR_INVALID_HANDLE,
        }
    })? as *mut c_void;
    let user_sid = match token_user_sid(token_handle) {
        Ok(user_sid) => user_sid,
        Err(RunnerAuthenticationError::TokenUserRead { code })
        | Err(RunnerAuthenticationError::TokenUserFormat { code }) => {
            return Err(RunnerAuthenticationError::ParentIdentityToken { code });
        }
        Err(RunnerAuthenticationError::InvalidTokenUser) => {
            return Err(RunnerAuthenticationError::ParentIdentityToken {
                code: windows_sys::Win32::Foundation::ERROR_INVALID_HANDLE,
            });
        }
        Err(error) => return Err(error),
    };
    Ok(ProcessTokenIdentity { user_sid })
}

#[allow(unsafe_code)]
fn current_process_token_identity() -> Result<ProcessTokenIdentity, RunnerAuthenticationError> {
    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(RunnerAuthenticationError::RunnerTokenOpen {
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
    local_sid_string(value).ok_or(RunnerAuthenticationError::TokenUserFormat {
        code: windows_sys::Win32::Foundation::ERROR_INVALID_DATA,
    })
}

fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

const fn client_pipe_access(direction: PipeDirection) -> u32 {
    match direction {
        PipeDirection::Read => FILE_GENERIC_READ,
        PipeDirection::Write => (FILE_GENERIC_WRITE & !FILE_APPEND_DATA) | FILE_READ_ATTRIBUTES,
    }
}

#[allow(unsafe_code)]
#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::{
        FILE_APPEND_DATA, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES,
        PipeDirection, client_pipe_access, runner_resources_are_adjacent,
    };
    use crate::runner_manifest::COMMAND_RUNNER_NAME;

    fn command_runner_path() -> PathBuf {
        PathBuf::from(r"\\?\C:\ProgramData\Cageforge\bin").join(COMMAND_RUNNER_NAME)
    }

    #[test]
    fn client_pipe_access_excludes_named_pipe_instance_creation() {
        assert_eq!(client_pipe_access(PipeDirection::Read), FILE_GENERIC_READ);
        assert_eq!(
            client_pipe_access(PipeDirection::Write),
            (FILE_GENERIC_WRITE & !FILE_APPEND_DATA) | FILE_READ_ATTRIBUTES
        );
        assert_eq!(
            client_pipe_access(PipeDirection::Write) & FILE_APPEND_DATA,
            0
        );
    }

    #[test]
    fn runner_resources_must_share_one_directory_and_manifest_name() {
        let runner = command_runner_path();
        assert!(runner_resources_are_adjacent(
            &runner,
            Path::new(r"\\?\C:\ProgramData\Cageforge\bin\runner-manifest.json"),
        ));
        assert!(!runner_resources_are_adjacent(
            &runner,
            Path::new(r"\\?\C:\ProgramData\Cageforge\other\runner-manifest.json"),
        ));
        assert!(!runner_resources_are_adjacent(
            &runner,
            Path::new(r"\\?\C:\ProgramData\Cageforge\bin\other.json"),
        ));
    }
}
