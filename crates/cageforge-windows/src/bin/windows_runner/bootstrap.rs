// SPDX-License-Identifier: Apache-2.0

//! Clean current-user bridge for `CreateProcessWithLogonW`.

use std::ffi::c_void;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::mem::{offset_of, size_of};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde::Deserialize;
use sha2::{Digest, Sha256};
use windows_sys::Win32::Foundation::{
    DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_DATA,
    GetLastError, HLOCAL, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptUnprotectData,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, SID_AND_ATTRIBUTES, TOKEN_GROUPS, TOKEN_QUERY, TokenGroups,
};
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, FILE_GENERIC_WRITE, OPEN_EXISTING};
use windows_sys::Win32::System::Memory::LocalSize;
use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessWithLogonW,
    GetCurrentProcess, OpenProcessToken, PROCESS_INFORMATION, STARTUPINFOW, TerminateProcess,
};
use zeroize::{Zeroize, Zeroizing};

use crate::runner_protocol::{
    RunnerMessage, WindowsRunnerFailure, WindowsRunnerFailureCode, WindowsRunnerFailureStage,
    write_frame,
};

use crate::native_strings::local_sid_string;

const CREDENTIALS_VERSION: u32 = 1;
const SE_GROUP_LOGON_ID: u32 = 0xc000_0000;
const SID_HEADER_BYTES: usize = 8;

struct BootstrapArguments {
    report_pipe: String,
    parent_process_id: u32,
    credential_path: PathBuf,
    credential_sha256: String,
    account_name: String,
    request_pipe: String,
    response_pipe: String,
    working_directory: String,
}

struct SuspendedRunner {
    process: OwnedHandle,
    thread: OwnedHandle,
    process_id: u32,
    released: bool,
}

struct TokenBuffer(Vec<u8>);

#[derive(Deserialize)]
struct ProtectedCredentials {
    version: u32,
    offline_name: String,
    offline_password: Vec<u8>,
    online_name: String,
    online_password: Vec<u8>,
}

#[derive(Debug)]
enum BootstrapFailure {
    Arguments,
    ParentProcess,
    PipeOpen(u32),
    PipeServerPid(u32),
    PipeServerMismatch,
    CredentialRead,
    CredentialDigest,
    CredentialDecode,
    CredentialAccount,
    CredentialDecrypt(u32),
    CredentialEncoding,
    RunnerPath,
    RunnerStart(u32),
    RunnerInformation,
    RunnerToken(u32),
    RunnerLogonSid,
    RunnerHandleDuplicate(u32),
    ReportWrite,
}

enum BootstrapRunError {
    Reported,
    Unreported(BootstrapFailure),
}

impl BootstrapArguments {
    #[allow(unsafe_code)]
    fn parse(
        mut arguments: impl Iterator<Item = std::ffi::OsString>,
    ) -> Result<Self, BootstrapFailure> {
        let report_pipe = argument(&mut arguments)?;
        let parent_process_id = argument(&mut arguments)?
            .parse()
            .map_err(|_| BootstrapFailure::Arguments)?;
        let credential_path = PathBuf::from(argument(&mut arguments)?);
        let credential_sha256 = argument(&mut arguments)?;
        let account_name = argument(&mut arguments)?;
        let request_pipe = argument(&mut arguments)?;
        let response_pipe = argument(&mut arguments)?;
        let working_directory = argument(&mut arguments)?;
        if arguments.next().is_some()
            || report_pipe.contains('\0')
            || parent_process_id == 0
            || credential_path.as_os_str().is_empty()
            || credential_path.as_os_str().to_string_lossy().contains('\0')
            || credential_sha256.contains('\0')
            || account_name.contains('\0')
            || request_pipe.contains('\0')
            || response_pipe.contains('\0')
            || working_directory.contains('\0')
            || !report_pipe.starts_with(r"\\.\pipe\Cageforge-bootstrap-")
            || !request_pipe.starts_with(r"\\.\pipe\Cageforge-runner-")
            || !response_pipe.starts_with(r"\\.\pipe\Cageforge-runner-")
        {
            return Err(BootstrapFailure::Arguments);
        }
        Ok(Self {
            report_pipe,
            parent_process_id,
            credential_path,
            credential_sha256,
            account_name,
            request_pipe,
            response_pipe,
            working_directory,
        })
    }
}

impl SuspendedRunner {
    #[allow(unsafe_code)]
    fn start(arguments: &BootstrapArguments) -> Result<Self, BootstrapFailure> {
        let password = credential_password(
            &arguments.credential_path,
            &arguments.credential_sha256,
            &arguments.account_name,
        )?;
        let runner = std::env::current_exe().map_err(|_| BootstrapFailure::RunnerPath)?;
        let runner = runner.to_str().ok_or(BootstrapFailure::RunnerPath)?;
        let command_line = [runner, &arguments.request_pipe, &arguments.response_pipe]
            .into_iter()
            .map(quote_argument)
            .collect::<Vec<_>>()
            .join(" ");
        let application = wide(runner);
        let mut command_line = wide(&command_line);
        let working_directory = wide(&arguments.working_directory);
        let username = wide(&arguments.account_name);
        let domain = wide(".");
        let startup = STARTUPINFOW {
            cb: size_of::<STARTUPINFOW>() as u32,
            ..Default::default()
        };
        let mut process = PROCESS_INFORMATION::default();
        if unsafe {
            CreateProcessWithLogonW(
                username.as_ptr(),
                domain.as_ptr(),
                password.as_ptr(),
                0,
                application.as_ptr(),
                command_line.as_mut_ptr(),
                CREATE_NO_WINDOW | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
                std::ptr::null(),
                working_directory.as_ptr(),
                &startup,
                &mut process,
            )
        } == 0
        {
            return Err(BootstrapFailure::RunnerStart(unsafe { GetLastError() }));
        }
        if process.hProcess.is_null() || process.hThread.is_null() || process.dwProcessId == 0 {
            if !process.hProcess.is_null() {
                unsafe { windows_sys::Win32::Foundation::CloseHandle(process.hProcess) };
            }
            if !process.hThread.is_null() {
                unsafe { windows_sys::Win32::Foundation::CloseHandle(process.hThread) };
            }
            return Err(BootstrapFailure::RunnerInformation);
        }
        Ok(Self {
            process: unsafe { OwnedHandle::from_raw_handle(process.hProcess as RawHandle) },
            thread: unsafe { OwnedHandle::from_raw_handle(process.hThread as RawHandle) },
            process_id: process.dwProcessId,
            released: false,
        })
    }

    #[allow(unsafe_code)]
    fn logon_sid(&self) -> Result<String, BootstrapFailure> {
        let mut token = std::ptr::null_mut();
        if unsafe { OpenProcessToken(self.process.as_raw_handle() as _, TOKEN_QUERY, &mut token) }
            == 0
        {
            return Err(BootstrapFailure::RunnerToken(unsafe { GetLastError() }));
        }
        let token = unsafe { OwnedHandle::from_raw_handle(token as RawHandle) };
        let buffer = token_groups(token.as_raw_handle() as _)?;
        let offset = offset_of!(TOKEN_GROUPS, Groups);
        if buffer.0.len() < offset {
            return Err(BootstrapFailure::RunnerLogonSid);
        }
        let count = unsafe { std::ptr::read_unaligned(buffer.0.as_ptr().cast::<u32>()) } as usize;
        if count > (buffer.0.len() - offset) / size_of::<SID_AND_ATTRIBUTES>() {
            return Err(BootstrapFailure::RunnerLogonSid);
        }
        let entries = unsafe { buffer.0.as_ptr().add(offset).cast::<SID_AND_ATTRIBUTES>() };
        let mut logon = Vec::new();
        for index in 0..count {
            let entry = unsafe { std::ptr::read_unaligned(entries.add(index)) };
            if entry.Attributes & SE_GROUP_LOGON_ID == SE_GROUP_LOGON_ID {
                if !sid_fits_buffer(&buffer.0, entry.Sid) {
                    return Err(BootstrapFailure::RunnerLogonSid);
                }
                logon.push(entry.Sid);
            }
        }
        if logon.len() != 1 {
            return Err(BootstrapFailure::RunnerLogonSid);
        }
        sid_string(logon[0])
    }

    #[allow(unsafe_code)]
    fn duplicate_into_parent(
        &self,
        parent_process_id: u32,
    ) -> Result<(u64, u64), BootstrapFailure> {
        let process = duplicate_into_parent(self.process.as_raw_handle() as _, parent_process_id)?;
        let thread = duplicate_into_parent(self.thread.as_raw_handle() as _, parent_process_id)?;
        Ok((process, thread))
    }
}

#[allow(unsafe_code)]
impl Drop for SuspendedRunner {
    fn drop(&mut self) {
        if !self.released {
            unsafe { TerminateProcess(self.process.as_raw_handle() as _, 125) };
        }
    }
}

pub(super) fn run(arguments: impl Iterator<Item = std::ffi::OsString>) -> ExitCode {
    match run_inner(arguments) {
        Ok(()) => ExitCode::SUCCESS,
        Err(BootstrapRunError::Reported) => ExitCode::from(125),
        Err(BootstrapRunError::Unreported(error)) => {
            eprintln!(
                "{} bootstrap: {error:?}",
                crate::runner_manifest::COMMAND_RUNNER_NAME
            );
            ExitCode::from(125)
        }
    }
}

#[allow(unsafe_code)]
fn run_inner(arguments: impl Iterator<Item = std::ffi::OsString>) -> Result<(), BootstrapRunError> {
    let arguments = BootstrapArguments::parse(arguments).map_err(BootstrapRunError::Unreported)?;
    let mut report = open_report_pipe(&arguments).map_err(BootstrapRunError::Unreported)?;
    let result: Result<(), BootstrapFailure> = (|| {
        let mut runner = SuspendedRunner::start(&arguments)?;
        let logon_sid = runner.logon_sid()?;
        let (process_handle, thread_handle) =
            runner.duplicate_into_parent(arguments.parent_process_id)?;
        write_frame(
            &mut report,
            RunnerMessage::BootstrapRunner {
                process_id: runner.process_id,
                process_handle,
                thread_handle,
                logon_sid,
            },
        )
        .map_err(|_| BootstrapFailure::ReportWrite)?;
        runner.released = true;
        Ok(())
    })();
    match result {
        Ok(()) => Ok(()),
        Err(error) => {
            write_frame(
                &mut report,
                RunnerMessage::Failed {
                    failure: error.typed_failure(),
                },
            )
            .map_err(|_| BootstrapRunError::Unreported(BootstrapFailure::ReportWrite))?;
            Err(BootstrapRunError::Reported)
        }
    }
}

impl BootstrapFailure {
    fn typed_failure(&self) -> WindowsRunnerFailure {
        let (stage, code, native_code, detail) = match self {
            Self::Arguments => (
                WindowsRunnerFailureStage::Request,
                WindowsRunnerFailureCode::RequestField,
                None,
                "bootstrap arguments were invalid",
            ),
            Self::ParentProcess => (
                WindowsRunnerFailureStage::Authentication,
                WindowsRunnerFailureCode::ParentIdentityHandle,
                None,
                "bootstrap parent process handle was invalid",
            ),
            Self::CredentialRead => (
                WindowsRunnerFailureStage::Authentication,
                WindowsRunnerFailureCode::BootstrapCredentialRead,
                None,
                "bootstrap could not read the pinned credential record",
            ),
            Self::PipeOpen(code) => (
                WindowsRunnerFailureStage::Authentication,
                WindowsRunnerFailureCode::PipeOpen,
                Some(*code),
                "bootstrap report pipe could not be opened",
            ),
            Self::PipeServerPid(code) => (
                WindowsRunnerFailureStage::Authentication,
                WindowsRunnerFailureCode::PipeServerMismatch,
                Some(*code),
                "bootstrap report pipe server PID could not be read",
            ),
            Self::PipeServerMismatch => (
                WindowsRunnerFailureStage::Authentication,
                WindowsRunnerFailureCode::PipeServerMismatch,
                None,
                "bootstrap report pipe server did not match its parent process",
            ),
            Self::CredentialDigest => (
                WindowsRunnerFailureStage::Authentication,
                WindowsRunnerFailureCode::BootstrapCredentialDigest,
                None,
                "bootstrap credential digest differed from verified setup state",
            ),
            Self::CredentialDecode | Self::CredentialAccount | Self::CredentialEncoding => (
                WindowsRunnerFailureStage::Authentication,
                WindowsRunnerFailureCode::BootstrapCredentialDecode,
                None,
                "bootstrap rejected the pinned credential record",
            ),
            Self::CredentialDecrypt(code) => (
                WindowsRunnerFailureStage::Authentication,
                WindowsRunnerFailureCode::BootstrapCredentialDecrypt,
                Some(*code),
                "Windows DPAPI could not decrypt the pinned credential record",
            ),
            Self::RunnerPath => (
                WindowsRunnerFailureStage::Authentication,
                WindowsRunnerFailureCode::ManifestPath,
                None,
                "bootstrap could not resolve the installed runner path",
            ),
            Self::RunnerStart(code) => (
                WindowsRunnerFailureStage::Process,
                WindowsRunnerFailureCode::BootstrapRunnerStart,
                Some(*code),
                "bootstrap could not start the suspended sandbox runner",
            ),
            Self::RunnerInformation | Self::RunnerLogonSid => (
                WindowsRunnerFailureStage::Process,
                WindowsRunnerFailureCode::BootstrapRunnerMetadata,
                None,
                "bootstrap received invalid suspended-runner metadata",
            ),
            Self::RunnerToken(code) => (
                WindowsRunnerFailureStage::Process,
                WindowsRunnerFailureCode::BootstrapRunnerMetadata,
                Some(*code),
                "bootstrap could not inspect the suspended runner token",
            ),
            Self::RunnerHandleDuplicate(code) => (
                WindowsRunnerFailureStage::Process,
                WindowsRunnerFailureCode::BootstrapHandleTransfer,
                Some(*code),
                "bootstrap could not transfer suspended-runner authority",
            ),
            Self::ReportWrite => (
                WindowsRunnerFailureStage::Process,
                WindowsRunnerFailureCode::ResponseFrame,
                None,
                "bootstrap could not report suspended-runner metadata",
            ),
        };
        WindowsRunnerFailure {
            stage,
            code,
            native_code,
            detail: detail.to_string(),
        }
    }
}

#[allow(unsafe_code)]
fn argument(
    arguments: &mut impl Iterator<Item = std::ffi::OsString>,
) -> Result<String, BootstrapFailure> {
    arguments
        .next()
        .ok_or(BootstrapFailure::Arguments)?
        .into_string()
        .map_err(|_| BootstrapFailure::Arguments)
}

#[allow(unsafe_code)]
fn open_report_pipe(arguments: &BootstrapArguments) -> Result<File, BootstrapFailure> {
    let wide = arguments
        .report_pipe
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_GENERIC_WRITE,
            0,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(BootstrapFailure::PipeOpen(unsafe { GetLastError() }));
    }
    let report = unsafe { File::from_raw_handle(handle as RawHandle) };
    let mut server = 0u32;
    if unsafe { GetNamedPipeServerProcessId(report.as_raw_handle() as _, &mut server) } == 0 {
        return Err(BootstrapFailure::PipeServerPid(unsafe { GetLastError() }));
    }
    if server != arguments.parent_process_id {
        return Err(BootstrapFailure::PipeServerMismatch);
    }
    Ok(report)
}

fn credential_password(
    credential_path: &Path,
    expected_sha256: &str,
    account_name: &str,
) -> Result<Zeroizing<Vec<u16>>, BootstrapFailure> {
    let mut credential = crate::setup_pinned_file::open_for_readback(credential_path, true)
        .map_err(|_| BootstrapFailure::CredentialRead)?;
    credential
        .seek(SeekFrom::Start(0))
        .map_err(|_| BootstrapFailure::CredentialRead)?;
    let mut encoded = Vec::new();
    credential
        .read_to_end(&mut encoded)
        .map_err(|_| BootstrapFailure::CredentialRead)?;
    let digest = Sha256::digest(&encoded)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if !digest.eq_ignore_ascii_case(expected_sha256) {
        return Err(BootstrapFailure::CredentialDigest);
    }
    let credentials: ProtectedCredentials =
        serde_json::from_slice(&encoded).map_err(|_| BootstrapFailure::CredentialDecode)?;
    if credentials.version != CREDENTIALS_VERSION {
        return Err(BootstrapFailure::CredentialDecode);
    }
    let protected = if credentials.offline_name == account_name {
        credentials.offline_password
    } else if credentials.online_name == account_name {
        credentials.online_password
    } else {
        return Err(BootstrapFailure::CredentialAccount);
    };
    let mut plaintext = decrypt_credential(&protected)?;
    let text = std::str::from_utf8(&plaintext)
        .ok()
        .filter(|text| !text.is_empty() && !text.contains('\0'))
        .ok_or(BootstrapFailure::CredentialEncoding)?;
    let mut password = text.encode_utf16().collect::<Vec<_>>();
    password.push(0);
    plaintext.zeroize();
    Ok(Zeroizing::new(password))
}

#[allow(unsafe_code)]
fn decrypt_credential(protected: &[u8]) -> Result<Vec<u8>, BootstrapFailure> {
    let length = u32::try_from(protected.len()).map_err(|_| BootstrapFailure::CredentialDecode)?;
    let input = CRYPT_INTEGER_BLOB {
        cbData: length,
        pbData: protected.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    if unsafe {
        CryptUnprotectData(
            &input,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    } == 0
    {
        return Err(BootstrapFailure::CredentialDecrypt(unsafe {
            GetLastError()
        }));
    }
    if output.cbData != 0 && output.pbData.is_null() {
        return Err(BootstrapFailure::CredentialDecrypt(ERROR_INVALID_DATA));
    }
    let allocated_bytes = if output.pbData.is_null() {
        0
    } else {
        unsafe { LocalSize(output.pbData as HLOCAL) }
    };
    let length = output.cbData as usize;
    if length > allocated_bytes {
        if !output.pbData.is_null() {
            unsafe { LocalFree(output.pbData as HLOCAL) };
        }
        return Err(BootstrapFailure::CredentialDecode);
    }
    let plaintext = if length == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(output.pbData, length) }.to_vec()
    };
    if !output.pbData.is_null() {
        unsafe { LocalFree(output.pbData as HLOCAL) };
    }
    Ok(plaintext)
}

fn range_fits_buffer(buffer: &[u8], pointer: *const u8, length: usize) -> bool {
    let start = buffer.as_ptr() as usize;
    let Some(end) = start.checked_add(buffer.len()) else {
        return false;
    };
    let pointer = pointer as usize;
    let Some(pointer_end) = pointer.checked_add(length) else {
        return false;
    };
    pointer >= start && pointer_end <= end
}

fn sid_fits_buffer(buffer: &[u8], sid: *mut c_void) -> bool {
    let Some(offset) = (sid as usize).checked_sub(buffer.as_ptr() as usize) else {
        return false;
    };
    if !range_fits_buffer(buffer, sid.cast(), SID_HEADER_BYTES) {
        return false;
    }
    let count = usize::from(buffer[offset + 1]);
    let Some(subauthority_bytes) = count.checked_mul(size_of::<u32>()) else {
        return false;
    };
    let Some(length) = SID_HEADER_BYTES.checked_add(subauthority_bytes) else {
        return false;
    };
    range_fits_buffer(buffer, sid.cast(), length)
}

#[allow(unsafe_code)]
fn token_groups(token: *mut c_void) -> Result<TokenBuffer, BootstrapFailure> {
    let mut length = 0;
    let first =
        unsafe { GetTokenInformation(token, TokenGroups, std::ptr::null_mut(), 0, &mut length) };
    if first != 0 || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER || length == 0 {
        return Err(BootstrapFailure::RunnerToken(unsafe { GetLastError() }));
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
        return Err(BootstrapFailure::RunnerToken(unsafe { GetLastError() }));
    }
    buffer.truncate(length as usize);
    Ok(TokenBuffer(buffer))
}

#[allow(unsafe_code)]
fn sid_string(sid: *mut c_void) -> Result<String, BootstrapFailure> {
    let mut value = std::ptr::null_mut();
    if unsafe {
        windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW(sid, &mut value)
    } == 0
    {
        return Err(BootstrapFailure::RunnerToken(unsafe { GetLastError() }));
    }
    local_sid_string(value).ok_or(BootstrapFailure::RunnerLogonSid)
}

#[allow(unsafe_code)]
fn duplicate_into_parent(
    source: *mut c_void,
    parent_process_id: u32,
) -> Result<u64, BootstrapFailure> {
    let parent = unsafe {
        windows_sys::Win32::System::Threading::OpenProcess(
            windows_sys::Win32::System::Threading::PROCESS_DUP_HANDLE,
            0,
            parent_process_id,
        )
    };
    if parent.is_null() {
        return Err(BootstrapFailure::ParentProcess);
    }
    let parent = unsafe { OwnedHandle::from_raw_handle(parent as RawHandle) };
    let mut duplicate = std::ptr::null_mut();
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            source,
            parent.as_raw_handle() as _,
            &mut duplicate,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        return Err(BootstrapFailure::RunnerHandleDuplicate(unsafe {
            GetLastError()
        }));
    }
    if duplicate.is_null() {
        return Err(BootstrapFailure::RunnerInformation);
    }
    Ok(duplicate as usize as u64)
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn quote_argument(value: &str) -> String {
    let needs_quotes = value.is_empty()
        || value
            .chars()
            .any(|character| matches!(character, '\t' | ' ' | '"'));
    if !needs_quotes {
        return value.to_string();
    }
    let mut quoted = String::from('"');
    let mut backslashes = 0usize;
    for character in value.chars() {
        if character == '\\' {
            backslashes += 1;
        } else if character == '"' {
            quoted.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
            quoted.push(character);
            backslashes = 0;
        } else {
            quoted.extend(std::iter::repeat_n('\\', backslashes));
            quoted.push(character);
            backslashes = 0;
        }
    }
    quoted.extend(std::iter::repeat_n('\\', backslashes * 2));
    quoted.push('"');
    quoted
}

#[cfg(test)]
mod tests {
    use super::sid_fits_buffer;

    #[test]
    fn bootstrap_sid_must_fit_the_token_groups_buffer() {
        let mut buffer = vec![0u8; 16];
        buffer[5] = 1;
        let sid = buffer.as_mut_ptr().wrapping_add(4).cast();

        assert!(sid_fits_buffer(&buffer, sid));
        assert!(!sid_fits_buffer(&buffer[..15], sid));
    }
}
