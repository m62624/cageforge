// SPDX-License-Identifier: Apache-2.0

use std::ffi::c_void;
use std::mem::size_of;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};

use thiserror::Error;
use windows_sys::Win32::Foundation::{
    GetHandleInformation, GetLastError, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW,
    DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, InitializeProcThreadAttributeList,
    LPPROC_THREAD_ATTRIBUTE_LIST, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
    PROC_THREAD_ATTRIBUTE_JOB_LIST, PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOEXW,
    UpdateProcThreadAttribute,
};

use crate::runner_protocol::{
    RunnerSpawnRequest, RunnerStandardHandles, WindowsRunnerFailureCode, WindowsRunnerFailureStage,
};

use super::{
    desktop::{PrivateDesktop, PrivateDesktopError},
    token::RestrictedPrimaryToken,
};

pub(super) struct SpawnedProcess {
    process: OwnedHandle,
    process_id: u32,
    finished: bool,
    _desktop: PrivateDesktop,
}

struct PreparedStandardHandles {
    stdin: OwnedHandle,
    stdout: OwnedHandle,
    stderr: OwnedHandle,
}

struct ProcessAttributeList {
    storage: Vec<usize>,
    handle_list: Vec<*mut c_void>,
    job_list: Vec<*mut c_void>,
    initialized: bool,
}

#[derive(Debug, Error)]
pub(super) enum ProcessStartError {
    #[error("spawn request has no command")]
    EmptyCommand,
    #[error("spawn request {field} contains an embedded NUL")]
    EmbeddedNul { field: &'static str },
    #[error("spawn request environment block is not double-NUL terminated")]
    InvalidEnvironmentBlock,
    #[error("spawn request working directory is empty")]
    EmptyWorkingDirectory,
    #[error(transparent)]
    PrivateDesktop(#[from] PrivateDesktopError),
    #[error("parent-supplied Job Object handle is invalid")]
    InvalidJobHandle,
    #[error("parent-supplied {stream} handle does not fit the runner architecture")]
    StandardHandleWidth { stream: &'static str },
    #[error("parent-supplied {stream} handle is null or invalid")]
    InvalidStandardHandle { stream: &'static str },
    #[error("parent supplied the same runner handle for {first} and {second}")]
    DuplicateStandardHandle {
        first: &'static str,
        second: &'static str,
    },
    #[error("parent-supplied {stream} handle aliases the Job Object handle")]
    StandardHandleMatchesJob { stream: &'static str },
    #[error("failed to inspect parent-supplied {stream}: Windows error {code}")]
    StandardHandleInspect { stream: &'static str, code: u32 },
    #[error("parent-supplied {stream} is not marked inheritable")]
    StandardHandleNotInheritable { stream: &'static str },
    #[error("parent-supplied {stream} has unexpected handle flags {flags:#x}")]
    UnexpectedStandardHandleFlags { stream: &'static str, flags: u32 },
    #[error("failed to size the process attribute list: Windows error {code}")]
    AttributeListSize { code: u32 },
    #[error("failed to initialize the process attribute list: Windows error {code}")]
    AttributeListInitialize { code: u32 },
    #[error("failed to install the explicit standard-handle list: Windows error {code}")]
    HandleListApply { code: u32 },
    #[error("failed to install atomic Job Object assignment: Windows error {code}")]
    JobListApply { code: u32 },
    #[error("CreateProcessAsUserW failed: Windows error {code}")]
    ProcessCreate { code: u32 },
    #[error("Windows returned no process or thread handle for the child")]
    MissingProcessHandle,
    #[error("waiting for the restricted process failed: Windows error {code}")]
    ProcessWait { code: u32 },
    #[error("waiting for the restricted process returned unexpected status {result:#x}")]
    UnexpectedWait { result: u32 },
    #[error("reading the restricted process exit code failed: Windows error {code}")]
    ExitCodeRead { code: u32 },
}

impl SpawnedProcess {
    #[allow(unsafe_code)]
    pub(super) fn start(
        token: &RestrictedPrimaryToken,
        request: RunnerSpawnRequest,
    ) -> Result<Self, ProcessStartError> {
        validate_request(&request)?;
        let mut command_line = command_line(&request.command);
        command_line.push(0);
        let mut application = request.command[0].clone();
        application.push(0);
        let mut working_directory = request.working_directory;
        working_directory.push(0);
        let desktop = PrivateDesktop::create(token)?;
        let job_value =
            usize::try_from(request.job_handle).map_err(|_| ProcessStartError::InvalidJobHandle)?;
        let job_handle = job_value as *mut c_void;
        if job_handle.is_null() || job_handle == INVALID_HANDLE_VALUE {
            return Err(ProcessStartError::InvalidJobHandle);
        }
        let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
        startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        startup.StartupInfo.lpDesktop = desktop.startup_name().as_ptr() as _;
        let mut process: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        {
            let standard = PreparedStandardHandles::new(request.standard_handles, job_value)?;
            let job = unsafe { OwnedHandle::from_raw_handle(job_handle as RawHandle) };
            let child_handles = standard.raw_handles();
            let mut attributes = ProcessAttributeList::new(2)?;
            attributes.apply_job(job.as_raw_handle())?;
            attributes.apply_handles(child_handles)?;
            startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
            startup.StartupInfo.hStdInput = child_handles[0];
            startup.StartupInfo.hStdOutput = child_handles[1];
            startup.StartupInfo.hStdError = child_handles[2];
            startup.lpAttributeList = attributes.as_mut_ptr();
            if unsafe {
                CreateProcessAsUserW(
                    token.raw(),
                    application.as_ptr(),
                    command_line.as_mut_ptr(),
                    std::ptr::null(),
                    std::ptr::null(),
                    1,
                    CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
                    request.environment_block.as_ptr().cast(),
                    working_directory.as_ptr(),
                    &startup.StartupInfo,
                    &mut process,
                )
            } == 0
            {
                return Err(ProcessStartError::ProcessCreate {
                    code: unsafe { GetLastError() },
                });
            }
        }
        if process.hProcess.is_null() || process.hThread.is_null() || process.dwProcessId == 0 {
            if !process.hProcess.is_null() {
                unsafe {
                    windows_sys::Win32::Foundation::CloseHandle(process.hProcess);
                }
            }
            if !process.hThread.is_null() {
                unsafe {
                    windows_sys::Win32::Foundation::CloseHandle(process.hThread);
                }
            }
            return Err(ProcessStartError::MissingProcessHandle);
        }
        let process_handle = unsafe { OwnedHandle::from_raw_handle(process.hProcess as RawHandle) };
        let _thread = unsafe { OwnedHandle::from_raw_handle(process.hThread as RawHandle) };
        Ok(Self {
            process: process_handle,
            process_id: process.dwProcessId,
            finished: false,
            _desktop: desktop,
        })
    }

    pub(super) const fn id(&self) -> u32 {
        self.process_id
    }

    #[allow(unsafe_code)]
    pub(super) fn wait(&mut self) -> Result<u32, ProcessStartError> {
        let wait = unsafe {
            windows_sys::Win32::System::Threading::WaitForSingleObject(
                self.process.as_raw_handle() as _,
                windows_sys::Win32::System::Threading::INFINITE,
            )
        };
        if wait == windows_sys::Win32::Foundation::WAIT_FAILED {
            return Err(ProcessStartError::ProcessWait {
                code: unsafe { GetLastError() },
            });
        }
        if wait != windows_sys::Win32::Foundation::WAIT_OBJECT_0 {
            return Err(ProcessStartError::UnexpectedWait { result: wait });
        }
        let mut exit_code = 0;
        if unsafe {
            windows_sys::Win32::System::Threading::GetExitCodeProcess(
                self.process.as_raw_handle() as _,
                &mut exit_code,
            )
        } == 0
        {
            return Err(ProcessStartError::ExitCodeRead {
                code: unsafe { GetLastError() },
            });
        }
        self.finished = true;
        Ok(exit_code)
    }
}

#[allow(unsafe_code)]
impl Drop for SpawnedProcess {
    fn drop(&mut self) {
        if !self.finished {
            unsafe {
                windows_sys::Win32::System::Threading::TerminateProcess(
                    self.process.as_raw_handle() as _,
                    125,
                );
                windows_sys::Win32::System::Threading::WaitForSingleObject(
                    self.process.as_raw_handle() as _,
                    5_000,
                );
            }
        }
    }
}

impl PreparedStandardHandles {
    #[allow(unsafe_code)]
    fn new(handles: RunnerStandardHandles, job: usize) -> Result<Self, ProcessStartError> {
        let stdin = standard_handle_value("stdin", handles.stdin)?;
        let stdout = standard_handle_value("stdout", handles.stdout)?;
        let stderr = standard_handle_value("stderr", handles.stderr)?;
        reject_duplicate("stdin", stdin, "stdout", stdout)?;
        reject_duplicate("stdin", stdin, "stderr", stderr)?;
        reject_duplicate("stdout", stdout, "stderr", stderr)?;
        for (stream, handle) in [("stdin", stdin), ("stdout", stdout), ("stderr", stderr)] {
            if handle as usize == job {
                return Err(ProcessStartError::StandardHandleMatchesJob { stream });
            }
            validate_inheritable_handle(stream, handle)?;
        }
        Ok(Self {
            stdin: unsafe { OwnedHandle::from_raw_handle(stdin as RawHandle) },
            stdout: unsafe { OwnedHandle::from_raw_handle(stdout as RawHandle) },
            stderr: unsafe { OwnedHandle::from_raw_handle(stderr as RawHandle) },
        })
    }

    fn raw_handles(&self) -> [*mut c_void; 3] {
        [
            self.stdin.as_raw_handle(),
            self.stdout.as_raw_handle(),
            self.stderr.as_raw_handle(),
        ]
    }
}

impl ProcessAttributeList {
    #[allow(unsafe_code)]
    fn new(attribute_count: u32) -> Result<Self, ProcessStartError> {
        let mut bytes = 0usize;
        let first = unsafe {
            InitializeProcThreadAttributeList(std::ptr::null_mut(), attribute_count, 0, &mut bytes)
        };
        if first != 0 || bytes == 0 {
            return Err(ProcessStartError::AttributeListSize {
                code: unsafe { GetLastError() },
            });
        }
        let words = bytes.div_ceil(size_of::<usize>());
        let mut list = Self {
            storage: vec![0usize; words],
            handle_list: Vec::new(),
            job_list: Vec::new(),
            initialized: false,
        };
        if unsafe {
            InitializeProcThreadAttributeList(list.as_mut_ptr(), attribute_count, 0, &mut bytes)
        } == 0
        {
            return Err(ProcessStartError::AttributeListInitialize {
                code: unsafe { GetLastError() },
            });
        }
        list.initialized = true;
        Ok(list)
    }

    #[allow(unsafe_code)]
    fn apply_handles(&mut self, handles: [*mut c_void; 3]) -> Result<(), ProcessStartError> {
        let (handle_list, handle_list_bytes) = self.store_handles(&handles);
        if unsafe {
            UpdateProcThreadAttribute(
                self.as_mut_ptr(),
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                handle_list,
                handle_list_bytes,
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        } == 0
        {
            return Err(ProcessStartError::HandleListApply {
                code: unsafe { GetLastError() },
            });
        }
        Ok(())
    }

    #[allow(unsafe_code)]
    fn apply_job(&mut self, job: *mut c_void) -> Result<(), ProcessStartError> {
        let (job_list, job_list_bytes) = self.store_job(job);
        if unsafe {
            UpdateProcThreadAttribute(
                self.as_mut_ptr(),
                0,
                PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
                job_list,
                job_list_bytes,
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        } == 0
        {
            return Err(ProcessStartError::JobListApply {
                code: unsafe { GetLastError() },
            });
        }
        Ok(())
    }

    fn store_handles(&mut self, handles: &[*mut c_void; 3]) -> (*const c_void, usize) {
        self.handle_list = Vec::from(*handles);
        (
            self.handle_list.as_ptr().cast(),
            std::mem::size_of_val(self.handle_list.as_slice()),
        )
    }

    fn store_job(&mut self, job: *mut c_void) -> (*const c_void, usize) {
        self.job_list = vec![job];
        (
            self.job_list.as_ptr().cast(),
            std::mem::size_of_val(self.job_list.as_slice()),
        )
    }

    fn as_mut_ptr(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.storage.as_mut_ptr().cast()
    }
}

#[allow(unsafe_code)]
impl Drop for ProcessAttributeList {
    fn drop(&mut self) {
        if self.initialized {
            unsafe {
                DeleteProcThreadAttributeList(self.as_mut_ptr());
            }
        }
    }
}

#[allow(unsafe_code)]
impl ProcessStartError {
    pub(super) const fn stage(&self) -> WindowsRunnerFailureStage {
        match self {
            Self::InvalidJobHandle | Self::JobListApply { .. } => WindowsRunnerFailureStage::Job,
            Self::EmptyCommand
            | Self::EmbeddedNul { .. }
            | Self::InvalidEnvironmentBlock
            | Self::EmptyWorkingDirectory
            | Self::StandardHandleWidth { .. }
            | Self::InvalidStandardHandle { .. }
            | Self::DuplicateStandardHandle { .. }
            | Self::StandardHandleMatchesJob { .. }
            | Self::StandardHandleInspect { .. }
            | Self::StandardHandleNotInheritable { .. }
            | Self::UnexpectedStandardHandleFlags { .. } => WindowsRunnerFailureStage::Request,
            Self::PrivateDesktop(_) => WindowsRunnerFailureStage::Process,
            Self::AttributeListSize { .. }
            | Self::AttributeListInitialize { .. }
            | Self::HandleListApply { .. }
            | Self::ProcessCreate { .. }
            | Self::MissingProcessHandle => WindowsRunnerFailureStage::Process,
            Self::ProcessWait { .. } | Self::UnexpectedWait { .. } | Self::ExitCodeRead { .. } => {
                WindowsRunnerFailureStage::Wait
            }
        }
    }

    pub(super) const fn failure_code(&self) -> WindowsRunnerFailureCode {
        match self {
            Self::EmptyCommand
            | Self::EmbeddedNul { .. }
            | Self::InvalidEnvironmentBlock
            | Self::EmptyWorkingDirectory => WindowsRunnerFailureCode::RequestField,
            Self::PrivateDesktop(_) => WindowsRunnerFailureCode::PrivateDesktopPrepare,
            Self::InvalidJobHandle => WindowsRunnerFailureCode::JobHandleInvalid,
            Self::StandardHandleWidth { .. }
            | Self::InvalidStandardHandle { .. }
            | Self::DuplicateStandardHandle { .. }
            | Self::StandardHandleMatchesJob { .. }
            | Self::StandardHandleInspect { .. }
            | Self::StandardHandleNotInheritable { .. }
            | Self::UnexpectedStandardHandleFlags { .. } => {
                WindowsRunnerFailureCode::StandardStreamPrepare
            }
            Self::AttributeListSize { .. } | Self::AttributeListInitialize { .. } => {
                WindowsRunnerFailureCode::AttributeListCreate
            }
            Self::HandleListApply { .. } => WindowsRunnerFailureCode::HandleListApply,
            Self::JobListApply { .. } => WindowsRunnerFailureCode::JobListApply,
            Self::ProcessCreate { .. } | Self::MissingProcessHandle => {
                WindowsRunnerFailureCode::ProcessStart
            }
            Self::ProcessWait { .. } | Self::UnexpectedWait { .. } => {
                WindowsRunnerFailureCode::ProcessWait
            }
            Self::ExitCodeRead { .. } => WindowsRunnerFailureCode::ExitCodeRead,
        }
    }

    pub(super) const fn native_code(&self) -> Option<u32> {
        match self {
            Self::StandardHandleInspect { code, .. }
            | Self::AttributeListSize { code }
            | Self::AttributeListInitialize { code }
            | Self::HandleListApply { code }
            | Self::JobListApply { code }
            | Self::ProcessCreate { code }
            | Self::ProcessWait { code }
            | Self::ExitCodeRead { code } => Some(*code),
            Self::PrivateDesktop(error) => error.native_code(),
            Self::EmptyCommand
            | Self::EmbeddedNul { .. }
            | Self::InvalidEnvironmentBlock
            | Self::EmptyWorkingDirectory
            | Self::InvalidJobHandle
            | Self::StandardHandleWidth { .. }
            | Self::InvalidStandardHandle { .. }
            | Self::DuplicateStandardHandle { .. }
            | Self::StandardHandleMatchesJob { .. }
            | Self::StandardHandleNotInheritable { .. }
            | Self::UnexpectedStandardHandleFlags { .. }
            | Self::MissingProcessHandle
            | Self::UnexpectedWait { .. } => None,
        }
    }
}

fn standard_handle_value(
    stream: &'static str,
    value: u64,
) -> Result<*mut c_void, ProcessStartError> {
    let value =
        usize::try_from(value).map_err(|_| ProcessStartError::StandardHandleWidth { stream })?;
    let handle = value as *mut c_void;
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        Err(ProcessStartError::InvalidStandardHandle { stream })
    } else {
        Ok(handle)
    }
}

fn reject_duplicate(
    first: &'static str,
    first_handle: *mut c_void,
    second: &'static str,
    second_handle: *mut c_void,
) -> Result<(), ProcessStartError> {
    if first_handle == second_handle {
        Err(ProcessStartError::DuplicateStandardHandle { first, second })
    } else {
        Ok(())
    }
}

#[allow(unsafe_code)]
fn validate_inheritable_handle(
    stream: &'static str,
    handle: *mut c_void,
) -> Result<(), ProcessStartError> {
    let mut flags = 0;
    if unsafe { GetHandleInformation(handle, &mut flags) } == 0 {
        return Err(ProcessStartError::StandardHandleInspect {
            stream,
            code: unsafe { GetLastError() },
        });
    }
    if flags & HANDLE_FLAG_INHERIT == 0 {
        return Err(ProcessStartError::StandardHandleNotInheritable { stream });
    }
    if flags != HANDLE_FLAG_INHERIT {
        return Err(ProcessStartError::UnexpectedStandardHandleFlags { stream, flags });
    }
    Ok(())
}

fn validate_request(request: &RunnerSpawnRequest) -> Result<(), ProcessStartError> {
    if request.command.is_empty() || request.command[0].is_empty() {
        return Err(ProcessStartError::EmptyCommand);
    }
    if request.command.iter().any(|argument| argument.contains(&0)) {
        return Err(ProcessStartError::EmbeddedNul { field: "command" });
    }
    if request.working_directory.is_empty() {
        return Err(ProcessStartError::EmptyWorkingDirectory);
    }
    if request.working_directory.contains(&0) {
        return Err(ProcessStartError::EmbeddedNul {
            field: "working directory",
        });
    }
    if request.environment_block.len() < 2 || !request.environment_block.ends_with(&[0, 0]) {
        return Err(ProcessStartError::InvalidEnvironmentBlock);
    }
    Ok(())
}

fn command_line(arguments: &[Vec<u16>]) -> Vec<u16> {
    let mut result = Vec::new();
    for (index, argument) in arguments.iter().enumerate() {
        if index != 0 {
            result.push(b' ' as u16);
        }
        quote_argument(argument, &mut result);
    }
    result
}

fn quote_argument(argument: &[u16], output: &mut Vec<u16>) {
    let quote = b'"' as u16;
    let slash = b'\\' as u16;
    let needs_quotes = argument.is_empty()
        || argument
            .iter()
            .any(|unit| matches!(*unit, 0x09 | 0x20 | 0x22));
    if !needs_quotes {
        output.extend_from_slice(argument);
        return;
    }
    output.push(quote);
    let mut slashes = 0usize;
    for unit in argument.iter().copied() {
        if unit == slash {
            slashes += 1;
        } else if unit == quote {
            output.extend(std::iter::repeat_n(slash, slashes * 2 + 1));
            output.push(quote);
            slashes = 0;
        } else {
            output.extend(std::iter::repeat_n(slash, slashes));
            output.push(unit);
            slashes = 0;
        }
    }
    output.extend(std::iter::repeat_n(slash, slashes * 2));
    output.push(quote);
}

#[cfg(test)]
mod tests {
    use std::ffi::c_void;

    use super::{
        ProcessAttributeList, ProcessStartError, command_line, reject_duplicate,
        standard_handle_value,
    };

    #[test]
    fn process_attributes_retain_their_own_backing_arrays() {
        let source_handles = [
            0x101usize as *mut c_void,
            0x102usize as *mut c_void,
            0x103usize as *mut c_void,
        ];
        let job = 0x201usize as *mut c_void;
        let mut attributes = ProcessAttributeList {
            storage: Vec::new(),
            handle_list: Vec::new(),
            job_list: Vec::new(),
            initialized: false,
        };

        let (handle_list, handle_bytes) = attributes.store_handles(&source_handles);
        let (job_list, job_bytes) = attributes.store_job(job);

        assert_ne!(handle_list, source_handles.as_ptr().cast());
        assert_eq!(handle_list, attributes.handle_list.as_ptr().cast());
        assert_eq!(attributes.handle_list, source_handles);
        assert_eq!(handle_bytes, std::mem::size_of_val(&source_handles));
        assert_eq!(job_list, attributes.job_list.as_ptr().cast());
        assert_eq!(attributes.job_list, [job]);
        assert_eq!(job_bytes, std::mem::size_of::<*mut c_void>());
    }

    #[test]
    fn command_line_uses_windows_backslash_quote_rules() {
        let arguments = [
            r"C:\Program Files\tool.exe".encode_utf16().collect(),
            r#"plain\"quoted"#.encode_utf16().collect(),
            r"ends with\\".encode_utf16().collect(),
            Vec::new(),
        ];
        let actual = String::from_utf16(&command_line(&arguments)).expect("valid UTF-16");

        assert_eq!(
            actual,
            r#""C:\Program Files\tool.exe" "plain\\\"quoted" "ends with\\\\" """#
        );
    }

    #[test]
    fn standard_handle_values_reject_null_invalid_and_aliases_before_ownership() {
        assert!(matches!(
            standard_handle_value("stdin", 0),
            Err(ProcessStartError::InvalidStandardHandle { stream: "stdin" })
        ));
        assert!(matches!(
            reject_duplicate(
                "stdin",
                0x1234usize as *mut c_void,
                "stdout",
                0x1234usize as *mut c_void,
            ),
            Err(ProcessStartError::DuplicateStandardHandle {
                first: "stdin",
                second: "stdout"
            })
        ));
    }
}
