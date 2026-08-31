// SPDX-License-Identifier: Apache-2.0

//! Parent-owned Windows standard streams and authenticated runner duplication.

use std::fs::File;
use std::os::windows::io::{AsRawHandle, FromRawHandle, IntoRawHandle, OwnedHandle, RawHandle};

use cageforge_command::{StdioMode, StdioSpec};
use thiserror::Error;
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    OPEN_EXISTING,
};
use windows_sys::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows_sys::Win32::System::Pipes::CreatePipe;

use crate::runner::parent::{BoundaryTerminator, RunnerHandleDuplicateError};
use crate::runner::protocol::RunnerStandardHandles;

pub(crate) struct ParentStdio {
    handles: RunnerStandardHandles,
    stdin: Option<File>,
    stdout: Option<File>,
    stderr: Option<File>,
}

struct PreparedStream {
    child_source: StandardSource,
    parent_endpoint: Option<OwnedHandle>,
}

enum StandardSource {
    Owned(OwnedHandle),
    Borrowed(RawHandle),
}

/// Failure while preparing one explicit Windows standard-stream handle.
#[derive(Debug, Error)]
pub enum WindowsStandardStreamError {
    /// Windows could not create an anonymous pipe for the requested stream.
    #[error("failed to create the parent-owned {stream} pipe: Windows error {code}")]
    PipeCreate {
        /// Standard-stream name.
        stream: &'static str,
        /// Native Windows error code.
        code: u32,
    },
    /// Windows returned an incomplete anonymous pipe pair.
    #[error("Windows returned an invalid parent-owned {stream} pipe pair")]
    InvalidPipe {
        /// Standard-stream name.
        stream: &'static str,
    },
    /// The current process has no handle associated with an inherited stream.
    #[error("the parent process has no inherited {stream} handle")]
    MissingInheritedHandle {
        /// Standard-stream name.
        stream: &'static str,
    },
    /// Windows rejected the inherited standard-handle query.
    #[error("failed to query the parent process {stream} handle: Windows error {code}")]
    InheritedHandleQuery {
        /// Standard-stream name.
        stream: &'static str,
        /// Native Windows error code.
        code: u32,
    },
    /// Windows could not open `NUL` with the direction required by the stream.
    #[error("failed to open NUL for child {stream}: Windows error {code}")]
    NullOpen {
        /// Standard-stream name.
        stream: &'static str,
        /// Native Windows error code.
        code: u32,
    },
    /// Windows could not duplicate the prepared handle into the pinned runner process.
    #[error(
        "failed to duplicate child {stream} into the authenticated runner: Windows error {code}"
    )]
    HandleDuplicate {
        /// Standard-stream name.
        stream: &'static str,
        /// Native Windows error code.
        code: u32,
    },
    /// Windows reported success without returning a target-process handle value.
    #[error("Windows returned an invalid child {stream} handle in the authenticated runner")]
    InvalidHandleDuplicate {
        /// Standard-stream name.
        stream: &'static str,
    },
}

impl ParentStdio {
    pub(crate) fn prepare(
        spec: StdioSpec,
        boundary: &BoundaryTerminator,
    ) -> Result<Self, WindowsStandardStreamError> {
        let stdin = PreparedStream::input(spec.stdin())?;
        let stdout = PreparedStream::output("stdout", STD_OUTPUT_HANDLE, spec.stdout())?;
        let stderr = PreparedStream::output("stderr", STD_ERROR_HANDLE, spec.stderr())?;
        let handles = RunnerStandardHandles {
            stdin: duplicate_source(boundary, "stdin", &stdin.child_source)?,
            stdout: duplicate_source(boundary, "stdout", &stdout.child_source)?,
            stderr: duplicate_source(boundary, "stderr", &stderr.child_source)?,
        };
        Ok(Self {
            handles,
            stdin: stdin.into_parent_file(),
            stdout: stdout.into_parent_file(),
            stderr: stderr.into_parent_file(),
        })
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        RunnerStandardHandles,
        Option<File>,
        Option<File>,
        Option<File>,
    ) {
        (self.handles, self.stdin, self.stdout, self.stderr)
    }
}

impl PreparedStream {
    fn input(mode: StdioMode) -> Result<Self, WindowsStandardStreamError> {
        match mode {
            StdioMode::Pipe => {
                let (read, write) = anonymous_pipe("stdin")?;
                Ok(Self {
                    child_source: StandardSource::Owned(read),
                    parent_endpoint: Some(write),
                })
            }
            StdioMode::Inherit => Ok(Self {
                child_source: inherited_source("stdin", STD_INPUT_HANDLE)?,
                parent_endpoint: None,
            }),
            StdioMode::Null => Ok(Self {
                child_source: StandardSource::Owned(open_null("stdin", FILE_GENERIC_READ)?),
                parent_endpoint: None,
            }),
        }
    }

    fn output(
        stream: &'static str,
        inherited_kind: u32,
        mode: StdioMode,
    ) -> Result<Self, WindowsStandardStreamError> {
        match mode {
            StdioMode::Pipe => {
                let (read, write) = anonymous_pipe(stream)?;
                Ok(Self {
                    child_source: StandardSource::Owned(write),
                    parent_endpoint: Some(read),
                })
            }
            StdioMode::Inherit => Ok(Self {
                child_source: inherited_source(stream, inherited_kind)?,
                parent_endpoint: None,
            }),
            StdioMode::Null => Ok(Self {
                child_source: StandardSource::Owned(open_null(stream, FILE_GENERIC_WRITE)?),
                parent_endpoint: None,
            }),
        }
    }

    #[allow(unsafe_code)]
    fn into_parent_file(self) -> Option<File> {
        self.parent_endpoint
            .map(|endpoint| unsafe { File::from_raw_handle(endpoint.into_raw_handle()) })
    }
}

impl StandardSource {
    fn raw(&self) -> RawHandle {
        match self {
            Self::Owned(handle) => handle.as_raw_handle(),
            Self::Borrowed(handle) => *handle,
        }
    }
}

fn duplicate_source(
    boundary: &BoundaryTerminator,
    stream: &'static str,
    source: &StandardSource,
) -> Result<u64, WindowsStandardStreamError> {
    match boundary.duplicate_inheritable_handle(source.raw()) {
        Ok(handle) => Ok(handle),
        Err(RunnerHandleDuplicateError::Duplicate { code }) => {
            Err(WindowsStandardStreamError::HandleDuplicate { stream, code })
        }
        Err(RunnerHandleDuplicateError::InvalidDuplicate) => {
            Err(WindowsStandardStreamError::InvalidHandleDuplicate { stream })
        }
    }
}

#[allow(unsafe_code)]
fn anonymous_pipe(
    stream: &'static str,
) -> Result<(OwnedHandle, OwnedHandle), WindowsStandardStreamError> {
    let mut read = std::ptr::null_mut();
    let mut write = std::ptr::null_mut();
    if unsafe { CreatePipe(&mut read, &mut write, std::ptr::null(), 0) } == 0 {
        return Err(WindowsStandardStreamError::PipeCreate {
            stream,
            code: unsafe { GetLastError() },
        });
    }
    if read.is_null() || write.is_null() {
        if !read.is_null() {
            unsafe { CloseHandle(read) };
        }
        if !write.is_null() {
            unsafe { CloseHandle(write) };
        }
        return Err(WindowsStandardStreamError::InvalidPipe { stream });
    }
    Ok((
        unsafe { OwnedHandle::from_raw_handle(read as RawHandle) },
        unsafe { OwnedHandle::from_raw_handle(write as RawHandle) },
    ))
}

#[allow(unsafe_code)]
fn inherited_source(
    stream: &'static str,
    kind: u32,
) -> Result<StandardSource, WindowsStandardStreamError> {
    let handle = unsafe { GetStdHandle(kind) };
    if handle.is_null() {
        return Err(WindowsStandardStreamError::MissingInheritedHandle { stream });
    }
    if handle == INVALID_HANDLE_VALUE {
        return Err(WindowsStandardStreamError::InheritedHandleQuery {
            stream,
            code: unsafe { GetLastError() },
        });
    }
    Ok(StandardSource::Borrowed(handle as RawHandle))
}

#[allow(unsafe_code)]
fn open_null(stream: &'static str, access: u32) -> Result<OwnedHandle, WindowsStandardStreamError> {
    let name = "NUL\0".encode_utf16().collect::<Vec<_>>();
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        Err(WindowsStandardStreamError::NullOpen {
            stream,
            code: unsafe { GetLastError() },
        })
    } else {
        Ok(unsafe { OwnedHandle::from_raw_handle(handle as RawHandle) })
    }
}
