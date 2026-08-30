// SPDX-License-Identifier: Apache-2.0

//! Launch-unique parent-side named pipes with bounded authenticated connection.

use std::fs::File;
use std::os::windows::io::{AsRawHandle, FromRawHandle, IntoRawHandle, OwnedHandle, RawHandle};
use std::sync::mpsc;
use std::time::Duration;

use thiserror::Error;
use windows_sys::Win32::Foundation::{
    DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_NOT_FOUND, ERROR_PIPE_CONNECTED, GetLastError,
    HLOCAL, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
    SE_KERNEL_OBJECT,
};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    SECURITY_ATTRIBUTES,
};
use windows_sys::Win32::System::IO::CancelSynchronousIo;
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, PIPE_READMODE_BYTE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetCurrentThread};

const PIPE_ACCESS_INBOUND: u32 = 0x0000_0001;
const PIPE_ACCESS_OUTBOUND: u32 = 0x0000_0002;
const FILE_FLAG_FIRST_PIPE_INSTANCE: u32 = 0x0008_0000;
const FILE_READ_DATA: u32 = 0x0000_0001;
const FILE_WRITE_DATA: u32 = 0x0000_0002;
const SYNCHRONIZE: u32 = 0x0010_0000;
const PIPE_BUFFER_BYTES: u32 = 64 * 1024;

pub(crate) struct RunnerPipeNames {
    pub(crate) request: String,
    pub(crate) response: String,
}

pub(crate) struct ParentRunnerPipe {
    handle: OwnedHandle,
    direction: ParentPipeDirection,
}

struct LocalSecurityDescriptor(PSECURITY_DESCRIPTOR);

struct LocalWideString(*mut u16);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ParentPipeDirection {
    Request,
    Response,
}

#[derive(Debug, Error)]
pub(crate) enum ParentRunnerPipeError {
    #[error("failed to generate a random runner pipe identity: {source}")]
    Random {
        #[source]
        source: getrandom::Error,
    },
    #[error("failed to parse the launch-unique runner pipe descriptor: Windows error {code}")]
    DescriptorParse { code: u32 },
    #[error("failed to create the {direction:?} runner pipe: Windows error {code}")]
    Create {
        direction: ParentPipeDirection,
        code: u32,
    },
    #[error("failed to read back the {direction:?} runner pipe descriptor: Windows error {code}")]
    DescriptorReadBack {
        direction: ParentPipeDirection,
        code: u32,
    },
    #[error("the {direction:?} runner pipe descriptor differs after Windows read-back")]
    DescriptorMismatch { direction: ParentPipeDirection },
    #[error("failed to duplicate the {direction:?} connect-thread handle: Windows error {code}")]
    ConnectThreadHandle {
        direction: ParentPipeDirection,
        code: u32,
    },
    #[error("the {direction:?} connect thread ended before publishing its handle")]
    ConnectThreadMissing { direction: ParentPipeDirection },
    #[error("failed to connect the {direction:?} runner pipe: Windows error {code}")]
    Connect {
        direction: ParentPipeDirection,
        code: u32,
    },
    #[error("timed out waiting for the {direction:?} runner pipe")]
    ConnectTimeout { direction: ParentPipeDirection },
    #[error(
        "failed to cancel the timed-out {direction:?} runner pipe connect: Windows error {code}"
    )]
    ConnectCancel {
        direction: ParentPipeDirection,
        code: u32,
    },
    #[error("the {direction:?} runner pipe connect thread panicked")]
    ConnectThreadPanic { direction: ParentPipeDirection },
    #[error("failed to query the {direction:?} runner pipe client PID: Windows error {code}")]
    ClientPidRead {
        direction: ParentPipeDirection,
        code: u32,
    },
    #[error("the {direction:?} runner pipe client PID {actual} differs from runner PID {expected}")]
    ClientPidMismatch {
        direction: ParentPipeDirection,
        expected: u32,
        actual: u32,
    },
}

#[allow(unsafe_code)]
impl Drop for LocalSecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0 as HLOCAL);
            }
        }
    }
}

#[allow(unsafe_code)]
impl Drop for LocalWideString {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0 as HLOCAL);
            }
        }
    }
}

impl RunnerPipeNames {
    pub(crate) fn generate() -> Result<Self, ParentRunnerPipeError> {
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).map_err(|source| ParentRunnerPipeError::Random { source })?;
        let nonce = random
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let base = format!(r"\\.\pipe\Cageforge-runner-{nonce}");
        Ok(Self {
            request: format!("{base}-request"),
            response: format!("{base}-response"),
        })
    }
}

impl ParentRunnerPipe {
    #[allow(unsafe_code)]
    pub(crate) fn create(
        name: &str,
        owner_sid: &str,
        logon_sid: &str,
        direction: ParentPipeDirection,
    ) -> Result<Self, ParentRunnerPipeError> {
        let client_access = format!("0x{:08x}", client_access_mask(direction));
        let sddl = format!(
            "O:{owner_sid}D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{owner_sid})(A;;{client_access};;;{logon_sid})"
        )
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let mut descriptor = std::ptr::null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(ParentRunnerPipeError::DescriptorParse {
                code: unsafe { GetLastError() },
            });
        }
        let descriptor = LocalSecurityDescriptor(descriptor);
        let security = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 0,
        };
        let name = name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let access = match direction {
            ParentPipeDirection::Request => PIPE_ACCESS_OUTBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE,
            ParentPipeDirection::Response => PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE,
        };
        let handle = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                access,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                PIPE_BUFFER_BYTES,
                PIPE_BUFFER_BYTES,
                0,
                &security,
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(ParentRunnerPipeError::Create {
                direction,
                code: unsafe { GetLastError() },
            });
        }
        let pipe = Self {
            handle: unsafe { OwnedHandle::from_raw_handle(handle as RawHandle) },
            direction,
        };
        pipe.verify_descriptor(&descriptor)?;
        Ok(pipe)
    }

    #[allow(unsafe_code)]
    pub(crate) fn connect(
        &self,
        expected_runner_pid: u32,
        timeout: Duration,
    ) -> Result<(), ParentRunnerPipeError> {
        let direction = self.direction;
        let handle = self.handle.as_raw_handle() as usize;
        let (thread_handle_sender, thread_handle_receiver) = mpsc::sync_channel(1);
        let (result_sender, result_receiver) = mpsc::sync_channel(1);
        std::thread::scope(|scope| {
            let connect = scope.spawn(move || {
                let thread_handle = duplicate_current_thread(direction);
                let Ok(thread_handle) = thread_handle else {
                    let _ = thread_handle_sender.send(thread_handle);
                    return;
                };
                if thread_handle_sender.send(Ok(thread_handle)).is_err() {
                    return;
                }
                let result = connect_and_verify(handle, direction, expected_runner_pid);
                let _ = result_sender.send(result);
            });
            let thread_handle = thread_handle_receiver
                .recv()
                .map_err(|_| ParentRunnerPipeError::ConnectThreadMissing { direction })??;
            let result = match result_receiver.recv_timeout(timeout) {
                Ok(result) => result,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if unsafe { CancelSynchronousIo(thread_handle.as_raw_handle() as _) } == 0 {
                        let code = unsafe { GetLastError() };
                        if code != ERROR_NOT_FOUND {
                            return Err(ParentRunnerPipeError::ConnectCancel { direction, code });
                        }
                    }
                    Err(ParentRunnerPipeError::ConnectTimeout { direction })
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    Err(ParentRunnerPipeError::ConnectThreadMissing { direction })
                }
            };
            if connect.join().is_err() {
                return Err(ParentRunnerPipeError::ConnectThreadPanic { direction });
            }
            result
        })
    }

    #[allow(unsafe_code)]
    pub(crate) fn into_file(self) -> File {
        unsafe { File::from_raw_handle(self.handle.into_raw_handle()) }
    }

    #[allow(unsafe_code)]
    fn verify_descriptor(
        &self,
        expected: &LocalSecurityDescriptor,
    ) -> Result<(), ParentRunnerPipeError> {
        let mut actual = std::ptr::null_mut();
        let status = unsafe {
            GetSecurityInfo(
                self.handle.as_raw_handle() as _,
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
            return Err(ParentRunnerPipeError::DescriptorReadBack {
                direction: self.direction,
                code: status,
            });
        }
        let actual = LocalSecurityDescriptor(actual);
        if descriptor_string(expected.0, self.direction)?
            == descriptor_string(actual.0, self.direction)?
        {
            Ok(())
        } else {
            Err(ParentRunnerPipeError::DescriptorMismatch {
                direction: self.direction,
            })
        }
    }
}

#[allow(unsafe_code)]
fn descriptor_string(
    descriptor: PSECURITY_DESCRIPTOR,
    direction: ParentPipeDirection,
) -> Result<String, ParentRunnerPipeError> {
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
        return Err(ParentRunnerPipeError::DescriptorReadBack {
            direction,
            code: unsafe { GetLastError() },
        });
    }
    let value = LocalWideString(value);
    Ok(wide_string(value.0))
}

const fn client_access_mask(direction: ParentPipeDirection) -> u32 {
    let data_access = match direction {
        ParentPipeDirection::Request => FILE_READ_DATA,
        ParentPipeDirection::Response => FILE_WRITE_DATA,
    };
    data_access | SYNCHRONIZE
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

#[allow(unsafe_code)]
fn duplicate_current_thread(
    direction: ParentPipeDirection,
) -> Result<OwnedHandle, ParentRunnerPipeError> {
    let mut duplicate = std::ptr::null_mut();
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            GetCurrentThread(),
            GetCurrentProcess(),
            &mut duplicate,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        return Err(ParentRunnerPipeError::ConnectThreadHandle {
            direction,
            code: unsafe { GetLastError() },
        });
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(duplicate as RawHandle) })
}

#[allow(unsafe_code)]
fn connect_and_verify(
    handle: usize,
    direction: ParentPipeDirection,
    expected_runner_pid: u32,
) -> Result<(), ParentRunnerPipeError> {
    let handle = handle as RawHandle;
    if unsafe { ConnectNamedPipe(handle, std::ptr::null_mut()) } == 0 {
        let code = unsafe { GetLastError() };
        if code != ERROR_PIPE_CONNECTED {
            return Err(ParentRunnerPipeError::Connect { direction, code });
        }
    }
    let mut actual = 0;
    if unsafe { GetNamedPipeClientProcessId(handle, &mut actual) } == 0 {
        return Err(ParentRunnerPipeError::ClientPidRead {
            direction,
            code: unsafe { GetLastError() },
        });
    }
    if actual != expected_runner_pid {
        return Err(ParentRunnerPipeError::ClientPidMismatch {
            direction,
            expected: expected_runner_pid,
            actual,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{FILE_READ_DATA, FILE_WRITE_DATA, SYNCHRONIZE, client_access_mask};
    use crate::runner_pipe::ParentPipeDirection;

    #[test]
    fn client_pipe_access_is_directional_and_synchronous() {
        assert_eq!(
            client_access_mask(ParentPipeDirection::Request),
            FILE_READ_DATA | SYNCHRONIZE
        );
        assert_eq!(
            client_access_mask(ParentPipeDirection::Response),
            FILE_WRITE_DATA | SYNCHRONIZE
        );
    }
}
