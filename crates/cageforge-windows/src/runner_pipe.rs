// SPDX-License-Identifier: Apache-2.0

//! Launch-unique parent-side named pipes with bounded authenticated connection.

use std::ffi::c_void;
use std::fmt;
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
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
    SE_KERNEL_OBJECT,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetLengthSid,
    GetSecurityDescriptorControl, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner,
    IsValidSecurityDescriptor, IsValidSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    SE_DACL_PROTECTED, SECURITY_ATTRIBUTES,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_APPEND_DATA, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES,
};
use windows_sys::Win32::System::IO::CancelSynchronousIo;
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, PIPE_READMODE_BYTE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetCurrentThread};

const PIPE_ACCESS_INBOUND: u32 = 0x0000_0001;
const PIPE_ACCESS_OUTBOUND: u32 = 0x0000_0002;
const FILE_FLAG_FIRST_PIPE_INSTANCE: u32 = 0x0008_0000;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ParentPipeDirection {
    Request,
    Response,
}

#[derive(Debug)]
pub(crate) enum RunnerPipeDescriptorComponent {
    ExpectedInvalid,
    ActualInvalid,
    Owner,
    ProtectedDacl,
    Dacl,
    AceCount,
    Ace { index: u16 },
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
    #[error("the {direction:?} runner pipe descriptor {component} differs after Windows read-back")]
    DescriptorMismatch {
        direction: ParentPipeDirection,
        component: RunnerPipeDescriptorComponent,
    },
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

impl fmt::Display for RunnerPipeDescriptorComponent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExpectedInvalid => formatter.write_str("expected security descriptor is invalid"),
            Self::ActualInvalid => formatter.write_str("read-back security descriptor is invalid"),
            Self::Owner => formatter.write_str("owner"),
            Self::ProtectedDacl => formatter.write_str("protected DACL state"),
            Self::Dacl => formatter.write_str("DACL revision"),
            Self::AceCount => formatter.write_str("ACE count"),
            Self::Ace { index } => write!(formatter, "ACE at index {index}"),
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
        ready: mpsc::SyncSender<()>,
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
            let _ = ready.send(());
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
        if let Some(component) = descriptor_difference(expected.0, actual.0) {
            return Err(ParentRunnerPipeError::DescriptorMismatch {
                direction: self.direction,
                component,
            });
        }
        Ok(())
    }
}

#[allow(unsafe_code)]
fn descriptor_difference(
    expected: PSECURITY_DESCRIPTOR,
    actual: PSECURITY_DESCRIPTOR,
) -> Option<RunnerPipeDescriptorComponent> {
    if unsafe { IsValidSecurityDescriptor(expected) } == 0 {
        return Some(RunnerPipeDescriptorComponent::ExpectedInvalid);
    }
    if unsafe { IsValidSecurityDescriptor(actual) } == 0 {
        return Some(RunnerPipeDescriptorComponent::ActualInvalid);
    }

    let (expected_owner, expected_dacl) = match descriptor_owner_and_dacl(expected) {
        Ok(parts) => parts,
        Err(component) => return Some(component),
    };
    let (actual_owner, actual_dacl) = match descriptor_owner_and_dacl(actual) {
        Ok(parts) => parts,
        Err(component) => return Some(component),
    };
    if unsafe { EqualSid(expected_owner, actual_owner) } == 0 {
        return Some(RunnerPipeDescriptorComponent::Owner);
    }

    if !has_protected_dacl(expected) || !has_protected_dacl(actual) {
        return Some(RunnerPipeDescriptorComponent::ProtectedDacl);
    }
    if unsafe { (*expected_dacl).AclRevision } != unsafe { (*actual_dacl).AclRevision } {
        return Some(RunnerPipeDescriptorComponent::Dacl);
    }
    if unsafe { (*expected_dacl).AceCount } != unsafe { (*actual_dacl).AceCount } {
        return Some(RunnerPipeDescriptorComponent::AceCount);
    }

    for index in 0..unsafe { (*expected_dacl).AceCount } {
        if !ace_matches(expected_dacl, actual_dacl, index) {
            return Some(RunnerPipeDescriptorComponent::Ace { index });
        }
    }
    None
}

#[allow(unsafe_code)]
fn descriptor_owner_and_dacl(
    descriptor: PSECURITY_DESCRIPTOR,
) -> Result<(*mut c_void, *mut windows_sys::Win32::Security::ACL), RunnerPipeDescriptorComponent> {
    let mut owner = std::ptr::null_mut();
    let mut owner_defaulted = 0;
    if unsafe { GetSecurityDescriptorOwner(descriptor, &mut owner, &mut owner_defaulted) } == 0
        || owner.is_null()
        || unsafe { IsValidSid(owner) } == 0
    {
        return Err(RunnerPipeDescriptorComponent::Owner);
    }
    let mut dacl_present = 0;
    let mut dacl_defaulted = 0;
    let mut dacl = std::ptr::null_mut();
    if unsafe {
        GetSecurityDescriptorDacl(
            descriptor,
            &mut dacl_present,
            &mut dacl,
            &mut dacl_defaulted,
        )
    } == 0
        || dacl_present == 0
        || dacl.is_null()
    {
        return Err(RunnerPipeDescriptorComponent::Dacl);
    }
    Ok((owner, dacl))
}

#[allow(unsafe_code)]
fn has_protected_dacl(descriptor: PSECURITY_DESCRIPTOR) -> bool {
    let mut control = 0u16;
    let mut revision = 0u32;
    (unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) }) != 0
        && control & SE_DACL_PROTECTED != 0
}

#[allow(unsafe_code)]
fn ace_matches(
    expected_dacl: *mut windows_sys::Win32::Security::ACL,
    actual_dacl: *mut windows_sys::Win32::Security::ACL,
    index: u16,
) -> bool {
    let mut expected_raw = std::ptr::null_mut();
    let mut actual_raw = std::ptr::null_mut();
    if unsafe { GetAce(expected_dacl, u32::from(index), &mut expected_raw) } == 0
        || expected_raw.is_null()
        || unsafe { GetAce(actual_dacl, u32::from(index), &mut actual_raw) } == 0
        || actual_raw.is_null()
    {
        return false;
    }
    let expected = expected_raw.cast::<ACCESS_ALLOWED_ACE>();
    let actual = actual_raw.cast::<ACCESS_ALLOWED_ACE>();
    if unsafe { (*expected).Header.AceType } != ACCESS_ALLOWED_ACE_TYPE as u8
        || unsafe { (*actual).Header.AceType } != ACCESS_ALLOWED_ACE_TYPE as u8
        || unsafe { (*expected).Header.AceFlags } != 0
        || unsafe { (*actual).Header.AceFlags } != 0
        || unsafe { (*expected).Mask } != unsafe { (*actual).Mask }
    {
        return false;
    }
    let expected_sid = unsafe { (&raw mut (*expected).SidStart).cast::<c_void>() };
    let actual_sid = unsafe { (&raw mut (*actual).SidStart).cast::<c_void>() };
    if unsafe { IsValidSid(expected_sid) } == 0 || unsafe { IsValidSid(actual_sid) } == 0 {
        return false;
    }
    let expected_size = std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart)
        .checked_add(unsafe { GetLengthSid(expected_sid) } as usize);
    let actual_size = std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart)
        .checked_add(unsafe { GetLengthSid(actual_sid) } as usize);
    expected_size == Some(unsafe { (*expected).Header.AceSize } as usize)
        && actual_size == Some(unsafe { (*actual).Header.AceSize } as usize)
        && unsafe { EqualSid(expected_sid, actual_sid) } != 0
}

const fn client_access_mask(direction: ParentPipeDirection) -> u32 {
    const RESPONSE_PIPE_WRITE_ACCESS: u32 =
        (FILE_GENERIC_WRITE & !FILE_APPEND_DATA) | FILE_READ_ATTRIBUTES;

    match direction {
        ParentPipeDirection::Request => FILE_GENERIC_READ,
        ParentPipeDirection::Response => RESPONSE_PIPE_WRITE_ACCESS,
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
    use super::{
        FILE_APPEND_DATA, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES,
        client_access_mask,
    };
    use crate::runner_pipe::ParentPipeDirection;

    #[test]
    fn client_pipe_access_is_directional_without_create_pipe_instance() {
        assert_eq!(
            client_access_mask(ParentPipeDirection::Request),
            FILE_GENERIC_READ
        );
        assert_eq!(
            client_access_mask(ParentPipeDirection::Response),
            (FILE_GENERIC_WRITE & !FILE_APPEND_DATA) | FILE_READ_ATTRIBUTES
        );
        assert_eq!(
            client_access_mask(ParentPipeDirection::Response) & FILE_APPEND_DATA,
            0
        );
    }
}
