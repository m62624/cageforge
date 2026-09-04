// SPDX-License-Identifier: Apache-2.0

//! Shared protected range-lock primitive for runtime and elevated setup.

use std::fs::File;
use std::os::windows::io::AsRawHandle;

use thiserror::Error;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Storage::FileSystem::{
    LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, LockFileEx, UnlockFileEx,
};
use windows_sys::Win32::System::IO::OVERLAPPED;

pub(crate) struct CapabilityLock {
    file: File,
    offset: u32,
    locked: bool,
}

#[derive(Debug, Error)]
pub(crate) enum CapabilityLockError {
    #[error("failed to acquire the {purpose} capability lock: Windows error {code}")]
    Acquire { purpose: &'static str, code: u32 },
}

impl CapabilityLock {
    #[allow(unsafe_code)]
    pub(crate) fn acquire_file(
        file: File,
        offset: u32,
        exclusive: bool,
        fail_immediately: bool,
        purpose: &'static str,
    ) -> Result<Self, CapabilityLockError> {
        let mut overlapped = OVERLAPPED::default();
        overlapped.Anonymous.Anonymous.Offset = offset;
        let mut flags = if exclusive {
            LOCKFILE_EXCLUSIVE_LOCK
        } else {
            0
        };
        if fail_immediately {
            flags |= LOCKFILE_FAIL_IMMEDIATELY;
        }
        if unsafe { LockFileEx(file.as_raw_handle() as _, flags, 0, 1, 0, &mut overlapped) } == 0 {
            return Err(CapabilityLockError::Acquire {
                purpose,
                code: unsafe { GetLastError() },
            });
        }
        Ok(Self {
            file,
            offset,
            locked: true,
        })
    }
}

#[allow(unsafe_code)]
impl Drop for CapabilityLock {
    fn drop(&mut self) {
        if self.locked {
            let mut overlapped = OVERLAPPED::default();
            overlapped.Anonymous.Anonymous.Offset = self.offset;
            unsafe {
                UnlockFileEx(self.file.as_raw_handle() as _, 0, 1, 0, &mut overlapped);
            }
        }
    }
}
