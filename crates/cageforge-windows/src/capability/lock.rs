// SPDX-License-Identifier: Apache-2.0

//! Shared protected range-lock primitive for runtime and elevated setup.

use std::fs::File;
use std::os::windows::io::AsRawHandle;
use std::thread;
use std::time::{Duration, Instant};

use thiserror::Error;
use windows_sys::Win32::Foundation::{ERROR_LOCK_VIOLATION, GetLastError};
use windows_sys::Win32::Storage::FileSystem::{
    LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, LockFileEx, UnlockFileEx,
};
use windows_sys::Win32::System::IO::OVERLAPPED;

const MUTATION_LOCK_WAIT_TIMEOUT: Duration = Duration::from_secs(15);
const MUTATION_LOCK_POLL_INTERVAL: Duration = Duration::from_millis(10);

pub(crate) struct CapabilityLock {
    file: File,
    offset: u32,
    locked: bool,
}

#[derive(Debug, Error)]
pub(crate) enum CapabilityLockError {
    #[error("failed to acquire the {purpose} capability lock: Windows error {code}")]
    Acquire { purpose: &'static str, code: u32 },
    #[error("timed out acquiring the {purpose} capability lock after {timeout_ms} ms")]
    Timeout {
        purpose: &'static str,
        timeout_ms: u128,
    },
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
        let mut flags = if exclusive {
            LOCKFILE_EXCLUSIVE_LOCK
        } else {
            0
        };
        // Every attempt must be non-blocking.  The waiting variant is
        // implemented by the bounded poll loop below; allowing LockFileEx to
        // block here would make MUTATION_LOCK_WAIT_TIMEOUT ineffective.
        flags |= LOCKFILE_FAIL_IMMEDIATELY;
        let deadline = Instant::now() + MUTATION_LOCK_WAIT_TIMEOUT;
        loop {
            let mut overlapped = OVERLAPPED::default();
            overlapped.Anonymous.Anonymous.Offset = offset;
            if unsafe { LockFileEx(file.as_raw_handle() as _, flags, 0, 1, 0, &mut overlapped) }
                != 0
            {
                return Ok(Self {
                    file,
                    offset,
                    locked: true,
                });
            }
            let code = unsafe { GetLastError() };
            if fail_immediately || code != ERROR_LOCK_VIOLATION {
                return Err(CapabilityLockError::Acquire { purpose, code });
            }
            if Instant::now() >= deadline {
                return Err(CapabilityLockError::Timeout {
                    purpose,
                    timeout_ms: MUTATION_LOCK_WAIT_TIMEOUT.as_millis(),
                });
            }
            thread::sleep(MUTATION_LOCK_POLL_INTERVAL);
        }
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
