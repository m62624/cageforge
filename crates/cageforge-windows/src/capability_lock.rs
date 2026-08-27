// SPDX-License-Identifier: Apache-2.0

//! Shared protected range-lock primitive for runtime and elevated setup.

use std::fs::{File, OpenOptions};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};

use thiserror::Error;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Storage::FileSystem::{
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, LOCKFILE_EXCLUSIVE_LOCK,
    LOCKFILE_FAIL_IMMEDIATELY, LockFileEx, UnlockFileEx,
};
use windows_sys::Win32::System::IO::OVERLAPPED;

pub(crate) struct CapabilityLock {
    file: File,
    overlapped: OVERLAPPED,
    locked: bool,
}

#[derive(Debug, Error)]
pub(crate) enum CapabilityLockError {
    #[error("failed to open protected capability-SID lock file {path:?}: {source}")]
    Open {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to acquire the {purpose} capability lock: Windows error {code}")]
    Acquire { purpose: &'static str, code: u32 },
}

impl CapabilityLock {
    #[allow(unsafe_code)]
    pub(crate) fn acquire(
        path: &Path,
        offset: u32,
        exclusive: bool,
        fail_immediately: bool,
        purpose: &'static str,
    ) -> Result<Self, CapabilityLockError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .open(path)
            .map_err(|source| CapabilityLockError::Open {
                path: path.to_path_buf(),
                source,
            })?;
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
            overlapped,
            locked: true,
        })
    }
}

#[allow(unsafe_code)]
impl Drop for CapabilityLock {
    fn drop(&mut self) {
        if self.locked {
            unsafe {
                UnlockFileEx(
                    self.file.as_raw_handle() as _,
                    0,
                    1,
                    0,
                    &mut self.overlapped,
                );
            }
        }
    }
}
