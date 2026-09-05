// SPDX-License-Identifier: Apache-2.0

//! Bounded conversion of Windows-owned wide strings.

use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows_sys::Win32::Foundation::{HLOCAL, LocalFree};
use windows_sys::Win32::Security::SECURITY_MAX_SID_SIZE;
use windows_sys::Win32::System::Memory::LocalSize;

// A textual SID is substantially shorter than four UTF-16 code units for
// every byte of the maximum binary SID. The derived bound is intentionally
// generous while remaining finite and tied to the Windows SID contract.
const MAX_SID_STRING_CODE_UNITS: usize = SECURITY_MAX_SID_SIZE as usize * 4;

struct LocalWideString(*mut u16);

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

/// Encode a Windows string for an FFI call, including its terminating NUL.
pub(crate) fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Encode a Windows path for an FFI call, including its terminating NUL.
pub(crate) fn wide_path(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

#[allow(unsafe_code)]
pub(crate) fn local_sid_string(value: *mut u16) -> Option<String> {
    let value = LocalWideString(value);
    if value.0.is_null() {
        return None;
    }

    let allocation_bytes = unsafe { LocalSize(value.0 as HLOCAL) };
    if allocation_bytes == 0
        || !allocation_bytes.is_multiple_of(size_of::<u16>())
        || allocation_bytes / size_of::<u16>() > MAX_SID_STRING_CODE_UNITS
    {
        return None;
    }

    let units = allocation_bytes / size_of::<u16>();
    let value = unsafe { std::slice::from_raw_parts(value.0, units) };
    let length = value.iter().position(|unit| *unit == 0)?;
    String::from_utf16(&value[..length]).ok()
}

/// Read a bounded UTF-16 string returned in a LocalAlloc-owned buffer.
#[allow(unsafe_code)]
pub(crate) fn local_wide_string_with_length(value: *const u16, length: u32) -> Option<String> {
    if value.is_null() || length == 0 {
        return None;
    }
    let allocation_bytes = unsafe { LocalSize(value as HLOCAL) };
    if allocation_bytes == 0
        || !allocation_bytes.is_multiple_of(size_of::<u16>())
        || usize::try_from(length).ok()? > allocation_bytes / size_of::<u16>()
    {
        return None;
    }
    let units = unsafe { std::slice::from_raw_parts(value, length as usize) };
    let units = units.strip_suffix(&[0]).unwrap_or(units);
    Some(String::from_utf16_lossy(units))
}
