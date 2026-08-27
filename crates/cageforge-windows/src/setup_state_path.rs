// SPDX-License-Identifier: Apache-2.0

//! Owner-scoped Windows setup-state path derivation.

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;

use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::UI::Shell::{FOLDERID_ProgramData, KF_FLAG_DEFAULT, SHGetKnownFolderPath};

const STATE_PARENT: &str = "Cageforge";
const STATE_COMPONENT: &str = "windows-sandbox";

pub(crate) fn default_state_directory(owner_sid: &str) -> Result<PathBuf, i32> {
    Ok(program_data_directory()?
        .join(STATE_PARENT)
        .join(STATE_COMPONENT)
        .join(crate::owner_identity::owner_key(owner_sid)))
}

#[allow(unsafe_code)]
pub(crate) fn program_data_directory() -> Result<PathBuf, i32> {
    let mut value = std::ptr::null_mut();
    let result = unsafe {
        SHGetKnownFolderPath(
            &FOLDERID_ProgramData,
            KF_FLAG_DEFAULT as u32,
            std::ptr::null_mut(),
            &mut value,
        )
    };
    if result < 0 || value.is_null() {
        return Err(result);
    }
    let path = unsafe {
        let mut length = 0usize;
        while *value.add(length) != 0 {
            length += 1;
        }
        PathBuf::from(OsString::from_wide(std::slice::from_raw_parts(
            value, length,
        )))
    };
    unsafe {
        CoTaskMemFree(value.cast());
    }
    Ok(path)
}
