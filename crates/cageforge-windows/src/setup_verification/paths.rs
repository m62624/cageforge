// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use windows_sys::Win32::Foundation::{GetLastError, HLOCAL, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, GetNamedSecurityInfoW, SDDL_REVISION_1,
    SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};

use crate::error::WindowsSetupVerificationError;

struct LocalSecurityDescriptor(PSECURITY_DESCRIPTOR);

struct LocalWideString(*mut u16);

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

#[allow(unsafe_code)]
pub(super) fn verify_protected_dacl(
    path: &Path,
    owner_sid: &str,
    inherit: bool,
) -> Result<(), WindowsSetupVerificationError> {
    use std::os::windows::ffi::OsStrExt;

    let path_wide = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let status = unsafe {
        GetNamedSecurityInfoW(
            path_wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(WindowsSetupVerificationError::ProtectedAclRead {
            path: path.to_path_buf(),
            code: status,
        });
    }
    let descriptor = LocalSecurityDescriptor(descriptor);
    let mut value = std::ptr::null_mut();
    if unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor.0,
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            &mut value,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(WindowsSetupVerificationError::ProtectedAclRead {
            path: path.to_path_buf(),
            code: unsafe { GetLastError() },
        });
    }
    let value = LocalWideString(value);
    let actual = wide_pointer_to_string(value.0);
    if protected_dacl_matches(&actual, owner_sid, inherit) {
        Ok(())
    } else {
        Err(WindowsSetupVerificationError::ProtectedAclMismatch {
            path: path.to_path_buf(),
            actual,
        })
    }
}

fn protected_dacl_matches(actual: &str, owner_sid: &str, inherit: bool) -> bool {
    let Some(body) = actual.strip_prefix("D:P") else {
        return false;
    };
    let body = body.strip_prefix("AI").unwrap_or(body);
    let Some(body) = body
        .strip_prefix('(')
        .and_then(|value| value.strip_suffix(')'))
    else {
        return false;
    };
    let mut actual_aces = body.split(")(").collect::<Vec<_>>();
    actual_aces.sort_unstable();
    let flags = if inherit { "OICI" } else { "" };
    let mut expected_aces = [
        format!("A;{flags};GA;;;SY"),
        format!("A;{flags};GA;;;BA"),
        format!("A;{flags};GA;;;{owner_sid}"),
    ];
    expected_aces.sort_unstable();
    actual_aces == expected_aces
}

#[allow(unsafe_code)]
fn wide_pointer_to_string(value: *const u16) -> String {
    if value.is_null() {
        return String::new();
    }
    unsafe {
        let mut length = 0usize;
        while *value.add(length) != 0 {
            length += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(value, length))
    }
}
