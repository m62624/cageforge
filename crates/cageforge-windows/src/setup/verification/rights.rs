// SPDX-License-Identifier: Apache-2.0

use std::ffi::c_void;
use std::mem::size_of;

use windows_sys::Win32::Foundation::{ERROR_INVALID_DATA, HLOCAL};
use windows_sys::Win32::Security::Authentication::Identity::{
    LSA_HANDLE, LSA_OBJECT_ATTRIBUTES, LSA_UNICODE_STRING, LsaClose, LsaEnumerateAccountRights,
    LsaFreeMemory, LsaNtStatusToWinError, LsaOpenPolicy, POLICY_LOOKUP_NAMES,
};
use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;

use crate::error::WindowsSetupVerificationError;

const REQUIRED_RIGHTS: [&str; 1] = ["SeDenyRemoteInteractiveLogonRight"];
const INCOMPATIBLE_RIGHTS: [&str; 2] = ["SeBatchLogonRight", "SeDenyInteractiveLogonRight"];

struct PolicyHandle(LSA_HANDLE);

struct LocalSid(*mut c_void);

struct LsaMemory(*mut LSA_UNICODE_STRING);

#[allow(unsafe_code)]
impl Drop for PolicyHandle {
    fn drop(&mut self) {
        unsafe {
            LsaClose(self.0);
        }
    }
}

#[allow(unsafe_code)]
impl Drop for LocalSid {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Foundation::LocalFree(self.0 as HLOCAL);
        }
    }
}

#[allow(unsafe_code)]
impl Drop for LsaMemory {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LsaFreeMemory(self.0.cast());
            }
        }
    }
}

#[allow(unsafe_code)]
pub(super) fn verify(account_sid: &str) -> Result<(), WindowsSetupVerificationError> {
    let attributes = LSA_OBJECT_ATTRIBUTES {
        Length: size_of::<LSA_OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: std::ptr::null_mut(),
        ObjectName: std::ptr::null_mut(),
        Attributes: 0,
        SecurityDescriptor: std::ptr::null_mut(),
        SecurityQualityOfService: std::ptr::null_mut(),
    };
    let mut policy: LSA_HANDLE = 0;
    let opened = unsafe {
        LsaOpenPolicy(
            std::ptr::null(),
            &attributes,
            POLICY_LOOKUP_NAMES as u32,
            &mut policy,
        )
    };
    if opened != 0 {
        return Err(rights_error(account_sid, opened));
    }
    let policy = PolicyHandle(policy);
    let sid_wide = account_sid
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut sid = std::ptr::null_mut();
    if unsafe { ConvertStringSidToSidW(sid_wide.as_ptr(), &mut sid) } == 0 {
        return Err(WindowsSetupVerificationError::AccountRightsRead {
            account: account_sid.to_string(),
            code: unsafe { windows_sys::Win32::Foundation::GetLastError() },
        });
    }
    let sid = LocalSid(sid);
    let mut values = std::ptr::null_mut();
    let mut count = 0u32;
    let enumerated = unsafe { LsaEnumerateAccountRights(policy.0, sid.0, &mut values, &mut count) };
    if enumerated != 0 {
        return Err(rights_error(account_sid, enumerated));
    }
    let values = LsaMemory(values);
    let actual = if count == 0 {
        Vec::new()
    } else if values.0.is_null() {
        return Err(WindowsSetupVerificationError::AccountRightsRead {
            account: account_sid.to_string(),
            code: ERROR_INVALID_DATA,
        });
    } else {
        unsafe { std::slice::from_raw_parts(values.0, count as usize) }
            .iter()
            .map(lsa_string)
            .collect::<Vec<_>>()
    };
    for right in REQUIRED_RIGHTS {
        if !actual
            .iter()
            .any(|actual| actual.eq_ignore_ascii_case(right))
        {
            return Err(WindowsSetupVerificationError::MissingAccountRight {
                account: account_sid.to_string(),
                right,
            });
        }
    }
    for right in INCOMPATIBLE_RIGHTS {
        if actual
            .iter()
            .any(|actual| actual.eq_ignore_ascii_case(right))
        {
            return Err(WindowsSetupVerificationError::UnexpectedAccountRight {
                account: account_sid.to_string(),
                right,
            });
        }
    }
    Ok(())
}

#[allow(unsafe_code)]
fn lsa_string(value: &LSA_UNICODE_STRING) -> String {
    if value.Length == 0
        || value.Buffer.is_null()
        || !value.Length.is_multiple_of(2)
        || value.Length > value.MaximumLength
    {
        return String::new();
    }
    unsafe {
        String::from_utf16_lossy(std::slice::from_raw_parts(
            value.Buffer,
            usize::from(value.Length / 2),
        ))
    }
}

#[allow(unsafe_code)]
fn rights_error(account_sid: &str, status: i32) -> WindowsSetupVerificationError {
    WindowsSetupVerificationError::AccountRightsRead {
        account: account_sid.to_string(),
        code: unsafe { LsaNtStatusToWinError(status) },
    }
}
