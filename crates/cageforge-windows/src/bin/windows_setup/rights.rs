// SPDX-License-Identifier: Apache-2.0

use std::ffi::c_void;
use std::mem::size_of;

use windows_sys::Win32::Foundation::HLOCAL;
use windows_sys::Win32::Security::Authentication::Identity::{
    LSA_HANDLE, LSA_OBJECT_ATTRIBUTES, LSA_UNICODE_STRING, LsaAddAccountRights, LsaClose,
    LsaEnumerateAccountRights, LsaFreeMemory, LsaNtStatusToWinError, LsaOpenPolicy,
    LsaRemoveAccountRights, POLICY_CREATE_ACCOUNT, POLICY_LOOKUP_NAMES,
};
use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;

use crate::setup_protocol::{SetupFailureCode, SetupStage};

use super::{NativeSetupFailure, NativeSetupResult};

const REQUIRED_RIGHTS: [&str; 1] = ["SeDenyRemoteInteractiveLogonRight"];
const REMOVED_RIGHTS: [&str; 2] = ["SeBatchLogonRight", "SeDenyInteractiveLogonRight"];

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
pub(super) fn apply_and_verify(account_sid: &str) -> NativeSetupResult<()> {
    let policy = open_policy()?;
    let sid = parse_sid(account_sid)?;
    let mut right_buffers = REQUIRED_RIGHTS.map(wide_without_nul);
    let rights = right_buffers
        .iter_mut()
        .map(|buffer| lsa_string(buffer))
        .collect::<NativeSetupResult<Vec<_>>>()?;
    let status =
        unsafe { LsaAddAccountRights(policy.0, sid.0, rights.as_ptr(), rights.len() as u32) };
    if status != 0 {
        return Err(lsa_failure(
            SetupFailureCode::BatchLogonRight,
            status,
            format!("failed to grant sandbox logon rights to {account_sid}"),
        ));
    }
    let mut removed_right_buffers = REMOVED_RIGHTS.map(wide_without_nul);
    let removed_rights = removed_right_buffers
        .iter_mut()
        .map(|buffer| lsa_string(buffer))
        .collect::<NativeSetupResult<Vec<_>>>()?;
    let status = unsafe {
        LsaRemoveAccountRights(
            policy.0,
            sid.0,
            false,
            removed_rights.as_ptr(),
            removed_rights.len() as u32,
        )
    };
    if status != 0 {
        return Err(lsa_failure(
            SetupFailureCode::BatchLogonRight,
            status,
            format!("failed to remove obsolete sandbox logon rights from {account_sid}"),
        ));
    }
    verify_rights(&policy, &sid, account_sid)
}

#[allow(unsafe_code)]
fn open_policy() -> NativeSetupResult<PolicyHandle> {
    let attributes = LSA_OBJECT_ATTRIBUTES {
        Length: size_of::<LSA_OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: std::ptr::null_mut(),
        ObjectName: std::ptr::null_mut(),
        Attributes: 0,
        SecurityDescriptor: std::ptr::null_mut(),
        SecurityQualityOfService: std::ptr::null_mut(),
    };
    let mut handle: LSA_HANDLE = 0;
    let status = unsafe {
        LsaOpenPolicy(
            std::ptr::null(),
            &attributes,
            (POLICY_LOOKUP_NAMES | POLICY_CREATE_ACCOUNT) as u32,
            &mut handle,
        )
    };
    if status != 0 {
        return Err(lsa_failure(
            SetupFailureCode::BatchLogonRight,
            status,
            "failed to open local security policy",
        ));
    }
    Ok(PolicyHandle(handle))
}

#[allow(unsafe_code)]
fn parse_sid(value: &str) -> NativeSetupResult<LocalSid> {
    let value_wide = wide_with_nul(value);
    let mut sid = std::ptr::null_mut();
    if unsafe { ConvertStringSidToSidW(value_wide.as_ptr(), &mut sid) } == 0 {
        return Err(NativeSetupFailure::new(
            SetupStage::AccountRights,
            SetupFailureCode::InvalidOwnerSid,
            Some(unsafe { windows_sys::Win32::Foundation::GetLastError() }),
            format!("failed to parse sandbox account SID {value:?}"),
        ));
    }
    Ok(LocalSid(sid))
}

#[allow(unsafe_code)]
fn verify_rights(
    policy: &PolicyHandle,
    sid: &LocalSid,
    account_sid: &str,
) -> NativeSetupResult<()> {
    let mut values = std::ptr::null_mut();
    let mut count = 0u32;
    let status = unsafe { LsaEnumerateAccountRights(policy.0, sid.0, &mut values, &mut count) };
    if status != 0 {
        return Err(lsa_failure(
            SetupFailureCode::BatchLogonRight,
            status,
            format!("failed to read back sandbox logon rights for {account_sid}"),
        ));
    }
    let values = LsaMemory(values);
    let actual = unsafe { std::slice::from_raw_parts(values.0, count as usize) }
        .iter()
        .map(lsa_string_to_owned)
        .collect::<NativeSetupResult<Vec<_>>>()?;
    for required in REQUIRED_RIGHTS {
        if !actual
            .iter()
            .any(|value| value.eq_ignore_ascii_case(required))
        {
            return Err(NativeSetupFailure::new(
                SetupStage::AccountRights,
                SetupFailureCode::BatchLogonRight,
                None,
                format!("sandbox account {account_sid} is missing required right {required}"),
            ));
        }
    }
    for removed in REMOVED_RIGHTS {
        if actual
            .iter()
            .any(|value| value.eq_ignore_ascii_case(removed))
        {
            return Err(NativeSetupFailure::new(
                SetupStage::AccountRights,
                SetupFailureCode::BatchLogonRight,
                None,
                format!("sandbox account {account_sid} retains obsolete right {removed}"),
            ));
        }
    }
    Ok(())
}

fn lsa_string(value: &mut [u16]) -> NativeSetupResult<LSA_UNICODE_STRING> {
    let byte_length = value.len().checked_mul(size_of::<u16>()).ok_or_else(|| {
        NativeSetupFailure::new(
            SetupStage::AccountRights,
            SetupFailureCode::BatchLogonRight,
            None,
            "Windows account-right name length overflow",
        )
    })?;
    let length = u16::try_from(byte_length).map_err(|_| {
        NativeSetupFailure::new(
            SetupStage::AccountRights,
            SetupFailureCode::BatchLogonRight,
            None,
            "Windows account-right name exceeds LSA limits",
        )
    })?;
    Ok(LSA_UNICODE_STRING {
        Length: length,
        MaximumLength: length,
        Buffer: value.as_mut_ptr(),
    })
}

#[allow(unsafe_code)]
fn lsa_string_to_owned(value: &LSA_UNICODE_STRING) -> NativeSetupResult<String> {
    if !value.Length.is_multiple_of(2) || (value.Length != 0 && value.Buffer.is_null()) {
        return Err(NativeSetupFailure::new(
            SetupStage::AccountRights,
            SetupFailureCode::BatchLogonRight,
            None,
            "Windows returned a malformed account-right name",
        ));
    }
    let units = usize::from(value.Length / 2);
    let slice = if units == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(value.Buffer, units) }
    };
    String::from_utf16(slice).map_err(|error| {
        NativeSetupFailure::new(
            SetupStage::AccountRights,
            SetupFailureCode::BatchLogonRight,
            None,
            format!("Windows returned a non-UTF-16 account-right name: {error}"),
        )
    })
}

#[allow(unsafe_code)]
fn lsa_failure(
    code: SetupFailureCode,
    status: i32,
    detail: impl Into<String>,
) -> NativeSetupFailure {
    NativeSetupFailure::new(
        SetupStage::AccountRights,
        code,
        Some(unsafe { LsaNtStatusToWinError(status) }),
        detail,
    )
}

fn wide_without_nul(value: &str) -> Vec<u16> {
    value.encode_utf16().collect()
}

fn wide_with_nul(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}
