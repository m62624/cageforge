// SPDX-License-Identifier: Apache-2.0

//! Focused owned wrappers around Windows identity and known-folder APIs.

use std::ffi::{OsString, c_void};
use std::io;
use std::mem::{offset_of, size_of};
use std::os::windows::ffi::OsStringExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::path::PathBuf;

use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, GetLastError, HLOCAL, LocalFree};
use windows_sys::Win32::NetworkManagement::NetManagement::{
    LG_INCLUDE_INDIRECT, LOCALGROUP_USERS_INFO_0, MAX_PREFERRED_LENGTH, NERR_Success,
    NetApiBufferFree, NetUserGetInfo, NetUserGetLocalGroups, UF_ACCOUNTDISABLE, UF_LOCKOUT,
    USER_INFO_1, USER_PRIV_USER,
};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{
    GetTokenInformation, LookupAccountNameW, SID_NAME_USE, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::Win32::UI::Shell::{FOLDERID_ProgramData, KF_FLAG_DEFAULT, SHGetKnownFolderPath};

use crate::error::{WindowsAccountLookupError, WindowsAccountVerificationError};

struct NetApiBuffer(*mut u8);

#[allow(unsafe_code)]
impl Drop for NetApiBuffer {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                NetApiBufferFree(self.0.cast());
            }
        }
    }
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
    if result < 0 {
        return Err(result);
    }
    if value.is_null() {
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

#[allow(unsafe_code)]
pub(crate) fn current_user_sid() -> io::Result<String> {
    let mut token = std::ptr::null_mut();
    let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
    if opened == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = unsafe { OwnedHandle::from_raw_handle(token as RawHandle) };

    let mut byte_length = 0u32;
    let queried = unsafe {
        GetTokenInformation(
            token.as_raw_handle() as _,
            TokenUser,
            std::ptr::null_mut(),
            0,
            &mut byte_length,
        )
    };
    if queried != 0 || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
        return Err(io::Error::last_os_error());
    }
    let mut buffer = aligned_buffer(byte_length as usize)?;
    let queried = unsafe {
        GetTokenInformation(
            token.as_raw_handle() as _,
            TokenUser,
            buffer.as_mut_ptr().cast::<c_void>(),
            byte_length,
            &mut byte_length,
        )
    };
    if queried == 0 {
        return Err(io::Error::last_os_error());
    }
    let token_user = parse_token_user(&buffer, byte_length as usize)?;
    sid_to_string(token_user.User.Sid).map_err(|code| io::Error::from_raw_os_error(code as i32))
}

#[allow(unsafe_code)]
pub(crate) fn account_sid(account_name: &str) -> Result<String, WindowsAccountLookupError> {
    let name = to_wide(account_name);
    let mut sid_length = 0u32;
    let mut domain_length = 0u32;
    let mut use_type: SID_NAME_USE = 0;
    let queried = unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            name.as_ptr(),
            std::ptr::null_mut(),
            &mut sid_length,
            std::ptr::null_mut(),
            &mut domain_length,
            &mut use_type,
        )
    };
    if queried != 0 || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
        return Err(WindowsAccountLookupError::SidSizeQuery {
            account: account_name.to_string(),
            code: unsafe { GetLastError() },
        });
    }
    let mut sid = vec![0u8; sid_length as usize];
    let mut domain = vec![0u16; domain_length as usize];
    let queried = unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            name.as_ptr(),
            sid.as_mut_ptr().cast(),
            &mut sid_length,
            domain.as_mut_ptr(),
            &mut domain_length,
            &mut use_type,
        )
    };
    if queried == 0 {
        return Err(WindowsAccountLookupError::SidRead {
            account: account_name.to_string(),
            code: unsafe { GetLastError() },
        });
    }
    sid_to_string(sid.as_mut_ptr().cast()).map_err(|code| WindowsAccountLookupError::SidFormat {
        account: account_name.to_string(),
        code,
    })
}

pub(crate) fn verify_sandbox_account(
    account_name: &str,
    required_group_name: &str,
) -> Result<(), WindowsAccountVerificationError> {
    verify_regular_enabled_user(account_name)?;
    let group_sids = user_local_group_sids(account_name)?;
    let required_group_sid = account_sid(required_group_name).map_err(|source| {
        WindowsAccountVerificationError::GroupSidLookup {
            account: account_name.to_string(),
            group: required_group_name.to_string(),
            source,
        }
    })?;
    if !group_sids
        .iter()
        .any(|sid| sid.eq_ignore_ascii_case(&required_group_sid))
    {
        return Err(WindowsAccountVerificationError::MissingManagedGroup {
            account: account_name.to_string(),
            group: required_group_name.to_string(),
        });
    }
    if group_sids
        .iter()
        .any(|sid| sid.eq_ignore_ascii_case("S-1-5-32-544"))
    {
        return Err(WindowsAccountVerificationError::AdministratorMembership {
            account: account_name.to_string(),
        });
    }
    Ok(())
}

#[allow(unsafe_code)]
fn verify_regular_enabled_user(account_name: &str) -> Result<(), WindowsAccountVerificationError> {
    let name = to_wide(account_name);
    let mut buffer = std::ptr::null_mut();
    let status = unsafe { NetUserGetInfo(std::ptr::null(), name.as_ptr(), 1, &mut buffer) };
    if status != NERR_Success {
        return Err(WindowsAccountVerificationError::UserRecordRead {
            account: account_name.to_string(),
            code: status,
        });
    }
    let buffer = NetApiBuffer(buffer);
    let info = unsafe { &*buffer.0.cast::<USER_INFO_1>() };
    if info.usri1_priv != USER_PRIV_USER {
        return Err(WindowsAccountVerificationError::NotRegularUser {
            account: account_name.to_string(),
            actual: info.usri1_priv,
        });
    }
    if info.usri1_flags & UF_ACCOUNTDISABLE != 0 {
        return Err(WindowsAccountVerificationError::Disabled {
            account: account_name.to_string(),
        });
    }
    if info.usri1_flags & UF_LOCKOUT != 0 {
        return Err(WindowsAccountVerificationError::Locked {
            account: account_name.to_string(),
        });
    }
    Ok(())
}

#[allow(unsafe_code)]
fn user_local_group_sids(
    account_name: &str,
) -> Result<Vec<String>, WindowsAccountVerificationError> {
    let name = to_wide(account_name);
    let mut buffer = std::ptr::null_mut();
    let mut entries_read = 0u32;
    let mut total_entries = 0u32;
    let status = unsafe {
        NetUserGetLocalGroups(
            std::ptr::null(),
            name.as_ptr(),
            0,
            LG_INCLUDE_INDIRECT,
            &mut buffer,
            MAX_PREFERRED_LENGTH,
            &mut entries_read,
            &mut total_entries,
        )
    };
    if status != NERR_Success {
        return Err(WindowsAccountVerificationError::GroupEnumeration {
            account: account_name.to_string(),
            code: status,
        });
    }
    let buffer = NetApiBuffer(buffer);
    if entries_read == 0 {
        return Ok(Vec::new());
    }
    let entries = unsafe {
        std::slice::from_raw_parts(
            buffer.0.cast::<LOCALGROUP_USERS_INFO_0>(),
            entries_read as usize,
        )
    };
    let mut sids = Vec::with_capacity(entries.len());
    for entry in entries {
        let group_name = wide_ptr_to_string(entry.lgrui0_name).ok_or_else(|| {
            WindowsAccountVerificationError::InvalidGroupEntry {
                account: account_name.to_string(),
            }
        })?;
        let sid = account_sid(&group_name).map_err(|source| {
            WindowsAccountVerificationError::GroupSidLookup {
                account: account_name.to_string(),
                group: group_name.clone(),
                source,
            }
        })?;
        sids.push(sid);
    }
    Ok(sids)
}

#[allow(unsafe_code)]
fn parse_token_user(buffer: &[usize], byte_length: usize) -> io::Result<TOKEN_USER> {
    if byte_length > size_of_val(buffer)
        || byte_length
            < offset_of!(TOKEN_USER, User)
                + size_of::<windows_sys::Win32::Security::SID_AND_ATTRIBUTES>()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid Windows token-user buffer length",
        ));
    }
    Ok(unsafe { std::ptr::read_unaligned(buffer.as_ptr().cast::<TOKEN_USER>()) })
}

#[allow(unsafe_code)]
fn sid_to_string(sid: *mut c_void) -> Result<String, u32> {
    let mut value = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut value) } == 0 {
        return Err(unsafe { GetLastError() });
    }
    let string = unsafe {
        let mut length = 0usize;
        while *value.add(length) != 0 {
            length += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(value, length))
    };
    unsafe {
        LocalFree(value as HLOCAL);
    }
    Ok(string)
}

fn aligned_buffer(byte_length: usize) -> io::Result<Vec<usize>> {
    if byte_length == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows API returned an empty buffer length",
        ));
    }
    Ok(vec![0; byte_length.div_ceil(size_of::<usize>())])
}

#[allow(unsafe_code)]
fn wide_ptr_to_string(value: *const u16) -> Option<String> {
    if value.is_null() {
        return None;
    }
    let value = unsafe {
        let mut length = 0usize;
        while *value.add(length) != 0 {
            length += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(value, length))
    };
    Some(value)
}

fn to_wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}
