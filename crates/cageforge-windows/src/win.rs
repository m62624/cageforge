// SPDX-License-Identifier: Apache-2.0

//! Focused owned wrappers around Windows identity and known-folder APIs.

use std::ffi::c_void;
use std::io;
use std::mem::{align_of, offset_of, size_of};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};

use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_DATA, GetLastError};
use windows_sys::Win32::NetworkManagement::NetManagement::{
    LG_INCLUDE_INDIRECT, LOCALGROUP_USERS_INFO_0, MAX_PREFERRED_LENGTH, NERR_Success,
    NetApiBufferFree, NetUserGetInfo, NetUserGetLocalGroups, UF_ACCOUNTDISABLE, UF_LOCKOUT,
    USER_INFO_1, USER_PRIV_USER,
};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{
    GetTokenInformation, LookupAccountNameW, SID_NAME_USE, TOKEN_ELEVATION, TOKEN_QUERY,
    TOKEN_USER, TokenElevation, TokenUser,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::Win32::UI::Shell::{SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

use crate::account_groups::{is_allowed_sandbox_group_sid, is_privileged_group_sid};
use crate::error::{WindowsAccountLookupError, WindowsAccountVerificationError};
pub(crate) use crate::native_strings::wide as to_wide;
use crate::native_strings::{local_sid_string, wide_path};
use crate::net_api_strings::{
    net_api_array_len, net_api_buffer_size, net_api_struct_fits, net_api_wide_string,
};

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
pub(crate) fn current_process_is_elevated() -> io::Result<bool> {
    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = unsafe { OwnedHandle::from_raw_handle(token as RawHandle) };
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut returned = 0u32;
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle() as _,
            TokenElevation,
            (&raw mut elevation).cast(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if returned < size_of::<TOKEN_ELEVATION>() as u32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows returned a truncated token-elevation record",
        ));
    }
    Ok(elevation.TokenIsElevated != 0)
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
    if let Some(group_sid) = group_sids.iter().find(|sid| is_privileged_group_sid(sid)) {
        return Err(WindowsAccountVerificationError::PrivilegedGroupMembership {
            account: account_name.to_string(),
            group_sid: group_sid.clone(),
        });
    }
    if let Some(group_sid) = group_sids
        .iter()
        .find(|sid| !is_allowed_sandbox_group_sid(sid, &required_group_sid))
    {
        return Err(WindowsAccountVerificationError::UnexpectedGroupMembership {
            account: account_name.to_string(),
            group_sid: group_sid.clone(),
        });
    }
    Ok(())
}

#[allow(unsafe_code)]
pub(crate) fn run_elevated(executable: &std::path::Path, arguments: &[String]) -> io::Result<u32> {
    use windows_sys::Win32::Foundation::{WAIT_FAILED, WAIT_OBJECT_0};
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, INFINITE, WaitForSingleObject,
    };

    let verb = to_wide("runas");
    let executable = wide_path(executable);
    let parameters = to_wide(
        &arguments
            .iter()
            .map(|value| quote_argument(value))
            .collect::<Vec<_>>()
            .join(" "),
    );
    let mut execute = SHELLEXECUTEINFOW {
        cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        hwnd: std::ptr::null_mut(),
        lpVerb: verb.as_ptr(),
        lpFile: executable.as_ptr(),
        lpParameters: parameters.as_ptr(),
        lpDirectory: std::ptr::null(),
        nShow: SW_SHOWNORMAL,
        hInstApp: std::ptr::null_mut(),
        lpIDList: std::ptr::null_mut(),
        lpClass: std::ptr::null(),
        hkeyClass: std::ptr::null_mut(),
        dwHotKey: 0,
        Anonymous: Default::default(),
        hProcess: std::ptr::null_mut(),
    };
    if unsafe { ShellExecuteExW(&mut execute) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if execute.hProcess.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "elevated setup returned no process handle",
        ));
    }
    let process = unsafe { OwnedHandle::from_raw_handle(execute.hProcess as RawHandle) };
    let wait = unsafe { WaitForSingleObject(process.as_raw_handle() as _, INFINITE) };
    if wait == WAIT_FAILED {
        return Err(io::Error::last_os_error());
    }
    if wait != WAIT_OBJECT_0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected elevated setup wait result {wait:#x}"),
        ));
    }
    let mut exit_code = 0u32;
    if unsafe { GetExitCodeProcess(process.as_raw_handle() as _, &mut exit_code) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(exit_code)
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
    let allocation_bytes = net_api_buffer_size(buffer.0).map_err(|code| {
        WindowsAccountVerificationError::UserRecordRead {
            account: account_name.to_string(),
            code,
        }
    })?;
    if !net_api_struct_fits::<USER_INFO_1>(buffer.0, allocation_bytes) {
        return Err(WindowsAccountVerificationError::UserRecordRead {
            account: account_name.to_string(),
            code: ERROR_INVALID_DATA,
        });
    }
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
    let allocation_bytes = net_api_buffer_size(buffer.0).map_err(|code| {
        WindowsAccountVerificationError::GroupEnumeration {
            account: account_name.to_string(),
            code,
        }
    })?;
    let entry_count = net_api_array_len::<LOCALGROUP_USERS_INFO_0>(allocation_bytes, entries_read)
        .ok_or_else(|| WindowsAccountVerificationError::GroupEnumeration {
            account: account_name.to_string(),
            code: ERROR_INVALID_DATA,
        })?;
    if !(buffer.0 as usize).is_multiple_of(align_of::<LOCALGROUP_USERS_INFO_0>()) {
        return Err(WindowsAccountVerificationError::GroupEnumeration {
            account: account_name.to_string(),
            code: ERROR_INVALID_DATA,
        });
    }
    let entries = unsafe {
        std::slice::from_raw_parts(buffer.0.cast::<LOCALGROUP_USERS_INFO_0>(), entry_count)
    };
    let mut sids = Vec::with_capacity(entries.len());
    for entry in entries {
        let group_name = net_api_wide_string(buffer.0, entry.lgrui0_name)
            .map_err(|code| WindowsAccountVerificationError::GroupEnumeration {
                account: account_name.to_string(),
                code,
            })?
            .ok_or_else(|| WindowsAccountVerificationError::InvalidGroupEntry {
                account: account_name.to_string(),
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
    local_sid_string(value).ok_or(ERROR_INVALID_DATA)
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

pub(crate) fn quote_argument(value: &str) -> String {
    let mut quoted = String::from('"');
    let mut backslashes = 0usize;
    for character in value.chars() {
        if character == '\\' {
            backslashes += 1;
        } else if character == '"' {
            quoted.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
            quoted.push('"');
            backslashes = 0;
        } else {
            quoted.extend(std::iter::repeat_n('\\', backslashes));
            quoted.push(character);
            backslashes = 0;
        }
    }
    quoted.extend(std::iter::repeat_n('\\', backslashes * 2));
    quoted.push('"');
    quoted
}
