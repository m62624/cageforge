// SPDX-License-Identifier: Apache-2.0

use std::ffi::c_void;
use std::mem::align_of;

use getrandom::fill;
use windows_sys::Win32::Foundation::{
    ERROR_ALIAS_EXISTS, ERROR_INSUFFICIENT_BUFFER, ERROR_MEMBER_IN_ALIAS, GetLastError, HLOCAL,
    LocalFree,
};
use windows_sys::Win32::NetworkManagement::NetManagement::{
    LG_INCLUDE_INDIRECT, LOCALGROUP_INFO_1, LOCALGROUP_MEMBERS_INFO_3, LOCALGROUP_USERS_INFO_0,
    MAX_PREFERRED_LENGTH, NERR_GroupExists, NERR_GroupNotFound, NERR_Success, NERR_UserExists,
    NERR_UserNotFound, NetApiBufferFree, NetLocalGroupAdd, NetLocalGroupAddMembers,
    NetLocalGroupDel, NetUserAdd, NetUserDel, NetUserGetInfo, NetUserGetLocalGroups,
    NetUserSetInfo, UF_ACCOUNTDISABLE, UF_DONT_EXPIRE_PASSWD, UF_LOCKOUT, UF_NORMAL_ACCOUNT,
    UF_SCRIPT, USER_INFO_1, USER_INFO_1003, USER_INFO_1008, USER_PRIV_USER,
};
use windows_sys::Win32::Security::Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidW};
use windows_sys::Win32::Security::{LookupAccountNameW, LookupAccountSidW, SID_NAME_USE};
use zeroize::Zeroizing;

use crate::account_groups::{
    BUILTIN_USERS_SID, is_allowed_sandbox_group_sid, is_privileged_group_sid,
};
use crate::account_identity::ManagedAccountNames;
use crate::setup_protocol::{SetupFailureCode, SetupRequest, SetupStage};

use crate::native_strings::local_sid_string;
use crate::net_api_strings::{
    net_api_array_len, net_api_buffer_size, net_api_struct_fits, net_api_wide_string,
};

use super::{NativeSetupFailure, NativeSetupResult, ProvisionedAccounts};

const MANAGED_GROUP_COMMENT: &str = "Cageforge Windows sandbox identities (managed)";

struct NetApiBuffer(*mut u8);

struct LocalSid(*mut c_void);

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
impl Drop for LocalSid {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0 as HLOCAL);
            }
        }
    }
}

pub(super) fn provision(request: &SetupRequest) -> NativeSetupResult<ProvisionedAccounts> {
    let names = ManagedAccountNames::for_owner(&request.owner_sid);
    ensure_group(&names.group)?;

    let offline_password = random_password(SetupStage::OfflineAccount)?;
    let online_password = random_password(SetupStage::OnlineAccount)?;
    ensure_user(
        &names.offline,
        &offline_password,
        SetupStage::OfflineAccount,
    )?;
    ensure_user(&names.online, &online_password, SetupStage::OnlineAccount)?;
    ensure_member(&names.group, &names.offline, SetupStage::OfflineAccount)?;
    ensure_member(&names.group, &names.online, SetupStage::OnlineAccount)?;
    let users_group = account_name_for_sid(BUILTIN_USERS_SID)?;
    ensure_member(&users_group, &names.offline, SetupStage::OfflineAccount)?;
    ensure_member(&users_group, &names.online, SetupStage::OnlineAccount)?;

    let offline_sid = account_sid(&names.offline, SetupStage::OfflineAccount)?;
    let online_sid = account_sid(&names.online, SetupStage::OnlineAccount)?;
    let group_sid = account_sid(&names.group, SetupStage::ManagedGroup)?;
    verify_account(&names.offline, &group_sid, SetupStage::OfflineAccount)?;
    verify_account(&names.online, &group_sid, SetupStage::OnlineAccount)?;
    Ok(ProvisionedAccounts {
        offline_sid,
        online_sid,
        group_sid,
        offline_name: names.offline,
        offline_password,
        online_name: names.online,
        online_password,
        group_name: names.group,
    })
}

#[allow(unsafe_code)]
pub(super) fn remove(request: &SetupRequest) -> NativeSetupResult<()> {
    let names = ManagedAccountNames::for_owner(&request.owner_sid);
    for account in [&names.offline, &names.online] {
        let account_wide = wide(account);
        let status = unsafe { NetUserDel(std::ptr::null(), account_wide.as_ptr()) };
        if status != NERR_Success && status != NERR_UserNotFound {
            return Err(NativeSetupFailure::new(
                SetupStage::Uninstall,
                SetupFailureCode::Cleanup,
                Some(status),
                format!("failed to remove sandbox user {account:?}"),
            ));
        }
    }
    let group_wide = wide(&names.group);
    let status = unsafe { NetLocalGroupDel(std::ptr::null(), group_wide.as_ptr()) };
    if status != NERR_Success && status != NERR_GroupNotFound {
        return Err(NativeSetupFailure::new(
            SetupStage::Uninstall,
            SetupFailureCode::Cleanup,
            Some(status),
            format!("failed to remove managed group {:?}", names.group),
        ));
    }
    Ok(())
}

#[allow(unsafe_code)]
fn verify_account(
    account: &str,
    managed_group_sid: &str,
    stage: SetupStage,
) -> NativeSetupResult<()> {
    let account_wide = wide(account);
    let mut user_buffer = std::ptr::null_mut();
    let status =
        unsafe { NetUserGetInfo(std::ptr::null(), account_wide.as_ptr(), 1, &mut user_buffer) };
    if status != NERR_Success {
        return Err(NativeSetupFailure::new(
            stage,
            SetupFailureCode::UserUpdate,
            Some(status),
            format!("failed to read back sandbox user {account:?}"),
        ));
    }
    let user_buffer = NetApiBuffer(user_buffer);
    let allocation_bytes = net_api_buffer_size(user_buffer.0).map_err(|code| {
        NativeSetupFailure::new(
            stage,
            SetupFailureCode::UserUpdate,
            Some(code),
            format!("failed to determine the NetAPI user allocation for sandbox user {account:?}"),
        )
    })?;
    if !net_api_struct_fits::<USER_INFO_1>(user_buffer.0, allocation_bytes) {
        return Err(NativeSetupFailure::new(
            stage,
            SetupFailureCode::UserUpdate,
            None,
            format!("Windows returned a truncated user record for sandbox user {account:?}"),
        ));
    }
    let info = unsafe { &*user_buffer.0.cast::<USER_INFO_1>() };
    if info.usri1_priv != USER_PRIV_USER {
        return Err(NativeSetupFailure::new(
            stage,
            SetupFailureCode::UserNotRegular,
            None,
            format!(
                "sandbox user {account:?} has privilege class {}, expected {USER_PRIV_USER}",
                info.usri1_priv
            ),
        ));
    }
    if info.usri1_flags & UF_ACCOUNTDISABLE != 0 {
        return Err(NativeSetupFailure::new(
            stage,
            SetupFailureCode::UserDisabled,
            None,
            format!("sandbox user {account:?} remains disabled"),
        ));
    }
    if info.usri1_flags & UF_LOCKOUT != 0 {
        return Err(NativeSetupFailure::new(
            stage,
            SetupFailureCode::UserLocked,
            None,
            format!("sandbox user {account:?} remains locked"),
        ));
    }

    let mut group_buffer = std::ptr::null_mut();
    let mut entries = 0u32;
    let mut total = 0u32;
    let status = unsafe {
        NetUserGetLocalGroups(
            std::ptr::null(),
            account_wide.as_ptr(),
            0,
            LG_INCLUDE_INDIRECT,
            &mut group_buffer,
            MAX_PREFERRED_LENGTH,
            &mut entries,
            &mut total,
        )
    };
    if status != NERR_Success {
        return Err(NativeSetupFailure::new(
            stage,
            SetupFailureCode::GroupMembership,
            Some(status),
            format!("failed to read back local groups for sandbox user {account:?}"),
        ));
    }
    let group_buffer = NetApiBuffer(group_buffer);
    let allocation_bytes = net_api_buffer_size(group_buffer.0).map_err(|code| {
        NativeSetupFailure::new(
            stage,
            SetupFailureCode::GroupMembership,
            Some(code),
            format!("failed to determine the NetAPI group allocation for sandbox user {account:?}"),
        )
    })?;
    let entry_count = net_api_array_len::<LOCALGROUP_USERS_INFO_0>(allocation_bytes, entries)
        .ok_or_else(|| {
            NativeSetupFailure::new(
                stage,
                SetupFailureCode::GroupMembership,
                None,
                format!(
                    "Windows returned a truncated local-group array for sandbox user {account:?}"
                ),
            )
        })?;
    if !(group_buffer.0 as usize).is_multiple_of(align_of::<LOCALGROUP_USERS_INFO_0>()) {
        return Err(NativeSetupFailure::new(
            stage,
            SetupFailureCode::GroupMembership,
            None,
            format!("Windows returned an unaligned local-group array for sandbox user {account:?}"),
        ));
    }
    let groups = unsafe {
        std::slice::from_raw_parts(
            group_buffer.0.cast::<LOCALGROUP_USERS_INFO_0>(),
            entry_count,
        )
    };
    let mut found_managed = false;
    for group in groups {
        let name = net_api_wide_string(group_buffer.0, group.lgrui0_name)
            .map_err(|code| {
                NativeSetupFailure::new(
                    stage,
                    SetupFailureCode::GroupMembership,
                    Some(code),
                    format!(
                        "failed to determine the NetAPI group-name buffer size for sandbox user {account:?}"
                    ),
                )
            })?
            .ok_or_else(|| {
                NativeSetupFailure::new(
                    stage,
                    SetupFailureCode::GroupMembership,
                    None,
                    format!("Windows returned an invalid group name for sandbox user {account:?}"),
                )
            })?;
        let sid = account_sid(&name, stage)?;
        found_managed |= sid.eq_ignore_ascii_case(managed_group_sid);
        if is_privileged_group_sid(&sid) {
            return Err(NativeSetupFailure::new(
                stage,
                SetupFailureCode::GroupMembership,
                None,
                format!("sandbox user {account:?} belongs to privileged local group {sid}"),
            ));
        }
        if !is_allowed_sandbox_group_sid(&sid, managed_group_sid) {
            return Err(NativeSetupFailure::new(
                stage,
                SetupFailureCode::GroupMembership,
                None,
                format!("sandbox user {account:?} has unexpected local group {sid}"),
            ));
        }
    }
    if !found_managed {
        return Err(NativeSetupFailure::new(
            stage,
            SetupFailureCode::GroupMembership,
            None,
            format!("sandbox user {account:?} is missing the managed group"),
        ));
    }
    Ok(())
}

#[allow(unsafe_code)]
fn ensure_group(name: &str) -> NativeSetupResult<()> {
    let name_wide = wide(name);
    let comment_wide = wide(MANAGED_GROUP_COMMENT);
    let mut parameter_error = 0u32;
    let info = LOCALGROUP_INFO_1 {
        lgrpi1_name: name_wide.as_ptr().cast_mut(),
        lgrpi1_comment: comment_wide.as_ptr().cast_mut(),
    };
    let status = unsafe {
        NetLocalGroupAdd(
            std::ptr::null(),
            1,
            (&raw const info).cast::<u8>().cast_mut(),
            &mut parameter_error,
        )
    };
    if status == NERR_Success || status == ERROR_ALIAS_EXISTS || status == NERR_GroupExists {
        return Ok(());
    }
    Err(NativeSetupFailure::new(
        SetupStage::ManagedGroup,
        SetupFailureCode::GroupCreate,
        Some(status),
        format!("failed to create managed local group {name:?}; parameter {parameter_error}"),
    ))
}

#[allow(unsafe_code)]
fn ensure_user(name: &str, password: &str, stage: SetupStage) -> NativeSetupResult<()> {
    let name_wide = wide(name);
    let password_wide = Zeroizing::new(wide(password));
    let info = USER_INFO_1 {
        usri1_name: name_wide.as_ptr().cast_mut(),
        usri1_password: password_wide.as_ptr().cast_mut(),
        usri1_password_age: 0,
        usri1_priv: USER_PRIV_USER,
        usri1_home_dir: std::ptr::null_mut(),
        usri1_comment: std::ptr::null_mut(),
        usri1_flags: UF_SCRIPT | UF_DONT_EXPIRE_PASSWD | UF_NORMAL_ACCOUNT,
        usri1_script_path: std::ptr::null_mut(),
    };
    let mut parameter_error = 0u32;
    let status = unsafe {
        NetUserAdd(
            std::ptr::null(),
            1,
            (&raw const info).cast::<u8>().cast_mut(),
            &mut parameter_error,
        )
    };
    if status != NERR_Success && status != NERR_UserExists {
        return Err(NativeSetupFailure::new(
            stage,
            SetupFailureCode::UserCreate,
            Some(status),
            format!("failed to create local sandbox user {name:?}; parameter {parameter_error}"),
        ));
    }

    if status == NERR_UserExists {
        let password_info = USER_INFO_1003 {
            usri1003_password: password_wide.as_ptr().cast_mut(),
        };
        set_user_info(name, &name_wide, 1003, &raw const password_info, stage)?;
    }
    let flags_info = USER_INFO_1008 {
        usri1008_flags: UF_SCRIPT | UF_DONT_EXPIRE_PASSWD | UF_NORMAL_ACCOUNT,
    };
    set_user_info(name, &name_wide, 1008, &raw const flags_info, stage)
}

#[allow(unsafe_code)]
fn set_user_info<T>(
    name: &str,
    name_wide: &[u16],
    level: u32,
    info: *const T,
    stage: SetupStage,
) -> NativeSetupResult<()> {
    let mut parameter_error = 0u32;
    let status = unsafe {
        NetUserSetInfo(
            std::ptr::null(),
            name_wide.as_ptr(),
            level,
            info.cast::<u8>().cast_mut(),
            &mut parameter_error,
        )
    };
    if status == NERR_Success {
        return Ok(());
    }
    Err(NativeSetupFailure::new(
        stage,
        SetupFailureCode::UserUpdate,
        Some(status),
        format!(
            "failed to update local sandbox user {name:?} at level {level}; parameter {parameter_error}"
        ),
    ))
}

#[allow(unsafe_code)]
fn ensure_member(group: &str, account: &str, stage: SetupStage) -> NativeSetupResult<()> {
    let group_wide = wide(group);
    let account_wide = wide(account);
    let member = LOCALGROUP_MEMBERS_INFO_3 {
        lgrmi3_domainandname: account_wide.as_ptr().cast_mut(),
    };
    let status = unsafe {
        NetLocalGroupAddMembers(
            std::ptr::null(),
            group_wide.as_ptr(),
            3,
            (&raw const member).cast::<u8>().cast_mut(),
            1,
        )
    };
    if status == NERR_Success || status == ERROR_MEMBER_IN_ALIAS {
        return Ok(());
    }
    Err(NativeSetupFailure::new(
        stage,
        SetupFailureCode::GroupMembership,
        Some(status),
        format!("failed to add sandbox user {account:?} to managed group {group:?}"),
    ))
}

fn random_password(stage: SetupStage) -> NativeSetupResult<Zeroizing<String>> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    fill(bytes.as_mut()).map_err(|error| {
        NativeSetupFailure::new(
            stage,
            SetupFailureCode::RandomCredential,
            error.raw_os_error().map(|code| code as u32),
            format!("cryptographic password generation failed: {error}"),
        )
    })?;
    let random_hex = Zeroizing::new(
        bytes
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<String>(),
    );
    // Preserve 256 bits of operating-system entropy while constructively
    // satisfying the built-in Windows upper/lower/digit/symbol policy. Pure
    // hexadecimal is long but has only two character classes and is rejected
    // by Windows Server 2025 as NERR_PasswordTooShort.
    Ok(Zeroizing::new(format!("A!a0{}", random_hex.as_str())))
}

#[allow(unsafe_code)]
fn account_sid(account: &str, stage: SetupStage) -> NativeSetupResult<String> {
    let account_wide = wide(account);
    let mut sid_length = 0u32;
    let mut domain_length = 0u32;
    let mut sid_type: SID_NAME_USE = 0;
    let initial = unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            account_wide.as_ptr(),
            std::ptr::null_mut(),
            &mut sid_length,
            std::ptr::null_mut(),
            &mut domain_length,
            &mut sid_type,
        )
    };
    let initial_error = unsafe { GetLastError() };
    if initial != 0 || initial_error != ERROR_INSUFFICIENT_BUFFER {
        return Err(NativeSetupFailure::new(
            stage,
            SetupFailureCode::UserUpdate,
            Some(initial_error),
            format!("failed to query SID size for {account:?}"),
        ));
    }
    let mut sid = vec![0u8; sid_length as usize];
    let mut domain = vec![0u16; domain_length as usize];
    let resolved = unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            account_wide.as_ptr(),
            sid.as_mut_ptr().cast(),
            &mut sid_length,
            domain.as_mut_ptr(),
            &mut domain_length,
            &mut sid_type,
        )
    };
    if resolved == 0 {
        return Err(NativeSetupFailure::new(
            stage,
            SetupFailureCode::UserUpdate,
            Some(unsafe { GetLastError() }),
            format!("failed to resolve SID for {account:?}"),
        ));
    }
    sid_to_string(sid.as_mut_ptr().cast(), stage)
}

#[allow(unsafe_code)]
fn account_name_for_sid(sid: &str) -> NativeSetupResult<String> {
    let sid_wide = wide(sid);
    let mut parsed_sid = std::ptr::null_mut();
    if unsafe { ConvertStringSidToSidW(sid_wide.as_ptr(), &mut parsed_sid) } == 0 {
        return Err(NativeSetupFailure::new(
            SetupStage::ManagedGroup,
            SetupFailureCode::GroupMembership,
            Some(unsafe { GetLastError() }),
            format!("failed to parse required built-in group SID {sid}"),
        ));
    }
    let parsed_sid = LocalSid(parsed_sid);
    let mut name_length = 0u32;
    let mut domain_length = 0u32;
    let mut sid_type: SID_NAME_USE = 0;
    let initial = unsafe {
        LookupAccountSidW(
            std::ptr::null(),
            parsed_sid.0,
            std::ptr::null_mut(),
            &mut name_length,
            std::ptr::null_mut(),
            &mut domain_length,
            &mut sid_type,
        )
    };
    let initial_error = unsafe { GetLastError() };
    if initial != 0 || initial_error != ERROR_INSUFFICIENT_BUFFER {
        return Err(NativeSetupFailure::new(
            SetupStage::ManagedGroup,
            SetupFailureCode::GroupMembership,
            Some(initial_error),
            format!("failed to query the localized name for built-in group SID {sid}"),
        ));
    }
    let mut name = vec![0u16; name_length as usize];
    let mut domain = vec![0u16; domain_length as usize];
    if unsafe {
        LookupAccountSidW(
            std::ptr::null(),
            parsed_sid.0,
            name.as_mut_ptr(),
            &mut name_length,
            domain.as_mut_ptr(),
            &mut domain_length,
            &mut sid_type,
        )
    } == 0
    {
        return Err(NativeSetupFailure::new(
            SetupStage::ManagedGroup,
            SetupFailureCode::GroupMembership,
            Some(unsafe { GetLastError() }),
            format!("failed to resolve the localized name for built-in group SID {sid}"),
        ));
    }
    name.truncate(name_length as usize);
    while name.last() == Some(&0) {
        name.pop();
    }
    String::from_utf16(&name).map_err(|error| {
        NativeSetupFailure::new(
            SetupStage::ManagedGroup,
            SetupFailureCode::GroupMembership,
            None,
            format!("Windows returned an invalid built-in group name for SID {sid}: {error}"),
        )
    })
}

#[allow(unsafe_code)]
fn sid_to_string(sid: *mut c_void, stage: SetupStage) -> NativeSetupResult<String> {
    let mut value = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut value) } == 0 {
        return Err(NativeSetupFailure::new(
            stage,
            SetupFailureCode::UserUpdate,
            Some(unsafe { GetLastError() }),
            "failed to format provisioned account SID",
        ));
    }
    local_sid_string(value).ok_or_else(|| {
        NativeSetupFailure::new(
            stage,
            SetupFailureCode::UserUpdate,
            None,
            "Windows returned an invalid provisioned account SID string",
        )
    })
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::random_password;
    use crate::setup_protocol::SetupStage;

    #[test]
    fn generated_passwords_satisfy_windows_complexity_classes() {
        let first = random_password(SetupStage::OfflineAccount)
            .unwrap_or_else(|_| panic!("first password generation failed"));
        let second = random_password(SetupStage::OnlineAccount)
            .unwrap_or_else(|_| panic!("second password generation failed"));

        assert_ne!(first, second);
        assert!(first.len() >= 64);
        assert!(first.chars().any(char::is_uppercase));
        assert!(first.chars().any(char::is_lowercase));
        assert!(first.chars().any(|character| character.is_ascii_digit()));
        assert!(first.chars().any(|character| !character.is_alphanumeric()));
    }
}
