// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;
use std::ffi::c_void;
use std::mem::{offset_of, size_of};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};

use thiserror::Error;
use windows_sys::Win32::Foundation::{
    ERROR_INSUFFICIENT_BUFFER, ERROR_NOT_ALL_ASSIGNED, ERROR_SUCCESS, GetLastError, HLOCAL,
    LocalFree, SetLastError,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSidToSidW, EXPLICIT_ACCESS_W, GRANT_ACCESS,
    SetEntriesInAclW, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACL, AdjustTokenPrivileges, CreateRestrictedToken, DISABLE_MAX_PRIVILEGE,
    GetAce, GetTokenInformation, IsValidSid, LUA_TOKEN, LookupPrivilegeValueW,
    SE_CHANGE_NOTIFY_NAME, SE_PRIVILEGE_ENABLED, SID_AND_ATTRIBUTES, SetTokenInformation,
    TOKEN_ADJUST_DEFAULT, TOKEN_ADJUST_PRIVILEGES, TOKEN_ADJUST_SESSIONID, TOKEN_ASSIGN_PRIMARY,
    TOKEN_DEFAULT_DACL, TOKEN_DUPLICATE, TOKEN_PRIVILEGES, TOKEN_QUERY, TOKEN_USER,
    TokenDefaultDacl, TokenPrivileges, TokenRestrictedSids, TokenUser, WRITE_RESTRICTED,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::runner_protocol::{WindowsRunnerFailureCode, WindowsRunnerFailureStage};

const GENERIC_ALL: u32 = 0x1000_0000;
const SE_GROUP_LOGON_ID: u32 = 0xc000_0000;
const EVERYONE_SID: &str = "S-1-1-0";

pub(super) struct RestrictedPrimaryToken {
    handle: OwnedHandle,
}

struct LocalSid(*mut c_void);

struct LocalAcl(*mut ACL);

struct TokenBuffer(Vec<u8>);

#[derive(Debug, Error)]
pub(super) enum TokenHardeningError {
    #[error("failed to open the runner process token: Windows error {code}")]
    BaseTokenOpen { code: u32 },
    #[error("failed to read {component} from a Windows token: Windows error {code}")]
    TokenInformation { component: &'static str, code: u32 },
    #[error("Windows returned a truncated {component} token record")]
    TruncatedTokenInformation { component: &'static str },
    #[error("Windows returned an invalid SID in {component}")]
    InvalidTokenSid { component: &'static str },
    #[error("failed to format a SID from {component}: Windows error {code}")]
    TokenSidFormat { component: &'static str, code: u32 },
    #[error("runner token contains no unique logon SID")]
    MissingLogonSid,
    #[error("runner token contains more than one unique logon SID")]
    DuplicateLogonSid,
    #[error("invalid {component} SID declaration: Windows error {code}")]
    SidParse { component: &'static str, code: u32 },
    #[error("duplicate restricting SID after Windows canonicalization")]
    DuplicateRestrictingSid,
    #[error("no capability SID was supplied for a restricted Windows process")]
    MissingCapabilitySid,
    #[error("CreateRestrictedToken failed: Windows error {code}")]
    RestrictedTokenCreate { code: u32 },
    #[error("failed to construct the restricted-token default DACL: Windows error {code}")]
    DefaultDaclBuild { code: u32 },
    #[error("failed to install the restricted-token default DACL: Windows error {code}")]
    DefaultDaclSet { code: u32 },
    #[error("restricted-token default DACL differs from the requested logon/capability set")]
    DefaultDaclMismatch,
    #[error("failed to resolve SeChangeNotifyPrivilege: Windows error {code}")]
    ChangeNotifyLookup { code: u32 },
    #[error("failed to enable SeChangeNotifyPrivilege: Windows error {code}")]
    ChangeNotifyEnable { code: u32 },
    #[error("restricted token has an unexpected enabled privilege set")]
    PrivilegeMismatch,
    #[error("restricted token user differs from the authenticated runner account")]
    TokenUserMismatch,
    #[error("restricted-token SID set differs from the complete requested restriction set")]
    RestrictingSidMismatch,
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

#[allow(unsafe_code)]
impl Drop for LocalAcl {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0 as HLOCAL);
            }
        }
    }
}

impl RestrictedPrimaryToken {
    pub(super) fn create(
        capability_sids: &[String],
        route_sid: Option<&str>,
        expected_user_sid: &str,
    ) -> Result<Self, TokenHardeningError> {
        if capability_sids.is_empty() {
            return Err(TokenHardeningError::MissingCapabilitySid);
        }
        let base = open_base_token()?;
        let actual_user_sid = token_user_sid(base.as_raw_handle() as _)?;
        if !actual_user_sid.eq_ignore_ascii_case(expected_user_sid) {
            return Err(TokenHardeningError::TokenUserMismatch);
        }
        let logon_sid = token_logon_sid(base.as_raw_handle() as _)?;
        let capabilities = capability_sids
            .iter()
            .map(|sid| LocalSid::parse("capability", sid))
            .collect::<Result<Vec<_>, _>>()?;
        let route = route_sid
            .map(|sid| LocalSid::parse("network route", sid))
            .transpose()?;
        let user = LocalSid::parse("token user", &actual_user_sid)?;
        let logon = LocalSid::parse("logon", &logon_sid)?;
        let everyone = LocalSid::parse("Everyone", EVERYONE_SID)?;

        let mut restricting = capabilities
            .iter()
            .map(|sid| SID_AND_ATTRIBUTES {
                Sid: sid.0,
                Attributes: 0,
            })
            .collect::<Vec<_>>();
        restricting.push(SID_AND_ATTRIBUTES {
            Sid: user.0,
            Attributes: 0,
        });
        if let Some(route) = &route {
            restricting.push(SID_AND_ATTRIBUTES {
                Sid: route.0,
                Attributes: 0,
            });
        }
        restricting.push(SID_AND_ATTRIBUTES {
            Sid: logon.0,
            Attributes: 0,
        });
        restricting.push(SID_AND_ATTRIBUTES {
            Sid: everyone.0,
            Attributes: 0,
        });
        let expected_restricting = canonical_sid_set(
            restricting
                .iter()
                .map(|entry| ("restricting SID", entry.Sid)),
        )?;
        if expected_restricting.len() != restricting.len() {
            return Err(TokenHardeningError::DuplicateRestrictingSid);
        }

        let handle = create_restricted_token(base.as_raw_handle() as _, &restricting)?;
        let default_dacl_sids = capabilities
            .iter()
            .map(|sid| sid.0)
            .chain(std::iter::once(logon.0))
            .collect::<Vec<_>>();
        set_default_dacl(handle.as_raw_handle() as _, &default_dacl_sids)?;
        enable_change_notify(handle.as_raw_handle() as _)?;
        verify_token(
            handle.as_raw_handle() as _,
            expected_user_sid,
            &expected_restricting,
            &canonical_sid_set(
                default_dacl_sids
                    .iter()
                    .copied()
                    .map(|sid| ("default DACL SID", sid)),
            )?,
        )?;
        Ok(Self { handle })
    }

    pub(super) fn raw(&self) -> *mut c_void {
        self.handle.as_raw_handle() as _
    }
}

impl LocalSid {
    #[allow(unsafe_code)]
    fn parse(component: &'static str, value: &str) -> Result<Self, TokenHardeningError> {
        if value.contains('\0') {
            return Err(TokenHardeningError::SidParse { component, code: 0 });
        }
        let wide = value
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let mut sid = std::ptr::null_mut();
        if unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut sid) } == 0 {
            return Err(TokenHardeningError::SidParse {
                component,
                code: unsafe { GetLastError() },
            });
        }
        Ok(Self(sid))
    }
}

impl TokenHardeningError {
    pub(super) const fn failure_code(&self) -> WindowsRunnerFailureCode {
        match self {
            Self::BaseTokenOpen { .. } => WindowsRunnerFailureCode::BaseTokenOpen,
            Self::SidParse { .. }
            | Self::InvalidTokenSid { .. }
            | Self::TokenSidFormat { .. }
            | Self::MissingLogonSid
            | Self::DuplicateLogonSid
            | Self::DuplicateRestrictingSid
            | Self::MissingCapabilitySid => WindowsRunnerFailureCode::RestrictingSidParse,
            Self::RestrictedTokenCreate { .. } => WindowsRunnerFailureCode::RestrictedTokenCreate,
            Self::DefaultDaclBuild { .. }
            | Self::DefaultDaclSet { .. }
            | Self::DefaultDaclMismatch => WindowsRunnerFailureCode::TokenDefaultDacl,
            Self::ChangeNotifyLookup { .. }
            | Self::ChangeNotifyEnable { .. }
            | Self::PrivilegeMismatch => WindowsRunnerFailureCode::TokenPrivilege,
            Self::TokenInformation { .. }
            | Self::TruncatedTokenInformation { .. }
            | Self::TokenUserMismatch
            | Self::RestrictingSidMismatch => WindowsRunnerFailureCode::RestrictedTokenCreate,
        }
    }

    pub(super) const fn native_code(&self) -> Option<u32> {
        match self {
            Self::BaseTokenOpen { code }
            | Self::TokenInformation { code, .. }
            | Self::TokenSidFormat { code, .. }
            | Self::SidParse { code, .. }
            | Self::RestrictedTokenCreate { code }
            | Self::DefaultDaclBuild { code }
            | Self::DefaultDaclSet { code }
            | Self::ChangeNotifyLookup { code }
            | Self::ChangeNotifyEnable { code } => Some(*code),
            Self::TruncatedTokenInformation { .. }
            | Self::InvalidTokenSid { .. }
            | Self::MissingLogonSid
            | Self::DuplicateLogonSid
            | Self::DuplicateRestrictingSid
            | Self::MissingCapabilitySid
            | Self::DefaultDaclMismatch
            | Self::PrivilegeMismatch
            | Self::TokenUserMismatch
            | Self::RestrictingSidMismatch => None,
        }
    }

    pub(super) const fn stage(&self) -> WindowsRunnerFailureStage {
        WindowsRunnerFailureStage::Token
    }
}

#[allow(unsafe_code)]
fn open_base_token() -> Result<OwnedHandle, TokenHardeningError> {
    let access = TOKEN_DUPLICATE
        | TOKEN_QUERY
        | TOKEN_ASSIGN_PRIMARY
        | TOKEN_ADJUST_DEFAULT
        | TOKEN_ADJUST_SESSIONID
        | TOKEN_ADJUST_PRIVILEGES;
    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), access, &mut token) } == 0 {
        return Err(TokenHardeningError::BaseTokenOpen {
            code: unsafe { GetLastError() },
        });
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(token as RawHandle) })
}

#[allow(unsafe_code)]
fn create_restricted_token(
    base: *mut c_void,
    restricting: &[SID_AND_ATTRIBUTES],
) -> Result<OwnedHandle, TokenHardeningError> {
    let count = u32::try_from(restricting.len())
        .map_err(|_| TokenHardeningError::DuplicateRestrictingSid)?;
    let mut token = std::ptr::null_mut();
    if unsafe {
        CreateRestrictedToken(
            base,
            DISABLE_MAX_PRIVILEGE | LUA_TOKEN | WRITE_RESTRICTED,
            0,
            std::ptr::null(),
            0,
            std::ptr::null(),
            count,
            restricting.as_ptr(),
            &mut token,
        )
    } == 0
    {
        return Err(TokenHardeningError::RestrictedTokenCreate {
            code: unsafe { GetLastError() },
        });
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(token as RawHandle) })
}

#[allow(unsafe_code)]
fn set_default_dacl(token: *mut c_void, sids: &[*mut c_void]) -> Result<(), TokenHardeningError> {
    let entries = sids
        .iter()
        .map(|sid| EXPLICIT_ACCESS_W {
            grfAccessPermissions: GENERIC_ALL,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: 0,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: std::ptr::null_mut(),
                MultipleTrusteeOperation: 0,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_UNKNOWN,
                ptstrName: (*sid).cast(),
            },
        })
        .collect::<Vec<_>>();
    let count =
        u32::try_from(entries.len()).map_err(|_| TokenHardeningError::DefaultDaclMismatch)?;
    let mut acl = std::ptr::null_mut();
    let status = unsafe { SetEntriesInAclW(count, entries.as_ptr(), std::ptr::null(), &mut acl) };
    if status != ERROR_SUCCESS {
        return Err(TokenHardeningError::DefaultDaclBuild { code: status });
    }
    let acl = LocalAcl(acl);
    let mut information = TOKEN_DEFAULT_DACL { DefaultDacl: acl.0 };
    if unsafe {
        SetTokenInformation(
            token,
            TokenDefaultDacl,
            (&raw mut information).cast(),
            size_of::<TOKEN_DEFAULT_DACL>() as u32,
        )
    } == 0
    {
        return Err(TokenHardeningError::DefaultDaclSet {
            code: unsafe { GetLastError() },
        });
    }
    Ok(())
}

#[allow(unsafe_code)]
fn enable_change_notify(token: *mut c_void) -> Result<(), TokenHardeningError> {
    let mut luid = windows_sys::Win32::Foundation::LUID {
        LowPart: 0,
        HighPart: 0,
    };
    if unsafe { LookupPrivilegeValueW(std::ptr::null(), SE_CHANGE_NOTIFY_NAME, &mut luid) } == 0 {
        return Err(TokenHardeningError::ChangeNotifyLookup {
            code: unsafe { GetLastError() },
        });
    }
    let privileges = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [windows_sys::Win32::Security::LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };
    unsafe {
        SetLastError(ERROR_SUCCESS);
    }
    if unsafe {
        AdjustTokenPrivileges(
            token,
            0,
            &privileges,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(TokenHardeningError::ChangeNotifyEnable {
            code: unsafe { GetLastError() },
        });
    }
    let code = unsafe { GetLastError() };
    if code == ERROR_NOT_ALL_ASSIGNED {
        return Err(TokenHardeningError::ChangeNotifyEnable { code });
    }
    Ok(())
}

fn verify_token(
    token: *mut c_void,
    expected_user_sid: &str,
    expected_restricting: &BTreeSet<String>,
    expected_default_dacl: &BTreeSet<String>,
) -> Result<(), TokenHardeningError> {
    if !token_user_sid(token)?.eq_ignore_ascii_case(expected_user_sid) {
        return Err(TokenHardeningError::TokenUserMismatch);
    }
    if token_group_sid_set(token, TokenRestrictedSids, "restricted SIDs")? != *expected_restricting
    {
        return Err(TokenHardeningError::RestrictingSidMismatch);
    }
    verify_default_dacl(token, expected_default_dacl)?;
    verify_enabled_privileges(token)
}

#[allow(unsafe_code)]
fn token_user_sid(token: *mut c_void) -> Result<String, TokenHardeningError> {
    let buffer = token_information(token, TokenUser, "token user")?;
    if buffer.0.len() < size_of::<TOKEN_USER>() {
        return Err(TokenHardeningError::TruncatedTokenInformation {
            component: "token user",
        });
    }
    let user = unsafe { std::ptr::read_unaligned(buffer.0.as_ptr().cast::<TOKEN_USER>()) };
    sid_to_string("token user", user.User.Sid)
}

fn token_logon_sid(token: *mut c_void) -> Result<String, TokenHardeningError> {
    let buffer = token_information(token, windows_sys::Win32::Security::TokenGroups, "groups")?;
    let groups = token_group_entries(&buffer, "groups")?;
    let mut logon = groups
        .into_iter()
        .filter(|group| group.Attributes & SE_GROUP_LOGON_ID == SE_GROUP_LOGON_ID)
        .map(|group| sid_to_string("logon SID", group.Sid));
    let Some(logon_sid) = logon.next() else {
        return Err(TokenHardeningError::MissingLogonSid);
    };
    if logon.next().is_some() {
        return Err(TokenHardeningError::DuplicateLogonSid);
    }
    logon_sid
}

fn token_group_sid_set(
    token: *mut c_void,
    class: i32,
    component: &'static str,
) -> Result<BTreeSet<String>, TokenHardeningError> {
    let buffer = token_information(token, class, component)?;
    canonical_sid_set(
        token_group_entries(&buffer, component)?
            .into_iter()
            .map(|entry| (component, entry.Sid)),
    )
}

#[allow(unsafe_code)]
fn token_group_entries(
    buffer: &TokenBuffer,
    component: &'static str,
) -> Result<Vec<SID_AND_ATTRIBUTES>, TokenHardeningError> {
    if buffer.0.len() < offset_of!(windows_sys::Win32::Security::TOKEN_GROUPS, Groups) {
        return Err(TokenHardeningError::TruncatedTokenInformation { component });
    }
    let count = unsafe { std::ptr::read_unaligned(buffer.0.as_ptr().cast::<u32>()) } as usize;
    let offset = offset_of!(windows_sys::Win32::Security::TOKEN_GROUPS, Groups);
    let maximum = (buffer.0.len() - offset) / size_of::<SID_AND_ATTRIBUTES>();
    if count > maximum {
        return Err(TokenHardeningError::TruncatedTokenInformation { component });
    }
    let entries = unsafe { buffer.0.as_ptr().add(offset).cast::<SID_AND_ATTRIBUTES>() };
    Ok((0..count)
        .map(|index| unsafe { std::ptr::read_unaligned(entries.add(index)) })
        .collect())
}

fn canonical_sid_set(
    values: impl IntoIterator<Item = (&'static str, *mut c_void)>,
) -> Result<BTreeSet<String>, TokenHardeningError> {
    values
        .into_iter()
        .map(|(component, sid)| sid_to_string(component, sid).map(|sid| sid.to_ascii_uppercase()))
        .collect()
}

#[allow(unsafe_code)]
fn sid_to_string(component: &'static str, sid: *mut c_void) -> Result<String, TokenHardeningError> {
    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
        return Err(TokenHardeningError::InvalidTokenSid { component });
    }
    let mut value = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut value) } == 0 {
        return Err(TokenHardeningError::TokenSidFormat {
            component,
            code: unsafe { GetLastError() },
        });
    }
    let result = wide_pointer_to_string(value);
    unsafe {
        LocalFree(value as HLOCAL);
    }
    Ok(result)
}

#[allow(unsafe_code)]
fn token_information(
    token: *mut c_void,
    class: i32,
    component: &'static str,
) -> Result<TokenBuffer, TokenHardeningError> {
    let mut length = 0u32;
    let queried =
        unsafe { GetTokenInformation(token, class, std::ptr::null_mut(), 0, &mut length) };
    let code = unsafe { GetLastError() };
    if queried != 0 || code != ERROR_INSUFFICIENT_BUFFER || length == 0 {
        return Err(TokenHardeningError::TokenInformation { component, code });
    }
    let mut buffer = vec![0u8; length as usize];
    if unsafe {
        GetTokenInformation(
            token,
            class,
            buffer.as_mut_ptr().cast(),
            length,
            &mut length,
        )
    } == 0
    {
        return Err(TokenHardeningError::TokenInformation {
            component,
            code: unsafe { GetLastError() },
        });
    }
    buffer.truncate(length as usize);
    Ok(TokenBuffer(buffer))
}

#[allow(unsafe_code)]
fn verify_default_dacl(
    token: *mut c_void,
    expected: &BTreeSet<String>,
) -> Result<(), TokenHardeningError> {
    let buffer = token_information(token, TokenDefaultDacl, "default DACL")?;
    if buffer.0.len() < size_of::<TOKEN_DEFAULT_DACL>() {
        return Err(TokenHardeningError::TruncatedTokenInformation {
            component: "default DACL",
        });
    }
    let info = unsafe { std::ptr::read_unaligned(buffer.0.as_ptr().cast::<TOKEN_DEFAULT_DACL>()) };
    if info.DefaultDacl.is_null()
        || unsafe { (*info.DefaultDacl).AceCount } as usize != expected.len()
    {
        return Err(TokenHardeningError::DefaultDaclMismatch);
    }
    let mut actual = BTreeSet::new();
    for index in 0..expected.len() {
        let mut raw_ace = std::ptr::null_mut();
        if unsafe { GetAce(info.DefaultDacl, index as u32, &mut raw_ace) } == 0 || raw_ace.is_null()
        {
            return Err(TokenHardeningError::DefaultDaclMismatch);
        }
        let ace = raw_ace.cast::<ACCESS_ALLOWED_ACE>();
        if unsafe { (*ace).Header.AceType }
            != windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE as u8
            || unsafe { (*ace).Header.AceFlags } != 0
            || unsafe { (*ace).Mask } != GENERIC_ALL
        {
            return Err(TokenHardeningError::DefaultDaclMismatch);
        }
        let sid = unsafe { (&raw mut (*ace).SidStart).cast::<c_void>() };
        actual.insert(sid_to_string("default DACL", sid)?.to_ascii_uppercase());
    }
    if actual == *expected {
        Ok(())
    } else {
        Err(TokenHardeningError::DefaultDaclMismatch)
    }
}

#[allow(unsafe_code)]
fn verify_enabled_privileges(token: *mut c_void) -> Result<(), TokenHardeningError> {
    let mut expected = windows_sys::Win32::Foundation::LUID {
        LowPart: 0,
        HighPart: 0,
    };
    if unsafe { LookupPrivilegeValueW(std::ptr::null(), SE_CHANGE_NOTIFY_NAME, &mut expected) } == 0
    {
        return Err(TokenHardeningError::ChangeNotifyLookup {
            code: unsafe { GetLastError() },
        });
    }
    let buffer = token_information(token, TokenPrivileges, "privileges")?;
    let offset = offset_of!(TOKEN_PRIVILEGES, Privileges);
    if buffer.0.len() < offset {
        return Err(TokenHardeningError::TruncatedTokenInformation {
            component: "privileges",
        });
    }
    let count = unsafe { std::ptr::read_unaligned(buffer.0.as_ptr().cast::<u32>()) } as usize;
    let maximum =
        (buffer.0.len() - offset) / size_of::<windows_sys::Win32::Security::LUID_AND_ATTRIBUTES>();
    if count > maximum {
        return Err(TokenHardeningError::TruncatedTokenInformation {
            component: "privileges",
        });
    }
    let entries = unsafe {
        buffer
            .0
            .as_ptr()
            .add(offset)
            .cast::<windows_sys::Win32::Security::LUID_AND_ATTRIBUTES>()
    };
    let enabled = (0..count)
        .map(|index| unsafe { std::ptr::read_unaligned(entries.add(index)) })
        .filter(|entry| entry.Attributes & SE_PRIVILEGE_ENABLED != 0)
        .collect::<Vec<_>>();
    if enabled.len() == 1
        && enabled[0].Luid.LowPart == expected.LowPart
        && enabled[0].Luid.HighPart == expected.HighPart
    {
        Ok(())
    } else {
        Err(TokenHardeningError::PrivilegeMismatch)
    }
}

#[allow(unsafe_code)]
fn wide_pointer_to_string(value: *const u16) -> String {
    unsafe {
        let mut length = 0usize;
        while *value.add(length) != 0 {
            length += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(value, length))
    }
}
