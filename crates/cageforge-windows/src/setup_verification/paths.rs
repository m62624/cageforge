// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use std::ffi::c_void;

use windows_sys::Win32::Foundation::{GENERIC_ALL, GetLastError, HLOCAL, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW,
    ConvertStringSidToSidW, GetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, EqualSid, GetAce,
    GetSecurityDescriptorControl, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner,
    INHERIT_ONLY_ACE, IsValidSecurityDescriptor, IsValidSid, OBJECT_INHERIT_ACE,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SE_DACL_PROTECTED,
};
use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
use windows_sys::Win32::Storage::FileSystem::{FILE_GENERIC_EXECUTE, FILE_GENERIC_READ};
use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;

use crate::error::WindowsSetupVerificationError;

struct LocalSecurityDescriptor(PSECURITY_DESCRIPTOR);

struct LocalWideString(*mut u16);

struct LocalSid(*mut c_void);

enum ProtectedDescriptor<'a> {
    OwnerOnly { inherit: bool },
    RunnerDirectory { group_sid: &'a str },
    RunnerExecutable { group_sid: &'a str },
    RunnerManifest { group_sid: &'a str },
}

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
pub(super) fn verify_protected_dacl(
    path: &Path,
    owner_sid: &str,
    inherit: bool,
) -> Result<(), WindowsSetupVerificationError> {
    verify_dacl(path, owner_sid, &ProtectedDescriptor::OwnerOnly { inherit })
}

pub(super) fn verify_runner_directory_dacl(
    path: &Path,
    owner_sid: &str,
    group_sid: &str,
) -> Result<(), WindowsSetupVerificationError> {
    verify_dacl(
        path,
        owner_sid,
        &ProtectedDescriptor::RunnerDirectory { group_sid },
    )
}

pub(super) fn verify_runner_executable_dacl(
    path: &Path,
    owner_sid: &str,
    group_sid: &str,
) -> Result<(), WindowsSetupVerificationError> {
    verify_dacl(
        path,
        owner_sid,
        &ProtectedDescriptor::RunnerExecutable { group_sid },
    )
}

pub(super) fn verify_runner_manifest_dacl(
    path: &Path,
    owner_sid: &str,
    group_sid: &str,
) -> Result<(), WindowsSetupVerificationError> {
    verify_dacl(
        path,
        owner_sid,
        &ProtectedDescriptor::RunnerManifest { group_sid },
    )
}

#[allow(unsafe_code)]
fn verify_dacl(
    path: &Path,
    owner_sid: &str,
    descriptor_kind: &ProtectedDescriptor<'_>,
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
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
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
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
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
    if protected_descriptor_matches(descriptor.0, owner_sid, descriptor_kind) {
        Ok(())
    } else {
        Err(
            WindowsSetupVerificationError::ProtectedSecurityDescriptorMismatch {
                path: path.to_path_buf(),
                actual,
            },
        )
    }
}

#[allow(unsafe_code)]
fn protected_descriptor_matches(
    descriptor: PSECURITY_DESCRIPTOR,
    owner_sid: &str,
    descriptor_kind: &ProtectedDescriptor<'_>,
) -> bool {
    if unsafe { IsValidSecurityDescriptor(descriptor) } == 0 {
        return false;
    }
    let mut owner = std::ptr::null_mut();
    let mut owner_defaulted = 0;
    if unsafe { GetSecurityDescriptorOwner(descriptor, &mut owner, &mut owner_defaulted) } == 0
        || owner.is_null()
        || unsafe { IsValidSid(owner) } == 0
    {
        return false;
    }
    let Some(expected_owner) = local_sid(owner_sid) else {
        return false;
    };
    if unsafe { EqualSid(owner, expected_owner.0) } == 0 {
        return false;
    }
    let mut control = 0u16;
    let mut revision = 0u32;
    if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0
        || control & SE_DACL_PROTECTED == 0
    {
        return false;
    }
    let mut present = 0;
    let mut defaulted = 0;
    let mut dacl = std::ptr::null_mut();
    if unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) }
        == 0
        || present == 0
        || dacl.is_null()
    {
        return false;
    }
    let principals = ["S-1-5-18", "S-1-5-32-544", owner_sid];
    let mut expected_aces = principals
        .iter()
        .map(|sid| ((*sid).to_string(), 0u8, FILE_ALL_ACCESS))
        .collect::<Vec<_>>();
    match descriptor_kind {
        ProtectedDescriptor::OwnerOnly { inherit: true } => {
            let inherited_flags =
                (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE) as u8;
            expected_aces.extend(
                principals
                    .iter()
                    .map(|sid| ((*sid).to_string(), inherited_flags, GENERIC_ALL)),
            );
        }
        ProtectedDescriptor::OwnerOnly { inherit: false } => {}
        ProtectedDescriptor::RunnerDirectory { group_sid }
        | ProtectedDescriptor::RunnerExecutable { group_sid } => expected_aces.push((
            (*group_sid).to_string(),
            0,
            FILE_GENERIC_READ | FILE_GENERIC_EXECUTE,
        )),
        ProtectedDescriptor::RunnerManifest { group_sid } => {
            expected_aces.push(((*group_sid).to_string(), 0, FILE_GENERIC_READ));
        }
    }
    if unsafe { (*dacl).AceCount } as usize != expected_aces.len() {
        return false;
    }
    let mut actual_aces = Vec::with_capacity(expected_aces.len());
    for index in 0..expected_aces.len() {
        let mut raw_ace = std::ptr::null_mut();
        if unsafe { GetAce(dacl, index as u32, &mut raw_ace) } == 0 || raw_ace.is_null() {
            return false;
        }
        let ace = raw_ace.cast::<ACCESS_ALLOWED_ACE>();
        if unsafe { (*ace).Header.AceType } != ACCESS_ALLOWED_ACE_TYPE as u8
            || (unsafe { (*ace).Header.AceSize } as usize)
                < std::mem::size_of::<ACCESS_ALLOWED_ACE>()
        {
            return false;
        }
        let sid = unsafe { (&raw mut (*ace).SidStart).cast::<c_void>() };
        if unsafe { IsValidSid(sid) } == 0 {
            return false;
        }
        let Some(sid) = sid_string(sid) else {
            return false;
        };
        actual_aces.push((sid, unsafe { (*ace).Header.AceFlags }, unsafe {
            (*ace).Mask
        }));
    }
    actual_aces.sort_unstable();
    expected_aces.sort_unstable();
    actual_aces == expected_aces
}

#[allow(unsafe_code)]
fn local_sid(sid: &str) -> Option<LocalSid> {
    let value = sid
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut parsed = std::ptr::null_mut();
    if unsafe { ConvertStringSidToSidW(value.as_ptr(), &mut parsed) } == 0 {
        None
    } else {
        Some(LocalSid(parsed))
    }
}

#[allow(unsafe_code)]
fn sid_string(sid: *mut c_void) -> Option<String> {
    let mut value = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut value) } == 0 {
        return None;
    }
    let value = LocalWideString(value);
    Some(wide_pointer_to_string(value.0))
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
