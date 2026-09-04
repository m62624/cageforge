// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::os::windows::io::AsRawHandle;
use std::path::Path;

use std::ffi::c_void;
use std::mem::{align_of, offset_of, size_of};

use windows_sys::Win32::Foundation::{ERROR_INVALID_DATA, GetLastError, HLOCAL, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW,
    ConvertStringSidToSidW, GetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
    CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation,
    GetSecurityDescriptorControl, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner,
    IsValidSecurityDescriptor, IsValidSid, OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, SE_DACL_PROTECTED,
};
use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
use windows_sys::Win32::Storage::FileSystem::{FILE_GENERIC_EXECUTE, FILE_GENERIC_READ};
use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;

use crate::error::WindowsSetupVerificationError;
use crate::native_strings::local_sid_string;

struct LocalSecurityDescriptor(PSECURITY_DESCRIPTOR);

struct LocalWideString(*mut u16);

struct LocalSid(*mut c_void);

enum ProtectedDescriptor<'a> {
    OwnerOnly { inherit: bool },
    RunnerDirectory { group_sid: &'a str },
}

const SID_HEADER_BYTES: usize = 8;

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

pub(crate) fn verify_protected_dacl(
    path: &Path,
    owner_sid: &str,
    inherit: bool,
) -> Result<File, WindowsSetupVerificationError> {
    verify_dacl(
        path,
        owner_sid,
        &ProtectedDescriptor::OwnerOnly { inherit },
        inherit,
    )
}

pub(crate) fn verify_open_protected_dacl(
    file: File,
    path: &Path,
    owner_sid: &str,
    inherit: bool,
) -> Result<File, WindowsSetupVerificationError> {
    verify_open_dacl(
        file,
        path,
        owner_sid,
        &ProtectedDescriptor::OwnerOnly { inherit },
    )
}

pub(super) fn verify_runner_directory_dacl(
    path: &Path,
    owner_sid: &str,
    group_sid: &str,
) -> Result<File, WindowsSetupVerificationError> {
    verify_dacl(
        path,
        owner_sid,
        &ProtectedDescriptor::RunnerDirectory { group_sid },
        true,
    )
}

pub(super) fn verify_runner_executable_dacl(
    path: &Path,
    owner_sid: &str,
    group_sid: &str,
) -> Result<File, WindowsSetupVerificationError> {
    verify_shared_runner_resource(
        path,
        owner_sid,
        group_sid,
        crate::runner::resource_security::RunnerResourceKind::Executable,
    )
}

pub(super) fn verify_runner_manifest_dacl(
    path: &Path,
    owner_sid: &str,
    group_sid: &str,
) -> Result<File, WindowsSetupVerificationError> {
    verify_shared_runner_resource(
        path,
        owner_sid,
        group_sid,
        crate::runner::resource_security::RunnerResourceKind::Manifest,
    )
}

fn verify_shared_runner_resource(
    path: &Path,
    owner_sid: &str,
    group_sid: &str,
    kind: crate::runner::resource_security::RunnerResourceKind,
) -> Result<File, WindowsSetupVerificationError> {
    let file = crate::setup::pinned::file::open_for_readback(path, true).map_err(|error| {
        map_runner_resource_error(
            crate::runner::resource_security::RunnerResourceSecurityError::Unsafe {
                path: path.to_path_buf(),
                detail: error.to_string(),
            },
        )
    })?;
    crate::runner::resource_security::verify_open_runner_resource(
        &file, path, owner_sid, group_sid, kind,
    )
    .map_err(map_runner_resource_error)?;
    Ok(file)
}

pub(crate) fn verify_open_runner_resource_dacl(
    file: &File,
    path: &Path,
    owner_sid: &str,
    group_sid: &str,
    kind: crate::runner::resource_security::RunnerResourceKind,
) -> Result<(), WindowsSetupVerificationError> {
    crate::runner::resource_security::verify_open_runner_resource(
        file, path, owner_sid, group_sid, kind,
    )
    .map_err(map_runner_resource_error)
}

fn map_runner_resource_error(
    error: crate::runner::resource_security::RunnerResourceSecurityError,
) -> WindowsSetupVerificationError {
    match error {
        crate::runner::resource_security::RunnerResourceSecurityError::Unsafe { path, detail } => {
            WindowsSetupVerificationError::ProtectedPathUnsafe { path, detail }
        }
        crate::runner::resource_security::RunnerResourceSecurityError::Read { path, code } => {
            WindowsSetupVerificationError::ProtectedAclRead { path, code }
        }
        crate::runner::resource_security::RunnerResourceSecurityError::Mismatch {
            path,
            descriptor,
        } => WindowsSetupVerificationError::ProtectedSecurityDescriptorMismatch {
            path,
            actual: descriptor,
        },
    }
}

fn verify_dacl(
    path: &Path,
    owner_sid: &str,
    descriptor_kind: &ProtectedDescriptor<'_>,
    directory: bool,
) -> Result<File, WindowsSetupVerificationError> {
    let file = if directory {
        crate::setup::pinned::setup::open_for_pin(path)
    } else {
        crate::setup::pinned::file::open_for_readback(path, true)
    }
    .map_err(|error| WindowsSetupVerificationError::ProtectedPathUnsafe {
        path: path.to_path_buf(),
        detail: error.to_string(),
    })?;
    verify_open_dacl(file, path, owner_sid, descriptor_kind)
}

#[allow(unsafe_code)]
fn verify_open_dacl(
    file: File,
    path: &Path,
    owner_sid: &str,
    descriptor_kind: &ProtectedDescriptor<'_>,
) -> Result<File, WindowsSetupVerificationError> {
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle() as _,
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
    let mut value_length = 0u32;
    if unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor.0,
            SDDL_REVISION_1,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut value,
            &mut value_length,
        )
    } == 0
    {
        return Err(WindowsSetupVerificationError::ProtectedAclRead {
            path: path.to_path_buf(),
            code: unsafe { GetLastError() },
        });
    }
    let value = LocalWideString(value);
    let Some(actual) = wide_string_with_length(value.0, value_length) else {
        return Err(WindowsSetupVerificationError::ProtectedAclRead {
            path: path.to_path_buf(),
            code: ERROR_INVALID_DATA,
        });
    };
    if protected_descriptor_matches(descriptor.0, owner_sid, descriptor_kind) {
        Ok(file)
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
    let mut expected_aces = match descriptor_kind {
        ProtectedDescriptor::OwnerOnly { inherit: true } => {
            let inheritance = (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8;
            principals
                .iter()
                .map(|sid| ((*sid).to_string(), inheritance, FILE_ALL_ACCESS))
                .collect::<Vec<_>>()
        }
        ProtectedDescriptor::OwnerOnly { inherit: false }
        | ProtectedDescriptor::RunnerDirectory { .. } => principals
            .iter()
            .map(|sid| ((*sid).to_string(), 0u8, FILE_ALL_ACCESS))
            .collect::<Vec<_>>(),
    };
    match descriptor_kind {
        ProtectedDescriptor::OwnerOnly { inherit: true } => {}
        ProtectedDescriptor::OwnerOnly { inherit: false } => {}
        ProtectedDescriptor::RunnerDirectory { group_sid } => expected_aces.push((
            (*group_sid).to_string(),
            0,
            FILE_GENERIC_READ | FILE_GENERIC_EXECUTE,
        )),
    }
    if unsafe { (*dacl).AceCount } as usize != expected_aces.len() {
        return false;
    }
    let mut acl_size = ACL_SIZE_INFORMATION {
        AceCount: 0,
        AclBytesInUse: 0,
        AclBytesFree: 0,
    };
    if unsafe {
        GetAclInformation(
            dacl,
            (&raw mut acl_size).cast(),
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
    {
        return false;
    }
    let acl_start = dacl.cast::<u8>() as usize;
    let Some(acl_end) = acl_start.checked_add(acl_size.AclBytesInUse as usize) else {
        return false;
    };
    let Some(acl_header_end) = acl_start.checked_add(size_of::<ACL>()) else {
        return false;
    };
    if acl_header_end > acl_end {
        return false;
    }
    let mut actual_aces = Vec::with_capacity(expected_aces.len());
    for index in 0..expected_aces.len() {
        let mut raw_ace = std::ptr::null_mut();
        if unsafe { GetAce(dacl, index as u32, &mut raw_ace) } == 0 || raw_ace.is_null() {
            return false;
        }
        let raw_start = raw_ace as usize;
        if !raw_start.is_multiple_of(align_of::<ACE_HEADER>()) {
            return false;
        }
        let Some(header_end) = raw_start.checked_add(size_of::<ACE_HEADER>()) else {
            return false;
        };
        if raw_start < acl_start || header_end > acl_end {
            return false;
        }
        let ace = raw_ace.cast::<ACCESS_ALLOWED_ACE>();
        let ace_size = unsafe { (*ace).Header.AceSize } as usize;
        let Some(ace_end) = raw_start.checked_add(ace_size) else {
            return false;
        };
        if unsafe { (*ace).Header.AceType } != ACCESS_ALLOWED_ACE_TYPE as u8
            || ace_size < size_of::<ACCESS_ALLOWED_ACE>()
            || ace_end > acl_end
            || !sid_fits_ace(raw_ace.cast(), ace_size)
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
fn sid_fits_ace(raw_ace: *mut c_void, ace_size: usize) -> bool {
    let sid_offset = offset_of!(ACCESS_ALLOWED_ACE, SidStart);
    let Some(sid_header_end) = sid_offset.checked_add(SID_HEADER_BYTES) else {
        return false;
    };
    if sid_header_end > ace_size {
        return false;
    }
    let bytes = unsafe { std::slice::from_raw_parts(raw_ace.cast::<u8>(), ace_size) };
    let Some(subauthority_bytes) = usize::from(bytes[sid_offset + 1]).checked_mul(size_of::<u32>())
    else {
        return false;
    };
    let Some(sid_length) = SID_HEADER_BYTES.checked_add(subauthority_bytes) else {
        return false;
    };
    sid_offset
        .checked_add(sid_length)
        .is_some_and(|end| end <= bytes.len())
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
    local_sid_string(value)
}

#[allow(unsafe_code)]
fn wide_string_with_length(value: *const u16, length: u32) -> Option<String> {
    if value.is_null() || length == 0 {
        return None;
    }
    let units = unsafe { std::slice::from_raw_parts(value, length as usize) };
    let units = units.strip_suffix(&[0]).unwrap_or(units);
    Some(String::from_utf16_lossy(units))
}
