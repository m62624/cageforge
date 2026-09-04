// SPDX-License-Identifier: Apache-2.0

//! Exact installed-resource owner and DACL verification shared with the runner.

use std::ffi::c_void;
use std::fs::File;
use std::mem::{align_of, offset_of, size_of};
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};

use thiserror::Error;
use windows_sys::Win32::Foundation::{ERROR_INVALID_DATA, GetLastError, HLOCAL, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW,
    ConvertStringSidToSidW, GetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
    DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation, GetSecurityDescriptorControl,
    GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, IsValidSecurityDescriptor, IsValidSid,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SE_DACL_PROTECTED,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ALL_ACCESS, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ,
};
use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;

use crate::native_strings::local_sid_string;

const SID_HEADER_BYTES: usize = 8;

pub(crate) enum RunnerResourceKind {
    Executable,
    Manifest,
}

pub(crate) struct ResourceSecuritySnapshot {
    pub(crate) path: PathBuf,
    pub(crate) descriptor: String,
}

struct LocalSecurityDescriptor(PSECURITY_DESCRIPTOR);

struct LocalWideString(*mut u16);

struct LocalSid(*mut c_void);

#[derive(Debug, Error)]
pub(crate) enum RunnerResourceSecurityError {
    #[error("installed Windows resource path is unsafe at {path:?}: {detail}")]
    Unsafe { path: PathBuf, detail: String },
    #[error("failed to read Windows security descriptor for {path:?}: error {code}")]
    Read { path: PathBuf, code: u32 },
    #[error("protected Windows security descriptor mismatch for {path:?}: {descriptor}")]
    Mismatch { path: PathBuf, descriptor: String },
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
pub(crate) fn verify_open_runner_resource(
    file: &File,
    path: &Path,
    owner_sid: &str,
    group_sid: &str,
    kind: RunnerResourceKind,
) -> Result<(), RunnerResourceSecurityError> {
    let mut descriptor = std::ptr::null_mut();
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
        return Err(RunnerResourceSecurityError::Read {
            path: path.to_path_buf(),
            code: status,
        });
    }
    let descriptor = LocalSecurityDescriptor(descriptor);
    let snapshot = descriptor_snapshot(path, descriptor.0)?;
    if descriptor_matches(descriptor.0, owner_sid, group_sid, kind) {
        Ok(())
    } else {
        Err(RunnerResourceSecurityError::Mismatch {
            path: snapshot.path,
            descriptor: snapshot.descriptor,
        })
    }
}

#[allow(unsafe_code)]
fn descriptor_snapshot(
    path: &Path,
    descriptor: PSECURITY_DESCRIPTOR,
) -> Result<ResourceSecuritySnapshot, RunnerResourceSecurityError> {
    let mut value = std::ptr::null_mut();
    let mut value_length = 0u32;
    if unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            SDDL_REVISION_1,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut value,
            &mut value_length,
        )
    } == 0
    {
        return Err(RunnerResourceSecurityError::Read {
            path: path.to_path_buf(),
            code: unsafe { GetLastError() },
        });
    }
    let value = LocalWideString(value);
    let Some(descriptor) = wide_string_with_length(value.0, value_length) else {
        return Err(RunnerResourceSecurityError::Read {
            path: path.to_path_buf(),
            code: ERROR_INVALID_DATA,
        });
    };
    Ok(ResourceSecuritySnapshot {
        path: path.to_path_buf(),
        descriptor,
    })
}

#[allow(unsafe_code)]
fn descriptor_matches(
    descriptor: PSECURITY_DESCRIPTOR,
    owner_sid: &str,
    group_sid: &str,
    kind: RunnerResourceKind,
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
    let group_mask = match kind {
        RunnerResourceKind::Executable => FILE_GENERIC_READ | FILE_GENERIC_EXECUTE,
        RunnerResourceKind::Manifest => FILE_GENERIC_READ,
    };
    let mut expected = [
        ("S-1-5-18".to_string(), FILE_ALL_ACCESS),
        ("S-1-5-32-544".to_string(), FILE_ALL_ACCESS),
        (owner_sid.to_string(), FILE_ALL_ACCESS),
        (group_sid.to_string(), group_mask),
    ];
    let mut acl_size = ACL_SIZE_INFORMATION::default();
    if unsafe {
        GetAclInformation(
            dacl,
            (&raw mut acl_size).cast(),
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
        || acl_size.AceCount as usize != expected.len()
        || acl_size.AclBytesInUse < size_of::<ACL>() as u32
    {
        return false;
    }
    let acl_start = dacl as usize;
    let Some(acl_end) = acl_start.checked_add(acl_size.AclBytesInUse as usize) else {
        return false;
    };
    if !range_fits(acl_start, acl_end, dacl.cast(), size_of::<ACL>()) {
        return false;
    }
    let mut actual = Vec::with_capacity(expected.len());
    for index in 0..expected.len() {
        let mut raw_ace = std::ptr::null_mut();
        if unsafe { GetAce(dacl, index as u32, &mut raw_ace) } == 0 || raw_ace.is_null() {
            return false;
        }
        let raw_start = raw_ace as usize;
        let Some(header_end) = raw_start.checked_add(size_of::<ACE_HEADER>()) else {
            return false;
        };
        if !raw_start.is_multiple_of(align_of::<ACE_HEADER>())
            || raw_start < acl_start
            || header_end > acl_end
        {
            return false;
        }
        let ace = raw_ace.cast::<ACCESS_ALLOWED_ACE>();
        let ace_size = unsafe { (*ace).Header.AceSize } as usize;
        let Some(ace_end) = raw_start.checked_add(ace_size) else {
            return false;
        };
        if unsafe { (*ace).Header.AceType } != ACCESS_ALLOWED_ACE_TYPE as u8
            || unsafe { (*ace).Header.AceFlags } != 0
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
        actual.push((sid, unsafe { (*ace).Mask }));
    }
    actual.sort_unstable();
    expected.sort_unstable();
    actual == expected
}

fn range_fits(start: usize, end: usize, pointer: *const c_void, length: usize) -> bool {
    let pointer = pointer as usize;
    let Some(pointer_end) = pointer.checked_add(length) else {
        return false;
    };
    pointer >= start && pointer_end <= end
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
    let count = usize::from(bytes[sid_offset + 1]);
    let Some(subauthority_bytes) = count.checked_mul(size_of::<u32>()) else {
        return false;
    };
    let Some(length) = SID_HEADER_BYTES.checked_add(subauthority_bytes) else {
        return false;
    };
    sid_offset
        .checked_add(length)
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
