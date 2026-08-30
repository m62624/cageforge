// SPDX-License-Identifier: Apache-2.0

//! Exact installed-resource owner and DACL verification shared with the runner.

use std::ffi::c_void;
use std::fs::File;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};

use thiserror::Error;
use windows_sys::Win32::Foundation::{GetLastError, HLOCAL, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW,
    ConvertStringSidToSidW, GetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetSecurityDescriptorControl,
    GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, IsValidSecurityDescriptor, IsValidSid,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SE_DACL_PROTECTED,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ALL_ACCESS, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ,
};
use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;

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
    if unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            SDDL_REVISION_1,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut value,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(RunnerResourceSecurityError::Read {
            path: path.to_path_buf(),
            code: unsafe { GetLastError() },
        });
    }
    let value = LocalWideString(value);
    Ok(ResourceSecuritySnapshot {
        path: path.to_path_buf(),
        descriptor: wide_pointer_to_string(value.0),
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
    if unsafe { (*dacl).AceCount } as usize != expected.len() {
        return false;
    }
    let mut actual = Vec::with_capacity(expected.len());
    for index in 0..expected.len() {
        let mut raw_ace = std::ptr::null_mut();
        if unsafe { GetAce(dacl, index as u32, &mut raw_ace) } == 0 || raw_ace.is_null() {
            return false;
        }
        let ace = raw_ace.cast::<ACCESS_ALLOWED_ACE>();
        if unsafe { (*ace).Header.AceType } != ACCESS_ALLOWED_ACE_TYPE as u8
            || unsafe { (*ace).Header.AceFlags } != 0
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
        actual.push((sid, unsafe { (*ace).Mask }));
    }
    actual.sort_unstable();
    expected.sort_unstable();
    actual == expected
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
