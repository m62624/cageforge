// SPDX-License-Identifier: Apache-2.0

use std::ffi::c_void;
use std::fs::File;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, RawHandle};
use std::path::{Component, Path};

use windows_sys::Win32::Foundation::{
    ERROR_ALREADY_EXISTS, GENERIC_ALL, GENERIC_WRITE, GetLastError, HLOCAL, INVALID_HANDLE_VALUE,
    LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW, GetSecurityInfo,
    SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, EqualSid, GetAce,
    GetSecurityDescriptorControl, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner,
    INHERIT_ONLY_ACE, IsValidSecurityDescriptor, IsValidSid, OBJECT_INHERIT_ACE,
    OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    SE_DACL_PROTECTED, SECURITY_ATTRIBUTES, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
};
use windows_sys::Win32::Storage::FileSystem::{
    CREATE_ALWAYS, CreateDirectoryW, CreateFileW, FILE_ALL_ACCESS, FILE_ATTRIBUTE_NORMAL,
    FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, READ_CONTROL,
};
use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::setup_protocol::{SetupFailureCode, SetupRequest, SetupStage};

use super::{NativeSetupFailure, NativeSetupResult};

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
pub(super) fn require_elevated() -> NativeSetupResult<()> {
    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(last_error(
            SetupStage::Elevation,
            SetupFailureCode::NotElevated,
            "failed to open the setup helper process token",
        ));
    }
    let token = unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(token as RawHandle) };
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut returned = 0u32;
    let queried = unsafe {
        windows_sys::Win32::Security::GetTokenInformation(
            std::os::windows::io::AsRawHandle::as_raw_handle(&token) as _,
            TokenElevation,
            (&raw mut elevation).cast(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    };
    if queried == 0 {
        return Err(last_error(
            SetupStage::Elevation,
            SetupFailureCode::NotElevated,
            "failed to query setup helper elevation",
        ));
    }
    if returned < size_of::<TOKEN_ELEVATION>() as u32 || elevation.TokenIsElevated == 0 {
        return Err(NativeSetupFailure::new(
            SetupStage::Elevation,
            SetupFailureCode::NotElevated,
            None,
            "the Windows setup helper must run with an elevated administrator token",
        ));
    }
    Ok(())
}

pub(super) fn validate_request_boundary(request: &SetupRequest) -> NativeSetupResult<()> {
    if !request.owner_sid.starts_with("S-1-5-") || request.owner_sid.contains('\0') {
        return Err(NativeSetupFailure::new(
            SetupStage::Request,
            SetupFailureCode::InvalidOwnerSid,
            None,
            "setup owner must be a canonical Windows account SID",
        ));
    }
    if !request.state_directory.is_absolute()
        || request
            .state_directory
            .components()
            .any(|component| matches!(component, Component::ParentDir))
        || request
            .state_directory
            .as_os_str()
            .encode_wide()
            .any(|unit| unit == 0)
    {
        return Err(NativeSetupFailure::new(
            SetupStage::Request,
            SetupFailureCode::InvalidStateDirectory,
            None,
            format!(
                "setup state directory is not a safe absolute Windows path: {:?}",
                request.state_directory
            ),
        ));
    }
    let mut ports = request.proxy_ports.clone();
    ports.sort_unstable();
    ports.dedup();
    if ports.len() != 2 || ports.contains(&0) {
        return Err(NativeSetupFailure::new(
            SetupStage::Request,
            SetupFailureCode::InvalidStateDirectory,
            None,
            "setup requires two distinct non-zero loopback proxy ports",
        ));
    }
    Ok(())
}

#[allow(unsafe_code)]
pub(super) fn prepare_state_directory(path: &Path, owner_sid: &str) -> NativeSetupResult<()> {
    prepare_directory(
        path,
        owner_sid,
        &ProtectedDescriptor::OwnerOnly { inherit: true },
    )
}

#[allow(unsafe_code)]
pub(super) fn prepare_runner_directory(
    path: &Path,
    owner_sid: &str,
    group_sid: &str,
) -> NativeSetupResult<()> {
    prepare_directory(
        path,
        owner_sid,
        &ProtectedDescriptor::RunnerDirectory { group_sid },
    )
}

#[allow(unsafe_code)]
fn prepare_directory(
    path: &Path,
    owner_sid: &str,
    descriptor_kind: &ProtectedDescriptor<'_>,
) -> NativeSetupResult<()> {
    let parent = path.parent().ok_or_else(|| {
        NativeSetupFailure::new(
            SetupStage::StateDirectory,
            SetupFailureCode::InvalidStateDirectory,
            None,
            format!("setup state directory has no parent: {path:?}"),
        )
    })?;
    std::fs::create_dir_all(parent).map_err(|error| {
        NativeSetupFailure::new(
            SetupStage::StateDirectory,
            SetupFailureCode::DirectoryCreate,
            error.raw_os_error().map(|code| code as u32),
            format!("failed to create setup state parent {parent:?}: {error}"),
        )
    })?;
    let descriptor = security_descriptor(owner_sid, descriptor_kind)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let path_wide = wide_path(path);
    let created = unsafe { CreateDirectoryW(path_wide.as_ptr(), &attributes) };
    if created == 0 {
        let code = unsafe { GetLastError() };
        if code != ERROR_ALREADY_EXISTS {
            return Err(NativeSetupFailure::new(
                SetupStage::StateDirectory,
                SetupFailureCode::DirectoryCreate,
                Some(code),
                format!("failed to create protected setup state directory {path:?}"),
            ));
        }
    }
    apply_descriptor(path, &descriptor)?;
    verify_descriptor(path, owner_sid, descriptor_kind)
}

#[allow(unsafe_code)]
pub(super) fn create_protected_file(path: &Path, owner_sid: &str) -> NativeSetupResult<File> {
    create_file_with_descriptor(
        path,
        owner_sid,
        &ProtectedDescriptor::OwnerOnly { inherit: false },
    )
}

pub(super) fn verify_owner_file(path: &Path, owner_sid: &str) -> NativeSetupResult<()> {
    verify_descriptor(
        path,
        owner_sid,
        &ProtectedDescriptor::OwnerOnly { inherit: false },
    )
}

#[allow(unsafe_code)]
pub(super) fn create_runner_executable(
    path: &Path,
    owner_sid: &str,
    group_sid: &str,
) -> NativeSetupResult<File> {
    create_file_with_descriptor(
        path,
        owner_sid,
        &ProtectedDescriptor::RunnerExecutable { group_sid },
    )
}

#[allow(unsafe_code)]
pub(super) fn create_runner_manifest(
    path: &Path,
    owner_sid: &str,
    group_sid: &str,
) -> NativeSetupResult<File> {
    create_file_with_descriptor(
        path,
        owner_sid,
        &ProtectedDescriptor::RunnerManifest { group_sid },
    )
}

#[allow(unsafe_code)]
fn create_file_with_descriptor(
    path: &Path,
    owner_sid: &str,
    descriptor_kind: &ProtectedDescriptor<'_>,
) -> NativeSetupResult<File> {
    let descriptor = security_descriptor(owner_sid, descriptor_kind)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let path_wide = wide_path(path);
    let handle = unsafe {
        CreateFileW(
            path_wide.as_ptr(),
            GENERIC_WRITE | READ_CONTROL,
            0,
            &attributes,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(last_error(
            SetupStage::Credentials,
            SetupFailureCode::CredentialAcl,
            format!("failed to create protected setup file {path:?}"),
        ));
    }
    let file = unsafe { File::from_raw_handle(handle as RawHandle) };
    apply_descriptor(path, &descriptor)?;
    verify_file_descriptor(path, &file, owner_sid, descriptor_kind)?;
    Ok(file)
}

#[allow(unsafe_code)]
fn security_descriptor(
    owner_sid: &str,
    descriptor_kind: &ProtectedDescriptor<'_>,
) -> NativeSetupResult<LocalSecurityDescriptor> {
    let sddl = match descriptor_kind {
        ProtectedDescriptor::OwnerOnly { inherit } => {
            let inheritance = if *inherit { "OICI" } else { "" };
            format!(
                "O:{owner_sid}D:P(A;{inheritance};GA;;;SY)(A;{inheritance};GA;;;BA)(A;{inheritance};GA;;;{owner_sid})"
            )
        }
        ProtectedDescriptor::RunnerDirectory { group_sid }
        | ProtectedDescriptor::RunnerExecutable { group_sid } => {
            format!(
                "O:{owner_sid}D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{owner_sid})(A;;GRGX;;;{group_sid})"
            )
        }
        ProtectedDescriptor::RunnerManifest { group_sid } => {
            format!(
                "O:{owner_sid}D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{owner_sid})(A;;GR;;;{group_sid})"
            )
        }
    };
    let sddl_wide = wide(&sddl);
    let mut descriptor = std::ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl_wide.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(last_error(
            SetupStage::StateDirectory,
            SetupFailureCode::DirectoryAcl,
            "failed to construct the protected setup DACL",
        ));
    }
    Ok(LocalSecurityDescriptor(descriptor))
}

#[allow(unsafe_code)]
fn apply_descriptor(path: &Path, descriptor: &LocalSecurityDescriptor) -> NativeSetupResult<()> {
    let mut owner = std::ptr::null_mut();
    let mut owner_defaulted = 0;
    if unsafe { GetSecurityDescriptorOwner(descriptor.0, &mut owner, &mut owner_defaulted) } == 0
        || owner.is_null()
    {
        return Err(last_error(
            SetupStage::StateDirectory,
            SetupFailureCode::DirectoryAcl,
            "failed to extract the protected setup owner",
        ));
    }
    let mut present = 0;
    let mut defaulted = 0;
    let mut dacl = std::ptr::null_mut();
    if unsafe { GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut dacl, &mut defaulted) }
        == 0
        || present == 0
        || dacl.is_null()
    {
        return Err(last_error(
            SetupStage::StateDirectory,
            SetupFailureCode::DirectoryAcl,
            "failed to extract the protected setup DACL",
        ));
    }
    let path_wide = wide_path(path);
    let status = unsafe {
        windows_sys::Win32::Security::Authorization::SetNamedSecurityInfoW(
            path_wide.as_ptr().cast_mut(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION,
            owner,
            std::ptr::null_mut(),
            dacl,
            std::ptr::null(),
        )
    };
    if status != 0 {
        return Err(NativeSetupFailure::new(
            SetupStage::StateDirectory,
            SetupFailureCode::DirectoryAcl,
            Some(status),
            format!("failed to apply protected DACL to {path:?}"),
        ));
    }
    Ok(())
}

#[allow(unsafe_code)]
fn verify_descriptor(
    path: &Path,
    owner_sid: &str,
    descriptor_kind: &ProtectedDescriptor<'_>,
) -> NativeSetupResult<()> {
    let path_wide = wide_path(path);
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
        return Err(NativeSetupFailure::new(
            SetupStage::StateDirectory,
            SetupFailureCode::DirectoryAcl,
            Some(status),
            format!("failed to read back protected DACL from {path:?}"),
        ));
    }
    verify_descriptor_value(
        path,
        LocalSecurityDescriptor(descriptor),
        owner_sid,
        descriptor_kind,
    )
}

#[allow(unsafe_code)]
fn verify_file_descriptor(
    path: &Path,
    file: &File,
    owner_sid: &str,
    descriptor_kind: &ProtectedDescriptor<'_>,
) -> NativeSetupResult<()> {
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
        return Err(NativeSetupFailure::new(
            SetupStage::StateDirectory,
            SetupFailureCode::DirectoryAcl,
            Some(status),
            format!("failed to read back protected file DACL from {path:?}"),
        ));
    }
    verify_descriptor_value(
        path,
        LocalSecurityDescriptor(descriptor),
        owner_sid,
        descriptor_kind,
    )
}

#[allow(unsafe_code)]
fn verify_descriptor_value(
    path: &Path,
    descriptor: LocalSecurityDescriptor,
    owner_sid: &str,
    descriptor_kind: &ProtectedDescriptor<'_>,
) -> NativeSetupResult<()> {
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
        return Err(last_error(
            SetupStage::StateDirectory,
            SetupFailureCode::DirectoryAcl,
            format!("failed to format protected DACL from {path:?}"),
        ));
    }
    let value = LocalWideString(value);
    let actual = wide_pointer_to_string(value.0);
    if !protected_descriptor_matches(descriptor.0, owner_sid, descriptor_kind) {
        return Err(NativeSetupFailure::new(
            SetupStage::StateDirectory,
            SetupFailureCode::DirectoryAcl,
            None,
            format!("protected DACL read-back mismatch for {path:?}: {actual}"),
        ));
    }
    Ok(())
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
    let value = wide(sid);
    let mut parsed = std::ptr::null_mut();
    if unsafe {
        windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW(
            value.as_ptr(),
            &mut parsed,
        )
    } == 0
    {
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
fn last_error(
    stage: SetupStage,
    code: SetupFailureCode,
    detail: impl Into<String>,
) -> NativeSetupFailure {
    NativeSetupFailure::new(stage, code, Some(unsafe { GetLastError() }), detail)
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn wide_path(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
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
