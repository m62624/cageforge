// SPDX-License-Identifier: Apache-2.0

use std::ffi::c_void;
use std::fs::File;
use std::io::Write;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, RawHandle};
use std::path::{Component, Path, PathBuf};

use cageforge_path::paths_equal;
use getrandom::fill;
use windows_sys::Win32::Foundation::{
    ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS, GENERIC_ALL, GENERIC_WRITE, GetLastError, HLOCAL,
    INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
    SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, EqualSid, GetAce,
    GetSecurityDescriptorControl, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner,
    INHERIT_ONLY_ACE, IsValidSecurityDescriptor, IsValidSid, OBJECT_INHERIT_ACE,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SE_DACL_PROTECTED, SECURITY_ATTRIBUTES,
    TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
};
use windows_sys::Win32::Storage::FileSystem::{
    CREATE_NEW, CreateDirectoryW, CreateFileW, DELETE, FILE_ALL_ACCESS, FILE_ATTRIBUTE_NORMAL,
    FILE_DISPOSITION_INFO, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ,
    FILE_SHARE_DELETE, FileDispositionInfo, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    MoveFileExW, READ_CONTROL, SetFileInformationByHandle,
};
use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::setup_protocol::{SetupFailureCode, SetupRequest, SetupStage};

use super::{NativeSetupFailure, NativeSetupResult};

struct LocalSecurityDescriptor(PSECURITY_DESCRIPTOR);

struct LocalWideString(*mut u16);

struct LocalSid(*mut c_void);

struct PendingProtectedFile {
    file: File,
    path: PathBuf,
    delete_on_drop: bool,
}

pub(super) struct ProtectedFileWriteContext {
    stage: SetupStage,
    acl_code: SetupFailureCode,
    write_code: SetupFailureCode,
    label: &'static str,
}

enum ProtectedDescriptor<'a> {
    SharedStateDirectory,
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
impl Drop for PendingProtectedFile {
    fn drop(&mut self) {
        if self.delete_on_drop {
            let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
            unsafe {
                SetFileInformationByHandle(
                    self.file.as_raw_handle() as _,
                    FileDispositionInfo,
                    (&raw const disposition).cast(),
                    size_of::<FILE_DISPOSITION_INFO>() as u32,
                );
            }
        }
    }
}

impl ProtectedFileWriteContext {
    pub(super) const fn new(
        stage: SetupStage,
        acl_code: SetupFailureCode,
        write_code: SetupFailureCode,
        label: &'static str,
    ) -> Self {
        Self {
            stage,
            acl_code,
            write_code,
            label,
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
    let default = crate::setup_state_path::default_state_directory(owner_sid).map_err(|code| {
        NativeSetupFailure::new(
            SetupStage::StateDirectory,
            SetupFailureCode::InvalidStateDirectory,
            Some(code as u32),
            "failed to resolve the system ProgramData directory in the elevated helper",
        )
    })?;
    if paths_equal(path, &default) {
        prepare_default_state_directory(path, owner_sid)
    } else {
        prepare_explicit_state_directory(path, owner_sid)
    }
}

#[allow(unsafe_code)]
pub(super) fn prepare_runner_directory(
    path: &Path,
    owner_sid: &str,
    group_sid: &str,
) -> NativeSetupResult<()> {
    prepare_child_directory(
        path,
        owner_sid,
        &ProtectedDescriptor::RunnerDirectory { group_sid },
    )
}

#[allow(unsafe_code)]
fn prepare_default_state_directory(path: &Path, owner_sid: &str) -> NativeSetupResult<()> {
    let program_data = crate::setup_state_path::program_data_directory().map_err(|code| {
        NativeSetupFailure::new(
            SetupStage::StateDirectory,
            SetupFailureCode::InvalidStateDirectory,
            Some(code as u32),
            "failed to resolve the system ProgramData directory in the elevated helper",
        )
    })?;
    let mut pinned = pin_existing_directory_chain(&program_data)?;
    let cageforge = program_data.join("Cageforge");
    pinned.push(create_or_verify_directory(
        &cageforge,
        owner_sid,
        &ProtectedDescriptor::SharedStateDirectory,
    )?);
    let sandbox = cageforge.join("windows-sandbox");
    pinned.push(create_or_verify_directory(
        &sandbox,
        owner_sid,
        &ProtectedDescriptor::SharedStateDirectory,
    )?);
    pinned.push(create_or_verify_directory(
        path,
        owner_sid,
        &ProtectedDescriptor::OwnerOnly { inherit: true },
    )?);
    Ok(())
}

fn prepare_explicit_state_directory(path: &Path, owner_sid: &str) -> NativeSetupResult<()> {
    let base = path.parent().ok_or_else(|| {
        NativeSetupFailure::new(
            SetupStage::StateDirectory,
            SetupFailureCode::InvalidStateDirectory,
            None,
            format!("explicit setup state directory has no base: {path:?}"),
        )
    })?;
    let mut pinned = match std::fs::symlink_metadata(base) {
        Ok(_) => pin_existing_directory_chain(base)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = base.parent().ok_or_else(|| {
                NativeSetupFailure::new(
                    SetupStage::StateDirectory,
                    SetupFailureCode::InvalidStateDirectory,
                    None,
                    format!("explicit setup state base has no parent: {base:?}"),
                )
            })?;
            let mut pinned = pin_existing_directory_chain(parent)?;
            pinned.push(create_or_verify_directory(
                base,
                owner_sid,
                &ProtectedDescriptor::OwnerOnly { inherit: true },
            )?);
            pinned
        }
        Err(error) => {
            return Err(NativeSetupFailure::new(
                SetupStage::StateDirectory,
                SetupFailureCode::InvalidStateDirectory,
                error.raw_os_error().map(|code| code as u32),
                format!("failed to inspect explicit setup state base {base:?}: {error}"),
            ));
        }
    };
    pinned.push(create_or_verify_directory(
        path,
        owner_sid,
        &ProtectedDescriptor::OwnerOnly { inherit: true },
    )?);
    Ok(())
}

fn prepare_child_directory(
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
    let _pinned_ancestors = pin_existing_directory_chain(parent)?;
    create_or_verify_directory(path, owner_sid, descriptor_kind).map(|_| ())
}

fn pin_existing_directory_chain(path: &Path) -> NativeSetupResult<Vec<File>> {
    let mut ancestors = path
        .ancestors()
        .filter(|ancestor| !ancestor.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .collect::<Vec<_>>();
    ancestors.reverse();
    let mut pinned = Vec::with_capacity(ancestors.len());
    for ancestor in ancestors {
        let directory =
            crate::setup_pinned_directory::open_for_pin(&ancestor).map_err(|error| {
                NativeSetupFailure::new(
                    SetupStage::StateDirectory,
                    SetupFailureCode::InvalidStateDirectory,
                    None,
                    format!("setup directory chain is unsafe at {ancestor:?}: {error}"),
                )
            })?;
        pinned.push(directory);
    }
    Ok(pinned)
}

#[allow(unsafe_code)]
fn create_or_verify_directory(
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
    let created = unsafe { CreateDirectoryW(path_wide.as_ptr(), &attributes) };
    if created == 0 {
        let code = unsafe { GetLastError() };
        if code != ERROR_ALREADY_EXISTS {
            return Err(NativeSetupFailure::new(
                SetupStage::StateDirectory,
                SetupFailureCode::DirectoryCreate,
                Some(code),
                format!("failed to create protected setup directory {path:?}"),
            ));
        }
    }
    let directory = crate::setup_pinned_directory::open_for_pin(path).map_err(|error| {
        NativeSetupFailure::new(
            SetupStage::StateDirectory,
            SetupFailureCode::InvalidStateDirectory,
            None,
            format!("protected setup directory is unsafe at {path:?}: {error}"),
        )
    })?;
    verify_file_descriptor(path, &directory, owner_sid, descriptor_kind)?;
    Ok(directory)
}

pub(super) fn replace_owner_file(
    path: &Path,
    owner_sid: &str,
    bytes: &[u8],
    context: ProtectedFileWriteContext,
) -> NativeSetupResult<()> {
    replace_file_with_descriptor(
        path,
        owner_sid,
        &ProtectedDescriptor::OwnerOnly { inherit: false },
        bytes,
        &context,
    )
}

#[allow(unsafe_code)]
pub(super) fn create_new_protected_file(path: &Path, owner_sid: &str) -> NativeSetupResult<File> {
    create_file_with_descriptor(
        path,
        owner_sid,
        &ProtectedDescriptor::OwnerOnly { inherit: false },
        CREATE_NEW,
    )
}

pub(super) fn verify_owner_file(path: &Path, owner_sid: &str) -> NativeSetupResult<()> {
    let file = crate::setup_pinned_file::open_for_readback(path).map_err(|error| {
        NativeSetupFailure::new(
            SetupStage::StateDirectory,
            SetupFailureCode::DirectoryAcl,
            None,
            format!("protected setup file path is unsafe at {path:?}: {error}"),
        )
    })?;
    verify_file_descriptor(
        path,
        &file,
        owner_sid,
        &ProtectedDescriptor::OwnerOnly { inherit: false },
    )
}

pub(super) fn replace_runner_executable(
    path: &Path,
    owner_sid: &str,
    group_sid: &str,
    bytes: &[u8],
    context: ProtectedFileWriteContext,
) -> NativeSetupResult<()> {
    replace_file_with_descriptor(
        path,
        owner_sid,
        &ProtectedDescriptor::RunnerExecutable { group_sid },
        bytes,
        &context,
    )
}

pub(super) fn replace_runner_manifest(
    path: &Path,
    owner_sid: &str,
    group_sid: &str,
    bytes: &[u8],
    context: ProtectedFileWriteContext,
) -> NativeSetupResult<()> {
    replace_file_with_descriptor(
        path,
        owner_sid,
        &ProtectedDescriptor::RunnerManifest { group_sid },
        bytes,
        &context,
    )
}

#[allow(unsafe_code)]
fn replace_file_with_descriptor(
    path: &Path,
    owner_sid: &str,
    descriptor_kind: &ProtectedDescriptor<'_>,
    bytes: &[u8],
    context: &ProtectedFileWriteContext,
) -> NativeSetupResult<()> {
    let parent = path.parent().ok_or_else(|| {
        NativeSetupFailure::new(
            context.stage,
            context.acl_code,
            None,
            format!("{} path has no parent: {path:?}", context.label),
        )
    })?;
    let _pinned_ancestors = pin_existing_directory_chain(parent).map_err(|failure| {
        NativeSetupFailure::new(
            context.stage,
            context.acl_code,
            failure.native_code,
            failure.detail,
        )
    })?;
    let mut pending = create_pending_file(parent, owner_sid, descriptor_kind, context)?;
    pending.file.write_all(bytes).map_err(|error| {
        NativeSetupFailure::new(
            context.stage,
            context.write_code,
            error.raw_os_error().map(|code| code as u32),
            format!("failed to write staged {} {path:?}: {error}", context.label),
        )
    })?;
    pending.file.sync_all().map_err(|error| {
        NativeSetupFailure::new(
            context.stage,
            context.write_code,
            error.raw_os_error().map(|code| code as u32),
            format!("failed to flush staged {} {path:?}: {error}", context.label),
        )
    })?;
    let temporary_wide = wide_path(&pending.path);
    let destination_wide = wide_path(path);
    if unsafe {
        MoveFileExW(
            temporary_wide.as_ptr(),
            destination_wide.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        return Err(NativeSetupFailure::new(
            context.stage,
            context.write_code,
            Some(unsafe { GetLastError() }),
            format!("failed to atomically replace {} {path:?}", context.label),
        ));
    }
    crate::setup_pinned_mutation::verify_open_file_path(path, &pending.file).map_err(|error| {
        NativeSetupFailure::new(
            context.stage,
            context.acl_code,
            None,
            format!(
                "replaced {} path is unsafe at {path:?}: {error}",
                context.label
            ),
        )
    })?;
    verify_file_descriptor(path, &pending.file, owner_sid, descriptor_kind).map_err(|failure| {
        NativeSetupFailure::new(
            context.stage,
            context.acl_code,
            failure.native_code,
            failure.detail,
        )
    })?;
    pending.delete_on_drop = false;
    Ok(())
}

fn create_pending_file(
    parent: &Path,
    owner_sid: &str,
    descriptor_kind: &ProtectedDescriptor<'_>,
    context: &ProtectedFileWriteContext,
) -> NativeSetupResult<PendingProtectedFile> {
    for _ in 0..16 {
        let mut nonce = [0u8; 16];
        fill(&mut nonce).map_err(|error| {
            NativeSetupFailure::new(
                context.stage,
                context.write_code,
                None,
                format!("failed to generate staged {} name: {error}", context.label),
            )
        })?;
        let suffix = nonce
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let temporary_path = parent.join(format!(".cageforge-{suffix}.tmp"));
        match create_file_with_descriptor(&temporary_path, owner_sid, descriptor_kind, CREATE_NEW) {
            Ok(file) => {
                return Ok(PendingProtectedFile {
                    file,
                    path: temporary_path,
                    delete_on_drop: true,
                });
            }
            Err(failure)
                if matches!(
                    failure.native_code,
                    Some(ERROR_FILE_EXISTS) | Some(ERROR_ALREADY_EXISTS)
                ) => {}
            Err(failure) => {
                return Err(NativeSetupFailure::new(
                    context.stage,
                    context.acl_code,
                    failure.native_code,
                    failure.detail,
                ));
            }
        }
    }
    Err(NativeSetupFailure::new(
        context.stage,
        context.write_code,
        None,
        format!(
            "failed to reserve a unique staged {} name after 16 cryptographic attempts",
            context.label
        ),
    ))
}

#[allow(unsafe_code)]
fn create_file_with_descriptor(
    path: &Path,
    owner_sid: &str,
    descriptor_kind: &ProtectedDescriptor<'_>,
    creation_disposition: u32,
) -> NativeSetupResult<File> {
    let parent = path.parent().ok_or_else(|| {
        NativeSetupFailure::new(
            SetupStage::StateDirectory,
            SetupFailureCode::InvalidStateDirectory,
            None,
            format!("protected setup file has no parent: {path:?}"),
        )
    })?;
    let _pinned_ancestors = pin_existing_directory_chain(parent)?;
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
            GENERIC_WRITE | READ_CONTROL | DELETE,
            FILE_SHARE_DELETE,
            &attributes,
            creation_disposition,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
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
    crate::setup_pinned_mutation::verify_open_file_path(path, &file).map_err(|error| {
        NativeSetupFailure::new(
            SetupStage::StateDirectory,
            SetupFailureCode::CredentialAcl,
            None,
            format!("protected setup file path is unsafe at {path:?}: {error}"),
        )
    })?;
    verify_file_descriptor(path, &file, owner_sid, descriptor_kind)?;
    Ok(file)
}

#[allow(unsafe_code)]
fn security_descriptor(
    owner_sid: &str,
    descriptor_kind: &ProtectedDescriptor<'_>,
) -> NativeSetupResult<LocalSecurityDescriptor> {
    let sddl = match descriptor_kind {
        ProtectedDescriptor::SharedStateDirectory => {
            "O:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGX;;;AU)".to_string()
        }
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
    let expected_owner_sid = match descriptor_kind {
        ProtectedDescriptor::SharedStateDirectory => "S-1-5-32-544",
        ProtectedDescriptor::OwnerOnly { .. }
        | ProtectedDescriptor::RunnerDirectory { .. }
        | ProtectedDescriptor::RunnerExecutable { .. }
        | ProtectedDescriptor::RunnerManifest { .. } => owner_sid,
    };
    let Some(expected_owner) = local_sid(expected_owner_sid) else {
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
        ProtectedDescriptor::SharedStateDirectory => vec![
            ("S-1-5-18".to_string(), 0, FILE_ALL_ACCESS),
            ("S-1-5-32-544".to_string(), 0, FILE_ALL_ACCESS),
            (
                "S-1-5-11".to_string(),
                0,
                FILE_GENERIC_READ | FILE_GENERIC_EXECUTE,
            ),
        ],
        ProtectedDescriptor::OwnerOnly { .. }
        | ProtectedDescriptor::RunnerDirectory { .. }
        | ProtectedDescriptor::RunnerExecutable { .. }
        | ProtectedDescriptor::RunnerManifest { .. } => principals
            .iter()
            .map(|sid| ((*sid).to_string(), 0u8, FILE_ALL_ACCESS))
            .collect::<Vec<_>>(),
    };
    match descriptor_kind {
        ProtectedDescriptor::SharedStateDirectory => {}
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
