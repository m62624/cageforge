// SPDX-License-Identifier: Apache-2.0

//! Handle-pinned Windows filesystem paths for ACL enforcement.

use std::ffi::OsString;
use std::fs::File;
use std::mem::size_of;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::path::{Path, PathBuf};

use cageforge_path::{contains_parent_traversal, paths_equal};
use thiserror::Error;
use windows_sys::Win32::Foundation::{GetLastError, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, DELETE, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FileAttributeTagInfo, GetFileInformationByHandleEx,
    GetFinalPathNameByHandleW, GetLongPathNameW, OPEN_EXISTING, READ_CONTROL, VOLUME_NAME_DOS,
    WRITE_DAC,
};

pub(crate) struct ValidatedPath {
    handle: OwnedHandle,
    final_path: PathBuf,
    identity: FilesystemObjectIdentity,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct FilesystemObjectIdentity {
    volume_serial_number: u64,
    file_id: [u8; 16],
}

#[derive(Debug, Error)]
pub(crate) enum ValidatedPathError {
    #[error("Windows filesystem enforcement requires an absolute path: {path:?}")]
    Relative { path: PathBuf },
    #[error("Windows filesystem enforcement rejects parent traversal in {path:?}")]
    ParentTraversal { path: PathBuf },
    #[error("Windows filesystem path contains NUL: {path:?}")]
    Nul { path: PathBuf },
    #[error("failed to open Windows filesystem path {path:?}: Windows error {code}")]
    Open { path: PathBuf, code: u32 },
    #[error("failed to inspect reparse metadata for {path:?}: Windows error {code}")]
    AttributeRead { path: PathBuf, code: u32 },
    #[error("failed to read the stable filesystem identity for {path:?}: Windows error {code}")]
    ObjectIdentityRead { path: PathBuf, code: u32 },
    #[error("Windows filesystem path is a reparse point and cannot anchor enforcement: {path:?}")]
    ReparsePoint { path: PathBuf },
    #[error("failed to resolve the final handle path for {path:?}: Windows error {code}")]
    FinalPathRead { path: PathBuf, code: u32 },
    #[error("Windows returned an invalid final handle-path length for {path:?}")]
    FinalPathLength { path: PathBuf },
    #[error("failed to expand Windows short names in {path:?}: Windows error {code}")]
    LongPathRead { path: PathBuf, code: u32 },
    #[error("Windows returned an invalid expanded path length for {path:?}")]
    LongPathLength { path: PathBuf },
    #[error(
        "Windows final handle path differs from the requested enforcement path: requested {requested:?}, final {final_path:?}"
    )]
    FinalPathMismatch {
        requested: PathBuf,
        final_path: PathBuf,
    },
}

impl ValidatedPath {
    pub(crate) fn open_for_acl(path: &Path) -> Result<Self, ValidatedPathError> {
        Self::open(
            path,
            READ_CONTROL | WRITE_DAC,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
        )
    }

    pub(crate) fn open_for_readback(path: &Path) -> Result<Self, ValidatedPathError> {
        Self::open(path, READ_CONTROL, FILE_SHARE_READ | FILE_SHARE_WRITE)
    }

    pub(crate) fn open_file_for_readback(path: &Path) -> Result<Self, ValidatedPathError> {
        Self::open(
            path,
            READ_CONTROL | FILE_GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
        )
    }

    pub(crate) fn open_file_for_execution(path: &Path) -> Result<Self, ValidatedPathError> {
        Self::open(path, READ_CONTROL | FILE_GENERIC_READ, FILE_SHARE_READ)
    }

    pub(crate) fn open_for_cleanup(path: &Path) -> Result<Self, ValidatedPathError> {
        Self::open(
            path,
            READ_CONTROL | WRITE_DAC | DELETE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
        )
    }

    pub(crate) fn open_file_for_cleanup(path: &Path) -> Result<Self, ValidatedPathError> {
        Self::open(
            path,
            READ_CONTROL | WRITE_DAC | DELETE | FILE_GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
        )
    }

    pub(crate) fn final_path(&self) -> &Path {
        &self.final_path
    }

    pub(crate) fn raw_handle(&self) -> windows_sys::Win32::Foundation::HANDLE {
        self.handle.as_raw_handle() as _
    }

    pub(crate) fn identity(&self) -> &FilesystemObjectIdentity {
        &self.identity
    }

    pub(crate) fn try_clone_file(&self) -> std::io::Result<File> {
        self.handle.try_clone().map(File::from)
    }

    #[allow(unsafe_code)]
    fn open(path: &Path, access: u32, share_mode: u32) -> Result<Self, ValidatedPathError> {
        validate_lexical_path(path)?;
        let path_wide = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let handle = unsafe {
            CreateFileW(
                path_wide.as_ptr(),
                access,
                share_mode,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(ValidatedPathError::Open {
                path: path.to_path_buf(),
                code: unsafe { GetLastError() },
            });
        }
        let handle = unsafe { OwnedHandle::from_raw_handle(handle as RawHandle) };
        reject_reparse_point(path, handle.as_raw_handle() as _)?;
        let identity = object_identity(path, handle.as_raw_handle() as _)?;
        let final_path = final_path(path, handle.as_raw_handle() as _)?;
        let expanded_path = long_path(path)?;
        if !paths_equal(&expanded_path, &final_path) {
            return Err(ValidatedPathError::FinalPathMismatch {
                requested: path.to_path_buf(),
                final_path,
            });
        }
        Ok(Self {
            handle,
            final_path,
            identity,
        })
    }
}

#[allow(unsafe_code)]
fn long_path(path: &Path) -> Result<PathBuf, ValidatedPathError> {
    let input = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let required = unsafe { GetLongPathNameW(input.as_ptr(), std::ptr::null_mut(), 0) };
    if required == 0 {
        return Err(ValidatedPathError::LongPathRead {
            path: path.to_path_buf(),
            code: unsafe { GetLastError() },
        });
    }
    let mut buffer = vec![0; required as usize];
    let length = unsafe { GetLongPathNameW(input.as_ptr(), buffer.as_mut_ptr(), required) };
    if length == 0 {
        return Err(ValidatedPathError::LongPathRead {
            path: path.to_path_buf(),
            code: unsafe { GetLastError() },
        });
    }
    if length >= required {
        return Err(ValidatedPathError::LongPathLength {
            path: path.to_path_buf(),
        });
    }
    buffer.truncate(length as usize);
    Ok(PathBuf::from(OsString::from_wide(&buffer)))
}

impl FilesystemObjectIdentity {
    pub(crate) const fn volume_serial_number(&self) -> u64 {
        self.volume_serial_number
    }

    pub(crate) const fn file_id(&self) -> &[u8; 16] {
        &self.file_id
    }
}

fn validate_lexical_path(path: &Path) -> Result<(), ValidatedPathError> {
    if !path.is_absolute() {
        return Err(ValidatedPathError::Relative {
            path: path.to_path_buf(),
        });
    }
    if contains_parent_traversal(path) {
        return Err(ValidatedPathError::ParentTraversal {
            path: path.to_path_buf(),
        });
    }
    if path.as_os_str().encode_wide().any(|value| value == 0) {
        return Err(ValidatedPathError::Nul {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

#[allow(unsafe_code)]
fn reject_reparse_point(
    path: &Path,
    handle: windows_sys::Win32::Foundation::HANDLE,
) -> Result<(), ValidatedPathError> {
    let mut attributes = FILE_ATTRIBUTE_TAG_INFO::default();
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileAttributeTagInfo,
            (&raw mut attributes).cast(),
            size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    } == 0
    {
        return Err(ValidatedPathError::AttributeRead {
            path: path.to_path_buf(),
            code: unsafe { GetLastError() },
        });
    }
    if attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        Err(ValidatedPathError::ReparsePoint {
            path: path.to_path_buf(),
        })
    } else {
        Ok(())
    }
}

#[allow(unsafe_code)]
fn object_identity(
    path: &Path,
    handle: windows_sys::Win32::Foundation::HANDLE,
) -> Result<FilesystemObjectIdentity, ValidatedPathError> {
    let mut identity = windows_sys::Win32::Storage::FileSystem::FILE_ID_INFO::default();
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            windows_sys::Win32::Storage::FileSystem::FileIdInfo,
            (&raw mut identity).cast(),
            size_of::<windows_sys::Win32::Storage::FileSystem::FILE_ID_INFO>() as u32,
        )
    } == 0
    {
        return Err(ValidatedPathError::ObjectIdentityRead {
            path: path.to_path_buf(),
            code: unsafe { GetLastError() },
        });
    }
    Ok(FilesystemObjectIdentity {
        volume_serial_number: identity.VolumeSerialNumber,
        file_id: identity.FileId.Identifier,
    })
}

#[allow(unsafe_code)]
fn final_path(
    requested: &Path,
    handle: windows_sys::Win32::Foundation::HANDLE,
) -> Result<PathBuf, ValidatedPathError> {
    let required =
        unsafe { GetFinalPathNameByHandleW(handle, std::ptr::null_mut(), 0, VOLUME_NAME_DOS) };
    if required == 0 {
        return Err(ValidatedPathError::FinalPathRead {
            path: requested.to_path_buf(),
            code: unsafe { GetLastError() },
        });
    }
    let capacity = required
        .checked_add(1)
        .ok_or_else(|| ValidatedPathError::FinalPathLength {
            path: requested.to_path_buf(),
        })?;
    let mut buffer = vec![0u16; capacity as usize];
    let length = unsafe {
        GetFinalPathNameByHandleW(handle, buffer.as_mut_ptr(), capacity, VOLUME_NAME_DOS)
    };
    if length == 0 {
        return Err(ValidatedPathError::FinalPathRead {
            path: requested.to_path_buf(),
            code: unsafe { GetLastError() },
        });
    }
    if length >= capacity {
        return Err(ValidatedPathError::FinalPathLength {
            path: requested.to_path_buf(),
        });
    }
    buffer.truncate(length as usize);
    Ok(PathBuf::from(OsString::from_wide(&buffer)))
}
