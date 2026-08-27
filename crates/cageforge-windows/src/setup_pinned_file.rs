// SPDX-License-Identifier: Apache-2.0

//! Handle-pinned setup files for the elevated helper crate root.

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
    CreateFileW, DELETE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_ATTRIBUTE_TAG_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_GENERIC_READ, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FileAttributeTagInfo, GetFileInformationByHandleEx, GetFinalPathNameByHandleW,
    GetLongPathNameW, OPEN_EXISTING, READ_CONTROL, VOLUME_NAME_DOS,
};

#[derive(Debug, Error)]
pub(crate) enum SetupPinnedFileError {
    #[error("elevated setup requires an absolute file path: {path:?}")]
    Relative { path: PathBuf },
    #[error("elevated setup rejects parent traversal in file path {path:?}")]
    ParentTraversal { path: PathBuf },
    #[error("elevated setup file path contains NUL: {path:?}")]
    Nul { path: PathBuf },
    #[error("failed to open elevated setup file {path:?}: Windows error {code}")]
    Open { path: PathBuf, code: u32 },
    #[error("failed to inspect elevated setup file attributes {path:?}: Windows error {code}")]
    AttributeRead { path: PathBuf, code: u32 },
    #[error("elevated setup path is a reparse point: {path:?}")]
    ReparsePoint { path: PathBuf },
    #[error("elevated setup directory path is not a directory: {path:?}")]
    NotDirectory { path: PathBuf },
    #[error("failed to resolve elevated setup file handle {path:?}: Windows error {code}")]
    FinalPathRead { path: PathBuf, code: u32 },
    #[error("Windows returned an invalid final elevated setup file path length for {path:?}")]
    FinalPathLength { path: PathBuf },
    #[error("failed to expand an elevated setup file path {path:?}: Windows error {code}")]
    LongPathRead { path: PathBuf, code: u32 },
    #[error("Windows returned an invalid expanded elevated setup path length for {path:?}")]
    LongPathLength { path: PathBuf },
    #[error(
        "elevated setup file handle resolves outside its requested path: requested {requested:?}, final {final_path:?}"
    )]
    FinalPathMismatch {
        requested: PathBuf,
        final_path: PathBuf,
    },
}

pub(crate) fn open_for_readback(path: &Path) -> Result<File, SetupPinnedFileError> {
    open_existing(
        path,
        READ_CONTROL | FILE_GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
    )
}

pub(crate) fn open_for_cleanup(path: &Path) -> Result<File, SetupPinnedFileError> {
    open_existing(
        path,
        READ_CONTROL | FILE_GENERIC_READ | DELETE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
    )
}

pub(crate) fn open_directory_for_pin(path: &Path) -> Result<File, SetupPinnedFileError> {
    open_checked(
        path,
        READ_CONTROL | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        true,
    )
}

#[allow(unsafe_code)]
fn open_existing(path: &Path, access: u32, share_mode: u32) -> Result<File, SetupPinnedFileError> {
    open_checked(path, access, share_mode, false)
}

#[allow(unsafe_code)]
fn open_checked(
    path: &Path,
    access: u32,
    share_mode: u32,
    require_directory: bool,
) -> Result<File, SetupPinnedFileError> {
    validate_lexical_path(path)?;
    let path_wide = wide_path(path);
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
        return Err(SetupPinnedFileError::Open {
            path: path.to_path_buf(),
            code: unsafe { GetLastError() },
        });
    }
    let handle = unsafe { OwnedHandle::from_raw_handle(handle as RawHandle) };
    reject_reparse_point(path, handle.as_raw_handle() as _, require_directory)?;
    let final_path = final_path(path, handle.as_raw_handle() as _)?;
    let expanded_path = long_path(path)?;
    if !paths_equal(&expanded_path, &final_path) {
        return Err(SetupPinnedFileError::FinalPathMismatch {
            requested: path.to_path_buf(),
            final_path,
        });
    }
    Ok(File::from(handle))
}

fn validate_lexical_path(path: &Path) -> Result<(), SetupPinnedFileError> {
    if !path.is_absolute() {
        return Err(SetupPinnedFileError::Relative {
            path: path.to_path_buf(),
        });
    }
    if contains_parent_traversal(path) {
        return Err(SetupPinnedFileError::ParentTraversal {
            path: path.to_path_buf(),
        });
    }
    if path.as_os_str().encode_wide().any(|value| value == 0) {
        return Err(SetupPinnedFileError::Nul {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

#[allow(unsafe_code)]
fn reject_reparse_point(
    path: &Path,
    handle: windows_sys::Win32::Foundation::HANDLE,
    require_directory: bool,
) -> Result<(), SetupPinnedFileError> {
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
        return Err(SetupPinnedFileError::AttributeRead {
            path: path.to_path_buf(),
            code: unsafe { GetLastError() },
        });
    }
    if attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(SetupPinnedFileError::ReparsePoint {
            path: path.to_path_buf(),
        });
    }
    if require_directory && attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
        return Err(SetupPinnedFileError::NotDirectory {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

#[allow(unsafe_code)]
fn final_path(
    requested: &Path,
    handle: windows_sys::Win32::Foundation::HANDLE,
) -> Result<PathBuf, SetupPinnedFileError> {
    let required =
        unsafe { GetFinalPathNameByHandleW(handle, std::ptr::null_mut(), 0, VOLUME_NAME_DOS) };
    if required == 0 {
        return Err(SetupPinnedFileError::FinalPathRead {
            path: requested.to_path_buf(),
            code: unsafe { GetLastError() },
        });
    }
    let capacity =
        required
            .checked_add(1)
            .ok_or_else(|| SetupPinnedFileError::FinalPathLength {
                path: requested.to_path_buf(),
            })?;
    let mut buffer = vec![0u16; capacity as usize];
    let length = unsafe {
        GetFinalPathNameByHandleW(handle, buffer.as_mut_ptr(), capacity, VOLUME_NAME_DOS)
    };
    if length == 0 {
        return Err(SetupPinnedFileError::FinalPathRead {
            path: requested.to_path_buf(),
            code: unsafe { GetLastError() },
        });
    }
    if length >= capacity {
        return Err(SetupPinnedFileError::FinalPathLength {
            path: requested.to_path_buf(),
        });
    }
    buffer.truncate(length as usize);
    Ok(PathBuf::from(OsString::from_wide(&buffer)))
}

#[allow(unsafe_code)]
fn long_path(path: &Path) -> Result<PathBuf, SetupPinnedFileError> {
    let input = wide_path(path);
    let required = unsafe { GetLongPathNameW(input.as_ptr(), std::ptr::null_mut(), 0) };
    if required == 0 {
        return Err(SetupPinnedFileError::LongPathRead {
            path: path.to_path_buf(),
            code: unsafe { GetLastError() },
        });
    }
    let mut buffer = vec![0; required as usize];
    let length = unsafe { GetLongPathNameW(input.as_ptr(), buffer.as_mut_ptr(), required) };
    if length == 0 {
        return Err(SetupPinnedFileError::LongPathRead {
            path: path.to_path_buf(),
            code: unsafe { GetLastError() },
        });
    }
    if length >= required {
        return Err(SetupPinnedFileError::LongPathLength {
            path: path.to_path_buf(),
        });
    }
    buffer.truncate(length as usize);
    Ok(PathBuf::from(OsString::from_wide(&buffer)))
}

fn wide_path(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}
