// SPDX-License-Identifier: Apache-2.0

//! Elevated setup operations on handle-pinned protected paths.

use std::fs::File;
use std::os::windows::io::AsRawHandle;
use std::path::Path;

use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_GENERIC_READ, FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL,
};

use crate::setup_pinned_file::{self, SetupPinnedFileError};

pub(crate) fn open_for_cleanup(path: &Path) -> Result<File, SetupPinnedFileError> {
    setup_pinned_file::open_with_options(
        path,
        READ_CONTROL | FILE_GENERIC_READ | DELETE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        false,
        true,
    )
}

pub(crate) fn verify_open_file_path(path: &Path, file: &File) -> Result<(), SetupPinnedFileError> {
    setup_pinned_file::verify_open_path(path, file.as_raw_handle() as _, false)
}
