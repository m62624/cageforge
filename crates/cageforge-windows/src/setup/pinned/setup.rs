// SPDX-License-Identifier: Apache-2.0

//! Handle-pinned setup directory access shared by setup and runtime verification.

use std::fs::File;
use std::path::Path;

use windows_sys::Win32::Storage::FileSystem::{
    FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL,
};

use crate::setup_pinned_file::{self, SetupPinnedFileError};

pub(crate) fn open_for_pin(path: &Path) -> Result<File, SetupPinnedFileError> {
    setup_pinned_file::open_with_options(
        path,
        READ_CONTROL | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        true,
        true,
    )
}
