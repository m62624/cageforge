// SPDX-License-Identifier: Apache-2.0

//! macOS runtime paths that belong to the native Seatbelt baseline.

use std::path::Path;

use cageforge_path::is_within;

/// System command roots made executable by the fixed Seatbelt baseline.
pub(crate) const FIXED_EXECUTABLE_ROOTS: &[&str] =
    &["/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/libexec"];

/// Returns whether a program is covered by the fixed native baseline.
pub(crate) fn is_fixed_executable(path: &Path) -> bool {
    FIXED_EXECUTABLE_ROOTS
        .iter()
        .map(Path::new)
        .any(|root| is_within(path, root))
}
