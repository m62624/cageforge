// Copyright 2026 Mansur Azatbek
// SPDX-License-Identifier: Apache-2.0

//! Shared native path comparison primitives for Cageforge.
//!
//! These helpers are lexical only. They do not inspect the filesystem or
//! resolve symlinks; a native backend must perform those operations when its
//! enforcement model requires them.

#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

use std::path::{Component, Path};

/// Returns whether a path contains a lexical parent traversal component.
pub fn contains_parent_traversal(path: &Path) -> bool {
    path.components()
        .any(|component| component == Component::ParentDir)
}

/// Compares two complete paths using the target platform's path case rules.
pub fn paths_equal(left: &Path, right: &Path) -> bool {
    let mut left = left.components();
    let mut right = right.components();
    loop {
        match (left.next(), right.next()) {
            (None, None) => return true,
            (Some(left), Some(right)) if components_equal(left, right) => {}
            _ => return false,
        }
    }
}

/// Returns whether `path` is the same as or below `root` by path component.
pub fn is_within(path: &Path, root: &Path) -> bool {
    let mut path = path.components();
    let mut root = root.components();
    loop {
        match (root.next(), path.next()) {
            (None, _) => return true,
            (Some(root), Some(path)) if components_equal(path, root) => {}
            (Some(_), _) => return false,
        }
    }
}

/// Compares two path components with the target platform's path case rules.
pub fn components_equal(left: Component<'_>, right: Component<'_>) -> bool {
    #[cfg(windows)]
    {
        strings_equal(
            &left.as_os_str().to_string_lossy(),
            &right.as_os_str().to_string_lossy(),
        )
    }
    #[cfg(not(windows))]
    {
        left == right
    }
}

/// Compares path-component strings with the target platform's path case rules.
pub fn strings_equal(left: &str, right: &str) -> bool {
    #[cfg(windows)]
    {
        case_fold(left) == case_fold(right)
    }
    #[cfg(not(windows))]
    {
        left == right
    }
}

/// Folds a string using the target platform's path comparison case rules.
pub fn case_fold(value: &str) -> String {
    #[cfg(windows)]
    {
        value.to_lowercase()
    }
    #[cfg(not(windows))]
    {
        value.to_owned()
    }
}
