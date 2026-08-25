// SPDX-License-Identifier: Apache-2.0

//! Shared native path comparison primitives for Cageforge.
//!
//! These helpers are lexical only. They do not inspect the filesystem or
//! resolve symlinks; a native backend must perform those operations when its
//! enforcement model requires them.
//!
//! # Reading this crate
//!
//! Use [`paths_equal`] and [`is_within`] for direct decisions, and
//! [`NativePathKey`] when the same identity must be stored in a map or set.
//! [`contains_parent_traversal`] validates a lexical input boundary, while
//! [`normalize_lexical_path`] exposes supported Windows aliases. The policy,
//! command, and configuration crates build their higher-level rules on these
//! primitives.

#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

use std::borrow::Cow;
use std::path::{Component, Path, PathBuf};

mod native;

/// A hashable and orderable lexical path identity using native case rules.
///
/// The key is useful when another crate needs a map or set whose identity must
/// agree with [`paths_equal`]. It does not canonicalize the filesystem or
/// resolve links.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NativePathKey(Vec<native::NativeComponentKey>);

impl NativePathKey {
    /// Creates a native lexical key for `path`.
    pub fn new(path: &Path) -> Self {
        let path = normalize_lexical_path(path);
        Self(
            path.components()
                .filter(|component| *component != Component::CurDir)
                .map(native::component_key)
                .collect(),
        )
    }
}

/// Returns whether a path contains a lexical parent traversal component.
pub fn contains_parent_traversal(path: &Path) -> bool {
    path.components()
        .any(|component| component == Component::ParentDir)
}

/// Normalizes lexical aliases that the target platform treats as the same path.
///
/// This removes current-directory components without resolving parent
/// traversal. On Windows it also converts supported verbatim/device drive and
/// UNC prefixes to their ordinary spelling. Unsupported device namespaces are
/// otherwise preserved. The function performs no filesystem I/O.
pub fn normalize_lexical_path(path: &Path) -> Cow<'_, Path> {
    #[cfg(windows)]
    let path = native::normalize_windows_device_path(path);
    #[cfg(not(windows))]
    let path = Cow::Borrowed(path);

    let normalized = path
        .components()
        .filter(|component| *component != Component::CurDir)
        .collect::<PathBuf>();
    if normalized.as_os_str() == path.as_os_str() {
        path
    } else {
        Cow::Owned(normalized)
    }
}

/// Compares two complete paths using the target platform's path case rules.
pub fn paths_equal(left: &Path, right: &Path) -> bool {
    #[cfg(windows)]
    {
        NativePathKey::new(left) == NativePathKey::new(right)
    }
    #[cfg(not(windows))]
    let mut left = left
        .components()
        .filter(|component| *component != Component::CurDir);
    #[cfg(not(windows))]
    let mut right = right
        .components()
        .filter(|component| *component != Component::CurDir);
    #[cfg(not(windows))]
    loop {
        match (left.next(), right.next()) {
            (None, None) => return true,
            (Some(left), Some(right)) if components_equal(left, right) => {}
            _ => return false,
        }
    }
}

/// Returns whether `path` is the same as or below `root` by path component.
///
/// Parent traversal fails closed. An empty or current-directory relative root
/// contains relative descendants, but never an absolute or drive-qualified
/// path.
pub fn is_within(path: &Path, root: &Path) -> bool {
    if contains_parent_traversal(path) || contains_parent_traversal(root) {
        return false;
    }
    #[cfg(windows)]
    {
        let path = NativePathKey::new(path);
        let root = NativePathKey::new(root);
        if root.0.is_empty() {
            return !matches!(
                path.0.first(),
                Some(native::NativeComponentKey::Prefix(_) | native::NativeComponentKey::RootDir)
            );
        }
        path.0.starts_with(&root.0)
    }
    #[cfg(not(windows))]
    let mut path = path
        .components()
        .filter(|component| *component != Component::CurDir);
    #[cfg(not(windows))]
    let mut root = root
        .components()
        .filter(|component| *component != Component::CurDir);
    #[cfg(not(windows))]
    if root.clone().next().is_none() {
        return path.clone().next() != Some(Component::RootDir);
    }
    #[cfg(not(windows))]
    loop {
        match (root.next(), path.next()) {
            (None, _) => return true,
            (Some(root), Some(path)) if components_equal(path, root) => {}
            (Some(_), _) => return false,
        }
    }
}

/// Returns whether `path` contains `needle` as a contiguous component path.
///
/// This is useful for relative metadata protections such as `.git` or
/// `.cache`. The comparison uses the same native component semantics as
/// [`paths_equal`] and [`is_within`]. It is lexical only and does not inspect
/// the filesystem.
pub fn contains_component_path(path: &Path, needle: &Path) -> bool {
    #[cfg(windows)]
    {
        let path = NativePathKey::new(path);
        let needle = NativePathKey::new(needle);
        !needle.0.is_empty()
            && needle.0.len() <= path.0.len()
            && path
                .0
                .windows(needle.0.len())
                .any(|window| window == needle.0)
    }
    #[cfg(not(windows))]
    let path_components: Vec<_> = path
        .components()
        .filter(|component| *component != Component::CurDir)
        .collect();
    #[cfg(not(windows))]
    let needle_components: Vec<_> = needle
        .components()
        .filter(|component| *component != Component::CurDir)
        .collect();
    #[cfg(not(windows))]
    if needle_components.is_empty() || needle_components.len() > path_components.len() {
        return false;
    }
    #[cfg(not(windows))]
    path_components
        .windows(needle_components.len())
        .any(|window| {
            window
                .iter()
                .zip(&needle_components)
                .all(|(left, right)| components_equal(*left, *right))
        })
}

/// Compares two path components with the target platform's path case rules.
pub fn components_equal(left: Component<'_>, right: Component<'_>) -> bool {
    native::components_equal(left, right)
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
