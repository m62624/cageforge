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
use std::path::{Component, Path};

#[cfg(not(windows))]
use std::ffi::{OsStr, OsString};
#[cfg(windows)]
use std::ffi::{OsStr, OsString};
#[cfg(windows)]
use std::os::windows::ffi::{OsStrExt, OsStringExt};
#[cfg(windows)]
use std::path::PathBuf;

/// A hashable and orderable lexical path identity using native case rules.
///
/// The key is useful when another crate needs a map or set whose identity must
/// agree with [`paths_equal`]. It does not canonicalize the filesystem or
/// resolve links.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NativePathKey(Vec<NativeComponentKey>);

impl NativePathKey {
    /// Creates a native lexical key for `path`.
    pub fn new(path: &Path) -> Self {
        let path = normalize_lexical_path(path);
        Self(
            path.components()
                .filter(|component| *component != Component::CurDir)
                .map(component_key)
                .collect(),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum NativeComponentKey {
    Prefix(NativeOsKey),
    RootDir,
    CurDir,
    ParentDir,
    Normal(NativeOsKey),
}

#[cfg(not(windows))]
type NativeOsKey = OsString;

#[cfg(windows)]
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum NativeOsKey {
    Folded(Vec<u16>),
    IllFormed(Vec<u16>),
}

/// Returns whether a path contains a lexical parent traversal component.
pub fn contains_parent_traversal(path: &Path) -> bool {
    path.components()
        .any(|component| component == Component::ParentDir)
}

/// Normalizes lexical aliases that the target platform treats as the same path.
///
/// On Windows this converts supported verbatim/device drive and UNC prefixes
/// to their ordinary spelling. Other paths, including unsupported device
/// namespaces, are returned unchanged. POSIX paths are always borrowed
/// unchanged. The function performs no filesystem I/O.
pub fn normalize_lexical_path(path: &Path) -> Cow<'_, Path> {
    #[cfg(windows)]
    {
        normalize_windows_device_path(path)
    }
    #[cfg(not(windows))]
    {
        Cow::Borrowed(path)
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
pub fn is_within(path: &Path, root: &Path) -> bool {
    #[cfg(windows)]
    {
        let path = NativePathKey::new(path);
        let root = NativePathKey::new(root);
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
    component_key(left) == component_key(right)
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

fn component_key(component: Component<'_>) -> NativeComponentKey {
    match component {
        Component::Prefix(prefix) => NativeComponentKey::Prefix(native_os_key(prefix.as_os_str())),
        Component::RootDir => NativeComponentKey::RootDir,
        Component::CurDir => NativeComponentKey::CurDir,
        Component::ParentDir => NativeComponentKey::ParentDir,
        Component::Normal(value) => NativeComponentKey::Normal(native_os_key(value)),
    }
}

#[cfg(not(windows))]
fn native_os_key(value: &OsStr) -> NativeOsKey {
    value.to_os_string()
}

#[cfg(windows)]
fn normalize_windows_device_path(path: &Path) -> Cow<'_, Path> {
    let units = path.as_os_str().encode_wide().collect::<Vec<_>>();
    if units.len() < 7
        || !is_separator(units[0])
        || !is_separator(units[1])
        || (units[2] != b'?' as u16 && units[2] != b'.' as u16)
        || !is_separator(units[3])
    {
        return Cow::Borrowed(path);
    }

    let remainder = &units[4..];
    if remainder.len() >= 4
        && eq_ascii_case(remainder[0], b'U')
        && eq_ascii_case(remainder[1], b'N')
        && eq_ascii_case(remainder[2], b'C')
        && is_separator(remainder[3])
    {
        let mut normalized = vec![b'\\' as u16, b'\\' as u16];
        normalized.extend_from_slice(&remainder[4..]);
        return Cow::Owned(PathBuf::from(OsString::from_wide(&normalized)));
    }

    if remainder.len() >= 3
        && is_ascii_alpha(remainder[0])
        && remainder[1] == b':' as u16
        && is_separator(remainder[2])
    {
        return Cow::Owned(PathBuf::from(OsString::from_wide(remainder)));
    }

    Cow::Borrowed(path)
}

#[cfg(windows)]
fn is_separator(unit: u16) -> bool {
    matches!(unit, value if value == b'\\' as u16 || value == b'/' as u16)
}

#[cfg(windows)]
fn is_ascii_alpha(unit: u16) -> bool {
    unit <= u16::from(u8::MAX) && (unit as u8).is_ascii_alphabetic()
}

#[cfg(windows)]
fn eq_ascii_case(unit: u16, expected: u8) -> bool {
    unit <= u16::from(u8::MAX) && (unit as u8).eq_ignore_ascii_case(&expected)
}

#[cfg(windows)]
fn native_os_key(value: &OsStr) -> NativeOsKey {
    let units = value.encode_wide().collect::<Vec<_>>();
    match String::from_utf16(&units) {
        Ok(value) => NativeOsKey::Folded(value.to_lowercase().encode_utf16().collect()),
        Err(_) => NativeOsKey::IllFormed(units),
    }
}
