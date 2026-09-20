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

/// Lexical path syntax used by a configuration value.
///
/// This is separate from the compiling host target so a portable
/// configuration can validate a Windows overlay while it is read on Linux or
/// macOS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PathDialect {
    /// POSIX path syntax used by Linux and macOS.
    Posix,
    /// Windows drive, UNC, and separator syntax.
    Windows,
}

impl PathDialect {
    /// Returns the dialect of the compiling host.
    pub const fn native() -> Self {
        #[cfg(target_os = "windows")]
        {
            Self::Windows
        }
        #[cfg(not(target_os = "windows"))]
        {
            Self::Posix
        }
    }
}

/// A hashable lexical path identity for an explicitly selected dialect.
///
/// Unlike [`NativePathKey`], this key does not use the compiling host target.
/// It is intended for portable configuration and profile merging. It does
/// not inspect the filesystem or resolve links.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PlatformPathKey {
    dialect: PathDialect,
    components: Vec<PlatformComponentKey>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum PlatformComponentKey {
    Prefix(String),
    Root,
    Parent,
    Normal(String),
}

impl PlatformPathKey {
    /// Creates a lexical identity using the explicitly selected dialect.
    pub fn new(value: &str, dialect: PathDialect) -> Self {
        Self {
            dialect,
            components: lexical_components(value, dialect),
        }
    }
}

/// Returns whether `value` is absolute according to `dialect`.
pub fn is_absolute_text(value: &str, dialect: PathDialect) -> bool {
    match dialect {
        PathDialect::Posix => value.starts_with('/'),
        PathDialect::Windows => {
            let bytes = value.as_bytes();
            value.starts_with("\\\\")
                || value.starts_with("//")
                || (bytes.len() >= 3
                    && bytes[0].is_ascii_alphabetic()
                    && bytes[1] == b':'
                    && matches!(bytes[2], b'/' | b'\\'))
        }
    }
}

/// Returns whether `value` contains a literal parent traversal component.
pub fn contains_parent_traversal_text(value: &str, dialect: PathDialect) -> bool {
    let is_separator = |character: char| match dialect {
        PathDialect::Posix => character == '/',
        PathDialect::Windows => matches!(character, '/' | '\\'),
    };
    let mut component = String::new();
    for character in value.chars().chain(std::iter::once('/')) {
        if is_separator(character) {
            if component == ".." {
                return true;
            }
            component.clear();
        } else {
            component.push(character);
        }
    }
    false
}

fn lexical_components(value: &str, dialect: PathDialect) -> Vec<PlatformComponentKey> {
    match dialect {
        PathDialect::Posix => lexical_posix_components(value),
        PathDialect::Windows => lexical_windows_components(value),
    }
}

fn lexical_posix_components(value: &str) -> Vec<PlatformComponentKey> {
    let mut components = Vec::new();
    if value.starts_with('/') {
        components.push(PlatformComponentKey::Root);
    }
    for component in value.split('/') {
        match component {
            "" | "." => {}
            ".." => components.push(PlatformComponentKey::Parent),
            value => components.push(PlatformComponentKey::Normal(value.to_owned())),
        }
    }
    components
}

fn lexical_windows_components(value: &str) -> Vec<PlatformComponentKey> {
    let mut value = value.replace('\\', "/");
    if value
        .get(..8)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("//?/unc/"))
        || value
            .get(..8)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("//./unc/"))
    {
        value = format!("//{}", &value[8..]);
    } else if value
        .get(..4)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("//?/"))
        || value
            .get(..4)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("//./"))
    {
        value = value[4..].to_owned();
    }

    let mut components = Vec::new();
    let mut parts = value.split('/');
    if let Some(first) = parts.next()
        && first.len() == 2
        && first.as_bytes()[1] == b':'
        && first.as_bytes()[0].is_ascii_alphabetic()
    {
        components.push(PlatformComponentKey::Prefix(first.to_ascii_lowercase()));
        if value.as_bytes().get(2) == Some(&b'/') {
            components.push(PlatformComponentKey::Root);
        }
    } else {
        if value.starts_with("//") {
            components.push(PlatformComponentKey::Root);
            components.push(PlatformComponentKey::Prefix("unc".to_owned()));
        }
        parts = value.split('/');
    }

    for component in parts {
        match component {
            "" | "." => {}
            value
                if value.len() == 2
                    && value.as_bytes()[1] == b':'
                    && value.as_bytes()[0].is_ascii_alphabetic()
                    && components
                        .iter()
                        .any(|entry| matches!(entry, PlatformComponentKey::Prefix(_))) => {}
            ".." => components.push(PlatformComponentKey::Parent),
            value => components.push(PlatformComponentKey::Normal(value.to_lowercase())),
        }
    }
    components
}

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

/// The lexical validation failures returned by [`resolve_lexical_path`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathResolutionError {
    /// The declaration is empty.
    Empty,
    /// The declaration contains a NUL byte.
    ContainsNul,
    /// The declaration contains a parent traversal component.
    ParentTraversal,
}

impl std::fmt::Display for PathResolutionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::Empty => "path declaration is empty",
            Self::ContainsNul => "path declaration contains NUL",
            Self::ParentTraversal => "path declaration contains parent traversal",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for PathResolutionError {}

/// Resolves a relative-or-absolute declaration against `base` lexically.
///
/// The declaration is validated before joining, and the result removes only
/// current-directory components. It does not access the filesystem, resolve
/// symlinks, or canonicalize the result.
pub fn resolve_lexical_path(
    base: &Path,
    declaration: &Path,
) -> Result<PathBuf, PathResolutionError> {
    if declaration.as_os_str().is_empty() {
        return Err(PathResolutionError::Empty);
    }
    if declaration.as_os_str().to_string_lossy().contains('\0') {
        return Err(PathResolutionError::ContainsNul);
    }
    if contains_parent_traversal(declaration) {
        return Err(PathResolutionError::ParentTraversal);
    }
    let resolved = if declaration.is_absolute() {
        declaration.to_path_buf()
    } else {
        base.join(declaration)
    };
    Ok(normalize_lexical_path(&resolved).into_owned())
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
