// SPDX-License-Identifier: Apache-2.0

//! Validated filesystem selectors and policy globs.
//!
//! [`crate::PathSelector`] represents a concrete or symbolic filesystem scope;
//! [`crate::PathPattern`] represents a validated deny-glob. Shared lexical
//! identity comes from [`cageforge_path`], while policy-specific glob access
//! remains in this module.

use crate::PathResolutionContext;
use crate::PolicyError;
use cageforge_path::{
    NativePathKey, case_fold, contains_parent_traversal, is_within, normalize_lexical_path,
    paths_equal, strings_equal,
};
use globset::{GlobBuilder, GlobMatcher};
use std::cmp::Ordering;
use std::hash::{Hash, Hasher};
use std::path::Component;
use std::path::Path;
use std::path::PathBuf;

/// A platform-independent description of a filesystem scope.
#[derive(Debug, Clone)]
pub struct PathSelector {
    kind: PathSelectorKind,
}

#[derive(Debug, Clone)]
enum PathSelectorKind {
    Absolute(PathBuf),
    WorkspaceRoot(PathBuf),
    Root,
    Minimal,
    Tmpdir,
    SlashTmp,
}

impl PartialEq for PathSelector {
    fn eq(&self, other: &Self) -> bool {
        selectors_equal(self, other)
    }
}

impl Eq for PathSelector {}

impl Hash for PathSelector {
    fn hash<H: Hasher>(&self, state: &mut H) {
        selector_kind_rank(&self.kind).hash(state);
        if let Some(path) = self.path() {
            NativePathKey::new(path).hash(state);
        }
    }
}

impl PartialOrd for PathSelector {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PathSelector {
    fn cmp(&self, other: &Self) -> Ordering {
        let kind_order = selector_kind_rank(&self.kind).cmp(&selector_kind_rank(&other.kind));
        if kind_order != Ordering::Equal {
            return kind_order;
        }
        match (self.path(), other.path()) {
            (Some(left), Some(right)) => NativePathKey::new(left).cmp(&NativePathKey::new(right)),
            (None, None) => Ordering::Equal,
            _ => Ordering::Equal,
        }
    }
}

impl PathSelector {
    /// Creates an absolute selector without touching the filesystem.
    pub fn absolute(path: impl Into<PathBuf>) -> Result<Self, PolicyError> {
        let path = path.into();
        if path.as_os_str().is_empty() {
            return Err(PolicyError::EmptyPath);
        }
        if contains_nul(&path) {
            return Err(PolicyError::PathContainsNul { path });
        }
        if !path.is_absolute() {
            return Err(PolicyError::ExpectedAbsolute { path });
        }
        if contains_parent_traversal(&path) {
            return Err(PolicyError::ParentTraversal { path });
        }
        Ok(Self {
            kind: PathSelectorKind::Absolute(path),
        })
    }

    /// Creates a selector for the workspace root itself.
    pub fn workspace_root() -> Self {
        Self {
            kind: PathSelectorKind::WorkspaceRoot(PathBuf::from(".")),
        }
    }

    /// Creates a selector for every system root supplied by the runtime.
    ///
    /// The selector is symbolic. A backend must populate
    /// [`PathResolutionContext::with_root`] for the target platform.
    pub const fn root() -> Self {
        Self {
            kind: PathSelectorKind::Root,
        }
    }

    /// Creates a selector relative to every workspace root.
    pub fn workspace(relative: impl Into<PathBuf>) -> Result<Self, PolicyError> {
        let relative = relative.into();
        let normalized = normalize_relative_path(relative.clone())?;
        Ok(Self {
            kind: PathSelectorKind::WorkspaceRoot(normalized),
        })
    }

    /// Creates the platform-minimal runtime scope.
    pub const fn minimal() -> Self {
        Self {
            kind: PathSelectorKind::Minimal,
        }
    }

    /// Creates the platform temporary-directory scope.
    pub const fn tmpdir() -> Self {
        Self {
            kind: PathSelectorKind::Tmpdir,
        }
    }

    /// Creates the conventional `/tmp` scope.
    pub const fn slash_tmp() -> Self {
        Self {
            kind: PathSelectorKind::SlashTmp,
        }
    }

    /// Resolves this selector against a caller-provided runtime context.
    pub fn resolve(&self, context: &PathResolutionContext) -> Vec<PathBuf> {
        match &self.kind {
            PathSelectorKind::Absolute(path) => vec![path.clone()],
            PathSelectorKind::WorkspaceRoot(relative) => context
                .workspace_roots()
                .iter()
                .map(|root| root.join(relative))
                .collect(),
            PathSelectorKind::Root => context.root_paths().to_vec(),
            PathSelectorKind::Minimal => context.minimal_paths().to_vec(),
            PathSelectorKind::Tmpdir => context
                .tmpdir()
                .into_iter()
                .map(Path::to_path_buf)
                .collect(),
            PathSelectorKind::SlashTmp => context
                .slash_tmp()
                .into_iter()
                .map(Path::to_path_buf)
                .collect(),
        }
    }

    /// Returns the stored path for an absolute or workspace-relative selector.
    pub fn path(&self) -> Option<&Path> {
        match &self.kind {
            PathSelectorKind::Absolute(path) | PathSelectorKind::WorkspaceRoot(path) => Some(path),
            PathSelectorKind::Root
            | PathSelectorKind::Minimal
            | PathSelectorKind::Tmpdir
            | PathSelectorKind::SlashTmp => None,
        }
    }

    /// Returns whether this selector is a special platform-defined scope.
    pub const fn is_special(&self) -> bool {
        matches!(
            &self.kind,
            PathSelectorKind::Root
                | PathSelectorKind::Minimal
                | PathSelectorKind::Tmpdir
                | PathSelectorKind::SlashTmp
        )
    }

    /// Returns whether this selector resolves relative to runtime workspace
    /// roots.
    pub const fn is_workspace_scope(&self) -> bool {
        matches!(&self.kind, PathSelectorKind::WorkspaceRoot(_))
    }

    /// Returns whether this selector targets caller-supplied system roots.
    pub const fn is_root_scope(&self) -> bool {
        matches!(&self.kind, PathSelectorKind::Root)
    }

    /// Returns whether this selector targets the platform-minimal scope.
    pub const fn is_minimal_scope(&self) -> bool {
        matches!(&self.kind, PathSelectorKind::Minimal)
    }

    /// Returns whether this selector targets the platform temporary directory.
    pub const fn is_tmpdir_scope(&self) -> bool {
        matches!(&self.kind, PathSelectorKind::Tmpdir)
    }

    /// Returns whether this selector targets the conventional `/tmp` scope.
    pub const fn is_slash_tmp_scope(&self) -> bool {
        matches!(&self.kind, PathSelectorKind::SlashTmp)
    }

    /// Returns whether this selector stores a native absolute path.
    pub const fn is_absolute_scope(&self) -> bool {
        matches!(&self.kind, PathSelectorKind::Absolute(_))
    }

    /// Returns the number of concrete path components represented by this
    /// selector after resolution.
    pub(crate) fn is_definitely_outside(&self, parent: &Self) -> bool {
        match (&self.kind, &parent.kind) {
            (PathSelectorKind::Absolute(child), PathSelectorKind::Absolute(parent))
            | (PathSelectorKind::WorkspaceRoot(child), PathSelectorKind::WorkspaceRoot(parent)) => {
                !is_within(child, parent)
            }
            _ => false,
        }
    }
}

pub(crate) fn selectors_equal(left: &PathSelector, right: &PathSelector) -> bool {
    match (&left.kind, &right.kind) {
        (PathSelectorKind::Absolute(left), PathSelectorKind::Absolute(right))
        | (PathSelectorKind::WorkspaceRoot(left), PathSelectorKind::WorkspaceRoot(right)) => {
            paths_equal(left, right)
        }
        (PathSelectorKind::Root, PathSelectorKind::Root)
        | (PathSelectorKind::Minimal, PathSelectorKind::Minimal)
        | (PathSelectorKind::Tmpdir, PathSelectorKind::Tmpdir)
        | (PathSelectorKind::SlashTmp, PathSelectorKind::SlashTmp) => true,
        _ => false,
    }
}

fn selector_kind_rank(kind: &PathSelectorKind) -> u8 {
    match kind {
        PathSelectorKind::Absolute(_) => 0,
        PathSelectorKind::WorkspaceRoot(_) => 1,
        PathSelectorKind::Root => 2,
        PathSelectorKind::Minimal => 3,
        PathSelectorKind::Tmpdir => 4,
        PathSelectorKind::SlashTmp => 5,
    }
}

/// A validated path glob used by a filesystem rule.
#[derive(Debug, Clone)]
pub struct PathPattern {
    raw: String,
    absolute: bool,
    prefix: Option<String>,
    components: Vec<String>,
    matchers: Vec<GlobMatcher>,
}

impl PartialEq for PathPattern {
    fn eq(&self, other: &Self) -> bool {
        self.semantic_key() == other.semantic_key()
    }
}

impl Eq for PathPattern {}

impl Hash for PathPattern {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.semantic_key().hash(state);
    }
}

impl PartialOrd for PathPattern {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PathPattern {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.semantic_key().cmp(&other.semantic_key())
    }
}

impl PathPattern {
    /// Creates a glob rooted at a native absolute path.
    pub fn absolute(pattern: impl Into<String>) -> Result<Self, PolicyError> {
        Self::new(pattern.into(), true)
    }

    /// Creates a glob relative to every workspace root in the context.
    pub fn workspace(pattern: impl Into<String>) -> Result<Self, PolicyError> {
        Self::new(pattern.into(), false)
    }

    /// Returns the original normalized pattern text.
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// Returns whether this pattern is rooted at an absolute path.
    pub const fn is_absolute(&self) -> bool {
        self.absolute
    }

    pub(crate) fn matches(&self, path: &Path, context: &PathResolutionContext) -> bool {
        if self.absolute {
            let (prefix, components) = path_components(path);
            return path.is_absolute()
                && prefixes_equal(prefix.as_deref(), self.prefix.as_deref())
                && glob_components_match(&self.components, &self.matchers, &components);
        }

        context.workspace_roots().iter().any(|root| {
            relative_path_components(path, root).is_some_and(|components| {
                glob_components_match(&self.components, &self.matchers, &components)
            })
        })
    }

    pub(crate) fn specificity(&self) -> usize {
        self.components
            .iter()
            .filter(|component| !contains_glob_meta(component))
            .count()
    }

    pub(crate) fn semantic_key(&self) -> (bool, Option<String>, Vec<String>) {
        (
            self.absolute,
            self.prefix.as_deref().map(case_fold),
            self.components
                .iter()
                .map(|component| case_fold(component))
                .collect(),
        )
    }

    fn new(raw: String, absolute: bool) -> Result<Self, PolicyError> {
        if raw.trim().is_empty() {
            return Err(PolicyError::InvalidGlobPattern {
                pattern: raw,
                reason: "pattern cannot be empty".to_string(),
            });
        }
        if raw.contains('\0') {
            return Err(PolicyError::InvalidGlobPattern {
                pattern: raw,
                reason: "pattern cannot contain a NUL character".to_string(),
            });
        }
        let normalized_path = normalize_lexical_path(Path::new(&raw));
        let path = normalized_path.as_ref();
        if absolute && !path.is_absolute() {
            return Err(PolicyError::InvalidGlobPattern {
                pattern: raw,
                reason: "absolute glob must use a native absolute path".to_string(),
            });
        }
        if !absolute && path.is_absolute() {
            return Err(PolicyError::InvalidGlobPattern {
                pattern: raw,
                reason: "workspace glob must be relative".to_string(),
            });
        }

        let mut components = Vec::new();
        let mut matchers = Vec::new();
        let mut prefix = None;
        for component in path.components() {
            match component {
                Component::Prefix(value) => {
                    prefix = Some(value.as_os_str().to_string_lossy().into_owned());
                }
                Component::RootDir => {}
                Component::CurDir => {}
                Component::ParentDir => {
                    return Err(PolicyError::InvalidGlobPattern {
                        pattern: raw,
                        reason: "parent traversal is not allowed".to_string(),
                    });
                }
                Component::Normal(value) => {
                    let component = value.to_string_lossy();
                    matchers.push(compile_glob_component(&component, &raw)?);
                    components.push(component.into_owned());
                }
            }
        }
        if components.is_empty() {
            return Err(PolicyError::InvalidGlobPattern {
                pattern: raw,
                reason: "pattern must contain at least one component".to_string(),
            });
        }
        Ok(Self {
            raw,
            absolute,
            prefix,
            components,
            matchers,
        })
    }
}

fn normalize_relative_path(relative: PathBuf) -> Result<PathBuf, PolicyError> {
    if relative.as_os_str().is_empty() {
        return Err(PolicyError::EmptyPath);
    }
    if contains_nul(&relative) {
        return Err(PolicyError::PathContainsNul { path: relative });
    }
    if relative.is_absolute() {
        return Err(PolicyError::ExpectedRelative { path: relative });
    }
    let mut normalized = PathBuf::new();
    for component in relative.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(part) => normalized.push(part),
            Component::ParentDir => {
                return Err(PolicyError::ParentTraversal { path: relative });
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(PolicyError::ExpectedRelative { path: relative });
            }
        }
    }
    if normalized.as_os_str().is_empty() {
        normalized.push(".");
    }
    Ok(normalized)
}

pub(crate) fn contains_nul(path: &Path) -> bool {
    path.as_os_str().to_string_lossy().contains('\0')
}

fn path_components(path: &Path) -> (Option<String>, Vec<String>) {
    let normalized_path = normalize_lexical_path(path);
    let path = normalized_path.as_ref();
    let mut prefix = None;
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::Prefix(value) => {
                prefix = Some(value.as_os_str().to_string_lossy().into_owned());
            }
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir | Component::Normal(_) => {
                if let Component::Normal(value) = component {
                    components.push(value.to_string_lossy().into_owned());
                }
            }
        }
    }
    (prefix, components)
}

pub(crate) fn normal_component_count(path: &Path) -> usize {
    path.components()
        .filter(|component| matches!(component, Component::Normal(_)))
        .count()
}

fn relative_path_components(path: &Path, root: &Path) -> Option<Vec<String>> {
    let (path_prefix, path_parts) = path_components(path);
    let (root_prefix, root_components) = path_components(root);
    if !prefixes_equal(path_prefix.as_deref(), root_prefix.as_deref())
        || root_components.len() > path_parts.len()
        || !root_components
            .iter()
            .zip(&path_parts)
            .all(|(root, path)| strings_equal(path, root))
    {
        return None;
    }
    Some(path_parts[root_components.len()..].to_vec())
}

fn glob_components_match(pattern: &[String], matchers: &[GlobMatcher], path: &[String]) -> bool {
    let mut current = vec![false; path.len() + 1];
    let mut next = vec![false; path.len() + 1];
    current[0] = true;
    for (pattern_index, pattern_component) in pattern.iter().enumerate() {
        next.fill(false);
        if pattern_component == "**" {
            next[0] = current[0];
            for index in 1..=path.len() {
                next[index] = current[index] || next[index - 1];
            }
        } else {
            let matcher = &matchers[pattern_index];
            for index in 1..=path.len() {
                next[index] = current[index - 1] && matcher.is_match(&path[index - 1]);
            }
        }
        std::mem::swap(&mut current, &mut next);
    }
    current[path.len()]
}

fn compile_glob_component(component: &str, pattern: &str) -> Result<GlobMatcher, PolicyError> {
    let mut builder = GlobBuilder::new(component);
    builder
        .case_insensitive(cfg!(windows))
        .literal_separator(true)
        .backslash_escape(false);
    builder
        .build()
        .map(|glob| glob.compile_matcher())
        .map_err(|error| PolicyError::InvalidGlobPattern {
            pattern: pattern.to_string(),
            reason: format!("invalid glob syntax: {error}"),
        })
}

fn contains_glob_meta(component: &str) -> bool {
    component
        .chars()
        .any(|character| matches!(character, '*' | '?' | '[' | ']' | '{' | '}'))
}

fn prefixes_equal(left: Option<&str>, right: Option<&str>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => strings_equal(left, right),
        (None, None) => true,
        _ => false,
    }
}
