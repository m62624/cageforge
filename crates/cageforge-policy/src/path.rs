// Copyright 2026 Mansur Azatbek
// SPDX-License-Identifier: Apache-2.0

use crate::PathResolutionContext;
use crate::PolicyError;
use std::path::Component;
use std::path::Path;
use std::path::PathBuf;

/// A platform-independent description of a filesystem scope.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PathSelector {
    kind: PathSelectorKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum PathSelectorKind {
    Absolute(PathBuf),
    WorkspaceRoot(PathBuf),
    Minimal,
    Tmpdir,
    SlashTmp,
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
        if path
            .components()
            .any(|component| component == Component::ParentDir)
        {
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
            PathSelectorKind::Minimal | PathSelectorKind::Tmpdir | PathSelectorKind::SlashTmp => {
                None
            }
        }
    }

    /// Returns whether this selector is a special platform-defined scope.
    pub const fn is_special(&self) -> bool {
        matches!(
            &self.kind,
            PathSelectorKind::Minimal | PathSelectorKind::Tmpdir | PathSelectorKind::SlashTmp
        )
    }

    /// Returns the number of concrete path components represented by this
    /// selector after resolution.
    pub(crate) fn specificity(&self, resolved: &Path) -> usize {
        match &self.kind {
            PathSelectorKind::Absolute(_) | PathSelectorKind::WorkspaceRoot(_) => {
                resolved.components().count()
            }
            PathSelectorKind::Minimal | PathSelectorKind::Tmpdir | PathSelectorKind::SlashTmp => 0,
        }
    }
}

/// A validated path glob used by a filesystem rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PathPattern {
    raw: String,
    absolute: bool,
    prefix: Option<String>,
    components: Vec<String>,
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
                && prefix == self.prefix
                && glob_components_match(&self.components, &components);
        }

        context.workspace_roots().iter().any(|root| {
            path.strip_prefix(root)
                .ok()
                .map(path_components_relative)
                .is_some_and(|components| glob_components_match(&self.components, &components))
        })
    }

    pub(crate) fn specificity(&self) -> usize {
        self.components
            .iter()
            .filter(|component| !component.contains('*') && !component.contains('?'))
            .count()
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
        let path = Path::new(&raw);
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
                    if component.contains('[') || component.contains(']') {
                        return Err(PolicyError::InvalidGlobPattern {
                            pattern: raw,
                            reason: "character classes are not supported".to_string(),
                        });
                    }
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

fn path_components_relative(path: &Path) -> Vec<String> {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value.to_string_lossy().into_owned()),
            Component::CurDir => None,
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => None,
        })
        .collect()
}

fn glob_components_match(pattern: &[String], path: &[String]) -> bool {
    let mut current = vec![false; path.len() + 1];
    current[0] = true;
    for pattern_component in pattern {
        let mut next = vec![false; path.len() + 1];
        if pattern_component == "**" {
            next[0] = current[0];
            for index in 1..=path.len() {
                next[index] = current[index] || next[index - 1];
            }
        } else {
            for index in 1..=path.len() {
                next[index] =
                    current[index - 1] && segment_matches(pattern_component, &path[index - 1]);
            }
        }
        current = next;
    }
    current[path.len()]
}

fn segment_matches(pattern: &str, value: &str) -> bool {
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let mut current = vec![false; value.len() + 1];
    current[0] = true;
    for pattern_byte in pattern {
        let mut next = vec![false; value.len() + 1];
        match pattern_byte {
            b'*' => {
                next[0] = current[0];
                for index in 1..=value.len() {
                    next[index] = current[index] || next[index - 1];
                }
            }
            b'?' => {
                next[1..].copy_from_slice(&current[..value.len()]);
            }
            byte => {
                for index in 1..=value.len() {
                    next[index] = current[index - 1] && value[index - 1] == *byte;
                }
            }
        }
        current = next;
    }
    current[value.len()]
}
