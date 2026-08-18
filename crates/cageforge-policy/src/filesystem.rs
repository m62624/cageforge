// Copyright 2026 Mansur Azatbek
// SPDX-License-Identifier: Apache-2.0

use crate::AccessMode;
use crate::FilesystemDecision;
use crate::PathPattern;
use crate::PathResolutionContext;
use crate::PathSelector;
use crate::PolicyError;
use cageforge_path::{contains_parent_traversal, is_within, paths_equal, strings_equal};
use std::num::NonZeroUsize;
use std::path::{Component, Path, PathBuf};

/// The enforcement ownership for filesystem access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum FilesystemMode {
    /// Cageforge must enforce the listed restrictions through its backend.
    Restricted,
    /// The command runs without a Cageforge filesystem boundary.
    Unrestricted,
    /// Another trusted sandbox is responsible for enforcement.
    External,
}

/// What a filesystem rule targets.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum FilesystemTarget {
    /// A concrete or runtime-defined filesystem scope.
    Scope(PathSelector),
    /// A validated absolute or workspace-relative path glob.
    Glob(PathPattern),
}

/// What a backend should do when a concrete rule target is absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum MissingPathBehavior {
    /// Treat an absent target as an error during backend preparation.
    Error,
    /// Ignore an absent target without creating it.
    Skip,
}

/// One filesystem target and its access mode.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FilesystemRule {
    target: FilesystemTarget,
    access: AccessMode,
    missing_path_behavior: MissingPathBehavior,
    read_only_subpaths: Vec<PathSelector>,
}

fn targets_equal(left: &FilesystemTarget, right: &FilesystemTarget) -> bool {
    match (left, right) {
        (FilesystemTarget::Scope(left), FilesystemTarget::Scope(right)) => {
            crate::path::selectors_equal(left, right)
        }
        (FilesystemTarget::Glob(left), FilesystemTarget::Glob(right)) => {
            left.is_absolute() == right.is_absolute()
                && cageforge_path::case_fold(left.as_str())
                    == cageforge_path::case_fold(right.as_str())
        }
        _ => false,
    }
}

impl FilesystemRule {
    /// Creates a rule from an already validated path selector.
    pub const fn new(selector: PathSelector, access: AccessMode) -> Self {
        Self {
            target: FilesystemTarget::Scope(selector),
            access,
            missing_path_behavior: MissingPathBehavior::Error,
            read_only_subpaths: Vec::new(),
        }
    }

    /// Creates a rule from a validated target.
    pub fn from_target(target: FilesystemTarget, access: AccessMode) -> Result<Self, PolicyError> {
        if matches!(target, FilesystemTarget::Glob(_)) && access != AccessMode::Deny {
            return Err(PolicyError::UnsupportedGlobAccess { access });
        }
        Ok(Self {
            target,
            access,
            missing_path_behavior: MissingPathBehavior::Error,
            read_only_subpaths: Vec::new(),
        })
    }

    /// Creates an absolute-path glob rule.
    pub fn absolute_glob(
        pattern: impl Into<String>,
        access: AccessMode,
    ) -> Result<Self, PolicyError> {
        Self::from_target(
            FilesystemTarget::Glob(PathPattern::absolute(pattern)?),
            access,
        )
    }

    /// Creates a workspace-relative glob rule.
    pub fn workspace_glob(
        pattern: impl Into<String>,
        access: AccessMode,
    ) -> Result<Self, PolicyError> {
        Self::from_target(
            FilesystemTarget::Glob(PathPattern::workspace(pattern)?),
            access,
        )
    }

    /// Sets how the backend handles an absent concrete target.
    pub const fn with_missing_path_behavior(mut self, behavior: MissingPathBehavior) -> Self {
        self.missing_path_behavior = behavior;
        self
    }

    /// Adds a read-only carve-out below a writable rule.
    pub fn with_read_only_subpath(mut self, selector: PathSelector) -> Result<Self, PolicyError> {
        if self.access != AccessMode::Write {
            return Err(PolicyError::InvalidRule {
                message: "read-only subpaths require a writable parent rule".to_string(),
            });
        }
        if let FilesystemTarget::Scope(parent) = &self.target
            && selector.is_definitely_outside(parent)
        {
            return Err(PolicyError::InvalidRule {
                message: "read-only subpath must be below the writable parent rule".to_string(),
            });
        }
        self.read_only_subpaths.push(selector);
        Ok(self)
    }

    /// Returns the rule target.
    pub const fn target(&self) -> &FilesystemTarget {
        &self.target
    }

    /// Returns the access mode of this rule.
    pub const fn access(&self) -> AccessMode {
        self.access
    }

    /// Returns the missing-target behavior.
    pub const fn missing_path_behavior(&self) -> MissingPathBehavior {
        self.missing_path_behavior
    }

    /// Returns read-only carve-outs below this rule.
    pub fn read_only_subpaths(&self) -> &[PathSelector] {
        &self.read_only_subpaths
    }

    fn matches_path(&self, path: &Path, context: &PathResolutionContext) -> Option<RuleMatch> {
        let (specificity, target_matches) = match &self.target {
            FilesystemTarget::Scope(selector) => selector
                .resolve(context)
                .into_iter()
                .filter(|root| is_within(path, root))
                .map(|_| (selector.specificity(), true))
                .max_by_key(|(specificity, _)| *specificity)
                .unwrap_or((0, false)),
            FilesystemTarget::Glob(pattern) => {
                (pattern.specificity(), pattern.matches(path, context))
            }
        };
        if !target_matches {
            return None;
        }

        let mut access = self.access;
        let mut specificity = specificity;
        if access == AccessMode::Write {
            for subpath in &self.read_only_subpaths {
                let matches = subpath
                    .resolve(context)
                    .into_iter()
                    .filter(|root| is_within(path, root))
                    .map(|_| subpath.specificity())
                    .max();
                if let Some(subpath_specificity) = matches {
                    access = AccessMode::Read;
                    specificity = specificity.max(subpath_specificity);
                }
            }
        }
        Some(RuleMatch {
            specificity,
            access,
        })
    }
}

/// Filesystem restrictions passed to a platform backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesystemPolicy {
    mode: FilesystemMode,
    entries: Vec<FilesystemRule>,
    glob_scan_max_depth: Option<NonZeroUsize>,
    protected_relative_paths: Vec<PathBuf>,
}

impl FilesystemPolicy {
    /// Creates a restricted policy from filesystem rules.
    pub fn restricted(entries: impl IntoIterator<Item = FilesystemRule>) -> Self {
        Self {
            mode: FilesystemMode::Restricted,
            entries: entries.into_iter().collect(),
            glob_scan_max_depth: None,
            protected_relative_paths: vec![PathBuf::from(".git")],
        }
    }

    /// Creates a policy with no Cageforge filesystem restrictions.
    pub const fn unrestricted() -> Self {
        Self {
            mode: FilesystemMode::Unrestricted,
            entries: Vec::new(),
            glob_scan_max_depth: None,
            protected_relative_paths: Vec::new(),
        }
    }

    /// Creates a policy whose filesystem boundary is owned by another sandbox.
    pub const fn external() -> Self {
        Self {
            mode: FilesystemMode::External,
            entries: Vec::new(),
            glob_scan_max_depth: None,
            protected_relative_paths: Vec::new(),
        }
    }

    /// Sets the maximum depth used when a backend expands glob targets.
    pub fn with_glob_scan_max_depth(mut self, depth: NonZeroUsize) -> Result<Self, PolicyError> {
        if self.mode != FilesystemMode::Restricted {
            return Err(PolicyError::InvalidRule {
                message: "glob scan depth requires a restricted filesystem policy".to_string(),
            });
        }
        self.glob_scan_max_depth = Some(depth);
        Ok(self)
    }

    /// Returns the enforcement mode.
    pub const fn mode(&self) -> FilesystemMode {
        self.mode
    }

    /// Returns the configured filesystem rules in declaration order.
    pub fn entries(&self) -> &[FilesystemRule] {
        &self.entries
    }

    /// Returns the optional backend glob expansion depth.
    pub const fn glob_scan_max_depth(&self) -> Option<NonZeroUsize> {
        self.glob_scan_max_depth
    }

    /// Returns protected relative paths applied below writable scopes.
    pub fn protected_relative_paths(&self) -> &[PathBuf] {
        &self.protected_relative_paths
    }

    /// Adds a protected relative path without removing the mandatory `.git`
    /// protection.
    pub fn with_additional_protected_relative_path(
        mut self,
        path: impl Into<PathBuf>,
    ) -> Result<Self, PolicyError> {
        if self.mode != FilesystemMode::Restricted {
            return Err(PolicyError::InvalidRule {
                message: "protected paths require a restricted filesystem policy".to_string(),
            });
        }
        let path = validate_protected_relative_path(path.into())?;
        if !self
            .protected_relative_paths
            .iter()
            .any(|existing| paths_equal(existing, &path))
        {
            self.protected_relative_paths.push(path);
        }
        Ok(self)
    }

    /// Explicitly disables the default `.git` write protection.
    ///
    /// This opt-out is intentionally named as a dangerous operation. A
    /// backend or policy composer may still reject the resulting request.
    pub fn dangerously_allow_git_write(mut self) -> Self {
        self.protected_relative_paths
            .retain(|path| !paths_equal(path, Path::new(".git")));
        self
    }

    /// Adds one rule while retaining the existing policy.
    pub fn with_rule(mut self, rule: FilesystemRule) -> Result<Self, PolicyError> {
        if self.mode != FilesystemMode::Restricted {
            return Err(PolicyError::InvalidRule {
                message: "filesystem rules require a restricted filesystem policy".to_string(),
            });
        }
        rule.validate()?;
        self.entries.push(rule);
        Ok(self)
    }

    /// Validates the policy and rejects rules that are meaningless for its mode.
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.mode != FilesystemMode::Restricted
            && (!self.entries.is_empty() || self.glob_scan_max_depth.is_some())
        {
            return Err(PolicyError::InvalidRule {
                message: "unrestricted and external filesystem policies cannot contain local rules"
                    .to_string(),
            });
        }
        for rule in &self.entries {
            rule.validate()?;
            if rule.access != AccessMode::Write && !rule.read_only_subpaths.is_empty() {
                return Err(PolicyError::InvalidRule {
                    message: "read-only subpaths require a writable parent rule".to_string(),
                });
            }
        }
        for path in &self.protected_relative_paths {
            validate_protected_relative_path(path.clone())?;
        }
        Ok(())
    }

    /// Returns a normalized policy with duplicate targets collapsed conservatively.
    pub fn normalized(&self) -> Result<Self, PolicyError> {
        self.validate()?;
        if self.mode != FilesystemMode::Restricted {
            return Ok(self.clone());
        }

        let mut entries = Vec::new();
        for rule in &self.entries {
            if let Some(existing) = entries.iter_mut().find(|existing: &&mut FilesystemRule| {
                targets_equal(existing.target(), rule.target())
            }) {
                existing.access = existing.access.most_restrictive(rule.access);
                existing.missing_path_behavior = existing
                    .missing_path_behavior
                    .min(rule.missing_path_behavior);
                for selector in &rule.read_only_subpaths {
                    if !existing
                        .read_only_subpaths
                        .iter()
                        .any(|existing| crate::path::selectors_equal(existing, selector))
                    {
                        existing.read_only_subpaths.push(selector.clone());
                    }
                }
                if existing.access != AccessMode::Write {
                    existing.read_only_subpaths.clear();
                }
            } else {
                entries.push(rule.clone());
            }
        }
        Ok(Self {
            entries,
            ..self.clone()
        })
    }

    /// Resolves a rule for an exact selector, defaulting to deny in restricted mode.
    pub fn access_for(&self, selector: &PathSelector) -> FilesystemDecision {
        let access = match self.mode {
            FilesystemMode::Unrestricted => AccessMode::Write,
            FilesystemMode::External => return FilesystemDecision::ExternallyEnforced,
            FilesystemMode::Restricted => self
                .entries
                .iter()
                .filter_map(|entry| match entry.target() {
                    FilesystemTarget::Scope(candidate)
                        if crate::path::selectors_equal(candidate, selector) =>
                    {
                        Some(entry.access())
                    }
                    FilesystemTarget::Scope(_) | FilesystemTarget::Glob(_) => None,
                })
                .reduce(AccessMode::most_restrictive)
                .unwrap_or(AccessMode::Deny),
        };
        if access == AccessMode::Write
            && selector
                .path()
                .is_some_and(|path| self.is_protected_path(path))
        {
            FilesystemDecision::Read
        } else {
            access.into()
        }
    }

    /// Resolves access for an absolute path using recursive and most-specific matching.
    pub fn access_for_path(
        &self,
        path: &Path,
        context: &PathResolutionContext,
    ) -> Result<FilesystemDecision, PolicyError> {
        if crate::path::contains_nul(path) {
            return Err(PolicyError::PathContainsNul {
                path: path.to_path_buf(),
            });
        }
        if !path.is_absolute() {
            return Err(PolicyError::ExpectedAbsolute {
                path: path.to_path_buf(),
            });
        }
        if contains_parent_traversal(path) {
            return Err(PolicyError::ParentTraversal {
                path: path.to_path_buf(),
            });
        }
        match self.mode {
            FilesystemMode::Unrestricted => Ok(FilesystemDecision::Write),
            FilesystemMode::External => Ok(FilesystemDecision::ExternallyEnforced),
            FilesystemMode::Restricted => {
                let mut best: Option<RuleMatch> = None;
                let mut writable_match = false;
                for rule in &self.entries {
                    if let Some(candidate) = rule.matches_path(path, context) {
                        writable_match |= candidate.access == AccessMode::Write;
                        best = Some(match best {
                            Some(current) if current.specificity > candidate.specificity => current,
                            Some(current) if current.specificity == candidate.specificity => {
                                RuleMatch {
                                    specificity: current.specificity,
                                    access: current.access.most_restrictive(candidate.access),
                                }
                            }
                            _ => candidate,
                        });
                    }
                }
                let access = best.map_or(AccessMode::Deny, |matched| matched.access);
                if writable_match && access == AccessMode::Write && self.is_protected_path(path) {
                    Ok(FilesystemDecision::Read)
                } else {
                    Ok(access.into())
                }
            }
        }
    }

    fn is_protected_path(&self, path: &Path) -> bool {
        let components: Vec<_> = path
            .components()
            .filter_map(|component| match component {
                Component::Normal(value) => Some(value),
                Component::CurDir
                | Component::ParentDir
                | Component::RootDir
                | Component::Prefix(_) => None,
            })
            .collect();
        self.protected_relative_paths.iter().any(|protected| {
            let protected_components: Vec<_> = protected
                .components()
                .filter_map(|component| match component {
                    Component::Normal(value) => Some(value),
                    Component::CurDir
                    | Component::ParentDir
                    | Component::RootDir
                    | Component::Prefix(_) => None,
                })
                .collect();
            components
                .windows(protected_components.len())
                .any(|window| {
                    window.len() == protected_components.len()
                        && window
                            .iter()
                            .zip(&protected_components)
                            .all(|(left, right)| {
                                strings_equal(&left.to_string_lossy(), &right.to_string_lossy())
                            })
                })
        })
    }
}

impl FilesystemRule {
    fn validate(&self) -> Result<(), PolicyError> {
        if matches!(self.target, FilesystemTarget::Glob(_)) && self.access != AccessMode::Deny {
            return Err(PolicyError::UnsupportedGlobAccess {
                access: self.access,
            });
        }
        Ok(())
    }
}

fn validate_protected_relative_path(path: PathBuf) -> Result<PathBuf, PolicyError> {
    if path.as_os_str().is_empty() {
        return Err(PolicyError::InvalidProtectedPath {
            path,
            reason: "path must not be empty".to_string(),
        });
    }
    if crate::path::contains_nul(&path) {
        return Err(PolicyError::InvalidProtectedPath {
            path,
            reason: "path must not contain a NUL character".to_string(),
        });
    }
    if path.is_absolute() {
        return Err(PolicyError::InvalidProtectedPath {
            path,
            reason: "path must be relative".to_string(),
        });
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(value) => normalized.push(value),
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(PolicyError::InvalidProtectedPath {
                    path,
                    reason: "path must not contain parent traversal or a root".to_string(),
                });
            }
        }
    }
    if normalized.as_os_str().is_empty() {
        return Err(PolicyError::InvalidProtectedPath {
            path,
            reason: "path must name a descendant".to_string(),
        });
    }
    Ok(normalized)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RuleMatch {
    specificity: usize,
    access: AccessMode,
}
