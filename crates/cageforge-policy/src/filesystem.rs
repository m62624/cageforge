// Copyright 2026 Mansur Azatbek
// SPDX-License-Identifier: Apache-2.0

use crate::AccessMode;
use crate::PathPattern;
use crate::PathResolutionContext;
use crate::PathSelector;
use crate::PolicyError;
use std::num::NonZeroUsize;
use std::path::Path;

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

    /// Creates a rule from a validated glob pattern.
    pub const fn from_target(target: FilesystemTarget, access: AccessMode) -> Self {
        Self {
            target,
            access,
            missing_path_behavior: MissingPathBehavior::Error,
            read_only_subpaths: Vec::new(),
        }
    }

    /// Creates an absolute-path glob rule.
    pub fn absolute_glob(
        pattern: impl Into<String>,
        access: AccessMode,
    ) -> Result<Self, PolicyError> {
        Ok(Self::from_target(
            FilesystemTarget::Glob(PathPattern::absolute(pattern)?),
            access,
        ))
    }

    /// Creates a workspace-relative glob rule.
    pub fn workspace_glob(
        pattern: impl Into<String>,
        access: AccessMode,
    ) -> Result<Self, PolicyError> {
        Ok(Self::from_target(
            FilesystemTarget::Glob(PathPattern::workspace(pattern)?),
            access,
        ))
    }

    /// Sets how the backend handles an absent concrete target.
    pub const fn with_missing_path_behavior(mut self, behavior: MissingPathBehavior) -> Self {
        self.missing_path_behavior = behavior;
        self
    }

    /// Adds a read-only carve-out below a writable rule.
    pub fn with_read_only_subpath(mut self, selector: PathSelector) -> Self {
        self.read_only_subpaths.push(selector);
        self
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
                .filter(|root| path.starts_with(root))
                .map(|root| (selector.specificity(&root), true))
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
                    .filter(|root| path.starts_with(root))
                    .map(|root| subpath.specificity(&root))
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
}

impl FilesystemPolicy {
    /// Creates a restricted policy from filesystem rules.
    pub fn restricted(entries: impl IntoIterator<Item = FilesystemRule>) -> Self {
        Self {
            mode: FilesystemMode::Restricted,
            entries: entries.into_iter().collect(),
            glob_scan_max_depth: None,
        }
    }

    /// Creates a policy with no Cageforge filesystem restrictions.
    pub const fn unrestricted() -> Self {
        Self {
            mode: FilesystemMode::Unrestricted,
            entries: Vec::new(),
            glob_scan_max_depth: None,
        }
    }

    /// Creates a policy whose filesystem boundary is owned by another sandbox.
    pub const fn external() -> Self {
        Self {
            mode: FilesystemMode::External,
            entries: Vec::new(),
            glob_scan_max_depth: None,
        }
    }

    /// Sets the maximum depth used when a backend expands glob targets.
    pub const fn with_glob_scan_max_depth(mut self, depth: NonZeroUsize) -> Self {
        self.glob_scan_max_depth = Some(depth);
        self
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

    /// Adds one rule while retaining the existing policy.
    pub fn with_rule(mut self, rule: FilesystemRule) -> Self {
        self.entries.push(rule);
        self
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
            if rule.access != AccessMode::Write && !rule.read_only_subpaths.is_empty() {
                return Err(PolicyError::InvalidRule {
                    message: "read-only subpaths require a writable parent rule".to_string(),
                });
            }
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
            if let Some(existing) = entries
                .iter_mut()
                .find(|existing: &&mut FilesystemRule| existing.target == rule.target)
            {
                existing.access = existing.access.most_restrictive(rule.access);
                existing.missing_path_behavior = existing
                    .missing_path_behavior
                    .min(rule.missing_path_behavior);
                for selector in &rule.read_only_subpaths {
                    if !existing.read_only_subpaths.contains(selector) {
                        existing.read_only_subpaths.push(selector.clone());
                    }
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
    pub fn access_for(&self, selector: &PathSelector) -> AccessMode {
        match self.mode {
            FilesystemMode::Unrestricted => AccessMode::Write,
            FilesystemMode::External => AccessMode::Deny,
            FilesystemMode::Restricted => self
                .entries
                .iter()
                .filter_map(|entry| match entry.target() {
                    FilesystemTarget::Scope(candidate) if candidate == selector => {
                        Some(entry.access())
                    }
                    FilesystemTarget::Scope(_) | FilesystemTarget::Glob(_) => None,
                })
                .reduce(AccessMode::most_restrictive)
                .unwrap_or(AccessMode::Deny),
        }
    }

    /// Resolves access for an absolute path using recursive and most-specific matching.
    pub fn access_for_path(
        &self,
        path: &Path,
        context: &PathResolutionContext,
    ) -> Result<AccessMode, PolicyError> {
        if !path.is_absolute() {
            return Err(PolicyError::ExpectedAbsolute {
                path: path.to_path_buf(),
            });
        }
        if path
            .components()
            .any(|component| component == std::path::Component::ParentDir)
        {
            return Err(PolicyError::ParentTraversal {
                path: path.to_path_buf(),
            });
        }
        match self.mode {
            FilesystemMode::Unrestricted => Ok(AccessMode::Write),
            FilesystemMode::External => Ok(AccessMode::Deny),
            FilesystemMode::Restricted => {
                let mut best: Option<RuleMatch> = None;
                for rule in &self.entries {
                    if let Some(candidate) = rule.matches_path(path, context) {
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
                Ok(best.map_or(AccessMode::Deny, |matched| matched.access))
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RuleMatch {
    specificity: usize,
    access: AccessMode,
}
