// SPDX-License-Identifier: Apache-2.0

//! Effective filesystem constraints for backend lowering.
//!
//! [`crate::EffectiveFilesystemPolicy`] keeps its component policies private
//! and exposes only combined decisions and aggregate requirements. This keeps
//! a backend from accidentally lowering the requested side without the
//! ceiling.

use std::num::NonZeroUsize;

use cageforge_policy::{
    AccessMode, FilesystemMode, FilesystemPolicy, FilesystemTarget, PathSelector,
};

use crate::context::{ContextIdentity, EffectivePathContext};

/// Filesystem decisions constrained by both input policies.
///
/// The component policies remain private. Use the decision methods and
/// [`EffectiveFilesystemRequirements`] rather than selecting one side for
/// backend lowering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveFilesystemPolicy {
    requested: FilesystemPolicy,
    ceiling: FilesystemPolicy,
    context_identity: ContextIdentity,
}

/// The filesystem features a backend must be able to enforce for one
/// effective composition.
///
/// This is an aggregate view. It intentionally does not expose the requested
/// policy or the ceiling as independent policies, because a backend must not
/// accidentally lower either side without applying the other side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EffectiveFilesystemRequirements {
    mode: FilesystemMode,
    scopes: bool,
    absolute_scopes: bool,
    workspace_scopes: bool,
    root_scopes: bool,
    minimal_scopes: bool,
    tmpdir_scopes: bool,
    slash_tmp_scopes: bool,
    globs: bool,
    glob_scan_depth: bool,
    read_only_subpaths: bool,
    missing_path_behavior: bool,
    protected_paths: bool,
}

impl EffectiveFilesystemRequirements {
    /// Returns the effective filesystem ownership mode.
    pub const fn mode(self) -> FilesystemMode {
        self.mode
    }

    /// Returns whether any concrete or symbolic scope must be enforced.
    pub const fn scopes(self) -> bool {
        self.scopes
    }

    /// Returns whether absolute scopes or absolute globs are present.
    pub const fn absolute_scopes(self) -> bool {
        self.absolute_scopes
    }

    /// Returns whether workspace-relative scopes or globs are present.
    pub const fn workspace_scopes(self) -> bool {
        self.workspace_scopes
    }

    /// Returns whether system-root scopes are present.
    pub const fn root_scopes(self) -> bool {
        self.root_scopes
    }

    /// Returns whether minimal-runtime scopes are present.
    pub const fn minimal_scopes(self) -> bool {
        self.minimal_scopes
    }

    /// Returns whether temporary-directory scopes are present.
    pub const fn tmpdir_scopes(self) -> bool {
        self.tmpdir_scopes
    }

    /// Returns whether conventional `/tmp` scopes are present.
    pub const fn slash_tmp_scopes(self) -> bool {
        self.slash_tmp_scopes
    }

    /// Returns whether deny globs are present.
    pub const fn globs(self) -> bool {
        self.globs
    }

    /// Returns whether glob scan-depth semantics must be enforced.
    pub const fn glob_scan_depth(self) -> bool {
        self.glob_scan_depth
    }

    /// Returns whether read-only carve-outs are present.
    pub const fn read_only_subpaths(self) -> bool {
        self.read_only_subpaths
    }

    /// Returns whether missing-path behavior must be enforced.
    pub const fn missing_path_behavior(self) -> bool {
        self.missing_path_behavior
    }

    /// Returns whether protected relative paths must be enforced.
    pub const fn protected_paths(self) -> bool {
        self.protected_paths
    }
}

impl EffectiveFilesystemPolicy {
    pub(crate) fn new(
        requested: FilesystemPolicy,
        ceiling: FilesystemPolicy,
        context_identity: ContextIdentity,
    ) -> Self {
        Self {
            requested,
            ceiling,
            context_identity,
        }
    }

    pub(crate) fn requested_policy(&self) -> &FilesystemPolicy {
        &self.requested
    }

    pub(crate) fn ceiling_policy(&self) -> &FilesystemPolicy {
        &self.ceiling
    }

    /// Returns the aggregate filesystem requirements for backend preflight.
    pub fn requirements(&self) -> EffectiveFilesystemRequirements {
        let mut requirements = EffectiveFilesystemRequirements {
            mode: effective_mode(self.requested.mode(), self.ceiling.mode()),
            scopes: false,
            absolute_scopes: false,
            workspace_scopes: false,
            root_scopes: false,
            minimal_scopes: false,
            tmpdir_scopes: false,
            slash_tmp_scopes: false,
            globs: false,
            glob_scan_depth: false,
            read_only_subpaths: false,
            missing_path_behavior: false,
            protected_paths: false,
        };

        for policy in [&self.requested, &self.ceiling] {
            requirements.protected_paths |= !policy.protected_relative_paths().is_empty();
            for rule in policy.entries() {
                requirements.missing_path_behavior |=
                    matches!(rule.target(), FilesystemTarget::Scope(_));
                match rule.target() {
                    FilesystemTarget::Scope(selector) => {
                        add_selector_requirements(&mut requirements, selector);
                    }
                    FilesystemTarget::Glob(pattern) => {
                        requirements.scopes = true;
                        requirements.globs = true;
                        if pattern.is_absolute() {
                            requirements.absolute_scopes = true;
                        } else {
                            requirements.workspace_scopes = true;
                        }
                        requirements.glob_scan_depth |= rule.access() == AccessMode::Deny;
                    }
                }
                for selector in rule.read_only_subpaths() {
                    add_selector_requirements(&mut requirements, selector);
                }
                requirements.read_only_subpaths |= !rule.read_only_subpaths().is_empty();
            }
        }
        requirements
    }

    pub(crate) fn context_identity(&self) -> ContextIdentity {
        self.context_identity.clone()
    }

    pub(crate) fn owns_context(&self, context: &EffectivePathContext) -> bool {
        context.belongs_to(&self.context_identity)
    }

    /// Returns the scan depth required to preserve all deny-glob rules.
    ///
    /// A bounded depth is widened to the larger bound. If a relevant deny
    /// glob is unbounded on either side, the effective result is unbounded.
    pub fn glob_scan_max_depth(&self) -> Option<NonZeroUsize> {
        merge_glob_scan_depth(
            effective_glob_scan_depth(&self.requested),
            effective_glob_scan_depth(&self.ceiling),
        )
    }
}

fn effective_mode(left: FilesystemMode, right: FilesystemMode) -> FilesystemMode {
    match (left, right) {
        (FilesystemMode::External, FilesystemMode::External) => FilesystemMode::External,
        (FilesystemMode::Restricted, _) | (_, FilesystemMode::Restricted) => {
            FilesystemMode::Restricted
        }
        (FilesystemMode::Unrestricted, FilesystemMode::Unrestricted) => {
            FilesystemMode::Unrestricted
        }
        (FilesystemMode::External, _) | (_, FilesystemMode::External) => {
            unreachable!("mixed filesystem ownership is rejected during composition")
        }
    }
}

fn add_selector_requirements(
    requirements: &mut EffectiveFilesystemRequirements,
    selector: &PathSelector,
) {
    requirements.scopes = true;
    if selector.is_absolute_scope() {
        requirements.absolute_scopes = true;
    } else if selector.is_workspace_scope() {
        requirements.workspace_scopes = true;
    } else if selector.is_root_scope() {
        requirements.root_scopes = true;
    } else if selector.is_minimal_scope() {
        requirements.minimal_scopes = true;
    } else if selector.is_tmpdir_scope() {
        requirements.tmpdir_scopes = true;
    } else if selector.is_slash_tmp_scope() {
        requirements.slash_tmp_scopes = true;
    }
}

fn effective_glob_scan_depth(policy: &FilesystemPolicy) -> Option<Option<NonZeroUsize>> {
    policy
        .entries()
        .iter()
        .any(|entry| {
            matches!(entry.target(), cageforge_policy::FilesystemTarget::Glob(_))
                && entry.access() == AccessMode::Deny
        })
        .then_some(policy.glob_scan_max_depth())
}

fn merge_glob_scan_depth(
    left: Option<Option<NonZeroUsize>>,
    right: Option<Option<NonZeroUsize>>,
) -> Option<NonZeroUsize> {
    match (left, right) {
        (Some(None), _) | (_, Some(None)) => None,
        (Some(Some(left)), Some(Some(right))) => Some(left.max(right)),
        (Some(Some(depth)), None) | (None, Some(Some(depth))) => Some(depth),
        (None, None) => None,
    }
}
