// Copyright 2026 Mansur Azatbek
// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};

use cageforge_command::EnvironmentSpec;
use cageforge_path::{contains_parent_traversal, is_within, paths_equal};
use cageforge_policy::{NetworkPolicy, PathResolutionContext, SandboxPolicy};

use crate::CompositionError;
use crate::context::EffectivePathContext;
use crate::environment::EffectiveEnvironment;
use crate::filesystem::EffectiveFilesystemPolicy;
use crate::ownership::ExternalOwner;

/// A neutral maximum policy supplied by the component that owns the outer
/// safety boundary.
///
/// A ceiling is not a backend or a harness contract. It is simply another
/// portable policy whose decisions must also permit an operation. Workspace
/// roots are unrestricted when no root limit was configured; use
/// [`Self::with_workspace_roots`] to make the limit explicit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyCeiling {
    policy: SandboxPolicy,
    environment: EnvironmentSpec,
    workspace_roots: Option<Vec<PathBuf>>,
    external_owner: Option<ExternalOwner>,
}

impl PolicyCeiling {
    /// Creates a ceiling with no workspace-root limit.
    pub fn new(policy: SandboxPolicy, environment: EnvironmentSpec) -> Self {
        Self {
            policy,
            environment,
            workspace_roots: None,
            external_owner: None,
        }
    }

    /// Limits requested workspace roots to supplied runtime-resolved absolute scopes.
    pub fn with_workspace_roots<I, P>(mut self, roots: I) -> Result<Self, CompositionError>
    where
        I: IntoIterator<Item = P>,
        P: Into<PathBuf>,
    {
        self.workspace_roots = Some(normalize_roots(roots)?);
        Ok(self)
    }

    /// Removes the workspace-root limit explicitly.
    pub fn without_workspace_root_limit(mut self) -> Self {
        self.workspace_roots = None;
        self
    }

    /// Associates an external-enforcement owner proof with this ceiling.
    pub fn with_external_owner(mut self, owner: ExternalOwner) -> Self {
        self.external_owner = Some(owner);
        self
    }

    /// Returns the portable policy ceiling.
    pub fn policy(&self) -> &SandboxPolicy {
        &self.policy
    }

    /// Returns the environment restrictions in the ceiling.
    pub fn environment(&self) -> &EnvironmentSpec {
        &self.environment
    }

    /// Returns the configured workspace-root limit, if any.
    pub fn workspace_roots(&self) -> Option<&[PathBuf]> {
        self.workspace_roots.as_deref()
    }

    pub(crate) fn external_owner(&self) -> Option<&ExternalOwner> {
        self.external_owner.as_ref()
    }
}

/// Inputs to a pure policy composition operation.
#[derive(Debug, Clone)]
pub struct CompositionRequest<'a> {
    pub(crate) requested_policy: &'a SandboxPolicy,
    pub(crate) requested_environment: &'a EnvironmentSpec,
    pub(crate) requested_workspace_roots: Option<Vec<PathBuf>>,
    pub(crate) ceiling: &'a PolicyCeiling,
    pub(crate) external_owner: Option<ExternalOwner>,
}

impl<'a> CompositionRequest<'a> {
    /// Creates a composition request from portable policy declarations.
    pub fn new(
        requested_policy: &'a SandboxPolicy,
        requested_environment: &'a EnvironmentSpec,
        ceiling: &'a PolicyCeiling,
    ) -> Self {
        Self {
            requested_policy,
            requested_environment,
            requested_workspace_roots: None,
            ceiling,
            external_owner: None,
        }
    }

    /// Limits the request to the supplied, runtime-resolved workspace roots.
    pub fn with_workspace_roots<I, P>(mut self, roots: I) -> Result<Self, CompositionError>
    where
        I: IntoIterator<Item = P>,
        P: Into<PathBuf>,
    {
        self.requested_workspace_roots = Some(normalize_roots(roots)?);
        Ok(self)
    }

    /// Associates an external-enforcement owner proof with this request.
    pub fn with_external_owner(mut self, owner: ExternalOwner) -> Self {
        self.external_owner = Some(owner);
        self
    }
}

/// The effective policy constraints after composition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveSandbox {
    filesystem: EffectiveFilesystemPolicy,
    network: EffectiveNetworkPolicy,
    environment: EffectiveEnvironment,
    workspace_roots: Option<Vec<PathBuf>>,
}

impl EffectiveSandbox {
    pub(crate) fn new(
        filesystem: EffectiveFilesystemPolicy,
        network: EffectiveNetworkPolicy,
        environment: EffectiveEnvironment,
        workspace_roots: Option<Vec<PathBuf>>,
    ) -> Self {
        Self {
            filesystem,
            network,
            environment,
            workspace_roots,
        }
    }

    /// Returns the composed filesystem constraint.
    pub fn filesystem(&self) -> &EffectiveFilesystemPolicy {
        &self.filesystem
    }

    /// Returns the composed network constraint.
    pub fn network(&self) -> &EffectiveNetworkPolicy {
        &self.network
    }

    /// Returns the composed environment constraint.
    pub fn environment(&self) -> &EffectiveEnvironment {
        &self.environment
    }

    /// Returns the effective workspace-root restriction.
    ///
    /// `None` means that composition did not add a workspace-root limit and a
    /// supplied runtime context may retain its existing roots. `Some(&[])`
    /// means that the effective request deliberately contains no workspace
    /// roots.
    pub fn workspace_roots(&self) -> Option<&[PathBuf]> {
        self.workspace_roots.as_deref()
    }

    /// Creates a runtime path context constrained by the effective roots.
    ///
    /// Non-workspace runtime paths are copied from `base`. When the effective
    /// result contains a root restriction, the base workspace roots are
    /// replaced by that restriction; otherwise they are retained unchanged.
    pub fn path_context(
        &self,
        base: &PathResolutionContext,
    ) -> Result<EffectivePathContext, CompositionError> {
        let mut context = PathResolutionContext::new();
        for path in base.root_paths() {
            context = context
                .with_root(path.clone())
                .map_err(|source| CompositionError::InvalidPathContext { source })?;
        }
        let workspace_roots = self
            .workspace_roots()
            .unwrap_or_else(|| base.workspace_roots());
        for path in workspace_roots {
            context = context
                .with_workspace_root(path.clone())
                .map_err(|source| CompositionError::InvalidPathContext { source })?;
        }
        for path in base.minimal_paths() {
            context = context
                .with_minimal_path(path.clone())
                .map_err(|source| CompositionError::InvalidPathContext { source })?;
        }
        if let Some(path) = base.tmpdir() {
            context = context
                .with_tmpdir(path.to_path_buf())
                .map_err(|source| CompositionError::InvalidPathContext { source })?;
        }
        if let Some(path) = base.slash_tmp() {
            context = context
                .with_slash_tmp(path.to_path_buf())
                .map_err(|source| CompositionError::InvalidPathContext { source })?;
        }
        Ok(EffectivePathContext::new(context))
    }
}

/// A network decision constrained by both input policies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveNetworkPolicy {
    requested: NetworkPolicy,
    ceiling: NetworkPolicy,
}

impl EffectiveNetworkPolicy {
    pub(crate) fn new(requested: NetworkPolicy, ceiling: NetworkPolicy) -> Self {
        Self { requested, ceiling }
    }

    /// Returns the requested network policy retained for backend lowering.
    pub fn requested(&self) -> &NetworkPolicy {
        &self.requested
    }

    /// Returns the ceiling network policy retained for backend lowering.
    pub fn ceiling(&self) -> &NetworkPolicy {
        &self.ceiling
    }
}

pub(crate) fn normalize_roots<I, P>(roots: I) -> Result<Vec<PathBuf>, CompositionError>
where
    I: IntoIterator<Item = P>,
    P: Into<PathBuf>,
{
    let mut normalized: Vec<PathBuf> = Vec::new();
    for root in roots {
        let root = root.into();
        validate_root(&root)?;
        if !normalized
            .iter()
            .any(|existing| paths_equal(existing, &root))
        {
            normalized.push(root);
        }
    }
    Ok(normalized)
}

pub(crate) fn validate_root(path: &Path) -> Result<(), CompositionError> {
    if path.as_os_str().is_empty() {
        return Err(CompositionError::InvalidWorkspaceRoot {
            path: path.to_path_buf(),
            reason: "root must not be empty",
        });
    }
    if path.to_string_lossy().contains('\0') {
        return Err(CompositionError::InvalidWorkspaceRoot {
            path: path.to_path_buf(),
            reason: "root must not contain NUL",
        });
    }
    if contains_parent_traversal(path) {
        return Err(CompositionError::InvalidWorkspaceRoot {
            path: path.to_path_buf(),
            reason: "parent traversal is not allowed",
        });
    }
    if !path.is_absolute() {
        return Err(CompositionError::InvalidWorkspaceRoot {
            path: path.to_path_buf(),
            reason: "root must be absolute at composition time",
        });
    }
    Ok(())
}

pub(crate) fn root_is_within(root: &Path, ceiling_roots: &[PathBuf]) -> bool {
    ceiling_roots
        .iter()
        .any(|ceiling_root| is_within(root, ceiling_root))
}
