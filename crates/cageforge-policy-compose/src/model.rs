// Copyright 2026 Mansur Azatbek
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::path::{Component, Path, PathBuf};

use cageforge_command::{EnvironmentBase, EnvironmentSpec};
use cageforge_policy::{FilesystemPolicy, NetworkPolicy, SandboxPolicy};

use crate::CompositionError;

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
}

impl PolicyCeiling {
    /// Creates a ceiling with no workspace-root limit.
    pub fn new(policy: SandboxPolicy, environment: EnvironmentSpec) -> Self {
        Self {
            policy,
            environment,
            workspace_roots: None,
        }
    }

    /// Limits requested workspace roots to the supplied root scopes.
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
}

/// Inputs to a pure policy composition operation.
#[derive(Debug, Clone, Copy)]
pub struct CompositionRequest<'a> {
    pub(crate) requested_policy: &'a SandboxPolicy,
    pub(crate) requested_environment: &'a EnvironmentSpec,
    pub(crate) requested_workspace_roots: &'a [PathBuf],
    pub(crate) ceiling: &'a PolicyCeiling,
}

impl<'a> CompositionRequest<'a> {
    /// Creates a composition request from portable policy declarations.
    pub fn new(
        requested_policy: &'a SandboxPolicy,
        requested_environment: &'a EnvironmentSpec,
        requested_workspace_roots: &'a [PathBuf],
        ceiling: &'a PolicyCeiling,
    ) -> Self {
        Self {
            requested_policy,
            requested_environment,
            requested_workspace_roots,
            ceiling,
        }
    }
}

/// The effective policy constraints after composition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveSandbox {
    filesystem: EffectiveFilesystemPolicy,
    network: EffectiveNetworkPolicy,
    environment: EffectiveEnvironment,
    workspace_roots: Vec<PathBuf>,
}

impl EffectiveSandbox {
    pub(crate) fn new(
        filesystem: EffectiveFilesystemPolicy,
        network: EffectiveNetworkPolicy,
        environment: EffectiveEnvironment,
        workspace_roots: Vec<PathBuf>,
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

    /// Returns workspace roots that remain inside the ceiling.
    pub fn workspace_roots(&self) -> &[PathBuf] {
        &self.workspace_roots
    }
}

/// A filesystem decision constrained by both input policies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveFilesystemPolicy {
    requested: FilesystemPolicy,
    ceiling: FilesystemPolicy,
}

impl EffectiveFilesystemPolicy {
    pub(crate) fn new(requested: FilesystemPolicy, ceiling: FilesystemPolicy) -> Self {
        Self { requested, ceiling }
    }

    /// Returns the requested filesystem policy retained for backend lowering.
    pub fn requested(&self) -> &FilesystemPolicy {
        &self.requested
    }

    /// Returns the ceiling filesystem policy retained for backend lowering.
    pub fn ceiling(&self) -> &FilesystemPolicy {
        &self.ceiling
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

/// An environment transformation constrained by two portable specifications.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveEnvironment {
    requested: EnvironmentSpec,
    ceiling: EnvironmentSpec,
}

impl EffectiveEnvironment {
    pub(crate) fn new(requested: EnvironmentSpec, ceiling: EnvironmentSpec) -> Self {
        Self { requested, ceiling }
    }

    /// Returns the least permissive inherited-environment base.
    pub fn base(&self) -> EnvironmentBase {
        least_permissive_base(self.requested.base(), self.ceiling.base())
    }

    /// Returns the requested environment specification.
    pub fn requested(&self) -> &EnvironmentSpec {
        &self.requested
    }

    /// Returns the ceiling environment specification.
    pub fn ceiling(&self) -> &EnvironmentSpec {
        &self.ceiling
    }

    /// Applies both environment transformations without allowing the ceiling
    /// to introduce a variable absent from the requested result.
    ///
    /// The caller must provide variables selected according to [`Self::base`];
    /// this method applies the portable filters and overrides after that base
    /// has been selected.
    pub fn apply_to<I>(&self, variables: I) -> BTreeMap<OsString, OsString>
    where
        I: IntoIterator<Item = (OsString, OsString)>,
    {
        let requested = self.requested.apply_to(variables);
        let requested_names: Vec<OsString> = requested.keys().cloned().collect();
        let mut effective = self.ceiling.apply_to(requested);
        effective.retain(|name, _| {
            requested_names
                .iter()
                .any(|requested_name| environment_names_equal(requested_name, name))
        });
        effective
    }
}

pub(crate) fn normalize_roots<I, P>(roots: I) -> Result<Vec<PathBuf>, CompositionError>
where
    I: IntoIterator<Item = P>,
    P: Into<PathBuf>,
{
    let mut normalized = Vec::new();
    for root in roots {
        let root = root.into();
        validate_root(&root)?;
        if !normalized.iter().any(|existing| existing == &root) {
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
    if path
        .components()
        .any(|component| component == Component::ParentDir)
    {
        return Err(CompositionError::InvalidWorkspaceRoot {
            path: path.to_path_buf(),
            reason: "parent traversal is not allowed",
        });
    }
    Ok(())
}

pub(crate) fn root_is_within(root: &Path, ceiling_roots: &[PathBuf]) -> bool {
    ceiling_roots
        .iter()
        .any(|ceiling_root| root.starts_with(ceiling_root))
}

fn least_permissive_base(left: EnvironmentBase, right: EnvironmentBase) -> EnvironmentBase {
    match (left, right) {
        (EnvironmentBase::None, _) | (_, EnvironmentBase::None) => EnvironmentBase::None,
        (EnvironmentBase::Core, _) | (_, EnvironmentBase::Core) => EnvironmentBase::Core,
        (EnvironmentBase::All, EnvironmentBase::All) => EnvironmentBase::All,
    }
}

fn environment_names_equal(left: &OsStr, right: &OsStr) -> bool {
    left.to_string_lossy()
        .eq_ignore_ascii_case(&right.to_string_lossy())
}
