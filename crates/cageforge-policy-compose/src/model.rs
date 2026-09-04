// SPDX-License-Identifier: Apache-2.0

//! Public request, ceiling, and effective-result models for composition.
//!
//! [`crate::PolicyCeiling`] describes the outer limit,
//! [`crate::CompositionRequest`] supplies the requested values, and
//! [`crate::EffectiveSandbox`] is the only result that should cross into a
//! native execution layer.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use cageforge_command::EnvironmentSpec;
use cageforge_path::{NativePathKey, contains_parent_traversal, is_within};
use cageforge_policy::{
    DomainAccess, DomainMode, LocalNetworkAccess, NetworkMode, NetworkPolicy,
    PathResolutionContext, SandboxPolicy, UnixSocketMode,
};

use crate::CompositionError;
use crate::context::EffectivePathContext;
use crate::environment::EffectiveEnvironment;
use crate::filesystem::EffectiveFilesystemPolicy;
use crate::lowering::EffectiveNetworkLowering;
use crate::ownership::ExternalOwner;

mod types;

pub use types::{
    CompositionRequest, EffectiveNetworkPolicy, EffectiveNetworkRequirements, EffectiveSandbox,
    PolicyCeiling,
};

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

impl EffectiveSandbox {
    pub(crate) fn new(
        filesystem: EffectiveFilesystemPolicy,
        network: EffectiveNetworkPolicy,
        environment: EffectiveEnvironment,
        workspace_roots: Option<Vec<PathBuf>>,
        workspace_root_limit: Option<Vec<PathBuf>>,
    ) -> Self {
        Self {
            filesystem,
            network,
            environment,
            workspace_roots,
            workspace_root_limit,
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

    /// Returns the outer workspace-root ceiling, if one was configured.
    ///
    /// A ceiling limits explicit request roots and runtime roots but never
    /// creates a workspace root by itself.
    pub fn workspace_root_limit(&self) -> Option<&[PathBuf]> {
        self.workspace_root_limit.as_deref()
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
        for path in workspace_roots.iter().filter(|path| {
            self.workspace_root_limit()
                .is_none_or(|limit| root_is_within(path, limit))
        }) {
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
        if let Some(path) = base.current_directory() {
            context = context
                .with_current_directory(path.to_path_buf())
                .map_err(|source| CompositionError::InvalidPathContext { source })?;
        }
        Ok(EffectivePathContext::new(
            context,
            self.filesystem.context_identity(),
        ))
    }
}

impl EffectiveNetworkPolicy {
    pub(crate) fn new(requested: NetworkPolicy, ceiling: NetworkPolicy) -> Self {
        Self { requested, ceiling }
    }

    pub(crate) fn requested_policy(&self) -> &NetworkPolicy {
        &self.requested
    }

    pub(crate) fn ceiling_policy(&self) -> &NetworkPolicy {
        &self.ceiling
    }

    /// Returns the aggregate network requirements for backend preflight.
    pub fn requirements(&self) -> EffectiveNetworkRequirements {
        let mode = effective_network_mode(self.requested.mode(), self.ceiling.mode());
        let enabled = mode == NetworkMode::Enabled;
        let domain_rules = enabled
            && [&self.requested, &self.ceiling].iter().any(|policy| {
                !policy.domains().is_empty() || policy.domain_mode() != DomainMode::Enabled
            });
        let local_address_restrictions = enabled
            && [&self.requested, &self.ceiling]
                .iter()
                .any(|policy| policy.local_network_access() == LocalNetworkAccess::Deny);
        let policies = [&self.requested, &self.ceiling];
        let local_ipc_isolation = enabled
            && policies
                .iter()
                .any(|policy| denies_all_unix_sockets(policy));
        let local_ipc_rules = enabled
            && !local_ipc_isolation
            && policies.iter().any(|policy| {
                !policy.unix_sockets().is_empty()
                    || policy.unix_socket_mode() == UnixSocketMode::Restricted
            });
        EffectiveNetworkRequirements {
            mode,
            domain_rules,
            local_address_restrictions,
            resolved_targets: domain_rules || local_address_restrictions,
            local_ipc_isolation,
            local_ipc_rules,
        }
    }

    /// Returns every immutable network constraint needed by a native backend
    /// to lower this effective result.
    ///
    /// The returned view contains both mandatory layers. A backend must
    /// enforce their conjunction; the view is not a permission to select one
    /// layer and discard the other.
    pub fn lowering(&self) -> EffectiveNetworkLowering<'_> {
        EffectiveNetworkLowering::new(&self.requested, &self.ceiling)
    }
}

impl EffectiveNetworkRequirements {
    /// Returns the effective network ownership mode.
    pub const fn mode(self) -> NetworkMode {
        self.mode
    }

    /// Returns whether domain rules or a non-default domain mode are present.
    pub const fn domain_rules(self) -> bool {
        self.domain_rules
    }

    /// Returns whether non-public and special-purpose address restrictions are present.
    pub const fn local_address_restrictions(self) -> bool {
        self.local_address_restrictions
    }

    /// Returns whether exact resolved-target authorization is required.
    pub const fn resolved_targets(self) -> bool {
        self.resolved_targets
    }

    /// Returns whether pathname local-IPC endpoints must be fully
    /// unavailable.
    pub const fn local_ipc_isolation(self) -> bool {
        self.local_ipc_isolation
    }

    /// Returns whether per-path local-IPC endpoint rules must be enforced.
    pub const fn local_ipc_rules(self) -> bool {
        self.local_ipc_rules
    }
}

fn denies_all_unix_sockets(policy: &NetworkPolicy) -> bool {
    policy.unix_socket_mode() == UnixSocketMode::Disabled
        || (policy.unix_socket_mode() == UnixSocketMode::Restricted
            && !policy
                .unix_sockets()
                .iter()
                .any(|rule| rule.access() == DomainAccess::Allow))
}

fn effective_network_mode(left: NetworkMode, right: NetworkMode) -> NetworkMode {
    match (left, right) {
        (NetworkMode::External, NetworkMode::External) => NetworkMode::External,
        (NetworkMode::Disabled, _) | (_, NetworkMode::Disabled) => NetworkMode::Disabled,
        (NetworkMode::Enabled, NetworkMode::Enabled) => NetworkMode::Enabled,
        (NetworkMode::External, _) | (_, NetworkMode::External) => {
            // `compose` rejects mixed ownership before constructing this
            // model. If that invariant changes, fail closed rather than
            // turning an external boundary into a local permission.
            NetworkMode::Disabled
        }
    }
}

pub(crate) fn normalize_roots<I, P>(roots: I) -> Result<Vec<PathBuf>, CompositionError>
where
    I: IntoIterator<Item = P>,
    P: Into<PathBuf>,
{
    let mut normalized: Vec<PathBuf> = Vec::new();
    let mut seen = HashSet::new();
    for root in roots {
        let root = root.into();
        validate_root(&root)?;
        if seen.insert(NativePathKey::new(&root)) {
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
