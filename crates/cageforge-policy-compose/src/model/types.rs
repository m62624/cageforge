// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use cageforge_command::EnvironmentSpec;
use cageforge_policy::{NetworkMode, NetworkPolicy, SandboxPolicy};

use crate::environment::EffectiveEnvironment;
use crate::filesystem::EffectiveFilesystemPolicy;
use crate::ownership::ExternalOwner;

/// A neutral maximum policy supplied by the component that owns the outer
/// safety boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyCeiling {
    pub(super) policy: SandboxPolicy,
    pub(super) environment: EnvironmentSpec,
    pub(super) workspace_roots: Option<Vec<PathBuf>>,
    pub(super) external_owner: Option<ExternalOwner>,
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

/// The effective policy constraints after composition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveSandbox {
    pub(super) filesystem: EffectiveFilesystemPolicy,
    pub(super) network: EffectiveNetworkPolicy,
    pub(super) environment: EffectiveEnvironment,
    pub(super) workspace_roots: Option<Vec<PathBuf>>,
    pub(super) workspace_root_limit: Option<Vec<PathBuf>>,
}

/// Network decisions constrained by both input policies.
///
/// The component policies remain private. Use the decision methods and
/// [`EffectiveNetworkRequirements`] for preflight, and [`Self::lowering`] for
/// native lowering. The lowering view contains both sides as mandatory
/// constraints rather than selecting one side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveNetworkPolicy {
    pub(super) requested: NetworkPolicy,
    pub(super) ceiling: NetworkPolicy,
}

/// The network features a backend must be able to enforce for one effective
/// composition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EffectiveNetworkRequirements {
    pub(super) mode: NetworkMode,
    pub(super) domain_rules: bool,
    pub(super) local_address_restrictions: bool,
    pub(super) resolved_targets: bool,
    pub(super) unix_socket_isolation: bool,
    pub(super) unix_socket_rules: bool,
}
