// SPDX-License-Identifier: Apache-2.0

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use cageforge_policy::{
    AccessMode, FilesystemDecision, FilesystemMode, NetworkDecision, NetworkMode, PathSelector,
    ResolvedNetworkTarget,
};

use crate::context::EffectivePathContext;
use crate::environment::EffectiveEnvironment;
use crate::error::{CompositionBoundary, CompositionError};
use crate::filesystem::EffectiveFilesystemPolicy;
use crate::model::{
    CompositionRequest, EffectiveNetworkPolicy, EffectiveSandbox, normalize_roots, root_is_within,
};
use crate::ownership::ExternalOwner;

/// Computes a safe effective sandbox from a requested policy and a ceiling.
///
/// Every filesystem and network decision must be permitted by both inputs.
/// The environment is narrowed in sequence and the inherited base is reduced
/// to the least permissive choice. An external owner can only be composed with
/// another external owner; silently combining external and local ownership
/// would make the enforcement boundary ambiguous.
pub fn compose(request: CompositionRequest<'_>) -> Result<EffectiveSandbox, CompositionError> {
    request
        .requested_policy
        .validate()
        .map_err(|source| CompositionError::InvalidRequestedPolicy { source })?;
    request
        .ceiling
        .policy()
        .validate()
        .map_err(|source| CompositionError::InvalidCeiling { source })?;

    validate_ownership(
        request.requested_policy.filesystem().mode(),
        request.ceiling.policy().filesystem().mode(),
        CompositionBoundary::Filesystem,
    )?;
    validate_ownership(
        request.requested_policy.network().mode(),
        request.ceiling.policy().network().mode(),
        CompositionBoundary::Network,
    )?;
    validate_external_owner(
        request.requested_policy.filesystem().mode() == FilesystemMode::External,
        request.external_owner.as_ref(),
        request.ceiling.external_owner(),
        CompositionBoundary::Filesystem,
    )?;
    validate_external_owner(
        request.requested_policy.network().mode() == NetworkMode::External,
        request.external_owner.as_ref(),
        request.ceiling.external_owner(),
        CompositionBoundary::Network,
    )?;
    if request.requested_policy.filesystem().mode() != FilesystemMode::External
        && request.requested_policy.network().mode() != NetworkMode::External
        && (request.external_owner.is_some() || request.ceiling.external_owner().is_some())
    {
        return Err(CompositionError::UnexpectedExternalOwner {
            boundary: CompositionBoundary::Filesystem,
        });
    }

    let workspace_roots = intersect_workspace_roots(
        request.requested_workspace_roots.as_deref(),
        request.ceiling.workspace_roots(),
    )?;

    Ok(EffectiveSandbox::new(
        EffectiveFilesystemPolicy::new(
            request.requested_policy.filesystem().clone(),
            request.ceiling.policy().filesystem().clone(),
        ),
        EffectiveNetworkPolicy::new(
            request.requested_policy.network().clone(),
            request.ceiling.policy().network().clone(),
        ),
        EffectiveEnvironment::new(
            request.requested_environment.clone(),
            request.ceiling.environment().clone(),
        ),
        workspace_roots,
    ))
}

impl EffectiveFilesystemPolicy {
    /// Evaluates a symbolic filesystem selector against both policies.
    pub fn access_for(&self, selector: &PathSelector) -> FilesystemDecision {
        combine_filesystem_decisions(
            self.requested().access_for(selector),
            self.ceiling().access_for(selector),
        )
    }

    /// Evaluates a concrete filesystem path against both policies.
    pub fn access_for_path(
        &self,
        path: &Path,
        context: &EffectivePathContext,
    ) -> Result<FilesystemDecision, CompositionError> {
        let requested = self
            .requested()
            .access_for_path(path, context.as_ref())
            .map_err(|source| CompositionError::PolicyEvaluation {
                boundary: CompositionBoundary::Filesystem,
                source,
            })?;
        let ceiling = self
            .ceiling()
            .access_for_path(path, context.as_ref())
            .map_err(|source| CompositionError::PolicyEvaluation {
                boundary: CompositionBoundary::Filesystem,
                source,
            })?;
        Ok(combine_filesystem_decisions(requested, ceiling))
    }
}

impl EffectiveNetworkPolicy {
    /// Evaluates a domain against both policies.
    pub fn decision_for_domain(&self, domain: &str) -> Result<NetworkDecision, CompositionError> {
        let requested = self
            .requested()
            .decision_for_domain(domain)
            .map_err(|source| CompositionError::PolicyEvaluation {
                boundary: CompositionBoundary::Network,
                source,
            })?;
        let ceiling = self
            .ceiling()
            .decision_for_domain(domain)
            .map_err(|source| CompositionError::PolicyEvaluation {
                boundary: CompositionBoundary::Network,
                source,
            })?;
        Ok(combine_network_decisions(requested, ceiling))
    }

    /// Evaluates a domain and all addresses resolved for it against both
    /// policies.
    ///
    /// The resolver belongs to the consuming backend. Passing every resolved
    /// address, or an empty slice after a failed lookup, keeps DNS and network
    /// I/O outside this pure composition crate while preserving narrowing.
    pub fn decision_for_domain_with_resolved_ips(
        &self,
        domain: &str,
        resolved_ips: &[IpAddr],
    ) -> Result<NetworkDecision, CompositionError> {
        let requested = self
            .requested()
            .decision_for_domain_with_resolved_ips(domain, resolved_ips)
            .map_err(|source| CompositionError::PolicyEvaluation {
                boundary: CompositionBoundary::Network,
                source,
            })?;
        let ceiling = self
            .ceiling()
            .decision_for_domain_with_resolved_ips(domain, resolved_ips)
            .map_err(|source| CompositionError::PolicyEvaluation {
                boundary: CompositionBoundary::Network,
                source,
            })?;
        Ok(combine_network_decisions(requested, ceiling))
    }

    /// Evaluates one resolved network target against both component policies.
    pub fn decision_for_resolved_target(
        &self,
        target: &ResolvedNetworkTarget,
    ) -> Result<NetworkDecision, CompositionError> {
        let requested = self
            .requested()
            .decision_for_resolved_target(target)
            .map_err(|source| CompositionError::PolicyEvaluation {
                boundary: CompositionBoundary::Network,
                source,
            })?;
        let ceiling = self
            .ceiling()
            .decision_for_resolved_target(target)
            .map_err(|source| CompositionError::PolicyEvaluation {
                boundary: CompositionBoundary::Network,
                source,
            })?;
        Ok(combine_network_decisions(requested, ceiling))
    }

    /// Evaluates the exact address a backend is about to connect to against
    /// both component policies.
    pub fn decision_for_connected_address(
        &self,
        target: &ResolvedNetworkTarget,
        connected: SocketAddr,
    ) -> Result<NetworkDecision, CompositionError> {
        let requested = self
            .requested()
            .decision_for_connected_address(target, connected)
            .map_err(|source| CompositionError::PolicyEvaluation {
                boundary: CompositionBoundary::Network,
                source,
            })?;
        let ceiling = self
            .ceiling()
            .decision_for_connected_address(target, connected)
            .map_err(|source| CompositionError::PolicyEvaluation {
                boundary: CompositionBoundary::Network,
                source,
            })?;
        Ok(combine_network_decisions(requested, ceiling))
    }

    /// Evaluates a Unix socket against both policies.
    pub fn decision_for_unix_socket(
        &self,
        socket: &Path,
    ) -> Result<NetworkDecision, CompositionError> {
        let requested = self
            .requested()
            .decision_for_unix_socket(socket)
            .map_err(|source| CompositionError::PolicyEvaluation {
                boundary: CompositionBoundary::Network,
                source,
            })?;
        let ceiling = self
            .ceiling()
            .decision_for_unix_socket(socket)
            .map_err(|source| CompositionError::PolicyEvaluation {
                boundary: CompositionBoundary::Network,
                source,
            })?;
        Ok(combine_network_decisions(requested, ceiling))
    }
}

fn validate_ownership(
    requested: impl EnforcementMode,
    ceiling: impl EnforcementMode,
    boundary: CompositionBoundary,
) -> Result<(), CompositionError> {
    if requested.delegates_enforcement() != ceiling.delegates_enforcement() {
        return Err(CompositionError::EnforcementOwnershipConflict { boundary });
    }
    Ok(())
}

fn validate_external_owner(
    external: bool,
    requested_owner: Option<&ExternalOwner>,
    ceiling_owner: Option<&ExternalOwner>,
    boundary: CompositionBoundary,
) -> Result<(), CompositionError> {
    if external && (requested_owner != ceiling_owner || requested_owner.is_none()) {
        return Err(CompositionError::ExternalOwnerMismatch { boundary });
    }
    Ok(())
}

trait EnforcementMode {
    fn delegates_enforcement(self) -> bool;
}

impl EnforcementMode for FilesystemMode {
    fn delegates_enforcement(self) -> bool {
        self == Self::External
    }
}

impl EnforcementMode for NetworkMode {
    fn delegates_enforcement(self) -> bool {
        self == Self::External
    }
}

fn combine_filesystem_decisions(
    requested: FilesystemDecision,
    ceiling: FilesystemDecision,
) -> FilesystemDecision {
    match (requested, ceiling) {
        (FilesystemDecision::ExternallyEnforced, FilesystemDecision::ExternallyEnforced) => {
            FilesystemDecision::ExternallyEnforced
        }
        (FilesystemDecision::ExternallyEnforced, _)
        | (_, FilesystemDecision::ExternallyEnforced) => FilesystemDecision::Deny,
        (left, right) => match (left.as_access_mode(), right.as_access_mode()) {
            (Some(left), Some(right)) => AccessMode::most_restrictive(left, right).into(),
            _ => FilesystemDecision::Deny,
        },
    }
}

fn combine_network_decisions(
    requested: NetworkDecision,
    ceiling: NetworkDecision,
) -> NetworkDecision {
    match (requested, ceiling) {
        (NetworkDecision::ExternallyEnforced, NetworkDecision::ExternallyEnforced) => {
            NetworkDecision::ExternallyEnforced
        }
        (NetworkDecision::ExternallyEnforced, _) | (_, NetworkDecision::ExternallyEnforced) => {
            NetworkDecision::Deny
        }
        (NetworkDecision::Allow, NetworkDecision::Allow) => NetworkDecision::Allow,
        _ => NetworkDecision::Deny,
    }
}

fn intersect_workspace_roots(
    requested_roots: Option<&[PathBuf]>,
    ceiling_roots: Option<&[PathBuf]>,
) -> Result<Option<Vec<PathBuf>>, CompositionError> {
    let requested_roots = requested_roots
        .map(|roots| normalize_roots(roots.iter().cloned()))
        .transpose()?;
    let ceiling_roots = ceiling_roots
        .map(|roots| normalize_roots(roots.iter().cloned()))
        .transpose()?;

    match (requested_roots, ceiling_roots) {
        (Some(requested), Some(ceiling)) => {
            for root in &requested {
                if !root_is_within(root, &ceiling) {
                    return Err(CompositionError::WorkspaceRootNotGranted { path: root.clone() });
                }
            }
            Ok(Some(requested))
        }
        (Some(requested), None) => Ok(Some(requested)),
        (None, Some(ceiling)) => Ok(Some(ceiling)),
        (None, None) => Ok(None),
    }
}
