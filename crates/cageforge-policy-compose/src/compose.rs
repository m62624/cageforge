// Copyright 2026 Mansur Azatbek
// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};

use cageforge_policy::{
    AccessMode, FilesystemDecision, FilesystemMode, NetworkDecision, NetworkMode,
    PathResolutionContext, PathSelector,
};

use crate::error::{CompositionBoundary, CompositionError};
use crate::model::{
    CompositionRequest, EffectiveEnvironment, EffectiveFilesystemPolicy, EffectiveNetworkPolicy,
    EffectiveSandbox, normalize_roots, root_is_within,
};

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

    let workspace_roots = intersect_workspace_roots(
        request.requested_workspace_roots,
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
        context: &PathResolutionContext,
    ) -> Result<FilesystemDecision, CompositionError> {
        let requested = self
            .requested()
            .access_for_path(path, context)
            .map_err(|source| CompositionError::PolicyEvaluation {
                boundary: CompositionBoundary::Filesystem,
                source,
            })?;
        let ceiling = self
            .ceiling()
            .access_for_path(path, context)
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
    requested_roots: &[PathBuf],
    ceiling_roots: Option<&[PathBuf]>,
) -> Result<Vec<PathBuf>, CompositionError> {
    let requested_roots = normalize_roots(requested_roots.iter().cloned())?;
    let Some(ceiling_roots) = ceiling_roots else {
        return Ok(requested_roots);
    };

    for root in &requested_roots {
        if !root_is_within(root, ceiling_roots) {
            return Err(CompositionError::WorkspaceRootNotGranted { path: root.clone() });
        }
    }
    Ok(requested_roots)
}
