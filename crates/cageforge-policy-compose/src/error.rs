// SPDX-License-Identifier: Apache-2.0

//! Typed failures raised while composing portable policy boundaries.

use std::path::PathBuf;

use cageforge_command::{CommandError, EnvironmentBase};
use cageforge_policy::PolicyError;
use thiserror::Error;

/// The policy boundary involved in a composition error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompositionBoundary {
    /// The filesystem policy boundary.
    Filesystem,
    /// The network policy boundary.
    Network,
}

/// An error raised while narrowing a requested policy.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CompositionError {
    /// The requested policy failed its own invariant checks.
    #[error("requested sandbox policy is invalid: {source}")]
    InvalidRequestedPolicy {
        /// The validation error from the policy crate.
        #[source]
        source: PolicyError,
    },
    /// The ceiling failed its own invariant checks.
    #[error("policy ceiling is invalid: {source}")]
    InvalidCeiling {
        /// The validation error from the policy crate.
        #[source]
        source: PolicyError,
    },
    /// A path could not be used as a workspace-root declaration.
    #[error("invalid workspace root {path:?}: {reason}")]
    InvalidWorkspaceRoot {
        /// The invalid root declaration.
        path: PathBuf,
        /// Why the declaration is unsafe or ambiguous.
        reason: &'static str,
    },
    /// A requested root is outside the roots permitted by the ceiling.
    #[error("requested workspace root {path:?} is outside the policy ceiling")]
    WorkspaceRootNotGranted {
        /// The root that could not be granted.
        path: PathBuf,
    },
    /// The effective runtime path context could not be rebuilt safely.
    #[error("effective path context is invalid: {source}")]
    InvalidPathContext {
        /// The underlying path-context validation error.
        #[source]
        source: PolicyError,
    },
    /// A filesystem context came from a different effective composition.
    #[error("effective path context belongs to a different composed sandbox")]
    PathContextMismatch,
    /// The caller supplied an environment base broader than the effective
    /// composition allows.
    #[error("environment input base {supplied:?} is broader than effective base {required:?}")]
    EnvironmentBaseTooPermissive {
        /// The narrowest base accepted by the effective policy.
        required: EnvironmentBase,
        /// The base supplied by the backend caller.
        supplied: EnvironmentBase,
    },
    /// Applying a validated environment transformation failed.
    #[error("environment transformation failed: {source}")]
    EnvironmentApplication {
        /// The command-layer error raised while applying the transformation.
        #[source]
        source: CommandError,
    },
    /// One side delegates enforcement while the other expects local enforcement.
    #[error("{boundary} enforcement ownership cannot be composed safely")]
    EnforcementOwnershipConflict {
        /// The boundary with incompatible ownership.
        boundary: CompositionBoundary,
    },
    /// External enforcement was requested without one shared owner proof.
    #[error("{boundary} external enforcement requires one shared owner proof")]
    ExternalOwnerMismatch {
        /// The boundary with unrelated or missing external owners.
        boundary: CompositionBoundary,
    },
    /// An external owner proof was attached to a locally enforced boundary.
    #[error("{boundary} external owner proof is only valid for external enforcement")]
    UnexpectedExternalOwner {
        /// The boundary with an unexpected owner proof.
        boundary: CompositionBoundary,
    },
    /// Evaluating one component policy failed after composition.
    #[error("{boundary} policy evaluation failed: {source}")]
    PolicyEvaluation {
        /// The boundary being evaluated.
        boundary: CompositionBoundary,
        /// The underlying policy error.
        #[source]
        source: PolicyError,
    },
}

impl std::fmt::Display for CompositionBoundary {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Filesystem => formatter.write_str("filesystem"),
            Self::Network => formatter.write_str("network"),
        }
    }
}
