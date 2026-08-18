// Copyright 2026 Mansur Azatbek
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

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

impl std::fmt::Display for CompositionBoundary {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Filesystem => formatter.write_str("filesystem"),
            Self::Network => formatter.write_str("network"),
        }
    }
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
    /// One side delegates enforcement while the other expects local enforcement.
    #[error("{boundary} enforcement ownership cannot be composed safely")]
    EnforcementOwnershipConflict {
        /// The boundary with incompatible ownership.
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
