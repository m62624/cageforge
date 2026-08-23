// SPDX-License-Identifier: Apache-2.0

//! Typed Linux backend failures.

use std::path::PathBuf;

use cageforge_backend_api::{BackendCapability, BackendContractError};
use thiserror::Error;

/// Errors raised while constructing, lowering, or launching the Linux
/// backend. Security-relevant failures remain distinguishable from ordinary
/// child-process failures.
#[derive(Debug, Error)]
pub enum LinuxBackendError {
    /// The common portable backend contract rejected the request.
    #[error("backend preflight failed: {0}")]
    Contract(#[from] BackendContractError),
    /// The configured Bubblewrap executable was not found.
    #[error("Bubblewrap executable was not found")]
    BubblewrapUnavailable,
    /// The in-sandbox hardening helper was not found.
    #[error("Cageforge Linux hardening helper was not found")]
    HardeningHelperUnavailable,
    /// The command path collides with the reserved in-sandbox helper path.
    #[error("command path is reserved by the Linux backend hardening helper: {path:?}")]
    HardeningHelperPathCollision {
        /// Reserved path requested as the user command.
        path: PathBuf,
    },
    /// Bubblewrap did not expose the flags required by this backend.
    #[error("Bubblewrap executable is missing required capabilities: {missing:?}")]
    BubblewrapIncompatible {
        /// Required Bubblewrap flags absent from its help output.
        missing: Vec<String>,
    },
    /// A Bubblewrap user-namespace probe failed.
    #[error("Bubblewrap cannot create the required user/network namespace: {message}")]
    UserNamespaceUnavailable {
        /// Diagnostic emitted by the namespace probe.
        message: String,
    },
    /// The backend configuration cannot provide the requested proc boundary.
    #[error("the requested proc mount is unavailable")]
    ProcMountUnavailable,
    /// The policy requires a capability this implementation cannot enforce.
    #[error("Linux backend cannot safely enforce {capability}")]
    UnsupportedCapability {
        /// Capability that the Linux implementation cannot enforce.
        capability: BackendCapability,
    },
    /// The runtime path cannot be safely lowered.
    #[error("filesystem lowering failed for {path:?}: {reason}")]
    FilesystemLoweringFailed {
        /// Path whose mount or mask could not be constructed.
        path: PathBuf,
        /// Explanation of the failed lowering step.
        reason: String,
    },
    /// The network policy cannot be lowered by this backend.
    #[error("network lowering failed: {reason}")]
    NetworkLoweringFailed {
        /// Explanation of the failed network lowering step.
        reason: String,
    },
    /// A process failed to spawn.
    #[error("failed to spawn sandboxed process: {source}")]
    ProcessSpawnFailed {
        /// Operating-system error returned by process creation.
        source: std::io::Error,
    },
    /// The child exceeded its effective timeout.
    #[error("sandboxed process exceeded its timeout")]
    ProcessTimedOut,
    /// Waiting for the child failed.
    #[error("failed while waiting for sandboxed process: {source}")]
    ProcessWaitFailed {
        /// Operating-system error returned while waiting or terminating.
        source: std::io::Error,
    },
}
