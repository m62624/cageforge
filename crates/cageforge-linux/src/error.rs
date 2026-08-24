// SPDX-License-Identifier: Apache-2.0

//! Typed Linux backend failures.

use std::fmt;
use std::io;
use std::path::PathBuf;

use cageforge_backend_api::{BackendCapability, BackendContractError};
use cageforge_network_proxy::GatewayError;
use thiserror::Error;

/// The filesystem operation whose native lowering failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilesystemMetadataOperation {
    /// Inspecting a requested scope.
    Scope,
    /// Inspecting a mask target.
    Mask,
    /// Inspecting an ancestor while checking a writable symlink boundary.
    WritableSymlinkAncestor,
    /// Inspecting a descendant mount target.
    DescendantMount,
}

impl fmt::Display for FilesystemMetadataOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let operation = match self {
            Self::Scope => "scope",
            Self::Mask => "mask",
            Self::WritableSymlinkAncestor => "writable symlink ancestor",
            Self::DescendantMount => "descendant mount",
        };
        formatter.write_str(operation)
    }
}

/// A typed failure while translating a portable filesystem rule to Bubblewrap
/// mounts. Each variant identifies the failed operation without requiring a
/// caller to parse an implementation-specific reason string.
#[derive(Debug, Error)]
pub enum FilesystemLoweringError {
    /// Metadata for a native path could not be inspected.
    #[error("cannot inspect {operation} metadata: {source}")]
    Metadata {
        /// Operation being performed.
        operation: FilesystemMetadataOperation,
        /// Operating-system failure.
        #[source]
        source: io::Error,
    },
    /// A mount target was empty or relative.
    #[error("mount target must be an absolute non-empty path")]
    InvalidMountTarget,
    /// The requested target overlaps a backend-reserved path.
    #[error("the Linux backend reserves /proc and its private runtime/state mounts")]
    ReservedRuntimePath,
    /// The fixed in-sandbox gateway socket has no parent directory.
    #[error("gateway socket has no parent directory")]
    GatewaySocketParentMissing,
    /// A mount source could not be canonicalized before Bubblewrap lowering.
    #[error("cannot canonicalize the mount source: {source}")]
    Canonicalize {
        /// Operating-system failure.
        #[source]
        source: io::Error,
    },
    /// A deny target was incorrectly passed to a bind-mount operation.
    #[error("deny access cannot be lowered as a bind mount")]
    DenyBind,
    /// A pinned mount source descriptor could not be cloned.
    #[error("cannot clone the pinned mount source: {source}")]
    CloneSource {
        /// Operating-system failure.
        #[source]
        source: io::Error,
    },
    /// A mount source contained an embedded NUL byte.
    #[error("mount source contains NUL")]
    SourceContainsNul,
    /// A mount source descriptor could not be opened.
    #[error("cannot open the mount source: {source}")]
    OpenSource {
        /// Operating-system failure.
        #[source]
        source: io::Error,
    },
    /// The filesystem root cannot be replaced with a deny mask.
    #[error("the filesystem root cannot be masked")]
    RootCannotBeMasked,
    /// An attempted protected mask crosses a writable symbolic link.
    #[error("protected path crosses writable symbolic link {symlink:?}")]
    WritableSymlink {
        /// Symbolic link that would make the mask escape its writable root.
        symlink: PathBuf,
    },
    /// The shared empty mask source could not be opened.
    #[error("cannot open the empty mask source: {source}")]
    EmptyMaskSource {
        /// Operating-system failure.
        #[source]
        source: io::Error,
    },
}

/// A network mount relationship that cannot be lowered safely.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum NetworkLoweringError {
    /// A proxy-routed policy did not receive its authenticated gateway mount.
    #[error("proxy-routed policy has no authenticated gateway mount")]
    MissingGatewayMount,
    /// A gateway mount was supplied to a policy that must not use one.
    #[error("gateway mount was supplied for a policy that must not use it")]
    UnexpectedGatewayMount,
}

/// A network policy combination that needs a capability not represented by
/// the Linux backend's native lowering.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum NetworkCombinationError {
    /// Proxy routing must also isolate unrestricted pathname Unix sockets.
    #[error("proxy-routed Linux networking requires pathname Unix socket isolation")]
    ProxyRequiresUnixSocketIsolation,
}

/// The expected invariant when portable and native filesystem decisions
/// disagree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyLoweringExpectation {
    /// A directly matched deny glob must lower to a denied path.
    DenyGlobMatch,
}

impl fmt::Display for PolicyLoweringExpectation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DenyGlobMatch => formatter.write_str("deny-glob match"),
        }
    }
}

/// A failure returned by the per-launch gateway thread.
#[derive(Debug, Error)]
pub enum NetworkGatewayRuntimeError {
    /// The runtime reported a concrete failure.
    #[error("{reason}")]
    Failed {
        /// Runtime diagnostic.
        reason: String,
    },
    /// The startup readiness channel closed before reporting a result.
    #[error("gateway startup channel closed: {message}")]
    StartupChannelClosed {
        /// Channel diagnostic.
        message: String,
    },
    /// The gateway thread terminated by panic.
    #[error("gateway runtime thread panicked")]
    Panicked,
}

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
    /// A bundled Bubblewrap resource had no trusted digest manifest.
    #[error("bundled Bubblewrap digest manifest was not found: {path:?}")]
    BubblewrapDigestUnavailable {
        /// Bundled executable whose digest manifest is missing.
        path: PathBuf,
    },
    /// A bundled Bubblewrap resource did not match its digest manifest.
    #[error("bundled Bubblewrap digest mismatch for {path:?}: expected {expected}, got {actual}")]
    BubblewrapDigestMismatch {
        /// Bundled executable whose digest was checked.
        path: PathBuf,
        /// Digest declared by the resource manifest.
        expected: String,
        /// Digest calculated from the executable.
        actual: String,
    },
    /// The in-sandbox hardening helper was not found.
    #[error("Cageforge Linux hardening helper was not found")]
    HardeningHelperUnavailable,
    /// The configured packaged-resource directory was not available.
    #[error("Cageforge Linux resource directory was not found")]
    ResourceDirectoryUnavailable,
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
    /// A Bubblewrap compatibility probe could not run or be observed.
    #[error("Bubblewrap {stage} probe failed: {source}")]
    BubblewrapProbeFailed {
        /// Probe operation that failed.
        stage: &'static str,
        /// Operating-system failure.
        #[source]
        source: std::io::Error,
    },
    /// A Bubblewrap compatibility probe did not complete within its deadline.
    #[error("Bubblewrap {stage} probe timed out")]
    BubblewrapProbeTimedOut {
        /// Probe operation that exceeded its deadline.
        stage: &'static str,
    },
    /// A Bubblewrap compatibility probe emitted an unsafe amount of output.
    #[error("Bubblewrap {stage} probe emitted more than {limit} bytes per stream")]
    BubblewrapProbeOutputLimitExceeded {
        /// Probe operation that exceeded its output bound.
        stage: &'static str,
        /// Per-stream byte limit.
        limit: usize,
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
    #[error("filesystem lowering failed for {path:?}: {source}")]
    FilesystemLoweringFailed {
        /// Path whose mount or mask could not be constructed.
        path: PathBuf,
        /// Typed native lowering failure.
        #[source]
        source: FilesystemLoweringError,
    },
    /// The network policy cannot be lowered by this backend.
    #[error("network lowering failed: {0}")]
    NetworkLoweringFailed(#[from] NetworkLoweringError),
    /// Two individually valid network settings require an unsupported Linux lowering.
    #[error("Linux backend cannot enforce this network policy combination: {0}")]
    UnsupportedNetworkCombination(#[from] NetworkCombinationError),
    /// The policy-enforcing host gateway could not be constructed.
    #[error("failed to initialize the Linux network gateway: {source}")]
    NetworkGatewayInitialization {
        /// Gateway construction failure.
        #[source]
        source: GatewayError,
    },
    /// A per-run bridge authentication token could not be generated.
    #[error("failed to generate the Linux network bridge token: {source}")]
    NetworkBridgeTokenGeneration {
        /// Operating-system randomness failure.
        #[source]
        source: getrandom::Error,
    },
    /// The private host-to-namespace gateway transport could not be prepared.
    #[error("failed to prepare the Linux network gateway transport: {source}")]
    NetworkGatewaySetup {
        /// Host runtime setup failure.
        #[source]
        source: std::io::Error,
    },
    /// The host gateway stopped while its sandboxed process still depended on it.
    #[error("Linux network gateway runtime failed: {0}")]
    NetworkGatewayRuntimeFailed(#[from] NetworkGatewayRuntimeError),
    /// A deny-glob would require scanning an unsafe or unbounded root.
    #[error("deny-glob {pattern:?} cannot be scanned safely from {search_root:?}")]
    UnsafeGlobScan {
        /// Validated policy pattern that could not be lowered safely.
        pattern: String,
        /// Static scan root derived from the pattern.
        search_root: PathBuf,
    },
    /// Reading a deny-glob scan root failed.
    #[error("failed to expand deny-glob {pattern:?} at {path:?}: {source}")]
    GlobScanFailed {
        /// Validated policy pattern being expanded.
        pattern: String,
        /// Filesystem path that could not be inspected.
        path: PathBuf,
        /// Operating-system error raised during the scan.
        #[source]
        source: std::io::Error,
    },
    /// One deny-glob matched more paths than the safe startup bound.
    #[error("deny-glob {pattern:?} matched more than {limit} paths")]
    GlobMatchLimitExceeded {
        /// Validated policy pattern being expanded.
        pattern: String,
        /// Maximum number of concrete paths accepted by one expansion.
        limit: usize,
    },
    /// A deny-glob filesystem walk exceeded its startup work bound.
    #[error("deny-glob {pattern:?} scanned more than {limit} filesystem entries")]
    GlobScanEntryLimitExceeded {
        /// Validated policy pattern being expanded.
        pattern: String,
        /// Maximum number of directory entries inspected by one expansion.
        limit: usize,
    },
    /// Native lowering disagreed with the effective portable policy.
    #[error("policy lowering mismatch for {path:?}: expected {expected}")]
    PolicyLoweringMismatch {
        /// Path whose portable and native interpretations disagreed.
        path: PathBuf,
        /// Native invariant that was expected.
        expected: PolicyLoweringExpectation,
    },
    /// The per-user setup lock could not be opened or acquired.
    #[error("failed to acquire Linux sandbox setup lock {path:?}: {source}")]
    SetupLockFailed {
        /// Lock file path.
        path: PathBuf,
        /// Operating-system failure.
        #[source]
        source: std::io::Error,
    },
    /// The setup lock is not a private regular file owned by the current user.
    #[error("Linux sandbox setup lock is unsafe: {path:?}")]
    UnsafeSetupLock {
        /// Rejected lock path.
        path: PathBuf,
    },
    /// A temporary Bubblewrap mount target could not be created or removed.
    #[error("temporary Bubblewrap mount target failed at {path:?}: {source}")]
    SyntheticMountTargetFailed {
        /// Temporary host path.
        path: PathBuf,
        /// Operating-system failure.
        #[source]
        source: std::io::Error,
    },
    /// A temporary Bubblewrap mount target changed identity before cleanup.
    #[error("temporary Bubblewrap mount target changed before cleanup: {path:?}")]
    SyntheticMountTargetChanged {
        /// Temporary host path whose identity changed.
        path: PathBuf,
    },
    /// A protected path became present after lowering but before command release.
    #[error("protected path appeared before Linux sandbox launch: {path:?}")]
    ProtectedPathAppearedBeforeLaunch {
        /// Protected path whose missing-state invariant changed.
        path: PathBuf,
    },
    /// A protected path was created while the sandboxed command was running.
    #[error("sandboxed command created protected path {path:?}")]
    ProtectedPathCreated {
        /// Protected path removed by the backend monitor.
        path: PathBuf,
    },
    /// The per-launch protected-path monitor could not be started.
    #[error("failed to start protected-path monitor: {source}")]
    ProtectedPathMonitorSetupFailed {
        /// Thread startup failure.
        #[source]
        source: std::io::Error,
    },
    /// Inspecting or removing a newly created protected path failed.
    #[error("protected-path monitor failed at {path:?}: {source}")]
    ProtectedPathMonitorFailed {
        /// Protected path being monitored.
        path: PathBuf,
        /// Filesystem operation failure.
        #[source]
        source: std::io::Error,
    },
    /// The per-launch protected-path monitor panicked.
    #[error("protected-path monitor thread panicked")]
    ProtectedPathMonitorPanicked,
    /// Bubblewrap failed before its native namespace setup handshake completed.
    #[error("Linux sandbox setup handshake failed: {source}; child diagnostic: {diagnostic}")]
    SetupHandshakeFailed {
        /// Authentication-channel failure.
        #[source]
        source: std::io::Error,
        /// Captured Bubblewrap/helper diagnostic, when stderr was piped.
        diagnostic: String,
    },
    /// The trusted helper returned an invalid native command status frame.
    #[error("failed to receive sandboxed command status: {source}")]
    CommandStatusFailed {
        /// Status-channel failure.
        #[source]
        source: std::io::Error,
    },
    /// A process failed to spawn.
    #[error("failed to spawn sandboxed process: {source}")]
    ProcessSpawnFailed {
        /// Operating-system error returned by process creation.
        source: std::io::Error,
    },
    /// Selecting or validating the platform environment failed.
    #[error("failed to prepare the sandboxed process environment: {source}")]
    EnvironmentPreparationFailed {
        /// Portable environment-model failure.
        #[source]
        source: cageforge_command::CommandError,
    },
    /// The backend could not establish a PID-reuse-safe automatic timeout.
    #[error("failed to start the Linux timeout watchdog: {source}")]
    TimeoutWatchdogSetupFailed {
        /// Linux pidfd or watchdog-thread setup failure.
        #[source]
        source: std::io::Error,
    },
    /// The automatic timeout watchdog could not terminate its exact child.
    #[error("Linux timeout watchdog failed: {source}")]
    TimeoutWatchdogFailed {
        /// Linux pidfd signaling failure.
        #[source]
        source: std::io::Error,
    },
    /// The automatic timeout watchdog thread panicked.
    #[error("Linux timeout watchdog thread panicked")]
    TimeoutWatchdogPanicked,
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
