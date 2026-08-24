// SPDX-License-Identifier: Apache-2.0

//! Typed Linux backend failures.

use std::path::PathBuf;

use cageforge_backend_api::{BackendCapability, BackendContractError};
use cageforge_network_proxy::GatewayError;
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
    /// Two individually valid network settings require an unsupported Linux lowering.
    #[error("Linux backend cannot enforce this network policy combination: {reason}")]
    UnsupportedNetworkCombination {
        /// Stable explanation of the incompatible effective settings.
        reason: &'static str,
    },
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
    #[error("Linux network gateway runtime failed: {reason}")]
    NetworkGatewayRuntimeFailed {
        /// Runtime failure diagnostic.
        reason: String,
    },
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
        expected: &'static str,
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
