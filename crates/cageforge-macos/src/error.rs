// SPDX-License-Identifier: Apache-2.0

//! Typed macOS backend failures.

use std::io;
use std::path::PathBuf;

use cageforge_backend_api::{BackendCapability, BackendContractError};
use cageforge_command::CommandError;
use thiserror::Error;

/// Errors returned by the macOS backend.
#[derive(Debug, Error)]
pub enum MacosBackendError {
    /// Portable capability or prepared-handoff validation failed.
    #[error(transparent)]
    Contract(#[from] BackendContractError),
    /// The effective filesystem policy could not be lowered safely.
    #[error(transparent)]
    Filesystem(#[from] MacosFilesystemError),
    /// The effective network policy could not be lowered safely.
    #[error(transparent)]
    Network(#[from] MacosNetworkError),
    /// Seatbelt profile construction failed before process launch.
    #[error(transparent)]
    SeatbeltProfile(#[from] SeatbeltProfileError),
    /// The Seatbelt process could not be started.
    #[error("failed to start macOS Seatbelt process: {source}")]
    ProcessStart {
        /// The operating-system failure.
        #[source]
        source: io::Error,
    },
    /// The parent-death notification channel could not be created.
    #[error("failed to create macOS sandbox parent-death channel: {source}")]
    ParentDeathChannel {
        /// The operating-system failure.
        #[source]
        source: io::Error,
    },
    /// Waiting for the sandbox boundary failed.
    #[error("failed to wait for macOS sandbox boundary: {source}")]
    ProcessWait {
        /// The operating-system failure.
        #[source]
        source: io::Error,
    },
    /// The boundary was transferred to the detached recovery owner after a
    /// failed cleanup attempt and is no longer accessible through this child.
    #[error("macOS sandbox boundary is owned by its recovery owner")]
    BoundaryOwnedByRecovery,
    /// The command exceeded its prepared timeout.
    #[error("the macOS sandboxed command exceeded its prepared timeout")]
    ProcessTimedOut,
    /// The independent command-timeout worker could not be created.
    #[error("failed to start macOS command-timeout watchdog: {source}")]
    TimeoutWatchdogSetup {
        /// The operating-system thread creation failure.
        #[source]
        source: io::Error,
    },
    /// The timeout worker failed while supervising its process group.
    #[error("macOS command-timeout watchdog panicked")]
    TimeoutWatchdogPanicked,
    /// Watchdog signalling and child collection could not be synchronized.
    #[error("macOS command-timeout watchdog synchronization is poisoned")]
    TimeoutWatchdogLockPoisoned,
    /// The prepared timeout cannot be represented by the native monotonic
    /// deadline used by the child lifecycle.
    #[error("macOS sandbox timeout cannot be represented by a native deadline: {timeout_ms} ms")]
    TimeoutOutOfRange {
        /// The rejected timeout in milliseconds.
        timeout_ms: u128,
    },
    /// The process boundary could not be terminated and confirmed.
    #[error("could not confirm termination of the complete macOS sandbox process group")]
    BoundaryTerminationUnconfirmed,
    /// A process-group operation failed.
    #[error("macOS sandbox process-group operation failed: {source}")]
    ProcessGroup {
        /// The operating-system failure.
        #[source]
        source: io::Error,
    },
    /// The host lacks the native API needed to signal an exact process
    /// generation without risking delivery to a reused PID.
    #[error(
        "macOS does not provide proc_signal_with_audittoken for generation-bound process cleanup"
    )]
    VersionedProcessSignallingUnavailable,
    /// The process identifier cannot be represented by the native `pid_t`.
    #[error("macOS sandbox process ID {pid} is outside the native pid_t range")]
    ProcessGroupPidOutOfRange {
        /// Process identifier returned by the Rust child handle.
        pid: u32,
    },
    /// The native process-group identifier is zero and cannot be used as a
    /// sandbox boundary target.
    #[error("macOS sandbox returned an invalid zero process-group ID")]
    ProcessGroupIdInvalid,
    /// Selecting the backend environment or applying its transforms failed.
    #[error("failed to prepare the macOS command environment: {source}")]
    EnvironmentPreparation {
        /// Portable environment construction failure.
        #[source]
        source: CommandError,
    },
    /// The configured Seatbelt executable could not be inspected.
    #[error("failed to inspect Seatbelt executable {path:?}: {source}")]
    SeatbeltExecutable {
        /// The configured executable.
        path: PathBuf,
        /// The operating-system failure.
        #[source]
        source: io::Error,
    },
    /// The configured Seatbelt executable is a symbolic link and cannot be
    /// pinned safely by the backend.
    #[error("Seatbelt executable must not be a symbolic link: {path:?}")]
    SeatbeltExecutableSymlink {
        /// Rejected executable path.
        path: PathBuf,
    },
    /// The configured Seatbelt executable is not a regular file.
    #[error("Seatbelt executable is not a regular file: {path:?}")]
    SeatbeltExecutableNotRegular {
        /// Rejected executable path.
        path: PathBuf,
    },
    /// Native lowering is not yet available for a requested capability.
    #[error("macOS backend cannot safely lower requested capability: {capability}")]
    UnsupportedCapability {
        /// The unsupported portable capability.
        capability: BackendCapability,
    },
}

/// Filesystem failures raised while constructing a Seatbelt policy.
#[derive(Debug, Error)]
pub enum MacosFilesystemError {
    /// The prepared request no longer belongs to the backend instance that
    /// performed preflight, or its capability snapshot changed.
    #[error(transparent)]
    BackendContract(#[from] BackendContractError),
    /// The effective policy delegates enforcement to another owner.
    #[error("external filesystem ownership is not a local macOS backend mode")]
    ExternalOwnership,
    /// A required concrete path was not present.
    #[error("required filesystem scope is missing: {path:?}")]
    RequiredPathMissing {
        /// The missing path.
        path: PathBuf,
    },
    /// The backend could not inspect a path.
    #[error("failed to inspect filesystem scope {path:?}: {source}")]
    Metadata {
        /// The inspected path.
        path: PathBuf,
        /// The operating-system failure.
        #[source]
        source: io::Error,
    },
    /// A scope or carve-out traversed a symbolic link.
    #[error("filesystem scope contains a symbolic link: {path:?}")]
    Symlink {
        /// Symbolic link encountered while inspecting the scope.
        path: PathBuf,
    },
    /// A read-only carve-out escaped its writable root.
    #[error("read-only path {path:?} is outside writable root {root:?}")]
    ReadOnlyOutsideRoot {
        /// Read-only path requested by the policy.
        path: PathBuf,
        /// Writable root that was expected to contain the path.
        root: PathBuf,
    },
    /// A filesystem scope was not an absolute normalized path after context
    /// resolution.
    #[error("macOS filesystem scope is not an absolute normalized path: {path:?}")]
    InvalidScope {
        /// Rejected scope path.
        path: PathBuf,
    },
    /// A workspace root could not be represented in the UTF-8 Seatbelt glob
    /// expression required by the native lowering.
    #[error("macOS filesystem glob root is not valid UTF-8: {path:?}")]
    GlobRootNotUtf8 {
        /// Workspace root that cannot be represented in a Seatbelt regex.
        path: PathBuf,
    },
    /// A canonical target of an absolute deny glob could not be represented
    /// losslessly in the Seatbelt regex used for the native lowering.
    #[error("macOS filesystem glob canonical target is not valid UTF-8: {path:?}")]
    GlobCanonicalPathNotUtf8 {
        /// Canonical path that cannot be represented in the Seatbelt profile.
        path: PathBuf,
    },
    /// A filesystem glob had an access mode other than deny.
    #[error("macOS filesystem glob {pattern:?} must use deny access")]
    NonDenyGlob {
        /// Rejected policy glob.
        pattern: String,
    },
}

/// Network failures raised while constructing a macOS launch.
#[derive(Debug, Error)]
pub enum MacosNetworkError {
    /// The prepared request failed the portable backend contract.
    #[error(transparent)]
    BackendContract(#[from] BackendContractError),
    /// The effective policy delegates network enforcement to another owner.
    #[error("external network ownership is not a local macOS backend mode")]
    ExternalOwnership,
    /// The requested pathname Unix-socket mode is not representable by the
    /// native policy being constructed.
    #[error("macOS pathname Unix-socket policy is not representable: {mode:?}")]
    UnixSocketPolicy {
        /// The exact portable mode that could not be lowered.
        mode: cageforge_policy::UnixSocketMode,
    },
    /// The per-instance gateway could not be created.
    #[error("failed to create the per-instance macOS network gateway: {source}")]
    Gateway {
        /// The gateway failure.
        #[source]
        source: cageforge_network_proxy::GatewayError,
    },
    /// The gateway listener could not be created.
    #[error("failed to bind the per-instance macOS gateway ingress: {source}")]
    Listener {
        /// The operating-system failure.
        #[source]
        source: io::Error,
    },
    /// The gateway runtime could not create its async runtime.
    #[error("failed to construct the macOS network gateway runtime: {source}")]
    RuntimeConstruction {
        /// The operating-system failure.
        #[source]
        source: io::Error,
    },
    /// The gateway listener could not be registered with its runtime.
    #[error("failed to register the macOS network gateway listener: {source}")]
    ListenerRegistration {
        /// The operating-system failure.
        #[source]
        source: io::Error,
    },
    /// The gateway thread could not be created.
    #[error("failed to start the macOS network gateway thread: {source}")]
    ThreadSpawn {
        /// Thread creation failure.
        #[source]
        source: io::Error,
    },
    /// The gateway listener failed after startup.
    #[error("macOS network gateway listener failed: {source}")]
    RuntimeListener {
        /// The operating-system failure.
        #[source]
        source: io::Error,
    },
    /// The gateway stopped before reporting readiness.
    #[error("macOS network gateway startup channel closed")]
    StartupChannelClosed,
    /// The gateway did not report readiness within its startup deadline.
    #[error("macOS network gateway did not report readiness within {timeout_ms} ms")]
    StartupTimeout {
        /// Maximum time allowed for gateway runtime startup.
        timeout_ms: u128,
    },
    /// The gateway stopped unexpectedly while its child was active.
    #[error("macOS network gateway stopped unexpectedly")]
    RuntimeStopped,
    /// The gateway did not finish shutting down within the bounded cleanup
    /// interval. Its owner must retain the runtime and retry cleanup.
    #[error("macOS network gateway did not shut down within {timeout_ms} ms")]
    RuntimeShutdownTimeout {
        /// Maximum time allowed for one gateway shutdown attempt.
        timeout_ms: u128,
    },
    /// The gateway thread panicked.
    #[error("macOS network gateway runtime panicked")]
    RuntimePanicked,
}

/// Failures while rendering a Seatbelt profile.
#[derive(Debug, Error)]
pub enum SeatbeltProfileError {
    /// A path could not be represented as a valid Seatbelt definition.
    #[error("path contains an unsupported NUL character: {path:?}")]
    PathContainsNul {
        /// Path that could not be represented in a Seatbelt definition.
        path: PathBuf,
    },
    /// A filesystem glob could not be represented in a Seatbelt regex.
    #[error("filesystem glob contains an unsupported NUL character: {pattern:?}")]
    GlobContainsNul {
        /// Glob that could not be represented in a Seatbelt definition.
        pattern: String,
    },
    /// A generated Seatbelt definition name was not a valid parameter name.
    #[error("generated Seatbelt definition name is invalid: {name:?}")]
    InvalidDefinitionName {
        /// Invalid generated definition name.
        name: String,
    },
    /// A generated Seatbelt profile fragment contained an invalid value.
    #[error("generated Seatbelt profile fragment is invalid: {fragment}")]
    InvalidFragment {
        /// Bounded fragment description for diagnostics.
        fragment: &'static str,
    },
}
