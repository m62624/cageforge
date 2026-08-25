// SPDX-License-Identifier: Apache-2.0

//! Typed Linux backend failures.

use std::fmt;
use std::io;
use std::path::PathBuf;

use cageforge_backend_api::{BackendCapability, BackendContractError};
use cageforge_network_proxy::GatewayError;
use thiserror::Error;

/// A Bubblewrap command-line option required by the Linux backend.
///
/// Values identify missing executable support, not options that an application
/// or end user must pass manually. [`Self::purpose`] explains why Cageforge
/// requires each flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BubblewrapFlag {
    /// `--as-pid-1` support.
    AsPidOne,
    /// `--bind` support.
    Bind,
    /// `--bind-fd` support.
    BindFd,
    /// `--bind-try` support.
    BindTry,
    /// `--cap-drop` support.
    CapabilityDrop,
    /// `--chdir` support.
    ChangeDirectory,
    /// `--disable-userns` support.
    DisableUserNamespace,
    /// `--dir` support.
    Directory,
    /// `--dev` support.
    Devices,
    /// `--die-with-parent` support.
    DieWithParent,
    /// `--new-session` support.
    NewSession,
    /// `--perms` support.
    Permissions,
    /// `--proc` support.
    Proc,
    /// `--remount-ro` support.
    RemountReadOnly,
    /// `--ro-bind` support.
    ReadOnlyBind,
    /// `--ro-bind-data` support.
    ReadOnlyBindData,
    /// `--ro-bind-fd` support.
    ReadOnlyBindFd,
    /// `--tmpfs` support.
    Tmpfs,
    /// `--unshare-ipc` support.
    UnshareIpc,
    /// `--unshare-net` support.
    UnshareNetwork,
    /// `--unshare-pid` support.
    UnsharePid,
    /// `--unshare-user` support.
    UnshareUser,
}

/// A Linux namespace required by the Bubblewrap process boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxNamespace {
    /// User and mount privilege isolation established by `--unshare-user`.
    User,
    /// Process-tree isolation established by `--unshare-pid`.
    Pid,
    /// System V IPC isolation established by `--unshare-ipc`.
    Ipc,
    /// Network-stack isolation established by `--unshare-net`.
    Network,
}

/// Trusted executable captured into an immutable Linux launch snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxExecutable {
    /// Bubblewrap namespace launcher.
    Bubblewrap,
    /// Cageforge process-hardening helper.
    HardeningHelper,
}

/// Operation used while creating an immutable executable snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutableSnapshotOperation {
    /// Creating the anonymous executable file.
    Create,
    /// Cloning the validated source descriptor.
    CloneSource,
    /// Rewinding the validated source descriptor.
    RewindSource,
    /// Copying the executable bytes.
    Copy,
    /// Applying executable-only permissions.
    Permissions,
    /// Sealing the bytes against later mutation.
    Seal,
    /// Reopening the sealed snapshot through a read-only launch descriptor.
    OpenSnapshot,
}

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
    /// A deny target was incorrectly passed to a canonical bind-mount operation.
    #[error("deny access cannot be lowered as a canonical bind mount")]
    DenyCanonicalBind,
    /// A deny target was incorrectly passed to a descriptor bind-mount operation.
    #[error("deny access cannot be lowered as a descriptor bind mount")]
    DenyDescriptorBind,
    /// An immutable executable snapshot could not be opened for Bubblewrap.
    #[error("cannot open the immutable executable snapshot: {source}")]
    OpenExecutableSnapshot {
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
    /// A bind mount source or destination crosses a writable symbolic link.
    #[error("bind mount crosses writable symbolic link {symlink:?}")]
    WritableSymlinkMount {
        /// Symbolic link that would make the bind mount escape its writable root.
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

pub use crate::hardening_error::{
    EnvironmentFrameError, LinuxBridgeError, LinuxBridgeOperation, LinuxHardeningError,
    LinuxHardeningOperation, LinuxHelperRuntimeFailure, LinuxHelperRuntimeFailureKind,
    LinuxHelperSetupFailure, LinuxHelperSetupFailureKind, SeccompBuildError,
};

/// A framed command-status failure.
#[derive(Debug, Error)]
pub enum StatusFrameError {
    /// Reading a status frame component failed.
    #[error("command status frame {operation} failed: {source}")]
    Io {
        /// Frame component that could not be read.
        operation: &'static str,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },
    /// The helper closed the authenticated channel without reporting a result.
    #[error("command status frame was not reported")]
    MissingFrame,
    /// The status frame had an invalid magic prefix.
    #[error("command status frame magic did not match")]
    InvalidMagic,
    /// The helper returned an unknown status-result tag.
    #[error("command status frame returned unknown result tag {tag}")]
    InvalidResultTag {
        /// Unrecognized one-byte result tag.
        tag: u8,
    },
    /// The helper returned an unknown runtime-failure category.
    #[error("command status frame returned unknown helper failure code {code}")]
    InvalidFailureCode {
        /// Unrecognized stable wire code.
        code: u16,
    },
    /// The reader returned an invalid prefix length.
    #[error("command status frame returned an invalid prefix length")]
    InvalidPrefixLength,
}

/// A failure while completing the authenticated Bubblewrap setup handshake.
#[derive(Debug, Error)]
pub enum SetupHandshakeError {
    /// An authenticated channel operation failed.
    #[error("setup handshake I/O failed: {source}")]
    Io {
        /// Operating-system failure.
        #[source]
        source: io::Error,
    },
    /// The environment frame could not be sent.
    #[error("setup handshake environment frame failed: {source}")]
    EnvironmentFrame {
        /// Framing failure.
        #[source]
        source: EnvironmentFrameError,
    },
    /// The per-run gateway bridge token could not be sent.
    #[error("setup handshake gateway token failed: {source}")]
    GatewayToken {
        /// Transport failure.
        #[source]
        source: NetworkGatewayTransportError,
    },
    /// The helper returned a wrong ready marker.
    #[error("setup handshake ready marker did not match")]
    InvalidReady,
    /// The helper returned an unknown setup-result tag.
    #[error("setup handshake returned unknown result tag {tag}")]
    InvalidResultTag {
        /// Unrecognized one-byte result tag.
        tag: u8,
    },
    /// The helper returned an unknown typed failure category.
    #[error("setup handshake returned unknown helper failure code {code}")]
    InvalidFailureCode {
        /// Unrecognized stable wire code.
        code: u16,
    },
    /// The authenticated helper rejected setup before releasing the command.
    #[error("Linux hardening helper rejected setup: {failure}")]
    HelperRejected {
        /// Typed helper-side failure and retained OS error number.
        failure: LinuxHelperSetupFailure,
    },
}

/// A per-run gateway token transport failure.
#[derive(Debug, Error)]
pub enum NetworkGatewayTransportError {
    /// Writing the bridge token to the authenticated helper channel failed.
    #[error("writing the gateway bridge token failed: {source}")]
    BridgeTokenWrite {
        /// Operating-system failure.
        #[source]
        source: io::Error,
    },
}

/// A host gateway setup failure.
#[derive(Debug, Error)]
pub enum NetworkGatewaySetupError {
    /// Creating a private temporary directory failed.
    #[error("cannot create gateway temporary directory {parent:?}: {source}")]
    TemporaryDirectory {
        /// Parent directory selected for the temporary directory.
        parent: PathBuf,
        /// Operating-system failure.
        #[source]
        source: io::Error,
    },
    /// No candidate temporary directory was available.
    #[error("no usable temporary directory exists for the gateway")]
    NoTemporaryDirectory,
    /// The candidate Unix socket path exceeded Linux's address limit.
    #[error("gateway Unix socket path is too long: {path:?}")]
    SocketPathTooLong {
        /// Rejected socket path.
        path: PathBuf,
    },
    /// Setting the private directory permissions failed.
    #[error("cannot secure gateway directory {path:?}: {source}")]
    DirectoryPermissions {
        /// Directory whose mode could not be set.
        path: PathBuf,
        /// Operating-system failure.
        #[source]
        source: io::Error,
    },
    /// Binding the private gateway socket failed.
    #[error("cannot bind gateway socket {path:?}: {source}")]
    SocketBind {
        /// Socket path.
        path: PathBuf,
        /// Operating-system failure.
        #[source]
        source: io::Error,
    },
    /// Switching the gateway socket to nonblocking mode failed.
    #[error("cannot configure gateway socket {path:?}: {source}")]
    SocketNonblocking {
        /// Socket path.
        path: PathBuf,
        /// Operating-system failure.
        #[source]
        source: io::Error,
    },
    /// Starting the gateway thread failed.
    #[error("cannot start gateway thread: {source}")]
    ThreadSpawn {
        /// Operating-system failure.
        #[source]
        source: io::Error,
    },
}

/// A private gateway ingress authentication failure.
#[derive(Debug, Error)]
pub enum NetworkGatewayIngressError {
    /// Reading the per-connection bridge token failed.
    #[error("reading gateway bridge authentication token failed: {source}")]
    TokenRead {
        /// Underlying asynchronous I/O failure.
        #[source]
        source: io::Error,
    },
    /// The bridge token did not match this launch's token.
    #[error("gateway bridge authentication token mismatch")]
    TokenMismatch,
}

/// A typed failure produced by the per-launch gateway runtime.
#[derive(Debug, Error)]
pub enum NetworkGatewayRuntimeFailure {
    /// Tokio could not construct the runtime used by the gateway thread.
    #[error("failed to construct the gateway runtime: {source}")]
    RuntimeConstruction {
        /// Runtime construction failure.
        #[source]
        source: io::Error,
    },
    /// The host gateway listener could not be registered with Tokio.
    #[error("failed to register the gateway listener: {source}")]
    ListenerRegistration {
        /// Listener registration failure.
        #[source]
        source: io::Error,
    },
    /// The gateway startup acknowledgement could not reach its owner.
    #[error("gateway startup receiver closed")]
    StartupReceiverClosed,
    /// The gateway listener failed after startup.
    #[error("gateway listener failed: {source}")]
    Listener {
        /// Listener failure.
        #[source]
        source: io::Error,
    },
    /// The runtime stopped normally even though its sandbox still depended on it.
    #[error("gateway stopped before the sandboxed process")]
    StoppedBeforeProcess,
}

/// A failure returned by the per-launch gateway thread.
#[derive(Debug, Error)]
pub enum NetworkGatewayRuntimeError {
    /// The runtime reported a concrete typed failure.
    #[error("gateway runtime failed: {source}")]
    Failed {
        /// Runtime failure category and source.
        #[source]
        source: NetworkGatewayRuntimeFailure,
    },
    /// The startup readiness channel closed before reporting a result.
    #[error("gateway startup channel closed")]
    StartupChannelClosed,
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
    /// The Bubblewrap path changed after compatibility probing and before the
    /// backend pinned the executable used for launch.
    #[error("Bubblewrap executable changed after validation: {path:?}")]
    BubblewrapChanged {
        /// Path whose file identity no longer matches the probed executable.
        path: PathBuf,
    },
    /// A validated executable could not be captured into an immutable launch
    /// snapshot.
    #[error("cannot capture {executable} during {operation}: {source}")]
    ExecutableSnapshotFailed {
        /// Executable whose bytes were being captured.
        executable: LinuxExecutable,
        /// Snapshot operation that failed.
        operation: ExecutableSnapshotOperation,
        /// Operating-system failure.
        #[source]
        source: io::Error,
    },
    /// The in-sandbox hardening helper was not found.
    #[error("Cageforge Linux hardening helper was not found")]
    HardeningHelperUnavailable,
    /// The configured packaged-resource directory was not available.
    #[error("Cageforge Linux resource directory was not found")]
    ResourceDirectoryUnavailable,
    /// The embedded Bubblewrap resource could not be materialized securely.
    #[error("cannot materialize the bundled Bubblewrap resource during {operation}: {source}")]
    BundledBubblewrapMaterialization {
        /// Resource operation that failed.
        operation: &'static str,
        /// Operating-system failure.
        #[source]
        source: std::io::Error,
    },
    /// The command path collides with the reserved in-sandbox helper path.
    #[error("command path is reserved by the Linux backend hardening helper: {path:?}")]
    HardeningHelperPathCollision {
        /// Reserved path requested as the user command.
        path: PathBuf,
    },
    /// Bubblewrap did not expose the flags required by this backend.
    #[error(
        "Bubblewrap executable is missing required command-line options: {details}. Install a compatible system Bubblewrap or enable the cageforge-linux bundled-bubblewrap feature",
        details = format_missing_bubblewrap_flags(.missing)
    )]
    BubblewrapIncompatible {
        /// Required Bubblewrap flags absent from its help output.
        missing: Vec<BubblewrapFlag>,
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
    /// A required Bubblewrap probe stream was not piped.
    #[error("Bubblewrap {stage} probe did not provide its {stream} pipe")]
    BubblewrapProbePipeMissing {
        /// Probe operation that omitted the pipe.
        stage: &'static str,
        /// Missing stream name.
        stream: &'static str,
    },
    /// Bubblewrap could not create one required Linux namespace.
    #[error(
        "Bubblewrap cannot create the required {namespace} namespace with {flag}: {message}. {guidance}",
        flag = .namespace.bubblewrap_flag(),
        guidance = .namespace.host_guidance()
    )]
    NamespaceUnavailable {
        /// Exact namespace whose isolated probe failed.
        namespace: LinuxNamespace,
        /// Diagnostic emitted by the namespace probe.
        message: String,
    },
    /// Bubblewrap could not remove the command's Linux capabilities.
    #[error(
        "Bubblewrap cannot drop all Linux capabilities with --cap-drop ALL: {message}. Ensure the kernel and any outer container permit capability reduction inside user namespaces"
    )]
    CapabilityDropUnavailable {
        /// Diagnostic emitted by the capability-drop probe.
        message: String,
    },
    /// Bubblewrap could not disable nested user-namespace creation.
    #[error(
        "Bubblewrap cannot disable nested user namespaces with --disable-userns: {message}. Ensure the kernel and any outer container permit the namespaced user.max_user_namespaces lockdown"
    )]
    NestedUserNamespaceIsolationUnavailable {
        /// Diagnostic emitted by the nested-user-namespace probe.
        message: String,
    },
    /// Bubblewrap could not mount procfs for the isolated PID namespace.
    #[error(
        "Bubblewrap cannot mount the sandbox procfs with --proc /proc: {message}. Ensure the kernel and any outer container permit procfs mounts inside user and PID namespaces"
    )]
    ProcMountUnavailable {
        /// Diagnostic emitted by the proc-mount probe.
        message: String,
    },
    /// This build does not contain a seccomp filter lowering for the host CPU.
    #[error("Linux seccomp hardening is unsupported on architecture {architecture}")]
    UnsupportedSeccompArchitecture {
        /// Target architecture reported by Rust.
        architecture: String,
    },
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
        source: NetworkGatewaySetupError,
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
    /// The protected directory changed identity before the backend could
    /// remove it.
    #[error("protected directory changed before removal: {path:?}")]
    ProtectedPathChanged {
        /// Protected path whose inode no longer matches the observed entry.
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
        source: SetupHandshakeError,
        /// Captured Bubblewrap/helper diagnostic, when stderr was piped.
        diagnostic: String,
    },
    /// The trusted helper returned an invalid native command status frame.
    #[error("failed to receive sandboxed command status: {source}")]
    CommandStatusFailed {
        /// Status-channel failure.
        #[source]
        source: StatusFrameError,
    },
    /// The trusted helper failed after the setup barrier opened.
    #[error("Linux hardening helper failed during execution: {failure}")]
    HardeningHelperRuntimeFailed {
        /// Typed helper-side failure and retained OS error number.
        failure: LinuxHelperRuntimeFailure,
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
    /// The child PID could not be represented by the Linux pidfd API.
    #[error("child PID {pid} is outside the Linux pidfd range")]
    TimeoutPidOutOfRange {
        /// Rejected child PID.
        pid: u32,
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

impl BubblewrapFlag {
    /// Every Bubblewrap flag required by the current Linux backend.
    pub const ALL: [Self; 22] = [
        Self::AsPidOne,
        Self::Bind,
        Self::BindFd,
        Self::BindTry,
        Self::CapabilityDrop,
        Self::ChangeDirectory,
        Self::DisableUserNamespace,
        Self::Directory,
        Self::Devices,
        Self::DieWithParent,
        Self::NewSession,
        Self::Permissions,
        Self::Proc,
        Self::RemountReadOnly,
        Self::ReadOnlyBind,
        Self::ReadOnlyBindData,
        Self::ReadOnlyBindFd,
        Self::Tmpfs,
        Self::UnshareIpc,
        Self::UnshareNetwork,
        Self::UnsharePid,
        Self::UnshareUser,
    ];

    /// Returns the exact Bubblewrap command-line flag.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AsPidOne => "--as-pid-1",
            Self::Bind => "--bind",
            Self::BindFd => "--bind-fd",
            Self::BindTry => "--bind-try",
            Self::CapabilityDrop => "--cap-drop",
            Self::ChangeDirectory => "--chdir",
            Self::DisableUserNamespace => "--disable-userns",
            Self::Directory => "--dir",
            Self::Devices => "--dev",
            Self::DieWithParent => "--die-with-parent",
            Self::NewSession => "--new-session",
            Self::Permissions => "--perms",
            Self::Proc => "--proc",
            Self::RemountReadOnly => "--remount-ro",
            Self::ReadOnlyBind => "--ro-bind",
            Self::ReadOnlyBindData => "--ro-bind-data",
            Self::ReadOnlyBindFd => "--ro-bind-fd",
            Self::Tmpfs => "--tmpfs",
            Self::UnshareIpc => "--unshare-ipc",
            Self::UnshareNetwork => "--unshare-net",
            Self::UnsharePid => "--unshare-pid",
            Self::UnshareUser => "--unshare-user",
        }
    }

    /// Explains the security or launch operation that needs this flag.
    pub const fn purpose(self) -> &'static str {
        match self {
            Self::AsPidOne => {
                "runs the Cageforge hardening helper as PID 1 without a separate Bubblewrap reaper"
            }
            Self::Bind => "mounts explicitly writable host paths into the sandbox",
            Self::BindFd => {
                "mounts writable paths from descriptors pinned before the sandbox starts"
            }
            Self::BindTry => "restores optional host shared memory only when that path exists",
            Self::CapabilityDrop => "removes every Linux capability from the sandboxed command",
            Self::ChangeDirectory => "enters the validated working directory before execution",
            Self::DisableUserNamespace => {
                "prevents the command from creating nested user namespaces"
            }
            Self::Directory => "creates required in-sandbox mount-point directories",
            Self::Devices => "creates the isolated /dev filesystem",
            Self::DieWithParent => "kills the sandbox boundary if Bubblewrap or its parent dies",
            Self::NewSession => "starts the sandbox in a separate terminal session",
            Self::Permissions => {
                "sets exact modes on synthetic mount targets, mask files, and the hardening helper"
            }
            Self::Proc => "mounts procfs for the sandbox PID namespace",
            Self::RemountReadOnly => "makes completed mount targets read-only",
            Self::ReadOnlyBind => "mounts explicitly readable host paths without write access",
            Self::ReadOnlyBindData => {
                "materializes immutable file masks and the hardening helper from Cageforge descriptors"
            }
            Self::ReadOnlyBindFd => {
                "mounts read-only paths from descriptors pinned before the sandbox starts"
            }
            Self::Tmpfs => "creates isolated filesystem roots and in-memory deny masks",
            Self::UnshareIpc => "isolates System V IPC and POSIX message queues",
            Self::UnshareNetwork => "isolates the network stack when direct networking is denied",
            Self::UnsharePid => "isolates process identifiers and the process tree",
            Self::UnshareUser => "creates the user and mount privilege boundary",
        }
    }
}

impl fmt::Display for BubblewrapFlag {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl fmt::Display for LinuxExecutable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bubblewrap => formatter.write_str("Bubblewrap executable"),
            Self::HardeningHelper => formatter.write_str("Linux hardening helper"),
        }
    }
}

impl fmt::Display for ExecutableSnapshotOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Create => formatter.write_str("anonymous snapshot creation"),
            Self::CloneSource => formatter.write_str("source descriptor cloning"),
            Self::RewindSource => formatter.write_str("source descriptor rewind"),
            Self::Copy => formatter.write_str("snapshot byte copy"),
            Self::Permissions => formatter.write_str("snapshot permission setup"),
            Self::Seal => formatter.write_str("snapshot sealing"),
            Self::OpenSnapshot => formatter.write_str("read-only snapshot open"),
        }
    }
}

impl LinuxNamespace {
    pub(crate) const fn bubblewrap_flag(self) -> &'static str {
        match self {
            Self::User => "--unshare-user",
            Self::Pid => "--unshare-pid",
            Self::Ipc => "--unshare-ipc",
            Self::Network => "--unshare-net",
        }
    }

    pub(crate) const fn host_guidance(self) -> &'static str {
        match self {
            Self::User => {
                "Enable unprivileged user namespaces and permit them in the host security policy"
            }
            Self::Pid => {
                "Ensure the kernel and any outer container permit CLONE_NEWPID/PID namespaces"
            }
            Self::Ipc => {
                "Ensure the kernel and any outer container permit CLONE_NEWIPC/IPC namespaces"
            }
            Self::Network => {
                "Ensure the kernel and any outer container permit CLONE_NEWNET/network namespaces"
            }
        }
    }

    pub(crate) const fn probe_stage(self) -> &'static str {
        match self {
            Self::User => "user namespace",
            Self::Pid => "PID namespace",
            Self::Ipc => "IPC namespace",
            Self::Network => "network namespace",
        }
    }
}

impl fmt::Display for LinuxNamespace {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::User => "user",
            Self::Pid => "PID",
            Self::Ipc => "IPC",
            Self::Network => "network",
        })
    }
}

fn format_missing_bubblewrap_flags(flags: &[BubblewrapFlag]) -> String {
    flags
        .iter()
        .map(|flag| format!("{flag} ({})", flag.purpose()))
        .collect::<Vec<_>>()
        .join("; ")
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

impl fmt::Display for PolicyLoweringExpectation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DenyGlobMatch => formatter.write_str("deny-glob match"),
        }
    }
}

impl From<io::Error> for SetupHandshakeError {
    fn from(source: io::Error) -> Self {
        Self::Io { source }
    }
}

impl From<EnvironmentFrameError> for SetupHandshakeError {
    fn from(source: EnvironmentFrameError) -> Self {
        Self::EnvironmentFrame { source }
    }
}

impl From<NetworkGatewayTransportError> for SetupHandshakeError {
    fn from(source: NetworkGatewayTransportError) -> Self {
        Self::GatewayToken { source }
    }
}
