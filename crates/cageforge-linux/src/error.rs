// SPDX-License-Identifier: Apache-2.0

//! Typed Linux backend failures.

use std::fmt;
use std::io;
use std::num::ParseIntError;
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
    /// A deny target was incorrectly passed to a canonical bind-mount operation.
    #[error("deny access cannot be lowered as a canonical bind mount")]
    DenyCanonicalBind,
    /// A deny target was incorrectly passed to a descriptor bind-mount operation.
    #[error("deny access cannot be lowered as a descriptor bind mount")]
    DenyDescriptorBind,
    /// A deny target was incorrectly passed to a pinned-file bind operation.
    #[error("deny access cannot be lowered as a pinned-file bind")]
    DenyPinnedFileBind,
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

impl fmt::Display for PolicyLoweringExpectation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DenyGlobMatch => formatter.write_str("deny-glob match"),
        }
    }
}

/// A native operation performed while hardening a Linux process boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxHardeningOperation {
    /// Setting the parent-death signal.
    ParentDeathSignal,
    /// Setting the dumpability flag.
    Dumpability,
    /// Setting the core-dump resource limit.
    CoreDumpLimit,
    /// Setting `PR_SET_NO_NEW_PRIVS`.
    NoNewPrivileges,
    /// Writing the setup-ready marker.
    SetupReady,
    /// Reading the authenticated bridge token.
    BridgeTokenRead,
    /// Reading the authentication token.
    AuthenticationTokenRead,
    /// Reading the setup-release marker.
    SetupRelease,
    /// Setting close-on-exec on the helper channel.
    CloseOnExec,
}

impl fmt::Display for LinuxHardeningOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let operation = match self {
            Self::ParentDeathSignal => "parent-death signal",
            Self::Dumpability => "dumpability",
            Self::CoreDumpLimit => "core-dump limit",
            Self::NoNewPrivileges => "no-new-privileges",
            Self::SetupReady => "setup-ready marker",
            Self::BridgeTokenRead => "bridge token",
            Self::AuthenticationTokenRead => "authentication token",
            Self::SetupRelease => "setup-release marker",
            Self::CloseOnExec => "close-on-exec",
        };
        formatter.write_str(operation)
    }
}

/// A typed seccomp construction failure.
#[derive(Debug, Error)]
pub enum SeccompBuildError {
    /// A seccomp condition could not be created.
    #[error("seccomp condition construction failed: {source}")]
    Condition {
        /// Underlying seccompiler validation failure.
        #[source]
        source: seccompiler::BackendError,
    },
    /// A seccomp rule could not be created.
    #[error("seccomp rule construction failed: {source}")]
    Rule {
        /// Underlying seccompiler validation failure.
        #[source]
        source: seccompiler::BackendError,
    },
    /// The filter could not be assembled.
    #[error("seccomp filter construction failed: {source}")]
    Filter {
        /// Underlying seccompiler validation failure.
        #[source]
        source: seccompiler::BackendError,
    },
    /// The filter could not be converted to a BPF program.
    #[error("seccomp BPF conversion failed: {source}")]
    BpfConversion {
        /// Underlying seccompiler backend failure.
        #[source]
        source: seccompiler::BackendError,
    },
    /// The target architecture has no supported seccomp lowering.
    #[error("unsupported Linux seccomp architecture {architecture}")]
    UnsupportedArchitecture {
        /// Architecture reported by Rust.
        architecture: String,
    },
}

/// A native hardening-helper failure.
#[derive(Debug, Error)]
pub enum LinuxHardeningError {
    /// A required helper environment variable was absent.
    #[error("missing helper environment variable {name}")]
    MissingEnvironment {
        /// Missing variable name.
        name: &'static str,
    },
    /// A helper environment variable could not be parsed.
    #[error("invalid helper environment variable {name}: {source}")]
    InvalidEnvironment {
        /// Invalid variable name.
        name: &'static str,
        /// Parsing failure.
        #[source]
        source: ParseIntError,
    },
    /// A helper authentication descriptor was a standard stream.
    #[error("authentication descriptor {fd} must be above the standard streams")]
    AuthenticationDescriptorTooLow {
        /// Rejected descriptor number.
        fd: libc::c_int,
    },
    /// The authentication descriptor was not a Unix socket.
    #[error("authentication descriptor is not a Unix socket: {source}")]
    AuthenticationPeerQuery {
        /// Operating-system failure.
        #[source]
        source: io::Error,
    },
    /// The peer credentials structure was truncated.
    #[error("authentication peer credentials were truncated")]
    AuthenticationPeerCredentialsTruncated,
    /// The peer was visible from inside the sandbox namespace.
    #[error("authentication peer is inside the sandbox namespace")]
    AuthenticationPeerInsideNamespace,
    /// The peer was not a live host-side process.
    #[error("authentication peer is not a live host-side peer")]
    AuthenticationPeerNotLive,
    /// The helper's parent changed while the boundary was being hardened.
    #[error("sandbox parent exited during hardening")]
    ParentExitedDuringHardening,
    /// The authentication marker did not match.
    #[error("authentication token mismatch")]
    AuthenticationTokenMismatch,
    /// The network hardening mode was not recognized.
    #[error("unknown network hardening mode {value:?}")]
    UnknownNetworkMode {
        /// Unrecognized environment value.
        value: String,
    },
    /// The proxy gateway socket was not configured.
    #[error("missing gateway socket")]
    MissingGatewaySocket,
    /// The proxy gateway socket was not absolute.
    #[error("gateway socket must be absolute: {path:?}")]
    RelativeGatewaySocket {
        /// Rejected socket path.
        path: PathBuf,
    },
    /// The proxy gateway connection limit was not configured.
    #[error("missing gateway connection limit")]
    MissingGatewayConnectionLimit,
    /// The proxy gateway connection limit was invalid.
    #[error("invalid gateway connection limit: {source}")]
    InvalidGatewayConnectionLimit {
        /// Parsing failure.
        #[source]
        source: ParseIntError,
    },
    /// The proxy gateway connection limit was zero.
    #[error("gateway connection limit must be non-zero")]
    ZeroGatewayConnectionLimit,
    /// A bridge could not be created.
    #[error("gateway bridge failed: {source}")]
    GatewayBridge {
        /// Bridge-specific failure.
        #[source]
        source: LinuxBridgeError,
    },
    /// The command environment frame was invalid or unreadable.
    #[error("sandbox environment frame failed: {source}")]
    EnvironmentFrame {
        /// Environment-frame failure.
        #[source]
        source: EnvironmentFrameError,
    },
    /// A hardening syscall failed.
    #[error("Linux {operation} failed: {source}")]
    Operation {
        /// Native operation that failed.
        operation: LinuxHardeningOperation,
        /// Operating-system failure.
        #[source]
        source: io::Error,
    },
    /// The seccomp filter could not be built.
    #[error("Linux seccomp filter build failed: {source}")]
    SeccompBuild {
        /// Typed seccomp construction failure.
        #[source]
        source: SeccompBuildError,
    },
    /// Installing the seccomp filter failed.
    #[error("Linux seccomp installation failed: {source}")]
    SeccompInstallation {
        /// Underlying seccompiler failure.
        #[source]
        source: seccompiler::Error,
    },
    /// The setup release marker was invalid.
    #[error("invalid setup release token")]
    InvalidSetupRelease,
    /// Reporting the command status failed.
    #[error("sandbox command status write failed: {source}")]
    StatusWrite {
        /// Operating-system failure.
        #[source]
        source: io::Error,
    },
    /// Starting the final command failed inside the helper.
    #[error("sandbox command start failed: {source}")]
    CommandStart {
        /// Operating-system failure.
        #[source]
        source: io::Error,
    },
}

/// A distinct operation in the host-to-helper bridge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxBridgeOperation {
    /// Creating the readiness pipe.
    CreateReadyPipe,
    /// Moving a descriptor out of the standard stream range.
    MoveDescriptor,
    /// Closing a descriptor.
    CloseDescriptor,
    /// Binding the loopback listener.
    BindListener,
    /// Reading the listener address.
    ReadListenerAddress,
    /// Reading the bridge readiness port.
    ReadReadyPort,
    /// Writing the readiness port.
    WriteReadyPort,
    /// Accepting a loopback connection.
    AcceptConnection,
    /// Connecting to the private gateway socket.
    ConnectGateway,
    /// Relaying TCP data into the gateway.
    RelayToGateway,
    /// Relaying gateway data to TCP.
    RelayToClient,
    /// Detaching bridge standard streams.
    DetachStandardStreams,
    /// Hardening the bridge process.
    HardenProcess,
}

impl fmt::Display for LinuxBridgeOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let operation = match self {
            Self::CreateReadyPipe => "create ready pipe",
            Self::MoveDescriptor => "move descriptor",
            Self::CloseDescriptor => "close descriptor",
            Self::BindListener => "bind loopback listener",
            Self::ReadListenerAddress => "read listener address",
            Self::ReadReadyPort => "read ready port",
            Self::WriteReadyPort => "write ready port",
            Self::AcceptConnection => "accept bridge connection",
            Self::ConnectGateway => "connect gateway",
            Self::RelayToGateway => "relay to gateway",
            Self::RelayToClient => "relay to client",
            Self::DetachStandardStreams => "detach standard streams",
            Self::HardenProcess => "harden bridge process",
        };
        formatter.write_str(operation)
    }
}

/// A host-to-helper bridge failure.
#[derive(Debug, Error)]
pub enum LinuxBridgeError {
    /// A bridge operation failed at the operating-system boundary.
    #[error("{operation} failed: {source}")]
    Operation {
        /// Operation that failed.
        operation: LinuxBridgeOperation,
        /// Operating-system failure.
        #[source]
        source: io::Error,
    },
    /// The bridge child exited before publishing a usable parent relationship.
    #[error("gateway bridge parent exited before startup")]
    ParentExited,
    /// The bridge child did not publish a listening port before the deadline.
    #[error("gateway bridge startup timed out")]
    StartupTimedOut,
    /// The child published port zero.
    #[error("gateway bridge returned port zero")]
    ZeroPort,
    /// The relay worker panicked.
    #[error("gateway bridge relay worker panicked")]
    RelayPanicked,
    /// The bridge fork failed.
    #[error("gateway bridge fork failed: {source}")]
    Fork {
        /// Operating-system failure.
        #[source]
        source: io::Error,
    },
}

/// A framed command-environment failure.
#[derive(Debug, Error)]
pub enum EnvironmentFrameError {
    /// Reading or writing a frame component failed.
    #[error("environment frame {operation} failed: {source}")]
    Io {
        /// Frame component that could not be transferred.
        operation: &'static str,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },
    /// A frame length exceeded the representable platform size.
    #[error("environment frame length is too large")]
    LengthTooLarge,
    /// A frame length exceeded the helper's memory-safety bound.
    #[error("environment frame length {length} exceeds the {maximum}-byte limit")]
    LengthLimitExceeded {
        /// Rejected frame length.
        length: usize,
        /// Maximum accepted frame length.
        maximum: usize,
    },
    /// The aggregate environment frame exceeded the helper's memory bound.
    #[error("environment frame exceeds the {maximum}-byte limit")]
    FrameLimitExceeded {
        /// Maximum accepted frame size.
        maximum: usize,
    },
    /// A frame contained too many environment entries.
    #[error("environment frame contains {count} entries, exceeding the {maximum}-entry limit")]
    EntryLimitExceeded {
        /// Rejected entry count.
        count: usize,
        /// Maximum accepted entry count.
        maximum: usize,
    },
    /// The frame contained an invalid variable name.
    #[error("environment frame contains an invalid variable name")]
    InvalidName,
    /// The frame contained an invalid variable value.
    #[error("environment frame contains an invalid variable value")]
    InvalidValue,
    /// The frame repeated a variable name.
    #[error("environment frame contains a duplicate variable")]
    DuplicateVariable,
    /// The frame magic did not match.
    #[error("environment frame magic did not match")]
    InvalidMagic,
}

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
    /// The status frame had an invalid magic prefix.
    #[error("command status frame magic did not match")]
    InvalidMagic,
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
    /// A required Bubblewrap probe stream was not piped.
    #[error("Bubblewrap {stage} probe did not provide its {stream} pipe")]
    BubblewrapProbePipeMissing {
        /// Probe operation that omitted the pipe.
        stage: &'static str,
        /// Missing stream name.
        stream: &'static str,
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
