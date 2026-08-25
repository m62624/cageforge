// SPDX-License-Identifier: Apache-2.0

//! Typed failures shared by the Linux backend and its private helper binary.

use std::fmt;
use std::io;
use std::num::ParseIntError;
use std::path::PathBuf;

use thiserror::Error;

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
    /// Replacing the inherited session keyring with an anonymous keyring.
    KeyringIsolation,
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
    /// Waiting for a traced command or descendant.
    TraceWait,
    /// Installing supervision options on a traced command.
    TraceSetOptions,
    /// Continuing a traced command while preserving signal delivery.
    TraceContinue,
    /// Waiting for an untraced command.
    CommandWait,
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

/// Typed helper setup failure reconstructed by the host-side protocol reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinuxHelperSetupFailure {
    kind: LinuxHelperSetupFailureKind,
    raw_os_error: Option<i32>,
}

/// A typed helper runtime failure reconstructed by the host-side protocol reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinuxHelperRuntimeFailure {
    kind: LinuxHelperRuntimeFailureKind,
    raw_os_error: Option<i32>,
}

/// Stable category sent by the private helper when setup fails before launch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum LinuxHelperSetupFailureKind {
    /// The requested network-hardening mode was malformed.
    NetworkMode = 1,
    /// The private host-to-namespace gateway bridge could not start.
    GatewayBridge = 2,
    /// The final command environment frame was rejected.
    EnvironmentFrame = 3,
    /// The helper could not set its parent-death invariant.
    ParentDeathSignal = 4,
    /// The helper could not disable dumpability.
    Dumpability = 5,
    /// The helper could not disable core dumps.
    CoreDumpLimit = 6,
    /// The helper could not set `no_new_privs`.
    NoNewPrivileges = 7,
    /// The command seccomp filter could not be built.
    SeccompBuild = 8,
    /// Process hardening failed in an unclassified setup operation.
    ProcessHardening = 9,
    /// The final command could not be started while still behind the barrier.
    CommandStart = 10,
    /// The trusted helper could not establish ptrace supervision.
    TraceSupervision = 11,
    /// The helper could not replace the inherited host session keyring.
    KeyringIsolation = 12,
}

/// Stable category sent by the private helper when execution fails after setup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum LinuxHelperRuntimeFailureKind {
    /// The final command could not be started after the setup barrier opened.
    CommandStart = 1,
    /// The trusted helper failed while supervising the traced process tree.
    TraceSupervision = 2,
    /// The trusted helper failed while waiting for an untraced command.
    CommandWait = 3,
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
    /// A traced command entered a state outside the supervision protocol.
    #[error("traced command {pid} produced unexpected wait status {status}")]
    UnexpectedTraceStatus {
        /// Process identifier returned by `waitpid`.
        pid: libc::pid_t,
        /// Raw wait status returned by the kernel.
        status: libc::c_int,
    },
}

impl fmt::Display for LinuxHardeningOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let operation = match self {
            Self::ParentDeathSignal => "parent-death signal",
            Self::Dumpability => "dumpability",
            Self::CoreDumpLimit => "core-dump limit",
            Self::NoNewPrivileges => "no-new-privileges",
            Self::KeyringIsolation => "session-keyring isolation",
            Self::SetupReady => "setup-ready marker",
            Self::BridgeTokenRead => "bridge token",
            Self::AuthenticationTokenRead => "authentication token",
            Self::SetupRelease => "setup-release marker",
            Self::CloseOnExec => "close-on-exec",
            Self::TraceWait => "trace wait",
            Self::TraceSetOptions => "trace options",
            Self::TraceContinue => "trace continue",
            Self::CommandWait => "command wait",
        };
        formatter.write_str(operation)
    }
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

impl LinuxHelperSetupFailure {
    /// Creates a helper setup failure from its stable category and optional
    /// operating-system error number.
    pub const fn new(kind: LinuxHelperSetupFailureKind, raw_os_error: Option<i32>) -> Self {
        Self { kind, raw_os_error }
    }

    /// Returns the stable failure category.
    pub const fn kind(&self) -> LinuxHelperSetupFailureKind {
        self.kind
    }

    /// Returns the original operating-system error number, when one existed.
    pub const fn raw_os_error(&self) -> Option<i32> {
        self.raw_os_error
    }
}

impl fmt::Display for LinuxHelperSetupFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} failed", self.kind)?;
        if let Some(errno) = self.raw_os_error {
            write!(formatter, " with OS error {errno}")?;
        }
        Ok(())
    }
}

impl LinuxHelperRuntimeFailure {
    /// Creates a helper runtime failure from its stable category and optional
    /// operating-system error number.
    pub const fn new(kind: LinuxHelperRuntimeFailureKind, raw_os_error: Option<i32>) -> Self {
        Self { kind, raw_os_error }
    }

    /// Returns the stable failure category.
    pub const fn kind(&self) -> LinuxHelperRuntimeFailureKind {
        self.kind
    }

    /// Returns the original operating-system error number, when one existed.
    pub const fn raw_os_error(&self) -> Option<i32> {
        self.raw_os_error
    }
}

impl fmt::Display for LinuxHelperRuntimeFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} failed", self.kind)?;
        if let Some(errno) = self.raw_os_error {
            write!(formatter, " with OS error {errno}")?;
        }
        Ok(())
    }
}

impl From<LinuxHelperSetupFailureKind> for u16 {
    fn from(value: LinuxHelperSetupFailureKind) -> Self {
        value as Self
    }
}

impl TryFrom<u16> for LinuxHelperSetupFailureKind {
    type Error = ();

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::NetworkMode),
            2 => Ok(Self::GatewayBridge),
            3 => Ok(Self::EnvironmentFrame),
            4 => Ok(Self::ParentDeathSignal),
            5 => Ok(Self::Dumpability),
            6 => Ok(Self::CoreDumpLimit),
            7 => Ok(Self::NoNewPrivileges),
            8 => Ok(Self::SeccompBuild),
            9 => Ok(Self::ProcessHardening),
            10 => Ok(Self::CommandStart),
            11 => Ok(Self::TraceSupervision),
            12 => Ok(Self::KeyringIsolation),
            _ => Err(()),
        }
    }
}

impl fmt::Display for LinuxHelperSetupFailureKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let description = match self {
            Self::NetworkMode => "network hardening mode",
            Self::GatewayBridge => "gateway bridge",
            Self::EnvironmentFrame => "environment frame",
            Self::ParentDeathSignal => "parent-death signal",
            Self::Dumpability => "dumpability",
            Self::CoreDumpLimit => "core-dump limit",
            Self::NoNewPrivileges => "no-new-privileges",
            Self::SeccompBuild => "seccomp build",
            Self::ProcessHardening => "process hardening",
            Self::CommandStart => "command start",
            Self::TraceSupervision => "trace supervision",
            Self::KeyringIsolation => "session-keyring isolation",
        };
        formatter.write_str(description)
    }
}

impl From<LinuxHelperRuntimeFailureKind> for u16 {
    fn from(value: LinuxHelperRuntimeFailureKind) -> Self {
        value as Self
    }
}

impl TryFrom<u16> for LinuxHelperRuntimeFailureKind {
    type Error = ();

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::CommandStart),
            2 => Ok(Self::TraceSupervision),
            3 => Ok(Self::CommandWait),
            _ => Err(()),
        }
    }
}

impl fmt::Display for LinuxHelperRuntimeFailureKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let description = match self {
            Self::CommandStart => "command start",
            Self::TraceSupervision => "trace supervision",
            Self::CommandWait => "command wait",
        };
        formatter.write_str(description)
    }
}
