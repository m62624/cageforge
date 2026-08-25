// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;
use std::marker::PhantomData;
use std::path::PathBuf;
use std::sync::Arc;

use cageforge_command::CommandRequest;
use cageforge_policy_compose::{CompositionError, EffectivePathContext, EffectiveSandbox};
use thiserror::Error;

/// A portable command and effective policy submitted for backend preflight.
///
/// The request borrows the already validated values. It cannot be constructed
/// from a raw [`cageforge_policy::SandboxPolicy`], which keeps composition a
/// mandatory boundary for native execution.
#[derive(Debug, Clone, Copy)]
pub struct BackendRequest<'a> {
    pub(super) command: &'a CommandRequest,
    pub(super) sandbox: &'a EffectiveSandbox,
}

/// The capabilities advertised by one backend.
///
/// The set is deterministic so missing-capability diagnostics and tests are
/// stable across platforms. Use named builders rather than positional
/// booleans when constructing it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BackendCapabilities {
    pub(crate) capabilities: BTreeSet<BackendCapability>,
}

/// A request that passed backend capability preflight.
///
/// This type is still portable and contains no process handle. Native backend
/// code may lower it to an OS-specific launch request after applying the
/// filesystem, network, environment, and lifecycle contracts.
///
/// The `B` type parameter is a type-level binding to the backend whose
/// capabilities were checked during preparation. The handoff also stores a
/// runtime [`BackendIdentity`], so every accessor verifies the exact backend
/// instance that was checked. Native lowering should accept
/// `PreparedBackendRequest<'_, Self>` and pass the same backend instance to its
/// accessors.
///
/// ```compile_fail
/// use cageforge_backend_api::{
///     BackendCapabilities, BackendIdentity, PreparedBackendRequest, SandboxBackend,
/// };
///
/// struct LinuxBackend(BackendIdentity);
/// struct WindowsBackend(BackendIdentity);
///
/// impl SandboxBackend for LinuxBackend {
///     fn identity(&self) -> &BackendIdentity {
///         &self.0
///     }
///
///     fn capabilities(&self) -> BackendCapabilities {
///         BackendCapabilities::new()
///     }
/// }
///
/// impl SandboxBackend for WindowsBackend {
///     fn identity(&self) -> &BackendIdentity {
///         &self.0
///     }
///
///     fn capabilities(&self) -> BackendCapabilities {
///         BackendCapabilities::new()
///     }
/// }
///
/// fn take_linux<'a>(_: PreparedBackendRequest<'a, LinuxBackend>) {}
///
/// fn pass_windows_to_linux<'a>(prepared: PreparedBackendRequest<'a, WindowsBackend>) {
///     take_linux(prepared);
/// }
/// ```
pub struct PreparedBackendRequest<'a, B: SandboxBackend> {
    pub(super) request: BackendRequest<'a>,
    pub(super) path_context: EffectivePathContext,
    pub(super) working_directory: PathBuf,
    pub(super) capabilities: BackendCapabilities,
    pub(super) backend_identity: BackendIdentity,
    pub(super) backend: PhantomData<fn() -> B>,
}

/// Identity of one backend enforcement instance.
///
/// A backend must store one identity for the lifetime of its enforcement
/// state and return a reference to it from [`SandboxBackend::identity`]. Two
/// backend instances may share an identity only when they intentionally share
/// the same capability and enforcement state. This is an identity token, not
/// proof that operating-system enforcement exists.
///
/// This type intentionally has no [`Default`] implementation. Every identity
/// must be created explicitly with [`Self::new`], because a default value
/// would be a fresh identity rather than a shared backend boundary.
///
/// ```compile_fail
/// use cageforge_backend_api::BackendIdentity;
/// let _ = BackendIdentity::default();
/// ```
#[derive(Clone)]
pub struct BackendIdentity(pub(super) Arc<()>);

/// One capability that a native backend may advertise.
///
/// A capability means that the backend can enforce the corresponding
/// effective request safely. It is not a hint that the backend can parse the
/// value. Backends must not advertise a capability whose enforcement would be
/// best-effort or silently incomplete. `Ord` is used only for deterministic
/// capability-set iteration and diagnostics; it is not an enforcement
/// precedence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum BackendCapability {
    /// Execute a validated command request.
    CommandExecution,
    /// Resolve and enforce the effective working directory, including the
    /// runtime directory inherited when the command has no explicit cwd.
    WorkingDirectory,
    /// Inherit a standard stream from the launcher.
    StdioInherit,
    /// Connect a standard stream to the platform null device.
    StdioNull,
    /// Create a pipe for a standard stream.
    StdioPipe,
    /// Apply the backend's default timeout policy.
    TimeoutBackendDefault,
    /// Apply an explicit timeout duration.
    TimeoutLimit,
    /// Run without an automatic timeout.
    TimeoutDisabled,
    /// Enforce a restricted filesystem policy.
    FilesystemRestricted,
    /// Run without a local filesystem boundary.
    FilesystemUnrestricted,
    /// Delegate filesystem enforcement to an external owner.
    FilesystemExternal,
    /// Enforce concrete and symbolic filesystem scopes, including workspace
    /// roots required by workspace-relative selectors and globs.
    FilesystemScopes,
    /// Enforce native absolute filesystem scopes and absolute globs.
    FilesystemAbsoluteScopes,
    /// Resolve filesystem scopes and globs against runtime workspace roots.
    FilesystemWorkspaceScopes,
    /// Resolve filesystem scopes against caller-supplied system roots.
    FilesystemRootScopes,
    /// Resolve filesystem scopes against the platform-minimal paths.
    FilesystemMinimalScopes,
    /// Resolve filesystem scopes against the platform temporary directory.
    FilesystemTmpdirScopes,
    /// Resolve filesystem scopes against the conventional `/tmp` path.
    FilesystemSlashTmpScopes,
    /// Enforce filesystem deny globs.
    FilesystemGlobs,
    /// Expand filesystem globs with the requested scan-depth semantics.
    FilesystemGlobScanDepth,
    /// Enforce read-only subpaths below writable scopes.
    FilesystemReadOnlySubpaths,
    /// Enforce the error-or-skip behavior for missing concrete filesystem
    /// scopes.
    FilesystemMissingPathBehavior,
    /// Enforce protected relative paths such as the default `.git` path.
    FilesystemProtectedPaths,
    /// Disable outbound networking.
    NetworkDisabled,
    /// Enforce local outbound networking.
    NetworkEnabled,
    /// Delegate network enforcement to an external owner.
    NetworkExternal,
    /// Enforce domain rules and domain defaults.
    NetworkDomainRules,
    /// Enforce the policy for non-public and special-purpose addresses.
    NetworkLocalAddressRestrictions,
    /// Resolve once and authorize the exact address used for a connection.
    NetworkResolvedTargets,
    /// Prevent pathname Unix socket access while retaining process-local IPC.
    NetworkUnixSocketIsolation,
    /// Enforce per-path Unix socket allow and deny rules.
    NetworkUnixSocketRules,
    /// Start from all inherited environment variables.
    EnvironmentAll,
    /// Start from a backend-selected core environment.
    EnvironmentCore,
    /// Start from an empty environment.
    EnvironmentNone,
    /// Apply environment include and exclude filters.
    EnvironmentFilters,
    /// Apply environment set and remove overrides.
    EnvironmentOverrides,
}

/// Common failures at the portable backend contract boundary.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BackendContractError {
    /// The backend cannot safely enforce one required capability.
    #[error("backend cannot safely enforce required capability: {capability}")]
    UnsupportedCapability {
        /// The missing capability.
        capability: BackendCapability,
    },
    /// The command and composed sandbox were built from different environment
    /// specifications.
    #[error("command environment does not match the composed requested environment")]
    CommandEnvironmentMismatch,
    /// The backend could not construct a safe runtime path context.
    #[error("invalid backend runtime context: {source}")]
    InvalidRuntimeContext {
        /// The composition failure raised while narrowing the runtime context.
        #[source]
        source: CompositionError,
    },
    /// The backend could not construct the selected environment base.
    #[error("environment preparation failed: {source}")]
    EnvironmentPreparation {
        /// The composition failure raised while applying the environment.
        #[source]
        source: CompositionError,
    },
    /// The effective filesystem policy rejected a backend query.
    #[error("filesystem policy evaluation failed: {source}")]
    FilesystemEvaluation {
        /// The composition failure raised while evaluating filesystem access.
        #[source]
        source: CompositionError,
    },
    /// The command's working directory is outside the effective filesystem
    /// policy.
    #[error("working directory {path:?} is denied by the effective filesystem policy")]
    WorkingDirectoryDenied {
        /// The denied working directory.
        path: PathBuf,
    },
    /// A relative working directory had no runtime current directory.
    #[error("relative working directory {path:?} requires a runtime current directory")]
    WorkingDirectoryResolution {
        /// The unresolved relative working directory.
        path: PathBuf,
    },
    /// The command omitted a working directory and the runtime did not supply
    /// the directory that would otherwise be inherited by the child.
    #[error("runtime current directory is required for backend preflight")]
    MissingRuntimeCurrentDirectory,
    /// The effective network policy rejected a backend query.
    #[error("network policy evaluation failed: {source}")]
    NetworkEvaluation {
        /// The composition failure raised while evaluating network access.
        #[source]
        source: CompositionError,
    },
    /// A prepared handoff was used with a different backend instance than the
    /// one whose capabilities were checked.
    #[error("prepared backend request belongs to a different backend instance")]
    BackendIdentityMismatch,
    /// A prepared handoff was used after its backend changed capabilities.
    #[error("backend capabilities changed after request preparation")]
    BackendCapabilitiesMismatch,
}

/// The capability-discovery contract implemented by a native backend.
///
/// Implementations advertise only capabilities they can enforce. Call
/// [`BackendRequest::prepare_for`] to run the common preflight; native
/// backends cannot replace that check with a broader capability set. Process
/// launch, platform I/O, and backend-specific errors remain outside this
/// trait. Prepared accessors reject a changed capability snapshot with a typed
/// error. The identity and capability checks do not prove that operating-system
/// enforcement exists.
pub trait SandboxBackend {
    /// Returns the stable identity of this backend enforcement instance.
    ///
    /// The same reference must be returned for the lifetime of the backend.
    /// Two instances may return the same identity only when they share the
    /// same enforcement state and capability contract.
    fn identity(&self) -> &BackendIdentity;

    /// Returns the capabilities this backend can enforce safely.
    fn capabilities(&self) -> BackendCapabilities;
}
