// SPDX-License-Identifier: Apache-2.0

//! Backend capability negotiation and preflight for Cageforge execution.
//!
//! This crate is the typed boundary between [`cageforge_command`] and
//! [`cageforge_policy_compose`] values and a native execution backend. It does
//! not launch processes, perform filesystem or network I/O, resolve DNS, or
//! select an operating-system sandbox.
//!
//! Start with [`BackendRequest`] and [`BackendCapabilities`]. A native backend
//! implements [`SandboxBackend`], advertises the capabilities it can enforce,
//! and calls [`BackendRequest::prepare_for`] before lowering the prepared
//! request to its operating-system API. The backend owns process launch and
//! lifecycle after this preflight boundary.

#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fmt;

use cageforge_command::{CommandRequest, EnvironmentBase, StdioMode, TimeoutPolicy};
use cageforge_policy::{
    DomainMode, FilesystemMode, FilesystemTarget, LocalNetworkAccess, NetworkMode,
    PathResolutionContext, UnixSocketMode,
};
use cageforge_policy_compose::{
    CompositionError, EffectivePathContext, EffectiveSandbox, EnvironmentInput,
};
use thiserror::Error;

/// One capability that a native backend may advertise.
///
/// A capability means that the backend can enforce the corresponding
/// effective request safely. It is not a hint that the backend can parse the
/// value. Backends must not advertise a capability whose enforcement would be
/// best-effort or silently incomplete.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum BackendCapability {
    /// Execute a validated command request.
    CommandExecution,
    /// Resolve and enforce a requested working directory.
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
    /// Enforce the policy for private, loopback, and link-local addresses.
    NetworkLocalAddressRestrictions,
    /// Resolve once and authorize the exact address used for a connection.
    NetworkResolvedTargets,
    /// Enforce Unix socket rules.
    NetworkUnixSockets,
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

impl fmt::Display for BackendCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let description = match self {
            Self::CommandExecution => "command execution",
            Self::WorkingDirectory => "working-directory resolution",
            Self::StdioInherit => "inherited standard streams",
            Self::StdioNull => "null standard streams",
            Self::StdioPipe => "piped standard streams",
            Self::TimeoutBackendDefault => "backend-default timeout",
            Self::TimeoutLimit => "explicit timeout limits",
            Self::TimeoutDisabled => "disabled automatic timeouts",
            Self::FilesystemRestricted => "restricted filesystem enforcement",
            Self::FilesystemUnrestricted => "unrestricted filesystem execution",
            Self::FilesystemExternal => "external filesystem enforcement",
            Self::FilesystemScopes => "filesystem scope resolution, including workspace roots",
            Self::FilesystemGlobs => "filesystem deny-glob matching",
            Self::FilesystemGlobScanDepth => {
                "filesystem glob scan-depth semantics, including unbounded scans"
            }
            Self::FilesystemReadOnlySubpaths => "filesystem read-only subpaths",
            Self::FilesystemMissingPathBehavior => {
                "filesystem missing-path behavior (error or skip)"
            }
            Self::FilesystemProtectedPaths => "filesystem protected paths such as .git",
            Self::NetworkDisabled => "disabled network enforcement",
            Self::NetworkEnabled => "local network enforcement",
            Self::NetworkExternal => "external network enforcement",
            Self::NetworkDomainRules => "network domain rules",
            Self::NetworkLocalAddressRestrictions => {
                "network private, loopback, and link-local address restrictions"
            }
            Self::NetworkResolvedTargets => "exact resolved network targets",
            Self::NetworkUnixSockets => "Unix socket network rules",
            Self::EnvironmentAll => "all inherited environment variables",
            Self::EnvironmentCore => "backend-selected core environment variables",
            Self::EnvironmentNone => "an empty inherited environment",
            Self::EnvironmentFilters => "environment include and exclude filters",
            Self::EnvironmentOverrides => "environment set and remove overrides",
        };
        formatter.write_str(description)
    }
}

/// The capabilities advertised by one backend.
///
/// The set is deterministic so missing-capability diagnostics and tests are
/// stable across platforms. Use named builders rather than positional
/// booleans when constructing it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BackendCapabilities {
    capabilities: BTreeSet<BackendCapability>,
}

impl BackendCapabilities {
    /// Creates an empty capability set.
    pub const fn new() -> Self {
        Self {
            capabilities: BTreeSet::new(),
        }
    }

    /// Creates a capability set from an iterable collection.
    pub fn from_capabilities<I>(capabilities: I) -> Self
    where
        I: IntoIterator<Item = BackendCapability>,
    {
        Self {
            capabilities: capabilities.into_iter().collect(),
        }
    }

    /// Returns a copy with one capability added.
    pub fn with(mut self, capability: BackendCapability) -> Self {
        self.capabilities.insert(capability);
        self
    }

    /// Returns whether this backend advertises a capability.
    pub fn supports(&self, capability: BackendCapability) -> bool {
        self.capabilities.contains(&capability)
    }

    /// Returns capabilities in deterministic order.
    pub fn iter(&self) -> impl Iterator<Item = &BackendCapability> {
        self.capabilities.iter()
    }
}

impl FromIterator<BackendCapability> for BackendCapabilities {
    fn from_iter<T: IntoIterator<Item = BackendCapability>>(iter: T) -> Self {
        Self::from_capabilities(iter)
    }
}

/// A portable command and effective policy submitted for backend preflight.
///
/// The request borrows the already validated values. It cannot be constructed
/// from a raw [`cageforge_policy::SandboxPolicy`], which keeps composition a
/// mandatory boundary for native execution.
#[derive(Debug, Clone, Copy)]
pub struct BackendRequest<'a> {
    command: &'a CommandRequest,
    sandbox: &'a EffectiveSandbox,
}

impl<'a> BackendRequest<'a> {
    /// Creates a backend request from a command and composed sandbox.
    pub const fn new(command: &'a CommandRequest, sandbox: &'a EffectiveSandbox) -> Self {
        Self { command, sandbox }
    }

    /// Returns the command intent.
    pub const fn command(&self) -> &'a CommandRequest {
        self.command
    }

    /// Returns the effective sandbox constraint.
    pub const fn sandbox(&self) -> &'a EffectiveSandbox {
        self.sandbox
    }

    /// Performs common preflight using exactly the capabilities advertised by
    /// `backend`.
    ///
    /// This is the safe handoff entry point for native integrations. The
    /// capability check is defined by Cageforge and cannot be overridden by a
    /// backend implementation.
    pub fn prepare_for<B: SandboxBackend>(
        self,
        backend: &B,
    ) -> Result<PreparedBackendRequest<'a>, BackendContractError> {
        self.validate(&backend.capabilities())
    }

    /// Computes the capabilities required by this request.
    pub fn required_capabilities(&self) -> BackendCapabilities {
        let mut required = BackendCapabilities::new().with(BackendCapability::CommandExecution);
        add_command_capabilities(&mut required, self.command);
        add_filesystem_capabilities(&mut required, self.sandbox);
        add_network_capabilities(&mut required, self.sandbox);
        add_environment_capabilities(&mut required, self.sandbox);
        required
    }

    /// Validates this request against advertised backend capabilities.
    ///
    /// No process, filesystem, DNS, or socket operation is performed. The
    /// returned value only proves that the request's portable requirements are
    /// represented by the advertised capability set; native enforcement still
    /// belongs to the backend.
    fn validate(
        self,
        capabilities: &BackendCapabilities,
    ) -> Result<PreparedBackendRequest<'a>, BackendContractError> {
        if self.command.environment() != self.sandbox.environment().requested() {
            return Err(BackendContractError::CommandEnvironmentMismatch);
        }
        for capability in self.required_capabilities().iter().copied() {
            if !capabilities.supports(capability) {
                return Err(BackendContractError::UnsupportedCapability { capability });
            }
        }
        Ok(PreparedBackendRequest { request: self })
    }
}

/// A request that passed backend capability preflight.
///
/// This type is still portable and contains no process handle. Native backend
/// code may lower it to an OS-specific launch request after applying the
/// filesystem, network, environment, and lifecycle contracts.
#[derive(Debug, Clone, Copy)]
pub struct PreparedBackendRequest<'a> {
    request: BackendRequest<'a>,
}

impl<'a> PreparedBackendRequest<'a> {
    /// Returns the validated command intent.
    pub const fn command(&self) -> &'a CommandRequest {
        self.request.command()
    }

    /// Returns the validated effective sandbox.
    pub const fn sandbox(&self) -> &'a EffectiveSandbox {
        self.request.sandbox()
    }

    /// Narrows a backend-owned runtime path context to the effective
    /// workspace-root ceiling.
    pub fn path_context(
        &self,
        base: &PathResolutionContext,
    ) -> Result<EffectivePathContext, BackendContractError> {
        self.sandbox()
            .path_context(base)
            .map_err(|source| BackendContractError::InvalidRuntimeContext { source })
    }

    /// Applies the effective environment to a backend-selected input base.
    ///
    /// A backend must construct [`EnvironmentInput::core`] only after it has
    /// selected the platform's conservative core environment.
    pub fn apply_environment(
        &self,
        input: EnvironmentInput,
    ) -> Result<BTreeMap<OsString, OsString>, BackendContractError> {
        self.sandbox()
            .environment()
            .apply_to(input)
            .map_err(|source| BackendContractError::EnvironmentPreparation { source })
    }
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
}

/// The capability-discovery contract implemented by a native backend.
///
/// Implementations advertise only capabilities they can enforce. Call
/// [`BackendRequest::prepare_for`] to run the common preflight; native
/// backends cannot replace that check with a broader capability set. Process
/// launch, platform I/O, and backend-specific errors remain outside this
/// trait.
pub trait SandboxBackend {
    /// Returns the capabilities this backend can enforce safely.
    fn capabilities(&self) -> BackendCapabilities;
}

fn add_command_capabilities(required: &mut BackendCapabilities, command: &CommandRequest) {
    if command.working_directory().is_some() {
        required
            .capabilities
            .insert(BackendCapability::WorkingDirectory);
    }
    for mode in [
        command.stdio().stdin(),
        command.stdio().stdout(),
        command.stdio().stderr(),
    ] {
        required.capabilities.insert(match mode {
            StdioMode::Inherit => BackendCapability::StdioInherit,
            StdioMode::Null => BackendCapability::StdioNull,
            StdioMode::Pipe => BackendCapability::StdioPipe,
        });
    }
    required
        .capabilities
        .insert(match command.timeout_policy() {
            TimeoutPolicy::BackendDefault => BackendCapability::TimeoutBackendDefault,
            TimeoutPolicy::Limit(_) => BackendCapability::TimeoutLimit,
            TimeoutPolicy::Disabled => BackendCapability::TimeoutDisabled,
        });
}

fn add_filesystem_capabilities(required: &mut BackendCapabilities, sandbox: &EffectiveSandbox) {
    let requested = sandbox.filesystem().requested();
    let ceiling = sandbox.filesystem().ceiling();
    let mode = match (requested.mode(), ceiling.mode()) {
        (FilesystemMode::External, FilesystemMode::External) => FilesystemMode::External,
        (FilesystemMode::Restricted, _) | (_, FilesystemMode::Restricted) => {
            FilesystemMode::Restricted
        }
        (FilesystemMode::Unrestricted, FilesystemMode::Unrestricted) => {
            FilesystemMode::Unrestricted
        }
        (FilesystemMode::External, _) | (_, FilesystemMode::External) => {
            unreachable!("effective sandbox cannot contain mixed filesystem ownership")
        }
    };
    required.capabilities.insert(match mode {
        FilesystemMode::Restricted => BackendCapability::FilesystemRestricted,
        FilesystemMode::Unrestricted => BackendCapability::FilesystemUnrestricted,
        FilesystemMode::External => BackendCapability::FilesystemExternal,
    });
    if sandbox.workspace_roots().is_some() || sandbox.workspace_root_limit().is_some() {
        required
            .capabilities
            .insert(BackendCapability::FilesystemScopes);
    }
    if mode != FilesystemMode::Restricted {
        return;
    }
    let has_deny_glob = [requested, ceiling].iter().any(|policy| {
        policy.entries().iter().any(|rule| {
            matches!(rule.target(), FilesystemTarget::Glob(_))
                && rule.access() == cageforge_policy::AccessMode::Deny
        })
    });
    if has_deny_glob {
        required
            .capabilities
            .insert(BackendCapability::FilesystemGlobScanDepth);
    }
    for policy in [requested, ceiling] {
        if !policy.protected_relative_paths().is_empty() {
            required
                .capabilities
                .insert(BackendCapability::FilesystemProtectedPaths);
        }
        for rule in policy.entries() {
            match rule.target() {
                FilesystemTarget::Scope(_) => {
                    required
                        .capabilities
                        .insert(BackendCapability::FilesystemScopes);
                    required
                        .capabilities
                        .insert(BackendCapability::FilesystemMissingPathBehavior);
                }
                FilesystemTarget::Glob(pattern) => {
                    required
                        .capabilities
                        .insert(BackendCapability::FilesystemGlobs);
                    if !pattern.is_absolute() {
                        required
                            .capabilities
                            .insert(BackendCapability::FilesystemScopes);
                    }
                }
            }
            if !rule.read_only_subpaths().is_empty() {
                required
                    .capabilities
                    .insert(BackendCapability::FilesystemReadOnlySubpaths);
            }
        }
    }
}

fn add_network_capabilities(required: &mut BackendCapabilities, sandbox: &EffectiveSandbox) {
    let requested = sandbox.network().requested();
    let ceiling = sandbox.network().ceiling();
    let mode = match (requested.mode(), ceiling.mode()) {
        (NetworkMode::External, NetworkMode::External) => NetworkMode::External,
        (NetworkMode::Disabled, _) | (_, NetworkMode::Disabled) => NetworkMode::Disabled,
        (NetworkMode::Enabled, NetworkMode::Enabled) => NetworkMode::Enabled,
        (NetworkMode::External, _) | (_, NetworkMode::External) => {
            unreachable!("effective sandbox cannot contain mixed network ownership")
        }
    };
    required.capabilities.insert(match mode {
        NetworkMode::Disabled => BackendCapability::NetworkDisabled,
        NetworkMode::Enabled => BackendCapability::NetworkEnabled,
        NetworkMode::External => BackendCapability::NetworkExternal,
    });
    if mode != NetworkMode::Enabled {
        return;
    }
    required
        .capabilities
        .insert(BackendCapability::NetworkResolvedTargets);
    for policy in [requested, ceiling] {
        if !policy.domains().is_empty() || policy.domain_mode() != DomainMode::Enabled {
            required
                .capabilities
                .insert(BackendCapability::NetworkDomainRules);
        }
        if policy.local_network_access() == LocalNetworkAccess::Deny {
            required
                .capabilities
                .insert(BackendCapability::NetworkLocalAddressRestrictions);
        }
        if !policy.unix_sockets().is_empty()
            || policy.unix_socket_mode() != UnixSocketMode::Disabled
        {
            required
                .capabilities
                .insert(BackendCapability::NetworkUnixSockets);
        }
    }
}

fn add_environment_capabilities(required: &mut BackendCapabilities, sandbox: &EffectiveSandbox) {
    required
        .capabilities
        .insert(match sandbox.environment().base() {
            EnvironmentBase::All => BackendCapability::EnvironmentAll,
            EnvironmentBase::Core => BackendCapability::EnvironmentCore,
            EnvironmentBase::None => BackendCapability::EnvironmentNone,
        });
    if !sandbox.environment().requested().filters().is_empty()
        || !sandbox.environment().ceiling().filters().is_empty()
    {
        required
            .capabilities
            .insert(BackendCapability::EnvironmentFilters);
    }
    if !sandbox.environment().requested().overrides().is_empty()
        || !sandbox.environment().ceiling().overrides().is_empty()
    {
        required
            .capabilities
            .insert(BackendCapability::EnvironmentOverrides);
    }
}
