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

mod capability;
mod requirements;

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use cageforge_command::{CommandRequest, CommandSpec, StdioSpec, TimeoutPolicy};
use cageforge_path::normalize_lexical_path;
use cageforge_policy::{
    ConnectionAuthorization, FilesystemDecision, NetworkDecision, PathResolutionContext,
    PathSelector, ResolvedNetworkTarget,
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
    /// `backend` and the backend's runtime path context.
    ///
    /// This is the safe handoff entry point for native integrations. The
    /// capability check is defined by Cageforge and cannot be overridden by a
    /// backend implementation. The context is narrowed before return, and an
    /// effective working directory must be supplied by the runtime context and
    /// permitted by the effective filesystem policy.
    pub fn prepare_for<B: SandboxBackend>(
        self,
        backend: &B,
        base_context: &PathResolutionContext,
    ) -> Result<PreparedBackendRequest<'a>, BackendContractError> {
        self.validate(&backend.capabilities(), base_context)
    }

    /// Computes the capabilities required by this request.
    pub fn required_capabilities(&self) -> BackendCapabilities {
        let mut required = BackendCapabilities::new().with(BackendCapability::CommandExecution);
        requirements::add_command_capabilities(&mut required, self.command);
        requirements::add_filesystem_capabilities(&mut required, self.sandbox);
        requirements::add_network_capabilities(&mut required, self.sandbox);
        requirements::add_environment_capabilities(&mut required, self.sandbox);
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
        base_context: &PathResolutionContext,
    ) -> Result<PreparedBackendRequest<'a>, BackendContractError> {
        if self.command.environment() != self.sandbox.environment().requested() {
            return Err(BackendContractError::CommandEnvironmentMismatch);
        }
        for capability in self.required_capabilities().iter().copied() {
            if !capabilities.supports(capability) {
                return Err(BackendContractError::UnsupportedCapability { capability });
            }
        }
        let path_context = self
            .sandbox
            .path_context(base_context)
            .map_err(|source| BackendContractError::InvalidRuntimeContext { source })?;
        let working_directory = match self.command.working_directory() {
            Some(path) if path.is_absolute() => normalize_lexical_path(path).into_owned(),
            Some(path) => {
                let current_directory = path_context.current_directory().ok_or_else(|| {
                    BackendContractError::WorkingDirectoryResolution {
                        path: path.to_path_buf(),
                    }
                })?;
                normalize_lexical_path(&current_directory.join(path)).into_owned()
            }
            None => path_context
                .current_directory()
                .map(normalize_lexical_path)
                .map(std::borrow::Cow::into_owned)
                .ok_or(BackendContractError::MissingRuntimeCurrentDirectory)?,
        };
        match self
            .sandbox
            .filesystem()
            .access_for_path(&working_directory, &path_context)
            .map_err(|source| BackendContractError::FilesystemEvaluation { source })?
        {
            FilesystemDecision::Read
            | FilesystemDecision::Write
            | FilesystemDecision::ExternallyEnforced => {}
            FilesystemDecision::Deny => {
                return Err(BackendContractError::WorkingDirectoryDenied {
                    path: working_directory.clone(),
                });
            }
        }
        Ok(PreparedBackendRequest {
            request: self,
            path_context,
            working_directory,
        })
    }
}

/// A request that passed backend capability preflight.
///
/// This type is still portable and contains no process handle. Native backend
/// code may lower it to an OS-specific launch request after applying the
/// filesystem, network, environment, and lifecycle contracts.
#[derive(Debug, Clone)]
pub struct PreparedBackendRequest<'a> {
    request: BackendRequest<'a>,
    path_context: EffectivePathContext,
    working_directory: PathBuf,
}

impl<'a> PreparedBackendRequest<'a> {
    /// Returns the validated executable and argv values.
    ///
    /// The working directory is intentionally exposed separately through
    /// [`Self::working_directory`]. A backend must not recover or inherit the
    /// original optional cwd from a raw [`CommandRequest`] after preflight.
    pub fn command_spec(&self) -> &'a CommandSpec {
        self.request.command().command()
    }

    /// Returns the validated effective sandbox.
    pub const fn sandbox(&self) -> &'a EffectiveSandbox {
        self.request.sandbox()
    }

    /// Returns the runtime path context that was narrowed and checked during
    /// [`BackendRequest::prepare_for`].
    pub fn path_context(&self) -> &EffectivePathContext {
        &self.path_context
    }

    /// Returns the effective working directory resolved during preflight.
    ///
    /// This is always present. When the command did not specify an explicit
    /// directory, it is the runtime current directory supplied in the path
    /// context and checked against the effective filesystem policy.
    pub fn working_directory(&self) -> &Path {
        &self.working_directory
    }

    /// Returns the validated standard-stream routing.
    pub fn stdio(&self) -> StdioSpec {
        self.request.command().stdio()
    }

    /// Returns the validated timeout intent.
    pub fn timeout_policy(&self) -> TimeoutPolicy {
        self.request.command().timeout_policy()
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

    /// Evaluates one absolute path against both effective filesystem policies.
    pub fn filesystem_access_for_path(
        &self,
        path: &Path,
    ) -> Result<FilesystemDecision, BackendContractError> {
        self.sandbox()
            .filesystem()
            .access_for_path(path, &self.path_context)
            .map_err(|source| BackendContractError::FilesystemEvaluation { source })
    }

    /// Evaluates one symbolic filesystem selector against both effective
    /// policies and the narrowed runtime context.
    ///
    /// The context must come from [`Self::path_context`]. A selector that has
    /// no effective runtime paths is denied, so a backend cannot accidentally
    /// replace a workspace-root ceiling with a broader context.
    pub fn filesystem_access_for(
        &self,
        selector: &PathSelector,
    ) -> Result<FilesystemDecision, BackendContractError> {
        self.sandbox()
            .filesystem()
            .access_for(selector, &self.path_context)
            .map_err(|source| BackendContractError::FilesystemEvaluation { source })
    }

    /// Evaluates a resolved hostname and all addresses captured for it.
    ///
    /// This is a policy query, not connection authorization. A backend must
    /// call [`Self::authorize_connection`] immediately before connecting.
    pub fn network_decision_for_domain_with_resolved_ips(
        &self,
        domain: &str,
        resolved_ips: &[IpAddr],
    ) -> Result<NetworkDecision, BackendContractError> {
        self.sandbox()
            .network()
            .decision_for_domain_with_resolved_ips(domain, resolved_ips)
            .map_err(|source| BackendContractError::NetworkEvaluation { source })
    }

    /// Authorizes the exact socket address the backend is about to connect to.
    pub fn authorize_connection(
        &self,
        target: &ResolvedNetworkTarget,
        connected: SocketAddr,
    ) -> Result<ConnectionAuthorization, BackendContractError> {
        self.sandbox()
            .network()
            .authorize_connection(target, connected)
            .map_err(|source| BackendContractError::NetworkEvaluation { source })
    }

    /// Evaluates one Unix socket path against both effective network policies.
    pub fn network_decision_for_unix_socket(
        &self,
        socket: &Path,
    ) -> Result<NetworkDecision, BackendContractError> {
        self.sandbox()
            .network()
            .decision_for_unix_socket(socket)
            .map_err(|source| BackendContractError::NetworkEvaluation { source })
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
