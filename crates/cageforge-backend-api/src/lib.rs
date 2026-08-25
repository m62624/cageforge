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
use std::fmt;
use std::marker::PhantomData;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;

use cageforge_command::{CommandRequest, CommandSpec, StdioSpec, TimeoutPolicy};
use cageforge_path::normalize_lexical_path;
use cageforge_policy::{
    ConnectionAuthorization, FilesystemDecision, NetworkDecision, PathResolutionContext,
    PathSelector, ResolvedNetworkTarget,
};
use cageforge_policy_compose::{
    EffectiveFilesystemLowering, EffectiveNetworkLowering, EffectivePathContext, EffectiveSandbox,
    EnvironmentInput,
};
mod model;

pub use model::{
    BackendCapabilities, BackendCapability, BackendContractError, BackendIdentity, BackendRequest,
    PreparedBackendRequest, SandboxBackend,
};

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
    /// permitted by the effective filesystem policy. The returned value is
    /// bound to `B`, so a handoff prepared for one backend type cannot be passed
    /// to a native lowering method for another backend type by accident.
    pub fn prepare_for<B: SandboxBackend>(
        self,
        backend: &B,
        base_context: &PathResolutionContext,
    ) -> Result<PreparedBackendRequest<'a, B>, BackendContractError> {
        self.validate::<B>(&backend.capabilities(), backend.identity(), base_context)
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
    fn validate<B: SandboxBackend>(
        self,
        capabilities: &BackendCapabilities,
        backend_identity: &BackendIdentity,
        base_context: &PathResolutionContext,
    ) -> Result<PreparedBackendRequest<'a, B>, BackendContractError> {
        if !self
            .sandbox
            .environment()
            .requested_matches(self.command.environment())
        {
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
                let current_directory = base_context.current_directory().ok_or_else(|| {
                    BackendContractError::WorkingDirectoryResolution {
                        path: path.to_path_buf(),
                    }
                })?;
                normalize_lexical_path(&current_directory.join(path)).into_owned()
            }
            None => base_context
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
            capabilities: capabilities.clone(),
            backend_identity: backend_identity.clone(),
            backend: PhantomData,
        })
    }
}

impl BackendIdentity {
    /// Creates a new backend-instance identity.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self(Arc::new(()))
    }
}

impl fmt::Debug for BackendIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BackendIdentity")
            .finish_non_exhaustive()
    }
}

impl PartialEq for BackendIdentity {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for BackendIdentity {}

impl<'a, B: SandboxBackend> Clone for PreparedBackendRequest<'a, B> {
    fn clone(&self) -> Self {
        Self {
            request: self.request,
            path_context: self.path_context.clone(),
            working_directory: self.working_directory.clone(),
            capabilities: self.capabilities.clone(),
            backend_identity: self.backend_identity.clone(),
            backend: PhantomData,
        }
    }
}

impl<'a, B: SandboxBackend> fmt::Debug for PreparedBackendRequest<'a, B> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedBackendRequest")
            .field("request", &self.request)
            .field("path_context", &self.path_context)
            .field("working_directory", &self.working_directory)
            .field("capabilities", &self.capabilities)
            .finish()
    }
}

impl<'a, B: SandboxBackend> PreparedBackendRequest<'a, B> {
    fn ensure_backend(&self, backend: &B) -> Result<(), BackendContractError> {
        if self.backend_identity != *backend.identity() {
            Err(BackendContractError::BackendIdentityMismatch)
        } else if self.capabilities != backend.capabilities() {
            Err(BackendContractError::BackendCapabilitiesMismatch)
        } else {
            Ok(())
        }
    }

    /// Returns the validated executable and argv values.
    ///
    /// The working directory is intentionally exposed separately through
    /// [`Self::working_directory`]. A backend must not recover or inherit the
    /// original optional cwd from a raw [`CommandRequest`] after preflight.
    pub fn command_spec(&self, backend: &B) -> Result<&'a CommandSpec, BackendContractError> {
        self.ensure_backend(backend)?;
        Ok(self.request.command().command())
    }

    /// Returns the validated effective sandbox.
    pub fn sandbox(&self, backend: &B) -> Result<&'a EffectiveSandbox, BackendContractError> {
        self.ensure_backend(backend)?;
        Ok(self.request.sandbox())
    }

    /// Returns all filesystem constraint layers required for native lowering.
    ///
    /// The backend must enforce every layer in the returned view. This is
    /// distinct from the combined decision helpers: a native sandbox builder
    /// needs the concrete rules, protected paths, and glob settings, while
    /// the view prevents it from selecting only the requested or ceiling
    /// side.
    pub fn filesystem_lowering(
        &self,
        backend: &B,
    ) -> Result<EffectiveFilesystemLowering<'_>, BackendContractError> {
        self.ensure_backend(backend)?;
        Ok(self.request.sandbox().filesystem().lowering())
    }

    /// Returns all network constraint layers required for native lowering.
    ///
    /// These rules configure enforcement only. Actual connections must still
    /// use [`Self::authorize_connection`] with a resolved target and exact
    /// socket address.
    pub fn network_lowering(
        &self,
        backend: &B,
    ) -> Result<EffectiveNetworkLowering<'_>, BackendContractError> {
        self.ensure_backend(backend)?;
        Ok(self.request.sandbox().network().lowering())
    }

    /// Returns the runtime path context that was narrowed and checked during
    /// [`BackendRequest::prepare_for`].
    pub fn path_context(&self, backend: &B) -> Result<&EffectivePathContext, BackendContractError> {
        self.ensure_backend(backend)?;
        Ok(&self.path_context)
    }

    /// Returns the effective working directory resolved during preflight.
    ///
    /// This is always present. When the command did not specify an explicit
    /// directory, it is the runtime current directory supplied in the path
    /// context and checked against the effective filesystem policy.
    pub fn working_directory(&self, backend: &B) -> Result<&Path, BackendContractError> {
        self.ensure_backend(backend)?;
        Ok(&self.working_directory)
    }

    /// Returns the validated standard-stream routing.
    pub fn stdio(&self, backend: &B) -> Result<StdioSpec, BackendContractError> {
        self.ensure_backend(backend)?;
        Ok(self.request.command().stdio())
    }

    /// Returns the validated timeout intent.
    pub fn timeout_policy(&self, backend: &B) -> Result<TimeoutPolicy, BackendContractError> {
        self.ensure_backend(backend)?;
        Ok(self.request.command().timeout_policy())
    }

    /// Applies the effective environment to a backend-selected input base.
    ///
    /// A backend must construct [`EnvironmentInput::core`] only after it has
    /// selected the platform's conservative core environment.
    pub fn apply_environment(
        &self,
        backend: &B,
        input: EnvironmentInput,
    ) -> Result<BTreeMap<OsString, OsString>, BackendContractError> {
        self.ensure_backend(backend)?;
        self.request
            .sandbox()
            .environment()
            .apply_to(input)
            .map_err(|source| BackendContractError::EnvironmentPreparation { source })
    }

    /// Evaluates one absolute path against both effective filesystem policies.
    pub fn filesystem_access_for_path(
        &self,
        backend: &B,
        path: &Path,
    ) -> Result<FilesystemDecision, BackendContractError> {
        self.ensure_backend(backend)?;
        self.request
            .sandbox()
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
        backend: &B,
        selector: &PathSelector,
    ) -> Result<FilesystemDecision, BackendContractError> {
        self.ensure_backend(backend)?;
        self.request
            .sandbox()
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
        backend: &B,
        domain: &str,
        resolved_ips: &[IpAddr],
    ) -> Result<NetworkDecision, BackendContractError> {
        self.ensure_backend(backend)?;
        self.request
            .sandbox()
            .network()
            .decision_for_domain_with_resolved_ips(domain, resolved_ips)
            .map_err(|source| BackendContractError::NetworkEvaluation { source })
    }

    /// Authorizes the exact socket address the backend is about to connect to.
    pub fn authorize_connection(
        &self,
        backend: &B,
        target: &ResolvedNetworkTarget,
        connected: SocketAddr,
    ) -> Result<ConnectionAuthorization, BackendContractError> {
        self.ensure_backend(backend)?;
        self.request
            .sandbox()
            .network()
            .authorize_connection(target, connected)
            .map_err(|source| BackendContractError::NetworkEvaluation { source })
    }

    /// Evaluates one Unix socket path against both effective network policies.
    pub fn network_decision_for_unix_socket(
        &self,
        backend: &B,
        socket: &Path,
    ) -> Result<NetworkDecision, BackendContractError> {
        self.ensure_backend(backend)?;
        self.request
            .sandbox()
            .network()
            .decision_for_unix_socket(socket)
            .map_err(|source| BackendContractError::NetworkEvaluation { source })
    }
}
