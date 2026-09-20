// SPDX-License-Identifier: Apache-2.0

//! Preflight preparation shared by the facade and language adapters.

use cageforge_command::EnvironmentSpec;
use cageforge_permissions::{
    FilesystemCapability, FilesystemOperation, NetworkCapability, PermissionError,
    PermissionEscalationRequest, PermissionGrant, PermissionRequest, PermissionSet, PlatformId,
    ProcessCapability,
};
use cageforge_policy::{
    AccessMode, DomainAccess, DomainMode, FilesystemMode, FilesystemPolicy, FilesystemRule,
    FilesystemTarget, LocalIpcEndpoint, LocalNetworkAccess, NetworkMode, NetworkPolicy,
    PathSelector, SandboxPolicy, UnixSocketMode,
};
use cageforge_policy_compose::{CompositionRequest, EffectiveSandbox, PolicyCeiling, compose};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Immutable identity metadata bound to one preflight request.
#[derive(Debug, Clone)]
pub struct PreflightIdentity {
    tool_id: String,
    tool_version: String,
    manifest_digest: String,
    config_digest: String,
    platform: PlatformId,
    architecture: String,
}

impl PreflightIdentity {
    /// Describes the immutable host identity bound to a launch request.
    pub fn new(
        tool_id: impl Into<String>,
        tool_version: impl Into<String>,
        manifest_digest: impl Into<String>,
        config_digest: impl Into<String>,
        platform: PlatformId,
        architecture: impl Into<String>,
    ) -> Self {
        Self {
            tool_id: tool_id.into(),
            tool_version: tool_version.into(),
            manifest_digest: manifest_digest.into(),
            config_digest: config_digest.into(),
            platform,
            architecture: architecture.into(),
        }
    }
}

/// A prepared launch that has not yet received a trusted approval.
#[derive(Debug, Clone)]
pub struct PreflightPlan {
    request: PermissionRequest,
    effective: EffectiveSandbox,
    narrowing: Option<NarrowingInputs>,
}

#[derive(Debug, Clone)]
struct NarrowingInputs {
    requested: SandboxPolicy,
    context: cageforge_policy::PathResolutionContext,
    environment: EnvironmentSpec,
    ceiling: PolicyCeiling,
    workspace_roots: Option<Vec<std::path::PathBuf>>,
}

/// An immutable effective sandbox paired with its approved grant.
#[derive(Debug, Clone)]
pub struct AuthorizedPlan {
    effective: EffectiveSandbox,
    grant: PermissionGrant,
    context: Option<cageforge_policy::PathResolutionContext>,
}

/// A validated policy expansion that must be approved before relaunch.
#[derive(Debug, Clone)]
pub struct PermissionEscalationPlan {
    request: PermissionEscalationRequest,
    plan: PreflightPlan,
}

/// Errors returned while preparing or authorizing a preflight launch.
#[derive(Debug, Error)]
pub enum PreflightError {
    /// The requested capability model could not be constructed.
    #[error("invalid permission request: {0}")]
    Permission(#[from] PermissionError),
    /// The grant belongs to another request or tool identity.
    #[error("permission grant does not match the preflight request")]
    GrantMismatch,
    /// The grant's expiration has elapsed.
    #[error("permission grant has expired")]
    GrantExpired,
    /// The approval host did not answer before the configured deadline.
    #[error("permission approval timed out")]
    ApprovalTimeout,
    /// The profile requests a dynamic mode not implemented by this release.
    #[error("permission mode {0:?} is not supported by this launch adapter")]
    UnsupportedMode(cageforge_permissions::PermissionMode),
    /// A partial grant cannot be lowered safely until policy narrowing is
    /// implemented for every native backend.
    #[error("partial permission grants are not supported for this launch")]
    PartialGrantUnsupported,
    /// The approved subset could not be lowered safely inside the ceiling.
    #[error("approved permission subset cannot be lowered safely: {0}")]
    Narrowing(String),
    /// The active plan has no policy context from which an expansion can be
    /// composed.
    #[error("dynamic permission escalation requires a policy-backed preflight plan")]
    EscalationUnsupported,
    /// The requested capability cannot be added to a relaunch with the
    /// current command and policy model.
    #[error("unsupported dynamic escalation capability: {0}")]
    UnsupportedEscalationCapability(&'static str),
    /// The selected platform is unavailable on this target.
    #[error("unsupported platform: {0}")]
    Platform(#[from] cageforge_permissions::PlatformError),
}

impl PreflightPlan {
    /// Creates a plan from a fully composed immutable sandbox and typed request.
    pub fn new(request: PermissionRequest, effective: EffectiveSandbox) -> Self {
        Self {
            request,
            effective,
            narrowing: None,
        }
    }

    /// Builds a request from a resolved policy and runtime context.
    pub fn from_policy(
        policy: &SandboxPolicy,
        context: &cageforge_policy::PathResolutionContext,
        effective: EffectiveSandbox,
        identity: PreflightIdentity,
    ) -> Result<Self, PreflightError> {
        let capabilities = permission_set(policy, context)?;
        let request = PermissionRequest::new(
            identity.tool_id,
            identity.tool_version,
            identity.manifest_digest,
            identity.config_digest,
            identity.platform,
            identity.architecture,
            capabilities,
        )?;
        Ok(Self::new(request, effective))
    }

    /// Builds a plan that can lower partial grants against the same ceiling
    /// used to create the composed effective sandbox.
    pub fn from_policy_with_ceiling(
        policy: &SandboxPolicy,
        context: &cageforge_policy::PathResolutionContext,
        effective: EffectiveSandbox,
        environment: &EnvironmentSpec,
        ceiling: &PolicyCeiling,
        identity: PreflightIdentity,
    ) -> Result<Self, PreflightError> {
        let mut plan = Self::from_policy(policy, context, effective.clone(), identity)?;
        plan.narrowing = Some(NarrowingInputs {
            requested: policy.clone(),
            context: context.clone(),
            environment: environment.clone(),
            ceiling: ceiling.clone(),
            workspace_roots: effective.workspace_roots().map(<[_]>::to_vec),
        });
        Ok(plan)
    }

    /// Builds a request using the current target platform and architecture.
    pub fn from_policy_current(
        policy: &SandboxPolicy,
        context: &cageforge_policy::PathResolutionContext,
        effective: EffectiveSandbox,
        tool_id: impl Into<String>,
        tool_version: impl Into<String>,
        manifest_digest: impl Into<String>,
        config_digest: impl Into<String>,
    ) -> Result<Self, PreflightError> {
        let identity = PreflightIdentity::new(
            tool_id,
            tool_version,
            manifest_digest,
            config_digest,
            PlatformId::current()?,
            std::env::consts::ARCH,
        );
        Self::from_policy(policy, context, effective, identity)
    }

    /// Returns the descriptive request shown to a trusted host or user.
    pub fn request(&self) -> &PermissionRequest {
        &self.request
    }

    /// Adds the executable selected for this launch to the request.
    pub fn with_process_program(
        mut self,
        program: impl Into<String>,
    ) -> Result<Self, PreflightError> {
        let capabilities = self
            .request
            .capabilities()
            .clone()
            .with_child_process(ProcessCapability::new(program)?);
        self.request = PermissionRequest::new(
            self.request.tool_id(),
            self.request.tool_version(),
            self.request.manifest_digest(),
            self.request.config_digest(),
            self.request.platform(),
            self.request.architecture(),
            capabilities,
        )?;
        Ok(self)
    }

    /// Creates a validated escalation plan for an approved relaunch.
    ///
    /// Additional filesystem and network capabilities are translated back to
    /// the same portable policy model used for the original launch. The
    /// existing policy ceiling remains in force; the trusted grant never
    /// widens that outer boundary.
    pub fn request_escalation(
        &self,
        additional: PermissionSet,
        reason: impl Into<String>,
    ) -> Result<PermissionEscalationPlan, PreflightError> {
        let inputs = self
            .narrowing
            .as_ref()
            .ok_or(PreflightError::EscalationUnsupported)?;
        if !additional.child_processes().is_empty() {
            return Err(PreflightError::UnsupportedEscalationCapability(
                "child-process",
            ));
        }
        let (policy, context) = expanded_policy(&inputs.requested, &inputs.context, &additional)?;
        let mut composition =
            CompositionRequest::new(&policy, &inputs.environment, &inputs.ceiling);
        if let Some(roots) = &inputs.workspace_roots {
            composition = composition
                .with_workspace_roots(roots.clone())
                .map_err(|error| PreflightError::Narrowing(error.to_string()))?;
        }
        let effective =
            compose(composition).map_err(|error| PreflightError::Narrowing(error.to_string()))?;
        let mut expanded = Self::from_policy_with_ceiling(
            &policy,
            &context,
            effective,
            &inputs.environment,
            &inputs.ceiling,
            PreflightIdentity::new(
                self.request.tool_id(),
                self.request.tool_version(),
                self.request.manifest_digest(),
                self.request.config_digest(),
                self.request.platform(),
                self.request.architecture(),
            ),
        )?;
        for process in self.request.capabilities().child_processes() {
            expanded = expanded.with_process_program(process.program())?;
        }
        let request = PermissionEscalationRequest::new(self.request.clone(), additional, reason)?;
        if expanded.request != *request.request() {
            return Err(PreflightError::Narrowing(
                "expanded policy and permission request disagree".to_owned(),
            ));
        }
        Ok(PermissionEscalationPlan {
            request,
            plan: expanded,
        })
    }

    /// Authorizes the plan with a trusted grant.
    pub fn authorize(&self, grant: PermissionGrant) -> Result<AuthorizedPlan, PreflightError> {
        if !grant.matches(&self.request) {
            return Err(PreflightError::GrantMismatch);
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs());
        if !grant.is_valid_at(now) {
            return Err(PreflightError::GrantExpired);
        }
        if grant.approved().child_processes() != self.request.capabilities().child_processes() {
            return Err(PreflightError::PartialGrantUnsupported);
        }
        for capability in self.request.capabilities().filesystem() {
            if capability.operation() != FilesystemOperation::MapExecutable {
                continue;
            }
            let read =
                FilesystemCapability::new(FilesystemOperation::Read, capability.path().to_owned())?;
            if !grant.approved().filesystem().contains(capability)
                || (self.request.capabilities().filesystem().contains(&read)
                    && !grant.approved().filesystem().contains(&read))
            {
                return Err(PreflightError::PartialGrantUnsupported);
            }
        }
        let effective = if grant.approved() == self.request.capabilities() {
            self.effective.clone()
        } else if let Some(inputs) = &self.narrowing {
            let policy = narrow_policy(&inputs.requested, &inputs.context, grant.approved())?;
            let mut composition =
                CompositionRequest::new(&policy, &inputs.environment, &inputs.ceiling);
            if let Some(roots) = &inputs.workspace_roots {
                composition = composition
                    .with_workspace_roots(roots.clone())
                    .map_err(|error| PreflightError::Narrowing(error.to_string()))?;
            }
            compose(composition).map_err(|error| PreflightError::Narrowing(error.to_string()))?
        } else {
            return Err(PreflightError::PartialGrantUnsupported);
        };
        Ok(AuthorizedPlan {
            effective,
            grant,
            context: self.narrowing.as_ref().map(|inputs| inputs.context.clone()),
        })
    }
}

impl PermissionEscalationPlan {
    /// Returns the complete escalation request sent to the trusted host.
    pub fn request(&self) -> &PermissionEscalationRequest {
        &self.request
    }

    /// Returns the capabilities added by this escalation.
    pub fn additional(&self) -> &PermissionSet {
        self.request.additional()
    }

    /// Returns the host-visible reason for this escalation.
    pub fn reason(&self) -> &str {
        self.request.reason()
    }

    /// Authorizes the expanded plan with a trusted grant.
    pub fn authorize(&self, grant: PermissionGrant) -> Result<AuthorizedPlan, PreflightError> {
        self.plan.authorize(grant)
    }
}

impl AuthorizedPlan {
    /// Returns the immutable effective sandbox for backend launch.
    pub fn effective(&self) -> &EffectiveSandbox {
        &self.effective
    }

    /// Returns the grant that authorized this plan.
    pub fn grant(&self) -> &PermissionGrant {
        &self.grant
    }

    /// Returns the runtime context used to compose this authorized plan.
    pub fn context(&self) -> Option<&cageforge_policy::PathResolutionContext> {
        self.context.as_ref()
    }
}

/// Computes the canonical SHA-256 digest used for configuration identity.
pub fn sha256_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn permission_set(
    policy: &SandboxPolicy,
    context: &cageforge_policy::PathResolutionContext,
) -> Result<PermissionSet, PreflightError> {
    let mut capabilities = PermissionSet::new();
    for rule in policy.filesystem().entries() {
        let operation = filesystem_operation(rule.access());
        match rule.target() {
            FilesystemTarget::Scope(selector) => {
                let paths = selector.resolve(context);
                if paths.is_empty() {
                    capabilities = capabilities.with_filesystem(FilesystemCapability::new(
                        operation,
                        format!("selector:{selector:?}"),
                    )?);
                } else {
                    for path in paths {
                        capabilities = capabilities.with_filesystem(FilesystemCapability::new(
                            operation,
                            path_to_string(&path),
                        )?);
                    }
                }
            }
            FilesystemTarget::Glob(pattern) => {
                capabilities = capabilities.with_filesystem(FilesystemCapability::new(
                    operation,
                    format!("glob:{}", pattern.as_str()),
                )?);
            }
        }
        for selector in rule.read_only_subpaths() {
            for path in selector.resolve(context) {
                capabilities = capabilities.with_filesystem(FilesystemCapability::new(
                    FilesystemOperation::Read,
                    path_to_string(&path),
                )?);
            }
        }
    }
    if policy.filesystem().mode() == cageforge_policy::FilesystemMode::Unrestricted {
        capabilities = capabilities.with_filesystem(FilesystemCapability::new(
            FilesystemOperation::Read,
            "filesystem://unrestricted",
        )?);
        capabilities = capabilities.with_filesystem(FilesystemCapability::new(
            FilesystemOperation::Write,
            "filesystem://unrestricted",
        )?);
    }
    for path in context.executable_roots() {
        capabilities = capabilities.with_filesystem(FilesystemCapability::new(
            FilesystemOperation::MapExecutable,
            path_to_string(path),
        )?);
    }
    for domain in policy.network().domains() {
        if domain.access() == DomainAccess::Allow {
            capabilities = capabilities.with_network(NetworkCapability::new(domain.pattern())?);
        }
    }
    for socket in policy.network().unix_sockets() {
        if socket.access() == DomainAccess::Allow {
            capabilities = capabilities.with_network(NetworkCapability::new(format!(
                "unix:{}",
                socket.path().display()
            ))?);
        }
    }
    for rule in policy.network().local_ipc() {
        if rule.access() == DomainAccess::Allow {
            let endpoint = match rule.endpoint() {
                cageforge_policy::LocalIpcEndpoint::UnixSocket(path) => {
                    format!("unix:{}", path.as_path().display())
                }
                cageforge_policy::LocalIpcEndpoint::WindowsNamedPipe(name) => {
                    format!("pipe:{}", name.as_str())
                }
            };
            capabilities = capabilities.with_network(NetworkCapability::new(endpoint)?);
        }
    }
    if policy.network().mode() == NetworkMode::Enabled
        && policy.network().domain_mode() == cageforge_policy::DomainMode::Enabled
    {
        capabilities = capabilities.with_network(NetworkCapability::new("network://enabled")?);
    }
    if policy.network().mode() == NetworkMode::Enabled
        && policy.network().unix_socket_mode() == cageforge_policy::UnixSocketMode::Enabled
    {
        capabilities = capabilities.with_network(NetworkCapability::new("unix://enabled")?);
    }
    if policy.network().local_network_access() == cageforge_policy::LocalNetworkAccess::Allow {
        capabilities = capabilities.with_network(NetworkCapability::new("network://local")?);
    }
    Ok(capabilities)
}

fn expanded_policy(
    policy: &SandboxPolicy,
    context: &cageforge_policy::PathResolutionContext,
    additional: &PermissionSet,
) -> Result<(SandboxPolicy, cageforge_policy::PathResolutionContext), PreflightError> {
    let mut filesystem = policy.filesystem().clone();
    let mut network = policy.network().clone();
    let mut context = context.clone();

    for capability in additional.filesystem() {
        match capability.operation() {
            FilesystemOperation::Read | FilesystemOperation::Write => {
                let selector = PathSelector::absolute(capability.path())
                    .map_err(|error| PreflightError::Narrowing(error.to_string()))?;
                filesystem = filesystem
                    .with_rule(FilesystemRule::new(
                        selector,
                        match capability.operation() {
                            FilesystemOperation::Read => AccessMode::Read,
                            FilesystemOperation::Write => AccessMode::Write,
                            _ => {
                                return Err(PreflightError::UnsupportedEscalationCapability(
                                    "invalid filesystem operation",
                                ));
                            }
                        },
                    ))
                    .map_err(|error| PreflightError::Narrowing(error.to_string()))?;
            }
            FilesystemOperation::MapExecutable => {
                let read = FilesystemCapability::new(
                    FilesystemOperation::Read,
                    capability.path().to_owned(),
                )?;
                if !policy_permission_contains(policy, &context, &read)?
                    && !additional.filesystem().contains(&read)
                {
                    return Err(PreflightError::UnsupportedEscalationCapability(
                        "map-executable without read",
                    ));
                }
                context = context
                    .with_executable_root(capability.path())
                    .map_err(|error| PreflightError::Narrowing(error.to_string()))?;
            }
            FilesystemOperation::Deny => {
                return Err(PreflightError::UnsupportedEscalationCapability(
                    "deny-only filesystem rule",
                ));
            }
        }
    }

    for capability in additional.network() {
        let endpoint = capability.endpoint();
        if endpoint.starts_with("network://") || endpoint.starts_with("unix://") {
            return Err(PreflightError::UnsupportedEscalationCapability(
                "unrestricted network sentinel",
            ));
        }
        if let Some(path) = endpoint.strip_prefix("unix:") {
            let endpoint = LocalIpcEndpoint::unix_socket(path)
                .map_err(|error| PreflightError::Narrowing(error.to_string()))?;
            network = network
                .with_local_ipc(endpoint, DomainAccess::Allow)
                .map_err(|error| PreflightError::Narrowing(error.to_string()))?;
        } else if let Some(name) = endpoint.strip_prefix("pipe:") {
            let endpoint = LocalIpcEndpoint::windows_named_pipe(name)
                .map_err(|error| PreflightError::Narrowing(error.to_string()))?;
            network = network
                .with_local_ipc(endpoint, DomainAccess::Allow)
                .map_err(|error| PreflightError::Narrowing(error.to_string()))?;
        } else {
            if network.mode() == NetworkMode::External {
                return Err(PreflightError::UnsupportedEscalationCapability(
                    "network on externally enforced policy",
                ));
            }
            if network.mode() == NetworkMode::Disabled {
                network = NetworkPolicy::enabled()
                    .with_domain_mode(DomainMode::Restricted)
                    .with_unix_socket_mode(UnixSocketMode::Disabled);
            }
            network = network
                .with_domain(endpoint, DomainAccess::Allow)
                .map_err(|error| PreflightError::Narrowing(error.to_string()))?;
        }
    }

    Ok((SandboxPolicy::new(filesystem, network), context))
}

fn policy_permission_contains(
    policy: &SandboxPolicy,
    context: &cageforge_policy::PathResolutionContext,
    capability: &FilesystemCapability,
) -> Result<bool, PreflightError> {
    Ok(permission_set(policy, context)?
        .filesystem()
        .contains(capability))
}

fn narrow_policy(
    policy: &SandboxPolicy,
    context: &cageforge_policy::PathResolutionContext,
    approved: &PermissionSet,
) -> Result<SandboxPolicy, PreflightError> {
    Ok(SandboxPolicy::new(
        narrow_filesystem(policy, context, approved)?,
        narrow_network(policy, approved)?,
    ))
}

fn narrow_filesystem(
    policy: &SandboxPolicy,
    context: &cageforge_policy::PathResolutionContext,
    approved: &PermissionSet,
) -> Result<FilesystemPolicy, PreflightError> {
    let original = policy.filesystem();
    match original.mode() {
        FilesystemMode::External => Ok(FilesystemPolicy::external()),
        FilesystemMode::Unrestricted => {
            let read =
                FilesystemCapability::new(FilesystemOperation::Read, "filesystem://unrestricted")?;
            let write =
                FilesystemCapability::new(FilesystemOperation::Write, "filesystem://unrestricted")?;
            if approved.filesystem().contains(&read) && approved.filesystem().contains(&write) {
                Ok(FilesystemPolicy::unrestricted())
            } else {
                Err(PreflightError::Narrowing(
                    "unrestricted filesystem access requires an explicit full grant".to_owned(),
                ))
            }
        }
        FilesystemMode::Restricted => {
            let mut entries = Vec::new();
            for rule in original.entries() {
                match rule.target() {
                    FilesystemTarget::Glob(_) => {
                        if rule.access() == AccessMode::Deny {
                            entries.push(rule.clone());
                        }
                    }
                    FilesystemTarget::Scope(selector) => {
                        for path in selector.resolve(context) {
                            let operation = filesystem_operation(rule.access());
                            let capability = FilesystemCapability::new(
                                operation,
                                path.to_string_lossy().into_owned(),
                            )?;
                            if operation != FilesystemOperation::Deny
                                && !approved.filesystem().contains(&capability)
                            {
                                continue;
                            }
                            let mut narrowed = FilesystemRule::new(
                                cageforge_policy::PathSelector::absolute(path).map_err(
                                    |error| PreflightError::Narrowing(error.to_string()),
                                )?,
                                rule.access(),
                            )
                            .with_missing_path_behavior(rule.missing_path_behavior());
                            for subpath in rule.read_only_subpaths() {
                                for subpath in subpath.resolve(context) {
                                    narrowed = narrowed
                                        .with_read_only_subpath(
                                            cageforge_policy::PathSelector::absolute(subpath)
                                                .map_err(|error| {
                                                    PreflightError::Narrowing(error.to_string())
                                                })?,
                                        )
                                        .map_err(|error| {
                                            PreflightError::Narrowing(error.to_string())
                                        })?;
                                }
                            }
                            entries.push(narrowed);
                        }
                    }
                }
            }
            let mut narrowed = FilesystemPolicy::restricted(entries);
            if let Some(max_depth) = original.glob_scan_max_depth() {
                narrowed = narrowed
                    .with_glob_scan_max_depth(max_depth)
                    .map_err(|error| PreflightError::Narrowing(error.to_string()))?;
            }
            if !original
                .protected_relative_paths()
                .iter()
                .any(|path| path == Path::new(".git"))
            {
                narrowed = narrowed.dangerously_allow_git_write();
            }
            for path in original.protected_relative_paths() {
                if path != Path::new(".git") {
                    narrowed = narrowed
                        .with_additional_protected_relative_path(path.clone())
                        .map_err(|error| PreflightError::Narrowing(error.to_string()))?;
                }
            }
            Ok(narrowed)
        }
    }
}

fn narrow_network(
    policy: &SandboxPolicy,
    approved: &PermissionSet,
) -> Result<NetworkPolicy, PreflightError> {
    let original = policy.network();
    match original.mode() {
        NetworkMode::Disabled => Ok(NetworkPolicy::disabled()),
        NetworkMode::External => Ok(NetworkPolicy::external()),
        NetworkMode::Enabled => {
            let full_network = network_approved(approved, "network://enabled")?;
            let full_unix = network_approved(approved, "unix://enabled")?;
            let full_local = network_approved(approved, "network://local")?;
            let mut narrowed = NetworkPolicy::enabled()
                .with_domain_mode(if full_network {
                    original.domain_mode()
                } else if original.domain_mode() == DomainMode::Enabled {
                    DomainMode::Restricted
                } else {
                    original.domain_mode()
                })
                .with_unix_socket_mode(if full_unix {
                    original.unix_socket_mode()
                } else if original.unix_socket_mode() == UnixSocketMode::Enabled {
                    UnixSocketMode::Restricted
                } else {
                    original.unix_socket_mode()
                })
                .with_local_network_access(if full_local {
                    original.local_network_access()
                } else {
                    LocalNetworkAccess::Deny
                });
            for rule in original.domains() {
                let approved_rule = network_approved(approved, rule.pattern())?;
                if rule.access() == DomainAccess::Deny || full_network || approved_rule {
                    narrowed = narrowed
                        .with_domain(rule.pattern(), rule.access())
                        .map_err(|error| PreflightError::Narrowing(error.to_string()))?;
                }
            }
            for rule in original.unix_sockets() {
                let endpoint = format!("unix:{}", rule.path().display());
                let approved_rule = network_approved(approved, &endpoint)?;
                if rule.access() == DomainAccess::Deny || full_unix || approved_rule {
                    narrowed = narrowed
                        .with_unix_socket(rule.path().to_path_buf(), rule.access())
                        .map_err(|error| PreflightError::Narrowing(error.to_string()))?;
                }
            }
            for rule in original.local_ipc() {
                let endpoint = match rule.endpoint() {
                    cageforge_policy::LocalIpcEndpoint::UnixSocket(path) => {
                        format!("unix:{}", path.as_path().display())
                    }
                    cageforge_policy::LocalIpcEndpoint::WindowsNamedPipe(name) => {
                        format!("pipe:{}", name.as_str())
                    }
                };
                if rule.access() == DomainAccess::Deny || network_approved(approved, &endpoint)? {
                    narrowed = narrowed
                        .with_local_ipc(rule.endpoint().clone(), rule.access())
                        .map_err(|error| PreflightError::Narrowing(error.to_string()))?;
                }
            }
            Ok(narrowed)
        }
    }
}

fn network_approved(approved: &PermissionSet, endpoint: &str) -> Result<bool, PreflightError> {
    Ok(approved
        .network()
        .iter()
        .any(|capability| capability.endpoint() == endpoint))
}

fn filesystem_operation(access: AccessMode) -> FilesystemOperation {
    match access {
        AccessMode::Read => FilesystemOperation::Read,
        AccessMode::Write => FilesystemOperation::Write,
        AccessMode::Deny => FilesystemOperation::Deny,
    }
}

fn path_to_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use cageforge_permissions::GrantAuthority;
    use cageforge_permissions::{FilesystemCapability, FilesystemOperation};
    use cageforge_policy::{
        FilesystemDecision, FilesystemPolicy, FilesystemRule, NetworkPolicy, PathSelector,
    };
    use cageforge_policy_compose::{CompositionRequest, PolicyCeiling, compose};
    use std::path::PathBuf;

    fn test_absolute_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("cageforge-preflight-{name}"))
    }

    #[test]
    fn authorization_requires_the_exact_request() {
        let tool_path = test_absolute_path("tool");
        let policy = SandboxPolicy::new(
            FilesystemPolicy::restricted([FilesystemRule::new(
                PathSelector::absolute(tool_path).unwrap(),
                AccessMode::Read,
            )]),
            NetworkPolicy::disabled(),
        );
        let context = cageforge_policy::PathResolutionContext::new();
        let ceiling = PolicyCeiling::new(policy.clone(), Default::default());
        let effective = compose(CompositionRequest::new(
            &policy,
            &Default::default(),
            &ceiling,
        ))
        .unwrap();
        let plan = PreflightPlan::from_policy(
            &policy,
            &context,
            effective,
            PreflightIdentity::new(
                "tool",
                "1",
                "a".repeat(64),
                "b".repeat(64),
                PlatformId::Linux,
                "x86_64",
            ),
        )
        .unwrap();
        let grant = GrantAuthority::new().approve(plan.request());
        assert!(plan.authorize(grant).is_ok());
    }

    #[test]
    fn executable_mapping_is_a_separate_capability_and_cannot_be_partially_approved() {
        let runtime_root = test_absolute_path("runtime-root");
        let policy = SandboxPolicy::new(
            FilesystemPolicy::restricted([FilesystemRule::new(
                PathSelector::absolute(runtime_root.clone()).unwrap(),
                AccessMode::Read,
            )]),
            NetworkPolicy::disabled(),
        );
        let context = cageforge_policy::PathResolutionContext::new()
            .with_executable_root(runtime_root.clone())
            .unwrap();
        let environment = EnvironmentSpec::default();
        let ceiling = PolicyCeiling::new(policy.clone(), environment.clone());
        let effective = compose(CompositionRequest::new(&policy, &environment, &ceiling)).unwrap();
        let plan = PreflightPlan::from_policy_with_ceiling(
            &policy,
            &context,
            effective,
            &environment,
            &ceiling,
            PreflightIdentity::new(
                "tool",
                "1",
                "a".repeat(64),
                "b".repeat(64),
                PlatformId::Macos,
                "arm64",
            ),
        )
        .unwrap();
        let read = FilesystemCapability::new(
            FilesystemOperation::Read,
            runtime_root.to_string_lossy().into_owned(),
        )
        .unwrap();
        let map = FilesystemCapability::new(
            FilesystemOperation::MapExecutable,
            runtime_root.to_string_lossy().into_owned(),
        )
        .unwrap();
        assert!(plan.request().capabilities().filesystem().contains(&read));
        assert!(plan.request().capabilities().filesystem().contains(&map));
        assert_eq!(
            FilesystemOperation::MapExecutable.as_str(),
            "map-executable"
        );

        let grant = GrantAuthority::new()
            .approve_subset(plan.request(), PermissionSet::new().with_filesystem(read))
            .unwrap();
        assert!(matches!(
            plan.authorize(grant),
            Err(PreflightError::PartialGrantUnsupported)
        ));
    }

    #[test]
    fn a_partial_grant_narrows_the_effective_filesystem_policy() {
        let approved_path = test_absolute_path("approved");
        let denied_path = test_absolute_path("denied");
        let policy = SandboxPolicy::new(
            FilesystemPolicy::restricted([
                FilesystemRule::new(
                    PathSelector::absolute(approved_path.clone()).unwrap(),
                    AccessMode::Read,
                ),
                FilesystemRule::new(
                    PathSelector::absolute(denied_path.clone()).unwrap(),
                    AccessMode::Read,
                ),
            ]),
            NetworkPolicy::disabled(),
        );
        let context = cageforge_policy::PathResolutionContext::new();
        let environment = EnvironmentSpec::default();
        let ceiling = PolicyCeiling::new(policy.clone(), environment.clone());
        let effective = compose(CompositionRequest::new(&policy, &environment, &ceiling)).unwrap();
        let plan = PreflightPlan::from_policy_with_ceiling(
            &policy,
            &context,
            effective,
            &environment,
            &ceiling,
            PreflightIdentity::new(
                "tool",
                "1",
                "a".repeat(64),
                "b".repeat(64),
                PlatformId::Linux,
                "x86_64",
            ),
        )
        .unwrap();
        let approved = PermissionSet::new().with_filesystem(
            FilesystemCapability::new(
                FilesystemOperation::Read,
                approved_path.to_string_lossy().into_owned(),
            )
            .unwrap(),
        );
        let grant = GrantAuthority::new()
            .approve_subset(plan.request(), approved)
            .unwrap();
        let authorized = plan.authorize(grant).unwrap();
        let context = authorized.effective().path_context(&context).unwrap();
        assert_eq!(
            authorized
                .effective()
                .filesystem()
                .access_for_path(&approved_path, &context)
                .unwrap(),
            FilesystemDecision::Read
        );
        assert_eq!(
            authorized
                .effective()
                .filesystem()
                .access_for_path(&denied_path, &context)
                .unwrap(),
            FilesystemDecision::Deny
        );
    }

    #[test]
    fn escalation_composes_an_additional_filesystem_capability_for_relaunch() {
        let base_path = test_absolute_path("escalation-base");
        let additional_path = test_absolute_path("escalation-additional");
        let policy = SandboxPolicy::new(
            FilesystemPolicy::restricted([FilesystemRule::new(
                PathSelector::absolute(base_path.clone()).unwrap(),
                AccessMode::Read,
            )]),
            NetworkPolicy::disabled(),
        );
        let context = cageforge_policy::PathResolutionContext::new();
        let environment = EnvironmentSpec::default();
        let ceiling = PolicyCeiling::new(SandboxPolicy::full_access(), environment.clone());
        let effective = compose(CompositionRequest::new(&policy, &environment, &ceiling)).unwrap();
        let plan = PreflightPlan::from_policy_with_ceiling(
            &policy,
            &context,
            effective,
            &environment,
            &ceiling,
            PreflightIdentity::new(
                "tool",
                "1",
                "a".repeat(64),
                "b".repeat(64),
                PlatformId::Linux,
                "x86_64",
            ),
        )
        .unwrap();
        let additional = PermissionSet::new().with_filesystem(
            FilesystemCapability::new(
                FilesystemOperation::Read,
                additional_path.to_string_lossy().into_owned(),
            )
            .unwrap(),
        );
        let escalation = plan
            .request_escalation(additional.clone(), "read an approved input")
            .unwrap();
        let grant = GrantAuthority::new()
            .approve_escalation(
                escalation.request(),
                additional,
                cageforge_permissions::PermissionScope::Launch,
                None,
            )
            .unwrap();
        let authorized = escalation.authorize(grant).unwrap();
        let context = authorized.effective().path_context(&context).unwrap();
        assert_eq!(
            authorized
                .effective()
                .filesystem()
                .access_for_path(&additional_path, &context)
                .unwrap(),
            FilesystemDecision::Read
        );
        assert_eq!(
            authorized
                .effective()
                .filesystem()
                .access_for_path(&base_path, &context)
                .unwrap(),
            FilesystemDecision::Read
        );
    }
}
