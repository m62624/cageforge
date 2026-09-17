// SPDX-License-Identifier: Apache-2.0

//! Preflight preparation shared by the facade and language adapters.

use cageforge_command::EnvironmentSpec;
use cageforge_permissions::{
    FilesystemCapability, FilesystemOperation, NetworkCapability, PermissionError, PermissionGrant,
    PermissionRequest, PermissionSet, PlatformId, ProcessCapability,
};
use cageforge_policy::{
    AccessMode, DomainAccess, DomainMode, FilesystemMode, FilesystemPolicy, FilesystemRule,
    FilesystemTarget, LocalNetworkAccess, NetworkMode, NetworkPolicy, SandboxPolicy,
    UnixSocketMode,
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
        Ok(AuthorizedPlan { effective, grant })
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
            if original.glob_scan_max_depth().is_some() {
                narrowed = narrowed
                    .with_glob_scan_max_depth(original.glob_scan_max_depth().expect("checked"))
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

    #[test]
    fn authorization_requires_the_exact_request() {
        let policy = SandboxPolicy::new(
            FilesystemPolicy::restricted([FilesystemRule::new(
                PathSelector::absolute("/tmp/tool").unwrap(),
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
    fn a_partial_grant_narrows_the_effective_filesystem_policy() {
        let policy = SandboxPolicy::new(
            FilesystemPolicy::restricted([
                FilesystemRule::new(
                    PathSelector::absolute("/tmp/approved").unwrap(),
                    AccessMode::Read,
                ),
                FilesystemRule::new(
                    PathSelector::absolute("/tmp/denied").unwrap(),
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
            FilesystemCapability::new(FilesystemOperation::Read, "/tmp/approved").unwrap(),
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
                .access_for_path(Path::new("/tmp/approved"), &context)
                .unwrap(),
            FilesystemDecision::Read
        );
        assert_eq!(
            authorized
                .effective()
                .filesystem()
                .access_for_path(Path::new("/tmp/denied"), &context)
                .unwrap(),
            FilesystemDecision::Deny
        );
    }
}
