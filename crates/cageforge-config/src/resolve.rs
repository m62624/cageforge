// SPDX-License-Identifier: Apache-2.0

//! Public configuration loading and profile resolution.
//!
//! [`crate::Config`] owns the parsed document and [`crate::ResolvedProfile`]
//! is the validated handoff to policy, command, composition, and backend
//! layers. Runtime path discovery remains outside this module.

use crate::build;
use crate::error::{ConfigError, invalid_value};

use crate::merge::{
    MergedProfile, ProfileMerger, domain_rule_key, environment_filter_key, filesystem_rule_key,
};
use crate::model::{RawApproval, RawConfig, RawRuntime};
use cageforge_command::{CommandRequest, EnvironmentNameKey};
use cageforge_network_proxy::GatewayConfig;
use cageforge_path::{
    PathDialect, PlatformPathKey, contains_parent_traversal_text, is_absolute_text,
};
use cageforge_permissions::{ApprovalConfig, PermissionMode, PlatformId};
use cageforge_policy::SandboxPolicy;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// A parsed Cageforge TOML document.
#[derive(Debug, Clone)]
pub struct Config {
    raw: RawConfig,
}

/// A fully resolved profile ready for a backend or harness adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedProfile {
    description: Option<String>,
    workspace_roots: Vec<PathBuf>,
    executable_roots: Vec<PathBuf>,
    policy: SandboxPolicy,
    command: Option<CommandRequest>,
    network_gateway: GatewayConfig,
    approval: ApprovalConfig,
}

struct ResolveFrame {
    name: String,
    next_parent: usize,
}

impl Config {
    /// Parses a strict Cageforge TOML document.
    pub fn from_toml(source: &str) -> Result<Self, ConfigError> {
        let raw = toml::from_str(source).map_err(|error| ConfigError::InvalidToml {
            message: error.to_string(),
            location: error.span().map(|span| source_location(source, span)),
        })?;
        validate_raw_config(&raw)?;
        Ok(Self { raw })
    }

    /// Reads and parses a Cageforge TOML document from a file.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref().to_path_buf();
        let source = std::fs::read_to_string(&path).map_err(|error| ConfigError::ReadFile {
            path: path.clone(),
            message: error.to_string(),
        })?;
        Self::from_toml(&source)
    }

    /// Returns profile names in deterministic lexical order.
    pub fn profile_names(&self) -> impl Iterator<Item = &str> {
        self.raw.profiles.keys().map(String::as_str)
    }

    /// Returns the configured default profile name, if one exists.
    pub fn default_profile_name(&self) -> Option<&str> {
        self.raw.default_profile.as_deref()
    }

    /// Resolves one named profile through its inheritance graph.
    pub fn resolve(&self, name: &str) -> Result<ResolvedProfile, ConfigError> {
        self.resolve_with_platform(name, None)
    }

    /// Resolves one named profile and applies its overlay for `platform`.
    pub fn resolve_for_platform(
        &self,
        name: &str,
        platform: PlatformId,
    ) -> Result<ResolvedProfile, ConfigError> {
        self.resolve_with_platform(name, Some(platform))
    }

    fn resolve_with_platform(
        &self,
        name: &str,
        platform: Option<PlatformId>,
    ) -> Result<ResolvedProfile, ConfigError> {
        let merged = self.resolve_raw(name, platform)?;
        let policy = build::build_policy(
            merged.filesystem.as_ref(),
            merged.network.as_ref(),
            merged.local_ipc.as_ref(),
            name,
        )?;
        let command = build::build_command(merged.command.as_ref(), name)?;
        let network_gateway = build::build_gateway_config(
            merged
                .network
                .as_ref()
                .and_then(|network| network.gateway.as_ref()),
            name,
        )?;
        let workspace_roots = merged
            .workspace_roots
            .into_iter()
            .filter_map(|(path, enabled)| enabled.then_some(PathBuf::from(path)))
            .collect();
        let executable_roots = merged
            .runtime
            .as_ref()
            .map(|runtime| runtime.executable_roots.iter().map(PathBuf::from).collect())
            .unwrap_or_default();
        let approval = build_approval(merged.approval.as_ref(), name)?;
        Ok(ResolvedProfile {
            description: merged.description,
            workspace_roots,
            executable_roots,
            policy,
            command,
            network_gateway,
            approval,
        })
    }

    /// Resolves the configured default profile.
    pub fn resolve_default(&self) -> Result<ResolvedProfile, ConfigError> {
        let name = self
            .default_profile_name()
            .ok_or(ConfigError::NoDefaultProfile)?;
        self.resolve(name)
    }

    /// Resolves the configured default profile with its platform overlay.
    pub fn resolve_default_for_platform(
        &self,
        platform: PlatformId,
    ) -> Result<ResolvedProfile, ConfigError> {
        let name = self
            .default_profile_name()
            .ok_or(ConfigError::NoDefaultProfile)?;
        self.resolve_for_platform(name, platform)
    }

    fn resolve_raw(
        &self,
        name: &str,
        platform: Option<PlatformId>,
    ) -> Result<MergedProfile, ConfigError> {
        if !self.raw.profiles.contains_key(name) {
            return Err(ConfigError::UnknownProfile {
                name: name.to_owned(),
            });
        }

        let mut frames = vec![ResolveFrame::new(name.to_owned())];
        let mut active = HashMap::new();
        let mut active_names = Vec::new();
        let mut completed = HashSet::new();
        let mut order = Vec::new();
        active.insert(name.to_owned(), 0);
        active_names.push(name.to_owned());

        loop {
            let frame_index = frames.len() - 1;
            let frame_name = frames[frame_index].name.clone();
            let profile =
                self.raw
                    .profiles
                    .get(&frame_name)
                    .ok_or_else(|| ConfigError::UnknownProfile {
                        name: frame_name.clone(),
                    })?;

            if let Some(parent_name) = profile
                .inherits
                .get(frames[frame_index].next_parent)
                .cloned()
            {
                frames[frame_index].next_parent += 1;
                if completed.contains(&parent_name) {
                    continue;
                }
                if let Some(start) = active.get(&parent_name) {
                    let mut chain = active_names[*start..].to_vec();
                    chain.push(parent_name);
                    return Err(ConfigError::ProfileCycle { chain });
                }
                if !self.raw.profiles.contains_key(&parent_name) {
                    return Err(ConfigError::UnknownProfile { name: parent_name });
                }
                active.insert(parent_name.clone(), active_names.len());
                active_names.push(parent_name.clone());
                frames.push(ResolveFrame::new(parent_name));
                continue;
            }

            let Some(frame) = frames.pop() else {
                return Err(ConfigError::ResolutionInvariant {
                    message: "resolution stack was empty while completing a profile",
                });
            };
            active.remove(&frame.name);
            active_names.pop();
            completed.insert(frame.name.clone());
            order.push(frame.name);
            if frames.is_empty() {
                break;
            }
        }

        let mut merger = ProfileMerger::new(path_dialect(platform));
        for profile_name in order {
            let Some(profile) = self.raw.profiles.get(&profile_name) else {
                return Err(ConfigError::UnknownProfile { name: profile_name });
            };
            merger.apply(profile, platform);
        }
        Ok(merger.finish())
    }
}

impl ResolvedProfile {
    /// Returns the selected profile's description, if configured.
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// Returns enabled workspace roots declared by the selected profile.
    ///
    /// The paths are declarations only. A backend or harness resolves relative
    /// paths against its execution context and registers the resulting
    /// absolute paths in [`cageforge_policy::PathResolutionContext`].
    pub fn workspace_roots(&self) -> &[PathBuf] {
        &self.workspace_roots
    }

    /// Returns absolute runtime roots whose executable files may be mapped by
    /// a supporting native backend.
    pub fn executable_roots(&self) -> &[PathBuf] {
        &self.executable_roots
    }

    /// Returns the resolved sandbox policy.
    pub fn policy(&self) -> &SandboxPolicy {
        &self.policy
    }

    /// Returns the optional resolved command request.
    pub fn command(&self) -> Option<&CommandRequest> {
        self.command.as_ref()
    }

    /// Returns the validated outbound gateway runtime configuration.
    pub fn network_gateway(&self) -> &GatewayConfig {
        &self.network_gateway
    }

    /// Returns the resolved host-approval settings.
    pub fn approval(&self) -> ApprovalConfig {
        self.approval
    }
}

impl ResolveFrame {
    fn new(name: String) -> Self {
        Self {
            name,
            next_parent: 0,
        }
    }
}

fn validate_raw_config(config: &RawConfig) -> Result<(), ConfigError> {
    if let Some(default_profile) = &config.default_profile {
        validate_profile_name(default_profile)?;
        if !config.profiles.contains_key(default_profile) {
            return Err(ConfigError::UnknownProfile {
                name: default_profile.clone(),
            });
        }
    }
    let native_dialect = PathDialect::native();
    for (name, profile) in &config.profiles {
        validate_profile_name(name)?;
        validate_policy_duplicates(
            name,
            profile.filesystem.as_ref(),
            profile.network.as_ref(),
            native_dialect,
        )?;
        validate_approval(name, profile.approval.as_ref())?;
        validate_runtime(name, profile.runtime.as_ref(), None)?;
        validate_workspace_roots(name, &profile.workspace_roots, native_dialect)?;
        for (platform, overlay) in &profile.platforms {
            let dialect = path_dialect(Some(*platform));
            validate_policy_duplicates(
                name,
                overlay.filesystem.as_ref(),
                overlay.network.as_ref(),
                dialect,
            )?;
            validate_approval(name, overlay.approval.as_ref())?;
            validate_runtime(name, overlay.runtime.as_ref(), Some(*platform))?;
            validate_workspace_roots(name, &overlay.workspace_roots, dialect)?;
        }
        let mut inherited = BTreeSet::new();
        for parent in &profile.inherits {
            validate_profile_name(parent)?;
            if !inherited.insert(parent) {
                return Err(invalid_value(
                    name,
                    "inherits",
                    format!("duplicate parent {parent:?}"),
                ));
            }
        }
        if let Some(command) = &profile.command
            && let Some(environment) = &command.environment
        {
            let mut filter_patterns = HashSet::new();
            for pattern in environment.filters.keys() {
                if !filter_patterns.insert(environment_filter_key(pattern)) {
                    return Err(invalid_value(
                        name,
                        "command.environment.filters",
                        format!("duplicate pattern ignoring case {pattern:?}"),
                    ));
                }
            }
            let mut set_names = HashSet::new();
            for variable in environment.set.keys() {
                if !set_names.insert(EnvironmentNameKey::new(OsStr::new(variable))) {
                    return Err(invalid_value(
                        name,
                        "command.environment",
                        format!("duplicate set variable ignoring case {variable:?}"),
                    ));
                }
            }
            let mut remove_names = HashSet::new();
            for variable in &environment.remove {
                let key = EnvironmentNameKey::new(OsStr::new(variable));
                if !remove_names.insert(key.clone()) {
                    return Err(invalid_value(
                        name,
                        "command.environment.remove",
                        format!("duplicate removed variable ignoring case {variable:?}"),
                    ));
                }
                if set_names.contains(&key) {
                    return Err(invalid_value(
                        name,
                        "command.environment",
                        format!("variable {variable:?} appears in both set and remove"),
                    ));
                }
            }
        }
    }
    Ok(())
}

fn validate_approval(profile: &str, approval: Option<&RawApproval>) -> Result<(), ConfigError> {
    if approval
        .and_then(|value| value.timeout_ms)
        .is_some_and(|timeout| timeout == 0)
    {
        return Err(invalid_value(
            profile,
            "approval.timeout_ms",
            "timeout must be greater than zero",
        ));
    }
    Ok(())
}

fn build_approval(
    approval: Option<&RawApproval>,
    profile: &str,
) -> Result<ApprovalConfig, ConfigError> {
    let Some(approval) = approval else {
        return Ok(ApprovalConfig::default());
    };
    ApprovalConfig::new(
        approval.mode.unwrap_or(PermissionMode::Disabled),
        approval
            .timeout_ms
            .unwrap_or(ApprovalConfig::default().timeout_ms()),
        approval
            .on_timeout
            .unwrap_or(ApprovalConfig::default().on_timeout()),
        approval
            .persistence
            .unwrap_or(ApprovalConfig::default().persistence()),
    )
    .map_err(|error| invalid_value(profile, "approval", error.to_string()))
}

fn validate_policy_duplicates(
    name: &str,
    filesystem: Option<&crate::model::RawFilesystem>,
    network: Option<&crate::model::RawNetwork>,
    dialect: PathDialect,
) -> Result<(), ConfigError> {
    if let Some(filesystem) = filesystem {
        let mut rules = HashSet::with_capacity(filesystem.rules.len());
        for rule in &filesystem.rules {
            if !rules.insert(filesystem_rule_key(rule, dialect)) {
                return Err(invalid_value(
                    name,
                    "filesystem.rules",
                    "duplicate target under native path semantics",
                ));
            }
        }
        let mut protected_paths =
            HashSet::with_capacity(filesystem.additional_protected_paths.len());
        for path in &filesystem.additional_protected_paths {
            if !protected_paths.insert(PlatformPathKey::new(path, dialect)) {
                return Err(invalid_value(
                    name,
                    "filesystem.additional_protected_paths",
                    "duplicate path under native semantics",
                ));
            }
        }
    }
    if let Some(network) = network {
        let mut domains = HashSet::with_capacity(network.domains.len());
        for rule in &network.domains {
            if !domains.insert(domain_rule_key(&rule.pattern)) {
                return Err(invalid_value(
                    name,
                    "network.domains",
                    "duplicate normalized domain pattern",
                ));
            }
        }
        let mut sockets = HashSet::with_capacity(network.unix_sockets.len());
        for rule in &network.unix_sockets {
            if !sockets.insert(PlatformPathKey::new(&rule.path, dialect)) {
                return Err(invalid_value(
                    name,
                    "network.unix_sockets",
                    "duplicate path under native semantics",
                ));
            }
        }
    }
    Ok(())
}

fn validate_profile_name(name: &str) -> Result<(), ConfigError> {
    let valid = !name.is_empty()
        && name
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
    if valid {
        Ok(())
    } else {
        Err(ConfigError::InvalidProfileName {
            name: name.to_owned(),
        })
    }
}

fn validate_workspace_roots(
    profile: &str,
    values: &std::collections::BTreeMap<String, bool>,
    dialect: PathDialect,
) -> Result<(), ConfigError> {
    let mut roots = HashSet::with_capacity(values.len());
    for root in values.keys() {
        validate_workspace_root(profile, root, dialect)?;
        if !roots.insert(PlatformPathKey::new(root, dialect)) {
            return Err(invalid_value(
                profile,
                "workspace_roots",
                format!("duplicate path under target path semantics {root:?}"),
            ));
        }
    }
    Ok(())
}

fn validate_workspace_root(
    profile: &str,
    root: &str,
    dialect: PathDialect,
) -> Result<(), ConfigError> {
    if root.is_empty() {
        return Err(invalid_value(
            profile,
            "workspace_roots",
            "path must not be empty",
        ));
    }
    if root.contains('\0') {
        return Err(invalid_value(
            profile,
            "workspace_roots",
            "path must not contain a NUL character",
        ));
    }
    if contains_parent_traversal_text(root, dialect) {
        return Err(invalid_value(
            profile,
            "workspace_roots",
            "path must not contain parent traversal",
        ));
    }
    Ok(())
}

fn validate_runtime(
    profile: &str,
    runtime: Option<&RawRuntime>,
    platform: Option<PlatformId>,
) -> Result<(), ConfigError> {
    let Some(runtime) = runtime else {
        return Ok(());
    };
    let mut roots = HashSet::with_capacity(runtime.executable_roots.len());
    for root in &runtime.executable_roots {
        if root.is_empty() {
            return Err(invalid_value(
                profile,
                "runtime.executable_roots",
                "path must not be empty",
            ));
        }
        if root.contains('\0') {
            return Err(invalid_value(
                profile,
                "runtime.executable_roots",
                "path must not contain a NUL character",
            ));
        }
        let dialect = path_dialect(platform);
        if !is_absolute_text(root, dialect) {
            return Err(invalid_value(
                profile,
                "runtime.executable_roots",
                format!("path must be absolute: {root:?}"),
            ));
        }
        if contains_parent_traversal_text(root, dialect) {
            return Err(invalid_value(
                profile,
                "runtime.executable_roots",
                format!("path must not contain parent traversal: {root:?}"),
            ));
        }
        if !roots.insert(PlatformPathKey::new(root, dialect)) {
            return Err(invalid_value(
                profile,
                "runtime.executable_roots",
                format!("duplicate path under native semantics: {root:?}"),
            ));
        }
    }
    Ok(())
}

fn path_dialect(platform: Option<PlatformId>) -> PathDialect {
    match platform {
        Some(PlatformId::Windows) => PathDialect::Windows,
        Some(PlatformId::Linux | PlatformId::Macos) => PathDialect::Posix,
        None => PathDialect::native(),
    }
}

fn source_location(source: &str, span: std::ops::Range<usize>) -> crate::SourceLocation {
    let offset = span.start.min(source.len());
    let line_start = source[..offset].rfind('\n').map_or(0, |index| index + 1);
    crate::SourceLocation {
        line: source[..offset]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count()
            + 1,
        column: source[line_start..offset].chars().count() + 1,
        offset,
        length: span.end.saturating_sub(span.start),
    }
}
