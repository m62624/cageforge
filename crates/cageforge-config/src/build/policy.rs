// SPDX-License-Identifier: Apache-2.0

//! Converts TOML filesystem and network sections into
//! [`cageforge_policy::SandboxPolicy`] values.

use super::super::error::{ConfigError, invalid_value};
use super::super::model::{
    RawAccessMode, RawDomainAccess, RawDomainMode, RawDomainRule, RawFilesystem, RawFilesystemMode,
    RawFilesystemRule, RawFilesystemTarget, RawLocalNetworkAccess, RawMissingPathBehavior,
    RawNetwork, RawNetworkMode, RawSelector, RawUnixSocketMode, RawUnixSocketRule,
};
use cageforge_policy::{
    AccessMode, DomainAccess, DomainMode, FilesystemMode, FilesystemPolicy, FilesystemRule,
    FilesystemTarget, LocalNetworkAccess, MissingPathBehavior, NetworkMode, NetworkPolicy,
    PathPattern, PathSelector, SandboxPolicy, UnixSocketMode,
};
use std::num::NonZeroUsize;
use std::path::PathBuf;

pub(crate) fn build_policy(
    filesystem: Option<&RawFilesystem>,
    network: Option<&RawNetwork>,
    profile: &str,
) -> Result<SandboxPolicy, ConfigError> {
    let filesystem = build_filesystem(filesystem, profile)?;
    let network = build_network(network, profile)?;
    let policy = SandboxPolicy::new(filesystem, network);
    policy.validate().map_err(|source| ConfigError::Policy {
        profile: profile.to_owned(),
        source,
    })?;
    Ok(policy)
}

fn build_filesystem(
    raw: Option<&RawFilesystem>,
    profile: &str,
) -> Result<FilesystemPolicy, ConfigError> {
    let raw = raw.cloned().unwrap_or_default();
    let mode = filesystem_mode(raw.mode);
    let mut policy = match mode {
        FilesystemMode::Restricted => FilesystemPolicy::restricted([]),
        FilesystemMode::Unrestricted => FilesystemPolicy::unrestricted(),
        FilesystemMode::External => FilesystemPolicy::external(),
    };
    for raw_rule in &raw.rules {
        let rule = build_filesystem_rule(raw_rule, profile)?;
        policy = policy
            .with_rule(rule)
            .map_err(|source| ConfigError::Policy {
                profile: profile.to_owned(),
                source,
            })?;
    }
    for path in &raw.additional_protected_paths {
        policy = policy
            .with_additional_protected_relative_path(path)
            .map_err(|source| ConfigError::Policy {
                profile: profile.to_owned(),
                source,
            })?;
    }
    if raw
        .security
        .as_ref()
        .and_then(|security| security.dangerously_allow_git_write)
        .unwrap_or(false)
    {
        policy = policy.dangerously_allow_git_write();
    }
    if let Some(depth) = raw.glob_scan_max_depth {
        let depth = NonZeroUsize::new(depth).ok_or_else(|| {
            invalid_value(
                profile,
                "filesystem.glob_scan_max_depth",
                "must be greater than zero",
            )
        })?;
        policy = policy
            .with_glob_scan_max_depth(depth)
            .map_err(|source| ConfigError::Policy {
                profile: profile.to_owned(),
                source,
            })?;
    }
    policy.validate().map_err(|source| ConfigError::Policy {
        profile: profile.to_owned(),
        source,
    })?;
    Ok(policy)
}

fn build_filesystem_rule(
    raw: &RawFilesystemRule,
    profile: &str,
) -> Result<FilesystemRule, ConfigError> {
    let access = access_mode(raw.access);
    let target = match raw.target {
        RawFilesystemTarget::Absolute => {
            if raw.pattern.is_some() {
                return Err(invalid_value(
                    profile,
                    "filesystem.rules.pattern",
                    "not allowed for a scope target",
                ));
            }
            FilesystemTarget::Scope(build_selector(
                &RawSelector {
                    target: RawFilesystemTarget::Absolute,
                    path: raw.path.clone(),
                },
                profile,
                "filesystem.rules.path",
            )?)
        }
        RawFilesystemTarget::Workspace
        | RawFilesystemTarget::WorkspaceRoot
        | RawFilesystemTarget::Root
        | RawFilesystemTarget::Minimal
        | RawFilesystemTarget::Tmpdir
        | RawFilesystemTarget::SlashTmp => {
            if raw.pattern.is_some() {
                return Err(invalid_value(
                    profile,
                    "filesystem.rules.pattern",
                    "not allowed for a scope target",
                ));
            }
            FilesystemTarget::Scope(build_selector(
                &RawSelector {
                    target: raw.target,
                    path: raw.path.clone(),
                },
                profile,
                "filesystem.rules.path",
            )?)
        }
        RawFilesystemTarget::AbsoluteGlob => {
            if raw.path.is_some() {
                return Err(invalid_value(
                    profile,
                    "filesystem.rules.path",
                    "not allowed for a glob target",
                ));
            }
            FilesystemTarget::Glob(
                PathPattern::absolute(required_string(
                    raw.pattern.as_deref(),
                    profile,
                    "filesystem.rules.pattern",
                )?)
                .map_err(|source| ConfigError::Policy {
                    profile: profile.to_owned(),
                    source,
                })?,
            )
        }
        RawFilesystemTarget::WorkspaceGlob => {
            if raw.path.is_some() {
                return Err(invalid_value(
                    profile,
                    "filesystem.rules.path",
                    "not allowed for a glob target",
                ));
            }
            FilesystemTarget::Glob(
                PathPattern::workspace(required_string(
                    raw.pattern.as_deref(),
                    profile,
                    "filesystem.rules.pattern",
                )?)
                .map_err(|source| ConfigError::Policy {
                    profile: profile.to_owned(),
                    source,
                })?,
            )
        }
    };
    if matches!(&target, FilesystemTarget::Glob(_)) && raw.missing_path.is_some() {
        return Err(invalid_value(
            profile,
            "filesystem.rules.missing_path",
            "not allowed for a glob target",
        ));
    }
    let mut rule =
        FilesystemRule::from_target(target, access).map_err(|source| ConfigError::Policy {
            profile: profile.to_owned(),
            source,
        })?;
    if let Some(missing_path) = &raw.missing_path {
        let behavior = match missing_path {
            RawMissingPathBehavior::Error => MissingPathBehavior::Error,
            RawMissingPathBehavior::Skip => MissingPathBehavior::Skip,
        };
        rule = rule.with_missing_path_behavior(behavior);
    }
    for selector in &raw.read_only_subpaths {
        rule = rule
            .with_read_only_subpath(build_selector(
                selector,
                profile,
                "filesystem.rules.read_only_subpaths",
            )?)
            .map_err(|source| ConfigError::Policy {
                profile: profile.to_owned(),
                source,
            })?;
    }
    Ok(rule)
}

fn build_selector(
    raw: &RawSelector,
    profile: &str,
    field: &str,
) -> Result<PathSelector, ConfigError> {
    let path = || raw.path.clone().map(PathBuf::from);
    let require_path = || path().ok_or_else(|| invalid_value(profile, field, "path is required"));
    let reject_path = || {
        if raw.path.is_some() {
            Err(invalid_value(
                profile,
                field,
                "path is not allowed for this target",
            ))
        } else {
            Ok(())
        }
    };
    let result = match raw.target {
        RawFilesystemTarget::Absolute => PathSelector::absolute(require_path()?),
        RawFilesystemTarget::Workspace => PathSelector::workspace(require_path()?),
        RawFilesystemTarget::WorkspaceRoot => {
            reject_path()?;
            Ok(PathSelector::workspace_root())
        }
        RawFilesystemTarget::Root => {
            reject_path()?;
            Ok(PathSelector::root())
        }
        RawFilesystemTarget::Minimal => {
            reject_path()?;
            Ok(PathSelector::minimal())
        }
        RawFilesystemTarget::Tmpdir => {
            reject_path()?;
            Ok(PathSelector::tmpdir())
        }
        RawFilesystemTarget::SlashTmp => {
            reject_path()?;
            Ok(PathSelector::slash_tmp())
        }
        value => {
            return Err(invalid_value(
                profile,
                field,
                format!("unsupported selector {value:?}"),
            ));
        }
    };
    result.map_err(|source| ConfigError::Policy {
        profile: profile.to_owned(),
        source,
    })
}

fn build_network(raw: Option<&RawNetwork>, profile: &str) -> Result<NetworkPolicy, ConfigError> {
    let raw = raw.cloned().unwrap_or_default();
    let mode = network_mode(raw.mode);
    let mut policy = match mode {
        NetworkMode::Disabled => NetworkPolicy::disabled(),
        NetworkMode::Enabled => NetworkPolicy::enabled(),
        NetworkMode::External => NetworkPolicy::external(),
    };
    if let Some(mode) = raw.domain_mode {
        policy = policy.with_domain_mode(domain_mode(mode));
    }
    if let Some(mode) = raw.unix_socket_mode {
        policy = policy.with_unix_socket_mode(unix_socket_mode(mode));
    }
    if let Some(access) = raw.local_network_access {
        policy = policy.with_local_network_access(local_network_access(access));
    }
    for RawDomainRule { pattern, access } in &raw.domains {
        policy = policy
            .with_domain(pattern, domain_access(*access))
            .map_err(|source| ConfigError::Policy {
                profile: profile.to_owned(),
                source,
            })?;
    }
    for RawUnixSocketRule { path, access } in &raw.unix_sockets {
        policy = policy
            .with_unix_socket(path, domain_access(*access))
            .map_err(|source| ConfigError::Policy {
                profile: profile.to_owned(),
                source,
            })?;
    }
    policy.validate().map_err(|source| ConfigError::Policy {
        profile: profile.to_owned(),
        source,
    })?;
    Ok(policy)
}

fn filesystem_mode(value: Option<RawFilesystemMode>) -> FilesystemMode {
    match value.unwrap_or(RawFilesystemMode::Restricted) {
        RawFilesystemMode::Restricted => FilesystemMode::Restricted,
        RawFilesystemMode::Unrestricted => FilesystemMode::Unrestricted,
        RawFilesystemMode::External => FilesystemMode::External,
    }
}

fn network_mode(value: Option<RawNetworkMode>) -> NetworkMode {
    match value.unwrap_or(RawNetworkMode::Disabled) {
        RawNetworkMode::Disabled => NetworkMode::Disabled,
        RawNetworkMode::Enabled => NetworkMode::Enabled,
        RawNetworkMode::External => NetworkMode::External,
    }
}

fn domain_mode(value: RawDomainMode) -> DomainMode {
    match value {
        RawDomainMode::Disabled => DomainMode::Disabled,
        RawDomainMode::Enabled => DomainMode::Enabled,
        RawDomainMode::Restricted => DomainMode::Restricted,
    }
}

fn unix_socket_mode(value: RawUnixSocketMode) -> UnixSocketMode {
    match value {
        RawUnixSocketMode::Disabled => UnixSocketMode::Disabled,
        RawUnixSocketMode::Enabled => UnixSocketMode::Enabled,
        RawUnixSocketMode::Restricted => UnixSocketMode::Restricted,
    }
}

fn local_network_access(value: RawLocalNetworkAccess) -> LocalNetworkAccess {
    match value {
        RawLocalNetworkAccess::Allow => LocalNetworkAccess::Allow,
        RawLocalNetworkAccess::Deny => LocalNetworkAccess::Deny,
    }
}

fn access_mode(value: RawAccessMode) -> AccessMode {
    match value {
        RawAccessMode::Read => AccessMode::Read,
        RawAccessMode::Write => AccessMode::Write,
        RawAccessMode::Deny => AccessMode::Deny,
    }
}

fn domain_access(value: RawDomainAccess) -> DomainAccess {
    match value {
        RawDomainAccess::Allow => DomainAccess::Allow,
        RawDomainAccess::Deny => DomainAccess::Deny,
    }
}

fn required_string<'a>(
    value: Option<&'a str>,
    profile: &str,
    field: &str,
) -> Result<&'a str, ConfigError> {
    value.ok_or_else(|| invalid_value(profile, field, "value is required"))
}
