// Copyright 2026 Mansur Azatbek
// SPDX-License-Identifier: Apache-2.0

use super::super::error::{ConfigError, invalid_value};
use super::super::model::{
    RawDomainRule, RawFilesystem, RawFilesystemRule, RawNetwork, RawSelector, RawUnixSocketRule,
};
use cageforge_policy::{
    AccessMode, DomainAccess, DomainMode, FilesystemMode, FilesystemPolicy, FilesystemRule,
    FilesystemTarget, MissingPathBehavior, NetworkMode, NetworkPolicy, PathPattern, PathSelector,
    SandboxPolicy, UnixSocketMode,
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
    let mode = parse_filesystem_mode(raw.mode.as_deref(), profile)?;
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
    let access = parse_access(&raw.access, profile, "filesystem.rules.access")?;
    let target = match raw.target.as_str() {
        "absolute" => {
            if raw.pattern.is_some() {
                return Err(invalid_value(
                    profile,
                    "filesystem.rules.pattern",
                    "not allowed for a scope target",
                ));
            }
            FilesystemTarget::Scope(build_selector(
                &RawSelector {
                    target: "absolute".to_owned(),
                    path: raw.path.clone(),
                },
                profile,
                "filesystem.rules.path",
            )?)
        }
        "workspace" | "workspace-root" | "minimal" | "tmpdir" | "slash-tmp" => {
            if raw.pattern.is_some() {
                return Err(invalid_value(
                    profile,
                    "filesystem.rules.pattern",
                    "not allowed for a scope target",
                ));
            }
            FilesystemTarget::Scope(build_selector(
                &RawSelector {
                    target: raw.target.clone(),
                    path: raw.path.clone(),
                },
                profile,
                "filesystem.rules.path",
            )?)
        }
        "absolute-glob" => {
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
        "workspace-glob" => {
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
        value => {
            return Err(invalid_value(
                profile,
                "filesystem.rules.target",
                format!("unsupported target {value:?}"),
            ));
        }
    };
    if matches!(&target, FilesystemTarget::Glob(_)) && raw.missing_path.is_some() {
        return Err(invalid_value(
            profile,
            "filesystem.rules.missing_path",
            "not allowed for a glob target",
        ));
    }
    let mut rule = FilesystemRule::from_target(target, access);
    if let Some(missing_path) = &raw.missing_path {
        let behavior = match missing_path.as_str() {
            "error" => MissingPathBehavior::Error,
            "skip" => MissingPathBehavior::Skip,
            value => {
                return Err(invalid_value(
                    profile,
                    "filesystem.rules.missing_path",
                    format!("unsupported behavior {value:?}"),
                ));
            }
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
    let result = match raw.target.as_str() {
        "absolute" => PathSelector::absolute(require_path()?),
        "workspace" => PathSelector::workspace(require_path()?),
        "workspace-root" => {
            reject_path()?;
            Ok(PathSelector::workspace_root())
        }
        "minimal" => {
            reject_path()?;
            Ok(PathSelector::minimal())
        }
        "tmpdir" => {
            reject_path()?;
            Ok(PathSelector::tmpdir())
        }
        "slash-tmp" => {
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
    let mode = parse_network_mode(raw.mode.as_deref(), profile)?;
    let mut policy = match mode {
        NetworkMode::Disabled => NetworkPolicy::disabled(),
        NetworkMode::Enabled => NetworkPolicy::enabled(),
        NetworkMode::External => NetworkPolicy::external(),
    };
    if let Some(mode) = raw.domain_mode.as_deref() {
        policy = policy.with_domain_mode(parse_domain_mode(mode, profile)?);
    }
    if let Some(mode) = raw.unix_socket_mode.as_deref() {
        policy = policy.with_unix_socket_mode(parse_unix_socket_mode(mode, profile)?);
    }
    for RawDomainRule { pattern, access } in &raw.domains {
        policy = policy
            .with_domain(
                pattern,
                parse_domain_access(access, profile, "network.domains.access")?,
            )
            .map_err(|source| ConfigError::Policy {
                profile: profile.to_owned(),
                source,
            })?;
    }
    for RawUnixSocketRule { path, access } in &raw.unix_sockets {
        policy = policy
            .with_unix_socket(
                path,
                parse_domain_access(access, profile, "network.unix_sockets.access")?,
            )
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

fn parse_filesystem_mode(
    value: Option<&str>,
    profile: &str,
) -> Result<FilesystemMode, ConfigError> {
    match value.unwrap_or("restricted") {
        "restricted" => Ok(FilesystemMode::Restricted),
        "unrestricted" => Ok(FilesystemMode::Unrestricted),
        "external" => Ok(FilesystemMode::External),
        value => Err(invalid_value(
            profile,
            "filesystem.mode",
            format!("unsupported mode {value:?}"),
        )),
    }
}

fn parse_network_mode(value: Option<&str>, profile: &str) -> Result<NetworkMode, ConfigError> {
    match value.unwrap_or("disabled") {
        "disabled" => Ok(NetworkMode::Disabled),
        "enabled" => Ok(NetworkMode::Enabled),
        "external" => Ok(NetworkMode::External),
        value => Err(invalid_value(
            profile,
            "network.mode",
            format!("unsupported mode {value:?}"),
        )),
    }
}

fn parse_domain_mode(value: &str, profile: &str) -> Result<DomainMode, ConfigError> {
    match value {
        "disabled" => Ok(DomainMode::Disabled),
        "enabled" => Ok(DomainMode::Enabled),
        "restricted" => Ok(DomainMode::Restricted),
        value => Err(invalid_value(
            profile,
            "network.domain_mode",
            format!("unsupported mode {value:?}"),
        )),
    }
}

fn parse_unix_socket_mode(value: &str, profile: &str) -> Result<UnixSocketMode, ConfigError> {
    match value {
        "disabled" => Ok(UnixSocketMode::Disabled),
        "enabled" => Ok(UnixSocketMode::Enabled),
        "restricted" => Ok(UnixSocketMode::Restricted),
        value => Err(invalid_value(
            profile,
            "network.unix_socket_mode",
            format!("unsupported mode {value:?}"),
        )),
    }
}

fn parse_access(value: &str, profile: &str, field: &str) -> Result<AccessMode, ConfigError> {
    match value {
        "read" => Ok(AccessMode::Read),
        "write" => Ok(AccessMode::Write),
        "deny" => Ok(AccessMode::Deny),
        value => Err(invalid_value(
            profile,
            field,
            format!("unsupported access {value:?}"),
        )),
    }
}

fn parse_domain_access(
    value: &str,
    profile: &str,
    field: &str,
) -> Result<DomainAccess, ConfigError> {
    match value {
        "allow" => Ok(DomainAccess::Allow),
        "deny" => Ok(DomainAccess::Deny),
        value => Err(invalid_value(
            profile,
            field,
            format!("unsupported access {value:?}"),
        )),
    }
}

fn required_string<'a>(
    value: Option<&'a str>,
    profile: &str,
    field: &str,
) -> Result<&'a str, ConfigError> {
    value.ok_or_else(|| invalid_value(profile, field, "value is required"))
}
