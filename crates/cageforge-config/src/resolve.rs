// Copyright 2026 Mansur Azatbek
// SPDX-License-Identifier: Apache-2.0

use crate::build;
use crate::error::{ConfigError, invalid_value};

use crate::model::{
    RawCommand, RawConfig, RawEnvironment, RawFilesystem, RawNetwork, RawProfile, RawStdio,
    RawTimeout,
};
use cageforge_command::CommandRequest;
use cageforge_policy::SandboxPolicy;
use std::collections::BTreeSet;
use std::path::Path;

/// A parsed Cageforge TOML document.
#[derive(Debug, Clone)]
pub struct Config {
    raw: RawConfig,
}

/// A fully resolved profile ready for a backend or harness adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedProfile {
    policy: SandboxPolicy,
    command: Option<CommandRequest>,
}

impl Config {
    /// Parses a strict Cageforge TOML document.
    pub fn from_toml(source: &str) -> Result<Self, ConfigError> {
        let raw = toml::from_str(source).map_err(|error| ConfigError::InvalidToml {
            message: error.to_string(),
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
        let mut stack = Vec::new();
        let merged = self.resolve_raw(name, &mut stack)?;
        let policy =
            build::build_policy(merged.filesystem.as_ref(), merged.network.as_ref(), name)?;
        let command = build::build_command(merged.command.as_ref(), name)?;
        Ok(ResolvedProfile { policy, command })
    }

    /// Resolves the configured default profile.
    pub fn resolve_default(&self) -> Result<ResolvedProfile, ConfigError> {
        let name = self
            .default_profile_name()
            .ok_or(ConfigError::NoDefaultProfile)?;
        self.resolve(name)
    }

    fn resolve_raw(
        &self,
        name: &str,
        stack: &mut Vec<String>,
    ) -> Result<MergedProfile, ConfigError> {
        if let Some(start) = stack.iter().position(|profile| profile == name) {
            let mut chain = stack[start..].to_vec();
            chain.push(name.to_owned());
            return Err(ConfigError::ProfileCycle { chain });
        }
        let profile = self
            .raw
            .profiles
            .get(name)
            .ok_or_else(|| ConfigError::UnknownProfile {
                name: name.to_owned(),
            })?;
        stack.push(name.to_owned());
        let mut merged = MergedProfile::default();
        for parent in &profile.inherits {
            let parent = self.resolve_raw(parent, stack)?;
            merged = merge_profiles(merged, parent);
        }
        merged = apply_profile(merged, profile);
        stack.pop();
        Ok(merged)
    }
}

impl ResolvedProfile {
    /// Returns the resolved sandbox policy.
    pub fn policy(&self) -> &SandboxPolicy {
        &self.policy
    }

    /// Returns the optional resolved command request.
    pub fn command(&self) -> Option<&CommandRequest> {
        self.command.as_ref()
    }
}

#[derive(Debug, Clone, Default)]
struct MergedProfile {
    filesystem: Option<RawFilesystem>,
    network: Option<RawNetwork>,
    command: Option<RawCommand>,
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
    for (name, profile) in &config.profiles {
        validate_profile_name(name)?;
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
        if let Some(command) = &profile.command {
            if let Some(environment) = &command.environment {
                for variable in &environment.remove {
                    if environment.set.contains_key(variable) {
                        return Err(invalid_value(
                            name,
                            "command.environment",
                            format!("variable {variable:?} appears in both set and remove"),
                        ));
                    }
                }
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

fn apply_profile(mut merged: MergedProfile, profile: &RawProfile) -> MergedProfile {
    if let Some(filesystem) = &profile.filesystem {
        merged.filesystem = Some(merge_filesystem(merged.filesystem.take(), filesystem));
    }
    if let Some(network) = &profile.network {
        merged.network = Some(merge_network(merged.network.take(), network));
    }
    if let Some(command) = &profile.command {
        merged.command = Some(merge_command(merged.command.take(), command));
    }
    merged
}

fn merge_profiles(mut left: MergedProfile, right: MergedProfile) -> MergedProfile {
    if let Some(filesystem) = right.filesystem {
        left.filesystem = Some(merge_filesystem(left.filesystem.take(), &filesystem));
    }
    if let Some(network) = right.network {
        left.network = Some(merge_network(left.network.take(), &network));
    }
    if let Some(command) = right.command {
        left.command = Some(merge_command(left.command.take(), &command));
    }
    left
}

fn merge_filesystem(parent: Option<RawFilesystem>, child: &RawFilesystem) -> RawFilesystem {
    let mut merged = parent.unwrap_or_default();
    if child.mode.is_some() {
        merged.mode = child.mode.clone();
    }
    if child.glob_scan_max_depth.is_some() {
        merged.glob_scan_max_depth = child.glob_scan_max_depth;
    }
    merged.rules.extend(child.rules.clone());
    merged
}

fn merge_network(parent: Option<RawNetwork>, child: &RawNetwork) -> RawNetwork {
    let mut merged = parent.unwrap_or_default();
    if child.mode.is_some() {
        merged.mode = child.mode.clone();
    }
    if child.domain_mode.is_some() {
        merged.domain_mode = child.domain_mode.clone();
    }
    if child.unix_socket_mode.is_some() {
        merged.unix_socket_mode = child.unix_socket_mode.clone();
    }
    merged.domains.extend(child.domains.clone());
    merged.unix_sockets.extend(child.unix_sockets.clone());
    merged
}

fn merge_command(parent: Option<RawCommand>, child: &RawCommand) -> RawCommand {
    let mut merged = parent.unwrap_or_default();
    if child.program.is_some() {
        merged.program = child.program.clone();
    }
    if child.args.is_some() {
        merged.args = child.args.clone();
    }
    if child.working_directory.is_some() {
        merged.working_directory = child.working_directory.clone();
    }
    if let Some(environment) = &child.environment {
        merged.environment = Some(merge_environment(merged.environment.take(), environment));
    }
    if let Some(stdio) = &child.stdio {
        merged.stdio = Some(merge_stdio(merged.stdio.take(), stdio));
    }
    if let Some(timeout) = &child.timeout {
        merged.timeout = Some(merge_timeout(merged.timeout.take(), timeout));
    }
    merged
}

fn merge_environment(parent: Option<RawEnvironment>, child: &RawEnvironment) -> RawEnvironment {
    let mut merged = parent.unwrap_or_default();
    if child.base.is_some() {
        merged.base = child.base.clone();
    }
    for (name, value) in &child.set {
        merged.remove.retain(|removed| removed != name);
        merged.set.insert(name.clone(), value.clone());
    }
    for name in &child.remove {
        merged.set.remove(name);
        if !merged.remove.contains(name) {
            merged.remove.push(name.clone());
        }
    }
    merged
}

fn merge_stdio(parent: Option<RawStdio>, child: &RawStdio) -> RawStdio {
    let mut merged = parent.unwrap_or_default();
    if child.stdin.is_some() {
        merged.stdin = child.stdin.clone();
    }
    if child.stdout.is_some() {
        merged.stdout = child.stdout.clone();
    }
    if child.stderr.is_some() {
        merged.stderr = child.stderr.clone();
    }
    merged
}

fn merge_timeout(parent: Option<RawTimeout>, child: &RawTimeout) -> RawTimeout {
    let mut merged = parent.unwrap_or_default();
    if child.mode.is_some() {
        merged.mode = child.mode.clone();
        if child.milliseconds.is_none()
            && matches!(child.mode.as_deref(), Some("backend-default" | "disabled"))
        {
            merged.milliseconds = None;
        }
    }
    if child.milliseconds.is_some() {
        merged.milliseconds = child.milliseconds;
    }
    merged
}
