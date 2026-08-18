// Copyright 2026 Mansur Azatbek
// SPDX-License-Identifier: Apache-2.0

use crate::build;
use crate::error::{ConfigError, invalid_value};

use crate::model::{
    RawCommand, RawConfig, RawEnvironment, RawFilesystem, RawFilesystemRule, RawNetwork,
    RawProfile, RawStdio, RawTimeout,
};
use cageforge_command::CommandRequest;
use cageforge_path::{contains_parent_traversal, paths_equal, strings_equal};
use cageforge_policy::{DomainAccess, DomainRule, SandboxPolicy};
use std::collections::{BTreeMap, BTreeSet, HashMap};
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
    policy: SandboxPolicy,
    command: Option<CommandRequest>,
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
        let mut cache = HashMap::new();
        let merged = self.resolve_raw(name, &mut cache)?;
        let policy =
            build::build_policy(merged.filesystem.as_ref(), merged.network.as_ref(), name)?;
        let command = build::build_command(merged.command.as_ref(), name)?;
        let workspace_roots = merged
            .workspace_roots
            .into_iter()
            .filter_map(|(path, enabled)| enabled.then_some(PathBuf::from(path)))
            .collect();
        Ok(ResolvedProfile {
            description: merged.description,
            workspace_roots,
            policy,
            command,
        })
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
        cache: &mut HashMap<String, MergedProfile>,
    ) -> Result<MergedProfile, ConfigError> {
        if let Some(merged) = cache.get(name) {
            return Ok(merged.clone());
        }
        if !self.raw.profiles.contains_key(name) {
            return Err(ConfigError::UnknownProfile {
                name: name.to_owned(),
            });
        }

        let mut frames = vec![ResolveFrame::new(name.to_owned())];
        let mut active = HashMap::new();
        let mut active_names = Vec::new();
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
                if let Some(parent) = cache.get(&parent_name).cloned() {
                    let merged = std::mem::take(&mut frames[frame_index].merged);
                    frames[frame_index].merged = merge_profiles(merged, parent);
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

            let frame = frames.pop().expect("resolution frame exists");
            let merged = apply_profile(frame.merged, profile);
            active.remove(&frame.name);
            active_names.pop();
            cache.insert(frame.name, merged.clone());

            if let Some(parent) = frames.last_mut() {
                let parent_merged = std::mem::take(&mut parent.merged);
                parent.merged = merge_profiles(parent_merged, merged);
            } else {
                return Ok(merged);
            }
        }
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
    description: Option<String>,
    workspace_roots: BTreeMap<String, bool>,
    filesystem: Option<RawFilesystem>,
    network: Option<RawNetwork>,
    command: Option<RawCommand>,
}

struct ResolveFrame {
    name: String,
    next_parent: usize,
    merged: MergedProfile,
}

impl ResolveFrame {
    fn new(name: String) -> Self {
        Self {
            name,
            next_parent: 0,
            merged: MergedProfile::default(),
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
    for (name, profile) in &config.profiles {
        validate_profile_name(name)?;
        for root in profile.workspace_roots.keys() {
            validate_workspace_root(name, root)?;
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
        if let Some(command) = &profile.command {
            if let Some(environment) = &command.environment {
                let mut filter_patterns = BTreeSet::new();
                for pattern in environment.filters.keys() {
                    if !filter_patterns.insert(pattern.to_lowercase()) {
                        return Err(invalid_value(
                            name,
                            "command.environment.filters",
                            format!("duplicate pattern ignoring case {pattern:?}"),
                        ));
                    }
                }
                let mut set_names = BTreeSet::new();
                for variable in environment.set.keys() {
                    let normalized = variable.to_lowercase();
                    if !set_names.insert(normalized) {
                        return Err(invalid_value(
                            name,
                            "command.environment",
                            format!("duplicate set variable ignoring case {variable:?}"),
                        ));
                    }
                }
                let mut remove_names = BTreeSet::new();
                for variable in &environment.remove {
                    let normalized = variable.to_lowercase();
                    if !remove_names.insert(normalized.clone()) {
                        return Err(invalid_value(
                            name,
                            "command.environment.remove",
                            format!("duplicate removed variable ignoring case {variable:?}"),
                        ));
                    }
                    if set_names.contains(&normalized) {
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

fn validate_workspace_root(profile: &str, root: &str) -> Result<(), ConfigError> {
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
    if contains_parent_traversal(Path::new(root)) {
        return Err(invalid_value(
            profile,
            "workspace_roots",
            "path must not contain parent traversal",
        ));
    }
    Ok(())
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

fn apply_profile(mut merged: MergedProfile, profile: &RawProfile) -> MergedProfile {
    merged.description = profile.description.clone();
    merge_workspace_roots(&mut merged.workspace_roots, profile.workspace_roots.clone());
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
    merge_workspace_roots(&mut left.workspace_roots, right.workspace_roots);
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

fn merge_workspace_roots(
    target: &mut BTreeMap<String, bool>,
    values: impl IntoIterator<Item = (String, bool)>,
) {
    for (path, enabled) in values {
        if let Some(existing) = target
            .keys()
            .find(|existing| paths_equal(Path::new(existing), Path::new(&path)))
            .cloned()
        {
            target.remove(&existing);
        }
        target.insert(path, enabled);
    }
}

fn merge_filesystem(parent: Option<RawFilesystem>, child: &RawFilesystem) -> RawFilesystem {
    let mut merged = parent.unwrap_or_default();
    if child.mode.is_some() {
        merged.mode = child.mode;
    }
    if child.glob_scan_max_depth.is_some() {
        merged.glob_scan_max_depth = child.glob_scan_max_depth;
    }
    append_unique_case_insensitive(
        &mut merged.additional_protected_paths,
        &child.additional_protected_paths,
    );
    if let Some(security) = &child.security {
        let merged_security = merged.security.get_or_insert_with(Default::default);
        if security.dangerously_allow_git_write.is_some() {
            merged_security.dangerously_allow_git_write = security.dangerously_allow_git_write;
        }
    }
    for child_rule in &child.rules {
        if let Some(parent_rule) = merged
            .rules
            .iter_mut()
            .find(|parent_rule| same_filesystem_rule_target(parent_rule, child_rule))
        {
            *parent_rule = child_rule.clone();
        } else {
            merged.rules.push(child_rule.clone());
        }
    }
    merged
}

fn merge_network(parent: Option<RawNetwork>, child: &RawNetwork) -> RawNetwork {
    let mut merged = parent.unwrap_or_default();
    if child.mode.is_some() {
        merged.mode = child.mode;
    }
    if child.domain_mode.is_some() {
        merged.domain_mode = child.domain_mode;
    }
    if child.unix_socket_mode.is_some() {
        merged.unix_socket_mode = child.unix_socket_mode;
    }
    if child.local_network_access.is_some() {
        merged.local_network_access = child.local_network_access;
    }
    for child_rule in &child.domains {
        if let Some(parent_rule) = merged
            .domains
            .iter_mut()
            .find(|parent_rule| same_domain_rule(parent_rule, child_rule))
        {
            *parent_rule = child_rule.clone();
        } else {
            merged.domains.push(child_rule.clone());
        }
    }
    for child_rule in &child.unix_sockets {
        if let Some(parent_rule) = merged.unix_sockets.iter_mut().find(|parent_rule| {
            paths_equal(Path::new(&parent_rule.path), Path::new(&child_rule.path))
        }) {
            *parent_rule = child_rule.clone();
        } else {
            merged.unix_sockets.push(child_rule.clone());
        }
    }
    merged
}

fn same_domain_rule(
    left: &crate::model::RawDomainRule,
    right: &crate::model::RawDomainRule,
) -> bool {
    match (
        DomainRule::new(left.pattern.clone(), DomainAccess::Allow),
        DomainRule::new(right.pattern.clone(), DomainAccess::Allow),
    ) {
        (Ok(left), Ok(right)) => left.pattern() == right.pattern(),
        _ => left
            .pattern
            .trim_end_matches('.')
            .eq_ignore_ascii_case(right.pattern.trim_end_matches('.')),
    }
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
    if child.inherit.is_some() {
        merged.inherit = child.inherit;
    }
    for (child_pattern, child_action) in &child.filters {
        if let Some(parent_pattern) = merged
            .filters
            .keys()
            .find(|parent_pattern| parent_pattern.eq_ignore_ascii_case(child_pattern))
            .cloned()
        {
            merged.filters.remove(&parent_pattern);
        }
        merged.filters.insert(child_pattern.clone(), *child_action);
    }
    for (name, value) in &child.set {
        merged
            .remove
            .retain(|removed| !environment_names_equal(removed, name));
        if let Some(existing) = merged
            .set
            .keys()
            .find(|existing| environment_names_equal(existing, name))
            .cloned()
        {
            merged.set.remove(&existing);
        }
        merged.set.insert(name.clone(), value.clone());
    }
    for name in &child.remove {
        if let Some(existing) = merged
            .set
            .keys()
            .find(|existing| environment_names_equal(existing, name))
            .cloned()
        {
            merged.set.remove(&existing);
        }
        if !merged
            .remove
            .iter()
            .any(|removed| environment_names_equal(removed, name))
        {
            merged.remove.push(name.clone());
        }
    }
    merged
}

fn environment_names_equal(left: &str, right: &str) -> bool {
    left.to_lowercase() == right.to_lowercase()
}

fn append_unique_case_insensitive(target: &mut Vec<String>, values: &[String]) {
    for value in values {
        if !target
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(value))
        {
            target.push(value.clone());
        }
    }
}

fn same_filesystem_rule_target(left: &RawFilesystemRule, right: &RawFilesystemRule) -> bool {
    left.target == right.target
        && optional_path_strings_equal(left.path.as_deref(), right.path.as_deref())
        && optional_path_strings_equal(left.pattern.as_deref(), right.pattern.as_deref())
}

fn optional_path_strings_equal(left: Option<&str>, right: Option<&str>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => strings_equal(left, right),
        (None, None) => true,
        _ => false,
    }
}

fn merge_stdio(parent: Option<RawStdio>, child: &RawStdio) -> RawStdio {
    let mut merged = parent.unwrap_or_default();
    if child.stdin.is_some() {
        merged.stdin = child.stdin;
    }
    if child.stdout.is_some() {
        merged.stdout = child.stdout;
    }
    if child.stderr.is_some() {
        merged.stderr = child.stderr;
    }
    merged
}

fn merge_timeout(parent: Option<RawTimeout>, child: &RawTimeout) -> RawTimeout {
    let mut merged = parent.unwrap_or_default();
    if child.mode.is_some() {
        merged.mode = child.mode;
        if child.milliseconds.is_none()
            && matches!(
                child.mode,
                Some(
                    crate::model::RawTimeoutMode::BackendDefault
                        | crate::model::RawTimeoutMode::Disabled
                )
            )
        {
            merged.milliseconds = None;
        }
    }
    if child.milliseconds.is_some() {
        merged.milliseconds = child.milliseconds;
    }
    merged
}
