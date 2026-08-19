// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};

use cageforge_command::EnvironmentNameKey;
use cageforge_path::{NativePathKey, case_fold, normalize_lexical_path};
use cageforge_policy::{DomainAccess, DomainRule, PathPattern, PathSelector};

use crate::model::{
    RawCommand, RawEnvironment, RawFilesystem, RawFilesystemMode, RawFilesystemRule,
    RawFilesystemTarget, RawNetwork, RawNetworkMode, RawProfile, RawStdio, RawTimeout,
};

#[derive(Debug, Clone, Default)]
pub(crate) struct MergedProfile {
    pub(crate) description: Option<String>,
    pub(crate) workspace_roots: BTreeMap<String, bool>,
    pub(crate) filesystem: Option<RawFilesystem>,
    pub(crate) network: Option<RawNetwork>,
    pub(crate) command: Option<RawCommand>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum FilesystemRuleKey {
    Selector(RawFilesystemTarget, SelectorKey),
    Glob(RawFilesystemTarget, GlobKey),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum SelectorKey {
    Valid(PathSelector),
    Native(NativePathKey),
    Missing,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum GlobKey {
    Valid {
        prefix: Option<String>,
        components: Vec<String>,
    },
    Raw(String),
    Missing,
}

#[derive(Default)]
pub(crate) struct ProfileMerger {
    merged: MergedProfile,
    workspace_roots: HashMap<NativePathKey, String>,
    protected_paths: HashSet<NativePathKey>,
    filesystem_rules: HashMap<FilesystemRuleKey, usize>,
    domain_rules: HashMap<String, usize>,
    unix_sockets: HashMap<NativePathKey, usize>,
    environment_filters: HashMap<String, String>,
    environment_overrides: BTreeMap<EnvironmentNameKey, (String, Option<String>)>,
}

impl ProfileMerger {
    pub(crate) fn apply(&mut self, profile: &RawProfile) {
        self.merged.description = profile.description.clone();
        self.merge_workspace_roots(&profile.workspace_roots);
        if let Some(filesystem) = &profile.filesystem {
            self.merge_filesystem(filesystem);
        }
        if let Some(network) = &profile.network {
            self.merge_network(network);
        }
        if let Some(command) = &profile.command {
            self.merge_command(command);
        }
    }

    pub(crate) fn finish(mut self) -> MergedProfile {
        if let Some(environment) = self
            .merged
            .command
            .as_mut()
            .and_then(|command| command.environment.as_mut())
        {
            environment.set.clear();
            environment.remove.clear();
            for (_, (name, value)) in self.environment_overrides {
                if let Some(value) = value {
                    environment.set.insert(name, value);
                } else {
                    environment.remove.push(name);
                }
            }
        }
        self.merged
    }

    fn merge_workspace_roots(&mut self, values: &BTreeMap<String, bool>) {
        for (path, enabled) in values {
            let key = NativePathKey::new(Path::new(path));
            if let Some(existing) = self.workspace_roots.insert(key, path.clone()) {
                self.merged.workspace_roots.remove(&existing);
            }
            self.merged.workspace_roots.insert(path.clone(), *enabled);
        }
    }

    fn merge_filesystem(&mut self, child: &RawFilesystem) {
        let merged = self
            .merged
            .filesystem
            .get_or_insert_with(RawFilesystem::default);
        if let Some(mode) = child.mode {
            if mode != RawFilesystemMode::Restricted {
                merged.rules.clear();
                merged.additional_protected_paths.clear();
                merged.glob_scan_max_depth = None;
                merged.security = None;
                self.filesystem_rules.clear();
                self.protected_paths.clear();
            }
            merged.mode = Some(mode);
        }
        if child.glob_scan_max_depth.is_some() {
            merged.glob_scan_max_depth = child.glob_scan_max_depth;
        }
        for path in &child.additional_protected_paths {
            if self
                .protected_paths
                .insert(NativePathKey::new(Path::new(path)))
            {
                merged.additional_protected_paths.push(path.clone());
            }
        }
        if let Some(security) = &child.security {
            let merged_security = merged.security.get_or_insert_with(Default::default);
            if security.dangerously_allow_git_write.is_some() {
                merged_security.dangerously_allow_git_write = security.dangerously_allow_git_write;
            }
        }
        for rule in &child.rules {
            let key = filesystem_rule_key(rule);
            if let Some(&index) = self.filesystem_rules.get(&key) {
                merged.rules[index] = rule.clone();
            } else {
                self.filesystem_rules.insert(key, merged.rules.len());
                merged.rules.push(rule.clone());
            }
        }
    }

    fn merge_network(&mut self, child: &RawNetwork) {
        let merged = self.merged.network.get_or_insert_with(RawNetwork::default);
        if let Some(mode) = child.mode {
            if mode == RawNetworkMode::External {
                merged.domain_mode = None;
                merged.unix_socket_mode = None;
                merged.local_network_access = None;
                merged.domains.clear();
                merged.unix_sockets.clear();
                self.domain_rules.clear();
                self.unix_sockets.clear();
            }
            merged.mode = Some(mode);
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
        for rule in &child.domains {
            let key = domain_rule_key(&rule.pattern);
            if let Some(&index) = self.domain_rules.get(&key) {
                merged.domains[index] = rule.clone();
            } else {
                self.domain_rules.insert(key, merged.domains.len());
                merged.domains.push(rule.clone());
            }
        }
        for rule in &child.unix_sockets {
            let key = NativePathKey::new(Path::new(&rule.path));
            if let Some(&index) = self.unix_sockets.get(&key) {
                merged.unix_sockets[index] = rule.clone();
            } else {
                self.unix_sockets.insert(key, merged.unix_sockets.len());
                merged.unix_sockets.push(rule.clone());
            }
        }
    }

    fn merge_command(&mut self, child: &RawCommand) {
        let merged = self.merged.command.get_or_insert_with(RawCommand::default);
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
            merge_environment(
                merged
                    .environment
                    .get_or_insert_with(RawEnvironment::default),
                environment,
                &mut self.environment_filters,
                &mut self.environment_overrides,
            );
        }
        if let Some(stdio) = &child.stdio {
            merged.stdio = Some(merge_stdio(merged.stdio.take(), stdio));
        }
        if let Some(timeout) = &child.timeout {
            merged.timeout = Some(merge_timeout(merged.timeout.take(), timeout));
        }
    }
}

pub(crate) fn filesystem_rule_key(rule: &RawFilesystemRule) -> FilesystemRuleKey {
    match rule.target {
        RawFilesystemTarget::Absolute => FilesystemRuleKey::Selector(
            rule.target,
            selector_key(rule.path.as_deref(), PathSelector::absolute),
        ),
        RawFilesystemTarget::Workspace => FilesystemRuleKey::Selector(
            rule.target,
            selector_key(rule.path.as_deref(), PathSelector::workspace),
        ),
        RawFilesystemTarget::WorkspaceRoot
        | RawFilesystemTarget::Root
        | RawFilesystemTarget::Minimal
        | RawFilesystemTarget::Tmpdir
        | RawFilesystemTarget::SlashTmp => {
            FilesystemRuleKey::Selector(rule.target, SelectorKey::Missing)
        }
        RawFilesystemTarget::AbsoluteGlob => FilesystemRuleKey::Glob(
            rule.target,
            glob_key(rule.pattern.as_deref(), PathPattern::absolute),
        ),
        RawFilesystemTarget::WorkspaceGlob => FilesystemRuleKey::Glob(
            rule.target,
            glob_key(rule.pattern.as_deref(), PathPattern::workspace),
        ),
    }
}

fn selector_key(
    path: Option<&str>,
    constructor: impl FnOnce(PathBuf) -> Result<PathSelector, cageforge_policy::PolicyError>,
) -> SelectorKey {
    let Some(path) = path else {
        return SelectorKey::Missing;
    };
    constructor(PathBuf::from(path)).map_or_else(
        |_| SelectorKey::Native(NativePathKey::new(Path::new(path))),
        SelectorKey::Valid,
    )
}

fn glob_key(
    pattern: Option<&str>,
    constructor: impl FnOnce(String) -> Result<PathPattern, cageforge_policy::PolicyError>,
) -> GlobKey {
    let Some(pattern) = pattern else {
        return GlobKey::Missing;
    };
    if constructor(pattern.to_owned()).is_err() {
        return GlobKey::Raw(case_fold(pattern));
    }

    let normalized = normalize_lexical_path(Path::new(pattern));
    let mut prefix = None;
    let mut components = Vec::new();
    for component in normalized.components() {
        match component {
            Component::Prefix(value) => {
                prefix = Some(case_fold(&value.as_os_str().to_string_lossy()));
            }
            Component::Normal(value) => {
                components.push(case_fold(&value.to_string_lossy()));
            }
            Component::RootDir | Component::CurDir | Component::ParentDir => {}
        }
    }
    GlobKey::Valid { prefix, components }
}

pub(crate) fn domain_rule_key(pattern: &str) -> String {
    DomainRule::new(pattern, DomainAccess::Allow).map_or_else(
        |_| pattern.trim().trim_end_matches('.').to_ascii_lowercase(),
        |rule| rule.pattern().to_owned(),
    )
}

fn merge_environment(
    merged: &mut RawEnvironment,
    child: &RawEnvironment,
    filter_keys: &mut HashMap<String, String>,
    overrides: &mut BTreeMap<EnvironmentNameKey, (String, Option<String>)>,
) {
    if child.inherit.is_some() {
        merged.inherit = child.inherit;
    }
    for (pattern, action) in &child.filters {
        let key = pattern.to_lowercase();
        if let Some(existing) = filter_keys.insert(key, pattern.clone()) {
            merged.filters.remove(&existing);
        }
        merged.filters.insert(pattern.clone(), *action);
    }
    for (name, value) in &child.set {
        overrides.insert(
            EnvironmentNameKey::new(OsStr::new(name)),
            (name.clone(), Some(value.clone())),
        );
    }
    for name in &child.remove {
        overrides.insert(
            EnvironmentNameKey::new(OsStr::new(name)),
            (name.clone(), None),
        );
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
