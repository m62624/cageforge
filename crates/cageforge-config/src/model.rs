// SPDX-License-Identifier: Apache-2.0

use schemars::JsonSchema;
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum RawFilesystemMode {
    Restricted,
    Unrestricted,
    External,
}

#[derive(Debug, Clone, Copy, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum RawFilesystemTarget {
    Absolute,
    Workspace,
    WorkspaceRoot,
    Root,
    Minimal,
    Tmpdir,
    SlashTmp,
    AbsoluteGlob,
    WorkspaceGlob,
}

#[derive(Debug, Clone, Copy, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum RawAccessMode {
    Read,
    Write,
    Deny,
}

#[derive(Debug, Clone, Copy, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum RawNetworkMode {
    Disabled,
    Enabled,
    External,
}

#[derive(Debug, Clone, Copy, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum RawDomainMode {
    Disabled,
    Enabled,
    Restricted,
}

#[derive(Debug, Clone, Copy, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum RawUnixSocketMode {
    Disabled,
    Enabled,
    Restricted,
}

#[derive(Debug, Clone, Copy, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum RawLocalNetworkAccess {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum RawDomainAccess {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum RawEnvironmentBase {
    All,
    Core,
    None,
}

#[derive(Debug, Clone, Copy, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum RawEnvironmentFilterAction {
    Include,
    Exclude,
}

#[derive(Debug, Clone, Copy, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum RawStdioMode {
    Inherit,
    Null,
    Pipe,
}

#[derive(Debug, Clone, Copy, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum RawTimeoutMode {
    BackendDefault,
    Limit,
    Disabled,
}

#[derive(Debug, Clone, Copy, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum RawMissingPathBehavior {
    Error,
    Skip,
}

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub(crate) struct RawConfig {
    #[serde(default)]
    pub(crate) default_profile: Option<String>,
    #[serde(default)]
    pub(crate) profiles: BTreeMap<String, RawProfile>,
}

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub(crate) struct RawProfile {
    #[serde(default)]
    pub(crate) description: Option<String>,
    #[serde(default)]
    pub(crate) inherits: Vec<String>,
    #[serde(default)]
    pub(crate) workspace_roots: BTreeMap<String, bool>,
    pub(crate) filesystem: Option<RawFilesystem>,
    pub(crate) network: Option<RawNetwork>,
    pub(crate) command: Option<RawCommand>,
}

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub(crate) struct RawFilesystem {
    pub(crate) mode: Option<RawFilesystemMode>,
    #[schemars(range(min = 1))]
    pub(crate) glob_scan_max_depth: Option<usize>,
    #[serde(default)]
    pub(crate) additional_protected_paths: Vec<String>,
    pub(crate) security: Option<RawFilesystemSecurity>,
    #[serde(default)]
    pub(crate) rules: Vec<RawFilesystemRule>,
}

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub(crate) struct RawFilesystemSecurity {
    #[serde(default)]
    pub(crate) dangerously_allow_git_write: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub(crate) struct RawFilesystemRule {
    pub(crate) target: RawFilesystemTarget,
    pub(crate) path: Option<String>,
    pub(crate) pattern: Option<String>,
    pub(crate) access: RawAccessMode,
    pub(crate) missing_path: Option<RawMissingPathBehavior>,
    #[serde(default)]
    pub(crate) read_only_subpaths: Vec<RawSelector>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub(crate) struct RawSelector {
    pub(crate) target: RawFilesystemTarget,
    pub(crate) path: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub(crate) struct RawNetwork {
    pub(crate) mode: Option<RawNetworkMode>,
    pub(crate) domain_mode: Option<RawDomainMode>,
    pub(crate) unix_socket_mode: Option<RawUnixSocketMode>,
    pub(crate) local_network_access: Option<RawLocalNetworkAccess>,
    #[serde(default)]
    pub(crate) domains: Vec<RawDomainRule>,
    #[serde(default)]
    pub(crate) unix_sockets: Vec<RawUnixSocketRule>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub(crate) struct RawDomainRule {
    pub(crate) pattern: String,
    pub(crate) access: RawDomainAccess,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub(crate) struct RawUnixSocketRule {
    pub(crate) path: String,
    pub(crate) access: RawDomainAccess,
}

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub(crate) struct RawCommand {
    pub(crate) program: Option<String>,
    pub(crate) args: Option<Vec<String>>,
    pub(crate) working_directory: Option<String>,
    pub(crate) environment: Option<RawEnvironment>,
    pub(crate) stdio: Option<RawStdio>,
    pub(crate) timeout: Option<RawTimeout>,
}

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub(crate) struct RawEnvironment {
    pub(crate) inherit: Option<RawEnvironmentBase>,
    #[serde(default)]
    pub(crate) filters: BTreeMap<String, RawEnvironmentFilterAction>,
    #[serde(default)]
    pub(crate) set: BTreeMap<String, String>,
    #[serde(default)]
    pub(crate) remove: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub(crate) struct RawStdio {
    pub(crate) stdin: Option<RawStdioMode>,
    pub(crate) stdout: Option<RawStdioMode>,
    pub(crate) stderr: Option<RawStdioMode>,
}

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub(crate) struct RawTimeout {
    pub(crate) mode: Option<RawTimeoutMode>,
    pub(crate) milliseconds: Option<u64>,
}
