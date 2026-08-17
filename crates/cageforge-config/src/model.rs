// Copyright 2026 Mansur Azatbek
// SPDX-License-Identifier: Apache-2.0

use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawConfig {
    #[serde(default)]
    pub(crate) default_profile: Option<String>,
    #[serde(default)]
    pub(crate) profiles: BTreeMap<String, RawProfile>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawProfile {
    #[serde(default)]
    pub(crate) inherits: Vec<String>,
    pub(crate) filesystem: Option<RawFilesystem>,
    pub(crate) network: Option<RawNetwork>,
    pub(crate) command: Option<RawCommand>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawFilesystem {
    pub(crate) mode: Option<String>,
    pub(crate) glob_scan_max_depth: Option<usize>,
    #[serde(default)]
    pub(crate) rules: Vec<RawFilesystemRule>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawFilesystemRule {
    pub(crate) target: String,
    pub(crate) path: Option<String>,
    pub(crate) pattern: Option<String>,
    pub(crate) access: String,
    pub(crate) missing_path: Option<String>,
    #[serde(default)]
    pub(crate) read_only_subpaths: Vec<RawSelector>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawSelector {
    pub(crate) target: String,
    pub(crate) path: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawNetwork {
    pub(crate) mode: Option<String>,
    pub(crate) domain_mode: Option<String>,
    pub(crate) unix_socket_mode: Option<String>,
    #[serde(default)]
    pub(crate) domains: Vec<RawDomainRule>,
    #[serde(default)]
    pub(crate) unix_sockets: Vec<RawUnixSocketRule>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawDomainRule {
    pub(crate) pattern: String,
    pub(crate) access: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawUnixSocketRule {
    pub(crate) path: String,
    pub(crate) access: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawCommand {
    pub(crate) program: Option<String>,
    pub(crate) args: Option<Vec<String>>,
    pub(crate) working_directory: Option<String>,
    pub(crate) environment: Option<RawEnvironment>,
    pub(crate) stdio: Option<RawStdio>,
    pub(crate) timeout: Option<RawTimeout>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawEnvironment {
    pub(crate) base: Option<String>,
    #[serde(default)]
    pub(crate) set: BTreeMap<String, String>,
    #[serde(default)]
    pub(crate) remove: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawStdio {
    pub(crate) stdin: Option<String>,
    pub(crate) stdout: Option<String>,
    pub(crate) stderr: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawTimeout {
    pub(crate) mode: Option<String>,
    pub(crate) milliseconds: Option<u64>,
}
