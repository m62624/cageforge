// SPDX-License-Identifier: Apache-2.0

//! Protected identity contract consumed by the installed command runner.

use serde::{Deserialize, Serialize};

pub(crate) const RUNNER_MANIFEST_VERSION: u32 = 2;
pub(crate) const RUNNER_MANIFEST_NAME: &str = "runner-manifest.json";

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct RunnerManifest {
    pub(crate) version: u32,
    pub(crate) owner_sid: String,
    pub(crate) group_name: String,
    pub(crate) group_sid: String,
    pub(crate) offline_name: String,
    pub(crate) offline_sid: String,
    pub(crate) online_name: String,
    pub(crate) online_sid: String,
    pub(crate) command_runner_sha256: String,
}
