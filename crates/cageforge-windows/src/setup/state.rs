// SPDX-License-Identifier: Apache-2.0

//! Persistent state committed only after complete native setup verification.

use serde::{Deserialize, Serialize};

pub(crate) const SETUP_STATE_VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct SetupMarker {
    pub(crate) version: u32,
    pub(crate) owner_sid: String,
    pub(crate) accounts: SetupMarkerAccounts,
    pub(crate) proxy_ports: Vec<u16>,
    pub(crate) firewall_policy_id: String,
    pub(crate) wfp_provider_id: String,
    pub(crate) setup_helper_sha256: String,
    pub(crate) command_runner_sha256: String,
    #[serde(default)]
    pub(crate) runner_manifest_sha256: String,
    pub(crate) credential_sha256: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct SetupMarkerAccounts {
    pub(crate) offline_name: String,
    pub(crate) offline_sid: String,
    pub(crate) online_name: String,
    pub(crate) online_sid: String,
    pub(crate) group_name: String,
    pub(crate) group_sid: String,
}
