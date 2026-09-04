// SPDX-License-Identifier: Apache-2.0

#[cfg(target_os = "windows")]
mod windows {
    //! Protected identity contract consumed by the installed command runner.

    use serde::{Deserialize, Serialize};

    pub(crate) const RUNNER_MANIFEST_VERSION: u32 = 1;
    pub(crate) const RUNNER_MANIFEST_NAME: &str = "runner-manifest.json";
    pub(crate) const COMMAND_RUNNER_NAME: &str = "cageforge-windows-command-runner.exe";

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
}

#[cfg(target_os = "windows")]
pub(crate) use windows::{
    COMMAND_RUNNER_NAME, RUNNER_MANIFEST_NAME, RUNNER_MANIFEST_VERSION, RunnerManifest,
};
