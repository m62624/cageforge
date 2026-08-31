// SPDX-License-Identifier: Apache-2.0

#![cfg(target_os = "windows")]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

use std::process::ExitCode;

#[path = "../account_identity.rs"]
mod account_identity;
#[path = "../owner_identity.rs"]
mod owner_identity;
#[path = "../runner/manifest.rs"]
mod runner_manifest;
#[path = "../runner/protocol.rs"]
mod runner_protocol;
#[path = "../runner/resource_security.rs"]
mod runner_resource_security;
#[path = "../setup/pinned/file.rs"]
mod setup_pinned_file;
mod windows_runner;

fn main() -> ExitCode {
    windows_runner::run()
}
