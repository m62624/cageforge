// SPDX-License-Identifier: Apache-2.0

#![cfg(target_os = "windows")]

use std::process::ExitCode;

#[path = "../account_identity.rs"]
mod account_identity;
#[path = "../runner_manifest.rs"]
mod runner_manifest;
#[path = "../runner_protocol.rs"]
mod runner_protocol;
#[path = "../runner_resource_security.rs"]
mod runner_resource_security;
mod windows_runner;

fn main() -> ExitCode {
    windows_runner::run()
}
