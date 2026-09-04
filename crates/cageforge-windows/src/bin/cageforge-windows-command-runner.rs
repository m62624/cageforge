// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

use std::process::ExitCode;

#[cfg(target_os = "windows")]
#[path = "../account_identity.rs"]
mod account_identity;
#[cfg(target_os = "windows")]
#[path = "../native_strings.rs"]
mod native_strings;
#[cfg(target_os = "windows")]
#[path = "../owner_identity.rs"]
mod owner_identity;
#[cfg(target_os = "windows")]
#[path = "../runner/manifest.rs"]
mod runner_manifest;
#[cfg(target_os = "windows")]
#[path = "../runner/protocol.rs"]
mod runner_protocol;
#[cfg(target_os = "windows")]
#[path = "../runner/resource_security.rs"]
mod runner_resource_security;
#[cfg(target_os = "windows")]
#[path = "../setup/pinned/file.rs"]
mod setup_pinned_file;
#[cfg(target_os = "windows")]
mod windows_runner;

#[cfg(target_os = "windows")]
fn main() -> ExitCode {
    windows_runner::run()
}

#[cfg(not(target_os = "windows"))]
fn main() -> ExitCode {
    eprintln!("{} is only available on Windows", env!("CARGO_BIN_NAME"));
    ExitCode::from(1)
}
