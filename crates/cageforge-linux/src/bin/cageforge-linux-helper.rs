// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

#[cfg(not(target_os = "linux"))]
#[path = "../resource_names.rs"]
mod resource_names;

#[cfg(target_os = "linux")]
#[path = "../helper_protocol.rs"]
mod helper_protocol;

#[cfg(target_os = "linux")]
#[path = "../hardening_error.rs"]
mod error;

#[cfg(target_os = "linux")]
#[path = "../hardening.rs"]
mod hardening;

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    hardening::run_helper(std::env::args_os().skip(1))
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!(
        "{} is supported only on Linux",
        resource_names::HARDENING_HELPER_NAME
    );
    std::process::ExitCode::from(1)
}
