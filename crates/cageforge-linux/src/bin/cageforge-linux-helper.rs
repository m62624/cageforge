// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    cageforge_linux::run_hardening_helper(std::env::args_os().skip(1))
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("cageforge-linux-helper is supported only on Linux");
    std::process::ExitCode::from(1)
}
