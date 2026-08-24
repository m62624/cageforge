// SPDX-License-Identifier: Apache-2.0

#[cfg(target_os = "linux")]
#[path = "../helper_protocol.rs"]
mod helper_protocol;

#[cfg(target_os = "linux")]
#[path = "../error.rs"]
#[allow(dead_code)]
mod error;

#[cfg(target_os = "linux")]
#[path = "../environment_transport.rs"]
#[allow(dead_code)]
mod environment_transport;

#[cfg(target_os = "linux")]
#[path = "../hardening.rs"]
mod hardening;

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    hardening::run_helper(std::env::args_os().skip(1))
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("cageforge-linux-helper is supported only on Linux");
    std::process::ExitCode::from(1)
}
