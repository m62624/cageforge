// SPDX-License-Identifier: Apache-2.0

#[cfg(target_os = "macos")]
fn main() -> std::process::ExitCode {
    cageforge_macos::run_macos_helper()
}

#[cfg(not(target_os = "macos"))]
fn main() -> std::process::ExitCode {
    std::process::ExitCode::from(125)
}
