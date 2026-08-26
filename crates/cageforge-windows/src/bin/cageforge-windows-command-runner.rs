// SPDX-License-Identifier: Apache-2.0

#![cfg(target_os = "windows")]

use std::process::ExitCode;

fn main() -> ExitCode {
    eprintln!(
        "cageforge-windows-command-runner: direct invocation is forbidden; an authenticated inherited setup channel is required"
    );
    ExitCode::from(125)
}
