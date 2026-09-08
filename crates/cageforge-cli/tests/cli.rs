// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsString;

use cageforge_cli::{Cli, Command, RunArgs};
use clap::Parser;

#[test]
fn parses_explicit_argv_without_shell_interpretation() {
    let cli = Cli::try_parse_from([
        "cageforge-cli",
        "run",
        "--config",
        "sandbox.toml",
        "--profile",
        "isolated",
        "--",
        "untrusted-program",
        "--script",
        "$(touch escaped)",
    ])
    .expect("valid CLI");

    let Command::Run(RunArgs { command, .. }) = cli.command else {
        panic!("expected run command");
    };
    assert_eq!(
        command,
        vec![
            OsString::from("untrusted-program"),
            OsString::from("--script"),
            OsString::from("$(touch escaped)"),
        ]
    );
}

#[test]
fn requires_a_config_path_for_run() {
    let result = Cli::try_parse_from(["cageforge-cli", "run", "--", "true"]);
    assert!(result.is_err());
}
