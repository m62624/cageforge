// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsString;
use std::process::Command as ProcessCommand;

#[cfg(all(feature = "windows", target_os = "windows"))]
use cageforge_cli::SetupCommand;
use cageforge_cli::{Cli, Command, RunArgs};
use clap::Parser;
#[cfg(all(feature = "linux", target_os = "linux"))]
use tempfile::TempDir;

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

#[test]
fn help_and_version_succeed() {
    for flag in ["--help", "--version"] {
        let output = ProcessCommand::new(env!("CARGO_BIN_EXE_cageforge-cli"))
            .arg(flag)
            .output()
            .expect("run cageforge-cli");
        assert!(output.status.success(), "{flag} should exit successfully");
    }
}

#[test]
fn no_command_is_a_usage_error() {
    let output = ProcessCommand::new(env!("CARGO_BIN_EXE_cageforge-cli"))
        .output()
        .expect("run cageforge-cli");
    assert_eq!(output.status.code(), Some(2));
}

#[cfg(all(feature = "windows", target_os = "windows"))]
#[test]
fn parses_windows_setup_commands() {
    for (arguments, expected) in [
        (["cageforge-cli", "setup", "install"], SetupCommand::Install),
        (["cageforge-cli", "setup", "status"], SetupCommand::Status),
        (
            ["cageforge-cli", "setup", "uninstall"],
            SetupCommand::Uninstall,
        ),
    ] {
        let cli = Cli::try_parse_from(arguments).expect("valid Windows setup command");
        let Command::Setup(actual) = cli.command else {
            panic!("expected Windows setup command");
        };
        assert_eq!(actual, expected);
    }
}

#[cfg(all(feature = "linux", target_os = "linux"))]
#[test]
fn linux_cli_starts_a_sandbox_with_its_self_hosted_helper_entrypoint() {
    let workspace = TempDir::new().expect("temporary workspace");
    let config = workspace.path().join("sandbox.toml");
    let workspace_path = workspace.path().to_str().expect("UTF-8 workspace path");
    std::fs::write(
        &config,
        format!(
            "default_profile = \"test\"\n\n[profiles.test]\nworkspace_roots = {{ \"{workspace_path}\" = true }}\n\n[profiles.test.filesystem]\nmode = \"restricted\"\nrules = [\n  {{ target = \"minimal\", access = \"read\" }},\n  {{ target = \"workspace-root\", access = \"write\" }},\n]\n\n[profiles.test.network]\nmode = \"disabled\"\n"
        ),
    )
    .expect("sandbox configuration");

    let output = ProcessCommand::new(env!("CARGO_BIN_EXE_cageforge-cli"))
        .current_dir(workspace.path())
        .args([
            "run",
            "--config",
            config.to_str().expect("UTF-8 config path"),
            "--",
            "/bin/true",
        ])
        .output()
        .expect("run cageforge-cli");

    assert!(
        output.status.success(),
        "sandboxed CLI failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(feature = "config")]
#[test]
fn schema_is_valid_json() {
    let output = ProcessCommand::new(env!("CARGO_BIN_EXE_cageforge-cli"))
        .arg("schema")
        .output()
        .expect("run cageforge-cli schema");
    assert!(output.status.success());
    let _: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("schema output should be JSON");
}
