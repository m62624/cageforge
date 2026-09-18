// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsString;
use std::process::Command as ProcessCommand;

use cageforge::{GrantAuthority, PermissionRequest, PermissionScope, PermissionSet, PlatformId};
#[cfg(target_os = "windows")]
use cageforge_cli::SetupCommand;
use cageforge_cli::{Cli, Command, RunArgs};
use clap::Parser;
// This is a native Bubblewrap smoke test. Keep it out of common portable
// component checks; the Linux bundled/native lane owns execution tests.
#[cfg(all(feature = "linux-bundled-bubblewrap", target_os = "linux"))]
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
    let help = ProcessCommand::new(env!("CARGO_BIN_EXE_cageforge-cli"))
        .arg("--help")
        .output()
        .expect("run cageforge-cli --help");
    assert!(help.status.success(), "--help should exit successfully");
    let help_text = String::from_utf8_lossy(&help.stdout);
    for expected in [
        "approval.mode = \"preflight\"",
        "persistent approval",
        "permissions revoke-all --yes",
    ] {
        assert!(help_text.contains(expected), "help is missing {expected:?}");
    }
    #[cfg(target_os = "windows")]
    assert!(help_text.contains("cageforge-cli setup status"));

    let run_help = ProcessCommand::new(env!("CARGO_BIN_EXE_cageforge-cli"))
        .args(["run", "--help"])
        .output()
        .expect("run cageforge-cli run --help");
    assert!(
        run_help.status.success(),
        "run --help should exit successfully"
    );
    let run_help_text = String::from_utf8_lossy(&run_help.stdout);
    for expected in ["--approve", "--permission-store <PATH>"] {
        assert!(
            run_help_text.contains(expected),
            "run help is missing {expected:?}"
        );
    }

    let version = ProcessCommand::new(env!("CARGO_BIN_EXE_cageforge-cli"))
        .arg("--version")
        .output()
        .expect("run cageforge-cli --version");
    assert!(
        version.status.success(),
        "--version should exit successfully"
    );
}

#[test]
fn help_output_is_snapshotted() {
    let output = ProcessCommand::new(env!("CARGO_BIN_EXE_cageforge-cli"))
        .arg("--help")
        .output()
        .expect("run cageforge-cli --help");
    assert!(output.status.success());
    let help = String::from_utf8_lossy(&output.stdout)
        .replace("\r\n", "\n")
        .replace("cageforge-cli.exe", "cageforge-cli")
        .replace("  cageforge-cli setup status\n", "")
        .replace(
            "On Windows, run `cageforge-cli setup install` once before the first `run`. It may request UAC and keeps the setup for later launches.\n\n",
            "",
        );
    insta::assert_snapshot!(help);
}

#[test]
fn usage_error_is_snapshotted() {
    let output = ProcessCommand::new(env!("CARGO_BIN_EXE_cageforge-cli"))
        .args(["permissions", "revoke-all"])
        .output()
        .expect("run cageforge-cli permissions revoke-all");
    assert_eq!(output.status.code(), Some(2));
    insta::assert_snapshot!(String::from_utf8_lossy(&output.stderr));
}

#[test]
fn permission_list_output_is_snapshotted() {
    let workspace = tempfile::tempdir().expect("temporary permission store");
    let store_path = workspace.path().join("permissions.json");
    let request = PermissionRequest::new(
        "snapshot-tool",
        "1.0.0",
        "a".repeat(64),
        "b".repeat(64),
        PlatformId::Linux,
        "x86_64",
        PermissionSet::new(),
    )
    .expect("valid snapshot request");
    let grant = GrantAuthority::new()
        .approve_with(
            &request,
            request.capabilities().clone(),
            PermissionScope::Persistent,
            None,
        )
        .expect("valid persistent grant");
    cageforge::PermissionStore::open(&store_path)
        .expect("open store")
        .put(&grant, &request)
        .expect("persist grant");

    let output = ProcessCommand::new(env!("CARGO_BIN_EXE_cageforge-cli"))
        .args([
            "permissions",
            "list",
            "--permission-store",
            store_path.to_str().expect("UTF-8 store path"),
        ])
        .output()
        .expect("run permission list");
    assert!(output.status.success());
    let normalized = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| {
            if line.starts_with("next-cursor\t") {
                "next-cursor\t<opaque-cursor>".to_owned()
            } else {
                let mut fields = line.splitn(2, '\t');
                let _id = fields.next().unwrap_or_default();
                format!("<grant-id>\t{}", fields.next().unwrap_or_default())
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    insta::assert_snapshot!(normalized);
}

#[test]
fn permission_revoke_validation_error_is_snapshotted() {
    let output = ProcessCommand::new(env!("CARGO_BIN_EXE_cageforge-cli"))
        .args(["permissions", "revoke", "--id", "not-a-grant-id"])
        .output()
        .expect("run permission revoke");
    assert_eq!(output.status.code(), Some(2));
    insta::assert_snapshot!(String::from_utf8_lossy(&output.stderr));
}

#[test]
fn no_command_is_a_usage_error() {
    let output = ProcessCommand::new(env!("CARGO_BIN_EXE_cageforge-cli"))
        .output()
        .expect("run cageforge-cli");
    assert_eq!(output.status.code(), Some(2));
}

#[cfg(target_os = "windows")]
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

#[cfg(all(feature = "linux-bundled-bubblewrap", target_os = "linux"))]
#[test]
fn linux_cli_starts_a_sandbox_with_its_self_hosted_helper_entrypoint() {
    let workspace = TempDir::new().expect("temporary workspace");
    let config = workspace.path().join("sandbox.toml");
    let workspace_path = workspace.path().to_str().expect("UTF-8 workspace path");
    std::fs::write(
        &config,
        format!(
            "default_profile = \"test\"\n\n[profiles.test]\nworkspace_roots = {{ \"{workspace_path}\" = true }}\n\n[profiles.test.approval]\nmode = \"preflight\"\npersistence = \"session\"\n\n[profiles.test.filesystem]\nmode = \"restricted\"\nrules = [\n  {{ target = \"minimal\", access = \"read\" }},\n  {{ target = \"workspace-root\", access = \"write\" }},\n]\n\n[profiles.test.network]\nmode = \"disabled\"\n"
        ),
    )
    .expect("sandbox configuration");

    let output = ProcessCommand::new(env!("CARGO_BIN_EXE_cageforge-cli"))
        .current_dir(workspace.path())
        .args([
            "run",
            "--config",
            config.to_str().expect("UTF-8 config path"),
            "--approve",
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
