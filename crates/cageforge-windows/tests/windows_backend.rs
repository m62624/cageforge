// SPDX-License-Identifier: Apache-2.0

#![cfg(target_os = "windows")]

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use cageforge_backend_api::BackendRequest;
use cageforge_command::{CommandRequest, CommandSpec, EnvironmentSpec};
use cageforge_policy::{
    AccessMode, FilesystemPolicy, FilesystemRule, NetworkPolicy, PathResolutionContext,
    PathSelector, SandboxPolicy,
};
use cageforge_policy_compose::{CompositionRequest, PolicyCeiling, compose};
use cageforge_windows::{
    WindowsBackend, WindowsBackendConfig, WindowsBackendConfigError, WindowsBackendError,
    WindowsSetup, WindowsSetupConfig, WindowsSetupError, WindowsSetupStatus,
    WindowsSetupVerificationError,
};
use pretty_assertions::assert_eq;

struct SetupCleanup<'a> {
    setup: &'a WindowsSetup,
    armed: bool,
}

impl Drop for SetupCleanup<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.setup.uninstall();
        }
    }
}

fn restricted_request(
    workspace: &Path,
    command: CommandSpec,
) -> (
    CommandRequest,
    cageforge_policy_compose::EffectiveSandbox,
    PathResolutionContext,
) {
    let environment = EnvironmentSpec::inherit_all();
    let filesystem = FilesystemPolicy::restricted([
        FilesystemRule::new(PathSelector::minimal(), AccessMode::Read),
        FilesystemRule::new(PathSelector::workspace_root(), AccessMode::Write),
        FilesystemRule::new(PathSelector::tmpdir(), AccessMode::Write),
        FilesystemRule::new(PathSelector::slash_tmp(), AccessMode::Write),
    ])
    .with_additional_protected_relative_path(".cageforge-test-protected")
    .expect("protected test path");
    let policy = SandboxPolicy::new(filesystem, NetworkPolicy::disabled());
    let ceiling = PolicyCeiling::new(SandboxPolicy::full_access(), environment.clone());
    let effective = compose(CompositionRequest::new(&policy, &environment, &ceiling))
        .expect("policies compose");
    let windows_directory =
        PathBuf::from(std::env::var_os("WINDIR").expect("Windows test runner must define WINDIR"));
    let temporary = std::env::temp_dir();
    let context = PathResolutionContext::new()
        .with_workspace_root(workspace.to_path_buf())
        .expect("workspace root")
        .with_minimal_path(windows_directory)
        .expect("Windows runtime scope")
        .with_tmpdir(temporary.clone())
        .expect("temporary directory")
        .with_slash_tmp(temporary)
        .expect("slash-tmp compatibility directory")
        .with_current_directory(workspace.to_path_buf())
        .expect("current directory");
    let command = CommandRequest::new(command)
        .with_working_directory(workspace.to_path_buf())
        .expect("working directory")
        .with_environment(environment);
    (command, effective, context)
}

#[test]
fn backend_configuration_rejects_a_zero_default_timeout() {
    let error = WindowsBackendConfig::new()
        .with_default_timeout(Duration::ZERO)
        .expect_err("zero timeout");

    assert_eq!(error, WindowsBackendConfigError::ZeroDefaultTimeout);
}

#[test]
fn setup_configuration_rejects_relative_security_paths() {
    let state_error = WindowsSetupConfig::new()
        .with_state_directory(PathBuf::from("relative-state"))
        .expect_err("relative state directory");
    let helper_error = WindowsSetupConfig::new()
        .with_setup_helper_path(PathBuf::from("relative-helper.exe"))
        .expect_err("relative helper path");
    let runner_error = WindowsSetupConfig::new()
        .with_command_runner_path(PathBuf::from("relative-runner.exe"))
        .expect_err("relative command runner path");

    assert_eq!(
        state_error,
        WindowsBackendConfigError::RelativeStateDirectory {
            path: PathBuf::from("relative-state"),
        }
    );
    assert_eq!(
        helper_error,
        WindowsBackendConfigError::RelativeSetupHelper {
            path: PathBuf::from("relative-helper.exe"),
        }
    );
    assert_eq!(
        runner_error,
        WindowsBackendConfigError::RelativeCommandRunner {
            path: PathBuf::from("relative-runner.exe"),
        }
    );
}

#[test]
fn setup_state_recovery_active_child_exclusion_and_cleanup_are_end_to_end() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let helper = PathBuf::from(env!("CARGO_BIN_EXE_cageforge-windows-setup"));
    let runner = PathBuf::from(env!("CARGO_BIN_EXE_cageforge-windows-command-runner"));
    let config = WindowsSetupConfig::new()
        .with_state_directory(temporary.path().join("state"))
        .expect("absolute state directory")
        .with_setup_helper_path(helper)
        .expect("absolute setup helper")
        .with_command_runner_path(runner)
        .expect("absolute command runner");
    let setup = WindowsSetup::new(config);
    let mut cleanup = SetupCleanup {
        setup: &setup,
        armed: true,
    };

    let first = setup.install().expect("first elevated setup");
    assert_ne!(
        first.accounts().offline_sid(),
        first.accounts().online_sid()
    );
    assert_eq!(first.proxy_ports().len(), 2);
    assert!(matches!(
        setup.status().expect("verified setup status"),
        WindowsSetupStatus::Ready(_)
    ));

    let second = setup.install().expect("idempotent elevated setup");
    assert_eq!(first.owner_sid(), second.owner_sid());
    assert_eq!(first.accounts(), second.accounts());
    assert_eq!(first.proxy_ports(), second.proxy_ports());

    let capability_state = second.state_directory().join("capabilities.json");
    let capability_backup = second.state_directory().join("capabilities.json.backup");
    let original_state = fs::read(&capability_state).expect("read capability state fixture");
    fs::rename(&capability_state, &capability_backup)
        .expect("simulate an interrupted atomic state replacement");
    fs::write(&capability_backup, b"{}").expect("corrupt protected backup contents");
    assert!(matches!(
        setup
            .status()
            .expect_err("malformed backup must fail closed"),
        WindowsSetupError::Verification(
            WindowsSetupVerificationError::CapabilityStateInvalid { path, .. }
        ) if path == capability_state
    ));
    assert!(!capability_state.exists());
    assert!(capability_backup.is_file());
    fs::write(&capability_backup, original_state).expect("restore valid backup fixture");
    assert!(matches!(
        setup.status().expect("status recovers protected backup"),
        WindowsSetupStatus::Ready(_)
    ));
    assert!(capability_state.is_file());
    assert!(!capability_backup.exists());

    let backend =
        WindowsBackend::new(WindowsBackendConfig::new().with_setup(setup.config().clone()))
            .expect("backend after capability-state recovery");
    let workspace = tempfile::tempdir().expect("sandbox workspace");
    let powershell = PathBuf::from(std::env::var_os("WINDIR").expect("WINDIR"))
        .join("System32")
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe");
    let command = CommandSpec::new(powershell)
        .expect("PowerShell command")
        .with_args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Start-Sleep -Seconds 30",
        ])
        .expect("PowerShell arguments");
    let (command, effective, context) = restricted_request(workspace.path(), command);
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &context)
        .expect("prepare restricted launch");
    let mut child = backend.spawn(prepared).expect("spawn restricted child");
    let protected = workspace.path().join(".cageforge-test-protected");
    assert!(
        protected.is_dir(),
        "missing protected path was materialized"
    );
    assert!(matches!(
        setup
            .uninstall()
            .expect_err("active child must exclude uninstall"),
        WindowsSetupError::ActiveSandboxes
    ));
    assert!(protected.is_dir(), "failed uninstall retained its boundary");

    child.kill().expect("terminate complete sandbox job");
    let _ = child.wait().expect("reap terminated sandbox job");

    setup.uninstall().expect("explicit setup cleanup");
    cleanup.armed = false;
    assert!(
        !protected.exists(),
        "uninstall removed exact materialized path"
    );
    assert!(matches!(
        setup.status().expect("status after cleanup"),
        WindowsSetupStatus::Missing { .. }
    ));
}

#[test]
fn absent_setup_is_reported_without_creating_host_state() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let config = WindowsSetupConfig::new()
        .with_state_directory(temporary.path())
        .expect("absolute state directory");
    let setup = WindowsSetup::new(config);
    let state_directory = setup.state_directory().expect("resolved state directory");

    assert!(!state_directory.exists());
    assert_eq!(
        setup.status().expect("setup status"),
        WindowsSetupStatus::Missing {
            marker_path: state_directory.join("setup.json"),
        }
    );
    assert!(!state_directory.exists());
}

#[test]
fn backend_requires_verified_setup_without_creating_host_state() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let setup = WindowsSetupConfig::new()
        .with_state_directory(temporary.path())
        .expect("absolute state directory");
    let state_directory = WindowsSetup::new(setup.clone())
        .state_directory()
        .expect("resolved state directory");

    let error = WindowsBackend::new(WindowsBackendConfig::new().with_setup(setup))
        .expect_err("missing setup must reject backend construction");

    assert!(matches!(
        error,
        WindowsBackendError::Setup(WindowsSetupError::Missing { path })
            if path == state_directory.join("setup.json")
    ));
    assert!(!state_directory.exists());
}
