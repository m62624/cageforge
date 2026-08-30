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
    restricted_request_with_environment(workspace, command, EnvironmentSpec::inherit_core())
}

fn restricted_request_with_environment(
    workspace: &Path,
    command: CommandSpec,
    environment: EnvironmentSpec,
) -> (
    CommandRequest,
    cageforge_policy_compose::EffectiveSandbox,
    PathResolutionContext,
) {
    let filesystem = FilesystemPolicy::restricted([
        FilesystemRule::new(PathSelector::minimal(), AccessMode::Read),
        FilesystemRule::new(PathSelector::workspace_root(), AccessMode::Write),
    ])
    .with_additional_protected_relative_path(".cageforge-test-protected")
    .expect("protected test path");
    let policy = SandboxPolicy::new(filesystem, NetworkPolicy::disabled());
    let ceiling = PolicyCeiling::new(SandboxPolicy::full_access(), environment.clone());
    let effective = compose(CompositionRequest::new(&policy, &environment, &ceiling))
        .expect("policies compose");
    let windows_directory =
        PathBuf::from(std::env::var_os("WINDIR").expect("Windows test runner must define WINDIR"));
    let context = PathResolutionContext::new()
        .with_workspace_root(workspace.to_path_buf())
        .expect("workspace root")
        .with_minimal_path(windows_directory)
        .expect("Windows runtime scope")
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
fn elevated_setup_rejects_a_reparse_state_root_before_touching_its_target() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let target = temporary.path().join("reparse-target");
    let selected = temporary.path().join("selected-state-root");
    fs::create_dir(&target).expect("state-root reparse target");
    std::os::windows::fs::symlink_dir(&target, &selected).expect("state-root directory symlink");
    let helper = PathBuf::from(env!("CARGO_BIN_EXE_cageforge-windows-setup"));
    let runner = PathBuf::from(env!("CARGO_BIN_EXE_cageforge-windows-command-runner"));
    let config = WindowsSetupConfig::new()
        .with_state_directory(&selected)
        .expect("absolute state directory")
        .with_setup_helper_path(helper)
        .expect("absolute setup helper")
        .with_command_runner_path(runner)
        .expect("absolute command runner");
    let setup = WindowsSetup::new(config);

    assert!(matches!(
        setup
            .install()
            .expect_err("reparse state root must fail closed"),
        WindowsSetupError::HelperFailed {
            code: cageforge_windows::WindowsSetupFailureCode::InvalidStateDirectory,
            ..
        }
    ));
    assert_eq!(
        fs::read_dir(&target)
            .expect("inspect untouched reparse target")
            .count(),
        0,
        "elevated setup followed the reparse root before rejecting it"
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

    let marker_path = first.state_directory().join("setup.json");
    let marker_backup = temporary.path().join("setup-marker.backup");
    let marker_reparse_target = temporary.path().join("setup-marker-target.json");
    fs::write(
        &marker_reparse_target,
        fs::read(&marker_path).expect("read protected marker fixture"),
    )
    .expect("setup marker reparse target");
    fs::rename(&marker_path, &marker_backup).expect("retain protected setup marker");
    std::os::windows::fs::symlink_file(&marker_reparse_target, &marker_path)
        .expect("setup marker file symlink");
    assert!(matches!(
        setup.status().expect_err("reparse marker must fail closed"),
        WindowsSetupError::StatePathUnsafe { path, .. } if path == marker_path
    ));
    fs::remove_file(&marker_path).expect("remove setup marker symlink");
    fs::rename(&marker_backup, &marker_path).expect("restore protected setup marker");

    let manifest_path = first
        .state_directory()
        .join("bin")
        .join("runner-manifest.json");
    let manifest_backup = temporary.path().join("runner-manifest.backup");
    let manifest_reparse_target = temporary.path().join("runner-manifest-target.json");
    fs::write(
        &manifest_reparse_target,
        fs::read(&manifest_path).expect("read protected runner manifest fixture"),
    )
    .expect("runner manifest reparse target");
    fs::rename(&manifest_path, &manifest_backup).expect("retain protected runner manifest");
    std::os::windows::fs::symlink_file(&manifest_reparse_target, &manifest_path)
        .expect("runner manifest file symlink");
    assert!(matches!(
        setup
            .status()
            .expect_err("reparse runner manifest must fail closed"),
        WindowsSetupError::Verification(
            WindowsSetupVerificationError::ProtectedPathUnsafe { path, .. }
        ) if path == manifest_path
    ));
    fs::remove_file(&manifest_path).expect("remove runner manifest symlink");
    fs::rename(&manifest_backup, &manifest_path).expect("restore protected runner manifest");
    assert!(matches!(
        setup.status().expect("status after restoring pinned files"),
        WindowsSetupStatus::Ready(_)
    ));

    let credential_path = first.state_directory().join("credentials.json.dpapi");
    let credential_reparse_target = temporary.path().join("credential-reparse-target.txt");
    fs::write(&credential_reparse_target, b"must remain unchanged")
        .expect("credential reparse target");
    fs::remove_file(&credential_path).expect("remove protected credential fixture");
    std::os::windows::fs::symlink_file(&credential_reparse_target, &credential_path)
        .expect("credential file symlink");

    let second = setup.install().expect("idempotent elevated setup");
    assert_eq!(
        fs::read(&credential_reparse_target).expect("read credential reparse target"),
        b"must remain unchanged",
        "elevated setup followed an existing credential reparse point"
    );
    assert!(
        !fs::symlink_metadata(&credential_path)
            .expect("reconciled credential metadata")
            .file_type()
            .is_symlink(),
        "credential reconciliation retained the attacker-controlled reparse point"
    );
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
    let runner_path = backend.command_runner_path();
    assert!(
        fs::OpenOptions::new()
            .write(true)
            .open(runner_path)
            .is_err(),
        "a verified backend did not pin its command runner against writes"
    );
    assert!(
        fs::rename(
            runner_path,
            temporary.path().join("displaced-command-runner.exe")
        )
        .is_err(),
        "a verified backend did not pin its command runner against replacement"
    );
    let runner_manifest_path = first
        .state_directory()
        .join("bin")
        .join("runner-manifest.json");
    assert!(
        fs::OpenOptions::new()
            .write(true)
            .open(&runner_manifest_path)
            .is_err(),
        "a verified backend did not pin its runner manifest against writes"
    );
    assert!(
        fs::rename(
            &runner_manifest_path,
            temporary.path().join("displaced-runner-manifest.json"),
        )
        .is_err(),
        "a verified backend did not pin its runner manifest against replacement"
    );
    let workspace = tempfile::tempdir().expect("sandbox workspace");
    let powershell = PathBuf::from(std::env::var_os("WINDIR").expect("WINDIR"))
        .join("System32")
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe");

    let outside_secret = temporary.path().join("outside-secret.txt");
    fs::write(&outside_secret, b"host secret").expect("outside secret fixture");
    let environment = EnvironmentSpec::inherit_core()
        .with_var("CAGEFORGE_DENIED_READ", outside_secret.as_os_str())
        .expect("denied-read fixture environment");
    let access_probe = CommandSpec::new(&powershell)
        .expect("PowerShell command")
        .with_args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "try { [IO.File]::ReadAllText($env:CAGEFORGE_DENIED_READ) | Out-Null; exit 91 } catch [System.UnauthorizedAccessException] { [Console]::Out.Write('denied') } catch { [Console]::Error.Write($_.Exception.GetType().FullName); exit 92 }",
        ])
        .expect("PowerShell arguments");
    let (command, effective, context) =
        restricted_request_with_environment(workspace.path(), access_probe, environment);
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &context)
        .expect("prepare denied-read probe");
    let mut access_child = backend.spawn(prepared).expect("spawn denied-read probe");
    let mut access_stdout = String::new();
    access_child
        .stdout()
        .expect("captured probe stdout")
        .read_to_string(&mut access_stdout)
        .expect("read probe stdout");
    let mut access_stderr = String::new();
    access_child
        .stderr()
        .expect("captured probe stderr")
        .read_to_string(&mut access_stderr)
        .expect("read probe stderr");
    let access_status = access_child.wait().expect("wait for denied-read probe");
    assert!(
        access_status.success(),
        "outside read probe failed with {access_status}: {access_stderr}"
    );
    assert_eq!(access_stdout, "denied");

    let descendant_ready = workspace.path().join("descendant-ready.txt");
    let descendant_marker = workspace.path().join("descendant-escaped.txt");
    let environment = EnvironmentSpec::inherit_core()
        .with_var("CAGEFORGE_DESCENDANT_READY", descendant_ready.as_os_str())
        .expect("descendant readiness environment")
        .with_var("CAGEFORGE_DESCENDANT_MARKER", descendant_marker.as_os_str())
        .expect("descendant marker environment");
    let descendant_probe = CommandSpec::new(&powershell)
        .expect("PowerShell command")
        .with_args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "$program = Join-Path $PSHOME 'powershell.exe'; $script = '[IO.File]::WriteAllText($env:CAGEFORGE_DESCENDANT_READY, ''ready''); Start-Sleep -Seconds 2; [IO.File]::WriteAllText($env:CAGEFORGE_DESCENDANT_MARKER, ''escaped'')'; $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script)); $descendant = Start-Process -FilePath $program -ArgumentList \"-NoLogo -NoProfile -NonInteractive -EncodedCommand $encoded\" -PassThru; $deadline = [DateTime]::UtcNow.AddSeconds(10); while (-not [IO.File]::Exists($env:CAGEFORGE_DESCENDANT_READY) -and -not $descendant.HasExited -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 10 }; if (-not [IO.File]::Exists($env:CAGEFORGE_DESCENDANT_READY)) { exit 93 }",
        ])
        .expect("PowerShell descendant arguments");
    let (command, effective, context) =
        restricted_request_with_environment(workspace.path(), descendant_probe, environment);
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &context)
        .expect("prepare descendant probe");
    let mut descendant_child = backend
        .spawn(prepared)
        .expect("spawn descendant lifecycle probe");
    let status = descendant_child
        .wait()
        .expect("wait for root process and complete Job Object");
    assert!(status.success(), "descendant probe root failed: {status}");
    assert!(
        descendant_ready.is_file(),
        "descendant did not reach the pre-exit synchronization point"
    );
    std::thread::sleep(Duration::from_secs(3));
    assert!(
        !descendant_marker.exists(),
        "a descendant survived the completed WindowsChild boundary"
    );

    let command = CommandSpec::new(&powershell)
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
    let active_capability_state =
        fs::read(&capability_state).expect("read state before rejected install");
    assert!(matches!(
        setup
            .install()
            .expect_err("active child must exclude setup reconciliation"),
        WindowsSetupError::ActiveSandboxes
    ));
    assert_eq!(
        fs::read(&capability_state).expect("read state after rejected install"),
        active_capability_state,
        "rejected setup reconciliation must not rewrite capability state"
    );

    child.kill().expect("terminate complete sandbox job");
    let _ = child.wait().expect("reap terminated sandbox job");

    let timeout_backend = WindowsBackend::new(
        WindowsBackendConfig::new()
            .with_setup(setup.config().clone())
            .with_default_timeout(Duration::from_millis(100))
            .expect("non-zero timeout"),
    )
    .expect("timeout backend");
    let timeout_command = CommandSpec::new(&powershell)
        .expect("PowerShell command")
        .with_args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Start-Sleep -Seconds 30",
        ])
        .expect("PowerShell arguments");
    let (timeout_command, timeout_effective, timeout_context) =
        restricted_request(workspace.path(), timeout_command);
    let timeout_prepared = timeout_backend
        .prepare(
            BackendRequest::new(&timeout_command, &timeout_effective),
            &timeout_context,
        )
        .expect("prepare timed launch");
    let mut timeout_child = timeout_backend
        .spawn(timeout_prepared)
        .expect("spawn timed child");
    assert!(matches!(
        timeout_child.wait(),
        Err(WindowsBackendError::ProcessTimedOut)
    ));

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
    setup
        .uninstall()
        .expect("uninstalling absent setup is a no-op");
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
