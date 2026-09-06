// SPDX-License-Identifier: Apache-2.0

#![cfg(target_os = "macos")]

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use cageforge_backend_api::{BackendRequest, SandboxBackend};
use cageforge_command::{CommandRequest, CommandSpec, EnvironmentSpec};
use cageforge_macos::{MacosBackend, MacosBackendConfig, MacosBackendError};
use cageforge_policy::{
    AccessMode, FilesystemPolicy, FilesystemRule, NetworkPolicy, PathResolutionContext,
    PathSelector, SandboxPolicy,
};
use cageforge_policy_compose::{CompositionRequest, PolicyCeiling, compose};
use tempfile::TempDir;

fn context(workspace: &Path) -> PathResolutionContext {
    PathResolutionContext::new()
        .with_root(PathBuf::from("/"))
        .expect("root")
        .with_workspace_root(workspace.to_path_buf())
        .expect("workspace")
        .with_minimal_path(PathBuf::from("/bin"))
        .expect("bin")
        .with_minimal_path(PathBuf::from("/usr"))
        .expect("usr")
        .with_minimal_path(PathBuf::from("/lib"))
        .expect("lib")
        .with_minimal_path(PathBuf::from("/usr/lib"))
        .expect("usr lib")
        .with_tmpdir(PathBuf::from("/tmp"))
        .expect("tmpdir")
        .with_slash_tmp(PathBuf::from("/tmp"))
        .expect("slash tmp")
        .with_current_directory(workspace.to_path_buf())
        .expect("cwd")
}

fn backend() -> MacosBackend {
    MacosBackend::new(MacosBackendConfig::new()).expect("macOS Seatbelt is available")
}

fn restricted_policy(workspace: &Path) -> SandboxPolicy {
    SandboxPolicy::new(
        FilesystemPolicy::restricted([
            FilesystemRule::new(
                PathSelector::absolute(workspace.to_path_buf()).expect("workspace selector"),
                AccessMode::Read,
            ),
            FilesystemRule::new(PathSelector::minimal(), AccessMode::Read),
        ]),
        NetworkPolicy::disabled(),
    )
}

fn request_for(
    workspace: &Path,
    policy: &SandboxPolicy,
    command: CommandSpec,
) -> (
    CommandRequest,
    cageforge_policy_compose::EffectiveSandbox,
    PathResolutionContext,
) {
    let environment = EnvironmentSpec::inherit_core();
    let ceiling = PolicyCeiling::new(SandboxPolicy::full_access(), environment.clone());
    let effective =
        compose(CompositionRequest::new(policy, &environment, &ceiling)).expect("compose policy");
    let command = CommandRequest::new(command)
        .with_working_directory(workspace.to_path_buf())
        .expect("working directory")
        .with_environment(environment);
    (command, effective, context(workspace))
}

fn cat_command(path: &Path) -> CommandSpec {
    CommandSpec::new("/bin/cat")
        .expect("cat")
        .with_arg(path.as_os_str())
        .expect("cat argument")
}

#[test]
fn backend_is_send_sync_and_reusable_for_independent_instances() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Arc<MacosBackend>>();
    let backend = backend();
    assert!(
        backend
            .capabilities()
            .supports(cageforge_backend_api::BackendCapability::CommandExecution)
    );
}

#[test]
fn restricted_command_reads_its_workspace() {
    let workspace = TempDir::new().expect("workspace");
    let file = workspace.path().join("input.txt");
    fs::write(&file, "workspace-data").expect("fixture");
    let policy = restricted_policy(workspace.path());
    let (command, effective, context) = request_for(workspace.path(), &policy, cat_command(&file));
    let backend = backend();
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &context)
        .expect("prepare");
    let mut child = backend.spawn(prepared).expect("spawn");
    let mut output = String::new();
    child
        .stdout()
        .expect("stdout pipe")
        .read_to_string(&mut output)
        .expect("read stdout");
    let mut error = String::new();
    child
        .stderr()
        .expect("stderr pipe")
        .read_to_string(&mut error)
        .expect("read stderr");
    let status = child.wait().expect("wait");
    assert!(status.success(), "{status:?}; stderr: {error}");
    assert_eq!(output, "workspace-data");
}

#[test]
fn restricted_command_cannot_read_outside_its_workspace() {
    let workspace = TempDir::new().expect("workspace");
    let outside = Path::new("/etc/hosts");
    let policy = restricted_policy(workspace.path());
    let (command, effective, context) =
        request_for(workspace.path(), &policy, cat_command(outside));
    let backend = backend();
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &context)
        .expect("prepare");
    let mut child = backend.spawn(prepared).expect("spawn");
    let mut error = String::new();
    child
        .stderr()
        .expect("stderr pipe")
        .read_to_string(&mut error)
        .expect("read stderr");
    let status = child.wait().expect("wait");
    assert!(
        !status.success(),
        "outside read unexpectedly succeeded: {status:?}; stderr: {error}"
    );
}

#[test]
fn simultaneous_instances_keep_separate_filesystem_scopes() {
    let first_workspace = TempDir::new().expect("first workspace");
    let second_workspace = TempDir::new().expect("second workspace");
    let first_file = first_workspace.path().join("value");
    let second_file = second_workspace.path().join("value");
    fs::write(&first_file, "first").expect("first fixture");
    fs::write(&second_file, "second").expect("second fixture");

    let first_policy = restricted_policy(first_workspace.path());
    let second_policy = restricted_policy(second_workspace.path());
    let (first_command, first_effective, first_context) = request_for(
        first_workspace.path(),
        &first_policy,
        cat_command(&first_file),
    );
    let (second_command, second_effective, second_context) = request_for(
        second_workspace.path(),
        &second_policy,
        cat_command(&second_file),
    );
    let backend = backend();
    let first = backend
        .prepare(
            BackendRequest::new(&first_command, &first_effective),
            &first_context,
        )
        .expect("first prepare");
    let second = backend
        .prepare(
            BackendRequest::new(&second_command, &second_effective),
            &second_context,
        )
        .expect("second prepare");
    let mut first = backend.spawn(first).expect("first spawn");
    let mut second = backend.spawn(second).expect("second spawn");
    let mut first_output = String::new();
    let mut second_output = String::new();
    first
        .stdout()
        .expect("first stdout")
        .read_to_string(&mut first_output)
        .expect("first output");
    second
        .stdout()
        .expect("second stdout")
        .read_to_string(&mut second_output)
        .expect("second output");
    let mut first_error = String::new();
    first
        .stderr()
        .expect("first stderr")
        .read_to_string(&mut first_error)
        .expect("first error");
    let mut second_error = String::new();
    second
        .stderr()
        .expect("second stderr")
        .read_to_string(&mut second_error)
        .expect("second error");
    let first_status = first.wait().expect("first wait");
    let second_status = second.wait().expect("second wait");
    assert!(
        first_status.success(),
        "{first_status:?}; stderr: {first_error}"
    );
    assert!(
        second_status.success(),
        "{second_status:?}; stderr: {second_error}"
    );
    assert_eq!(first_output, "first");
    assert_eq!(second_output, "second");
}

#[test]
fn missing_seatbelt_executable_is_typed() {
    let error = MacosBackend::new(
        MacosBackendConfig::new()
            .with_seatbelt_executable("/definitely/missing/sandbox-exec")
            .expect("absolute path"),
    )
    .expect_err("missing executable");
    assert!(matches!(
        error,
        MacosBackendError::SeatbeltExecutable { .. }
    ));
}
