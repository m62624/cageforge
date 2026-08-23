// SPDX-License-Identifier: Apache-2.0

#![cfg(target_os = "linux")]

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use cageforge_backend_api::{
    BackendCapability, BackendContractError, BackendRequest, SandboxBackend,
};
use cageforge_command::{CommandRequest, CommandSpec, EnvironmentSpec, StdioSpec};
use cageforge_linux::{LinuxBackend, LinuxBackendConfig, LinuxBackendError};
use cageforge_policy::{
    AccessMode, FilesystemPolicy, FilesystemRule, NetworkPolicy, PathResolutionContext,
    PathSelector, SandboxPolicy,
};
use cageforge_policy_compose::{CompositionRequest, PolicyCeiling, compose};
use pretty_assertions::assert_eq;
use tempfile::TempDir;

fn backend() -> LinuxBackend {
    LinuxBackend::new(
        LinuxBackendConfig::new()
            .with_hardening_helper_path(env!("CARGO_BIN_EXE_cageforge-linux-helper")),
    )
    .expect("Linux CI requires usable Bubblewrap and hardening helper")
}

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
        .with_minimal_path(PathBuf::from("/lib64"))
        .expect("lib64")
        .with_tmpdir(PathBuf::from("/tmp"))
        .expect("tmpdir")
        .with_slash_tmp(PathBuf::from("/tmp"))
        .expect("slash tmp")
        .with_current_directory(workspace.to_path_buf())
        .expect("cwd")
}

fn request(
    workspace: &Path,
    policy: SandboxPolicy,
    command: CommandSpec,
) -> (
    CommandRequest,
    cageforge_policy_compose::EffectiveSandbox,
    PathResolutionContext,
) {
    let environment = EnvironmentSpec::inherit_all();
    let ceiling = PolicyCeiling::new(SandboxPolicy::full_access(), environment.clone());
    let effective = compose(CompositionRequest::new(&policy, &environment, &ceiling))
        .expect("policies compose");
    let command = CommandRequest::new(command)
        .with_working_directory(workspace.to_path_buf())
        .expect("cwd")
        .with_environment(environment);
    (command, effective, context(workspace))
}

#[test]
fn workspace_write_and_protected_git_are_enforced_by_bwrap() {
    let temp = TempDir::new().expect("temporary workspace");
    let workspace = temp.path();
    std::fs::create_dir(workspace.join(".git")).expect("git directory");
    let output_path = workspace.join("created.txt");
    let git_path = workspace.join(".git").join("created");
    let script = format!(
        "printf allowed > {}; if printf forbidden > {}; then exit 17; else exit 0; fi",
        output_path.display(),
        git_path.display()
    );
    let command = CommandSpec::new("/bin/sh")
        .expect("shell")
        .with_args(["-c", script.as_str()])
        .expect("arguments");
    let (command, effective, runtime) = request(workspace, SandboxPolicy::workspace(), command);
    let backend = backend();
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &runtime)
        .expect("preflight");
    let mut child = backend.spawn(prepared).expect("spawn");
    let mut stderr = Vec::new();
    child
        .stderr()
        .expect("captured stderr")
        .read_to_end(&mut stderr)
        .expect("read stderr");
    let status = child.wait().expect("wait");

    assert_eq!(
        status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&stderr)
    );
    assert_eq!(
        std::fs::read_to_string(output_path).expect("workspace write"),
        "allowed"
    );
    assert!(!git_path.exists(), "protected .git path was created");
}

#[test]
fn denied_existing_file_cannot_be_read() {
    let temp = TempDir::new().expect("temporary workspace");
    let denied = temp.path().join("secret.txt");
    std::fs::write(&denied, "secret").expect("denied fixture");
    let policy = SandboxPolicy::new(
        FilesystemPolicy::restricted([
            FilesystemRule::new(PathSelector::root(), AccessMode::Read),
            FilesystemRule::new(PathSelector::minimal(), AccessMode::Read),
            FilesystemRule::new(PathSelector::workspace_root(), AccessMode::Write),
            FilesystemRule::new(
                PathSelector::workspace("secret.txt").expect("secret selector"),
                AccessMode::Deny,
            ),
        ]),
        NetworkPolicy::disabled(),
    );
    let command = CommandSpec::new("/bin/sh")
        .expect("shell")
        .with_args([
            "-c",
            &format!(
                "if cat {} >/dev/null 2>/dev/null; then exit 17; else exit 0; fi",
                denied.display()
            ),
        ])
        .expect("arguments");
    let (command, effective, runtime) = request(temp.path(), policy, command);
    let backend = backend();
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &runtime)
        .expect("preflight");
    let mut child = backend.spawn(prepared).expect("spawn");
    let status = child.wait().expect("wait");
    assert_eq!(status.code(), Some(0));
    assert_eq!(
        std::fs::read_to_string(denied).expect("host fixture"),
        "secret"
    );
}

#[test]
fn ordinary_bin_true_is_not_reserved_by_the_backend() {
    let temp = TempDir::new().expect("temporary workspace");
    let command = CommandSpec::new("/bin/true").expect("command");
    let (command, effective, runtime) = request(temp.path(), SandboxPolicy::workspace(), command);
    let backend = backend();
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &runtime)
        .expect("preflight");
    let mut child = backend.spawn(prepared).expect("spawn");
    assert_eq!(child.wait().expect("wait").code(), Some(0));
}

#[test]
fn hardening_helper_rejects_direct_invocation_without_backend_authentication() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_cageforge-linux-helper"))
        .args(["--apply-hardening", "/bin/true"])
        .output()
        .expect("helper");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid Linux hardening helper"));
}

#[cfg(target_os = "linux")]
#[test]
fn read_only_symlink_masks_fail_closed_before_launch() {
    let temp = TempDir::new().expect("temporary workspace");
    let outside = TempDir::new_in("/var/tmp").expect("outside directory");
    let link = temp.path().join("protected");
    std::os::unix::fs::symlink(outside.path(), &link).expect("symlink fixture");
    let rule = FilesystemRule::new(PathSelector::workspace_root(), AccessMode::Write)
        .with_read_only_subpath(PathSelector::workspace("protected").expect("selector"))
        .expect("carveout");
    let policy = SandboxPolicy::new(
        FilesystemPolicy::restricted([
            FilesystemRule::new(PathSelector::root(), AccessMode::Read),
            FilesystemRule::new(PathSelector::minimal(), AccessMode::Read),
            rule,
        ]),
        NetworkPolicy::disabled(),
    );
    let command = CommandSpec::new("/bin/true").expect("command");
    let (command, effective, runtime) = request(temp.path(), policy, command);
    let backend = backend();
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &runtime)
        .expect("preflight");
    let error = match backend.spawn(prepared) {
        Ok(_) => panic!("symlink read-only mask must fail closed"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        LinuxBackendError::FilesystemLoweringFailed { .. }
    ));
}

#[test]
fn unsupported_glob_is_rejected_before_launch() {
    let temp = TempDir::new().expect("temporary workspace");
    let rule = FilesystemRule::workspace_glob("secret/**", AccessMode::Deny).expect("glob");
    let policy = SandboxPolicy::new(
        FilesystemPolicy::restricted([rule]),
        NetworkPolicy::disabled(),
    );
    let command = CommandSpec::new("/bin/true").expect("command");
    let (command, effective, runtime) = request(temp.path(), policy, command);
    let command = command.with_stdio(StdioSpec::captured());
    let backend = backend();

    let error = backend
        .prepare(BackendRequest::new(&command, &effective), &runtime)
        .expect_err("glob must not be silently ignored");
    assert!(matches!(
        error,
        LinuxBackendError::Contract(BackendContractError::UnsupportedCapability {
            capability: BackendCapability::FilesystemGlobs,
        })
    ));
}

#[test]
fn reserved_dev_mounts_fail_closed_before_launch() {
    let temp = TempDir::new().expect("temporary workspace");
    let policy = SandboxPolicy::new(
        FilesystemPolicy::restricted([
            FilesystemRule::new(PathSelector::root(), AccessMode::Read),
            FilesystemRule::new(PathSelector::minimal(), AccessMode::Read),
            FilesystemRule::new(PathSelector::workspace_root(), AccessMode::Write),
            FilesystemRule::new(
                PathSelector::absolute("/dev/shm").expect("dev shm selector"),
                AccessMode::Write,
            ),
        ]),
        NetworkPolicy::disabled(),
    );
    let command = CommandSpec::new("/bin/true").expect("command");
    let (command, effective, runtime) = request(temp.path(), policy, command);
    let backend = backend();
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &runtime)
        .expect("preflight");
    let error = match backend.spawn(prepared) {
        Ok(_) => panic!("reserved runtime path must be rejected"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        LinuxBackendError::FilesystemLoweringFailed { path, .. }
            if path == Path::new("/dev/shm")
    ));
}

#[test]
fn reserved_proc_mounts_fail_closed_before_launch() {
    let temp = TempDir::new().expect("temporary workspace");
    let policy = SandboxPolicy::new(
        FilesystemPolicy::restricted([
            FilesystemRule::new(PathSelector::root(), AccessMode::Read),
            FilesystemRule::new(PathSelector::minimal(), AccessMode::Read),
            FilesystemRule::new(PathSelector::workspace_root(), AccessMode::Write),
            FilesystemRule::new(
                PathSelector::absolute("/proc").expect("proc selector"),
                AccessMode::Deny,
            ),
        ]),
        NetworkPolicy::disabled(),
    );
    let command = CommandSpec::new("/bin/true").expect("command");
    let (command, effective, runtime) = request(temp.path(), policy, command);
    let backend = backend();
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &runtime)
        .expect("preflight");
    let error = match backend.spawn(prepared) {
        Ok(_) => panic!("reserved proc path must be rejected"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        LinuxBackendError::FilesystemLoweringFailed { path, .. }
            if path == Path::new("/proc")
    ));
}

#[test]
fn local_network_restriction_is_rejected_without_exact_runtime_authorization() {
    let temp = TempDir::new().expect("temporary workspace");
    let policy = SandboxPolicy::new(FilesystemPolicy::unrestricted(), NetworkPolicy::enabled());
    let command = CommandSpec::new("/bin/true").expect("command");
    let (command, effective, runtime) = request(temp.path(), policy, command);
    let backend = backend();

    let error = backend
        .prepare(BackendRequest::new(&command, &effective), &runtime)
        .expect_err("local network policy needs exact authorization");
    assert!(matches!(
        error,
        LinuxBackendError::Contract(BackendContractError::UnsupportedCapability {
            capability: BackendCapability::NetworkLocalAddressRestrictions,
        })
    ));
}

#[test]
fn unrestricted_network_does_not_require_dns_authorization_capability() {
    let backend = backend();
    assert!(
        backend
            .capabilities()
            .supports(BackendCapability::NetworkEnabled)
    );
    assert!(
        !backend
            .capabilities()
            .supports(BackendCapability::NetworkResolvedTargets)
    );
}

#[test]
fn restricted_child_has_no_new_privs() {
    let temp = TempDir::new().expect("temporary workspace");
    let command = CommandSpec::new("/bin/sh")
        .expect("shell")
        .with_args([
            "-c",
            "while IFS= read line; do case \"$line\" in NoNewPrivs:*) set -- $line; printf \"%s\\n\" \"$2\";; esac; done < /proc/self/status",
        ])
        .expect("arguments");
    let (command, effective, runtime) = request(temp.path(), SandboxPolicy::workspace(), command);
    let command = command.with_stdio(StdioSpec::captured());
    let backend = backend();
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &runtime)
        .expect("preflight");
    let mut child = backend.spawn(prepared).expect("spawn");
    let mut stdout = String::new();
    let mut stderr = String::new();
    child
        .stdout()
        .expect("captured stdout")
        .read_to_string(&mut stdout)
        .expect("read stdout");
    child
        .stderr()
        .expect("captured stderr")
        .read_to_string(&mut stderr)
        .expect("read stderr");
    let status = child.wait().expect("wait");
    assert_eq!(
        status.code(),
        Some(0),
        "stdout: {stdout:?}, stderr: {stderr:?}"
    );
    assert_eq!(stdout.trim(), "1");
}

#[test]
fn timeout_kills_the_bubblewrap_boundary_and_reports_typed_error() {
    let temp = TempDir::new().expect("temporary workspace");
    let command = CommandSpec::new("/bin/sh")
        .expect("shell")
        .with_args(["-c", "sleep 2"])
        .expect("arguments");
    let (command, effective, runtime) = request(temp.path(), SandboxPolicy::workspace(), command);
    let command = command.with_timeout(Duration::from_millis(50));
    let backend = backend();
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &runtime)
        .expect("preflight");
    let mut child = backend.spawn(prepared).expect("spawn");
    let error = child
        .wait_with_timeout()
        .expect_err("sleep must exceed the configured timeout");
    assert!(matches!(error, LinuxBackendError::ProcessTimedOut));
    assert!(child.try_wait().expect("reaped child").is_some());
}

#[test]
fn dropping_a_running_child_terminates_the_boundary() {
    let temp = TempDir::new().expect("temporary workspace");
    let command = CommandSpec::new("/bin/sh")
        .expect("shell")
        .with_args(["-c", "sleep 30"])
        .expect("arguments");
    let (command, effective, runtime) = request(temp.path(), SandboxPolicy::workspace(), command);
    let backend = backend();
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &runtime)
        .expect("preflight");
    let child = backend.spawn(prepared).expect("spawn");
    let pid = child.id();
    drop(child);

    for _ in 0..100 {
        #[allow(unsafe_code)]
        let result = unsafe { libc::kill(pid as libc::pid_t, 0) };
        if result == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
            return;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    panic!("dropped sandbox boundary is still alive: {pid}");
}

#[test]
fn read_only_carveout_remains_read_only_under_workspace_write() {
    let temp = TempDir::new().expect("temporary workspace");
    let readonly = temp.path().join("readonly.txt");
    std::fs::write(&readonly, "original").expect("readonly fixture");
    let rule = FilesystemRule::new(PathSelector::workspace_root(), AccessMode::Write)
        .with_read_only_subpath(PathSelector::workspace("readonly.txt").expect("selector"))
        .expect("carveout");
    let policy = SandboxPolicy::new(
        FilesystemPolicy::restricted([
            FilesystemRule::new(PathSelector::root(), AccessMode::Read),
            FilesystemRule::new(PathSelector::minimal(), AccessMode::Read),
            rule,
        ]),
        NetworkPolicy::disabled(),
    );
    let command = CommandSpec::new("/bin/sh")
        .expect("shell")
        .with_args([
            "-c",
            &format!(
                "if printf changed > {}; then exit 17; else exit 0; fi",
                readonly.display()
            ),
        ])
        .expect("arguments");
    let (command, effective, runtime) = request(temp.path(), policy, command);
    let backend = backend();
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &runtime)
        .expect("preflight");
    let mut child = backend.spawn(prepared).expect("spawn");
    let mut stderr = String::new();
    child
        .stderr()
        .expect("captured stderr")
        .read_to_string(&mut stderr)
        .expect("read stderr");
    let status = child.wait().expect("wait");
    assert_eq!(status.code(), Some(0), "stderr: {stderr:?}");
    assert_eq!(
        std::fs::read_to_string(readonly).expect("read fixture"),
        "original"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn symlink_inside_workspace_cannot_escape_the_mounted_root() {
    let temp = TempDir::new().expect("temporary workspace");
    let outside = TempDir::new_in("/var/tmp").expect("outside directory");
    let link = temp.path().join("escape");
    std::os::unix::fs::symlink(outside.path(), &link).expect("symlink");
    let escaped = outside.path().join("escaped.txt");
    let command = CommandSpec::new("/bin/sh")
        .expect("shell")
        .with_args([
            "-c",
            &format!(
                "if printf escaped > {}; then exit 17; else exit 0; fi",
                temp.path().join("escape/escaped.txt").display()
            ),
        ])
        .expect("arguments");
    let (command, effective, runtime) = request(temp.path(), SandboxPolicy::workspace(), command);
    let backend = backend();
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &runtime)
        .expect("preflight");
    let mut child = backend.spawn(prepared).expect("spawn");
    let mut stderr = String::new();
    child
        .stderr()
        .expect("captured stderr")
        .read_to_string(&mut stderr)
        .expect("read stderr");
    let status = child.wait().expect("wait");
    assert_eq!(status.code(), Some(0), "stderr: {stderr:?}");
    assert!(!escaped.exists(), "symlink escaped the workspace mount");
}
