// SPDX-License-Identifier: Apache-2.0

#![cfg(target_os = "windows")]

use std::ffi::c_void;
use std::fs;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

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
use sha2::{Digest, Sha256};
use windows_sys::Win32::Foundation::{GetLastError, INVALID_HANDLE_VALUE, STILL_ACTIVE};
use windows_sys::Win32::System::Diagnostics::Debug::{
    CloseThreadWaitChainSession, GetThreadWaitChain, OpenThreadWaitChainSession,
    WAITCHAIN_NODE_INFO, WCT_MAX_NODE_COUNT, WCT_OUT_OF_PROC_COM_FLAG, WCT_OUT_OF_PROC_CS_FLAG,
    WCT_OUT_OF_PROC_FLAG, WctThreadType,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
};
use windows_sys::Win32::System::Threading::{
    GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
};

const SANDBOX_FIXTURE_MODE: &str = "CAGEFORGE_WINDOWS_SANDBOX_FIXTURE_MODE";
const SANDBOX_FIXTURE_READY: &str = "CAGEFORGE_WINDOWS_SANDBOX_FIXTURE_READY";
const SANDBOX_FIXTURE_MARKER: &str = "CAGEFORGE_WINDOWS_SANDBOX_FIXTURE_MARKER";
const SANDBOX_FIXTURE_DENIED_READ: &str = "CAGEFORGE_WINDOWS_SANDBOX_FIXTURE_DENIED_READ";
const SANDBOX_FIXTURE_DENIED_WRITE: &str = "CAGEFORGE_WINDOWS_SANDBOX_FIXTURE_DENIED_WRITE";
const SANDBOX_FIXTURE_PROGRESS: &str = "CAGEFORGE_WINDOWS_SANDBOX_FIXTURE_PROGRESS";
const END_TO_END_PROBE_TIMEOUT: Duration = Duration::from_secs(15);
const FIXTURE_START_DEADLINE: Duration = Duration::from_secs(5);

struct SetupCleanup<'a> {
    setup: &'a WindowsSetup,
    armed: bool,
}

struct WaitChainSession(*mut c_void);

impl Drop for SetupCleanup<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.setup.uninstall();
        }
    }
}

#[allow(unsafe_code)]
impl Drop for WaitChainSession {
    fn drop(&mut self) {
        unsafe { CloseThreadWaitChainSession(self.0) };
    }
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
    let minimal = workspace.join(".cageforge-test-runtime");
    fs::create_dir_all(&minimal).expect("minimal runtime fixture directory");
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
    let context = PathResolutionContext::new()
        .with_workspace_root(workspace.to_path_buf())
        .expect("workspace root")
        .with_minimal_path(minimal)
        .expect("minimal runtime fixture directory")
        .with_current_directory(workspace.to_path_buf())
        .expect("current directory");
    let command = CommandRequest::new(command)
        .with_working_directory(workspace.to_path_buf())
        .expect("working directory")
        .with_environment(environment);
    (command, effective, context)
}

fn fixture_command(path: &Path) -> CommandSpec {
    CommandSpec::new(path)
        .expect("sandbox fixture command")
        .with_args(["--exact", "sandbox_process_fixture", "--nocapture"])
        .expect("sandbox fixture arguments")
}

fn access_fixture_command(path: &Path) -> CommandSpec {
    CommandSpec::new(path).expect("denied-read fixture command")
}

fn acl_diagnostic(path: &Path) -> String {
    match Command::new("icacls").arg(path).output() {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).into_owned()
        }
        Ok(output) => format!(
            "icacls exited with {}; stderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ),
        Err(error) => format!("could not run icacls: {error}"),
    }
}

fn raw_acl_diagnostic(path: &Path) -> String {
    let literal_path = path.to_string_lossy().replace('\'', "''");
    let script = format!(
        "$descriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new((Get-Acl -LiteralPath '{literal_path}').GetSecurityDescriptorBinaryForm(), 0); $descriptor.DiscretionaryAcl | ForEach-Object {{ \"type=$($_.AceType) flags=$([int]$_.AceFlags) mask=$($_.AccessMask) sid=$($_.SecurityIdentifier.Value)\" }}"
    );
    match Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
    {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).into_owned()
        }
        Ok(output) => format!(
            "raw ACL inspection failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ),
        Err(error) => format!("could not run raw ACL inspection: {error}"),
    }
}

fn raw_dacl_fingerprint(path: &Path) -> String {
    let literal_path = path.to_string_lossy().replace('\'', "''");
    let script = format!(
        "$descriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new((Get-Acl -LiteralPath '{literal_path}').GetSecurityDescriptorBinaryForm(), 0); $bytes = New-Object byte[] $descriptor.DiscretionaryAcl.BinaryLength; $descriptor.DiscretionaryAcl.GetBinaryForm($bytes, 0); $hasher = [System.Security.Cryptography.SHA256]::Create(); try {{ $hash = $hasher.ComputeHash($bytes) }} finally {{ $hasher.Dispose() }}; \"bytes=$($bytes.Length) sha256=$([BitConverter]::ToString($hash).Replace('-', '').ToLowerInvariant())\""
    );
    match Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
    {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).trim().to_string()
        }
        Ok(output) => format!(
            "raw DACL fingerprint failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ),
        Err(error) => format!("could not fingerprint raw DACL: {error}"),
    }
}

fn filesystem_authority_diagnostic(capability_state: &Path, group_sid: &str) -> String {
    let state = match fs::read(capability_state)
        .map_err(|error| error.to_string())
        .and_then(|bytes| {
            serde_json::from_slice::<serde_json::Value>(&bytes).map_err(|error| error.to_string())
        }) {
        Ok(state) => state,
        Err(error) => return format!("could not read filesystem authorities: {error}"),
    };
    let namespace_sid = state
        .get("namespace_sid")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("<missing>");
    let entries = state
        .get("entries")
        .and_then(serde_json::Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .map(|entry| {
                    let role = entry
                        .get("role")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("<missing>");
                    let path = entry
                        .get("path")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("<missing>");
                    let sid = entry
                        .get("sid")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("<missing>");
                    format!("{role}:{path}:{sid}")
                })
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_else(|| "<missing>".to_string());
    let acl_objects = state
        .get("acl_objects")
        .and_then(serde_json::Value::as_array)
        .map(|objects| {
            objects
                .iter()
                .map(|object| {
                    let path = object
                        .get("path")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("<missing>");
                    let original = object
                        .get("original")
                        .map(dacl_state_fingerprint)
                        .unwrap_or_else(|| "<missing>".to_string());
                    let current = object
                        .get("current")
                        .map(dacl_state_fingerprint)
                        .unwrap_or_else(|| "<missing>".to_string());
                    format!("{path}:original={original},current={current}")
                })
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_else(|| "<missing>".to_string());
    format!(
        "group={group_sid}; read_base={namespace_sid}-1; capabilities=[{entries}]; acl_objects=[{acl_objects}]"
    )
}

fn dacl_state_fingerprint(descriptor: &serde_json::Value) -> String {
    let Some(bytes) = descriptor
        .get("bytes")
        .and_then(serde_json::Value::as_array)
        .and_then(|bytes| {
            bytes
                .iter()
                .map(|value| value.as_u64().and_then(|value| u8::try_from(value).ok()))
                .collect::<Option<Vec<_>>>()
        })
    else {
        return "<invalid>".to_string();
    };
    let digest = Sha256::digest(&bytes);
    let sha256 = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let protected = descriptor
        .get("protected")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    format!(
        "protected={protected} bytes={} sha256={sha256}",
        bytes.len()
    )
}

#[allow(unsafe_code)]
fn process_exit_code(process_id: u32) -> Result<Option<u32>, u32> {
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if handle.is_null() {
        return Err(unsafe { GetLastError() });
    }
    let handle = unsafe { OwnedHandle::from_raw_handle(handle as RawHandle) };
    let mut exit_code = 0;
    if unsafe { GetExitCodeProcess(handle.as_raw_handle() as _, &mut exit_code) } == 0 {
        return Err(unsafe { GetLastError() });
    }
    Ok((exit_code != STILL_ACTIVE as u32).then_some(exit_code))
}

fn wait_for_fixture_exit(process_id: u32) -> Result<u32, String> {
    let deadline = Instant::now() + FIXTURE_START_DEADLINE;
    loop {
        match process_exit_code(process_id) {
            Ok(Some(exit_code)) => return Ok(exit_code),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            Ok(None) => return Err("the process remained active".to_string()),
            Err(code) => return Err(format!("failed to query the process: Windows error {code}")),
        }
    }
}

#[allow(unsafe_code)]
fn describe_wait_chain_node(node: WAITCHAIN_NODE_INFO) -> String {
    if node.ObjectType == WctThreadType {
        let thread = unsafe { node.Anonymous.ThreadObject };
        return format!(
            "{}:{}(process={}, thread={}, wait_ms={}, context_switches={})",
            node.ObjectType,
            node.ObjectStatus,
            thread.ProcessId,
            thread.ThreadId,
            thread.WaitTime,
            thread.ContextSwitches,
        );
    }
    let lock = unsafe { node.Anonymous.LockObject };
    let name = String::from_utf16_lossy(&lock.ObjectName);
    let name = name
        .split_once('\0')
        .map_or(name.as_str(), |(name, _)| name);
    format!(
        "{}:{}(name={name:?}, timeout={}, alertable={})",
        node.ObjectType, node.ObjectStatus, lock.Timeout, lock.Alertable
    )
}

#[allow(unsafe_code)]
fn fixture_wait_chains(process_id: u32) -> Result<String, String> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(format!(
            "failed to snapshot process threads: Windows error {}",
            unsafe { GetLastError() }
        ));
    }
    let snapshot = unsafe { OwnedHandle::from_raw_handle(snapshot as RawHandle) };
    let session = unsafe { OpenThreadWaitChainSession(0, None) };
    if session.is_null() {
        return Err(format!(
            "failed to open a wait-chain session: Windows error {}",
            unsafe { GetLastError() }
        ));
    }
    let session = WaitChainSession(session);
    let mut entry = THREADENTRY32 {
        dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
        ..Default::default()
    };
    if unsafe { Thread32First(snapshot.as_raw_handle() as _, &mut entry) } == 0 {
        return Err(format!(
            "failed to read the first process thread: Windows error {}",
            unsafe { GetLastError() }
        ));
    }
    let mut chains = Vec::new();
    loop {
        if entry.th32OwnerProcessID == process_id {
            let mut nodes = [WAITCHAIN_NODE_INFO::default(); WCT_MAX_NODE_COUNT as usize];
            let mut node_count = WCT_MAX_NODE_COUNT;
            let mut cycle = 0;
            if unsafe {
                GetThreadWaitChain(
                    session.0,
                    0,
                    WCT_OUT_OF_PROC_FLAG | WCT_OUT_OF_PROC_COM_FLAG | WCT_OUT_OF_PROC_CS_FLAG,
                    entry.th32ThreadID,
                    &mut node_count,
                    nodes.as_mut_ptr(),
                    &mut cycle,
                )
            } == 0
            {
                return Err(format!(
                    "failed to inspect wait chain for thread {}: Windows error {}",
                    entry.th32ThreadID,
                    unsafe { GetLastError() }
                ));
            }
            let nodes = nodes
                .into_iter()
                .take(node_count as usize)
                .map(describe_wait_chain_node)
                .collect::<Vec<_>>()
                .join(" -> ");
            chains.push(format!(
                "thread {} cycle={} [{nodes}]",
                entry.th32ThreadID, cycle
            ));
        }
        entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
        if unsafe { Thread32Next(snapshot.as_raw_handle() as _, &mut entry) } == 0 {
            break;
        }
    }
    if chains.is_empty() {
        Err("the process had no visible threads".to_string())
    } else {
        Ok(chains.join("; "))
    }
}

#[test]
fn sandbox_process_fixture() {
    let Some(mode) = std::env::var_os(SANDBOX_FIXTURE_MODE) else {
        return;
    };
    match mode.to_string_lossy().as_ref() {
        "denied-read" => {
            let path = PathBuf::from(
                std::env::var_os(SANDBOX_FIXTURE_DENIED_READ).expect("denied-read fixture path"),
            );
            let progress = PathBuf::from(
                std::env::var_os(SANDBOX_FIXTURE_PROGRESS).expect("denied-read fixture progress"),
            );
            fs::write(&progress, b"before-denied-read").expect("record denied-read start");
            match fs::read(&path) {
                Ok(_) => panic!("sandbox fixture read denied host file {path:?}"),
                Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                    print!("denied");
                }
                Err(error) => panic!("sandbox fixture received unexpected read error: {error}"),
            }
            fs::write(progress, b"after-denied-read").expect("record denied-read completion");
        }
        "descendant-root" => {
            let executable = std::env::current_exe().expect("fixture executable");
            let ready = PathBuf::from(
                std::env::var_os(SANDBOX_FIXTURE_READY).expect("descendant readiness path"),
            );
            let mut descendant = Command::new(executable)
                .args(["--exact", "sandbox_process_fixture", "--nocapture"])
                .env(SANDBOX_FIXTURE_MODE, "descendant")
                .spawn()
                .expect("spawn descendant fixture");
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            while !ready.exists() && std::time::Instant::now() < deadline {
                if let Some(status) = descendant.try_wait().expect("poll descendant fixture") {
                    panic!("descendant fixture exited before becoming ready: {status}");
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            assert!(ready.is_file(), "descendant fixture did not become ready");
            // The enclosing WindowsChild Job Object must terminate this process after
            // the root fixture exits; waiting here would erase that boundary test.
            std::mem::forget(descendant);
        }
        "descendant" => {
            let ready = PathBuf::from(
                std::env::var_os(SANDBOX_FIXTURE_READY).expect("descendant readiness path"),
            );
            let marker = PathBuf::from(
                std::env::var_os(SANDBOX_FIXTURE_MARKER).expect("descendant marker path"),
            );
            fs::write(ready, b"ready").expect("write descendant readiness marker");
            std::thread::sleep(Duration::from_secs(2));
            fs::write(marker, b"escaped").expect("write descendant escape marker");
        }
        "sleep" => std::thread::sleep(Duration::from_secs(30)),
        other => panic!("unknown Windows sandbox fixture mode: {other}"),
    }
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

    let backend = WindowsBackend::new(
        WindowsBackendConfig::new()
            .with_setup(setup.config().clone())
            .with_default_timeout(END_TO_END_PROBE_TIMEOUT)
            .expect("bounded end-to-end probe timeout"),
    )
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
    let fixture = workspace.path().join("cageforge-windows-fixture.exe");
    fs::copy(
        std::env::current_exe().expect("integration-test fixture executable"),
        &fixture,
    )
    .expect("copy sandbox fixture into the writable workspace");
    let access_fixture = workspace
        .path()
        .join("cageforge-windows-access-fixture.exe");
    fs::copy(
        env!("CARGO_BIN_EXE_cageforge-windows-test-fixture"),
        &access_fixture,
    )
    .expect("copy denied-read fixture into the writable workspace");

    let outside_secret = temporary.path().join("outside-secret.txt");
    let access_progress = workspace.path().join("denied-read-progress.txt");
    let minimal_write = workspace
        .path()
        .join(".cageforge-test-runtime")
        .join("write-must-be-denied.txt");
    fs::write(&outside_secret, b"host secret").expect("outside secret fixture");
    let environment = EnvironmentSpec::inherit_core()
        .with_var(SANDBOX_FIXTURE_MODE, "denied-read")
        .expect("denied-read fixture mode")
        .with_var(SANDBOX_FIXTURE_DENIED_READ, outside_secret.as_os_str())
        .expect("denied-read fixture environment")
        .with_var(SANDBOX_FIXTURE_DENIED_WRITE, minimal_write.as_os_str())
        .expect("denied-write fixture environment")
        .with_var(SANDBOX_FIXTURE_PROGRESS, access_progress.as_os_str())
        .expect("denied-read fixture progress");
    let access_probe = access_fixture_command(&access_fixture);
    let (command, effective, context) =
        restricted_request_with_environment(workspace.path(), access_probe, environment);
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &context)
        .expect("prepare denied-read probe");
    let mut access_child = backend.spawn(prepared).expect("spawn denied-read probe");
    let fixture_exit = wait_for_fixture_exit(access_child.id()).unwrap_or_else(|detail| {
        let progress = fs::read_to_string(&access_progress).ok();
        let wait_chains = fixture_wait_chains(access_child.id());
        panic!(
            "denied-read fixture did not exit promptly: {detail}; fixture progress: {progress:?}; fixture wait chains: {wait_chains:?}"
        );
    });
    assert_eq!(fixture_exit, 0, "denied-read fixture exit status");
    let access_status = access_child.wait().unwrap_or_else(|error| {
        let progress = fs::read_to_string(&access_progress).ok();
        panic!("wait for denied-read probe: {error}; fixture progress: {progress:?}");
    });
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
    assert!(
        access_status.success(),
        "outside read probe failed with {access_status}: {access_stderr}"
    );
    assert!(
        access_stdout.contains("denied"),
        "denied-read fixture did not report its typed access result: {access_stdout}"
    );
    let workspace_acl_before_descendant = acl_diagnostic(workspace.path());
    let workspace_raw_dacl_before_descendant = raw_dacl_fingerprint(workspace.path());
    let workspace_raw_acl_before_descendant = raw_acl_diagnostic(workspace.path());
    let access_progress_acl_before_descendant = acl_diagnostic(&access_progress);
    let access_progress_raw_acl_before_descendant = raw_acl_diagnostic(&access_progress);
    let filesystem_authorities_before_descendant =
        filesystem_authority_diagnostic(&capability_state, first.accounts().group_sid());

    let descendant_ready = workspace.path().join("descendant-ready.txt");
    let descendant_marker = workspace.path().join("descendant-escaped.txt");
    let environment = EnvironmentSpec::inherit_core()
        .with_var(SANDBOX_FIXTURE_MODE, "descendant-root")
        .expect("descendant fixture mode")
        .with_var(SANDBOX_FIXTURE_READY, descendant_ready.as_os_str())
        .expect("descendant readiness environment")
        .with_var(SANDBOX_FIXTURE_MARKER, descendant_marker.as_os_str())
        .expect("descendant marker environment");
    let descendant_probe = fixture_command(&fixture);
    let (command, effective, context) =
        restricted_request_with_environment(workspace.path(), descendant_probe, environment);
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &context)
        .expect("prepare descendant probe");
    let mut descendant_child = backend.spawn(prepared).unwrap_or_else(|error| {
        panic!(
            "spawn descendant lifecycle probe: {error}; workspace ACL: {}; access fixture ACL: {}",
            acl_diagnostic(workspace.path()),
            acl_diagnostic(&access_fixture),
        );
    });
    let status = descendant_child
        .wait()
        .expect("wait for root process and complete Job Object");
    if !status.success() {
        let mut stdout = String::new();
        let mut stderr = String::new();
        descendant_child
            .stdout()
            .expect("captured descendant probe stdout")
            .read_to_string(&mut stdout)
            .expect("read descendant probe stdout");
        descendant_child
            .stderr()
            .expect("captured descendant probe stderr")
            .read_to_string(&mut stderr)
            .expect("read descendant probe stderr");
        panic!(
            "descendant probe root failed: {status}; stdout: {stdout}; stderr: {stderr}; workspace ACL: {}; fixture ACL: {}",
            acl_diagnostic(workspace.path()),
            acl_diagnostic(&fixture),
        );
    }
    assert!(
        descendant_ready.is_file(),
        "descendant did not reach the pre-exit synchronization point"
    );
    std::thread::sleep(Duration::from_secs(3));
    assert!(
        !descendant_marker.exists(),
        "a descendant survived the completed WindowsChild boundary"
    );

    let active_environment = EnvironmentSpec::inherit_core()
        .with_var(SANDBOX_FIXTURE_MODE, "sleep")
        .expect("active-child fixture mode");
    let (command, effective, context) = restricted_request_with_environment(
        workspace.path(),
        fixture_command(&fixture),
        active_environment,
    );
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
    let timeout_environment = EnvironmentSpec::inherit_core()
        .with_var(SANDBOX_FIXTURE_MODE, "sleep")
        .expect("timeout fixture mode");
    let (timeout_command, timeout_effective, timeout_context) = restricted_request_with_environment(
        workspace.path(),
        fixture_command(&fixture),
        timeout_environment,
    );
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

    setup.uninstall().unwrap_or_else(|error| {
        panic!(
            "explicit setup cleanup: {error}; workspace ACL before descendant: {workspace_acl_before_descendant}; workspace raw DACL before descendant: {workspace_raw_dacl_before_descendant}; workspace raw ACL before descendant: {workspace_raw_acl_before_descendant}; denied-read progress ACL before descendant: {access_progress_acl_before_descendant}; denied-read progress raw ACL before descendant: {access_progress_raw_acl_before_descendant}; filesystem authorities before descendant: {filesystem_authorities_before_descendant}"
        )
    });
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
