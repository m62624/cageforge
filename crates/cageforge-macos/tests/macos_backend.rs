// SPDX-License-Identifier: Apache-2.0

#![cfg(target_os = "macos")]

use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::io::{AsFd, AsRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use cageforge_backend_api::{
    BackendCapabilities, BackendCapability, BackendContractError, BackendRequest, SandboxBackend,
};
use cageforge_command::{CommandRequest, CommandSpec, EnvironmentSpec, StdioMode, StdioSpec};
use cageforge_macos::{MacosBackend, MacosBackendConfig, MacosBackendError, MacosFilesystemError};
use cageforge_policy::{
    AccessMode, DomainAccess, DomainMode, FilesystemPolicy, FilesystemRule, LocalNetworkAccess,
    NetworkPolicy, PathResolutionContext, PathSelector, SandboxPolicy, UnixSocketMode,
};
use cageforge_policy_compose::{CompositionRequest, PolicyCeiling, compose};
use tempfile::TempDir;

const PARENT_DEATH_ROOT: &str = "CAGEFORGE_MACOS_PARENT_DEATH_ROOT";
const PARENT_DEATH_CHILD: &str = "CAGEFORGE_MACOS_PARENT_DEATH_CHILD";
const UNIX_SOCKET_TEST_PATH: &str = "CAGEFORGE_MACOS_UNIX_SOCKET_TEST_PATH";
const GROUP_CHANGE_MODE: &str = "CAGEFORGE_MACOS_GROUP_CHANGE_MODE";
const GROUP_CHANGE_ROOT: &str = "CAGEFORGE_MACOS_GROUP_CHANGE_ROOT";

struct LaunchdTestJob {
    label: String,
}

impl LaunchdTestJob {
    fn remove(&self) -> std::process::Output {
        Command::new("/bin/launchctl")
            .args(["remove", &self.label])
            .output()
            .expect("remove this test's launchd job")
    }
}

impl Drop for LaunchdTestJob {
    fn drop(&mut self) {
        // The label belongs only to this fixture. Cleanup also runs when an
        // assertion detects an unexpected successful sandboxed registration.
        let _ = Command::new("/bin/launchctl")
            .args(["remove", &self.label])
            .output();
    }
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

fn writable_policy(workspace: &Path) -> SandboxPolicy {
    SandboxPolicy::new(
        FilesystemPolicy::restricted([
            FilesystemRule::new(
                PathSelector::absolute(workspace.to_path_buf()).expect("workspace selector"),
                AccessMode::Write,
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
        .with_stdio(
            StdioSpec::inherited()
                .with_stdout(StdioMode::Pipe)
                .with_stderr(StdioMode::Pipe),
        )
        .with_environment(environment);
    (command, effective, context(workspace))
}

fn network_request(
    workspace: &Path,
    policy: &SandboxPolicy,
    mode: &str,
    target: SocketAddr,
) -> (
    CommandRequest,
    cageforge_policy_compose::EffectiveSandbox,
    PathResolutionContext,
) {
    let environment = EnvironmentSpec::inherit_all()
        .with_var("CAGEFORGE_NETWORK_TEST_MODE", mode)
        .expect("mode")
        .with_var("CAGEFORGE_NETWORK_TEST_TARGET", target.to_string())
        .expect("target");
    let command = CommandSpec::new(std::env::current_exe().expect("test executable"))
        .expect("test executable command")
        .with_args(["--exact", "network_client_fixture", "--nocapture"])
        .expect("fixture arguments");
    let ceiling = PolicyCeiling::new(SandboxPolicy::full_access(), environment.clone());
    let effective =
        compose(CompositionRequest::new(policy, &environment, &ceiling)).expect("compose policy");
    let command = CommandRequest::new(command)
        .with_working_directory(workspace.to_path_buf())
        .expect("working directory")
        .with_stdio(
            StdioSpec::inherited()
                .with_stdout(StdioMode::Pipe)
                .with_stderr(StdioMode::Pipe),
        )
        .with_environment(environment);
    (command, effective, context(workspace))
}

fn start_http_server() -> (SocketAddr, thread::JoinHandle<io::Result<()>>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("HTTP listener");
    let address = listener.local_addr().expect("HTTP address");
    listener
        .set_nonblocking(true)
        .expect("nonblocking HTTP listener");
    let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
    let server = thread::spawn(move || -> io::Result<()> {
        ready_sender.send(()).expect("HTTP readiness receiver");
        let deadline = Instant::now() + Duration::from_secs(3);
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(connection) => break connection,
                Err(source) if source.kind() == io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "HTTP fixture did not receive a connection",
                        ));
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                Err(source) => return Err(source),
            }
        };
        stream.set_nonblocking(false)?;
        stream.set_read_timeout(Some(Duration::from_secs(3)))?;
        stream.set_write_timeout(Some(Duration::from_secs(3)))?;
        let mut request = Vec::new();
        let mut chunk = [0; 1024];
        loop {
            let read = stream.read(&mut chunk)?;
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "HTTP client closed before request headers",
                ));
            }
            request.extend_from_slice(&chunk[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
            if request.len() > 16 * 1024 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "HTTP request headers exceeded fixture limit",
                ));
            }
        }
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")?;
        stream.shutdown(Shutdown::Write)?;
        let mut close = [0; 1];
        while stream.read(&mut close)? != 0 {}
        Ok(())
    });
    ready_receiver.recv().expect("HTTP readiness signal");
    (address, server)
}

fn start_unix_server(path: &Path) -> thread::JoinHandle<io::Result<()>> {
    let listener = UnixListener::bind(path).expect("Unix listener");
    listener
        .set_nonblocking(true)
        .expect("nonblocking Unix listener");
    let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
    let server = thread::spawn(move || -> io::Result<()> {
        ready_sender.send(()).expect("Unix readiness receiver");
        let deadline = Instant::now() + Duration::from_secs(3);
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(connection) => break connection,
                Err(source) if source.kind() == io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "Unix fixture did not receive a connection",
                        ));
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                Err(source) => return Err(source),
            }
        };
        stream.set_nonblocking(false)?;
        let mut request = [0; 4];
        stream.read_exact(&mut request)?;
        if request != *b"ping" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unix fixture received an unexpected request",
            ));
        }
        stream.write_all(b"pong")
    });
    ready_receiver.recv().expect("Unix readiness signal");
    server
}

fn unix_network_request(
    workspace: &Path,
    policy: &SandboxPolicy,
    mode: &str,
    socket_path: &Path,
) -> (
    CommandRequest,
    cageforge_policy_compose::EffectiveSandbox,
    PathResolutionContext,
) {
    let environment = EnvironmentSpec::inherit_all()
        .with_var("CAGEFORGE_NETWORK_TEST_MODE", mode)
        .expect("mode")
        .with_var(UNIX_SOCKET_TEST_PATH, socket_path.as_os_str())
        .expect("Unix socket path");
    let command = CommandSpec::new(std::env::current_exe().expect("test executable"))
        .expect("test executable command")
        .with_args(["--exact", "network_client_fixture", "--nocapture"])
        .expect("fixture arguments");
    let ceiling = PolicyCeiling::new(SandboxPolicy::full_access(), environment.clone());
    let effective =
        compose(CompositionRequest::new(policy, &environment, &ceiling)).expect("compose policy");
    let command = CommandRequest::new(command)
        .with_working_directory(workspace.to_path_buf())
        .expect("working directory")
        .with_stdio(
            StdioSpec::inherited()
                .with_stdout(StdioMode::Pipe)
                .with_stderr(StdioMode::Pipe),
        )
        .with_environment(environment);
    (command, effective, context(workspace))
}

fn proxy_endpoint(value: &str) -> SocketAddr {
    value
        .split_once("://")
        .map(|(_, authority)| authority)
        .unwrap_or(value)
        .trim_end_matches('/')
        .parse()
        .expect("loopback proxy address")
}

fn send_http_proxy_request(target: SocketAddr) -> io::Result<Vec<u8>> {
    let mut stream = TcpStream::connect(proxy_endpoint(
        &std::env::var("HTTP_PROXY").expect("HTTP proxy"),
    ))?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    write!(
        stream,
        "GET http://{target}/ HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
    )?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    Ok(response)
}

fn send_direct_request(target: SocketAddr) -> io::Result<Vec<u8>> {
    let mut stream = TcpStream::connect_timeout(&target, Duration::from_millis(250))?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    write!(
        stream,
        "GET / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
    )?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    Ok(response)
}

fn restricted_network_policy(target: SocketAddr) -> SandboxPolicy {
    let network = NetworkPolicy::enabled()
        .with_domain_mode(DomainMode::Restricted)
        .with_domain(target.to_string(), DomainAccess::Allow)
        .expect("loopback domain rule");
    SandboxPolicy::new(FilesystemPolicy::unrestricted(), network)
}

fn cat_command(path: &Path) -> CommandSpec {
    CommandSpec::new("/bin/cat")
        .expect("cat")
        .with_arg(path.as_os_str())
        .expect("cat argument")
}

fn shell_command(script: &str) -> CommandSpec {
    CommandSpec::new("/bin/sh")
        .expect("shell")
        .with_args(["-c", script])
        .expect("shell arguments")
}

fn delayed_marker_child(
    workspace: &Path,
    backend: &MacosBackend,
) -> (cageforge_macos::MacosChild, PathBuf) {
    let marker = workspace.join("marker-after-boundary");
    let command = CommandSpec::new("/bin/sh")
        .expect("shell")
        .with_arg("-c")
        .expect("shell option")
        .with_arg(
            "(sleep 1; touch \"$1\") & descendant=$!; ".to_owned()
                + "printf 'ready:%s\\n' \"$descendant\"; wait",
        )
        .expect("shell script")
        .with_arg("cageforge-marker")
        .expect("shell name")
        .with_arg(marker.as_os_str())
        .expect("marker argument");
    let policy = writable_policy(workspace);
    let (command, effective, context) = request_for(workspace, &policy, command);
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &context)
        .expect("prepare");
    let child = backend.spawn(prepared).expect("spawn");
    (child, marker)
}

fn read_descendant_process_group(child: &mut cageforge_macos::MacosChild) -> (u32, u32) {
    let mut line = String::new();
    BufReader::new(child.stdout().expect("stdout pipe"))
        .read_line(&mut line)
        .expect("ready marker");
    let mut fields = line.trim().split(':');
    assert_eq!(fields.next(), Some("ready"));
    let descendant = fields
        .next()
        .expect("descendant PID")
        .parse()
        .expect("numeric descendant PID");
    assert_eq!(fields.next(), None);
    #[allow(unsafe_code)]
    let process_group = unsafe { libc::getpgid(descendant as libc::pid_t) };
    assert!(process_group > 0, "descendant process group lookup failed");
    (descendant, process_group as u32)
}

fn exiting_marker_child(
    workspace: &Path,
    backend: &MacosBackend,
) -> (cageforge_macos::MacosChild, PathBuf) {
    let marker = workspace.join("marker-after-leader-exit");
    let command = CommandSpec::new("/bin/sh")
        .expect("shell")
        .with_arg("-c")
        .expect("shell option")
        .with_arg(
            "(sleep 1; touch \"$1\") & descendant=$!; ".to_owned()
                + "printf 'ready:%s\\n' \"$descendant\"; exit 0",
        )
        .expect("shell script")
        .with_arg("cageforge-marker")
        .expect("shell name")
        .with_arg(marker.as_os_str())
        .expect("marker argument");
    let policy = writable_policy(workspace);
    let (command, effective, context) = request_for(workspace, &policy, command);
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &context)
        .expect("prepare");
    let child = backend.spawn(prepared).expect("spawn");
    (child, marker)
}

#[test]
fn parent_death_child_harness() {
    let Some(root) = std::env::var_os(PARENT_DEATH_ROOT) else {
        return;
    };
    let root = PathBuf::from(root);
    fs::create_dir_all(&root).expect("parent-death workspace");
    let backend = backend();
    let (child, marker) = delayed_marker_child(&root, &backend);
    fs::write(
        std::env::var_os(PARENT_DEATH_CHILD).expect("parent-death child path"),
        child.id().to_string(),
    )
    .expect("publish parent-death child PID");
    let _ = marker;
    std::process::exit(0);
}

#[test]
fn parent_process_death_terminates_the_complete_seatbelt_process_group() {
    let temporary = TempDir::new().expect("parent-death temporary root");
    let workspace = temporary.path().join("workspace");
    let child_pid = temporary.path().join("child.pid");
    let marker = workspace.join("marker-after-boundary");
    let parent = Command::new(std::env::current_exe().expect("test executable"))
        .args(["--exact", "parent_death_child_harness", "--nocapture"])
        .env(PARENT_DEATH_ROOT, &workspace)
        .env(PARENT_DEATH_CHILD, &child_pid)
        .spawn()
        .expect("spawn parent-death harness");
    let status = parent
        .wait_with_output()
        .expect("wait parent-death harness");
    assert!(
        status.status.success(),
        "parent-death harness failed: {status:?}"
    );
    let pid = fs::read_to_string(&child_pid)
        .expect("read parent-death child PID")
        .trim()
        .parse::<libc::pid_t>()
        .expect("parse parent-death child PID");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        #[allow(unsafe_code)]
        let alive = unsafe { libc::kill(pid, 0) == 0 };
        if !alive {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "parent death left the sandbox boundary active: {pid}"
        );
        thread::sleep(Duration::from_millis(20));
    }
    thread::sleep(Duration::from_secs(2));
    assert!(!marker.exists(), "parent death left a descendant running");
}

#[test]
fn host_accepts_the_backend_seatbelt_profile() {
    let workspace = TempDir::new().expect("workspace");
    let policy = SandboxPolicy::new(FilesystemPolicy::unrestricted(), NetworkPolicy::disabled());
    let command = CommandSpec::new("/usr/bin/true").expect("true");
    let (command, effective, context) = request_for(workspace.path(), &policy, command);
    let backend = backend();
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &context)
        .expect("prepare");
    let mut child = backend.spawn(prepared).expect("spawn");
    let status = child.wait().expect("wait");
    assert!(
        status.success(),
        "backend Seatbelt probe failed: {status:?}"
    );
}

#[test]
fn sandboxed_commands_cannot_delegate_execution_to_launchd() {
    let workspace = TempDir::new().expect("launchd fixture workspace");
    let suffix = workspace.path().file_name().expect("unique fixture suffix");
    let backend = backend();
    for (mode, policy) in [
        ("restricted", writable_policy(workspace.path())),
        ("unrestricted", SandboxPolicy::full_access()),
    ] {
        let job = LaunchdTestJob {
            label: format!(
                "cageforge-test-delegation-{}-{}-{mode}",
                std::process::id(),
                suffix.to_string_lossy()
            ),
        };
        let marker = workspace.path().join(format!("{mode}-delegated"));
        let arguments: Vec<OsString> = ["submit", "-l", &job.label, "--", "/usr/bin/touch"]
            .into_iter()
            .map(OsString::from)
            .chain([marker.clone().into_os_string()])
            .collect();

        // Prove that this user/session can register exactly this finite job.
        // Otherwise a host configuration error could look like a sandbox deny.
        let positive = Command::new("/bin/launchctl")
            .args(&arguments)
            .output()
            .expect("submit unsandboxed positive control");
        assert!(positive.status.success(), "positive control: {positive:?}");
        let deadline = Instant::now() + Duration::from_secs(5);
        while !marker.exists() {
            assert!(
                Instant::now() < deadline,
                "positive control did not execute"
            );
            thread::sleep(Duration::from_millis(10));
        }
        let removed = job.remove();
        assert!(
            removed.status.success(),
            "remove positive control: {removed:?}"
        );
        fs::remove_file(&marker).expect("remove positive-control marker");

        let command = CommandSpec::new("/bin/launchctl")
            .expect("launchctl executable")
            .with_args(arguments)
            .expect("launchctl arguments");
        let (command, effective, context) = request_for(workspace.path(), &policy, command);
        let command = command.with_timeout(Duration::from_secs(5));
        let prepared = backend
            .prepare(BackendRequest::new(&command, &effective), &context)
            .expect("prepare launchd delegation probe");
        let mut child = backend
            .spawn(prepared)
            .expect("spawn launchctl inside sandbox");
        let mut stderr = File::from(
            child
                .stderr()
                .expect("launchctl stderr")
                .as_fd()
                .try_clone_to_owned()
                .expect("retain diagnostics across wait"),
        );
        let status = child.wait().expect("wait for launchctl delegation probe");
        let mut diagnostic = Vec::new();
        read_pipe_until_eof(&mut stderr, |bytes| {
            diagnostic.extend_from_slice(bytes);
            Ok(())
        })
        .expect("bounded diagnostic read");
        let registered = Command::new("/bin/launchctl")
            .args(["list", &job.label])
            .output()
            .expect("check exact fixture job registration");
        assert!(
            !status.success() && !registered.status.success() && !marker.exists(),
            "{mode} command delegated execution outside Seatbelt: status={status:?}; \
             registration={registered:?}; stderr={}",
            String::from_utf8_lossy(&diagnostic)
        );
    }
}

#[test]
fn restricted_command_can_start_a_native_runtime_program() {
    let workspace = TempDir::new().expect("workspace");
    let policy = restricted_policy(workspace.path());
    let command = CommandSpec::new("/usr/bin/true").expect("true");
    let (command, effective, context) = request_for(workspace.path(), &policy, command);
    let backend = backend();
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &context)
        .expect("prepare");
    let mut child = backend.spawn(prepared).expect("spawn");
    let status = child.wait().expect("wait");
    let mut stderr = Vec::new();
    if let Some(stream) = child.stderr() {
        stream.read_to_end(&mut stderr).expect("read stderr");
    }
    assert!(
        status.success(),
        "restricted native runtime probe failed: {status:?}; stderr: {}",
        String::from_utf8_lossy(&stderr)
    );
    let backend: Arc<dyn cageforge_backend_api::DynSandbox> = Arc::new(backend);
    thread::scope(|scope| {
        let workers: Vec<_> = (0..2)
            .map(|_| {
                let backend = Arc::clone(&backend);
                let request = BackendRequest::new(&command, &effective);
                let context = &context;
                scope.spawn(move || {
                    let mut child = backend.launch(request, context).expect("dynamic launch");
                    assert!(child.wait().expect("dynamic wait").success());
                })
            })
            .collect();
        for worker in workers {
            worker.join().expect("dynamic worker");
        }
    });
}

#[test]
fn backend_is_send_sync_and_reusable_for_independent_instances() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Arc<MacosBackend>>();
    let backend = backend();
    let actual = backend.capabilities();
    let expected = BackendCapabilities::from_capabilities([
        BackendCapability::CommandExecution,
        BackendCapability::WorkingDirectory,
        BackendCapability::StdioInherit,
        BackendCapability::StdioNull,
        BackendCapability::StdioPipe,
        BackendCapability::TimeoutDisabled,
        BackendCapability::TimeoutBackendDefault,
        BackendCapability::TimeoutLimit,
        BackendCapability::FilesystemRestricted,
        BackendCapability::FilesystemUnrestricted,
        BackendCapability::FilesystemScopes,
        BackendCapability::FilesystemAbsoluteScopes,
        BackendCapability::FilesystemWorkspaceScopes,
        BackendCapability::FilesystemRootScopes,
        BackendCapability::FilesystemMinimalScopes,
        BackendCapability::FilesystemTmpdirScopes,
        BackendCapability::FilesystemConventionalTemporaryScopes,
        BackendCapability::FilesystemReadOnlySubpaths,
        BackendCapability::FilesystemGlobs,
        BackendCapability::FilesystemGlobScanDepth,
        BackendCapability::FilesystemMissingPathBehavior,
        BackendCapability::FilesystemProtectedPaths,
        BackendCapability::NetworkDisabled,
        BackendCapability::NetworkEnabled,
        BackendCapability::NetworkDomainRules,
        BackendCapability::NetworkLocalAddressRestrictions,
        BackendCapability::NetworkResolvedTargets,
        BackendCapability::NetworkLocalIpcIsolation,
        BackendCapability::NetworkLocalIpcRules,
        BackendCapability::EnvironmentAll,
        BackendCapability::EnvironmentCore,
        BackendCapability::EnvironmentNone,
        BackendCapability::EnvironmentFilters,
        BackendCapability::EnvironmentOverrides,
    ]);
    assert_eq!(
        actual.iter().copied().collect::<Vec<_>>(),
        expected.iter().copied().collect::<Vec<_>>()
    );
    assert!(!actual.supports(BackendCapability::NetworkLocalIpcDenyRules));
    assert!(actual.supports(BackendCapability::CommandExecution));
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
fn parent_watcher_does_not_retain_closed_stdin() {
    let workspace = TempDir::new().expect("workspace");
    let marker = workspace.path().join("stdin-closed");
    let command = shell_command("exec 0<&-; touch \"$1\"; sleep 5")
        .with_arg("cageforge-stdin")
        .expect("shell name")
        .with_arg(marker.as_os_str())
        .expect("marker argument");
    let policy = writable_policy(workspace.path());
    let (mut request, effective, context) = request_for(workspace.path(), &policy, command);
    request = request.with_stdio(
        StdioSpec::inherited()
            .with_stdin(StdioMode::Pipe)
            .with_stdout(StdioMode::Pipe)
            .with_stderr(StdioMode::Pipe),
    );
    let backend = backend();
    let prepared = backend
        .prepare(BackendRequest::new(&request, &effective), &context)
        .expect("prepare");
    let mut child = backend.spawn(prepared).expect("spawn");
    let deadline = Instant::now() + Duration::from_secs(3);
    while !marker.exists() {
        assert!(
            Instant::now() < deadline,
            "stdin close fixture did not start"
        );
        thread::sleep(Duration::from_millis(5));
    }
    let error = child
        .stdin()
        .expect("stdin pipe")
        .write(&[1])
        .expect_err("parent watcher retained the closed stdin read end");
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    child.kill().expect("terminate fixture");
}

#[test]
fn parent_watcher_does_not_retain_closed_stdout_or_stderr() {
    let workspace = TempDir::new().expect("workspace");
    let marker = workspace.path().join("standard-streams-closed");
    let command = shell_command("exec 1>&- 2>&-; touch \"$1\"; sleep 5")
        .with_arg("cageforge-stdio")
        .expect("shell name")
        .with_arg(marker.as_os_str())
        .expect("marker argument");
    let policy = writable_policy(workspace.path());
    let (mut request, effective, context) = request_for(workspace.path(), &policy, command);
    request = request.with_stdio(
        StdioSpec::inherited()
            .with_stdin(StdioMode::Null)
            .with_stdout(StdioMode::Pipe)
            .with_stderr(StdioMode::Pipe),
    );
    let backend = backend();
    let prepared = backend
        .prepare(BackendRequest::new(&request, &effective), &context)
        .expect("prepare");
    let mut child = backend.spawn(prepared).expect("spawn");
    let deadline = Instant::now() + Duration::from_secs(3);
    while !marker.exists() {
        assert!(
            Instant::now() < deadline,
            "standard-stream close fixture did not start"
        );
        thread::sleep(Duration::from_millis(5));
    }

    let stdout_result = wait_for_pipe_eof(child.stdout().expect("stdout pipe"));
    let stderr_result = wait_for_pipe_eof(child.stderr().expect("stderr pipe"));
    child.kill().expect("terminate fixture");

    stdout_result.expect("parent watcher retained the closed stdout write end");
    stderr_result.expect("parent watcher retained the closed stderr write end");
}

fn wait_for_pipe_eof<T: Read + AsRawFd>(stream: &mut T) -> io::Result<()> {
    read_pipe_until_eof(stream, |_| {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "closed standard-stream fixture produced output",
        ))
    })
}

#[allow(unsafe_code)]
fn read_pipe_until_eof<T: Read + AsRawFd>(
    stream: &mut T,
    mut on_output: impl FnMut(&[u8]) -> io::Result<()>,
) -> io::Result<()> {
    let mut poll = libc::pollfd {
        fd: stream.as_raw_fd(),
        events: libc::POLLIN | libc::POLLHUP,
        revents: 0,
    };
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut buffer = [0; 4096];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "standard stream did not reach EOF",
            ));
        }
        let timeout = remaining.as_millis().min(i32::MAX as u128) as i32;
        let result = unsafe { libc::poll(&mut poll, 1, timeout) };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if result == 0 {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "standard stream did not reach EOF",
            ));
        }
        match stream.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(read) => on_output(&buffer[..read])?,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

#[test]
fn restricted_command_cannot_read_outside_its_workspace() {
    let workspace = TempDir::new().expect("workspace");
    let outside_directory = TempDir::new().expect("outside directory");
    let outside = outside_directory.path().join("outside.txt");
    fs::write(&outside, "outside-data").expect("outside fixture");
    let policy = restricted_policy(workspace.path());
    let (command, effective, context) =
        request_for(workspace.path(), &policy, cat_command(&outside));
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
    assert!(
        !status.success(),
        "outside read unexpectedly succeeded: {status:?}; stderr: {error}"
    );
}

#[test]
fn restricted_command_cannot_write_outside_its_workspace() {
    let workspace = TempDir::new().expect("workspace");
    let outside = workspace.path().join("..").join("outside-write");
    let policy = writable_policy(workspace.path());
    let script = format!("printf denied > '{}'", outside.display());
    let (command, effective, context) =
        request_for(workspace.path(), &policy, shell_command(&script));
    let backend = backend();
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &context)
        .expect("prepare");
    let mut child = backend.spawn(prepared).expect("spawn");
    let status = child.wait().expect("wait");
    assert!(!status.success(), "outside write unexpectedly succeeded");
    assert!(!outside.exists(), "outside file was created");
}

#[test]
fn restricted_filesystem_does_not_grant_unlisted_conventional_tmp() {
    let workspace = TempDir::new().expect("workspace");
    let unlisted_tmp = tempfile::tempdir_in("/private/tmp").expect("unlisted temp directory");
    let marker = unlisted_tmp.path().join("marker");
    let command = shell_command("touch \"$1\"")
        .with_arg("cageforge-unlisted-tmp")
        .expect("shell name")
        .with_arg(marker.as_os_str())
        .expect("marker argument");
    let policy = writable_policy(workspace.path());
    let (command, effective, context) = request_for(workspace.path(), &policy, command);
    let backend = backend();
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &context)
        .expect("prepare");
    let mut child = backend.spawn(prepared).expect("spawn");
    let status = child.wait().expect("wait");
    assert!(!status.success(), "unlisted /private/tmp write succeeded");
    assert!(!marker.exists(), "unlisted /private/tmp marker was created");
}

#[test]
fn writable_workspace_preserves_read_only_and_protected_descendants() {
    let workspace = TempDir::new().expect("workspace");
    let readonly = workspace.path().join("readonly");
    let protected = workspace.path().join(".git");
    fs::create_dir(&readonly).expect("readonly directory");
    fs::create_dir(&protected).expect("protected directory");
    let readonly_file = readonly.join("value");
    let protected_file = protected.join("value");
    fs::write(&readonly_file, "readonly").expect("readonly fixture");
    fs::write(&protected_file, "protected").expect("protected fixture");
    let writable = FilesystemRule::new(
        PathSelector::absolute(workspace.path().to_path_buf()).expect("workspace selector"),
        AccessMode::Write,
    )
    .with_read_only_subpath(PathSelector::absolute(readonly.clone()).expect("readonly selector"))
    .expect("readonly carve-out");
    let policy = SandboxPolicy::new(
        FilesystemPolicy::restricted([
            writable,
            FilesystemRule::new(PathSelector::minimal(), AccessMode::Read),
        ]),
        NetworkPolicy::disabled(),
    );
    let script = format!(
        "printf changed > '{}' && printf changed > '{}'",
        readonly_file.display(),
        protected_file.display()
    );
    let (command, effective, context) =
        request_for(workspace.path(), &policy, shell_command(&script));
    let backend = backend();
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &context)
        .expect("prepare");
    let mut child = backend.spawn(prepared).expect("spawn");
    let status = child.wait().expect("wait");
    assert!(!status.success(), "protected write unexpectedly succeeded");
    assert_eq!(
        fs::read_to_string(&readonly_file).expect("readonly result"),
        "readonly"
    );
    assert_eq!(
        fs::read_to_string(&protected_file).expect("protected result"),
        "protected"
    );
}

#[test]
fn deny_glob_blocks_writes_inside_a_writable_workspace() {
    let workspace = TempDir::new().expect("workspace");
    let secret = workspace.path().join("nested").join("value.secret");
    fs::create_dir(workspace.path().join("nested")).expect("nested directory");
    let glob =
        FilesystemRule::workspace_glob("**/*.secret", AccessMode::Deny).expect("secret glob");
    let policy = SandboxPolicy::new(
        FilesystemPolicy::restricted([
            FilesystemRule::new(
                PathSelector::absolute(workspace.path().to_path_buf()).expect("workspace"),
                AccessMode::Write,
            ),
            glob,
            FilesystemRule::new(PathSelector::minimal(), AccessMode::Read),
        ]),
        NetworkPolicy::disabled(),
    );
    let script = format!("printf secret > '{}'", secret.display());
    let (command, effective, context) =
        request_for(workspace.path(), &policy, shell_command(&script));
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
    assert!(!status.success(), "deny glob was bypassed; stderr: {error}");
    assert!(!secret.exists(), "deny glob was bypassed");
}

#[test]
fn deny_glob_blocks_a_symlinked_static_prefix() {
    use std::os::unix::fs::symlink;

    let workspace = TempDir::new().expect("workspace");
    let real_root = workspace.path().join("real");
    fs::create_dir(&real_root).expect("real root");
    let link = workspace.path().join("link");
    symlink(&real_root, &link).expect("static-prefix symlink");
    let secret = real_root.join("value.secret");
    let glob =
        FilesystemRule::absolute_glob(format!("{}/**/*.secret", link.display()), AccessMode::Deny)
            .expect("absolute secret glob");
    let policy = SandboxPolicy::new(
        FilesystemPolicy::restricted([
            FilesystemRule::new(
                PathSelector::absolute(workspace.path().to_path_buf()).expect("workspace"),
                AccessMode::Write,
            ),
            glob,
            FilesystemRule::new(PathSelector::minimal(), AccessMode::Read),
        ]),
        NetworkPolicy::disabled(),
    );
    let script = format!("printf secret > '{}/value.secret'", link.display());
    let (command, effective, context) =
        request_for(workspace.path(), &policy, shell_command(&script));
    let backend = backend();
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &context)
        .expect("prepare");
    let mut child = backend.spawn(prepared).expect("spawn");
    let status = child.wait().expect("wait");
    assert!(!status.success(), "symlinked deny glob was bypassed");
    assert!(!secret.exists(), "symlinked deny glob was bypassed");
}

#[test]
fn brace_deny_glob_blocks_a_symlinked_static_prefix() {
    use std::os::unix::fs::symlink;

    let workspace = TempDir::new().expect("workspace");
    let real_root = workspace.path().join("real");
    fs::create_dir(&real_root).expect("real root");
    let link = workspace.path().join("link");
    symlink(&real_root, &link).expect("static-prefix symlink");
    let secret = real_root.join("value.secret");
    let glob = FilesystemRule::absolute_glob(
        format!(
            "{}/{{value,{{other,内部}}}}.[sS][eE][cC][rR][eE][tT]",
            link.display()
        ),
        AccessMode::Deny,
    )
    .expect("nested brace secret glob");
    let policy = SandboxPolicy::new(
        FilesystemPolicy::restricted([
            FilesystemRule::new(
                PathSelector::absolute(workspace.path().to_path_buf()).expect("workspace"),
                AccessMode::Write,
            ),
            glob,
            FilesystemRule::new(PathSelector::minimal(), AccessMode::Read),
        ]),
        NetworkPolicy::disabled(),
    );
    let script = format!("printf secret > '{}/value.secret'", link.display());
    let (command, effective, context) =
        request_for(workspace.path(), &policy, shell_command(&script));
    let backend = backend();
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &context)
        .expect("prepare");
    let mut child = backend.spawn(prepared).expect("spawn");
    let status = child.wait().expect("wait");
    assert!(!status.success(), "brace symlinked deny glob was bypassed");
    assert!(!secret.exists(), "brace symlinked deny glob was bypassed");
}

#[test]
fn writable_workspace_cannot_escape_through_a_symlink() {
    use std::os::unix::fs::symlink;

    let workspace = TempDir::new().expect("workspace");
    let outside = TempDir::new().expect("outside");
    let outside_file = outside.path().join("secret");
    fs::write(&outside_file, "outside").expect("outside fixture");
    symlink(outside.path(), workspace.path().join("link")).expect("workspace symlink");
    let policy = writable_policy(workspace.path());
    let (command, effective, context) = request_for(
        workspace.path(),
        &policy,
        cat_command(&workspace.path().join("link").join("secret")),
    );
    let backend = backend();
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &context)
        .expect("prepare");
    let mut child = backend.spawn(prepared).expect("spawn");
    assert!(!child.wait().expect("wait").success());
}

#[test]
fn workspace_glob_rejects_a_non_utf8_root_before_launch() {
    let parent = TempDir::new().expect("workspace parent");
    let root = parent
        .path()
        .join(OsString::from_vec(vec![b'w', b'o', b'r', b'k', 0xff]));
    let rule = FilesystemRule::workspace_glob("**/*.secret", AccessMode::Deny)
        .expect("workspace deny glob");
    let policy = SandboxPolicy::new(
        FilesystemPolicy::restricted([
            FilesystemRule::new(
                PathSelector::absolute(parent.path().to_path_buf()).expect("parent scope"),
                AccessMode::Read,
            ),
            rule,
        ]),
        NetworkPolicy::disabled(),
    );
    let (command, effective, context) = request_for(&root, &policy, shell_command(":"));
    let error = backend()
        .prepare(BackendRequest::new(&command, &effective), &context)
        .expect_err("macOS Seatbelt glob lowering must reject lossy roots");
    match error {
        MacosBackendError::Filesystem(MacosFilesystemError::GlobRootNotUtf8 { path }) => {
            assert!(
                path.to_str().is_none(),
                "the diagnostic path must retain its non-UTF-8 identity"
            );
        }
        error => panic!("unexpected non-UTF-8 glob error: {error:?}"),
    }
}

#[test]
fn command_timeout_closes_pipes_without_wait_or_polling() {
    let workspace = TempDir::new().expect("workspace");
    let policy = restricted_policy(workspace.path());
    let (request, effective, context) =
        request_for(workspace.path(), &policy, shell_command("sleep 30 & wait"));
    let request = request.with_timeout(Duration::from_millis(200));
    let backend = backend();
    let prepared = backend
        .prepare(BackendRequest::new(&request, &effective), &context)
        .expect("prepare");
    let mut child = backend.spawn(prepared).expect("spawn");

    // Observe only the pipe. Calling wait/try_wait here would hide a deadline
    // that is enforced only when the embedding application polls the child.
    // The observer itself is bounded so a broken watchdog cannot hang CI.
    let stdout_eof = wait_for_pipe_eof(child.stdout().expect("stdout pipe"));
    let stderr_eof = wait_for_pipe_eof(child.stderr().expect("stderr pipe"));
    let result = child.wait();

    stdout_eof.expect("command timeout must close stdout without lifecycle polling");
    stderr_eof.expect("command timeout must close stderr without lifecycle polling");
    assert!(
        matches!(result, Err(MacosBackendError::ProcessTimedOut)),
        "timeout must retain its typed result: {result:?}"
    );
}

#[test]
fn timeout_terminates_the_complete_seatbelt_process_group() {
    let workspace = TempDir::new().expect("workspace");
    let policy = restricted_policy(workspace.path());
    let (command, effective, context) =
        request_for(workspace.path(), &policy, shell_command("sleep 30 & wait"));
    let backend = MacosBackend::new(
        MacosBackendConfig::new()
            .with_default_timeout(Duration::from_millis(100))
            .expect("timeout"),
    )
    .expect("backend");
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &context)
        .expect("prepare");
    let mut child = backend.spawn(prepared).expect("spawn");
    let error = child.wait().expect_err("timeout");
    assert!(matches!(error, MacosBackendError::ProcessTimedOut));
}

#[test]
fn explicit_kill_terminates_the_complete_seatbelt_process_group() {
    let workspace = TempDir::new().expect("workspace");
    let backend = backend();
    let (mut child, marker) = delayed_marker_child(workspace.path(), &backend);
    let (descendant, descendant_group) = read_descendant_process_group(&mut child);
    assert_eq!(
        descendant_group,
        child.id(),
        "descendant {descendant} escaped boundary group {}",
        child.id()
    );
    child.kill().expect("kill");
    thread::sleep(Duration::from_secs(2));
    assert!(
        !marker.exists(),
        "descendant {descendant} survived explicit kill"
    );
}

#[test]
fn dropping_child_terminates_the_complete_seatbelt_process_group() {
    let workspace = TempDir::new().expect("workspace");
    let backend = backend();
    let (mut child, marker) = delayed_marker_child(workspace.path(), &backend);
    let (descendant, descendant_group) = read_descendant_process_group(&mut child);
    assert_eq!(
        descendant_group,
        child.id(),
        "descendant {descendant} escaped boundary group {}",
        child.id()
    );
    drop(child);
    thread::sleep(Duration::from_secs(2));
    assert!(
        !marker.exists(),
        "descendant {descendant} survived child drop"
    );
}

#[test]
fn reaped_leader_does_not_leave_a_running_descendant() {
    let workspace = TempDir::new().expect("workspace");
    let backend = backend();
    let (mut child, marker) = exiting_marker_child(workspace.path(), &backend);
    let (descendant, descendant_group) = read_descendant_process_group(&mut child);
    assert_eq!(
        descendant_group,
        child.id(),
        "descendant {descendant} escaped boundary group {}",
        child.id()
    );
    assert!(child.wait().expect("wait").success());
    thread::sleep(Duration::from_secs(2));
    assert!(
        !marker.exists(),
        "descendant {descendant} survived leader exit"
    );
}

#[test]
fn process_group_change_fixture() {
    let Ok(mode) = std::env::var(GROUP_CHANGE_MODE) else {
        return;
    };
    let root = PathBuf::from(std::env::var_os(GROUP_CHANGE_ROOT).expect("fixture root"));
    let ready = root.join("ready");
    let release = root.join("release");
    if let Some(operation) = mode.strip_prefix("root-") {
        let mut command = Command::new(std::env::current_exe().expect("fixture executable"));
        command
            .args(["--exact", "process_group_change_fixture", "--nocapture"])
            .env(GROUP_CHANGE_MODE, operation)
            .stdin(std::process::Stdio::null());
        if operation == "spawn-group" {
            // Also exercise native spawn attributes: denying only the direct
            // setpgid/setsid syscalls cannot establish immutable membership.
            command.process_group(0);
        }
        let mut descendant = command.spawn().expect("spawn group-changing descendant");
        let deadline = Instant::now() + Duration::from_secs(5);
        while !ready.exists() {
            assert!(
                descendant.try_wait().expect("poll descendant").is_none(),
                "descendant exited before readiness"
            );
            assert!(Instant::now() < deadline, "descendant readiness timeout");
            thread::sleep(Duration::from_millis(2));
        }
        // Deliberately finish the root while its descendant is alive. The
        // backend must complete descendant cleanup before wait() succeeds.
        drop(descendant);
        return;
    }

    #[allow(unsafe_code)]
    let (before, result, after) = unsafe {
        let before = libc::getpgrp();
        let result = match mode.as_str() {
            "setsid" => libc::setsid(),
            "setpgid" => libc::setpgid(0, 0),
            "spawn-group" => 0,
            other => panic!("unexpected group-change operation: {other}"),
        };
        (before, result, libc::getpgrp())
    };
    fs::write(
        ready,
        format!("{mode}: before={before}, result={result}, after={after}"),
    )
    .expect("record group-change result");
    let deadline = Instant::now() + Duration::from_secs(15);
    while !release.exists() {
        // Bound the fixture's own lifetime even on a broken cleanup path.
        if Instant::now() >= deadline {
            return;
        }
        thread::sleep(Duration::from_millis(2));
    }
    fs::write(
        root.join("survived"),
        b"executed after backend wait completed",
    )
    .expect("record surviving descendant");
}

#[test]
fn successful_wait_terminates_descendants_that_change_group_or_session() {
    let backend = backend();
    let executable = std::env::current_exe().expect("fixture executable");
    let mut survivors = Vec::new();
    for operation in ["setsid", "setpgid", "spawn-group"] {
        let workspace = TempDir::new().expect("workspace");
        let root = fs::canonicalize(workspace.path()).expect("canonical workspace");
        let environment = EnvironmentSpec::inherit_core()
            .with_var(GROUP_CHANGE_MODE, format!("root-{operation}"))
            .expect("fixture mode")
            .with_var(GROUP_CHANGE_ROOT, root.as_os_str())
            .expect("fixture root");
        let policy = writable_policy(&root);
        let ceiling = PolicyCeiling::new(SandboxPolicy::full_access(), environment.clone());
        let effective = compose(CompositionRequest::new(&policy, &environment, &ceiling))
            .expect("compose policy");
        let context = context(&root)
            .with_minimal_path(executable.clone())
            .expect("fixture runtime path");
        let command = CommandRequest::new(
            CommandSpec::new(&executable)
                .expect("fixture program")
                .with_args(["--exact", "process_group_change_fixture", "--nocapture"])
                .expect("fixture arguments"),
        )
        .with_working_directory(root.clone())
        .expect("working directory")
        .with_environment(environment)
        .with_timeout(Duration::from_secs(10))
        .with_stdio(
            StdioSpec::inherited()
                .with_stdout(StdioMode::Pipe)
                .with_stderr(StdioMode::Pipe),
        );
        let prepared = backend
            .prepare(BackendRequest::new(&command, &effective), &context)
            .expect("prepare group-change fixture");
        let mut child = backend.spawn(prepared).expect("spawn group-change fixture");
        // MacosChild closes its own stream handles at successful completion.
        // Keep only reader duplicates to observe EOF after that cleanup.
        let mut stdout = File::from(
            child
                .stdout()
                .expect("stdout")
                .as_fd()
                .try_clone_to_owned()
                .expect("stdout reader"),
        );
        let mut stderr = File::from(
            child
                .stderr()
                .expect("stderr")
                .as_fd()
                .try_clone_to_owned()
                .expect("stderr reader"),
        );
        let status = child.wait();
        // Release the finite descendant only after the public boundary claims
        // completion. On the broken implementation it records the violation
        // and exits itself, leaving no unbounded orphan or host-side PID kill.
        fs::write(root.join("release"), b"boundary wait returned").expect("release fixture");
        read_pipe_until_eof(&mut stdout, |_| Ok(()))
            .expect("descendant closes stdout after release");
        let mut diagnostic = String::new();
        read_pipe_until_eof(&mut stderr, |chunk| {
            diagnostic.push_str(&String::from_utf8_lossy(chunk));
            Ok(())
        })
        .expect("stderr diagnostic");
        assert!(status.expect("wait for fixture").success(), "{diagnostic}");
        if root.join("survived").exists() {
            survivors.push(fs::read_to_string(root.join("ready")).expect("group-change record"));
        }
    }
    assert!(
        survivors.is_empty(),
        "descendants survived successful boundary wait: {survivors:?}"
    );
}

#[test]
fn unrelated_inheritable_file_descriptors_do_not_cross_the_boundary() {
    let workspace = TempDir::new().expect("workspace");
    let inherited = File::open("/dev/null").expect("inheritable fixture");
    let descriptor = inherited.as_raw_fd();
    #[allow(unsafe_code)]
    unsafe {
        // Make the fixture genuinely inheritable so the test proves the
        // backend closes it instead of relying on the default file flags.
        libc::fcntl(descriptor, libc::F_SETFD, 0);
    }
    let script = format!(
        "test ! -e /dev/fd/{descriptor}",
        descriptor = descriptor as RawFd
    );
    let policy = restricted_policy(workspace.path());
    let (command, effective, context) =
        request_for(workspace.path(), &policy, shell_command(&script));
    let backend = backend();
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &context)
        .expect("prepare");
    let mut child = backend.spawn(prepared).expect("spawn");
    assert!(
        child.wait().expect("wait").success(),
        "unrelated descriptor crossed the Seatbelt boundary"
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
fn shared_backend_spawns_independent_instances_concurrently() {
    let backend = Arc::new(backend());
    let workers = ["first", "second"]
        .into_iter()
        .map(|expected| {
            let backend = Arc::clone(&backend);
            thread::spawn(move || {
                let workspace = TempDir::new().expect("workspace");
                let file = workspace.path().join("value");
                fs::write(&file, expected).expect("fixture");
                let policy = restricted_policy(workspace.path());
                let (command, effective, context) =
                    request_for(workspace.path(), &policy, cat_command(&file));
                let prepared = backend
                    .prepare(BackendRequest::new(&command, &effective), &context)
                    .expect("prepare");
                let mut child = backend.spawn(prepared).expect("spawn");
                let mut output = String::new();
                child
                    .stdout()
                    .expect("stdout")
                    .read_to_string(&mut output)
                    .expect("output");
                let status = child.wait().expect("wait");
                assert!(status.success(), "{status:?}");
                assert_eq!(output, expected);
            })
        })
        .collect::<Vec<_>>();

    for worker in workers {
        worker.join().expect("concurrent sandbox worker");
    }
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

#[test]
fn network_client_fixture() {
    let Ok(mode) = std::env::var("CAGEFORGE_NETWORK_TEST_MODE") else {
        return;
    };
    match mode.as_str() {
        "unix" => {
            let path = std::env::var_os(UNIX_SOCKET_TEST_PATH).expect("Unix socket path");
            let mut stream = UnixStream::connect(path).expect("Unix socket response");
            stream.write_all(b"ping").expect("Unix socket request");
            let mut response = [0; 4];
            stream
                .read_exact(&mut response)
                .expect("Unix socket response");
            assert_eq!(&response, b"pong");
        }
        "unix-denied" => {
            let path = std::env::var_os(UNIX_SOCKET_TEST_PATH).expect("Unix socket path");
            assert!(
                UnixStream::connect(path).is_err(),
                "sandbox connected to a denied Unix socket"
            );
        }
        "http" | "http-denied" | "direct" | "direct-denied" => {
            let target: SocketAddr = std::env::var("CAGEFORGE_NETWORK_TEST_TARGET")
                .expect("target")
                .parse()
                .expect("socket address");
            match mode.as_str() {
                "http" => {
                    let response = send_http_proxy_request(target).expect("HTTP proxy response");
                    assert!(
                        response.starts_with(b"HTTP/1.1 200"),
                        "unexpected HTTP proxy response: {}",
                        String::from_utf8_lossy(&response)
                    );
                }
                "http-denied" => assert!(
                    !send_http_proxy_request(target)
                        .expect("denied HTTP response")
                        .starts_with(b"HTTP/1.1 200")
                ),
                "direct" => assert!(
                    send_direct_request(target)
                        .expect("direct response")
                        .starts_with(b"HTTP/1.1 200")
                ),
                "direct-denied" => assert!(send_direct_request(target).is_err()),
                _ => unreachable!(),
            }
        }
        other => panic!("unknown network fixture mode: {other}"),
    }
}

#[test]
fn restricted_network_reaches_only_the_authorized_loopback_target() {
    let (target, server) = start_http_server();
    let workspace = TempDir::new().expect("workspace");
    let policy = restricted_network_policy(target);
    let (command, effective, runtime) = network_request(workspace.path(), &policy, "http", target);
    let backend = backend();
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &runtime)
        .expect("prepare");
    let mut child = backend.spawn(prepared).expect("spawn");
    let mut output = Vec::new();
    child
        .stdout()
        .expect("stdout pipe")
        .read_to_end(&mut output)
        .expect("read stdout");
    let mut error = String::new();
    child
        .stderr()
        .expect("stderr pipe")
        .read_to_string(&mut error)
        .expect("read stderr");
    let status = child.wait().expect("wait");
    let server_result = server.join().expect("HTTP server");
    assert_eq!(
        status.code(),
        Some(0),
        "sandbox stdout: {}; stderr: {error}",
        String::from_utf8_lossy(&output)
    );
    server_result.expect("HTTP server I/O");
}

#[test]
fn simultaneous_restricted_network_instances_keep_separate_gateway_policies() {
    let (first_target, first_server) = start_http_server();
    let (second_target, second_server) = start_http_server();
    assert_ne!(first_target, second_target);

    let first_workspace = TempDir::new().expect("first workspace");
    let second_workspace = TempDir::new().expect("second workspace");
    let first_policy = restricted_network_policy(first_target);
    let second_policy = restricted_network_policy(second_target);
    let (first_command, first_effective, first_context) =
        network_request(first_workspace.path(), &first_policy, "http", first_target);
    let (second_command, second_effective, second_context) = network_request(
        second_workspace.path(),
        &second_policy,
        "http",
        second_target,
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

    let mut first_output = Vec::new();
    first
        .stdout()
        .expect("first stdout")
        .read_to_end(&mut first_output)
        .expect("first output");
    let mut second_output = Vec::new();
    second
        .stdout()
        .expect("second stdout")
        .read_to_end(&mut second_output)
        .expect("second output");
    let first_status = first.wait().expect("first wait");
    let second_status = second.wait().expect("second wait");

    first_server
        .join()
        .expect("first HTTP server")
        .expect("first HTTP server I/O");
    second_server
        .join()
        .expect("second HTTP server")
        .expect("second HTTP server I/O");
    assert_eq!(
        first_status.code(),
        Some(0),
        "first sandbox output: {}",
        String::from_utf8_lossy(&first_output)
    );
    assert_eq!(
        second_status.code(),
        Some(0),
        "second sandbox output: {}",
        String::from_utf8_lossy(&second_output)
    );
}

#[test]
fn restricted_network_denies_an_unlisted_domain_target() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("target listener");
    let target = listener.local_addr().expect("target address");
    let workspace = TempDir::new().expect("workspace");
    let policy = SandboxPolicy::new(
        FilesystemPolicy::unrestricted(),
        NetworkPolicy::enabled().with_domain_mode(DomainMode::Restricted),
    );
    let (command, effective, runtime) =
        network_request(workspace.path(), &policy, "http-denied", target);
    let backend = backend();
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &runtime)
        .expect("prepare");
    let mut child = backend.spawn(prepared).expect("spawn");
    let mut error = String::new();
    child
        .stderr()
        .expect("stderr pipe")
        .read_to_string(&mut error)
        .expect("read stderr");
    let status = child.wait().expect("wait");
    assert_eq!(status.code(), Some(0), "sandbox stderr: {error}");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    assert!(
        listener.accept().is_err(),
        "denied target received a connection"
    );
}

#[test]
fn disabled_network_denies_direct_loopback_connections() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("target listener");
    let target = listener.local_addr().expect("target address");
    let workspace = TempDir::new().expect("workspace");
    let policy = SandboxPolicy::new(FilesystemPolicy::unrestricted(), NetworkPolicy::disabled());
    let (command, effective, runtime) =
        network_request(workspace.path(), &policy, "direct-denied", target);
    let backend = backend();
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &runtime)
        .expect("prepare");
    let mut child = backend.spawn(prepared).expect("spawn");
    assert_eq!(child.wait().expect("wait").code(), Some(0));
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    assert!(
        listener.accept().is_err(),
        "disabled network reached target"
    );
}

#[test]
fn disabled_network_accepts_irrelevant_unix_socket_rules() {
    let socket_directory = TempDir::new().expect("Unix socket directory");
    let denied = socket_directory.path().join("denied.sock");
    let workspace = TempDir::new().expect("workspace");
    let network = NetworkPolicy::disabled()
        .with_unix_socket_mode(UnixSocketMode::Enabled)
        .with_unix_socket(&denied, DomainAccess::Allow)
        .expect("irrelevant Unix socket rule");
    let policy = SandboxPolicy::new(FilesystemPolicy::unrestricted(), network);
    let (command, effective, runtime) =
        unix_network_request(workspace.path(), &policy, "unix-denied", &denied);
    let backend = backend();
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &runtime)
        .expect("disabled network must not reject irrelevant socket rules");
    let mut child = backend.spawn(prepared).expect("spawn");
    let status = child.wait().expect("wait");
    assert_eq!(status.code(), Some(0));
}

#[test]
fn unrestricted_network_preserves_direct_loopback_connections() {
    let (target, server) = start_http_server();
    let workspace = TempDir::new().expect("workspace");
    let policy = SandboxPolicy::full_access();
    let (command, effective, runtime) =
        network_request(workspace.path(), &policy, "direct", target);
    let backend = backend();
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &runtime)
        .expect("prepare");
    let mut child = backend.spawn(prepared).expect("spawn");
    assert_eq!(child.wait().expect("wait").code(), Some(0));
    server
        .join()
        .expect("HTTP server")
        .expect("HTTP server I/O");
}

#[test]
fn restricted_unix_socket_policy_allows_an_explicit_path() {
    let socket_directory = TempDir::new().expect("Unix socket directory");
    let allowed = socket_directory.path().join("allowed.sock");
    let server = start_unix_server(&allowed);
    let workspace = TempDir::new().expect("workspace");
    let network = NetworkPolicy::enabled()
        .with_local_network_access(LocalNetworkAccess::Allow)
        .with_unix_socket_mode(UnixSocketMode::Restricted)
        .with_unix_socket(&allowed, DomainAccess::Allow)
        .expect("allowed Unix socket rule");
    let policy = SandboxPolicy::new(FilesystemPolicy::unrestricted(), network);
    let (command, effective, context) =
        unix_network_request(workspace.path(), &policy, "unix", &allowed);
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
    assert_eq!(
        status.code(),
        Some(0),
        "sandbox stdout: {output}; stderr: {error}"
    );
    server
        .join()
        .expect("Unix server")
        .expect("Unix server I/O");
    fs::remove_file(&allowed).expect("remove allowed Unix socket");
}

#[test]
fn restricted_unix_socket_policy_allows_an_existing_symlink_alias() {
    use std::os::unix::fs::symlink;

    let socket_directory = TempDir::new().expect("Unix socket directory");
    let target = socket_directory.path().join("target.sock");
    let alias = socket_directory.path().join("alias.sock");
    let server = start_unix_server(&target);
    symlink(&target, &alias).expect("Unix socket alias");
    let workspace = TempDir::new().expect("workspace");
    let network = NetworkPolicy::enabled()
        .with_local_network_access(LocalNetworkAccess::Allow)
        .with_unix_socket_mode(UnixSocketMode::Restricted)
        .with_unix_socket(&alias, DomainAccess::Allow)
        .expect("allowed Unix socket alias");
    let policy = SandboxPolicy::new(FilesystemPolicy::unrestricted(), network);
    let (command, effective, context) =
        unix_network_request(workspace.path(), &policy, "unix", &alias);
    let backend = backend();
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &context)
        .expect("prepare");
    let mut child = backend.spawn(prepared).expect("spawn");
    let status = child.wait().expect("wait");
    assert_eq!(status.code(), Some(0));
    server
        .join()
        .expect("Unix server")
        .expect("Unix server I/O");
}

#[test]
fn enabled_unix_socket_policy_rejects_an_explicit_denial() {
    let socket_directory = TempDir::new().expect("Unix socket directory");
    let denied = socket_directory.path().join("denied.sock");
    let workspace = TempDir::new().expect("workspace");
    let network = NetworkPolicy::enabled()
        .with_local_network_access(LocalNetworkAccess::Allow)
        .with_unix_socket_mode(UnixSocketMode::Enabled)
        .with_unix_socket(&denied, DomainAccess::Deny)
        .expect("denied Unix socket rule");
    let policy = SandboxPolicy::new(FilesystemPolicy::unrestricted(), network);
    let (command, effective, context) =
        unix_network_request(workspace.path(), &policy, "unix-denied", &denied);
    let backend = backend();
    let error = backend
        .prepare(BackendRequest::new(&command, &effective), &context)
        .expect_err("unsupported explicit deny must fail before launch");
    assert!(matches!(
        error,
        MacosBackendError::Contract(BackendContractError::UnsupportedCapability {
            capability: BackendCapability::NetworkLocalIpcDenyRules
        })
    ));
}

#[test]
fn symlinked_seatbelt_executable_is_rejected_before_launch() {
    use std::os::unix::fs::symlink;

    let temporary = TempDir::new().expect("temporary directory");
    let link = temporary.path().join("sandbox-exec");
    symlink("/usr/bin/sandbox-exec", &link).expect("Seatbelt symlink");
    let error = MacosBackend::new(
        MacosBackendConfig::new()
            .with_seatbelt_executable(link.clone())
            .expect("absolute path"),
    )
    .expect_err("symlinked executable");
    assert!(matches!(
        error,
        MacosBackendError::SeatbeltExecutableSymlink { path } if path == link
    ));
}
