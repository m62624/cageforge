// SPDX-License-Identifier: Apache-2.0

#![cfg(target_os = "macos")]

use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use cageforge_backend_api::{BackendRequest, SandboxBackend};
use cageforge_command::{CommandRequest, CommandSpec, EnvironmentSpec, StdioMode, StdioSpec};
use cageforge_macos::{MacosBackend, MacosBackendConfig, MacosBackendError};
use cageforge_policy::{
    AccessMode, DomainAccess, DomainMode, FilesystemPolicy, FilesystemRule, NetworkPolicy,
    PathResolutionContext, PathSelector, SandboxPolicy,
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

fn network_policy() -> SandboxPolicy {
    let network = NetworkPolicy::enabled()
        .with_domain_mode(DomainMode::Restricted)
        .with_domain("127.0.0.1", DomainAccess::Allow)
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
                + "printf 'ready:%s:%s\\n' \"$descendant\" "
                + "\"$(ps -o pgid= -p \"$descendant\")\"; wait",
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
    let process_group = fields
        .next()
        .expect("descendant process group")
        .trim()
        .parse()
        .expect("numeric descendant process group");
    (descendant, process_group)
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
        other => panic!("unknown network fixture mode: {other}"),
    }
}

#[test]
fn restricted_network_reaches_only_the_authorized_loopback_target() {
    let (target, server) = start_http_server();
    let workspace = TempDir::new().expect("workspace");
    let policy = network_policy();
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
