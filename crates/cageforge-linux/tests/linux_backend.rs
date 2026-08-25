// SPDX-License-Identifier: Apache-2.0

#![cfg(target_os = "linux")]

use std::fs;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::num::NonZeroUsize;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::net::{UnixDatagram, UnixStream};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use cageforge_backend_api::{
    BackendCapability, BackendContractError, BackendRequest, SandboxBackend,
};
use cageforge_command::{CommandRequest, CommandSpec, EnvironmentSpec, StdioSpec};
use cageforge_config::Config;
use cageforge_linux::{
    FilesystemLoweringError, HardeningHelperSource, LinuxBackend, LinuxBackendConfig,
    LinuxBackendConfigError, LinuxBackendError, LinuxHelperRuntimeFailureKind,
    LinuxHelperSetupFailureKind, NetworkCombinationError, SetupHandshakeError,
};
use cageforge_network_proxy::GatewayConfig;
use cageforge_policy::{
    AccessMode, DomainAccess, DomainMode, FilesystemPolicy, FilesystemRule, LocalNetworkAccess,
    NetworkPolicy, PathResolutionContext, PathSelector, SandboxPolicy, UnixSocketMode,
};
use cageforge_policy_compose::{CompositionRequest, PolicyCeiling, compose};
use command_fds::CommandFdExt;
use pretty_assertions::assert_eq;
use tempfile::TempDir;

const SYNTHETIC_FIXTURE_WORKSPACE: &str = "CAGEFORGE_SYNTHETIC_FIXTURE_WORKSPACE";
const SYNTHETIC_FIXTURE_READY: &str = "CAGEFORGE_SYNTHETIC_FIXTURE_READY";
const SYNTHETIC_FIXTURE_RELEASE: &str = "CAGEFORGE_SYNTHETIC_FIXTURE_RELEASE";
const COMMON_SECCOMP_FIXTURE: &str = "CAGEFORGE_COMMON_SECCOMP_FIXTURE";
const CORE_LIMIT_FIXTURE: &str = "CAGEFORGE_CORE_LIMIT_FIXTURE";
const TRACER_GUARD_FIXTURE: &str = "CAGEFORGE_TRACER_GUARD_FIXTURE";
const TRACER_GUARD_DESCENDANT_FIXTURE: &str = "CAGEFORGE_TRACER_GUARD_DESCENDANT_FIXTURE";
const EXPECTED_TRACER_PID: &str = "CAGEFORGE_EXPECTED_TRACER_PID";
const CLONE_UNTRACED_FIXTURE: &str = "CAGEFORGE_CLONE_UNTRACED_FIXTURE";
const UNIX_SOCKET_BYPASS_TARGET: &str = "CAGEFORGE_UNIX_SOCKET_BYPASS_TARGET";

fn backend() -> LinuxBackend {
    LinuxBackend::new(test_backend_config())
        .expect("Linux CI requires usable Bubblewrap and hardening helper")
}

fn test_backend_config() -> LinuxBackendConfig {
    let config = LinuxBackendConfig::new()
        .with_hardening_helper_path(env!("CARGO_BIN_EXE_cageforge-linux-helper"));
    #[cfg(feature = "bundled-bubblewrap")]
    let config = config.with_bundled_bubblewrap();
    match std::env::var_os("CAGEFORGE_BWRAP_TEST_RESOURCE_DIR") {
        Some(path) => config
            .with_resource_directory(path)
            .with_bundled_bubblewrap(),
        None => config,
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
    request_with_environment(workspace, policy, command, EnvironmentSpec::inherit_all())
}

fn request_with_environment(
    workspace: &Path,
    policy: SandboxPolicy,
    command: CommandSpec,
    environment: EnvironmentSpec,
) -> (
    CommandRequest,
    cageforge_policy_compose::EffectiveSandbox,
    PathResolutionContext,
) {
    let ceiling = PolicyCeiling::new(SandboxPolicy::full_access(), environment.clone());
    let effective = compose(CompositionRequest::new(&policy, &environment, &ceiling))
        .expect("policies compose");
    let command = CommandRequest::new(command)
        .with_working_directory(workspace.to_path_buf())
        .expect("cwd")
        .with_environment(environment);
    (command, effective, context(workspace))
}

fn nested_repository_filesystem(parent: &Path, workspace: &Path) -> FilesystemPolicy {
    FilesystemPolicy::restricted([
        FilesystemRule::new(PathSelector::minimal(), AccessMode::Read),
        FilesystemRule::new(
            PathSelector::absolute(parent).expect("parent repository selector"),
            AccessMode::Read,
        ),
        FilesystemRule::new(
            PathSelector::absolute(workspace).expect("nested workspace selector"),
            AccessMode::Write,
        ),
    ])
}

fn restricted_loopback_policy() -> SandboxPolicy {
    let network = NetworkPolicy::enabled()
        .with_domain_mode(DomainMode::Restricted)
        .with_domain("127.0.0.1", DomainAccess::Allow)
        .expect("loopback rule");
    SandboxPolicy::new(FilesystemPolicy::unrestricted(), network)
}

fn network_client_command() -> CommandSpec {
    CommandSpec::new(std::env::current_exe().expect("integration test executable"))
        .expect("test command")
        .with_args(["--exact", "network_client_fixture", "--nocapture"])
        .expect("test arguments")
}

fn network_environment(mode: &str, target: SocketAddr) -> EnvironmentSpec {
    EnvironmentSpec::inherit_all()
        .with_var("CAGEFORGE_NETWORK_TEST_MODE", mode)
        .expect("mode")
        .with_var("CAGEFORGE_NETWORK_TEST_TARGET", target.to_string())
        .expect("target")
}

fn spawn_network_client(
    policy: SandboxPolicy,
    mode: &str,
    target: SocketAddr,
) -> Result<std::process::ExitStatus, LinuxBackendError> {
    let backend = backend();
    spawn_network_client_with_backend(&backend, policy, mode, target)
}

fn spawn_network_client_with_backend(
    backend: &LinuxBackend,
    policy: SandboxPolicy,
    mode: &str,
    target: SocketAddr,
) -> Result<std::process::ExitStatus, LinuxBackendError> {
    let temp = TempDir::new().expect("temporary workspace");
    let environment = network_environment(mode, target);
    let (command, effective, runtime) =
        request_with_environment(temp.path(), policy, network_client_command(), environment);
    let prepared = backend.prepare(BackendRequest::new(&command, &effective), &runtime)?;
    let mut child = backend.spawn(prepared)?;
    let status = child.wait()?;
    let mut stderr = String::new();
    child
        .stderr()
        .expect("network fixture stderr")
        .read_to_string(&mut stderr)
        .expect("network fixture stderr read");
    if !status.success() {
        eprintln!("network fixture failed with {status}: {stderr}");
    }
    Ok(status)
}

fn start_http_server() -> (SocketAddr, thread::JoinHandle<io::Result<()>>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("HTTP listener");
    let address = listener.local_addr().expect("HTTP address");
    let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
    let server = thread::spawn(move || -> io::Result<()> {
        ready_sender
            .send(())
            .expect("HTTP server readiness receiver");
        let (mut stream, _) = listener.accept()?;
        stream.set_read_timeout(Some(Duration::from_secs(3)))?;
        stream.set_write_timeout(Some(Duration::from_secs(3)))?;

        let mut request = Vec::with_capacity(4096);
        let mut chunk = [0; 1024];
        loop {
            let read = stream.read(&mut chunk)?;
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "HTTP client closed before the complete request",
                ));
            }
            request.extend_from_slice(&chunk[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
            if request.len() > 16 * 1024 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "HTTP request headers exceeded the fixture limit",
                ));
            }
        }

        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")?;
        stream.shutdown(Shutdown::Write)?;
        let mut client_close = [0; 1];
        while stream.read(&mut client_close)? != 0 {}
        Ok(())
    });
    ready_receiver.recv().expect("HTTP server readiness signal");
    (address, server)
}

fn proxy_endpoint(variable: &str) -> SocketAddr {
    let value = std::env::var(variable).expect("proxy endpoint");
    value
        .split_once("://")
        .map(|(_, authority)| authority)
        .unwrap_or(&value)
        .trim_end_matches('/')
        .parse()
        .expect("loopback proxy address")
}

fn send_http_proxy_request(target: SocketAddr) -> Vec<u8> {
    try_send_http_proxy_request(target).expect("proxy response")
}

fn try_send_http_proxy_request(target: SocketAddr) -> io::Result<Vec<u8>> {
    let mut stream = TcpStream::connect(proxy_endpoint("HTTP_PROXY"))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    write!(
        stream,
        "GET http://{target}/ HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
    )?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    Ok(response)
}

fn send_socks_request(target: SocketAddr) -> Vec<u8> {
    let mut stream = TcpStream::connect(proxy_endpoint("ALL_PROXY")).expect("SOCKS proxy");
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("read timeout");
    stream.write_all(&[5, 1, 0]).expect("SOCKS greeting");
    let mut greeting = [0; 2];
    stream.read_exact(&mut greeting).expect("SOCKS selection");
    assert_eq!(greeting, [5, 0]);
    let SocketAddr::V4(target) = target else {
        panic!("test target must be IPv4");
    };
    let mut connect = vec![5, 1, 0, 1];
    connect.extend(target.ip().octets());
    connect.extend(target.port().to_be_bytes());
    stream.write_all(&connect).expect("SOCKS connect");
    let mut reply = [0; 10];
    stream.read_exact(&mut reply).expect("SOCKS reply");
    assert_eq!(reply[1], 0);
    write!(
        stream,
        "GET / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
    )
    .expect("tunneled request");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .expect("tunneled response");
    response
}

fn send_direct_request(target: SocketAddr) -> Vec<u8> {
    let mut stream = TcpStream::connect(target).expect("direct target");
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .expect("write timeout");
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("read timeout");
    write!(
        stream,
        "GET / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
    )
    .expect("direct request");
    let mut response = Vec::new();
    stream.read_to_end(&mut response).expect("direct response");
    response
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
        "http" => assert!(send_http_proxy_request(target).starts_with(b"HTTP/1.1 200")),
        "http-denied" => {
            assert!(!send_http_proxy_request(target).starts_with(b"HTTP/1.1 200"));
        }
        "socks" => assert!(send_socks_request(target).starts_with(b"HTTP/1.1 200")),
        "direct" => assert!(send_direct_request(target).starts_with(b"HTTP/1.1 200")),
        "direct-denied" => {
            assert!(TcpStream::connect_timeout(&target, Duration::from_millis(250)).is_err());
        }
        "unix-denied" => {
            assert!(UnixStream::connect("/dev/.cageforge-runtime/network/gateway.sock").is_err());
            assert!(UnixStream::pair().is_ok());
        }
        "stalled-proxy-slot" => {
            let mut stalled =
                TcpStream::connect(proxy_endpoint("HTTP_PROXY")).expect("first proxy connection");
            stalled
                .set_read_timeout(Some(Duration::from_secs(3)))
                .expect("stalled proxy read timeout");
            let mut end = [0; 1];
            assert_eq!(
                stalled.read(&mut end).expect("stalled proxy closure"),
                0,
                "gateway timeout did not close its response half"
            );
            let deadline = Instant::now() + Duration::from_secs(3);
            loop {
                match try_send_http_proxy_request(target) {
                    Ok(response) if response.starts_with(b"HTTP/1.1 200") => break,
                    Ok(_) | Err(_) if Instant::now() < deadline => {
                        thread::sleep(Duration::from_millis(1));
                    }
                    result => panic!("local bridge slot was not released: {result:?}"),
                }
            }
        }
        other => panic!("unknown network fixture mode: {other}"),
    }
}

#[test]
fn multiprocess_synthetic_owner_fixture() {
    let Some(workspace) = std::env::var_os(SYNTHETIC_FIXTURE_WORKSPACE) else {
        return;
    };
    let ready = PathBuf::from(
        std::env::var_os(SYNTHETIC_FIXTURE_READY).expect("fixture ready-marker path"),
    );
    let release = std::env::var_os(SYNTHETIC_FIXTURE_RELEASE)
        .expect("fixture release-marker path")
        .to_string_lossy()
        .into_owned();
    let workspace = PathBuf::from(workspace);
    let environment = EnvironmentSpec::inherit_all()
        .with_var("CAGEFORGE_SYNTHETIC_RELEASE", release)
        .expect("fixture release environment");
    let command = CommandSpec::new("/bin/sh")
        .expect("shell")
        .with_args([
            "-c",
            "while [ ! -e \"$CAGEFORGE_SYNTHETIC_RELEASE\" ]; do sleep 0.01; done; \
             if mkdir .git 2>/dev/null; then exit 17; else exit 0; fi",
        ])
        .expect("fixture command");
    let (command, effective, runtime) =
        request_with_environment(&workspace, SandboxPolicy::workspace(), command, environment);
    let backend = backend();
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &runtime)
        .expect("fixture preflight");
    let mut child = backend.spawn(prepared).expect("fixture spawn");
    std::fs::write(ready, b"ready").expect("fixture ready marker");

    assert_eq!(child.wait().expect("fixture wait").code(), Some(0));
}

#[test]
fn common_seccomp_fixture() {
    if std::env::var_os(COMMON_SECCOMP_FIXTURE).is_none() {
        return;
    }
    #[allow(unsafe_code)]
    let result = unsafe {
        libc::ptrace(
            libc::PTRACE_TRACEME,
            0,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        )
    };
    assert_eq!(result, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EPERM)
    );
    #[allow(unsafe_code)]
    let ip_socket = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    assert!(ip_socket >= 0, "direct IP sockets must remain available");
    #[allow(unsafe_code)]
    unsafe {
        libc::close(ip_socket);
    }
    #[allow(unsafe_code)]
    let unix_socket = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    assert_eq!(unix_socket, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EPERM)
    );
    #[allow(unsafe_code)]
    let mut socket_pair = [-1; 2];
    #[allow(unsafe_code)]
    let result = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            socket_pair.as_mut_ptr(),
        )
    };
    assert_eq!(result, 0, "local socketpair IPC must remain available");
    #[allow(unsafe_code)]
    unsafe {
        libc::close(socket_pair[0]);
        libc::close(socket_pair[1]);
    }

    if let Some(target) = std::env::var_os(UNIX_SOCKET_BYPASS_TARGET) {
        let mut datagram_pair = [-1; 2];
        #[allow(unsafe_code)]
        let result = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_DGRAM | libc::SOCK_NONBLOCK,
                0,
                datagram_pair.as_mut_ptr(),
            )
        };
        if result == -1 {
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EPERM)
            );
        } else {
            assert_eq!(result, 0, "unexpected datagram socketpair result");
            #[allow(unsafe_code)]
            let socket = unsafe { UnixDatagram::from_raw_fd(datagram_pair[0]) };
            #[allow(unsafe_code)]
            unsafe {
                libc::close(datagram_pair[1]);
            }
            match socket.connect(&target) {
                Ok(()) => {
                    socket
                        .send(b"bypass")
                        .expect("send through pathname Unix bypass");
                }
                Err(error) => assert_eq!(error.raw_os_error(), Some(libc::EPERM)),
            }
        }

        let mut seqpacket_pair = [-1; 2];
        #[allow(unsafe_code)]
        let result = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                0,
                seqpacket_pair.as_mut_ptr(),
            )
        };
        assert_eq!(result, -1, "seqpacket socketpair must be denied");
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EPERM)
        );
    }
}

#[test]
fn core_limit_fixture() {
    if std::env::var_os(CORE_LIMIT_FIXTURE).is_none() {
        return;
    }
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    #[allow(unsafe_code)]
    let result = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) };
    assert_eq!(result, 0);
    assert_eq!(
        limit.rlim_cur, 0,
        "restricted child must not create core dumps"
    );
    assert_eq!(
        limit.rlim_max, 0,
        "restricted child must not raise core limit"
    );
}

fn proc_status_pid(field: &str) -> u32 {
    let status = fs::read_to_string("/proc/self/status").expect("process status");
    status
        .lines()
        .find_map(|line| {
            let value = line.strip_prefix(field)?.trim();
            value.parse().ok()
        })
        .unwrap_or_else(|| panic!("missing {field} in /proc/self/status"))
}

#[test]
fn tracer_guard_fixture() {
    if std::env::var_os(TRACER_GUARD_FIXTURE).is_none() {
        return;
    }
    let tracer_pid = proc_status_pid("TracerPid:");
    assert_ne!(tracer_pid, 0, "restricted child must have a tracer");
    assert_eq!(
        tracer_pid,
        proc_status_pid("PPid:"),
        "the direct trusted helper must trace the root command"
    );

    let descendant_status = Command::new(std::env::current_exe().expect("test executable"))
        .args(["--exact", "tracer_guard_descendant_fixture", "--nocapture"])
        .env(TRACER_GUARD_DESCENDANT_FIXTURE, "1")
        .env(EXPECTED_TRACER_PID, tracer_pid.to_string())
        .status()
        .expect("descendant fixture");
    assert!(
        descendant_status.success(),
        "descendant fixture failed with {descendant_status}"
    );
}

#[test]
fn tracer_guard_descendant_fixture() {
    if std::env::var_os(TRACER_GUARD_DESCENDANT_FIXTURE).is_none() {
        return;
    }
    let expected = std::env::var(EXPECTED_TRACER_PID)
        .expect("expected tracer")
        .parse::<u32>()
        .expect("numeric tracer");
    assert_eq!(
        proc_status_pid("TracerPid:"),
        expected,
        "descendants must remain under the trusted helper tracer"
    );
}

#[test]
fn clone_untraced_fixture() {
    if std::env::var_os(CLONE_UNTRACED_FIXTURE).is_none() {
        return;
    }
    #[allow(unsafe_code)]
    let clone3 =
        unsafe { libc::syscall(libc::SYS_clone3, std::ptr::null_mut::<libc::c_void>(), 0) };
    assert_eq!(clone3, -1);
    assert_eq!(
        io::Error::last_os_error().raw_os_error(),
        Some(libc::ENOSYS),
        "clone3 must request a compatible clone fallback because seccomp cannot inspect its flags"
    );

    #[allow(unsafe_code)]
    let pid = unsafe {
        libc::syscall(
            libc::SYS_clone,
            libc::CLONE_UNTRACED | libc::SIGCHLD,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
            0,
        )
    };
    if pid == 0 {
        #[allow(unsafe_code)]
        let trace_me = unsafe {
            libc::ptrace(
                libc::PTRACE_TRACEME,
                0,
                std::ptr::null_mut::<libc::c_void>(),
                std::ptr::null_mut::<libc::c_void>(),
            )
        };
        #[allow(unsafe_code)]
        unsafe {
            libc::_exit(if trace_me == -1 { 0 } else { 42 });
        }
    }
    if pid == -1 {
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::EPERM),
            "CLONE_UNTRACED must fail closed"
        );
        return;
    }
    assert!(pid > 0, "clone returned invalid PID {pid}");
    let mut status = 0;
    #[allow(unsafe_code)]
    let waited = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, 0) };
    assert_eq!(waited, pid as libc::pid_t);
    assert!(libc::WIFEXITED(status));
    assert_eq!(
        libc::WEXITSTATUS(status),
        0,
        "CLONE_UNTRACED escaped trusted trace supervision"
    );
}

fn wait_for_marker(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !path.exists() {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {}",
            path.display()
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn spawn_synthetic_owner_fixture(
    workspace: &Path,
    temp_directory: &Path,
    ready: &Path,
    release: &Path,
) -> std::process::Child {
    Command::new(std::env::current_exe().expect("integration test executable"))
        .args([
            "--exact",
            "multiprocess_synthetic_owner_fixture",
            "--nocapture",
        ])
        .env("TMPDIR", temp_directory)
        .env(SYNTHETIC_FIXTURE_WORKSPACE, workspace)
        .env(SYNTHETIC_FIXTURE_READY, ready)
        .env(SYNTHETIC_FIXTURE_RELEASE, release)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn synthetic-owner fixture")
}

fn assert_fixture_success(output: std::process::Output) {
    assert!(
        output.status.success(),
        "fixture failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
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
fn writable_child_remains_available_below_a_read_only_parent() {
    let workspace = TempDir::new().expect("temporary workspace");
    let readonly = workspace.path().join("readonly");
    let allowed = readonly.join("allowed");
    std::fs::create_dir_all(&allowed).expect("allowed directory");
    let parent_file = readonly.join("parent.txt");
    std::fs::write(&parent_file, "original").expect("read-only fixture");
    let output = allowed.join("output.txt");
    let policy = SandboxPolicy::new(
        FilesystemPolicy::restricted([
            FilesystemRule::new(PathSelector::minimal(), AccessMode::Read),
            FilesystemRule::new(PathSelector::workspace_root(), AccessMode::Write)
                .with_read_only_subpath(
                    PathSelector::workspace("readonly").expect("read-only selector"),
                )
                .expect("read-only carveout"),
            FilesystemRule::new(
                PathSelector::workspace("readonly/allowed").expect("allowed selector"),
                AccessMode::Write,
            ),
        ]),
        NetworkPolicy::disabled(),
    );
    let script = format!(
        "if printf changed > {} 2>/dev/null; then exit 17; fi; printf allowed > {}",
        parent_file.display(),
        output.display()
    );
    let command = CommandSpec::new("/bin/sh")
        .expect("shell")
        .with_args(["-c", script.as_str()])
        .expect("arguments");
    let (command, effective, runtime) = request(workspace.path(), policy, command);
    let backend = backend();
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &runtime)
        .expect("preflight");
    let mut child = backend.spawn(prepared).expect("spawn");

    assert_eq!(child.wait().expect("wait").code(), Some(0));
    assert_eq!(
        std::fs::read_to_string(output).expect("allowed output"),
        "allowed"
    );
    assert_eq!(
        std::fs::read_to_string(parent_file).expect("parent file"),
        "original"
    );
}

#[test]
fn unrelated_inherited_file_descriptors_do_not_cross_the_sandbox_boundary() {
    let workspace = TempDir::new().expect("temporary workspace");
    let outside = TempDir::new_in("/var/tmp").expect("outside directory");
    let secret_path = outside.path().join("secret.txt");
    std::fs::write(&secret_path, "secret").expect("secret fixture");
    let secret = std::fs::File::open(&secret_path).expect("open secret fixture");
    let secret_fd = secret.as_raw_fd();
    #[allow(unsafe_code)]
    let flags = unsafe { libc::fcntl(secret_fd, libc::F_GETFD) };
    assert_ne!(flags, -1, "read secret fd flags");
    #[allow(unsafe_code)]
    let result = unsafe { libc::fcntl(secret_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) };
    assert_ne!(result, -1, "make test descriptor inheritable");

    let policy = SandboxPolicy::new(
        FilesystemPolicy::restricted([
            FilesystemRule::new(PathSelector::minimal(), AccessMode::Read),
            FilesystemRule::new(PathSelector::workspace_root(), AccessMode::Write),
        ]),
        NetworkPolicy::disabled(),
    );
    let script = format!("if IFS= read -r value <&{secret_fd}; then exit 17; else exit 0; fi");
    let command = CommandSpec::new("/bin/sh")
        .expect("shell")
        .with_args(["-c", script.as_str()])
        .expect("arguments");
    let (command, effective, runtime) = request(workspace.path(), policy, command);
    let backend = backend();
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &runtime)
        .expect("preflight");
    let mut child = backend.spawn(prepared).expect("spawn");

    assert_eq!(child.wait().expect("wait").code(), Some(0));
}

#[test]
fn pinned_mount_source_descriptors_do_not_reach_the_user_command() {
    let workspace = TempDir::new().expect("temporary workspace");
    let script = format!(
        "for fd in /proc/self/fd/*; do \
         target=$(readlink \"$fd\" 2>/dev/null) || continue; \
         case \"$target\" in /|/usr|{}) printf 'leaked mount fd: %s -> %s\\n' \"$fd\" \"$target\" >&2; exit 17;; esac; \
         done; exit 0",
        workspace.path().display()
    );
    let command = CommandSpec::new("/bin/sh")
        .expect("shell")
        .with_args(["-c", script.as_str()])
        .expect("arguments");
    let (command, effective, runtime) =
        request(workspace.path(), SandboxPolicy::workspace(), command);
    let backend = backend();
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &runtime)
        .expect("preflight");
    let mut child = backend.spawn(prepared).expect("spawn");

    assert_eq!(child.wait().expect("wait").code(), Some(0));
}

#[test]
fn parallel_backend_spawns_do_not_inherit_another_instances_mount_descriptors() {
    const INSTANCE_COUNT: usize = 12;

    let root = TempDir::new().expect("shared temporary root");
    let root_path = root.path().to_path_buf();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(INSTANCE_COUNT));
    let mut workers = Vec::with_capacity(INSTANCE_COUNT);
    for index in 0..INSTANCE_COUNT {
        let workspace = root_path.join(format!("instance-{index}"));
        std::fs::create_dir(&workspace).expect("instance workspace");
        let shared_root = root_path.clone();
        let barrier = barrier.clone();
        workers.push(thread::spawn(move || {
            let script = format!(
                "for fd in /proc/self/fd/*; do \
                 target=$(readlink \"$fd\" 2>/dev/null) || continue; \
                 case \"$target\" in {}/*) exit 17;; esac; \
                 done; exit 0",
                shared_root.display()
            );
            let command = CommandSpec::new("/bin/sh")
                .expect("shell")
                .with_args(["-c", script.as_str()])
                .expect("arguments");
            let (command, effective, runtime) =
                request(&workspace, SandboxPolicy::workspace(), command);
            let backend = backend();
            let prepared = backend
                .prepare(BackendRequest::new(&command, &effective), &runtime)
                .expect("preflight");
            barrier.wait();
            let mut child = backend.spawn(prepared).expect("spawn");
            child.wait().expect("wait").code()
        }));
    }

    for worker in workers {
        assert_eq!(worker.join().expect("worker"), Some(0));
    }
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
fn backend_configuration_rejects_a_zero_default_timeout() {
    assert_eq!(
        LinuxBackendConfig::new().hardening_helper_source(),
        &HardeningHelperSource::SiblingThenResource
    );
    assert_eq!(
        LinuxBackendConfig::new().with_default_timeout(Duration::ZERO),
        Err(LinuxBackendConfigError::ZeroDefaultTimeout)
    );
}

#[test]
fn command_signal_termination_is_preserved_by_the_backend_boundary() {
    let temp = TempDir::new().expect("temporary workspace");
    let command = CommandSpec::new("/bin/sh")
        .expect("shell")
        .with_args(["-c", "kill -TERM $$"])
        .expect("arguments");
    let (command, effective, runtime) = request(temp.path(), SandboxPolicy::workspace(), command);
    let backend = backend();
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &runtime)
        .expect("preflight");
    let mut child = backend.spawn(prepared).expect("spawn");

    let status = child.wait().expect("wait");
    assert_eq!(
        status.signal(),
        Some(libc::SIGTERM),
        "unexpected command status: {status:?}"
    );
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

#[test]
fn hardening_helper_rejects_an_invalid_authentication_descriptor() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_cageforge-linux-helper"))
        .args(["--apply-hardening", "/bin/true"])
        .env("CAGEFORGE_LINUX_HELPER_AUTH_FD", "-1")
        .output()
        .expect("helper");

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid Linux hardening helper"));
}

#[test]
fn hardening_helper_rejects_a_forged_authentication_protocol_from_a_visible_peer() {
    let (mut peer, helper_socket) = UnixStream::pair().expect("authentication socket");
    peer.set_read_timeout(Some(Duration::from_secs(2)))
        .expect("authentication read timeout");
    let helper_fd = helper_socket.as_raw_fd();
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_cageforge-linux-helper"));
    command
        .args(["--apply-hardening", "/bin/true"])
        .env("CAGEFORGE_LINUX_HELPER_AUTH_FD", helper_fd.to_string())
        .stderr(Stdio::piped())
        .preserved_fds(vec![helper_socket.into()]);
    let child = command.spawn().expect("helper");
    drop(command);
    let frame_sent = peer
        .write_all(b"cageforge-linux-helper-v1CFENV\x01\x00\x00\x00\x00\x00\x00\x00\x00")
        .is_ok();
    let mut ready = [0; 4];
    let helper_replied = frame_sent && peer.read_exact(&mut ready).is_ok();
    if helper_replied {
        let _ = peer.write_all(b"run");
    }
    drop(peer);
    let output = child.wait_with_output().expect("helper");

    assert!(!output.status.success());
    assert!(!helper_replied, "a visible peer must not complete setup");
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid Linux hardening helper"));
}

#[test]
fn user_dynamic_loader_environment_reaches_only_the_sandboxed_command() {
    let workspace = TempDir::new().expect("temporary workspace");
    let outside = TempDir::new_in("/var/tmp").expect("outside directory");
    let source = workspace.path().join("preload.c");
    let library = workspace.path().join("preload.so");
    let marker = outside.path().join("escaped");
    std::fs::write(
        &source,
        r#"
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
__attribute__((constructor)) static void cageforge_probe(void) {
    const char *path = getenv("CAGEFORGE_PRELOAD_MARKER");
    if (path == NULL) return;
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd >= 0) { (void)write(fd, "escaped", 7); (void)close(fd); }
}
"#,
    )
    .expect("preload source");
    let compiler = std::process::Command::new("cc")
        .args(["-shared", "-fPIC", "-o"])
        .arg(&library)
        .arg(&source)
        .status()
        .expect("C compiler required by Linux native tests");
    assert!(compiler.success(), "failed to build preload fixture");

    let environment = EnvironmentSpec::inherit_all()
        .with_var("LD_PRELOAD", library.as_os_str())
        .expect("preload variable")
        .with_var("CAGEFORGE_PRELOAD_MARKER", marker.as_os_str())
        .expect("marker variable");
    let (command, effective, runtime) = request_with_environment(
        workspace.path(),
        SandboxPolicy::workspace(),
        CommandSpec::new("/bin/true").expect("command"),
        environment,
    );
    let backend = backend();
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &runtime)
        .expect("preflight");
    let mut child = backend.spawn(prepared).expect("spawn");
    assert_eq!(child.wait().expect("wait").code(), Some(0));
    assert!(
        !marker.exists(),
        "user LD_PRELOAD executed before the filesystem sandbox was active"
    );
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
    assert!(
        matches!(error, LinuxBackendError::FilesystemLoweringFailed { .. }),
        "unexpected lowering error: {error:?}"
    );
}

#[test]
fn missing_protected_path_rejects_writable_symlink_before_host_creation() {
    use std::os::unix::fs::PermissionsExt;

    let workspace = TempDir::new().expect("temporary workspace");
    let outside = TempDir::new_in("/var/tmp").expect("outside directory");
    let link = workspace.path().join("redirect");
    std::os::unix::fs::symlink(outside.path(), &link).expect("symlink fixture");
    std::fs::set_permissions(outside.path(), std::fs::Permissions::from_mode(0o555))
        .expect("read-only outside directory");
    let filesystem = SandboxPolicy::workspace()
        .filesystem()
        .clone()
        .with_additional_protected_relative_path("redirect/missing")
        .expect("protected path");
    let policy = SandboxPolicy::new(filesystem, NetworkPolicy::disabled());
    let command = CommandSpec::new("/bin/true").expect("command");
    let (command, effective, runtime) = request(workspace.path(), policy, command);
    let backend = backend();
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &runtime)
        .expect("preflight");
    let error = match backend.spawn(prepared) {
        Ok(_) => panic!("missing protected path below a writable symlink must fail closed"),
        Err(error) => error,
    };

    std::fs::set_permissions(outside.path(), std::fs::Permissions::from_mode(0o700))
        .expect("restore outside permissions");
    assert!(
        matches!(
            &error,
            LinuxBackendError::FilesystemLoweringFailed {
                source: FilesystemLoweringError::WritableSymlink { .. },
                ..
            }
        ),
        "symlink must be rejected before host creation, got: {error:?}"
    );
    assert!(!outside.path().join("missing").exists());
}

#[test]
fn missing_path_skip_does_not_suppress_non_not_found_errors() {
    let workspace = TempDir::new().expect("temporary workspace");
    let blocking_file = workspace.path().join("not-a-directory");
    std::fs::write(&blocking_file, "blocking file").expect("blocking fixture");
    let invalid_child = blocking_file.join("child");
    let deny = FilesystemRule::new(
        PathSelector::absolute(&invalid_child).expect("absolute deny path"),
        AccessMode::Deny,
    )
    .with_missing_path_behavior(cageforge_policy::MissingPathBehavior::Skip);
    let policy = SandboxPolicy::new(
        FilesystemPolicy::restricted([
            FilesystemRule::new(PathSelector::root(), AccessMode::Read),
            FilesystemRule::new(PathSelector::minimal(), AccessMode::Read),
            deny,
        ]),
        NetworkPolicy::disabled(),
    );
    let command = CommandSpec::new("/bin/true").expect("command");
    let (command, effective, runtime) = request(workspace.path(), policy, command);
    let backend = backend();
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &runtime)
        .expect("preflight");
    let error = match backend.spawn(prepared) {
        Ok(_) => panic!("skip must not suppress a non-NotFound filesystem error"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        LinuxBackendError::FilesystemLoweringFailed { path, .. } if path == invalid_child
    ));
}

#[test]
fn deny_glob_is_expanded_and_enforced_before_launch() {
    let temp = TempDir::new().expect("temporary workspace");
    let secret_dir = temp.path().join("secret/nested");
    std::fs::create_dir_all(&secret_dir).expect("secret directory");
    let secret = secret_dir.join("token.txt");
    let public = temp.path().join("public.txt");
    std::fs::write(&secret, "secret").expect("secret fixture");
    std::fs::write(&public, "public").expect("public fixture");
    let policy = SandboxPolicy::new(
        FilesystemPolicy::restricted([
            FilesystemRule::new(PathSelector::root(), AccessMode::Read),
            FilesystemRule::new(PathSelector::minimal(), AccessMode::Read),
            FilesystemRule::new(PathSelector::workspace_root(), AccessMode::Write),
            FilesystemRule::workspace_glob("secret/**", AccessMode::Deny).expect("glob"),
        ]),
        NetworkPolicy::disabled(),
    );
    let command = CommandSpec::new("/bin/sh")
        .expect("shell")
        .with_args([
            "-c",
            &format!(
                "cat {} >/dev/null || exit 18; if cat {} >/dev/null 2>/dev/null; then exit 17; else exit 0; fi",
                public.display(),
                secret.display()
            ),
        ])
        .expect("arguments");
    let (command, effective, runtime) = request(temp.path(), policy, command);
    let backend = backend();
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &runtime)
        .expect("glob preflight");
    let mut child = backend.spawn(prepared).expect("spawn");
    assert_eq!(child.wait().expect("wait").code(), Some(0));
    assert_eq!(
        std::fs::read_to_string(secret).expect("host secret"),
        "secret"
    );
}

#[test]
fn deny_glob_cannot_be_bypassed_through_a_symlinked_directory() {
    let workspace = TempDir::new().expect("temporary workspace");
    let outside = TempDir::new_in("/var/tmp").expect("outside directory");
    std::fs::write(outside.path().join("token.txt"), "secret").expect("secret fixture");
    std::os::unix::fs::symlink(outside.path(), workspace.path().join("linked"))
        .expect("directory symlink");
    let policy = SandboxPolicy::new(
        FilesystemPolicy::restricted([
            FilesystemRule::new(PathSelector::root(), AccessMode::Read),
            FilesystemRule::new(PathSelector::minimal(), AccessMode::Read),
            FilesystemRule::new(PathSelector::workspace_root(), AccessMode::Write),
            FilesystemRule::workspace_glob("**/token.txt", AccessMode::Deny).expect("glob"),
        ]),
        NetworkPolicy::disabled(),
    );
    let (command, effective, runtime) = request(
        workspace.path(),
        policy,
        CommandSpec::new("/bin/true").expect("command"),
    );
    let backend = backend();
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &runtime)
        .expect("preflight");
    let error = match backend.spawn(prepared) {
        Ok(_) => panic!("symlinked deny-glob must not launch without a complete mask"),
        Err(error) => error,
    };
    assert!(
        matches!(error, LinuxBackendError::FilesystemLoweringFailed { .. }),
        "unexpected lowering error: {error:?}"
    );
}

#[test]
fn deny_glob_scan_terminates_on_a_directory_symlink_cycle() {
    let workspace = TempDir::new().expect("temporary workspace");
    std::fs::create_dir(workspace.path().join("cycle")).expect("cycle directory");
    std::os::unix::fs::symlink(
        workspace.path(),
        workspace.path().join("cycle").join("workspace"),
    )
    .expect("cycle symlink");
    let policy = SandboxPolicy::new(
        FilesystemPolicy::restricted([
            FilesystemRule::new(PathSelector::root(), AccessMode::Read),
            FilesystemRule::new(PathSelector::minimal(), AccessMode::Read),
            FilesystemRule::new(PathSelector::workspace_root(), AccessMode::Write),
            FilesystemRule::workspace_glob("**/*.secret", AccessMode::Deny).expect("glob"),
        ]),
        NetworkPolicy::disabled(),
    );
    let (command, effective, runtime) = request(
        workspace.path(),
        policy,
        CommandSpec::new("/bin/true").expect("command"),
    );
    let backend = backend();
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &runtime)
        .expect("preflight");
    let mut child = backend.spawn(prepared).expect("cycle-safe spawn");
    assert_eq!(child.wait().expect("wait").code(), Some(0));
}

#[test]
fn missing_protected_git_path_is_not_created_on_the_host() {
    let temp = TempDir::new().expect("temporary workspace");
    let git = temp.path().join(".git");
    let command = CommandSpec::new("/bin/sh")
        .expect("shell")
        .with_args([
            "-c",
            "if mkdir .git 2>/dev/null; then exit 17; else exit 0; fi",
        ])
        .expect("arguments");
    let (command, effective, runtime) = request(temp.path(), SandboxPolicy::workspace(), command);
    let backend = backend();
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &runtime)
        .expect("preflight");
    let mut child = backend.spawn(prepared).expect("spawn");

    assert_eq!(child.wait().expect("wait").code(), Some(0));
    assert!(
        !git.exists(),
        "sandbox setup left a protected host artifact"
    );
}

#[test]
fn missing_nested_git_remains_absent_for_parent_repository_discovery() {
    let parent = TempDir::new().expect("parent repository");
    std::fs::create_dir(parent.path().join(".git")).expect("parent metadata");
    std::fs::write(parent.path().join(".git/HEAD"), "ref: refs/heads/main\n").expect("parent HEAD");
    let workspace = parent.path().join("nested");
    std::fs::create_dir(&workspace).expect("nested workspace");
    let policy = SandboxPolicy::new(
        nested_repository_filesystem(parent.path(), &workspace),
        NetworkPolicy::disabled(),
    );
    let command = CommandSpec::new("/bin/sh")
        .expect("shell")
        .with_args(["-c", "test ! -e .git && test -r ../.git/HEAD"])
        .expect("arguments");
    let (command, effective, runtime) = request(&workspace, policy, command);
    let backend = backend();
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &runtime)
        .expect("preflight");
    let mut child = backend.spawn(prepared).expect("spawn");

    assert_eq!(child.wait().expect("wait").code(), Some(0));
    assert!(!workspace.join(".git").exists());
}

#[test]
fn creating_monitored_nested_git_is_removed_and_reported() {
    let parent = TempDir::new().expect("parent repository");
    std::fs::create_dir(parent.path().join(".git")).expect("parent metadata");
    std::fs::write(parent.path().join(".git/HEAD"), "ref: refs/heads/main\n").expect("parent HEAD");
    let workspace = parent.path().join("nested");
    std::fs::create_dir(&workspace).expect("nested workspace");
    let policy = SandboxPolicy::new(
        nested_repository_filesystem(parent.path(), &workspace),
        NetworkPolicy::disabled(),
    );
    let command = CommandSpec::new("/bin/sh")
        .expect("shell")
        .with_args(["-c", "mkdir .git && printf forbidden > .git/config; exit 0"])
        .expect("arguments");
    let (command, effective, runtime) = request(&workspace, policy, command);
    let backend = backend();
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &runtime)
        .expect("preflight");
    let mut child = backend.spawn(prepared).expect("spawn");

    let error = child
        .wait()
        .expect_err("protected creation must be reported");
    assert!(matches!(
        error,
        LinuxBackendError::ProtectedPathCreated { path } if path == workspace.join(".git")
    ));
    assert!(!workspace.join(".git").exists());
}

#[test]
fn protected_create_monitor_remains_active_after_the_first_violation() {
    let parent = TempDir::new().expect("parent repository");
    std::fs::create_dir(parent.path().join(".git")).expect("parent metadata");
    std::fs::write(parent.path().join(".git/HEAD"), "ref: refs/heads/main\n").expect("parent HEAD");
    let workspace = parent.path().join("nested");
    std::fs::create_dir(&workspace).expect("nested workspace");
    let filesystem = nested_repository_filesystem(parent.path(), &workspace);
    let policy = SandboxPolicy::new(filesystem, NetworkPolicy::disabled());
    let command = CommandSpec::new("/bin/sh")
        .expect("shell")
        .with_args([
            "-c",
            "mkdir .git; while [ -e .git ]; do :; done; mkdir .git; printf forbidden > .git/config; sleep 1",
        ])
        .expect("arguments");
    let (command, effective, runtime) = request(&workspace, policy, command);
    let backend = backend();
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &runtime)
        .expect("preflight");
    let mut child = backend.spawn(prepared).expect("spawn");

    let error = child
        .wait()
        .expect_err("every protected creation must remain monitored");
    assert!(matches!(
        error,
        LinuxBackendError::ProtectedPathCreated { path } if path == workspace.join(".git")
    ));
    assert!(!workspace.join(".git").exists());
}

#[test]
fn explicit_git_write_opt_out_disables_native_git_protection() {
    let parent = TempDir::new().expect("parent repository");
    std::fs::create_dir(parent.path().join(".git")).expect("parent metadata");
    std::fs::write(parent.path().join(".git/HEAD"), "ref: refs/heads/main\n").expect("parent HEAD");
    let workspace = parent.path().join("nested");
    std::fs::create_dir(&workspace).expect("nested workspace");
    let filesystem =
        nested_repository_filesystem(parent.path(), &workspace).dangerously_allow_git_write();
    let policy = SandboxPolicy::new(filesystem, NetworkPolicy::disabled());
    let command = CommandSpec::new("/bin/sh")
        .expect("shell")
        .with_args(["-c", "mkdir .git && printf allowed > .git/config"])
        .expect("arguments");
    let (command, effective, runtime) = request(&workspace, policy, command);
    let backend = backend();
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &runtime)
        .expect("preflight");
    let mut child = backend.spawn(prepared).expect("spawn");

    assert_eq!(child.wait().expect("wait").code(), Some(0));
    assert_eq!(
        std::fs::read_to_string(workspace.join(".git/config")).expect("written metadata"),
        "allowed"
    );
}

#[test]
fn git_opt_out_preserves_additional_native_protected_paths() {
    let workspace = TempDir::new().expect("temporary workspace");
    let filesystem = SandboxPolicy::workspace()
        .filesystem()
        .clone()
        .dangerously_allow_git_write()
        .with_additional_protected_relative_path(".metadata")
        .expect("additional protected path");
    let policy = SandboxPolicy::new(filesystem, NetworkPolicy::disabled());
    let command = CommandSpec::new("/bin/sh")
        .expect("shell")
        .with_args([
            "-c",
            "mkdir .git && printf allowed > .git/config; if mkdir .metadata; then exit 17; fi",
        ])
        .expect("arguments");
    let (command, effective, runtime) = request(workspace.path(), policy, command);
    let backend = backend();
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &runtime)
        .expect("preflight");
    let mut child = backend.spawn(prepared).expect("spawn");

    assert_eq!(child.wait().expect("wait").code(), Some(0));
    assert_eq!(
        std::fs::read_to_string(workspace.path().join(".git/config")).expect("git write"),
        "allowed"
    );
    assert!(!workspace.path().join(".metadata").exists());
}

#[test]
fn toml_git_opt_out_reaches_native_enforcement_without_removing_other_protection() {
    let workspace = TempDir::new().expect("temporary workspace");
    let config = Config::from_toml(
        r#"
default_profile = "metadata-writer"

[profiles.metadata-writer.filesystem]
additional_protected_paths = [".metadata"]
rules = [
  { target = "minimal", access = "read" },
  { target = "workspace-root", access = "write" },
]

[profiles.metadata-writer.filesystem.security]
dangerously_allow_git_write = true

[profiles.metadata-writer.network]
mode = "disabled"
"#,
    )
    .expect("metadata writer config");
    let resolved = config.resolve_default().expect("resolved profile");
    let command = CommandSpec::new("/bin/sh")
        .expect("shell")
        .with_args([
            "-c",
            "mkdir .git && printf allowed > .git/config; if mkdir .metadata; then exit 17; fi",
        ])
        .expect("arguments");
    let (command, effective, runtime) =
        request(workspace.path(), resolved.policy().clone(), command);
    let backend = backend();
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &runtime)
        .expect("preflight");
    let mut child = backend.spawn(prepared).expect("spawn");

    assert_eq!(child.wait().expect("wait").code(), Some(0));
    assert_eq!(
        std::fs::read_to_string(workspace.path().join(".git/config")).expect("git write"),
        "allowed"
    );
    assert!(!workspace.path().join(".metadata").exists());
}

#[test]
fn equal_length_missing_protected_paths_have_independent_synthetic_targets() {
    let temp = TempDir::new().expect("temporary workspace");
    let first = temp.path().join(".one");
    let second = temp.path().join(".two");
    let filesystem = SandboxPolicy::workspace()
        .filesystem()
        .clone()
        .with_additional_protected_relative_path(".one")
        .expect("first protected path")
        .with_additional_protected_relative_path(".two")
        .expect("second protected path");
    let policy = SandboxPolicy::new(filesystem, NetworkPolicy::disabled());
    let command = CommandSpec::new("/bin/sh")
        .expect("shell")
        .with_args([
            "-c",
            "if mkdir .one 2>/dev/null || mkdir .two 2>/dev/null; then exit 17; else exit 0; fi",
        ])
        .expect("arguments");
    let (command, effective, runtime) = request(temp.path(), policy, command);
    let backend = backend();
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &runtime)
        .expect("preflight");
    let mut child = backend.spawn(prepared).expect("spawn");

    assert_eq!(child.wait().expect("wait").code(), Some(0));
    assert!(!first.exists());
    assert!(!second.exists());
}

#[test]
fn concurrent_sandboxes_share_missing_protected_target_without_early_cleanup() {
    let temp = TempDir::new().expect("temporary workspace");
    let git = temp.path().join(".git");
    let command = CommandSpec::new("/bin/sh")
        .expect("shell")
        .with_args([
            "-c",
            "sleep 0.1; if mkdir .git 2>/dev/null; then exit 17; else exit 0; fi",
        ])
        .expect("arguments");
    let (first_command, first_effective, first_runtime) =
        request(temp.path(), SandboxPolicy::workspace(), command.clone());
    let (second_command, second_effective, second_runtime) =
        request(temp.path(), SandboxPolicy::workspace(), command);
    let first_backend = backend();
    let second_backend = backend();
    let first = first_backend
        .prepare(
            BackendRequest::new(&first_command, &first_effective),
            &first_runtime,
        )
        .expect("first preflight");
    let second = second_backend
        .prepare(
            BackendRequest::new(&second_command, &second_effective),
            &second_runtime,
        )
        .expect("second preflight");
    let mut first_child = first_backend.spawn(first).expect("first spawn");
    let mut second_child = second_backend.spawn(second).expect("second spawn");

    assert_eq!(first_child.wait().expect("first wait").code(), Some(0));
    assert!(
        git.exists(),
        "the first owner removed a target still used by the second sandbox"
    );
    assert_eq!(second_child.wait().expect("second wait").code(), Some(0));
    assert!(!git.exists(), "the final owner left a synthetic host path");
}

#[test]
fn separate_processes_with_different_tmpdirs_share_only_the_same_mount_target() {
    let workspace = TempDir::new().expect("temporary workspace");
    let fixture_state = TempDir::new().expect("fixture state");
    let first_tmp = TempDir::new().expect("first process TMPDIR");
    let second_tmp = TempDir::new().expect("second process TMPDIR");
    let first_ready = fixture_state.path().join("first.ready");
    let second_ready = fixture_state.path().join("second.ready");
    let first_release = workspace.path().join("first.release");
    let second_release = workspace.path().join("second.release");
    let git = workspace.path().join(".git");

    let first = spawn_synthetic_owner_fixture(
        workspace.path(),
        first_tmp.path(),
        &first_ready,
        &first_release,
    );
    wait_for_marker(&first_ready);
    let second = spawn_synthetic_owner_fixture(
        workspace.path(),
        second_tmp.path(),
        &second_ready,
        &second_release,
    );
    wait_for_marker(&second_ready);

    assert!(git.is_dir(), "shared synthetic target was not materialized");
    std::fs::write(&first_release, b"release").expect("release first fixture");
    assert_fixture_success(first.wait_with_output().expect("wait for first fixture"));
    assert!(
        git.is_dir(),
        "the first process removed a target still owned by the second process"
    );

    std::fs::write(&second_release, b"release").expect("release second fixture");
    assert_fixture_success(second.wait_with_output().expect("wait for second fixture"));
    assert!(
        !git.exists(),
        "the final process left a synthetic host target"
    );
}

#[test]
fn explicit_dev_shm_scope_remains_usable_without_exposing_backend_runtime() {
    let temp = TempDir::new().expect("temporary workspace");
    let shared = TempDir::new_in("/dev/shm").expect("shared-memory fixture");
    let output = shared.path().join("created.txt");
    let policy = SandboxPolicy::new(
        FilesystemPolicy::restricted([
            FilesystemRule::new(PathSelector::root(), AccessMode::Read),
            FilesystemRule::new(PathSelector::minimal(), AccessMode::Read),
            FilesystemRule::new(PathSelector::workspace_root(), AccessMode::Write),
            FilesystemRule::new(
                PathSelector::absolute(shared.path()).expect("dev shm selector"),
                AccessMode::Write,
            ),
        ]),
        NetworkPolicy::disabled(),
    );
    let command = CommandSpec::new("/bin/sh")
        .expect("shell")
        .with_args(["-c", &format!("printf allowed > {}", output.display())])
        .expect("arguments");
    let (command, effective, runtime) = request(temp.path(), policy, command);
    let backend = backend();
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &runtime)
        .expect("preflight");
    let mut child = backend.spawn(prepared).expect("spawn");
    assert_eq!(child.wait().expect("wait").code(), Some(0));
    assert_eq!(
        std::fs::read_to_string(output).expect("shared output"),
        "allowed"
    );
}

#[test]
fn unrestricted_filesystem_restores_host_shared_memory() {
    let workspace = TempDir::new().expect("temporary workspace");
    let shared = TempDir::new_in("/dev/shm").expect("shared-memory fixture");
    let output = shared.path().join("created.txt");
    let command = CommandSpec::new("/bin/sh")
        .expect("shell")
        .with_args(["-c", &format!("printf allowed > {}", output.display())])
        .expect("arguments");
    let (command, effective, runtime) =
        request(workspace.path(), SandboxPolicy::full_access(), command);
    let backend = backend();
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &runtime)
        .expect("preflight");
    let mut child = backend.spawn(prepared).expect("spawn");

    assert_eq!(child.wait().expect("wait").code(), Some(0));
    assert_eq!(
        std::fs::read_to_string(output).expect("shared output"),
        "allowed"
    );
}

#[test]
fn post_handshake_command_start_failure_is_not_an_exit_status() {
    let workspace = TempDir::new().expect("temporary workspace");
    let missing_program = workspace.path().join("missing-command");
    let command = CommandSpec::new(&missing_program).expect("missing command path");
    let (command, effective, runtime) =
        request(workspace.path(), SandboxPolicy::full_access(), command);
    let backend = backend();
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &runtime)
        .expect("preflight");
    let mut child = backend.spawn(prepared).expect("setup handshake");

    let error = child
        .wait()
        .expect_err("helper command-start failure must be typed");
    let LinuxBackendError::HardeningHelperRuntimeFailed { failure } = error else {
        panic!("unexpected error: {error}");
    };
    assert_eq!(failure.kind(), LinuxHelperRuntimeFailureKind::CommandStart);
    assert_eq!(failure.raw_os_error(), Some(libc::ENOENT));
}

#[test]
fn pre_release_command_start_failure_remains_a_setup_error() {
    let workspace = TempDir::new().expect("temporary workspace");
    let missing_program = workspace.path().join("missing-command");
    let command = CommandSpec::new(&missing_program).expect("missing command path");
    let (command, effective, runtime) =
        request(workspace.path(), SandboxPolicy::workspace(), command);
    let backend = backend();
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &runtime)
        .expect("preflight");
    let error = match backend.spawn(prepared) {
        Ok(_) => panic!("command start must fail before release"),
        Err(error) => error,
    };

    let LinuxBackendError::SetupHandshakeFailed {
        source: SetupHandshakeError::HelperRejected { failure },
        ..
    } = error
    else {
        panic!("unexpected error: {error}");
    };
    assert_eq!(failure.kind(), LinuxHelperSetupFailureKind::CommandStart);
    assert_eq!(failure.raw_os_error(), Some(libc::ENOENT));
}

#[test]
fn real_command_exit_126_remains_a_command_status() {
    let workspace = TempDir::new().expect("temporary workspace");
    let command = CommandSpec::new("/bin/sh")
        .expect("shell")
        .with_args(["-c", "exit 126"])
        .expect("arguments");
    let (command, effective, runtime) =
        request(workspace.path(), SandboxPolicy::full_access(), command);
    let backend = backend();
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &runtime)
        .expect("preflight");
    let mut child = backend.spawn(prepared).expect("setup handshake");

    assert_eq!(child.wait().expect("command status").code(), Some(126));
}

#[test]
fn backend_coordination_state_is_hidden_from_restricted_and_unrestricted_commands() {
    #[allow(unsafe_code)]
    let uid = unsafe { libc::geteuid() };
    let state_root = PathBuf::from(format!("/tmp/.cageforge-linux-{uid}"));
    let attack = state_root.join(format!("sandbox-attack-{}", std::process::id()));
    let _ = std::fs::remove_dir(&attack);

    for policy in [SandboxPolicy::workspace(), SandboxPolicy::full_access()] {
        let workspace = TempDir::new().expect("temporary workspace");
        let command = CommandSpec::new("/bin/sh")
            .expect("shell")
            .with_args([
                "-c",
                &format!(
                    "if mkdir {} 2>/dev/null; then exit 17; else exit 0; fi",
                    attack.display()
                ),
            ])
            .expect("arguments");
        let (command, effective, runtime) = request(workspace.path(), policy, command);
        let backend = backend();
        let prepared = backend
            .prepare(BackendRequest::new(&command, &effective), &runtime)
            .expect("preflight");
        let mut child = backend.spawn(prepared).expect("spawn");

        assert_eq!(child.wait().expect("wait").code(), Some(0));
        assert!(
            !attack.exists(),
            "sandbox modified backend coordination state"
        );
    }
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
fn disabling_proc_mount_masks_host_procfs() {
    let workspace = TempDir::new().expect("temporary workspace");
    let command = CommandSpec::new("/bin/sh")
        .expect("shell")
        .with_args([
            "-c",
            "if test -e /proc/1/status; then exit 17; else exit 0; fi",
        ])
        .expect("arguments");
    let (command, effective, runtime) =
        request(workspace.path(), SandboxPolicy::workspace(), command);
    let backend = LinuxBackend::new(
        test_backend_config().with_proc_mount(cageforge_linux::ProcMountPolicy::Disabled),
    )
    .expect("backend without procfs");
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &runtime)
        .expect("preflight");
    let mut child = backend.spawn(prepared).expect("spawn");
    assert_eq!(child.wait().expect("wait").code(), Some(0));
}

#[test]
fn restricted_network_capabilities_are_advertised_for_exact_gateway_enforcement() {
    let backend = backend();
    assert!(
        backend
            .capabilities()
            .supports(BackendCapability::NetworkEnabled)
    );
    assert!(
        backend
            .capabilities()
            .supports(BackendCapability::NetworkResolvedTargets)
    );
    assert!(
        backend
            .capabilities()
            .supports(BackendCapability::NetworkDomainRules)
    );
    assert!(
        backend
            .capabilities()
            .supports(BackendCapability::NetworkLocalAddressRestrictions)
    );
    assert!(
        backend
            .capabilities()
            .supports(BackendCapability::NetworkUnixSocketIsolation)
    );
    assert!(
        !backend
            .capabilities()
            .supports(BackendCapability::NetworkUnixSocketRules)
    );
}

#[test]
fn http_proxy_reaches_only_an_exactly_authorized_loopback_target() {
    let (target, server) = start_http_server();
    let status = spawn_network_client(restricted_loopback_policy(), "http", target)
        .expect("restricted HTTP execution");
    let server_result = server.join().expect("HTTP server");
    assert_eq!(status.code(), Some(0));
    server_result.expect("HTTP server I/O");
}

#[test]
fn socks_proxy_reaches_only_an_exactly_authorized_loopback_target() {
    let (target, server) = start_http_server();
    let status = spawn_network_client(restricted_loopback_policy(), "socks", target)
        .expect("restricted SOCKS execution");
    let server_result = server.join().expect("HTTP server");
    assert_eq!(status.code(), Some(0));
    server_result.expect("HTTP server I/O");
}

#[test]
fn timed_out_protocol_handshake_releases_the_local_bridge_slot() {
    let (target, server) = start_http_server();
    let gateway = GatewayConfig::new()
        .with_handshake_timeout(Duration::from_millis(20))
        .expect("handshake timeout")
        .with_relay_idle_timeout(Duration::from_millis(20))
        .expect("relay idle timeout")
        .with_max_concurrent_connections(NonZeroUsize::new(1).expect("non-zero"))
        .expect("connection limit");
    let backend = LinuxBackend::new(test_backend_config().with_network_gateway(gateway))
        .expect("limited Linux backend");
    let status = spawn_network_client_with_backend(
        &backend,
        restricted_loopback_policy(),
        "stalled-proxy-slot",
        target,
    )
    .expect("restricted execution");
    if !status.success() {
        let _ = send_direct_request(target);
    }
    let server_result = server.join().expect("HTTP server");

    assert_eq!(status.code(), Some(0));
    server_result.expect("HTTP server I/O");
}

#[test]
fn concurrent_backend_instances_own_independent_gateway_lifecycles() {
    let (first_target, first_server) = start_http_server();
    let (second_target, second_server) = start_http_server();
    let first = thread::spawn(move || {
        spawn_network_client(restricted_loopback_policy(), "http", first_target)
            .expect("first restricted execution")
    });
    let second = thread::spawn(move || {
        spawn_network_client(restricted_loopback_policy(), "http", second_target)
            .expect("second restricted execution")
    });

    let first_status = first.join().expect("first backend thread");
    let second_status = second.join().expect("second backend thread");
    let first_server_result = first_server.join().expect("first HTTP server");
    let second_server_result = second_server.join().expect("second HTTP server");
    assert!(first_status.success());
    assert!(second_status.success());
    first_server_result.expect("first HTTP server I/O");
    second_server_result.expect("second HTTP server I/O");
}

#[test]
fn denied_domain_cannot_reach_a_live_host_target_through_the_gateway() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("target listener");
    let target = listener.local_addr().expect("target address");
    let network = NetworkPolicy::enabled().with_domain_mode(DomainMode::Restricted);
    let policy = SandboxPolicy::new(FilesystemPolicy::unrestricted(), network);
    let status =
        spawn_network_client(policy, "http-denied", target).expect("denied HTTP execution");
    assert_eq!(status.code(), Some(0));
    listener
        .set_nonblocking(true)
        .expect("non-blocking target listener");
    assert!(
        listener.accept().is_err(),
        "denied target received a connection"
    );
}

#[test]
fn disabled_network_blocks_direct_loopback_connections() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("target listener");
    let target = listener.local_addr().expect("target address");
    let status = spawn_network_client(SandboxPolicy::workspace(), "direct-denied", target)
        .expect("disabled-network execution");

    assert_eq!(status.code(), Some(0));
    listener
        .set_nonblocking(true)
        .expect("non-blocking target listener");
    assert!(listener.accept().is_err());
}

#[test]
fn unrestricted_network_preserves_direct_loopback_connections() {
    let (target, server) = start_http_server();
    let status = spawn_network_client(SandboxPolicy::full_access(), "direct", target)
        .expect("unrestricted-network execution");
    let server_result = server.join().expect("HTTP server");

    assert_eq!(status.code(), Some(0));
    server_result.expect("HTTP server I/O");
}

#[test]
fn proxy_routed_process_cannot_connect_directly_or_open_the_gateway_unix_socket() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("target listener");
    let target = listener.local_addr().expect("target address");
    let direct = spawn_network_client(restricted_loopback_policy(), "direct-denied", target)
        .expect("direct bypass test");
    assert_eq!(direct.code(), Some(0));

    let unix = spawn_network_client(restricted_loopback_policy(), "unix-denied", target)
        .expect("Unix bypass test");
    assert_eq!(unix.code(), Some(0));
}

#[test]
fn explicit_unix_socket_policy_remains_a_typed_unsupported_requirement() {
    let temp = TempDir::new().expect("temporary workspace");
    let network = NetworkPolicy::enabled()
        .with_unix_socket_mode(UnixSocketMode::Restricted)
        .with_unix_socket("/run/example.sock", DomainAccess::Allow)
        .expect("Unix socket policy");
    let policy = SandboxPolicy::new(FilesystemPolicy::unrestricted(), network);
    let command = CommandSpec::new("/bin/true").expect("command");
    let (command, effective, runtime) = request(temp.path(), policy, command);
    let backend = backend();
    let error = backend
        .prepare(BackendRequest::new(&command, &effective), &runtime)
        .expect_err("explicit Unix socket enforcement is unavailable");
    assert!(matches!(
        error,
        LinuxBackendError::Contract(BackendContractError::UnsupportedCapability {
            capability: BackendCapability::NetworkUnixSocketRules,
        })
    ));
}

#[test]
fn proxy_routing_rejects_unrestricted_pathname_unix_socket_access() {
    let workspace = TempDir::new().expect("temporary workspace");
    let network = NetworkPolicy::unrestricted()
        .with_domain_mode(DomainMode::Restricted)
        .with_domain("example.com", DomainAccess::Allow)
        .expect("domain rule");
    let policy = SandboxPolicy::new(FilesystemPolicy::unrestricted(), network);
    let command = CommandSpec::new("/bin/true").expect("command");
    let (command, effective, runtime) = request(workspace.path(), policy, command);
    let backend = backend();
    let error = backend
        .prepare(BackendRequest::new(&command, &effective), &runtime)
        .expect_err("proxy routing cannot preserve unrestricted Unix sockets");

    assert!(matches!(
        error,
        LinuxBackendError::UnsupportedNetworkCombination(
            NetworkCombinationError::ProxyRequiresUnixSocketIsolation
        )
    ));
}

#[test]
fn restricted_filesystem_keeps_common_seccomp_with_direct_network() {
    assert_common_seccomp_policy(
        NetworkPolicy::enabled().with_local_network_access(LocalNetworkAccess::Allow),
    );
}

#[test]
fn proxy_routed_network_rejects_socketpair_pathname_reconnect() {
    let network = NetworkPolicy::enabled()
        .with_domain_mode(DomainMode::Restricted)
        .with_domain("example.com", DomainAccess::Allow)
        .expect("domain rule");
    assert_common_seccomp_policy(network);
}

fn assert_common_seccomp_policy(network: NetworkPolicy) {
    let workspace = TempDir::new().expect("temporary workspace");
    let unix_target = workspace.path().join("target.sock");
    let unix_listener = UnixDatagram::bind(&unix_target).expect("Unix datagram target");
    unix_listener
        .set_read_timeout(Some(Duration::from_millis(100)))
        .expect("Unix target timeout");
    let filesystem = FilesystemPolicy::restricted([
        FilesystemRule::new(PathSelector::root(), AccessMode::Read),
        FilesystemRule::new(PathSelector::workspace_root(), AccessMode::Write),
    ]);
    let policy = SandboxPolicy::new(filesystem, network);
    let environment = EnvironmentSpec::inherit_all()
        .with_var(COMMON_SECCOMP_FIXTURE, "1")
        .expect("fixture environment")
        .with_var(UNIX_SOCKET_BYPASS_TARGET, unix_target.as_os_str())
        .expect("Unix target environment");
    let command = CommandSpec::new(std::env::current_exe().expect("test executable"))
        .expect("fixture command")
        .with_args(["--exact", "common_seccomp_fixture", "--nocapture"])
        .expect("fixture arguments");
    let (command, effective, runtime) =
        request_with_environment(workspace.path(), policy, command, environment);
    let backend = backend();
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &runtime)
        .expect("preflight");
    let mut child = backend.spawn(prepared).expect("spawn");

    assert_eq!(child.wait().expect("wait").code(), Some(0));
    let mut datagram = [0; 16];
    match unix_listener.recv(&mut datagram) {
        Ok(size) => panic!(
            "socketpair endpoint reached pathname Unix target: {:?}",
            &datagram[..size]
        ),
        Err(error) => assert!(matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        )),
    }
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
fn restricted_child_cannot_create_core_dumps() {
    let workspace = TempDir::new().expect("temporary workspace");
    let filesystem = FilesystemPolicy::restricted([
        FilesystemRule::new(PathSelector::root(), AccessMode::Read),
        FilesystemRule::new(PathSelector::workspace_root(), AccessMode::Write),
    ]);
    let policy = SandboxPolicy::new(filesystem, NetworkPolicy::disabled());
    let environment = EnvironmentSpec::inherit_all()
        .with_var(CORE_LIMIT_FIXTURE, "1")
        .expect("fixture environment");
    let command = CommandSpec::new(std::env::current_exe().expect("test executable"))
        .expect("fixture command")
        .with_args(["--exact", "core_limit_fixture", "--nocapture"])
        .expect("fixture arguments");
    let (command, effective, runtime) =
        request_with_environment(workspace.path(), policy, command, environment);
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
    assert_eq!(status.code(), Some(0), "stdout={stdout}\nstderr={stderr}");
}

#[test]
fn restricted_child_has_trusted_ptrace_guard_after_exec() {
    let workspace = TempDir::new().expect("temporary workspace");
    let filesystem = FilesystemPolicy::restricted([
        FilesystemRule::new(PathSelector::root(), AccessMode::Read),
        FilesystemRule::new(PathSelector::workspace_root(), AccessMode::Write),
    ]);
    let policy = SandboxPolicy::new(filesystem, NetworkPolicy::disabled());
    let environment = EnvironmentSpec::inherit_all()
        .with_var(TRACER_GUARD_FIXTURE, "1")
        .expect("fixture environment");
    let command = CommandSpec::new(std::env::current_exe().expect("test executable"))
        .expect("fixture command")
        .with_args(["--exact", "tracer_guard_fixture", "--nocapture"])
        .expect("fixture arguments");
    let (command, effective, runtime) =
        request_with_environment(workspace.path(), policy, command, environment);
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
    assert_eq!(status.code(), Some(0), "stdout={stdout}\nstderr={stderr}");
}

#[test]
fn restricted_child_cannot_escape_tracer_with_clone_untraced() {
    let workspace = TempDir::new().expect("temporary workspace");
    let filesystem = FilesystemPolicy::restricted([
        FilesystemRule::new(PathSelector::root(), AccessMode::Read),
        FilesystemRule::new(PathSelector::workspace_root(), AccessMode::Write),
    ]);
    let policy = SandboxPolicy::new(filesystem, NetworkPolicy::disabled());
    let environment = EnvironmentSpec::inherit_all()
        .with_var(CLONE_UNTRACED_FIXTURE, "1")
        .expect("fixture environment");
    let command = CommandSpec::new(std::env::current_exe().expect("test executable"))
        .expect("fixture command")
        .with_args(["--exact", "clone_untraced_fixture", "--nocapture"])
        .expect("fixture arguments");
    let (command, effective, runtime) =
        request_with_environment(workspace.path(), policy, command, environment);
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
    assert_eq!(status.code(), Some(0), "stdout={stdout}\nstderr={stderr}");
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
        .wait()
        .expect_err("sleep must exceed the configured timeout");
    assert!(matches!(error, LinuxBackendError::ProcessTimedOut));
    assert!(child.try_wait().expect("reaped child").is_some());
}

#[test]
fn polling_cannot_bypass_the_prepared_timeout_policy() {
    let temp = TempDir::new().expect("temporary workspace");
    let command = CommandSpec::new("/bin/sh")
        .expect("shell")
        .with_args(["-c", "sleep 2"])
        .expect("arguments");
    let (command, effective, runtime) = request(temp.path(), SandboxPolicy::workspace(), command);
    let command = command.with_timeout(Duration::from_millis(20));
    let backend = backend();
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &runtime)
        .expect("preflight");
    let mut child = backend.spawn(prepared).expect("spawn");
    std::thread::sleep(Duration::from_millis(40));

    assert!(matches!(
        child.try_wait(),
        Err(LinuxBackendError::ProcessTimedOut)
    ));
    assert!(child.try_wait().expect("reaped child").is_some());
}

#[test]
fn blocking_stdio_cannot_bypass_the_prepared_timeout_policy() {
    let temp = TempDir::new().expect("temporary workspace");
    let command = CommandSpec::new("/bin/sh")
        .expect("shell")
        .with_args(["-c", "sleep 2"])
        .expect("arguments");
    let (command, effective, runtime) = request(temp.path(), SandboxPolicy::workspace(), command);
    let command = command
        .with_timeout(Duration::from_millis(50))
        .with_stdio(StdioSpec::captured());
    let backend = backend();
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &runtime)
        .expect("preflight");
    let mut child = backend.spawn(prepared).expect("spawn");
    let started = Instant::now();
    let mut output = Vec::new();

    child
        .stdout()
        .expect("captured stdout")
        .read_to_end(&mut output)
        .expect("watchdog closes stdout");

    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(matches!(
        child.wait(),
        Err(LinuxBackendError::ProcessTimedOut)
    ));
}

#[test]
fn timeout_terminates_the_complete_pid_namespace_process_tree() {
    let workspace = TempDir::new().expect("temporary workspace");
    let marker = workspace.path().join("late-write");
    let command = CommandSpec::new("/bin/sh")
        .expect("shell")
        .with_args([
            "-c",
            &format!("(sleep 0.25; printf escaped > {}) & wait", marker.display()),
        ])
        .expect("arguments");
    let (command, effective, runtime) =
        request(workspace.path(), SandboxPolicy::workspace(), command);
    let command = command.with_timeout(Duration::from_millis(50));
    let backend = backend();
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &runtime)
        .expect("preflight");
    let mut child = backend.spawn(prepared).expect("spawn");

    assert!(matches!(
        child.wait(),
        Err(LinuxBackendError::ProcessTimedOut)
    ));
    thread::sleep(Duration::from_millis(350));
    assert!(
        !marker.exists(),
        "timed-out descendant survived the boundary"
    );
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

#[test]
fn explicit_workspace_symlink_scope_cannot_bind_an_external_directory() {
    let temp = TempDir::new().expect("temporary workspace");
    let outside = TempDir::new_in("/var/tmp").expect("outside directory");
    let secret = outside.path().join("secret.txt");
    std::fs::write(&secret, "outside-secret").expect("secret");
    let link = temp.path().join("expose");
    std::os::unix::fs::symlink(outside.path(), &link).expect("symlink");
    let policy = SandboxPolicy::new(
        FilesystemPolicy::restricted([
            FilesystemRule::new(PathSelector::minimal(), AccessMode::Read),
            FilesystemRule::new(PathSelector::workspace_root(), AccessMode::Write),
            FilesystemRule::new(
                PathSelector::workspace("expose").expect("workspace symlink selector"),
                AccessMode::Write,
            ),
        ])
        .dangerously_allow_git_write(),
        NetworkPolicy::disabled(),
    );
    let command = CommandSpec::new("/bin/sh")
        .expect("shell")
        .with_args([
            "-c",
            &format!(
                "if cat {} >/dev/null; then exit 17; else exit 0; fi",
                link.join("secret.txt").display()
            ),
        ])
        .expect("arguments");
    let (command, effective, runtime) = request(temp.path(), policy, command);
    let backend = backend();
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &runtime)
        .expect("preflight");
    assert!(matches!(
        backend.spawn(prepared),
        Err(LinuxBackendError::FilesystemLoweringFailed {
            source: FilesystemLoweringError::WritableSymlinkMount { .. },
            ..
        })
    ));
    assert_eq!(
        std::fs::read_to_string(secret).expect("host secret"),
        "outside-secret"
    );
}

#[test]
fn symlinked_workspace_root_is_rejected_before_bubblewrap() {
    let temp = TempDir::new().expect("temporary workspace");
    let real_workspace = temp.path().join("real");
    std::fs::create_dir(&real_workspace).expect("real workspace");
    let workspace_alias = temp.path().join("alias");
    std::os::unix::fs::symlink(&real_workspace, &workspace_alias).expect("workspace symlink");
    let command = CommandSpec::new("/bin/true").expect("command");
    let (command, effective, runtime) =
        request(&workspace_alias, SandboxPolicy::workspace(), command);
    let backend = backend();
    let prepared = backend
        .prepare(BackendRequest::new(&command, &effective), &runtime)
        .expect("preflight");

    assert!(matches!(
        backend.spawn(prepared),
        Err(LinuxBackendError::FilesystemLoweringFailed {
            source: FilesystemLoweringError::WritableSymlinkMount { .. },
            ..
        })
    ));
}
