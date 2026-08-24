// SPDX-License-Identifier: Apache-2.0

//! Linux process hardening applied to the Bubblewrap boundary.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::{Command, ExitCode};

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, apply_filter,
};

#[path = "hardening/bridge.rs"]
mod bridge;
#[path = "hardening/environment.rs"]
mod environment;

use crate::helper_protocol::{
    AUTH_FD_ENV, AUTH_TOKEN, BRIDGE_TOKEN_BYTES, GATEWAY_CONNECTION_LIMIT_ENV, GATEWAY_SOCKET_ENV,
    HARDENING_REQUIRED_ENV, NETWORK_MODE_DIRECT_WITHOUT_UNIX, NETWORK_MODE_DISABLED,
    NETWORK_MODE_ENV, NETWORK_MODE_PROXY, READY, RELEASE, STATUS_MAGIC,
};
use bridge::LocalGatewayBridge;
use environment::read_environment;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NetworkHardeningMode {
    None,
    DirectWithoutUnixSockets,
    Disabled,
    ProxyRouted,
}

/// Applies process hardening inside the Bubblewrap namespace.
fn apply(hardening_required: bool, network_mode: NetworkHardeningMode) -> io::Result<()> {
    if !hardening_required && network_mode == NetworkHardeningMode::None {
        return Ok(());
    }
    set_parent_death_signal()?;
    set_no_new_privs()?;
    let filter = build_filter(network_mode).map_err(io::Error::other)?;
    apply_filter(&filter).map_err(io::Error::other)?;
    Ok(())
}

/// Runs the private helper command used as Bubblewrap's final payload.
pub(crate) fn run_helper(mut args: impl Iterator<Item = OsString>) -> ExitCode {
    if args.next().is_none_or(|arg| arg != "--apply-hardening") {
        eprintln!("missing --apply-hardening");
        return ExitCode::from(2);
    }
    let Some(program) = args.next() else {
        eprintln!("missing hardened program");
        return ExitCode::from(2);
    };
    let mut authentication = match verify_helper_authentication() {
        Ok(authentication) => authentication,
        Err(error) => {
            eprintln!("invalid Linux hardening helper invocation: {error}");
            return ExitCode::from(125);
        }
    };
    let hardening_required = std::env::var_os(HARDENING_REQUIRED_ENV).is_some();
    let network_mode = match network_hardening_mode() {
        Ok(mode) => mode,
        Err(error) => {
            eprintln!("invalid Linux network hardening mode: {error}");
            return ExitCode::from(125);
        }
    };
    let bridge = match start_gateway_bridge(network_mode, &mut authentication) {
        Ok(bridge) => bridge,
        Err(error) => {
            eprintln!("failed to activate Linux network gateway bridge: {error}");
            return ExitCode::from(125);
        }
    };
    let environment = match read_environment(&mut authentication) {
        Ok(environment) => environment,
        Err(error) => {
            eprintln!("failed to receive sandboxed command environment: {error}");
            return ExitCode::from(125);
        }
    };
    if let Err(error) = apply(hardening_required, network_mode) {
        eprintln!("failed to apply Linux process hardening: {error}");
        return ExitCode::from(125);
    }
    if let Err(error) = complete_setup_handshake(&mut authentication) {
        eprintln!("failed Linux sandbox setup handshake: {error}");
        return ExitCode::from(125);
    }
    if let Err(error) = set_close_on_exec(authentication.as_raw_fd(), true) {
        eprintln!("failed to protect Linux helper status channel: {error}");
        return ExitCode::from(125);
    }
    let mut command = Command::new(program);
    command.args(args).env_clear().envs(environment);
    command
        .env_remove(HARDENING_REQUIRED_ENV)
        .env_remove(NETWORK_MODE_ENV)
        .env_remove(GATEWAY_SOCKET_ENV)
        .env_remove(GATEWAY_CONNECTION_LIMIT_ENV)
        .env_remove(AUTH_FD_ENV);
    if let Some(bridge) = &bridge {
        bridge.configure_command(&mut command);
    }
    let status = match command.status() {
        Ok(status) => status,
        Err(error) => {
            eprintln!("failed to start hardened command: {error}");
            return ExitCode::from(126);
        }
    };
    if let Err(error) = write_command_status(&mut authentication, status) {
        eprintln!("failed to report sandboxed command status: {error}");
        return ExitCode::from(125);
    }
    ExitCode::from(status.code().unwrap_or(1) as u8)
}

fn write_command_status(
    writer: &mut impl Write,
    status: std::process::ExitStatus,
) -> io::Result<()> {
    writer.write_all(STATUS_MAGIC)?;
    writer.write_all(&status.into_raw().to_ne_bytes())
}

fn network_hardening_mode() -> io::Result<NetworkHardeningMode> {
    match std::env::var_os(NETWORK_MODE_ENV).as_deref() {
        None => Ok(NetworkHardeningMode::None),
        Some(value) if value == NETWORK_MODE_DIRECT_WITHOUT_UNIX => {
            Ok(NetworkHardeningMode::DirectWithoutUnixSockets)
        }
        Some(value) if value == NETWORK_MODE_DISABLED => Ok(NetworkHardeningMode::Disabled),
        Some(value) if value == NETWORK_MODE_PROXY => Ok(NetworkHardeningMode::ProxyRouted),
        Some(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unknown network hardening mode",
        )),
    }
}

fn start_gateway_bridge(
    mode: NetworkHardeningMode,
    authentication: &mut File,
) -> io::Result<Option<LocalGatewayBridge>> {
    if mode != NetworkHardeningMode::ProxyRouted {
        return Ok(None);
    }
    let socket = std::env::var_os(GATEWAY_SOCKET_ENV)
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing gateway socket"))?;
    if !socket.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "gateway socket must be absolute",
        ));
    }
    let max_connections = std::env::var(GATEWAY_CONNECTION_LIMIT_ENV)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "missing gateway limit"))?
        .parse::<usize>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid gateway limit"))?;
    if max_connections == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "gateway limit must be non-zero",
        ));
    }
    let mut bridge_token = [0; BRIDGE_TOKEN_BYTES];
    authentication.read_exact(&mut bridge_token)?;
    LocalGatewayBridge::start(
        &socket,
        max_connections,
        authentication.as_raw_fd(),
        bridge_token,
    )
    .map(Some)
}

fn verify_helper_authentication() -> io::Result<File> {
    let fd: libc::c_int = std::env::var(AUTH_FD_ENV)
        .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "missing auth fd"))?
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid auth fd"))?;
    if fd <= libc::STDERR_FILENO {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "auth fd must be above the standard streams",
        ));
    }
    #[allow(unsafe_code)]
    let mut auth = unsafe { File::from_raw_fd(fd) };
    let mut token = vec![0; AUTH_TOKEN.len()];
    auth.read_exact(&mut token)?;
    if token == AUTH_TOKEN {
        Ok(auth)
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "auth token mismatch",
        ))
    }
}

fn complete_setup_handshake(authentication: &mut File) -> io::Result<()> {
    authentication.write_all(READY)?;
    let mut release = vec![0; RELEASE.len()];
    authentication.read_exact(&mut release)?;
    if release == RELEASE {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid setup release token",
        ))
    }
}

#[allow(unsafe_code)]
fn set_no_new_privs() -> io::Result<()> {
    let result = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[allow(unsafe_code)]
fn set_parent_death_signal() -> io::Result<()> {
    let expected_parent = unsafe { libc::getppid() };
    let result = unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::getppid() } != expected_parent {
        return Err(io::Error::other("sandbox parent exited during hardening"));
    }
    Ok(())
}

#[allow(unsafe_code)]
fn set_close_on_exec(fd: std::os::fd::RawFd, close_on_exec: bool) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags == -1 {
        return Err(io::Error::last_os_error());
    }
    let updated = if close_on_exec {
        flags | libc::FD_CLOEXEC
    } else {
        flags & !libc::FD_CLOEXEC
    };
    if unsafe { libc::fcntl(fd, libc::F_SETFD, updated) } == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn build_filter(mode: NetworkHardeningMode) -> Result<BpfProgram, String> {
    fn deny_syscall(rules: &mut BTreeMap<i64, Vec<SeccompRule>>, syscall: i64) {
        rules.insert(syscall, Vec::new());
    }

    let mut rules = BTreeMap::new();
    for syscall in [
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
    ] {
        deny_syscall(&mut rules, syscall);
    }
    match mode {
        NetworkHardeningMode::None => {}
        NetworkHardeningMode::DirectWithoutUnixSockets => {
            add_unix_socket_isolation_rules(&mut rules)?;
        }
        NetworkHardeningMode::Disabled => add_disabled_network_rules(&mut rules)?,
        NetworkHardeningMode::ProxyRouted => add_proxy_network_rules(&mut rules)?,
    }

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        target_architecture()?,
    )
    .map_err(|error| error.to_string())?;
    let program: BpfProgram = filter
        .try_into()
        .map_err(|error: seccompiler::BackendError| error.to_string())?;
    Ok(program)
}

fn add_unix_socket_isolation_rules(
    rules: &mut BTreeMap<i64, Vec<SeccompRule>>,
) -> Result<(), String> {
    let unix_socket = SeccompRule::new(vec![
        SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Eq,
            libc::AF_UNIX as u64,
        )
        .map_err(|error| error.to_string())?,
    ])
    .map_err(|error| error.to_string())?;
    rules.insert(libc::SYS_socket, vec![unix_socket]);
    Ok(())
}

fn add_disabled_network_rules(rules: &mut BTreeMap<i64, Vec<SeccompRule>>) -> Result<(), String> {
    for syscall in [
        libc::SYS_connect,
        libc::SYS_accept,
        libc::SYS_accept4,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_getpeername,
        libc::SYS_getsockname,
        libc::SYS_shutdown,
        libc::SYS_sendto,
        libc::SYS_sendmmsg,
        libc::SYS_recvmmsg,
        libc::SYS_getsockopt,
        libc::SYS_setsockopt,
    ] {
        rules.insert(syscall, Vec::new());
    }
    let unix_only = SeccompRule::new(vec![
        SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Ne,
            libc::AF_UNIX as u64,
        )
        .map_err(|error| error.to_string())?,
    ])
    .map_err(|error| error.to_string())?;
    rules.insert(libc::SYS_socket, vec![unix_only.clone()]);
    rules.insert(libc::SYS_socketpair, vec![unix_only]);
    Ok(())
}

fn add_proxy_network_rules(rules: &mut BTreeMap<i64, Vec<SeccompRule>>) -> Result<(), String> {
    let ip_only = SeccompRule::new(vec![
        SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Ne,
            libc::AF_INET as u64,
        )
        .map_err(|error| error.to_string())?,
        SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Ne,
            libc::AF_INET6 as u64,
        )
        .map_err(|error| error.to_string())?,
    ])
    .map_err(|error| error.to_string())?;
    let unix_socketpair_only = SeccompRule::new(vec![
        SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Ne,
            libc::AF_UNIX as u64,
        )
        .map_err(|error| error.to_string())?,
    ])
    .map_err(|error| error.to_string())?;
    rules.insert(libc::SYS_socket, vec![ip_only]);
    rules.insert(libc::SYS_socketpair, vec![unix_socketpair_only]);
    Ok(())
}

fn target_architecture() -> Result<seccompiler::TargetArch, String> {
    if cfg!(target_arch = "x86_64") {
        Ok(seccompiler::TargetArch::x86_64)
    } else if cfg!(target_arch = "aarch64") {
        Ok(seccompiler::TargetArch::aarch64)
    } else {
        Err(format!(
            "unsupported Linux seccomp architecture: {}",
            std::env::consts::ARCH
        ))
    }
}
