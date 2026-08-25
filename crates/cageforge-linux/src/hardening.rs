// SPDX-License-Identifier: Apache-2.0

//! Linux process hardening applied to the Bubblewrap boundary.

use std::collections::{BTreeMap, HashSet};
use std::error::Error as StdError;
use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::io::{Read, Write};
use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::{Child, Command, ExitCode, ExitStatus};

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, apply_filter,
};

#[path = "hardening/bridge.rs"]
mod bridge;
#[path = "hardening/environment.rs"]
mod environment;

use crate::error::{
    LinuxHardeningError, LinuxHardeningOperation, LinuxHelperRuntimeFailure,
    LinuxHelperRuntimeFailureKind, LinuxHelperSetupFailure, LinuxHelperSetupFailureKind,
    SeccompBuildError,
};
use crate::helper_protocol::{
    AUTH_FD_ENV, AUTH_TOKEN, BRIDGE_TOKEN_BYTES, GATEWAY_CONNECTION_LIMIT_ENV, GATEWAY_SOCKET_ENV,
    HARDENING_REQUIRED_ENV, NETWORK_MODE_DIRECT_WITHOUT_UNIX, NETWORK_MODE_DISABLED,
    NETWORK_MODE_ENV, NETWORK_MODE_PROXY, RELEASE, SETUP_RESULT_FAILURE, SETUP_RESULT_MAGIC,
    SETUP_RESULT_NO_ERRNO, SETUP_RESULT_READY, STATUS_MAGIC, STATUS_RESULT_COMMAND,
    STATUS_RESULT_FAILURE, STATUS_RESULT_NO_ERRNO,
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

#[derive(Debug)]
struct TraceSupervisor {
    root_pid: libc::pid_t,
    tracees: HashSet<libc::pid_t>,
}

#[derive(Debug)]
struct CommandSeccompFilter {
    clone3_compatibility: BpfProgram,
    policy: BpfProgram,
}

const LINUX_SOCKET_TYPE_MASK: u64 = 0x0f;
const KEYCTL_JOIN_SESSION_KEYRING: libc::c_long = 1;

/// Applies hardening to the trusted helper and prepares the command filter.
fn prepare_hardening(
    hardening_required: bool,
    network_mode: NetworkHardeningMode,
) -> Result<Option<CommandSeccompFilter>, LinuxHardeningError> {
    isolate_session_keyring().map_err(|source| LinuxHardeningError::Operation {
        operation: LinuxHardeningOperation::KeyringIsolation,
        source,
    })?;
    if !hardening_required && network_mode == NetworkHardeningMode::None {
        return Ok(None);
    }
    set_parent_death_signal()?;
    set_dumpable(false).map_err(|source| LinuxHardeningError::Operation {
        operation: LinuxHardeningOperation::Dumpability,
        source,
    })?;
    set_core_dump_limit_zero().map_err(|source| LinuxHardeningError::Operation {
        operation: LinuxHardeningOperation::CoreDumpLimit,
        source,
    })?;
    set_no_new_privs().map_err(|source| LinuxHardeningError::Operation {
        operation: LinuxHardeningOperation::NoNewPrivileges,
        source,
    })?;
    let clone3_compatibility = build_clone3_compatibility_filter()
        .map_err(|source| LinuxHardeningError::SeccompBuild { source })?;
    let policy = build_filter(network_mode, true)
        .map_err(|source| LinuxHardeningError::SeccompBuild { source })?;
    Ok(Some(CommandSeccompFilter {
        clone3_compatibility,
        policy,
    }))
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
            return report_setup_failure(
                &mut authentication,
                LinuxHelperSetupFailureKind::NetworkMode,
                &error,
            );
        }
    };
    let bridge = match start_gateway_bridge(network_mode, &mut authentication) {
        Ok(bridge) => bridge,
        Err(error) => {
            return report_setup_failure(
                &mut authentication,
                LinuxHelperSetupFailureKind::GatewayBridge,
                &error,
            );
        }
    };
    let environment = match read_environment(&mut authentication) {
        Ok(environment) => environment,
        Err(error) => {
            return report_setup_failure(
                &mut authentication,
                LinuxHelperSetupFailureKind::EnvironmentFrame,
                &error,
            );
        }
    };
    let command_filter = match prepare_hardening(hardening_required, network_mode) {
        Ok(filter) => filter,
        Err(error) => {
            let kind = process_hardening_failure_kind(&error);
            return report_setup_failure(&mut authentication, kind, &error);
        }
    };
    if let Err(error) = set_close_on_exec(authentication.as_raw_fd(), true) {
        return report_setup_failure(
            &mut authentication,
            LinuxHelperSetupFailureKind::ProcessHardening,
            &error,
        );
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
    let trace_command = command_filter.is_some();
    if let Some(filter) = command_filter {
        // The helper is intentionally left outside the command's seccomp
        // filter so it can supervise the traced process tree. The child
        // installs the filter and requests tracing before exec, while it is
        // still non-dumpable and stopped by the trusted helper boundary.
        #[allow(unsafe_code)]
        unsafe {
            command.pre_exec(move || prepare_traced_command(&filter));
        }
    }
    let status = if trace_command {
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                let error = LinuxHardeningError::CommandStart { source: error };
                return report_setup_failure(
                    &mut authentication,
                    LinuxHelperSetupFailureKind::CommandStart,
                    &error,
                );
            }
        };
        let supervisor = match prepare_trace_supervision(&child) {
            Ok(supervisor) => supervisor,
            Err(error) => {
                terminate_traced_command(&mut child);
                return report_setup_failure(
                    &mut authentication,
                    LinuxHelperSetupFailureKind::TraceSupervision,
                    &error,
                );
            }
        };
        if let Err(error) = complete_setup_handshake(&mut authentication) {
            terminate_traced_command(&mut child);
            eprintln!("failed Linux sandbox setup handshake: {error}");
            return ExitCode::from(125);
        }
        match supervise_traced_command(supervisor) {
            Ok(status) => status,
            Err(error) => {
                terminate_traced_command(&mut child);
                return report_runtime_failure(
                    &mut authentication,
                    LinuxHelperRuntimeFailureKind::TraceSupervision,
                    &error,
                    125,
                );
            }
        }
    } else {
        if let Err(error) = complete_setup_handshake(&mut authentication) {
            eprintln!("failed Linux sandbox setup handshake: {error}");
            return ExitCode::from(125);
        }
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                let error = LinuxHardeningError::CommandStart { source: error };
                return report_runtime_failure(
                    &mut authentication,
                    LinuxHelperRuntimeFailureKind::CommandStart,
                    &error,
                    126,
                );
            }
        };
        match child.wait() {
            Ok(status) => status,
            Err(source) => {
                let error = LinuxHardeningError::Operation {
                    operation: LinuxHardeningOperation::CommandWait,
                    source,
                };
                return report_runtime_failure(
                    &mut authentication,
                    LinuxHelperRuntimeFailureKind::CommandWait,
                    &error,
                    125,
                );
            }
        }
    };
    if let Err(error) = write_command_status(&mut authentication, status) {
        eprintln!("failed to report sandboxed command status: {error}");
        return ExitCode::from(125);
    }
    ExitCode::from(status.code().unwrap_or(1) as u8)
}

fn process_hardening_failure_kind(error: &LinuxHardeningError) -> LinuxHelperSetupFailureKind {
    match error {
        LinuxHardeningError::ParentExitedDuringHardening
        | LinuxHardeningError::Operation {
            operation: LinuxHardeningOperation::ParentDeathSignal,
            ..
        } => LinuxHelperSetupFailureKind::ParentDeathSignal,
        LinuxHardeningError::Operation {
            operation: LinuxHardeningOperation::Dumpability,
            ..
        } => LinuxHelperSetupFailureKind::Dumpability,
        LinuxHardeningError::Operation {
            operation: LinuxHardeningOperation::CoreDumpLimit,
            ..
        } => LinuxHelperSetupFailureKind::CoreDumpLimit,
        LinuxHardeningError::Operation {
            operation: LinuxHardeningOperation::NoNewPrivileges,
            ..
        } => LinuxHelperSetupFailureKind::NoNewPrivileges,
        LinuxHardeningError::Operation {
            operation: LinuxHardeningOperation::KeyringIsolation,
            ..
        } => LinuxHelperSetupFailureKind::KeyringIsolation,
        LinuxHardeningError::SeccompBuild { .. } => LinuxHelperSetupFailureKind::SeccompBuild,
        _ => LinuxHelperSetupFailureKind::ProcessHardening,
    }
}

fn report_setup_failure(
    authentication: &mut File,
    kind: LinuxHelperSetupFailureKind,
    error: &(dyn StdError + 'static),
) -> ExitCode {
    let failure = LinuxHelperSetupFailure::new(kind, first_raw_os_error(error));
    if let Err(source) = write_setup_failure(authentication, failure) {
        eprintln!("failed to report typed Linux helper setup failure: {source}");
    }
    eprintln!("Linux helper setup failed: {error}");
    ExitCode::from(125)
}

fn report_runtime_failure(
    authentication: &mut File,
    kind: LinuxHelperRuntimeFailureKind,
    error: &(dyn StdError + 'static),
    exit_code: u8,
) -> ExitCode {
    let failure = LinuxHelperRuntimeFailure::new(kind, first_raw_os_error(error));
    if let Err(source) = write_runtime_failure(authentication, failure) {
        eprintln!("failed to report typed Linux helper runtime failure: {source}");
    }
    eprintln!("Linux helper runtime failed: {error}");
    ExitCode::from(exit_code)
}

fn first_raw_os_error(error: &(dyn StdError + 'static)) -> Option<i32> {
    let mut current = Some(error);
    while let Some(error) = current {
        if let Some(error) = error.downcast_ref::<io::Error>()
            && let Some(raw_os_error) = error.raw_os_error()
        {
            return Some(raw_os_error);
        }
        current = error.source();
    }
    None
}

fn isolate_session_keyring() -> io::Result<()> {
    #[allow(unsafe_code)]
    let result = unsafe {
        libc::syscall(
            libc::SYS_keyctl,
            KEYCTL_JOIN_SESSION_KEYRING,
            std::ptr::null::<libc::c_char>(),
            0,
            0,
            0,
        )
    };
    if result >= 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn write_setup_failure(
    writer: &mut impl Write,
    failure: LinuxHelperSetupFailure,
) -> io::Result<()> {
    writer.write_all(SETUP_RESULT_MAGIC)?;
    writer.write_all(&[SETUP_RESULT_FAILURE])?;
    writer.write_all(&u16::from(failure.kind()).to_be_bytes())?;
    writer.write_all(
        &failure
            .raw_os_error()
            .unwrap_or(SETUP_RESULT_NO_ERRNO)
            .to_be_bytes(),
    )
}

fn write_runtime_failure(
    writer: &mut impl Write,
    failure: LinuxHelperRuntimeFailure,
) -> io::Result<()> {
    writer.write_all(STATUS_MAGIC)?;
    writer.write_all(&[STATUS_RESULT_FAILURE])?;
    writer.write_all(&u16::from(failure.kind()).to_be_bytes())?;
    writer.write_all(
        &failure
            .raw_os_error()
            .unwrap_or(STATUS_RESULT_NO_ERRNO)
            .to_be_bytes(),
    )
}

fn prepare_traced_command(filter: &CommandSeccompFilter) -> io::Result<()> {
    set_command_parent_death_signal()?;
    apply_filter(&filter.clone3_compatibility)
        .and_then(|()| apply_filter(&filter.policy))
        .map_err(|_| io::Error::from_raw_os_error(libc::EPERM))?;
    request_parent_tracing()
}

fn prepare_trace_supervision(child: &Child) -> Result<TraceSupervisor, LinuxHardeningError> {
    let root_pid = child.id() as libc::pid_t;
    let initial_status = wait_for_tracee(root_pid)?;
    if !libc::WIFSTOPPED(initial_status) || libc::WSTOPSIG(initial_status) != libc::SIGTRAP {
        return Err(LinuxHardeningError::UnexpectedTraceStatus {
            pid: root_pid,
            status: initial_status,
        });
    }
    set_trace_options(root_pid)?;
    Ok(TraceSupervisor {
        root_pid,
        tracees: HashSet::from([root_pid]),
    })
}

fn supervise_traced_command(
    mut supervisor: TraceSupervisor,
) -> Result<ExitStatus, LinuxHardeningError> {
    continue_tracee(supervisor.root_pid, 0)?;
    loop {
        let mut status = 0;
        #[allow(unsafe_code)]
        let pid = unsafe { libc::waitpid(-1, &mut status, libc::__WALL) };
        if pid == -1 {
            let source = io::Error::last_os_error();
            if source.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(LinuxHardeningError::Operation {
                operation: LinuxHardeningOperation::TraceWait,
                source,
            });
        }
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            supervisor.tracees.remove(&pid);
            if pid == supervisor.root_pid {
                return Ok(ExitStatus::from_raw(status));
            }
            continue;
        }
        if libc::WIFCONTINUED(status) {
            continue;
        }
        if !libc::WIFSTOPPED(status) {
            return Err(LinuxHardeningError::UnexpectedTraceStatus { pid, status });
        }

        if supervisor.tracees.insert(pid) {
            set_trace_options(pid)?;
            continue_tracee(pid, 0)?;
            continue;
        }
        let event = status >> 16;
        if event != 0 {
            continue_tracee(pid, 0)?;
        } else {
            continue_tracee(pid, libc::WSTOPSIG(status))?;
        }
    }
}

fn wait_for_tracee(pid: libc::pid_t) -> Result<libc::c_int, LinuxHardeningError> {
    loop {
        let mut status = 0;
        #[allow(unsafe_code)]
        let result = unsafe { libc::waitpid(pid, &mut status, libc::__WALL) };
        if result == pid {
            return Ok(status);
        }
        let source = io::Error::last_os_error();
        if source.kind() != io::ErrorKind::Interrupted {
            return Err(LinuxHardeningError::Operation {
                operation: LinuxHardeningOperation::TraceWait,
                source,
            });
        }
    }
}

#[allow(unsafe_code)]
fn set_trace_options(pid: libc::pid_t) -> Result<(), LinuxHardeningError> {
    let options = libc::PTRACE_O_EXITKILL
        | libc::PTRACE_O_TRACECLONE
        | libc::PTRACE_O_TRACEEXEC
        | libc::PTRACE_O_TRACEFORK
        | libc::PTRACE_O_TRACEVFORK;
    let result = unsafe {
        libc::ptrace(
            libc::PTRACE_SETOPTIONS,
            pid,
            std::ptr::null_mut::<libc::c_void>(),
            options as usize as *mut libc::c_void,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(LinuxHardeningError::Operation {
            operation: LinuxHardeningOperation::TraceSetOptions,
            source: io::Error::last_os_error(),
        })
    }
}

#[allow(unsafe_code)]
fn continue_tracee(pid: libc::pid_t, signal: libc::c_int) -> Result<(), LinuxHardeningError> {
    let result = unsafe {
        libc::ptrace(
            libc::PTRACE_CONT,
            pid,
            std::ptr::null_mut::<libc::c_void>(),
            signal as usize as *mut libc::c_void,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(LinuxHardeningError::Operation {
            operation: LinuxHardeningOperation::TraceContinue,
            source: io::Error::last_os_error(),
        })
    }
}

fn terminate_traced_command(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn write_command_status(
    writer: &mut impl Write,
    status: std::process::ExitStatus,
) -> Result<(), LinuxHardeningError> {
    writer
        .write_all(STATUS_MAGIC)
        .map_err(|source| LinuxHardeningError::StatusWrite { source })?;
    writer
        .write_all(&[STATUS_RESULT_COMMAND])
        .and_then(|()| writer.write_all(&status.into_raw().to_be_bytes()))
        .map_err(|source| LinuxHardeningError::StatusWrite { source })
}

fn network_hardening_mode() -> Result<NetworkHardeningMode, LinuxHardeningError> {
    match std::env::var_os(NETWORK_MODE_ENV).as_deref() {
        None => Ok(NetworkHardeningMode::None),
        Some(value) if value == NETWORK_MODE_DIRECT_WITHOUT_UNIX => {
            Ok(NetworkHardeningMode::DirectWithoutUnixSockets)
        }
        Some(value) if value == NETWORK_MODE_DISABLED => Ok(NetworkHardeningMode::Disabled),
        Some(value) if value == NETWORK_MODE_PROXY => Ok(NetworkHardeningMode::ProxyRouted),
        Some(value) => Err(LinuxHardeningError::UnknownNetworkMode {
            value: value.to_string_lossy().into_owned(),
        }),
    }
}

fn start_gateway_bridge(
    mode: NetworkHardeningMode,
    authentication: &mut File,
) -> Result<Option<LocalGatewayBridge>, LinuxHardeningError> {
    if mode != NetworkHardeningMode::ProxyRouted {
        return Ok(None);
    }
    let socket = std::env::var_os(GATEWAY_SOCKET_ENV)
        .map(PathBuf::from)
        .ok_or(LinuxHardeningError::MissingGatewaySocket)?;
    if !socket.is_absolute() {
        return Err(LinuxHardeningError::RelativeGatewaySocket { path: socket });
    }
    let max_connections = std::env::var(GATEWAY_CONNECTION_LIMIT_ENV)
        .map_err(|_| LinuxHardeningError::MissingGatewayConnectionLimit)?
        .parse::<usize>()
        .map_err(|source| LinuxHardeningError::InvalidGatewayConnectionLimit { source })?;
    if max_connections == 0 {
        return Err(LinuxHardeningError::ZeroGatewayConnectionLimit);
    }
    let mut bridge_token = [0; BRIDGE_TOKEN_BYTES];
    authentication
        .read_exact(&mut bridge_token)
        .map_err(|source| LinuxHardeningError::Operation {
            operation: LinuxHardeningOperation::BridgeTokenRead,
            source,
        })?;
    LocalGatewayBridge::start(
        &socket,
        max_connections,
        authentication.as_raw_fd(),
        bridge_token,
    )
    .map(Some)
    .map_err(|source| LinuxHardeningError::GatewayBridge { source })
}

fn verify_helper_authentication() -> Result<File, LinuxHardeningError> {
    let fd: libc::c_int = std::env::var(AUTH_FD_ENV)
        .map_err(|_| LinuxHardeningError::MissingEnvironment { name: AUTH_FD_ENV })?
        .parse()
        .map_err(|source| LinuxHardeningError::InvalidEnvironment {
            name: AUTH_FD_ENV,
            source,
        })?;
    if fd <= libc::STDERR_FILENO {
        return Err(LinuxHardeningError::AuthenticationDescriptorTooLow { fd });
    }
    verify_authentication_peer(fd)?;
    #[allow(unsafe_code)]
    let mut auth = unsafe { File::from_raw_fd(fd) };
    let mut token = vec![0; AUTH_TOKEN.len()];
    auth.read_exact(&mut token)
        .map_err(|source| LinuxHardeningError::Operation {
            operation: LinuxHardeningOperation::AuthenticationTokenRead,
            source,
        })?;
    if token == AUTH_TOKEN {
        Ok(auth)
    } else {
        Err(LinuxHardeningError::AuthenticationTokenMismatch)
    }
}

/// Verifies that the authentication channel came from the host side of the
/// Bubblewrap PID namespace. The protocol marker below is deliberately not a
/// secret: a process inside the namespace can know it, so the Unix peer
/// credentials are the actual boundary authentication.
#[allow(unsafe_code)]
fn verify_authentication_peer(fd: RawFd) -> Result<(), LinuxHardeningError> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(LinuxHardeningError::AuthenticationPeerQuery {
            source: io::Error::last_os_error(),
        });
    }
    if length < size_of::<libc::ucred>() as libc::socklen_t {
        return Err(LinuxHardeningError::AuthenticationPeerCredentialsTruncated);
    }

    // A valid backend peer lives outside the helper's PID namespace. Its PID
    // is therefore not visible to the helper. A socket made by the untrusted
    // command instead has a visible peer and must not authenticate.
    if credentials.pid <= 0 {
        return Ok(());
    }
    let probe = unsafe { libc::kill(credentials.pid, 0) };
    if probe == 0 {
        return Err(LinuxHardeningError::AuthenticationPeerInsideNamespace);
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        Err(LinuxHardeningError::AuthenticationPeerNotLive)
    } else {
        Err(LinuxHardeningError::AuthenticationPeerInsideNamespace)
    }
}

fn complete_setup_handshake(authentication: &mut File) -> Result<(), LinuxHardeningError> {
    authentication
        .write_all(SETUP_RESULT_MAGIC)
        .and_then(|()| authentication.write_all(&[SETUP_RESULT_READY]))
        .map_err(|source| LinuxHardeningError::Operation {
            operation: LinuxHardeningOperation::SetupReady,
            source,
        })?;
    let mut release = vec![0; RELEASE.len()];
    authentication
        .read_exact(&mut release)
        .map_err(|source| LinuxHardeningError::Operation {
            operation: LinuxHardeningOperation::SetupRelease,
            source,
        })?;
    if release == RELEASE {
        Ok(())
    } else {
        Err(LinuxHardeningError::InvalidSetupRelease)
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
fn set_dumpable(dumpable: bool) -> io::Result<()> {
    let value = libc::c_ulong::from(dumpable);
    let result = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, value, 0, 0, 0) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[allow(unsafe_code)]
fn set_core_dump_limit_zero() -> io::Result<()> {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let result = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[allow(unsafe_code)]
fn set_parent_death_signal() -> Result<(), LinuxHardeningError> {
    let expected_parent = unsafe { libc::getppid() };
    let result = unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) };
    if result != 0 {
        return Err(LinuxHardeningError::Operation {
            operation: LinuxHardeningOperation::ParentDeathSignal,
            source: io::Error::last_os_error(),
        });
    }
    if unsafe { libc::getppid() } != expected_parent {
        return Err(LinuxHardeningError::ParentExitedDuringHardening);
    }
    Ok(())
}

#[allow(unsafe_code)]
fn set_command_parent_death_signal() -> io::Result<()> {
    let expected_parent = unsafe { libc::getppid() };
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::getppid() } != expected_parent {
        return Err(io::Error::from_raw_os_error(libc::ESRCH));
    }
    Ok(())
}

#[allow(unsafe_code)]
fn request_parent_tracing() -> io::Result<()> {
    let result = unsafe {
        libc::ptrace(
            libc::PTRACE_TRACEME,
            0,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[allow(unsafe_code)]
fn set_close_on_exec(
    fd: std::os::fd::RawFd,
    close_on_exec: bool,
) -> Result<(), LinuxHardeningError> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags == -1 {
        return Err(LinuxHardeningError::Operation {
            operation: LinuxHardeningOperation::CloseOnExec,
            source: io::Error::last_os_error(),
        });
    }
    let updated = if close_on_exec {
        flags | libc::FD_CLOEXEC
    } else {
        flags & !libc::FD_CLOEXEC
    };
    if unsafe { libc::fcntl(fd, libc::F_SETFD, updated) } == -1 {
        Err(LinuxHardeningError::Operation {
            operation: LinuxHardeningOperation::CloseOnExec,
            source: io::Error::last_os_error(),
        })
    } else {
        Ok(())
    }
}

fn build_filter(
    mode: NetworkHardeningMode,
    permit_trace_me: bool,
) -> Result<BpfProgram, SeccompBuildError> {
    fn deny_syscall(rules: &mut BTreeMap<i64, Vec<SeccompRule>>, syscall: i64) {
        rules.insert(syscall, Vec::new());
    }

    let mut rules = BTreeMap::new();
    if permit_trace_me {
        let non_trace_me = SeccompRule::new(vec![
            SeccompCondition::new(
                0,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::Ne,
                libc::PTRACE_TRACEME as u64,
            )
            .map_err(|source| SeccompBuildError::Condition { source })?,
        ])
        .map_err(|source| SeccompBuildError::Rule { source })?;
        rules.insert(libc::SYS_ptrace, vec![non_trace_me]);
    } else {
        deny_syscall(&mut rules, libc::SYS_ptrace);
    }
    let clone_untraced = SeccompRule::new(vec![
        SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::MaskedEq(libc::CLONE_UNTRACED as u64),
            libc::CLONE_UNTRACED as u64,
        )
        .map_err(|source| SeccompBuildError::Condition { source })?,
    ])
    .map_err(|source| SeccompBuildError::Rule { source })?;
    rules.insert(libc::SYS_clone, vec![clone_untraced]);
    for syscall in [
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
    .map_err(|source| SeccompBuildError::Filter { source })?;
    let program: BpfProgram = filter
        .try_into()
        .map_err(|source: seccompiler::BackendError| SeccompBuildError::BpfConversion { source })?;
    Ok(program)
}

fn build_clone3_compatibility_filter() -> Result<BpfProgram, SeccompBuildError> {
    let filter = SeccompFilter::new(
        BTreeMap::from([(libc::SYS_clone3, Vec::new())]),
        SeccompAction::Allow,
        SeccompAction::Errno(libc::ENOSYS as u32),
        target_architecture()?,
    )
    .map_err(|source| SeccompBuildError::Filter { source })?;
    filter
        .try_into()
        .map_err(|source: seccompiler::BackendError| SeccompBuildError::BpfConversion { source })
}

fn add_unix_socket_isolation_rules(
    rules: &mut BTreeMap<i64, Vec<SeccompRule>>,
) -> Result<(), SeccompBuildError> {
    let unix_socket = SeccompRule::new(vec![
        SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Eq,
            libc::AF_UNIX as u64,
        )
        .map_err(|source| SeccompBuildError::Condition { source })?,
    ])
    .map_err(|source| SeccompBuildError::Rule { source })?;
    rules.insert(libc::SYS_socket, vec![unix_socket]);

    rules.insert(libc::SYS_socketpair, isolated_unix_socketpair_rules()?);
    Ok(())
}

fn add_disabled_network_rules(
    rules: &mut BTreeMap<i64, Vec<SeccompRule>>,
) -> Result<(), SeccompBuildError> {
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
    let non_unix = SeccompRule::new(vec![
        SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Ne,
            libc::AF_UNIX as u64,
        )
        .map_err(|source| SeccompBuildError::Condition { source })?,
    ])
    .map_err(|source| SeccompBuildError::Rule { source })?;
    rules.insert(
        libc::SYS_socket,
        vec![
            non_unix,
            unix_socket_type_rule(libc::SOCK_DGRAM)?,
            unix_socket_type_rule(libc::SOCK_SEQPACKET)?,
        ],
    );
    rules.insert(libc::SYS_socketpair, isolated_unix_socketpair_rules()?);
    Ok(())
}

fn add_proxy_network_rules(
    rules: &mut BTreeMap<i64, Vec<SeccompRule>>,
) -> Result<(), SeccompBuildError> {
    let ip_only = SeccompRule::new(vec![
        SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Ne,
            libc::AF_INET as u64,
        )
        .map_err(|source| SeccompBuildError::Condition { source })?,
        SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Ne,
            libc::AF_INET6 as u64,
        )
        .map_err(|source| SeccompBuildError::Condition { source })?,
    ])
    .map_err(|source| SeccompBuildError::Rule { source })?;
    rules.insert(libc::SYS_socket, vec![ip_only]);
    rules.insert(libc::SYS_socketpair, isolated_unix_socketpair_rules()?);
    Ok(())
}

fn isolated_unix_socketpair_rules() -> Result<Vec<SeccompRule>, SeccompBuildError> {
    let non_unix = SeccompRule::new(vec![
        SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Ne,
            libc::AF_UNIX as u64,
        )
        .map_err(|source| SeccompBuildError::Condition { source })?,
    ])
    .map_err(|source| SeccompBuildError::Rule { source })?;
    let unix_datagram = unix_socket_type_rule(libc::SOCK_DGRAM)?;
    let unix_seqpacket = unix_socket_type_rule(libc::SOCK_SEQPACKET)?;
    Ok(vec![non_unix, unix_datagram, unix_seqpacket])
}

fn unix_socket_type_rule(socket_type: libc::c_int) -> Result<SeccompRule, SeccompBuildError> {
    SeccompRule::new(vec![
        SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Eq,
            libc::AF_UNIX as u64,
        )
        .map_err(|source| SeccompBuildError::Condition { source })?,
        SeccompCondition::new(
            1,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::MaskedEq(LINUX_SOCKET_TYPE_MASK),
            socket_type as u64,
        )
        .map_err(|source| SeccompBuildError::Condition { source })?,
    ])
    .map_err(|source| SeccompBuildError::Rule { source })
}

fn target_architecture() -> Result<seccompiler::TargetArch, SeccompBuildError> {
    if cfg!(target_arch = "x86_64") {
        Ok(seccompiler::TargetArch::x86_64)
    } else if cfg!(target_arch = "aarch64") {
        Ok(seccompiler::TargetArch::aarch64)
    } else {
        Err(SeccompBuildError::UnsupportedArchitecture {
            architecture: std::env::consts::ARCH.to_string(),
        })
    }
}
