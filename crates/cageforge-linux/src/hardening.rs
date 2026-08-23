// SPDX-License-Identifier: Apache-2.0

//! Linux process hardening applied to the Bubblewrap boundary.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io;
use std::io::Read;
use std::os::fd::FromRawFd;
use std::process::{Command, ExitCode};

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, apply_filter,
};

const HELPER_AUTH_ENV: &str = "CAGEFORGE_LINUX_HELPER_AUTH_FD";
const HELPER_AUTH_TOKEN: &[u8] = b"cageforge-linux-helper-v1";

/// Applies process hardening inside the Bubblewrap namespace.
pub(crate) fn apply(hardening_required: bool, network_isolated: bool) -> io::Result<()> {
    if !hardening_required && !network_isolated {
        return Ok(());
    }
    set_parent_death_signal()?;
    set_no_new_privs()?;
    if network_isolated {
        let filter = build_filter().map_err(io::Error::other)?;
        apply_filter(&filter).map_err(io::Error::other)?;
    }
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
    if let Err(error) = verify_helper_authentication() {
        eprintln!("invalid Linux hardening helper invocation: {error}");
        return ExitCode::from(125);
    }
    let hardening_required = std::env::var_os("CAGEFORGE_LINUX_HARDENING_REQUIRED").is_some();
    let network_isolated = std::env::var_os("CAGEFORGE_LINUX_NETWORK_ISOLATED").is_some();
    if let Err(error) = apply(hardening_required, network_isolated) {
        eprintln!("failed to apply Linux process hardening: {error}");
        return ExitCode::from(125);
    }
    let status = match Command::new(program)
        .args(args)
        .env_remove("CAGEFORGE_LINUX_NETWORK_ISOLATED")
        .env_remove("CAGEFORGE_LINUX_HARDENING_REQUIRED")
        .env_remove(HELPER_AUTH_ENV)
        .status()
    {
        Ok(status) => status,
        Err(error) => {
            eprintln!("failed to start hardened command: {error}");
            return ExitCode::from(126);
        }
    };
    ExitCode::from(status.code().unwrap_or(1) as u8)
}

fn verify_helper_authentication() -> io::Result<()> {
    let fd = std::env::var(HELPER_AUTH_ENV)
        .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "missing auth fd"))?
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid auth fd"))?;
    #[allow(unsafe_code)]
    let mut auth = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut token = vec![0; HELPER_AUTH_TOKEN.len()];
    auth.read_exact(&mut token)?;
    if token == HELPER_AUTH_TOKEN {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "auth token mismatch",
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
    let result = unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn build_filter() -> Result<BpfProgram, String> {
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
        deny_syscall(&mut rules, syscall);
    }

    // Match Codex's restricted Linux sandbox: local Unix sockets remain
    // available for process-local IPC, while creating an IP socket is denied
    // before a command can attempt to bypass the blocked connect/send paths.
    let unix_only_condition = SeccompCondition::new(
        0,
        SeccompCmpArgLen::Dword,
        SeccompCmpOp::Ne,
        libc::AF_UNIX as u64,
    )
    .map_err(|error| error.to_string())?;
    let unix_only_rule =
        SeccompRule::new(vec![unix_only_condition]).map_err(|error| error.to_string())?;
    rules.insert(libc::SYS_socket, vec![unix_only_rule.clone()]);
    rules.insert(libc::SYS_socketpair, vec![unix_only_rule]);

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
