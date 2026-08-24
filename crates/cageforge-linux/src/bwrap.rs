// SPDX-License-Identifier: Apache-2.0

//! Bubblewrap discovery, probing, and common namespace arguments.

use std::ffi::OsString;
use std::fs;
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::config::{BubblewrapSource, HardeningHelperSource, ProcMountPolicy};
use crate::error::LinuxBackendError;

const REQUIRED_HELP_FLAGS: &[&str] = &[
    "--as-pid-1",
    "--bind",
    "--bind-fd",
    "--bind-try",
    "--chdir",
    "--dir",
    "--dev",
    "--die-with-parent",
    "--new-session",
    "--perms",
    "--proc",
    "--remount-ro",
    "--ro-bind",
    "--ro-bind-data",
    "--ro-bind-fd",
    "--tmpfs",
    "--unshare-net",
    "--unshare-pid",
    "--unshare-user",
];
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const PROBE_OUTPUT_LIMIT_BYTES: usize = 256 * 1024;
const PROBE_POLL_INTERVAL: Duration = Duration::from_millis(5);

struct ProbeOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

enum ProbeError {
    Io(io::Error),
    TimedOut,
    OutputLimitExceeded,
}

pub(crate) fn discover_hardening_helper(
    source: &HardeningHelperSource,
) -> Result<PathBuf, LinuxBackendError> {
    let path = match source {
        HardeningHelperSource::Sibling => std::env::current_exe()
            .ok()
            .and_then(|executable| executable.parent().map(Path::to_path_buf))
            .map(|directory| directory.join("cageforge-linux-helper"))
            .ok_or(LinuxBackendError::HardeningHelperUnavailable)?,
        HardeningHelperSource::Explicit(path) => path.clone(),
    };
    let path = fs::canonicalize(path).map_err(|_| LinuxBackendError::HardeningHelperUnavailable)?;
    validate_executable(&path).map_err(|_| LinuxBackendError::HardeningHelperUnavailable)?;
    Ok(path)
}

pub(crate) fn discover_and_probe(
    source: &BubblewrapSource,
    proc_mount: ProcMountPolicy,
) -> Result<PathBuf, LinuxBackendError> {
    let path = match source {
        BubblewrapSource::System => {
            find_on_path("bwrap").ok_or(LinuxBackendError::BubblewrapUnavailable)?
        }
        BubblewrapSource::Explicit(path) => path.clone(),
    };
    let path = fs::canonicalize(&path).map_err(|_| LinuxBackendError::BubblewrapUnavailable)?;
    validate_executable(&path)?;
    probe_help(&path)?;
    probe_namespaces(&path)?;
    if proc_mount == ProcMountPolicy::Required {
        probe_proc_mount(&path)?;
    }
    Ok(path)
}

fn find_on_path(program: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    let current_directory = std::env::current_dir().ok()?;
    find_in_search_paths(program, std::env::split_paths(&path), &current_directory)
}

fn validate_executable(path: &Path) -> Result<(), LinuxBackendError> {
    let metadata = fs::metadata(path).map_err(|_| LinuxBackendError::BubblewrapUnavailable)?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err(LinuxBackendError::BubblewrapUnavailable);
    }
    Ok(())
}

fn probe_help(path: &Path) -> Result<(), LinuxBackendError> {
    let output =
        run_probe(path, &["--help"], PROBE_TIMEOUT).map_err(|error| probe_error("help", error))?;
    let mut help = String::from_utf8_lossy(&output.stdout).into_owned();
    help.push_str(&String::from_utf8_lossy(&output.stderr));
    let missing = missing_help_flags(&help);
    if missing.is_empty() {
        Ok(())
    } else {
        Err(LinuxBackendError::BubblewrapIncompatible { missing })
    }
}

fn missing_help_flags(help: &str) -> Vec<String> {
    let available = help
        .split_ascii_whitespace()
        .collect::<std::collections::HashSet<_>>();
    REQUIRED_HELP_FLAGS
        .iter()
        .filter(|flag| !available.contains(**flag))
        .map(|flag| (*flag).to_string())
        .collect()
}

fn probe_namespaces(path: &Path) -> Result<(), LinuxBackendError> {
    let output = run_probe(
        path,
        &[
            "--die-with-parent",
            "--unshare-user",
            "--unshare-pid",
            "--unshare-net",
            "--as-pid-1",
            "--ro-bind",
            "/",
            "/",
            "/bin/true",
        ],
        PROBE_TIMEOUT,
    )
    .map_err(|error| probe_error("user namespace", error))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(LinuxBackendError::UserNamespaceUnavailable {
            message: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
    }
}

fn probe_proc_mount(path: &Path) -> Result<(), LinuxBackendError> {
    let output = run_probe(
        path,
        &[
            "--die-with-parent",
            "--unshare-user",
            "--unshare-pid",
            "--as-pid-1",
            "--ro-bind",
            "/",
            "/",
            "--proc",
            "/proc",
            "/bin/true",
        ],
        PROBE_TIMEOUT,
    )
    .map_err(|error| probe_error("proc mount", error))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(LinuxBackendError::ProcMountUnavailable)
    }
}

fn find_in_search_paths(
    program: &str,
    search_paths: impl IntoIterator<Item = PathBuf>,
    current_directory: &Path,
) -> Option<PathBuf> {
    let current_directory = fs::canonicalize(current_directory).ok()?;
    let current_directory_is_root = current_directory.parent().is_none();
    search_paths.into_iter().find_map(|directory| {
        let candidate = fs::canonicalize(directory.join(program)).ok()?;
        if (!current_directory_is_root && candidate.starts_with(&current_directory))
            || validate_executable(&candidate).is_err()
        {
            None
        } else {
            Some(candidate)
        }
    })
}

fn run_probe(path: &Path, args: &[&str], timeout: Duration) -> Result<ProbeOutput, ProbeError> {
    let mut child = Command::new(path)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(ProbeError::Io)?;
    let mut stdout = child.stdout.take().expect("piped stdout is present");
    let mut stderr = child.stderr.take().expect("piped stderr is present");
    set_nonblocking(stdout.as_raw_fd()).map_err(ProbeError::Io)?;
    set_nonblocking(stderr.as_raw_fd()).map_err(ProbeError::Io)?;
    let deadline = Instant::now() + timeout;
    let mut stdout_bytes = Vec::new();
    let mut stderr_bytes = Vec::new();
    loop {
        if drain_probe_output(&mut stdout, &mut stdout_bytes).map_err(ProbeError::Io)?
            || drain_probe_output(&mut stderr, &mut stderr_bytes).map_err(ProbeError::Io)?
        {
            terminate_probe(&mut child);
            return Err(ProbeError::OutputLimitExceeded);
        }
        match child.try_wait().map_err(ProbeError::Io)? {
            Some(status) => {
                if drain_probe_output(&mut stdout, &mut stdout_bytes).map_err(ProbeError::Io)?
                    || drain_probe_output(&mut stderr, &mut stderr_bytes).map_err(ProbeError::Io)?
                {
                    return Err(ProbeError::OutputLimitExceeded);
                }
                return Ok(ProbeOutput {
                    status,
                    stdout: stdout_bytes,
                    stderr: stderr_bytes,
                });
            }
            None if Instant::now() >= deadline => {
                terminate_probe(&mut child);
                return Err(ProbeError::TimedOut);
            }
            None => thread::sleep(PROBE_POLL_INTERVAL),
        }
    }
}

fn drain_probe_output(reader: &mut impl Read, output: &mut Vec<u8>) -> io::Result<bool> {
    let mut buffer = [0_u8; 8192];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(false),
            Ok(read) => {
                output.extend_from_slice(&buffer[..read]);
                if output.len() > PROBE_OUTPUT_LIMIT_BYTES {
                    return Ok(true);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

fn terminate_probe(child: &mut std::process::Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn probe_error(stage: &'static str, error: ProbeError) -> LinuxBackendError {
    match error {
        ProbeError::Io(source) => LinuxBackendError::BubblewrapProbeFailed { stage, source },
        ProbeError::TimedOut => LinuxBackendError::BubblewrapProbeTimedOut { stage },
        ProbeError::OutputLimitExceeded => LinuxBackendError::BubblewrapProbeOutputLimitExceeded {
            stage,
            limit: PROBE_OUTPUT_LIMIT_BYTES,
        },
    }
}

#[allow(unsafe_code)]
fn set_nonblocking(fd: std::os::fd::RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
#[path = "bwrap_tests.rs"]
mod tests;

pub(crate) fn namespace_args(
    _proc_mount: ProcMountPolicy,
    network_isolated: bool,
) -> Vec<OsString> {
    let mut args = vec![
        "--die-with-parent".into(),
        "--new-session".into(),
        "--unshare-user".into(),
        "--unshare-pid".into(),
        "--as-pid-1".into(),
    ];
    if network_isolated {
        args.push("--unshare-net".into());
    }
    args
}
