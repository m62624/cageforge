// SPDX-License-Identifier: Apache-2.0

//! Bubblewrap discovery, probing, and common namespace arguments.

use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::config::{BubblewrapSource, HardeningHelperSource, ProcMountPolicy};
use crate::error::LinuxBackendError;

const REQUIRED_HELP_FLAGS: &[&str] = &[
    "--as-pid-1",
    "--bind",
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
    "--tmpfs",
    "--unshare-net",
    "--unshare-pid",
    "--unshare-user",
];

pub(crate) fn discover_hardening_helper(
    source: &HardeningHelperSource,
) -> Result<PathBuf, LinuxBackendError> {
    let path = match source {
        HardeningHelperSource::System => find_on_path("cageforge-linux-helper")
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
    std::env::split_paths(&path)
        .map(|directory| directory.join(program))
        .find(|candidate| candidate.is_file())
}

fn validate_executable(path: &Path) -> Result<(), LinuxBackendError> {
    let metadata = fs::metadata(path).map_err(|_| LinuxBackendError::BubblewrapUnavailable)?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err(LinuxBackendError::BubblewrapUnavailable);
    }
    Ok(())
}

fn probe_help(path: &Path) -> Result<(), LinuxBackendError> {
    let output = Command::new(path)
        .arg("--help")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|_| LinuxBackendError::BubblewrapUnavailable)?;
    let mut help = String::from_utf8_lossy(&output.stdout).into_owned();
    help.push_str(&String::from_utf8_lossy(&output.stderr));
    let missing = REQUIRED_HELP_FLAGS
        .iter()
        .filter(|flag| !help.contains(**flag))
        .map(|flag| (*flag).to_string())
        .collect::<Vec<_>>();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(LinuxBackendError::BubblewrapIncompatible { missing })
    }
}

fn probe_namespaces(path: &Path) -> Result<(), LinuxBackendError> {
    let output = Command::new(path)
        .args([
            "--die-with-parent",
            "--unshare-user",
            "--unshare-pid",
            "--unshare-net",
            "--as-pid-1",
            "--ro-bind",
            "/",
            "/",
            "/bin/true",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|source| LinuxBackendError::UserNamespaceUnavailable {
            message: source.to_string(),
        })?;
    if output.status.success() {
        Ok(())
    } else {
        Err(LinuxBackendError::UserNamespaceUnavailable {
            message: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
    }
}

fn probe_proc_mount(path: &Path) -> Result<(), LinuxBackendError> {
    let output = Command::new(path)
        .args([
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
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|_| LinuxBackendError::ProcMountUnavailable)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(LinuxBackendError::ProcMountUnavailable)
    }
}

pub(crate) fn namespace_args(
    _proc_mount: ProcMountPolicy,
    network_isolated: bool,
) -> Vec<OsString> {
    let mut args = vec![
        "--die-with-parent".into(),
        "--unshare-user".into(),
        "--unshare-pid".into(),
        "--as-pid-1".into(),
    ];
    if network_isolated {
        args.push("--unshare-net".into());
    }
    args
}
