// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::error::WindowsSetupVerificationError;
use crate::setup::WindowsSetupDetails;

mod credentials;
mod firewall;
mod paths;
mod rights;
mod wfp;

const SETUP_HELPER_NAME: &str = "cageforge-windows-setup.exe";
const COMMAND_RUNNER_NAME: &str = "cageforge-windows-command-runner.exe";

pub(super) fn verify(details: &WindowsSetupDetails) -> Result<(), WindowsSetupVerificationError> {
    verify_ports(details.proxy_ports())?;
    let state = details.state_directory();
    let bin_directory = state.join("bin");
    let credentials_path = state.join("credentials.json.dpapi");
    let setup_helper_path = bin_directory.join(SETUP_HELPER_NAME);
    let command_runner_path = bin_directory.join(COMMAND_RUNNER_NAME);
    for path in [state, &bin_directory] {
        paths::verify_protected_dacl(path, details.owner_sid(), true)?;
    }
    for path in [
        &credentials_path,
        &setup_helper_path,
        &command_runner_path,
        &state.join("setup.json"),
    ] {
        paths::verify_protected_dacl(path, details.owner_sid(), false)?;
    }
    rights::verify(details.accounts().offline_sid())?;
    rights::verify(details.accounts().online_sid())?;
    credentials::verify(details, &credentials_path)?;
    verify_resource_digest(
        "setup helper",
        &setup_helper_path,
        details.setup_helper_sha256(),
    )?;
    verify_resource_digest(
        "command runner",
        &command_runner_path,
        details.command_runner_sha256(),
    )?;
    firewall::verify(details)?;
    wfp::verify(details)?;
    Ok(())
}

fn verify_ports(ports: &[u16]) -> Result<(), WindowsSetupVerificationError> {
    let mut canonical = ports.to_vec();
    canonical.sort_unstable();
    canonical.dedup();
    if canonical.len() == 2 && canonical.iter().all(|port| *port != 0) {
        Ok(())
    } else {
        Err(WindowsSetupVerificationError::InvalidProxyPorts {
            ports: ports.to_vec(),
        })
    }
}

fn verify_resource_digest(
    component: &'static str,
    path: &Path,
    expected: &str,
) -> Result<(), WindowsSetupVerificationError> {
    let bytes = fs::read(path).map_err(|source| WindowsSetupVerificationError::ResourceRead {
        path: path.to_path_buf(),
        source,
    })?;
    let actual = hex_digest(&bytes);
    if actual.eq_ignore_ascii_case(expected) {
        Ok(())
    } else {
        Err(WindowsSetupVerificationError::DigestMismatch {
            component,
            expected: expected.to_string(),
            actual,
        })
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
