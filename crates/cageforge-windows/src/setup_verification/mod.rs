// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::error::WindowsSetupVerificationError;
use crate::setup::WindowsSetupDetails;

pub(crate) mod credentials;
mod firewall;
pub(crate) mod paths;
mod rights;
mod runner;
mod wfp;

const SETUP_HELPER_NAME: &str = "cageforge-windows-setup.exe";
const COMMAND_RUNNER_NAME: &str = "cageforge-windows-command-runner.exe";

pub(super) fn verify(details: &WindowsSetupDetails) -> Result<(), WindowsSetupVerificationError> {
    verify_ports(details.proxy_ports())?;
    let state = details.state_directory();
    let bin_directory = state.join("bin");
    let credentials_path = state.join("credentials.json.dpapi");
    let capability_state_path = state.join(crate::capability_state::CAPABILITY_STATE_NAME);
    let capability_lock_path = state.join(crate::capability_state::CAPABILITY_LOCK_NAME);
    let setup_helper_path = bin_directory.join(SETUP_HELPER_NAME);
    let command_runner_path = bin_directory.join(COMMAND_RUNNER_NAME);
    let runner_manifest_path = bin_directory.join(crate::runner_manifest::RUNNER_MANIFEST_NAME);
    paths::verify_protected_dacl(state, details.owner_sid(), true)?;
    paths::verify_runner_directory_dacl(
        &bin_directory,
        details.owner_sid(),
        details.accounts().group_sid(),
    )?;
    for path in [
        &capability_state_path,
        &capability_lock_path,
        &credentials_path,
        &setup_helper_path,
        &state.join("setup.json"),
    ] {
        paths::verify_protected_dacl(path, details.owner_sid(), false)?;
    }
    verify_capability_state(state, details.owner_sid())?;
    paths::verify_runner_executable_dacl(
        &command_runner_path,
        details.owner_sid(),
        details.accounts().group_sid(),
    )?;
    paths::verify_runner_manifest_dacl(
        &runner_manifest_path,
        details.owner_sid(),
        details.accounts().group_sid(),
    )?;
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
    runner::verify(details, &runner_manifest_path)?;
    firewall::verify(details)?;
    wfp::verify(details)?;
    Ok(())
}

fn verify_capability_state(
    state_directory: &Path,
    owner_sid: &str,
) -> Result<(), WindowsSetupVerificationError> {
    crate::capability_store::CapabilityStateStore::new(state_directory, owner_sid)
        .verify()
        .map_err(
            |error| WindowsSetupVerificationError::CapabilityStateInvalid {
                path: state_directory.join(crate::capability_state::CAPABILITY_STATE_NAME),
                detail: error.to_string(),
            },
        )
}

pub(crate) fn read_credentials(
    details: &WindowsSetupDetails,
) -> Result<credentials::SandboxCredentials, WindowsSetupVerificationError> {
    credentials::read(
        details,
        &details.state_directory().join("credentials.json.dpapi"),
    )
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
