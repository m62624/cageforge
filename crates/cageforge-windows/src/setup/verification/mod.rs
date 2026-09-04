// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::command_runner_name::COMMAND_RUNNER_NAME;
use crate::error::WindowsSetupVerificationError;
use crate::resource_names::SETUP_HELPER_NAME;
use crate::setup::WindowsSetupDetails;

pub(crate) mod credentials;
mod firewall;
pub(crate) mod paths;
mod rights;
mod runner;
mod wfp;

pub(crate) struct PinnedRunnerResources {
    command_runner_path: PathBuf,
    runner_manifest_path: PathBuf,
    command_runner: fs::File,
    runner_manifest: fs::File,
}

impl PinnedRunnerResources {
    pub(crate) fn open(
        details: &WindowsSetupDetails,
    ) -> Result<Self, WindowsSetupVerificationError> {
        let bin_directory = details.state_directory().join("bin");
        let command_runner_path = bin_directory.join(COMMAND_RUNNER_NAME);
        let runner_manifest_path =
            bin_directory.join(crate::runner::manifest::RUNNER_MANIFEST_NAME);
        let mut command_runner = paths::verify_runner_executable_dacl(
            &command_runner_path,
            details.owner_sid(),
            details.accounts().group_sid(),
        )?;
        let mut runner_manifest = paths::verify_runner_manifest_dacl(
            &runner_manifest_path,
            details.owner_sid(),
            details.accounts().group_sid(),
        )?;
        verify_resource_digest(
            "command runner",
            &command_runner_path,
            details.command_runner_sha256(),
            &mut command_runner,
        )?;
        runner::verify(details, &runner_manifest_path, &mut runner_manifest)?;
        Ok(Self {
            command_runner_path,
            runner_manifest_path,
            command_runner,
            runner_manifest,
        })
    }

    pub(crate) fn command_runner_path(&self) -> &Path {
        &self.command_runner_path
    }

    pub(crate) fn verify_launch_security(
        &self,
        owner_sid: &str,
        group_sid: &str,
    ) -> Result<(), WindowsSetupVerificationError> {
        paths::verify_open_runner_resource_dacl(
            &self.command_runner,
            &self.command_runner_path,
            owner_sid,
            group_sid,
            crate::runner::resource_security::RunnerResourceKind::Executable,
        )?;
        paths::verify_open_runner_resource_dacl(
            &self.runner_manifest,
            &self.runner_manifest_path,
            owner_sid,
            group_sid,
            crate::runner::resource_security::RunnerResourceKind::Manifest,
        )
    }
}

pub(super) fn verify(
    details: &WindowsSetupDetails,
    setup_marker: fs::File,
) -> Result<(), WindowsSetupVerificationError> {
    verify_ports(details.proxy_ports())?;
    let state = details.state_directory();
    let bin_directory = state.join("bin");
    let credentials_path = state.join("credentials.json.dpapi");
    let capability_state_path = state.join(crate::capability::state::CAPABILITY_STATE_NAME);
    let capability_lock_path = state.join(crate::capability::state::CAPABILITY_LOCK_NAME);
    let setup_helper_path = bin_directory.join(SETUP_HELPER_NAME);
    let _state_directory = paths::verify_protected_dacl(state, details.owner_sid(), true)?;
    let _bin_directory = paths::verify_runner_directory_dacl(
        &bin_directory,
        details.owner_sid(),
        details.accounts().group_sid(),
    )?;
    let _capability_lock =
        paths::verify_protected_dacl(&capability_lock_path, details.owner_sid(), false)?;
    verify_capability_state(state, details.owner_sid())?;
    let mut credentials =
        paths::verify_protected_dacl(&credentials_path, details.owner_sid(), false)?;
    let mut setup_helper =
        paths::verify_protected_dacl(&setup_helper_path, details.owner_sid(), false)?;
    let _setup_marker = paths::verify_open_protected_dacl(
        setup_marker,
        &state.join("setup.json"),
        details.owner_sid(),
        false,
    )?;
    let _capability_state =
        paths::verify_protected_dacl(&capability_state_path, details.owner_sid(), false)?;
    let _runner_resources = PinnedRunnerResources::open(details)?;
    rights::verify(details.accounts().offline_sid())?;
    rights::verify(details.accounts().online_sid())?;
    credentials::verify(details, &credentials_path, &mut credentials)?;
    verify_resource_digest(
        "setup helper",
        &setup_helper_path,
        details.setup_helper_sha256(),
        &mut setup_helper,
    )?;
    firewall::verify(details)?;
    wfp::verify(details)?;
    Ok(())
}

fn verify_capability_state(
    state_directory: &Path,
    owner_sid: &str,
) -> Result<(), WindowsSetupVerificationError> {
    crate::capability::store::CapabilityStateStore::new(state_directory, owner_sid)
        .verify()
        .map_err(
            |error| WindowsSetupVerificationError::CapabilityStateInvalid {
                path: state_directory.join(crate::capability::state::CAPABILITY_STATE_NAME),
                detail: error.to_string(),
            },
        )
}

pub(crate) fn open_verified_credentials(
    details: &WindowsSetupDetails,
) -> Result<fs::File, WindowsSetupVerificationError> {
    let path = details.state_directory().join("credentials.json.dpapi");
    let mut file = paths::verify_protected_dacl(&path, details.owner_sid(), false)?;
    credentials::verify(details, &path, &mut file)?;
    file.seek(SeekFrom::Start(0)).map_err(|source| {
        WindowsSetupVerificationError::CredentialRead {
            path: path.clone(),
            source,
        }
    })?;
    Ok(file)
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
    file: &mut fs::File,
) -> Result<(), WindowsSetupVerificationError> {
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|source| WindowsSetupVerificationError::ResourceRead {
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
