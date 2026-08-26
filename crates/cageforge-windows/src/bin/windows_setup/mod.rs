// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::io::Write;

use crate::setup_protocol::{SetupFailureCode, SetupOperation, SetupRequest, SetupStage};
use crate::setup_state::{SETUP_STATE_VERSION, SetupMarker, SetupMarkerAccounts};

mod accounts;
mod credentials;
mod firewall;
mod resources;
mod rights;
mod security;
mod wfp;

pub(super) struct NativeSetupFailure {
    pub(super) stage: SetupStage,
    pub(super) code: SetupFailureCode,
    pub(super) native_code: Option<u32>,
    pub(super) detail: String,
}

pub(super) struct ProvisionedAccounts {
    pub(super) offline_name: String,
    pub(super) offline_sid: String,
    pub(super) offline_password: String,
    pub(super) online_name: String,
    pub(super) online_sid: String,
    pub(super) online_password: String,
    pub(super) group_name: String,
    pub(super) group_sid: String,
}

pub(super) type NativeSetupResult<T> = Result<T, NativeSetupFailure>;

impl NativeSetupFailure {
    pub(super) fn new(
        stage: SetupStage,
        code: SetupFailureCode,
        native_code: Option<u32>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            stage,
            code,
            native_code,
            detail: detail.into(),
        }
    }
}

pub(super) fn execute(request: &SetupRequest) -> NativeSetupResult<()> {
    security::require_elevated()?;
    security::validate_request_boundary(request)?;
    match request.operation {
        SetupOperation::Install => install(request),
        SetupOperation::Uninstall => uninstall(request),
    }
}

fn install(request: &SetupRequest) -> NativeSetupResult<()> {
    security::prepare_state_directory(&request.state_directory, &request.owner_sid)?;
    resources::verify_and_stage(request)?;
    let marker_path = request.state_directory.join("setup.json");
    match fs::remove_file(&marker_path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(NativeSetupFailure::new(
                SetupStage::Marker,
                SetupFailureCode::MarkerWrite,
                error.raw_os_error().map(|code| code as u32),
                format!("failed to remove stale marker {marker_path:?}: {error}"),
            ));
        }
    }

    let accounts = accounts::provision(request)?;
    rights::apply_and_verify(&accounts.offline_sid)?;
    rights::apply_and_verify(&accounts.online_sid)?;
    let credential_sha256 = credentials::write_protected(request, &accounts)?;
    let firewall_policy_id = firewall::install_and_verify(request, &accounts.offline_sid)?;
    let wfp_provider_id = wfp::install_and_verify(
        &request.owner_sid,
        &accounts.offline_name,
        &accounts.offline_sid,
    )?;
    write_marker(
        request,
        accounts,
        credential_sha256,
        firewall_policy_id,
        wfp_provider_id,
    )
}

fn write_marker(
    request: &SetupRequest,
    accounts: ProvisionedAccounts,
    credential_sha256: String,
    firewall_policy_id: String,
    wfp_provider_id: String,
) -> NativeSetupResult<()> {
    let marker = SetupMarker {
        version: SETUP_STATE_VERSION,
        owner_sid: request.owner_sid.clone(),
        accounts: SetupMarkerAccounts {
            offline_name: accounts.offline_name,
            offline_sid: accounts.offline_sid,
            online_name: accounts.online_name,
            online_sid: accounts.online_sid,
            group_name: accounts.group_name,
            group_sid: accounts.group_sid,
        },
        proxy_ports: request.proxy_ports.clone(),
        firewall_policy_id,
        wfp_provider_id,
        setup_helper_sha256: request.setup_helper_sha256.clone(),
        command_runner_sha256: request.command_runner_sha256.clone(),
        credential_sha256,
    };
    let encoded = serde_json::to_vec(&marker).map_err(|error| {
        NativeSetupFailure::new(
            SetupStage::Marker,
            SetupFailureCode::MarkerSerialize,
            None,
            format!("failed to encode the completed setup marker: {error}"),
        )
    })?;
    let path = request.state_directory.join("setup.json");
    let mut file =
        security::create_protected_file(&path, &request.owner_sid).map_err(|failure| {
            NativeSetupFailure::new(
                SetupStage::Marker,
                SetupFailureCode::MarkerAcl,
                failure.native_code,
                failure.detail,
            )
        })?;
    file.write_all(&encoded).map_err(|error| {
        NativeSetupFailure::new(
            SetupStage::Marker,
            SetupFailureCode::MarkerWrite,
            error.raw_os_error().map(|code| code as u32),
            format!("failed to write completed setup marker {path:?}: {error}"),
        )
    })?;
    file.sync_all().map_err(|error| {
        NativeSetupFailure::new(
            SetupStage::Marker,
            SetupFailureCode::MarkerWrite,
            error.raw_os_error().map(|code| code as u32),
            format!("failed to flush completed setup marker {path:?}: {error}"),
        )
    })
}

fn uninstall(request: &SetupRequest) -> NativeSetupResult<()> {
    firewall::remove(&request.owner_sid)?;
    wfp::remove(&request.owner_sid)?;
    accounts::remove(request)?;
    for path in [
        request.state_directory.join("setup.json"),
        request.state_directory.join("credentials.json.dpapi"),
        request
            .state_directory
            .join("bin")
            .join("cageforge-windows-setup.exe"),
        request
            .state_directory
            .join("bin")
            .join("cageforge-windows-command-runner.exe"),
    ] {
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(NativeSetupFailure::new(
                    SetupStage::Uninstall,
                    SetupFailureCode::Cleanup,
                    error.raw_os_error().map(|code| code as u32),
                    format!("failed to remove setup file {path:?}: {error}"),
                ));
            }
        }
    }
    for directory in [
        request.state_directory.join("bin"),
        request.state_directory.clone(),
    ] {
        match fs::remove_dir(&directory) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(NativeSetupFailure::new(
                    SetupStage::Uninstall,
                    SetupFailureCode::Cleanup,
                    error.raw_os_error().map(|code| code as u32),
                    format!("failed to remove empty setup directory {directory:?}: {error}"),
                ));
            }
        }
    }
    Ok(())
}
