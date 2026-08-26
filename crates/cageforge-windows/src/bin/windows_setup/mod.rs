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

pub(super) fn execute(
    request: &SetupRequest,
    progress: &mut dyn FnMut(SetupStage, &str),
) -> NativeSetupResult<()> {
    progress(SetupStage::Elevation, "validating elevated setup identity");
    security::require_elevated()?;
    progress(SetupStage::Request, "validating setup request boundary");
    security::validate_request_boundary(request)?;
    match request.operation {
        SetupOperation::Install => install(request, progress),
        SetupOperation::Uninstall => uninstall(request),
    }
}

fn install(
    request: &SetupRequest,
    progress: &mut dyn FnMut(SetupStage, &str),
) -> NativeSetupResult<()> {
    progress(
        SetupStage::StateDirectory,
        "preparing protected state directory",
    );
    security::prepare_state_directory(&request.state_directory, &request.owner_sid)?;
    progress(
        SetupStage::CapabilityState,
        "creating and verifying protected capability-SID state",
    );
    prepare_capability_state(request)?;
    progress(SetupStage::Request, "verifying helper resources");
    let resources = resources::verify(request)?;
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

    progress(
        SetupStage::OfflineAccount,
        "provisioning dedicated sandbox accounts",
    );
    let accounts = accounts::provision(request)?;
    progress(
        SetupStage::StateDirectory,
        "staging protected helper resources and runner manifest",
    );
    let runner_manifest_sha256 = resources::stage(request, &accounts, &resources)?;
    progress(
        SetupStage::AccountRights,
        "applying offline account logon rights",
    );
    rights::apply_and_verify(&accounts.offline_sid)?;
    progress(
        SetupStage::AccountRights,
        "applying online account logon rights",
    );
    rights::apply_and_verify(&accounts.online_sid)?;
    progress(
        SetupStage::Credentials,
        "writing protected sandbox credentials",
    );
    let credential_sha256 = credentials::write_protected(request, &accounts)?;
    progress(
        SetupStage::Firewall,
        "installing and verifying firewall policy",
    );
    let firewall_policy_id =
        firewall::install_and_verify(request, &accounts.offline_sid, progress)?;
    progress(SetupStage::Wfp, "installing WFP policy");
    let wfp_provider_id = wfp::install_and_verify(
        &request.owner_sid,
        &accounts.offline_name,
        &accounts.offline_sid,
        progress,
    )?;
    progress(SetupStage::Marker, "committing verified setup marker");
    write_marker(
        request,
        accounts,
        credential_sha256,
        runner_manifest_sha256,
        firewall_policy_id,
        wfp_provider_id,
    )
}

fn write_marker(
    request: &SetupRequest,
    accounts: ProvisionedAccounts,
    credential_sha256: String,
    runner_manifest_sha256: String,
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
        runner_manifest_sha256,
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

fn prepare_capability_state(request: &SetupRequest) -> NativeSetupResult<()> {
    let path = request
        .state_directory
        .join(crate::capability_state::CAPABILITY_STATE_NAME);
    let state = match fs::read(&path) {
        Ok(bytes) => crate::capability_state::CapabilityState::decode(&bytes)
            .map_err(capability_state_model_failure)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            crate::capability_state::CapabilityState::fresh()
                .map_err(capability_state_model_failure)?
        }
        Err(error) => {
            return Err(NativeSetupFailure::new(
                SetupStage::CapabilityState,
                SetupFailureCode::CapabilityStateRead,
                error.raw_os_error().map(|code| code as u32),
                format!("failed to read capability-SID state {path:?}: {error}"),
            ));
        }
    };
    let encoded = state.encode().map_err(capability_state_model_failure)?;
    let mut file =
        security::create_protected_file(&path, &request.owner_sid).map_err(|failure| {
            NativeSetupFailure::new(
                SetupStage::CapabilityState,
                SetupFailureCode::CapabilityStateAcl,
                failure.native_code,
                failure.detail,
            )
        })?;
    file.write_all(&encoded).map_err(|error| {
        NativeSetupFailure::new(
            SetupStage::CapabilityState,
            SetupFailureCode::CapabilityStateWrite,
            error.raw_os_error().map(|code| code as u32),
            format!("failed to write capability-SID state {path:?}: {error}"),
        )
    })?;
    file.sync_all().map_err(|error| {
        NativeSetupFailure::new(
            SetupStage::CapabilityState,
            SetupFailureCode::CapabilityStateWrite,
            error.raw_os_error().map(|code| code as u32),
            format!("failed to flush capability-SID state {path:?}: {error}"),
        )
    })?;
    let lock_path = request
        .state_directory
        .join(crate::capability_state::CAPABILITY_LOCK_NAME);
    let lock =
        security::create_protected_file(&lock_path, &request.owner_sid).map_err(|failure| {
            NativeSetupFailure::new(
                SetupStage::CapabilityState,
                SetupFailureCode::CapabilityStateAcl,
                failure.native_code,
                failure.detail,
            )
        })?;
    lock.sync_all().map_err(|error| {
        NativeSetupFailure::new(
            SetupStage::CapabilityState,
            SetupFailureCode::CapabilityStateWrite,
            error.raw_os_error().map(|code| code as u32),
            format!("failed to flush capability-SID lock file {lock_path:?}: {error}"),
        )
    })
}

fn capability_state_model_failure(
    error: crate::capability_state::CapabilityStateError,
) -> NativeSetupFailure {
    let code = match error {
        crate::capability_state::CapabilityStateError::Random { .. } => {
            SetupFailureCode::CapabilityStateRandom
        }
        crate::capability_state::CapabilityStateError::Encode { .. } => {
            SetupFailureCode::CapabilityStateSerialize
        }
        crate::capability_state::CapabilityStateError::Decode { .. }
        | crate::capability_state::CapabilityStateError::Version { .. }
        | crate::capability_state::CapabilityStateError::InvalidProfileIdentity
        | crate::capability_state::CapabilityStateError::InvalidSid { .. }
        | crate::capability_state::CapabilityStateError::NonCanonicalSid
        | crate::capability_state::CapabilityStateError::ForeignAuthoritySid
        | crate::capability_state::CapabilityStateError::DuplicateSid
        | crate::capability_state::CapabilityStateError::RelativeRoot { .. }
        | crate::capability_state::CapabilityStateError::ParentTraversal { .. }
        | crate::capability_state::CapabilityStateError::DuplicateAuthority
        | crate::capability_state::CapabilityStateError::NonCanonicalOrder
        | crate::capability_state::CapabilityStateError::InvalidDacl
        | crate::capability_state::CapabilityStateError::DuplicateAclObject
        | crate::capability_state::CapabilityStateError::NonCanonicalAclOrder
        | crate::capability_state::CapabilityStateError::RedundantAclObject
        | crate::capability_state::CapabilityStateError::InvalidAclMutation
        | crate::capability_state::CapabilityStateError::PendingAclMutation { .. }
        | crate::capability_state::CapabilityStateError::MissingAclMutation
        | crate::capability_state::CapabilityStateError::AclObjectIdentityMismatch { .. }
        | crate::capability_state::CapabilityStateError::AclBeforeMismatch { .. }
        | crate::capability_state::CapabilityStateError::AclMutationDrift { .. } => {
            SetupFailureCode::CapabilityStateDecode
        }
    };
    NativeSetupFailure::new(SetupStage::CapabilityState, code, None, error.to_string())
}

fn uninstall(request: &SetupRequest) -> NativeSetupResult<()> {
    firewall::remove(&request.owner_sid)?;
    wfp::remove(&request.owner_sid)?;
    accounts::remove(request)?;
    for path in [
        request.state_directory.join("setup.json"),
        request
            .state_directory
            .join(crate::capability_state::CAPABILITY_STATE_NAME),
        request
            .state_directory
            .join(crate::capability_state::CAPABILITY_LOCK_NAME),
        request.state_directory.join("credentials.json.dpapi"),
        request
            .state_directory
            .join("bin")
            .join("cageforge-windows-setup.exe"),
        request
            .state_directory
            .join("bin")
            .join("cageforge-windows-command-runner.exe"),
        request
            .state_directory
            .join("bin")
            .join(crate::runner_manifest::RUNNER_MANIFEST_NAME),
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
