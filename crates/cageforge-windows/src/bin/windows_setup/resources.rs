// SPDX-License-Identifier: Apache-2.0

use sha2::{Digest, Sha256};
use std::fs;

use crate::runner_manifest::{RUNNER_MANIFEST_NAME, RUNNER_MANIFEST_VERSION, RunnerManifest};
use crate::setup_protocol::{SetupFailureCode, SetupRequest, SetupStage};

use super::{NativeSetupFailure, NativeSetupResult, ProvisionedAccounts, security};

const RUNNER_NAME: &str = "cageforge-windows-command-runner.exe";
const SETUP_HELPER_NAME: &str = "cageforge-windows-setup.exe";

pub(super) struct VerifiedResources {
    helper_bytes: Vec<u8>,
    runner_bytes: Vec<u8>,
}

pub(super) fn verify(request: &SetupRequest) -> NativeSetupResult<VerifiedResources> {
    let helper = std::env::current_exe().map_err(|error| {
        NativeSetupFailure::new(
            SetupStage::Request,
            SetupFailureCode::HelperDigestMismatch,
            error.raw_os_error().map(|code| code as u32),
            format!("failed to resolve the running setup helper: {error}"),
        )
    })?;
    let helper_bytes = fs::read(&helper).map_err(|error| {
        NativeSetupFailure::new(
            SetupStage::Request,
            SetupFailureCode::HelperDigestMismatch,
            error.raw_os_error().map(|code| code as u32),
            format!("failed to read the running setup helper {helper:?}: {error}"),
        )
    })?;
    verify_digest(
        &helper_bytes,
        &request.setup_helper_sha256,
        SetupFailureCode::HelperDigestMismatch,
        "setup helper",
    )?;

    let runner_bytes = fs::read(&request.command_runner_source).map_err(|error| {
        NativeSetupFailure::new(
            SetupStage::Request,
            SetupFailureCode::CommandRunnerRead,
            error.raw_os_error().map(|code| code as u32),
            format!(
                "failed to read command runner {:?}: {error}",
                request.command_runner_source
            ),
        )
    })?;
    verify_digest(
        &runner_bytes,
        &request.command_runner_sha256,
        SetupFailureCode::CommandRunnerDigestMismatch,
        "command runner",
    )?;

    Ok(VerifiedResources {
        helper_bytes,
        runner_bytes,
    })
}

pub(super) fn stage(
    request: &SetupRequest,
    accounts: &ProvisionedAccounts,
    resources: &VerifiedResources,
) -> NativeSetupResult<String> {
    let bin_directory = request.state_directory.join("bin");
    security::prepare_runner_directory(&bin_directory, &request.owner_sid, &accounts.group_sid)
        .map_err(resource_install_failure)?;
    stage_private_resource(
        &bin_directory.join(SETUP_HELPER_NAME),
        &resources.helper_bytes,
        request,
    )?;
    stage_runner_resource(
        &bin_directory.join(RUNNER_NAME),
        &resources.runner_bytes,
        request,
        &accounts.group_sid,
    )?;
    write_runner_manifest(request, accounts, &bin_directory)
}

fn stage_private_resource(
    destination: &std::path::Path,
    bytes: &[u8],
    request: &SetupRequest,
) -> NativeSetupResult<()> {
    security::replace_owner_file(
        destination,
        &request.owner_sid,
        bytes,
        security::ProtectedFileWriteContext::new(
            SetupStage::StateDirectory,
            SetupFailureCode::CommandRunnerInstall,
            SetupFailureCode::CommandRunnerInstall,
            "Windows setup helper",
        ),
    )
}

fn stage_runner_resource(
    destination: &std::path::Path,
    bytes: &[u8],
    request: &SetupRequest,
    group_sid: &str,
) -> NativeSetupResult<()> {
    security::replace_runner_executable(
        destination,
        &request.owner_sid,
        group_sid,
        bytes,
        security::ProtectedFileWriteContext::new(
            SetupStage::StateDirectory,
            SetupFailureCode::CommandRunnerInstall,
            SetupFailureCode::CommandRunnerInstall,
            "Windows command runner",
        ),
    )
}

fn write_runner_manifest(
    request: &SetupRequest,
    accounts: &ProvisionedAccounts,
    bin_directory: &std::path::Path,
) -> NativeSetupResult<String> {
    let manifest = RunnerManifest {
        version: RUNNER_MANIFEST_VERSION,
        owner_sid: request.owner_sid.clone(),
        group_name: accounts.group_name.clone(),
        group_sid: accounts.group_sid.clone(),
        offline_name: accounts.offline_name.clone(),
        offline_sid: accounts.offline_sid.clone(),
        online_name: accounts.online_name.clone(),
        online_sid: accounts.online_sid.clone(),
        command_runner_sha256: request.command_runner_sha256.clone(),
    };
    let encoded = serde_json::to_vec(&manifest).map_err(|error| {
        NativeSetupFailure::new(
            SetupStage::StateDirectory,
            SetupFailureCode::CommandRunnerInstall,
            None,
            format!("failed to encode the protected command-runner manifest: {error}"),
        )
    })?;
    let path = bin_directory.join(RUNNER_MANIFEST_NAME);
    security::replace_runner_manifest(
        &path,
        &request.owner_sid,
        &accounts.group_sid,
        &encoded,
        security::ProtectedFileWriteContext::new(
            SetupStage::StateDirectory,
            SetupFailureCode::CommandRunnerInstall,
            SetupFailureCode::CommandRunnerInstall,
            "command-runner manifest",
        ),
    )?;
    Ok(hex_digest(&encoded))
}

fn verify_digest(
    bytes: &[u8],
    expected: &str,
    code: SetupFailureCode,
    label: &str,
) -> NativeSetupResult<()> {
    let actual = Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if actual.eq_ignore_ascii_case(expected) {
        Ok(())
    } else {
        Err(NativeSetupFailure::new(
            SetupStage::Request,
            code,
            None,
            format!("{label} SHA-256 mismatch: expected {expected}, found {actual}"),
        ))
    }
}

fn resource_install_failure(failure: NativeSetupFailure) -> NativeSetupFailure {
    NativeSetupFailure::new(
        SetupStage::StateDirectory,
        SetupFailureCode::CommandRunnerInstall,
        failure.native_code,
        failure.detail,
    )
}

fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
