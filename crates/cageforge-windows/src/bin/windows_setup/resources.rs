// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::io::Write;

use sha2::{Digest, Sha256};

use crate::setup_protocol::{SetupFailureCode, SetupRequest, SetupStage};

use super::{NativeSetupFailure, NativeSetupResult, security};

const RUNNER_NAME: &str = "cageforge-windows-command-runner.exe";
const SETUP_HELPER_NAME: &str = "cageforge-windows-setup.exe";

pub(super) fn verify_and_stage(request: &SetupRequest) -> NativeSetupResult<()> {
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

    let bin_directory = request.state_directory.join("bin");
    security::prepare_state_directory(&bin_directory, &request.owner_sid).map_err(|failure| {
        NativeSetupFailure::new(
            SetupStage::StateDirectory,
            SetupFailureCode::CommandRunnerInstall,
            failure.native_code,
            failure.detail,
        )
    })?;
    stage_resource(
        &bin_directory.join(SETUP_HELPER_NAME),
        &helper_bytes,
        request,
    )?;
    stage_resource(&bin_directory.join(RUNNER_NAME), &runner_bytes, request)
}

fn stage_resource(
    destination: &std::path::Path,
    bytes: &[u8],
    request: &SetupRequest,
) -> NativeSetupResult<()> {
    let mut file =
        security::create_protected_file(destination, &request.owner_sid).map_err(|failure| {
            NativeSetupFailure::new(
                SetupStage::StateDirectory,
                SetupFailureCode::CommandRunnerInstall,
                failure.native_code,
                failure.detail,
            )
        })?;
    file.write_all(bytes).map_err(|error| {
        NativeSetupFailure::new(
            SetupStage::StateDirectory,
            SetupFailureCode::CommandRunnerInstall,
            error.raw_os_error().map(|code| code as u32),
            format!("failed to stage protected Windows helper {destination:?}: {error}"),
        )
    })?;
    file.sync_all().map_err(|error| {
        NativeSetupFailure::new(
            SetupStage::StateDirectory,
            SetupFailureCode::CommandRunnerInstall,
            error.raw_os_error().map(|code| code as u32),
            format!("failed to flush protected Windows helper {destination:?}: {error}"),
        )
    })
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
