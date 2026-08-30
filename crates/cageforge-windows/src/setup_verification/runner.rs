// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::error::WindowsSetupVerificationError;
use crate::runner_manifest::{RUNNER_MANIFEST_VERSION, RunnerManifest};
use crate::setup::WindowsSetupDetails;

pub(super) fn verify(
    details: &WindowsSetupDetails,
    path: &Path,
    file: &mut File,
) -> Result<(), WindowsSetupVerificationError> {
    let mut encoded = Vec::new();
    file.read_to_end(&mut encoded).map_err(|source| {
        WindowsSetupVerificationError::RunnerManifestRead {
            path: path.to_path_buf(),
            source,
        }
    })?;
    let actual_digest = super::hex_digest(&encoded);
    if !actual_digest.eq_ignore_ascii_case(details.runner_manifest_sha256()) {
        return Err(WindowsSetupVerificationError::DigestMismatch {
            component: "command-runner manifest",
            expected: details.runner_manifest_sha256().to_string(),
            actual: actual_digest,
        });
    }
    let manifest: RunnerManifest = serde_json::from_slice(&encoded).map_err(|source| {
        WindowsSetupVerificationError::RunnerManifestDecode {
            path: path.to_path_buf(),
            source,
        }
    })?;
    verify_field(
        "version",
        &RUNNER_MANIFEST_VERSION.to_string(),
        &manifest.version.to_string(),
    )?;
    verify_field("owner_sid", details.owner_sid(), &manifest.owner_sid)?;
    verify_field(
        "group_name",
        details.accounts().group_name(),
        &manifest.group_name,
    )?;
    verify_field(
        "group_sid",
        details.accounts().group_sid(),
        &manifest.group_sid,
    )?;
    verify_field(
        "offline_name",
        details.accounts().offline_name(),
        &manifest.offline_name,
    )?;
    verify_field(
        "offline_sid",
        details.accounts().offline_sid(),
        &manifest.offline_sid,
    )?;
    verify_field(
        "online_name",
        details.accounts().online_name(),
        &manifest.online_name,
    )?;
    verify_field(
        "online_sid",
        details.accounts().online_sid(),
        &manifest.online_sid,
    )?;
    verify_field(
        "command_runner_sha256",
        details.command_runner_sha256(),
        &manifest.command_runner_sha256,
    )
}

fn verify_field(
    field: &'static str,
    expected: &str,
    actual: &str,
) -> Result<(), WindowsSetupVerificationError> {
    if expected.eq_ignore_ascii_case(actual) {
        Ok(())
    } else {
        Err(WindowsSetupVerificationError::RunnerManifestFieldMismatch {
            field,
            expected: expected.to_string(),
            actual: actual.to_string(),
        })
    }
}
