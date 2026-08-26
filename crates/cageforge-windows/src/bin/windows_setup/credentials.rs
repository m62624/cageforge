// SPDX-License-Identifier: Apache-2.0

use std::io::Write;

use sha2::{Digest, Sha256};
use windows_sys::Win32::Foundation::{GetLastError, HLOCAL, LocalFree};
use windows_sys::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData,
};

use serde::Serialize;

use crate::setup_protocol::{SetupFailureCode, SetupRequest, SetupStage};

use super::{NativeSetupFailure, NativeSetupResult, ProvisionedAccounts, security};

const CREDENTIALS_VERSION: u32 = 1;
const CREDENTIALS_NAME: &str = "credentials.json.dpapi";

#[derive(Serialize)]
struct ProtectedCredentials {
    version: u32,
    offline_name: String,
    offline_password: Vec<u8>,
    online_name: String,
    online_password: Vec<u8>,
}

pub(super) fn write_protected(
    request: &SetupRequest,
    accounts: &ProvisionedAccounts,
) -> NativeSetupResult<String> {
    let credentials = ProtectedCredentials {
        version: CREDENTIALS_VERSION,
        offline_name: accounts.offline_name.clone(),
        offline_password: protect(accounts.offline_password.as_bytes())?,
        online_name: accounts.online_name.clone(),
        online_password: protect(accounts.online_password.as_bytes())?,
    };
    let encoded = serde_json::to_vec(&credentials).map_err(|error| {
        NativeSetupFailure::new(
            SetupStage::Credentials,
            SetupFailureCode::CredentialSerialize,
            None,
            format!("failed to encode protected sandbox credentials: {error}"),
        )
    })?;
    let path = request.state_directory.join(CREDENTIALS_NAME);
    let mut file =
        security::create_protected_file(&path, &request.owner_sid).map_err(|failure| {
            NativeSetupFailure::new(
                SetupStage::Credentials,
                SetupFailureCode::CredentialAcl,
                failure.native_code,
                failure.detail,
            )
        })?;
    file.write_all(&encoded).map_err(|error| {
        NativeSetupFailure::new(
            SetupStage::Credentials,
            SetupFailureCode::CredentialWrite,
            error.raw_os_error().map(|code| code as u32),
            format!("failed to write protected credentials {path:?}: {error}"),
        )
    })?;
    file.sync_all().map_err(|error| {
        NativeSetupFailure::new(
            SetupStage::Credentials,
            SetupFailureCode::CredentialWrite,
            error.raw_os_error().map(|code| code as u32),
            format!("failed to flush protected credentials {path:?}: {error}"),
        )
    })?;
    Ok(hex_digest(&encoded))
}

#[allow(unsafe_code)]
fn protect(data: &[u8]) -> NativeSetupResult<Vec<u8>> {
    let input_length = u32::try_from(data.len()).map_err(|_| {
        NativeSetupFailure::new(
            SetupStage::Credentials,
            SetupFailureCode::DpapiProtect,
            None,
            "sandbox credential exceeds DPAPI input limits",
        )
    })?;
    let input = CRYPT_INTEGER_BLOB {
        cbData: input_length,
        pbData: data.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    let protected = unsafe {
        CryptProtectData(
            &input,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE,
            &mut output,
        )
    };
    if protected == 0 {
        return Err(NativeSetupFailure::new(
            SetupStage::Credentials,
            SetupFailureCode::DpapiProtect,
            Some(unsafe { GetLastError() }),
            "Windows DPAPI could not protect a sandbox credential",
        ));
    }
    let bytes =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) }.to_vec();
    unsafe {
        LocalFree(output.pbData as HLOCAL);
    }
    Ok(bytes)
}

fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
