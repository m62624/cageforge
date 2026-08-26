// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::Path;

use serde::Deserialize;
use windows_sys::Win32::Foundation::{GetLastError, HLOCAL, LocalFree};
use windows_sys::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptUnprotectData,
};

use crate::error::WindowsSetupVerificationError;
use crate::setup::WindowsSetupDetails;

const CREDENTIALS_VERSION: u32 = 1;

#[derive(Deserialize)]
struct ProtectedCredentials {
    version: u32,
    offline_name: String,
    offline_password: Vec<u8>,
    online_name: String,
    online_password: Vec<u8>,
}

pub(super) fn verify(
    details: &WindowsSetupDetails,
    path: &Path,
) -> Result<(), WindowsSetupVerificationError> {
    let encoded =
        fs::read(path).map_err(|source| WindowsSetupVerificationError::CredentialRead {
            path: path.to_path_buf(),
            source,
        })?;
    let expected_digest = super::hex_digest(&encoded);
    if !expected_digest.eq_ignore_ascii_case(details.credential_sha256()) {
        return Err(WindowsSetupVerificationError::DigestMismatch {
            component: "credential record",
            expected: details.credential_sha256().to_string(),
            actual: expected_digest,
        });
    }
    let credentials: ProtectedCredentials = serde_json::from_slice(&encoded).map_err(|source| {
        WindowsSetupVerificationError::CredentialDecode {
            path: path.to_path_buf(),
            source,
        }
    })?;
    if credentials.version != CREDENTIALS_VERSION
        || credentials.offline_name != details.accounts().offline_name()
        || credentials.online_name != details.accounts().online_name()
    {
        return Err(WindowsSetupVerificationError::CredentialIdentityMismatch);
    }
    let offline = decrypt("offline", &credentials.offline_password)?;
    let online = decrypt("online", &credentials.online_password)?;
    if offline.is_empty() || online.is_empty() || offline == online {
        return Err(WindowsSetupVerificationError::CredentialIdentityMismatch);
    }
    Ok(())
}

#[allow(unsafe_code)]
fn decrypt(component: &'static str, data: &[u8]) -> Result<Vec<u8>, WindowsSetupVerificationError> {
    let input_length = u32::try_from(data.len())
        .map_err(|_| WindowsSetupVerificationError::CredentialIdentityMismatch)?;
    let input = CRYPT_INTEGER_BLOB {
        cbData: input_length,
        pbData: data.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    if unsafe {
        CryptUnprotectData(
            &input,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    } == 0
    {
        return Err(WindowsSetupVerificationError::CredentialDecrypt {
            component,
            code: unsafe { GetLastError() },
        });
    }
    let decrypted =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) }.to_vec();
    unsafe {
        LocalFree(output.pbData as HLOCAL);
    }
    Ok(decrypted)
}
