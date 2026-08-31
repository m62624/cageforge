// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io::Read;
use std::path::Path;

use serde::Deserialize;
use windows_sys::Win32::Foundation::{GetLastError, HLOCAL, LocalFree};
use windows_sys::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptUnprotectData,
};
use zeroize::{Zeroize, Zeroizing};

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

pub(crate) struct SandboxCredentials {
    offline: AccountCredential,
    online: AccountCredential,
}

pub(crate) struct AccountCredential {
    name: String,
    password: Zeroizing<Vec<u16>>,
}

impl SandboxCredentials {
    pub(crate) const fn offline(&self) -> &AccountCredential {
        &self.offline
    }

    pub(crate) const fn online(&self) -> &AccountCredential {
        &self.online
    }
}

impl AccountCredential {
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn password_wide(&self) -> &[u16] {
        &self.password
    }
}

pub(super) fn verify(
    details: &WindowsSetupDetails,
    path: &Path,
    file: &mut File,
) -> Result<(), WindowsSetupVerificationError> {
    read(details, path, file).map(|_| ())
}

pub(super) fn read(
    details: &WindowsSetupDetails,
    path: &Path,
    file: &mut File,
) -> Result<SandboxCredentials, WindowsSetupVerificationError> {
    let mut encoded = Vec::new();
    file.read_to_end(&mut encoded).map_err(|source| {
        WindowsSetupVerificationError::CredentialRead {
            path: path.to_path_buf(),
            source,
        }
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
    if credentials.version != CREDENTIALS_VERSION {
        return Err(WindowsSetupVerificationError::CredentialIdentityMismatch);
    }
    let offline = decode_password(
        "offline",
        decrypt("offline", &credentials.offline_password)?,
    )?;
    let online = decode_password("online", decrypt("online", &credentials.online_password)?)?;
    let credentials = SandboxCredentials {
        offline: AccountCredential {
            name: credentials.offline_name,
            password: offline,
        },
        online: AccountCredential {
            name: credentials.online_name,
            password: online,
        },
    };
    if credentials.offline().name() != details.accounts().offline_name()
        || credentials.online().name() != details.accounts().online_name()
        || credentials.offline().password_wide().len() < 2
        || credentials.online().password_wide().len() < 2
        || credentials.offline().password_wide() == credentials.online().password_wide()
    {
        return Err(WindowsSetupVerificationError::CredentialIdentityMismatch);
    }
    Ok(credentials)
}

fn decode_password(
    component: &'static str,
    mut decrypted: Vec<u8>,
) -> Result<Zeroizing<Vec<u16>>, WindowsSetupVerificationError> {
    let text = match std::str::from_utf8(&decrypted) {
        Ok(text) if !text.is_empty() && !text.contains('\0') => text,
        Ok(_) | Err(_) => {
            decrypted.zeroize();
            return Err(WindowsSetupVerificationError::CredentialEncoding { component });
        }
    };
    let mut wide = text.encode_utf16().collect::<Vec<_>>();
    wide.push(0);
    decrypted.zeroize();
    Ok(Zeroizing::new(wide))
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
