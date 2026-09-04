// SPDX-License-Identifier: Apache-2.0

//! Machine-wide owner binding for setup objects shared by all runtime instances.

#![allow(unsafe_code)]

use std::ffi::{OsStr, OsString};
use std::mem::size_of;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;

use cageforge_path::paths_equal;
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_SUCCESS,
    GetLastError, HANDLE, SetLastError, WAIT_ABANDONED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE, REG_OPTION_NON_VOLATILE, REG_SZ, RegCloseKey,
    RegCreateKeyExW, RegDeleteValueW, RegQueryValueExW, RegSetValueExW,
};
use windows_sys::Win32::System::Threading::{CreateMutexW, ReleaseMutex, WaitForSingleObject};

use crate::owner_identity::owner_key;
use crate::setup_protocol::{SetupFailureCode, SetupRequest, SetupStage};

use super::{NativeSetupFailure, NativeSetupResult};

const REGISTRY_SUBKEY: &str = r"SOFTWARE\Cageforge\WindowsSandbox\Owners";
const STATE_DIRECTORY_VALUE: &str = "StateDirectory";
const MUTEX_PREFIX: &str = r"Global\Cageforge.WindowsSandbox.Setup.";
const MAX_STATE_DIRECTORY_UNITS: usize = 32_768;

pub(super) struct OwnerSetupLease {
    mutex: HANDLE,
    key: HKEY,
}

impl Drop for OwnerSetupLease {
    fn drop(&mut self) {
        unsafe {
            RegCloseKey(self.key);
            ReleaseMutex(self.mutex);
            CloseHandle(self.mutex);
        }
    }
}

impl OwnerSetupLease {
    pub(super) fn clear(&self) -> NativeSetupResult<()> {
        let value = wide(STATE_DIRECTORY_VALUE);
        let status = unsafe { RegDeleteValueW(self.key, value.as_ptr()) };
        if status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND {
            Ok(())
        } else {
            Err(registry_failure(
                SetupFailureCode::SetupRegistryWrite,
                format!("failed to clear the owner setup binding: Windows error {status}"),
            ))
        }
    }
}

pub(super) fn claim(request: &SetupRequest) -> NativeSetupResult<OwnerSetupLease> {
    let mutex = acquire_mutex(&request.owner_sid)?;
    let key = open_registry_key(&request.owner_sid, &mutex)?;
    let lease = OwnerSetupLease { mutex, key };
    match read_state_directory(lease.key)? {
        Some(existing) if !paths_equal(&existing, &request.state_directory) => {
            Err(NativeSetupFailure::new(
                SetupStage::StateDirectory,
                SetupFailureCode::OwnerSetupConflict,
                None,
                format!(
                    "owner setup is bound to {existing:?}; requested {requested:?}",
                    requested = request.state_directory
                ),
            ))
        }
        Some(_) => Ok(lease),
        None => {
            write_state_directory(lease.key, &request.state_directory)?;
            Ok(lease)
        }
    }
}

fn acquire_mutex(owner_sid: &str) -> NativeSetupResult<HANDLE> {
    let name = wide(format!("{MUTEX_PREFIX}{}", owner_key(owner_sid)));
    unsafe { SetLastError(ERROR_SUCCESS) };
    let mutex = unsafe { CreateMutexW(std::ptr::null(), 1, name.as_ptr()) };
    if mutex.is_null() {
        return Err(registry_failure(
            SetupFailureCode::SetupRegistryRead,
            format!(
                "failed to create the owner setup lifecycle mutex: Windows error {}",
                unsafe { GetLastError() }
            ),
        ));
    }
    let already_exists = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
    if already_exists {
        let result = unsafe { WaitForSingleObject(mutex, 0) };
        if result != WAIT_OBJECT_0 && result != WAIT_ABANDONED {
            unsafe { CloseHandle(mutex) };
            return Err(NativeSetupFailure::new(
                SetupStage::StateDirectory,
                SetupFailureCode::SetupLifecycleActive,
                (result == WAIT_TIMEOUT).then_some(WAIT_TIMEOUT),
                "another Windows setup lifecycle is active for this user",
            ));
        }
    }
    Ok(mutex)
}

fn open_registry_key(owner_sid: &str, mutex: &HANDLE) -> NativeSetupResult<HKEY> {
    let subkey = wide(format!(r"{REGISTRY_SUBKEY}\{}", owner_key(owner_sid)));
    let mut key = std::ptr::null_mut();
    let mut _disposition = 0u32;
    let status = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            subkey.as_ptr(),
            0,
            std::ptr::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_READ | KEY_WRITE,
            std::ptr::null(),
            &mut key,
            &mut _disposition,
        )
    };
    if status != ERROR_SUCCESS || key.is_null() {
        unsafe { ReleaseMutex(*mutex) };
        unsafe { CloseHandle(*mutex) };
        return Err(registry_failure(
            SetupFailureCode::SetupRegistryRead,
            format!("failed to open the owner setup registry: Windows error {status}"),
        ));
    }
    Ok(key)
}

fn read_state_directory(key: HKEY) -> NativeSetupResult<Option<PathBuf>> {
    let value = wide(STATE_DIRECTORY_VALUE);
    let mut kind = 0u32;
    let mut bytes = 0u32;
    let status = unsafe {
        RegQueryValueExW(
            key,
            value.as_ptr(),
            std::ptr::null(),
            &mut kind,
            std::ptr::null_mut(),
            &mut bytes,
        )
    };
    if status == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    if status != ERROR_SUCCESS && status != ERROR_MORE_DATA {
        return Err(registry_failure(
            SetupFailureCode::SetupRegistryRead,
            format!("failed to query the owner setup binding size: Windows error {status}"),
        ));
    }
    if kind != REG_SZ || bytes == 0 || !(bytes as usize).is_multiple_of(size_of::<u16>()) {
        return Err(registry_failure(
            SetupFailureCode::SetupRegistryRead,
            "owner setup binding has an invalid registry value type or size",
        ));
    }
    let units = bytes as usize / size_of::<u16>();
    if units > MAX_STATE_DIRECTORY_UNITS {
        return Err(registry_failure(
            SetupFailureCode::SetupRegistryRead,
            "owner setup binding exceeds the supported path bound",
        ));
    }
    let mut data = vec![0u16; units];
    let mut data_bytes = bytes;
    let status = unsafe {
        RegQueryValueExW(
            key,
            value.as_ptr(),
            std::ptr::null(),
            &mut kind,
            data.as_mut_ptr().cast(),
            &mut data_bytes,
        )
    };
    if status != ERROR_SUCCESS || kind != REG_SZ {
        return Err(registry_failure(
            SetupFailureCode::SetupRegistryRead,
            format!("failed to read the owner setup binding: Windows error {status}"),
        ));
    }
    let length = data
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(data.len());
    if length == 0 {
        return Err(registry_failure(
            SetupFailureCode::SetupRegistryRead,
            "owner setup binding is empty",
        ));
    }
    Ok(Some(PathBuf::from(OsString::from_wide(&data[..length]))))
}

fn write_state_directory(key: HKEY, path: &std::path::Path) -> NativeSetupResult<()> {
    let value = wide(STATE_DIRECTORY_VALUE);
    let data = wide(path.as_os_str());
    if data.len() > MAX_STATE_DIRECTORY_UNITS {
        return Err(registry_failure(
            SetupFailureCode::SetupRegistryWrite,
            "requested state directory exceeds the supported path bound",
        ));
    }
    let status = unsafe {
        RegSetValueExW(
            key,
            value.as_ptr(),
            0,
            REG_SZ,
            data.as_ptr().cast(),
            (data.len() * size_of::<u16>()) as u32,
        )
    };
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(registry_failure(
            SetupFailureCode::SetupRegistryWrite,
            format!("failed to claim the owner setup binding: Windows error {status}"),
        ))
    }
}

fn registry_failure(code: SetupFailureCode, detail: impl Into<String>) -> NativeSetupFailure {
    NativeSetupFailure::new(SetupStage::StateDirectory, code, None, detail)
}

fn wide(value: impl AsRef<OsStr>) -> Vec<u16> {
    value
        .as_ref()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}
