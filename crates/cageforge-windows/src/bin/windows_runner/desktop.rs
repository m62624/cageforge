// SPDX-License-Identifier: Apache-2.0

use std::mem::size_of;

use thiserror::Error;
use windows_sys::Win32::Foundation::{ERROR_INVALID_DATA, GetLastError, HLOCAL, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
    SE_WINDOW_OBJECT,
};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    SECURITY_ATTRIBUTES,
};
use windows_sys::Win32::System::StationsAndDesktops::{
    CloseDesktop, CreateDesktopW, DESKTOP_CREATEMENU, DESKTOP_CREATEWINDOW, DESKTOP_DELETE,
    DESKTOP_ENUMERATE, DESKTOP_HOOKCONTROL, DESKTOP_JOURNALPLAYBACK, DESKTOP_JOURNALRECORD,
    DESKTOP_READ_CONTROL, DESKTOP_READOBJECTS, DESKTOP_SWITCHDESKTOP, DESKTOP_WRITE_DAC,
    DESKTOP_WRITE_OWNER, DESKTOP_WRITEOBJECTS, HDESK,
};

use super::token::RestrictedPrimaryToken;

const PRIVATE_DESKTOP_ACCESS: u32 = DESKTOP_READOBJECTS
    | DESKTOP_CREATEWINDOW
    | DESKTOP_CREATEMENU
    | DESKTOP_HOOKCONTROL
    | DESKTOP_JOURNALRECORD
    | DESKTOP_JOURNALPLAYBACK
    | DESKTOP_ENUMERATE
    | DESKTOP_WRITEOBJECTS
    | DESKTOP_SWITCHDESKTOP
    | DESKTOP_DELETE
    | DESKTOP_READ_CONTROL
    | DESKTOP_WRITE_DAC
    | DESKTOP_WRITE_OWNER;

pub(super) struct PrivateDesktop {
    handle: HDESK,
    startup_name: Vec<u16>,
}

struct LocalSecurityDescriptor(PSECURITY_DESCRIPTOR);

struct LocalWideString(*mut u16);

#[derive(Debug, Error)]
pub(super) enum PrivateDesktopError {
    #[error("failed to generate a private desktop identity: {source}")]
    Random {
        #[source]
        source: getrandom::Error,
    },
    #[error("failed to parse the private desktop descriptor: Windows error {code}")]
    DescriptorParse { code: u32 },
    #[error(
        "failed to create the private desktop in the sandbox runner session: Windows error {code}"
    )]
    Create { code: u32 },
    #[error("failed to read back the private desktop descriptor: Windows error {code}")]
    DescriptorReadBack { code: u32 },
    #[error("private desktop descriptor differs after Windows read-back")]
    DescriptorMismatch,
}

#[allow(unsafe_code)]
impl Drop for PrivateDesktop {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { CloseDesktop(self.handle) };
        }
    }
}

#[allow(unsafe_code)]
impl Drop for LocalSecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { LocalFree(self.0 as HLOCAL) };
        }
    }
}

#[allow(unsafe_code)]
impl Drop for LocalWideString {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { LocalFree(self.0 as HLOCAL) };
        }
    }
}

impl PrivateDesktop {
    #[allow(unsafe_code)]
    pub(super) fn create(token: &RestrictedPrimaryToken) -> Result<Self, PrivateDesktopError> {
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).map_err(|source| PrivateDesktopError::Random { source })?;
        let nonce = random
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let name = format!("Cageforge-{nonce}");
        let name_wide = to_wide(&name);
        let sddl = format!(
            "O:{}D:P(A;;0x{PRIVATE_DESKTOP_ACCESS:08x};;;SY)(A;;0x{PRIVATE_DESKTOP_ACCESS:08x};;;BA)(A;;0x{PRIVATE_DESKTOP_ACCESS:08x};;;{})(A;;0x{PRIVATE_DESKTOP_ACCESS:08x};;;{})",
            token.user_sid(),
            token.user_sid(),
            token.logon_sid(),
        );
        let descriptor = parse_descriptor(&sddl)?;
        let security = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 0,
        };
        let handle = unsafe {
            CreateDesktopW(
                name_wide.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                PRIVATE_DESKTOP_ACCESS,
                &security,
            )
        };
        if handle.is_null() {
            return Err(PrivateDesktopError::Create {
                code: unsafe { GetLastError() },
            });
        }
        let desktop = Self {
            handle,
            startup_name: startup_desktop_name(&name),
        };
        desktop.verify_descriptor(&descriptor)?;
        Ok(desktop)
    }

    pub(super) fn startup_name(&self) -> &[u16] {
        &self.startup_name
    }

    #[allow(unsafe_code)]
    fn verify_descriptor(
        &self,
        expected: &LocalSecurityDescriptor,
    ) -> Result<(), PrivateDesktopError> {
        let mut actual = std::ptr::null_mut();
        let status = unsafe {
            GetSecurityInfo(
                self.handle,
                SE_WINDOW_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut actual,
            )
        };
        if status != 0 {
            return Err(PrivateDesktopError::DescriptorReadBack { code: status });
        }
        let actual = LocalSecurityDescriptor(actual);
        if descriptor_string(expected.0)? == descriptor_string(actual.0)? {
            Ok(())
        } else {
            Err(PrivateDesktopError::DescriptorMismatch)
        }
    }
}

impl PrivateDesktopError {
    pub(super) const fn native_code(&self) -> Option<u32> {
        match self {
            Self::DescriptorParse { code }
            | Self::Create { code }
            | Self::DescriptorReadBack { code } => Some(*code),
            Self::Random { .. } | Self::DescriptorMismatch => None,
        }
    }
}

#[allow(unsafe_code)]
fn parse_descriptor(value: &str) -> Result<LocalSecurityDescriptor, PrivateDesktopError> {
    let wide = to_wide(value);
    let mut descriptor = std::ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    } == 0
    {
        Err(PrivateDesktopError::DescriptorParse {
            code: unsafe { GetLastError() },
        })
    } else {
        Ok(LocalSecurityDescriptor(descriptor))
    }
}

#[allow(unsafe_code)]
fn descriptor_string(descriptor: PSECURITY_DESCRIPTOR) -> Result<String, PrivateDesktopError> {
    let mut value = std::ptr::null_mut();
    let mut value_length = 0u32;
    if unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            SDDL_REVISION_1,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut value,
            &mut value_length,
        )
    } == 0
    {
        return Err(PrivateDesktopError::DescriptorReadBack {
            code: unsafe { GetLastError() },
        });
    }
    let value = LocalWideString(value);
    wide_string(value.0, value_length).ok_or(PrivateDesktopError::DescriptorReadBack {
        code: ERROR_INVALID_DATA,
    })
}

#[allow(unsafe_code)]
fn wide_string(value: *const u16, length: u32) -> Option<String> {
    if value.is_null() || length == 0 {
        return None;
    }
    let units = unsafe { std::slice::from_raw_parts(value, length as usize) };
    let units = units.strip_suffix(&[0]).unwrap_or(units);
    Some(String::from_utf16_lossy(units))
}

fn to_wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn startup_desktop_name(name: &str) -> Vec<u16> {
    to_wide(&format!("Winsta0\\{name}"))
}

#[cfg(test)]
mod tests {
    use super::startup_desktop_name;

    #[test]
    fn startup_desktop_name_is_a_nul_terminated_windows_string() {
        let name = startup_desktop_name("Cageforge-test");

        assert_eq!(
            name,
            "Winsta0\\Cageforge-test"
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect::<Vec<_>>()
        );
    }
}
