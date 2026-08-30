// SPDX-License-Identifier: Apache-2.0

//! Parent-owned launch-unique desktop with an isolated sandbox grant.

use std::mem::size_of;

use thiserror::Error;
use windows_sys::Win32::Foundation::{GetLastError, HLOCAL, LocalFree};
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

pub(crate) struct ParentDesktop {
    handle: HDESK,
    startup_name: Vec<u16>,
}

struct LocalSecurityDescriptor(PSECURITY_DESCRIPTOR);

struct LocalWideString(*mut u16);

#[derive(Debug, Error)]
pub(crate) enum ParentDesktopError {
    #[error("failed to generate a private desktop identity: {source}")]
    Random {
        #[source]
        source: getrandom::Error,
    },
    #[error("failed to parse the private desktop descriptor: Windows error {code}")]
    DescriptorParse { code: u32 },
    #[error("failed to create the private desktop: Windows error {code}")]
    Create { code: u32 },
    #[error("failed to read back the private desktop descriptor: Windows error {code}")]
    DescriptorReadBack { code: u32 },
    #[error("private desktop descriptor differs after Windows read-back")]
    DescriptorMismatch,
}

#[allow(unsafe_code)]
impl Drop for ParentDesktop {
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

impl ParentDesktop {
    #[allow(unsafe_code)]
    pub(crate) fn create(owner_sid: &str, logon_sid: &str) -> Result<Self, ParentDesktopError> {
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).map_err(|source| ParentDesktopError::Random { source })?;
        let nonce = random
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let name = format!("Cageforge-{nonce}");
        let name_wide = crate::win::to_wide(&name);
        let sddl = format!(
            "O:{owner_sid}D:P(A;;0x{PRIVATE_DESKTOP_ACCESS:08x};;;SY)(A;;0x{PRIVATE_DESKTOP_ACCESS:08x};;;BA)(A;;0x{PRIVATE_DESKTOP_ACCESS:08x};;;{owner_sid})(A;;0x{PRIVATE_DESKTOP_ACCESS:08x};;;{logon_sid})"
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
            return Err(ParentDesktopError::Create {
                code: unsafe { GetLastError() },
            });
        }
        let desktop = Self {
            handle,
            startup_name: format!("Winsta0\\{name}").encode_utf16().collect(),
        };
        desktop.verify_descriptor(&descriptor)?;
        Ok(desktop)
    }

    pub(crate) fn startup_name(&self) -> &[u16] {
        &self.startup_name
    }

    #[allow(unsafe_code)]
    fn verify_descriptor(
        &self,
        expected: &LocalSecurityDescriptor,
    ) -> Result<(), ParentDesktopError> {
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
            return Err(ParentDesktopError::DescriptorReadBack { code: status });
        }
        let actual = LocalSecurityDescriptor(actual);
        if descriptor_string(expected.0)? == descriptor_string(actual.0)? {
            Ok(())
        } else {
            Err(ParentDesktopError::DescriptorMismatch)
        }
    }
}

#[allow(unsafe_code)]
fn parse_descriptor(sddl: &str) -> Result<LocalSecurityDescriptor, ParentDesktopError> {
    let sddl = crate::win::to_wide(sddl);
    let mut descriptor = std::ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    } == 0
    {
        Err(ParentDesktopError::DescriptorParse {
            code: unsafe { GetLastError() },
        })
    } else {
        Ok(LocalSecurityDescriptor(descriptor))
    }
}

#[allow(unsafe_code)]
fn descriptor_string(descriptor: PSECURITY_DESCRIPTOR) -> Result<String, ParentDesktopError> {
    let mut value = std::ptr::null_mut();
    if unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            SDDL_REVISION_1,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut value,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(ParentDesktopError::DescriptorReadBack {
            code: unsafe { GetLastError() },
        });
    }
    let value = LocalWideString(value);
    Ok(wide_string(value.0))
}

#[allow(unsafe_code)]
fn wide_string(value: *const u16) -> String {
    unsafe {
        let mut length = 0;
        while *value.add(length) != 0 {
            length += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(value, length))
    }
}
