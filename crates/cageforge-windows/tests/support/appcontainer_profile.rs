// SPDX-License-Identifier: Apache-2.0

use std::ffi::c_void;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Security::FreeSid;
use windows_sys::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeleteAppContainerProfile,
};

pub(super) struct Profile {
    name: Vec<u16>,
    pub(super) sid: *mut c_void,
    removed: bool,
}

#[allow(unsafe_code)]
impl Profile {
    pub(super) fn new() -> Self {
        let mut entropy = [0_u8; 16];
        getrandom::fill(&mut entropy).expect("profile identity entropy");
        let suffix: String = entropy.iter().map(|byte| format!("{byte:02x}")).collect();
        let name = format!("CageforgeProbe.{suffix}")
            .encode_utf16()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let mut sid = null_mut();
        // All strings are owned NUL-terminated buffers; no capabilities granted.
        let status = unsafe {
            CreateAppContainerProfile(
                name.as_ptr(),
                name.as_ptr(),
                name.as_ptr(),
                null(),
                0,
                &mut sid,
            )
        };
        assert_eq!(status, 0, "CreateAppContainerProfile: {status:#x}");
        assert!(!sid.is_null());
        Self {
            name,
            sid,
            removed: false,
        }
    }

    pub(super) fn remove(&mut self) {
        let status = unsafe { DeleteAppContainerProfile(self.name.as_ptr()) };
        assert_eq!(status, 0, "DeleteAppContainerProfile: {status:#x}");
        self.removed = true;
    }
}

#[allow(unsafe_code)]
impl Drop for Profile {
    fn drop(&mut self) {
        unsafe {
            if !self.removed {
                DeleteAppContainerProfile(self.name.as_ptr());
            }
            FreeSid(self.sid);
        }
    }
}
