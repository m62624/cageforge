// SPDX-License-Identifier: Apache-2.0

//! Temporary host diagnostics for the Windows read-isolation investigation.
//! This queries API availability only; it neither creates a sandbox nor proves
//! enforcement. The calling regression test must still exercise Cageforge.
//!
//! Signatures: Microsoft's processmodel.h API documentation for
//! QueryProcessSecurityEnvironmentSupport and
//! IsProcessSecurityEnvironmentVersionSupported.

use windows_sys::Win32::Foundation::{FreeLibrary, GetLastError, HMODULE};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
};

struct SystemModule(HMODULE);

type QuerySupport = unsafe extern "system" fn(*mut u64) -> i32;
type QueryVersion = unsafe extern "system" fn(u32, *mut u8, *mut u32) -> i32;

#[allow(unsafe_code)]
impl Drop for SystemModule {
    fn drop(&mut self) {
        // SAFETY: this guard owns one successful LoadLibraryExW reference.
        unsafe { FreeLibrary(self.0) };
    }
}

#[allow(unsafe_code)]
pub(super) fn report() {
    let name = "processmodel.dll\0".encode_utf16().collect::<Vec<_>>();
    // SAFETY: the name is NUL-terminated. Only the trusted system directory is
    // searched; no current-directory or PATH library can supply these exports.
    let module = unsafe {
        LoadLibraryExW(
            name.as_ptr(),
            std::ptr::null_mut(),
            LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
    };
    if module.is_null() {
        eprintln!("PSEC diagnostic: system module unavailable: {}", unsafe {
            GetLastError()
        });
        return;
    }
    let module = SystemModule(module);
    // SAFETY: module remains loaded and all export names are NUL-terminated.
    let (create, close, query, version) = unsafe {
        (
            GetProcAddress(
                module.0,
                c"CreateProcessSecurityEnvironment".as_ptr().cast(),
            ),
            GetProcAddress(module.0, c"CloseProcessSecurityEnvironment".as_ptr().cast()),
            GetProcAddress(
                module.0,
                c"QueryProcessSecurityEnvironmentSupport".as_ptr().cast(),
            ),
            GetProcAddress(
                module.0,
                c"IsProcessSecurityEnvironmentVersionSupported"
                    .as_ptr()
                    .cast(),
            ),
        )
    };
    eprintln!(
        "PSEC diagnostic exports: create={}, close={}, query={}, version={}",
        create.is_some(),
        close.is_some(),
        query.is_some(),
        version.is_some()
    );
    if let Some(query) = query {
        // SAFETY: this exact system export has the processmodel.h signature.
        let query = unsafe {
            std::mem::transmute::<unsafe extern "system" fn() -> isize, QuerySupport>(query)
        };
        let mut flags = 0_u64;
        // SAFETY: flags is valid writable storage; the module is still loaded.
        let status = unsafe { query(&mut flags) };
        eprintln!("PSEC diagnostic support: HRESULT={status:#010x}, flags={flags:#018x}");
    }
    if let Some(version) = version {
        // SAFETY: BOOLEAN is one byte and DWORD is u32 in processmodel.h.
        let version = unsafe {
            std::mem::transmute::<unsafe extern "system" fn() -> isize, QueryVersion>(version)
        };
        let mut available = 0_u8;
        let mut minor = 0_u32;
        // SAFETY: both out-parameters are valid and the module remains loaded.
        let status = unsafe { version(1, &mut available, &mut minor) };
        eprintln!(
            "PSEC diagnostic version: HRESULT={status:#010x}, major=1, available={available}, minor={minor}"
        );
    }
}
