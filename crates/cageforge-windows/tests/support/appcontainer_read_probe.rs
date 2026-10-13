// SPDX-License-Identifier: Apache-2.0

//! Temporary experiment for PR #56, not a production backend or a parity test.
//! Independently authored using the documented Win32 AppContainer APIs:
//! https://learn.microsoft.com/windows/win32/secauthz/implementing-an-appcontainer
//! Two distinct package identities receive disjoint file grants. Both processes
//! must start, read their own file, and fail to read/write the unapproved file.

use std::ffi::{OsStr, c_void};
use std::fs;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{
    GetLastError, HANDLE_FLAG_INHERIT, LocalFree, SetHandleInformation, WAIT_OBJECT_0,
};
use windows_sys::Win32::Security::Authorization::{
    EXPLICIT_ACCESS_W, GRANT_ACCESS, GetNamedSecurityInfoW, SE_FILE_OBJECT, SetEntriesInAclW,
    SetNamedSecurityInfoW, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
};
use windows_sys::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeleteAppContainerProfile,
};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, FreeSid, GetTokenInformation, SECURITY_CAPABILITIES,
    TOKEN_DUPLICATE, TOKEN_QUERY, TokenIsAppContainer,
};
use windows_sys::Win32::Storage::FileSystem::{FILE_GENERIC_EXECUTE, FILE_GENERIC_READ};
use windows_sys::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW,
    DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess,
    GetExitCodeProcess, InitializeProcThreadAttributeList, OpenProcessToken,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
    PROCESS_INFORMATION, ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOEXW, TerminateProcess,
    UpdateProcThreadAttribute, WaitForSingleObject,
};

struct Profile {
    name: Vec<u16>,
    sid: *mut c_void,
    removed: bool,
}

struct Child {
    process: OwnedHandle,
    thread: OwnedHandle,
    output: PathBuf,
}

struct Attributes(Vec<usize>);
struct LocalAllocation(*mut c_void);
struct Environment(*mut c_void);

#[allow(unsafe_code)]
impl Profile {
    fn new() -> Self {
        let mut entropy = [0_u8; 16];
        getrandom::fill(&mut entropy).expect("profile identity entropy");
        let suffix: String = entropy.iter().map(|byte| format!("{byte:02x}")).collect();
        let name = wide(OsStr::new(&format!("CageforgeProbe.{suffix}")));
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

    fn remove(&mut self) {
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

#[allow(unsafe_code)]
impl Child {
    fn resume(&self) {
        assert_ne!(
            unsafe { ResumeThread(self.thread.as_raw_handle()) },
            u32::MAX
        );
    }

    fn wait(&self) {
        assert_eq!(
            unsafe { WaitForSingleObject(self.process.as_raw_handle(), 15_000) },
            WAIT_OBJECT_0,
            "AppContainer fixture did not terminate"
        );
        let mut status = 0;
        assert_ne!(
            unsafe { GetExitCodeProcess(self.process.as_raw_handle(), &mut status) },
            0
        );
        assert_eq!(
            status,
            0,
            "AppContainer read fixture exit: {status:#x}; output: {:?}",
            fs::read_to_string(&self.output)
        );
    }
}

#[allow(unsafe_code)]
impl Drop for Child {
    fn drop(&mut self) {
        // The fixture never spawns descendants. Terminate on assertion failure
        // as well as the success path before deleting profiles or temporary ACLs.
        unsafe {
            TerminateProcess(self.process.as_raw_handle(), 1);
            WaitForSingleObject(self.process.as_raw_handle(), 5_000);
        }
    }
}

#[allow(unsafe_code)]
impl Drop for Attributes {
    fn drop(&mut self) {
        unsafe { DeleteProcThreadAttributeList(self.0.as_mut_ptr().cast()) };
    }
}

#[allow(unsafe_code)]
impl Drop for LocalAllocation {
    fn drop(&mut self) {
        unsafe { LocalFree(self.0) };
    }
}

#[allow(unsafe_code)]
impl Drop for Environment {
    fn drop(&mut self) {
        unsafe { DestroyEnvironmentBlock(self.0) };
    }
}

fn wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}

#[allow(unsafe_code)]
fn grant_read(path: &Path, profile: &Profile, executable: bool) {
    let name = wide(path.as_os_str());
    let mut old_acl = null_mut();
    let mut descriptor = null_mut();
    let status = unsafe {
        GetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            &mut old_acl,
            null_mut(),
            &mut descriptor,
        )
    };
    assert_eq!(status, 0, "read fixture DACL: {path:?}");
    let _descriptor = LocalAllocation(descriptor);
    let entry = EXPLICIT_ACCESS_W {
        grfAccessPermissions: FILE_GENERIC_READ | if executable { FILE_GENERIC_EXECUTE } else { 0 },
        grfAccessMode: GRANT_ACCESS,
        grfInheritance: 0,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: null_mut(),
            MultipleTrusteeOperation: 0,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_UNKNOWN,
            ptstrName: profile.sid.cast(),
        },
    };
    let mut new_acl = null_mut();
    assert_eq!(
        unsafe { SetEntriesInAclW(1, &entry, old_acl, &mut new_acl) },
        0
    );
    let _new_acl = LocalAllocation(new_acl.cast());
    assert_eq!(
        unsafe {
            SetNamedSecurityInfoW(
                name.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                new_acl,
                null(),
            )
        },
        0
    );
}

#[allow(unsafe_code)]
fn launch(profile: &Profile, executable: &Path, own: &Path, other: &Path) -> Child {
    let mut capabilities = SECURITY_CAPABILITIES {
        AppContainerSid: profile.sid,
        Capabilities: null_mut(),
        CapabilityCount: 0,
        Reserved: 0,
    };
    let mut size = 0;
    unsafe { InitializeProcThreadAttributeList(null_mut(), 2, 0, &mut size) };
    assert!(size > 0);
    let mut storage = vec![0_usize; size.div_ceil(size_of::<usize>())];
    assert_ne!(
        unsafe { InitializeProcThreadAttributeList(storage.as_mut_ptr().cast(), 2, 0, &mut size) },
        0
    );
    let mut attributes = Attributes(storage);
    assert_ne!(
        unsafe {
            UpdateProcThreadAttribute(
                attributes.0.as_mut_ptr().cast(),
                0,
                PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
                (&raw mut capabilities).cast(),
                size_of::<SECURITY_CAPABILITIES>(),
                null_mut(),
                null(),
            )
        },
        0
    );
    let output = executable
        .parent()
        .expect("fixture directory")
        .join(own.file_name().expect("resource name"))
        .with_extension("log");
    let output_file = fs::File::create(&output).expect("fixture output");
    let input_file = fs::File::open("NUL").expect("fixture input");
    let handles = [input_file.as_raw_handle(), output_file.as_raw_handle()];
    for handle in handles {
        assert_ne!(
            unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) },
            0
        );
    }
    assert_ne!(
        unsafe {
            UpdateProcThreadAttribute(
                attributes.0.as_mut_ptr().cast(),
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                handles.as_ptr().cast(),
                size_of_val(&handles),
                null_mut(),
                null(),
            )
        },
        0
    );
    let startup = STARTUPINFOEXW {
        StartupInfo: windows_sys::Win32::System::Threading::STARTUPINFOW {
            cb: size_of::<STARTUPINFOEXW>() as u32,
            dwFlags: STARTF_USESTDHANDLES,
            hStdInput: handles[0],
            hStdOutput: handles[1],
            hStdError: handles[1],
            ..Default::default()
        },
        lpAttributeList: attributes.0.as_mut_ptr().cast(),
    };
    // Test-owned file paths have no quotes or trailing slashes. This is not a
    // replacement for the production Windows command-line encoder.
    let mut command = Vec::new();
    for argument in [
        executable.as_os_str(),
        OsStr::new("--appcontainer-read-probe"),
        own.as_os_str(),
        other.as_os_str(),
    ] {
        let encoded: Vec<_> = argument.encode_wide().collect();
        assert!(!encoded.contains(&34) && !encoded.contains(&0) && encoded.last() != Some(&92));
        command.push(34);
        command.extend(encoded);
        command.extend([34, 32]);
    }
    command.push(0);
    let program = wide(executable.as_os_str());
    let cwd = wide(executable.parent().expect("fixture directory").as_os_str());
    let mut user_token = null_mut();
    assert_ne!(
        unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY | TOKEN_DUPLICATE,
                &mut user_token,
            )
        },
        0
    );
    let user_token = unsafe { OwnedHandle::from_raw_handle(user_token) };
    let mut environment = null_mut();
    // Build the system/user baseline without inheriting the CI process env.
    assert_ne!(
        unsafe { CreateEnvironmentBlock(&mut environment, user_token.as_raw_handle(), 0) },
        0,
        "CreateEnvironmentBlock: {}",
        unsafe { GetLastError() }
    );
    let environment = Environment(environment);
    let mut information = PROCESS_INFORMATION::default();
    let created = unsafe {
        CreateProcessW(
            program.as_ptr(),
            command.as_mut_ptr(),
            null(),
            null(),
            1,
            EXTENDED_STARTUPINFO_PRESENT
                | CREATE_NO_WINDOW
                | CREATE_SUSPENDED
                | CREATE_UNICODE_ENVIRONMENT,
            environment.0,
            cwd.as_ptr(),
            &startup.StartupInfo,
            &mut information,
        )
    };
    assert_ne!(created, 0, "CreateProcessW AppContainer: {}", unsafe {
        GetLastError()
    });
    let child = Child {
        process: unsafe { OwnedHandle::from_raw_handle(information.hProcess) },
        thread: unsafe { OwnedHandle::from_raw_handle(information.hThread) },
        output,
    };
    let mut token = null_mut();
    assert_ne!(
        unsafe { OpenProcessToken(child.process.as_raw_handle(), TOKEN_QUERY, &mut token) },
        0
    );
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    let mut is_container = 0_u32;
    let mut returned = 0;
    assert_ne!(
        unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenIsAppContainer,
                (&raw mut is_container).cast(),
                size_of::<u32>() as u32,
                &mut returned,
            )
        },
        0
    );
    assert_eq!(
        is_container, 1,
        "child must actually use an AppContainer token"
    );
    child
}

#[test]
fn distinct_appcontainer_packages_keep_file_reads_separate() {
    let mut first = Profile::new();
    let mut second = Profile::new();
    let runtime = tempfile::tempdir().expect("runtime directory");
    let resources = tempfile::tempdir().expect("resource directory");
    let executable = runtime.path().join("probe.exe");
    fs::copy(
        env!("CARGO_BIN_EXE_cageforge-windows-test-fixture"),
        &executable,
    )
    .expect("copy fixture");
    let a = resources.path().join("a.txt");
    let b = resources.path().join("b.txt");
    fs::write(&a, b"appcontainer-read-probe").expect("first resource");
    fs::write(&b, b"appcontainer-read-probe").expect("second resource");
    for profile in [&first, &second] {
        grant_read(runtime.path(), profile, true);
        grant_read(&executable, profile, true);
    }
    grant_read(&a, &first, false);
    let guardian = launch(&first, &executable, &a, &b);
    // Install the second grant only after the first token already exists.
    grant_read(&b, &second, false);
    let grantee = launch(&second, &executable, &b, &a);
    guardian.resume();
    grantee.resume();
    guardian.wait();
    grantee.wait();
    drop(grantee);
    drop(guardian);
    first.remove();
    second.remove();
}
