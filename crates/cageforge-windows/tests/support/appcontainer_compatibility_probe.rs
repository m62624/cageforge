// SPDX-License-Identifier: Apache-2.0

//! Temporary native compatibility experiment, compiled only in runner tests.
//! Calls the real restricted-token and private-desktop implementations. This
//! does not exercise dedicated-account bootstrap, WFP, or named-pipe access.

use std::ffi::{OsStr, c_void};
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::PathBuf;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{GetLastError, WAIT_OBJECT_0};
use windows_sys::Win32::Security::{
    GetTokenInformation, SECURITY_CAPABILITIES, TOKEN_QUERY, TokenIsAppContainer,
    TokenRestrictedSids,
};
use windows_sys::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
use windows_sys::Win32::System::JobObjects::{
    CreateJobObjectW, IsProcessInJob, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_BASIC_UI_RESTRICTIONS, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectBasicUIRestrictions, JobObjectExtendedLimitInformation, SetInformationJobObject,
    TerminateJobObject,
};
use windows_sys::Win32::System::SystemServices::JOB_OBJECT_UILIMIT_ALL;
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW,
    DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess,
    InitializeProcThreadAttributeList, OpenProcessToken, PROC_THREAD_ATTRIBUTE_JOB_LIST,
    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, PROCESS_INFORMATION, ResumeThread, STARTUPINFOEXW,
    STARTUPINFOW, UpdateProcThreadAttribute, WaitForSingleObject,
};

use super::super::desktop::PrivateDesktop;
use super::{RestrictedPrimaryToken, open_base_token, token_group_sid_set, token_user_sid};

#[path = "appcontainer_profile.rs"]
mod appcontainer_profile;
use appcontainer_profile::Profile;

struct Child {
    process: OwnedHandle,
    thread: OwnedHandle,
    job: OwnedHandle,
}

struct Attributes(Vec<usize>);
struct Environment(*mut c_void);

#[allow(unsafe_code)]
impl Drop for Child {
    fn drop(&mut self) {
        // Job ownership also covers an assertion before the suspended thread
        // resumes. The profile and desktop remain alive until this completes.
        unsafe {
            TerminateJobObject(self.job.as_raw_handle(), 1);
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
impl Drop for Environment {
    fn drop(&mut self) {
        unsafe { DestroyEnvironmentBlock(self.0) };
    }
}

fn wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}

#[allow(unsafe_code)]
fn job() -> OwnedHandle {
    let handle = unsafe { CreateJobObjectW(null(), null()) };
    assert!(!handle.is_null(), "create compatibility Job");
    let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
    // Match ParentJob: kill-on-close, no breakaway, every UI restriction.
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    assert_ne!(
        unsafe {
            SetInformationJobObject(
                handle.as_raw_handle(),
                JobObjectExtendedLimitInformation,
                (&raw const limits).cast(),
                size_of_val(&limits) as u32,
            )
        },
        0,
        "configure compatibility Job"
    );
    let ui = JOBOBJECT_BASIC_UI_RESTRICTIONS {
        UIRestrictionsClass: JOB_OBJECT_UILIMIT_ALL,
    };
    assert_ne!(
        unsafe {
            SetInformationJobObject(
                handle.as_raw_handle(),
                JobObjectBasicUIRestrictions,
                (&raw const ui).cast(),
                size_of_val(&ui) as u32,
            )
        },
        0,
        "configure compatibility UI limits"
    );
    handle
}

#[allow(unsafe_code)]
fn exercise(strict_local_ipc: bool) {
    let mut profile = Profile::new();
    let base = open_base_token().expect("base primary token");
    let user = token_user_sid(base.as_raw_handle()).expect("base user");
    // An identity marker, not an object-access capability. Production generates
    // fresh route SIDs; this test only checks that lowbox creation preserves it.
    let route = "S-1-5-21-117733-229955-331177-440099";
    // Preserve Cageforge restriction identities. The AppContainer package SID
    // belongs in SECURITY_CAPABILITIES, not in this ordinary restricting set.
    let token = RestrictedPrimaryToken::create(
        &["S-1-5-21-117733-229955-331177-440100".to_owned()],
        strict_local_ipc,
        Some(route),
        &user,
    )
    .expect("ordinary restricted-token control before AppContainer");
    let expected = token_group_sid_set(token.raw(), TokenRestrictedSids, "input restrictions")
        .expect("input restrictions");
    let desktop = PrivateDesktop::create(&token).expect("production private desktop");
    let job = job();
    let jobs = [job.as_raw_handle()];
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
    for (kind, value, length) in [
        (
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
            (&raw mut capabilities).cast::<c_void>(),
            size_of_val(&capabilities),
        ),
        (
            PROC_THREAD_ATTRIBUTE_JOB_LIST,
            jobs.as_ptr().cast_mut().cast::<c_void>(),
            size_of_val(&jobs),
        ),
    ] {
        assert_ne!(
            unsafe {
                UpdateProcThreadAttribute(
                    attributes.0.as_mut_ptr().cast(),
                    0,
                    kind as usize,
                    value,
                    length,
                    null_mut(),
                    null(),
                )
            },
            0,
            "attribute {kind}: {}",
            unsafe { GetLastError() }
        );
    }
    let mut desktop_name = desktop.startup_name().to_vec();
    let startup = STARTUPINFOEXW {
        StartupInfo: STARTUPINFOW {
            cb: size_of::<STARTUPINFOEXW>() as u32,
            lpDesktop: desktop_name.as_mut_ptr(),
            ..Default::default()
        },
        lpAttributeList: attributes.0.as_mut_ptr().cast(),
    };
    let system =
        PathBuf::from(std::env::var_os("SystemRoot").expect("SystemRoot")).join("System32");
    let executable = wide(system.join("cmd.exe").as_os_str());
    let cwd = wide(system.as_os_str());
    let mut command = wide(OsStr::new("cmd.exe /d /c exit 0"));
    let mut environment = null_mut();
    assert_ne!(
        unsafe { CreateEnvironmentBlock(&mut environment, base.as_raw_handle(), 0) },
        0,
        "profile environment: {}",
        unsafe { GetLastError() }
    );
    let environment = Environment(environment);
    let mut information = PROCESS_INFORMATION::default();
    let created = unsafe {
        CreateProcessAsUserW(
            token.raw(),
            executable.as_ptr(),
            command.as_mut_ptr(),
            null(),
            null(),
            0,
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
    assert_ne!(
        created,
        0,
        "restricted AppContainer spawn (strict IPC={strict_local_ipc}): {}",
        unsafe { GetLastError() }
    );
    let child = Child {
        process: unsafe { OwnedHandle::from_raw_handle(information.hProcess) },
        thread: unsafe { OwnedHandle::from_raw_handle(information.hThread) },
        job,
    };
    let mut child_token = null_mut();
    assert_ne!(
        unsafe { OpenProcessToken(child.process.as_raw_handle(), TOKEN_QUERY, &mut child_token) },
        0
    );
    let child_token = unsafe { OwnedHandle::from_raw_handle(child_token) };
    let mut lowbox = 0_u32;
    let mut returned = 0;
    assert_ne!(
        unsafe {
            GetTokenInformation(
                child_token.as_raw_handle(),
                TokenIsAppContainer,
                (&raw mut lowbox).cast(),
                size_of_val(&lowbox) as u32,
                &mut returned,
            )
        },
        0
    );
    assert_eq!(lowbox, 1, "child must actually be AppContainer");
    assert_eq!(
        token_user_sid(child_token.as_raw_handle()).expect("child user"),
        user
    );
    let actual = token_group_sid_set(
        child_token.as_raw_handle(),
        TokenRestrictedSids,
        "child restrictions",
    )
    .expect("child restrictions");
    assert_eq!(
        actual, expected,
        "AppContainer must preserve route and filesystem restricting SIDs"
    );
    let mut assigned = 0;
    assert_ne!(
        unsafe {
            IsProcessInJob(
                child.process.as_raw_handle(),
                child.job.as_raw_handle(),
                &mut assigned,
            )
        },
        0
    );
    assert_ne!(assigned, 0, "atomic Job assignment");
    assert_ne!(
        unsafe { ResumeThread(child.thread.as_raw_handle()) },
        u32::MAX
    );
    assert_eq!(
        unsafe { WaitForSingleObject(child.process.as_raw_handle(), 15_000) },
        WAIT_OBJECT_0,
        "restricted AppContainer startup stalled (strict IPC={strict_local_ipc})"
    );
    let mut status = 0;
    assert_ne!(
        unsafe { GetExitCodeProcess(child.process.as_raw_handle(), &mut status) },
        0
    );
    assert_eq!(
        status, 0,
        "restricted AppContainer exit (strict IPC={strict_local_ipc}): {status:#x}"
    );
    drop(child_token);
    drop(child);
    drop(desktop);
    drop(token);
    profile.remove();
}

#[test]
fn appcontainer_preserves_restricted_token_private_desktop_and_job() {
    exercise(false);
}

#[test]
fn appcontainer_preserves_strict_ipc_token_private_desktop_and_job() {
    exercise(true);
}
