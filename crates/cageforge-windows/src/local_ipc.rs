// SPDX-License-Identifier: Apache-2.0

//! Launch-scoped Windows named-pipe ACL enforcement.
//!
//! Windows has no pathname IPC namespace that can be unshared per process.
//! The native boundary therefore combines a fresh restricting SID with an
//! ACL transaction on each explicitly approved pipe. The restricted token is
//! put into the strict local-IPC mode only for this launch: broad user and
//! Everyone restricting SIDs are not retained, while the authenticated logon
//! SID is retained only for Windows session initialization. An unrelated pipe
//! that merely grants Everyone cannot satisfy the restricted access check.

use std::ffi::c_void;
use std::mem::size_of;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr;

use cageforge_policy::{DomainAccess, LocalIpcEndpoint};
use cageforge_policy_compose::EffectiveNetworkLowering;
use getrandom::Error as RandomError;
use thiserror::Error;
use windows_sys::Win32::Foundation::{
    ERROR_SUCCESS, GetLastError, HLOCAL, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    EXPLICIT_ACCESS_W, GRANT_ACCESS, GetSecurityInfo, SE_KERNEL_OBJECT, SetEntriesInAclW,
    SetSecurityInfo, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
    DACL_SECURITY_INFORMATION, GetAce, GetAclInformation, GetSecurityDescriptorControl, IsValidSid,
    PROTECTED_DACL_SECURITY_INFORMATION, SE_DACL_PROTECTED, UNPROTECTED_DACL_SECURITY_INFORMATION,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, READ_CONTROL,
    WRITE_DAC,
};

use crate::capability::state::{NamedPipeAclObject, PersistedDacl};
use crate::capability::store::{
    CapabilityLocalIpcLease, CapabilityStateStore, CapabilityStateStoreError,
};
use crate::native_strings::wide;

const PIPE_ACCESS_MASK: u32 = FILE_GENERIC_READ | FILE_GENERIC_WRITE;
const MAX_PIPE_ACL_BYTES: usize = u16::MAX as usize;

/// A native local-IPC setup failure. It is wrapped by the public backend error
/// without collapsing the native error category.
#[derive(Debug, Error)]
pub enum WindowsLocalIpcError {
    #[error("failed to coordinate Windows named-pipe ACLs: {0}")]
    Lock(#[from] CapabilityStateStoreError),
    #[error("Windows local-IPC policy contains a denied named-pipe rule for {name:?}")]
    DenyRule { name: String },
    #[error("Windows local-IPC policy contains a POSIX endpoint on Windows: {endpoint:?}")]
    PosixEndpoint { endpoint: String },
    #[error("failed to generate the launch-unique local-IPC capability SID: {source}")]
    SidGeneration { source: RandomError },
    #[error("failed to read the named-pipe DACL for {name:?}: Windows error {code}")]
    DescriptorRead { name: String, code: u32 },
    #[error("named-pipe DACL for {name:?} is absent or malformed")]
    DescriptorInvalid { name: String },
    #[error("failed to construct the named-pipe DACL for {name:?}: Windows error {code}")]
    DescriptorBuild { name: String, code: u32 },
    #[error("failed to apply the named-pipe DACL for {name:?}: Windows error {code}")]
    DescriptorWrite { name: String, code: u32 },
    #[error("named-pipe DACL read-back for {name:?} does not contain the launch capability")]
    DescriptorReadBack { name: String },
    #[error("named-pipe DACL for {name:?} changed outside Cageforge while the child was active")]
    DescriptorDrift { name: String },
    #[error("failed to restore the named-pipe DACL for {name:?}: Windows error {code}")]
    DescriptorRestore { name: String, code: u32 },
}

/// The ACL changes and cross-process lock owned by one Windows child.
pub(crate) struct WindowsLocalIpcEnforcement {
    _lease: CapabilityLocalIpcLease,
    state: CapabilityStateStore,
    pipes: Vec<NamedPipeAclLease>,
    capability_sid: String,
}

struct NamedPipeAclLease {
    name: String,
    runner_account_sid: String,
    handle: OwnedHandle,
    original: AclSnapshot,
    after: AclSnapshot,
    released: bool,
}

#[derive(Clone, PartialEq, Eq)]
struct AclSnapshot {
    words: Vec<u32>,
    bytes: usize,
    protected: bool,
}

struct LocalSecurityDescriptor(*mut c_void);

struct LocalSid(*mut c_void);

struct LocalAcl(*mut ACL);

impl WindowsLocalIpcEnforcement {
    pub(crate) fn apply(
        lowering: EffectiveNetworkLowering<'_>,
        state: &CapabilityStateStore,
        runner_account_sid: &str,
    ) -> Result<Option<Self>, WindowsLocalIpcError> {
        let mut names = Vec::new();
        for layer in lowering.layers() {
            for rule in layer.local_ipc() {
                match rule.endpoint() {
                    LocalIpcEndpoint::WindowsNamedPipe(name) => {
                        if rule.access() == DomainAccess::Deny {
                            return Err(WindowsLocalIpcError::DenyRule {
                                name: name.as_str().to_owned(),
                            });
                        }
                        if !names
                            .iter()
                            .any(|existing: &String| existing == name.as_str())
                        {
                            names.push(name.as_str().to_owned());
                        }
                    }
                    LocalIpcEndpoint::UnixSocket(path) => {
                        return Err(WindowsLocalIpcError::PosixEndpoint {
                            endpoint: path.as_path().display().to_string(),
                        });
                    }
                }
            }
        }
        if names.is_empty() {
            return Ok(None);
        }

        let lease = state.acquire_local_ipc_lease()?;
        let capability_sid = random_capability_sid()?;
        let mut state_session = state.begin()?;
        let mut pipes = Vec::with_capacity(names.len());
        for name in names {
            match NamedPipeAclLease::prepare(name, &capability_sid, runner_account_sid).and_then(
                |mut pipe| {
                    state_session.begin_named_pipe_acl(NamedPipeAclObject {
                        name: pipe.name.clone(),
                        capability_sid: capability_sid.clone(),
                        original: pipe.original.persisted(),
                        current: pipe.after.persisted(),
                    })?;
                    if let Err(error) = pipe.activate(&capability_sid) {
                        let _ =
                            restore_snapshot_on_handle(&pipe.name, &pipe.handle, &pipe.original);
                        return Err(error);
                    }
                    if let Err(error) = state_session
                        .update_named_pipe_acl_current(&pipe.name, pipe.after.persisted())
                    {
                        let _ =
                            restore_snapshot_on_handle(&pipe.name, &pipe.handle, &pipe.original);
                        return Err(error.into());
                    }
                    Ok(pipe)
                },
            ) {
                Ok(pipe) => pipes.push(pipe),
                Err(error) => {
                    drop(state_session);
                    drop(pipes);
                    drop(lease);
                    return Err(error);
                }
            }
        }
        state_session.finish()?;
        Ok(Some(Self {
            _lease: lease,
            state: state.clone(),
            pipes,
            capability_sid,
        }))
    }

    pub(crate) fn capability_sid(&self) -> &str {
        &self.capability_sid
    }

    pub(crate) fn release(&mut self) -> Result<(), WindowsLocalIpcError> {
        let mut state_session = self.state.begin()?;
        for pipe in self.pipes.iter_mut().rev() {
            let actual = pipe.release()?.persisted();
            state_session.resolve_named_pipe_acl(&pipe.name, &actual)?;
        }
        state_session.finish()?;
        self.pipes.clear();
        Ok(())
    }

    pub(crate) fn recover(state: &CapabilityStateStore) -> Result<(), WindowsLocalIpcError> {
        let Some(_lease) = state.try_acquire_local_ipc_lease()? else {
            // Another Cageforge child owns the launch-scoped ACL transaction.
            // Its durable journal is live, not stale; recovery will run after
            // that owner releases the system lock.
            return Ok(());
        };
        let mut session = state.begin()?;
        let records = session.named_pipe_acl_objects().to_vec();
        for record in records {
            let current = read_snapshot(&record.name)?;
            let original = snapshot_from_persisted(&record.name, &record.original)?;
            let expected = snapshot_from_persisted(&record.name, &record.current)?;
            if current == original {
                session.resolve_named_pipe_acl(&record.name, &record.original)?;
                continue;
            }
            if current != expected {
                return Err(WindowsLocalIpcError::DescriptorDrift { name: record.name });
            }
            restore_snapshot(&record.name, &original)?;
            let restored = read_snapshot(&record.name)?;
            if restored != original {
                return Err(WindowsLocalIpcError::DescriptorDrift { name: record.name });
            }
            session.resolve_named_pipe_acl(&record.name, &record.original)?;
        }
        session.finish()?;
        Ok(())
    }
}

impl NamedPipeAclLease {
    fn prepare(
        name: String,
        capability_sid: &str,
        runner_account_sid: &str,
    ) -> Result<Self, WindowsLocalIpcError> {
        let handle = open_pipe(&name)?;
        let original = read_snapshot_from_handle(&name, &handle)?;
        let capability = LocalSid::parse(capability_sid).map_err(|code| {
            WindowsLocalIpcError::DescriptorBuild {
                name: name.clone(),
                code,
            }
        })?;
        let runner_account = LocalSid::parse(runner_account_sid).map_err(|code| {
            WindowsLocalIpcError::DescriptorBuild {
                name: name.clone(),
                code,
            }
        })?;
        let updated_acl = build_granted_acl(&name, &original, capability.0, runner_account.0)?;
        let updated = snapshot_from_acl(&name, updated_acl.0, original.protected)?;
        Ok(Self {
            name,
            runner_account_sid: runner_account_sid.to_owned(),
            handle,
            original,
            after: updated,
            released: false,
        })
    }

    fn activate(&mut self, capability_sid: &str) -> Result<(), WindowsLocalIpcError> {
        let capability = LocalSid::parse(capability_sid).map_err(|code| {
            WindowsLocalIpcError::DescriptorBuild {
                name: self.name.clone(),
                code,
            }
        })?;
        let runner_account = LocalSid::parse(&self.runner_account_sid).map_err(|code| {
            WindowsLocalIpcError::DescriptorBuild {
                name: self.name.clone(),
                code,
            }
        })?;
        write_snapshot_on_handle(
            &self.name,
            &self.handle,
            &self.after,
            self.original.protected,
        )?;
        let after = match read_snapshot_from_handle(&self.name, &self.handle) {
            Ok(snapshot)
                if snapshot_contains_sid(&snapshot, capability.0)
                    && snapshot_contains_sid(&snapshot, runner_account.0) =>
            {
                snapshot
            }
            Ok(_) => {
                let _ = write_snapshot_on_handle(
                    &self.name,
                    &self.handle,
                    &self.original,
                    self.original.protected,
                );
                return Err(WindowsLocalIpcError::DescriptorReadBack {
                    name: self.name.clone(),
                });
            }
            Err(error) => {
                let _ = write_snapshot_on_handle(
                    &self.name,
                    &self.handle,
                    &self.original,
                    self.original.protected,
                );
                return Err(error);
            }
        };
        self.after = after;
        Ok(())
    }

    fn release(&mut self) -> Result<AclSnapshot, WindowsLocalIpcError> {
        if self.released {
            return Ok(self.original.clone());
        }
        let current = read_snapshot_from_handle(&self.name, &self.handle)?;
        if current != self.after {
            return Err(WindowsLocalIpcError::DescriptorDrift {
                name: self.name.clone(),
            });
        }
        restore_snapshot_on_handle(&self.name, &self.handle, &self.original)?;
        let restored = read_snapshot_from_handle(&self.name, &self.handle)?;
        if restored != self.original {
            return Err(WindowsLocalIpcError::DescriptorDrift {
                name: self.name.clone(),
            });
        }
        self.released = true;
        Ok(restored)
    }
}

impl Drop for NamedPipeAclLease {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        if let Ok(current) = read_snapshot_from_handle(&self.name, &self.handle)
            && current == self.after
        {
            let _ = write_snapshot_on_handle(
                &self.name,
                &self.handle,
                &self.original,
                self.original.protected,
            );
        }
        self.released = true;
    }
}

#[allow(unsafe_code)]
impl AclSnapshot {
    fn as_acl(&self) -> *const ACL {
        self.words.as_ptr().cast()
    }

    fn persisted(&self) -> PersistedDacl {
        let mut bytes = vec![0u8; self.bytes];
        unsafe {
            ptr::copy_nonoverlapping(
                self.words.as_ptr().cast::<u8>(),
                bytes.as_mut_ptr(),
                self.bytes,
            );
        }
        PersistedDacl {
            bytes,
            protected: self.protected,
        }
    }
}

#[allow(unsafe_code)]
fn snapshot_from_persisted(
    name: &str,
    persisted: &PersistedDacl,
) -> Result<AclSnapshot, WindowsLocalIpcError> {
    if persisted.validate().is_err() {
        return Err(WindowsLocalIpcError::DescriptorInvalid {
            name: name.to_owned(),
        });
    }
    let mut words = vec![0u32; persisted.bytes.len().div_ceil(size_of::<u32>())];
    unsafe {
        ptr::copy_nonoverlapping(
            persisted.bytes.as_ptr(),
            words.as_mut_ptr().cast::<u8>(),
            persisted.bytes.len(),
        );
    }
    Ok(AclSnapshot {
        words,
        bytes: persisted.bytes.len(),
        protected: persisted.protected,
    })
}

impl LocalSid {
    #[allow(unsafe_code)]
    fn parse(value: &str) -> Result<Self, u32> {
        let value = wide(value);
        let mut sid = ptr::null_mut();
        if unsafe {
            windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW(
                value.as_ptr(),
                &mut sid,
            )
        } == 0
        {
            Err(unsafe { GetLastError() })
        } else {
            Ok(Self(sid))
        }
    }
}

#[allow(unsafe_code)]
impl Drop for LocalSecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0 as HLOCAL);
            }
        }
    }
}

#[allow(unsafe_code)]
impl Drop for LocalSid {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0 as HLOCAL);
            }
        }
    }
}

#[allow(unsafe_code)]
impl Drop for LocalAcl {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0 as HLOCAL);
            }
        }
    }
}

#[allow(unsafe_code)]
fn read_snapshot(name: &str) -> Result<AclSnapshot, WindowsLocalIpcError> {
    let pipe = open_pipe(name)?;
    read_snapshot_from_handle(name, &pipe)
}

#[allow(unsafe_code)]
fn read_snapshot_from_handle(
    name: &str,
    pipe: &OwnedHandle,
) -> Result<AclSnapshot, WindowsLocalIpcError> {
    let mut dacl = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            pipe.as_raw_handle() as _,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    let _descriptor = LocalSecurityDescriptor(descriptor);
    if status != ERROR_SUCCESS {
        return Err(WindowsLocalIpcError::DescriptorRead {
            name: name.to_owned(),
            code: status,
        });
    }
    if dacl.is_null() || descriptor.is_null() {
        return Err(WindowsLocalIpcError::DescriptorInvalid {
            name: name.to_owned(),
        });
    }
    let mut size = ACL_SIZE_INFORMATION::default();
    if unsafe {
        GetAclInformation(
            dacl,
            (&raw mut size).cast(),
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
        || size.AclBytesInUse < size_of::<ACL>() as u32
        || size.AclBytesInUse as usize > MAX_PIPE_ACL_BYTES
    {
        return Err(WindowsLocalIpcError::DescriptorInvalid {
            name: name.to_owned(),
        });
    }
    let bytes = size.AclBytesInUse as usize;
    let mut words = vec![0u32; bytes.div_ceil(size_of::<u32>())];
    unsafe {
        ptr::copy_nonoverlapping(dacl.cast::<u8>(), words.as_mut_ptr().cast::<u8>(), bytes);
    }
    let mut control = 0u16;
    let mut revision = 0u32;
    if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0 {
        return Err(WindowsLocalIpcError::DescriptorInvalid {
            name: name.to_owned(),
        });
    }
    Ok(AclSnapshot {
        words,
        bytes,
        protected: control & SE_DACL_PROTECTED != 0,
    })
}

#[allow(unsafe_code)]
fn build_granted_acl(
    name: &str,
    original: &AclSnapshot,
    capability_sid: *mut c_void,
    runner_account_sid: *mut c_void,
) -> Result<LocalAcl, WindowsLocalIpcError> {
    let mut entries = [
        EXPLICIT_ACCESS_W {
            grfAccessPermissions: PIPE_ACCESS_MASK,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: 0,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: ptr::null_mut(),
                MultipleTrusteeOperation: 0,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_UNKNOWN,
                ptstrName: capability_sid.cast(),
            },
        },
        EXPLICIT_ACCESS_W {
            grfAccessPermissions: PIPE_ACCESS_MASK,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: 0,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: ptr::null_mut(),
                MultipleTrusteeOperation: 0,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_UNKNOWN,
                ptstrName: runner_account_sid.cast(),
            },
        },
    ];
    let mut updated = ptr::null_mut();
    let status = unsafe {
        SetEntriesInAclW(
            entries.len() as u32,
            entries.as_mut_ptr(),
            original.as_acl(),
            &mut updated,
        )
    };
    if status != ERROR_SUCCESS || updated.is_null() {
        return Err(WindowsLocalIpcError::DescriptorBuild {
            name: name.to_owned(),
            code: if status == ERROR_SUCCESS {
                unsafe { GetLastError() }
            } else {
                status
            },
        });
    }
    Ok(LocalAcl(updated))
}

#[allow(unsafe_code)]
fn snapshot_from_acl(
    name: &str,
    acl: *mut ACL,
    protected: bool,
) -> Result<AclSnapshot, WindowsLocalIpcError> {
    let mut size = ACL_SIZE_INFORMATION::default();
    if acl.is_null()
        || unsafe {
            GetAclInformation(
                acl,
                (&raw mut size).cast(),
                size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
        } == 0
        || size.AclBytesInUse < size_of::<ACL>() as u32
        || size.AclBytesInUse as usize > MAX_PIPE_ACL_BYTES
    {
        return Err(WindowsLocalIpcError::DescriptorInvalid {
            name: name.to_owned(),
        });
    }
    let bytes = size.AclBytesInUse as usize;
    let mut words = vec![0u32; bytes.div_ceil(size_of::<u32>())];
    unsafe {
        ptr::copy_nonoverlapping(acl.cast::<u8>(), words.as_mut_ptr().cast::<u8>(), bytes);
    }
    Ok(AclSnapshot {
        words,
        bytes,
        protected,
    })
}

#[allow(unsafe_code)]
fn write_snapshot_on_handle(
    name: &str,
    pipe: &OwnedHandle,
    snapshot: &AclSnapshot,
    protected: bool,
) -> Result<(), WindowsLocalIpcError> {
    let security = DACL_SECURITY_INFORMATION
        | if protected {
            PROTECTED_DACL_SECURITY_INFORMATION
        } else {
            UNPROTECTED_DACL_SECURITY_INFORMATION
        };
    let status = unsafe {
        SetSecurityInfo(
            pipe.as_raw_handle() as _,
            SE_KERNEL_OBJECT,
            security,
            ptr::null_mut(),
            ptr::null_mut(),
            snapshot.as_acl(),
            ptr::null_mut(),
        )
    };
    if status != ERROR_SUCCESS {
        Err(WindowsLocalIpcError::DescriptorWrite {
            name: name.to_owned(),
            code: status,
        })
    } else {
        Ok(())
    }
}

#[allow(unsafe_code)]
fn open_pipe(name: &str) -> Result<OwnedHandle, WindowsLocalIpcError> {
    let name_wide = wide(name);
    let handle = unsafe {
        CreateFileW(
            name_wide.as_ptr(),
            READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(WindowsLocalIpcError::DescriptorRead {
            name: name.to_owned(),
            code: unsafe { GetLastError() },
        });
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(handle as _) })
}

fn restore_snapshot(name: &str, snapshot: &AclSnapshot) -> Result<(), WindowsLocalIpcError> {
    let pipe = open_pipe(name)?;
    restore_snapshot_on_handle(name, &pipe, snapshot)
}

fn restore_snapshot_on_handle(
    name: &str,
    pipe: &OwnedHandle,
    snapshot: &AclSnapshot,
) -> Result<(), WindowsLocalIpcError> {
    write_snapshot_on_handle(name, pipe, snapshot, snapshot.protected).map_err(
        |error| match error {
            WindowsLocalIpcError::DescriptorWrite { code, .. } => {
                WindowsLocalIpcError::DescriptorRestore {
                    name: name.to_owned(),
                    code,
                }
            }
            other => other,
        },
    )
}

#[allow(unsafe_code)]
fn snapshot_contains_sid(snapshot: &AclSnapshot, sid: *mut c_void) -> bool {
    let acl = snapshot.as_acl() as *mut ACL;
    let mut info = ACL_SIZE_INFORMATION::default();
    if unsafe {
        GetAclInformation(
            acl,
            (&raw mut info).cast(),
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
    {
        return false;
    }
    let acl_start = acl as usize;
    let Some(acl_end) = acl_start.checked_add(snapshot.bytes) else {
        return false;
    };
    for index in 0..info.AceCount {
        let mut raw_ace = ptr::null_mut();
        if unsafe { GetAce(acl, index, &mut raw_ace) } == 0 || raw_ace.is_null() {
            return false;
        }
        let start = raw_ace as usize;
        let Some(header_end) = start.checked_add(size_of::<ACE_HEADER>()) else {
            return false;
        };
        if start < acl_start || header_end > acl_end {
            return false;
        }
        let ace = raw_ace.cast::<ACCESS_ALLOWED_ACE>();
        let ace_size = unsafe { (*ace).Header.AceSize } as usize;
        let Some(end) = start.checked_add(ace_size) else {
            return false;
        };
        if end > acl_end || unsafe { (*ace).Header.AceType } != 0 {
            continue;
        }
        let ace_sid = unsafe { (&raw mut (*ace).SidStart).cast::<c_void>() };
        if unsafe { IsValidSid(ace_sid) } != 0
            && unsafe { windows_sys::Win32::Security::EqualSid(ace_sid, sid) } != 0
            && unsafe { (*ace).Mask & PIPE_ACCESS_MASK == PIPE_ACCESS_MASK }
        {
            return true;
        }
    }
    false
}

fn random_capability_sid() -> Result<String, WindowsLocalIpcError> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|source| WindowsLocalIpcError::SidGeneration { source })?;
    let first = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let second = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    let third = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    let fourth = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
    Ok(format!("S-1-5-21-{first}-{second}-{third}-{fourth}"))
}
