// SPDX-License-Identifier: Apache-2.0

//! Serialized multi-process access to protected capability-SID state.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};

use thiserror::Error;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Storage::FileSystem::{LOCKFILE_EXCLUSIVE_LOCK, LockFileEx, UnlockFileEx};
use windows_sys::Win32::System::IO::OVERLAPPED;

use crate::capability_state::{
    AclMutationRecovery, CAPABILITY_LOCK_NAME, CAPABILITY_STATE_NAME, CapabilityRole,
    CapabilityState, CapabilityStateError, ManagedAclObject, MaterializationEvidence,
    MaterializationRecovery, MaterializedObject, PendingMaterializationView, PersistedDacl,
    PersistedFileIdentity,
};
use crate::error::WindowsSetupVerificationError;

pub(crate) struct CapabilityStateStore {
    state_path: PathBuf,
    lock_path: PathBuf,
    owner_sid: String,
}

pub(crate) struct CapabilityStateLock {
    file: File,
    overlapped: OVERLAPPED,
    locked: bool,
}

pub(crate) struct CapabilityStateSession<'store> {
    store: &'store CapabilityStateStore,
    lock: CapabilityStateLock,
    state: CapabilityState,
}

#[derive(Debug, Error)]
pub(crate) enum CapabilityStateStoreError {
    #[error(transparent)]
    Model(#[from] CapabilityStateError),
    #[error(transparent)]
    Security(#[from] WindowsSetupVerificationError),
    #[error("failed to open protected capability-SID lock file {path:?}: {source}")]
    LockOpen {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to acquire the capability-SID state lock: Windows error {code}")]
    LockAcquire { code: u32 },
    #[error("failed to release the capability-SID state lock: Windows error {code}")]
    LockRelease { code: u32 },
    #[error("failed to read protected capability-SID state {path:?}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to open protected capability-SID state {path:?} for update: {source}")]
    UpdateOpen {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to write protected capability-SID state {path:?}: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("capability-SID state differs after durable write read-back")]
    ReadBackMismatch,
}

impl CapabilityStateStore {
    pub(crate) fn new(state_directory: &Path, owner_sid: &str) -> Self {
        Self {
            state_path: state_directory.join(CAPABILITY_STATE_NAME),
            lock_path: state_directory.join(CAPABILITY_LOCK_NAME),
            owner_sid: owner_sid.to_string(),
        }
    }

    pub(crate) fn verify(&self) -> Result<(), CapabilityStateStoreError> {
        self.begin()?.finish()
    }

    pub(crate) fn ensure_authorities(
        &self,
        profile_sha256: &str,
        roots: impl IntoIterator<Item = (PathBuf, CapabilityRole)>,
    ) -> Result<Vec<String>, CapabilityStateStoreError> {
        let mut session = self.begin()?;
        let capabilities = session.ensure_authorities(profile_sha256, roots)?;
        session.finish()?;
        Ok(capabilities)
    }

    pub(crate) fn read_base_sid(&self) -> Result<String, CapabilityStateStoreError> {
        let session = self.begin()?;
        let sid = session.read_base_sid()?;
        session.finish()?;
        Ok(sid)
    }

    pub(crate) fn coordination_lock(
        &self,
    ) -> Result<CapabilityStateLock, CapabilityStateStoreError> {
        self.lock()
    }

    pub(crate) fn begin(&self) -> Result<CapabilityStateSession<'_>, CapabilityStateStoreError> {
        let lock = self.lock()?;
        let state = self.read_locked()?;
        Ok(CapabilityStateSession {
            store: self,
            lock,
            state,
        })
    }

    fn lock(&self) -> Result<CapabilityStateLock, CapabilityStateStoreError> {
        crate::setup_verification::paths::verify_protected_dacl(
            &self.lock_path,
            &self.owner_sid,
            false,
        )?;
        CapabilityStateLock::acquire(&self.lock_path)
    }

    fn read_locked(&self) -> Result<CapabilityState, CapabilityStateStoreError> {
        crate::setup_verification::paths::verify_protected_dacl(
            &self.state_path,
            &self.owner_sid,
            false,
        )?;
        let bytes =
            fs::read(&self.state_path).map_err(|source| CapabilityStateStoreError::Read {
                path: self.state_path.clone(),
                source,
            })?;
        CapabilityState::decode(&bytes).map_err(Into::into)
    }

    fn write_locked(&self, state: &CapabilityState) -> Result<(), CapabilityStateStoreError> {
        let encoded = state.encode()?;
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&self.state_path)
            .map_err(|source| CapabilityStateStoreError::UpdateOpen {
                path: self.state_path.clone(),
                source,
            })?;
        file.write_all(&encoded)
            .and_then(|()| file.sync_all())
            .map_err(|source| CapabilityStateStoreError::Write {
                path: self.state_path.clone(),
                source,
            })?;
        crate::setup_verification::paths::verify_protected_dacl(
            &self.state_path,
            &self.owner_sid,
            false,
        )?;
        let actual =
            fs::read(&self.state_path).map_err(|source| CapabilityStateStoreError::Read {
                path: self.state_path.clone(),
                source,
            })?;
        if CapabilityState::decode(&actual)? == *state {
            Ok(())
        } else {
            Err(CapabilityStateStoreError::ReadBackMismatch)
        }
    }
}

impl CapabilityStateSession<'_> {
    pub(crate) fn owner_sid(&self) -> &str {
        &self.store.owner_sid
    }

    pub(crate) fn ensure_authorities(
        &mut self,
        profile_sha256: &str,
        roots: impl IntoIterator<Item = (PathBuf, CapabilityRole)>,
    ) -> Result<Vec<String>, CapabilityStateStoreError> {
        let mut authorities: Vec<(PathBuf, CapabilityRole)> = Vec::new();
        for (path, role) in roots {
            if !authorities.iter().any(|(existing_path, existing_role)| {
                existing_role == &role
                    && cageforge_path::paths_equal(existing_path.as_path(), path.as_path())
            }) {
                authorities.push((path, role));
            }
        }
        for (root, role) in &authorities {
            self.state
                .ensure_authority(profile_sha256, role.clone(), root.clone())?;
        }
        self.persist()?;
        let mut capabilities = Vec::with_capacity(authorities.len());
        for (root, role) in &authorities {
            let Some(sid) = self.state.authority_sid(profile_sha256, role, root) else {
                return Err(CapabilityStateStoreError::ReadBackMismatch);
            };
            capabilities.push(sid.to_string());
        }
        Ok(capabilities)
    }

    pub(crate) fn read_base_sid(&self) -> Result<String, CapabilityStateStoreError> {
        self.state.read_base_sid().map_err(Into::into)
    }

    pub(crate) fn pending_acl_path(&self) -> Option<&Path> {
        self.state.pending_acl_path()
    }

    pub(crate) fn begin_acl_mutation(
        &mut self,
        path: PathBuf,
        identity: PersistedFileIdentity,
        before: PersistedDacl,
        after: PersistedDacl,
    ) -> Result<(), CapabilityStateStoreError> {
        self.state
            .begin_acl_mutation(path, identity, before, after)?;
        self.persist()
    }

    pub(crate) fn resolve_acl_mutation(
        &mut self,
        identity: &PersistedFileIdentity,
        actual: &PersistedDacl,
    ) -> Result<AclMutationRecovery, CapabilityStateStoreError> {
        let recovery = self.state.resolve_acl_mutation(identity, actual)?;
        self.persist()?;
        Ok(recovery)
    }

    pub(crate) fn managed_acl_objects(&self) -> &[ManagedAclObject] {
        self.state.managed_acl_objects()
    }

    pub(crate) fn materialized_object(&self, path: &Path) -> Option<&MaterializedObject> {
        self.state.materialized_object(path)
    }

    pub(crate) fn pending_materialization_path(&self) -> Option<&Path> {
        self.state.pending_materialization_path()
    }

    pub(crate) fn pending_materialization(&self) -> Option<PendingMaterializationView<'_>> {
        self.state.pending_materialization()
    }

    pub(crate) fn begin_materialization(
        &mut self,
        path: PathBuf,
        descriptor: PersistedDacl,
        marker_path: PathBuf,
        marker_descriptor: PersistedDacl,
        marker_nonce: [u8; 32],
    ) -> Result<(), CapabilityStateStoreError> {
        self.state.begin_materialization(
            path,
            descriptor,
            marker_path,
            marker_descriptor,
            marker_nonce,
        )?;
        self.persist()
    }

    pub(crate) fn resolve_materialization(
        &mut self,
        evidence: Option<MaterializationEvidence>,
    ) -> Result<MaterializationRecovery, CapabilityStateStoreError> {
        let recovery = self.state.resolve_materialization(evidence)?;
        self.persist()?;
        Ok(recovery)
    }

    pub(crate) fn finish(self) -> Result<(), CapabilityStateStoreError> {
        self.lock.release()
    }

    fn persist(&self) -> Result<(), CapabilityStateStoreError> {
        self.store.write_locked(&self.state)
    }
}

impl CapabilityStateLock {
    #[allow(unsafe_code)]
    fn acquire(path: &Path) -> Result<Self, CapabilityStateStoreError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|source| CapabilityStateStoreError::LockOpen {
                path: path.to_path_buf(),
                source,
            })?;
        let mut overlapped = OVERLAPPED::default();
        if unsafe {
            LockFileEx(
                file.as_raw_handle() as _,
                LOCKFILE_EXCLUSIVE_LOCK,
                0,
                u32::MAX,
                u32::MAX,
                &mut overlapped,
            )
        } == 0
        {
            return Err(CapabilityStateStoreError::LockAcquire {
                code: unsafe { GetLastError() },
            });
        }
        Ok(Self {
            file,
            overlapped,
            locked: true,
        })
    }

    #[allow(unsafe_code)]
    pub(crate) fn release(mut self) -> Result<(), CapabilityStateStoreError> {
        if unsafe {
            UnlockFileEx(
                self.file.as_raw_handle() as _,
                0,
                u32::MAX,
                u32::MAX,
                &mut self.overlapped,
            )
        } == 0
        {
            return Err(CapabilityStateStoreError::LockRelease {
                code: unsafe { GetLastError() },
            });
        }
        self.locked = false;
        Ok(())
    }
}

#[allow(unsafe_code)]
impl Drop for CapabilityStateLock {
    fn drop(&mut self) {
        if self.locked {
            unsafe {
                UnlockFileEx(
                    self.file.as_raw_handle() as _,
                    0,
                    u32::MAX,
                    u32::MAX,
                    &mut self.overlapped,
                );
            }
        }
    }
}
