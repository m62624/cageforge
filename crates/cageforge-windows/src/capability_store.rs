// SPDX-License-Identifier: Apache-2.0

//! Serialized multi-process access to protected capability-SID state.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};

use thiserror::Error;
use windows_sys::Win32::Foundation::{ERROR_LOCK_VIOLATION, GetLastError};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, LockFileEx, MOVEFILE_WRITE_THROUGH,
    MoveFileExW, REPLACEFILE_WRITE_THROUGH, ReplaceFileW, UnlockFileEx,
};
use windows_sys::Win32::System::IO::OVERLAPPED;

use crate::capability_state::{
    CAPABILITY_LOCK_NAME, CAPABILITY_STATE_NAME, CapabilityRole, CapabilityState,
    CapabilityStateError, ManagedAclObject, MaterializedObject, PersistedDacl,
    PersistedFileIdentity,
};
use crate::capability_state_runtime::{
    AclMutationRecovery, CapabilityStateTransitionError, MaterializationEvidence,
    MaterializationRecovery, PendingMaterializationRemovalView, PendingMaterializationView,
};
use crate::error::WindowsSetupVerificationError;

const STATE_LOCK_OFFSET: u32 = 0;
const ACTIVE_LIFETIME_LOCK_OFFSET: u32 = 1;
const LOCK_LENGTH: u32 = 1;

pub(crate) struct CapabilityStateStore {
    state_path: PathBuf,
    lock_path: PathBuf,
    owner_sid: String,
}

pub(crate) struct CapabilityStateLock {
    file: File,
    overlapped: OVERLAPPED,
    purpose: &'static str,
    locked: bool,
}

pub(crate) struct CapabilityActiveLease {
    _lock: CapabilityStateLock,
}

pub(crate) struct CapabilityUninstallGuard {
    _lock: CapabilityStateLock,
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
    Transition(#[from] CapabilityStateTransitionError),
    #[error(transparent)]
    Security(#[from] WindowsSetupVerificationError),
    #[error("failed to open protected capability-SID lock file {path:?}: {source}")]
    LockOpen {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to acquire the {purpose} capability lock: Windows error {code}")]
    LockAcquire { purpose: &'static str, code: u32 },
    #[error("failed to release the {purpose} capability lock: Windows error {code}")]
    LockRelease { purpose: &'static str, code: u32 },
    #[error("cannot launch a Windows sandbox while setup uninstall is active")]
    UninstallInProgress,
    #[error("cannot uninstall Windows setup while a sandbox child is active")]
    ActiveChildren,
    #[error("failed to read protected capability-SID state {path:?}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to prepare atomic capability-SID state replacement {path:?}: {source}")]
    ReplacementOpen {
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
    #[error(
        "failed to atomically replace protected capability-SID state {path:?}: Windows error {code}"
    )]
    Replace { path: PathBuf, code: u32 },
    #[error(
        "failed to recover protected capability-SID state from {backup:?} to {state:?}: Windows error {code}"
    )]
    RecoveryMove {
        backup: PathBuf,
        state: PathBuf,
        code: u32,
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

    pub(crate) fn acquire_active_lease(
        &self,
    ) -> Result<CapabilityActiveLease, CapabilityStateStoreError> {
        self.verify_lock_path()?;
        match CapabilityStateLock::acquire(
            &self.lock_path,
            ACTIVE_LIFETIME_LOCK_OFFSET,
            false,
            true,
            "active-sandbox lifetime",
        ) {
            Err(CapabilityStateStoreError::LockAcquire {
                code: ERROR_LOCK_VIOLATION,
                ..
            }) => Err(CapabilityStateStoreError::UninstallInProgress),
            result => result.map(|lock| CapabilityActiveLease { _lock: lock }),
        }
    }

    pub(crate) fn acquire_uninstall_guard(
        &self,
    ) -> Result<CapabilityUninstallGuard, CapabilityStateStoreError> {
        self.verify_lock_path()?;
        match CapabilityStateLock::acquire(
            &self.lock_path,
            ACTIVE_LIFETIME_LOCK_OFFSET,
            true,
            true,
            "setup-uninstall exclusion",
        ) {
            Err(CapabilityStateStoreError::LockAcquire {
                code: ERROR_LOCK_VIOLATION,
                ..
            }) => Err(CapabilityStateStoreError::ActiveChildren),
            result => result.map(|lock| CapabilityUninstallGuard { _lock: lock }),
        }
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
        self.verify_lock_path()?;
        CapabilityStateLock::acquire(
            &self.lock_path,
            STATE_LOCK_OFFSET,
            true,
            false,
            "capability-state mutation",
        )
    }

    fn verify_lock_path(&self) -> Result<(), CapabilityStateStoreError> {
        crate::setup_verification::paths::verify_protected_dacl(
            &self.lock_path,
            &self.owner_sid,
            false,
        )
        .map_err(Into::into)
    }

    fn read_locked(&self) -> Result<CapabilityState, CapabilityStateStoreError> {
        self.recover_missing_state_from_backup()?;
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
        let state = CapabilityState::decode(&bytes)?;
        remove_stale_replacement(&self.state_path.with_extension("json.next"))?;
        remove_stale_replacement(&self.state_path.with_extension("json.backup"))?;
        Ok(state)
    }

    #[allow(unsafe_code)]
    fn write_locked(&self, state: &CapabilityState) -> Result<(), CapabilityStateStoreError> {
        let encoded = state.encode()?;
        let replacement_path = self.state_path.with_extension("json.next");
        let backup_path = self.state_path.with_extension("json.backup");
        verify_existing_regular_replacement(&backup_path)?;
        remove_stale_replacement(&replacement_path)?;
        remove_stale_replacement(&backup_path)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
            .open(&replacement_path)
            .map_err(|source| CapabilityStateStoreError::ReplacementOpen {
                path: replacement_path.clone(),
                source,
            })?;
        file.write_all(&encoded)
            .and_then(|()| file.sync_all())
            .map_err(|source| CapabilityStateStoreError::Write {
                path: replacement_path.clone(),
                source,
            })?;
        drop(file);
        let state_path_wide = wide_path(&self.state_path);
        let replacement_path_wide = wide_path(&replacement_path);
        let backup_path_wide = wide_path(&backup_path);
        if unsafe {
            ReplaceFileW(
                state_path_wide.as_ptr(),
                replacement_path_wide.as_ptr(),
                backup_path_wide.as_ptr(),
                REPLACEFILE_WRITE_THROUGH,
                std::ptr::null(),
                std::ptr::null(),
            )
        } == 0
        {
            let code = unsafe { GetLastError() };
            self.recover_missing_state_from_backup()?;
            return Err(CapabilityStateStoreError::Replace {
                path: self.state_path.clone(),
                code,
            });
        }
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
        if CapabilityState::decode(&actual)? != *state {
            return Err(CapabilityStateStoreError::ReadBackMismatch);
        }
        remove_stale_replacement(&backup_path)
    }

    #[allow(unsafe_code)]
    fn recover_missing_state_from_backup(&self) -> Result<(), CapabilityStateStoreError> {
        match fs::symlink_metadata(&self.state_path) {
            Ok(_) => return Ok(()),
            Err(source) if source.kind() == io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(CapabilityStateStoreError::Read {
                    path: self.state_path.clone(),
                    source,
                });
            }
        }

        let backup_path = self.state_path.with_extension("json.backup");
        crate::setup_verification::paths::verify_protected_dacl(
            &backup_path,
            &self.owner_sid,
            false,
        )?;
        let bytes = fs::read(&backup_path).map_err(|source| CapabilityStateStoreError::Read {
            path: backup_path.clone(),
            source,
        })?;
        let expected = CapabilityState::decode(&bytes)?;
        let backup_path_wide = wide_path(&backup_path);
        let state_path_wide = wide_path(&self.state_path);
        if unsafe {
            MoveFileExW(
                backup_path_wide.as_ptr(),
                state_path_wide.as_ptr(),
                MOVEFILE_WRITE_THROUGH,
            )
        } == 0
        {
            return Err(CapabilityStateStoreError::RecoveryMove {
                backup: backup_path,
                state: self.state_path.clone(),
                code: unsafe { GetLastError() },
            });
        }
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
        if CapabilityState::decode(&actual)? == expected {
            Ok(())
        } else {
            Err(CapabilityStateStoreError::ReadBackMismatch)
        }
    }
}

fn remove_stale_replacement(path: &Path) -> Result<(), CapabilityStateStoreError> {
    match fs::symlink_metadata(path) {
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(CapabilityStateStoreError::ReplacementOpen {
            path: path.to_path_buf(),
            source,
        }),
        Ok(metadata)
            if metadata.is_file()
                && !metadata.file_type().is_symlink()
                && metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0 =>
        {
            fs::remove_file(path).map_err(|source| CapabilityStateStoreError::ReplacementOpen {
                path: path.to_path_buf(),
                source,
            })
        }
        Ok(_) => Err(CapabilityStateStoreError::ReplacementOpen {
            path: path.to_path_buf(),
            source: io::Error::new(
                io::ErrorKind::InvalidData,
                "atomic state replacement path is not a regular file",
            ),
        }),
    }
}

fn verify_existing_regular_replacement(path: &Path) -> Result<(), CapabilityStateStoreError> {
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.is_file()
                && !metadata.file_type().is_symlink()
                && metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0 =>
        {
            Ok(())
        }
        Ok(_) => Err(CapabilityStateStoreError::ReplacementOpen {
            path: path.to_path_buf(),
            source: io::Error::new(
                io::ErrorKind::InvalidData,
                "atomic state replacement path is not a regular non-reparse file",
            ),
        }),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(CapabilityStateStoreError::ReplacementOpen {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn wide_path(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

impl CapabilityStateLock {
    #[allow(unsafe_code)]
    fn acquire(
        path: &Path,
        offset: u32,
        exclusive: bool,
        fail_immediately: bool,
        purpose: &'static str,
    ) -> Result<Self, CapabilityStateStoreError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .open(path)
            .map_err(|source| CapabilityStateStoreError::LockOpen {
                path: path.to_path_buf(),
                source,
            })?;
        let mut overlapped = OVERLAPPED::default();
        overlapped.Anonymous.Anonymous.Offset = offset;
        let mut flags = 0;
        if exclusive {
            flags |= LOCKFILE_EXCLUSIVE_LOCK;
        }
        if fail_immediately {
            flags |= LOCKFILE_FAIL_IMMEDIATELY;
        }
        if unsafe {
            LockFileEx(
                file.as_raw_handle() as _,
                flags,
                0,
                LOCK_LENGTH,
                0,
                &mut overlapped,
            )
        } == 0
        {
            return Err(CapabilityStateStoreError::LockAcquire {
                purpose,
                code: unsafe { GetLastError() },
            });
        }
        Ok(Self {
            file,
            overlapped,
            purpose,
            locked: true,
        })
    }

    #[allow(unsafe_code)]
    pub(crate) fn release(mut self) -> Result<(), CapabilityStateStoreError> {
        if unsafe {
            UnlockFileEx(
                self.file.as_raw_handle() as _,
                0,
                LOCK_LENGTH,
                0,
                &mut self.overlapped,
            )
        } == 0
        {
            return Err(CapabilityStateStoreError::LockRelease {
                purpose: self.purpose,
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
                    LOCK_LENGTH,
                    0,
                    &mut self.overlapped,
                );
            }
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

    pub(crate) fn materialized_objects(&self) -> &[MaterializedObject] {
        self.state.materialized_objects()
    }

    pub(crate) fn filesystem_cleanup_complete(&self) -> bool {
        self.state.filesystem_cleanup_complete()
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

    pub(crate) fn pending_materialization_removal(
        &self,
    ) -> Option<PendingMaterializationRemovalView<'_>> {
        self.state.pending_materialization_removal()
    }

    pub(crate) fn begin_materialization_removal(
        &mut self,
        path: &Path,
    ) -> Result<(), CapabilityStateStoreError> {
        self.state.begin_materialization_removal(path)?;
        self.persist()
    }

    pub(crate) fn arm_materialized_directory_removal(
        &mut self,
        identity: &PersistedFileIdentity,
    ) -> Result<(), CapabilityStateStoreError> {
        self.state.arm_materialized_directory_removal(identity)?;
        self.persist()
    }

    pub(crate) fn resolve_materialization_removal(
        &mut self,
        identity: &PersistedFileIdentity,
    ) -> Result<(), CapabilityStateStoreError> {
        self.state.resolve_materialization_removal(identity)?;
        self.persist()
    }

    pub(crate) fn finish(self) -> Result<(), CapabilityStateStoreError> {
        self.lock.release()
    }

    fn persist(&self) -> Result<(), CapabilityStateStoreError> {
        self.store.write_locked(&self.state)
    }
}
