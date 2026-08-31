// SPDX-License-Identifier: Apache-2.0

//! Serialized multi-process access to protected capability-SID state.

use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use thiserror::Error;
use windows_sys::Win32::Foundation::{ERROR_LOCK_VIOLATION, GetLastError};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, MOVEFILE_WRITE_THROUGH,
    MoveFileExW, REPLACEFILE_WRITE_THROUGH, ReplaceFileW,
};

use crate::capability::lock::{CapabilityLock, CapabilityLockError};
use crate::capability::state::{
    CAPABILITY_LOCK_NAME, CAPABILITY_STATE_NAME, CapabilityRole, CapabilityState,
    CapabilityStateError, ManagedAclObject, ManagedAclParent, MaterializedObject, PersistedDacl,
    PersistedFileIdentity,
};
use crate::capability::state_runtime::{
    AclMutationRecovery, CapabilityStateTransitionError, InheritedAclReleaseRecovery,
    MaterializationEvidence, MaterializationRecovery, PendingMaterializationRemovalView,
    PendingMaterializationView,
};
use crate::error::WindowsSetupVerificationError;
use crate::filesystem::path::{ValidatedPath, ValidatedPathError};

pub(crate) struct CapabilityStateStore {
    state_path: PathBuf,
    lock_path: PathBuf,
    owner_sid: String,
}

pub(crate) struct CapabilityActiveLease {
    _lock: CapabilityLock,
}

pub(crate) struct CapabilityUninstallGuard {
    lock: CapabilityLock,
}

pub(crate) struct CapabilityStateSession<'store> {
    store: &'store CapabilityStateStore,
    lock: CapabilityLock,
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
    #[error(transparent)]
    Lock(#[from] CapabilityLockError),
    #[error("cannot launch a Windows sandbox while setup uninstall is active")]
    UninstallInProgress,
    #[error("cannot uninstall Windows setup while a sandbox child is active")]
    ActiveChildren,
    #[error("protected capability-state path {path:?} is unsafe: {source}")]
    UnsafeProtectedPath {
        path: PathBuf,
        #[source]
        source: ValidatedPathError,
    },
    #[error("failed to clone the pinned protected capability-state handle {path:?}: {source}")]
    ProtectedHandleClone {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
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
        let file = self.open_protected_file(&self.lock_path)?;
        match CapabilityLock::acquire_file(file, 1, false, true, "active-sandbox lifetime") {
            Err(CapabilityLockError::Acquire {
                code: ERROR_LOCK_VIOLATION,
                ..
            }) => Err(CapabilityStateStoreError::UninstallInProgress),
            Err(error) => Err(error.into()),
            Ok(lock) => Ok(CapabilityActiveLease { _lock: lock }),
        }
    }

    pub(crate) fn acquire_uninstall_guard(
        &self,
    ) -> Result<CapabilityUninstallGuard, CapabilityStateStoreError> {
        let file = self.open_protected_file(&self.lock_path)?;
        match CapabilityLock::acquire_file(file, 1, true, true, "setup-uninstall exclusion") {
            Err(CapabilityLockError::Acquire {
                code: ERROR_LOCK_VIOLATION,
                ..
            }) => Err(CapabilityStateStoreError::ActiveChildren),
            Err(error) => Err(error.into()),
            Ok(lock) => Ok(CapabilityUninstallGuard { lock }),
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

    fn lock(&self) -> Result<CapabilityLock, CapabilityStateStoreError> {
        let file = self.open_protected_file(&self.lock_path)?;
        CapabilityLock::acquire_file(file, 0, true, false, "capability-state mutation")
            .map_err(Into::into)
    }

    fn open_protected_file(&self, path: &Path) -> Result<std::fs::File, CapabilityStateStoreError> {
        let pinned = ValidatedPath::open_file_for_readback(path).map_err(|source| {
            CapabilityStateStoreError::UnsafeProtectedPath {
                path: path.to_path_buf(),
                source,
            }
        })?;
        crate::setup::verification::paths::verify_protected_dacl(path, &self.owner_sid, false)?;
        pinned
            .try_clone_file()
            .map_err(|source| CapabilityStateStoreError::ProtectedHandleClone {
                path: path.to_path_buf(),
                source,
            })
    }

    fn read_locked(&self) -> Result<CapabilityState, CapabilityStateStoreError> {
        self.recover_missing_state_from_backup()?;
        let mut file = self.open_protected_file(&self.state_path)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|source| CapabilityStateStoreError::Read {
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
        let mut file = self.open_protected_file(&self.state_path)?;
        let mut actual = Vec::new();
        file.read_to_end(&mut actual)
            .map_err(|source| CapabilityStateStoreError::Read {
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
        let mut file = self.open_protected_file(&backup_path)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|source| CapabilityStateStoreError::Read {
                path: backup_path.clone(),
                source,
            })?;
        let expected = CapabilityState::decode(&bytes)?;
        drop(file);
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
        let mut file = self.open_protected_file(&self.state_path)?;
        let mut actual = Vec::new();
        file.read_to_end(&mut actual)
            .map_err(|source| CapabilityStateStoreError::Read {
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

impl CapabilityUninstallGuard {
    pub(crate) fn release(self) {
        drop(self.lock);
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

    pub(crate) fn pending_inherited_acl_release(&self) -> Option<&ManagedAclObject> {
        self.state.pending_inherited_acl_release()
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

    pub(crate) fn begin_inherited_acl_mutation(
        &mut self,
        path: PathBuf,
        identity: PersistedFileIdentity,
        before: PersistedDacl,
        after: PersistedDacl,
        parent: ManagedAclParent,
    ) -> Result<(), CapabilityStateStoreError> {
        self.state
            .begin_inherited_acl_mutation(path, identity, before, after, parent)?;
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

    pub(crate) fn begin_inherited_acl_release(
        &mut self,
        path: &Path,
        identity: &PersistedFileIdentity,
    ) -> Result<(), CapabilityStateStoreError> {
        self.state.begin_inherited_acl_release(path, identity)?;
        self.persist()
    }

    pub(crate) fn resolve_inherited_acl_release(
        &mut self,
        identity: &PersistedFileIdentity,
        recovery: InheritedAclReleaseRecovery,
    ) -> Result<(), CapabilityStateStoreError> {
        self.state
            .resolve_inherited_acl_release(identity, recovery)?;
        self.persist()
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
        drop(self.lock);
        Ok(())
    }

    fn persist(&self) -> Result<(), CapabilityStateStoreError> {
        self.store.write_locked(&self.state)
    }
}
