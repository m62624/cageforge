// SPDX-License-Identifier: Apache-2.0

//! Runtime transitions for protected Windows capability state.

use std::path::{Path, PathBuf};

use cageforge_path::NativePathKey;
use thiserror::Error;

use crate::capability_state::{
    CapabilityRole, CapabilityState, CapabilityStateError, FilesystemCapability, ManagedAclObject,
    MaterializationRemovalPhase, MaterializedObject, PendingAclMutation, PendingMaterialization,
    PendingMaterializationRemoval, PersistedDacl, PersistedFileIdentity, authority_key,
    canonical_sid, entry_key, managed_acl_key, materialized_object_key,
    validate_materialization_paths, validate_materialized_objects, validate_profile_identity,
    validate_root,
};

const READ_BASE_SUBAUTHORITY: &str = "1";

pub(crate) struct MaterializationEvidence {
    identity: PersistedFileIdentity,
    descriptor: PersistedDacl,
    marker_identity: PersistedFileIdentity,
    marker_descriptor: PersistedDacl,
    marker_nonce: [u8; 32],
}

pub(crate) struct PendingMaterializationView<'state> {
    path: &'state Path,
    descriptor: &'state PersistedDacl,
    marker_path: &'state Path,
    marker_descriptor: &'state PersistedDacl,
    marker_nonce: &'state [u8; 32],
}

pub(crate) struct PendingMaterializationRemovalView<'state> {
    object: &'state MaterializedObject,
    phase: MaterializationRemovalPhase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AclMutationRecovery {
    Prior,
    Next,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MaterializationRecovery {
    Absent,
    Present,
}

#[derive(Debug, Error)]
pub(crate) enum CapabilityStateTransitionError {
    #[error(transparent)]
    State(#[from] CapabilityStateError),
    #[error("capability-SID state repeats one SID across separate authority entries")]
    DuplicateSid,
    #[error("capability-SID state repeats one profile/access/root authority identity")]
    DuplicateAuthority,
    #[error("an ACL mutation journal is already pending for {path:?}")]
    PendingAclMutation { path: PathBuf },
    #[error("no ACL mutation journal is pending")]
    MissingAclMutation,
    #[error("managed ACL object identity changed at {path:?}")]
    AclObjectIdentityMismatch { path: PathBuf },
    #[error("managed ACL state for {path:?} does not match the handle-read descriptor")]
    AclBeforeMismatch { path: PathBuf },
    #[error("pending ACL mutation for {path:?} matches neither its before nor after descriptor")]
    AclMutationDrift { path: PathBuf },
    #[error("a filesystem materialization journal is already pending for {path:?}")]
    PendingMaterialization { path: PathBuf },
    #[error("no filesystem materialization journal is pending")]
    MissingMaterialization,
    #[error("capability-SID state repeats one materialized filesystem object")]
    DuplicateMaterializedObject,
    #[error("capability-SID state contains an incomplete materialization record")]
    InvalidMaterialization,
    #[error("materialized filesystem object at {path:?} failed identity or marker verification")]
    MaterializationDrift { path: PathBuf },
    #[error("a filesystem materialization removal is already pending for {path:?}")]
    PendingMaterializationRemoval { path: PathBuf },
    #[error("no filesystem materialization removal is pending")]
    MissingMaterializationRemoval,
    #[error("capability-SID state contains an incomplete materialization-removal journal")]
    InvalidMaterializationRemoval,
}

impl CapabilityState {
    pub(crate) fn ensure_authority(
        &mut self,
        profile_sha256: &str,
        role: CapabilityRole,
        path: PathBuf,
    ) -> Result<&str, CapabilityStateTransitionError> {
        validate_profile_identity(profile_sha256)?;
        validate_root(&path)?;
        let key = authority_key(profile_sha256, &role, &path);
        if let Some(index) = self
            .entries
            .iter()
            .position(|entry| entry_key(entry) == key)
        {
            return Ok(&self.entries[index].sid);
        }
        let sid = random_authority_sid(&self.namespace_sid)?;
        if self
            .entries
            .iter()
            .any(|entry| entry.sid.eq_ignore_ascii_case(&sid))
        {
            return Err(CapabilityStateTransitionError::DuplicateSid);
        }
        self.entries.push(FilesystemCapability {
            profile_sha256: profile_sha256.to_string(),
            role,
            path,
            sid,
        });
        self.entries.sort_by_key(entry_key);
        self.entries
            .iter()
            .find(|entry| entry_key(entry) == key)
            .map(|entry| entry.sid.as_str())
            .ok_or(CapabilityStateTransitionError::DuplicateAuthority)
    }

    pub(crate) fn authority_sid(
        &self,
        profile_sha256: &str,
        role: &CapabilityRole,
        path: &Path,
    ) -> Option<&str> {
        let key = authority_key(profile_sha256, role, path);
        self.entries
            .iter()
            .find(|entry| entry_key(entry) == key)
            .map(|entry| entry.sid.as_str())
    }

    pub(crate) fn read_base_sid(&self) -> Result<String, CapabilityStateTransitionError> {
        Ok(canonical_sid(&format!(
            "{}-{READ_BASE_SUBAUTHORITY}",
            self.namespace_sid
        ))?)
    }

    pub(crate) fn pending_acl_path(&self) -> Option<&Path> {
        self.pending_acl_mutation
            .as_ref()
            .map(|mutation| mutation.path.as_path())
    }

    pub(crate) fn begin_acl_mutation(
        &mut self,
        path: PathBuf,
        identity: PersistedFileIdentity,
        before: PersistedDacl,
        after: PersistedDacl,
    ) -> Result<(), CapabilityStateTransitionError> {
        if let Some(pending) = &self.pending_acl_mutation {
            return Err(CapabilityStateTransitionError::PendingAclMutation {
                path: pending.path.clone(),
            });
        }
        if let Some(pending) = &self.pending_materialization {
            return Err(CapabilityStateTransitionError::PendingMaterialization {
                path: pending.path.clone(),
            });
        }
        if let Some(pending) = &self.pending_materialization_removal {
            return Err(
                CapabilityStateTransitionError::PendingMaterializationRemoval {
                    path: pending.object.path.clone(),
                },
            );
        }
        validate_root(&path)?;
        before.validate()?;
        after.validate()?;
        let key = NativePathKey::new(&path);
        let prior = self
            .acl_objects
            .iter()
            .find(|object| NativePathKey::new(&object.path) == key)
            .cloned();
        if let Some(object) = &prior {
            if object.identity != identity {
                return Err(CapabilityStateTransitionError::AclObjectIdentityMismatch { path });
            }
            if object.current != before {
                return Err(CapabilityStateTransitionError::AclBeforeMismatch { path });
            }
        }
        let original = prior
            .as_ref()
            .map_or_else(|| before.clone(), |object| object.original.clone());
        let next = if after == original {
            None
        } else {
            Some(ManagedAclObject {
                path: path.clone(),
                identity: identity.clone(),
                original,
                current: after.clone(),
            })
        };
        self.pending_acl_mutation = Some(PendingAclMutation {
            path,
            identity,
            before,
            after,
            prior,
            next,
        });
        self.validate()
            .map_err(CapabilityStateTransitionError::from)
    }

    pub(crate) fn resolve_acl_mutation(
        &mut self,
        identity: &PersistedFileIdentity,
        actual: &PersistedDacl,
    ) -> Result<AclMutationRecovery, CapabilityStateTransitionError> {
        actual.validate()?;
        let pending = self
            .pending_acl_mutation
            .take()
            .ok_or(CapabilityStateTransitionError::MissingAclMutation)?;
        if &pending.identity != identity {
            let path = pending.path.clone();
            self.pending_acl_mutation = Some(pending);
            return Err(CapabilityStateTransitionError::AclObjectIdentityMismatch { path });
        }
        let recovery = if actual == &pending.before {
            replace_managed_acl_object(&mut self.acl_objects, &pending.path, pending.prior);
            AclMutationRecovery::Prior
        } else if actual == &pending.after {
            replace_managed_acl_object(&mut self.acl_objects, &pending.path, pending.next);
            AclMutationRecovery::Next
        } else {
            let path = pending.path.clone();
            self.pending_acl_mutation = Some(pending);
            return Err(CapabilityStateTransitionError::AclMutationDrift { path });
        };
        self.acl_objects.sort_by_key(managed_acl_key);
        self.validate()
            .map_err(CapabilityStateTransitionError::from)?;
        Ok(recovery)
    }

    pub(crate) fn managed_acl_objects(&self) -> &[ManagedAclObject] {
        &self.acl_objects
    }

    pub(crate) fn materialized_object(&self, path: &Path) -> Option<&MaterializedObject> {
        let key = NativePathKey::new(path);
        self.materialized_objects
            .iter()
            .find(|object| NativePathKey::new(&object.path) == key)
    }

    pub(crate) fn materialized_objects(&self) -> &[MaterializedObject] {
        &self.materialized_objects
    }

    pub(crate) fn filesystem_cleanup_complete(&self) -> bool {
        self.acl_objects.is_empty()
            && self.pending_acl_mutation.is_none()
            && self.materialized_objects.is_empty()
            && self.pending_materialization.is_none()
            && self.pending_materialization_removal.is_none()
    }

    pub(crate) fn pending_materialization(&self) -> Option<PendingMaterializationView<'_>> {
        self.pending_materialization
            .as_ref()
            .map(|pending| PendingMaterializationView {
                path: &pending.path,
                descriptor: &pending.descriptor,
                marker_path: &pending.marker_path,
                marker_descriptor: &pending.marker_descriptor,
                marker_nonce: &pending.marker_nonce,
            })
    }

    pub(crate) fn begin_materialization(
        &mut self,
        path: PathBuf,
        descriptor: PersistedDacl,
        marker_path: PathBuf,
        marker_descriptor: PersistedDacl,
        marker_nonce: [u8; 32],
    ) -> Result<(), CapabilityStateTransitionError> {
        if let Some(pending) = &self.pending_acl_mutation {
            return Err(CapabilityStateTransitionError::PendingAclMutation {
                path: pending.path.clone(),
            });
        }
        if let Some(pending) = &self.pending_materialization {
            return Err(CapabilityStateTransitionError::PendingMaterialization {
                path: pending.path.clone(),
            });
        }
        if let Some(pending) = &self.pending_materialization_removal {
            return Err(
                CapabilityStateTransitionError::PendingMaterializationRemoval {
                    path: pending.object.path.clone(),
                },
            );
        }
        if self.materialized_object(&path).is_some() {
            return Err(CapabilityStateTransitionError::DuplicateMaterializedObject);
        }
        validate_materialization_paths(&path, &marker_path)?;
        descriptor.validate()?;
        marker_descriptor.validate()?;
        if marker_nonce.iter().all(|byte| *byte == 0) {
            return Err(CapabilityStateTransitionError::InvalidMaterialization);
        }
        self.pending_materialization = Some(PendingMaterialization {
            path,
            descriptor,
            marker_path,
            marker_descriptor,
            marker_nonce,
        });
        self.validate()
            .map_err(CapabilityStateTransitionError::from)
    }

    pub(crate) fn resolve_materialization(
        &mut self,
        evidence: Option<MaterializationEvidence>,
    ) -> Result<MaterializationRecovery, CapabilityStateTransitionError> {
        let pending = self
            .pending_materialization
            .as_ref()
            .ok_or(CapabilityStateTransitionError::MissingMaterialization)?;
        match evidence {
            None => {
                self.pending_materialization = None;
                Ok(MaterializationRecovery::Absent)
            }
            Some(evidence)
                if evidence.descriptor == pending.descriptor
                    && evidence.marker_descriptor == pending.marker_descriptor
                    && evidence.marker_nonce == pending.marker_nonce =>
            {
                let candidate = MaterializedObject {
                    path: pending.path.clone(),
                    identity: evidence.identity,
                    descriptor: evidence.descriptor,
                    marker_path: pending.marker_path.clone(),
                    marker_identity: evidence.marker_identity,
                    marker_descriptor: evidence.marker_descriptor,
                    marker_nonce: evidence.marker_nonce,
                };
                let mut next = self.materialized_objects.clone();
                next.push(candidate);
                next.sort_by_key(materialized_object_key);
                validate_materialized_objects(&next).map_err(|_| {
                    CapabilityStateTransitionError::MaterializationDrift {
                        path: pending.path.clone(),
                    }
                })?;
                self.materialized_objects = next;
                self.pending_materialization = None;
                Ok(MaterializationRecovery::Present)
            }
            Some(_) => Err(CapabilityStateTransitionError::MaterializationDrift {
                path: pending.path.clone(),
            }),
        }
    }

    pub(crate) fn pending_materialization_removal(
        &self,
    ) -> Option<PendingMaterializationRemovalView<'_>> {
        self.pending_materialization_removal
            .as_ref()
            .map(|pending| PendingMaterializationRemovalView {
                object: &pending.object,
                phase: pending.phase,
            })
    }

    pub(crate) fn begin_materialization_removal(
        &mut self,
        path: &Path,
    ) -> Result<(), CapabilityStateTransitionError> {
        if let Some(pending) = &self.pending_acl_mutation {
            return Err(CapabilityStateTransitionError::PendingAclMutation {
                path: pending.path.clone(),
            });
        }
        if let Some(pending) = &self.pending_materialization {
            return Err(CapabilityStateTransitionError::PendingMaterialization {
                path: pending.path.clone(),
            });
        }
        if let Some(pending) = &self.pending_materialization_removal {
            return Err(
                CapabilityStateTransitionError::PendingMaterializationRemoval {
                    path: pending.object.path.clone(),
                },
            );
        }
        let key = NativePathKey::new(path);
        let object = self
            .materialized_objects
            .iter()
            .find(|object| NativePathKey::new(&object.path) == key)
            .cloned()
            .ok_or_else(|| CapabilityStateTransitionError::MaterializationDrift {
                path: path.to_path_buf(),
            })?;
        self.pending_materialization_removal = Some(PendingMaterializationRemoval {
            object,
            phase: MaterializationRemovalPhase::MarkerDeleteArmed,
        });
        self.validate()
            .map_err(CapabilityStateTransitionError::from)
    }

    pub(crate) fn arm_materialized_directory_removal(
        &mut self,
        identity: &PersistedFileIdentity,
    ) -> Result<(), CapabilityStateTransitionError> {
        let pending = self
            .pending_materialization_removal
            .as_mut()
            .ok_or(CapabilityStateTransitionError::MissingMaterializationRemoval)?;
        if pending.phase != MaterializationRemovalPhase::MarkerDeleteArmed
            || &pending.object.identity != identity
        {
            return Err(CapabilityStateTransitionError::InvalidMaterializationRemoval);
        }
        pending.phase = MaterializationRemovalPhase::DirectoryDeleteArmed;
        self.validate()
            .map_err(CapabilityStateTransitionError::from)
    }

    pub(crate) fn resolve_materialization_removal(
        &mut self,
        identity: &PersistedFileIdentity,
    ) -> Result<(), CapabilityStateTransitionError> {
        let pending = self
            .pending_materialization_removal
            .as_ref()
            .ok_or(CapabilityStateTransitionError::MissingMaterializationRemoval)?;
        if pending.phase != MaterializationRemovalPhase::DirectoryDeleteArmed
            || &pending.object.identity != identity
        {
            return Err(CapabilityStateTransitionError::InvalidMaterializationRemoval);
        }
        let path = pending.object.path.clone();
        let key = NativePathKey::new(&path);
        self.materialized_objects
            .retain(|object| NativePathKey::new(&object.path) != key);
        self.pending_materialization_removal = None;
        self.validate()
            .map_err(CapabilityStateTransitionError::from)
    }
}

impl ManagedAclObject {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn identity(&self) -> &PersistedFileIdentity {
        &self.identity
    }

    pub(crate) fn original(&self) -> &PersistedDacl {
        &self.original
    }

    pub(crate) fn current(&self) -> &PersistedDacl {
        &self.current
    }
}

impl MaterializedObject {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn identity(&self) -> &PersistedFileIdentity {
        &self.identity
    }

    pub(crate) fn descriptor(&self) -> &PersistedDacl {
        &self.descriptor
    }

    pub(crate) fn marker_path(&self) -> &Path {
        &self.marker_path
    }

    pub(crate) fn marker_identity(&self) -> &PersistedFileIdentity {
        &self.marker_identity
    }

    pub(crate) fn marker_descriptor(&self) -> &PersistedDacl {
        &self.marker_descriptor
    }

    pub(crate) const fn marker_nonce(&self) -> &[u8; 32] {
        &self.marker_nonce
    }
}

impl MaterializationEvidence {
    pub(crate) fn new(
        identity: PersistedFileIdentity,
        descriptor: PersistedDacl,
        marker_identity: PersistedFileIdentity,
        marker_descriptor: PersistedDacl,
        marker_nonce: [u8; 32],
    ) -> Self {
        Self {
            identity,
            descriptor,
            marker_identity,
            marker_descriptor,
            marker_nonce,
        }
    }
}

impl PendingMaterializationView<'_> {
    pub(crate) fn path(&self) -> &Path {
        self.path
    }

    pub(crate) const fn descriptor(&self) -> &PersistedDacl {
        self.descriptor
    }

    pub(crate) fn marker_path(&self) -> &Path {
        self.marker_path
    }

    pub(crate) const fn marker_descriptor(&self) -> &PersistedDacl {
        self.marker_descriptor
    }

    pub(crate) const fn marker_nonce(&self) -> &[u8; 32] {
        self.marker_nonce
    }
}

impl PendingMaterializationRemovalView<'_> {
    pub(crate) const fn object(&self) -> &MaterializedObject {
        self.object
    }

    pub(crate) const fn phase(&self) -> MaterializationRemovalPhase {
        self.phase
    }
}

impl PersistedFileIdentity {
    pub(crate) const fn new(volume_serial_number: u64, file_id: [u8; 16]) -> Self {
        Self {
            volume_serial_number,
            file_id,
        }
    }
}

impl PersistedDacl {
    pub(crate) fn new(bytes: Vec<u8>, protected: bool) -> Result<Self, CapabilityStateError> {
        let snapshot = Self { bytes, protected };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) const fn is_protected(&self) -> bool {
        self.protected
    }
}

fn replace_managed_acl_object(
    objects: &mut Vec<ManagedAclObject>,
    path: &Path,
    replacement: Option<ManagedAclObject>,
) {
    let key = NativePathKey::new(path);
    objects.retain(|object| NativePathKey::new(&object.path) != key);
    if let Some(replacement) = replacement {
        objects.push(replacement);
    }
}

fn random_authority_sid(namespace: &str) -> Result<String, CapabilityStateError> {
    let mut random = [0u8; 8];
    getrandom::fill(&mut random).map_err(|source| CapabilityStateError::Random { source })?;
    let first = u32::from_le_bytes([random[0], random[1], random[2], random[3]]);
    let second = u32::from_le_bytes([random[4], random[5], random[6], random[7]]);
    Ok(format!("{namespace}-{first}-{second}"))
}

#[cfg(test)]
mod tests {
    use std::mem::size_of;
    use std::path::PathBuf;

    use pretty_assertions::{assert_eq, assert_ne};
    use windows_sys::Win32::Security::{ACL, ACL_REVISION, ACL_REVISION_DS, InitializeAcl};

    use crate::capability_state::CAPABILITY_STATE_VERSION;

    use super::{
        AclMutationRecovery, CapabilityRole, CapabilityState, CapabilityStateTransitionError,
        MaterializationEvidence, MaterializationRecovery, MaterializationRemovalPhase,
        PersistedDacl, PersistedFileIdentity,
    };

    const PROFILE_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const PROFILE_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn fresh_state() -> CapabilityState {
        let state = CapabilityState {
            version: CAPABILITY_STATE_VERSION,
            namespace_sid: "S-1-5-21-1-2-3-4".to_string(),
            entries: Vec::new(),
            acl_objects: Vec::new(),
            pending_acl_mutation: None,
            materialized_objects: Vec::new(),
            pending_materialization: None,
            pending_materialization_removal: None,
        };
        state.validate().expect("valid fresh capability state");
        state
    }

    #[test]
    fn equivalent_windows_roots_share_one_profile_authority() {
        let mut state = fresh_state();
        let first = state
            .ensure_authority(
                PROFILE_A,
                CapabilityRole::WriteRoot,
                PathBuf::from(r"C:\Workspace"),
            )
            .expect("first authority")
            .to_string();
        let second = state
            .ensure_authority(
                PROFILE_A,
                CapabilityRole::WriteRoot,
                PathBuf::from(r"c:/workspace"),
            )
            .expect("equivalent authority")
            .to_string();

        assert_eq!(first, second);
        assert_eq!(state.entries.len(), 1);
    }

    #[test]
    fn different_policy_profiles_cannot_share_path_authority() {
        let mut state = fresh_state();
        let first = state
            .ensure_authority(
                PROFILE_A,
                CapabilityRole::ProfileGuard,
                PathBuf::from(r"C:\Workspace"),
            )
            .expect("first profile authority")
            .to_string();
        let second = state
            .ensure_authority(
                PROFILE_B,
                CapabilityRole::ProfileGuard,
                PathBuf::from(r"C:\Workspace"),
            )
            .expect("second profile authority")
            .to_string();

        assert_ne!(first, second);
    }

    #[test]
    fn installation_read_base_is_stable_and_not_a_profile_authority() {
        let mut state = fresh_state();
        let read_base = state.read_base_sid().expect("read-base SID");
        let repeated = state.read_base_sid().expect("repeated read-base SID");
        let profile = state
            .ensure_authority(
                PROFILE_A,
                CapabilityRole::ProfileGuard,
                PathBuf::from(r"C:\Workspace"),
            )
            .expect("profile guard");

        assert_eq!(read_base, repeated);
        assert_ne!(read_base, profile);
        assert!(read_base.starts_with(&format!("{}-", state.namespace_sid)));
    }

    #[test]
    fn durable_state_round_trip_preserves_canonical_identity() {
        let mut expected = fresh_state();
        expected
            .ensure_authority(
                PROFILE_A,
                CapabilityRole::WriteRoot,
                PathBuf::from(r"D:\Build"),
            )
            .expect("write authority");
        let encoded = expected.encode().expect("encode capability state");
        let actual = CapabilityState::decode(&encoded).expect("decode capability state");

        assert_eq!(actual, expected);
    }

    #[test]
    fn completed_acl_journal_commits_only_the_after_descriptor() {
        let mut state = fresh_state();
        let identity = PersistedFileIdentity::new(7, [8; 16]);
        let before = empty_dacl(ACL_REVISION, false);
        let after = empty_dacl(ACL_REVISION, true);
        state
            .begin_acl_mutation(
                PathBuf::from(r"C:\Workspace"),
                identity.clone(),
                before,
                after.clone(),
            )
            .expect("begin ACL journal");

        assert_eq!(
            state
                .resolve_acl_mutation(&identity, &after)
                .expect("commit after descriptor"),
            AclMutationRecovery::Next
        );
        assert!(state.pending_acl_path().is_none());
        assert_eq!(state.acl_objects.len(), 1);
        assert_eq!(state.acl_objects[0].current, after);
        CapabilityState::decode(&state.encode().expect("encode committed state"))
            .expect("decode committed state");
    }

    #[test]
    fn unapplied_acl_journal_keeps_the_prior_state() {
        let mut state = fresh_state();
        let identity = PersistedFileIdentity::new(9, [10; 16]);
        let before = empty_dacl(ACL_REVISION, false);
        state
            .begin_acl_mutation(
                PathBuf::from(r"C:\Workspace"),
                identity.clone(),
                before.clone(),
                empty_dacl(ACL_REVISION, true),
            )
            .expect("begin ACL journal");

        assert_eq!(
            state
                .resolve_acl_mutation(&identity, &before)
                .expect("retain prior descriptor"),
            AclMutationRecovery::Prior
        );
        assert!(state.pending_acl_path().is_none());
        assert!(state.acl_objects.is_empty());
    }

    #[test]
    fn acl_journal_rejects_descriptor_drift_without_guessing() {
        let mut state = fresh_state();
        let identity = PersistedFileIdentity::new(11, [12; 16]);
        state
            .begin_acl_mutation(
                PathBuf::from(r"C:\Workspace"),
                identity.clone(),
                empty_dacl(ACL_REVISION, false),
                empty_dacl(ACL_REVISION, true),
            )
            .expect("begin ACL journal");

        assert!(matches!(
            state.resolve_acl_mutation(&identity, &empty_dacl(ACL_REVISION_DS, false)),
            Err(CapabilityStateTransitionError::AclMutationDrift { .. })
        ));
        assert_eq!(
            state.pending_acl_path(),
            Some(PathBuf::from(r"C:\Workspace").as_path())
        );
    }

    #[test]
    fn exact_materialization_evidence_commits_and_clears_the_journal() {
        let mut state = fresh_state();
        let descriptor = empty_dacl(ACL_REVISION, true);
        let marker_descriptor = empty_dacl(ACL_REVISION_DS, true);
        let nonce = [13; 32];
        begin_materialization(
            &mut state,
            descriptor.clone(),
            marker_descriptor.clone(),
            nonce,
        );

        let recovery = state
            .resolve_materialization(Some(MaterializationEvidence::new(
                PersistedFileIdentity::new(14, [15; 16]),
                descriptor,
                PersistedFileIdentity::new(14, [16; 16]),
                marker_descriptor,
                nonce,
            )))
            .expect("commit matching materialization");

        assert_eq!(recovery, MaterializationRecovery::Present);
        assert!(state.pending_materialization().is_none());
        assert_eq!(state.materialized_objects.len(), 1);
        CapabilityState::decode(&state.encode().expect("encode committed state"))
            .expect("decode committed state");
    }

    #[test]
    fn absent_materialization_clears_the_journal_without_adopting_an_object() {
        let mut state = fresh_state();
        begin_materialization(
            &mut state,
            empty_dacl(ACL_REVISION, true),
            empty_dacl(ACL_REVISION_DS, true),
            [17; 32],
        );

        assert_eq!(
            state
                .resolve_materialization(None)
                .expect("resolve absent materialization"),
            MaterializationRecovery::Absent
        );
        assert!(state.pending_materialization().is_none());
        assert!(state.materialized_objects.is_empty());
    }

    #[test]
    fn materialization_drift_preserves_the_pending_journal() {
        let mut state = fresh_state();
        let descriptor = empty_dacl(ACL_REVISION, true);
        let marker_descriptor = empty_dacl(ACL_REVISION_DS, true);
        begin_materialization(
            &mut state,
            descriptor.clone(),
            marker_descriptor.clone(),
            [18; 32],
        );

        assert!(matches!(
            state.resolve_materialization(Some(MaterializationEvidence::new(
                PersistedFileIdentity::new(19, [20; 16]),
                descriptor,
                PersistedFileIdentity::new(19, [21; 16]),
                marker_descriptor,
                [22; 32],
            ))),
            Err(CapabilityStateTransitionError::MaterializationDrift { .. })
        ));
        assert_eq!(
            state
                .pending_materialization()
                .expect("pending journal after drift")
                .path(),
            PathBuf::from(r"C:\Workspace\missing").as_path()
        );
        assert!(state.materialized_objects.is_empty());
    }

    #[test]
    fn duplicate_materialization_identity_fails_without_mutating_state() {
        let mut state = fresh_state();
        let descriptor = empty_dacl(ACL_REVISION, true);
        let marker_descriptor = empty_dacl(ACL_REVISION_DS, true);
        let nonce = [23; 32];
        begin_materialization(
            &mut state,
            descriptor.clone(),
            marker_descriptor.clone(),
            nonce,
        );
        let identity = PersistedFileIdentity::new(24, [25; 16]);

        assert!(matches!(
            state.resolve_materialization(Some(MaterializationEvidence::new(
                identity.clone(),
                descriptor,
                identity,
                marker_descriptor,
                nonce,
            ))),
            Err(CapabilityStateTransitionError::MaterializationDrift { .. })
        ));
        assert!(state.pending_materialization().is_some());
        assert!(state.materialized_objects.is_empty());
    }

    #[test]
    fn zero_materialization_nonce_is_rejected_before_journaling() {
        let mut state = fresh_state();

        assert!(matches!(
            state.begin_materialization(
                PathBuf::from(r"C:\Workspace\missing"),
                empty_dacl(ACL_REVISION, true),
                PathBuf::from(r"C:\Workspace\missing\.cageforge-materialized-path"),
                empty_dacl(ACL_REVISION_DS, true),
                [0; 32],
            ),
            Err(CapabilityStateTransitionError::InvalidMaterialization)
        ));
        assert!(state.pending_materialization().is_none());
    }

    #[test]
    fn materialization_removal_advances_only_after_each_durable_phase() {
        let mut state = fresh_state();
        let identity = commit_materialization(&mut state);
        state
            .begin_materialization_removal(PathBuf::from(r"C:\Workspace\missing").as_path())
            .expect("arm marker removal");

        let pending = state
            .pending_materialization_removal()
            .expect("pending marker removal");
        assert_eq!(
            pending.phase(),
            MaterializationRemovalPhase::MarkerDeleteArmed
        );
        assert_eq!(pending.object().identity(), &identity);
        let encoded = state.encode().expect("encode armed marker removal");
        state = CapabilityState::decode(&encoded).expect("decode armed marker removal");

        state
            .arm_materialized_directory_removal(&identity)
            .expect("arm directory removal");
        assert_eq!(
            state
                .pending_materialization_removal()
                .expect("pending directory removal")
                .phase(),
            MaterializationRemovalPhase::DirectoryDeleteArmed
        );
        state
            .resolve_materialization_removal(&identity)
            .expect("commit directory removal");
        assert!(state.pending_materialization_removal().is_none());
        assert!(state.materialized_objects().is_empty());
    }

    #[test]
    fn materialization_removal_rejects_replaced_identity_without_clearing_state() {
        let mut state = fresh_state();
        let identity = commit_materialization(&mut state);
        state
            .begin_materialization_removal(PathBuf::from(r"C:\Workspace\missing").as_path())
            .expect("arm marker removal");

        assert!(matches!(
            state.arm_materialized_directory_removal(&PersistedFileIdentity::new(31, [32; 16])),
            Err(CapabilityStateTransitionError::InvalidMaterializationRemoval)
        ));
        assert_eq!(
            state
                .pending_materialization_removal()
                .expect("journal retained after drift")
                .phase(),
            MaterializationRemovalPhase::MarkerDeleteArmed
        );
        assert_eq!(state.materialized_objects()[0].identity(), &identity);
    }

    fn begin_materialization(
        state: &mut CapabilityState,
        descriptor: PersistedDacl,
        marker_descriptor: PersistedDacl,
        nonce: [u8; 32],
    ) {
        state
            .begin_materialization(
                PathBuf::from(r"C:\Workspace\missing"),
                descriptor,
                PathBuf::from(r"C:\Workspace\missing\.cageforge-materialized-path"),
                marker_descriptor,
                nonce,
            )
            .expect("begin materialization journal");
    }

    fn commit_materialization(state: &mut CapabilityState) -> PersistedFileIdentity {
        let descriptor = empty_dacl(ACL_REVISION, true);
        let marker_descriptor = empty_dacl(ACL_REVISION_DS, true);
        let identity = PersistedFileIdentity::new(27, [28; 16]);
        begin_materialization(
            state,
            descriptor.clone(),
            marker_descriptor.clone(),
            [29; 32],
        );
        state
            .resolve_materialization(Some(MaterializationEvidence::new(
                identity.clone(),
                descriptor,
                PersistedFileIdentity::new(27, [30; 16]),
                marker_descriptor,
                [29; 32],
            )))
            .expect("commit materialization");
        identity
    }

    #[allow(unsafe_code)]
    fn empty_dacl(revision: u32, protected: bool) -> PersistedDacl {
        let byte_length = size_of::<ACL>();
        let mut aligned = vec![0u32; byte_length.div_ceil(size_of::<u32>())];
        assert_ne!(
            unsafe { InitializeAcl(aligned.as_mut_ptr().cast(), byte_length as u32, revision) },
            0
        );
        let bytes = unsafe {
            std::slice::from_raw_parts(aligned.as_ptr().cast::<u8>(), byte_length).to_vec()
        };
        PersistedDacl::new(bytes, protected).expect("valid empty DACL")
    }
}
