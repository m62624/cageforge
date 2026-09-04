// SPDX-License-Identifier: Apache-2.0

//! Serialized capability-state model shared by runtime and elevated setup.

use std::collections::BTreeSet;
use std::ffi::c_void;
use std::path::{Path, PathBuf};

use cageforge_path::{NativePathKey, contains_parent_traversal, is_within, paths_equal};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use windows_sys::Win32::Foundation::{GetLastError, HLOCAL, LocalFree};
use windows_sys::Win32::Security::Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidW};
use windows_sys::Win32::Security::{ACL, IsValidAcl, IsValidSid};

pub(crate) const CAPABILITY_STATE_NAME: &str = "capabilities.json";
pub(crate) const CAPABILITY_LOCK_NAME: &str = "capabilities.lock";
pub(crate) const CAPABILITY_STATE_VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct CapabilityState {
    pub(crate) version: u32,
    pub(crate) namespace_sid: String,
    pub(crate) entries: Vec<FilesystemCapability>,
    pub(crate) acl_objects: Vec<ManagedAclObject>,
    pub(crate) pending_acl_mutation: Option<PendingAclMutation>,
    #[serde(default)]
    pub(crate) pending_inherited_acl_release: Option<PendingInheritedAclRelease>,
    pub(crate) materialized_objects: Vec<MaterializedObject>,
    pub(crate) pending_materialization: Option<PendingMaterialization>,
    pub(crate) pending_materialization_removal: Option<PendingMaterializationRemoval>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct FilesystemCapability {
    pub(crate) profile_sha256: String,
    pub(crate) role: CapabilityRole,
    pub(crate) path: PathBuf,
    pub(crate) sid: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct ManagedAclObject {
    pub(crate) path: PathBuf,
    pub(crate) identity: PersistedFileIdentity,
    pub(crate) original: PersistedDacl,
    pub(crate) current: PersistedDacl,
    #[serde(default)]
    pub(crate) restore_parent: Option<ManagedAclParent>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct ManagedAclParent {
    pub(crate) path: PathBuf,
    pub(crate) identity: PersistedFileIdentity,
    pub(crate) release_descriptor: PersistedDacl,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct PendingAclMutation {
    pub(crate) path: PathBuf,
    pub(crate) identity: PersistedFileIdentity,
    pub(crate) before: PersistedDacl,
    pub(crate) after: PersistedDacl,
    pub(crate) prior: Option<ManagedAclObject>,
    pub(crate) next: Option<ManagedAclObject>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct PendingInheritedAclRelease {
    pub(crate) object: ManagedAclObject,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct MaterializedObject {
    pub(crate) path: PathBuf,
    pub(crate) identity: PersistedFileIdentity,
    pub(crate) descriptor: PersistedDacl,
    pub(crate) marker_path: PathBuf,
    pub(crate) marker_identity: PersistedFileIdentity,
    pub(crate) marker_descriptor: PersistedDacl,
    pub(crate) marker_nonce: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct PendingMaterialization {
    pub(crate) path: PathBuf,
    pub(crate) descriptor: PersistedDacl,
    pub(crate) marker_path: PathBuf,
    pub(crate) marker_descriptor: PersistedDacl,
    pub(crate) marker_nonce: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct PendingMaterializationRemoval {
    pub(crate) object: MaterializedObject,
    pub(crate) phase: MaterializationRemovalPhase,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct PersistedFileIdentity {
    pub(crate) volume_serial_number: u64,
    pub(crate) file_id: [u8; 16],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct PersistedDacl {
    pub(crate) bytes: Vec<u8>,
    pub(crate) protected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CapabilityRole {
    ProfileGuard,
    WriteRoot,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MaterializationRemovalPhase {
    MarkerDeleteArmed,
    DirectoryDeleteArmed,
}

struct LocalSid(*mut c_void);

struct LocalWideString(*mut u16);

#[derive(Debug, Error)]
pub(crate) enum CapabilityStateError {
    #[error("failed to generate a cryptographically random capability SID: {source}")]
    Random {
        #[source]
        source: getrandom::Error,
    },
    #[error("failed to decode the capability-SID state: {source}")]
    Decode {
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to encode the capability-SID state: {source}")]
    Encode {
        #[source]
        source: serde_json::Error,
    },
    #[error("capability-SID state version mismatch: expected {expected}, found {actual}")]
    Version { expected: u32, actual: u32 },
    #[error("capability-SID state contains an invalid policy-profile SHA-256 identity")]
    InvalidProfileIdentity,
    #[error(
        "capability-SID state contains an invalid filesystem capability SID: Windows error {code}"
    )]
    InvalidSid { code: u32 },
    #[error("capability-SID state contains a non-canonical filesystem capability SID")]
    NonCanonicalSid,
    #[error("capability-SID state contains an authority outside its installation namespace")]
    ForeignAuthoritySid,
    #[error("capability-SID state repeats one SID across separate authority entries")]
    DuplicateSid,
    #[error("capability-SID state contains a non-absolute root: {path:?}")]
    RelativeRoot { path: PathBuf },
    #[error("capability-SID state contains parent traversal in root {path:?}")]
    ParentTraversal { path: PathBuf },
    #[error("capability-SID state repeats one profile/access/root authority identity")]
    DuplicateAuthority,
    #[error("capability-SID state entries are not in canonical identity order")]
    NonCanonicalOrder,
    #[error("capability-SID state contains an invalid persisted DACL")]
    InvalidDacl,
    #[error("capability-SID state repeats one managed ACL object identity")]
    DuplicateAclObject,
    #[error("capability-SID state managed ACL objects are not in canonical path order")]
    NonCanonicalAclOrder,
    #[error("capability-SID state retains a managed ACL object whose descriptor is unchanged")]
    RedundantAclObject,
    #[error("capability-SID state contains an incomplete or inconsistent ACL mutation journal")]
    InvalidAclMutation,
    #[error("capability-SID state contains an invalid inherited ACL restore dependency")]
    InvalidInheritedAclDependency,
    #[error("capability-SID state repeats one materialized filesystem object")]
    DuplicateMaterializedObject,
    #[error("capability-SID state materialized objects are not in canonical path order")]
    NonCanonicalMaterializedOrder,
    #[error("capability-SID state contains an incomplete materialization record")]
    InvalidMaterialization,
    #[error("capability-SID state contains an incomplete materialization-removal journal")]
    InvalidMaterializationRemoval,
}

impl CapabilityState {
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, CapabilityStateError> {
        let state: Self = serde_json::from_slice(bytes)
            .map_err(|source| CapabilityStateError::Decode { source })?;
        state.validate()?;
        Ok(state)
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, CapabilityStateError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|source| CapabilityStateError::Encode { source })
    }

    pub(crate) fn validate(&self) -> Result<(), CapabilityStateError> {
        if self.version != CAPABILITY_STATE_VERSION {
            return Err(CapabilityStateError::Version {
                expected: CAPABILITY_STATE_VERSION,
                actual: self.version,
            });
        }
        let namespace = canonical_sid(&self.namespace_sid)?;
        if namespace != self.namespace_sid {
            return Err(CapabilityStateError::NonCanonicalSid);
        }
        let mut identities = BTreeSet::new();
        let mut sids = BTreeSet::new();
        let mut previous = None;
        for entry in &self.entries {
            validate_profile_identity(&entry.profile_sha256)?;
            validate_root(&entry.path)?;
            let key = entry_key(entry);
            if previous.as_ref().is_some_and(|previous| previous >= &key) {
                return Err(CapabilityStateError::NonCanonicalOrder);
            }
            previous = Some(key.clone());
            if !identities.insert(key) {
                return Err(CapabilityStateError::DuplicateAuthority);
            }
            let sid = canonical_sid(&entry.sid)?;
            if sid != entry.sid {
                return Err(CapabilityStateError::NonCanonicalSid);
            }
            if !sid.starts_with(&format!("{}-", self.namespace_sid)) {
                return Err(CapabilityStateError::ForeignAuthoritySid);
            }
            if !sids.insert(sid) {
                return Err(CapabilityStateError::DuplicateSid);
            }
        }
        let mut object_paths = BTreeSet::new();
        let mut object_identities = BTreeSet::new();
        let mut previous_object = None;
        for object in &self.acl_objects {
            object.validate()?;
            let key = managed_acl_key(object);
            if previous_object
                .as_ref()
                .is_some_and(|previous| previous >= &key)
            {
                return Err(CapabilityStateError::NonCanonicalAclOrder);
            }
            previous_object = Some(key.clone());
            if !object_paths.insert(key)
                || !object_identities.insert((
                    object.identity.volume_serial_number,
                    object.identity.file_id,
                ))
            {
                return Err(CapabilityStateError::DuplicateAclObject);
            }
        }
        if let Some(pending) = &self.pending_acl_mutation {
            pending.validate(&self.acl_objects)?;
        }
        if let Some(pending) = &self.pending_inherited_acl_release {
            pending.validate(&self.acl_objects)?;
        }
        validate_materialized_objects(&self.materialized_objects)?;
        let pending_journal_count = usize::from(self.pending_acl_mutation.is_some())
            + usize::from(self.pending_inherited_acl_release.is_some())
            + usize::from(self.pending_materialization.is_some())
            + usize::from(self.pending_materialization_removal.is_some());
        if pending_journal_count > 1 {
            return Err(CapabilityStateError::InvalidMaterialization);
        }
        if let Some(pending) = &self.pending_materialization {
            pending.validate(&self.materialized_objects)?;
        }
        if let Some(pending) = &self.pending_materialization_removal {
            pending.validate(&self.materialized_objects)?;
        }
        Ok(())
    }
}

impl ManagedAclObject {
    pub(crate) fn validate(&self) -> Result<(), CapabilityStateError> {
        validate_root(&self.path)?;
        self.original.validate()?;
        self.current.validate()?;
        if self.original == self.current {
            return Err(CapabilityStateError::RedundantAclObject);
        }
        if let Some(parent) = &self.restore_parent {
            parent.validate(&self.path, &self.identity)?;
        }
        Ok(())
    }
}

impl ManagedAclParent {
    fn validate(
        &self,
        child_path: &Path,
        child_identity: &PersistedFileIdentity,
    ) -> Result<(), CapabilityStateError> {
        validate_root(&self.path)?;
        self.release_descriptor.validate()?;
        if paths_equal(child_path, &self.path)
            || !is_within(child_path, &self.path)
            || &self.identity == child_identity
        {
            return Err(CapabilityStateError::InvalidInheritedAclDependency);
        }
        Ok(())
    }
}

impl PendingAclMutation {
    fn validate(&self, objects: &[ManagedAclObject]) -> Result<(), CapabilityStateError> {
        validate_root(&self.path)?;
        self.before.validate()?;
        self.after.validate()?;
        let key = NativePathKey::new(&self.path);
        let current = objects
            .iter()
            .find(|object| NativePathKey::new(&object.path) == key);
        if current != self.prior.as_ref() {
            return Err(CapabilityStateError::InvalidAclMutation);
        }
        if let Some(prior) = &self.prior {
            prior.validate()?;
            if NativePathKey::new(&prior.path) != key
                || prior.identity != self.identity
                || prior.current != self.before
            {
                return Err(CapabilityStateError::InvalidAclMutation);
            }
        }
        let original = self
            .prior
            .as_ref()
            .map_or(&self.before, |object| &object.original);
        match &self.next {
            Some(next) => {
                next.validate()?;
                if NativePathKey::new(&next.path) != key
                    || next.identity != self.identity
                    || &next.original != original
                    || next.current != self.after
                {
                    return Err(CapabilityStateError::InvalidAclMutation);
                }
            }
            None => {
                if self.prior.is_none() || &self.after != original {
                    return Err(CapabilityStateError::InvalidAclMutation);
                }
            }
        }
        Ok(())
    }
}

impl PendingInheritedAclRelease {
    fn validate(&self, objects: &[ManagedAclObject]) -> Result<(), CapabilityStateError> {
        self.object.validate()?;
        if self.object.restore_parent.is_none()
            || objects.iter().find(|object| {
                NativePathKey::new(&object.path) == NativePathKey::new(&self.object.path)
            }) != Some(&self.object)
        {
            return Err(CapabilityStateError::InvalidInheritedAclDependency);
        }
        Ok(())
    }
}

impl MaterializedObject {
    pub(crate) fn validate(&self) -> Result<(), CapabilityStateError> {
        validate_materialization_paths(&self.path, &self.marker_path)?;
        self.descriptor.validate()?;
        self.marker_descriptor.validate()?;
        if self.identity == self.marker_identity || self.marker_nonce.iter().all(|byte| *byte == 0)
        {
            return Err(CapabilityStateError::InvalidMaterialization);
        }
        Ok(())
    }
}

impl PendingMaterialization {
    fn validate(&self, objects: &[MaterializedObject]) -> Result<(), CapabilityStateError> {
        validate_materialization_paths(&self.path, &self.marker_path)?;
        self.descriptor.validate()?;
        self.marker_descriptor.validate()?;
        if self.marker_nonce.iter().all(|byte| *byte == 0)
            || objects
                .iter()
                .any(|object| NativePathKey::new(&object.path) == NativePathKey::new(&self.path))
        {
            return Err(CapabilityStateError::InvalidMaterialization);
        }
        Ok(())
    }
}

impl PendingMaterializationRemoval {
    fn validate(&self, objects: &[MaterializedObject]) -> Result<(), CapabilityStateError> {
        self.object.validate()?;
        let key = NativePathKey::new(&self.object.path);
        if objects
            .iter()
            .find(|object| NativePathKey::new(&object.path) == key)
            != Some(&self.object)
        {
            return Err(CapabilityStateError::InvalidMaterializationRemoval);
        }
        Ok(())
    }
}

impl PersistedDacl {
    #[allow(unsafe_code)]
    pub(crate) fn validate(&self) -> Result<(), CapabilityStateError> {
        if self.bytes.len() < std::mem::size_of::<ACL>() || self.bytes.len() > u16::MAX as usize {
            return Err(CapabilityStateError::InvalidDacl);
        }
        let header = unsafe { self.bytes.as_ptr().cast::<ACL>().read_unaligned() };
        if usize::from(header.AclSize) != self.bytes.len() {
            return Err(CapabilityStateError::InvalidDacl);
        }
        let mut aligned = vec![0u32; self.bytes.len().div_ceil(std::mem::size_of::<u32>())];
        unsafe {
            std::ptr::copy_nonoverlapping(
                self.bytes.as_ptr(),
                aligned.as_mut_ptr().cast::<u8>(),
                self.bytes.len(),
            );
        }
        if unsafe { IsValidAcl(aligned.as_ptr().cast()) } == 0 {
            return Err(CapabilityStateError::InvalidDacl);
        }
        Ok(())
    }
}

#[allow(unsafe_code)]
impl Drop for LocalSid {
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

pub(crate) fn validate_profile_identity(value: &str) -> Result<(), CapabilityStateError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(CapabilityStateError::InvalidProfileIdentity)
    }
}

pub(crate) fn validate_root(path: &Path) -> Result<(), CapabilityStateError> {
    if !path.is_absolute() {
        return Err(CapabilityStateError::RelativeRoot {
            path: path.to_path_buf(),
        });
    }
    if contains_parent_traversal(path) {
        return Err(CapabilityStateError::ParentTraversal {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

pub(crate) fn validate_materialization_paths(
    path: &Path,
    marker_path: &Path,
) -> Result<(), CapabilityStateError> {
    validate_root(path)?;
    validate_root(marker_path)?;
    if marker_path
        .parent()
        .is_none_or(|parent| NativePathKey::new(parent) != NativePathKey::new(path))
    {
        return Err(CapabilityStateError::InvalidMaterialization);
    }
    Ok(())
}

pub(crate) fn authority_key(
    profile_sha256: &str,
    role: &CapabilityRole,
    path: &Path,
) -> (String, u8, NativePathKey) {
    let role = match role {
        CapabilityRole::ProfileGuard => 0,
        CapabilityRole::WriteRoot => 1,
    };
    (profile_sha256.to_string(), role, NativePathKey::new(path))
}

pub(crate) fn entry_key(entry: &FilesystemCapability) -> (String, u8, NativePathKey) {
    authority_key(&entry.profile_sha256, &entry.role, &entry.path)
}

pub(crate) fn managed_acl_key(object: &ManagedAclObject) -> NativePathKey {
    NativePathKey::new(&object.path)
}

pub(crate) fn materialized_object_key(object: &MaterializedObject) -> NativePathKey {
    NativePathKey::new(&object.path)
}

pub(crate) fn validate_materialized_objects(
    objects: &[MaterializedObject],
) -> Result<(), CapabilityStateError> {
    let mut paths = BTreeSet::new();
    let mut identities = BTreeSet::new();
    let mut previous = None;
    for object in objects {
        object.validate()?;
        let key = materialized_object_key(object);
        if previous.as_ref().is_some_and(|previous| previous >= &key) {
            return Err(CapabilityStateError::NonCanonicalMaterializedOrder);
        }
        previous = Some(key.clone());
        if !paths.insert(key)
            || !paths.insert(NativePathKey::new(&object.marker_path))
            || !identities.insert((
                object.identity.volume_serial_number,
                object.identity.file_id,
            ))
            || !identities.insert((
                object.marker_identity.volume_serial_number,
                object.marker_identity.file_id,
            ))
        {
            return Err(CapabilityStateError::DuplicateMaterializedObject);
        }
    }
    Ok(())
}

#[allow(unsafe_code)]
pub(crate) fn canonical_sid(value: &str) -> Result<String, CapabilityStateError> {
    if value.contains('\0') {
        return Err(CapabilityStateError::InvalidSid { code: 0 });
    }
    let value = value
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut sid = std::ptr::null_mut();
    if unsafe { ConvertStringSidToSidW(value.as_ptr(), &mut sid) } == 0 {
        return Err(CapabilityStateError::InvalidSid {
            code: unsafe { GetLastError() },
        });
    }
    let sid = LocalSid(sid);
    if unsafe { IsValidSid(sid.0) } == 0 {
        return Err(CapabilityStateError::InvalidSid { code: 0 });
    }
    let mut canonical = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid.0, &mut canonical) } == 0 {
        return Err(CapabilityStateError::InvalidSid {
            code: unsafe { GetLastError() },
        });
    }
    let canonical = LocalWideString(canonical);
    Ok(wide_string(canonical.0))
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
