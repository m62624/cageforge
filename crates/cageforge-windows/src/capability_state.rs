// SPDX-License-Identifier: Apache-2.0

//! Persistent policy-scoped capability identities for Windows filesystem enforcement.

use std::collections::BTreeSet;
use std::ffi::c_void;
use std::path::{Path, PathBuf};

use cageforge_path::{NativePathKey, contains_parent_traversal};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use windows_sys::Win32::Foundation::{GetLastError, HLOCAL, LocalFree};
use windows_sys::Win32::Security::Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidW};
use windows_sys::Win32::Security::{ACL, IsValidAcl, IsValidSid};

pub(crate) const CAPABILITY_STATE_NAME: &str = "capabilities.json";
pub(crate) const CAPABILITY_LOCK_NAME: &str = "capabilities.lock";
const CAPABILITY_STATE_VERSION: u32 = 2;
const READ_BASE_SUBAUTHORITY: &str = "1";

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct CapabilityState {
    version: u32,
    namespace_sid: String,
    entries: Vec<FilesystemCapability>,
    acl_objects: Vec<ManagedAclObject>,
    pending_acl_mutation: Option<PendingAclMutation>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct FilesystemCapability {
    profile_sha256: String,
    role: CapabilityRole,
    path: PathBuf,
    sid: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct ManagedAclObject {
    path: PathBuf,
    identity: PersistedFileIdentity,
    original: PersistedDacl,
    current: PersistedDacl,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct PendingAclMutation {
    path: PathBuf,
    identity: PersistedFileIdentity,
    before: PersistedDacl,
    after: PersistedDacl,
    prior: Option<ManagedAclObject>,
    next: Option<ManagedAclObject>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct PersistedFileIdentity {
    volume_serial_number: u64,
    file_id: [u8; 16],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct PersistedDacl {
    bytes: Vec<u8>,
    protected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CapabilityRole {
    ProfileGuard,
    WriteRoot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AclMutationRecovery {
    Prior,
    Next,
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
}

impl CapabilityState {
    pub(crate) fn fresh() -> Result<Self, CapabilityStateError> {
        let state = Self {
            version: CAPABILITY_STATE_VERSION,
            namespace_sid: random_namespace_sid()?,
            entries: Vec::new(),
            acl_objects: Vec::new(),
            pending_acl_mutation: None,
        };
        state.validate()?;
        Ok(state)
    }

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

    pub(crate) fn ensure_authority(
        &mut self,
        profile_sha256: &str,
        role: CapabilityRole,
        path: PathBuf,
    ) -> Result<&str, CapabilityStateError> {
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
            return Err(CapabilityStateError::DuplicateSid);
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
            .ok_or(CapabilityStateError::DuplicateAuthority)
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

    pub(crate) fn read_base_sid(&self) -> Result<String, CapabilityStateError> {
        canonical_sid(&format!("{}-{READ_BASE_SUBAUTHORITY}", self.namespace_sid))
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
    ) -> Result<(), CapabilityStateError> {
        if let Some(pending) = &self.pending_acl_mutation {
            return Err(CapabilityStateError::PendingAclMutation {
                path: pending.path.clone(),
            });
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
                return Err(CapabilityStateError::AclObjectIdentityMismatch { path });
            }
            if object.current != before {
                return Err(CapabilityStateError::AclBeforeMismatch { path });
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
    }

    pub(crate) fn resolve_acl_mutation(
        &mut self,
        identity: &PersistedFileIdentity,
        actual: &PersistedDacl,
    ) -> Result<AclMutationRecovery, CapabilityStateError> {
        actual.validate()?;
        let pending = self
            .pending_acl_mutation
            .take()
            .ok_or(CapabilityStateError::MissingAclMutation)?;
        if &pending.identity != identity {
            let path = pending.path.clone();
            self.pending_acl_mutation = Some(pending);
            return Err(CapabilityStateError::AclObjectIdentityMismatch { path });
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
            return Err(CapabilityStateError::AclMutationDrift { path });
        };
        self.acl_objects.sort_by_key(managed_acl_key);
        self.validate()?;
        Ok(recovery)
    }

    pub(crate) fn managed_acl_objects(&self) -> &[ManagedAclObject] {
        &self.acl_objects
    }

    fn validate(&self) -> Result<(), CapabilityStateError> {
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
        Ok(())
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

    fn validate(&self) -> Result<(), CapabilityStateError> {
        validate_root(&self.path)?;
        self.original.validate()?;
        self.current.validate()?;
        if self.original == self.current {
            return Err(CapabilityStateError::RedundantAclObject);
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

impl PersistedFileIdentity {
    pub(crate) const fn new(volume_serial_number: u64, file_id: [u8; 16]) -> Self {
        Self {
            volume_serial_number,
            file_id,
        }
    }

    pub(crate) const fn volume_serial_number(&self) -> u64 {
        self.volume_serial_number
    }

    pub(crate) const fn file_id(&self) -> &[u8; 16] {
        &self.file_id
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

    #[allow(unsafe_code)]
    fn validate(&self) -> Result<(), CapabilityStateError> {
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

fn validate_profile_identity(value: &str) -> Result<(), CapabilityStateError> {
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

fn validate_root(path: &Path) -> Result<(), CapabilityStateError> {
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

fn authority_key(
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

fn entry_key(entry: &FilesystemCapability) -> (String, u8, NativePathKey) {
    authority_key(&entry.profile_sha256, &entry.role, &entry.path)
}

fn managed_acl_key(object: &ManagedAclObject) -> NativePathKey {
    NativePathKey::new(&object.path)
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

fn random_namespace_sid() -> Result<String, CapabilityStateError> {
    let mut random = [0u8; 16];
    getrandom::fill(&mut random).map_err(|source| CapabilityStateError::Random { source })?;
    let first = u32::from_le_bytes([random[0], random[1], random[2], random[3]]);
    let second = u32::from_le_bytes([random[4], random[5], random[6], random[7]]);
    let third = u32::from_le_bytes([random[8], random[9], random[10], random[11]]);
    let fourth = u32::from_le_bytes([random[12], random[13], random[14], random[15]]);
    Ok(format!("S-1-5-21-{first}-{second}-{third}-{fourth}"))
}

fn random_authority_sid(namespace: &str) -> Result<String, CapabilityStateError> {
    let mut random = [0u8; 8];
    getrandom::fill(&mut random).map_err(|source| CapabilityStateError::Random { source })?;
    let first = u32::from_le_bytes([random[0], random[1], random[2], random[3]]);
    let second = u32::from_le_bytes([random[4], random[5], random[6], random[7]]);
    Ok(format!("{namespace}-{first}-{second}"))
}

#[allow(unsafe_code)]
fn canonical_sid(value: &str) -> Result<String, CapabilityStateError> {
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

#[cfg(test)]
mod tests {
    use std::mem::size_of;
    use std::path::PathBuf;

    use pretty_assertions::{assert_eq, assert_ne};
    use windows_sys::Win32::Security::{ACL, ACL_REVISION, ACL_REVISION_DS, InitializeAcl};

    use super::{
        AclMutationRecovery, CapabilityRole, CapabilityState, CapabilityStateError, PersistedDacl,
        PersistedFileIdentity,
    };

    const PROFILE_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const PROFILE_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[test]
    fn equivalent_windows_roots_share_one_profile_authority() {
        let mut state = CapabilityState::fresh().expect("fresh capability state");
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
        let mut state = CapabilityState::fresh().expect("fresh capability state");
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
        let mut state = CapabilityState::fresh().expect("fresh capability state");
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
        let mut expected = CapabilityState::fresh().expect("fresh capability state");
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
        let mut state = CapabilityState::fresh().expect("fresh capability state");
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
        let mut state = CapabilityState::fresh().expect("fresh capability state");
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
        let mut state = CapabilityState::fresh().expect("fresh capability state");
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
            Err(CapabilityStateError::AclMutationDrift { .. })
        ));
        assert_eq!(
            state.pending_acl_path(),
            Some(PathBuf::from(r"C:\Workspace").as_path())
        );
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
