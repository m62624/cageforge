// SPDX-License-Identifier: Apache-2.0

//! Transactional handle-based Windows filesystem ACL enforcement.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::c_void;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::mem::{offset_of, size_of};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::MetadataExt;
use std::os::windows::io::{FromRawHandle, RawHandle};
use std::path::{Path, PathBuf};

use cageforge_path::{NativePathKey, is_within, paths_equal};
use thiserror::Error;
use windows_sys::Win32::Foundation::{
    ERROR_ALREADY_EXISTS, ERROR_SUCCESS, GetLastError, HLOCAL, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, ConvertStringSidToSidW, DENY_ACCESS,
    EXPLICIT_ACCESS_W, GetSecurityInfo, REVOKE_ACCESS, SDDL_REVISION_1, SE_FILE_OBJECT, SET_ACCESS,
    SetEntriesInAclW, SetSecurityInfo, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
    CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation,
    GetLengthSid, GetSecurityDescriptorControl, GetSecurityDescriptorDacl,
    GetSecurityDescriptorOwner, INHERIT_ONLY_ACE, INHERITED_ACE, InitializeAcl, IsValidSid,
    OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, SE_DACL_PROTECTED, SECURITY_ATTRIBUTES,
    UNPROTECTED_DACL_SECURITY_INFORMATION,
};
use windows_sys::Win32::Storage::FileSystem::{
    CREATE_NEW, CreateDirectoryW, CreateFileW, DELETE, FILE_ALL_ACCESS, FILE_APPEND_DATA,
    FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_DELETE_CHILD, FILE_GENERIC_EXECUTE,
    FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA, WRITE_DAC, WRITE_OWNER,
};

use crate::capability_state::{
    CapabilityRole, CapabilityStateError, MaterializationEvidence, MaterializationRecovery,
    PersistedDacl, PersistedFileIdentity,
};
use crate::capability_store::{
    CapabilityStateSession, CapabilityStateStore, CapabilityStateStoreError,
};
use crate::filesystem_path::{ValidatedPath, ValidatedPathError};
use crate::filesystem_plan::{FilesystemPlan, FilesystemPlanAccess};

const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const ACCESS_DENIED_ACE_TYPE: u8 = 1;
const WRITE_ALLOW_MASK: u32 =
    FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE;
const READ_ALLOW_MASK: u32 = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
const WRITE_DENY_MASK: u32 = FILE_GENERIC_WRITE
    | FILE_WRITE_DATA
    | FILE_APPEND_DATA
    | FILE_WRITE_EA
    | FILE_WRITE_ATTRIBUTES
    | DELETE
    | FILE_DELETE_CHILD
    | WRITE_DAC
    | WRITE_OWNER;
const SUBTREE_INHERITANCE: u32 = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
const MATERIALIZATION_MARKER_NAME: &str = ".cageforge-materialized-path";

pub(crate) struct FilesystemAclEnforcement {
    authorities: FilesystemAuthorities,
    retained_paths: Vec<ValidatedPath>,
}

pub(crate) struct FilesystemAuthorities {
    read_base_sid: String,
    profile_guard_sid: String,
    write_root_sids: BTreeMap<NativePathKey, String>,
    token_sids: Vec<String>,
}

struct FilesystemAclPlan {
    foundation: Vec<AclOperation>,
    continuation: Vec<AclOperation>,
    denies: Vec<AclOperation>,
}

struct AclPlanBuilder<'plan> {
    filesystem: &'plan FilesystemPlan,
    authorities: &'plan FilesystemAuthorities,
    group_sid: &'plan str,
    foundation: BTreeMap<NativePathKey, PendingAclOperation>,
    continuation: BTreeMap<NativePathKey, PendingAclOperation>,
    denies: BTreeMap<NativePathKey, PendingAclOperation>,
    write_roots: Vec<PathBuf>,
}

struct PendingAclOperation {
    path: PathBuf,
    entries: BTreeMap<(String, u8), AclEntry>,
    remove_sids: BTreeSet<String>,
    protect_dacl: bool,
    excluded_roots: BTreeMap<NativePathKey, PathBuf>,
}

struct AclOperation {
    path: ValidatedPath,
    entries: Vec<AclEntry>,
    remove_sids: Vec<String>,
    protect_dacl: bool,
    excluded_roots: Vec<PathBuf>,
}

struct PreparedAclPlan {
    operations: Vec<PreparedAclOperation>,
}

struct PreparedAclOperation {
    path: ValidatedPath,
    entries: Vec<PreparedAclEntry>,
    remove_sids: Vec<LocalSid>,
    protect_dacl: bool,
    excluded_roots: Vec<PathBuf>,
    original: SecurityDescriptor,
}

struct PreparedAclEntry {
    declaration: AclEntry,
    sid: LocalSid,
}

struct AclEntry {
    sid: String,
    mode: AclAccessMode,
    mask: u32,
    inheritance: AclInheritance,
}

struct SecurityDescriptor {
    descriptor: PSECURITY_DESCRIPTOR,
    dacl: *mut ACL,
}

struct LocalSid(*mut c_void);

struct LocalAcl(*mut ACL);

struct OwnedAclBuffer {
    storage: Vec<u32>,
}

struct MaterializedMissingPaths {
    retained_paths: Vec<ValidatedPath>,
}

struct CreationSecurityDescriptor {
    descriptor: LocalSecurityDescriptor,
    snapshot: PersistedDacl,
}

struct LocalSecurityDescriptor(PSECURITY_DESCRIPTOR);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AclAccessMode {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AclInheritance {
    Exact,
    Subtree,
}

#[derive(Debug, Error)]
pub(crate) enum FilesystemAclError {
    #[error(transparent)]
    CapabilityState(#[from] CapabilityStateStoreError),
    #[error(transparent)]
    CapabilityModel(#[from] CapabilityStateError),
    #[error(transparent)]
    InvalidPath(#[from] ValidatedPathError),
    #[error("capability state returned {actual} authorities for {expected} filesystem roles")]
    AuthorityCount { expected: usize, actual: usize },
    #[error("no write-root capability SID exists for {path:?}")]
    MissingWriteAuthority { path: PathBuf },
    #[error("invalid {component} SID {sid:?}: Windows error {code}")]
    SidParse {
        component: &'static str,
        sid: String,
        code: u32,
    },
    #[error("failed to read the DACL for {path:?}: Windows error {code}")]
    DescriptorRead { path: PathBuf, code: u32 },
    #[error("Windows returned a null DACL for filesystem target {path:?}")]
    NullDacl { path: PathBuf },
    #[error("Windows returned an invalid complete DACL snapshot for {path:?}")]
    InvalidDaclSnapshot { path: PathBuf },
    #[error("failed to inspect the DACL for {path:?}: Windows error {code}")]
    AclInspect { path: PathBuf, code: u32 },
    #[error("failed to read ACE {index} from the DACL for {path:?}: Windows error {code}")]
    AceRead {
        path: PathBuf,
        index: u32,
        code: u32,
    },
    #[error("DACL for {path:?} contains malformed ACE {index}")]
    MalformedAce { path: PathBuf, index: u32 },
    #[error("DACL for {path:?} contains the profile guard in unsupported ACE type {ace_type:#x}")]
    UnsupportedGuardAce { path: PathBuf, ace_type: u8 },
    #[error("failed to initialize a filtered DACL for {path:?}: Windows error {code}")]
    AclInitialize { path: PathBuf, code: u32 },
    #[error("filtered DACL for {path:?} exceeds the Windows ACL size representation")]
    AclSizeOverflow { path: PathBuf },
    #[error(
        "failed to preserve ACE {index} while filtering the DACL for {path:?}: Windows error {code}"
    )]
    AceCopy {
        path: PathBuf,
        index: u32,
        code: u32,
    },
    #[error("failed to build the canonical DACL for {path:?}: Windows error {code}")]
    AclBuild { path: PathBuf, code: u32 },
    #[error("failed to apply the canonical DACL to {path:?}: Windows error {code}")]
    AclApply { path: PathBuf, code: u32 },
    #[error("failed to read DACL control flags for {path:?}: Windows error {code}")]
    DescriptorControl { path: PathBuf, code: u32 },
    #[error("DACL protection state differs after read-back for {path:?}")]
    ProtectionMismatch { path: PathBuf },
    #[error("complete DACL bytes differ after read-back for {path:?}")]
    DescriptorSnapshotMismatch { path: PathBuf },
    #[error("effective {mode} ACE for SID {sid} on {path:?} differs from mask {expected:#x}")]
    AceMismatch {
        path: PathBuf,
        sid: String,
        mode: &'static str,
        expected: u32,
    },
    #[error("filesystem ACL scan encountered reparse point {path:?}")]
    ReparsePoint { path: PathBuf },
    #[error("failed to generate a cryptographically random missing-path marker: {source}")]
    MaterializationRandom {
        #[source]
        source: getrandom::Error,
    },
    #[error("failed to build the owner-only materialization descriptor: Windows error {code}")]
    MaterializationDescriptor { code: u32 },
    #[error("missing filesystem target changed before materialization at {path:?}")]
    MaterializationRace { path: PathBuf },
    #[error("failed to create protected missing-path directory {path:?}: Windows error {code}")]
    MaterializationCreate { path: PathBuf, code: u32 },
    #[error("failed to create protected missing-path marker {path:?}: Windows error {code}")]
    MaterializationMarkerCreate { path: PathBuf, code: u32 },
    #[error("failed to write protected missing-path marker {path:?}: {source}")]
    MaterializationMarkerWrite {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to read protected missing-path marker {path:?}: {source}")]
    MaterializationMarkerRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("protected missing-path marker content differs at {path:?}")]
    MaterializationMarkerMismatch { path: PathBuf },
    #[error("protected materialized object owner differs at {path:?}")]
    MaterializationOwnerMismatch { path: PathBuf },
    #[error("failed to enumerate filesystem ACL subtree {path:?}: {source}")]
    Enumerate {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to inspect filesystem ACL subtree entry {path:?}: {source}")]
    Metadata {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "filesystem ACL mutation failed ({original}); rollback of {path:?} also failed with Windows error {code}"
    )]
    Rollback {
        path: PathBuf,
        code: u32,
        original: Box<FilesystemAclError>,
    },
    #[error(
        "filesystem ACL mutation failed ({original}); journal reconciliation also failed ({recovery})"
    )]
    JournalRecovery {
        original: Box<FilesystemAclError>,
        recovery: Box<FilesystemAclError>,
    },
}

impl FilesystemAclEnforcement {
    pub(crate) fn apply(
        filesystem: &FilesystemPlan,
        state_store: &CapabilityStateStore,
        group_sid: &str,
    ) -> Result<Self, FilesystemAclError> {
        let mut state = state_store.begin()?;
        recover_pending_acl_mutation(&mut state)?;
        let authorities = FilesystemAuthorities::load(filesystem, &mut state)?;
        let plan = FilesystemAclPlan::build(filesystem, &authorities, group_sid)?;
        let prepared = plan.prepare()?;
        let retained_paths = prepared.apply(&mut state)?;
        state.finish()?;
        Ok(Self {
            authorities,
            retained_paths,
        })
    }

    pub(crate) fn token_sids(&self) -> &[String] {
        self.authorities.token_sids()
    }

    pub(crate) fn retained_paths(&self) -> &[ValidatedPath] {
        &self.retained_paths
    }
}

impl FilesystemAuthorities {
    fn load(
        filesystem: &FilesystemPlan,
        state: &mut CapabilityStateSession<'_>,
    ) -> Result<Self, FilesystemAclError> {
        let mut declarations = vec![(
            filesystem.profile_anchor().to_path_buf(),
            CapabilityRole::ProfileGuard,
        )];
        let mut write_roots = Vec::new();
        for target in filesystem.targets() {
            if target.access() == FilesystemPlanAccess::WriteRoot {
                let path = target.path().final_path().to_path_buf();
                declarations.push((path.clone(), CapabilityRole::WriteRoot));
                write_roots.push(path);
            }
        }
        let sids = state.ensure_authorities(filesystem.profile_sha256(), declarations)?;
        let expected = write_roots.len() + 1;
        if sids.len() != expected {
            return Err(FilesystemAclError::AuthorityCount {
                expected,
                actual: sids.len(),
            });
        }
        let profile_guard_sid = sids[0].clone();
        let mut write_root_sids = BTreeMap::new();
        for (path, sid) in write_roots.into_iter().zip(sids.into_iter().skip(1)) {
            write_root_sids.insert(NativePathKey::new(&path), sid);
        }
        let read_base_sid = state.read_base_sid()?;
        let mut token_sids = vec![read_base_sid.clone(), profile_guard_sid.clone()];
        token_sids.extend(write_root_sids.values().cloned());
        token_sids.sort_unstable();
        token_sids.dedup();
        Ok(Self {
            read_base_sid,
            profile_guard_sid,
            write_root_sids,
            token_sids,
        })
    }

    fn write_sid(&self, path: &Path) -> Option<&str> {
        self.write_root_sids
            .get(&NativePathKey::new(path))
            .map(String::as_str)
    }

    pub(crate) fn token_sids(&self) -> &[String] {
        &self.token_sids
    }
}

impl FilesystemAclPlan {
    fn build(
        filesystem: &FilesystemPlan,
        authorities: &FilesystemAuthorities,
        group_sid: &str,
    ) -> Result<Self, FilesystemAclError> {
        let mut builder = AclPlanBuilder::new(filesystem, authorities, group_sid);
        builder.collect()?;
        builder.finish()
    }

    fn prepare(self) -> Result<PreparedAclPlan, FilesystemAclError> {
        let operations = self
            .foundation
            .into_iter()
            .chain(self.continuation)
            .chain(self.denies)
            .map(AclOperation::prepare)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(PreparedAclPlan { operations })
    }
}

impl<'plan> AclPlanBuilder<'plan> {
    fn new(
        filesystem: &'plan FilesystemPlan,
        authorities: &'plan FilesystemAuthorities,
        group_sid: &'plan str,
    ) -> Self {
        let write_roots = filesystem
            .targets()
            .iter()
            .filter(|target| target.access() == FilesystemPlanAccess::WriteRoot)
            .map(|target| target.path().final_path().to_path_buf())
            .collect();
        Self {
            filesystem,
            authorities,
            group_sid,
            foundation: BTreeMap::new(),
            continuation: BTreeMap::new(),
            denies: BTreeMap::new(),
            write_roots,
        }
    }

    fn collect(&mut self) -> Result<(), FilesystemAclError> {
        for target in self.filesystem.targets() {
            let path = target.path().final_path();
            match target.access() {
                FilesystemPlanAccess::ReadRoot => {
                    let entries = vec![
                        AclEntry::allow(self.group_sid, READ_ALLOW_MASK),
                        AclEntry::allow(&self.authorities.read_base_sid, READ_ALLOW_MASK),
                    ];
                    self.insert_foundation(path, entries, false, Vec::new());
                }
                FilesystemPlanAccess::WriteRoot => {
                    let write_sid = self.authorities.write_sid(path).ok_or_else(|| {
                        FilesystemAclError::MissingWriteAuthority {
                            path: path.to_path_buf(),
                        }
                    })?;
                    let entries = vec![
                        AclEntry::allow(self.group_sid, WRITE_ALLOW_MASK),
                        AclEntry::allow(&self.authorities.read_base_sid, READ_ALLOW_MASK),
                        AclEntry::allow(write_sid, WRITE_ALLOW_MASK),
                    ];
                    self.insert_foundation(
                        path,
                        entries,
                        true,
                        vec![self.authorities.profile_guard_sid.clone()],
                    );
                }
                FilesystemPlanAccess::ReadOnly => {
                    self.insert_deny(
                        path,
                        AclEntry::deny(&self.authorities.profile_guard_sid, WRITE_DENY_MASK),
                    );
                }
                FilesystemPlanAccess::Deny => {
                    self.insert_deny(
                        path,
                        AclEntry::deny(&self.authorities.profile_guard_sid, FILE_ALL_ACCESS),
                    );
                }
            }
        }
        self.expand_protected_boundaries()
    }

    fn insert_foundation(
        &mut self,
        path: &Path,
        entries: Vec<AclEntry>,
        protect_dacl: bool,
        remove_sids: Vec<String>,
    ) {
        merge_pending(
            &mut self.foundation,
            path,
            entries,
            protect_dacl,
            remove_sids,
            Vec::new(),
        );
    }

    fn insert_deny(&mut self, path: &Path, entry: AclEntry) {
        let exclusions = self
            .write_roots
            .iter()
            .filter(|root| is_within(root, path))
            .cloned()
            .collect::<Vec<_>>();
        merge_pending(
            &mut self.denies,
            path,
            vec![entry],
            false,
            Vec::new(),
            exclusions,
        );
    }

    fn expand_protected_boundaries(&mut self) -> Result<(), FilesystemAclError> {
        let allow_roots = self
            .foundation
            .values()
            .map(|operation| {
                (
                    operation.path.clone(),
                    operation.entries.values().cloned().collect::<Vec<_>>(),
                )
            })
            .collect::<Vec<_>>();
        for (root, entries) in allow_roots {
            for boundary in protected_descendants(&root, &[])? {
                merge_pending(
                    &mut self.continuation,
                    boundary.final_path(),
                    entries.clone(),
                    false,
                    Vec::new(),
                    Vec::new(),
                );
            }
        }
        let deny_roots = self
            .denies
            .values()
            .map(|operation| {
                (
                    operation.path.clone(),
                    operation.entries.values().cloned().collect::<Vec<_>>(),
                    operation
                        .excluded_roots
                        .values()
                        .cloned()
                        .collect::<Vec<_>>(),
                )
            })
            .collect::<Vec<_>>();
        for (root, entries, exclusions) in deny_roots {
            for boundary in protected_descendants(&root, &exclusions)? {
                merge_pending(
                    &mut self.denies,
                    boundary.final_path(),
                    entries.clone(),
                    false,
                    Vec::new(),
                    exclusions.clone(),
                );
            }
        }
        Ok(())
    }

    fn finish(self) -> Result<FilesystemAclPlan, FilesystemAclError> {
        Ok(FilesystemAclPlan {
            foundation: finish_operations(self.foundation)?,
            continuation: finish_operations(self.continuation)?,
            denies: finish_operations(self.denies)?,
        })
    }
}

impl PendingAclOperation {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            entries: BTreeMap::new(),
            remove_sids: BTreeSet::new(),
            protect_dacl: false,
            excluded_roots: BTreeMap::new(),
        }
    }

    fn merge(
        &mut self,
        entries: Vec<AclEntry>,
        protect_dacl: bool,
        remove_sids: Vec<String>,
        excluded_roots: Vec<PathBuf>,
    ) {
        for entry in entries {
            let key = (entry.sid.clone(), entry.mode.key());
            if let Some(existing) = self.entries.get_mut(&key) {
                existing.mask |= entry.mask;
                if entry.inheritance == AclInheritance::Subtree {
                    existing.inheritance = AclInheritance::Subtree;
                }
            } else {
                self.entries.insert(key, entry);
            }
        }
        self.remove_sids.extend(remove_sids);
        self.protect_dacl |= protect_dacl;
        for root in excluded_roots {
            self.excluded_roots
                .entry(NativePathKey::new(&root))
                .or_insert(root);
        }
    }
}

impl AclOperation {
    fn prepare(self) -> Result<PreparedAclOperation, FilesystemAclError> {
        let original = SecurityDescriptor::read(&self.path)?;
        let entries = self
            .entries
            .into_iter()
            .map(|declaration| {
                let sid = LocalSid::parse("ACL entry", &declaration.sid)?;
                Ok(PreparedAclEntry { declaration, sid })
            })
            .collect::<Result<Vec<_>, FilesystemAclError>>()?;
        let remove_sids = self
            .remove_sids
            .into_iter()
            .map(|sid| LocalSid::parse("protected-DACL removal", &sid))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(PreparedAclOperation {
            path: self.path,
            entries,
            remove_sids,
            protect_dacl: self.protect_dacl,
            excluded_roots: self.excluded_roots,
            original,
        })
    }
}

impl PreparedAclPlan {
    fn apply(
        self,
        state: &mut CapabilityStateSession<'_>,
    ) -> Result<Vec<ValidatedPath>, FilesystemAclError> {
        let mut applied = Vec::new();
        for (index, operation) in self.operations.iter().enumerate() {
            if let Err(error) = operation.apply(state) {
                return Err(rollback(&self.operations, &applied, state, error));
            }
            applied.push(index);
        }
        for operation in &self.operations {
            if let Err(error) = operation.verify_subtree() {
                return Err(rollback(&self.operations, &applied, state, error));
            }
        }
        Ok(self
            .operations
            .into_iter()
            .map(|operation| operation.path)
            .collect())
    }
}

#[allow(unsafe_code)]
impl PreparedAclOperation {
    fn apply(&self, state: &mut CapabilityStateSession<'_>) -> Result<(), FilesystemAclError> {
        let filtered;
        let base = if self.remove_sids.is_empty() {
            self.original.dacl
        } else {
            filtered = filter_acl(&self.path, self.original.dacl, &self.remove_sids)?;
            filtered.as_ptr()
        };
        let acl = canonical_acl(&self.path, base, &self.entries)?;
        let before = self.original.snapshot(&self.path)?;
        let protected = self.protect_dacl || before.is_protected();
        let after = acl.snapshot(protected)?;
        if before == after {
            self.verify_root(&after)?;
            return Ok(());
        }
        let identity = persisted_identity(&self.path);
        state.begin_acl_mutation(
            self.path.final_path().to_path_buf(),
            identity.clone(),
            before,
            after.clone(),
        )?;
        let security_information = DACL_SECURITY_INFORMATION
            | if self.protect_dacl {
                PROTECTED_DACL_SECURITY_INFORMATION
            } else {
                0
            };
        let status = unsafe {
            SetSecurityInfo(
                self.path.raw_handle(),
                SE_FILE_OBJECT,
                security_information,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                acl.0,
                std::ptr::null_mut(),
            )
        };
        if status != ERROR_SUCCESS {
            let error = FilesystemAclError::AclApply {
                path: self.path.final_path().to_path_buf(),
                code: status,
            };
            return Err(self.reconcile_failed_mutation(state, &identity, error));
        }
        let actual = match self.verify_root(&after) {
            Ok(actual) => actual,
            Err(error) => return Err(self.restore_failed_mutation(state, &identity, error)),
        };
        if state.resolve_acl_mutation(&identity, &actual)?
            != crate::capability_state::AclMutationRecovery::Next
        {
            return Err(FilesystemAclError::DescriptorSnapshotMismatch {
                path: self.path.final_path().to_path_buf(),
            });
        }
        Ok(())
    }

    fn verify_root(&self, expected: &PersistedDacl) -> Result<PersistedDacl, FilesystemAclError> {
        let descriptor = SecurityDescriptor::read(&self.path)?;
        let actual = descriptor.snapshot(&self.path)?;
        if expected.is_protected() != actual.is_protected() {
            return Err(FilesystemAclError::ProtectionMismatch {
                path: self.path.final_path().to_path_buf(),
            });
        }
        for entry in &self.entries {
            verify_entry(&self.path, descriptor.dacl, entry, true)?;
        }
        for sid in &self.remove_sids {
            verify_sid_absent(&self.path, descriptor.dacl, sid)?;
        }
        if &actual != expected {
            return Err(FilesystemAclError::DescriptorSnapshotMismatch {
                path: self.path.final_path().to_path_buf(),
            });
        }
        Ok(actual)
    }

    fn verify_subtree(&self) -> Result<(), FilesystemAclError> {
        for path in subtree_paths(self.path.final_path(), &self.excluded_roots)? {
            let validated = ValidatedPath::open_for_readback(&path)?;
            let descriptor = SecurityDescriptor::read(&validated)?;
            for entry in &self.entries {
                verify_entry(&validated, descriptor.dacl, entry, false)?;
            }
        }
        Ok(())
    }

    fn restore(&self) -> Result<(), u32> {
        let protected = self
            .original
            .is_protected(&self.path)
            .map_err(|error| match error {
                FilesystemAclError::DescriptorControl { code, .. } => code,
                _ => 0,
            })?;
        let security_information = DACL_SECURITY_INFORMATION
            | if protected {
                PROTECTED_DACL_SECURITY_INFORMATION
            } else {
                UNPROTECTED_DACL_SECURITY_INFORMATION
            };
        let status = unsafe {
            SetSecurityInfo(
                self.path.raw_handle(),
                SE_FILE_OBJECT,
                security_information,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                self.original.dacl,
                std::ptr::null_mut(),
            )
        };
        if status == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(status)
        }
    }

    fn reconcile_failed_mutation(
        &self,
        state: &mut CapabilityStateSession<'_>,
        identity: &PersistedFileIdentity,
        original: FilesystemAclError,
    ) -> FilesystemAclError {
        let recovery = SecurityDescriptor::read(&self.path)
            .and_then(|descriptor| descriptor.snapshot(&self.path))
            .and_then(|actual| {
                state
                    .resolve_acl_mutation(identity, &actual)
                    .map(|_| ())
                    .map_err(Into::into)
            });
        match recovery {
            Ok(()) => original,
            Err(recovery) => FilesystemAclError::JournalRecovery {
                original: Box::new(original),
                recovery: Box::new(recovery),
            },
        }
    }

    fn restore_failed_mutation(
        &self,
        state: &mut CapabilityStateSession<'_>,
        identity: &PersistedFileIdentity,
        original: FilesystemAclError,
    ) -> FilesystemAclError {
        if let Err(code) = self.restore() {
            return FilesystemAclError::Rollback {
                path: self.path.final_path().to_path_buf(),
                code,
                original: Box::new(original),
            };
        }
        self.reconcile_failed_mutation(state, identity, original)
    }

    fn rollback(&self, state: &mut CapabilityStateSession<'_>) -> Result<(), FilesystemAclError> {
        let current = SecurityDescriptor::read(&self.path)?.snapshot(&self.path)?;
        let target = self.original.snapshot(&self.path)?;
        if current == target {
            return Ok(());
        }
        let identity = persisted_identity(&self.path);
        state.begin_acl_mutation(
            self.path.final_path().to_path_buf(),
            identity.clone(),
            current,
            target.clone(),
        )?;
        if let Err(code) = self.restore() {
            return Err(FilesystemAclError::Rollback {
                path: self.path.final_path().to_path_buf(),
                code,
                original: Box::new(FilesystemAclError::DescriptorSnapshotMismatch {
                    path: self.path.final_path().to_path_buf(),
                }),
            });
        }
        let actual = SecurityDescriptor::read(&self.path)?.snapshot(&self.path)?;
        if actual != target {
            return Err(FilesystemAclError::DescriptorSnapshotMismatch {
                path: self.path.final_path().to_path_buf(),
            });
        }
        state.resolve_acl_mutation(&identity, &actual)?;
        Ok(())
    }
}

impl AclEntry {
    fn allow(sid: &str, mask: u32) -> Self {
        Self {
            sid: sid.to_string(),
            mode: AclAccessMode::Allow,
            mask,
            inheritance: AclInheritance::Subtree,
        }
    }

    fn deny(sid: &str, mask: u32) -> Self {
        Self {
            sid: sid.to_string(),
            mode: AclAccessMode::Deny,
            mask,
            inheritance: AclInheritance::Subtree,
        }
    }
}

impl Clone for AclEntry {
    fn clone(&self) -> Self {
        Self {
            sid: self.sid.clone(),
            mode: self.mode,
            mask: self.mask,
            inheritance: self.inheritance,
        }
    }
}

#[allow(unsafe_code)]
impl SecurityDescriptor {
    fn read(path: &ValidatedPath) -> Result<Self, FilesystemAclError> {
        let mut descriptor = std::ptr::null_mut();
        let mut dacl = std::ptr::null_mut();
        let status = unsafe {
            GetSecurityInfo(
                path.raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut dacl,
                std::ptr::null_mut(),
                &mut descriptor,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(FilesystemAclError::DescriptorRead {
                path: path.final_path().to_path_buf(),
                code: status,
            });
        }
        if descriptor.is_null() || dacl.is_null() {
            if !descriptor.is_null() {
                unsafe {
                    LocalFree(descriptor as HLOCAL);
                }
            }
            return Err(FilesystemAclError::NullDacl {
                path: path.final_path().to_path_buf(),
            });
        }
        Ok(Self { descriptor, dacl })
    }

    fn is_protected(&self, path: &ValidatedPath) -> Result<bool, FilesystemAclError> {
        let mut control = 0;
        let mut revision = 0;
        if unsafe { GetSecurityDescriptorControl(self.descriptor, &mut control, &mut revision) }
            == 0
        {
            return Err(FilesystemAclError::DescriptorControl {
                path: path.final_path().to_path_buf(),
                code: unsafe { GetLastError() },
            });
        }
        Ok(control & SE_DACL_PROTECTED != 0)
    }

    fn snapshot(&self, path: &ValidatedPath) -> Result<PersistedDacl, FilesystemAclError> {
        snapshot_dacl(path, self.dacl, self.is_protected(path)?)
    }
}

#[allow(unsafe_code)]
impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        if !self.descriptor.is_null() {
            unsafe {
                LocalFree(self.descriptor as HLOCAL);
            }
        }
    }
}

#[allow(unsafe_code)]
impl LocalSid {
    fn parse(component: &'static str, value: &str) -> Result<Self, FilesystemAclError> {
        if value.contains('\0') {
            return Err(FilesystemAclError::SidParse {
                component,
                sid: value.to_string(),
                code: 0,
            });
        }
        let wide = value
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let mut sid = std::ptr::null_mut();
        if unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut sid) } == 0
            || unsafe { IsValidSid(sid) } == 0
        {
            let code = unsafe { GetLastError() };
            if !sid.is_null() {
                unsafe {
                    LocalFree(sid as HLOCAL);
                }
            }
            return Err(FilesystemAclError::SidParse {
                component,
                sid: value.to_string(),
                code,
            });
        }
        Ok(Self(sid))
    }

    fn bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.0.cast::<u8>(), GetLengthSid(self.0) as usize) }
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

impl LocalAcl {
    fn snapshot(&self, protected: bool) -> Result<PersistedDacl, FilesystemAclError> {
        snapshot_acl_pointer(self.0, protected)
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
impl OwnedAclBuffer {
    fn new(bytes: usize, revision: u32, path: &Path) -> Result<Self, FilesystemAclError> {
        let bytes = u32::try_from(bytes).map_err(|_| FilesystemAclError::AclSizeOverflow {
            path: path.to_path_buf(),
        })?;
        let words = bytes.div_ceil(size_of::<u32>() as u32);
        let mut storage = vec![0u32; words as usize];
        if unsafe { InitializeAcl(storage.as_mut_ptr().cast(), bytes, revision) } == 0 {
            return Err(FilesystemAclError::AclInitialize {
                path: path.to_path_buf(),
                code: unsafe { GetLastError() },
            });
        }
        Ok(Self { storage })
    }

    fn as_ptr(&self) -> *mut ACL {
        self.storage.as_ptr().cast_mut().cast()
    }
}

impl AclAccessMode {
    const fn key(self) -> u8 {
        match self {
            Self::Allow => 0,
            Self::Deny => 1,
        }
    }

    const fn native(self) -> i32 {
        match self {
            Self::Allow => SET_ACCESS,
            Self::Deny => DENY_ACCESS,
        }
    }

    const fn ace_type(self) -> u8 {
        match self {
            Self::Allow => ACCESS_ALLOWED_ACE_TYPE,
            Self::Deny => ACCESS_DENIED_ACE_TYPE,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

impl AclInheritance {
    const fn native(self) -> u32 {
        match self {
            Self::Exact => 0,
            Self::Subtree => SUBTREE_INHERITANCE,
        }
    }
}

fn recover_pending_acl_mutation(
    state: &mut CapabilityStateSession<'_>,
) -> Result<(), FilesystemAclError> {
    let Some(path) = state.pending_acl_path().map(Path::to_path_buf) else {
        return Ok(());
    };
    let validated = ValidatedPath::open_for_acl(&path)?;
    let identity = persisted_identity(&validated);
    let actual = SecurityDescriptor::read(&validated)?.snapshot(&validated)?;
    state.resolve_acl_mutation(&identity, &actual)?;
    Ok(())
}

fn persisted_identity(path: &ValidatedPath) -> PersistedFileIdentity {
    PersistedFileIdentity::new(
        path.identity().volume_serial_number(),
        *path.identity().file_id(),
    )
}

fn snapshot_dacl(
    path: &ValidatedPath,
    dacl: *mut ACL,
    protected: bool,
) -> Result<PersistedDacl, FilesystemAclError> {
    snapshot_acl_pointer(dacl, protected).map_err(|error| match error {
        FilesystemAclError::CapabilityModel(CapabilityStateError::InvalidDacl) => {
            FilesystemAclError::InvalidDaclSnapshot {
                path: path.final_path().to_path_buf(),
            }
        }
        other => other,
    })
}

#[allow(unsafe_code)]
fn snapshot_acl_pointer(
    dacl: *mut ACL,
    protected: bool,
) -> Result<PersistedDacl, FilesystemAclError> {
    if dacl.is_null() {
        return Err(CapabilityStateError::InvalidDacl.into());
    }
    let mut information = ACL_SIZE_INFORMATION::default();
    if unsafe {
        GetAclInformation(
            dacl,
            (&raw mut information).cast(),
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
    {
        return Err(CapabilityStateError::InvalidDacl.into());
    }
    let length = usize::try_from(information.AclBytesInUse)
        .map_err(|_| CapabilityStateError::InvalidDacl)?;
    if length < size_of::<ACL>() || length > u16::MAX as usize {
        return Err(CapabilityStateError::InvalidDacl.into());
    }
    let mut bytes = unsafe { std::slice::from_raw_parts(dacl.cast::<u8>(), length) }.to_vec();
    let acl_size_offset = offset_of!(ACL, AclSize);
    bytes[acl_size_offset..acl_size_offset + size_of::<u16>()]
        .copy_from_slice(&(length as u16).to_ne_bytes());
    PersistedDacl::new(bytes, protected).map_err(Into::into)
}

fn merge_pending(
    operations: &mut BTreeMap<NativePathKey, PendingAclOperation>,
    path: &Path,
    entries: Vec<AclEntry>,
    protect_dacl: bool,
    remove_sids: Vec<String>,
    excluded_roots: Vec<PathBuf>,
) {
    operations
        .entry(NativePathKey::new(path))
        .or_insert_with(|| PendingAclOperation::new(path.to_path_buf()))
        .merge(entries, protect_dacl, remove_sids, excluded_roots);
}

fn finish_operations(
    operations: BTreeMap<NativePathKey, PendingAclOperation>,
) -> Result<Vec<AclOperation>, FilesystemAclError> {
    let mut operations = operations
        .into_values()
        .map(|operation| {
            Ok(AclOperation {
                path: ValidatedPath::open_for_acl(&operation.path)?,
                entries: operation.entries.into_values().collect(),
                remove_sids: operation.remove_sids.into_iter().collect(),
                protect_dacl: operation.protect_dacl,
                excluded_roots: operation.excluded_roots.into_values().collect(),
            })
        })
        .collect::<Result<Vec<_>, FilesystemAclError>>()?;
    operations.sort_by(|left, right| {
        left.path
            .final_path()
            .components()
            .count()
            .cmp(&right.path.final_path().components().count())
            .then_with(|| {
                NativePathKey::new(left.path.final_path())
                    .cmp(&NativePathKey::new(right.path.final_path()))
            })
    });
    Ok(operations)
}

fn protected_descendants(
    root: &Path,
    excluded_roots: &[PathBuf],
) -> Result<Vec<ValidatedPath>, FilesystemAclError> {
    let mut protected = Vec::new();
    for path in subtree_paths(root, excluded_roots)? {
        let validated = ValidatedPath::open_for_readback(&path)?;
        if SecurityDescriptor::read(&validated)?.is_protected(&validated)? {
            protected.push(validated);
        }
    }
    Ok(protected)
}

fn subtree_paths(
    root: &Path,
    excluded_roots: &[PathBuf],
) -> Result<Vec<PathBuf>, FilesystemAclError> {
    let metadata = fs::symlink_metadata(root).map_err(|source| FilesystemAclError::Metadata {
        path: root.to_path_buf(),
        source,
    })?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(FilesystemAclError::ReparsePoint {
            path: root.to_path_buf(),
        });
    }
    if !metadata.is_dir() {
        return Ok(Vec::new());
    }
    let mut paths = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(parent) = stack.pop() {
        let entries = fs::read_dir(&parent).map_err(|source| FilesystemAclError::Enumerate {
            path: parent.clone(),
            source,
        })?;
        let mut children = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|source| FilesystemAclError::Enumerate {
                path: parent.clone(),
                source,
            })?;
            let child = entry.path();
            if excluded_roots
                .iter()
                .any(|excluded| paths_equal(&child, excluded) || is_within(&child, excluded))
            {
                continue;
            }
            let metadata =
                fs::symlink_metadata(&child).map_err(|source| FilesystemAclError::Metadata {
                    path: child.clone(),
                    source,
                })?;
            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(FilesystemAclError::ReparsePoint { path: child });
            }
            children.push((NativePathKey::new(&child), child, metadata.is_dir()));
        }
        children.sort_by(|left, right| left.0.cmp(&right.0));
        for (_, child, is_directory) in children.into_iter().rev() {
            if is_directory {
                stack.push(child.clone());
            }
            paths.push(child);
        }
    }
    paths.sort_by_key(|path| NativePathKey::new(path));
    Ok(paths)
}

#[allow(unsafe_code)]
fn filter_acl(
    path: &ValidatedPath,
    source: *mut ACL,
    remove_sids: &[LocalSid],
) -> Result<OwnedAclBuffer, FilesystemAclError> {
    let information = acl_information(path, source)?;
    let mut retained = Vec::new();
    let mut bytes = size_of::<ACL>();
    for index in 0..information.AceCount {
        let raw = ace(path, source, index)?;
        let header = unsafe { &*raw.cast::<ACE_HEADER>() };
        let ace_size = header.AceSize as usize;
        if ace_size < size_of::<ACE_HEADER>() {
            return Err(FilesystemAclError::MalformedAce {
                path: path.final_path().to_path_buf(),
                index,
            });
        }
        let raw_bytes = unsafe { std::slice::from_raw_parts(raw.cast::<u8>(), ace_size) };
        let standard_sid = if matches!(
            header.AceType,
            ACCESS_ALLOWED_ACE_TYPE | ACCESS_DENIED_ACE_TYPE
        ) && ace_size >= size_of::<ACCESS_ALLOWED_ACE>()
        {
            Some(
                unsafe {
                    raw.cast::<u8>()
                        .add(offset_of!(ACCESS_ALLOWED_ACE, SidStart))
                }
                .cast(),
            )
        } else {
            None
        };
        let remove = standard_sid.is_some_and(|sid| {
            remove_sids
                .iter()
                .any(|candidate| unsafe { EqualSid(sid, candidate.0) } != 0)
        });
        if remove {
            continue;
        }
        for sid in remove_sids {
            if contains_bytes(raw_bytes, sid.bytes()) {
                return Err(FilesystemAclError::UnsupportedGuardAce {
                    path: path.final_path().to_path_buf(),
                    ace_type: header.AceType,
                });
            }
        }
        let mut copy = raw_bytes.to_vec();
        copy[1] &= !(INHERITED_ACE as u8);
        bytes =
            bytes
                .checked_add(copy.len())
                .ok_or_else(|| FilesystemAclError::AclSizeOverflow {
                    path: path.final_path().to_path_buf(),
                })?;
        retained.push((index, copy));
    }
    let revision = unsafe { (*source).AclRevision as u32 };
    let acl = OwnedAclBuffer::new(bytes, revision, path.final_path())?;
    for (index, entry) in retained {
        if unsafe {
            windows_sys::Win32::Security::AddAce(
                acl.as_ptr(),
                revision,
                u32::MAX,
                entry.as_ptr().cast(),
                entry.len() as u32,
            )
        } == 0
        {
            return Err(FilesystemAclError::AceCopy {
                path: path.final_path().to_path_buf(),
                index,
                code: unsafe { GetLastError() },
            });
        }
    }
    Ok(acl)
}

#[allow(unsafe_code)]
fn canonical_acl(
    path: &ValidatedPath,
    base: *mut ACL,
    entries: &[PreparedAclEntry],
) -> Result<LocalAcl, FilesystemAclError> {
    let revocations = entries
        .iter()
        .map(|entry| explicit_entry(&entry.sid, REVOKE_ACCESS, 0, AclInheritance::Exact))
        .collect::<Vec<_>>();
    let mut stripped = std::ptr::null_mut();
    let status = unsafe {
        SetEntriesInAclW(
            revocations.len() as u32,
            revocations.as_ptr(),
            base,
            &mut stripped,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(FilesystemAclError::AclBuild {
            path: path.final_path().to_path_buf(),
            code: status,
        });
    }
    let stripped = LocalAcl(stripped);
    let declarations = entries
        .iter()
        .map(|entry| {
            explicit_entry(
                &entry.sid,
                entry.declaration.mode.native(),
                entry.declaration.mask,
                entry.declaration.inheritance,
            )
        })
        .collect::<Vec<_>>();
    let mut canonical = std::ptr::null_mut();
    let status = unsafe {
        SetEntriesInAclW(
            declarations.len() as u32,
            declarations.as_ptr(),
            stripped.0,
            &mut canonical,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(FilesystemAclError::AclBuild {
            path: path.final_path().to_path_buf(),
            code: status,
        });
    }
    Ok(LocalAcl(canonical))
}

fn explicit_entry(
    sid: &LocalSid,
    mode: i32,
    mask: u32,
    inheritance: AclInheritance,
) -> EXPLICIT_ACCESS_W {
    EXPLICIT_ACCESS_W {
        grfAccessPermissions: mask,
        grfAccessMode: mode,
        grfInheritance: inheritance.native(),
        Trustee: TRUSTEE_W {
            pMultipleTrustee: std::ptr::null_mut(),
            MultipleTrusteeOperation: 0,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_UNKNOWN,
            ptstrName: sid.0.cast(),
        },
    }
}

#[allow(unsafe_code)]
fn verify_entry(
    path: &ValidatedPath,
    dacl: *mut ACL,
    expected: &PreparedAclEntry,
    explicit_only: bool,
) -> Result<(), FilesystemAclError> {
    let information = acl_information(path, dacl)?;
    let mut expected_mask = 0u32;
    let mut opposite = false;
    for index in 0..information.AceCount {
        let raw = ace(path, dacl, index)?;
        let header = unsafe { &*raw.cast::<ACE_HEADER>() };
        if header.AceFlags & INHERIT_ONLY_ACE as u8 != 0
            || (explicit_only && header.AceFlags & INHERITED_ACE as u8 != 0)
            || !matches!(
                header.AceType,
                ACCESS_ALLOWED_ACE_TYPE | ACCESS_DENIED_ACE_TYPE
            )
        {
            continue;
        }
        if (header.AceSize as usize) < size_of::<ACCESS_ALLOWED_ACE>() {
            return Err(FilesystemAclError::MalformedAce {
                path: path.final_path().to_path_buf(),
                index,
            });
        }
        let value = unsafe { &*raw.cast::<ACCESS_ALLOWED_ACE>() };
        let sid = (&raw const value.SidStart).cast_mut().cast::<c_void>();
        if unsafe { IsValidSid(sid) } == 0 {
            return Err(FilesystemAclError::MalformedAce {
                path: path.final_path().to_path_buf(),
                index,
            });
        }
        if unsafe { EqualSid(sid, expected.sid.0) } == 0 {
            continue;
        }
        if header.AceType == expected.declaration.mode.ace_type() {
            if !explicit_only
                || u32::from(header.AceFlags & !(INHERITED_ACE as u8))
                    == expected.declaration.inheritance.native()
            {
                expected_mask |= value.Mask;
            }
        } else {
            opposite = true;
        }
    }
    if expected_mask == expected.declaration.mask && !opposite {
        Ok(())
    } else {
        Err(FilesystemAclError::AceMismatch {
            path: path.final_path().to_path_buf(),
            sid: expected.declaration.sid.clone(),
            mode: expected.declaration.mode.label(),
            expected: expected.declaration.mask,
        })
    }
}

#[allow(unsafe_code)]
fn verify_sid_absent(
    path: &ValidatedPath,
    dacl: *mut ACL,
    sid: &LocalSid,
) -> Result<(), FilesystemAclError> {
    let information = acl_information(path, dacl)?;
    for index in 0..information.AceCount {
        let raw = ace(path, dacl, index)?;
        let header = unsafe { &*raw.cast::<ACE_HEADER>() };
        let size = header.AceSize as usize;
        if size < size_of::<ACE_HEADER>() {
            return Err(FilesystemAclError::MalformedAce {
                path: path.final_path().to_path_buf(),
                index,
            });
        }
        let bytes = unsafe { std::slice::from_raw_parts(raw.cast::<u8>(), size) };
        if contains_bytes(bytes, sid.bytes()) {
            return Err(FilesystemAclError::AceMismatch {
                path: path.final_path().to_path_buf(),
                sid: "profile guard".to_string(),
                mode: "removed",
                expected: 0,
            });
        }
    }
    Ok(())
}

#[allow(unsafe_code)]
fn acl_information(
    path: &ValidatedPath,
    dacl: *mut ACL,
) -> Result<ACL_SIZE_INFORMATION, FilesystemAclError> {
    let mut information = ACL_SIZE_INFORMATION::default();
    if unsafe {
        GetAclInformation(
            dacl,
            (&raw mut information).cast(),
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
    {
        return Err(FilesystemAclError::AclInspect {
            path: path.final_path().to_path_buf(),
            code: unsafe { GetLastError() },
        });
    }
    Ok(information)
}

#[allow(unsafe_code)]
fn ace(
    path: &ValidatedPath,
    dacl: *mut ACL,
    index: u32,
) -> Result<*mut c_void, FilesystemAclError> {
    let mut raw = std::ptr::null_mut();
    if unsafe { GetAce(dacl, index, &mut raw) } == 0 || raw.is_null() {
        return Err(FilesystemAclError::AceRead {
            path: path.final_path().to_path_buf(),
            index,
            code: unsafe { GetLastError() },
        });
    }
    Ok(raw)
}

fn rollback(
    operations: &[PreparedAclOperation],
    applied: &[usize],
    state: &mut CapabilityStateSession<'_>,
    original: FilesystemAclError,
) -> FilesystemAclError {
    for index in applied.iter().rev() {
        if let Err(recovery) = operations[*index].rollback(state) {
            return FilesystemAclError::JournalRecovery {
                original: Box::new(original),
                recovery: Box::new(recovery),
            };
        }
    }
    original
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && needle.len() <= haystack.len()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use pretty_assertions::assert_eq;
    use windows_sys::Win32::Storage::FileSystem::FILE_DELETE_CHILD;

    use super::{
        AclAccessMode, AclEntry, PendingAclOperation, READ_ALLOW_MASK, WRITE_ALLOW_MASK,
        subtree_paths,
    };

    #[test]
    fn overlapping_allow_requirements_merge_independently_of_order() {
        let mut first = PendingAclOperation::new(PathBuf::from(r"C:\workspace"));
        first.merge(
            vec![AclEntry::allow("S-1-5-21-1", READ_ALLOW_MASK)],
            false,
            Vec::new(),
            Vec::new(),
        );
        first.merge(
            vec![AclEntry::allow("S-1-5-21-1", WRITE_ALLOW_MASK)],
            false,
            Vec::new(),
            Vec::new(),
        );
        let mut second = PendingAclOperation::new(PathBuf::from(r"C:\workspace"));
        second.merge(
            vec![AclEntry::allow("S-1-5-21-1", WRITE_ALLOW_MASK)],
            false,
            Vec::new(),
            Vec::new(),
        );
        second.merge(
            vec![AclEntry::allow("S-1-5-21-1", READ_ALLOW_MASK)],
            false,
            Vec::new(),
            Vec::new(),
        );

        assert_eq!(allow_mask(&first), READ_ALLOW_MASK | WRITE_ALLOW_MASK);
        assert_eq!(allow_mask(&first), allow_mask(&second));
    }

    #[test]
    fn writable_root_grant_cannot_delete_unprotected_children() {
        assert_eq!(WRITE_ALLOW_MASK & FILE_DELETE_CHILD, 0);
    }

    #[test]
    fn subtree_enumeration_excludes_the_complete_writable_boundary() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let denied = temporary.path().join("denied");
        let sibling = denied.join("sibling");
        let writable = denied.join("writable");
        let writable_child = writable.join("child");
        std::fs::create_dir_all(&sibling).expect("denied sibling");
        std::fs::create_dir_all(&writable_child).expect("writable child");

        let paths = subtree_paths(&denied, std::slice::from_ref(&writable))
            .expect("enumerate denied subtree");

        assert!(paths.contains(&sibling));
        assert!(!paths.contains(&writable));
        assert!(!paths.contains(&writable_child));
    }

    fn allow_mask(operation: &PendingAclOperation) -> u32 {
        operation
            .entries
            .get(&("S-1-5-21-1".to_string(), AclAccessMode::Allow.key()))
            .expect("merged allow entry")
            .mask
    }
}
