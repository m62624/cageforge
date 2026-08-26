// SPDX-License-Identifier: Apache-2.0

//! Complete Windows filesystem lowering before ACL mutation.

use std::collections::BTreeMap;
use std::fs;
use std::num::NonZeroUsize;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use cageforge_backend_api::{BackendContractError, PreparedBackendRequest, SandboxBackend};
use cageforge_path::{NativePathKey, is_within, normalize_lexical_path};
use cageforge_policy::{
    FilesystemDecision, FilesystemMode, FilesystemTarget, MissingPathBehavior, PathPattern,
};
use cageforge_policy_compose::{EffectiveFilesystemLayer, EffectivePathContext};
use sha2::{Digest, Sha256};
use thiserror::Error;
use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

use crate::filesystem_path::{ValidatedPath, ValidatedPathError};

pub(crate) struct FilesystemPlan {
    profile_sha256: String,
    targets: Vec<FilesystemPlanTarget>,
    missing: Vec<MissingFilesystemTarget>,
    profile_anchor: PathBuf,
}

pub(crate) struct FilesystemPlanTarget {
    path: ValidatedPath,
    access: FilesystemPlanAccess,
    origins: TargetOrigins,
}

pub(crate) struct MissingFilesystemTarget {
    path: PathBuf,
    anchor: Option<ValidatedPath>,
    kind: MissingFilesystemTargetKind,
}

struct FilesystemPlanCollector<'scope, 'request, B: SandboxBackend> {
    backend: &'scope B,
    prepared: &'scope PreparedBackendRequest<'request, B>,
    context: &'scope EffectivePathContext,
    glob_scan_max_depth: Option<NonZeroUsize>,
    pending: BTreeMap<NativePathKey, PendingFilesystemTarget>,
    missing: BTreeMap<(MissingFilesystemTargetKind, NativePathKey), MissingFilesystemTarget>,
    protected_relative_paths: BTreeMap<NativePathKey, PathBuf>,
    readable_platform_base: bool,
}

struct PendingFilesystemTarget {
    path: ValidatedPath,
    origins: TargetOrigins,
}

#[derive(Debug, Clone, Copy, Default)]
struct TargetOrigins {
    scope: bool,
    read_only: bool,
    glob: bool,
    protected: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum MissingFilesystemTargetKind {
    SkippedScope,
    ReadOnly,
    Protected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FilesystemPlanAccess {
    ReadRoot,
    WriteRoot,
    ReadOnly,
    Deny,
}

#[derive(Debug, Error)]
pub(crate) enum FilesystemPlanError {
    #[error(transparent)]
    BackendContract(#[from] BackendContractError),
    #[error("Windows filesystem planning does not accept external ownership")]
    ExternalOwnership,
    #[error(
        "Windows elevated filesystem enforcement requires a readable root or platform-minimal scope"
    )]
    MissingReadablePlatformBase,
    #[error("Windows filesystem planning cannot enforce the conventional Unix /tmp selector")]
    SlashTmpScope,
    #[error("Windows filesystem rule requires missing path {path:?}")]
    RequiredPathMissing { path: PathBuf },
    #[error("failed to inspect Windows filesystem target {path:?}: {source}")]
    Metadata {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to enumerate Windows deny-glob root {path:?}: {source}")]
    GlobScan {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("Windows deny-glob scan encountered reparse point {path:?}")]
    GlobReparsePoint { path: PathBuf },
    #[error("Windows rejects an unbounded recursive deny glob rooted at a complete volume")]
    UnboundedRootGlob,
    #[error("read-only path {path:?} is outside its resolved writable root {root:?}")]
    ReadOnlyOutsideWriteRoot { path: PathBuf, root: PathBuf },
    #[error("read-only path {path:?} remained writable after effective policy composition")]
    ReadOnlyPolicyMismatch { path: PathBuf },
    #[error("protected path {path:?} remained writable after effective policy composition")]
    ProtectedPathWritable { path: PathBuf },
    #[error("deny-glob match {path:?} was not denied by the complete effective policy")]
    GlobPolicyMismatch { path: PathBuf },
    #[error("Windows filesystem planning received an externally enforced path {path:?}")]
    ExternalPath { path: PathBuf },
    #[error("missing protected or read-only target {path:?} has no validated existing ancestor")]
    MissingTargetWithoutAnchor { path: PathBuf },
    #[error(transparent)]
    InvalidPath(#[from] ValidatedPathError),
}

impl FilesystemPlan {
    pub(crate) fn lower<'request, B: SandboxBackend>(
        backend: &B,
        prepared: &PreparedBackendRequest<'request, B>,
    ) -> Result<Self, FilesystemPlanError> {
        let sandbox = prepared.sandbox(backend)?;
        if sandbox.filesystem().requirements().mode() == FilesystemMode::External {
            return Err(FilesystemPlanError::ExternalOwnership);
        }
        let lowering = prepared.filesystem_lowering(backend)?;
        let context = prepared.path_context(backend)?;
        let mut collector = FilesystemPlanCollector::new(
            backend,
            prepared,
            context,
            lowering.glob_scan_max_depth(),
        );
        for layer in lowering.layers() {
            collector.collect_layer(layer)?;
        }
        collector.finish()
    }

    pub(crate) fn profile_sha256(&self) -> &str {
        &self.profile_sha256
    }

    pub(crate) fn profile_anchor(&self) -> &Path {
        &self.profile_anchor
    }

    pub(crate) fn targets(&self) -> &[FilesystemPlanTarget] {
        &self.targets
    }

    pub(crate) fn missing_targets(&self) -> &[MissingFilesystemTarget] {
        &self.missing
    }
}

impl FilesystemPlanTarget {
    pub(crate) const fn access(&self) -> FilesystemPlanAccess {
        self.access
    }

    pub(crate) fn path(&self) -> &ValidatedPath {
        &self.path
    }
}

impl MissingFilesystemTarget {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn anchor(&self) -> Option<&ValidatedPath> {
        self.anchor.as_ref()
    }

    pub(crate) const fn kind(&self) -> MissingFilesystemTargetKind {
        self.kind
    }
}

impl<'scope, 'request, B: SandboxBackend> FilesystemPlanCollector<'scope, 'request, B> {
    fn new(
        backend: &'scope B,
        prepared: &'scope PreparedBackendRequest<'request, B>,
        context: &'scope EffectivePathContext,
        glob_scan_max_depth: Option<NonZeroUsize>,
    ) -> Self {
        Self {
            backend,
            prepared,
            context,
            glob_scan_max_depth,
            pending: BTreeMap::new(),
            missing: BTreeMap::new(),
            protected_relative_paths: BTreeMap::new(),
            readable_platform_base: false,
        }
    }

    fn collect_layer(
        &mut self,
        layer: EffectiveFilesystemLayer<'_>,
    ) -> Result<(), FilesystemPlanError> {
        if layer.mode() == FilesystemMode::External {
            return Err(FilesystemPlanError::ExternalOwnership);
        }
        for protected in layer.protected_relative_paths() {
            self.protected_relative_paths
                .entry(NativePathKey::new(protected))
                .or_insert_with(|| protected.clone());
        }
        for rule in layer.entries() {
            match rule.target() {
                FilesystemTarget::Scope(selector) => {
                    if selector.is_slash_tmp_scope() {
                        return Err(FilesystemPlanError::SlashTmpScope);
                    }
                    for path in self.context.resolve(selector) {
                        let decision = self
                            .prepared
                            .filesystem_access_for_path(self.backend, &path)?;
                        if matches!(
                            decision,
                            FilesystemDecision::Read | FilesystemDecision::Write
                        ) && (selector.is_root_scope()
                            || selector.is_minimal_scope()
                            || is_complete_volume_root(&path))
                        {
                            self.readable_platform_base = true;
                        }
                        let exists = self.collect_scope(
                            &path,
                            rule.missing_path_behavior(),
                            TargetOrigins {
                                scope: true,
                                ..TargetOrigins::default()
                            },
                        )?;
                        if exists && decision == FilesystemDecision::Write {
                            self.collect_read_only_subpaths(&path, rule.read_only_subpaths())?;
                        }
                    }
                }
                FilesystemTarget::Glob(pattern) => self.collect_glob(pattern)?,
            }
        }
        Ok(())
    }

    fn collect_scope(
        &mut self,
        path: &Path,
        missing: MissingPathBehavior,
        origins: TargetOrigins,
    ) -> Result<bool, FilesystemPlanError> {
        match fs::symlink_metadata(path) {
            Ok(_) => {
                self.insert_existing(path, origins)?;
                Ok(true)
            }
            Err(source)
                if source.kind() == std::io::ErrorKind::NotFound
                    && missing == MissingPathBehavior::Skip =>
            {
                self.insert_missing(path, MissingFilesystemTargetKind::SkippedScope, None)?;
                Ok(false)
            }
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                Err(FilesystemPlanError::RequiredPathMissing {
                    path: path.to_path_buf(),
                })
            }
            Err(source) => Err(FilesystemPlanError::Metadata {
                path: path.to_path_buf(),
                source,
            }),
        }
    }

    fn collect_read_only_subpaths(
        &mut self,
        write_root: &Path,
        selectors: &[cageforge_policy::PathSelector],
    ) -> Result<(), FilesystemPlanError> {
        for selector in selectors {
            for path in self.context.resolve(selector) {
                if !is_within(&path, write_root) {
                    return Err(FilesystemPlanError::ReadOnlyOutsideWriteRoot {
                        path,
                        root: write_root.to_path_buf(),
                    });
                }
                match fs::symlink_metadata(&path) {
                    Ok(_) => self.insert_existing(
                        &path,
                        TargetOrigins {
                            read_only: true,
                            ..TargetOrigins::default()
                        },
                    )?,
                    Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                        self.insert_missing(
                            &path,
                            MissingFilesystemTargetKind::ReadOnly,
                            Some(write_root),
                        )?;
                    }
                    Err(source) => {
                        return Err(FilesystemPlanError::Metadata { path, source });
                    }
                }
            }
        }
        Ok(())
    }

    fn collect_glob(&mut self, pattern: &PathPattern) -> Result<(), FilesystemPlanError> {
        for root in self.context.glob_search_roots(pattern) {
            if self.glob_scan_max_depth.is_none()
                && is_complete_volume_root(&root)
                && pattern_is_recursive(pattern)
            {
                return Err(FilesystemPlanError::UnboundedRootGlob);
            }
            for path in scan_glob(
                pattern,
                self.context,
                &root,
                self.glob_scan_max_depth.map(NonZeroUsize::get),
            )? {
                if self
                    .prepared
                    .filesystem_access_for_path(self.backend, &path)?
                    != FilesystemDecision::Deny
                {
                    return Err(FilesystemPlanError::GlobPolicyMismatch { path });
                }
                self.insert_existing(
                    &path,
                    TargetOrigins {
                        glob: true,
                        ..TargetOrigins::default()
                    },
                )?;
            }
        }
        Ok(())
    }

    fn insert_existing(
        &mut self,
        path: &Path,
        origins: TargetOrigins,
    ) -> Result<(), FilesystemPlanError> {
        let validated = ValidatedPath::open_for_acl(path)?;
        let key = NativePathKey::new(validated.final_path());
        if let Some(existing) = self.pending.get_mut(&key) {
            existing.origins.merge(origins);
        } else {
            self.pending.insert(
                key,
                PendingFilesystemTarget {
                    path: validated,
                    origins,
                },
            );
        }
        Ok(())
    }

    fn insert_missing(
        &mut self,
        path: &Path,
        kind: MissingFilesystemTargetKind,
        required_root: Option<&Path>,
    ) -> Result<(), FilesystemPlanError> {
        let anchor = match kind {
            MissingFilesystemTargetKind::SkippedScope => None,
            MissingFilesystemTargetKind::ReadOnly | MissingFilesystemTargetKind::Protected => {
                Some(nearest_existing_ancestor(path, required_root)?)
            }
        };
        let key = (kind, NativePathKey::new(path));
        self.missing
            .entry(key)
            .or_insert_with(|| MissingFilesystemTarget {
                path: path.to_path_buf(),
                anchor,
                kind,
            });
        Ok(())
    }

    fn finish(mut self) -> Result<FilesystemPlan, FilesystemPlanError> {
        if !self.readable_platform_base {
            return Err(FilesystemPlanError::MissingReadablePlatformBase);
        }
        let preliminary = self.classify_pending()?;
        let write_roots = preliminary
            .iter()
            .filter(|target| target.access == FilesystemPlanAccess::WriteRoot)
            .map(|target| target.path.final_path().to_path_buf())
            .collect::<Vec<_>>();
        drop(preliminary);

        for root in &write_roots {
            let protected_paths = self
                .protected_relative_paths
                .values()
                .cloned()
                .collect::<Vec<_>>();
            for protected in protected_paths {
                let path = root.join(protected);
                match self
                    .prepared
                    .filesystem_access_for_path(self.backend, &path)?
                {
                    FilesystemDecision::Write => {
                        return Err(FilesystemPlanError::ProtectedPathWritable { path });
                    }
                    FilesystemDecision::ExternallyEnforced => {
                        return Err(FilesystemPlanError::ExternalPath { path });
                    }
                    FilesystemDecision::Read | FilesystemDecision::Deny => {}
                }
                match fs::symlink_metadata(&path) {
                    Ok(_) => self.insert_existing(
                        &path,
                        TargetOrigins {
                            protected: true,
                            ..TargetOrigins::default()
                        },
                    )?,
                    Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                        self.insert_missing(
                            &path,
                            MissingFilesystemTargetKind::Protected,
                            Some(root),
                        )?;
                    }
                    Err(source) => {
                        return Err(FilesystemPlanError::Metadata { path, source });
                    }
                }
            }
        }

        let targets = self.classify_pending()?;
        let profile_anchor = targets
            .iter()
            .find(|target| {
                matches!(
                    target.access,
                    FilesystemPlanAccess::ReadRoot | FilesystemPlanAccess::WriteRoot
                )
            })
            .map(|target| target.path.final_path().to_path_buf())
            .ok_or(FilesystemPlanError::MissingReadablePlatformBase)?;
        let missing = self.missing.into_values().collect::<Vec<_>>();
        let profile_sha256 = profile_digest(&targets, &missing);
        Ok(FilesystemPlan {
            profile_sha256,
            targets,
            missing,
            profile_anchor,
        })
    }

    fn classify_pending(&self) -> Result<Vec<FilesystemPlanTarget>, FilesystemPlanError> {
        let mut decisions = Vec::with_capacity(self.pending.len());
        let mut write_roots = Vec::new();
        for pending in self.pending.values() {
            let path = pending.path.final_path();
            let decision = self
                .prepared
                .filesystem_access_for_path(self.backend, path)?;
            if decision == FilesystemDecision::Write {
                if pending.origins.protected {
                    return Err(FilesystemPlanError::ProtectedPathWritable {
                        path: path.to_path_buf(),
                    });
                }
                if pending.origins.read_only {
                    return Err(FilesystemPlanError::ReadOnlyPolicyMismatch {
                        path: path.to_path_buf(),
                    });
                }
                write_roots.push(path.to_path_buf());
            }
            decisions.push(decision);
        }
        let mut targets = Vec::with_capacity(self.pending.len());
        for (pending, decision) in self.pending.values().zip(decisions) {
            let path = pending.path.final_path();
            let access = match decision {
                FilesystemDecision::Write => FilesystemPlanAccess::WriteRoot,
                FilesystemDecision::Read
                    if write_roots.iter().any(|root| is_within(path, root)) =>
                {
                    FilesystemPlanAccess::ReadOnly
                }
                FilesystemDecision::Read => FilesystemPlanAccess::ReadRoot,
                FilesystemDecision::Deny => FilesystemPlanAccess::Deny,
                FilesystemDecision::ExternallyEnforced => {
                    return Err(FilesystemPlanError::ExternalPath {
                        path: path.to_path_buf(),
                    });
                }
            };
            targets.push(FilesystemPlanTarget {
                path: ValidatedPath::open_for_acl(path)?,
                access,
                origins: pending.origins,
            });
        }
        Ok(targets)
    }
}

impl TargetOrigins {
    fn merge(&mut self, other: Self) {
        self.scope |= other.scope;
        self.read_only |= other.read_only;
        self.glob |= other.glob;
        self.protected |= other.protected;
    }
}

fn nearest_existing_ancestor(
    path: &Path,
    required_root: Option<&Path>,
) -> Result<ValidatedPath, FilesystemPlanError> {
    let mut candidate = path.parent();
    while let Some(parent) = candidate {
        if required_root.is_some_and(|root| !is_within(parent, root)) {
            break;
        }
        match fs::symlink_metadata(parent) {
            Ok(_) => return ValidatedPath::open_for_acl(parent).map_err(Into::into),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                candidate = parent.parent();
            }
            Err(source) => {
                return Err(FilesystemPlanError::Metadata {
                    path: parent.to_path_buf(),
                    source,
                });
            }
        }
    }
    Err(FilesystemPlanError::MissingTargetWithoutAnchor {
        path: path.to_path_buf(),
    })
}

fn scan_glob(
    pattern: &PathPattern,
    context: &EffectivePathContext,
    root: &Path,
    maximum_depth: Option<usize>,
) -> Result<Vec<PathBuf>, FilesystemPlanError> {
    let root_metadata = match fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(source) => {
            return Err(FilesystemPlanError::Metadata {
                path: root.to_path_buf(),
                source,
            });
        }
    };
    let mut stack = vec![(root.to_path_buf(), root_metadata, 0usize)];
    let mut matches = BTreeMap::new();
    while let Some((path, metadata, depth)) = stack.pop() {
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(FilesystemPlanError::GlobReparsePoint { path });
        }
        if context.pattern_matches(pattern, &path) {
            matches
                .entry(NativePathKey::new(&path))
                .or_insert_with(|| path.clone());
        }
        if !metadata.is_dir() || maximum_depth.is_some_and(|maximum| depth >= maximum) {
            continue;
        }
        let entries = fs::read_dir(&path).map_err(|source| FilesystemPlanError::GlobScan {
            path: path.clone(),
            source,
        })?;
        let mut children = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|source| FilesystemPlanError::GlobScan {
                path: path.clone(),
                source,
            })?;
            let child = entry.path();
            let metadata =
                fs::symlink_metadata(&child).map_err(|source| FilesystemPlanError::Metadata {
                    path: child.clone(),
                    source,
                })?;
            children.push((NativePathKey::new(&child), child, metadata));
        }
        children.sort_by(|left, right| left.0.cmp(&right.0));
        stack.extend(
            children
                .into_iter()
                .rev()
                .map(|(_, path, metadata)| (path, metadata, depth + 1)),
        );
    }
    Ok(matches.into_values().collect())
}

fn profile_digest(targets: &[FilesystemPlanTarget], missing: &[MissingFilesystemTarget]) -> String {
    let mut records = Vec::new();
    for target in targets {
        records.push((
            access_digest_tag(target.access),
            canonical_path_units(target.path.final_path()),
            Vec::new(),
        ));
        if target.origins.read_only {
            records.push((
                4,
                canonical_path_units(target.path.final_path()),
                Vec::new(),
            ));
        }
        if target.origins.glob {
            records.push((
                5,
                canonical_path_units(target.path.final_path()),
                Vec::new(),
            ));
        }
        if target.origins.protected {
            records.push((
                6,
                canonical_path_units(target.path.final_path()),
                Vec::new(),
            ));
        }
    }
    for target in missing {
        records.push((
            missing_digest_tag(target.kind),
            canonical_path_units(&target.path),
            target
                .anchor
                .as_ref()
                .map(|anchor| canonical_path_units(anchor.final_path()))
                .unwrap_or_default(),
        ));
    }
    records.sort();
    records.dedup();
    let mut digest = Sha256::new();
    digest.update(b"cageforge-windows-filesystem-profile-v1\0");
    for (kind, path, anchor) in records {
        digest.update([kind]);
        update_units(&mut digest, &path);
        update_units(&mut digest, &anchor);
    }
    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

const fn access_digest_tag(access: FilesystemPlanAccess) -> u8 {
    match access {
        FilesystemPlanAccess::ReadRoot => 0,
        FilesystemPlanAccess::WriteRoot => 1,
        FilesystemPlanAccess::ReadOnly => 2,
        FilesystemPlanAccess::Deny => 3,
    }
}

const fn missing_digest_tag(kind: MissingFilesystemTargetKind) -> u8 {
    match kind {
        MissingFilesystemTargetKind::SkippedScope => 7,
        MissingFilesystemTargetKind::ReadOnly => 8,
        MissingFilesystemTargetKind::Protected => 9,
    }
}

fn canonical_path_units(path: &Path) -> Vec<u16> {
    let normalized = normalize_lexical_path(path);
    let units = normalized.as_os_str().encode_wide().collect::<Vec<_>>();
    match String::from_utf16(&units) {
        Ok(value) => value.to_lowercase().encode_utf16().collect(),
        Err(_) => units,
    }
}

fn update_units(digest: &mut Sha256, units: &[u16]) {
    digest.update((units.len() as u64).to_le_bytes());
    for unit in units {
        digest.update(unit.to_le_bytes());
    }
}

fn pattern_is_recursive(pattern: &PathPattern) -> bool {
    pattern
        .as_str()
        .split(['/', '\\'])
        .any(|component| component == "**")
}

fn is_complete_volume_root(path: &Path) -> bool {
    let mut components = path.components();
    matches!(components.next(), Some(Component::Prefix(_)))
        && matches!(components.next(), Some(Component::RootDir))
        && components.next().is_none()
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use cageforge_backend_api::{
        BackendCapabilities, BackendCapability, BackendIdentity, BackendRequest, SandboxBackend,
    };
    use cageforge_command::{CommandRequest, CommandSpec, EnvironmentSpec};
    use cageforge_path::paths_equal;
    use cageforge_policy::{
        AccessMode, FilesystemPolicy, FilesystemRule, NetworkPolicy, PathResolutionContext,
        PathSelector, SandboxPolicy,
    };
    use cageforge_policy_compose::{CompositionRequest, PolicyCeiling, compose};
    use pretty_assertions::{assert_eq, assert_ne};

    use super::{FilesystemPlan, FilesystemPlanAccess};

    struct TestBackend {
        identity: BackendIdentity,
        capabilities: BackendCapabilities,
    }

    impl TestBackend {
        fn new() -> Self {
            Self {
                identity: BackendIdentity::new(),
                capabilities: BackendCapabilities::from_capabilities([
                    BackendCapability::CommandExecution,
                    BackendCapability::WorkingDirectory,
                    BackendCapability::StdioInherit,
                    BackendCapability::TimeoutBackendDefault,
                    BackendCapability::FilesystemRestricted,
                    BackendCapability::FilesystemScopes,
                    BackendCapability::FilesystemAbsoluteScopes,
                    BackendCapability::FilesystemWorkspaceScopes,
                    BackendCapability::FilesystemMinimalScopes,
                    BackendCapability::FilesystemGlobs,
                    BackendCapability::FilesystemGlobScanDepth,
                    BackendCapability::FilesystemReadOnlySubpaths,
                    BackendCapability::FilesystemMissingPathBehavior,
                    BackendCapability::FilesystemProtectedPaths,
                    BackendCapability::NetworkDisabled,
                    BackendCapability::EnvironmentAll,
                ]),
            }
        }
    }

    impl SandboxBackend for TestBackend {
        fn identity(&self) -> &BackendIdentity {
            &self.identity
        }

        fn capabilities(&self) -> BackendCapabilities {
            self.capabilities.clone()
        }
    }

    #[test]
    fn filesystem_plan_consumes_ceiling_deny_layer() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let minimal = temporary.path().join("minimal");
        let workspace = temporary.path().join("workspace");
        let secret = workspace.join("secret.txt");
        std::fs::create_dir_all(&minimal).expect("minimal directory");
        std::fs::create_dir_all(&workspace).expect("workspace directory");
        std::fs::write(&secret, b"secret").expect("secret fixture");
        let requested = FilesystemPolicy::restricted([
            FilesystemRule::new(PathSelector::minimal(), AccessMode::Read),
            FilesystemRule::new(absolute(&workspace), AccessMode::Write),
        ]);
        let ceiling = FilesystemPolicy::restricted([
            FilesystemRule::new(PathSelector::minimal(), AccessMode::Read),
            FilesystemRule::new(absolute(&workspace), AccessMode::Write),
            FilesystemRule::new(absolute(&secret), AccessMode::Deny),
        ]);

        let plan = plan(&workspace, &minimal, requested, ceiling);

        assert_eq!(
            target_access(&plan, &secret),
            Some(FilesystemPlanAccess::Deny)
        );
    }

    #[test]
    fn filesystem_profile_digest_ignores_declaration_order() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let minimal = temporary.path().join("minimal");
        let workspace = temporary.path().join("workspace");
        std::fs::create_dir_all(&minimal).expect("minimal directory");
        std::fs::create_dir_all(&workspace).expect("workspace directory");
        let first = FilesystemPolicy::restricted([
            FilesystemRule::new(PathSelector::minimal(), AccessMode::Read),
            FilesystemRule::new(absolute(&workspace), AccessMode::Write),
        ]);
        let second = FilesystemPolicy::restricted([
            FilesystemRule::new(absolute(&workspace), AccessMode::Write),
            FilesystemRule::new(PathSelector::minimal(), AccessMode::Read),
        ]);

        let first = plan(&workspace, &minimal, first.clone(), first);
        let second = plan(&workspace, &minimal, second.clone(), second);

        assert_eq!(first.profile_sha256(), second.profile_sha256());
    }

    #[test]
    fn filesystem_profile_digest_changes_with_missing_protected_obligation() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let minimal = temporary.path().join("minimal");
        let workspace = temporary.path().join("workspace");
        std::fs::create_dir_all(&minimal).expect("minimal directory");
        std::fs::create_dir_all(&workspace).expect("workspace directory");
        let base = FilesystemPolicy::restricted([
            FilesystemRule::new(PathSelector::minimal(), AccessMode::Read),
            FilesystemRule::new(absolute(&workspace), AccessMode::Write),
        ]);
        let extended = base
            .clone()
            .with_additional_protected_relative_path(".cageforge-test")
            .expect("protected path");

        let base = plan(&workspace, &minimal, base.clone(), base);
        let extended = plan(&workspace, &minimal, extended.clone(), extended);

        assert_ne!(base.profile_sha256(), extended.profile_sha256());
    }

    #[test]
    fn writable_child_remains_distinct_below_read_only_parent() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let minimal = temporary.path().join("minimal");
        let workspace = temporary.path().join("workspace");
        let read_only = workspace.join("read-only");
        let writable = read_only.join("writable");
        std::fs::create_dir_all(&minimal).expect("minimal directory");
        std::fs::create_dir_all(&writable).expect("nested writable directory");
        let workspace_rule = FilesystemRule::new(absolute(&workspace), AccessMode::Write)
            .with_read_only_subpath(absolute(&read_only))
            .expect("read-only carve-out");
        let policy = FilesystemPolicy::restricted([
            FilesystemRule::new(PathSelector::minimal(), AccessMode::Read),
            workspace_rule,
            FilesystemRule::new(absolute(&writable), AccessMode::Write),
        ]);

        let plan = plan(&workspace, &minimal, policy.clone(), policy);

        assert_eq!(
            target_access(&plan, &workspace),
            Some(FilesystemPlanAccess::WriteRoot)
        );
        assert_eq!(
            target_access(&plan, &read_only),
            Some(FilesystemPlanAccess::ReadOnly)
        );
        assert_eq!(
            target_access(&plan, &writable),
            Some(FilesystemPlanAccess::WriteRoot)
        );
    }

    fn plan(
        workspace: &Path,
        minimal: &Path,
        requested_filesystem: FilesystemPolicy,
        ceiling_filesystem: FilesystemPolicy,
    ) -> FilesystemPlan {
        let environment = EnvironmentSpec::inherit_all();
        let requested = SandboxPolicy::new(requested_filesystem, NetworkPolicy::disabled());
        let ceiling = PolicyCeiling::new(
            SandboxPolicy::new(ceiling_filesystem, NetworkPolicy::disabled()),
            environment.clone(),
        );
        let effective = compose(CompositionRequest::new(&requested, &environment, &ceiling))
            .expect("compose policies");
        let command = CommandRequest::new(CommandSpec::new("cmd.exe").expect("command"))
            .with_working_directory(workspace)
            .expect("working directory")
            .with_environment(environment);
        let context = PathResolutionContext::new()
            .with_workspace_root(workspace)
            .expect("workspace root")
            .with_minimal_path(minimal)
            .expect("minimal path")
            .with_current_directory(workspace)
            .expect("current directory");
        let backend = TestBackend::new();
        let prepared = BackendRequest::new(&command, &effective)
            .prepare_for(&backend, &context)
            .expect("prepare backend request");
        FilesystemPlan::lower(&backend, &prepared).expect("lower filesystem plan")
    }

    fn target_access(plan: &FilesystemPlan, path: &Path) -> Option<FilesystemPlanAccess> {
        plan.targets()
            .iter()
            .find(|target| paths_equal(target.path().final_path(), path))
            .map(|target| target.access())
    }

    fn absolute(path: &Path) -> PathSelector {
        PathSelector::absolute(PathBuf::from(path)).expect("absolute selector")
    }
}
