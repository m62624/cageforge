// SPDX-License-Identifier: Apache-2.0

//! Linux filesystem policy lowering into a Bubblewrap mount overlay.

mod glob;
pub(super) mod protected_create;
pub(super) mod synthetic;

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CString, OsString};
use std::fs::{self, File};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use cageforge_backend_api::{BackendCapability, PreparedBackendRequest};
use cageforge_path::normalize_lexical_path;
use cageforge_policy::{
    AccessMode, FilesystemDecision, FilesystemMode, FilesystemTarget, MissingPathBehavior,
};
use cageforge_policy_compose::{EffectiveFilesystemLayer, EffectiveSandbox};

use self::synthetic::{SetupLock, SyntheticMountTarget};
use crate::backend::{IN_SANDBOX_HELPER_PATH, LinuxBackend};
use crate::error::{
    FilesystemLoweringError, FilesystemMetadataOperation, LinuxBackendError,
    PolicyLoweringExpectation,
};
use crate::network::IN_SANDBOX_GATEWAY_SOCKET;

const PRIVATE_RUNTIME_ROOT: &str = "/dev/.cageforge-runtime";

#[derive(Debug)]
pub(crate) struct FilesystemPlan {
    pub(crate) args: Vec<OsString>,
    pub(crate) preserved_files: Vec<File>,
    synthetic_targets: Vec<SyntheticMountTarget>,
    protected_create_paths: Vec<PathBuf>,
}

impl FilesystemPlan {
    pub(crate) fn take_synthetic_targets(&mut self) -> Vec<SyntheticMountTarget> {
        std::mem::take(&mut self.synthetic_targets)
    }

    pub(crate) fn take_protected_create_paths(&mut self) -> Vec<PathBuf> {
        std::mem::take(&mut self.protected_create_paths)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mount {
    Read,
    Write,
    ReadOnly,
    Deny,
}

impl Mount {
    fn is_bind(self) -> bool {
        matches!(self, Self::Read | Self::Write)
    }

    fn is_mask(self) -> bool {
        matches!(self, Self::ReadOnly | Self::Deny)
    }

    fn access(self) -> AccessMode {
        match self {
            Self::Read | Self::ReadOnly | Self::Deny => AccessMode::Read,
            Self::Write => AccessMode::Write,
        }
    }
}

pub(crate) fn lower<'a>(
    backend: &LinuxBackend,
    prepared: &PreparedBackendRequest<'a, LinuxBackend>,
    sandbox: &EffectiveSandbox,
    gateway_mount: Option<&Path>,
) -> Result<FilesystemPlan, LinuxBackendError> {
    let mode = sandbox.filesystem().requirements().mode();
    if mode == FilesystemMode::External {
        return Err(LinuxBackendError::UnsupportedCapability {
            capability: BackendCapability::FilesystemExternal,
        });
    }
    if mode == FilesystemMode::Unrestricted {
        let setup_lock = SetupLock::acquire()?;
        drop(setup_lock);
        let mut args = Vec::new();
        let mut preserved_files = Vec::new();
        add_bind(
            &mut args,
            Path::new("/"),
            AccessMode::Write,
            &mut preserved_files,
        )?;
        append_dev(&mut args, true);
        append_shared_state_mask(&mut args);
        append_private_runtime(
            &mut args,
            backend.hardening_helper_file(),
            gateway_mount,
            &mut preserved_files,
        )?;
        return Ok(FilesystemPlan {
            args,
            preserved_files,
            synthetic_targets: Vec::new(),
            protected_create_paths: Vec::new(),
        });
    }

    let context = prepared.path_context(backend)?;
    let lowering = prepared.filesystem_lowering(backend)?;
    let mut mounts = BTreeMap::<PathBuf, Mount>::new();
    let mut protected_paths = BTreeSet::new();
    for layer in lowering.layers() {
        collect_layer_mounts(
            backend,
            prepared,
            context,
            layer,
            lowering.glob_scan_max_depth(),
            &mut mounts,
            &mut protected_paths,
        )?;
    }
    reject_unsafe_bind_symlinks(&mounts)?;
    let mut protected_create_paths = BTreeSet::new();
    apply_protected_paths(
        backend,
        prepared,
        &protected_paths,
        &mut mounts,
        &mut protected_create_paths,
    )?;
    let shared_state_root = synthetic::shared_state_root();
    reject_reserved_runtime_paths(&mounts, &shared_state_root)?;
    if mounts
        .iter()
        .any(|(path, mount)| mount.is_bind() && shared_state_root.starts_with(path))
    {
        insert_mount(&mut mounts, shared_state_root, Mount::Deny);
    }

    let writable_roots = mounts
        .iter()
        .filter(|(_, mount)| **mount == Mount::Write)
        .map(|(path, _)| path.clone())
        .collect::<Vec<_>>();
    let mut synthetic_targets = Vec::new();
    materialize_missing_masks(&writable_roots, &mut mounts, &mut synthetic_targets)?;

    let mut args = vec!["--tmpfs".into(), "/".into()];
    let mut preserved_files = Vec::new();
    let mut empty_mask_descriptor = None;
    if let Some(mount) = mounts.get(Path::new("/")).copied() {
        match mount {
            Mount::Read | Mount::Write => add_bind(
                &mut args,
                Path::new("/"),
                mount.access(),
                &mut preserved_files,
            )?,
            Mount::ReadOnly => add_bind(
                &mut args,
                Path::new("/"),
                AccessMode::Read,
                &mut preserved_files,
            )?,
            Mount::Deny => {}
        }
    }
    append_dev(&mut args, false);

    let mut ordered_mounts = mounts
        .iter()
        .filter(|(path, _)| path.as_path() != Path::new("/"))
        .map(|(path, mount)| (path.clone(), *mount))
        .collect::<Vec<_>>();
    ordered_mounts.sort_by(|(left, _), (right, _)| {
        left.components()
            .count()
            .cmp(&right.components().count())
            .then_with(|| left.cmp(right))
    });
    for (path, mount) in &ordered_mounts {
        if mount.is_bind() {
            add_bind(&mut args, path, mount.access(), &mut preserved_files)?;
        } else {
            add_mask(
                &mut args,
                path,
                *mount,
                &writable_roots,
                &ordered_mounts,
                &mut preserved_files,
                &mut empty_mask_descriptor,
            )?;
        }
    }
    append_private_runtime(
        &mut args,
        backend.hardening_helper_file(),
        gateway_mount,
        &mut preserved_files,
    )?;
    Ok(FilesystemPlan {
        args,
        preserved_files,
        synthetic_targets,
        protected_create_paths: protected_create_paths.into_iter().collect(),
    })
}

#[allow(clippy::too_many_arguments)]
fn collect_layer_mounts<'a>(
    backend: &LinuxBackend,
    prepared: &PreparedBackendRequest<'a, LinuxBackend>,
    context: &cageforge_policy_compose::EffectivePathContext,
    layer: EffectiveFilesystemLayer<'_>,
    glob_scan_max_depth: Option<std::num::NonZeroUsize>,
    mounts: &mut BTreeMap<PathBuf, Mount>,
    protected_paths: &mut BTreeSet<PathBuf>,
) -> Result<(), LinuxBackendError> {
    protected_paths.extend(layer.protected_relative_paths().iter().cloned());
    for rule in layer.entries() {
        match rule.target() {
            FilesystemTarget::Scope(selector) => {
                for path in context.resolve(selector) {
                    add_scope_mount(
                        backend,
                        prepared,
                        &path,
                        rule.missing_path_behavior(),
                        mounts,
                    )?;
                    for subpath in rule.read_only_subpaths() {
                        for subpath in context.resolve(subpath) {
                            if subpath.starts_with(&path) {
                                add_read_only_path(backend, prepared, &subpath, mounts)?;
                            }
                        }
                    }
                }
            }
            FilesystemTarget::Glob(pattern) => {
                for (path, directly_matched) in glob::expand(pattern, context, glob_scan_max_depth)?
                {
                    if directly_matched
                        && prepared.filesystem_access_for_path(backend, &path)?
                            != FilesystemDecision::Deny
                    {
                        return Err(LinuxBackendError::PolicyLoweringMismatch {
                            path,
                            expected: PolicyLoweringExpectation::DenyGlobMatch,
                        });
                    }
                    insert_mount(mounts, path, Mount::Deny);
                }
            }
        }
    }
    Ok(())
}

fn add_scope_mount<'a>(
    backend: &LinuxBackend,
    prepared: &PreparedBackendRequest<'a, LinuxBackend>,
    path: &Path,
    missing: MissingPathBehavior,
    mounts: &mut BTreeMap<PathBuf, Mount>,
) -> Result<(), LinuxBackendError> {
    let decision = prepared.filesystem_access_for_path(backend, path)?;
    let mount = match decision {
        FilesystemDecision::Read => Mount::Read,
        FilesystemDecision::Write => Mount::Write,
        FilesystemDecision::Deny => Mount::Deny,
        FilesystemDecision::ExternallyEnforced => {
            return Err(LinuxBackendError::UnsupportedCapability {
                capability: BackendCapability::FilesystemExternal,
            });
        }
    };
    add_existing_scope(path, mount, missing, mounts)?;
    if mount == Mount::Deny
        && let Ok(canonical) = fs::canonicalize(path)
        && canonical != path
    {
        insert_mount(mounts, canonical, Mount::Deny);
    }
    Ok(())
}

fn add_existing_scope(
    path: &Path,
    mount: Mount,
    missing: MissingPathBehavior,
    mounts: &mut BTreeMap<PathBuf, Mount>,
) -> Result<(), LinuxBackendError> {
    validate_mount_path(path)?;
    match fs::symlink_metadata(path) {
        Ok(_) => insert_mount(mounts, path.to_path_buf(), mount),
        Err(source)
            if missing == MissingPathBehavior::Skip
                && source.kind() == std::io::ErrorKind::NotFound =>
        {
            return Ok(());
        }
        Err(source) => {
            return Err(LinuxBackendError::FilesystemLoweringFailed {
                path: path.to_path_buf(),
                source: FilesystemLoweringError::Metadata {
                    operation: FilesystemMetadataOperation::Scope,
                    source,
                },
            });
        }
    }
    Ok(())
}

fn add_read_only_path<'a>(
    backend: &LinuxBackend,
    prepared: &PreparedBackendRequest<'a, LinuxBackend>,
    path: &Path,
    mounts: &mut BTreeMap<PathBuf, Mount>,
) -> Result<(), LinuxBackendError> {
    match prepared.filesystem_access_for_path(backend, path)? {
        FilesystemDecision::Deny => insert_mount(mounts, path.to_path_buf(), Mount::Deny),
        FilesystemDecision::Read => insert_mount(mounts, path.to_path_buf(), Mount::ReadOnly),
        FilesystemDecision::Write => {}
        FilesystemDecision::ExternallyEnforced => {
            return Err(LinuxBackendError::UnsupportedCapability {
                capability: BackendCapability::FilesystemExternal,
            });
        }
    }
    Ok(())
}

fn apply_protected_paths<'a>(
    backend: &LinuxBackend,
    prepared: &PreparedBackendRequest<'a, LinuxBackend>,
    protected_paths: &BTreeSet<PathBuf>,
    mounts: &mut BTreeMap<PathBuf, Mount>,
    protected_create_paths: &mut BTreeSet<PathBuf>,
) -> Result<(), LinuxBackendError> {
    let writable_roots = mounts
        .iter()
        .filter(|(_, mount)| **mount == Mount::Write)
        .map(|(path, _)| path.clone())
        .collect::<Vec<_>>();
    for root in writable_roots {
        for protected in protected_paths {
            let path = root.join(protected);
            if let Some(symlink) = first_writable_symlink(&path, std::slice::from_ref(&root)) {
                return Err(writable_symlink_error(&path, &symlink));
            }
            if should_monitor_missing_git(&root, protected, &path) {
                protected_create_paths.insert(path);
            } else {
                add_read_only_path(backend, prepared, &path, mounts)?;
            }
        }
    }
    Ok(())
}

fn reject_unsafe_bind_symlinks(mounts: &BTreeMap<PathBuf, Mount>) -> Result<(), LinuxBackendError> {
    let writable_roots = mounts
        .iter()
        .filter(|(_, mount)| **mount == Mount::Write)
        .map(|(path, _)| path.as_path())
        .collect::<Vec<_>>();
    if writable_roots.iter().any(|root| *root == Path::new("/")) {
        return Ok(());
    }

    for (path, mount) in mounts.iter().filter(|(_, mount)| mount.is_bind()) {
        let under_writable_root = writable_roots
            .iter()
            .any(|root| path == *root || path.starts_with(root));
        if (*mount == Mount::Write || under_writable_root)
            && let Some(symlink) = first_symlink_component(path)
        {
            return Err(LinuxBackendError::FilesystemLoweringFailed {
                path: path.clone(),
                source: FilesystemLoweringError::WritableSymlinkMount { symlink },
            });
        }
    }
    Ok(())
}

fn first_symlink_component(path: &Path) -> Option<PathBuf> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if fs::symlink_metadata(&current)
            .ok()?
            .file_type()
            .is_symlink()
        {
            return Some(current);
        }
    }
    None
}

fn should_monitor_missing_git(root: &Path, protected: &Path, path: &Path) -> bool {
    protected == Path::new(".git")
        && matches!(
            fs::symlink_metadata(path),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound
        )
        && fs::canonicalize(root)
            .unwrap_or_else(|_| root.to_path_buf())
            .ancestors()
            .skip(1)
            .any(ancestor_has_git_metadata)
}

fn ancestor_has_git_metadata(ancestor: &Path) -> bool {
    let git = ancestor.join(".git");
    let Ok(metadata) = fs::symlink_metadata(&git) else {
        return false;
    };
    if metadata.is_dir() {
        return fs::symlink_metadata(git.join("HEAD")).is_ok();
    }
    metadata.is_file()
        && fs::read_to_string(git)
            .is_ok_and(|contents| contents.trim_start().starts_with("gitdir:"))
}

fn materialize_missing_masks(
    writable_roots: &[PathBuf],
    mounts: &mut BTreeMap<PathBuf, Mount>,
    synthetic_targets: &mut Vec<SyntheticMountTarget>,
) -> Result<(), LinuxBackendError> {
    for path in mounts
        .iter()
        .filter(|(_, mount)| mount.is_mask())
        .map(|(path, _)| path)
    {
        if let Some(symlink) = first_writable_symlink(path, writable_roots) {
            return Err(writable_symlink_error(path, &symlink));
        }
    }
    let setup_lock = SetupLock::acquire()?;
    let mask_paths = mounts
        .iter()
        .filter(|(_, mount)| mount.is_mask())
        .map(|(path, mount)| (path.clone(), *mount))
        .collect::<Vec<_>>();
    let mut missing_masks = Vec::new();
    for (path, mount) in mask_paths {
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                if let Some(target) = SyntheticMountTarget::join(&path, &setup_lock)? {
                    synthetic_targets.push(target);
                }
            }
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                missing_masks.push((path, mount));
            }
            Err(source) => {
                return Err(LinuxBackendError::FilesystemLoweringFailed {
                    path,
                    source: FilesystemLoweringError::Metadata {
                        operation: FilesystemMetadataOperation::Mask,
                        source,
                    },
                });
            }
        }
    }
    for (path, mount) in missing_masks {
        mounts.remove(&path);
        let Some(first_missing) = first_missing_component(&path)? else {
            continue;
        };
        if !writable_roots
            .iter()
            .any(|root| first_missing.starts_with(root))
        {
            continue;
        }
        validate_mount_path(&first_missing)?;
        let target = SyntheticMountTarget::create(&first_missing, &setup_lock)?;
        insert_mount(mounts, target.path().to_path_buf(), mount);
        synthetic_targets.push(target);
    }
    prune_redundant_denied_descendants(mounts);
    Ok(())
}

fn prune_redundant_denied_descendants(mounts: &mut BTreeMap<PathBuf, Mount>) {
    let denied = mounts
        .iter()
        .filter(|(_, mount)| **mount == Mount::Deny)
        .map(|(path, _)| path.clone())
        .collect::<Vec<_>>();
    for path in denied {
        if mounts.iter().any(|(ancestor, mount)| {
            *mount == Mount::Deny && ancestor != &path && path.starts_with(ancestor)
        }) {
            mounts.remove(&path);
        }
    }
}

fn first_missing_component(path: &Path) -> Result<Option<PathBuf>, LinuxBackendError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(_) => {}
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Some(current));
            }
            Err(source) => {
                return Err(LinuxBackendError::FilesystemLoweringFailed {
                    path: current,
                    source: FilesystemLoweringError::Metadata {
                        operation: FilesystemMetadataOperation::WritableSymlinkAncestor,
                        source,
                    },
                });
            }
        }
    }
    Ok(None)
}

fn insert_mount(mounts: &mut BTreeMap<PathBuf, Mount>, path: PathBuf, mount: Mount) {
    let path = normalize_lexical_path(&path).into_owned();
    mounts
        .entry(path)
        .and_modify(|current| *current = stricter_mount(*current, mount))
        .or_insert(mount);
}

fn stricter_mount(left: Mount, right: Mount) -> Mount {
    match (left, right) {
        (Mount::Deny, _) | (_, Mount::Deny) => Mount::Deny,
        (Mount::ReadOnly, _) | (_, Mount::ReadOnly) => Mount::ReadOnly,
        (Mount::Read, _) | (_, Mount::Read) => Mount::Read,
        (Mount::Write, Mount::Write) => Mount::Write,
    }
}

fn validate_mount_path(path: &Path) -> Result<(), LinuxBackendError> {
    if path.as_os_str().is_empty() || !path.is_absolute() {
        Err(LinuxBackendError::FilesystemLoweringFailed {
            path: path.to_path_buf(),
            source: FilesystemLoweringError::InvalidMountTarget,
        })
    } else {
        Ok(())
    }
}

fn reject_reserved_runtime_paths(
    mounts: &BTreeMap<PathBuf, Mount>,
    shared_state_root: &Path,
) -> Result<(), LinuxBackendError> {
    let runtime = Path::new(PRIVATE_RUNTIME_ROOT);
    if let Some(path) = mounts.keys().find(|path| {
        path.as_path() != Path::new("/")
            && (path.starts_with("/proc")
                || path.starts_with(runtime)
                || runtime.starts_with(path.as_path())
                || path.starts_with(shared_state_root))
    }) {
        return Err(LinuxBackendError::FilesystemLoweringFailed {
            path: path.clone(),
            source: FilesystemLoweringError::ReservedRuntimePath,
        });
    }
    Ok(())
}

fn append_dev(args: &mut Vec<OsString>, restore_shared_memory: bool) {
    args.extend(["--dev".into(), "/dev".into()]);
    if restore_shared_memory {
        args.extend(["--bind-try".into(), "/dev/shm".into(), "/dev/shm".into()]);
    }
}

fn append_shared_state_mask(args: &mut Vec<OsString>) {
    let state = synthetic::shared_state_root();
    args.extend([
        "--perms".into(),
        "000".into(),
        "--tmpfs".into(),
        state.as_os_str().into(),
        "--remount-ro".into(),
        state.into_os_string(),
    ]);
}

fn append_private_runtime(
    args: &mut Vec<OsString>,
    helper: &File,
    gateway_mount: Option<&Path>,
    preserved_files: &mut Vec<File>,
) -> Result<(), LinuxBackendError> {
    args.extend([
        "--dir".into(),
        PRIVATE_RUNTIME_ROOT.into(),
        "--tmpfs".into(),
        PRIVATE_RUNTIME_ROOT.into(),
    ]);
    add_bind_file(
        args,
        helper,
        Path::new(IN_SANDBOX_HELPER_PATH),
        AccessMode::Read,
        preserved_files,
    )?;
    if let Some(gateway_mount) = gateway_mount {
        let gateway_directory = Path::new(IN_SANDBOX_GATEWAY_SOCKET)
            .parent()
            .ok_or_else(|| LinuxBackendError::FilesystemLoweringFailed {
                path: PathBuf::from(IN_SANDBOX_GATEWAY_SOCKET),
                source: FilesystemLoweringError::GatewaySocketParentMissing,
            })?;
        args.extend(["--dir".into(), gateway_directory.as_os_str().into()]);
        add_bind_fd(
            args,
            gateway_mount,
            gateway_directory,
            AccessMode::Read,
            preserved_files,
        )?;
    }
    args.extend(["--remount-ro".into(), PRIVATE_RUNTIME_ROOT.into()]);
    Ok(())
}

fn add_bind(
    args: &mut Vec<OsString>,
    path: &Path,
    access: AccessMode,
    preserved_files: &mut Vec<File>,
) -> Result<(), LinuxBackendError> {
    let canonical =
        fs::canonicalize(path).map_err(|source| LinuxBackendError::FilesystemLoweringFailed {
            path: path.to_path_buf(),
            source: FilesystemLoweringError::Canonicalize { source },
        })?;
    if canonical == path {
        add_bind_fd(args, path, path, access, preserved_files)
    } else {
        // Bubblewrap must resolve a symlink destination such as `/bin` while
        // constructing the namespace; its `--*-bind-fd` race check compares
        // the source inode with the destination and therefore rejects that
        // legitimate layout.  Keep the canonical source explicit here, as
        // Codex does for the same runtime roots.
        args.extend([
            match access {
                AccessMode::Read => "--ro-bind".into(),
                AccessMode::Write => "--bind".into(),
                AccessMode::Deny => {
                    return Err(LinuxBackendError::FilesystemLoweringFailed {
                        path: path.to_path_buf(),
                        source: FilesystemLoweringError::DenyCanonicalBind,
                    });
                }
            },
            canonical.into_os_string(),
            path.as_os_str().into(),
        ]);
        Ok(())
    }
}

fn add_bind_fd(
    args: &mut Vec<OsString>,
    source: &Path,
    destination: &Path,
    access: AccessMode,
    preserved_files: &mut Vec<File>,
) -> Result<(), LinuxBackendError> {
    let file = open_mount_source(source)?;
    let descriptor = file.as_raw_fd();
    args.extend([
        match access {
            AccessMode::Read => "--ro-bind-fd".into(),
            AccessMode::Write => "--bind-fd".into(),
            AccessMode::Deny => {
                return Err(LinuxBackendError::FilesystemLoweringFailed {
                    path: destination.to_path_buf(),
                    source: FilesystemLoweringError::DenyDescriptorBind,
                });
            }
        },
        descriptor.to_string().into(),
        destination.as_os_str().into(),
    ]);
    preserved_files.push(file);
    Ok(())
}

fn add_bind_file(
    args: &mut Vec<OsString>,
    source: &File,
    destination: &Path,
    access: AccessMode,
    preserved_files: &mut Vec<File>,
) -> Result<(), LinuxBackendError> {
    let file =
        source
            .try_clone()
            .map_err(|source| LinuxBackendError::FilesystemLoweringFailed {
                path: destination.to_path_buf(),
                source: FilesystemLoweringError::CloneSource { source },
            })?;
    let descriptor = file.as_raw_fd();
    args.extend([
        match access {
            AccessMode::Read => "--ro-bind-fd".into(),
            AccessMode::Write => "--bind-fd".into(),
            AccessMode::Deny => {
                return Err(LinuxBackendError::FilesystemLoweringFailed {
                    path: destination.to_path_buf(),
                    source: FilesystemLoweringError::DenyPinnedFileBind,
                });
            }
        },
        descriptor.to_string().into(),
        destination.as_os_str().into(),
    ]);
    preserved_files.push(file);
    Ok(())
}

fn open_mount_source(path: &Path) -> Result<File, LinuxBackendError> {
    let path_bytes = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        LinuxBackendError::FilesystemLoweringFailed {
            path: path.to_path_buf(),
            source: FilesystemLoweringError::SourceContainsNul,
        }
    })?;
    #[allow(unsafe_code)]
    let descriptor = unsafe { libc::open(path_bytes.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if descriptor < 0 {
        return Err(LinuxBackendError::FilesystemLoweringFailed {
            path: path.to_path_buf(),
            source: FilesystemLoweringError::OpenSource {
                source: std::io::Error::last_os_error(),
            },
        });
    }
    #[allow(unsafe_code)]
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn add_mask(
    args: &mut Vec<OsString>,
    path: &Path,
    mount: Mount,
    writable_roots: &[PathBuf],
    ordered_mounts: &[(PathBuf, Mount)],
    preserved_files: &mut Vec<File>,
    empty_mask_descriptor: &mut Option<std::os::fd::RawFd>,
) -> Result<(), LinuxBackendError> {
    if path == Path::new("/") {
        return Err(LinuxBackendError::FilesystemLoweringFailed {
            path: path.to_path_buf(),
            source: FilesystemLoweringError::RootCannotBeMasked,
        });
    }
    if let Some(symlink) = first_writable_symlink(path, writable_roots) {
        return Err(writable_symlink_error(path, &symlink));
    }
    let metadata = fs::symlink_metadata(path).map_err(|source| {
        LinuxBackendError::FilesystemLoweringFailed {
            path: path.to_path_buf(),
            source: FilesystemLoweringError::Metadata {
                operation: FilesystemMetadataOperation::Mask,
                source,
            },
        }
    })?;
    if metadata.file_type().is_symlink() && mount == Mount::Deny {
        return Ok(());
    }
    if mount == Mount::ReadOnly {
        add_bind(args, path, AccessMode::Read, preserved_files)?;
    } else if metadata.is_dir() {
        let descendant_targets = descendant_mount_directories(path, ordered_mounts)?;
        args.extend([
            "--perms".into(),
            if descendant_targets.is_empty() {
                "000".into()
            } else {
                "111".into()
            },
            "--tmpfs".into(),
            path.as_os_str().into(),
        ]);
        for target in descendant_targets {
            args.extend(["--dir".into(), target.into_os_string()]);
        }
        args.extend(["--remount-ro".into(), path.as_os_str().into()]);
    } else {
        let descriptor = match *empty_mask_descriptor {
            Some(descriptor) => descriptor,
            None => {
                let file = File::open("/dev/null").map_err(|source| {
                    LinuxBackendError::FilesystemLoweringFailed {
                        path: path.to_path_buf(),
                        source: FilesystemLoweringError::EmptyMaskSource { source },
                    }
                })?;
                let descriptor = file.as_raw_fd();
                preserved_files.push(file);
                *empty_mask_descriptor = Some(descriptor);
                descriptor
            }
        };
        args.extend([
            "--perms".into(),
            "000".into(),
            "--ro-bind-data".into(),
            descriptor.to_string().into(),
            path.as_os_str().into(),
        ]);
    }
    Ok(())
}

fn writable_symlink_error(path: &Path, symlink: &Path) -> LinuxBackendError {
    LinuxBackendError::FilesystemLoweringFailed {
        path: path.to_path_buf(),
        source: FilesystemLoweringError::WritableSymlink {
            symlink: symlink.to_path_buf(),
        },
    }
}

fn descendant_mount_directories(
    masked_path: &Path,
    ordered_mounts: &[(PathBuf, Mount)],
) -> Result<Vec<PathBuf>, LinuxBackendError> {
    let mut directories = BTreeSet::new();
    for (path, _) in ordered_mounts
        .iter()
        .filter(|(path, _)| path != masked_path && path.starts_with(masked_path))
    {
        let metadata =
            fs::metadata(path).map_err(|source| LinuxBackendError::FilesystemLoweringFailed {
                path: path.clone(),
                source: FilesystemLoweringError::Metadata {
                    operation: FilesystemMetadataOperation::DescendantMount,
                    source,
                },
            })?;
        let target = if metadata.is_dir() {
            path.as_path()
        } else {
            path.parent().unwrap_or(masked_path)
        };
        let mut current = target.to_path_buf();
        let mut reversed = Vec::new();
        while current != masked_path && current.starts_with(masked_path) {
            reversed.push(current.clone());
            let Some(parent) = current.parent() else {
                break;
            };
            current = parent.to_path_buf();
        }
        directories.extend(reversed.into_iter().rev());
    }
    let mut directories = directories.into_iter().collect::<Vec<_>>();
    directories.sort_by(|left, right| {
        left.components()
            .count()
            .cmp(&right.components().count())
            .then_with(|| left.cmp(right))
    });
    Ok(directories)
}

fn first_writable_symlink(path: &Path, writable_roots: &[PathBuf]) -> Option<PathBuf> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current).ok()?;
        if metadata.file_type().is_symlink()
            && writable_roots
                .iter()
                .any(|root| current.starts_with(root) && current != *root)
        {
            return Some(current);
        }
    }
    None
}
