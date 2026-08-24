// SPDX-License-Identifier: Apache-2.0

//! Cross-process ownership for short-lived Bubblewrap mount targets.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::LinuxBackendError;

static OWNER_SEQUENCE: AtomicU64 = AtomicU64::new(1);
const SHARED_SETUP_DIRECTORY: &str = "/tmp";

/// Serializes registry and mount-target mutations across Cageforge processes
/// running under the same user.
pub(crate) struct SetupLock {
    file: File,
}

impl SetupLock {
    pub(crate) fn acquire() -> Result<Self, LinuxBackendError> {
        let uid = effective_uid();
        let state_root = shared_state_root_for(uid);
        ensure_private_directory(&state_root, uid)?;
        let path = state_root.join("setup.lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|source| LinuxBackendError::SetupLockFailed {
                path: path.clone(),
                source,
            })?;
        validate_private_file(&path, &file, uid)?;
        loop {
            #[allow(unsafe_code)]
            let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
            if result == 0 {
                break;
            }
            let source = std::io::Error::last_os_error();
            if source.kind() != std::io::ErrorKind::Interrupted {
                return Err(LinuxBackendError::SetupLockFailed { path, source });
            }
        }
        Ok(Self { file })
    }
}

impl Drop for SetupLock {
    fn drop(&mut self) {
        #[allow(unsafe_code)]
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

impl FileIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }

    fn encode(self) -> String {
        format!("{}:{}", self.device, self.inode)
    }

    fn decode(value: &str) -> Option<Self> {
        let (device, inode) = value.trim().split_once(':')?;
        Some(Self {
            device: device.parse().ok()?,
            inode: inode.parse().ok()?,
        })
    }
}

/// One host directory shared by active Bubblewrap launch instances.
#[derive(Debug)]
pub(crate) struct SyntheticMountTarget {
    path: PathBuf,
    identity: FileIdentity,
    marker_file: PathBuf,
    marker_dir: PathBuf,
    active: bool,
}

impl SyntheticMountTarget {
    pub(super) fn create(path: &Path, _lock: &SetupLock) -> Result<Self, LinuxBackendError> {
        let uid = effective_uid();
        let registry_root = registry_root(uid);
        ensure_private_directory(&registry_root, uid)?;
        let marker_dir = registry_root.join(stable_path_key(path));
        ensure_private_directory(&marker_dir, uid)?;
        verify_registry_path(&marker_dir, path)?;
        cleanup_stale_markers(&marker_dir)?;

        let identity_path = marker_dir.join("identity");
        let identity = if has_active_owner(&marker_dir)? {
            let identity = read_identity(&identity_path, path)?;
            let metadata = fs::symlink_metadata(path).map_err(|source| {
                LinuxBackendError::SyntheticMountTargetFailed {
                    path: path.to_path_buf(),
                    source,
                }
            })?;
            if !metadata.file_type().is_dir() || FileIdentity::from_metadata(&metadata) != identity
            {
                return Err(LinuxBackendError::SyntheticMountTargetChanged {
                    path: path.to_path_buf(),
                });
            }
            identity
        } else {
            cleanup_stale_target(path, &identity_path)?;
            fs::DirBuilder::new()
                .mode(0o700)
                .create(path)
                .map_err(|source| LinuxBackendError::SyntheticMountTargetFailed {
                    path: path.to_path_buf(),
                    source,
                })?;
            let metadata = fs::symlink_metadata(path).map_err(|source| {
                LinuxBackendError::SyntheticMountTargetFailed {
                    path: path.to_path_buf(),
                    source,
                }
            })?;
            let identity = FileIdentity::from_metadata(&metadata);
            write_private_new(&identity_path, identity.encode().as_bytes())?;
            identity
        };
        let marker_file = register_owner(&marker_dir)?;
        Ok(Self {
            path: path.to_path_buf(),
            identity,
            marker_file,
            marker_dir,
            active: true,
        })
    }

    pub(super) fn join(path: &Path, _lock: &SetupLock) -> Result<Option<Self>, LinuxBackendError> {
        let marker_dir = registry_root(effective_uid()).join(stable_path_key(path));
        if !marker_dir.is_dir() {
            return Ok(None);
        }
        verify_existing_registry_path(&marker_dir, path)?;
        cleanup_stale_markers(&marker_dir)?;
        if !has_active_owner(&marker_dir)? {
            return Ok(None);
        }
        let identity = read_identity(&marker_dir.join("identity"), path)?;
        let metadata = fs::symlink_metadata(path).map_err(|source| {
            LinuxBackendError::SyntheticMountTargetFailed {
                path: path.to_path_buf(),
                source,
            }
        })?;
        if !metadata.file_type().is_dir() || FileIdentity::from_metadata(&metadata) != identity {
            return Err(LinuxBackendError::SyntheticMountTargetChanged {
                path: path.to_path_buf(),
            });
        }
        let marker_file = register_owner(&marker_dir)?;
        Ok(Some(Self {
            path: path.to_path_buf(),
            identity,
            marker_file,
            marker_dir,
            active: true,
        }))
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn cleanup(&mut self) -> Result<(), LinuxBackendError> {
        if !self.active {
            return Ok(());
        }
        let _lock = SetupLock::acquire()?;
        remove_if_exists(&self.marker_file)?;
        cleanup_stale_markers(&self.marker_dir)?;
        if has_active_owner(&self.marker_dir)? {
            self.active = false;
            return Ok(());
        }
        let metadata = fs::symlink_metadata(&self.path).map_err(|source| {
            LinuxBackendError::SyntheticMountTargetFailed {
                path: self.path.clone(),
                source,
            }
        })?;
        if !metadata.file_type().is_dir() || FileIdentity::from_metadata(&metadata) != self.identity
        {
            return Err(LinuxBackendError::SyntheticMountTargetChanged {
                path: self.path.clone(),
            });
        }
        fs::remove_dir(&self.path).map_err(|source| {
            if source.kind() == std::io::ErrorKind::DirectoryNotEmpty {
                LinuxBackendError::SyntheticMountTargetChanged {
                    path: self.path.clone(),
                }
            } else {
                LinuxBackendError::SyntheticMountTargetFailed {
                    path: self.path.clone(),
                    source,
                }
            }
        })?;
        remove_if_exists(&self.marker_dir.join("identity"))?;
        remove_if_exists(&self.marker_dir.join("path"))?;
        match fs::remove_dir(&self.marker_dir) {
            Ok(()) => {}
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) if source.kind() == std::io::ErrorKind::DirectoryNotEmpty => {}
            Err(source) => {
                return Err(LinuxBackendError::SyntheticMountTargetFailed {
                    path: self.marker_dir.clone(),
                    source,
                });
            }
        }
        self.active = false;
        Ok(())
    }
}

impl Drop for SyntheticMountTarget {
    fn drop(&mut self) {
        if self.active {
            let _ = self.cleanup();
        }
    }
}

fn effective_uid() -> libc::uid_t {
    #[allow(unsafe_code)]
    unsafe {
        libc::geteuid()
    }
}

fn registry_root(uid: libc::uid_t) -> PathBuf {
    shared_state_root_for(uid).join("mount-targets")
}

fn shared_state_root_for(uid: libc::uid_t) -> PathBuf {
    Path::new(SHARED_SETUP_DIRECTORY).join(format!(".cageforge-linux-{uid}"))
}

pub(crate) fn shared_state_root() -> PathBuf {
    shared_state_root_for(effective_uid())
}

fn ensure_private_directory(path: &Path, uid: libc::uid_t) -> Result<(), LinuxBackendError> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .map_err(|source| LinuxBackendError::SyntheticMountTargetFailed {
            path: path.to_path_buf(),
            source,
        })?;
    let metadata = fs::symlink_metadata(path).map_err(|source| {
        LinuxBackendError::SyntheticMountTargetFailed {
            path: path.to_path_buf(),
            source,
        }
    })?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != uid
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(LinuxBackendError::UnsafeSetupLock {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

fn validate_private_file(
    path: &Path,
    file: &File,
    uid: libc::uid_t,
) -> Result<(), LinuxBackendError> {
    let metadata = file
        .metadata()
        .map_err(|source| LinuxBackendError::SetupLockFailed {
            path: path.to_path_buf(),
            source,
        })?;
    if !metadata.file_type().is_file()
        || metadata.uid() != uid
        || metadata.permissions().mode() & 0o077 != 0
    {
        Err(LinuxBackendError::UnsafeSetupLock {
            path: path.to_path_buf(),
        })
    } else {
        Ok(())
    }
}

fn stable_path_key(path: &Path) -> String {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in path.as_os_str().as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:016x}")
}

fn verify_registry_path(marker_dir: &Path, path: &Path) -> Result<(), LinuxBackendError> {
    let record = marker_dir.join("path");
    match fs::read(&record) {
        Ok(value) if value == path.as_os_str().as_bytes() => Ok(()),
        Ok(_) => Err(LinuxBackendError::SyntheticMountTargetChanged {
            path: path.to_path_buf(),
        }),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(&record)
                .map_err(|source| LinuxBackendError::SyntheticMountTargetFailed {
                    path: record.clone(),
                    source,
                })?;
            file.write_all(path.as_os_str().as_bytes())
                .map_err(|source| LinuxBackendError::SyntheticMountTargetFailed {
                    path: record,
                    source,
                })
        }
        Err(source) => Err(LinuxBackendError::SyntheticMountTargetFailed {
            path: record,
            source,
        }),
    }
}

fn verify_existing_registry_path(marker_dir: &Path, path: &Path) -> Result<(), LinuxBackendError> {
    let record = marker_dir.join("path");
    let value =
        fs::read(&record).map_err(|source| LinuxBackendError::SyntheticMountTargetFailed {
            path: record,
            source,
        })?;
    if value == path.as_os_str().as_bytes() {
        Ok(())
    } else {
        Err(LinuxBackendError::SyntheticMountTargetChanged {
            path: path.to_path_buf(),
        })
    }
}

fn register_owner(marker_dir: &Path) -> Result<PathBuf, LinuxBackendError> {
    let pid = std::process::id();
    let start_time = process_start_time(pid).map_err(|source| {
        LinuxBackendError::SyntheticMountTargetFailed {
            path: marker_dir.to_path_buf(),
            source,
        }
    })?;
    let sequence = OWNER_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let marker_file = marker_dir.join(format!("owner-{pid}-{sequence}"));
    write_private_new(&marker_file, format!("{pid}:{start_time}").as_bytes())?;
    Ok(marker_file)
}

fn write_private_new(path: &Path, contents: &[u8]) -> Result<(), LinuxBackendError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| LinuxBackendError::SyntheticMountTargetFailed {
            path: path.to_path_buf(),
            source,
        })?;
    file.write_all(contents)
        .map_err(|source| LinuxBackendError::SyntheticMountTargetFailed {
            path: path.to_path_buf(),
            source,
        })
}

fn cleanup_stale_markers(marker_dir: &Path) -> Result<(), LinuxBackendError> {
    for entry in fs::read_dir(marker_dir).map_err(|source| {
        LinuxBackendError::SyntheticMountTargetFailed {
            path: marker_dir.to_path_buf(),
            source,
        }
    })? {
        let entry = entry.map_err(|source| LinuxBackendError::SyntheticMountTargetFailed {
            path: marker_dir.to_path_buf(),
            source,
        })?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.strip_prefix("owner-"))
            .and_then(parse_owner_name)
        else {
            continue;
        };
        let Ok(marker) = fs::read_to_string(entry.path()) else {
            continue;
        };
        let Some((marker_pid, start_time)) = parse_owner_marker(&marker) else {
            continue;
        };
        if marker_pid != pid {
            continue;
        }
        if owner_is_stale(pid, start_time) {
            remove_if_exists(&entry.path())?;
        }
    }
    Ok(())
}

fn has_active_owner(marker_dir: &Path) -> Result<bool, LinuxBackendError> {
    for entry in fs::read_dir(marker_dir).map_err(|source| {
        LinuxBackendError::SyntheticMountTargetFailed {
            path: marker_dir.to_path_buf(),
            source,
        }
    })? {
        let entry = entry.map_err(|source| LinuxBackendError::SyntheticMountTargetFailed {
            path: marker_dir.to_path_buf(),
            source,
        })?;
        if entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with("owner-"))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn read_identity(identity_path: &Path, target: &Path) -> Result<FileIdentity, LinuxBackendError> {
    let mut value = String::new();
    File::open(identity_path)
        .and_then(|mut file| file.read_to_string(&mut value))
        .map_err(|source| LinuxBackendError::SyntheticMountTargetFailed {
            path: identity_path.to_path_buf(),
            source,
        })?;
    FileIdentity::decode(&value).ok_or_else(|| LinuxBackendError::SyntheticMountTargetChanged {
        path: target.to_path_buf(),
    })
}

fn cleanup_stale_target(path: &Path, identity_path: &Path) -> Result<(), LinuxBackendError> {
    let identity = match fs::read_to_string(identity_path) {
        Ok(value) => FileIdentity::decode(&value),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => None,
        Err(source) => {
            return Err(LinuxBackendError::SyntheticMountTargetFailed {
                path: identity_path.to_path_buf(),
                source,
            });
        }
    };
    let Some(identity) = identity else {
        return Ok(());
    };
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            remove_if_exists(identity_path)?;
            return Ok(());
        }
        Err(source) => {
            return Err(LinuxBackendError::SyntheticMountTargetFailed {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    if metadata.file_type().is_dir() && FileIdentity::from_metadata(&metadata) == identity {
        fs::remove_dir(path).map_err(|source| {
            if source.kind() == std::io::ErrorKind::DirectoryNotEmpty {
                LinuxBackendError::SyntheticMountTargetChanged {
                    path: path.to_path_buf(),
                }
            } else {
                LinuxBackendError::SyntheticMountTargetFailed {
                    path: path.to_path_buf(),
                    source,
                }
            }
        })?;
        remove_if_exists(identity_path)?;
        Ok(())
    } else {
        Err(LinuxBackendError::SyntheticMountTargetChanged {
            path: path.to_path_buf(),
        })
    }
}

fn remove_if_exists(path: &Path) -> Result<(), LinuxBackendError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(LinuxBackendError::SyntheticMountTargetFailed {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn parse_owner_name(value: &str) -> Option<u32> {
    let (pid, _sequence) = value.split_once('-')?;
    pid.parse().ok()
}

fn parse_owner_marker(value: &str) -> Option<(u32, u64)> {
    let (pid, start_time) = value.trim().split_once(':')?;
    Some((pid.parse().ok()?, start_time.parse().ok()?))
}

fn owner_is_stale(pid: u32, start_time: u64) -> bool {
    match process_start_time(pid) {
        Ok(current) => current != start_time,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => true,
        Err(_) => false,
    }
}

fn process_start_time(pid: u32) -> std::io::Result<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let (_, fields) = stat.rsplit_once(')').ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid process stat")
    })?;
    fields
        .split_whitespace()
        .nth(19)
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid start time"))
}

#[cfg(test)]
#[path = "synthetic_tests.rs"]
mod tests;
