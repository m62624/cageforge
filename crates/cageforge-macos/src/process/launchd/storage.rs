// SPDX-License-Identifier: Apache-2.0

//! Non-recursive cleanup of the two files owned by one launchd registration.

use std::{
    ffi::CString,
    fs::{File, OpenOptions},
    io,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
        },
    },
    path::{Path, PathBuf},
};

use thiserror::Error;

pub(super) const PLIST_NAME: &str = "helper.plist";
pub(super) const LOG_NAME: &str = "helper.log";

pub(super) struct Directory {
    parent: File,
    root: File,
    path: PathBuf,
    name: CString,
    files: Vec<(CString, File)>,
}

/// Failure to acquire or remove the exact files belonging to a macOS helper.
#[derive(Debug, Error)]
pub enum StorageError {
    /// A native filesystem operation failed without deleting unknown contents.
    #[error("macOS helper storage operation failed for {path:?}: {source}")]
    Io {
        /// Path associated with the failed operation.
        path: PathBuf,
        /// Original operating-system failure.
        source: io::Error,
    },
    /// The registration directory was not a private directory owned by this user.
    #[error("macOS helper storage is not a private owner directory: {path:?}")]
    NotPrivate {
        /// Rejected registration directory.
        path: PathBuf,
    },
    /// An entry was replaced after its ownership had been acquired.
    #[error("macOS helper storage entry was replaced: {path:?}")]
    Replaced {
        /// Entry left untouched because its identity changed.
        path: PathBuf,
    },
    /// A path could not be represented as a native directory entry.
    #[error("macOS helper storage path is invalid: {path:?}")]
    InvalidPath {
        /// Invalid registration path.
        path: PathBuf,
    },
}

impl Directory {
    pub(super) fn capture(path: &Path) -> Result<Self, StorageError> {
        let error = || StorageError::InvalidPath {
            path: path.to_owned(),
        };
        let parent_path = path
            .parent()
            .filter(|_| path.is_absolute())
            .ok_or_else(error)?;
        let name =
            CString::new(path.file_name().ok_or_else(error)?.as_bytes()).map_err(|_| error())?;
        let parent = open_directory(parent_path)?;
        let root = open_entry(&parent, &name, libc::O_DIRECTORY, path)?;
        let metadata = root.metadata().map_err(|source| fail(path, source))?;
        #[allow(unsafe_code)]
        let owner = unsafe { libc::geteuid() };
        if metadata.uid() != owner || metadata.mode() & 0o077 != 0 {
            return Err(StorageError::NotPrivate {
                path: path.to_owned(),
            });
        }
        let mut files = Vec::new();
        for name in [PLIST_NAME, LOG_NAME] {
            let file_path = path.join(name);
            let name = CString::new(name).map_err(|_| error())?;
            let file = open_entry(&root, &name, 0, &file_path)?;
            let metadata = file.metadata().map_err(|source| fail(&file_path, source))?;
            if !metadata.is_file() || metadata.uid() != owner || metadata.nlink() != 1 {
                return Err(StorageError::Replaced { path: file_path });
            }
            files.push((name, file));
        }
        Ok(Self {
            parent,
            root,
            path: path.to_owned(),
            name,
            files,
        })
    }

    pub(super) fn cleanup(&self) -> Result<(), StorageError> {
        // The pinned directory is checked before any removal. Never follow a
        // replacement path, recursively remove unknown contents, or infer
        // ownership from a name prefix alone.
        if !same_entry(&self.parent, &self.name, &self.root, &self.path)? {
            return Ok(());
        }
        for (name, file) in &self.files {
            let path = self.path.join(std::ffi::OsStr::from_bytes(name.as_bytes()));
            if same_entry(&self.root, name, file, &path)? {
                unlink(&self.root, name, 0, &path)?;
            }
        }
        if same_entry(&self.parent, &self.name, &self.root, &self.path)? {
            // AT_REMOVEDIR can remove only an empty directory. An unexpected
            // entry therefore stays intact even when cleanup cannot finish.
            unlink(&self.parent, &self.name, libc::AT_REMOVEDIR, &self.path)?;
        }
        Ok(())
    }
}

fn open_directory(path: &Path) -> Result<File, StorageError> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|source| fail(path, source))
}

#[allow(unsafe_code)]
fn open_entry(
    parent: &File,
    name: &CString,
    flags: libc::c_int,
    path: &Path,
) -> Result<File, StorageError> {
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK | flags,
        )
    };
    if fd < 0 {
        return Err(fail(path, io::Error::last_os_error()));
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[allow(unsafe_code)]
fn same_entry(
    parent: &File,
    name: &CString,
    file: &File,
    path: &Path,
) -> Result<bool, StorageError> {
    let mut actual = std::mem::MaybeUninit::<libc::stat>::uninit();
    let result = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            actual.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result != 0 {
        let source = io::Error::last_os_error();
        return if source.kind() == io::ErrorKind::NotFound {
            Ok(false)
        } else {
            Err(fail(path, source))
        };
    }
    let actual = unsafe { actual.assume_init() };
    let expected = file.metadata().map_err(|source| fail(path, source))?;
    if actual.st_dev as u64 != expected.dev() || actual.st_ino != expected.ino() {
        return Err(StorageError::Replaced {
            path: path.to_owned(),
        });
    }
    Ok(true)
}

#[allow(unsafe_code)]
fn unlink(
    parent: &File,
    name: &CString,
    flags: libc::c_int,
    path: &Path,
) -> Result<(), StorageError> {
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), flags) } == 0 {
        return Ok(());
    }
    let source = io::Error::last_os_error();
    if source.kind() == io::ErrorKind::NotFound {
        Ok(())
    } else {
        Err(fail(path, source))
    }
}

fn fail(path: &Path, source: io::Error) -> StorageError {
    StorageError::Io {
        path: path.to_owned(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};

    fn fixture() -> (tempfile::TempDir, Directory) {
        let root = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .expect("private fixture directory");
        for name in [PLIST_NAME, LOG_NAME] {
            fs::write(root.path().join(name), b"owned").expect("owned fixture file");
        }
        let directory = Directory::capture(root.path()).expect("capture owned files");
        (root, directory)
    }

    #[test]
    fn owned_files_are_removed_idempotently_without_recursive_cleanup() {
        let (root, directory) = fixture();
        let unknown = root.path().join("unrelated");
        fs::write(&unknown, b"keep").expect("unrelated entry");
        assert!(matches!(directory.cleanup(), Err(StorageError::Io { .. })));
        assert_eq!(fs::read(&unknown).expect("unknown file retained"), b"keep");
        fs::remove_file(unknown).expect("fixture removes its own extra file");
        directory.cleanup().expect("finish empty-directory cleanup");
        directory.cleanup().expect("repeated cleanup");
        assert!(!root.path().exists());
    }

    #[test]
    fn replacement_files_are_not_removed() {
        let (root, directory) = fixture();
        let path = root.path().join(PLIST_NAME);
        fs::rename(&path, root.path().join("old.plist")).expect("preserve original inode");
        fs::write(&path, b"replacement").expect("replacement entry");
        assert!(matches!(
            directory.cleanup(),
            Err(StorageError::Replaced { .. })
        ));
        assert_eq!(
            fs::read(path).expect("replacement retained"),
            b"replacement"
        );
    }
}
