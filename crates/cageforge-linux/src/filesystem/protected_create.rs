// SPDX-License-Identifier: Apache-2.0

//! Per-launch monitoring for protected paths that must remain absent.

use std::ffi::{CString, OsString};
use std::fs;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

const REMOVE_RENAME_ATTEMPTS: usize = 8;
const PROTECTED_CREATE_THREAD_NAME: &str = "cageforge-protected-create";
static REMOVE_SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

use crate::error::LinuxBackendError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

struct ProtectedCreateWatcher {
    descriptor: libc::c_int,
}

pub(crate) struct ProtectedCreateMonitor {
    stop: Arc<AtomicBool>,
    event: Receiver<LinuxBackendError>,
    thread: Option<JoinHandle<()>>,
}

impl ProtectedCreateMonitor {
    pub(crate) fn start(paths: Vec<PathBuf>) -> Result<Option<Self>, LinuxBackendError> {
        if paths.is_empty() {
            return Ok(None);
        }
        for path in &paths {
            match fs::symlink_metadata(path) {
                Err(source) if source.kind() == io::ErrorKind::NotFound => {}
                Ok(_) => {
                    return Err(LinuxBackendError::ProtectedPathAppearedBeforeLaunch {
                        path: path.clone(),
                    });
                }
                Err(source) => {
                    return Err(LinuxBackendError::ProtectedPathMonitorFailed {
                        path: path.clone(),
                        source,
                    });
                }
            }
        }
        let watcher = ProtectedCreateWatcher::new(&paths);
        let stop = Arc::new(AtomicBool::new(false));
        let monitor_stop = Arc::clone(&stop);
        let (event_sender, event) = mpsc::sync_channel(1);
        let thread = thread::Builder::new()
            .name(PROTECTED_CREATE_THREAD_NAME.to_owned())
            .spawn(move || monitor_paths(&paths, watcher, &monitor_stop, &event_sender))
            .map_err(|source| LinuxBackendError::ProtectedPathMonitorSetupFailed { source })?;
        Ok(Some(Self {
            stop,
            event,
            thread: Some(thread),
        }))
    }

    pub(crate) fn check_health(&mut self) -> Result<(), LinuxBackendError> {
        match self.event.try_recv() {
            Ok(error) => return Err(error),
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => return self.finish(),
        }
        if self.thread.as_ref().is_some_and(JoinHandle::is_finished) {
            self.finish()
        } else {
            Ok(())
        }
    }

    pub(crate) fn shutdown(&mut self) -> Result<(), LinuxBackendError> {
        self.stop.store(true, Ordering::SeqCst);
        self.finish()
    }

    fn finish(&mut self) -> Result<(), LinuxBackendError> {
        let Some(thread) = self.thread.take() else {
            return Ok(());
        };
        if thread.join().is_err() {
            return Err(LinuxBackendError::ProtectedPathMonitorPanicked);
        }
        match self.event.try_recv() {
            Ok(error) => Err(error),
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => Ok(()),
        }
    }
}

impl Drop for ProtectedCreateMonitor {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

fn monitor_paths(
    paths: &[PathBuf],
    watcher: Option<ProtectedCreateWatcher>,
    stop: &AtomicBool,
    event: &mpsc::SyncSender<LinuxBackendError>,
) {
    while !stop.load(Ordering::SeqCst) {
        for path in paths {
            match remove_if_created(path) {
                Ok(true) => {
                    let _ = event
                        .try_send(LinuxBackendError::ProtectedPathCreated { path: path.clone() });
                }
                Ok(false) => {}
                Err(error) => {
                    let _ = event.try_send(error);
                    return;
                }
            }
        }
        match &watcher {
            Some(watcher) => watcher.wait_for_event(stop),
            None => thread::sleep(Duration::from_millis(1)),
        }
    }
    for path in paths {
        match remove_if_created(path) {
            Ok(true) => {
                let _ =
                    event.try_send(LinuxBackendError::ProtectedPathCreated { path: path.clone() });
            }
            Ok(false) => {}
            Err(error) => {
                let _ = event.try_send(error);
                return;
            }
        }
    }
}

fn remove_if_created(path: &Path) -> Result<bool, LinuxBackendError> {
    let parent = path.parent().ok_or_else(|| {
        protected_path_monitor_error(
            path,
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "protected path has no parent directory",
            ),
        )
    })?;
    let name = path.file_name().ok_or_else(|| {
        protected_path_monitor_error(
            path,
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "protected path has no final component",
            ),
        )
    })?;
    let parent_fd = open_directory_without_symlinks(parent)
        .map_err(|source| protected_path_monitor_error(path, source))?;
    let name = CString::new(name.as_bytes()).map_err(|_| {
        protected_path_monitor_error(
            path,
            io::Error::new(io::ErrorKind::InvalidInput, "protected path contains NUL"),
        )
    })?;

    match open_directory_entry(parent_fd.as_raw_fd(), &name) {
        Ok(directory_fd) => {
            remove_directory_entry(parent_fd.as_raw_fd(), &name, directory_fd, path)
        }
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(source)
            if matches!(
                source.raw_os_error(),
                Some(errno) if errno == libc::ELOOP || errno == libc::ENOTDIR
            ) =>
        {
            unlink_entry(parent_fd.as_raw_fd(), &name, path)
        }
        Err(source) => Err(protected_path_monitor_error(path, source)),
    }
}

fn protected_path_monitor_error(path: &Path, source: io::Error) -> LinuxBackendError {
    LinuxBackendError::ProtectedPathMonitorFailed {
        path: path.to_path_buf(),
        source,
    }
}

fn open_directory_without_symlinks(path: &Path) -> io::Result<OwnedFd> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "protected path parent must be absolute",
        ));
    }
    let root = CString::new("/")
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "root path contains NUL"))?;
    let descriptor = open_directory_at(libc::AT_FDCWD, &root)?;
    let mut descriptor = descriptor;
    for component in path.components() {
        match component {
            std::path::Component::RootDir | std::path::Component::CurDir => {}
            std::path::Component::Normal(component) => {
                let component = CString::new(component.as_bytes()).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "directory path contains NUL")
                })?;
                descriptor = open_directory_at(descriptor.as_raw_fd(), &component)?;
            }
            std::path::Component::ParentDir | std::path::Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "protected path parent is not normalized",
                ));
            }
        }
    }
    Ok(descriptor)
}

fn open_directory_at(parent: libc::c_int, name: &CString) -> io::Result<OwnedFd> {
    #[allow(unsafe_code)]
    let descriptor = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if descriptor < 0 {
        Err(io::Error::last_os_error())
    } else {
        #[allow(unsafe_code)]
        Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
    }
}

fn open_directory_entry(parent: libc::c_int, name: &CString) -> io::Result<OwnedFd> {
    open_directory_at(parent, name)
}

fn remove_directory_entry(
    parent: libc::c_int,
    name: &CString,
    directory: OwnedFd,
    path: &Path,
) -> Result<bool, LinuxBackendError> {
    let expected = file_identity(directory.as_raw_fd())
        .map_err(|source| protected_path_monitor_error(path, source))?;
    let current = entry_identity(parent, name)
        .map_err(|source| protected_path_monitor_error(path, source))?;
    if current != expected {
        return Err(LinuxBackendError::ProtectedPathChanged {
            path: path.to_path_buf(),
        });
    }

    let sequence = REMOVE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary_name = OsString::from(format!(
        ".cageforge-protected-remove-{}-{sequence}",
        std::process::id()
    ));
    let temporary_name = CString::new(temporary_name.as_os_str().as_bytes()).map_err(|_| {
        protected_path_monitor_error(
            path,
            io::Error::new(io::ErrorKind::InvalidInput, "temporary path contains NUL"),
        )
    })?;
    let mut renamed = false;
    for _ in 0..REMOVE_RENAME_ATTEMPTS {
        #[allow(unsafe_code)]
        let result =
            unsafe { libc::renameat(parent, name.as_ptr(), parent, temporary_name.as_ptr()) };
        if result == 0 {
            renamed = true;
            break;
        }
        let source = io::Error::last_os_error();
        if source.raw_os_error() != Some(libc::EEXIST) {
            if source.kind() == io::ErrorKind::NotFound {
                return Ok(false);
            }
            return Err(protected_path_monitor_error(path, source));
        }
    }
    if !renamed {
        return Err(protected_path_monitor_error(
            path,
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "could not reserve a protected-path removal name",
            ),
        ));
    }
    let directory_path = PathBuf::from(format!(
        "/proc/self/fd/{}/{}",
        parent,
        temporary_name.to_string_lossy()
    ));
    match fs::remove_dir_all(&directory_path) {
        Ok(()) => Ok(true),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(true),
        Err(source) => Err(protected_path_monitor_error(path, source)),
    }
}

#[allow(unsafe_code)]
fn file_identity(fd: libc::c_int) -> io::Result<FileIdentity> {
    let mut metadata = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstat(fd, &mut metadata) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(FileIdentity {
        device: metadata.st_dev as u64,
        inode: metadata.st_ino as u64,
    })
}

#[allow(unsafe_code)]
fn entry_identity(parent: libc::c_int, name: &CString) -> io::Result<FileIdentity> {
    let mut metadata = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe {
        libc::fstatat(
            parent,
            name.as_ptr(),
            &mut metadata,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(FileIdentity {
        device: metadata.st_dev as u64,
        inode: metadata.st_ino as u64,
    })
}

fn unlink_entry(
    parent: libc::c_int,
    name: &CString,
    path: &Path,
) -> Result<bool, LinuxBackendError> {
    #[allow(unsafe_code)]
    let result = unsafe { libc::unlinkat(parent, name.as_ptr(), 0) };
    if result == 0 {
        Ok(true)
    } else {
        let source = io::Error::last_os_error();
        if source.kind() == io::ErrorKind::NotFound {
            Ok(true)
        } else {
            Err(protected_path_monitor_error(path, source))
        }
    }
}

impl ProtectedCreateWatcher {
    fn new(paths: &[PathBuf]) -> Option<Self> {
        #[allow(unsafe_code)]
        let descriptor = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        if descriptor < 0 {
            return None;
        }
        let mut parents = Vec::<PathBuf>::new();
        let mut watches = 0_usize;
        for path in paths {
            let Some(parent) = path.parent() else {
                continue;
            };
            if parents.iter().any(|known| known == parent) {
                continue;
            }
            parents.push(parent.to_path_buf());
            let Ok(parent) = CString::new(parent.as_os_str().as_bytes()) else {
                continue;
            };
            let events =
                libc::IN_CREATE | libc::IN_MOVED_TO | libc::IN_DELETE_SELF | libc::IN_MOVE_SELF;
            #[allow(unsafe_code)]
            let watch = unsafe { libc::inotify_add_watch(descriptor, parent.as_ptr(), events) };
            if watch >= 0 {
                watches += 1;
            }
        }
        if watches == 0 {
            #[allow(unsafe_code)]
            unsafe {
                libc::close(descriptor);
            }
            None
        } else {
            Some(Self { descriptor })
        }
    }

    fn wait_for_event(&self, stop: &AtomicBool) {
        let mut descriptor = libc::pollfd {
            fd: self.descriptor,
            events: libc::POLLIN,
            revents: 0,
        };
        while !stop.load(Ordering::SeqCst) {
            #[allow(unsafe_code)]
            let result = unsafe { libc::poll(&mut descriptor, 1, 10) };
            if result > 0 {
                self.drain();
                return;
            }
            if result == 0 {
                return;
            }
            if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                return;
            }
        }
    }

    fn drain(&self) {
        let mut buffer = [0_u8; 4096];
        loop {
            #[allow(unsafe_code)]
            let read =
                unsafe { libc::read(self.descriptor, buffer.as_mut_ptr().cast(), buffer.len()) };
            if read > 0 {
                continue;
            }
            if read == 0 || io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                return;
            }
        }
    }
}

impl Drop for ProtectedCreateWatcher {
    fn drop(&mut self) {
        #[allow(unsafe_code)]
        unsafe {
            libc::close(self.descriptor);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::fd::AsRawFd;

    use tempfile::TempDir;

    use crate::error::LinuxBackendError;

    use super::remove_if_created;

    #[test]
    fn protected_removal_rejects_a_symlinked_parent() {
        let workspace = TempDir::new().expect("workspace");
        let outside = TempDir::new().expect("outside");
        let outside_metadata = outside.path().join(".git");
        fs::create_dir(&outside_metadata).expect("outside metadata");
        fs::write(outside_metadata.join("marker"), "keep").expect("outside marker");
        std::os::unix::fs::symlink(outside.path(), workspace.path().join("link"))
            .expect("parent symlink");

        let result = remove_if_created(&workspace.path().join("link/.git"));

        assert!(result.is_err(), "symlinked parent must fail closed");
        assert!(outside_metadata.join("marker").exists());
    }

    #[test]
    fn protected_removal_does_not_follow_symlinks_inside_the_removed_directory() {
        let workspace = TempDir::new().expect("workspace");
        let outside = TempDir::new().expect("outside");
        let protected = workspace.path().join(".git");
        fs::create_dir(&protected).expect("protected directory");
        let outside_file = outside.path().join("keep");
        fs::write(&outside_file, "keep").expect("outside file");
        std::os::unix::fs::symlink(&outside_file, protected.join("escape")).expect("child symlink");

        assert!(remove_if_created(&protected).expect("safe removal"));
        assert!(!protected.exists());
        assert_eq!(
            fs::read_dir(workspace.path()).expect("workspace").count(),
            0
        );
        assert_eq!(
            fs::read_to_string(outside_file).expect("outside file"),
            "keep"
        );
    }

    #[test]
    fn protected_removal_rejects_a_replaced_directory() {
        let workspace = TempDir::new().expect("workspace");
        let protected = workspace.path().join(".git");
        let replacement = workspace.path().join("replacement");
        fs::create_dir(&protected).expect("protected directory");
        fs::create_dir(&replacement).expect("replacement directory");

        let parent =
            super::open_directory_without_symlinks(workspace.path()).expect("parent descriptor");
        let name = std::ffi::CString::new(".git").expect("name");
        let directory =
            super::open_directory_entry(parent.as_raw_fd(), &name).expect("protected descriptor");
        fs::rename(&protected, workspace.path().join("old")).expect("move protected");
        fs::rename(&replacement, &protected).expect("install replacement");

        let result =
            super::remove_directory_entry(parent.as_raw_fd(), &name, directory, &protected);

        assert!(matches!(
            result,
            Err(LinuxBackendError::ProtectedPathChanged { .. })
        ));
        assert!(protected.is_dir(), "replacement must remain intact");
    }
}
