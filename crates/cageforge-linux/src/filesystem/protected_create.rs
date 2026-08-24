// SPDX-License-Identifier: Apache-2.0

//! Per-launch monitoring for protected paths that must remain absent.

use std::ffi::CString;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::error::LinuxBackendError;

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
            .name("cageforge-protected-create".to_string())
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
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(source) => {
            return Err(LinuxBackendError::ProtectedPathMonitorFailed {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    let result = if metadata.file_type().is_dir() {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    };
    match result {
        Ok(()) => Ok(true),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(true),
        Err(source) => Err(LinuxBackendError::ProtectedPathMonitorFailed {
            path: path.to_path_buf(),
            source,
        }),
    }
}

struct ProtectedCreateWatcher {
    descriptor: libc::c_int,
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
