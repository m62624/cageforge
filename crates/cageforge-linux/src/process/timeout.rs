// SPDX-License-Identifier: Apache-2.0

//! PID-reuse-safe automatic timeout enforcement for one Linux child.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::error::LinuxBackendError;

enum Control {
    Cancel,
}

pub(crate) struct TimeoutWatchdog {
    cancel: Option<Sender<Control>>,
    timed_out: Arc<AtomicBool>,
    error: Receiver<io::Error>,
    thread: Option<JoinHandle<()>>,
}

impl TimeoutWatchdog {
    pub(crate) fn is_supported() -> bool {
        #[allow(unsafe_code)]
        let pid = unsafe { libc::getpid() };
        open_pidfd(pid).is_ok()
    }

    pub(crate) fn start(pid: u32, timeout: Duration) -> Result<Self, LinuxBackendError> {
        let pid = libc::pid_t::try_from(pid).map_err(|_| {
            LinuxBackendError::TimeoutWatchdogSetupFailed {
                source: io::Error::new(io::ErrorKind::InvalidInput, "child PID is out of range"),
            }
        })?;
        let pidfd = open_pidfd(pid)
            .map_err(|source| LinuxBackendError::TimeoutWatchdogSetupFailed { source })?;
        let (cancel, control) = mpsc::channel();
        let (error_sender, error) = mpsc::sync_channel(1);
        let timed_out = Arc::new(AtomicBool::new(false));
        let watchdog_timed_out = Arc::clone(&timed_out);
        let thread = thread::Builder::new()
            .name("cageforge-timeout".to_string())
            .spawn(move || {
                if matches!(
                    control.recv_timeout(timeout),
                    Err(mpsc::RecvTimeoutError::Timeout)
                ) {
                    match send_kill(&pidfd) {
                        Ok(()) => watchdog_timed_out.store(true, Ordering::SeqCst),
                        Err(source) if source.raw_os_error() == Some(libc::ESRCH) => {}
                        Err(source) => {
                            let _ = error_sender.try_send(source);
                        }
                    }
                }
            })
            .map_err(|source| LinuxBackendError::TimeoutWatchdogSetupFailed { source })?;
        Ok(Self {
            cancel: Some(cancel),
            timed_out,
            error,
            thread: Some(thread),
        })
    }

    pub(super) fn timed_out(&self) -> bool {
        self.timed_out.load(Ordering::SeqCst)
    }

    pub(super) fn check_health(&mut self) -> Result<(), LinuxBackendError> {
        match self.error.try_recv() {
            Ok(source) => Err(LinuxBackendError::TimeoutWatchdogFailed { source }),
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => Ok(()),
        }
    }

    pub(super) fn shutdown(&mut self) -> Result<bool, LinuxBackendError> {
        if let Some(cancel) = self.cancel.take() {
            let _ = cancel.send(Control::Cancel);
        }
        if let Some(thread) = self.thread.take()
            && thread.join().is_err()
        {
            return Err(LinuxBackendError::TimeoutWatchdogPanicked);
        }
        self.check_health()?;
        Ok(self.timed_out())
    }
}

impl Drop for TimeoutWatchdog {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

#[allow(unsafe_code)]
fn open_pidfd(pid: libc::pid_t) -> io::Result<OwnedFd> {
    let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0_u32) };
    if descriptor < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(descriptor as libc::c_int) })
    }
}

#[allow(unsafe_code)]
fn send_kill(pidfd: &OwnedFd) -> io::Result<()> {
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            libc::SIGKILL,
            std::ptr::null::<libc::siginfo_t>(),
            0_u32,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
