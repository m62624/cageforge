// SPDX-License-Identifier: Apache-2.0

//! Linux child lifecycle and timeout handling.

use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, ExitStatus};
use std::thread;
use std::time::{Duration, Instant};

use crate::error::LinuxBackendError;

/// A child launched inside the Linux backend boundary.
pub struct LinuxChild {
    child: Child,
    timeout: Option<Duration>,
    started: Instant,
}

impl LinuxChild {
    pub(crate) fn new(child: Child, timeout: Option<Duration>) -> Self {
        Self {
            child,
            timeout,
            started: Instant::now(),
        }
    }

    /// Returns the child process identifier.
    pub fn id(&self) -> u32 {
        self.child.id()
    }

    /// Returns the child's standard input pipe, if one was requested.
    pub fn stdin(&mut self) -> Option<&mut ChildStdin> {
        self.child.stdin.as_mut()
    }

    /// Returns the child's standard output pipe, if one was requested.
    pub fn stdout(&mut self) -> Option<&mut ChildStdout> {
        self.child.stdout.as_mut()
    }

    /// Returns the child's standard error pipe, if one was requested.
    pub fn stderr(&mut self) -> Option<&mut ChildStderr> {
        self.child.stderr.as_mut()
    }

    /// Checks whether the child has exited.
    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>, LinuxBackendError> {
        self.child
            .try_wait()
            .map_err(|source| LinuxBackendError::ProcessWaitFailed { source })
    }

    /// Waits for the child without applying an additional timeout.
    pub fn wait(&mut self) -> Result<ExitStatus, LinuxBackendError> {
        self.child
            .wait()
            .map_err(|source| LinuxBackendError::ProcessWaitFailed { source })
    }

    /// Waits for the child and terminates the Bubblewrap boundary on timeout.
    pub fn wait_with_timeout(&mut self) -> Result<ExitStatus, LinuxBackendError> {
        let Some(timeout) = self.timeout else {
            return self.wait();
        };
        loop {
            if let Some(status) = self.try_wait()? {
                return Ok(status);
            }
            if self.started.elapsed() >= timeout {
                if let Err(source) = self.child.kill()
                    && source.raw_os_error() != Some(libc::ESRCH)
                {
                    return Err(LinuxBackendError::ProcessWaitFailed { source });
                }
                self.child
                    .wait()
                    .map_err(|source| LinuxBackendError::ProcessWaitFailed { source })?;
                return Err(LinuxBackendError::ProcessTimedOut);
            }
            thread::sleep(Duration::from_millis(5));
        }
    }

    /// Sends the platform termination request to the Bubblewrap process.
    pub fn kill(&mut self) -> Result<(), LinuxBackendError> {
        self.child
            .kill()
            .map_err(|source| LinuxBackendError::ProcessWaitFailed { source })
    }
}

impl Drop for LinuxChild {
    fn drop(&mut self) {
        let Ok(None) = self.child.try_wait() else {
            return;
        };
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
