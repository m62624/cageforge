// SPDX-License-Identifier: Apache-2.0

//! macOS process-group lifecycle for one Seatbelt child.

use std::io;
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, ExitStatus};
use std::thread;
use std::time::{Duration, Instant};

use cageforge_command::StdioMode;

use crate::error::MacosBackendError;
use crate::network::GatewayRuntime;

const BOUNDARY_WAIT_TIMEOUT: Duration = Duration::from_secs(5);
const BOUNDARY_POLL_INTERVAL: Duration = Duration::from_millis(5);
const BOUNDARY_RECOVERY_INTERVAL: Duration = Duration::from_secs(1);
const BOUNDARY_RECOVERY_THREAD_NAME: &str = "cageforge-macos-boundary-recovery";

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
unsafe extern "C" {
    fn closefrom(lowfd: libc::c_int);
}

/// A command running inside one macOS Seatbelt boundary.
pub struct MacosChild {
    child: Option<Child>,
    gateway: Option<GatewayRuntime>,
    deadline: Option<Instant>,
    recovery_attempted: bool,
}

impl MacosChild {
    pub(crate) fn new(
        child: Child,
        gateway: Option<GatewayRuntime>,
        timeout: Option<Duration>,
    ) -> Self {
        Self {
            child: Some(child),
            gateway,
            deadline: timeout.map(|timeout| Instant::now() + timeout),
            recovery_attempted: false,
        }
    }

    /// Returns the process identifier of the Seatbelt boundary.
    pub fn id(&self) -> u32 {
        self.child.as_ref().map_or(0, Child::id)
    }

    /// Returns the child's standard input pipe, if one was requested.
    pub fn stdin(&mut self) -> Option<&mut ChildStdin> {
        self.child.as_mut().and_then(|child| child.stdin.as_mut())
    }

    /// Returns the child's standard output pipe, if one was requested.
    pub fn stdout(&mut self) -> Option<&mut ChildStdout> {
        self.child.as_mut().and_then(|child| child.stdout.as_mut())
    }

    /// Returns the child's standard error pipe, if one was requested.
    pub fn stderr(&mut self) -> Option<&mut ChildStderr> {
        self.child.as_mut().and_then(|child| child.stderr.as_mut())
    }

    /// Checks whether the boundary has exited, enforcing its timeout.
    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>, MacosBackendError> {
        self.check_gateway_health()?;
        if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            self.terminate_boundary()?;
            self.cleanup_boundaries()?;
            return Err(MacosBackendError::ProcessTimedOut);
        }
        let status = self
            .child_mut()?
            .try_wait()
            .map_err(|source| MacosBackendError::ProcessWait { source })?;
        match status {
            Some(status) => self.finish(status).map(Some),
            None => Ok(None),
        }
    }

    /// Waits for the boundary while enforcing the prepared command timeout.
    pub fn wait(&mut self) -> Result<ExitStatus, MacosBackendError> {
        loop {
            if let Some(status) = self.try_wait()? {
                return Ok(status);
            }
            thread::sleep(BOUNDARY_POLL_INTERVAL);
        }
    }

    /// Terminates the complete process group and confirms its disappearance.
    pub fn kill(&mut self) -> Result<(), MacosBackendError> {
        self.terminate_boundary()?;
        self.cleanup_boundaries()
    }

    fn child_mut(&mut self) -> Result<&mut Child, MacosBackendError> {
        self.child
            .as_mut()
            .ok_or(MacosBackendError::BoundaryOwnedByRecovery)
    }

    fn check_gateway_health(&mut self) -> Result<(), MacosBackendError> {
        let Some(gateway) = self.gateway.as_mut() else {
            return Ok(());
        };
        gateway.check_health().map_err(MacosBackendError::Network)
    }

    fn terminate_boundary(&mut self) -> Result<(), MacosBackendError> {
        let Some(child) = self.child.as_mut() else {
            return Ok(());
        };
        terminate_process_group(child)
    }

    fn finish(&mut self, status: ExitStatus) -> Result<ExitStatus, MacosBackendError> {
        let pid = self.id();
        if pid != 0 {
            terminate_process_group_if_present(pid)?;
        }
        self.child.take();
        self.cleanup_boundaries()?;
        Ok(status)
    }

    fn cleanup_boundaries(&mut self) -> Result<(), MacosBackendError> {
        if let Some(mut gateway) = self.gateway.take() {
            gateway.shutdown().map_err(MacosBackendError::Network)?;
        }
        self.child = None;
        Ok(())
    }

    fn transfer_to_recovery(&mut self) {
        if self.recovery_attempted {
            return;
        }
        self.recovery_attempted = true;
        let Some(child) = self.child.take() else {
            return;
        };
        let gateway = self.gateway.take();
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let recovery = thread::Builder::new()
            .name(BOUNDARY_RECOVERY_THREAD_NAME.to_owned())
            .spawn(move || {
                if let Ok((mut child, gateway)) = receiver.recv() {
                    recover_boundary(&mut child, gateway);
                }
            });
        if recovery.is_err() {
            forget_recovery_payload(child, gateway);
        } else if let Err(error) = sender.send((child, gateway)) {
            let (child, gateway) = error.0;
            forget_recovery_payload(child, gateway);
        }
    }
}

impl Drop for MacosChild {
    fn drop(&mut self) {
        if self.child.is_none() {
            let _ = self.cleanup_boundaries();
            return;
        }
        if self.terminate_boundary().is_ok() && self.cleanup_boundaries().is_ok() {
            return;
        }
        self.transfer_to_recovery();
    }
}

#[allow(unsafe_code)]
pub(crate) fn configure_process_group(command: &mut std::process::Command) {
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: pre_exec runs in the child between fork and exec; setpgid
        // only changes the child process's own process-group membership.
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) == -1 {
                    Err(io::Error::last_os_error())
                } else {
                    // SAFETY: stdio has already been configured by
                    // `Command`; closing every descriptor above stderr keeps
                    // unrelated parent handles out of the Seatbelt boundary.
                    closefrom(3);
                    Ok(())
                }
            });
        }
    }
}

pub(crate) fn stream(mode: StdioMode) -> std::process::Stdio {
    match mode {
        StdioMode::Inherit => std::process::Stdio::inherit(),
        StdioMode::Null => std::process::Stdio::null(),
        StdioMode::Pipe => std::process::Stdio::piped(),
    }
}

fn recover_boundary(child: &mut Child, mut gateway: Option<GatewayRuntime>) {
    loop {
        if terminate_process_group(child).is_ok() {
            if let Some(mut gateway) = gateway.take() {
                let _ = gateway.shutdown();
            }
            return;
        }
        thread::sleep(BOUNDARY_RECOVERY_INTERVAL);
    }
}

fn forget_recovery_payload(mut child: Child, gateway: Option<GatewayRuntime>) {
    let _ = terminate_process_group(&mut child);
    std::mem::forget(child);
    if let Some(gateway) = gateway {
        std::mem::forget(gateway);
    }
}

fn terminate_process_group(child: &mut Child) -> Result<(), MacosBackendError> {
    let pid = child.id();
    terminate_process_group_if_present(pid)?;
    child
        .wait()
        .map_err(|source| MacosBackendError::ProcessWait { source })?;
    confirm_process_group_gone(pid)
}

#[allow(unsafe_code)]
fn terminate_process_group_if_present(pid: u32) -> Result<(), MacosBackendError> {
    #[cfg(target_os = "macos")]
    {
        let pid = libc::pid_t::try_from(pid).map_err(|_| MacosBackendError::ProcessGroup {
            source: io::Error::new(io::ErrorKind::InvalidInput, "process ID is out of range"),
        })?;
        // SAFETY: a negative PID targets exactly the process group whose
        // leader is the Seatbelt boundary; SIGKILL cannot be caught by it.
        let result = unsafe { libc::kill(-pid, libc::SIGKILL) };
        if result == -1 {
            let source = io::Error::last_os_error();
            if source.raw_os_error() != Some(libc::ESRCH) {
                return Err(MacosBackendError::ProcessGroup { source });
            }
        }
    }
    Ok(())
}

#[allow(unsafe_code)]
fn confirm_process_group_gone(pid: u32) -> Result<(), MacosBackendError> {
    let deadline = Instant::now() + BOUNDARY_WAIT_TIMEOUT;
    loop {
        #[cfg(target_os = "macos")]
        let state = {
            let pid = libc::pid_t::try_from(pid).map_err(|_| MacosBackendError::ProcessGroup {
                source: io::Error::new(io::ErrorKind::InvalidInput, "process ID is out of range"),
            })?;
            // SAFETY: signal 0 performs an existence check without changing
            // process state; the negative PID addresses this exact group.
            unsafe { libc::kill(-pid, 0) }
        };
        #[cfg(not(target_os = "macos"))]
        let state = -1;
        if state == -1 {
            let source = io::Error::last_os_error();
            if source.raw_os_error() == Some(libc::ESRCH) {
                return Ok(());
            }
            if source.raw_os_error() == Some(libc::EPERM) {
                if Instant::now() >= deadline {
                    return Err(MacosBackendError::BoundaryTerminationUnconfirmed);
                }
            } else {
                return Err(MacosBackendError::ProcessGroup { source });
            }
        } else if Instant::now() >= deadline {
            return Err(MacosBackendError::BoundaryTerminationUnconfirmed);
        }
        thread::sleep(BOUNDARY_POLL_INTERVAL);
    }
}

#[cfg(test)]
mod tests {
    use super::MacosChild;
    use crate::error::MacosBackendError;

    #[test]
    fn recovery_owned_boundary_is_reported_as_a_typed_state() {
        let mut child = MacosChild {
            child: None,
            gateway: None,
            deadline: None,
            recovery_attempted: true,
        };

        assert!(matches!(
            child.try_wait(),
            Err(MacosBackendError::BoundaryOwnedByRecovery)
        ));
    }
}
