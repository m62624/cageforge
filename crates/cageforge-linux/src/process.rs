// SPDX-License-Identifier: Apache-2.0

//! Linux child lifecycle and timeout handling.

use std::os::unix::net::UnixStream;
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, ExitStatus};
use std::thread;
use std::time::{Duration, Instant};

#[path = "process/timeout.rs"]
pub(crate) mod timeout;

use crate::error::LinuxBackendError;
use crate::filesystem::protected_create::ProtectedCreateMonitor;
use crate::filesystem::synthetic::SyntheticMountTarget;
use crate::network::GatewayRuntime;
use crate::status_transport::{HelperExecutionResult, read_status};
use timeout::TimeoutWatchdog;

const BOUNDARY_WAIT_TIMEOUT: Duration = Duration::from_secs(5);
const BOUNDARY_RECOVERY_INTERVAL: Duration = Duration::from_secs(1);
const BOUNDARY_POLL_INTERVAL: Duration = Duration::from_millis(5);
const BOUNDARY_RECOVERY_THREAD_NAME: &str = "cageforge-linux-boundary-recovery";

/// A child launched inside the Linux backend boundary.
pub struct LinuxChild {
    child: Option<Child>,
    child_reaped: bool,
    timeout_watchdog: Option<TimeoutWatchdog>,
    synthetic_targets: Vec<SyntheticMountTarget>,
    protected_create_monitor: Option<ProtectedCreateMonitor>,
    gateway_runtime: Option<GatewayRuntime>,
    status_channel: Option<UnixStream>,
    recovery_attempted: bool,
}

impl LinuxChild {
    pub(crate) fn new(
        child: Child,
        timeout_watchdog: Option<TimeoutWatchdog>,
        synthetic_targets: Vec<SyntheticMountTarget>,
        protected_create_monitor: Option<ProtectedCreateMonitor>,
        gateway_runtime: Option<GatewayRuntime>,
        status_channel: UnixStream,
    ) -> Self {
        Self {
            child: Some(child),
            child_reaped: false,
            timeout_watchdog,
            synthetic_targets,
            protected_create_monitor,
            gateway_runtime,
            status_channel: Some(status_channel),
            recovery_attempted: false,
        }
    }

    /// Returns the child process identifier.
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

    /// Checks whether the child has exited.
    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>, LinuxBackendError> {
        if let Err(error) = self.check_protected_create_health() {
            if self.terminate_after_boundary_failure() {
                let _ = self.cleanup_boundaries();
            }
            return Err(error);
        }
        if let Err(error) = self.check_gateway_health() {
            if self.terminate_after_boundary_failure() {
                let _ = self.cleanup_boundaries();
            }
            return Err(error);
        }
        if let Err(error) = self.check_timeout_health() {
            if self.terminate_after_boundary_failure() {
                let _ = self.cleanup_boundaries();
            }
            return Err(error);
        }
        let status = self
            .child_mut()?
            .try_wait()
            .map_err(|source| LinuxBackendError::ProcessWaitFailed { source })?;
        if let Some(status) = status {
            self.child_reaped = true;
            return self.finish_status(status).map(Some);
        }
        if self
            .timeout_watchdog
            .as_ref()
            .is_some_and(TimeoutWatchdog::timed_out)
        {
            let status = self
                .child_mut()?
                .wait()
                .map_err(|source| LinuxBackendError::ProcessWaitFailed { source })?;
            self.child_reaped = true;
            return self.finish_status(status).map(Some);
        }
        Ok(None)
    }

    /// Waits for the child while enforcing its prepared timeout policy.
    pub fn wait(&mut self) -> Result<ExitStatus, LinuxBackendError> {
        if self.timeout_watchdog.is_some()
            || self.gateway_runtime.is_some()
            || self.protected_create_monitor.is_some()
        {
            loop {
                if let Some(status) = self.try_wait()? {
                    return Ok(status);
                }
                thread::sleep(Duration::from_millis(5));
            }
        }
        let boundary_status = self
            .child_mut()?
            .wait()
            .map_err(|source| LinuxBackendError::ProcessWaitFailed { source })?;
        self.child_reaped = true;
        self.finish_status(boundary_status)
    }

    /// Terminates and confirms the complete Bubblewrap process boundary.
    pub fn kill(&mut self) -> Result<(), LinuxBackendError> {
        self.terminate_boundary()?;
        self.cleanup_boundaries()
    }

    fn cleanup_synthetic_targets(&mut self) -> Result<(), LinuxBackendError> {
        let mut first_error = None;
        let mut remaining = Vec::new();
        while let Some(mut target) = self.synthetic_targets.pop() {
            match target.cleanup() {
                Ok(()) => {}
                Err(error) => {
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                    remaining.push(target);
                }
            }
        }
        remaining.reverse();
        self.synthetic_targets = remaining;
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn command_status(
        &mut self,
        boundary_status: ExitStatus,
    ) -> Result<ExitStatus, LinuxBackendError> {
        let Some(mut channel) = self.status_channel.take() else {
            return Ok(boundary_status);
        };
        match read_status(&mut channel) {
            Ok(HelperExecutionResult::CommandExited(status)) => Ok(status),
            Ok(HelperExecutionResult::HelperFailed(failure)) => {
                Err(LinuxBackendError::HardeningHelperRuntimeFailed { failure })
            }
            Err(source) => Err(LinuxBackendError::CommandStatusFailed { source }),
        }
    }

    fn finish_status(
        &mut self,
        boundary_status: ExitStatus,
    ) -> Result<ExitStatus, LinuxBackendError> {
        let timeout = self.finish_timeout_watchdog();
        let status = match timeout {
            Ok(true) => Err(LinuxBackendError::ProcessTimedOut),
            Ok(false) => self.command_status(boundary_status),
            Err(error) => Err(error),
        };
        let cleanup = self.cleanup_boundaries();
        match cleanup {
            Ok(()) => status,
            Err(error) => Err(error),
        }
    }

    fn check_gateway_health(&mut self) -> Result<(), LinuxBackendError> {
        match &mut self.gateway_runtime {
            Some(runtime) => runtime.check_health(),
            None => Ok(()),
        }
    }

    fn check_protected_create_health(&mut self) -> Result<(), LinuxBackendError> {
        match &mut self.protected_create_monitor {
            Some(monitor) => monitor.check_health(),
            None => Ok(()),
        }
    }

    fn check_timeout_health(&mut self) -> Result<(), LinuxBackendError> {
        match &mut self.timeout_watchdog {
            Some(watchdog) => watchdog.check_health(),
            None => Ok(()),
        }
    }

    fn finish_timeout_watchdog(&mut self) -> Result<bool, LinuxBackendError> {
        let Some(watchdog) = self.timeout_watchdog.as_mut() else {
            return Ok(false);
        };
        let timed_out = watchdog.shutdown()?;
        self.timeout_watchdog = None;
        Ok(timed_out)
    }

    fn cleanup_boundaries(&mut self) -> Result<(), LinuxBackendError> {
        let mut first_error = None;
        if self.timeout_watchdog.is_some() {
            match self.finish_timeout_watchdog() {
                Ok(_) => {}
                Err(error) => first_error = Some(error),
            }
        }
        if let Some(runtime) = self.gateway_runtime.as_mut() {
            match runtime.shutdown() {
                Ok(()) => self.gateway_runtime = None,
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        if let Some(monitor) = self.protected_create_monitor.as_mut() {
            match monitor.shutdown() {
                Ok(()) => self.protected_create_monitor = None,
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        self.status_channel = None;
        if let Err(error) = self.cleanup_synthetic_targets()
            && first_error.is_none()
        {
            first_error = Some(error);
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn terminate_after_boundary_failure(&mut self) -> bool {
        self.terminate_boundary().is_ok()
    }

    fn terminate_boundary(&mut self) -> Result<(), LinuxBackendError> {
        if self.child_reaped {
            return Ok(());
        }
        terminate_child_and_confirm(self.child_mut()?)?;
        self.child_reaped = true;
        Ok(())
    }

    fn child_mut(&mut self) -> Result<&mut Child, LinuxBackendError> {
        self.child
            .as_mut()
            .ok_or(LinuxBackendError::BoundaryOwnedByRecovery)
    }

    fn take_recovery_owner(&mut self) -> Option<Self> {
        Some(Self {
            child: self.child.take(),
            child_reaped: self.child_reaped,
            timeout_watchdog: self.timeout_watchdog.take(),
            synthetic_targets: std::mem::take(&mut self.synthetic_targets),
            protected_create_monitor: self.protected_create_monitor.take(),
            gateway_runtime: self.gateway_runtime.take(),
            status_channel: self.status_channel.take(),
            recovery_attempted: true,
        })
    }

    fn recover_until_terminated(mut self) {
        loop {
            let confirmed =
                self.child_reaped || self.child.as_mut().is_some_and(terminate_and_confirm);
            if confirmed {
                self.child_reaped = true;
            }
            if confirmed && self.cleanup_boundaries().is_ok() {
                return;
            }
            thread::sleep(BOUNDARY_RECOVERY_INTERVAL);
        }
    }
}

impl Drop for LinuxChild {
    fn drop(&mut self) {
        if self.recovery_attempted {
            // A recovery owner must retain enforcement if its thread cannot
            // finish. Releasing any remaining resource could expose a live
            // boundary without its policy.
            std::mem::forget(self.child.take());
            std::mem::forget(self.timeout_watchdog.take());
            std::mem::forget(self.gateway_runtime.take());
            std::mem::forget(self.protected_create_monitor.take());
            std::mem::forget(std::mem::take(&mut self.synthetic_targets));
            return;
        }
        if !self.child_reaped
            && self
                .child
                .as_mut()
                .is_some_and(|child| matches!(child.try_wait(), Ok(Some(_))))
        {
            self.child_reaped = true;
        }
        let boundary_terminated =
            self.child_reaped || self.child.as_mut().is_some_and(terminate_and_confirm);
        if boundary_terminated {
            if self.cleanup_boundaries().is_err()
                && let Some(recovery) = self.take_recovery_owner()
            {
                let _ = thread::Builder::new()
                    .name(BOUNDARY_RECOVERY_THREAD_NAME.to_owned())
                    .spawn(move || recovery.recover_until_terminated());
            }
        } else if !self.recovery_attempted {
            if let Some(recovery) = self.take_recovery_owner() {
                let _ = thread::Builder::new()
                    .name(BOUNDARY_RECOVERY_THREAD_NAME.to_owned())
                    .spawn(move || recovery.recover_until_terminated());
            }
        } else {
            // Dropping these resources would disable monitoring, remove the
            // gateway, or unmount synthetic targets while the boundary may
            // still be alive. Leak them deliberately until the process can
            // be recovered; this is fail-closed and preserves enforcement.
            std::mem::forget(self.child.take());
            std::mem::forget(self.timeout_watchdog.take());
            std::mem::forget(self.gateway_runtime.take());
            std::mem::forget(self.protected_create_monitor.take());
            std::mem::forget(std::mem::take(&mut self.synthetic_targets));
        }
    }
}

fn terminate_and_confirm(child: &mut Child) -> bool {
    terminate_child_and_confirm(child).is_ok()
}

fn terminate_child_and_confirm(child: &mut Child) -> Result<(), LinuxBackendError> {
    if let Err(source) = child.kill() {
        match child.try_wait() {
            Ok(Some(_)) => return Ok(()),
            Ok(None) | Err(_) => return Err(LinuxBackendError::ProcessWaitFailed { source }),
        }
    }
    let deadline = Instant::now() + BOUNDARY_WAIT_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return Ok(()),
            Ok(None) if Instant::now() < deadline => thread::sleep(BOUNDARY_POLL_INTERVAL),
            Ok(None) => return Err(LinuxBackendError::BoundaryTerminationUnconfirmed),
            Err(source) => return Err(LinuxBackendError::ProcessWaitFailed { source }),
        }
    }
}
