// SPDX-License-Identifier: Apache-2.0

//! Linux child lifecycle and timeout handling.

use std::os::unix::net::UnixStream;
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, ExitStatus};
use std::thread;
use std::time::Duration;

#[path = "process/timeout.rs"]
pub(crate) mod timeout;

use crate::error::LinuxBackendError;
use crate::filesystem::protected_create::ProtectedCreateMonitor;
use crate::filesystem::synthetic::SyntheticMountTarget;
use crate::network::GatewayRuntime;
use crate::status_transport::{HelperExecutionResult, read_status};
use timeout::TimeoutWatchdog;

/// A child launched inside the Linux backend boundary.
pub struct LinuxChild {
    child: Child,
    timeout_watchdog: Option<TimeoutWatchdog>,
    synthetic_targets: Vec<SyntheticMountTarget>,
    protected_create_monitor: Option<ProtectedCreateMonitor>,
    gateway_runtime: Option<GatewayRuntime>,
    status_channel: Option<UnixStream>,
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
            child,
            timeout_watchdog,
            synthetic_targets,
            protected_create_monitor,
            gateway_runtime,
            status_channel: Some(status_channel),
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
            .child
            .try_wait()
            .map_err(|source| LinuxBackendError::ProcessWaitFailed { source })?;
        if let Some(status) = status {
            return self.finish_status(status).map(Some);
        }
        if self
            .timeout_watchdog
            .as_ref()
            .is_some_and(TimeoutWatchdog::timed_out)
        {
            let status = self
                .child
                .wait()
                .map_err(|source| LinuxBackendError::ProcessWaitFailed { source })?;
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
            .child
            .wait()
            .map_err(|source| LinuxBackendError::ProcessWaitFailed { source })?;
        self.finish_status(boundary_status)
    }

    /// Sends the platform termination request to the Bubblewrap process.
    pub fn kill(&mut self) -> Result<(), LinuxBackendError> {
        self.child
            .kill()
            .map_err(|source| LinuxBackendError::ProcessWaitFailed { source })
    }

    fn cleanup_synthetic_targets(&mut self) -> Result<(), LinuxBackendError> {
        let mut first_error = None;
        for target in self.synthetic_targets.iter_mut().rev() {
            if let Err(error) = target.cleanup()
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        self.synthetic_targets.clear();
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
        let result = match &mut self.timeout_watchdog {
            Some(watchdog) => watchdog.shutdown(),
            None => Ok(false),
        };
        self.timeout_watchdog = None;
        result
    }

    fn cleanup_boundaries(&mut self) -> Result<(), LinuxBackendError> {
        let timeout = self.finish_timeout_watchdog().map(|_| ());
        let gateway = match &mut self.gateway_runtime {
            Some(runtime) => runtime.shutdown(),
            None => Ok(()),
        };
        self.gateway_runtime = None;
        let protected = match &mut self.protected_create_monitor {
            Some(monitor) => monitor.shutdown(),
            None => Ok(()),
        };
        self.protected_create_monitor = None;
        self.status_channel = None;
        let synthetic = self.cleanup_synthetic_targets();
        timeout.and(protected).and(gateway).and(synthetic)
    }

    fn terminate_after_boundary_failure(&mut self) -> bool {
        let _ = self.child.kill();
        self.child.wait().is_ok()
    }
}

impl Drop for LinuxChild {
    fn drop(&mut self) {
        let boundary_terminated = if matches!(self.child.try_wait(), Ok(Some(_))) {
            true
        } else {
            let _ = self.child.kill();
            self.child.wait().is_ok()
        };
        if boundary_terminated {
            let _ = self.cleanup_boundaries();
        } else {
            // Dropping these resources would disable monitoring, remove the
            // gateway, or unmount synthetic targets while the boundary may
            // still be alive. Leak them deliberately until the process can
            // be recovered; this is fail-closed and preserves enforcement.
            std::mem::forget(self.timeout_watchdog.take());
            std::mem::forget(self.gateway_runtime.take());
            std::mem::forget(self.protected_create_monitor.take());
            std::mem::forget(std::mem::take(&mut self.synthetic_targets));
        }
    }
}
