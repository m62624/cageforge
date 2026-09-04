// SPDX-License-Identifier: Apache-2.0

//! Public Windows child lifecycle over the authenticated command runner.

use std::io::{Read, Write};
use std::process::ExitStatus;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::capability::store::CapabilityActiveLease;
use crate::error::WindowsBackendError;
use crate::filesystem::acl::FilesystemAclEnforcement;
use crate::network::WindowsProxyRoute;
use crate::runner::parent::BoundaryTerminator;
use crate::runner::session::{RunnerSession, RunnerSessionError};

const BOUNDARY_RECOVERY_INTERVAL: Duration = Duration::from_secs(1);
const BOUNDARY_RECOVERY_THREAD_NAME: &str = "cageforge-windows-boundary-recovery";

/// A child launched inside the complete Windows sandbox boundary.
pub struct WindowsChild {
    session: Option<RunnerSession>,
    network_route: Option<WindowsProxyRoute>,
    filesystem_enforcement: Option<FilesystemAclEnforcement>,
    active_lease: Option<CapabilityActiveLease>,
}

struct WindowsBoundaryRecovery {
    session: Option<RunnerSession>,
    boundary: Option<Arc<BoundaryTerminator>>,
    network_route: Option<WindowsProxyRoute>,
    filesystem_enforcement: Option<FilesystemAclEnforcement>,
    active_lease: Option<CapabilityActiveLease>,
    released: bool,
}

impl WindowsChild {
    pub(crate) const fn new(
        session: RunnerSession,
        active_lease: CapabilityActiveLease,
        filesystem_enforcement: FilesystemAclEnforcement,
        network_route: Option<WindowsProxyRoute>,
    ) -> Self {
        Self {
            session: Some(session),
            network_route,
            filesystem_enforcement: Some(filesystem_enforcement),
            active_lease: Some(active_lease),
        }
    }

    /// Returns the sandboxed user-process identifier.
    pub const fn id(&self) -> u32 {
        match &self.session {
            Some(session) => session.id(),
            None => 0,
        }
    }

    /// Returns the command's standard-input transport when pipe mode was requested.
    pub fn stdin(&mut self) -> Option<&mut dyn Write> {
        self.session
            .as_mut()
            .and_then(RunnerSession::stdin)
            .map(|input| input as &mut dyn Write)
    }

    /// Returns the command's standard-output transport when pipe mode was requested.
    pub fn stdout(&mut self) -> Option<&mut dyn Read> {
        self.session
            .as_mut()
            .and_then(RunnerSession::stdout)
            .map(|output| output as &mut dyn Read)
    }

    /// Returns the command's standard-error transport when pipe mode was requested.
    pub fn stderr(&mut self) -> Option<&mut dyn Read> {
        self.session
            .as_mut()
            .and_then(RunnerSession::stderr)
            .map(|output| output as &mut dyn Read)
    }

    /// Closes piped standard input so the child observes end-of-file.
    pub fn close_stdin(&mut self) -> Result<(), WindowsBackendError> {
        self.session_mut()?.close_stdin();
        Ok(())
    }

    /// Checks whether the command has exited without blocking.
    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>, WindowsBackendError> {
        if let Err(error) = self.check_network_health() {
            if self
                .session
                .as_mut()
                .is_some_and(|session| session.kill().is_ok())
            {
                // A successful kill proves that the complete Job Object and
                // runner boundary terminated. A failed kill leaves every
                // enforcement resource owned until Drop can retry it.
                self.release_completed_boundaries();
            }
            return Err(error);
        }
        match self.session_mut()?.try_wait() {
            Ok(Some(status)) => {
                self.release_completed_boundaries();
                Ok(Some(status))
            }
            Ok(None) => Ok(None),
            Err(error) => {
                if self.session.as_ref().is_some_and(RunnerSession::finished) {
                    // A timeout is reported as an error to preserve the
                    // command result, but a successful watchdog termination
                    // already proved that the complete boundary is gone.
                    self.release_completed_boundaries();
                } else if self
                    .session
                    .as_mut()
                    .is_some_and(|session| session.kill().is_ok())
                {
                    // The recovery kill is also a proof when it succeeds.
                    // If it fails, keep the lease and enforcement handles
                    // until Drop can make another bounded attempt.
                    self.release_completed_boundaries();
                }
                Err(WindowsBackendError::runner_session(error))
            }
        }
    }

    /// Waits for completion while enforcing the prepared timeout.
    pub fn wait(&mut self) -> Result<ExitStatus, WindowsBackendError> {
        if self.network_route.is_some() {
            loop {
                if let Some(status) = self.try_wait()? {
                    return Ok(status);
                }
                thread::sleep(Duration::from_millis(5));
            }
        }
        let result = match self.session_mut()?.wait() {
            Ok(status) => {
                self.release_completed_boundaries();
                Ok(status)
            }
            Err(error) => {
                if self.session.as_ref().is_some_and(RunnerSession::finished) {
                    // Preserve the typed timeout error while releasing the
                    // resources whose boundary termination was confirmed.
                    self.release_completed_boundaries();
                }
                Err(WindowsBackendError::runner_session(error))
            }
        };
        // On error the session may still own a live runner or Job Object.
        // Keeping the lease is fail-closed; the caller can retry/Drop the
        // child, which performs the bounded termination attempt.
        result
    }

    /// Terminates the complete parent-owned Job Object and command runner.
    pub fn kill(&mut self) -> Result<(), WindowsBackendError> {
        let result = self
            .session_mut()?
            .kill()
            .map_err(WindowsBackendError::runner_session);
        if result.is_ok() {
            // RunnerSession returns Ok only after the complete Job Object and
            // runner boundary have terminated successfully. Release all
            // enforcement resources at that point; an error path leaves them
            // owned until Drop can retry the boundary.
            self.release_completed_boundaries();
        }
        result
    }

    fn check_network_health(&self) -> Result<(), WindowsBackendError> {
        match &self.network_route {
            Some(route) => route.check_health().map_err(WindowsBackendError::from),
            None => Ok(()),
        }
    }

    fn release_completed_boundaries(&mut self) {
        self.network_route.take();
        if let Some(enforcement) = self.filesystem_enforcement.take() {
            enforcement.release();
        }
        self.active_lease.take();
    }

    fn session_mut(&mut self) -> Result<&mut RunnerSession, WindowsBackendError> {
        self.session.as_mut().ok_or_else(|| {
            WindowsBackendError::runner_session(RunnerSessionError::LifecycleConsumed)
        })
    }
}

impl WindowsBoundaryRecovery {
    fn start_or_retain(mut self) {
        if self.try_terminate() {
            self.release_after_confirmed_boundary();
            return;
        }
        let _ = thread::Builder::new()
            .name(BOUNDARY_RECOVERY_THREAD_NAME.to_owned())
            .spawn(move || self.recover_until_terminated());
    }

    fn recover_until_terminated(mut self) {
        loop {
            if self.try_terminate() {
                self.release_after_confirmed_boundary();
                return;
            }
            thread::sleep(BOUNDARY_RECOVERY_INTERVAL);
        }
    }

    fn try_terminate(&self) -> bool {
        self.boundary
            .as_ref()
            .is_some_and(|boundary| boundary.terminate(125).is_ok())
    }

    fn release_after_confirmed_boundary(&mut self) {
        if let Some(mut session) = self.session.take() {
            session.mark_termination_confirmed();
            drop(session);
        }
        self.boundary.take();
        self.network_route.take();
        self.filesystem_enforcement.take();
        self.active_lease.take();
        self.released = true;
    }
}

impl Drop for WindowsBoundaryRecovery {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        // If the recovery thread cannot be created or terminates unexpectedly,
        // do not release enforcement while the process boundary may still be
        // alive. Keep every owner until an external recovery action succeeds.
        std::mem::forget(self.session.take());
        std::mem::forget(self.boundary.take());
        std::mem::forget(self.network_route.take());
        std::mem::forget(self.filesystem_enforcement.take());
        std::mem::forget(self.active_lease.take());
    }
}

impl Drop for WindowsChild {
    fn drop(&mut self) {
        let Some(session) = self.session.take() else {
            return;
        };
        let recovery = WindowsBoundaryRecovery {
            boundary: Some(session.boundary()),
            session: Some(session),
            network_route: self.network_route.take(),
            filesystem_enforcement: self.filesystem_enforcement.take(),
            active_lease: self.active_lease.take(),
            released: false,
        };
        recovery.start_or_retain();
    }
}

pub(crate) fn recover_failed_session_start(
    boundary: Arc<BoundaryTerminator>,
    network_route: Option<WindowsProxyRoute>,
    filesystem_enforcement: FilesystemAclEnforcement,
    active_lease: CapabilityActiveLease,
) {
    WindowsBoundaryRecovery {
        session: None,
        boundary: Some(boundary),
        network_route,
        filesystem_enforcement: Some(filesystem_enforcement),
        active_lease: Some(active_lease),
        released: false,
    }
    .start_or_retain();
}
