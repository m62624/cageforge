// SPDX-License-Identifier: Apache-2.0

//! Public Windows child lifecycle over the authenticated command runner.

use std::io::{Read, Write};
use std::process::ExitStatus;
use std::thread;
use std::time::Duration;

use crate::capability::store::CapabilityActiveLease;
use crate::error::WindowsBackendError;
use crate::filesystem::acl::FilesystemAclEnforcement;
use crate::network::WindowsProxyRoute;
use crate::runner::session::RunnerSession;

/// A child launched inside the complete Windows sandbox boundary.
pub struct WindowsChild {
    // Rust drops fields in declaration order. Keep the process boundary first,
    // then the route and pinned filesystem resources, and release the
    // active-child lease last so uninstall cannot begin ACL cleanup before
    // those resources are gone. This mirrors release_completed_boundaries.
    session: RunnerSession,
    network_route: Option<WindowsProxyRoute>,
    filesystem_enforcement: Option<FilesystemAclEnforcement>,
    active_lease: Option<CapabilityActiveLease>,
}

impl WindowsChild {
    pub(crate) const fn new(
        session: RunnerSession,
        active_lease: CapabilityActiveLease,
        filesystem_enforcement: FilesystemAclEnforcement,
        network_route: Option<WindowsProxyRoute>,
    ) -> Self {
        Self {
            session,
            network_route,
            filesystem_enforcement: Some(filesystem_enforcement),
            active_lease: Some(active_lease),
        }
    }

    /// Returns the sandboxed user-process identifier.
    pub const fn id(&self) -> u32 {
        self.session.id()
    }

    /// Returns the command's standard-input transport when pipe mode was requested.
    pub fn stdin(&mut self) -> Option<&mut dyn Write> {
        self.session.stdin().map(|input| input as &mut dyn Write)
    }

    /// Returns the command's standard-output transport when pipe mode was requested.
    pub fn stdout(&mut self) -> Option<&mut dyn Read> {
        self.session.stdout().map(|output| output as &mut dyn Read)
    }

    /// Returns the command's standard-error transport when pipe mode was requested.
    pub fn stderr(&mut self) -> Option<&mut dyn Read> {
        self.session.stderr().map(|output| output as &mut dyn Read)
    }

    /// Closes piped standard input so the child observes end-of-file.
    pub fn close_stdin(&mut self) -> Result<(), WindowsBackendError> {
        self.session.close_stdin();
        Ok(())
    }

    /// Checks whether the command has exited without blocking.
    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>, WindowsBackendError> {
        if let Err(error) = self.check_network_health() {
            let _ = self.session.kill();
            self.release_completed_boundaries();
            return Err(error);
        }
        match self.session.try_wait() {
            Ok(Some(status)) => {
                self.release_completed_boundaries();
                Ok(Some(status))
            }
            Ok(None) => Ok(None),
            Err(error) => {
                let _ = self.session.kill();
                self.release_completed_boundaries();
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
        let result = match self.session.wait() {
            Ok(status) => {
                self.release_completed_boundaries();
                Ok(status)
            }
            Err(error) => Err(WindowsBackendError::runner_session(error)),
        };
        if result.is_err() {
            self.release_completed_boundaries();
        }
        result
    }

    /// Terminates the complete parent-owned Job Object and command runner.
    pub fn kill(&mut self) -> Result<(), WindowsBackendError> {
        let result = self
            .session
            .kill()
            .map_err(WindowsBackendError::runner_session);
        self.network_route.take();
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
}
