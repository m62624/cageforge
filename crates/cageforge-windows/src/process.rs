// SPDX-License-Identifier: Apache-2.0

//! Public Windows child lifecycle over the authenticated command runner.

use std::io::{Read, Write};
use std::process::ExitStatus;
use std::thread;
use std::time::Duration;

use crate::error::WindowsBackendError;
use crate::filesystem_acl::FilesystemAclEnforcement;
use crate::network::WindowsProxyRoute;
use crate::runner_session::RunnerSession;

/// A child launched inside the complete Windows sandbox boundary.
pub struct WindowsChild {
    session: RunnerSession,
    _filesystem_enforcement: FilesystemAclEnforcement,
    network_route: Option<WindowsProxyRoute>,
}

impl WindowsChild {
    pub(crate) const fn new(
        session: RunnerSession,
        filesystem_enforcement: FilesystemAclEnforcement,
        network_route: Option<WindowsProxyRoute>,
    ) -> Self {
        Self {
            session,
            _filesystem_enforcement: filesystem_enforcement,
            network_route,
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

    /// Closes piped standard input and sends an authenticated EOF request.
    pub fn close_stdin(&mut self) -> Result<(), WindowsBackendError> {
        match self.session.stdin() {
            Some(input) => input.close().map_err(WindowsBackendError::runner_protocol),
            None => Ok(()),
        }
    }

    /// Checks whether the command has exited without blocking.
    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>, WindowsBackendError> {
        if let Err(error) = self.check_network_health() {
            let _ = self.session.kill();
            self.network_route.take();
            return Err(error);
        }
        match self.session.try_wait() {
            Ok(Some(status)) => {
                self.network_route.take();
                Ok(Some(status))
            }
            Ok(None) => Ok(None),
            Err(error) => {
                let _ = self.session.kill();
                self.network_route.take();
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
        self.session
            .wait()
            .map_err(WindowsBackendError::runner_session)
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
}
