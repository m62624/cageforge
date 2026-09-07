// SPDX-License-Identifier: Apache-2.0

//! Unified ergonomic facade for Cageforge sandbox execution.
//!
//! [`Sandbox`] is the common execution contract implemented by the native
//! Linux, Windows, and macOS backends. The portable command, policy,
//! composition, path, and backend-contract types are re-exported here so an
//! application can depend on one crate while choosing only the native backend
//! it needs through a Cargo feature.
//!
//! A backend is reusable, but each [`Sandbox::spawn`] call creates one
//! independent operating-system boundary around one command and its complete
//! descendant process tree. The public facade is synchronous; internal
//! gateways may use asynchronous tasks without imposing an async runtime on
//! the caller.

#![doc = include_str!("../README.md")]
#![deny(unsafe_code)]
#![deny(missing_docs)]

use std::io::{Read, Write};
use std::process::ExitStatus;

pub use cageforge_backend_api::*;
pub use cageforge_command::*;
pub use cageforge_path::*;
pub use cageforge_policy::*;
pub use cageforge_policy_compose::*;

#[cfg(feature = "config")]
pub use cageforge_config::*;

#[cfg(all(feature = "linux", target_os = "linux"))]
pub use cageforge_linux::*;

#[cfg(all(feature = "windows", target_os = "windows"))]
pub use cageforge_windows::*;

#[cfg(all(feature = "macos", target_os = "macos"))]
pub use cageforge_macos::*;

/// Common preparation and process-launch contract for native Cageforge
/// backends.
pub trait Sandbox: cageforge_backend_api::SandboxBackend {
    /// The native child handle returned by [`Self::spawn`].
    type Child: SandboxChild<Error = Self::Error>;

    /// The native error type for preparation and launch.
    type Error: std::error::Error + 'static;

    /// Validates a command and effective policy against this backend.
    fn prepare<'a>(
        &self,
        request: BackendRequest<'a>,
        context: &PathResolutionContext,
    ) -> Result<PreparedBackendRequest<'a, Self>, Self::Error>
    where
        Self: Sized;

    /// Launches one command in a new native sandbox boundary.
    fn spawn<'a>(
        &self,
        prepared: PreparedBackendRequest<'a, Self>,
    ) -> Result<Self::Child, Self::Error>
    where
        Self: Sized;
}

/// Common lifecycle operations for one native sandbox instance.
pub trait SandboxChild {
    /// The native process or boundary identifier.
    fn id(&self) -> u32;

    /// Returns the piped standard input stream, if requested.
    fn stdin(&mut self) -> Option<&mut dyn Write>;

    /// Returns the piped standard output stream, if requested.
    fn stdout(&mut self) -> Option<&mut dyn Read>;

    /// Returns the piped standard error stream, if requested.
    fn stderr(&mut self) -> Option<&mut dyn Read>;

    /// The native lifecycle error type.
    type Error: std::error::Error + 'static;

    /// Checks for completion without waiting for the command.
    fn try_wait(&mut self) -> Result<Option<ExitStatus>, Self::Error>;

    /// Waits for completion while enforcing the prepared timeout policy.
    fn wait(&mut self) -> Result<ExitStatus, Self::Error>;

    /// Terminates and confirms the complete sandbox boundary.
    fn kill(&mut self) -> Result<(), Self::Error>;
}

#[cfg(all(feature = "linux", target_os = "linux"))]
impl Sandbox for LinuxBackend {
    type Child = LinuxChild;
    type Error = LinuxBackendError;

    fn prepare<'a>(
        &self,
        request: BackendRequest<'a>,
        context: &PathResolutionContext,
    ) -> Result<PreparedBackendRequest<'a, Self>, Self::Error> {
        LinuxBackend::prepare(self, request, context)
    }

    fn spawn<'a>(
        &self,
        prepared: PreparedBackendRequest<'a, Self>,
    ) -> Result<Self::Child, Self::Error> {
        LinuxBackend::spawn(self, prepared)
    }
}

#[cfg(all(feature = "windows", target_os = "windows"))]
impl Sandbox for WindowsBackend {
    type Child = WindowsChild;
    type Error = WindowsBackendError;

    fn prepare<'a>(
        &self,
        request: BackendRequest<'a>,
        context: &PathResolutionContext,
    ) -> Result<PreparedBackendRequest<'a, Self>, Self::Error> {
        WindowsBackend::prepare(self, request, context)
    }

    fn spawn<'a>(
        &self,
        prepared: PreparedBackendRequest<'a, Self>,
    ) -> Result<Self::Child, Self::Error> {
        WindowsBackend::spawn(self, prepared)
    }
}

#[cfg(all(feature = "macos", target_os = "macos"))]
impl Sandbox for MacosBackend {
    type Child = MacosChild;
    type Error = MacosBackendError;

    fn prepare<'a>(
        &self,
        request: BackendRequest<'a>,
        context: &PathResolutionContext,
    ) -> Result<PreparedBackendRequest<'a, Self>, Self::Error> {
        MacosBackend::prepare(self, request, context)
    }

    fn spawn<'a>(
        &self,
        prepared: PreparedBackendRequest<'a, Self>,
    ) -> Result<Self::Child, Self::Error> {
        MacosBackend::spawn(self, prepared)
    }
}

#[cfg(all(feature = "linux", target_os = "linux"))]
impl SandboxChild for LinuxChild {
    type Error = LinuxBackendError;

    fn id(&self) -> u32 {
        LinuxChild::id(self)
    }

    fn stdin(&mut self) -> Option<&mut dyn Write> {
        LinuxChild::stdin(self).map(|stream| stream as &mut dyn Write)
    }

    fn stdout(&mut self) -> Option<&mut dyn Read> {
        LinuxChild::stdout(self).map(|stream| stream as &mut dyn Read)
    }

    fn stderr(&mut self) -> Option<&mut dyn Read> {
        LinuxChild::stderr(self).map(|stream| stream as &mut dyn Read)
    }

    fn try_wait(&mut self) -> Result<Option<ExitStatus>, Self::Error> {
        LinuxChild::try_wait(self)
    }

    fn wait(&mut self) -> Result<ExitStatus, Self::Error> {
        LinuxChild::wait(self)
    }

    fn kill(&mut self) -> Result<(), Self::Error> {
        LinuxChild::kill(self)
    }
}

#[cfg(all(feature = "windows", target_os = "windows"))]
impl SandboxChild for WindowsChild {
    type Error = WindowsBackendError;

    fn id(&self) -> u32 {
        WindowsChild::id(self)
    }

    fn stdin(&mut self) -> Option<&mut dyn Write> {
        WindowsChild::stdin(self)
    }

    fn stdout(&mut self) -> Option<&mut dyn Read> {
        WindowsChild::stdout(self)
    }

    fn stderr(&mut self) -> Option<&mut dyn Read> {
        WindowsChild::stderr(self)
    }

    fn try_wait(&mut self) -> Result<Option<ExitStatus>, Self::Error> {
        WindowsChild::try_wait(self)
    }

    fn wait(&mut self) -> Result<ExitStatus, Self::Error> {
        WindowsChild::wait(self)
    }

    fn kill(&mut self) -> Result<(), Self::Error> {
        WindowsChild::kill(self)
    }
}

#[cfg(all(feature = "macos", target_os = "macos"))]
impl SandboxChild for MacosChild {
    type Error = MacosBackendError;

    fn id(&self) -> u32 {
        MacosChild::id(self)
    }

    fn stdin(&mut self) -> Option<&mut dyn Write> {
        MacosChild::stdin(self).map(|stream| stream as &mut dyn Write)
    }

    fn stdout(&mut self) -> Option<&mut dyn Read> {
        MacosChild::stdout(self).map(|stream| stream as &mut dyn Read)
    }

    fn stderr(&mut self) -> Option<&mut dyn Read> {
        MacosChild::stderr(self).map(|stream| stream as &mut dyn Read)
    }

    fn try_wait(&mut self) -> Result<Option<ExitStatus>, Self::Error> {
        MacosChild::try_wait(self)
    }

    fn wait(&mut self) -> Result<ExitStatus, Self::Error> {
        MacosChild::wait(self)
    }

    fn kill(&mut self) -> Result<(), Self::Error> {
        MacosChild::kill(self)
    }
}
