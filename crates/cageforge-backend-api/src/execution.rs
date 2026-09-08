// SPDX-License-Identifier: Apache-2.0

//! Static and dynamic execution contracts shared by native backends.

use std::{
    error::Error,
    io::{Read, Write},
    process::ExitStatus,
};

use cageforge_policy::PathResolutionContext;

use crate::{BackendRequest, PreparedBackendRequest, SandboxBackend};

/// Execution through a reusable backend without naming its native child or error type.
///
/// Use `Box<dyn DynSandbox>` for ownership or `Arc<dyn DynSandbox>` to share a
/// backend across threads. Each launch retains its own effective policy and
/// child boundary. Native setup must already be complete before constructing
/// the backend; this interface never installs system components implicitly.
///
/// The blanket implementation uses the backend's [`Sandbox::prepare`] and
/// [`Sandbox::spawn`] in sequence on the same instance. Implementing a backend
/// remains a trusted integration responsibility, including native enforcement.
pub trait DynSandbox: SandboxBackend + Send + Sync {
    /// Prepares and starts a command in a new sandbox boundary.
    ///
    /// Preparation failure prevents spawn. The returned child owns its native
    /// resources independently of the borrowed request and backend reference.
    fn launch(
        &self,
        request: BackendRequest<'_>,
        context: &PathResolutionContext,
    ) -> Result<Box<dyn SandboxChild<Error = SandboxExecutionError> + Send>, SandboxExecutionError>;
}

/// A failed dynamic execution operation, retaining its concrete native cause.
///
/// [`Error::source`] exposes the original backend error, including its nested
/// source chain and `downcast_ref` support. Errors do not consume or detach a
/// live child: its native lifecycle still controls termination and recovery.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SandboxExecutionError {
    /// The selected backend rejected preparation before starting a process.
    #[error("sandbox preparation failed: {source}")]
    Prepare {
        /// The original native preparation error.
        source: Box<dyn Error + Send + Sync>,
    },
    /// Native process or boundary creation failed.
    #[error("sandbox launch failed: {source}")]
    Spawn {
        /// The original native launch error.
        source: Box<dyn Error + Send + Sync>,
    },
    /// Checking command completion failed.
    #[error("sandbox status check failed: {source}")]
    TryWait {
        /// The original native status error.
        source: Box<dyn Error + Send + Sync>,
    },
    /// Waiting for command completion failed, including a native timeout.
    #[error("sandbox wait failed: {source}")]
    Wait {
        /// The original native wait error.
        source: Box<dyn Error + Send + Sync>,
    },
    /// Terminating or cleaning up the complete boundary failed.
    #[error("sandbox termination failed: {source}")]
    Kill {
        /// The original native termination error.
        source: Box<dyn Error + Send + Sync>,
    },
}

struct ErasedChild<C> {
    child: C,
}

/// Common preparation and process-launch contract for native Cageforge
/// backends.
pub trait Sandbox: SandboxBackend {
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

impl<B> DynSandbox for B
where
    B: Sandbox + Send + Sync,
    B::Child: Send + 'static,
    B::Error: Send + Sync,
{
    fn launch(
        &self,
        request: BackendRequest<'_>,
        context: &PathResolutionContext,
    ) -> Result<Box<dyn SandboxChild<Error = SandboxExecutionError> + Send>, SandboxExecutionError>
    {
        let prepared =
            self.prepare(request, context)
                .map_err(|source| SandboxExecutionError::Prepare {
                    source: Box::new(source),
                })?;
        let child = self
            .spawn(prepared)
            .map_err(|source| SandboxExecutionError::Spawn {
                source: Box::new(source),
            })?;
        Ok(Box::new(ErasedChild { child }))
    }
}

impl<C> SandboxChild for ErasedChild<C>
where
    C: SandboxChild,
    C::Error: Send + Sync,
{
    type Error = SandboxExecutionError;

    fn id(&self) -> u32 {
        self.child.id()
    }

    fn stdin(&mut self) -> Option<&mut dyn Write> {
        self.child.stdin()
    }

    fn stdout(&mut self) -> Option<&mut dyn Read> {
        self.child.stdout()
    }

    fn stderr(&mut self) -> Option<&mut dyn Read> {
        self.child.stderr()
    }

    fn try_wait(&mut self) -> Result<Option<ExitStatus>, Self::Error> {
        self.child
            .try_wait()
            .map_err(|source| SandboxExecutionError::TryWait {
                source: Box::new(source),
            })
    }

    fn wait(&mut self) -> Result<ExitStatus, Self::Error> {
        self.child
            .wait()
            .map_err(|source| SandboxExecutionError::Wait {
                source: Box::new(source),
            })
    }

    fn kill(&mut self) -> Result<(), Self::Error> {
        self.child
            .kill()
            .map_err(|source| SandboxExecutionError::Kill {
                source: Box::new(source),
            })
    }
}
