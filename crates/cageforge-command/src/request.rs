// Copyright 2026 Mansur Azatbek
// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::command::contains_nul;
use crate::{CommandError, CommandSpec, EnvironmentSpec, StdioSpec, TimeoutPolicy};

/// A complete portable request to execute one command.
///
/// This type describes execution intent only. It does not contain a sandbox
/// policy because policy is a separate Cageforge concern and will be composed
/// by the backend API. It also does not expose PTY handles, inherited file
/// descriptors, process ids, or OS-specific user/token settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandRequest {
    command: CommandSpec,
    working_directory: Option<PathBuf>,
    environment: EnvironmentSpec,
    stdio: StdioSpec,
    timeout: TimeoutPolicy,
}

impl CommandRequest {
    /// Creates a request with the captured-stdio and inherited-environment
    /// defaults.
    pub fn new(command: CommandSpec) -> Self {
        Self {
            command,
            working_directory: None,
            environment: EnvironmentSpec::default(),
            stdio: StdioSpec::default(),
            timeout: TimeoutPolicy::default(),
        }
    }

    /// Sets the working directory.
    ///
    /// The path is kept in the caller's native representation. Resolution of
    /// relative paths and validation against a sandbox policy belong to the
    /// backend boundary.
    pub fn with_working_directory(
        mut self,
        path: impl Into<PathBuf>,
    ) -> Result<Self, CommandError> {
        let path = path.into();
        if path.as_os_str().is_empty() {
            return Err(CommandError::EmptyWorkingDirectory);
        }
        if contains_nul(path.as_os_str()) {
            return Err(CommandError::WorkingDirectoryContainsNul);
        }
        self.working_directory = Some(path);
        Ok(self)
    }

    /// Removes an explicitly configured working directory.
    pub fn without_working_directory(mut self) -> Self {
        self.working_directory = None;
        self
    }

    /// Replaces the environment construction rules.
    pub fn with_environment(mut self, environment: EnvironmentSpec) -> Self {
        self.environment = environment;
        self
    }

    /// Replaces standard stream routing.
    pub fn with_stdio(mut self, stdio: StdioSpec) -> Self {
        self.stdio = stdio;
        self
    }

    /// Sets an explicit maximum execution duration.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = TimeoutPolicy::Limit(timeout);
        self
    }

    /// Replaces the timeout intent with an explicit policy.
    pub fn with_timeout_policy(mut self, timeout: TimeoutPolicy) -> Self {
        self.timeout = timeout;
        self
    }

    /// Uses the timeout selected by the backend or resolved profile.
    pub fn use_backend_timeout(mut self) -> Self {
        self.timeout = TimeoutPolicy::BackendDefault;
        self
    }

    /// Disables the automatic timeout while leaving cancellation available to
    /// the execution lifecycle.
    pub fn disable_timeout(mut self) -> Self {
        self.timeout = TimeoutPolicy::Disabled;
        self
    }

    /// Returns the command line.
    pub fn command(&self) -> &CommandSpec {
        &self.command
    }

    /// Returns the optional working directory.
    pub fn working_directory(&self) -> Option<&Path> {
        self.working_directory.as_deref()
    }

    /// Returns environment construction rules.
    pub fn environment(&self) -> &EnvironmentSpec {
        &self.environment
    }

    /// Returns standard stream routing.
    pub fn stdio(&self) -> StdioSpec {
        self.stdio
    }

    /// Returns the timeout intent.
    pub fn timeout_policy(&self) -> TimeoutPolicy {
        self.timeout
    }
}
