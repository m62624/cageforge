// SPDX-License-Identifier: Apache-2.0

//! Windows backend and provisioning configuration.

use std::path::{Path, PathBuf};
use std::time::Duration;

use cageforge_network_proxy::GatewayConfig;
use thiserror::Error;

/// Immutable settings for one Windows backend instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsBackendConfig {
    setup: WindowsSetupConfig,
    default_timeout: Duration,
    network_gateway: GatewayConfig,
}

/// Settings used to locate and provision the elevated Windows boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsSetupConfig {
    state_directory: WindowsStateDirectorySource,
    setup_helper: SetupHelperSource,
    command_runner: CommandRunnerSource,
}

/// How Cageforge locates its protected Windows setup state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WindowsStateDirectorySource {
    /// Use the system ProgramData directory and a Cageforge-owned child.
    ProgramData,
    /// Use an application-selected absolute directory.
    Explicit(PathBuf),
}

/// How Cageforge locates the administrator setup helper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetupHelperSource {
    /// Use a release-packaged helper next to the application or in
    /// `cageforge-resources`.
    Bundled,
    /// Use `cageforge-windows-setup.exe` next to the current executable.
    Sibling,
    /// Use this explicitly selected helper executable.
    Explicit(PathBuf),
}

/// How Cageforge locates the authenticated sandbox command runner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandRunnerSource {
    /// Use a release-packaged command runner next to the application or in
    /// `cageforge-resources`.
    Bundled,
    /// Use `cageforge-windows-command-runner.exe` next to the current executable.
    Sibling,
    /// Use this explicitly selected command-runner executable.
    Explicit(PathBuf),
}

/// Invalid Windows backend configuration.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum WindowsBackendConfigError {
    /// A backend-default timeout of zero cannot bound a process.
    #[error("Windows backend default timeout must be greater than zero")]
    ZeroDefaultTimeout,
    /// A state directory must be an absolute Windows path.
    #[error("Windows setup state directory must be absolute: {path:?}")]
    RelativeStateDirectory {
        /// Rejected directory.
        path: PathBuf,
    },
    /// A setup-helper path must be an absolute Windows path.
    #[error("Windows setup helper path must be absolute: {path:?}")]
    RelativeSetupHelper {
        /// Rejected helper path.
        path: PathBuf,
    },
    /// A command-runner path must be an absolute Windows path.
    #[error("Windows command runner path must be absolute: {path:?}")]
    RelativeCommandRunner {
        /// Rejected command-runner path.
        path: PathBuf,
    },
}

impl Default for WindowsBackendConfig {
    fn default() -> Self {
        Self {
            setup: WindowsSetupConfig::default(),
            default_timeout: Duration::from_secs(300),
            network_gateway: GatewayConfig::new(),
        }
    }
}

impl WindowsBackendConfig {
    /// Creates the secure default configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Replaces the setup and state-location configuration.
    pub fn with_setup(mut self, setup: WindowsSetupConfig) -> Self {
        self.setup = setup;
        self
    }

    /// Sets the timeout used by backend-default timeout requests.
    pub fn with_default_timeout(
        mut self,
        timeout: Duration,
    ) -> Result<Self, WindowsBackendConfigError> {
        if timeout.is_zero() {
            return Err(WindowsBackendConfigError::ZeroDefaultTimeout);
        }
        self.default_timeout = timeout;
        Ok(self)
    }

    /// Sets resource limits used by restricted-network gateways.
    pub fn with_network_gateway(mut self, config: GatewayConfig) -> Self {
        self.network_gateway = config;
        self
    }

    /// Returns the setup configuration.
    pub const fn setup(&self) -> &WindowsSetupConfig {
        &self.setup
    }

    /// Returns the non-zero backend-default timeout.
    pub const fn default_timeout(&self) -> Duration {
        self.default_timeout
    }

    /// Returns the resource limits used by restricted-network gateways.
    pub const fn network_gateway_config(&self) -> &GatewayConfig {
        &self.network_gateway
    }
}

impl Default for WindowsSetupConfig {
    fn default() -> Self {
        Self {
            state_directory: WindowsStateDirectorySource::ProgramData,
            setup_helper: SetupHelperSource::Bundled,
            command_runner: CommandRunnerSource::Bundled,
        }
    }
}

impl WindowsSetupConfig {
    /// Creates the secure default setup configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Uses an explicit protected state directory.
    pub fn with_state_directory(
        mut self,
        path: impl Into<PathBuf>,
    ) -> Result<Self, WindowsBackendConfigError> {
        let path = path.into();
        if !path.is_absolute() {
            return Err(WindowsBackendConfigError::RelativeStateDirectory { path });
        }
        self.state_directory = WindowsStateDirectorySource::Explicit(path);
        Ok(self)
    }

    /// Uses the setup helper next to the current executable.
    pub fn with_sibling_setup_helper(mut self) -> Self {
        self.setup_helper = SetupHelperSource::Sibling;
        self
    }

    /// Uses a release-packaged helper resolved by the `bundled-helpers`
    /// resource layout.
    pub fn with_bundled_setup_helper(mut self) -> Self {
        self.setup_helper = SetupHelperSource::Bundled;
        self
    }

    /// Uses an explicitly selected setup helper.
    pub fn with_setup_helper_path(
        mut self,
        path: impl Into<PathBuf>,
    ) -> Result<Self, WindowsBackendConfigError> {
        let path = path.into();
        if !path.is_absolute() {
            return Err(WindowsBackendConfigError::RelativeSetupHelper { path });
        }
        self.setup_helper = SetupHelperSource::Explicit(path);
        Ok(self)
    }

    /// Returns how the protected setup directory is selected.
    pub const fn state_directory_source(&self) -> &WindowsStateDirectorySource {
        &self.state_directory
    }

    /// Returns an explicit state directory, if configured.
    pub fn state_directory(&self) -> Option<&Path> {
        match &self.state_directory {
            WindowsStateDirectorySource::ProgramData => None,
            WindowsStateDirectorySource::Explicit(path) => Some(path),
        }
    }

    /// Returns how the setup helper is selected.
    pub const fn setup_helper_source(&self) -> &SetupHelperSource {
        &self.setup_helper
    }

    /// Returns an explicit setup-helper path, if configured.
    pub fn setup_helper_path(&self) -> Option<&Path> {
        match &self.setup_helper {
            SetupHelperSource::Bundled | SetupHelperSource::Sibling => None,
            SetupHelperSource::Explicit(path) => Some(path),
        }
    }

    /// Uses the command runner next to the current executable.
    pub fn with_sibling_command_runner(mut self) -> Self {
        self.command_runner = CommandRunnerSource::Sibling;
        self
    }

    /// Uses a release-packaged command runner resolved by the
    /// `bundled-helpers` resource layout.
    pub fn with_bundled_command_runner(mut self) -> Self {
        self.command_runner = CommandRunnerSource::Bundled;
        self
    }

    /// Uses an explicitly selected command runner.
    pub fn with_command_runner_path(
        mut self,
        path: impl Into<PathBuf>,
    ) -> Result<Self, WindowsBackendConfigError> {
        let path = path.into();
        if !path.is_absolute() {
            return Err(WindowsBackendConfigError::RelativeCommandRunner { path });
        }
        self.command_runner = CommandRunnerSource::Explicit(path);
        Ok(self)
    }

    /// Returns how the command runner is selected.
    pub const fn command_runner_source(&self) -> &CommandRunnerSource {
        &self.command_runner
    }

    /// Returns an explicit command-runner path, if configured.
    pub fn command_runner_path(&self) -> Option<&Path> {
        match &self.command_runner {
            CommandRunnerSource::Bundled | CommandRunnerSource::Sibling => None,
            CommandRunnerSource::Explicit(path) => Some(path),
        }
    }
}
