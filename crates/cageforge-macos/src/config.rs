// SPDX-License-Identifier: Apache-2.0

//! Typed macOS backend construction settings.

use std::path::PathBuf;
use std::time::Duration;

use cageforge_network_proxy::GatewayConfig;
use thiserror::Error;

/// The fixed native executable used to enter a macOS Seatbelt boundary.
pub(crate) const DEFAULT_SEATBELT_EXECUTABLE: &str = "/usr/bin/sandbox-exec";

/// Invalid macOS backend construction settings.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum MacosBackendConfigError {
    /// A zero default timeout would make default-timed commands expire
    /// immediately.
    #[error("default command timeout must be greater than zero")]
    ZeroDefaultTimeout,
    /// The selected Seatbelt executable must be an absolute path.
    #[error("Seatbelt executable path must be absolute: {path:?}")]
    SeatbeltExecutableNotAbsolute { path: PathBuf },
}

/// Configuration for one reusable macOS enforcement backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacosBackendConfig {
    seatbelt_executable: PathBuf,
    default_timeout: Duration,
    network_gateway: GatewayConfig,
}

impl Default for MacosBackendConfig {
    fn default() -> Self {
        Self {
            seatbelt_executable: PathBuf::from(DEFAULT_SEATBELT_EXECUTABLE),
            default_timeout: Duration::from_secs(300),
            network_gateway: GatewayConfig::new(),
        }
    }
}

impl MacosBackendConfig {
    /// Creates the secure default configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Uses an explicitly selected absolute Seatbelt executable.
    pub fn with_seatbelt_executable(
        mut self,
        path: impl Into<PathBuf>,
    ) -> Result<Self, MacosBackendConfigError> {
        let path = path.into();
        if !path.is_absolute() {
            return Err(MacosBackendConfigError::SeatbeltExecutableNotAbsolute { path });
        }
        self.seatbelt_executable = path;
        Ok(self)
    }

    /// Sets the timeout used by `TimeoutPolicy::BackendDefault`.
    pub fn with_default_timeout(
        mut self,
        timeout: Duration,
    ) -> Result<Self, MacosBackendConfigError> {
        if timeout.is_zero() {
            return Err(MacosBackendConfigError::ZeroDefaultTimeout);
        }
        self.default_timeout = timeout;
        Ok(self)
    }

    /// Replaces the bounds used by restricted-network gateway instances.
    pub fn with_network_gateway(mut self, config: GatewayConfig) -> Self {
        self.network_gateway = config;
        self
    }

    pub(crate) fn seatbelt_executable(&self) -> &std::path::Path {
        &self.seatbelt_executable
    }

    pub(crate) const fn default_timeout(&self) -> Duration {
        self.default_timeout
    }

    pub(crate) const fn network_gateway(&self) -> &GatewayConfig {
        &self.network_gateway
    }
}
