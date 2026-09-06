// SPDX-License-Identifier: Apache-2.0

//! macOS backend capability declaration and initial construction boundary.

use std::fs;

use cageforge_backend_api::{BackendCapabilities, BackendIdentity, SandboxBackend};

use crate::config::MacosBackendConfig;
use crate::error::MacosBackendError;

/// A macOS-native backend bound to one validated Seatbelt executable.
///
/// The backend is reusable. Each future `spawn` operation will construct its
/// own policy and process boundary; this object does not represent a shared
/// persistent sandbox.
pub struct MacosBackend {
    config: MacosBackendConfig,
    identity: BackendIdentity,
}

impl std::fmt::Debug for MacosBackend {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MacosBackend")
            .field("config", &self.config)
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

impl MacosBackend {
    /// Constructs a backend after validating the fixed Seatbelt executable.
    pub fn new(config: MacosBackendConfig) -> Result<Self, MacosBackendError> {
        let metadata = fs::metadata(config.seatbelt_executable()).map_err(|source| {
            MacosBackendError::SeatbeltExecutable {
                path: config.seatbelt_executable().to_path_buf(),
                source,
            }
        })?;
        if !metadata.is_file() {
            return Err(MacosBackendError::SeatbeltExecutable {
                path: config.seatbelt_executable().to_path_buf(),
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "configured Seatbelt executable is not a regular file",
                ),
            });
        }
        Ok(Self {
            config,
            identity: BackendIdentity::new(),
        })
    }

    /// Returns the immutable backend configuration.
    pub const fn config(&self) -> &MacosBackendConfig {
        &self.config
    }
}

impl SandboxBackend for MacosBackend {
    fn identity(&self) -> &BackendIdentity {
        &self.identity
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities::new()
    }
}
