// SPDX-License-Identifier: Apache-2.0

//! Typed macOS backend failures.

use std::io;
use std::path::PathBuf;

use cageforge_backend_api::BackendContractError;
use thiserror::Error;

/// Errors returned by the macOS backend.
#[derive(Debug, Error)]
pub enum MacosBackendError {
    /// Portable capability or prepared-handoff validation failed.
    #[error("macOS backend request validation failed: {source}")]
    Contract {
        /// The portable contract failure.
        #[source]
        source: BackendContractError,
    },
    /// The configured Seatbelt executable could not be inspected.
    #[error("failed to inspect Seatbelt executable {path:?}: {source}")]
    SeatbeltExecutable {
        /// The configured executable.
        path: PathBuf,
        /// The operating-system failure.
        #[source]
        source: io::Error,
    },
    /// Native lowering is not yet available for a requested capability.
    #[error("macOS backend cannot safely lower requested capability: {capability}")]
    UnsupportedCapability {
        /// The unsupported portable capability.
        capability: cageforge_backend_api::BackendCapability,
    },
}
