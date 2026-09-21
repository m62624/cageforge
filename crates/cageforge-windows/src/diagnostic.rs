// SPDX-License-Identifier: Apache-2.0

//! Windows-specific classification of typed native errors.

use cageforge_backend_api::{BackendDiagnostic, BackendDiagnosticMetadata};

use crate::error::WindowsBackendError;

impl BackendDiagnostic for WindowsBackendError {
    fn diagnostic_metadata(&self) -> BackendDiagnosticMetadata {
        match self {
            Self::UnsupportedCapability { .. } => {
                BackendDiagnosticMetadata::new("windows_unsupported_capability", Some("capability"))
            }
            _ => BackendDiagnosticMetadata::new("windows_native_error", None),
        }
    }
}
