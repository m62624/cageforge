// SPDX-License-Identifier: Apache-2.0

//! Linux-specific classification of typed native errors.

use cageforge_backend_api::{BackendDiagnostic, BackendDiagnosticMetadata};

use crate::error::LinuxBackendError;

impl BackendDiagnostic for LinuxBackendError {
    fn diagnostic_metadata(&self) -> BackendDiagnosticMetadata {
        match self {
            Self::UnsupportedCapability { .. } => {
                BackendDiagnosticMetadata::new("linux_unsupported_capability", Some("capability"))
            }
            _ => BackendDiagnosticMetadata::new("linux_native_error", None),
        }
    }
}
