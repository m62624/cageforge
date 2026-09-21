// SPDX-License-Identifier: Apache-2.0

//! macOS-specific classification of typed native errors.

use cageforge_backend_api::{BackendDiagnostic, BackendDiagnosticMetadata};

use crate::error::{MacosBackendError, MacosFilesystemError};

impl BackendDiagnostic for MacosFilesystemError {
    fn diagnostic_metadata(&self) -> BackendDiagnosticMetadata {
        match self {
            Self::ProgramRequiresRead { .. } => BackendDiagnosticMetadata::new(
                "macos_program_requires_read",
                Some("command.program"),
            ),
            Self::ProgramRequiresExecutableRoot { .. } => BackendDiagnosticMetadata::new(
                "macos_program_requires_executable_root",
                Some("runtime.executable_roots"),
            ),
            Self::ExecutableRootMissing { .. }
            | Self::ExecutableRootNotDirectory { .. }
            | Self::ExecutableRootNotReadable { .. }
            | Self::InvalidExecutableRoot { .. } => BackendDiagnosticMetadata::new(
                "macos_invalid_executable_root",
                Some("runtime.executable_roots"),
            ),
            _ => BackendDiagnosticMetadata::new("macos_native_error", None),
        }
    }
}

impl BackendDiagnostic for MacosBackendError {
    fn diagnostic_metadata(&self) -> BackendDiagnosticMetadata {
        match self {
            Self::Filesystem(error) => error.diagnostic_metadata(),
            _ => BackendDiagnosticMetadata::new("macos_native_error", None),
        }
    }
}
