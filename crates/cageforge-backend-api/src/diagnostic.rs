// SPDX-License-Identifier: Apache-2.0

//! Shared metadata for native backend diagnostics.

/// Stable presentation metadata for one native backend failure.
///
/// The metadata is deliberately smaller than the backend's error enum. The
/// native backend remains the owner of the typed error and its platform
/// details; this value gives adapters a stable code and, when applicable, the
/// portable configuration field that caused the failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendDiagnosticMetadata {
    code: &'static str,
    field: Option<&'static str>,
}

impl BackendDiagnosticMetadata {
    /// Creates metadata for a backend failure.
    pub const fn new(code: &'static str, field: Option<&'static str>) -> Self {
        Self { code, field }
    }

    /// Returns the stable diagnostic code.
    pub const fn code(self) -> &'static str {
        self.code
    }

    /// Returns the portable configuration field associated with the failure.
    pub const fn field(self) -> Option<&'static str> {
        self.field
    }
}

/// Supplies stable presentation metadata for a concrete backend error.
///
/// Implement this for the backend's public top-level error and for nested
/// error types when callers may receive them directly. The implementation is
/// responsible for preserving the backend-specific typed error; this trait is
/// only an adapter-facing classification layer.
pub trait BackendDiagnostic {
    /// Classifies this error without replacing or flattening the typed error.
    fn diagnostic_metadata(&self) -> BackendDiagnosticMetadata;
}
