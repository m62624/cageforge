// SPDX-License-Identifier: Apache-2.0

//! Construction of the host backend behind the common execution interface.

use std::error::Error;

use crate::DynSandbox;

/// Stable source-field metadata for a native launch failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeDiagnosticMetadata {
    code: &'static str,
    field: Option<&'static str>,
}

impl NativeDiagnosticMetadata {
    /// Returns the stable native diagnostic code.
    pub const fn code(self) -> &'static str {
        self.code
    }

    /// Returns the logical configuration field associated with the failure.
    pub const fn field(self) -> Option<&'static str> {
        self.field
    }
}

/// Configuration of the backend selected for the compilation target.
#[cfg(target_os = "linux")]
pub use cageforge_linux::LinuxBackendConfig as NativeSandboxConfig;
/// Configuration of the backend selected for the compilation target.
#[cfg(target_os = "macos")]
pub use cageforge_macos::MacosBackendConfig as NativeSandboxConfig;
/// Configuration of the backend selected for the compilation target.
#[cfg(target_os = "windows")]
pub use cageforge_windows::WindowsBackendConfig as NativeSandboxConfig;

/// Failure to construct the native backend selected for this host.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NativeSandboxError {
    /// Cageforge has no native backend for this operating system.
    #[error("no native Cageforge backend is available for {target_os}")]
    UnsupportedPlatform {
        /// The target operating system.
        target_os: &'static str,
    },
    /// Native configuration, resource discovery, or setup verification failed.
    #[error("native sandbox initialization failed: {source}")]
    Initialization {
        /// The original backend error, available for downcasting.
        source: Box<dyn Error + Send + Sync>,
    },
}

/// Classifies a typed native failure for source-aware adapters.
///
/// This function only selects stable presentation metadata. The original
/// error remains the typed source error and must be retained by the caller.
pub fn native_diagnostic_metadata(error: &(dyn Error + 'static)) -> NativeDiagnosticMetadata {
    #[cfg(target_os = "macos")]
    {
        if let Some(native) = find_error::<cageforge_macos::MacosFilesystemError>(error) {
            return match native {
                cageforge_macos::MacosFilesystemError::ProgramRequiresRead { .. } => {
                    NativeDiagnosticMetadata {
                        code: "macos_program_requires_read",
                        field: Some("command.program"),
                    }
                }
                cageforge_macos::MacosFilesystemError::ProgramRequiresExecutableRoot { .. } => {
                    NativeDiagnosticMetadata {
                        code: "macos_program_requires_executable_root",
                        field: Some("runtime.executable_roots"),
                    }
                }
                cageforge_macos::MacosFilesystemError::ExecutableRootMissing { .. }
                | cageforge_macos::MacosFilesystemError::ExecutableRootNotDirectory { .. }
                | cageforge_macos::MacosFilesystemError::ExecutableRootNotReadable { .. }
                | cageforge_macos::MacosFilesystemError::InvalidExecutableRoot { .. } => {
                    NativeDiagnosticMetadata {
                        code: "macos_invalid_executable_root",
                        field: Some("runtime.executable_roots"),
                    }
                }
                _ => NativeDiagnosticMetadata {
                    code: "macos_native_error",
                    field: None,
                },
            };
        }
        NativeDiagnosticMetadata {
            code: "macos_native_error",
            field: None,
        }
    }

    #[cfg(target_os = "linux")]
    {
        let _ = error;
        NativeDiagnosticMetadata {
            code: "linux_native_error",
            field: None,
        }
    }
    #[cfg(target_os = "windows")]
    {
        let _ = error;
        NativeDiagnosticMetadata {
            code: "windows_native_error",
            field: None,
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        let _ = error;
        NativeDiagnosticMetadata {
            code: "native_error",
            field: None,
        }
    }
}

#[cfg(target_os = "macos")]
fn find_error<'a, T: Error + 'static>(error: &'a (dyn Error + 'static)) -> Option<&'a T> {
    if let Some(value) = error.downcast_ref::<T>() {
        return Some(value);
    }
    let mut source = error.source();
    while let Some(value) = source {
        if let Some(value) = value.downcast_ref::<T>() {
            return Some(value);
        }
        source = value.source();
    }
    None
}

/// Creates the host's native backend with its default configuration.
///
/// The native backend is selected from the compilation target. Missing native
/// prerequisites return errors. On Windows, provisioning through
/// `WindowsSetup::install` is an explicit preceding step; this function only
/// verifies the existing setup. Each subsequent `launch` creates an
/// independent sandbox boundary.
pub fn native_sandbox() -> Result<Box<dyn DynSandbox>, NativeSandboxError> {
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    {
        native_sandbox_with(NativeSandboxConfig::new())
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        let target_os = std::env::consts::OS;
        Err(NativeSandboxError::UnsupportedPlatform { target_os })
    }
}

/// Creates the Linux backend using caller-supplied native configuration.
#[cfg(target_os = "linux")]
pub fn native_sandbox_with(
    config: NativeSandboxConfig,
) -> Result<Box<dyn DynSandbox>, NativeSandboxError> {
    let backend = cageforge_linux::LinuxBackend::new(config).map_err(|source| {
        NativeSandboxError::Initialization {
            source: Box::new(source),
        }
    })?;
    Ok(Box::new(backend))
}

/// Creates the Windows backend using caller-supplied native configuration.
///
/// The configuration must point to an already installed `WindowsSetup`.
#[cfg(target_os = "windows")]
pub fn native_sandbox_with(
    config: NativeSandboxConfig,
) -> Result<Box<dyn DynSandbox>, NativeSandboxError> {
    let backend = cageforge_windows::WindowsBackend::new(config).map_err(|source| {
        NativeSandboxError::Initialization {
            source: Box::new(source),
        }
    })?;
    Ok(Box::new(backend))
}

/// Creates the macOS backend using caller-supplied native configuration.
#[cfg(target_os = "macos")]
pub fn native_sandbox_with(
    config: NativeSandboxConfig,
) -> Result<Box<dyn DynSandbox>, NativeSandboxError> {
    let backend = cageforge_macos::MacosBackend::new(config).map_err(|source| {
        NativeSandboxError::Initialization {
            source: Box::new(source),
        }
    })?;
    Ok(Box::new(backend))
}
