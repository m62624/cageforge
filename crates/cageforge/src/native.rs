// SPDX-License-Identifier: Apache-2.0

//! Construction of the host backend behind the common execution interface.

use std::error::Error;

use cageforge_backend_api::{BackendDiagnostic, BackendDiagnosticMetadata};

use crate::DynSandbox;

/// Backwards-compatible facade name for the shared backend diagnostic type.
pub type NativeDiagnosticMetadata = BackendDiagnosticMetadata;

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
/// Target-specific classification remains in the selected native backend.
/// This facade function only dispatches to that backend; the original error
/// remains the typed source error and must be retained by the caller.
pub fn native_diagnostic_metadata(error: &(dyn Error + 'static)) -> NativeDiagnosticMetadata {
    #[cfg(target_os = "macos")]
    {
        find_error_source::<cageforge_macos::MacosBackendError>(error)
            .map(BackendDiagnostic::diagnostic_metadata)
            .or_else(|| {
                find_error_source::<cageforge_macos::MacosFilesystemError>(error)
                    .map(BackendDiagnostic::diagnostic_metadata)
            })
            .unwrap_or_else(|| BackendDiagnosticMetadata::new("macos_native_error", None))
    }

    #[cfg(target_os = "linux")]
    {
        find_error_source::<cageforge_linux::LinuxBackendError>(error)
            .map(BackendDiagnostic::diagnostic_metadata)
            .unwrap_or_else(|| BackendDiagnosticMetadata::new("linux_native_error", None))
    }

    #[cfg(target_os = "windows")]
    {
        find_error_source::<cageforge_windows::WindowsBackendError>(error)
            .map(BackendDiagnostic::diagnostic_metadata)
            .unwrap_or_else(|| BackendDiagnosticMetadata::new("windows_native_error", None))
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        let _ = error;
        BackendDiagnosticMetadata::new("native_error", None)
    }
}

/// Builds the common source-aware diagnostic for a native launch failure.
///
/// The selected backend supplies the stable code and logical field through
/// [`BackendDiagnostic`]. The configuration layer supplies the profile,
/// platform, TOML path, and source location. The original error remains the
/// caller's typed source error; this helper only combines presentation
/// metadata for an application using the `config` feature.
#[cfg(feature = "config")]
pub fn config_diagnostic_for_runtime_failure(
    source: &cageforge_config::ProfileSourceContext,
    command: Option<&str>,
    error: &(dyn Error + 'static),
) -> cageforge_config::ConfigDiagnostic {
    let source = command.map_or_else(
        || source.clone(),
        |command| source.clone().with_command(command.to_owned()),
    );
    let metadata = native_diagnostic_metadata(error);
    cageforge_config::ConfigDiagnostic::for_runtime_failure(
        &source,
        metadata.code(),
        error.to_string(),
        metadata.field(),
    )
}

fn find_error_source<'a, T: Error + 'static>(error: &'a (dyn Error + 'static)) -> Option<&'a T> {
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
