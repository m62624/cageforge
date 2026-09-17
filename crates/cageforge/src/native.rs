// SPDX-License-Identifier: Apache-2.0

//! Construction of the host backend behind the common execution interface.

use std::error::Error;

use crate::DynSandbox;

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
