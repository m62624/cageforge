// SPDX-License-Identifier: Apache-2.0

//! Construction of the host backend behind the common execution interface.

use std::error::Error;

use crate::DynSandbox;

/// Configuration of the backend selected for the compilation target.
#[cfg(all(feature = "linux", target_os = "linux"))]
pub use cageforge_linux::LinuxBackendConfig as NativeSandboxConfig;
/// Configuration of the backend selected for the compilation target.
#[cfg(all(feature = "macos", target_os = "macos"))]
pub use cageforge_macos::MacosBackendConfig as NativeSandboxConfig;
/// Configuration of the backend selected for the compilation target.
#[cfg(all(feature = "windows", target_os = "windows"))]
pub use cageforge_windows::WindowsBackendConfig as NativeSandboxConfig;

/// Failure to construct the native backend selected for this host.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NativeSandboxError {
    /// The binary was built without the matching native backend feature.
    #[error("the {feature} feature is required for sandbox execution on {target_os}")]
    FeatureDisabled {
        /// The target operating system.
        target_os: &'static str,
        /// The Cargo feature needed on this target.
        feature: &'static str,
    },
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
/// Enable `linux`, `windows`, or `macos` for the compilation target. Missing
/// features and native prerequisites return errors. On Windows, provisioning
/// through `WindowsSetup::install` is an explicit preceding step; this function
/// only verifies the existing setup. Each subsequent `launch` creates an
/// independent sandbox boundary.
pub fn native_sandbox() -> Result<Box<dyn DynSandbox>, NativeSandboxError> {
    #[cfg(any(
        all(feature = "linux", target_os = "linux"),
        all(feature = "windows", target_os = "windows"),
        all(feature = "macos", target_os = "macos")
    ))]
    {
        native_sandbox_with(NativeSandboxConfig::new())
    }
    #[cfg(not(any(
        all(feature = "linux", target_os = "linux"),
        all(feature = "windows", target_os = "windows"),
        all(feature = "macos", target_os = "macos")
    )))]
    {
        let target_os = std::env::consts::OS;
        match target_os {
            "linux" | "windows" | "macos" => Err(NativeSandboxError::FeatureDisabled {
                target_os,
                feature: target_os,
            }),
            _ => Err(NativeSandboxError::UnsupportedPlatform { target_os }),
        }
    }
}

/// Creates the Linux backend using caller-supplied native configuration.
#[cfg(all(feature = "linux", target_os = "linux"))]
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
#[cfg(all(feature = "windows", target_os = "windows"))]
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
#[cfg(all(feature = "macos", target_os = "macos"))]
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
