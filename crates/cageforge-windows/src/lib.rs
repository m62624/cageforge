// SPDX-License-Identifier: Apache-2.0

//! Windows-native Cageforge execution backend.
//!
//! This first layer exposes versioned provisioning configuration and strict
//! read-back of dedicated Windows identities. The backend execution type is
//! exposed only together with its complete native token, process, filesystem,
//! and network enforcement path, so a partial implementation cannot advertise
//! capabilities it does not yet enforce.

#![cfg(target_os = "windows")]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

mod config;
mod error;
mod setup;
mod win;

pub use config::{
    SetupHelperSource, WindowsBackendConfig, WindowsBackendConfigError, WindowsSetupConfig,
    WindowsStateDirectorySource,
};
pub use error::{
    WindowsAccountLookupError, WindowsAccountVerificationError, WindowsBackendError,
    WindowsFilesystemShapeError, WindowsNetworkCombinationError, WindowsSetupError,
};
pub use setup::{
    WindowsSandboxAccounts, WindowsSetup, WindowsSetupDetails, WindowsSetupStaleReason,
    WindowsSetupStatus,
};
