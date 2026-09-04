// SPDX-License-Identifier: Apache-2.0

//! Windows-native Cageforge execution backend.
//!
//! The backend exposes versioned provisioning configuration and strict
//! read-back of dedicated Windows identities together with the native token,
//! process, filesystem, and network enforcement path. It advertises only
//! capabilities that the complete Windows boundary can enforce.

#![cfg(target_os = "windows")]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

mod account_identity;
mod backend;
mod capability;
mod config;
mod error;
mod filesystem;
mod firewall_contract;
mod network;
mod owner_identity;
mod process;
mod runner;
mod setup;
mod win;

pub(crate) use setup::pinned::file as setup_pinned_file;

pub use backend::WindowsBackend;
pub use config::{
    CommandRunnerSource, SetupHelperSource, WindowsBackendConfig, WindowsBackendConfigError,
    WindowsSetupConfig, WindowsStateDirectorySource,
};
pub use error::{
    WindowsAccountLookupError, WindowsAccountVerificationError, WindowsBackendError,
    WindowsFilesystemShapeError, WindowsNetworkCombinationError, WindowsSetupError,
    WindowsSetupVerificationError,
};
pub use network::attribution::WindowsNetworkAttributionError;
pub use network::{
    WindowsNetworkGatewayError, WindowsNetworkRuntimeError, WindowsNetworkRuntimeFailure,
};
pub use process::WindowsChild;
pub use runner::protocol::{
    WindowsRunnerFailure, WindowsRunnerFailureCode, WindowsRunnerFailureStage,
    WindowsRunnerProtocolError,
};
pub use runner::stdio::WindowsStandardStreamError;
pub use setup::protocol::{
    SetupFailureCode as WindowsSetupFailureCode, SetupStage as WindowsSetupStage,
};
pub use setup::{
    WindowsSandboxAccounts, WindowsSetup, WindowsSetupDetails, WindowsSetupStaleReason,
    WindowsSetupStatus,
};
