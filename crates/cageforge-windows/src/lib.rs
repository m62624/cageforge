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
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

mod account_identity;
mod capability_state;
mod capability_store;
mod config;
mod error;
mod filesystem_acl;
mod filesystem_path;
mod filesystem_plan;
mod firewall_contract;
mod runner_desktop;
mod runner_launch;
mod runner_manifest;
mod runner_parent;
mod runner_pipe;
mod runner_protocol;
mod runner_resource_security;
mod runner_session;
mod setup;
mod setup_protocol;
mod setup_state;
mod setup_verification;
mod win;

pub use config::{
    CommandRunnerSource, SetupHelperSource, WindowsBackendConfig, WindowsBackendConfigError,
    WindowsSetupConfig, WindowsStateDirectorySource,
};
pub use error::{
    WindowsAccountLookupError, WindowsAccountVerificationError, WindowsBackendError,
    WindowsFilesystemShapeError, WindowsNetworkCombinationError, WindowsSetupError,
    WindowsSetupVerificationError,
};
pub use setup::{
    WindowsSandboxAccounts, WindowsSetup, WindowsSetupDetails, WindowsSetupStaleReason,
    WindowsSetupStatus,
};
pub use setup_protocol::{
    SetupFailureCode as WindowsSetupFailureCode, SetupStage as WindowsSetupStage,
};
