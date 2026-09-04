// SPDX-License-Identifier: Apache-2.0

//! Linux-native Cageforge execution backend.
//!
//! [`LinuxBackend`] is the operating-system adapter between the portable
//! Cageforge models and a Bubblewrap process boundary. Construct it only on a
//! Linux target, pass a composed [`cageforge_policy_compose::EffectiveSandbox`]
//! through [`cageforge_backend_api::BackendRequest::prepare_for`], and launch
//! the returned backend-bound request.

#![cfg(target_os = "linux")]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

mod backend;
mod bwrap;
mod config;
mod environment_transport;
mod error;
mod filesystem;
mod hardening_error;
mod helper_protocol;
mod network;
mod process;
mod resource_names;
mod setup_transport;
mod status_transport;

pub use backend::LinuxBackend;
pub use config::{
    BubblewrapSource, HardeningHelperSource, LinuxBackendConfig, LinuxBackendConfigError,
    ProcMountPolicy, ResourceDirectorySource,
};
pub use error::{
    BubblewrapFlag, EnvironmentFrameError, ExecutableSnapshotOperation, FilesystemLoweringError,
    FilesystemMetadataOperation, LinuxBackendError, LinuxBridgeError, LinuxBridgeOperation,
    LinuxExecutable, LinuxHardeningError, LinuxHardeningOperation, LinuxHelperRuntimeFailure,
    LinuxHelperRuntimeFailureKind, LinuxHelperSetupFailure, LinuxHelperSetupFailureKind,
    LinuxNamespace, NetworkCombinationError, NetworkGatewayIngressError,
    NetworkGatewayRuntimeError, NetworkGatewayRuntimeFailure, NetworkGatewaySetupError,
    NetworkGatewayTransportError, NetworkLoweringError, PolicyLoweringExpectation,
    SeccompBuildError, SetupHandshakeError, StatusFrameError,
};
pub use process::LinuxChild;
