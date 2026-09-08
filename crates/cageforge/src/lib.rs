// SPDX-License-Identifier: Apache-2.0

//! Unified ergonomic facade for Cageforge sandbox execution.
//!
//! [`Sandbox`] is the common execution contract implemented by the native
//! Linux, Windows, and macOS backends. The portable command, policy,
//! composition, path, and backend-contract types are re-exported here so an
//! application can depend on one crate while choosing only the native backend
//! it needs through a Cargo feature.
//!
//! A backend is reusable, but each [`Sandbox::spawn`] call creates one
//! independent operating-system boundary around one command and its complete
//! descendant process tree. The public facade is synchronous; internal
//! gateways may use asynchronous tasks without imposing an async runtime on
//! the caller.

#![doc = include_str!("../README.md")]
#![deny(unsafe_code)]
#![deny(missing_docs)]

mod native;

#[cfg(any(
    all(feature = "linux", target_os = "linux"),
    all(feature = "windows", target_os = "windows"),
    all(feature = "macos", target_os = "macos")
))]
pub use native::{NativeSandboxConfig, native_sandbox_with};
pub use native::{NativeSandboxError, native_sandbox};

pub use cageforge_backend_api::*;
pub use cageforge_command::*;
pub use cageforge_network_proxy::{GatewayConfig, GatewayConfigError};
#[cfg(feature = "network-runtime")]
pub use cageforge_network_proxy::{
    GatewayError, GatewayIngressKey, NetworkGateway, NetworkResolver, SystemResolver,
    UnsupportedNetworkRequirement,
};
pub use cageforge_path::*;
pub use cageforge_policy::*;
pub use cageforge_policy_compose::*;

#[cfg(feature = "config")]
pub use cageforge_config::*;

#[cfg(all(feature = "linux", target_os = "linux"))]
pub use cageforge_linux::*;

#[cfg(all(feature = "windows", target_os = "windows"))]
pub use cageforge_windows::*;

#[cfg(all(feature = "macos", target_os = "macos"))]
pub use cageforge_macos::*;
