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

mod backend;
mod bwrap;
mod config;
mod error;
mod process;

pub use backend::LinuxBackend;
pub use config::{BubblewrapSource, HardeningHelperSource, LinuxBackendConfig, ProcMountPolicy};
pub use error::LinuxBackendError;
pub use process::LinuxChild;
