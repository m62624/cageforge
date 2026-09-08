// SPDX-License-Identifier: Apache-2.0

//! macOS-native Cageforge execution backend.
//!
//! The backend lowers Cageforge's portable command and effective-policy
//! models into an OS-enforced Seatbelt process boundary. Each spawn is an
//! independent boundary for one command tree; the backend object can be
//! reused by concurrent callers.

#![cfg(target_os = "macos")]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

mod backend;
mod config;
mod error;
mod filesystem;
mod network;
mod process;
mod seatbelt;

#[cfg(test)]
mod seatbelt_tests;

pub use backend::MacosBackend;
pub use config::{MacosBackendConfig, MacosBackendConfigError};
pub use error::{MacosBackendError, MacosFilesystemError, MacosNetworkError, SeatbeltProfileError};
pub use process::MacosChild;
pub use process::coalition::CoalitionError as MacosCoalitionError;
pub use process::launchd::{
    LaunchError as MacosHelperError, MACOS_HELPER_ARGUMENT, Operation as MacosHelperOperation,
    helper_entry as run_macos_helper,
};
pub use process::protocol::{ProtocolError as MacosHelperProtocolError, Stage as MacosHelperStage};
pub use process::transport::{
    FieldError as MacosHelperFieldError, FieldKind as MacosHelperFieldKind,
};
