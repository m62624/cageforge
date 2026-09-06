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

pub use backend::MacosBackend;
pub use config::{MacosBackendConfig, MacosBackendConfigError};
pub use error::{MacosBackendError, MacosFilesystemError, MacosNetworkError, SeatbeltProfileError};
pub use process::MacosChild;
