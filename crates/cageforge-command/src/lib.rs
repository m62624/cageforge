// SPDX-License-Identifier: Apache-2.0

//! Portable command invocation intent for Cageforge backends.
//!
//! [`CommandRequest`] describes what a caller wants to execute without
//! selecting an operating-system backend or launching a process. The request
//! is deliberately separate from sandbox policy, configuration parsing, PTY
//! handling, and process lifecycle management.
//!
//! # Reading this crate
//!
//! Start with [`CommandRequest`], which owns the complete execution intent.
//! Its [`CommandSpec`] describes native argv values, [`EnvironmentSpec`]
//! describes the environment transformation, and [`StdioSpec`] plus
//! [`TimeoutPolicy`] describe backend-facing execution options. Construction
//! errors are reported through [`CommandError`]. The implementation keeps
//! these concerns separate so a caller can reuse the command model without
//! adopting Cageforge's policy or TOML layers.

#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

mod command;
mod environment;
mod error;
mod request;
mod stdio;
mod timeout;

pub use command::CommandSpec;
pub use environment::{
    CoreEnvironment, EnvironmentBase, EnvironmentFilterAction, EnvironmentInput,
    EnvironmentNameKey, EnvironmentOverride, EnvironmentPattern, EnvironmentSpec,
};
pub use error::CommandError;
pub use request::CommandRequest;
pub use stdio::{StdioMode, StdioSpec};
pub use timeout::TimeoutPolicy;
