// SPDX-License-Identifier: Apache-2.0

//! Portable command invocation intent for Cageforge backends.
//!
//! [`CommandRequest`] describes what a caller wants to execute without
//! selecting an operating-system backend or launching a process. The request
//! is deliberately separate from sandbox policy, configuration parsing, PTY
//! handling, and process lifecycle management.

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
    EnvironmentBase, EnvironmentFilterAction, EnvironmentNameKey, EnvironmentOverride,
    EnvironmentPattern, EnvironmentSpec,
};
pub use error::CommandError;
pub use request::CommandRequest;
pub use stdio::{StdioMode, StdioSpec};
pub use timeout::TimeoutPolicy;
