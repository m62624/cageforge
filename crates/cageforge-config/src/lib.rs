// Copyright 2026 Mansur Azatbek
// SPDX-License-Identifier: Apache-2.0

//! Strict TOML profile resolution for Cageforge.
//!
//! [`Config`] turns named profiles into validated [`SandboxPolicy`] and
//! optional [`CommandRequest`] values. It does not launch a process, discover
//! paths, or select a native backend.

#![deny(missing_docs)]

mod build;
mod error;
mod model;
mod resolve;

pub use error::ConfigError;
pub use resolve::{Config, ResolvedProfile};

pub use cageforge_command::CommandRequest;
pub use cageforge_policy::SandboxPolicy;
