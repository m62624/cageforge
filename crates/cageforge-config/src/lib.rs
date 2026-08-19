// SPDX-License-Identifier: Apache-2.0

//! Strict TOML profile resolution for Cageforge.
//!
//! [`Config`] turns named profiles into validated [`SandboxPolicy`] and
//! optional [`CommandRequest`] values. It does not launch a process, discover
//! paths, or select a native backend.

#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

mod build;
mod diagnostics;
mod error;
mod model;
mod resolve;
mod schema;

pub use diagnostics::{ConfigDiagnostic, DiagnosticSeverity};
pub use error::{ConfigError, SourceLocation};
pub use resolve::{Config, ResolvedProfile};
pub use schema::config_schema_json;

pub use cageforge_command::CommandRequest;
pub use cageforge_policy::SandboxPolicy;
