// SPDX-License-Identifier: Apache-2.0

//! Strict TOML profile resolution for Cageforge.
//!
//! [`Config`] turns named profiles into validated [`SandboxPolicy`] and
//! optional [`CommandRequest`] values. It does not launch a process, discover
//! paths, or select a native backend.
//!
//! # Reading this crate
//!
//! Start with [`Config::from_toml`] or [`Config::from_file`], then choose
//! [`Config::resolve_default`] or [`Config::resolve`]. The resulting
//! [`ResolvedProfile`] exposes the policy, optional command, description, and
//! workspace-root declarations. Use [`ConfigDiagnostic`] for a stable
//! machine-readable error and [`config_schema_json`] for editor completion or
//! structural preflight checks.
//!
//! The resolved values belong to the model crates: [`SandboxPolicy`] comes
//! from `cageforge-policy`, while [`CommandRequest`] comes from
//! `cageforge-command`. This crate converts TOML into those values but does
//! not add process or backend behavior.

#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

mod build;
mod diagnostics;
mod error;
mod merge;
mod model;
mod resolve;
mod schema;

pub use diagnostics::{ConfigDiagnostic, DiagnosticSeverity};
pub use error::{ConfigError, SourceLocation};
pub use resolve::{Config, ResolvedProfile};
pub use schema::config_schema_json;

pub use cageforge_command::CommandRequest;
pub use cageforge_policy::SandboxPolicy;
