// SPDX-License-Identifier: Apache-2.0

//! Typed parse, profile, policy, and command errors for [`crate::Config`].
//!
//! [`crate::ConfigError`] keeps source locations and nested model errors
//! available without requiring callers to parse display strings.

use cageforge_command::CommandError;
use cageforge_network_proxy::GatewayConfigError;
use cageforge_policy::PolicyError;
use serde::Serialize;
use std::path::PathBuf;
use thiserror::Error;

/// A byte-based location in the source TOML document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SourceLocation {
    /// One-based line number.
    pub line: usize,
    /// One-based column number.
    pub column: usize,
    /// Zero-based byte offset into the source document.
    pub offset: usize,
    /// Number of bytes covered by the parser span.
    pub length: usize,
}

/// Errors returned while parsing or resolving a Cageforge configuration.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// The TOML document could not be parsed or contained an unknown field.
    #[error("invalid TOML: {message}")]
    InvalidToml {
        /// The parser's explanation.
        message: String,
        /// The parser span, when TOML provided one.
        location: Option<SourceLocation>,
    },
    /// The configuration file could not be read.
    #[error("cannot read configuration {}: {message}", path.display())]
    ReadFile {
        /// The file that could not be read.
        path: PathBuf,
        /// The I/O error description.
        message: String,
    },
    /// A profile name is not a safe configuration identifier.
    #[error("invalid profile name: {name:?}")]
    InvalidProfileName {
        /// The invalid profile name.
        name: String,
    },
    /// A referenced profile does not exist.
    #[error("unknown profile: {name}")]
    UnknownProfile {
        /// The missing profile name.
        name: String,
    },
    /// `resolve_default` was requested without a configured default profile.
    #[error("no default profile is configured")]
    NoDefaultProfile,
    /// Profile inheritance contains a cycle.
    #[error("profile inheritance cycle: {}", chain.join(" -> "))]
    ProfileCycle {
        /// The cycle path, including the repeated profile at the end.
        chain: Vec<String>,
    },
    /// A profile field contains an invalid or incomplete value.
    #[error("profile {profile:?} has invalid {field}: {value}")]
    InvalidValue {
        /// The profile containing the value.
        profile: String,
        /// The logical field path.
        field: String,
        /// The supplied value or an explanation of what is missing.
        value: String,
    },
    /// A command profile did not provide a program after inheritance.
    #[error("profile {profile:?} command has no program")]
    MissingCommandProgram {
        /// The profile containing the incomplete command.
        profile: String,
    },
    /// The policy model rejected a resolved profile value.
    #[error("profile {profile:?} has an invalid policy: {source}")]
    Policy {
        /// The profile being resolved.
        profile: String,
        /// The policy validation error.
        #[source]
        source: PolicyError,
    },
    /// The command model rejected a resolved profile value.
    #[error("profile {profile:?} has an invalid command: {source}")]
    Command {
        /// The profile being resolved.
        profile: String,
        /// The command validation error.
        #[source]
        source: CommandError,
    },
    /// The network gateway rejected a resolved runtime setting.
    #[error("profile {profile:?} has an invalid network gateway: {source}")]
    NetworkGateway {
        /// The profile being resolved.
        profile: String,
        /// Gateway validation error.
        #[source]
        source: GatewayConfigError,
    },
}

pub(crate) fn invalid_value(profile: &str, field: &str, value: impl Into<String>) -> ConfigError {
    ConfigError::InvalidValue {
        profile: profile.to_owned(),
        field: field.to_owned(),
        value: value.into(),
    }
}
