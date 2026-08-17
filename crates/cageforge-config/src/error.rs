// Copyright 2026 Mansur Azatbek
// SPDX-License-Identifier: Apache-2.0

use cageforge_command::CommandError;
use cageforge_policy::PolicyError;
use std::error::Error;
use std::fmt;
use std::path::PathBuf;

/// Errors returned while parsing or resolving a Cageforge configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// The TOML document could not be parsed or contained an unknown field.
    InvalidToml {
        /// The parser's explanation.
        message: String,
    },
    /// The configuration file could not be read.
    ReadFile {
        /// The file that could not be read.
        path: PathBuf,
        /// The I/O error description.
        message: String,
    },
    /// A profile name is not a safe configuration identifier.
    InvalidProfileName {
        /// The invalid profile name.
        name: String,
    },
    /// A referenced profile does not exist.
    UnknownProfile {
        /// The missing profile name.
        name: String,
    },
    /// `resolve_default` was requested without a configured default profile.
    NoDefaultProfile,
    /// Profile inheritance contains a cycle.
    ProfileCycle {
        /// The cycle path, including the repeated profile at the end.
        chain: Vec<String>,
    },
    /// A profile field contains an invalid or incomplete value.
    InvalidValue {
        /// The profile containing the value.
        profile: String,
        /// The logical field path.
        field: String,
        /// The supplied value or an explanation of what is missing.
        value: String,
    },
    /// A command profile did not provide a program after inheritance.
    MissingCommandProgram {
        /// The profile containing the incomplete command.
        profile: String,
    },
    /// The policy model rejected a resolved profile value.
    Policy {
        /// The profile being resolved.
        profile: String,
        /// The policy validation error.
        source: PolicyError,
    },
    /// The command model rejected a resolved profile value.
    Command {
        /// The profile being resolved.
        profile: String,
        /// The command validation error.
        source: CommandError,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidToml { message } => write!(formatter, "invalid TOML: {message}"),
            Self::ReadFile { path, message } => {
                write!(
                    formatter,
                    "cannot read configuration {}: {message}",
                    path.display()
                )
            }
            Self::InvalidProfileName { name } => {
                write!(formatter, "invalid profile name: {name:?}")
            }
            Self::UnknownProfile { name } => write!(formatter, "unknown profile: {name}"),
            Self::NoDefaultProfile => formatter.write_str("no default profile is configured"),
            Self::ProfileCycle { chain } => {
                write!(
                    formatter,
                    "profile inheritance cycle: {}",
                    chain.join(" -> ")
                )
            }
            Self::InvalidValue {
                profile,
                field,
                value,
            } => write!(
                formatter,
                "profile {profile:?} has invalid {field}: {value}"
            ),
            Self::MissingCommandProgram { profile } => {
                write!(formatter, "profile {profile:?} command has no program")
            }
            Self::Policy { profile, source } => {
                write!(
                    formatter,
                    "profile {profile:?} has an invalid policy: {source}"
                )
            }
            Self::Command { profile, source } => {
                write!(
                    formatter,
                    "profile {profile:?} has an invalid command: {source}"
                )
            }
        }
    }
}

impl Error for ConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Policy { source, .. } => Some(source),
            Self::Command { source, .. } => Some(source),
            _ => None,
        }
    }
}

pub(crate) fn invalid_value(profile: &str, field: &str, value: impl Into<String>) -> ConfigError {
    ConfigError::InvalidValue {
        profile: profile.to_owned(),
        field: field.to_owned(),
        value: value.into(),
    }
}
