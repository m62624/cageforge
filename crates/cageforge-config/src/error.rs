// SPDX-License-Identifier: Apache-2.0

//! Typed parse, profile, policy, and command errors for [`crate::Config`].
//!
//! [`crate::ConfigError`] keeps source locations and nested model errors
//! available without requiring callers to parse display strings.

use cageforge_command::CommandError;
use cageforge_network_proxy::GatewayConfigError;
use cageforge_permissions::PlatformId;
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

/// Context attached to a configuration failure after the source document has
/// been identified. The context is diagnostic metadata; it never changes the
/// policy value that failed validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConfigErrorContext {
    /// The TOML file, when the document came from a file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_path: Option<PathBuf>,
    /// The platform overlay being resolved, when one was selected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<PlatformId>,
    /// The source span for the logical field, when it can be located.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<SourceLocation>,
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
        /// File and platform context for this diagnostic.
        context: Option<Box<ConfigErrorContext>>,
    },
    /// The configuration file could not be read.
    #[error("cannot read configuration {}: {message}", path.display())]
    ReadFile {
        /// The file that could not be read.
        path: PathBuf,
        /// The I/O error description.
        message: String,
        /// File and platform context for this diagnostic.
        context: Option<Box<ConfigErrorContext>>,
    },
    /// A profile name is not a safe configuration identifier.
    #[error("invalid profile name: {name:?}")]
    InvalidProfileName {
        /// The invalid profile name.
        name: String,
        /// File and platform context for this diagnostic.
        context: Option<Box<ConfigErrorContext>>,
    },
    /// A referenced profile does not exist.
    #[error("unknown profile: {name}")]
    UnknownProfile {
        /// The missing profile name.
        name: String,
        /// File and platform context for this diagnostic.
        context: Option<Box<ConfigErrorContext>>,
    },
    /// `resolve_default` was requested without a configured default profile.
    #[error("no default profile is configured")]
    NoDefaultProfile {
        /// File and platform context for this diagnostic.
        context: Option<Box<ConfigErrorContext>>,
    },
    /// The iterative inheritance resolver reached an impossible internal
    /// state. This is returned instead of panicking so callers still receive
    /// a typed configuration failure if the resolver is changed incorrectly.
    #[error("configuration profile resolution invariant failed: {message}")]
    ResolutionInvariant {
        /// Stable explanation of the violated resolver invariant.
        message: &'static str,
        /// File and platform context for this diagnostic.
        context: Option<Box<ConfigErrorContext>>,
    },
    /// Profile inheritance contains a cycle.
    #[error("profile inheritance cycle: {}", chain.join(" -> "))]
    ProfileCycle {
        /// The cycle path, including the repeated profile at the end.
        chain: Vec<String>,
        /// File and platform context for this diagnostic.
        context: Option<Box<ConfigErrorContext>>,
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
        /// File and platform context for this diagnostic.
        context: Option<Box<ConfigErrorContext>>,
    },
    /// A command profile did not provide a program after inheritance.
    #[error("profile {profile:?} command has no program")]
    MissingCommandProgram {
        /// The profile containing the incomplete command.
        profile: String,
        /// File and platform context for this diagnostic.
        context: Option<Box<ConfigErrorContext>>,
    },
    /// The policy model rejected a resolved profile value.
    #[error("profile {profile:?} has an invalid policy: {source}")]
    Policy {
        /// The profile being resolved.
        profile: String,
        /// The policy validation error.
        #[source]
        source: PolicyError,
        /// File and platform context for this diagnostic.
        context: Option<Box<ConfigErrorContext>>,
    },
    /// The command model rejected a resolved profile value.
    #[error("profile {profile:?} has an invalid command: {source}")]
    Command {
        /// The profile being resolved.
        profile: String,
        /// The command validation error.
        #[source]
        source: CommandError,
        /// File and platform context for this diagnostic.
        context: Option<Box<ConfigErrorContext>>,
    },
    /// The network gateway rejected a resolved runtime setting.
    #[error("profile {profile:?} has an invalid network gateway: {source}")]
    NetworkGateway {
        /// The profile being resolved.
        profile: String,
        /// Gateway validation error.
        #[source]
        source: GatewayConfigError,
        /// File and platform context for this diagnostic.
        context: Option<Box<ConfigErrorContext>>,
    },
}

impl ConfigError {
    pub(crate) fn profile_field(&self) -> (Option<&str>, Option<&str>) {
        match self {
            Self::InvalidToml { .. } | Self::ReadFile { .. } => (None, None),
            Self::InvalidProfileName { name, .. } => (Some(name), None),
            Self::UnknownProfile { name, .. } => (Some(name), None),
            Self::NoDefaultProfile { .. } => (None, None),
            Self::ResolutionInvariant { .. } => (None, None),
            Self::ProfileCycle { chain, .. } => {
                (chain.first().map(String::as_str), Some("inherits"))
            }
            Self::InvalidValue { profile, field, .. } => (Some(profile), Some(field)),
            Self::MissingCommandProgram { profile, .. } => (Some(profile), Some("command.program")),
            Self::Policy { profile, .. } => (Some(profile), Some("filesystem")),
            Self::Command { profile, .. } => (Some(profile), Some("command")),
            Self::NetworkGateway { profile, .. } => (Some(profile), Some("network.gateway")),
        }
    }

    /// Adds source-file and selected-platform metadata without changing the
    /// typed error category or its nested source.
    pub fn with_context(self, context: ConfigErrorContext) -> Self {
        fn merge(
            existing: Option<Box<ConfigErrorContext>>,
            incoming: ConfigErrorContext,
        ) -> Option<Box<ConfigErrorContext>> {
            let mut result = existing.map(|value| *value).unwrap_or(ConfigErrorContext {
                config_path: None,
                platform: None,
                location: None,
            });
            if incoming.config_path.is_some() {
                result.config_path = incoming.config_path;
            }
            if incoming.platform.is_some() {
                result.platform = incoming.platform;
            }
            if incoming.location.is_some() {
                result.location = incoming.location;
            }
            (result.config_path.is_some() || result.platform.is_some() || result.location.is_some())
                .then(|| Box::new(result))
        }

        match self {
            Self::InvalidToml {
                message,
                location,
                context: existing,
            } => Self::InvalidToml {
                message,
                location,
                context: merge(existing, context),
            },
            Self::ReadFile {
                path,
                message,
                context: existing,
            } => Self::ReadFile {
                path,
                message,
                context: merge(existing, context),
            },
            Self::InvalidProfileName {
                name,
                context: existing,
            } => Self::InvalidProfileName {
                name,
                context: merge(existing, context),
            },
            Self::UnknownProfile {
                name,
                context: existing,
            } => Self::UnknownProfile {
                name,
                context: merge(existing, context),
            },
            Self::NoDefaultProfile { context: existing } => Self::NoDefaultProfile {
                context: merge(existing, context),
            },
            Self::ResolutionInvariant {
                message,
                context: existing,
            } => Self::ResolutionInvariant {
                message,
                context: merge(existing, context),
            },
            Self::ProfileCycle {
                chain,
                context: existing,
            } => Self::ProfileCycle {
                chain,
                context: merge(existing, context),
            },
            Self::InvalidValue {
                profile,
                field,
                value,
                context: existing,
            } => Self::InvalidValue {
                profile,
                field,
                value,
                context: merge(existing, context),
            },
            Self::MissingCommandProgram {
                profile,
                context: existing,
            } => Self::MissingCommandProgram {
                profile,
                context: merge(existing, context),
            },
            Self::Policy {
                profile,
                source,
                context: existing,
            } => Self::Policy {
                profile,
                source,
                context: merge(existing, context),
            },
            Self::Command {
                profile,
                source,
                context: existing,
            } => Self::Command {
                profile,
                source,
                context: merge(existing, context),
            },
            Self::NetworkGateway {
                profile,
                source,
                context: existing,
            } => Self::NetworkGateway {
                profile,
                source,
                context: merge(existing, context),
            },
        }
    }

    /// Returns the attached diagnostic context, if the error was produced by
    /// a source-aware configuration entry point.
    pub fn context(&self) -> Option<&ConfigErrorContext> {
        match self {
            Self::InvalidToml { context, .. }
            | Self::ReadFile { context, .. }
            | Self::InvalidProfileName { context, .. }
            | Self::UnknownProfile { context, .. }
            | Self::NoDefaultProfile { context }
            | Self::ResolutionInvariant { context, .. }
            | Self::ProfileCycle { context, .. }
            | Self::InvalidValue { context, .. }
            | Self::MissingCommandProgram { context, .. }
            | Self::Policy { context, .. }
            | Self::Command { context, .. }
            | Self::NetworkGateway { context, .. } => context.as_deref(),
        }
    }
}

pub(crate) fn invalid_value(profile: &str, field: &str, value: impl Into<String>) -> ConfigError {
    ConfigError::InvalidValue {
        profile: profile.to_owned(),
        field: field.to_owned(),
        value: value.into(),
        context: None,
    }
}
