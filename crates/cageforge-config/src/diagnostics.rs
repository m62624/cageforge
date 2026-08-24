// SPDX-License-Identifier: Apache-2.0

//! Stable diagnostic values for presenting [`crate::ConfigError`] to tools.
//!
//! The diagnostic shape is intended for editors, CLIs, and JSON-producing
//! integrations; typed [`crate::ConfigError`] remains the primary Rust error.

use crate::{ConfigError, SourceLocation};
use serde::Serialize;

/// Severity of a configuration diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticSeverity {
    /// The configuration cannot be safely used.
    Error,
}

/// A stable, machine-readable description of a configuration problem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConfigDiagnostic {
    code: &'static str,
    severity: DiagnosticSeverity,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    profile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    field: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    location: Option<SourceLocation>,
}

impl ConfigDiagnostic {
    /// Returns the stable diagnostic code.
    pub fn code(&self) -> &str {
        self.code
    }

    /// Returns the diagnostic severity.
    pub fn severity(&self) -> DiagnosticSeverity {
        self.severity
    }

    /// Returns the human-readable message.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Returns the affected profile, when the error belongs to one profile.
    pub fn profile(&self) -> Option<&str> {
        self.profile.as_deref()
    }

    /// Returns the logical configuration field, when one is known.
    pub fn field(&self) -> Option<&str> {
        self.field.as_deref()
    }

    /// Returns the source location, when the parser supplied one.
    pub fn location(&self) -> Option<SourceLocation> {
        self.location
    }

    /// Serializes this diagnostic as a JSON object.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

impl ConfigError {
    /// Converts this typed error into a stable diagnostic for UIs, CLIs, or
    /// structured application logs.
    pub fn diagnostic(&self) -> ConfigDiagnostic {
        let (code, profile, field, location) = match self {
            Self::InvalidToml { location, .. } => ("invalid_toml", None, None, *location),
            Self::ReadFile { .. } => ("config_file_unreadable", None, None, None),
            Self::InvalidProfileName { .. } => ("invalid_profile_name", None, None, None),
            Self::UnknownProfile { .. } => ("unknown_profile", None, None, None),
            Self::NoDefaultProfile => ("missing_default_profile", None, None, None),
            Self::ResolutionInvariant { .. } => ("profile_resolution_invariant", None, None, None),
            Self::ProfileCycle { .. } => ("profile_inheritance_cycle", None, None, None),
            Self::InvalidValue { profile, field, .. } => (
                "invalid_value",
                Some(profile.clone()),
                Some(field.clone()),
                None,
            ),
            Self::MissingCommandProgram { profile } => {
                ("missing_command_program", Some(profile.clone()), None, None)
            }
            Self::Policy { profile, .. } => ("invalid_policy", Some(profile.clone()), None, None),
            Self::Command { profile, .. } => ("invalid_command", Some(profile.clone()), None, None),
            Self::NetworkGateway { profile, .. } => (
                "invalid_network_gateway",
                Some(profile.clone()),
                Some("network.gateway".to_owned()),
                None,
            ),
        };
        ConfigDiagnostic {
            code,
            severity: DiagnosticSeverity::Error,
            message: self.to_string(),
            profile,
            field,
            location,
        }
    }
}
