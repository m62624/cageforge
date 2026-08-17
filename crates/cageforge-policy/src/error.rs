// Copyright 2026 Mansur Azatbek
// SPDX-License-Identifier: Apache-2.0

use std::fmt;
use std::path::PathBuf;

/// Errors returned when a policy value cannot represent a safe request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    /// A path argument was empty.
    EmptyPath,
    /// A path that must be absolute was relative.
    ExpectedAbsolute {
        /// The path that was supplied by the caller.
        path: PathBuf,
    },
    /// A path that must be workspace-relative was absolute.
    ExpectedRelative {
        /// The path that was supplied by the caller.
        path: PathBuf,
    },
    /// A workspace-relative path attempts to escape its root.
    ParentTraversal {
        /// The workspace-relative path that attempted to escape its root.
        path: PathBuf,
    },
    /// A domain pattern is empty or malformed.
    InvalidDomainPattern {
        /// The domain pattern that failed validation.
        pattern: String,
    },
    /// A filesystem glob is empty or malformed.
    InvalidGlobPattern {
        /// The glob pattern that failed validation.
        pattern: String,
        /// The reason the pattern is invalid.
        reason: String,
    },
    /// A path resolution context contains an invalid value.
    InvalidContext {
        /// A human-readable explanation of the invalid context.
        message: String,
    },
    /// A policy rule is internally inconsistent.
    InvalidRule {
        /// A human-readable explanation of the inconsistent rule.
        message: String,
    },
}

impl fmt::Display for PolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPath => formatter.write_str("path cannot be empty"),
            Self::ExpectedAbsolute { path } => {
                write!(formatter, "path must be absolute: {}", path.display())
            }
            Self::ExpectedRelative { path } => {
                write!(
                    formatter,
                    "path must be workspace-relative: {}",
                    path.display()
                )
            }
            Self::ParentTraversal { path } => write!(
                formatter,
                "workspace-relative path cannot contain parent traversal: {}",
                path.display()
            ),
            Self::InvalidDomainPattern { pattern } => {
                write!(formatter, "invalid domain pattern: {pattern}")
            }
            Self::InvalidGlobPattern { pattern, reason } => {
                write!(formatter, "invalid glob pattern {pattern:?}: {reason}")
            }
            Self::InvalidContext { message } => formatter.write_str(message),
            Self::InvalidRule { message } => formatter.write_str(message),
        }
    }
}

impl std::error::Error for PolicyError {}
