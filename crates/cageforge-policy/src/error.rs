// Copyright 2026 Mansur Azatbek
// SPDX-License-Identifier: Apache-2.0

use crate::AccessMode;
use std::path::PathBuf;
use thiserror::Error;

/// Errors returned when a policy value cannot represent a safe request.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PolicyError {
    /// A path argument was empty.
    #[error("path cannot be empty")]
    EmptyPath,
    /// A path that must be absolute was relative.
    #[error("path must be absolute: {}", path.display())]
    ExpectedAbsolute {
        /// The path that was supplied by the caller.
        path: PathBuf,
    },
    /// A path that must be workspace-relative was absolute.
    #[error("path must be workspace-relative: {}", path.display())]
    ExpectedRelative {
        /// The path that was supplied by the caller.
        path: PathBuf,
    },
    /// A path contained a NUL character that an operating-system backend cannot use.
    #[error("path must not contain a NUL character: {}", path.display())]
    PathContainsNul {
        /// The path that was supplied by the caller.
        path: PathBuf,
    },
    /// A workspace-relative path attempts to escape its root.
    #[error(
        "workspace-relative path cannot contain parent traversal: {}",
        path.display()
    )]
    ParentTraversal {
        /// The workspace-relative path that attempted to escape its root.
        path: PathBuf,
    },
    /// A domain pattern is empty or malformed.
    #[error("invalid domain pattern: {pattern}")]
    InvalidDomainPattern {
        /// The domain pattern that failed validation.
        pattern: String,
    },
    /// A filesystem glob is empty or malformed.
    #[error("invalid glob pattern {pattern:?}: {reason}")]
    InvalidGlobPattern {
        /// The glob pattern that failed validation.
        pattern: String,
        /// The reason the pattern is invalid.
        reason: String,
    },
    /// A glob requested an access mode that is not portable across backends.
    #[error("filesystem glob rules support only deny access; requested {access:?}")]
    UnsupportedGlobAccess {
        /// The access mode requested for the glob.
        access: AccessMode,
    },
    /// A protected relative path is empty or unsafe.
    #[error("invalid protected relative path {path:?}: {reason}")]
    InvalidProtectedPath {
        /// The protected path that failed validation.
        path: PathBuf,
        /// The reason the path is invalid.
        reason: String,
    },
    /// A path resolution context contains an invalid value.
    #[error("{message}")]
    InvalidContext {
        /// A human-readable explanation of the invalid context.
        message: String,
    },
    /// A policy rule is internally inconsistent.
    #[error("{message}")]
    InvalidRule {
        /// A human-readable explanation of the inconsistent rule.
        message: String,
    },
}
