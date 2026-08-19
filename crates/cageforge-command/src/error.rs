// SPDX-License-Identifier: Apache-2.0

//! Typed construction errors shared by [`crate::CommandSpec`],
//! [`crate::EnvironmentSpec`], and [`crate::CommandRequest`].

use std::path::PathBuf;
use thiserror::Error;

/// Errors raised while constructing a portable command request.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CommandError {
    /// The command program was empty.
    #[error("command program must not be empty")]
    EmptyProgram,
    /// The command program contained a NUL character.
    #[error("command program must not contain a NUL character")]
    ProgramContainsNul,
    /// A command argument contained a NUL character.
    #[error("command argument must not contain a NUL character")]
    ArgumentContainsNul,
    /// The working-directory path was empty.
    #[error("working directory must not be empty")]
    EmptyWorkingDirectory,
    /// The working-directory path contained a NUL character.
    #[error("working directory must not contain a NUL character")]
    WorkingDirectoryContainsNul,
    /// The working-directory path contained a parent traversal component.
    #[error(
        "working directory must not contain parent traversal: {}",
        path.display()
    )]
    WorkingDirectoryParentTraversal {
        /// The working-directory path that attempted parent traversal.
        path: PathBuf,
    },
    /// An environment variable name was empty.
    #[error("environment variable name must not be empty")]
    EmptyEnvironmentName,
    /// An environment variable name contained `=`.
    #[error("environment variable name must not contain '='")]
    EnvironmentNameContainsEquals,
    /// An environment variable name contained a NUL character.
    #[error("environment variable name must not contain a NUL character")]
    EnvironmentNameContainsNul,
    /// An environment variable value contained a NUL character.
    #[error("environment variable value must not contain a NUL character")]
    EnvironmentValueContainsNul,
    /// An environment-variable filter pattern was empty.
    #[error("environment variable pattern must not be empty")]
    EmptyEnvironmentPattern,
    /// An environment-variable filter pattern contained a NUL character.
    #[error("environment variable pattern must not contain a NUL character")]
    EnvironmentPatternContainsNul,
    /// An environment-variable filter pattern contained `=`.
    #[error("environment variable pattern must not contain '='")]
    EnvironmentPatternContainsEquals,
}
