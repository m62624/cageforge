// Copyright 2026 Mansur Azatbek
// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use std::fmt;

/// Errors raised while constructing a portable command request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandError {
    /// The command program was empty.
    EmptyProgram,
    /// The command program contained a NUL character.
    ProgramContainsNul,
    /// The working-directory path was empty.
    EmptyWorkingDirectory,
    /// An environment variable name was empty.
    EmptyEnvironmentName,
    /// An environment variable name contained `=`.
    EnvironmentNameContainsEquals,
    /// An environment variable name contained a NUL character.
    EnvironmentNameContainsNul,
    /// An environment variable value contained a NUL character.
    EnvironmentValueContainsNul,
}

impl fmt::Display for CommandError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::EmptyProgram => "command program must not be empty",
            Self::ProgramContainsNul => "command program must not contain a NUL character",
            Self::EmptyWorkingDirectory => "working directory must not be empty",
            Self::EmptyEnvironmentName => "environment variable name must not be empty",
            Self::EnvironmentNameContainsEquals => "environment variable name must not contain '='",
            Self::EnvironmentNameContainsNul => {
                "environment variable name must not contain a NUL character"
            }
            Self::EnvironmentValueContainsNul => {
                "environment variable value must not contain a NUL character"
            }
        };
        formatter.write_str(message)
    }
}

impl Error for CommandError {}
