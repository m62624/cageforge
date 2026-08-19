// SPDX-License-Identifier: Apache-2.0

use std::ffi::{OsStr, OsString};

use crate::CommandError;

/// An executable and its argv arguments.
///
/// The program and arguments use [`OsString`] so a local harness can preserve
/// platform-native command-line values. This type does not interpret shell
/// syntax; callers that need a shell must put the shell executable and its
/// arguments in the vector explicitly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandSpec {
    program: OsString,
    args: Vec<OsString>,
}

impl CommandSpec {
    /// Creates a command with no arguments.
    pub fn new(program: impl Into<OsString>) -> Result<Self, CommandError> {
        let program = program.into();
        validate_program(&program)?;
        Ok(Self {
            program,
            args: Vec::new(),
        })
    }

    /// Adds one argv argument and returns the updated command.
    pub fn with_arg(mut self, argument: impl Into<OsString>) -> Result<Self, CommandError> {
        let argument = argument.into();
        validate_argument(&argument)?;
        self.args.push(argument);
        Ok(self)
    }

    /// Adds several argv arguments and returns the updated command.
    pub fn with_args<I, S>(mut self, arguments: I) -> Result<Self, CommandError>
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        for argument in arguments {
            let argument = argument.into();
            validate_argument(&argument)?;
            self.args.push(argument);
        }
        Ok(self)
    }

    /// Returns the executable program.
    pub fn program(&self) -> &OsStr {
        &self.program
    }

    /// Returns the arguments after the executable program.
    pub fn args(&self) -> &[OsString] {
        &self.args
    }

    /// Returns the executable and arguments as owned values.
    pub fn into_parts(self) -> (OsString, Vec<OsString>) {
        (self.program, self.args)
    }
}

fn validate_program(program: &OsStr) -> Result<(), CommandError> {
    if program.is_empty() {
        return Err(CommandError::EmptyProgram);
    }
    if contains_nul(program) {
        return Err(CommandError::ProgramContainsNul);
    }
    Ok(())
}

fn validate_argument(argument: &OsStr) -> Result<(), CommandError> {
    if contains_nul(argument) {
        return Err(CommandError::ArgumentContainsNul);
    }
    Ok(())
}

pub(crate) fn contains_nul(value: &OsStr) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        value.as_bytes().contains(&0)
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        value.encode_wide().any(|unit| unit == 0)
    }
    #[cfg(not(any(unix, windows)))]
    {
        value.to_string_lossy().contains('\0')
    }
}
