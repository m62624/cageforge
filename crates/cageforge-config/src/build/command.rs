// SPDX-License-Identifier: Apache-2.0

//! Converts the TOML command section into [`cageforge_command::CommandRequest`].

use super::super::error::{ConfigError, invalid_value};
use super::super::model::{
    RawCommand, RawEnvironment, RawEnvironmentBase, RawEnvironmentFilterAction, RawStdio,
    RawStdioMode, RawTimeout, RawTimeoutMode,
};
use cageforge_command::{
    CommandRequest, CommandSpec, EnvironmentFilterAction, EnvironmentSpec, StdioMode, StdioSpec,
    TimeoutPolicy,
};
use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;

pub(crate) fn build_command(
    raw: Option<&RawCommand>,
    profile: &str,
) -> Result<Option<CommandRequest>, ConfigError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let program = raw
        .program
        .as_deref()
        .ok_or_else(|| ConfigError::MissingCommandProgram {
            profile: profile.to_owned(),
        })?;
    let mut command = CommandSpec::new(program).map_err(|source| ConfigError::Command {
        profile: profile.to_owned(),
        source,
    })?;
    if let Some(args) = &raw.args {
        command = command
            .with_args(args.iter().map(OsString::from))
            .map_err(|source| ConfigError::Command {
                profile: profile.to_owned(),
                source,
            })?;
    }
    let mut request = CommandRequest::new(command);
    if let Some(working_directory) = &raw.working_directory {
        request = request
            .with_working_directory(PathBuf::from(working_directory))
            .map_err(|source| ConfigError::Command {
                profile: profile.to_owned(),
                source,
            })?;
    }
    if let Some(environment) = &raw.environment {
        request = request.with_environment(build_environment(environment, profile)?);
    }
    if let Some(stdio) = &raw.stdio {
        request = request.with_stdio(build_stdio(stdio));
    }
    if let Some(timeout) = &raw.timeout {
        request = request.with_timeout_policy(build_timeout(timeout, profile)?);
    }
    Ok(Some(request))
}

fn build_environment(raw: &RawEnvironment, profile: &str) -> Result<EnvironmentSpec, ConfigError> {
    let mut environment = match raw.inherit.unwrap_or(RawEnvironmentBase::Core) {
        RawEnvironmentBase::All => EnvironmentSpec::inherit_all(),
        RawEnvironmentBase::Core => EnvironmentSpec::inherit_core(),
        RawEnvironmentBase::None => EnvironmentSpec::empty(),
    };
    for (pattern, action) in &raw.filters {
        let action = match action {
            RawEnvironmentFilterAction::Include => EnvironmentFilterAction::Include,
            RawEnvironmentFilterAction::Exclude => EnvironmentFilterAction::Exclude,
        };
        environment =
            environment
                .with_filter(pattern, action)
                .map_err(|source| ConfigError::Command {
                    profile: profile.to_owned(),
                    source,
                })?;
    }
    for (name, value) in &raw.set {
        environment = environment
            .with_var(name, value)
            .map_err(|source| ConfigError::Command {
                profile: profile.to_owned(),
                source,
            })?;
    }
    for name in &raw.remove {
        environment = environment
            .without_var(name)
            .map_err(|source| ConfigError::Command {
                profile: profile.to_owned(),
                source,
            })?;
    }
    Ok(environment)
}

fn build_stdio(raw: &RawStdio) -> StdioSpec {
    let mut stdio = StdioSpec::default();
    if let Some(mode) = &raw.stdin {
        stdio = stdio.with_stdin(stdio_mode(*mode));
    }
    if let Some(mode) = &raw.stdout {
        stdio = stdio.with_stdout(stdio_mode(*mode));
    }
    if let Some(mode) = &raw.stderr {
        stdio = stdio.with_stderr(stdio_mode(*mode));
    }
    stdio
}

fn stdio_mode(value: RawStdioMode) -> StdioMode {
    match value {
        RawStdioMode::Inherit => StdioMode::Inherit,
        RawStdioMode::Null => StdioMode::Null,
        RawStdioMode::Pipe => StdioMode::Pipe,
    }
}

fn build_timeout(raw: &RawTimeout, profile: &str) -> Result<TimeoutPolicy, ConfigError> {
    let mode = raw
        .mode
        .ok_or_else(|| invalid_value(profile, "command.timeout.mode", "value is required"))?;
    match mode {
        RawTimeoutMode::BackendDefault => {
            reject_timeout_milliseconds(raw, profile)?;
            Ok(TimeoutPolicy::BackendDefault)
        }
        RawTimeoutMode::Disabled => {
            reject_timeout_milliseconds(raw, profile)?;
            Ok(TimeoutPolicy::Disabled)
        }
        RawTimeoutMode::Limit => Ok(TimeoutPolicy::Limit(Duration::from_millis(
            raw.milliseconds.ok_or_else(|| {
                invalid_value(
                    profile,
                    "command.timeout.milliseconds",
                    "value is required for limit",
                )
            })?,
        ))),
    }
}

fn reject_timeout_milliseconds(raw: &RawTimeout, profile: &str) -> Result<(), ConfigError> {
    if raw.milliseconds.is_some() {
        Err(invalid_value(
            profile,
            "command.timeout.milliseconds",
            "only valid with mode = \"limit\"",
        ))
    } else {
        Ok(())
    }
}
