// Copyright 2026 Mansur Azatbek
// SPDX-License-Identifier: Apache-2.0

use super::super::error::{ConfigError, invalid_value};
use super::super::model::{RawCommand, RawEnvironment, RawStdio, RawTimeout};
use cageforge_command::{
    CommandRequest, CommandSpec, EnvironmentSpec, StdioMode, StdioSpec, TimeoutPolicy,
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
        request = request.with_stdio(build_stdio(stdio, profile)?);
    }
    if let Some(timeout) = &raw.timeout {
        request = request.with_timeout_policy(build_timeout(timeout, profile)?);
    }
    Ok(Some(request))
}

fn build_environment(raw: &RawEnvironment, profile: &str) -> Result<EnvironmentSpec, ConfigError> {
    let mut environment = match raw.inherit.as_deref().unwrap_or("all") {
        "all" => EnvironmentSpec::inherit_all(),
        "core" => EnvironmentSpec::inherit_core(),
        "none" => EnvironmentSpec::empty(),
        value => {
            return Err(invalid_value(
                profile,
                "command.environment.inherit",
                format!("unsupported base {value:?}"),
            ));
        }
    };
    for pattern in &raw.exclude {
        environment = environment
            .with_exclude_pattern(pattern)
            .map_err(|source| ConfigError::Command {
                profile: profile.to_owned(),
                source,
            })?;
    }
    for pattern in &raw.include {
        environment = environment
            .with_include_pattern(pattern)
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

fn build_stdio(raw: &RawStdio, profile: &str) -> Result<StdioSpec, ConfigError> {
    let mut stdio = StdioSpec::default();
    if let Some(mode) = &raw.stdin {
        stdio = stdio.with_stdin(parse_stdio_mode(mode, profile, "command.stdio.stdin")?);
    }
    if let Some(mode) = &raw.stdout {
        stdio = stdio.with_stdout(parse_stdio_mode(mode, profile, "command.stdio.stdout")?);
    }
    if let Some(mode) = &raw.stderr {
        stdio = stdio.with_stderr(parse_stdio_mode(mode, profile, "command.stdio.stderr")?);
    }
    Ok(stdio)
}

fn parse_stdio_mode(value: &str, profile: &str, field: &str) -> Result<StdioMode, ConfigError> {
    match value {
        "inherit" => Ok(StdioMode::Inherit),
        "null" => Ok(StdioMode::Null),
        "pipe" => Ok(StdioMode::Pipe),
        value => Err(invalid_value(
            profile,
            field,
            format!("unsupported mode {value:?}"),
        )),
    }
}

fn build_timeout(raw: &RawTimeout, profile: &str) -> Result<TimeoutPolicy, ConfigError> {
    let mode = raw
        .mode
        .as_deref()
        .ok_or_else(|| invalid_value(profile, "command.timeout.mode", "value is required"))?;
    match mode {
        "backend-default" => {
            reject_timeout_milliseconds(raw, profile)?;
            Ok(TimeoutPolicy::BackendDefault)
        }
        "disabled" => {
            reject_timeout_milliseconds(raw, profile)?;
            Ok(TimeoutPolicy::Disabled)
        }
        "limit" => Ok(TimeoutPolicy::Limit(Duration::from_millis(
            raw.milliseconds.ok_or_else(|| {
                invalid_value(
                    profile,
                    "command.timeout.milliseconds",
                    "value is required for limit",
                )
            })?,
        ))),
        value => Err(invalid_value(
            profile,
            "command.timeout.mode",
            format!("unsupported mode {value:?}"),
        )),
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
