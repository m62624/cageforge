// Copyright 2026 Mansur Azatbek
// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsString;
use std::time::Duration;

use cageforge_command::{
    CommandError, CommandRequest, CommandSpec, EnvironmentBase, EnvironmentOverride,
    EnvironmentSpec, StdioMode, StdioSpec,
};
use pretty_assertions::assert_eq;

#[test]
fn command_spec_preserves_native_argv() {
    let command = CommandSpec::new("tool")
        .expect("program should be accepted")
        .with_args(["--flag", "", "value"])
        .with_arg(OsString::from("native"));

    assert_eq!(command.program().to_string_lossy(), "tool");
    assert_eq!(
        command.args(),
        &[
            OsString::from("--flag"),
            OsString::new(),
            OsString::from("value"),
            OsString::from("native"),
        ]
    );
}

#[test]
fn command_spec_rejects_invalid_programs_and_returns_parts() {
    assert_eq!(
        CommandSpec::new("").expect_err("empty program should fail"),
        CommandError::EmptyProgram
    );
    assert_eq!(
        CommandSpec::new("bad\0program").expect_err("NUL program should fail"),
        CommandError::ProgramContainsNul
    );

    let parts = CommandSpec::new("tool")
        .expect("program should be accepted")
        .with_arg("arg")
        .into_parts();
    assert_eq!(parts, (OsString::from("tool"), vec![OsString::from("arg")]));
}

#[test]
fn environment_defaults_and_bases_are_explicit() {
    assert_eq!(EnvironmentSpec::default().base(), EnvironmentBase::Inherit);
    assert!(EnvironmentSpec::default().overrides().is_empty());
    assert_eq!(EnvironmentSpec::empty().base(), EnvironmentBase::Empty);
}

#[test]
fn environment_overrides_are_sorted_and_distinguish_set_from_remove() {
    let environment = EnvironmentSpec::empty()
        .with_var("Z_LAST", "")
        .expect("empty values are valid")
        .without_var("A_REMOVE")
        .expect("valid name should be accepted")
        .with_var("MIDDLE", "value")
        .expect("valid variable should be accepted");

    assert_eq!(environment.base(), EnvironmentBase::Empty);
    assert_eq!(
        environment.override_for("A_REMOVE".as_ref()),
        Some(&EnvironmentOverride::Remove)
    );
    assert_eq!(
        environment.override_for("MIDDLE".as_ref()),
        Some(&EnvironmentOverride::Set(OsString::from("value")))
    );
    let names: Vec<_> = environment.overrides().keys().collect();
    assert_eq!(
        names,
        vec![
            &OsString::from("A_REMOVE"),
            &OsString::from("MIDDLE"),
            &OsString::from("Z_LAST")
        ]
    );
}

#[test]
fn environment_rejects_invalid_names_and_values() {
    assert_eq!(
        EnvironmentSpec::default()
            .with_var("", "value")
            .expect_err("empty name should fail"),
        CommandError::EmptyEnvironmentName
    );
    assert_eq!(
        EnvironmentSpec::default()
            .without_var("A=B")
            .expect_err("equals in name should fail"),
        CommandError::EnvironmentNameContainsEquals
    );
    assert_eq!(
        EnvironmentSpec::default()
            .with_var("A\0B", "value")
            .expect_err("NUL in name should fail"),
        CommandError::EnvironmentNameContainsNul
    );
    assert_eq!(
        EnvironmentSpec::default()
            .with_var("A", "bad\0value")
            .expect_err("NUL in value should fail"),
        CommandError::EnvironmentValueContainsNul
    );
}

#[test]
fn stdio_defaults_and_named_modes_are_explicit() {
    assert_eq!(
        StdioSpec::default(),
        StdioSpec::new(StdioMode::Null, StdioMode::Pipe, StdioMode::Pipe)
    );
    assert_eq!(
        StdioSpec::inherited()
            .with_stdin(StdioMode::Pipe)
            .with_stdout(StdioMode::Null)
            .with_stderr(StdioMode::Pipe),
        StdioSpec::new(StdioMode::Pipe, StdioMode::Null, StdioMode::Pipe)
    );

    let stdio = StdioSpec::new(StdioMode::Inherit, StdioMode::Null, StdioMode::Pipe);
    assert_eq!(stdio.stdin(), StdioMode::Inherit);
    assert_eq!(stdio.stdout(), StdioMode::Null);
    assert_eq!(stdio.stderr(), StdioMode::Pipe);
}

#[test]
fn request_composes_command_environment_stdio_cwd_and_timeout() {
    let command = CommandSpec::new("tool")
        .expect("program should be accepted")
        .with_arg("--check");
    let environment = EnvironmentSpec::empty()
        .with_var("MODE", "test")
        .expect("valid variable should be accepted");
    let request = CommandRequest::new(command.clone())
        .with_working_directory("workspace")
        .expect("non-empty cwd should be accepted")
        .with_environment(environment.clone())
        .with_stdio(StdioSpec::inherited())
        .with_timeout(Duration::from_secs(5));

    assert_eq!(request.command(), &command);
    assert_eq!(
        request.working_directory(),
        Some(std::path::Path::new("workspace"))
    );
    assert_eq!(request.environment(), &environment);
    assert_eq!(request.stdio(), StdioSpec::inherited());
    assert_eq!(request.timeout(), Some(Duration::from_secs(5)));
}

#[test]
fn request_can_remove_optional_values() {
    let command = CommandSpec::new("tool").expect("program should be accepted");
    let request = CommandRequest::new(command)
        .with_working_directory("workspace")
        .expect("non-empty cwd should be accepted")
        .with_timeout(Duration::ZERO)
        .without_working_directory()
        .without_timeout();

    assert_eq!(request.working_directory(), None);
    assert_eq!(request.timeout(), None);
}

#[test]
fn request_rejects_empty_working_directory() {
    let command = CommandSpec::new("tool").expect("program should be accepted");
    assert_eq!(
        CommandRequest::new(command)
            .with_working_directory(OsString::new())
            .expect_err("empty cwd should fail"),
        CommandError::EmptyWorkingDirectory
    );
}

#[test]
fn errors_have_actionable_display_messages() {
    let errors = [
        (CommandError::EmptyProgram, "program must not be empty"),
        (
            CommandError::ProgramContainsNul,
            "program must not contain a NUL",
        ),
        (
            CommandError::EmptyWorkingDirectory,
            "working directory must not be empty",
        ),
        (
            CommandError::EmptyEnvironmentName,
            "environment variable name must not be empty",
        ),
        (
            CommandError::EnvironmentNameContainsEquals,
            "environment variable name must not contain '='",
        ),
        (
            CommandError::EnvironmentNameContainsNul,
            "environment variable name must not contain a NUL",
        ),
        (
            CommandError::EnvironmentValueContainsNul,
            "environment variable value must not contain a NUL",
        ),
    ];

    for (error, message) in errors {
        assert!(error.to_string().contains(message), "{error}");
    }
}
