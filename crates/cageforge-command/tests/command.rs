// Copyright 2026 Mansur Azatbek
// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsString;
use std::time::Duration;

use cageforge_command::{
    CommandError, CommandRequest, CommandSpec, EnvironmentBase, EnvironmentOverride,
    EnvironmentPattern, EnvironmentSpec, StdioMode, StdioSpec, TimeoutPolicy,
};
use pretty_assertions::assert_eq;

#[test]
fn command_spec_preserves_native_argv() {
    let command = CommandSpec::new("tool")
        .expect("program should be accepted")
        .with_args(["--flag", "", "value"])
        .expect("arguments should be accepted")
        .with_arg(OsString::from("native"))
        .expect("native argument should be accepted");

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
        .expect("argument should be accepted")
        .into_parts();
    assert_eq!(parts, (OsString::from("tool"), vec![OsString::from("arg")]));

    assert_eq!(
        CommandSpec::new("tool")
            .expect("program should be accepted")
            .with_arg("bad\0argument")
            .expect_err("NUL argument should fail"),
        CommandError::ArgumentContainsNul
    );
    assert_eq!(
        CommandSpec::new("tool")
            .expect("program should be accepted")
            .with_args(["valid", "bad\0argument"])
            .expect_err("NUL argument should fail"),
        CommandError::ArgumentContainsNul
    );
}

#[test]
fn environment_defaults_and_bases_are_explicit() {
    assert_eq!(EnvironmentSpec::default().base(), EnvironmentBase::All);
    assert!(EnvironmentSpec::default().overrides().is_empty());
    assert_eq!(EnvironmentSpec::empty().base(), EnvironmentBase::None);
    assert_eq!(
        EnvironmentSpec::inherit_core().base(),
        EnvironmentBase::Core
    );
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

    assert_eq!(environment.base(), EnvironmentBase::None);
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
fn environment_patterns_are_validated_and_match_wildcards() {
    let environment = EnvironmentSpec::inherit_core()
        .with_include_pattern("CARGO_*")
        .expect("include pattern")
        .with_exclude_pattern("*TOKEN*")
        .expect("exclude pattern")
        .with_include_pattern("CARGO_*")
        .expect("duplicate include pattern");

    assert_eq!(environment.include_patterns().len(), 1);
    assert_eq!(environment.exclude_patterns().len(), 1);
    assert_eq!(environment.include_patterns()[0].as_str(), "CARGO_*");
    assert!(environment.include_patterns()[0].matches("CARGO_HOME"));
    assert!(!environment.include_patterns()[0].matches("HOME"));
    assert!(environment.exclude_patterns()[0].matches("API_TOKEN"));
    assert!(!environment.exclude_patterns()[0].matches("PATH"));
    let single_character = EnvironmentPattern::new("A?C").expect("single-character pattern");
    assert!(single_character.matches("ABC"));
    assert!(!single_character.matches("AC"));

    assert_eq!(
        EnvironmentPattern::new("").expect_err("empty pattern"),
        CommandError::EmptyEnvironmentPattern
    );
    assert_eq!(
        EnvironmentPattern::new("BAD=NAME").expect_err("equals in pattern"),
        CommandError::EnvironmentPatternContainsEquals
    );
    assert_eq!(
        EnvironmentPattern::new("BAD\0NAME").expect_err("NUL in pattern"),
        CommandError::EnvironmentPatternContainsNul
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
        .with_arg("--check")
        .expect("argument should be accepted");
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
    assert_eq!(
        request.timeout_policy(),
        TimeoutPolicy::Limit(Duration::from_secs(5))
    );
}

#[test]
fn request_exposes_all_timeout_states_and_can_remove_cwd() {
    let command = CommandSpec::new("tool").expect("program should be accepted");
    let request = CommandRequest::new(command)
        .with_working_directory("workspace")
        .expect("non-empty cwd should be accepted")
        .with_timeout(Duration::ZERO)
        .without_working_directory()
        .disable_timeout();

    assert_eq!(request.working_directory(), None);
    assert_eq!(request.timeout_policy(), TimeoutPolicy::Disabled);
    assert_eq!(
        request.use_backend_timeout().timeout_policy(),
        TimeoutPolicy::BackendDefault
    );
    assert_eq!(
        CommandRequest::new(CommandSpec::new("tool").expect("program should be accepted"))
            .with_timeout_policy(TimeoutPolicy::Limit(Duration::from_secs(2)))
            .timeout_policy(),
        TimeoutPolicy::Limit(Duration::from_secs(2))
    );
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

    let command = CommandSpec::new("tool").expect("program should be accepted");
    assert_eq!(
        CommandRequest::new(command)
            .with_working_directory("bad\0directory")
            .expect_err("NUL cwd should fail"),
        CommandError::WorkingDirectoryContainsNul
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
            CommandError::ArgumentContainsNul,
            "argument must not contain a NUL",
        ),
        (
            CommandError::EmptyWorkingDirectory,
            "working directory must not be empty",
        ),
        (
            CommandError::WorkingDirectoryContainsNul,
            "working directory must not contain a NUL",
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
        (
            CommandError::EmptyEnvironmentPattern,
            "environment variable pattern must not be empty",
        ),
        (
            CommandError::EnvironmentPatternContainsNul,
            "environment variable pattern must not contain a NUL",
        ),
        (
            CommandError::EnvironmentPatternContainsEquals,
            "environment variable pattern must not contain '='",
        ),
    ];

    for (error, message) in errors {
        assert!(error.to_string().contains(message), "{error}");
    }
}

#[cfg(unix)]
#[test]
fn unix_native_working_directories_are_preserved() {
    let command = CommandSpec::new("tool").expect("program should be accepted");
    let request = CommandRequest::new(command)
        .with_working_directory("/var/empty")
        .expect("POSIX absolute cwd should be accepted");

    assert_eq!(
        request.working_directory(),
        Some(std::path::Path::new("/var/empty"))
    );
}

#[cfg(windows)]
#[test]
fn windows_native_working_directories_are_preserved() {
    let command = CommandSpec::new("tool").expect("program should be accepted");
    let request = CommandRequest::new(command)
        .with_working_directory(r"C:\work\empty")
        .expect("Windows absolute cwd should be accepted");

    assert_eq!(
        request.working_directory(),
        Some(std::path::Path::new(r"C:\work\empty"))
    );
}
