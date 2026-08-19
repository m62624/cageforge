// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;

use cageforge_command::{
    CommandError, CommandRequest, CommandSpec, EnvironmentBase, EnvironmentFilterAction,
    EnvironmentNameKey, EnvironmentOverride, EnvironmentPattern, EnvironmentSpec, StdioMode,
    StdioSpec, TimeoutPolicy,
};
use pretty_assertions::assert_eq;
#[cfg(unix)]
use std::collections::BTreeMap;
use std::collections::{BTreeSet, HashSet};

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
    assert_eq!(EnvironmentSpec::default().base(), EnvironmentBase::Core);
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
fn environment_override_names_are_case_insensitive() {
    let environment = EnvironmentSpec::empty()
        .with_var("PATH", "/usr/bin")
        .expect("valid variable should be accepted")
        .with_var("path", "/sandbox/bin")
        .expect("case variant should replace the variable")
        .without_var("PaTh")
        .expect("case variant should replace the variable with removal");

    assert_eq!(environment.overrides().len(), 1);
    assert_eq!(
        environment.override_for(OsString::from("PATH").as_os_str()),
        Some(&EnvironmentOverride::Remove)
    );
    assert_eq!(
        environment.apply_to([
            (OsString::from("Path"), OsString::from("/usr/bin")),
            (OsString::from("HOME"), OsString::from("/home/user")),
        ]),
        [(OsString::from("HOME"), OsString::from("/home/user"))]
            .into_iter()
            .collect()
    );

    let environment = EnvironmentSpec::empty()
        .with_var("PATH", "/sandbox/bin")
        .expect("valid variable should be accepted");
    assert_eq!(
        environment.apply_to([(OsString::from("path"), OsString::from("/usr/bin"))]),
        [(OsString::from("PATH"), OsString::from("/sandbox/bin"))]
            .into_iter()
            .collect()
    );
}

#[test]
fn environment_name_keys_follow_case_insensitive_policy_identity() {
    assert_eq!(
        EnvironmentNameKey::new("Path".as_ref()),
        EnvironmentNameKey::new("PATH".as_ref())
    );
}

#[cfg(unix)]
#[test]
fn malformed_unix_environment_names_do_not_collapse_lossily() {
    use std::os::unix::ffi::OsStringExt;

    let left = OsString::from_vec(vec![b'A', 0xff]);
    let right = OsString::from_vec(vec![b'A', 0xfe]);
    assert_ne!(
        EnvironmentNameKey::new(&left),
        EnvironmentNameKey::new(&right)
    );

    let environment = EnvironmentSpec::empty()
        .with_var(left.clone(), "left")
        .expect("first malformed native name")
        .with_var(right.clone(), "right")
        .expect("second malformed native name");
    assert_eq!(environment.overrides().len(), 2);

    let inherited = [(left.clone(), OsString::from("inherited"))];
    assert_eq!(
        EnvironmentSpec::inherit_all().apply_to(inherited.clone()),
        BTreeMap::from([(left.clone(), OsString::from("inherited"))])
    );
    assert!(
        EnvironmentSpec::inherit_all()
            .with_exclude_pattern("SECRET_*")
            .expect("exclude filter")
            .apply_to(inherited)
            .is_empty()
    );
}

#[cfg(windows)]
#[test]
fn malformed_windows_environment_names_do_not_collapse_lossily() {
    use std::os::windows::ffi::OsStringExt;

    let left = OsString::from_wide(&[b'A' as u16, 0xD800]);
    let right = OsString::from_wide(&[b'A' as u16, 0xD801]);
    assert_ne!(
        EnvironmentNameKey::new(&left),
        EnvironmentNameKey::new(&right)
    );
    assert!(
        EnvironmentSpec::inherit_all()
            .with_include_pattern("PATH")
            .expect("include filter")
            .apply_to([(left, OsString::from("value"))])
            .is_empty()
    );
}

#[test]
fn environment_patterns_are_validated_and_match_wildcards() {
    let environment = EnvironmentSpec::inherit_core()
        .with_filter("CARGO_*", EnvironmentFilterAction::Include)
        .expect("include pattern")
        .with_filter("*TOKEN*", EnvironmentFilterAction::Exclude)
        .expect("exclude pattern")
        .with_filter("CARGO_*", EnvironmentFilterAction::Include)
        .expect("duplicate include pattern");

    assert_eq!(environment.filters().len(), 2);
    let include = EnvironmentPattern::new("CARGO_*").expect("include key");
    let exclude = EnvironmentPattern::new("*TOKEN*").expect("exclude key");
    assert_eq!(
        environment.filters().get(&include),
        Some(&EnvironmentFilterAction::Include)
    );
    assert_eq!(
        environment.filters().get(&exclude),
        Some(&EnvironmentFilterAction::Exclude)
    );
    assert!(include.matches("cargo_home"));
    assert!(!include.matches("HOME"));
    assert!(exclude.matches("API_TOKEN"));
    assert!(!exclude.matches("PATH"));
    assert_eq!(
        environment.filter_action_for("cargo_token"),
        Some(EnvironmentFilterAction::Exclude)
    );
    assert_eq!(
        environment.filter_action_for("cargo_home"),
        Some(EnvironmentFilterAction::Include)
    );
    assert_eq!(environment.filter_action_for("HOME"), None);
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
fn environment_pattern_traits_follow_case_insensitive_matching() {
    let upper = EnvironmentPattern::new("SECRET_*").expect("upper-case pattern");
    let lower = EnvironmentPattern::new("secret_*").expect("lower-case pattern");

    assert_eq!(upper, lower);
    assert_eq!(HashSet::from([upper.clone(), lower.clone()]).len(), 1);
    assert_eq!(BTreeSet::from([upper, lower]).len(), 1);
}

#[test]
fn environment_application_has_explicit_codex_compatible_stage_order() {
    let environment = EnvironmentSpec::inherit_all()
        .with_filter("*TOKEN*", EnvironmentFilterAction::Exclude)
        .expect("exclude filter")
        .with_filter("PATH", EnvironmentFilterAction::Include)
        .expect("include filter")
        .with_var("PATH", "/custom/bin")
        .expect("path override")
        .with_var("REMOVED", "set then removed")
        .expect("set override")
        .without_var("REMOVED")
        .expect("remove override");

    let result = environment.apply_to([
        (OsString::from("PATH"), OsString::from("/usr/bin")),
        (OsString::from("ACCESS_TOKEN"), OsString::from("secret")),
        (OsString::from("HOME"), OsString::from("/home/user")),
    ]);
    assert_eq!(
        result,
        [(OsString::from("PATH"), OsString::from("/custom/bin"))]
            .into_iter()
            .collect()
    );

    let restored = EnvironmentSpec::inherit_all()
        .with_exclude_pattern("*TOKEN*")
        .expect("exclude filter")
        .with_var("ACCESS_TOKEN", "explicitly restored")
        .expect("explicit set override");
    assert_eq!(
        restored.apply_to([(
            OsString::from("ACCESS_TOKEN"),
            OsString::from("inherited secret"),
        )]),
        [(
            OsString::from("ACCESS_TOKEN"),
            OsString::from("explicitly restored"),
        )]
        .into_iter()
        .collect()
    );
}

#[test]
fn environment_application_uses_the_backend_selected_core_base() {
    let environment = EnvironmentSpec::inherit_core()
        .with_include_pattern("PATH")
        .expect("include pattern")
        .with_var("PATH", "/sandbox/bin")
        .expect("path override");
    let core_base = [
        (OsString::from("PATH"), OsString::from("/usr/bin")),
        (OsString::from("HOME"), OsString::from("/home/user")),
    ];

    assert_eq!(
        environment.apply_to(core_base),
        [(OsString::from("PATH"), OsString::from("/sandbox/bin"))]
            .into_iter()
            .collect()
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

    let command = CommandSpec::new("tool").expect("program should be accepted");
    let path = PathBuf::from("../outside");
    assert_eq!(
        CommandRequest::new(command)
            .with_working_directory(path.clone())
            .expect_err("parent traversal cwd should fail"),
        CommandError::WorkingDirectoryParentTraversal { path }
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
            CommandError::WorkingDirectoryParentTraversal {
                path: PathBuf::from("../outside"),
            },
            "working directory must not contain parent traversal",
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
