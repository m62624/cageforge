use cageforge_command::{
    CommandError, CommandRequest, CommandSpec, EnvironmentBase, EnvironmentFilterAction,
    EnvironmentOverride, EnvironmentPattern, EnvironmentSpec, StdioMode, StdioSpec, TimeoutPolicy,
};
use cageforge_config::{Config, ConfigError, DiagnosticSeverity};
use cageforge_policy::{
    AccessMode, DomainAccess, DomainMode, FilesystemMode, FilesystemTarget, LocalNetworkAccess,
    MissingPathBehavior, NetworkMode, PathSelector, UnixSocketMode,
};
use pretty_assertions::assert_eq;
use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::time::Duration;

fn absolute_path() -> PathBuf {
    std::env::current_dir()
        .expect("test working directory")
        .join("cageforge-config-state")
}

fn absolute_socket() -> PathBuf {
    absolute_path().join("agent.sock")
}

fn empty_profile() -> Config {
    Config::from_toml(
        r#"
default_profile = "safe"

[profiles.safe]
"#,
    )
    .expect("valid empty profile")
}

const COMMON_EXAMPLES: [(&str, &str); 5] = [
    (
        "minimal-policy.toml",
        include_str!("../examples/minimal-policy.toml"),
    ),
    (
        "workspace-development.toml",
        include_str!("../examples/workspace-development.toml"),
    ),
    (
        "profile-inheritance.toml",
        include_str!("../examples/profile-inheritance.toml"),
    ),
    (
        "environment-order.toml",
        include_str!("../examples/environment-order.toml"),
    ),
    (
        "trusted-metadata-write.toml",
        include_str!("../examples/trusted-metadata-write.toml"),
    ),
];

#[cfg(unix)]
fn platform_example() -> (&'static str, &'static str) {
    (
        "platform-targets-unix.toml",
        include_str!("../examples/platform-targets-unix.toml"),
    )
}

#[cfg(windows)]
fn platform_example() -> (&'static str, &'static str) {
    (
        "platform-targets-windows.toml",
        include_str!("../examples/platform-targets-windows.toml"),
    )
}

#[test]
fn documented_examples_are_live_parse_and_resolution_fixtures() {
    for (name, source) in COMMON_EXAMPLES {
        let config = Config::from_toml(source)
            .unwrap_or_else(|error| panic!("{name} should remain valid TOML: {error}"));
        config
            .resolve_default()
            .unwrap_or_else(|error| panic!("{name} should resolve: {error}"));
    }

    let (name, source) = platform_example();
    let config = Config::from_toml(source)
        .unwrap_or_else(|error| panic!("{name} should remain valid TOML: {error}"));
    config
        .resolve_default()
        .unwrap_or_else(|error| panic!("{name} should resolve: {error}"));
}

#[test]
fn documented_examples_cover_their_declared_behavior() {
    let inherited = Config::from_toml(include_str!("../examples/profile-inheritance.toml"))
        .expect("inheritance example parses")
        .resolve_default()
        .expect("inheritance example resolves");
    assert_eq!(
        inherited.workspace_roots(),
        &[
            PathBuf::from("/work/artifacts"),
            PathBuf::from("/work/project")
        ]
    );
    assert_eq!(inherited.policy().filesystem().entries().len(), 2);
    assert_eq!(
        inherited.policy().filesystem().entries()[0].access(),
        AccessMode::Write
    );
    assert_eq!(
        inherited.policy().network().domains()[1].access(),
        DomainAccess::Allow
    );
    let inherited_environment = inherited
        .command()
        .expect("inherited command")
        .environment();
    assert_eq!(
        inherited_environment.filter_action_for("PATH"),
        Some(EnvironmentFilterAction::Exclude)
    );

    let ordered = Config::from_toml(include_str!("../examples/environment-order.toml"))
        .expect("environment-order example parses")
        .resolve_default()
        .expect("environment-order example resolves");
    let result = ordered
        .command()
        .expect("ordered command")
        .environment()
        .apply_to([
            (OsString::from("PATH"), OsString::from("/usr/bin")),
            (OsString::from("ACCESS_TOKEN"), OsString::from("secret")),
            (OsString::from("REMOVE_ME"), OsString::from("old")),
        ]);
    assert_eq!(
        result,
        [
            (OsString::from("PATH"), OsString::from("/custom/bin")),
            (OsString::from("OVERRIDE"), OsString::from("explicit"))
        ]
        .into_iter()
        .collect()
    );

    let trusted = Config::from_toml(include_str!("../examples/trusted-metadata-write.toml"))
        .expect("trusted metadata example parses")
        .resolve_default()
        .expect("trusted metadata example resolves");
    assert_eq!(
        trusted.policy().filesystem().protected_relative_paths(),
        &[PathBuf::from(".cargo"), PathBuf::from(".env")]
    );
}

#[test]
fn platform_example_exercises_every_config_field() {
    let (name, source) = platform_example();
    let resolved = Config::from_toml(source)
        .unwrap_or_else(|error| panic!("{name} should parse: {error}"))
        .resolve_default()
        .unwrap_or_else(|error| panic!("{name} should resolve: {error}"));

    let filesystem = resolved.policy().filesystem();
    assert_eq!(filesystem.entries().len(), 9);
    assert_eq!(filesystem.glob_scan_max_depth(), NonZeroUsize::new(6));
    assert_eq!(filesystem.protected_relative_paths().len(), 3);

    let network = resolved.policy().network();
    assert_eq!(network.mode(), NetworkMode::Enabled);
    assert_eq!(network.domain_mode(), DomainMode::Restricted);
    assert_eq!(network.unix_socket_mode(), UnixSocketMode::Restricted);
    assert_eq!(network.local_network_access(), LocalNetworkAccess::Deny);
    assert_eq!(network.domains().len(), 4);
    assert_eq!(network.domains()[1].pattern(), "api.example.com");
    assert_eq!(network.domains()[2].pattern(), "2001:db8::1");
    assert_eq!(network.unix_sockets().len(), 1);

    let command = resolved.command().expect("platform command");
    assert_eq!(
        command.command().args(),
        [OsString::from("--profile"), OsString::from("all-targets")]
    );
    assert_eq!(command.working_directory(), Some(Path::new("src")));
    assert_eq!(command.environment().base(), EnvironmentBase::All);
    assert_eq!(command.environment().filters().len(), 3);
    assert_eq!(command.environment().overrides().len(), 2);
    assert_eq!(
        command.stdio(),
        StdioSpec::new(StdioMode::Inherit, StdioMode::Null, StdioMode::Pipe)
    );
    assert_eq!(
        command.timeout_policy(),
        TimeoutPolicy::Limit(Duration::from_millis(30000))
    );
}

#[test]
fn resolves_default_profile_and_command() {
    let config = Config::from_toml(
        r#"
default_profile = "workspace"

[profiles.workspace.filesystem]
mode = "restricted"
rules = [{ target = "workspace-root", access = "write" }]

[profiles.workspace.network]
mode = "disabled"

[profiles.workspace.command]
program = "echo"
args = ["hello", "world"]
working_directory = "work"

[profiles.workspace.command.environment]
inherit = "none"
set = { LANG = "C" }

[profiles.workspace.command.stdio]
stdin = "null"
stdout = "pipe"
stderr = "inherit"

[profiles.workspace.command.timeout]
mode = "limit"
milliseconds = 2500
"#,
    )
    .expect("valid config");

    assert_eq!(config.profile_names().collect::<Vec<_>>(), ["workspace"]);
    assert_eq!(config.default_profile_name(), Some("workspace"));
    let resolved = config.resolve_default().expect("default resolves");

    let expected_policy = cageforge_policy::SandboxPolicy::new(
        cageforge_policy::FilesystemPolicy::restricted([cageforge_policy::FilesystemRule::new(
            PathSelector::workspace_root(),
            AccessMode::Write,
        )]),
        cageforge_policy::NetworkPolicy::disabled(),
    );
    assert_eq!(resolved.policy(), &expected_policy);

    let expected_command = CommandRequest::new(
        CommandSpec::new("echo")
            .expect("program")
            .with_args([OsString::from("hello"), OsString::from("world")])
            .expect("args"),
    )
    .with_working_directory("work")
    .expect("working directory")
    .with_environment(
        EnvironmentSpec::empty()
            .with_var("LANG", "C")
            .expect("environment"),
    )
    .with_stdio(StdioSpec::new(
        StdioMode::Null,
        StdioMode::Pipe,
        StdioMode::Inherit,
    ))
    .with_timeout_policy(TimeoutPolicy::Limit(Duration::from_millis(2500)));
    assert_eq!(resolved.command(), Some(&expected_command));
}

#[test]
fn inheritance_merges_in_order_and_child_values_win() {
    let config = Config::from_toml(
        r#"
default_profile = "final"

[profiles.base.filesystem]
mode = "restricted"
rules = [{ target = "workspace-root", access = "read" }]

[profiles.base.network]
mode = "enabled"
domain_mode = "restricted"
domains = [{ pattern = "**.example.com", access = "allow" }]

[profiles.base.command]
program = "base-program"
args = ["base"]

[profiles.base.command.environment]
inherit = "none"
filters = { "BASE_*" = "include", "*SECRET*" = "exclude" }
set = { BASE = "one", SHARED = "base" }

[profiles.base.command.timeout]
mode = "limit"
milliseconds = 100

[profiles.override.filesystem]
rules = [{ target = "tmpdir", access = "write" }]

[profiles.override.network]
domains = [{ pattern = "blocked.example.com", access = "deny" }]

[profiles.override.command]
working_directory = "child"

[profiles.override.command.environment]
filters = { "OVERRIDE_*" = "include", "*TOKEN*" = "exclude" }
set = { OVERRIDE = "yes", SHARED = "override" }

[profiles.final]
inherits = ["base", "override"]

[profiles.final.filesystem]
rules = [
  { target = "workspace-root", access = "write" },
  { target = "slash-tmp", access = "write" },
]

[profiles.final.network]
domains = [{ pattern = "blocked.example.com", access = "allow" }]

[profiles.final.command]
args = ["final"]

[profiles.final.command.environment]
filters = { "FINAL_*" = "include" }
remove = ["BASE"]

[profiles.final.command.timeout]
mode = "disabled"
"#,
    )
    .expect("valid config");

    let resolved = config.resolve_default().expect("default resolves");
    assert_eq!(resolved.policy().filesystem().entries().len(), 3);
    assert_eq!(
        resolved.policy().filesystem().entries()[0].access(),
        AccessMode::Write
    );
    assert_eq!(
        resolved.policy().filesystem().entries()[1].access(),
        AccessMode::Write
    );
    assert_eq!(
        resolved.policy().filesystem().entries()[2].access(),
        AccessMode::Write
    );
    assert_eq!(resolved.policy().network().mode(), NetworkMode::Enabled);
    assert_eq!(
        resolved.policy().network().domain_mode(),
        DomainMode::Restricted
    );
    assert_eq!(resolved.policy().network().domains().len(), 2);
    assert_eq!(
        resolved.policy().network().domains()[1].access(),
        DomainAccess::Allow
    );

    let command = resolved.command().expect("command inherited");
    assert_eq!(command.command().program(), OsStr::new("base-program"));
    assert_eq!(command.command().args(), [OsString::from("final")]);
    assert_eq!(command.working_directory(), Some(Path::new("child")));
    assert_eq!(command.environment().base(), EnvironmentBase::None);
    assert_eq!(
        command
            .environment()
            .filters()
            .keys()
            .map(EnvironmentPattern::as_str)
            .collect::<Vec<_>>(),
        ["*SECRET*", "*TOKEN*", "BASE_*", "FINAL_*", "OVERRIDE_*"]
    );
    assert_eq!(
        command
            .environment()
            .filters()
            .get(&EnvironmentPattern::new("*SECRET*").expect("secret filter")),
        Some(&EnvironmentFilterAction::Exclude)
    );
    assert_eq!(
        command.environment().override_for(OsStr::new("BASE")),
        Some(&EnvironmentOverride::Remove)
    );
    assert_eq!(
        command.environment().override_for(OsStr::new("SHARED")),
        Some(&EnvironmentOverride::Set(OsString::from("override")))
    );
    assert_eq!(command.timeout_policy(), TimeoutPolicy::Disabled);
}

#[test]
fn inherited_domain_rules_merge_after_host_normalization() {
    let config = Config::from_toml(
        r#"
[profiles.base.network]
mode = "enabled"
domain_mode = "restricted"
domains = [{ pattern = "example.com:443", access = "deny" }]

[profiles.child]
inherits = ["base"]

[profiles.child.network]
domains = [{ pattern = "EXAMPLE.COM:8443", access = "allow" }]
"#,
    )
    .expect("normalized domain config should parse");

    let resolved = config.resolve("child").expect("child should resolve");
    let network = resolved.policy().network();
    assert_eq!(network.domains().len(), 1);
    assert_eq!(network.domains()[0].pattern(), "example.com");
    assert_eq!(network.domains()[0].access(), DomainAccess::Allow);
    assert!(
        network
            .allows_domain("example.com:443")
            .expect("domain should be evaluated")
    );
}

#[test]
fn local_network_access_is_inherited_and_overridden() {
    let config = Config::from_toml(
        r#"
[profiles.base.network]
mode = "enabled"
local_network_access = "deny"

[profiles.child]
inherits = ["base"]

[profiles.child.network]
local_network_access = "allow"
"#,
    )
    .expect("local network access config should parse");

    assert_eq!(
        config
            .resolve("child")
            .expect("child should resolve")
            .policy()
            .network()
            .local_network_access(),
        LocalNetworkAccess::Allow
    );
}

#[test]
fn environment_inheritance_replaces_case_variants_safely() {
    let config = Config::from_toml(
        r#"
[profiles.base.command]
program = "runner"

[profiles.base.command.environment]
set = { PATH = "/base/bin" }

[profiles.child]
inherits = ["base"]

[profiles.child.command.environment]
set = { path = "/child/bin" }
"#,
    )
    .expect("case-variant environment override should parse");

    let resolved = config.resolve("child").expect("child should resolve");
    let environment = resolved
        .command()
        .expect("command should be inherited")
        .environment();
    assert_eq!(environment.overrides().len(), 1);
    assert_eq!(
        environment.override_for(OsStr::new("PATH")),
        Some(&EnvironmentOverride::Set(OsString::from("/child/bin")))
    );
    assert_eq!(
        environment.apply_to([(OsString::from("Path"), OsString::from("/system/bin"))]),
        [(OsString::from("path"), OsString::from("/child/bin"))]
            .into_iter()
            .collect()
    );

    let remove_config = Config::from_toml(
        r#"
[profiles.base.command]
program = "runner"

[profiles.base.command.environment]
set = { PATH = "/base/bin" }

[profiles.child]
inherits = ["base"]

[profiles.child.command.environment]
remove = ["path"]
"#,
    )
    .expect("case-variant environment removal should parse");
    let remove_environment = remove_config
        .resolve("child")
        .expect("child removal should resolve")
        .command()
        .expect("command should be inherited")
        .environment()
        .clone();
    assert_eq!(remove_environment.overrides().len(), 1);
    assert_eq!(
        remove_environment.override_for(OsStr::new("PATH")),
        Some(&EnvironmentOverride::Remove)
    );
}

#[test]
fn maps_all_policy_and_command_modes() {
    let root = absolute_path();
    let socket = absolute_socket();
    let source = format!(
        r#"
default_profile = "all"

[profiles.all.filesystem]
glob_scan_max_depth = 8
rules = [
  {{ target = "absolute", path = '{root}', access = "read", missing_path = "skip" }},
  {{ target = "workspace", path = ".", access = "write", read_only_subpaths = [{{ target = "workspace", path = ".git" }}] }},
  {{ target = "root", access = "read" }},
  {{ target = "workspace-root", access = "read" }},
  {{ target = "minimal", access = "read" }},
  {{ target = "tmpdir", access = "write" }},
  {{ target = "slash-tmp", access = "write" }},
  {{ target = "absolute-glob", pattern = '{root}/**/*.json', access = "deny" }},
  {{ target = "workspace-glob", pattern = 'target/**/*.rlib', access = "deny" }},
]

[profiles.all.network]
mode = "enabled"
domain_mode = "restricted"
unix_socket_mode = "restricted"
local_network_access = "deny"
domains = [
  {{ pattern = "**.example.com", access = "allow" }},
  {{ pattern = "blocked.example.com", access = "deny" }},
]
unix_sockets = [{{ path = '{socket}', access = "allow" }}]

[profiles.all.command]
program = "runner"

[profiles.all.command.stdio]
stdin = "inherit"
stdout = "null"
stderr = "pipe"

[profiles.all.command.timeout]
mode = "backend-default"
"#,
        root = root.to_string_lossy(),
        socket = socket.to_string_lossy(),
    );
    let resolved = Config::from_toml(&source)
        .expect("valid all-modes config")
        .resolve_default()
        .expect("default resolves");

    let filesystem = resolved.policy().filesystem();
    assert_eq!(filesystem.mode(), FilesystemMode::Restricted);
    assert_eq!(filesystem.entries().len(), 9);
    assert_eq!(
        filesystem.glob_scan_max_depth().map(|depth| depth.get()),
        Some(8)
    );
    assert_eq!(
        filesystem.entries()[0].missing_path_behavior(),
        MissingPathBehavior::Skip
    );
    assert_eq!(filesystem.entries()[1].read_only_subpaths().len(), 1);
    assert_eq!(
        filesystem.entries()[2].target(),
        &FilesystemTarget::Scope(PathSelector::root())
    );
    assert!(matches!(
        filesystem.entries()[7].target(),
        FilesystemTarget::Glob(pattern) if pattern.is_absolute()
    ));
    assert!(matches!(
        filesystem.entries()[8].target(),
        FilesystemTarget::Glob(pattern) if !pattern.is_absolute()
    ));

    let network = resolved.policy().network();
    assert_eq!(network.mode(), NetworkMode::Enabled);
    assert_eq!(network.domain_mode(), DomainMode::Restricted);
    assert_eq!(network.unix_socket_mode(), UnixSocketMode::Restricted);
    assert_eq!(network.local_network_access(), LocalNetworkAccess::Deny);
    assert_eq!(network.domains().len(), 2);
    assert_eq!(network.unix_sockets().len(), 1);
    assert!(network.allows_domain("good.example.com").expect("domain"));
    assert!(
        !network
            .allows_domain("blocked.example.com")
            .expect("domain")
    );
    assert!(network.allows_unix_socket(&socket));

    let command = resolved.command().expect("command");
    assert_eq!(
        command.stdio(),
        StdioSpec::new(StdioMode::Inherit, StdioMode::Null, StdioMode::Pipe)
    );
    assert_eq!(command.timeout_policy(), TimeoutPolicy::BackendDefault);
}

#[test]
fn policy_only_profile_uses_safe_defaults() {
    let resolved = empty_profile().resolve_default().expect("default resolves");
    assert_eq!(
        resolved.policy().filesystem().mode(),
        FilesystemMode::Restricted
    );
    assert!(resolved.policy().filesystem().entries().is_empty());
    assert_eq!(resolved.policy().network().mode(), NetworkMode::Disabled);
    assert_eq!(resolved.command(), None);
}

#[test]
fn protected_metadata_defaults_and_explicit_opt_out_are_visible() {
    let config = Config::from_toml(
        r#"
default_profile = "profile"

[profiles.profile.filesystem]
additional_protected_paths = [".cargo"]
rules = [{ target = "workspace-root", access = "write" }]

[profiles.profile.filesystem.security]
dangerously_allow_git_write = true
"#,
    )
    .expect("protected metadata config should parse");
    let resolved = config
        .resolve_default()
        .expect("protected metadata config should resolve");
    let policy = resolved.policy().filesystem();
    assert_eq!(policy.protected_relative_paths(), [PathBuf::from(".cargo")]);
}

#[test]
fn resolves_profile_metadata_and_workspace_roots() {
    let config = Config::from_toml(
        r#"
[profiles.parent]
description = "shared workspace policy"

[profiles.parent.workspace_roots]
"/workspace/shared" = true
"/workspace/removed" = true

[profiles.child]
inherits = ["parent"]
description = "child workspace policy"

[profiles.child.workspace_roots]
"/workspace/removed" = false
"relative/shared" = true
"/workspace/shared" = true
"relative/disabled" = false
"#,
    )
    .expect("metadata and workspace roots should parse");

    assert_eq!(
        config
            .resolve("parent")
            .expect("parent resolves")
            .description(),
        Some("shared workspace policy")
    );
    let resolved = config.resolve("child").expect("child resolves");
    assert_eq!(resolved.description(), Some("child workspace policy"));
    assert_eq!(
        resolved.workspace_roots(),
        &[
            PathBuf::from("/workspace/shared"),
            PathBuf::from("relative/shared"),
        ]
    );
}

#[test]
fn workspace_root_overrides_use_native_path_identity() {
    let (parent_root, child_root) = if cfg!(windows) {
        ("C:/Workspace", "c:/workspace")
    } else {
        ("/workspace/shared", "/workspace/shared/")
    };
    let source = format!(
        r#"
[profiles.parent.workspace_roots]
"{parent_root}" = true

[profiles.child]
inherits = ["parent"]

[profiles.child.workspace_roots]
"{child_root}" = false
"#
    );
    let config = Config::from_toml(&source).expect("workspace root override should parse");

    assert!(
        config
            .resolve("child")
            .expect("child profile should resolve")
            .workspace_roots()
            .is_empty()
    );
}

#[test]
fn resolves_all_environment_bases_and_filters() {
    for (inherit, expected_base) in [
        ("all", EnvironmentBase::All),
        ("core", EnvironmentBase::Core),
        ("none", EnvironmentBase::None),
    ] {
        let source = format!(
            r#"
default_profile = "profile"

[profiles.profile.command]
program = "runner"

[profiles.profile.command.environment]
inherit = "{inherit}"
filters = {{ "CARGO_*" = "include", "PATH" = "include", "*TOKEN*" = "exclude" }}
"#
        );
        let resolved = Config::from_toml(&source)
            .expect("environment source should parse")
            .resolve_default()
            .expect("environment should resolve");
        let environment = resolved.command().expect("command").environment();
        assert_eq!(environment.base(), expected_base);
        assert_eq!(environment.filters().len(), 3);
        assert_eq!(
            environment
                .filters()
                .get(&EnvironmentPattern::new("CARGO_*").expect("cargo filter")),
            Some(&EnvironmentFilterAction::Include)
        );
        assert_eq!(
            environment
                .filters()
                .get(&EnvironmentPattern::new("*TOKEN*").expect("token filter")),
            Some(&EnvironmentFilterAction::Exclude)
        );
    }
}

#[test]
fn resolves_from_file_and_reports_read_errors() {
    let path = std::env::temp_dir().join(format!(
        "cageforge-config-{}-{}.toml",
        std::process::id(),
        std::thread::current().name().unwrap_or("test")
    ));
    std::fs::write(&path, "[profiles.file]\n").expect("write temporary config");
    let config = Config::from_file(&path).expect("read config");
    assert_eq!(config.profile_names().collect::<Vec<_>>(), ["file"]);
    std::fs::remove_file(&path).expect("remove temporary config");

    let error = Config::from_file(&path).expect_err("missing file must fail");
    assert!(matches!(error, ConfigError::ReadFile { .. }));
}

#[test]
fn rejects_unknown_fields_and_invalid_profile_names() {
    let error = Config::from_toml("[profiles.safe]\nunknown = true\n").expect_err("unknown field");
    assert!(matches!(error, ConfigError::InvalidToml { .. }));

    let error = Config::from_toml("[profiles.\"bad.name\"]\n").expect_err("invalid profile name");
    assert!(matches!(error, ConfigError::InvalidProfileName { name } if name == "bad.name"));

    let error = Config::from_toml(
        r#"
[profiles.safe.command]
program = "runner"

[profiles.safe.command.environment.filters]
PATH = "include"
path = "exclude"
"#,
    )
    .expect_err("case-insensitive duplicate filter");
    assert!(matches!(
        error,
        ConfigError::InvalidValue { field, .. } if field == "command.environment.filters"
    ));

    let error = Config::from_toml(
        r#"
[profiles.safe.command]
program = "runner"

[profiles.safe.command.environment]
set = { PATH = "/one", path = "/two" }
"#,
    )
    .expect_err("case-insensitive duplicate set variables");
    assert!(matches!(
        error,
        ConfigError::InvalidValue { field, .. } if field == "command.environment"
    ));

    let error = Config::from_toml(
        r#"
[profiles.safe.command]
program = "runner"

[profiles.safe.command.environment]
remove = ["PATH", "path"]
"#,
    )
    .expect_err("case-insensitive duplicate removed variables");
    assert!(matches!(
        error,
        ConfigError::InvalidValue { field, .. } if field == "command.environment.remove"
    ));

    let error = Config::from_toml(
        r#"
[profiles.safe.command]
program = "runner"

[profiles.safe.command.environment]
set = { PATH = "/one" }
remove = ["path"]
"#,
    )
    .expect_err("case-insensitive set/remove conflict");
    assert!(matches!(
        error,
        ConfigError::InvalidValue { field, .. } if field == "command.environment"
    ));
}

#[test]
fn rejects_inheritance_and_default_errors() {
    let error = Config::from_toml("default_profile = \"missing\"\n[profiles.safe]\n")
        .expect_err("unknown default profile");
    assert!(matches!(error, ConfigError::UnknownProfile { name } if name == "missing"));

    let error = Config::from_toml(
        "[profiles.safe]\ninherits = [\"parent\", \"parent\"]\n[profiles.parent]\n",
    )
    .expect_err("duplicate parent");
    assert!(
        matches!(error, ConfigError::InvalidValue { field, profile, .. } if field == "inherits" && profile == "safe")
    );

    let config = Config::from_toml(
        r#"
[profiles.a]
inherits = ["b"]

[profiles.b]
inherits = ["a"]
"#,
    )
    .expect("parse cycle");
    assert!(matches!(
        config.resolve("a"),
        Err(ConfigError::ProfileCycle { chain }) if chain == ["a", "b", "a"]
    ));

    let config = Config::from_toml(
        r#"
[profiles.safe]
inherits = ["missing"]
"#,
    )
    .expect("parse unknown parent");
    assert!(matches!(
        config.resolve("safe"),
        Err(ConfigError::UnknownProfile { name }) if name == "missing"
    ));

    let config = Config::from_toml("[profiles.safe]\n").expect("profile");
    assert!(matches!(
        config.resolve_default(),
        Err(ConfigError::NoDefaultProfile)
    ));
    assert!(matches!(
        config.resolve("missing"),
        Err(ConfigError::UnknownProfile { name }) if name == "missing"
    ));
}

#[test]
fn shared_inherited_ancestors_do_not_form_a_false_cycle() {
    let config = Config::from_toml(
        r#"
[profiles.base.network]
mode = "enabled"
domain_mode = "enabled"
domains = [{ pattern = "base.example", access = "deny" }]

[profiles.left]
inherits = ["base"]

[profiles.right]
inherits = ["base"]

[profiles.child]
inherits = ["left", "right"]
"#,
    )
    .expect("shared ancestors should parse");

    let resolved = config.resolve("child").expect("shared ancestors resolve");
    assert_eq!(resolved.policy().network().domains().len(), 1);
    assert_eq!(
        resolved
            .policy()
            .network()
            .access_for_domain("base.example")
            .expect("domain lookup"),
        Some(DomainAccess::Deny)
    );
}

#[test]
fn rejects_invalid_policy_values_and_unused_fields() {
    let cases = [
        (
            "[profiles.p.filesystem]\nmode = \"invalid\"\n",
            "filesystem mode",
        ),
        (
            "[profiles.p.filesystem]\nrules = [{ target = \"workspace-root\", path = \"bad\", access = \"read\" }]\n",
            "special selector path",
        ),
        (
            "[profiles.p.filesystem]\nrules = [{ target = \"workspace-glob\", path = \"bad\", pattern = \"src/**\", access = \"read\" }]\n",
            "glob path",
        ),
        (
            "[profiles.p.filesystem]\nrules = [{ target = \"workspace-glob\", pattern = \"src/**\", access = \"read\", missing_path = \"skip\" }]\n",
            "glob missing-path behavior",
        ),
        (
            "[profiles.p.filesystem]\nrules = [{ target = \"workspace-glob\", pattern = \"src/**\", access = \"read\" }]\n",
            "portable read glob",
        ),
        (
            "[profiles.p.filesystem]\nrules = [{ target = \"workspace\", path = \"../escape\", access = \"read\" }]\n",
            "parent traversal",
        ),
        (
            "[profiles.p.network]\nmode = \"external\"\ndomains = [{ pattern = \"example.com\", access = \"allow\" }]\n",
            "external network rules",
        ),
        (
            "[profiles.p.command.timeout]\nmode = \"limit\"\n",
            "missing timeout",
        ),
    ];
    for (source, label) in cases {
        match Config::from_toml(&format!("default_profile = \"p\"\n{source}")) {
            Ok(config) => assert!(config.resolve_default().is_err(), "{label} should fail"),
            Err(error) => assert!(
                matches!(error, ConfigError::InvalidToml { .. }),
                "{label} should fail with a typed TOML value error: {error}"
            ),
        }
    }

    let error = Config::from_toml(
        "default_profile = \"p\"\n[profiles.p.filesystem]\nrules = [{ target = \"workspace-root\", access = \"read\", pattern = \"oops\" }]\n",
    )
    .expect("parse unused pattern").resolve_default().expect_err("unused pattern");
    assert!(
        matches!(error, ConfigError::InvalidValue { field, .. } if field == "filesystem.rules.pattern")
    );

    let error = Config::from_toml(
        "default_profile = \"p\"\n[profiles.p.filesystem]\nrules = [{ target = \"workspace-glob\", pattern = \"src/**\", access = \"write\" }]\n",
    )
    .expect("glob source should parse")
    .resolve_default()
    .expect_err("portable write glob should fail");
    assert!(matches!(
        error,
        ConfigError::Policy {
            source: cageforge_policy::PolicyError::UnsupportedGlobAccess {
                access: AccessMode::Write
            },
            ..
        }
    ));
}

#[test]
fn rejects_invalid_command_values() {
    let sources = [
        "[profiles.p.command]\nargs = [\"ok\"]\n",
        "[profiles.p.command]\nprogram = \"\\u0000\"\n",
        "[profiles.p.command]\nprogram = \"runner\"\nworking_directory = \"\\u0000\"\n",
        "[profiles.p.command]\nprogram = \"runner\"\n[profiles.p.command.environment]\nset = { BAD = \"\\u0000\" }\n",
        "[profiles.p.command]\nprogram = \"runner\"\n[profiles.p.command.environment]\nset = { \"BAD=NAME\" = \"value\" }\n",
        "[profiles.p.command]\nprogram = \"runner\"\n[profiles.p.command.stdio]\nstdout = \"invalid\"\n",
        "[profiles.p.command]\nprogram = \"runner\"\n[profiles.p.command.timeout]\nmode = \"disabled\"\nmilliseconds = 1\n",
    ];
    for source in sources {
        match Config::from_toml(&format!("default_profile = \"p\"\n{source}")) {
            Ok(config) => assert!(
                config.resolve_default().is_err(),
                "invalid command must fail"
            ),
            Err(error) => assert!(matches!(error, ConfigError::InvalidToml { .. })),
        }
    }

    let error = Config::from_toml(
        r#"
default_profile = "p"

[profiles.p.command]
program = "runner"

[profiles.p.command.environment]
set = { SAME = "value" }
remove = ["SAME"]
"#,
    )
    .expect_err("set/remove conflict");
    assert!(
        matches!(error, ConfigError::InvalidValue { field, .. } if field == "command.environment")
    );

    let error = Config::from_toml(
        "default_profile = \"p\"\n[profiles.p.command]\nprogram = \"runner\"\n[profiles.p.command.timeout]\nmode = \"unknown\"\n",
    )
    .expect_err("unknown timeout");
    assert!(matches!(error, ConfigError::InvalidToml { .. }));
}

#[test]
fn rejects_remaining_policy_and_command_builder_errors() {
    let root = absolute_path();
    let absolute = root.to_string_lossy();
    let sources = [
        (
            "[profiles.p.filesystem]\nrules = [{ target = \"absolute\", access = \"read\" }]\n",
            "required absolute path",
        ),
        (
            "[profiles.p.filesystem]\nrules = [{ target = \"absolute-glob\", access = \"read\" }]\n",
            "required absolute glob",
        ),
        (
            "[profiles.p.filesystem]\nrules = [{ target = \"absolute\", path = \"PLACEHOLDER\", pattern = \"oops\", access = \"read\" }]\n",
            "absolute scope pattern",
        ),
        (
            "[profiles.p.filesystem]\nrules = [{ target = \"unknown\", access = \"read\" }]\n",
            "unknown filesystem target",
        ),
        (
            "[profiles.p.filesystem]\nrules = [{ target = \"workspace-root\", access = \"unknown\" }]\n",
            "unknown filesystem access",
        ),
        (
            "[profiles.p.filesystem]\nrules = [{ target = \"workspace-root\", access = \"read\", missing_path = \"unknown\" }]\n",
            "unknown missing-path behavior",
        ),
        (
            "[profiles.p.filesystem]\nglob_scan_max_depth = 0\n",
            "zero glob depth",
        ),
        (
            "[profiles.p.filesystem]\nmode = \"unrestricted\"\nrules = [{ target = \"workspace-root\", access = \"read\" }]\n",
            "unrestricted filesystem rule",
        ),
        (
            "[profiles.p.filesystem]\nmode = \"unrestricted\"\nglob_scan_max_depth = 2\n",
            "unrestricted glob depth",
        ),
        (
            "[profiles.p.network]\nmode = \"unknown\"\n",
            "unknown network mode",
        ),
        (
            "[profiles.p.network]\ndomain_mode = \"unknown\"\n",
            "unknown domain mode",
        ),
        (
            "[profiles.p.network]\nunix_socket_mode = \"unknown\"\n",
            "unknown socket mode",
        ),
        (
            "[profiles.p.network]\nmode = \"enabled\"\ndomains = [{ pattern = \"example.com\", access = \"unknown\" }]\n",
            "unknown domain access",
        ),
        (
            "[profiles.p.network]\nmode = \"enabled\"\nunix_sockets = [{ path = \"relative.sock\", access = \"allow\" }]\n",
            "relative socket",
        ),
        (
            "[profiles.p.network]\nmode = \"enabled\"\nunix_sockets = [{ path = \"PLACEHOLDER\", access = \"unknown\" }]\n",
            "unknown socket access",
        ),
        (
            "[profiles.p.network]\nmode = \"enabled\"\ndomains = [{ pattern = \"\", access = \"allow\" }]\n",
            "empty domain",
        ),
        ("[profiles.p.command]\n", "missing command program"),
        (
            "[profiles.p.command]\nprogram = \"runner\"\n[profiles.p.command.environment]\ninherit = \"unknown\"\n",
            "unknown environment base",
        ),
        (
            "[profiles.p.command]\nprogram = \"runner\"\n[profiles.p.command.environment]\nremove = [\"\"]\n",
            "empty environment name",
        ),
        (
            "[profiles.p.command.environment]\nfilters = { \"\" = \"include\" }\n",
            "empty environment include pattern",
        ),
        (
            "[profiles.p.command.environment]\nfilters = { \"BAD=NAME\" = \"exclude\" }\n",
            "invalid environment exclude pattern",
        ),
        (
            "[profiles.p.command]\nprogram = \"runner\"\nargs = [\"\\u0000\"]\n",
            "NUL argument",
        ),
        (
            "[profiles.p.command]\nprogram = \"runner\"\n[profiles.p.command.timeout]\n",
            "missing timeout mode",
        ),
    ];

    for (source, label) in sources {
        let source = source.replace("PLACEHOLDER", absolute.as_ref());
        match Config::from_toml(&format!("default_profile = \"p\"\n{source}")) {
            Ok(config) => assert!(config.resolve_default().is_err(), "{label} should fail"),
            Err(error) => assert!(
                matches!(error, ConfigError::InvalidToml { .. }),
                "{label} should fail with a typed TOML value error: {error}"
            ),
        }
    }

    let error =
        Config::from_toml("default_profile = \"p\"\n[profiles.p.workspace_roots]\n\"\" = true\n")
            .expect_err("empty workspace root should fail validation");
    assert!(matches!(
        error,
        ConfigError::InvalidValue { field, .. } if field == "workspace_roots"
    ));
}

#[test]
fn config_errors_have_context_and_sources() {
    let errors = [
        ConfigError::InvalidToml {
            message: "bad syntax".to_owned(),
            location: None,
        },
        ConfigError::ReadFile {
            path: PathBuf::from("config.toml"),
            message: "missing".to_owned(),
        },
        ConfigError::InvalidProfileName {
            name: "bad.name".to_owned(),
        },
        ConfigError::UnknownProfile {
            name: "missing".to_owned(),
        },
        ConfigError::NoDefaultProfile,
        ConfigError::ProfileCycle {
            chain: vec!["a".to_owned(), "b".to_owned(), "a".to_owned()],
        },
        ConfigError::InvalidValue {
            profile: "safe".to_owned(),
            field: "filesystem.mode".to_owned(),
            value: "bad".to_owned(),
        },
        ConfigError::MissingCommandProgram {
            profile: "safe".to_owned(),
        },
        ConfigError::Policy {
            profile: "safe".to_owned(),
            source: cageforge_policy::PolicyError::EmptyPath,
        },
        ConfigError::Command {
            profile: "safe".to_owned(),
            source: cageforge_command::CommandError::EmptyProgram,
        },
    ];
    for error in &errors {
        assert!(!error.to_string().is_empty());
    }
    let expected_codes = [
        "invalid_toml",
        "config_file_unreadable",
        "invalid_profile_name",
        "unknown_profile",
        "missing_default_profile",
        "profile_inheritance_cycle",
        "invalid_value",
        "missing_command_program",
        "invalid_policy",
        "invalid_command",
    ];
    for (error, code) in errors.iter().zip(expected_codes) {
        let diagnostic = error.diagnostic();
        assert_eq!(diagnostic.code(), code);
        assert_eq!(diagnostic.severity(), DiagnosticSeverity::Error);
        assert_eq!(diagnostic.message(), error.to_string());
    }
    assert_eq!(errors[6].diagnostic().profile(), Some("safe"));
    assert_eq!(errors[6].diagnostic().field(), Some("filesystem.mode"));
    assert_eq!(errors[0].diagnostic().location(), None);
    let policy = ConfigError::Policy {
        profile: "safe".to_owned(),
        source: cageforge_policy::PolicyError::EmptyPath,
    };
    assert!(policy.source().is_some());
    let command = ConfigError::Command {
        profile: "safe".to_owned(),
        source: cageforge_command::CommandError::EmptyProgram,
    };
    assert!(command.source().is_some());
    assert!(ConfigError::NoDefaultProfile.source().is_none());
}

#[test]
fn exposes_json_schema_and_structured_diagnostics() {
    let schema = cageforge_config::config_schema_json().expect("schema serializes");
    let schema_json: serde_json::Value =
        serde_json::from_str(&schema).expect("schema is valid JSON");
    assert_eq!(schema_json["type"], "object");
    let schema_text = schema_json.to_string();
    assert!(schema_text.contains("workspace_roots"));
    assert!(schema_text.contains("root"));
    assert!(schema_text.contains("description"));
    assert!(schema_text.contains("filters"));

    let error = Config::from_toml("default_profile = [").expect_err("invalid TOML");
    let diagnostic = error.diagnostic();
    assert_eq!(diagnostic.code(), "invalid_toml");
    assert_eq!(diagnostic.severity(), DiagnosticSeverity::Error);
    assert!(diagnostic.location().is_some());
    let diagnostic_json: serde_json::Value =
        serde_json::from_str(&diagnostic.to_json().expect("diagnostic serializes"))
            .expect("diagnostic is valid JSON");
    assert_eq!(diagnostic_json["code"], "invalid_toml");
    assert_eq!(diagnostic_json["severity"], "error");

    let error = Config::from_toml(
        "default_profile = \"profile\"\n[profiles.profile.command]\nprogram = \"runner\"\n[profiles.profile.command.environment]\nfilters = { \"\" = \"include\" }\n",
    )
    .expect("invalid pattern source should parse")
    .resolve_default()
    .expect_err("invalid pattern should fail resolution");
    assert!(matches!(
        error,
        ConfigError::Command {
            source: CommandError::EmptyEnvironmentPattern,
            ..
        }
    ));
    let diagnostic = error.diagnostic();
    assert_eq!(diagnostic.code(), "invalid_command");
    assert_eq!(diagnostic.profile(), Some("profile"));
}
