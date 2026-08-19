// SPDX-License-Identifier: Apache-2.0

use cageforge_command::{EnvironmentBase, StdioMode, StdioSpec, TimeoutPolicy};
use cageforge_config::Config;
use cageforge_policy::{
    AccessMode, FilesystemDecision, NetworkDecision, NetworkMode, PathResolutionContext,
};
use proptest::prelude::*;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

fn filesystem_mode() -> impl Strategy<Value = &'static str> {
    prop_oneof![Just("restricted"), Just("unrestricted"), Just("external")]
}

fn access_mode() -> impl Strategy<Value = &'static str> {
    prop_oneof![Just("read"), Just("write"), Just("deny")]
}

fn network_mode() -> impl Strategy<Value = &'static str> {
    prop_oneof![Just("disabled"), Just("enabled"), Just("external")]
}

fn domain_mode() -> impl Strategy<Value = &'static str> {
    prop_oneof![Just("disabled"), Just("enabled"), Just("restricted")]
}

fn unix_socket_mode() -> impl Strategy<Value = &'static str> {
    prop_oneof![Just("disabled"), Just("enabled"), Just("restricted")]
}

fn environment_base() -> impl Strategy<Value = &'static str> {
    prop_oneof![Just("all"), Just("core"), Just("none")]
}

fn stdio_mode() -> impl Strategy<Value = &'static str> {
    prop_oneof![Just("inherit"), Just("null"), Just("pipe")]
}

fn timeout_mode() -> impl Strategy<Value = &'static str> {
    prop_oneof![Just("backend-default"), Just("limit"), Just("disabled")]
}

fn access_value(value: &str) -> AccessMode {
    match value {
        "read" => AccessMode::Read,
        "write" => AccessMode::Write,
        "deny" => AccessMode::Deny,
        _ => unreachable!("strategy only produces known access modes"),
    }
}

fn filesystem_root() -> PathBuf {
    #[cfg(windows)]
    {
        PathBuf::from(r"C:\sandbox\workspace")
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("/sandbox/workspace")
    }
}

fn socket_path(name: &str) -> String {
    #[cfg(windows)]
    {
        format!("C:/sandbox/{name}.sock")
    }
    #[cfg(not(windows))]
    {
        format!("/sandbox/{name}.sock")
    }
}

fn render_filesystem_config(mode: &str, access: &str, git_opt_out: bool, carveout: bool) -> String {
    if mode == "restricted" {
        let carveout = if access == "write" && carveout {
            ", read_only_subpaths = [{ target = \"workspace\", path = \"readonly\" }]"
        } else {
            ""
        };
        let security = if git_opt_out {
            "\n[profiles.fs.filesystem.security]\ndangerously_allow_git_write = true\n"
        } else {
            ""
        };
        format!(
            r#"
default_profile = "fs"

[profiles.fs.filesystem]
mode = "restricted"
glob_scan_max_depth = 4
additional_protected_paths = ["metadata"]
rules = [
  {{ target = "workspace-root", access = "{access}"{carveout} }},
  {{ target = "workspace-glob", pattern = "blocked/*.secret", access = "deny" }},
]
{security}"#
        )
    } else {
        format!(
            r#"
default_profile = "fs"

[profiles.fs.filesystem]
mode = "{mode}"
"#
        )
    }
}

fn render_network_config(mode: &str, domain: &str, socket: &str) -> String {
    let local_policy = if mode == "external" {
        String::new()
    } else {
        format!(
            "domain_mode = \"{domain}\"\nunix_socket_mode = \"{socket}\"\ndomains = [\n  {{ pattern = \"EXAMPLE.COM:443\", access = \"allow\" }},\n  {{ pattern = \"blocked.example.com\", access = \"deny\" }},\n]\nunix_sockets = [{{ path = \"{}\", access = \"allow\" }}]\n",
            socket_path("allowed")
        )
    };
    format!(
        r#"
default_profile = "network"

[profiles.network.network]
mode = "{mode}"
{local_policy}"#
    )
}

fn render_command_config(
    base: &str,
    stdin: &str,
    stdout: &str,
    stderr: &str,
    timeout: &str,
    milliseconds: u64,
) -> String {
    let timeout_value = if timeout == "limit" {
        format!("milliseconds = {milliseconds}\n")
    } else {
        String::new()
    };
    format!(
        r#"
default_profile = "command"

[profiles.command.command]
program = "runner"
args = ["--bounded", "value"]
working_directory = "work"

[profiles.command.command.environment]
inherit = "{base}"

[profiles.command.command.stdio]
stdin = "{stdin}"
stdout = "{stdout}"
stderr = "{stderr}"

[profiles.command.command.timeout]
mode = "{timeout}"
{timeout_value}"#
    )
}

fn expected_stdio(value: &str) -> StdioMode {
    match value {
        "inherit" => StdioMode::Inherit,
        "null" => StdioMode::Null,
        "pipe" => StdioMode::Pipe,
        _ => unreachable!("strategy only produces known stdio modes"),
    }
}

fn expected_timeout(value: &str, milliseconds: u64) -> TimeoutPolicy {
    match value {
        "backend-default" => TimeoutPolicy::BackendDefault,
        "limit" => TimeoutPolicy::Limit(Duration::from_millis(milliseconds)),
        "disabled" => TimeoutPolicy::Disabled,
        _ => unreachable!("strategy only produces known timeout modes"),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    #[test]
    fn filesystem_modes_preserve_protection_and_blocking(
        mode in filesystem_mode(),
        access in access_mode(),
        git_opt_out in any::<bool>(),
        carveout in any::<bool>(),
    ) {
        let source = render_filesystem_config(mode, access, git_opt_out, carveout);
        let policy = Config::from_toml(&source)
            .expect("generated filesystem config should parse")
            .resolve_default()
            .expect("generated filesystem config should resolve")
            .policy()
            .clone();
        let workspace = filesystem_root();
        let context = PathResolutionContext::new()
            .with_workspace_root(workspace.clone())
            .expect("workspace root should be absolute");
        let normal = workspace.join("project/file.txt");
        let git = workspace.join(".git/config");
        let metadata = workspace.join("metadata/state");
        let blocked = workspace.join("blocked/file.secret");
        let readonly = workspace.join("readonly/file.txt");

        match mode {
            "unrestricted" => {
                prop_assert_eq!(policy.filesystem().mode(), cageforge_policy::FilesystemMode::Unrestricted);
                prop_assert_eq!(policy.filesystem().access_for_path(&normal, &context).unwrap(), FilesystemDecision::Write);
            }
            "external" => {
                prop_assert_eq!(policy.filesystem().mode(), cageforge_policy::FilesystemMode::External);
                prop_assert_eq!(policy.filesystem().access_for_path(&normal, &context).unwrap(), FilesystemDecision::ExternallyEnforced);
            }
            "restricted" => {
                let expected = access_value(access);
                prop_assert_eq!(policy.filesystem().mode(), cageforge_policy::FilesystemMode::Restricted);
                prop_assert_eq!(policy.filesystem().access_for_path(&normal, &context).unwrap(), expected.into());
                prop_assert_eq!(policy.filesystem().access_for_path(&blocked, &context).unwrap(), FilesystemDecision::Deny);

                let expected_git = if expected == AccessMode::Write && !git_opt_out {
                    FilesystemDecision::Read
                } else {
                    expected.into()
                };
                prop_assert_eq!(policy.filesystem().access_for_path(&git, &context).unwrap(), expected_git);
                prop_assert_eq!(policy.filesystem().access_for_path(&metadata, &context).unwrap(), if expected == AccessMode::Write {
                    FilesystemDecision::Read
                } else {
                    expected.into()
                });

                let expected_readonly = if expected == AccessMode::Write && carveout {
                    FilesystemDecision::Read
                } else {
                    expected.into()
                };
                prop_assert_eq!(policy.filesystem().access_for_path(&readonly, &context).unwrap(), expected_readonly);
            }
            _ => unreachable!("strategy only produces known filesystem modes"),
        }
    }

    #[test]
    fn network_modes_preserve_allow_deny_and_external_ownership(
        mode in network_mode(),
        domain in domain_mode(),
        socket in unix_socket_mode(),
    ) {
        let source = render_network_config(mode, domain, socket);
        let policy = Config::from_toml(&source)
            .expect("generated network config should parse")
            .resolve_default()
            .expect("generated network config should resolve")
            .policy()
            .clone();
        let allowed_socket = PathBuf::from(socket_path("allowed"));
        let unknown_socket = PathBuf::from(socket_path("unknown"));

        let expected_domain = |name: &str| {
            if mode == "external" {
                NetworkDecision::ExternallyEnforced
            } else if mode == "disabled"
                || domain == "disabled"
                || name == "blocked.example.com"
            {
                NetworkDecision::Deny
            } else if name == "example.com:443" || domain == "enabled" {
                NetworkDecision::Allow
            } else {
                NetworkDecision::Deny
            }
        };
        let expected_socket = |allowed: bool| {
            if mode == "external" {
                NetworkDecision::ExternallyEnforced
            } else if mode == "disabled" || socket == "disabled" {
                NetworkDecision::Deny
            } else if allowed || socket == "enabled" {
                NetworkDecision::Allow
            } else {
                NetworkDecision::Deny
            }
        };

        prop_assert_eq!(policy.network().mode(), match mode {
            "disabled" => NetworkMode::Disabled,
            "enabled" => NetworkMode::Enabled,
            "external" => NetworkMode::External,
            _ => unreachable!("strategy only produces known network modes"),
        });
        prop_assert_eq!(policy.network().decision_for_domain("example.com:443").unwrap(), expected_domain("example.com:443"));
        prop_assert_eq!(policy.network().decision_for_domain("blocked.example.com").unwrap(), expected_domain("blocked.example.com"));
        prop_assert_eq!(policy.network().decision_for_domain("unknown.example").unwrap(), expected_domain("unknown.example"));
        prop_assert_eq!(policy.network().decision_for_unix_socket(&allowed_socket).unwrap(), expected_socket(true));
        prop_assert_eq!(policy.network().decision_for_unix_socket(&unknown_socket).unwrap(), expected_socket(false));
    }

    #[test]
    fn command_variants_are_not_lost_in_toml_mapping(
        base in environment_base(),
        stdin in stdio_mode(),
        stdout in stdio_mode(),
        stderr in stdio_mode(),
        timeout in timeout_mode(),
        milliseconds in 1u64..=5000,
    ) {
        let source = render_command_config(base, stdin, stdout, stderr, timeout, milliseconds);
        let command = Config::from_toml(&source)
            .expect("generated command config should parse")
            .resolve_default()
            .expect("generated command config should resolve")
            .command()
            .cloned()
            .expect("generated command should exist");
        let expected_base = match base {
            "all" => EnvironmentBase::All,
            "core" => EnvironmentBase::Core,
            "none" => EnvironmentBase::None,
            _ => unreachable!("strategy only produces known environment bases"),
        };
        let expected_stdio = StdioSpec::new(
            expected_stdio(stdin),
            expected_stdio(stdout),
            expected_stdio(stderr),
        );

        prop_assert_eq!(command.command().program(), Path::new("runner").as_os_str());
        prop_assert_eq!(
            command.command().args(),
            &[OsString::from("--bounded"), OsString::from("value")]
        );
        prop_assert_eq!(command.environment().base(), expected_base);
        prop_assert_eq!(command.stdio(), expected_stdio);
        prop_assert_eq!(command.timeout_policy(), expected_timeout(timeout, milliseconds));
    }
}
