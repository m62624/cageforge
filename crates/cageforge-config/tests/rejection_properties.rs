use cageforge_config::Config;
use proptest::prelude::*;

fn access_mode() -> impl Strategy<Value = &'static str> {
    prop_oneof![Just("read"), Just("write"), Just("deny")]
}

fn non_local_filesystem_mode() -> impl Strategy<Value = &'static str> {
    prop_oneof![Just("unrestricted"), Just("external")]
}

fn timeout_mode() -> impl Strategy<Value = &'static str> {
    prop_oneof![Just("backend-default"), Just("limit"), Just("disabled")]
}

fn render_glob_config(access: &str) -> String {
    format!(
        r#"
default_profile = "policy"

[profiles.policy.filesystem]
mode = "restricted"
rules = [{{ target = "workspace-glob", pattern = "target/*.secret", access = "{access}" }}]
"#
    )
}

fn render_carveout_config(access: &str) -> String {
    format!(
        r#"
default_profile = "policy"

[profiles.policy.filesystem]
mode = "restricted"
rules = [{{
  target = "workspace-root",
  access = "{access}",
  read_only_subpaths = [{{ target = "workspace", path = "readonly" }}]
}}]
"#
    )
}

fn render_non_local_filesystem_config(mode: &str) -> String {
    format!(
        r#"
default_profile = "policy"

[profiles.policy.filesystem]
mode = "{mode}"
rules = [{{ target = "workspace-root", access = "write" }}]
"#
    )
}

fn render_external_network_config(with_rules: bool) -> String {
    let rules = if with_rules {
        "domains = [{ pattern = \"example.com\", access = \"allow\" }]\n"
    } else {
        ""
    };
    format!(
        r#"
default_profile = "network"

[profiles.network.network]
mode = "external"
{rules}"#
    )
}

fn render_timeout_config(mode: &str, include_milliseconds: bool) -> String {
    let milliseconds = if include_milliseconds {
        "milliseconds = 1000\n"
    } else {
        ""
    };
    format!(
        r#"
default_profile = "command"

[profiles.command.command]
program = "runner"

[profiles.command.command.timeout]
mode = "{mode}"
{milliseconds}"#
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    #[test]
    fn filesystem_rule_boundaries_accept_only_safe_combinations(access in access_mode()) {
        let glob_result = Config::from_toml(&render_glob_config(access))
            .and_then(|config| config.resolve_default());
        prop_assert_eq!(glob_result.is_ok(), access == "deny");

        let carveout_result = Config::from_toml(&render_carveout_config(access))
            .and_then(|config| config.resolve_default());
        prop_assert_eq!(carveout_result.is_ok(), access == "write");
    }

    #[test]
    fn local_filesystem_rules_cannot_escape_non_local_ownership(mode in non_local_filesystem_mode()) {
        let result = Config::from_toml(&render_non_local_filesystem_config(mode))
            .and_then(|config| config.resolve_default());
        prop_assert!(result.is_err());
    }

    #[test]
    fn external_network_rejects_local_rules(with_rules in any::<bool>()) {
        let result = Config::from_toml(&render_external_network_config(with_rules))
            .and_then(|config| config.resolve_default());
        prop_assert_eq!(result.is_ok(), !with_rules);
    }

    #[test]
    fn timeout_milliseconds_are_restricted_to_limit_mode(
        mode in timeout_mode(),
        include_milliseconds in any::<bool>(),
    ) {
        let result = Config::from_toml(&render_timeout_config(mode, include_milliseconds))
            .and_then(|config| config.resolve_default());
        prop_assert_eq!(result.is_ok(), (mode == "limit") == include_milliseconds);
    }
}
