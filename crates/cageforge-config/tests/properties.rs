// SPDX-License-Identifier: Apache-2.0

use cageforge_command::{EnvironmentFilterAction, EnvironmentSpec};
use cageforge_config::{Config, ConfigError};
use cageforge_policy::AccessMode;
use proptest::prelude::*;
use std::ffi::OsString;

fn access_mode() -> impl Strategy<Value = &'static str> {
    prop_oneof![Just("read"), Just("write"), Just("deny")]
}

fn filter_action() -> impl Strategy<Value = &'static str> {
    prop_oneof![Just("include"), Just("exclude")]
}

fn filter_action_value(value: &str) -> EnvironmentFilterAction {
    match value {
        "include" => EnvironmentFilterAction::Include,
        "exclude" => EnvironmentFilterAction::Exclude,
        _ => unreachable!("strategy only produces known filter actions"),
    }
}

fn access_mode_value(value: &str) -> AccessMode {
    match value {
        "read" => AccessMode::Read,
        "write" => AccessMode::Write,
        "deny" => AccessMode::Deny,
        _ => unreachable!("strategy only produces known access modes"),
    }
}

fn render_bounded_config(
    profile_count: usize,
    access: &str,
    network_enabled: bool,
    command_enabled: bool,
    root_enabled: bool,
) -> String {
    let last_profile = profile_count - 1;
    let mut source = format!("default_profile = \"p{last_profile}\"\n\n");

    for index in 0..profile_count {
        source.push_str(&format!("[profiles.p{index}]\n"));
        if index > 0 {
            source.push_str(&format!("inherits = [\"p{}\"]\n", index - 1));
        }
        source.push_str(&format!(
            "\n[profiles.p{index}.filesystem]\nmode = \"restricted\"\nrules = [{{ target = \"workspace-root\", access = \"{access}\" }}]\n"
        ));

        if network_enabled && index == last_profile {
            source.push_str(&format!(
                "\n[profiles.p{index}.network]\nmode = \"enabled\"\ndomain_mode = \"restricted\"\ndomains = [\n  {{ pattern = \"example.com\", access = \"allow\" }},\n  {{ pattern = \"blocked.example.com\", access = \"deny\" }},\n]\n"
            ));
        }

        if command_enabled && index == 0 {
            source.push_str(&format!(
                "\n[profiles.p{index}.command]\nprogram = \"runner\"\nargs = [\"--bounded\"]\n\n[profiles.p{index}.command.environment]\ninherit = \"none\"\nset = {{ MODE = \"safe\" }}\n"
            ));
        }
    }

    source.push_str(&format!(
        "\n[profiles.p{last_profile}.workspace_roots]\n\"/workspace/enabled\" = {root_enabled}\n\"relative/workspace\" = true\n"
    ));
    source
}

fn render_environment_config(token_action: &str, path_action: &str) -> String {
    format!(
        r#"
default_profile = "environment"

[profiles.environment.command]
program = "runner"

[profiles.environment.command.environment]
inherit = "all"
filters = {{ "*TOKEN*" = "{token_action}", "PATH" = "{path_action}" }}
set = {{ PATH = "/custom/bin", ACCESS_TOKEN = "explicitly-restored" }}
remove = ["REMOVE_ME"]
"#
    )
}

fn sample_environment() -> Vec<(OsString, OsString)> {
    vec![
        (OsString::from("PATH"), OsString::from("/usr/bin")),
        (
            OsString::from("ACCESS_TOKEN"),
            OsString::from("inherited-secret"),
        ),
        (OsString::from("HOME"), OsString::from("/home/user")),
        (OsString::from("REMOVE_ME"), OsString::from("old")),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    #[test]
    fn bounded_profiles_resolve_deterministically(
        profile_count in 1usize..=4,
        access in access_mode(),
        network_enabled in any::<bool>(),
        command_enabled in any::<bool>(),
        root_enabled in any::<bool>(),
    ) {
        let source = render_bounded_config(
            profile_count,
            access,
            network_enabled,
            command_enabled,
            root_enabled,
        );
        let config = Config::from_toml(&source).expect("generated config should parse");
        let first = config.resolve_default().expect("generated config should resolve");
        let second = config.resolve_default().expect("resolution should be repeatable");

        prop_assert_eq!(&first, &second);
        prop_assert_eq!(config.profile_names().count(), profile_count);
        prop_assert_eq!(first.workspace_roots().len(), 1 + usize::from(root_enabled));
        prop_assert_eq!(first.policy().filesystem().entries()[0].access(), access_mode_value(access));
        prop_assert_eq!(first.command().is_some(), command_enabled);
        prop_assert_eq!(first.policy().network().mode(), if network_enabled {
            cageforge_policy::NetworkMode::Enabled
        } else {
            cageforge_policy::NetworkMode::Disabled
        });
    }

    #[test]
    fn inheritance_graphs_are_bounded_and_cycles_are_typed(
        cycle in any::<bool>(),
        shared_ancestor in any::<bool>(),
    ) {
        let source = if cycle {
            r#"
default_profile = "first"
[profiles.first]
inherits = ["second"]
[profiles.second]
inherits = ["first"]
"#.to_owned()
        } else if shared_ancestor {
            r#"
default_profile = "leaf"
[profiles.base]
[profiles.left]
inherits = ["base"]
[profiles.right]
inherits = ["base"]
[profiles.leaf]
inherits = ["left", "right"]
"#.to_owned()
        } else {
            r#"
default_profile = "leaf"
[profiles.base]
[profiles.leaf]
inherits = ["base"]
"#.to_owned()
        };

        let result = Config::from_toml(&source)
            .expect("bounded inheritance fixture should parse")
            .resolve_default();
        if cycle {
            let is_cycle = matches!(result, Err(ConfigError::ProfileCycle { .. }));
            prop_assert!(is_cycle);
        } else {
            prop_assert!(result.is_ok());
        }
    }

    #[test]
    fn environment_config_matches_the_direct_environment_model(
        token_action in filter_action(),
        path_action in filter_action(),
    ) {
        let source = render_environment_config(token_action, path_action);
        let resolved = Config::from_toml(&source)
            .expect("generated environment config should parse")
            .resolve_default()
            .expect("generated environment config should resolve");

        let expected = EnvironmentSpec::inherit_all()
            .with_filter("*TOKEN*", filter_action_value(token_action))
            .expect("token filter")
            .with_filter("PATH", filter_action_value(path_action))
            .expect("path filter")
            .with_var("PATH", "/custom/bin")
            .expect("path override")
            .with_var("ACCESS_TOKEN", "explicitly-restored")
            .expect("token override")
            .without_var("REMOVE_ME")
            .expect("remove override");
        let actual = resolved.command().expect("generated command").environment();

        prop_assert_eq!(actual, &expected);
        prop_assert_eq!(actual.apply_to(sample_environment()), expected.apply_to(sample_environment()));
    }

    #[test]
    fn unsafe_working_directories_never_resolve(path in prop_oneof![
        Just("../outside"),
        Just("nested/../../outside"),
        Just("..\\outside"),
        Just("bad\0path"),
    ]) {
        let source = format!(
            r#"
default_profile = "unsafe"
[profiles.unsafe.command]
program = "runner"
working_directory = "{path}"
"#
        );
        let result = Config::from_toml(&source).and_then(|config| config.resolve_default());
        prop_assert!(result.is_err());
    }
}
