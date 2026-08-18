use cageforge_config::{Config, ConfigError, DiagnosticSeverity, config_schema_json};
use proptest::prelude::*;
use serde_json::Value;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

fn profile_name() -> impl Strategy<Value = String> {
    prop::string::string_regex("[a-zA-Z][a-zA-Z0-9_-]{0,10}").expect("profile name regex")
}

fn description() -> impl Strategy<Value = Option<String>> {
    prop_oneof![
        Just(None),
        prop::string::string_regex("[a-zA-Z0-9 _-]{0,24}")
            .expect("description regex")
            .prop_map(Some),
        Just(Some("тест profile".to_owned())),
    ]
}

fn render_profile_config(
    name: &str,
    description: Option<&str>,
    absolute_root: bool,
    relative_root: bool,
) -> String {
    let description = description.map_or_else(String::new, |description| {
        format!("description = \"{description}\"\n")
    });
    format!(
        r#"
default_profile = "{name}"

[profiles.{name}]
{description}

[profiles.{name}.workspace_roots]
"/workspace/root" = {absolute_root}
"relative/workspace" = {relative_root}

[profiles.other]
"#
    )
}

struct TemporaryConfigFile(PathBuf);

impl Drop for TemporaryConfigFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn write_temporary_config(source: &str) -> TemporaryConfigFile {
    static NEXT_FILE: AtomicU64 = AtomicU64::new(0);
    let id = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "cageforge-config-proptest-{}-{id}.toml",
        std::process::id()
    ));
    std::fs::write(&path, source).expect("temporary config should be writable");
    TemporaryConfigFile(path)
}

fn diagnostic_case(kind: u8) -> (ConfigError, &'static str) {
    match kind {
        0 => (
            Config::from_toml("[").expect_err("malformed TOML should fail"),
            "invalid_toml",
        ),
        1 => (
            Config::from_toml("[profiles.safe]\n")
                .expect("profile should parse")
                .resolve_default()
                .expect_err("missing default should fail"),
            "missing_default_profile",
        ),
        2 => (
            Config::from_toml("default_profile = \"missing\"\n[profiles.safe]\n")
                .expect_err("unknown default should fail"),
            "unknown_profile",
        ),
        3 => (
            Config::from_toml("default_profile = \"command\"\n[profiles.command.command]\n")
                .expect("command profile should parse")
                .resolve_default()
                .expect_err("missing command program should fail"),
            "missing_command_program",
        ),
        4 => (
            Config::from_toml("default_profile = \"safe\"\n[profiles.safe]\n")
                .expect("profile should parse")
                .resolve("missing")
                .expect_err("unknown selected profile should fail"),
            "unknown_profile",
        ),
        _ => unreachable!("strategy only produces known diagnostic cases"),
    }
}

fn invalid_value_fragment(field: u8, value: &str) -> String {
    match field {
        0 => "[profiles.invalid.filesystem]\nmode = \"VALUE\"\n",
        1 => "[profiles.invalid.filesystem]\nrules = [{ target = \"workspace-root\", access = \"VALUE\" }]\n",
        2 => "[profiles.invalid.filesystem]\nrules = [{ target = \"VALUE\", access = \"deny\" }]\n",
        3 => "[profiles.invalid.network]\nmode = \"VALUE\"\n",
        4 => "[profiles.invalid.network]\ndomain_mode = \"VALUE\"\n",
        5 => "[profiles.invalid.network]\nunix_socket_mode = \"VALUE\"\n",
        6 => "[profiles.invalid.network]\ndomains = [{ pattern = \"example.com\", access = \"VALUE\" }]\n",
        7 => "[profiles.invalid.command]\nprogram = \"runner\"\n[profiles.invalid.command.environment]\ninherit = \"VALUE\"\n",
        8 => "[profiles.invalid.command]\nprogram = \"runner\"\n[profiles.invalid.command.stdio]\nstdin = \"VALUE\"\n",
        9 => "[profiles.invalid.command]\nprogram = \"runner\"\n[profiles.invalid.command.timeout]\nmode = \"VALUE\"\n",
        10 => "[profiles.invalid.command]\nprogram = \"runner\"\n[profiles.invalid.command.environment]\nfilters = { \"TOKEN\" = \"VALUE\" }\n",
        11 => "[profiles.invalid.filesystem]\nrules = [{ target = \"workspace-root\", missing_path = \"VALUE\", access = \"write\" }]\n",
        _ => unreachable!("strategy only produces known invalid fields"),
    }
    .replace("VALUE", value)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    #[test]
    fn profile_names_metadata_resolution_and_files_are_consistent(
        name in profile_name(),
        text in description(),
        absolute_root in any::<bool>(),
        relative_root in any::<bool>(),
    ) {
        let source = render_profile_config(name.as_str(), text.as_deref(), absolute_root, relative_root);
        let parsed = Config::from_toml(&source).expect("generated profile config should parse");
        let resolved_by_name = parsed.resolve(&name).expect("named profile should resolve");
        let resolved_default = parsed.resolve_default().expect("default profile should resolve");

        prop_assert_eq!(&resolved_by_name, &resolved_default);
        prop_assert_eq!(parsed.default_profile_name(), Some(name.as_str()));
        prop_assert!(parsed.profile_names().any(|profile| profile == name));
        prop_assert_eq!(resolved_default.description(), text.as_deref());
        prop_assert_eq!(
            resolved_default.workspace_roots().len(),
            usize::from(absolute_root) + usize::from(relative_root)
        );

        let file = write_temporary_config(&source);
        let from_file = Config::from_file(&file.0)
            .expect("generated config file should parse")
            .resolve_default()
            .expect("generated config file should resolve");
        prop_assert_eq!(&from_file, &resolved_default);
    }

    #[test]
    fn generated_valid_documents_are_accepted_by_the_schema(
        name in profile_name(),
        text in description(),
        absolute_root in any::<bool>(),
        relative_root in any::<bool>(),
    ) {
        let source = render_profile_config(name.as_str(), text.as_deref(), absolute_root, relative_root);
        Config::from_toml(&source).expect("generated schema fixture should be semantically valid");
        let toml_document = toml::from_str::<toml::Value>(&source)
            .expect("generated schema fixture should be TOML");
        let json_document = serde_json::to_value(toml_document)
            .expect("TOML fixture should convert to JSON");
        let schema = serde_json::from_str::<Value>(&config_schema_json().expect("schema should serialize"))
            .expect("schema should be JSON");
        let validator = jsonschema::validator_for(&schema).expect("schema should compile");

        prop_assert!(validator.is_valid(&json_document));
    }

    #[test]
    fn diagnostics_are_structured_for_every_generated_error(kind in 0u8..=4) {
        let (error, expected_code) = diagnostic_case(kind);
        let diagnostic = error.diagnostic();

        prop_assert_eq!(diagnostic.severity(), DiagnosticSeverity::Error);
        prop_assert_eq!(diagnostic.code(), expected_code);
        prop_assert!(!diagnostic.message().is_empty());
        let json = serde_json::from_str::<Value>(
            &diagnostic.to_json().expect("diagnostic should serialize")
        )
        .expect("diagnostic JSON should parse");
        prop_assert_eq!(json["code"].as_str(), Some(expected_code));
        prop_assert_eq!(json["severity"].as_str(), Some("error"));
    }

    #[test]
    fn invalid_enum_values_are_rejected(field in 0u8..=11, value in prop::sample::select(vec![
        "bogus", "WRITE", "not-a-mode", ""
    ])) {
        let fragment = invalid_value_fragment(field, value);
        let source = format!("default_profile = \"invalid\"\n\n[profiles.invalid]\n{fragment}");
        prop_assert!(Config::from_toml(&source).is_err());
    }

    #[test]
    fn invalid_profile_names_are_rejected(name in prop::sample::select(vec![
        "", "_bad", "-bad", "has space", "has.dot"
    ])) {
        let source = format!(
            "default_profile = \"safe\"\n[profiles.safe]\n[profiles.\"{name}\"]\n"
        );
        let error = Config::from_toml(&source).expect_err("invalid profile name should fail");
        let diagnostic = error.diagnostic();
        prop_assert_eq!(diagnostic.code(), "invalid_profile_name");
    }
}
