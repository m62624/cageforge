use cageforge_config::Config;
use cageforge_policy::{DomainAccess, NetworkDecision};
use proptest::prelude::*;
use std::path::PathBuf;

fn domain_kind() -> impl Strategy<Value = u8> {
    0u8..=6
}

fn domain_label() -> impl Strategy<Value = String> {
    prop::string::string_regex("[a-z][a-z0-9]{0,5}").expect("domain label regex")
}

fn domain_base() -> impl Strategy<Value = String> {
    prop::collection::vec(domain_label(), 1..=2)
        .prop_map(|labels| format!("{}.example.test", labels.join(".")))
}

fn domain_case(kind: u8, base: &str) -> (String, String, String) {
    match kind {
        0 => (
            format!("{base}:443").to_uppercase(),
            format!("{base}:8443").to_uppercase(),
            base.to_owned(),
        ),
        1 => (
            "[2001:db8::1]:443".to_owned(),
            "[2001:DB8::1]:8443".to_owned(),
            "2001:db8::1".to_owned(),
        ),
        2 => (format!("{base}."), format!("{base}."), base.to_owned()),
        3 => (
            format!("*.{base}"),
            format!("api.{base}"),
            format!("*.{base}"),
        ),
        4 => (format!("**.{base}"), base.to_owned(), format!("**.{base}")),
        5 => (
            format!("api?.{base}"),
            format!("api1.{base}"),
            format!("api?.{base}"),
        ),
        6 => (
            format!("api*.{base}"),
            format!("api-v1.{base}"),
            format!("api*.{base}"),
        ),
        _ => unreachable!("strategy only produces known domain patterns"),
    }
}

fn socket_path(kind: u8, name: &str) -> String {
    let suffix = match kind {
        0 => format!("{name}.sock"),
        1 => format!("nested/{name}.sock"),
        2 => format!("тест/{name}.sock"),
        3 => name.to_owned(),
        _ => unreachable!("strategy only produces known socket paths"),
    };
    #[cfg(windows)]
    {
        format!("C:/cageforge/{suffix}")
    }
    #[cfg(not(windows))]
    {
        format!("/cageforge/{suffix}")
    }
}

fn render_domain_config(pattern: &str, domain_mode: &str) -> String {
    format!(
        r#"
default_profile = "network"

[profiles.network.network]
mode = "enabled"
domain_mode = "{domain_mode}"
domains = [
  {{ pattern = "{pattern}", access = "allow" }},
  {{ pattern = "blocked.example.com", access = "deny" }},
]
"#
    )
}

fn render_socket_config(path: &str, socket_mode: &str) -> String {
    format!(
        r#"
default_profile = "network"

[profiles.network.network]
mode = "enabled"
unix_socket_mode = "{socket_mode}"
unix_sockets = [{{ path = "{path}", access = "allow" }}]
"#
    )
}

fn socket_query(kind: u8, path: &str) -> PathBuf {
    match kind {
        0..=2 => PathBuf::from(path),
        3 => PathBuf::from(path).join("child.sock"),
        _ => unreachable!("strategy only produces known socket paths"),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    #[test]
    fn domain_patterns_normalize_and_keep_deny_precedence(
        kind in domain_kind(),
        base in domain_base(),
        domain_mode in prop::sample::select(vec!["disabled", "enabled", "restricted"]),
    ) {
        let (pattern, query, normalized) = domain_case(kind, &base);
        let resolved = Config::from_toml(&render_domain_config(&pattern, domain_mode))
            .expect("generated domain config should parse")
            .resolve_default()
            .expect("generated domain config should resolve");
        let network = resolved.policy().network();
        let expected_query = if domain_mode == "disabled" {
            NetworkDecision::Deny
        } else {
            NetworkDecision::Allow
        };

        prop_assert_eq!(network.domains()[0].pattern(), normalized);
        prop_assert_eq!(network.domains()[0].access(), DomainAccess::Allow);
        prop_assert_eq!(network.decision_for_domain(&query).unwrap(), expected_query);
        prop_assert_eq!(network.decision_for_domain("blocked.example.com").unwrap(), NetworkDecision::Deny);
        prop_assert_eq!(network.decision_for_domain("unknown.invalid").unwrap(), if domain_mode == "enabled" {
            NetworkDecision::Allow
        } else {
            NetworkDecision::Deny
        });
    }

    #[test]
    fn unix_socket_paths_are_normalized_and_evaluated(
        kind in 0u8..=3,
        name in prop::string::string_regex("[a-z][a-z0-9_-]{0,7}").expect("socket name regex"),
        socket_mode in prop::sample::select(vec!["disabled", "enabled", "restricted"]),
    ) {
        let path = socket_path(kind, &name);
        let resolved = Config::from_toml(&render_socket_config(&path, socket_mode))
            .expect("generated socket config should parse")
            .resolve_default()
            .expect("generated socket config should resolve");
        let network = resolved.policy().network();
        let query = socket_query(kind, &path);
        let declared = PathBuf::from(&path);
        let unknown = declared.with_file_name("unknown.sock");
        let expected = if socket_mode == "disabled" {
            NetworkDecision::Deny
        } else {
            NetworkDecision::Allow
        };
        let expected_unknown = if socket_mode == "enabled" {
            NetworkDecision::Allow
        } else {
            NetworkDecision::Deny
        };

        prop_assert_eq!(network.unix_sockets().len(), 1);
        prop_assert_eq!(network.unix_sockets()[0].path(), declared.as_path());
        prop_assert_eq!(network.decision_for_unix_socket(&query).unwrap(), expected);
        prop_assert_eq!(
            network.decision_for_unix_socket(&unknown).unwrap(),
            expected_unknown
        );
    }
}
