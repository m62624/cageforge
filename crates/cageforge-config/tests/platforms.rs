// SPDX-License-Identifier: Apache-2.0

use cageforge_config::Config;
use cageforge_permissions::PermissionMode;
use cageforge_permissions::PlatformId;

#[test]
fn one_document_selects_the_named_platform_overlay() {
    let config = Config::from_toml(
        r#"
default_profile = "tool"

[profiles.tool]
description = "portable"

[profiles.tool.platforms.linux]
description = "linux"

[profiles.tool.platforms.macos]
description = "macos"

[profiles.tool.platforms.windows]
description = "windows"
"#,
    )
    .expect("platform profile should parse");

    assert_eq!(
        config
            .resolve_for_platform("tool", PlatformId::Linux)
            .unwrap()
            .description(),
        Some("linux")
    );
    assert_eq!(
        config
            .resolve_for_platform("tool", PlatformId::Macos)
            .unwrap()
            .description(),
        Some("macos")
    );
    assert_eq!(
        config
            .resolve_default_for_platform(PlatformId::Windows)
            .unwrap()
            .description(),
        Some("windows")
    );
    assert_eq!(
        config.resolve("tool").unwrap().description(),
        Some("portable")
    );
}

#[test]
fn platform_overlays_inherit_and_child_values_win() {
    let config = Config::from_toml(
        r#"
[profiles.parent.platforms.linux]
description = "parent-linux"

[profiles.child]
inherits = ["parent"]

[profiles.child.platforms.linux]
description = "child-linux"
"#,
    )
    .expect("inherited platform profile should parse");

    assert_eq!(
        config
            .resolve_for_platform("child", PlatformId::Linux)
            .unwrap()
            .description(),
        Some("child-linux")
    );
}

#[test]
fn approval_settings_are_typed_and_platform_overridable() {
    let config = Config::from_toml(
        r#"
default_profile = "tool"

[profiles.tool]

[profiles.tool.approval]
mode = "preflight"
timeout_ms = 5000
on_timeout = "deny"
persistence = "persistent"

[profiles.tool.platforms.windows.approval]
mode = "disabled"
"#,
    )
    .unwrap();

    assert_eq!(
        config
            .resolve_default_for_platform(PlatformId::Linux)
            .unwrap()
            .approval()
            .mode(),
        PermissionMode::Preflight
    );
    assert_eq!(
        config
            .resolve_default_for_platform(PlatformId::Windows)
            .unwrap()
            .approval()
            .mode(),
        PermissionMode::Disabled
    );
}

#[test]
fn unknown_platform_names_are_rejected() {
    let error =
        Config::from_toml("[profiles.tool.platforms.freebsd]\ndescription = \"unsupported\"\n")
            .expect_err("unknown platform must not become an arbitrary string");
    assert!(error.to_string().contains("invalid TOML"));
}
