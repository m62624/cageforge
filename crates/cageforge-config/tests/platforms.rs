// SPDX-License-Identifier: Apache-2.0

use cageforge_config::{Config, ConfigError};
use cageforge_permissions::PlatformId;
use cageforge_permissions::{ApprovalPersistence, PermissionMode};

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
fn permission_inheritance_example_merges_approval_fields_before_platform_overlay() {
    let source = include_str!("../examples/permission-inheritance.toml");
    let config = Config::from_toml(source).expect("permission inheritance example");
    let linux = config
        .resolve_default_for_platform(PlatformId::Linux)
        .expect("Linux approval profile");
    assert_eq!(linux.approval().mode(), PermissionMode::Preflight);
    assert_eq!(linux.approval().timeout_ms(), 3000);
    assert_eq!(linux.approval().persistence(), ApprovalPersistence::Session);

    let windows = config
        .resolve_default_for_platform(PlatformId::Windows)
        .expect("Windows approval overlay");
    assert_eq!(windows.approval().mode(), PermissionMode::Disabled);
    assert_eq!(windows.approval().timeout_ms(), 3000);
    assert_eq!(
        windows.approval().persistence(),
        ApprovalPersistence::Session
    );
    assert_eq!(windows.workspace_roots().len(), 1);
}

#[test]
fn unknown_platform_names_are_rejected() {
    let error =
        Config::from_toml("[profiles.tool.platforms.freebsd]\ndescription = \"unsupported\"\n")
            .expect_err("unknown platform must not become an arbitrary string");
    assert!(error.to_string().contains("invalid TOML"));
}

#[test]
fn local_ipc_platform_overrides_select_native_endpoint_types() {
    let config = Config::from_toml(
        r#"
default_profile = "tool"

[profiles.tool.platforms.linux.local_ipc]
unix_sockets = ["/run/linux-service.sock"]

[profiles.tool.platforms.macos.local_ipc]
unix_sockets = ["/var/run/macos-service.sock"]

[profiles.tool.platforms.windows.local_ipc]
named_pipes = ["\\\\.\\pipe\\windows-service"]
"#,
    )
    .expect("local IPC configuration");

    let linux = config
        .resolve_default_for_platform(PlatformId::Linux)
        .expect("Linux profile");
    assert_eq!(linux.policy().network().local_ipc().len(), 1);
    assert!(
        linux.policy().network().local_ipc()[0]
            .endpoint()
            .unix_path()
            .is_some()
    );

    let windows = config
        .resolve_default_for_platform(PlatformId::Windows)
        .expect("Windows profile");
    assert_eq!(windows.policy().network().local_ipc().len(), 1);
    assert!(
        windows.policy().network().local_ipc()[0]
            .endpoint()
            .named_pipe()
            .is_some()
    );
}

#[test]
fn macos_runtime_roots_are_selected_only_by_the_macos_overlay() {
    let config = Config::from_toml(
        r#"
default_profile = "tool"

[profiles.tool.platforms.macos.runtime]
executable_roots = ["/opt/example-runtime"]
"#,
    )
    .expect("runtime-root configuration");

    assert_eq!(
        config
            .resolve_default_for_platform(PlatformId::Macos)
            .expect("macOS profile")
            .executable_roots(),
        &[std::path::PathBuf::from("/opt/example-runtime")]
    );
    assert!(
        config
            .resolve_default_for_platform(PlatformId::Linux)
            .expect("Linux profile")
            .executable_roots()
            .is_empty()
    );
}

#[test]
fn platform_runtime_overlays_validate_their_target_path_syntax() {
    let config = Config::from_toml(
        r#"
default_profile = "tool"

[profiles.tool.platforms.macos.runtime]
executable_roots = ["/opt/example-runtime"]

[profiles.tool.platforms.windows.runtime]
executable_roots = ["C:/Program Files/example-runtime"]
"#,
    )
    .expect("target platform runtime paths should parse on every host");

    assert_eq!(
        config
            .resolve_default_for_platform(PlatformId::Macos)
            .expect("macOS runtime path")
            .executable_roots(),
        &[std::path::PathBuf::from("/opt/example-runtime")]
    );
    assert_eq!(
        config
            .resolve_default_for_platform(PlatformId::Windows)
            .expect("Windows runtime path")
            .executable_roots(),
        &[std::path::PathBuf::from("C:/Program Files/example-runtime")]
    );
}

#[test]
fn runtime_roots_require_absolute_unique_safe_paths() {
    for source in [
        "[profiles.tool.runtime]\nexecutable_roots = [\"runtime\"]\n",
        "[profiles.tool.runtime]\nexecutable_roots = [\"/opt/../runtime\"]\n",
        "[profiles.tool.runtime]\nexecutable_roots = [\"/opt/runtime\", \"/opt/runtime/\"]\n",
    ] {
        let error = Config::from_toml(source).expect_err("unsafe runtime root must be rejected");
        assert!(matches!(error, ConfigError::InvalidValue { .. }));
    }
}
