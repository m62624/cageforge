// SPDX-License-Identifier: Apache-2.0

use cageforge::{CommandSpec, SandboxPolicy};

#[test]
fn portable_types_and_facade_traits_are_available_from_the_root_crate() {
    let command = CommandSpec::new("cargo").expect("valid command");
    let _policy = SandboxPolicy::workspace();
    let _gateway_config = cageforge::GatewayConfig::new();
    assert_eq!(command.program(), "cargo");
}

#[cfg(feature = "network-runtime")]
#[test]
fn network_runtime_public_api_is_available_from_the_root_crate() {
    use cageforge::{NetworkGateway, NetworkResolver, SystemResolver};

    fn assert_resolver<R: NetworkResolver>() {}

    let _: Option<NetworkGateway<SystemResolver>> = None;
    assert_resolver::<SystemResolver>();
}

#[cfg(all(feature = "linux", target_os = "linux"))]
#[test]
fn linux_backend_implements_the_unified_facade_contract() {
    use cageforge::{Sandbox, SandboxChild};

    fn assert_sandbox<B: Sandbox + cageforge::DynSandbox>() {}
    fn assert_child<C: SandboxChild>() {}

    assert_sandbox::<cageforge::LinuxBackend>();
    assert_child::<cageforge::LinuxChild>();
}

#[cfg(all(feature = "windows", target_os = "windows"))]
#[test]
fn windows_backend_implements_the_unified_facade_contract() {
    use cageforge::{Sandbox, SandboxChild};

    fn assert_sandbox<B: Sandbox + cageforge::DynSandbox>() {}
    fn assert_child<C: SandboxChild>() {}

    assert_sandbox::<cageforge::WindowsBackend>();
    assert_child::<cageforge::WindowsChild>();
}

#[cfg(all(feature = "macos", target_os = "macos"))]
#[test]
fn macos_backend_implements_the_unified_facade_contract() {
    use cageforge::{Sandbox, SandboxChild};

    fn assert_sandbox<B: Sandbox + cageforge::DynSandbox>() {}
    fn assert_child<C: SandboxChild>() {}

    assert_sandbox::<cageforge::MacosBackend>();
    assert_child::<cageforge::MacosChild>();
}

#[cfg(not(any(
    all(feature = "linux", target_os = "linux"),
    all(feature = "windows", target_os = "windows"),
    all(feature = "macos", target_os = "macos")
)))]
#[test]
fn native_selection_reports_a_missing_feature_or_unsupported_host() {
    let error = cageforge::native_sandbox()
        .err()
        .expect("no native backend");
    match std::env::consts::OS {
        "linux" | "windows" | "macos" => {
            assert!(
                matches!(error, cageforge::NativeSandboxError::FeatureDisabled {
                target_os, feature
            } if target_os == std::env::consts::OS && feature == target_os)
            );
        }
        _ => assert!(
            matches!(error, cageforge::NativeSandboxError::UnsupportedPlatform {
            target_os
        } if target_os == std::env::consts::OS)
        ),
    }
}

#[cfg(all(feature = "linux", target_os = "linux"))]
#[test]
fn native_selection_preserves_the_typed_initialization_error() {
    use std::error::Error;
    let config = cageforge::NativeSandboxConfig::new()
        .with_hardening_helper_path("/cageforge-nonexistent-helper/entry");
    let error = cageforge::native_sandbox_with(config)
        .err()
        .expect("missing helper");
    assert!(matches!(
        error,
        cageforge::NativeSandboxError::Initialization { .. }
    ));
    assert!(
        error
            .source()
            .expect("native cause")
            .is::<cageforge::LinuxBackendError>()
    );
}
