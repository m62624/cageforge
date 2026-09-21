// SPDX-License-Identifier: Apache-2.0

use cageforge::{CommandSpec, SandboxPolicy};

#[test]
fn portable_types_and_facade_traits_are_available_from_the_root_crate() {
    let command = CommandSpec::new("cargo").expect("valid command");
    let _policy = SandboxPolicy::workspace();
    let _gateway_config = cageforge::GatewayConfig::new();
    assert_eq!(command.program(), "cargo");
}

#[test]
fn native_diagnostic_metadata_uses_the_host_platform_code() {
    let error = std::io::Error::other("native test error");
    let metadata = cageforge::native_diagnostic_metadata(&error);
    #[cfg(target_os = "linux")]
    assert_eq!(metadata.code(), "linux_native_error");
    #[cfg(target_os = "windows")]
    assert_eq!(metadata.code(), "windows_native_error");
    #[cfg(target_os = "macos")]
    assert_eq!(metadata.code(), "macos_native_error");
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    assert_eq!(metadata.code(), "native_error");
    assert_eq!(metadata.field(), None);
}

#[cfg(target_os = "macos")]
#[test]
fn macos_native_diagnostic_metadata_preserves_runtime_fields() {
    use std::path::PathBuf;

    let cases: &[(Box<dyn std::error::Error>, &str, Option<&str>)] = &[
        (
            Box::new(cageforge::MacosFilesystemError::ProgramRequiresRead {
                path: PathBuf::from("/opt/tool/bin/runner"),
            }),
            "macos_program_requires_read",
            Some("command.program"),
        ),
        (
            Box::new(
                cageforge::MacosFilesystemError::ProgramRequiresExecutableRoot {
                    path: PathBuf::from("/opt/tool/bin/runner"),
                },
            ),
            "macos_program_requires_executable_root",
            Some("runtime.executable_roots"),
        ),
        (
            Box::new(cageforge::MacosFilesystemError::ExecutableRootMissing {
                path: PathBuf::from("/opt/tool/runtime"),
            }),
            "macos_invalid_executable_root",
            Some("runtime.executable_roots"),
        ),
        (
            Box::new(
                cageforge::MacosFilesystemError::ExecutableRootNotDirectory {
                    path: PathBuf::from("/opt/tool/runtime"),
                },
            ),
            "macos_invalid_executable_root",
            Some("runtime.executable_roots"),
        ),
        (
            Box::new(cageforge::MacosFilesystemError::ExecutableRootNotReadable {
                path: PathBuf::from("/opt/tool/runtime"),
            }),
            "macos_invalid_executable_root",
            Some("runtime.executable_roots"),
        ),
        (
            Box::new(cageforge::MacosFilesystemError::InvalidExecutableRoot {
                path: PathBuf::from("relative/runtime"),
            }),
            "macos_invalid_executable_root",
            Some("runtime.executable_roots"),
        ),
    ];

    for (error, code, field) in cases {
        let metadata = cageforge::native_diagnostic_metadata(error.as_ref());
        assert_eq!(metadata.code(), *code);
        assert_eq!(metadata.field(), *field);
    }
}

#[cfg(feature = "network-runtime")]
#[test]
fn network_runtime_public_api_is_available_from_the_root_crate() {
    use cageforge::{NetworkGateway, NetworkResolver, SystemResolver};

    fn assert_resolver<R: NetworkResolver>() {}

    let _: Option<NetworkGateway<SystemResolver>> = None;
    assert_resolver::<SystemResolver>();
}

#[cfg(target_os = "linux")]
#[test]
fn linux_backend_implements_the_unified_facade_contract() {
    use cageforge::{Sandbox, SandboxChild};

    fn assert_sandbox<B: Sandbox + cageforge::DynSandbox>() {}
    fn assert_child<C: SandboxChild>() {}

    assert_sandbox::<cageforge::LinuxBackend>();
    assert_child::<cageforge::LinuxChild>();
}

#[cfg(target_os = "windows")]
#[test]
fn windows_backend_implements_the_unified_facade_contract() {
    use cageforge::{Sandbox, SandboxChild};

    fn assert_sandbox<B: Sandbox + cageforge::DynSandbox>() {}
    fn assert_child<C: SandboxChild>() {}

    assert_sandbox::<cageforge::WindowsBackend>();
    assert_child::<cageforge::WindowsChild>();
}

#[cfg(target_os = "macos")]
#[test]
fn macos_backend_implements_the_unified_facade_contract() {
    use cageforge::{Sandbox, SandboxChild};

    fn assert_sandbox<B: Sandbox + cageforge::DynSandbox>() {}
    fn assert_child<C: SandboxChild>() {}

    assert_sandbox::<cageforge::MacosBackend>();
    assert_child::<cageforge::MacosChild>();
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
#[test]
fn native_selection_reports_an_unsupported_host() {
    let error = cageforge::native_sandbox()
        .err()
        .expect("no native backend");
    assert!(matches!(
        error,
        cageforge::NativeSandboxError::UnsupportedPlatform { target_os }
            if target_os == std::env::consts::OS
    ));
}

#[cfg(target_os = "linux")]
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
