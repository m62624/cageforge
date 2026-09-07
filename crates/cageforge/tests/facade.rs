use cageforge::{CommandSpec, SandboxPolicy};

#[test]
fn portable_types_and_facade_traits_are_available_from_the_root_crate() {
    let command = CommandSpec::new("cargo").expect("valid command");
    let _policy = SandboxPolicy::workspace();
    assert_eq!(command.program(), "cargo");
}

#[cfg(all(feature = "linux", target_os = "linux"))]
#[test]
fn linux_backend_implements_the_unified_facade_contract() {
    use cageforge::{Sandbox, SandboxChild};

    fn assert_sandbox<B: Sandbox>() {}
    fn assert_child<C: SandboxChild>() {}

    assert_sandbox::<cageforge::LinuxBackend>();
    assert_child::<cageforge::LinuxChild>();
}

#[cfg(all(feature = "windows", target_os = "windows"))]
#[test]
fn windows_backend_implements_the_unified_facade_contract() {
    use cageforge::{Sandbox, SandboxChild};

    fn assert_sandbox<B: Sandbox>() {}
    fn assert_child<C: SandboxChild>() {}

    assert_sandbox::<cageforge::WindowsBackend>();
    assert_child::<cageforge::WindowsChild>();
}

#[cfg(all(feature = "macos", target_os = "macos"))]
#[test]
fn macos_backend_implements_the_unified_facade_contract() {
    use cageforge::{Sandbox, SandboxChild};

    fn assert_sandbox<B: Sandbox>() {}
    fn assert_child<C: SandboxChild>() {}

    assert_sandbox::<cageforge::MacosBackend>();
    assert_child::<cageforge::MacosChild>();
}
