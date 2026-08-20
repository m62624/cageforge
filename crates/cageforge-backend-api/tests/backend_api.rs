use std::path::PathBuf;
use std::time::Duration;

use cageforge_backend_api::{
    BackendCapabilities, BackendCapability, BackendContractError, BackendRequest, SandboxBackend,
};
use cageforge_command::{CommandRequest, CommandSpec, EnvironmentSpec, StdioMode, StdioSpec};
use cageforge_policy::{
    AccessMode, DomainAccess, DomainMode, FilesystemPolicy, FilesystemRule, NetworkPolicy,
    PathSelector, UnixSocketMode,
};
use cageforge_policy_compose::{CompositionRequest, PolicyCeiling, compose};
use pretty_assertions::assert_eq;

struct TestBackend {
    capabilities: BackendCapabilities,
}

impl SandboxBackend for TestBackend {
    fn capabilities(&self) -> BackendCapabilities {
        self.capabilities.clone()
    }
}

fn effective_request() -> (CommandRequest, cageforge_policy_compose::EffectiveSandbox) {
    let filesystem = FilesystemPolicy::restricted([
        FilesystemRule::new(PathSelector::workspace_root(), AccessMode::Write)
            .with_read_only_subpath(PathSelector::workspace("secrets").unwrap())
            .unwrap(),
        FilesystemRule::workspace_glob("**/*.secret", AccessMode::Deny).unwrap(),
    ])
    .with_glob_scan_max_depth(std::num::NonZeroUsize::new(8).unwrap())
    .unwrap();
    let network = NetworkPolicy::enabled()
        .with_domain_mode(DomainMode::Restricted)
        .with_unix_socket_mode(UnixSocketMode::Restricted)
        .with_domain("example.com", DomainAccess::Allow)
        .unwrap()
        .with_unix_socket("/run/example.sock", DomainAccess::Allow)
        .unwrap();
    let requested = cageforge_policy::SandboxPolicy::new(filesystem, network);
    let command_environment = EnvironmentSpec::inherit_core()
        .with_include_pattern("PATH")
        .unwrap()
        .with_exclude_pattern("SECRET_*")
        .unwrap()
        .with_var("MODE", "test")
        .unwrap();
    let command = CommandRequest::new(CommandSpec::new("tool").unwrap())
        .with_working_directory("/workspace")
        .unwrap()
        .with_environment(command_environment.clone())
        .with_stdio(StdioSpec::new(
            StdioMode::Inherit,
            StdioMode::Null,
            StdioMode::Pipe,
        ))
        .with_timeout(Duration::from_secs(5));
    let ceiling = PolicyCeiling::new(
        cageforge_policy::SandboxPolicy::full_access(),
        EnvironmentSpec::inherit_all(),
    );
    let effective = compose(
        CompositionRequest::new(&requested, &command_environment, &ceiling)
            .with_workspace_roots([PathBuf::from("/workspace")])
            .unwrap(),
    )
    .unwrap();
    (command, effective)
}

fn all_capabilities() -> BackendCapabilities {
    BackendCapabilities::from_capabilities([
        BackendCapability::CommandExecution,
        BackendCapability::WorkingDirectory,
        BackendCapability::StdioInherit,
        BackendCapability::StdioNull,
        BackendCapability::StdioPipe,
        BackendCapability::TimeoutLimit,
        BackendCapability::FilesystemRestricted,
        BackendCapability::FilesystemUnrestricted,
        BackendCapability::FilesystemScopes,
        BackendCapability::FilesystemGlobs,
        BackendCapability::FilesystemGlobScanDepth,
        BackendCapability::FilesystemReadOnlySubpaths,
        BackendCapability::FilesystemProtectedPaths,
        BackendCapability::NetworkEnabled,
        BackendCapability::NetworkResolvedTargets,
        BackendCapability::NetworkDomainRules,
        BackendCapability::NetworkUnixSockets,
        BackendCapability::EnvironmentCore,
        BackendCapability::EnvironmentFilters,
        BackendCapability::EnvironmentOverrides,
    ])
}

#[test]
fn prepares_a_composed_request_without_launching() {
    let (command, sandbox) = effective_request();
    let request = BackendRequest::new(&command, &sandbox);
    let prepared = TestBackend {
        capabilities: all_capabilities(),
    }
    .prepare(request)
    .unwrap();

    assert_eq!(prepared.command(), &command);
    assert_eq!(prepared.sandbox(), &sandbox);
}

#[test]
fn reports_the_first_missing_capability_deterministically() {
    let (command, sandbox) = effective_request();
    let error = TestBackend {
        capabilities: BackendCapabilities::from_capabilities([BackendCapability::CommandExecution]),
    }
    .prepare(BackendRequest::new(&command, &sandbox))
    .unwrap_err();

    assert_eq!(
        error,
        BackendContractError::UnsupportedCapability {
            capability: BackendCapability::WorkingDirectory,
        }
    );
}

#[test]
fn required_capabilities_are_stable_and_complete_for_the_fixture() {
    let (command, sandbox) = effective_request();
    let required = BackendRequest::new(&command, &sandbox).required_capabilities();

    assert_eq!(
        required.iter().copied().collect::<Vec<_>>(),
        vec![
            BackendCapability::CommandExecution,
            BackendCapability::WorkingDirectory,
            BackendCapability::StdioInherit,
            BackendCapability::StdioNull,
            BackendCapability::StdioPipe,
            BackendCapability::TimeoutLimit,
            BackendCapability::FilesystemRestricted,
            BackendCapability::FilesystemScopes,
            BackendCapability::FilesystemGlobs,
            BackendCapability::FilesystemGlobScanDepth,
            BackendCapability::FilesystemReadOnlySubpaths,
            BackendCapability::FilesystemProtectedPaths,
            BackendCapability::NetworkEnabled,
            BackendCapability::NetworkDomainRules,
            BackendCapability::NetworkResolvedTargets,
            BackendCapability::NetworkUnixSockets,
            BackendCapability::EnvironmentCore,
            BackendCapability::EnvironmentFilters,
            BackendCapability::EnvironmentOverrides,
        ]
    );
}

#[test]
fn required_capabilities_follow_effective_modes_not_broad_inputs() {
    let (command, sandbox) = effective_request();
    let required = BackendRequest::new(&command, &sandbox).required_capabilities();

    assert!(!required.supports(BackendCapability::FilesystemUnrestricted));
    assert!(required.supports(BackendCapability::FilesystemRestricted));

    TestBackend {
        capabilities: required.clone(),
    }
    .prepare(BackendRequest::new(&command, &sandbox))
    .unwrap();
}

#[test]
fn required_capabilities_cover_unrestricted_default_modes() {
    let requested = cageforge_policy::SandboxPolicy::full_access();
    let environment = EnvironmentSpec::inherit_all();
    let ceiling = PolicyCeiling::new(
        cageforge_policy::SandboxPolicy::full_access(),
        environment.clone(),
    );
    let sandbox = compose(CompositionRequest::new(&requested, &environment, &ceiling)).unwrap();
    let command = CommandRequest::new(CommandSpec::new("tool").unwrap());
    let required = BackendRequest::new(&command, &sandbox).required_capabilities();

    assert!(required.supports(BackendCapability::TimeoutBackendDefault));
    assert!(required.supports(BackendCapability::FilesystemUnrestricted));
    assert!(required.supports(BackendCapability::NetworkEnabled));
    assert!(required.supports(BackendCapability::NetworkResolvedTargets));
    assert!(required.supports(BackendCapability::NetworkUnixSockets));
    assert!(required.supports(BackendCapability::EnvironmentAll));

    let collected: BackendCapabilities = required.iter().copied().collect();
    assert_eq!(collected, required);
}

#[test]
fn required_capabilities_cover_disabled_and_empty_environment_modes() {
    let requested = cageforge_policy::SandboxPolicy::read_only();
    let environment = EnvironmentSpec::empty();
    let ceiling = PolicyCeiling::new(
        cageforge_policy::SandboxPolicy::full_access(),
        environment.clone(),
    );
    let sandbox = compose(CompositionRequest::new(&requested, &environment, &ceiling)).unwrap();
    let command = CommandRequest::new(CommandSpec::new("tool").unwrap()).disable_timeout();
    let required = BackendRequest::new(&command, &sandbox).required_capabilities();

    assert!(required.supports(BackendCapability::TimeoutDisabled));
    assert!(required.supports(BackendCapability::NetworkDisabled));
    assert!(required.supports(BackendCapability::EnvironmentNone));
    assert!(!required.supports(BackendCapability::NetworkResolvedTargets));
}

#[test]
fn required_capabilities_cover_external_enforcement_modes() {
    let requested = cageforge_policy::SandboxPolicy::new(
        cageforge_policy::FilesystemPolicy::external(),
        cageforge_policy::NetworkPolicy::external(),
    );
    let environment = EnvironmentSpec::empty();
    let owner = cageforge_policy_compose::ExternalOwner::new();
    let ceiling = PolicyCeiling::new(requested.clone(), environment.clone())
        .with_external_owner(owner.clone());
    let sandbox = compose(
        CompositionRequest::new(&requested, &environment, &ceiling).with_external_owner(owner),
    )
    .unwrap();
    let command = CommandRequest::new(CommandSpec::new("tool").unwrap());
    let required = BackendRequest::new(&command, &sandbox).required_capabilities();

    assert!(required.supports(BackendCapability::FilesystemExternal));
    assert!(required.supports(BackendCapability::NetworkExternal));
    assert!(required.supports(BackendCapability::EnvironmentNone));
    assert!(!required.supports(BackendCapability::FilesystemRestricted));
    assert!(!required.supports(BackendCapability::NetworkResolvedTargets));
}

#[test]
fn rejects_a_command_with_a_different_environment_specification() {
    let (command, sandbox) = effective_request();
    let command = command.with_environment(EnvironmentSpec::empty());
    let error = TestBackend {
        capabilities: all_capabilities(),
    }
    .prepare(BackendRequest::new(&command, &sandbox))
    .unwrap_err();

    assert_eq!(error, BackendContractError::CommandEnvironmentMismatch);
}

#[test]
fn capability_sets_are_deterministic_and_composable() {
    let capabilities = BackendCapabilities::new()
        .with(BackendCapability::StdioPipe)
        .with(BackendCapability::CommandExecution)
        .with(BackendCapability::StdioPipe);

    assert!(capabilities.supports(BackendCapability::CommandExecution));
    assert!(capabilities.supports(BackendCapability::StdioPipe));
    assert_eq!(
        capabilities.iter().copied().collect::<Vec<_>>(),
        vec![
            BackendCapability::CommandExecution,
            BackendCapability::StdioPipe
        ]
    );
}
