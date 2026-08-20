use std::path::PathBuf;
use std::time::Duration;

use cageforge_backend_api::{
    BackendCapabilities, BackendCapability, BackendContractError, BackendRequest, SandboxBackend,
};
use cageforge_command::{CommandRequest, CommandSpec, EnvironmentSpec, StdioMode, StdioSpec};
use cageforge_policy::{
    AccessMode, DomainAccess, DomainMode, FilesystemMode, FilesystemPolicy, FilesystemRule,
    NetworkMode, NetworkPolicy, PathResolutionContext, PathSelector, UnixSocketMode,
};
use cageforge_policy_compose::{
    CompositionError, CompositionRequest, CoreEnvironment, EnvironmentInput, PolicyCeiling, compose,
};
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
        BackendCapability::FilesystemMissingPathBehavior,
        BackendCapability::FilesystemProtectedPaths,
        BackendCapability::NetworkEnabled,
        BackendCapability::NetworkLocalAddressRestrictions,
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
    let backend = TestBackend {
        capabilities: all_capabilities(),
    };
    let prepared = request.prepare_for(&backend).unwrap();

    assert_eq!(prepared.command(), &command);
    assert_eq!(prepared.sandbox(), &sandbox);
}

#[test]
fn reports_the_first_missing_capability_deterministically() {
    let (command, sandbox) = effective_request();
    let backend = TestBackend {
        capabilities: BackendCapabilities::from_capabilities([BackendCapability::CommandExecution]),
    };
    let error = BackendRequest::new(&command, &sandbox)
        .prepare_for(&backend)
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
            BackendCapability::FilesystemMissingPathBehavior,
            BackendCapability::FilesystemProtectedPaths,
            BackendCapability::NetworkEnabled,
            BackendCapability::NetworkDomainRules,
            BackendCapability::NetworkLocalAddressRestrictions,
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

    let backend = TestBackend {
        capabilities: required.clone(),
    };
    BackendRequest::new(&command, &sandbox)
        .prepare_for(&backend)
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
    let command =
        CommandRequest::new(CommandSpec::new("tool").unwrap()).with_environment(environment);
    let required = BackendRequest::new(&command, &sandbox).required_capabilities();

    assert!(required.supports(BackendCapability::TimeoutBackendDefault));
    assert!(required.supports(BackendCapability::FilesystemUnrestricted));
    assert!(required.supports(BackendCapability::NetworkEnabled));
    assert!(!required.supports(BackendCapability::NetworkLocalAddressRestrictions));
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
        CompositionRequest::new(&requested, &environment, &ceiling)
            .with_external_owner(owner)
            .with_workspace_roots([PathBuf::from("/workspace")])
            .unwrap(),
    )
    .unwrap();
    let command = CommandRequest::new(CommandSpec::new("tool").unwrap());
    let required = BackendRequest::new(&command, &sandbox).required_capabilities();

    assert!(required.supports(BackendCapability::FilesystemExternal));
    assert!(required.supports(BackendCapability::FilesystemScopes));
    assert!(required.supports(BackendCapability::NetworkExternal));
    assert!(required.supports(BackendCapability::EnvironmentNone));
    assert!(!required.supports(BackendCapability::FilesystemRestricted));
    assert!(!required.supports(BackendCapability::NetworkResolvedTargets));
}

#[test]
fn workspace_globs_require_workspace_scope_support() {
    let filesystem = FilesystemPolicy::restricted([FilesystemRule::workspace_glob(
        "secrets/**",
        AccessMode::Deny,
    )
    .unwrap()]);
    let requested = cageforge_policy::SandboxPolicy::new(
        filesystem,
        cageforge_policy::NetworkPolicy::disabled(),
    );
    let environment = EnvironmentSpec::empty();
    let ceiling = PolicyCeiling::new(
        cageforge_policy::SandboxPolicy::full_access(),
        environment.clone(),
    );
    let sandbox = compose(CompositionRequest::new(&requested, &environment, &ceiling)).unwrap();
    let command =
        CommandRequest::new(CommandSpec::new("tool").unwrap()).with_environment(environment);
    let required = BackendRequest::new(&command, &sandbox).required_capabilities();

    assert!(required.supports(BackendCapability::FilesystemGlobs));
    assert!(required.supports(BackendCapability::FilesystemScopes));
    assert!(required.supports(BackendCapability::FilesystemGlobScanDepth));

    let capabilities = required
        .iter()
        .copied()
        .filter(|capability| *capability != BackendCapability::FilesystemScopes)
        .collect();
    let error = BackendRequest::new(&command, &sandbox)
        .prepare_for(&TestBackend { capabilities })
        .unwrap_err();
    assert_eq!(
        error,
        BackendContractError::UnsupportedCapability {
            capability: BackendCapability::FilesystemScopes,
        }
    );
}

#[test]
fn all_filesystem_and_network_ownership_modes_have_exact_capabilities() {
    let environment = EnvironmentSpec::empty();
    for filesystem_mode in [
        FilesystemMode::Restricted,
        FilesystemMode::Unrestricted,
        FilesystemMode::External,
    ] {
        for network_mode in [
            NetworkMode::Disabled,
            NetworkMode::Enabled,
            NetworkMode::External,
        ] {
            let requested = cageforge_policy::SandboxPolicy::new(
                match filesystem_mode {
                    FilesystemMode::Restricted => FilesystemPolicy::restricted([]),
                    FilesystemMode::Unrestricted => FilesystemPolicy::unrestricted(),
                    FilesystemMode::External => FilesystemPolicy::external(),
                },
                match network_mode {
                    NetworkMode::Disabled => NetworkPolicy::disabled(),
                    NetworkMode::Enabled => NetworkPolicy::enabled(),
                    NetworkMode::External => NetworkPolicy::external(),
                },
            );
            let external_owner = (filesystem_mode == FilesystemMode::External
                || network_mode == NetworkMode::External)
                .then(cageforge_policy_compose::ExternalOwner::new);
            let mut ceiling = PolicyCeiling::new(requested.clone(), environment.clone());
            if let Some(owner) = &external_owner {
                ceiling = ceiling.with_external_owner(owner.clone());
            }
            let mut composition = CompositionRequest::new(&requested, &environment, &ceiling);
            if let Some(owner) = external_owner {
                composition = composition.with_external_owner(owner);
            }
            let sandbox = compose(composition).unwrap();
            let command = CommandRequest::new(CommandSpec::new("tool").unwrap())
                .with_environment(environment.clone());
            let required = BackendRequest::new(&command, &sandbox).required_capabilities();

            let filesystem_capability = match filesystem_mode {
                FilesystemMode::Restricted => BackendCapability::FilesystemRestricted,
                FilesystemMode::Unrestricted => BackendCapability::FilesystemUnrestricted,
                FilesystemMode::External => BackendCapability::FilesystemExternal,
            };
            let network_capability = match network_mode {
                NetworkMode::Disabled => BackendCapability::NetworkDisabled,
                NetworkMode::Enabled => BackendCapability::NetworkEnabled,
                NetworkMode::External => BackendCapability::NetworkExternal,
            };
            let mut expected = BackendCapabilities::from_capabilities([
                BackendCapability::CommandExecution,
                BackendCapability::StdioNull,
                BackendCapability::StdioPipe,
                BackendCapability::TimeoutBackendDefault,
                filesystem_capability,
                network_capability,
                BackendCapability::EnvironmentNone,
            ]);
            if filesystem_mode == FilesystemMode::Restricted {
                expected = expected.with(BackendCapability::FilesystemProtectedPaths);
            }
            if network_mode == NetworkMode::Enabled {
                expected = expected
                    .with(BackendCapability::NetworkLocalAddressRestrictions)
                    .with(BackendCapability::NetworkResolvedTargets)
                    .with(BackendCapability::NetworkUnixSockets);
            }

            assert_eq!(required, expected, "{filesystem_mode:?} + {network_mode:?}");
            BackendRequest::new(&command, &sandbox)
                .prepare_for(&TestBackend {
                    capabilities: required,
                })
                .unwrap();
        }
    }
}

#[test]
fn prepared_request_narrows_paths_and_applies_backend_selected_environment() {
    let (command, sandbox) = effective_request();
    let backend = TestBackend {
        capabilities: all_capabilities(),
    };
    let prepared = BackendRequest::new(&command, &sandbox)
        .prepare_for(&backend)
        .unwrap();

    let base = PathResolutionContext::new()
        .with_workspace_root("/workspace")
        .unwrap()
        .with_workspace_root("/outside")
        .unwrap();
    let context = prepared.path_context(&base).unwrap();
    assert_eq!(context.workspace_roots(), &[PathBuf::from("/workspace")]);

    let core = CoreEnvironment::from_selected([
        ("PATH".into(), "/bin".into()),
        ("SECRET_TOKEN".into(), "hidden".into()),
    ]);
    let environment = prepared
        .apply_environment(EnvironmentInput::core(core))
        .unwrap();
    assert_eq!(
        environment,
        std::collections::BTreeMap::from([
            ("MODE".into(), "test".into()),
            ("PATH".into(), "/bin".into()),
        ])
    );
}

#[test]
fn prepared_request_rejects_a_broader_environment_base() {
    let (command, sandbox) = effective_request();
    let backend = TestBackend {
        capabilities: all_capabilities(),
    };
    let prepared = BackendRequest::new(&command, &sandbox)
        .prepare_for(&backend)
        .unwrap();

    let error = prepared
        .apply_environment(EnvironmentInput::all([("PATH".into(), "/bin".into())]))
        .unwrap_err();
    assert_eq!(
        error,
        BackendContractError::EnvironmentPreparation {
            source: CompositionError::EnvironmentBaseTooPermissive {
                required: cageforge_command::EnvironmentBase::Core,
                supplied: cageforge_command::EnvironmentBase::All,
            },
        }
    );
}

#[test]
fn local_address_and_missing_path_capabilities_are_required() {
    let (command, sandbox) = effective_request();
    let required = BackendRequest::new(&command, &sandbox).required_capabilities();

    for missing in [
        BackendCapability::FilesystemMissingPathBehavior,
        BackendCapability::NetworkLocalAddressRestrictions,
    ] {
        let capabilities = required
            .iter()
            .copied()
            .filter(|capability| *capability != missing)
            .collect();
        let backend = TestBackend { capabilities };
        let error = BackendRequest::new(&command, &sandbox)
            .prepare_for(&backend)
            .unwrap_err();
        assert_eq!(
            error,
            BackendContractError::UnsupportedCapability {
                capability: missing
            }
        );
    }
}

#[test]
fn every_derived_capability_is_a_hard_preflight_requirement() {
    let (command, sandbox) = effective_request();
    let required = BackendRequest::new(&command, &sandbox).required_capabilities();

    for missing in required.iter().copied() {
        let capabilities = required
            .iter()
            .copied()
            .filter(|capability| *capability != missing)
            .collect();
        let backend = TestBackend { capabilities };
        let error = BackendRequest::new(&command, &sandbox)
            .prepare_for(&backend)
            .unwrap_err();
        assert_eq!(
            error,
            BackendContractError::UnsupportedCapability {
                capability: missing
            }
        );
    }
}

#[test]
fn rejects_a_command_with_a_different_environment_specification() {
    let (command, sandbox) = effective_request();
    let command = command.with_environment(EnvironmentSpec::empty());
    let backend = TestBackend {
        capabilities: all_capabilities(),
    };
    let error = BackendRequest::new(&command, &sandbox)
        .prepare_for(&backend)
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
