// Copyright 2026 Mansur Azatbek
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use cageforge_command::{EnvironmentFilterAction, EnvironmentSpec};
use cageforge_policy::{
    AccessMode, DomainAccess, FilesystemPolicy, FilesystemRule, NetworkPolicy,
    PathResolutionContext, PathSelector, SandboxPolicy, UnixSocketMode,
};
use cageforge_policy_compose::{CompositionError, CompositionRequest, PolicyCeiling, compose};

fn requested_policy() -> SandboxPolicy {
    SandboxPolicy::new(
        FilesystemPolicy::restricted([FilesystemRule::new(
            PathSelector::workspace_root(),
            AccessMode::Write,
        )]),
        NetworkPolicy::enabled(),
    )
}

#[test]
fn intersects_filesystem_and_network_decisions() {
    let requested = requested_policy();
    let ceiling = PolicyCeiling::new(
        SandboxPolicy::new(
            FilesystemPolicy::restricted([FilesystemRule::new(
                PathSelector::workspace_root(),
                AccessMode::Read,
            )]),
            NetworkPolicy::disabled(),
        ),
        EnvironmentSpec::inherit_all(),
    );
    let effective = compose(CompositionRequest::new(
        &requested,
        &EnvironmentSpec::inherit_all(),
        &[],
        &ceiling,
    ))
    .expect("valid policies compose");

    assert_eq!(
        effective
            .filesystem()
            .access_for(&PathSelector::workspace_root()),
        cageforge_policy::FilesystemDecision::Read
    );
    assert_eq!(
        effective
            .network()
            .decision_for_domain("example.com")
            .expect("valid domain"),
        cageforge_policy::NetworkDecision::Deny
    );
}

#[test]
fn denies_workspace_roots_outside_the_ceiling() {
    let ceiling = PolicyCeiling::new(SandboxPolicy::read_only(), EnvironmentSpec::inherit_core())
        .with_workspace_roots([PathBuf::from("project")])
        .expect("valid ceiling roots");
    let requested = requested_policy();

    let error = compose(CompositionRequest::new(
        &requested,
        &EnvironmentSpec::inherit_core(),
        &[PathBuf::from("other")],
        &ceiling,
    ))
    .expect_err("outside roots must not compose");

    assert_eq!(
        error,
        CompositionError::WorkspaceRootNotGranted {
            path: PathBuf::from("other")
        }
    );
}

#[test]
fn keeps_nested_workspace_roots_and_deduplicates_them() {
    let ceiling = PolicyCeiling::new(SandboxPolicy::read_only(), EnvironmentSpec::empty())
        .with_workspace_roots([PathBuf::from("project")])
        .expect("valid ceiling roots");
    let requested = requested_policy();
    let roots = [
        PathBuf::from("project/src"),
        PathBuf::from("project/src"),
        PathBuf::from("project/tests"),
    ];

    let effective = compose(CompositionRequest::new(
        &requested,
        &EnvironmentSpec::empty(),
        &roots,
        &ceiling,
    ))
    .expect("nested roots are inside the ceiling");

    assert_eq!(
        effective.workspace_roots(),
        &[PathBuf::from("project/src"), PathBuf::from("project/tests")]
    );
}

#[test]
fn external_ownership_must_match_on_each_boundary() {
    let requested = SandboxPolicy::new(FilesystemPolicy::external(), NetworkPolicy::enabled());
    let ceiling = PolicyCeiling::new(SandboxPolicy::read_only(), EnvironmentSpec::inherit_core());

    let error = compose(CompositionRequest::new(
        &requested,
        &EnvironmentSpec::inherit_core(),
        &[],
        &ceiling,
    ))
    .expect_err("mixed external and local ownership is ambiguous");

    assert_eq!(
        error,
        CompositionError::EnforcementOwnershipConflict {
            boundary: cageforge_policy_compose::CompositionBoundary::Filesystem
        }
    );
    assert_eq!(
        error.to_string(),
        "filesystem enforcement ownership cannot be composed safely"
    );
}

#[test]
fn external_decisions_remain_external_when_both_sides_delegate() {
    let policy = SandboxPolicy::new(FilesystemPolicy::external(), NetworkPolicy::external());
    let ceiling = PolicyCeiling::new(policy.clone(), EnvironmentSpec::empty());
    let effective = compose(CompositionRequest::new(
        &policy,
        &EnvironmentSpec::empty(),
        &[],
        &ceiling,
    ))
    .expect("matching external ownership composes");

    assert!(
        effective
            .filesystem()
            .access_for(&PathSelector::workspace_root())
            .is_externally_enforced()
    );
    assert!(
        effective
            .network()
            .decision_for_domain("example.com")
            .expect("valid domain")
            .is_externally_enforced()
    );
    assert!(
        effective
            .network()
            .decision_for_unix_socket(PathBuf::from("/tmp/socket").as_path())
            .expect("valid socket")
            .is_externally_enforced()
    );
}

#[test]
fn default_git_protection_survives_composition() {
    let requested = SandboxPolicy::workspace();
    let ceiling = PolicyCeiling::new(SandboxPolicy::full_access(), EnvironmentSpec::empty());
    let effective = compose(CompositionRequest::new(
        &requested,
        &EnvironmentSpec::empty(),
        &[],
        &ceiling,
    ))
    .expect("valid policies compose");
    let context = PathResolutionContext::new()
        .with_workspace_root("/project")
        .expect("valid workspace root");

    assert_eq!(
        effective
            .filesystem()
            .access_for_path(Path::new("/project/.git/config"), &context)
            .expect("valid path"),
        cageforge_policy::FilesystemDecision::Read
    );
}

#[test]
fn environment_is_narrowed_in_sequence_without_ceiling_additions() {
    let requested_environment = EnvironmentSpec::inherit_all()
        .with_filter("SECRET_*", EnvironmentFilterAction::Include)
        .expect("valid include filter")
        .with_var("REQUESTED", "yes")
        .expect("valid override");
    let ceiling_environment = EnvironmentSpec::inherit_core()
        .with_exclude_pattern("SECRET_TOKEN")
        .expect("valid exclude filter")
        .with_var("CEILING_ONLY", "must-not-appear")
        .expect("valid override");
    let policy = requested_policy();
    let ceiling = PolicyCeiling::new(SandboxPolicy::read_only(), ceiling_environment);
    let effective = compose(CompositionRequest::new(
        &policy,
        &requested_environment,
        &[],
        &ceiling,
    ))
    .expect("valid policies compose");
    let variables = BTreeMap::from([
        (OsString::from("SECRET_TOKEN"), OsString::from("hidden")),
        (OsString::from("SECRET_SAFE"), OsString::from("visible")),
    ]);

    let result = effective.environment().apply_to(variables);

    assert_eq!(
        result,
        BTreeMap::from([(OsString::from("SECRET_SAFE"), OsString::from("visible"))])
    );
    assert_eq!(
        effective.environment().base(),
        cageforge_command::EnvironmentBase::Core
    );
    assert_eq!(effective.environment().requested(), &requested_environment);
    assert_eq!(effective.environment().ceiling(), ceiling.environment());

    let unrestricted_ceiling =
        PolicyCeiling::new(SandboxPolicy::full_access(), EnvironmentSpec::inherit_all());
    let unrestricted_effective = compose(CompositionRequest::new(
        &policy,
        &EnvironmentSpec::inherit_all(),
        &[],
        &unrestricted_ceiling,
    ))
    .expect("valid policies compose");
    assert_eq!(
        unrestricted_effective.environment().base(),
        cageforge_command::EnvironmentBase::All
    );
}

#[test]
fn rejects_parent_traversal_in_ceiling_roots() {
    let error = PolicyCeiling::new(SandboxPolicy::read_only(), EnvironmentSpec::empty())
        .with_workspace_roots([PathBuf::from("project/../outside")])
        .expect_err("parent traversal must be rejected");

    assert!(matches!(
        error,
        CompositionError::InvalidWorkspaceRoot {
            reason: "parent traversal is not allowed",
            ..
        }
    ));
}

#[test]
fn rejects_empty_and_nul_workspace_roots() {
    let ceiling = PolicyCeiling::new(SandboxPolicy::read_only(), EnvironmentSpec::empty());
    let empty_error = ceiling
        .clone()
        .with_workspace_roots([PathBuf::new()])
        .expect_err("empty root must be rejected");
    let nul_error = ceiling
        .with_workspace_roots([PathBuf::from("bad\0root")])
        .expect_err("NUL root must be rejected");

    assert!(matches!(
        empty_error,
        CompositionError::InvalidWorkspaceRoot {
            reason: "root must not be empty",
            ..
        }
    ));
    assert!(matches!(
        nul_error,
        CompositionError::InvalidWorkspaceRoot {
            reason: "root must not contain NUL",
            ..
        }
    ));
}

#[test]
fn composes_unix_socket_allowlists_and_exposes_component_policies() {
    let requested_network = NetworkPolicy::enabled()
        .with_unix_socket_mode(UnixSocketMode::Restricted)
        .with_unix_socket("/tmp/allowed", DomainAccess::Allow)
        .expect("valid socket");
    let requested = SandboxPolicy::new(FilesystemPolicy::unrestricted(), requested_network);
    let ceiling = PolicyCeiling::new(requested.clone(), EnvironmentSpec::inherit_core())
        .with_workspace_roots([PathBuf::from("project")])
        .expect("valid root");
    let effective = compose(CompositionRequest::new(
        &requested,
        &EnvironmentSpec::inherit_core(),
        &[],
        &ceiling,
    ))
    .expect("valid policies compose");

    assert_eq!(effective.filesystem().requested(), requested.filesystem());
    assert_eq!(
        effective.filesystem().ceiling(),
        ceiling.policy().filesystem()
    );
    assert_eq!(effective.network().requested(), requested.network());
    assert_eq!(effective.network().ceiling(), ceiling.policy().network());
    assert_eq!(
        effective
            .network()
            .decision_for_unix_socket(PathBuf::from("/tmp/allowed").as_path())
            .expect("valid socket"),
        cageforge_policy::NetworkDecision::Allow
    );
    assert!(matches!(
        effective
            .network()
            .decision_for_unix_socket(PathBuf::from("relative").as_path()),
        Err(CompositionError::PolicyEvaluation {
            boundary: cageforge_policy_compose::CompositionBoundary::Network,
            ..
        })
    ));

    let full = SandboxPolicy::full_access();
    let full_ceiling = PolicyCeiling::new(full.clone(), EnvironmentSpec::inherit_all());
    let full_effective = compose(CompositionRequest::new(
        &full,
        &EnvironmentSpec::inherit_all(),
        &[],
        &full_ceiling,
    ))
    .expect("full policies compose");
    assert_eq!(
        full_effective
            .network()
            .decision_for_domain("example.com")
            .expect("valid domain"),
        cageforge_policy::NetworkDecision::Allow
    );

    let unlimited = ceiling.without_workspace_root_limit();
    assert_eq!(unlimited.workspace_roots(), None);
}

#[test]
fn combines_domain_allowlists_by_denying_unshared_access() {
    let requested_network = NetworkPolicy::enabled()
        .with_domain_mode(cageforge_policy::DomainMode::Restricted)
        .with_domain("one.example", DomainAccess::Allow)
        .expect("valid domain");
    let ceiling_network = NetworkPolicy::enabled()
        .with_domain_mode(cageforge_policy::DomainMode::Restricted)
        .with_domain("two.example", DomainAccess::Allow)
        .expect("valid domain");
    let requested = SandboxPolicy::new(FilesystemPolicy::unrestricted(), requested_network);
    let ceiling = PolicyCeiling::new(
        SandboxPolicy::new(FilesystemPolicy::unrestricted(), ceiling_network),
        EnvironmentSpec::empty(),
    );
    let effective = compose(CompositionRequest::new(
        &requested,
        &EnvironmentSpec::empty(),
        &[],
        &ceiling,
    ))
    .expect("valid policies compose");

    assert_eq!(
        effective
            .network()
            .decision_for_domain("one.example")
            .expect("valid domain"),
        cageforge_policy::NetworkDecision::Deny
    );
}
