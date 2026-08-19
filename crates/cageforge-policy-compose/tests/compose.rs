// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::path::PathBuf;

use cageforge_command::{EnvironmentFilterAction, EnvironmentSpec};
use cageforge_policy::{
    AccessMode, DomainAccess, FilesystemPolicy, FilesystemRule, NetworkPolicy,
    PathResolutionContext, PathSelector, SandboxPolicy, UnixSocketMode,
};
use cageforge_policy_compose::{
    CompositionError, CompositionRequest, CoreEnvironment, EnvironmentInput, ExternalOwner,
    PolicyCeiling, compose,
};

fn absolute_root(name: &str) -> PathBuf {
    std::env::temp_dir()
        .join("cageforge-policy-compose-tests")
        .join(name)
}

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
fn composition_canonicalizes_duplicate_filesystem_targets_before_backend_handoff() {
    let target = PathSelector::workspace_root();
    let requested = SandboxPolicy::new(
        FilesystemPolicy::restricted([
            FilesystemRule::new(target.clone(), AccessMode::Write),
            FilesystemRule::new(target, AccessMode::Deny),
        ]),
        NetworkPolicy::enabled(),
    );
    let ceiling = PolicyCeiling::new(
        SandboxPolicy::new(FilesystemPolicy::unrestricted(), NetworkPolicy::enabled()),
        EnvironmentSpec::empty(),
    );

    let effective = compose(CompositionRequest::new(
        &requested,
        &EnvironmentSpec::empty(),
        &ceiling,
    ))
    .expect("duplicate filesystem targets should normalize safely");

    assert_eq!(effective.filesystem().requested().entries().len(), 1);
    assert_eq!(
        effective
            .filesystem()
            .access_for(&PathSelector::workspace_root()),
        cageforge_policy::FilesystemDecision::Deny
    );
}

#[test]
fn denies_workspace_roots_outside_the_ceiling() {
    let ceiling = PolicyCeiling::new(SandboxPolicy::read_only(), EnvironmentSpec::inherit_core())
        .with_workspace_roots([absolute_root("project")])
        .expect("valid ceiling roots");
    let requested = requested_policy();

    let error = compose(
        CompositionRequest::new(&requested, &EnvironmentSpec::inherit_core(), &ceiling)
            .with_workspace_roots([absolute_root("other")])
            .expect("valid requested roots"),
    )
    .expect_err("outside roots must not compose");

    assert_eq!(
        error,
        CompositionError::WorkspaceRootNotGranted {
            path: absolute_root("other")
        }
    );
}

#[cfg(windows)]
#[test]
fn workspace_root_containment_uses_windows_case_rules() {
    let ceiling = PolicyCeiling::new(SandboxPolicy::read_only(), EnvironmentSpec::empty())
        .with_workspace_roots([absolute_root("Project")])
        .expect("valid ceiling root");
    let requested = requested_policy();
    let requested_root = absolute_root("project/src");

    let effective = compose(
        CompositionRequest::new(&requested, &EnvironmentSpec::empty(), &ceiling)
            .with_workspace_roots([requested_root.clone()])
            .expect("valid requested root"),
    )
    .expect("Windows paths with different case remain inside the root");

    assert_eq!(
        effective.workspace_roots(),
        Some([requested_root].as_slice())
    );
}

#[test]
fn keeps_nested_workspace_roots_and_deduplicates_them() {
    let ceiling = PolicyCeiling::new(SandboxPolicy::read_only(), EnvironmentSpec::empty())
        .with_workspace_roots([absolute_root("project")])
        .expect("valid ceiling roots");
    let requested = requested_policy();
    let roots = [
        absolute_root("project/src"),
        absolute_root("project/src"),
        absolute_root("project/tests"),
    ];

    let effective = compose(
        CompositionRequest::new(&requested, &EnvironmentSpec::empty(), &ceiling)
            .with_workspace_roots(roots)
            .expect("valid requested roots"),
    )
    .expect("nested roots are inside the ceiling");

    assert_eq!(
        effective.workspace_roots(),
        Some([absolute_root("project/src"), absolute_root("project/tests")].as_slice())
    );
}

#[test]
fn ceiling_roots_filter_runtime_roots_without_becoming_requested_roots() {
    let allowed = absolute_root("allowed");
    let outside = absolute_root("outside");
    let ceiling = PolicyCeiling::new(SandboxPolicy::workspace(), EnvironmentSpec::empty())
        .with_workspace_roots([allowed.clone()])
        .expect("valid ceiling root");
    let requested = SandboxPolicy::workspace();
    let effective = compose(CompositionRequest::new(
        &requested,
        &EnvironmentSpec::empty(),
        &ceiling,
    ))
    .expect("valid policies compose");
    let base = PathResolutionContext::new()
        .with_workspace_root(allowed.clone())
        .expect("allowed runtime root")
        .with_workspace_root(outside)
        .expect("outside runtime root");
    let context = effective.path_context(&base).expect("effective context");

    assert_eq!(effective.workspace_roots(), None);
    assert_eq!(context.workspace_roots(), std::slice::from_ref(&allowed));
}

#[test]
fn external_ownership_must_match_on_each_boundary() {
    let requested = SandboxPolicy::new(FilesystemPolicy::external(), NetworkPolicy::enabled());
    let ceiling = PolicyCeiling::new(SandboxPolicy::read_only(), EnvironmentSpec::inherit_core());

    let error = compose(CompositionRequest::new(
        &requested,
        &EnvironmentSpec::inherit_core(),
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
    let owner = ExternalOwner::new();
    let ceiling = PolicyCeiling::new(policy.clone(), EnvironmentSpec::empty())
        .with_external_owner(owner.clone());
    let effective = compose(
        CompositionRequest::new(&policy, &EnvironmentSpec::empty(), &ceiling)
            .with_external_owner(owner.clone()),
    )
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
    assert_eq!(owner.clone(), owner);
    assert_ne!(ExternalOwner::default(), owner);
    assert!(format!("{owner:?}").contains("ExternalOwner"));
}

#[test]
fn default_git_protection_survives_composition() {
    let requested = SandboxPolicy::workspace();
    let ceiling = PolicyCeiling::new(SandboxPolicy::full_access(), EnvironmentSpec::empty());
    let effective = compose(CompositionRequest::new(
        &requested,
        &EnvironmentSpec::empty(),
        &ceiling,
    ))
    .expect("valid policies compose");
    let context = PathResolutionContext::new()
        .with_workspace_root(absolute_root("project"))
        .expect("valid workspace root");
    let context = effective.path_context(&context).expect("effective context");

    assert_eq!(
        effective
            .filesystem()
            .access_for_path(absolute_root("project/.git/config").as_path(), &context,)
            .expect("valid path"),
        cageforge_policy::FilesystemDecision::Read
    );
}

#[test]
fn effective_context_restricts_workspace_roots_and_preserves_other_scopes() {
    let requested = requested_policy();
    let safe_root = absolute_root("safe");
    let other_root = absolute_root("other");
    let ceiling = PolicyCeiling::new(SandboxPolicy::full_access(), EnvironmentSpec::empty())
        .with_workspace_roots([safe_root.clone()])
        .expect("valid ceiling root");
    let effective = compose(CompositionRequest::new(
        &requested,
        &EnvironmentSpec::empty(),
        &ceiling,
    ))
    .expect("valid policies compose");
    let base = PathResolutionContext::new()
        .with_root(absolute_root("system-root"))
        .expect("valid system root")
        .with_workspace_root(safe_root.clone())
        .expect("valid safe root")
        .with_workspace_root(other_root.clone())
        .expect("valid other root")
        .with_minimal_path(absolute_root("minimal"))
        .expect("valid minimal path")
        .with_tmpdir(absolute_root("tmpdir"))
        .expect("valid tmpdir")
        .with_slash_tmp(absolute_root("slash-tmp"))
        .expect("valid slash-tmp");
    let context = effective.path_context(&base).expect("effective context");

    assert_eq!(context.workspace_roots(), std::slice::from_ref(&safe_root));
    assert_eq!(
        context.context().workspace_roots(),
        context.workspace_roots()
    );
    assert_eq!(
        context.as_ref().root_paths(),
        &[absolute_root("system-root")]
    );
    assert_eq!(
        context.as_ref().minimal_paths(),
        &[absolute_root("minimal")]
    );
    assert_eq!(
        context.as_ref().tmpdir(),
        Some(absolute_root("tmpdir").as_path())
    );
    assert_eq!(
        context.as_ref().slash_tmp(),
        Some(absolute_root("slash-tmp").as_path())
    );
    assert_eq!(
        effective
            .filesystem()
            .access_for_path(safe_root.join("file").as_path(), &context)
            .expect("valid safe path"),
        cageforge_policy::FilesystemDecision::Write
    );
    assert_eq!(
        effective
            .filesystem()
            .access_for_path(other_root.join("file").as_path(), &context)
            .expect("valid other path"),
        cageforge_policy::FilesystemDecision::Deny
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
        &ceiling,
    ))
    .expect("valid policies compose");
    let variables = BTreeMap::from([
        (OsString::from("SECRET_TOKEN"), OsString::from("hidden")),
        (OsString::from("SECRET_SAFE"), OsString::from("visible")),
    ]);

    let result = effective
        .environment()
        .apply_to(EnvironmentInput::core(CoreEnvironment::from_selected(
            variables,
        )))
        .expect("core input is not broader than effective base");

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

    let error = effective
        .environment()
        .apply_to(EnvironmentInput::all([(
            OsString::from("PATH"),
            OsString::from("/bin"),
        )]))
        .expect_err("all variables are broader than the effective core base");
    assert_eq!(
        error,
        CompositionError::EnvironmentBaseTooPermissive {
            required: cageforge_command::EnvironmentBase::Core,
            supplied: cageforge_command::EnvironmentBase::All,
        }
    );

    let unrestricted_ceiling =
        PolicyCeiling::new(SandboxPolicy::full_access(), EnvironmentSpec::inherit_all());
    let unrestricted_effective = compose(CompositionRequest::new(
        &policy,
        &EnvironmentSpec::inherit_all(),
        &unrestricted_ceiling,
    ))
    .expect("valid policies compose");
    assert_eq!(
        unrestricted_effective.environment().base(),
        cageforge_command::EnvironmentBase::All
    );
    assert_eq!(
        unrestricted_effective.filesystem().glob_scan_max_depth(),
        None
    );

    let empty_environment = EnvironmentSpec::empty();
    let empty_ceiling = PolicyCeiling::new(SandboxPolicy::full_access(), EnvironmentSpec::empty());
    let empty_effective = compose(CompositionRequest::new(
        &policy,
        &empty_environment,
        &empty_ceiling,
    ))
    .expect("valid empty environment policies compose");
    assert_eq!(
        empty_effective.environment().base(),
        cageforge_command::EnvironmentBase::None
    );
    assert_eq!(
        empty_effective
            .environment()
            .apply_to(EnvironmentInput::empty())
            .expect("empty input is valid for a none base"),
        BTreeMap::new()
    );
}

#[test]
fn rejects_parent_traversal_in_ceiling_roots() {
    let error = PolicyCeiling::new(SandboxPolicy::read_only(), EnvironmentSpec::empty())
        .with_workspace_roots([absolute_root("project/../outside")])
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
        .clone()
        .with_workspace_roots([PathBuf::from("/bad\0root")])
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

    let relative_error = ceiling
        .with_workspace_roots([PathBuf::from("relative")])
        .expect_err("composition roots must be runtime-resolved");
    assert!(matches!(
        relative_error,
        CompositionError::InvalidWorkspaceRoot {
            reason: "root must be absolute at composition time",
            ..
        }
    ));
}

#[test]
fn preserves_glob_denials_and_uses_the_widest_required_scan_depth() {
    let root = absolute_root("glob");
    let requested_filesystem = FilesystemPolicy::restricted([
        FilesystemRule::new(PathSelector::workspace_root(), AccessMode::Write),
        FilesystemRule::absolute_glob(root.join("*.secret").to_string_lossy(), AccessMode::Deny)
            .expect("valid requested glob"),
    ])
    .with_glob_scan_max_depth(NonZeroUsize::new(2).expect("non-zero depth"))
    .expect("valid requested glob depth");
    let ceiling_filesystem = FilesystemPolicy::restricted([
        FilesystemRule::new(PathSelector::workspace_root(), AccessMode::Write),
        FilesystemRule::absolute_glob(root.join("**/*.token").to_string_lossy(), AccessMode::Deny)
            .expect("valid ceiling glob"),
    ])
    .with_glob_scan_max_depth(NonZeroUsize::new(4).expect("non-zero depth"))
    .expect("valid ceiling glob depth");
    let requested = SandboxPolicy::new(requested_filesystem, NetworkPolicy::disabled());
    let ceiling = PolicyCeiling::new(
        SandboxPolicy::new(ceiling_filesystem, NetworkPolicy::disabled()),
        EnvironmentSpec::empty(),
    );
    let effective = compose(CompositionRequest::new(
        &requested,
        &EnvironmentSpec::empty(),
        &ceiling,
    ))
    .expect("valid policies compose");
    let context = PathResolutionContext::new()
        .with_workspace_root(root.clone())
        .expect("valid workspace root");
    let context = effective.path_context(&context).expect("effective context");

    assert_eq!(
        effective.filesystem().glob_scan_max_depth(),
        NonZeroUsize::new(4)
    );
    assert_eq!(
        effective
            .filesystem()
            .access_for_path(root.join("credentials.secret").as_path(), &context)
            .expect("valid path"),
        cageforge_policy::FilesystemDecision::Deny
    );

    let unbounded_ceiling = PolicyCeiling::new(
        SandboxPolicy::new(
            FilesystemPolicy::restricted([FilesystemRule::absolute_glob(
                root.join("**/*.token").to_string_lossy(),
                AccessMode::Deny,
            )
            .expect("valid unbounded glob")]),
            NetworkPolicy::disabled(),
        ),
        EnvironmentSpec::empty(),
    );
    let unbounded = compose(CompositionRequest::new(
        &requested,
        &EnvironmentSpec::empty(),
        &unbounded_ceiling,
    ))
    .expect("valid unbounded policy composition");
    assert_eq!(unbounded.filesystem().glob_scan_max_depth(), None);
}

#[test]
fn custom_protected_paths_remain_read_only_after_composition() {
    let requested = SandboxPolicy::workspace();
    let ceiling_filesystem = FilesystemPolicy::restricted([FilesystemRule::new(
        PathSelector::workspace_root(),
        AccessMode::Write,
    )])
    .with_additional_protected_relative_path(".secrets")
    .expect("valid protected path");
    let ceiling = PolicyCeiling::new(
        SandboxPolicy::new(ceiling_filesystem, NetworkPolicy::disabled()),
        EnvironmentSpec::empty(),
    );
    let effective = compose(CompositionRequest::new(
        &requested,
        &EnvironmentSpec::empty(),
        &ceiling,
    ))
    .expect("valid policies compose");
    let context = PathResolutionContext::new()
        .with_workspace_root(absolute_root("protected"))
        .expect("valid workspace root");
    let context = effective.path_context(&context).expect("effective context");

    assert_eq!(
        effective
            .filesystem()
            .access_for_path(absolute_root("protected/.secrets/file").as_path(), &context)
            .expect("valid path"),
        cageforge_policy::FilesystemDecision::Read
    );
}

#[test]
fn composes_unix_socket_allowlists_and_exposes_component_policies() {
    let requested_network = NetworkPolicy::enabled()
        .with_unix_socket_mode(UnixSocketMode::Restricted)
        .with_unix_socket("/tmp/allowed", DomainAccess::Allow)
        .expect("valid socket");
    let requested = SandboxPolicy::new(FilesystemPolicy::unrestricted(), requested_network);
    let ceiling = PolicyCeiling::new(requested.clone(), EnvironmentSpec::inherit_core())
        .with_workspace_roots([absolute_root("project")])
        .expect("valid root");
    let effective = compose(CompositionRequest::new(
        &requested,
        &EnvironmentSpec::inherit_core(),
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
fn unrelated_external_owners_are_rejected() {
    let policy = SandboxPolicy::new(FilesystemPolicy::external(), NetworkPolicy::enabled());
    let requested_owner = ExternalOwner::new();
    let ceiling_owner = ExternalOwner::new();
    let ceiling = PolicyCeiling::new(policy.clone(), EnvironmentSpec::empty())
        .with_external_owner(ceiling_owner);

    let error = compose(
        CompositionRequest::new(&policy, &EnvironmentSpec::empty(), &ceiling)
            .with_external_owner(requested_owner),
    )
    .expect_err("different external owners must not compose");

    assert_eq!(
        error,
        CompositionError::ExternalOwnerMismatch {
            boundary: cageforge_policy_compose::CompositionBoundary::Filesystem,
        }
    );
}

#[test]
fn owner_proof_is_rejected_without_an_external_boundary() {
    let policy = SandboxPolicy::full_access();
    let owner = ExternalOwner::new();
    let ceiling = PolicyCeiling::new(policy.clone(), EnvironmentSpec::empty())
        .with_external_owner(owner.clone());

    let error = compose(
        CompositionRequest::new(&policy, &EnvironmentSpec::empty(), &ceiling)
            .with_external_owner(owner),
    )
    .expect_err("owner proof has no meaning without external enforcement");

    assert_eq!(
        error,
        CompositionError::UnexpectedExternalOwner {
            boundary: cageforge_policy_compose::CompositionBoundary::Filesystem,
        }
    );
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

#[test]
fn composes_resolved_domain_safety_from_both_policies() {
    let requested_network = NetworkPolicy::enabled()
        .with_domain("service.example", DomainAccess::Allow)
        .expect("valid domain");
    let ceiling_network = NetworkPolicy::enabled()
        .with_domain("service.example", DomainAccess::Allow)
        .expect("valid domain");
    let requested = SandboxPolicy::new(FilesystemPolicy::unrestricted(), requested_network);
    let ceiling = PolicyCeiling::new(
        SandboxPolicy::new(FilesystemPolicy::unrestricted(), ceiling_network),
        EnvironmentSpec::empty(),
    );
    let effective = compose(CompositionRequest::new(
        &requested,
        &EnvironmentSpec::empty(),
        &ceiling,
    ))
    .expect("valid policies compose");

    let private: IpAddr = "10.0.0.8".parse().expect("private address");
    assert_eq!(
        effective
            .network()
            .decision_for_domain_with_resolved_ips("service.example", &[private])
            .expect("valid domain"),
        cageforge_policy::NetworkDecision::Deny
    );
    let public: IpAddr = "93.184.216.34".parse().expect("public address");
    assert_eq!(
        effective
            .network()
            .decision_for_domain_with_resolved_ips("service.example", &[public])
            .expect("valid domain"),
        cageforge_policy::NetworkDecision::Allow
    );
}
