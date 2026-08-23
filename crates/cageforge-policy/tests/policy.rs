// SPDX-License-Identifier: Apache-2.0

use cageforge_policy::{
    AccessMode, ConnectionAuthorization, DomainAccess, DomainMode, FilesystemDecision,
    FilesystemMode, FilesystemPolicy, FilesystemRule, FilesystemTarget, LocalNetworkAccess,
    MissingPathBehavior, NetworkDecision, NetworkMode, NetworkPolicy, PathPattern,
    PathResolutionContext, PathSelector, PolicyError, ResolvedNetworkTarget, SandboxPolicy,
    UnixSocketMode, UnixSocketRule,
};
use pretty_assertions::assert_eq;
use std::collections::{BTreeSet, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroUsize;
use std::path::Path;

#[test]
fn native_absolute_paths_are_accepted_and_relative_paths_are_rejected() {
    let absolute = if cfg!(windows) {
        r"C:\workspace"
    } else {
        "/workspace"
    };
    assert_eq!(
        PathSelector::absolute(absolute)
            .expect("native absolute path")
            .path(),
        Some(Path::new(absolute))
    );
    assert!(matches!(
        PathSelector::absolute("workspace"),
        Err(PolicyError::ExpectedAbsolute { .. })
    ));
}

#[test]
fn resolved_network_target_rejects_address_changes() {
    let public = IpAddr::V4("8.8.8.8".parse().expect("public address"));
    let checked = SocketAddr::new(public, 443);
    let changed = SocketAddr::new("1.1.1.1".parse().expect("public address"), 443);
    let target = ResolvedNetworkTarget::new("service.example", [checked])
        .expect("valid resolved network target");
    let policy = NetworkPolicy::enabled()
        .with_domain_mode(DomainMode::Restricted)
        .with_domain("service.example", DomainAccess::Allow)
        .expect("valid domain rule");

    match policy
        .authorize_connection(&target, checked)
        .expect("authorized connection")
    {
        ConnectionAuthorization::Allowed(address) => {
            assert_eq!(address.into_socket_addr(), checked);
        }
        other => panic!("expected an authorized address, got {other:?}"),
    }
    assert_eq!(
        policy
            .authorize_connection(&target, changed)
            .expect("changed connection authorization"),
        ConnectionAuthorization::Denied
    );
}

#[test]
fn resolved_ip_literal_cannot_claim_a_different_address() {
    let claimed = "8.8.8.8";
    let private = SocketAddr::new("127.0.0.1".parse().expect("loopback address"), 443);
    let error = ResolvedNetworkTarget::new(claimed, [private])
        .expect_err("an IP literal must agree with every resolved address");

    assert!(matches!(error, PolicyError::ResolvedAddressMismatch { .. }));
}

#[test]
fn resolved_ip_literal_decisions_reject_mismatched_addresses() {
    let policy = NetworkPolicy::enabled()
        .with_domain("*", DomainAccess::Allow)
        .expect("wildcard domain");

    for (literal, resolved) in [
        ("8.8.8.8", "10.0.0.1"),
        ("2001:4860:4860::8888", "2001:db8::1"),
    ] {
        assert_eq!(
            policy
                .decision_for_domain_with_resolved_ips(
                    literal,
                    &[resolved.parse().expect("resolved address")],
                )
                .expect("resolved literal decision"),
            NetworkDecision::Deny,
            "{literal} must not accept a different resolved address",
        );
    }
}

#[test]
fn resolved_target_rejects_policy_patterns_and_non_host_syntax() {
    let public = SocketAddr::new("93.184.216.34".parse().expect("public address"), 443);
    for host in ["*.example.com", "[a-c].example.com", "user@example.com"] {
        assert!(matches!(
            ResolvedNetworkTarget::new(host, [public]),
            Err(PolicyError::InvalidDomainPattern { .. })
        ));
    }
}

#[test]
fn absolute_paths_with_parent_traversal_are_rejected() {
    let absolute = if cfg!(windows) {
        r"C:\workspace\..\outside"
    } else {
        "/workspace/../outside"
    };
    assert!(matches!(
        PathSelector::absolute(absolute),
        Err(PolicyError::ParentTraversal { .. })
    ));
}

#[test]
fn workspace_paths_normalize_current_directory_and_reject_escape() {
    assert_eq!(
        PathSelector::workspace("./src")
            .expect("workspace-relative path")
            .path(),
        Some(std::path::Path::new("src"))
    );
    assert_eq!(
        PathSelector::workspace_root().path(),
        Some(std::path::Path::new("."))
    );
    assert!(matches!(
        PathSelector::workspace("../outside"),
        Err(PolicyError::ParentTraversal { .. })
    ));
}

#[test]
fn special_path_selectors_are_distinct() {
    let selectors = [
        PathSelector::root(),
        PathSelector::minimal(),
        PathSelector::tmpdir(),
        PathSelector::slash_tmp(),
    ];
    assert!(selectors.iter().all(PathSelector::is_special));
    assert!(selectors.iter().all(|selector| selector.path().is_none()));
    assert_ne!(selectors[0], selectors[1]);
    assert_ne!(selectors[1], selectors[2]);
    assert!(PathSelector::root().is_root_scope());
    assert!(PathSelector::minimal().is_minimal_scope());
    assert!(PathSelector::tmpdir().is_tmpdir_scope());
    assert!(PathSelector::slash_tmp().is_slash_tmp_scope());
    assert!(PathSelector::workspace_root().is_workspace_scope());
    assert!(
        PathSelector::absolute("/workspace")
            .expect("absolute selector")
            .is_absolute_scope()
    );
}

#[cfg(windows)]
#[test]
fn path_selector_collections_use_windows_path_identity() {
    let upper = PathSelector::absolute(r"C:\Workspace").expect("absolute path");
    let lower = PathSelector::absolute(r"c:\workspace").expect("absolute path");

    assert_eq!(upper, lower);
    assert_eq!(HashSet::from([upper.clone(), lower.clone()]).len(), 1);
    assert_eq!(BTreeSet::from([upper, lower]).len(), 1);
}

#[cfg(not(windows))]
#[test]
fn path_selector_collections_use_posix_path_identity() {
    let upper = PathSelector::absolute("/Workspace").expect("absolute path");
    let lower = PathSelector::absolute("/workspace").expect("absolute path");

    assert_ne!(upper, lower);
    assert_eq!(HashSet::from([upper.clone(), lower.clone()]).len(), 2);
    assert_eq!(BTreeSet::from([upper, lower]).len(), 2);
}

#[cfg(windows)]
#[test]
fn path_pattern_collections_use_windows_matching_identity() {
    let upper = PathPattern::workspace(r"Secrets\**").expect("upper-case glob");
    let lower = PathPattern::workspace(r"secrets\**").expect("lower-case glob");

    assert_eq!(upper, lower);
    assert_eq!(HashSet::from([upper.clone(), lower.clone()]).len(), 1);
    assert_eq!(BTreeSet::from([upper, lower]).len(), 1);
}

#[cfg(windows)]
#[test]
fn unicode_windows_globs_follow_their_native_trait_identity() {
    let pattern = PathPattern::workspace("ångström/**").expect("valid Unicode glob");
    let case_variant = PathPattern::workspace("ÅNGSTRÖM/**").expect("valid Unicode glob");
    assert_eq!(pattern, case_variant);
    assert_eq!(HashSet::from([pattern.clone(), case_variant]).len(), 1);

    let context = PathResolutionContext::new()
        .with_workspace_root(r"C:\Workspace")
        .expect("valid workspace root");
    let policy = FilesystemPolicy::restricted([FilesystemRule::from_target(
        FilesystemTarget::Glob(pattern),
        AccessMode::Deny,
    )
    .expect("valid deny glob")]);

    assert_eq!(
        policy
            .access_for_path(Path::new(r"c:\workspace\ÅNGSTRÖM\secret.txt"), &context,)
            .expect("filesystem decision"),
        FilesystemDecision::Deny
    );
}

#[cfg(windows)]
#[test]
fn absolute_globs_match_windows_verbatim_path_aliases() {
    let context = PathResolutionContext::new();
    let policy = FilesystemPolicy::restricted([])
        .with_rule(
            FilesystemRule::from_target(
                FilesystemTarget::Glob(
                    PathPattern::absolute(r"\\?\C:\Workspace\Secrets\**")
                        .expect("valid verbatim absolute glob"),
                ),
                AccessMode::Deny,
            )
            .expect("valid deny rule"),
        )
        .expect("restricted policy accepts a deny glob");

    assert_eq!(
        policy
            .access_for_path(Path::new(r"c:\workspace\secrets\token.txt"), &context)
            .expect("filesystem decision"),
        FilesystemDecision::Deny
    );
}

#[cfg(not(windows))]
#[test]
fn path_pattern_collections_use_posix_matching_identity() {
    let upper = PathPattern::workspace("Secrets/**").expect("upper-case glob");
    let lower = PathPattern::workspace("secrets/**").expect("lower-case glob");

    assert_ne!(upper, lower);
    assert_eq!(HashSet::from([upper.clone(), lower.clone()]).len(), 2);
    assert_eq!(BTreeSet::from([upper, lower]).len(), 2);
}

#[test]
fn unix_socket_rule_collections_follow_native_path_identity() {
    let upper = if cfg!(windows) {
        r"C:\Run\Cageforge.sock"
    } else {
        "/Run/Cageforge.sock"
    };
    let lower = if cfg!(windows) {
        r"c:\run\cageforge.sock"
    } else {
        "/run/cageforge.sock"
    };
    let upper = UnixSocketRule::new(upper, DomainAccess::Allow).expect("valid socket rule");
    let lower = UnixSocketRule::new(lower, DomainAccess::Allow).expect("valid socket rule");

    if cfg!(windows) {
        assert_eq!(upper, lower);
        assert_eq!(HashSet::from([upper, lower]).len(), 1);
    } else {
        assert_ne!(upper, lower);
        assert_eq!(HashSet::from([upper, lower]).len(), 2);
    }
}

#[test]
fn access_modes_follow_security_precedence() {
    assert!(AccessMode::Write.can_read());
    assert!(AccessMode::Write.can_write());
    assert!(AccessMode::Read.can_read());
    assert!(!AccessMode::Read.can_write());
    assert!(!AccessMode::Deny.can_read());
    assert!(!AccessMode::Deny.can_write());
    assert_eq!(
        AccessMode::Read.most_restrictive(AccessMode::Deny),
        AccessMode::Deny
    );
    assert_eq!(
        AccessMode::Read.most_restrictive(AccessMode::Write),
        AccessMode::Read
    );
    assert_eq!(
        AccessMode::Write.most_restrictive(AccessMode::Read),
        AccessMode::Read
    );
    assert_eq!(
        AccessMode::Write.most_restrictive(AccessMode::Deny),
        AccessMode::Deny
    );
    assert_eq!(
        AccessMode::Deny.most_restrictive(AccessMode::Read),
        AccessMode::Deny
    );
    assert_eq!(
        AccessMode::Read.most_restrictive(AccessMode::Read),
        AccessMode::Read
    );
    assert!(AccessMode::Write.permits(AccessMode::Read));
    assert!(AccessMode::Write.permits(AccessMode::Write));
    assert!(AccessMode::Read.permits(AccessMode::Read));
    assert!(AccessMode::Deny.permits(AccessMode::Deny));
    assert!(!AccessMode::Read.permits(AccessMode::Write));
}

#[test]
fn missing_path_behavior_uses_explicit_conservative_merge() {
    assert_eq!(
        MissingPathBehavior::Error.most_conservative(MissingPathBehavior::Skip),
        MissingPathBehavior::Error
    );
    assert_eq!(
        MissingPathBehavior::Skip.most_conservative(MissingPathBehavior::Error),
        MissingPathBehavior::Error
    );
    assert_eq!(
        MissingPathBehavior::Skip.most_conservative(MissingPathBehavior::Skip),
        MissingPathBehavior::Skip
    );
    assert_eq!(
        MissingPathBehavior::Error.most_conservative(MissingPathBehavior::Error),
        MissingPathBehavior::Error
    );
}

#[test]
fn filesystem_decisions_keep_external_ownership_distinct_from_deny() {
    assert_eq!(
        FilesystemDecision::Read.as_access_mode(),
        Some(AccessMode::Read)
    );
    assert_eq!(
        FilesystemDecision::Deny.as_access_mode(),
        Some(AccessMode::Deny)
    );
    assert!(FilesystemDecision::ExternallyEnforced.is_externally_enforced());
    assert_eq!(
        FilesystemDecision::ExternallyEnforced.as_access_mode(),
        None
    );
}

#[test]
fn policy_errors_have_actionable_display_messages() {
    let errors = [
        PolicyError::EmptyPath,
        PolicyError::ExpectedAbsolute {
            path: "relative".into(),
        },
        PolicyError::ExpectedRelative {
            path: "/absolute".into(),
        },
        PolicyError::PathContainsNul {
            path: "bad\0path".into(),
        },
        PolicyError::ParentTraversal {
            path: "../outside".into(),
        },
        PolicyError::InvalidDomainPattern {
            pattern: "https://example.com".into(),
        },
        PolicyError::InvalidGlobPattern {
            pattern: "../secret".into(),
            reason: "parent traversal is not allowed".into(),
        },
        PolicyError::InvalidContext {
            message: "invalid context".into(),
        },
        PolicyError::InvalidRule {
            message: "contradictory rule".into(),
        },
    ];
    let messages: Vec<_> = errors.iter().map(ToString::to_string).collect();
    assert_eq!(
        messages,
        vec![
            "path cannot be empty",
            "path must be absolute: relative",
            "path must be workspace-relative: /absolute",
            "path must not contain a NUL character: bad\0path",
            "workspace-relative path cannot contain parent traversal: ../outside",
            "invalid domain pattern: https://example.com",
            "invalid glob pattern \"../secret\": parent traversal is not allowed",
            "invalid context",
            "contradictory rule",
        ]
    );
}

#[test]
fn resolution_context_expands_all_runtime_scopes() {
    let context = PathResolutionContext::new()
        .with_root(native_path("/"))
        .expect("system root")
        .with_workspace_root(native_path("/workspace"))
        .expect("workspace root")
        .with_minimal_path(native_path("/usr/bin"))
        .expect("minimal path")
        .with_tmpdir(native_path("/tmp/runtime"))
        .expect("tmpdir")
        .with_slash_tmp(native_path("/tmp"))
        .expect("slash tmp")
        .with_current_directory(native_path("/workspace"))
        .expect("current directory");
    assert_eq!(
        PathSelector::root().resolve(&context),
        vec![native_path("/")]
    );
    assert_eq!(
        PathSelector::workspace("src")
            .expect("workspace selector")
            .resolve(&context),
        vec![native_path("/workspace/src")]
    );
    assert_eq!(
        PathSelector::minimal().resolve(&context),
        vec![native_path("/usr/bin")]
    );
    assert_eq!(
        PathSelector::tmpdir().resolve(&context),
        vec![native_path("/tmp/runtime")]
    );
    assert_eq!(
        PathSelector::slash_tmp().resolve(&context),
        vec![native_path("/tmp")]
    );
    assert_eq!(
        context.current_directory(),
        Some(Path::new(&native_path("/workspace")))
    );
    assert_eq!(
        PathSelector::absolute(native_path("/workspace"))
            .expect("absolute selector")
            .resolve(&context),
        vec![native_path("/workspace")]
    );
    assert_eq!(context.workspace_roots(), &[native_path("/workspace")]);
    assert_eq!(context.root_paths(), &[native_path("/")]);
    assert_eq!(context.minimal_paths(), &[native_path("/usr/bin")]);
    assert_eq!(
        context.tmpdir(),
        Some(Path::new(&native_path("/tmp/runtime")))
    );
    assert_eq!(context.slash_tmp(), Some(Path::new(&native_path("/tmp"))));
    assert!(
        PathResolutionContext::new()
            .with_workspace_root("relative")
            .is_err()
    );
    assert!(PathResolutionContext::new().with_root("relative").is_err());
}

#[test]
fn resolution_context_deduplicates_native_path_aliases() {
    let root = native_path("/workspace");
    let context = PathResolutionContext::new()
        .with_root(root.clone())
        .expect("first root")
        .with_root(root.clone())
        .expect("duplicate root")
        .with_workspace_root(root.clone())
        .expect("first workspace root")
        .with_workspace_root(root)
        .expect("duplicate workspace root");

    assert_eq!(context.root_paths().len(), 1);
    assert_eq!(context.workspace_roots().len(), 1);
}

#[test]
fn path_patterns_validate_and_match_absolute_and_workspace_paths() {
    let context = PathResolutionContext::new()
        .with_workspace_root(native_path("/workspace"))
        .expect("workspace root");
    let workspace = PathPattern::workspace("**/*.secret").expect("workspace glob");
    assert_eq!(workspace.as_str(), "**/*.secret");
    assert!(!workspace.is_absolute());
    let absolute =
        PathPattern::absolute(native_path("/workspace/**/config.?oml")).expect("absolute glob");
    assert!(absolute.is_absolute());
    let policy = FilesystemPolicy::restricted([
        FilesystemRule::from_target(FilesystemTarget::Glob(workspace), AccessMode::Deny)
            .expect("deny glob rule"),
        FilesystemRule::from_target(FilesystemTarget::Glob(absolute), AccessMode::Deny)
            .expect("deny glob rule"),
    ]);
    assert_eq!(
        policy
            .access_for_path(
                Path::new(&native_path("/workspace/nested/token.secret")),
                &context,
            )
            .expect("secret lookup"),
        FilesystemDecision::Deny
    );
    assert_eq!(
        policy
            .access_for_path(Path::new(&native_path("/workspace/config.toml")), &context)
            .expect("config lookup"),
        FilesystemDecision::Deny
    );
    for (pattern, expected) in [
        ("", "pattern cannot be empty"),
        ("../secret", "parent traversal is not allowed"),
        (".", "pattern must contain at least one component"),
        ("*.toml", "absolute glob must use a native absolute path"),
    ] {
        let result = if pattern == "*.toml" {
            PathPattern::absolute(pattern)
        } else {
            PathPattern::workspace(pattern)
        };
        assert_eq!(
            result.expect_err("invalid pattern").to_string(),
            format!("invalid glob pattern {pattern:?}: {expected}")
        );
    }
    assert!(matches!(
        PathPattern::workspace("bad\0pattern"),
        Err(PolicyError::InvalidGlobPattern { .. })
    ));
    assert!(matches!(
        PathPattern::workspace("[abc"),
        Err(PolicyError::InvalidGlobPattern { .. })
    ));
}

#[test]
fn filesystem_globs_support_character_classes_and_ranges() {
    let context = PathResolutionContext::new()
        .with_workspace_root("/workspace")
        .expect("workspace root");
    let policy = FilesystemPolicy::restricted([
        FilesystemRule::new(PathSelector::workspace_root(), AccessMode::Write),
        FilesystemRule::workspace_glob("Secrets/[a-z][0-9].token", AccessMode::Deny)
            .expect("range glob"),
        FilesystemRule::workspace_glob("Secrets/[!x]oken", AccessMode::Deny)
            .expect("negative class glob"),
    ]);

    assert_eq!(
        policy
            .access_for_path(Path::new("/workspace/Secrets/a7.token"), &context)
            .expect("range match"),
        FilesystemDecision::Deny
    );
    assert_eq!(
        policy
            .access_for_path(Path::new("/workspace/Secrets/token"), &context)
            .expect("negative class match"),
        FilesystemDecision::Deny
    );
    assert_eq!(
        policy
            .access_for_path(Path::new("/workspace/Secrets/xoken"), &context)
            .expect("negative class non-match"),
        FilesystemDecision::Write
    );
}

#[test]
fn filesystem_resolution_is_recursive_and_most_specific() {
    let context = PathResolutionContext::new()
        .with_workspace_root(native_path("/workspace"))
        .expect("workspace root");
    let policy = FilesystemPolicy::restricted([
        FilesystemRule::new(PathSelector::workspace_root(), AccessMode::Write),
        FilesystemRule::new(
            PathSelector::workspace("src").expect("src selector"),
            AccessMode::Read,
        ),
        FilesystemRule::new(
            PathSelector::workspace("src/secrets").expect("secrets selector"),
            AccessMode::Deny,
        ),
    ]);
    assert_eq!(
        policy
            .access_for_path(Path::new(&native_path("/workspace/src/lib.rs")), &context)
            .expect("source lookup"),
        FilesystemDecision::Read
    );
    assert_eq!(
        policy
            .access_for_path(
                Path::new(&native_path("/workspace/src/secrets/key")),
                &context,
            )
            .expect("secret lookup"),
        FilesystemDecision::Deny
    );
    assert_eq!(
        policy
            .access_for_path(Path::new(&native_path("/workspace/README.md")), &context)
            .expect("workspace lookup"),
        FilesystemDecision::Write
    );
    assert_eq!(
        policy
            .access_for_path(Path::new(&native_path("/outside/file")), &context)
            .expect("outside lookup"),
        FilesystemDecision::Deny
    );
    assert!(matches!(
        policy.access_for_path(Path::new("relative"), &context),
        Err(PolicyError::ExpectedAbsolute { .. })
    ));
    assert!(matches!(
        policy.access_for_path(Path::new("/workspace/bad\0path"), &context),
        Err(PolicyError::PathContainsNul { .. })
    ));
    assert!(matches!(
        policy.access_for_path(Path::new(&native_path("/workspace/../outside")), &context,),
        Err(PolicyError::ParentTraversal { .. })
    ));
}

#[test]
fn resolved_scope_depth_controls_filesystem_precedence() {
    let context = PathResolutionContext::new()
        .with_root(native_path("/"))
        .expect("system root")
        .with_workspace_root(native_path("/workspace"))
        .expect("workspace root");
    let workspace = SandboxPolicy::workspace();

    assert_eq!(
        workspace
            .filesystem()
            .access_for_path(Path::new(&native_path("/workspace/src/lib.rs")), &context)
            .expect("workspace lookup"),
        FilesystemDecision::Write
    );

    let policy = FilesystemPolicy::restricted([
        FilesystemRule::new(
            PathSelector::absolute(native_path("/workspace")).expect("absolute workspace selector"),
            AccessMode::Write,
        ),
        FilesystemRule::new(
            PathSelector::workspace("secrets").expect("workspace deny selector"),
            AccessMode::Deny,
        ),
    ]);
    assert_eq!(
        policy
            .access_for_path(
                Path::new(&native_path("/workspace/secrets/token")),
                &context,
            )
            .expect("nested deny lookup"),
        FilesystemDecision::Deny
    );
}

#[test]
fn matching_deny_glob_cannot_be_reopened_by_a_deeper_write_scope() {
    let context = PathResolutionContext::new()
        .with_workspace_root(native_path("/workspace"))
        .expect("workspace root");
    let policy = FilesystemPolicy::restricted([
        FilesystemRule::workspace_glob("secrets/**", AccessMode::Deny).expect("deny glob"),
        FilesystemRule::new(
            PathSelector::workspace("secrets/nested").expect("nested write selector"),
            AccessMode::Write,
        ),
    ]);

    assert_eq!(
        policy
            .access_for_path(
                Path::new(&native_path("/workspace/secrets/nested/token")),
                &context,
            )
            .expect("deny lookup"),
        FilesystemDecision::Deny
    );
}

#[test]
fn filesystem_rules_support_carveouts_missing_paths_and_glob_depth() {
    let context = PathResolutionContext::new()
        .with_workspace_root(native_path("/workspace"))
        .expect("workspace root");
    let protected = FilesystemRule::new(PathSelector::workspace_root(), AccessMode::Write)
        .with_missing_path_behavior(MissingPathBehavior::Skip)
        .with_read_only_subpath(
            PathSelector::workspace(".git").expect("protected subpath selector"),
        )
        .expect("writable rule can contain a read-only subpath");
    let policy = FilesystemPolicy::restricted([protected])
        .with_glob_scan_max_depth(NonZeroUsize::new(4).expect("non-zero depth"))
        .expect("restricted policy can configure glob depth");
    assert_eq!(
        policy.entries()[0].missing_path_behavior(),
        MissingPathBehavior::Skip
    );
    assert_eq!(policy.glob_scan_max_depth(), NonZeroUsize::new(4));
    assert_eq!(
        policy
            .access_for_path(Path::new(&native_path("/workspace/src/main.rs")), &context)
            .expect("writable lookup"),
        FilesystemDecision::Write
    );
    assert_eq!(
        policy
            .access_for_path(Path::new(&native_path("/workspace/.git/config")), &context)
            .expect("protected lookup"),
        FilesystemDecision::Read
    );
    assert_eq!(
        policy
            .access_for_path(Path::new(&native_path("/workspace/.GIT/config")), &context)
            .expect("case-variant protected lookup"),
        if cfg!(windows) {
            FilesystemDecision::Read
        } else {
            FilesystemDecision::Write
        }
    );
    let exact_mixed_case = FilesystemPolicy::restricted([FilesystemRule::new(
        PathSelector::workspace(".GIT").expect("protected selector"),
        AccessMode::Write,
    )]);
    assert_eq!(
        exact_mixed_case
            .access_for(
                &PathSelector::workspace(".GIT").expect("protected selector"),
                &context,
            )
            .expect("protected selector decision"),
        if cfg!(windows) {
            FilesystemDecision::Read
        } else {
            FilesystemDecision::Write
        }
    );
    let explicit_write = policy
        .clone()
        .with_rule(FilesystemRule::new(
            PathSelector::workspace(".git").expect("explicit selector"),
            AccessMode::Write,
        ))
        .expect("restricted policy can add a rule");
    assert_eq!(
        explicit_write
            .access_for_path(Path::new(&native_path("/workspace/.git/config")), &context)
            .expect("explicit write lookup"),
        FilesystemDecision::Read
    );
    let default_only = FilesystemPolicy::restricted([FilesystemRule::new(
        PathSelector::workspace_root(),
        AccessMode::Write,
    )]);
    assert_eq!(
        default_only
            .dangerously_allow_git_write()
            .access_for_path(Path::new(&native_path("/workspace/.git/config")), &context)
            .expect("explicitly unprotected lookup"),
        FilesystemDecision::Write
    );
    let protected_metadata = policy
        .clone()
        .with_additional_protected_relative_path(".cargo")
        .expect("additional protected path");
    assert_eq!(
        protected_metadata.protected_relative_paths(),
        &[
            std::path::PathBuf::from(".git"),
            std::path::PathBuf::from(".cargo")
        ]
    );
    assert!(matches!(
        policy
            .clone()
            .with_additional_protected_relative_path("../escape"),
        Err(PolicyError::InvalidProtectedPath { .. })
    ));
    assert!(matches!(
        FilesystemPolicy::unrestricted().with_additional_protected_relative_path(".cargo"),
        Err(PolicyError::InvalidRule { .. })
    ));
    let absolute_rule =
        FilesystemRule::absolute_glob(native_path("/workspace/**/*.lock"), AccessMode::Deny)
            .expect("absolute glob rule");
    let workspace_rule =
        FilesystemRule::workspace_glob("**/*.tmp", AccessMode::Deny).expect("workspace glob rule");
    assert!(matches!(absolute_rule.target(), FilesystemTarget::Glob(_)));
    assert!(matches!(workspace_rule.target(), FilesystemTarget::Glob(_)));
    assert_eq!(workspace_rule.access(), AccessMode::Deny);
    assert!(workspace_rule.read_only_subpaths().is_empty());
    let normalized = FilesystemPolicy::restricted([
        FilesystemRule::new(PathSelector::workspace_root(), AccessMode::Read)
            .with_missing_path_behavior(MissingPathBehavior::Skip),
        FilesystemRule::new(PathSelector::workspace_root(), AccessMode::Write)
            .with_read_only_subpath(PathSelector::minimal())
            .expect("writable rule can contain a read-only subpath"),
    ])
    .normalized()
    .expect("duplicate rules");
    assert_eq!(normalized.entries().len(), 1);
    assert_eq!(
        normalized.entries()[0].missing_path_behavior(),
        MissingPathBehavior::Error
    );
    assert!(normalized.entries()[0].read_only_subpaths().is_empty());
    assert!(normalized.validate().is_ok());
    assert!(matches!(
        FilesystemPolicy::unrestricted()
            .with_glob_scan_max_depth(NonZeroUsize::new(1).expect("depth")),
        Err(PolicyError::InvalidRule { .. })
    ));
    assert!(matches!(
        FilesystemRule::new(PathSelector::workspace_root(), AccessMode::Read,)
            .with_read_only_subpath(PathSelector::minimal()),
        Err(PolicyError::InvalidRule { .. })
    ));
    assert!(matches!(
        FilesystemRule::new(
            PathSelector::workspace("src").expect("workspace parent"),
            AccessMode::Write,
        )
        .with_read_only_subpath(PathSelector::workspace(".git").expect("workspace child")),
        Err(PolicyError::InvalidRule { .. })
    ));
    assert!(matches!(
        FilesystemRule::new(
            PathSelector::absolute(native_path("/workspace/src")).expect("absolute parent"),
            AccessMode::Write,
        )
        .with_read_only_subpath(
            PathSelector::absolute(native_path("/outside/.git")).expect("absolute child"),
        ),
        Err(PolicyError::InvalidRule { .. })
    ));
    assert!(matches!(
        FilesystemRule::absolute_glob(native_path("/workspace/**/*.lock"), AccessMode::Read),
        Err(PolicyError::UnsupportedGlobAccess {
            access: AccessMode::Read
        })
    ));
}

#[test]
fn filesystem_policy_normalizes_duplicate_rules_conservatively() {
    let selector = PathSelector::workspace("src").expect("workspace path");
    let policy = FilesystemPolicy::restricted([
        FilesystemRule::new(selector.clone(), AccessMode::Read),
        FilesystemRule::new(selector.clone(), AccessMode::Deny),
    ]);
    let normalized = policy.normalized().expect("valid policy");
    assert_eq!(normalized.entries().len(), 1);
    let context = PathResolutionContext::new()
        .with_workspace_root("/workspace")
        .expect("workspace root");
    assert_eq!(
        normalized
            .access_for(&selector, &context)
            .expect("selector decision"),
        FilesystemDecision::Deny
    );
}

#[test]
fn network_policy_normalizes_duplicate_rules_conservatively() {
    let socket = native_path("/run/cageforge.sock");
    let policy = NetworkPolicy::enabled()
        .with_domain("EXAMPLE.COM:443", DomainAccess::Allow)
        .expect("allow domain")
        .with_domain("example.com", DomainAccess::Deny)
        .expect("deny domain")
        .with_unix_socket(socket.clone(), DomainAccess::Allow)
        .expect("allow socket")
        .with_unix_socket(socket, DomainAccess::Deny)
        .expect("deny socket");

    let normalized = policy.normalized().expect("valid policy");
    assert_eq!(normalized.domains().len(), 1);
    assert_eq!(normalized.domains()[0].access(), DomainAccess::Deny);
    assert_eq!(normalized.unix_sockets().len(), 1);
    assert_eq!(normalized.unix_sockets()[0].access(), DomainAccess::Deny);
}

#[cfg(windows)]
#[test]
fn filesystem_normalization_merges_case_variants_on_windows() {
    let upper = PathSelector::absolute(r"C:\Workspace\src").expect("absolute path");
    let lower = PathSelector::absolute(r"c:\workspace\src").expect("absolute path");
    let policy = FilesystemPolicy::restricted([
        FilesystemRule::new(upper, AccessMode::Write),
        FilesystemRule::new(lower, AccessMode::Read),
    ]);

    let normalized = policy.normalized().expect("valid policy");
    assert_eq!(normalized.entries().len(), 1);
    assert_eq!(normalized.entries()[0].access(), AccessMode::Read);
}

#[cfg(unix)]
#[test]
fn filesystem_matching_preserves_posix_case_sensitivity() {
    let context = PathResolutionContext::new()
        .with_workspace_root("/workspace")
        .expect("workspace root");
    let policy = FilesystemPolicy::restricted([FilesystemRule::new(
        PathSelector::workspace_root(),
        AccessMode::Write,
    )]);

    assert_eq!(
        policy
            .access_for_path(Path::new("/workspace/file"), &context)
            .expect("matching path"),
        FilesystemDecision::Write
    );
    assert_eq!(
        policy
            .access_for_path(Path::new("/Workspace/file"), &context)
            .expect("case-variant path"),
        FilesystemDecision::Deny
    );

    let glob_policy = FilesystemPolicy::restricted([
        FilesystemRule::new(PathSelector::workspace_root(), AccessMode::Write),
        FilesystemRule::workspace_glob("Secrets/**", AccessMode::Deny).expect("deny glob"),
    ]);
    assert_eq!(
        glob_policy
            .access_for_path(Path::new("/workspace/Secrets/token"), &context)
            .expect("matching glob"),
        FilesystemDecision::Deny
    );
    assert_eq!(
        glob_policy
            .access_for_path(Path::new("/workspace/secrets/token"), &context)
            .expect("case-variant glob"),
        FilesystemDecision::Write
    );
}

#[test]
fn filesystem_modes_have_explicit_access_behavior() {
    let selector = PathSelector::workspace_root();
    let context = PathResolutionContext::new()
        .with_workspace_root(native_path("/workspace"))
        .expect("workspace root");
    let restricted =
        FilesystemPolicy::restricted([FilesystemRule::new(selector.clone(), AccessMode::Read)]);
    assert_eq!(restricted.mode(), FilesystemMode::Restricted);
    assert_eq!(
        restricted
            .access_for(&selector, &PathResolutionContext::new())
            .expect("empty context decision"),
        FilesystemDecision::Deny
    );
    assert_eq!(
        restricted
            .access_for(&selector, &context)
            .expect("selector decision"),
        FilesystemDecision::Read
    );
    assert_eq!(
        restricted
            .access_for(&PathSelector::minimal(), &context)
            .expect("selector decision"),
        FilesystemDecision::Deny
    );
    assert_eq!(
        FilesystemPolicy::unrestricted()
            .access_for(&selector, &context)
            .expect("selector decision"),
        FilesystemDecision::Write
    );
    assert_eq!(
        FilesystemPolicy::external()
            .access_for(&selector, &context)
            .expect("selector decision"),
        FilesystemDecision::ExternallyEnforced
    );
    assert_eq!(
        FilesystemPolicy::external()
            .access_for_path(Path::new(&native_path("/workspace/file")), &context)
            .expect("external decision"),
        FilesystemDecision::ExternallyEnforced
    );
    assert_eq!(
        FilesystemPolicy::unrestricted()
            .normalized()
            .expect("valid unrestricted policy")
            .mode(),
        FilesystemMode::Unrestricted
    );
}

#[test]
fn non_restricted_filesystem_rules_are_rejected() {
    assert!(matches!(
        FilesystemPolicy::unrestricted().with_rule(FilesystemRule::new(
            PathSelector::minimal(),
            AccessMode::Read,
        )),
        Err(PolicyError::InvalidRule { .. })
    ));
}

#[test]
fn domain_rules_normalize_and_apply_deny_precedence() {
    let policy = NetworkPolicy::enabled()
        .with_domain("API.Example.com.", DomainAccess::Allow)
        .expect("allow rule")
        .with_domain("blocked.example.com", DomainAccess::Deny)
        .expect("deny rule");
    assert_eq!(policy.mode(), NetworkMode::Enabled);
    assert_eq!(policy.domain_mode(), DomainMode::Enabled);
    assert_eq!(policy.unix_socket_mode(), UnixSocketMode::Enabled);
    assert_eq!(policy.domains()[0].pattern(), "api.example.com");
    assert_eq!(
        policy
            .decision_for_domain("blocked.example.com")
            .expect("domain lookup"),
        NetworkDecision::Deny
    );
    assert_eq!(
        policy
            .decision_for_domain("api.example.com")
            .expect("domain lookup"),
        NetworkDecision::Allow
    );
    assert_eq!(policy.domains()[0].access(), DomainAccess::Allow);
    assert!(policy.unix_sockets().is_empty());
    assert_eq!(
        policy
            .decision_for_domain("api.example.com")
            .expect("allowed domain"),
        NetworkDecision::Allow
    );
    assert_eq!(
        policy
            .decision_for_domain("blocked.example.com")
            .expect("denied domain"),
        NetworkDecision::Deny
    );
}

#[test]
fn domain_rules_normalize_ports_brackets_and_ip_literals() {
    let policy = NetworkPolicy::enabled()
        .with_domain_mode(DomainMode::Restricted)
        .with_domain("Example.COM:443", DomainAccess::Allow)
        .expect("host with port")
        .with_domain("[2001:DB8::1]:443", DomainAccess::Allow)
        .expect("bracketed IPv6 host with port");

    assert_eq!(
        policy.domains()[0].pattern(),
        "example.com",
        "ports are not part of domain identity"
    );
    assert_eq!(policy.domains()[1].pattern(), "2001:db8::1");
    assert_eq!(
        policy
            .decision_for_domain("example.com:8443")
            .expect("host lookup"),
        NetworkDecision::Allow
    );
    assert_eq!(
        policy
            .decision_for_domain("[2001:DB8::1]:9443")
            .expect("IPv6 lookup"),
        NetworkDecision::Allow
    );
}

#[test]
fn domain_wildcards_have_explicit_apex_semantics() {
    let policy = NetworkPolicy::enabled()
        .with_domain_mode(DomainMode::Restricted)
        .with_domain("*.example.com", DomainAccess::Allow)
        .expect("subdomain wildcard")
        .with_domain("**.root.example", DomainAccess::Deny)
        .expect("apex wildcard");
    assert_eq!(
        policy
            .decision_for_domain("example.com")
            .expect("domain lookup"),
        NetworkDecision::Deny
    );
    assert_eq!(
        policy
            .decision_for_domain("api.example.com")
            .expect("domain lookup"),
        NetworkDecision::Allow
    );
    assert_eq!(
        policy
            .decision_for_domain("root.example")
            .expect("domain lookup"),
        NetworkDecision::Deny
    );
    assert_eq!(
        policy
            .decision_for_domain("api.root.example")
            .expect("domain lookup"),
        NetworkDecision::Deny
    );
}

#[test]
fn domain_rules_support_mid_label_globs() {
    let policy = NetworkPolicy::enabled()
        .with_domain_mode(DomainMode::Restricted)
        .with_domain("region*.v2.example.com", DomainAccess::Deny)
        .expect("mid-label wildcard")
        .with_domain("zone?.example.com", DomainAccess::Allow)
        .expect("single-character wildcard");

    assert_eq!(
        policy
            .decision_for_domain("region1.v2.example.com")
            .expect("domain lookup"),
        NetworkDecision::Deny
    );
    assert_eq!(
        policy
            .decision_for_domain("region.v2.example.com")
            .expect("domain lookup"),
        NetworkDecision::Deny
    );
    assert_eq!(
        policy
            .decision_for_domain("xregion1.v2.example.com")
            .expect("domain lookup"),
        NetworkDecision::Deny
    );
    assert_eq!(
        policy
            .decision_for_domain("zone1.example.com")
            .expect("domain lookup"),
        NetworkDecision::Allow
    );
    assert_eq!(
        policy
            .decision_for_domain("zone12.example.com")
            .expect("domain lookup"),
        NetworkDecision::Deny
    );
}

#[test]
fn domain_rules_support_character_classes() {
    let policy = NetworkPolicy::enabled()
        .with_domain_mode(DomainMode::Restricted)
        .with_domain("[a-c].example.com", DomainAccess::Allow)
        .expect("character class domain")
        .with_domain("[!x].blocked.example.com", DomainAccess::Deny)
        .expect("negative character class domain");

    assert_eq!(
        policy
            .decision_for_domain("a.example.com")
            .expect("domain lookup"),
        NetworkDecision::Allow
    );
    assert_eq!(
        policy
            .decision_for_domain("c.example.com")
            .expect("domain lookup"),
        NetworkDecision::Allow
    );
    assert_eq!(
        policy
            .decision_for_domain("d.example.com")
            .expect("domain lookup"),
        NetworkDecision::Deny
    );
    assert_eq!(
        policy
            .decision_for_domain("a.blocked.example.com")
            .expect("domain lookup"),
        NetworkDecision::Deny
    );
    assert_eq!(
        policy
            .decision_for_domain("x.blocked.example.com")
            .expect("domain lookup"),
        NetworkDecision::Deny
    );

    let with_port = NetworkPolicy::enabled()
        .with_domain_mode(DomainMode::Restricted)
        .with_domain("[a-c].example.com:443", DomainAccess::Allow)
        .expect("character class with a port");
    assert_eq!(
        with_port
            .decision_for_domain("b.example.com:443")
            .expect("domain lookup"),
        NetworkDecision::Allow
    );
}

#[test]
fn malformed_domains_and_non_absolute_sockets_are_rejected() {
    assert!(matches!(
        NetworkPolicy::enabled().with_domain("https://example.com", DomainAccess::Allow),
        Err(PolicyError::InvalidDomainPattern { .. })
    ));
    assert!(matches!(
        NetworkPolicy::enabled().with_unix_socket("docker.sock", DomainAccess::Allow),
        Err(PolicyError::ExpectedAbsolute { .. })
    ));
    for pattern in [
        "",
        "**.",
        "bad/path",
        "bad#fragment",
        "bad domain",
        "bad..domain",
        "bad\0domain",
        "[abc",
        "[::1]junk",
        "[::1]:bad",
        "example.com:",
        "example.com:garbage",
        "example.com:65536",
    ] {
        assert!(matches!(
            NetworkPolicy::enabled().with_domain(pattern, DomainAccess::Allow),
            Err(PolicyError::InvalidDomainPattern { .. })
        ));
    }
    assert!(matches!(
        NetworkPolicy::enabled().with_unix_socket("/run/bad\0.sock", DomainAccess::Allow),
        Err(PolicyError::PathContainsNul { .. })
    ));
}

#[test]
fn network_rules_expose_accessors_and_validate_local_modes() {
    let socket_path = if cfg!(windows) {
        r"C:\sandbox\socket"
    } else {
        "/run/sandbox.sock"
    };
    let policy = NetworkPolicy::disabled()
        .with_domain("*", DomainAccess::Deny)
        .expect("wildcard rule")
        .with_unix_socket(socket_path, DomainAccess::Allow)
        .expect("absolute socket");
    assert_eq!(policy.mode(), NetworkMode::Disabled);
    assert_eq!(policy.domains().len(), 1);
    assert_eq!(policy.unix_sockets().len(), 1);
    assert_eq!(
        policy.unix_sockets()[0].path().to_string_lossy(),
        socket_path
    );
    assert_eq!(policy.unix_sockets()[0].access(), DomainAccess::Allow);
    assert!(policy.validate().is_ok());
    assert_eq!(
        policy
            .decision_for_domain("anything.example")
            .expect("disabled network"),
        NetworkDecision::Deny
    );
    assert_eq!(
        policy
            .decision_for_unix_socket(Path::new(socket_path))
            .expect("socket decision"),
        NetworkDecision::Deny
    );
    let enabled = NetworkPolicy::enabled()
        .with_unix_socket(socket_path, DomainAccess::Deny)
        .expect("socket rule")
        .with_unix_socket(
            if cfg!(windows) { r"C:\sandbox" } else { "/run" },
            DomainAccess::Allow,
        )
        .expect("parent socket rule");
    assert_eq!(
        enabled
            .decision_for_unix_socket(Path::new(socket_path))
            .expect("socket decision"),
        NetworkDecision::Deny
    );
    assert_eq!(
        enabled
            .decision_for_unix_socket(Path::new(&native_path("/other.sock")))
            .expect("socket decision"),
        NetworkDecision::Allow
    );
    assert_eq!(
        enabled
            .decision_for_domain("unmatched.example")
            .expect("enabled network"),
        NetworkDecision::Allow
    );
    let allow_only = NetworkPolicy::enabled()
        .with_unix_socket_mode(UnixSocketMode::Restricted)
        .with_unix_socket(socket_path, DomainAccess::Allow)
        .expect("allow socket rule");
    assert_eq!(
        allow_only
            .decision_for_unix_socket(Path::new(socket_path))
            .expect("socket decision"),
        NetworkDecision::Allow
    );
    assert_eq!(
        allow_only
            .decision_for_unix_socket(Path::new(&format!("{socket_path}/child")))
            .expect("child socket decision"),
        NetworkDecision::Deny
    );
    assert_eq!(
        NetworkPolicy::external()
            .decision_for_domain("example.com")
            .expect("external network"),
        NetworkDecision::ExternallyEnforced
    );
    let allowlisted = NetworkPolicy::enabled()
        .with_domain_mode(DomainMode::Restricted)
        .with_domain("allowed.example", DomainAccess::Allow)
        .expect("allow domain")
        .with_unix_socket_mode(UnixSocketMode::Restricted)
        .with_unix_socket(socket_path, DomainAccess::Allow)
        .expect("allow socket");
    assert_eq!(
        allowlisted
            .decision_for_domain("allowed.example")
            .expect("allowlisted domain"),
        NetworkDecision::Allow
    );
    assert_eq!(
        allowlisted
            .decision_for_domain("other.example")
            .expect("unlisted domain"),
        NetworkDecision::Deny
    );
    assert_eq!(
        allowlisted
            .decision_for_unix_socket(Path::new(socket_path))
            .expect("socket decision"),
        NetworkDecision::Allow
    );
    assert_eq!(
        allowlisted
            .decision_for_unix_socket(Path::new(&native_path("/other.sock")))
            .expect("socket decision"),
        NetworkDecision::Deny
    );
}

#[test]
fn disabled_network_cannot_be_reenabled_by_a_domain_rule() {
    let policy = NetworkPolicy::disabled()
        .with_domain("example.com", DomainAccess::Allow)
        .expect("valid domain rule");

    assert_eq!(
        policy
            .decision_for_domain("example.com")
            .expect("domain decision"),
        NetworkDecision::Deny
    );
}

#[test]
fn network_decisions_preserve_external_enforcement() {
    let socket_path = native_path("/run/cageforge.sock");

    assert_eq!(
        NetworkPolicy::disabled()
            .decision_for_domain("example.com")
            .expect("disabled domain"),
        NetworkDecision::Deny
    );
    assert_eq!(
        NetworkPolicy::enabled()
            .decision_for_domain("example.com")
            .expect("enabled domain"),
        NetworkDecision::Allow
    );
    assert_eq!(
        NetworkPolicy::external()
            .decision_for_domain("example.com")
            .expect("external domain"),
        NetworkDecision::ExternallyEnforced
    );
    assert_eq!(
        NetworkPolicy::external()
            .decision_for_unix_socket(Path::new(&socket_path))
            .expect("external socket"),
        NetworkDecision::ExternallyEnforced
    );
    assert!(NetworkDecision::ExternallyEnforced.is_externally_enforced());
}

#[test]
fn resolved_domains_reject_private_addresses_and_dns_failures_by_default() {
    let policy = NetworkPolicy::enabled()
        .with_domain("*", DomainAccess::Allow)
        .expect("wildcard domain");

    assert_eq!(
        policy
            .decision_for_domain_with_resolved_ips(
                "service.example",
                &["93.184.216.34".parse().expect("public address")],
            )
            .expect("public domain"),
        NetworkDecision::Allow
    );
    assert_eq!(
        policy
            .decision_for_domain_with_resolved_ips(
                "service.example",
                &["127.0.0.1".parse().expect("loopback address")],
            )
            .expect("loopback domain"),
        NetworkDecision::Deny
    );
    assert_eq!(
        policy
            .decision_for_domain_with_resolved_ips("service.example", &[])
            .expect("failed resolution"),
        NetworkDecision::Deny
    );
    assert_eq!(
        policy
            .decision_for_domain_with_resolved_ips(
                "service.example",
                &[
                    "93.184.216.34".parse().expect("public address"),
                    "10.0.0.1".parse().expect("private address"),
                ],
            )
            .expect("mixed resolution"),
        NetworkDecision::Deny
    );
    for address in ["169.254.1.1", "::1", "fc00::1"] {
        assert_eq!(
            policy
                .decision_for_domain_with_resolved_ips(
                    "service.example",
                    &[address.parse().expect("non-public address")],
                )
                .expect("non-public domain"),
            NetworkDecision::Deny,
            "{address} must remain denied"
        );
    }
}

#[test]
fn resolved_domains_support_explicit_literal_and_policy_opt_ins() {
    let literal = NetworkPolicy::enabled()
        .with_domain("127.0.0.1", DomainAccess::Allow)
        .expect("literal allow rule");
    assert_eq!(
        literal
            .decision_for_domain_with_resolved_ips("127.0.0.1", &[])
            .expect("literal address"),
        NetworkDecision::Allow
    );

    let opted_in = NetworkPolicy::enabled()
        .with_domain("service.example", DomainAccess::Allow)
        .expect("domain allow rule")
        .with_local_network_access(LocalNetworkAccess::Allow);
    assert_eq!(
        opted_in
            .decision_for_domain_with_resolved_ips(
                "service.example",
                &["192.168.1.10".parse().expect("private address")],
            )
            .expect("explicit local access"),
        NetworkDecision::Allow
    );
    assert_eq!(
        opted_in
            .decision_for_domain_with_resolved_ips("service.example", &[])
            .expect("failed resolution"),
        NetworkDecision::Deny
    );

    let localhost = NetworkPolicy::enabled()
        .with_domain("localhost", DomainAccess::Allow)
        .expect("localhost allow rule");
    assert_eq!(
        localhost
            .decision_for_domain_with_resolved_ips(
                "LOCALHOST.",
                &["93.184.216.34".parse().expect("public address")],
            )
            .expect("explicit localhost access"),
        NetworkDecision::Allow
    );
    for address in ["127.0.0.1", "::1"] {
        assert_eq!(
            localhost
                .decision_for_domain_with_resolved_ips(
                    "localhost",
                    &[address.parse().expect("loopback address")],
                )
                .expect("explicit localhost loopback access"),
            NetworkDecision::Allow
        );
    }
    for address in ["10.0.0.1", "169.254.169.254", "fc00::1"] {
        assert_eq!(
            localhost
                .decision_for_domain_with_resolved_ips(
                    "localhost",
                    &[address.parse().expect("non-loopback local address")],
                )
                .expect("explicit localhost non-loopback access"),
            NetworkDecision::Deny
        );
    }

    let hostname = NetworkPolicy::enabled()
        .with_domain("service.example", DomainAccess::Allow)
        .expect("hostname allow rule");
    assert_eq!(
        hostname
            .decision_for_domain_with_resolved_ips(
                "service.example",
                &["127.0.0.1".parse().expect("loopback address")],
            )
            .expect("hostname with loopback resolution"),
        NetworkDecision::Deny
    );
}

#[test]
fn public_ip_literals_do_not_require_dns_results() {
    assert_eq!(
        NetworkPolicy::enabled()
            .decision_for_domain_with_resolved_ips("8.8.8.8", &[])
            .expect("public IP literal"),
        NetworkDecision::Allow
    );
}

#[test]
fn path_selector_validates_empty_and_absolute_workspace_paths() {
    assert!(matches!(
        PathSelector::absolute("").expect_err("empty absolute path should fail"),
        PolicyError::EmptyPath
    ));
    assert!(matches!(
        PathSelector::workspace("").expect_err("empty workspace path should fail"),
        PolicyError::EmptyPath
    ));
    assert!(matches!(
        PathSelector::absolute("/workspace/bad\0path"),
        Err(PolicyError::PathContainsNul { .. })
    ));
    assert!(matches!(
        PathSelector::workspace("bad\0path"),
        Err(PolicyError::PathContainsNul { .. })
    ));
    assert!(matches!(
        PathResolutionContext::new().with_tmpdir("/tmp/bad\0path"),
        Err(PolicyError::PathContainsNul { .. })
    ));
    assert!(matches!(
        PathSelector::workspace(native_path("/")).expect_err("absolute workspace path should fail"),
        PolicyError::ExpectedRelative { .. }
    ));
    assert_eq!(
        PathSelector::workspace(".").expect("workspace root path"),
        PathSelector::workspace_root()
    );
}

#[test]
fn external_network_policy_cannot_carry_local_rules() {
    assert!(matches!(
        NetworkPolicy::external().with_domain("example.com", DomainAccess::Allow),
        Err(PolicyError::InvalidRule { .. })
    ));
    assert!(matches!(
        NetworkPolicy::external()
            .with_unix_socket(native_path("/run/sandbox.sock"), DomainAccess::Allow,),
        Err(PolicyError::InvalidRule { .. })
    ));
}

#[test]
fn socket_access_rejects_parent_traversal_and_nul() {
    let policy = NetworkPolicy::enabled();
    let parent_path = if cfg!(windows) {
        r"C:\sandbox\..\outside.sock"
    } else {
        "/run/../outside.sock"
    };
    assert!(matches!(
        policy.decision_for_unix_socket(Path::new(parent_path)),
        Err(PolicyError::ParentTraversal { .. })
    ));
    assert!(matches!(
        policy.decision_for_unix_socket(Path::new("/run/bad\0.sock")),
        Err(PolicyError::PathContainsNul { .. })
    ));
    assert!(matches!(
        NetworkPolicy::external()
            .decision_for_unix_socket(Path::new(&native_path("/run/bad\0.sock"))),
        Err(PolicyError::PathContainsNul { .. })
    ));
}

#[cfg(unix)]
#[test]
fn unix_path_forms_are_validated_as_posix_paths() {
    assert!(PathSelector::absolute("/var/lib/cageforge").is_ok());
    assert_eq!(
        PathSelector::workspace("src/lib.rs")
            .expect("POSIX workspace path")
            .path(),
        Some(Path::new("src/lib.rs"))
    );
    assert!(PathPattern::absolute("/var/lib/cageforge/**/config.toml").is_ok());
    assert!(
        NetworkPolicy::enabled()
            .with_unix_socket("/run/cageforge.sock", DomainAccess::Allow)
            .is_ok()
    );
}

#[cfg(windows)]
#[test]
fn windows_path_forms_are_validated_as_windows_paths() {
    assert!(PathSelector::absolute(r"C:\var\lib\cageforge").is_ok());
    assert!(PathSelector::absolute(r"\\server\share\cageforge").is_ok());
    assert_eq!(
        PathSelector::workspace(r"src\lib.rs")
            .expect("Windows workspace path")
            .path(),
        Some(Path::new(r"src\lib.rs"))
    );
    assert!(matches!(
        PathSelector::workspace(r"..\outside"),
        Err(PolicyError::ParentTraversal { .. })
    ));
    assert!(PathPattern::absolute(r"C:\var\lib\cageforge\**\config.toml").is_ok());
    assert!(
        NetworkPolicy::enabled()
            .with_unix_socket(r"C:\run\cageforge.sock", DomainAccess::Allow)
            .is_ok()
    );
}

#[cfg(windows)]
#[test]
fn filesystem_matching_is_case_insensitive_on_windows() {
    let context = PathResolutionContext::new()
        .with_workspace_root(r"C:\Workspace")
        .expect("workspace root");
    let policy = FilesystemPolicy::restricted([
        FilesystemRule::new(PathSelector::workspace_root(), AccessMode::Write),
        FilesystemRule::workspace_glob(r"Secrets\**", AccessMode::Deny).expect("deny glob"),
    ]);

    assert_eq!(
        policy
            .access_for_path(Path::new(r"c:\workspace\Secrets\token"), &context)
            .expect("case-variant matching path"),
        FilesystemDecision::Deny
    );
}

#[test]
fn built_in_policies_are_documented_and_distinct() {
    let read_only = SandboxPolicy::read_only();
    let workspace = SandboxPolicy::workspace();
    let full_access = SandboxPolicy::full_access();
    let context = PathResolutionContext::new()
        .with_root(native_path("/"))
        .expect("system root")
        .with_workspace_root(native_path("/workspace"))
        .expect("workspace root");

    assert_eq!(read_only.network().mode(), NetworkMode::Disabled);
    assert_eq!(workspace.network().mode(), NetworkMode::Disabled);
    assert_eq!(full_access.network().mode(), NetworkMode::Enabled);
    assert_eq!(
        full_access.network().local_network_access(),
        LocalNetworkAccess::Allow
    );
    assert_eq!(
        full_access
            .network()
            .decision_for_domain_with_resolved_ips(
                "service.example",
                &["127.0.0.1".parse().expect("loopback address")],
            )
            .expect("unrestricted network decision"),
        NetworkDecision::Allow
    );
    assert_eq!(
        workspace
            .filesystem()
            .access_for(&PathSelector::workspace_root(), &context)
            .expect("workspace selector decision"),
        FilesystemDecision::Write
    );
    assert_eq!(
        read_only
            .filesystem()
            .access_for(&PathSelector::workspace_root(), &context)
            .expect("workspace selector decision"),
        FilesystemDecision::Read
    );
    assert_eq!(
        read_only
            .filesystem()
            .access_for_path(Path::new(&native_path("/outside/file")), &context)
            .expect("root read decision"),
        FilesystemDecision::Read
    );
    assert_eq!(
        full_access.filesystem().mode(),
        FilesystemMode::Unrestricted
    );
    assert!(read_only.validate().is_ok());
    assert!(workspace.validate().is_ok());
    assert!(full_access.validate().is_ok());
}

fn native_path(unix_path: &str) -> String {
    if cfg!(windows) {
        match unix_path {
            "/workspace" => r"C:\workspace".to_string(),
            "/workspace/src" => r"C:\workspace\src".to_string(),
            "/workspace/src/secrets" => r"C:\workspace\src\secrets".to_string(),
            "/workspace/nested/token.secret" => r"C:\workspace\nested\token.secret".to_string(),
            "/workspace/config.toml" => r"C:\workspace\config.toml".to_string(),
            "/workspace/README.md" => r"C:\workspace\README.md".to_string(),
            "/workspace/.git/config" => r"C:\workspace\.git\config".to_string(),
            "/workspace/src/main.rs" => r"C:\workspace\src\main.rs".to_string(),
            "/workspace/../outside" => r"C:\workspace\..\outside".to_string(),
            "/outside/file" => r"C:\outside\file".to_string(),
            "/other.sock" => r"C:\other.sock".to_string(),
            "/run" => r"C:\run".to_string(),
            "/run/sandbox.sock" => r"C:\run\sandbox.sock".to_string(),
            "/tmp" => r"C:\tmp".to_string(),
            "/tmp/runtime" => r"C:\tmp\runtime".to_string(),
            "/usr/bin" => r"C:\usr\bin".to_string(),
            value => {
                let value = value.replace('/', "\\");
                if value.starts_with('\\') {
                    format!("C:{value}")
                } else {
                    value
                }
            }
        }
    } else {
        unix_path.to_string()
    }
}
