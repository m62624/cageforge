// Copyright 2026 Mansur Azatbek
// SPDX-License-Identifier: Apache-2.0

use cageforge_policy::AccessMode;
use cageforge_policy::DomainAccess;
use cageforge_policy::DomainMode;
use cageforge_policy::FilesystemMode;
use cageforge_policy::FilesystemPolicy;
use cageforge_policy::FilesystemRule;
use cageforge_policy::FilesystemTarget;
use cageforge_policy::MissingPathBehavior;
use cageforge_policy::NetworkMode;
use cageforge_policy::NetworkPolicy;
use cageforge_policy::PathPattern;
use cageforge_policy::PathResolutionContext;
use cageforge_policy::PathSelector;
use cageforge_policy::PolicyError;
use cageforge_policy::SandboxPolicy;
use cageforge_policy::UnixSocketMode;
use pretty_assertions::assert_eq;
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
        PathSelector::absolute(absolute).expect("native absolute path"),
        PathSelector::Absolute(absolute.into())
    );
    assert!(matches!(
        PathSelector::absolute("workspace"),
        Err(PolicyError::ExpectedAbsolute { .. })
    ));
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
        PathSelector::minimal(),
        PathSelector::tmpdir(),
        PathSelector::slash_tmp(),
    ];
    assert!(selectors.iter().all(PathSelector::is_special));
    assert!(selectors.iter().all(|selector| selector.path().is_none()));
    assert_ne!(selectors[0], selectors[1]);
    assert_ne!(selectors[1], selectors[2]);
}

#[test]
fn access_modes_follow_security_precedence() {
    assert!(AccessMode::Write.can_read());
    assert!(AccessMode::Write.can_write());
    assert!(!AccessMode::Read.can_write());
    assert_eq!(
        AccessMode::Read.most_restrictive(AccessMode::Deny),
        AccessMode::Deny
    );
    assert_eq!(
        AccessMode::Read.most_restrictive(AccessMode::Write),
        AccessMode::Write
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
fn policy_errors_have_actionable_display_messages() {
    let errors = [
        PolicyError::EmptyPath,
        PolicyError::ExpectedAbsolute {
            path: "relative".into(),
        },
        PolicyError::ExpectedRelative {
            path: "/absolute".into(),
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
        .with_workspace_root(native_path("/workspace"))
        .expect("workspace root")
        .with_minimal_path(native_path("/usr/bin"))
        .expect("minimal path")
        .with_tmpdir(native_path("/tmp/runtime"))
        .expect("tmpdir")
        .with_slash_tmp(native_path("/tmp"))
        .expect("slash tmp");
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
        PathSelector::absolute(native_path("/workspace"))
            .expect("absolute selector")
            .resolve(&context),
        vec![native_path("/workspace")]
    );
    assert_eq!(context.workspace_roots(), &[native_path("/workspace")]);
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
        FilesystemRule::from_target(FilesystemTarget::Glob(workspace), AccessMode::Deny),
        FilesystemRule::from_target(FilesystemTarget::Glob(absolute), AccessMode::Read),
    ]);
    assert_eq!(
        policy
            .access_for_path(
                Path::new(&native_path("/workspace/nested/token.secret")),
                &context,
            )
            .expect("secret lookup"),
        AccessMode::Deny
    );
    assert_eq!(
        policy
            .access_for_path(Path::new(&native_path("/workspace/config.toml")), &context)
            .expect("config lookup"),
        AccessMode::Read
    );
    for (pattern, expected) in [
        ("", "pattern cannot be empty"),
        ("../secret", "parent traversal is not allowed"),
        (".", "pattern must contain at least one component"),
        ("*.toml", "absolute glob must use a native absolute path"),
        ("[secret]", "character classes are not supported"),
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
        AccessMode::Read
    );
    assert_eq!(
        policy
            .access_for_path(
                Path::new(&native_path("/workspace/src/secrets/key")),
                &context,
            )
            .expect("secret lookup"),
        AccessMode::Deny
    );
    assert_eq!(
        policy
            .access_for_path(Path::new(&native_path("/workspace/README.md")), &context)
            .expect("workspace lookup"),
        AccessMode::Write
    );
    assert_eq!(
        policy
            .access_for_path(Path::new(&native_path("/outside/file")), &context)
            .expect("outside lookup"),
        AccessMode::Deny
    );
    assert!(matches!(
        policy.access_for_path(Path::new("relative"), &context),
        Err(PolicyError::ExpectedAbsolute { .. })
    ));
    assert!(matches!(
        policy.access_for_path(Path::new(&native_path("/workspace/../outside")), &context,),
        Err(PolicyError::ParentTraversal { .. })
    ));
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
        );
    let policy = FilesystemPolicy::restricted([protected])
        .with_glob_scan_max_depth(NonZeroUsize::new(4).expect("non-zero depth"));
    assert_eq!(
        policy.entries()[0].missing_path_behavior(),
        MissingPathBehavior::Skip
    );
    assert_eq!(policy.glob_scan_max_depth(), NonZeroUsize::new(4));
    assert_eq!(
        policy
            .access_for_path(Path::new(&native_path("/workspace/src/main.rs")), &context)
            .expect("writable lookup"),
        AccessMode::Write
    );
    assert_eq!(
        policy
            .access_for_path(Path::new(&native_path("/workspace/.git/config")), &context)
            .expect("protected lookup"),
        AccessMode::Read
    );
    let explicit_write = policy.clone().with_rule(FilesystemRule::new(
        PathSelector::workspace(".git").expect("explicit selector"),
        AccessMode::Write,
    ));
    assert_eq!(
        explicit_write
            .access_for_path(Path::new(&native_path("/workspace/.git/config")), &context)
            .expect("explicit write lookup"),
        AccessMode::Write
    );
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
            .with_read_only_subpath(PathSelector::minimal()),
    ])
    .normalized()
    .expect("duplicate rules");
    assert_eq!(normalized.entries().len(), 1);
    assert_eq!(
        normalized.entries()[0].missing_path_behavior(),
        MissingPathBehavior::Error
    );
    assert_eq!(normalized.entries()[0].read_only_subpaths().len(), 1);
    assert!(matches!(
        FilesystemPolicy::unrestricted()
            .with_glob_scan_max_depth(NonZeroUsize::new(1).expect("depth"))
            .validate(),
        Err(PolicyError::InvalidRule { .. })
    ));
    assert!(matches!(
        FilesystemPolicy::restricted([FilesystemRule::new(
            PathSelector::workspace_root(),
            AccessMode::Read,
        )
        .with_read_only_subpath(PathSelector::minimal())])
        .validate(),
        Err(PolicyError::InvalidRule { .. })
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
    assert_eq!(normalized.access_for(&selector), AccessMode::Deny);
}

#[test]
fn filesystem_modes_have_explicit_access_behavior() {
    let selector = PathSelector::workspace_root();
    let restricted =
        FilesystemPolicy::restricted([FilesystemRule::new(selector.clone(), AccessMode::Read)]);
    assert_eq!(restricted.mode(), FilesystemMode::Restricted);
    assert_eq!(restricted.access_for(&selector), AccessMode::Read);
    assert_eq!(
        restricted.access_for(&PathSelector::minimal()),
        AccessMode::Deny
    );
    assert_eq!(
        FilesystemPolicy::unrestricted().access_for(&selector),
        AccessMode::Write
    );
    assert_eq!(
        FilesystemPolicy::external().access_for(&selector),
        AccessMode::Deny
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
    let policy = FilesystemPolicy::unrestricted().with_rule(FilesystemRule::new(
        PathSelector::minimal(),
        AccessMode::Read,
    ));
    assert!(matches!(
        policy.validate(),
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
            .access_for_domain("blocked.example.com")
            .expect("domain lookup"),
        Some(DomainAccess::Deny)
    );
    assert_eq!(
        policy
            .access_for_domain("api.example.com")
            .expect("domain lookup"),
        Some(DomainAccess::Allow)
    );
    assert_eq!(policy.domains()[0].access(), DomainAccess::Allow);
    assert!(policy.unix_sockets().is_empty());
    assert!(
        policy
            .allows_domain("api.example.com")
            .expect("allowed domain")
    );
    assert!(
        !policy
            .allows_domain("blocked.example.com")
            .expect("denied domain")
    );
}

#[test]
fn domain_wildcards_have_explicit_apex_semantics() {
    let policy = NetworkPolicy::enabled()
        .with_domain("*.example.com", DomainAccess::Allow)
        .expect("subdomain wildcard")
        .with_domain("**.root.example", DomainAccess::Deny)
        .expect("apex wildcard");
    assert_eq!(
        policy
            .access_for_domain("example.com")
            .expect("domain lookup"),
        None
    );
    assert_eq!(
        policy
            .access_for_domain("api.example.com")
            .expect("domain lookup"),
        Some(DomainAccess::Allow)
    );
    assert_eq!(
        policy
            .access_for_domain("root.example")
            .expect("domain lookup"),
        Some(DomainAccess::Deny)
    );
    assert_eq!(
        policy
            .access_for_domain("api.root.example")
            .expect("domain lookup"),
        Some(DomainAccess::Deny)
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
        "*.bad*",
        "bad/path",
        "bad?query",
        "bad#fragment",
        "bad domain",
    ] {
        assert!(matches!(
            NetworkPolicy::enabled().with_domain(pattern, DomainAccess::Allow),
            Err(PolicyError::InvalidDomainPattern { .. })
        ));
    }
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
            .access_for_domain("anything.example")
            .expect("lookup"),
        Some(DomainAccess::Deny)
    );
    assert!(
        !policy
            .allows_domain("anything.example")
            .expect("disabled network")
    );
    assert!(!policy.allows_unix_socket(Path::new(socket_path)));
    let enabled = NetworkPolicy::enabled()
        .with_unix_socket(socket_path, DomainAccess::Deny)
        .expect("socket rule")
        .with_unix_socket(
            if cfg!(windows) { r"C:\sandbox" } else { "/run" },
            DomainAccess::Allow,
        )
        .expect("parent socket rule");
    assert!(!enabled.allows_unix_socket(Path::new(socket_path)));
    assert!(enabled.allows_unix_socket(Path::new(&native_path("/other.sock"))));
    assert!(
        enabled
            .allows_domain("unmatched.example")
            .expect("enabled network")
    );
    let allow_only = NetworkPolicy::enabled()
        .with_unix_socket(socket_path, DomainAccess::Allow)
        .expect("allow socket rule");
    assert!(allow_only.allows_unix_socket(Path::new(socket_path)));
    assert!(
        !NetworkPolicy::external()
            .allows_domain("example.com")
            .expect("external network")
    );
    let allowlisted = NetworkPolicy::enabled()
        .with_domain_mode(DomainMode::Restricted)
        .with_domain("allowed.example", DomainAccess::Allow)
        .expect("allow domain")
        .with_unix_socket_mode(UnixSocketMode::Restricted)
        .with_unix_socket(socket_path, DomainAccess::Allow)
        .expect("allow socket");
    assert!(
        allowlisted
            .allows_domain("allowed.example")
            .expect("allowlisted domain")
    );
    assert!(
        !allowlisted
            .allows_domain("other.example")
            .expect("unlisted domain")
    );
    assert!(allowlisted.allows_unix_socket(Path::new(socket_path)));
    assert!(!allowlisted.allows_unix_socket(Path::new(&native_path("/other.sock"))));
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
        PathSelector::workspace(native_path("/")).expect_err("absolute workspace path should fail"),
        PolicyError::ExpectedRelative { .. }
    ));
    assert_eq!(
        PathSelector::workspace(".").expect("workspace root path"),
        PathSelector::WorkspaceRoot(".".into())
    );
}

#[test]
fn external_network_policy_cannot_carry_local_rules() {
    let policy = NetworkPolicy::external()
        .with_domain("example.com", DomainAccess::Allow)
        .expect("domain syntax is valid");
    assert!(matches!(
        policy.validate(),
        Err(PolicyError::InvalidRule { .. })
    ));
}

#[test]
fn built_in_policies_are_documented_and_distinct() {
    let read_only = SandboxPolicy::read_only();
    let workspace = SandboxPolicy::workspace();
    let full_access = SandboxPolicy::full_access();

    assert_eq!(read_only.network().mode(), NetworkMode::Disabled);
    assert_eq!(workspace.network().mode(), NetworkMode::Disabled);
    assert_eq!(full_access.network().mode(), NetworkMode::Enabled);
    assert_eq!(
        workspace
            .filesystem()
            .access_for(&PathSelector::workspace_root()),
        AccessMode::Write
    );
    assert_eq!(
        read_only
            .filesystem()
            .access_for(&PathSelector::workspace_root()),
        AccessMode::Read
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
