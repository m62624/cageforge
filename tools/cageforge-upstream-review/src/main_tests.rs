// SPDX-License-Identifier: Apache-2.0

use super::*;

#[test]
fn repository_relative_paths_reject_empty_absolute_and_parent_paths() {
    assert!(validate_repo_relative_path("", "path").is_err());
    assert!(validate_repo_relative_path("/absolute", "path").is_err());
    assert!(validate_repo_relative_path("nested/../escape", "path").is_err());
    assert!(validate_repo_relative_path("codex-rs/config/src", "path").is_ok());
}

#[test]
fn diff_targets_are_resolved_to_commits_before_git_diff() {
    let repository_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let commit = resolve_commit(repository_root, "HEAD").expect("HEAD is a commit");
    assert_eq!(commit.len(), 40);
    assert!(resolve_commit(repository_root, "--output=/tmp/cageforge-review").is_err());
}

#[test]
fn upstream_review_configuration_rejects_unknown_fields() {
    let result = toml::from_str::<Config>(
        r#"
[upstream]
repository = "https://example.invalid/repository"
path = "../upstream"
branch = "main"
unexpected = true

[[scope]]
name = "policy"
upstream_paths = ["src/policy.rs"]
"#,
    );
    assert!(result.is_err());
}

#[test]
fn scope_pathspecs_watch_possible_rust_module_directories() {
    let scope = Scope {
        name: "config".to_owned(),
        upstream_paths: vec!["codex-rs/config/src/permissions_toml.rs".to_owned()],
        local_paths: Vec::new(),
    };

    assert_eq!(
        scope_pathspecs(&[&scope]),
        [
            "codex-rs/config/src/permissions_toml".to_owned(),
            "codex-rs/config/src/permissions_toml.rs".to_owned()
        ]
    );
}

#[test]
fn scope_pathspecs_watch_the_parent_of_mod_rs() {
    let scope = Scope {
        name: "sandboxing".to_owned(),
        upstream_paths: vec!["codex-rs/core/src/sandboxing/mod.rs".to_owned()],
        local_paths: Vec::new(),
    };

    assert_eq!(
        scope_pathspecs(&[&scope]),
        [
            "codex-rs/core/src/sandboxing".to_owned(),
            "codex-rs/core/src/sandboxing/mod.rs".to_owned()
        ]
    );
}

#[test]
fn git_diff_uses_literal_pathspecs_as_a_global_option() {
    let repository_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    run_git_diff(
        repository_root,
        "HEAD",
        "HEAD",
        &["Cargo.toml".to_owned()],
        &["--stat"],
    )
    .expect("literal pathspec diff should execute");
}
