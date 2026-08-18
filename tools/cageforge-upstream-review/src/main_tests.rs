use super::*;

#[test]
fn repository_relative_paths_reject_empty_absolute_and_parent_paths() {
    assert!(validate_repo_relative_path("", "path").is_err());
    assert!(validate_repo_relative_path("/absolute", "path").is_err());
    assert!(validate_repo_relative_path("nested/../escape", "path").is_err());
    assert!(validate_repo_relative_path("codex-rs/config/src", "path").is_ok());
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
