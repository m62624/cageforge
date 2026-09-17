// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::{Path, PathBuf};

use cageforge_config::Config;
use cageforge_policy::FilesystemTarget;

fn toml_examples(directory: &Path) -> Vec<PathBuf> {
    let mut examples = Vec::new();
    let mut directories = vec![directory.to_path_buf()];

    while let Some(directory) = directories.pop() {
        for entry in fs::read_dir(&directory)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", directory.display()))
        {
            let entry = entry.expect("example directory entry");
            let path = entry.path();
            if path.is_dir() {
                directories.push(path);
            } else if path
                .extension()
                .is_some_and(|extension| extension == "toml")
            {
                examples.push(path);
            }
        }
    }

    examples.sort();
    examples
}

fn is_host_compatible(path: &Path) -> bool {
    let path = path.to_string_lossy();
    let windows_example =
        path.contains("platform-targets-windows") || path.contains("runnable/windows");
    let unix_example = path.contains("platform-targets-unix");
    let linux_example = path.contains("runnable/linux");
    let macos_example = path.contains("runnable/macos");
    (!windows_example || cfg!(windows))
        && (!unix_example || cfg!(unix))
        && (!linux_example || cfg!(target_os = "linux"))
        && (!macos_example || cfg!(target_os = "macos"))
}

fn is_runnable_example(path: &Path) -> bool {
    path.to_string_lossy().contains("examples/runnable/")
}

#[test]
fn every_checked_in_toml_example_parses_and_host_examples_resolve() {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples");
    let examples = toml_examples(&directory);
    assert!(
        !examples.is_empty(),
        "the examples directory must contain TOML"
    );

    for path in examples {
        let source = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
        let config = Config::from_toml(&source)
            .unwrap_or_else(|error| panic!("{} should parse: {error}", path.display()));
        if !is_host_compatible(&path) {
            continue;
        }
        let default_profile = config
            .default_profile_name()
            .unwrap_or_else(|| panic!("{} must declare default_profile", path.display()));
        config.resolve_default().unwrap_or_else(|error| {
            panic!(
                "{} default profile {default_profile:?} should resolve: {error}",
                path.display()
            )
        });

        for profile in config.profile_names() {
            config.resolve(profile).unwrap_or_else(|error| {
                panic!(
                    "{} profile {profile:?} should resolve: {error}",
                    path.display()
                )
            });
        }
    }
}

#[test]
fn runnable_examples_allow_the_platform_minimal_runtime() {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples");
    for path in toml_examples(&directory)
        .into_iter()
        .filter(|path| is_runnable_example(path) && is_host_compatible(path))
    {
        let source = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
        let resolved = Config::from_toml(&source)
            .unwrap_or_else(|error| panic!("{} should parse: {error}", path.display()))
            .resolve_default()
            .unwrap_or_else(|error| panic!("{} should resolve: {error}", path.display()));
        assert!(
            resolved
                .policy()
                .filesystem()
                .entries()
                .iter()
                .any(|entry| matches!(entry.target(), FilesystemTarget::Scope(selector) if selector.is_minimal_scope())),
            "{} must explicitly allow the platform minimal runtime",
            path.display()
        );
    }
}
