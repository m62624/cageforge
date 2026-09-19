// SPDX-License-Identifier: Apache-2.0

#![cfg(target_os = "macos")]

use std::fs;
use std::path::{Path, PathBuf};

use cageforge_config::Config;
use cageforge_permissions::PlatformId;

fn toml_examples() -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../cageforge-config/examples");
    let mut pending = vec![root];
    let mut examples = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", directory.display()))
        {
            let entry = entry.expect("configuration example directory entry");
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
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

fn resolves_on_macos(path: &Path) -> bool {
    let path = path.to_string_lossy();
    !path.contains("platform-targets-windows")
        && !path.contains("runnable/linux")
        && !path.contains("runnable/windows")
}

#[test]
fn every_configuration_example_is_checked_by_the_macos_crate() {
    let examples = toml_examples();
    assert!(!examples.is_empty(), "configuration examples must exist");

    for path in examples {
        let config = Config::from_file(&path)
            .unwrap_or_else(|error| panic!("{} should parse: {error}", path.display()));
        if !resolves_on_macos(&path) {
            continue;
        }
        config
            .resolve_default_for_platform(PlatformId::Macos)
            .unwrap_or_else(|error| panic!("{} should resolve on macOS: {error}", path.display()));
        for profile in config.profile_names() {
            config
                .resolve_for_platform(profile, PlatformId::Macos)
                .unwrap_or_else(|error| {
                    panic!(
                        "{} profile {profile:?} should resolve on macOS: {error}",
                        path.display()
                    )
                });
        }
    }
}

#[test]
fn local_ipc_example_selects_a_macos_unix_socket() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../cageforge-config/examples/local-ipc-platforms.toml");
    let resolved = Config::from_file(&path)
        .expect("local IPC example")
        .resolve_default_for_platform(PlatformId::Macos)
        .expect("macOS local IPC profile");
    let endpoint = resolved
        .policy()
        .network()
        .local_ipc()
        .first()
        .expect("macOS local IPC endpoint");
    assert!(endpoint.endpoint().unix_path().is_some());
}
