// SPDX-License-Identifier: Apache-2.0

#![cfg(target_os = "linux")]

use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn builder_stages_original_bwrap_binary() {
    let directory = tempdir().expect("temporary staging directory");
    let binary = directory.path().join("bwrap");
    let builder = std::env::var("CARGO_BIN_EXE_cageforge-bwrap")
        .expect("Cargo should expose the builder binary path");
    let output = Command::new(builder)
        .args(["--output", binary.to_str().expect("UTF-8 temporary path")])
        .output()
        .expect("run bwrap builder");
    assert!(output.status.success(), "bwrap staging failed: {output:?}");

    let version = Command::new(&binary)
        .arg("--version")
        .output()
        .expect("run staged bwrap");
    assert!(
        version.status.success(),
        "bwrap --version failed: {version:?}"
    );
    assert_eq!(
        String::from_utf8_lossy(&version.stdout).trim(),
        "bubblewrap 0.11.2"
    );
    assert!(
        fs::metadata(binary)
            .expect("staged bwrap metadata")
            .is_file()
    );
    assert!(directory.path().join("bwrap.sha256").is_file());
}
