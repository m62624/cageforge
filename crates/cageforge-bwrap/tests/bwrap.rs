// SPDX-License-Identifier: Apache-2.0

#![cfg(target_os = "linux")]

#[cfg(feature = "build-from-source")]
use std::fs;
#[cfg(feature = "build-from-source")]
use std::process::Command;
#[cfg(feature = "build-from-source")]
use tempfile::tempdir;

#[cfg(feature = "build-from-source")]
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

#[cfg(all(feature = "embedded", target_os = "linux"))]
#[test]
fn embedded_bubblewrap_matches_its_architecture_specific_digest() {
    use sha2::{Digest, Sha256};

    let digest = Sha256::digest(cageforge_bwrap::bundled_bubblewrap());
    let actual = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();

    assert_eq!(actual, cageforge_bwrap::bundled_bubblewrap_sha256());
    assert_eq!(&cageforge_bwrap::bundled_bubblewrap()[..4], b"\x7fELF");
}
