// SPDX-License-Identifier: Apache-2.0

use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;

use pretty_assertions::assert_eq;

use super::{
    ProbeError, can_fall_back_to_bundled, find_in_search_paths, missing_help_flags,
    resource_directory, run_probe, verify_bundled_digest,
};
use crate::config::ResourceDirectorySource;
use crate::error::LinuxBackendError;

#[test]
fn executable_discovery_skips_workspace_local_and_non_executable_candidates() {
    let temporary = tempfile::tempdir().expect("temporary root");
    let workspace = temporary.path().join("workspace");
    let local_bin = workspace.join("bin");
    let non_executable_bin = temporary.path().join("non-executable");
    let trusted_bin = temporary.path().join("trusted");
    for directory in [&local_bin, &non_executable_bin, &trusted_bin] {
        fs::create_dir_all(directory).expect("search directory");
    }
    write_program(&local_bin.join("bwrap"), 0o755, "#!/bin/sh\nexit 99\n");
    write_program(
        &non_executable_bin.join("bwrap"),
        0o644,
        "#!/bin/sh\nexit 98\n",
    );
    let expected = trusted_bin.join("bwrap");
    write_program(&expected, 0o755, "#!/bin/sh\nexit 0\n");

    let selected = find_in_search_paths(
        "bwrap",
        [local_bin, non_executable_bin, trusted_bin],
        &workspace,
    );

    assert_eq!(
        selected,
        Some(fs::canonicalize(expected).expect("canonical trusted executable"))
    );
}

#[test]
fn executable_probe_has_a_hard_deadline() {
    let temporary = tempfile::tempdir().expect("temporary root");
    let program = temporary.path().join("busy");
    write_program(&program, 0o755, "#!/bin/sh\nwhile :; do :; done\n");

    let result = run_probe(&program, &[], Duration::from_millis(20));

    assert!(matches!(result, Err(ProbeError::TimedOut)));
}

#[test]
fn executable_probe_rejects_unbounded_output() {
    let temporary = tempfile::tempdir().expect("temporary root");
    let program = temporary.path().join("noisy");
    write_program(
        &program,
        0o755,
        "#!/bin/sh\nwhile :; do printf '0123456789abcdef'; done\n",
    );

    let result = run_probe(&program, &[], Duration::from_secs(2));

    assert!(
        matches!(&result, Err(ProbeError::OutputLimitExceeded)),
        "unexpected probe result: {result:?}"
    );
}

#[test]
fn help_capabilities_are_matched_as_complete_flags() {
    let missing = missing_help_flags("--bind-fd --ro-bind-fd --ro-bind-data");

    assert!(missing.iter().any(|flag| flag == "--bind"));
    assert!(missing.iter().any(|flag| flag == "--ro-bind"));
}

#[test]
fn bundled_bubblewrap_requires_a_matching_digest_manifest() {
    let temporary = tempfile::tempdir().expect("temporary root");
    let binary = temporary.path().join("bwrap");
    fs::write(&binary, b"trusted fixture").expect("write fixture");
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).expect("set executable mode");
    let digest = super::sha256_file(&binary).expect("hash fixture");
    fs::write(temporary.path().join("bwrap.sha256"), format!("{digest}\n"))
        .expect("write digest manifest");

    verify_bundled_digest(&binary).expect("matching digest should pass");
    fs::write(&binary, b"modified fixture").expect("modify fixture");
    assert!(matches!(
        verify_bundled_digest(&binary),
        Err(LinuxBackendError::BubblewrapDigestMismatch { .. })
    ));
}

#[test]
fn pinned_bubblewrap_keeps_the_validated_file_after_path_replacement() {
    let temporary = tempfile::tempdir().expect("temporary root");
    let binary = temporary.path().join("bwrap");
    fs::write(&binary, b"trusted fixture").expect("write fixture");
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).expect("set executable mode");
    let digest = super::sha256_file(&binary).expect("hash fixture");
    fs::write(temporary.path().join("bwrap.sha256"), format!("{digest}\n"))
        .expect("write digest manifest");

    let selected_file = File::open(&binary).expect("open selected executable");
    let selection = super::BubblewrapSelection {
        path: binary.clone(),
        bundled: true,
        identity: super::file_identity(&selected_file).expect("selected executable identity"),
    };
    let pinned = super::open_pinned(&selection).expect("pin bundled executable");
    fs::remove_file(&binary).expect("remove replaced path");
    fs::write(&binary, b"replacement fixture").expect("replace path contents");

    assert_eq!(
        super::sha256_file_handle(&pinned).expect("hash pinned file"),
        digest
    );
}

#[test]
fn pinned_bubblewrap_rejects_a_replaced_path_before_launch() {
    let temporary = tempfile::tempdir().expect("temporary root");
    let binary = temporary.path().join("bwrap");
    fs::write(&binary, b"trusted fixture").expect("write fixture");
    let selected_file = File::open(&binary).expect("open selected executable");
    let selection = super::BubblewrapSelection {
        path: binary.clone(),
        bundled: false,
        identity: super::file_identity(&selected_file).expect("selected executable identity"),
    };
    fs::remove_file(&binary).expect("remove selected path");
    fs::write(&binary, b"replacement fixture").expect("replace selected path");

    assert!(matches!(
        super::open_pinned(&selection),
        Err(LinuxBackendError::BubblewrapChanged { .. })
    ));
}

#[test]
fn explicit_missing_resource_directory_fails_closed() {
    let temporary = tempfile::tempdir().expect("temporary root");
    assert!(matches!(
        resource_directory(&ResourceDirectorySource::Explicit(
            temporary.path().join("missing")
        )),
        Err(LinuxBackendError::ResourceDirectoryUnavailable)
    ));
}

#[test]
fn only_system_executable_compatibility_failures_use_the_bundled_fallback() {
    assert!(can_fall_back_to_bundled(
        &LinuxBackendError::BubblewrapIncompatible { missing: vec![] }
    ));
    assert!(can_fall_back_to_bundled(
        &LinuxBackendError::BubblewrapProbeTimedOut { stage: "help" }
    ));
    assert!(!can_fall_back_to_bundled(
        &LinuxBackendError::UserNamespaceUnavailable {
            message: String::new()
        }
    ));
}

fn write_program(path: &Path, mode: u32, contents: &str) {
    fs::write(path, contents).expect("write executable fixture");
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("set executable mode");
}
