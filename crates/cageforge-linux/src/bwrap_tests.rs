// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;

use pretty_assertions::assert_eq;

use super::{ProbeError, find_in_search_paths, missing_help_flags, run_probe};

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

    assert!(matches!(result, Err(ProbeError::OutputLimitExceeded)));
}

#[test]
fn help_capabilities_are_matched_as_complete_flags() {
    let missing = missing_help_flags("--bind-fd --ro-bind-fd --ro-bind-data");

    assert!(missing.iter().any(|flag| flag == "--bind"));
    assert!(missing.iter().any(|flag| flag == "--ro-bind"));
}

fn write_program(path: &Path, mode: u32, contents: &str) {
    fs::write(path, contents).expect("write executable fixture");
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("set executable mode");
}
