// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashSet,
    fs::{self, File},
    os::unix::fs::PermissionsExt,
    path::Path,
    time::Duration,
};

use pretty_assertions::assert_eq;

#[cfg(feature = "bundled-bubblewrap")]
use super::materialize_bundled_resource;
use super::{
    ProbeError, can_fall_back_to_bundled, find_in_search_paths, missing_help_flags, namespace_args,
    probe_capability_drop, probe_namespace, probe_nested_user_namespace_isolation,
    probe_proc_mount, resource_directory, run_probe, verify_bundled_digest,
};
use crate::config::{ProcMountPolicy, ResourceDirectorySource};
use crate::error::{BubblewrapFlag, LinuxBackendError, LinuxNamespace};

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
    let result = run_probe(
        Path::new("/bin/sh"),
        ["-c", "while :; do :; done"].as_slice(),
        Duration::from_millis(20),
    );

    assert!(matches!(result, Err(ProbeError::TimedOut)));
}

#[test]
fn executable_probe_rejects_unbounded_output() {
    let result = run_probe(
        Path::new("/bin/sh"),
        ["-c", "while :; do printf '0123456789abcdef'; done"].as_slice(),
        Duration::from_secs(2),
    );

    assert!(
        matches!(&result, Err(ProbeError::OutputLimitExceeded)),
        "unexpected probe result: {result:?}"
    );
}

#[test]
fn help_capabilities_are_matched_as_complete_flags() {
    let missing = missing_help_flags("--bind-fd --ro-bind-fd --ro-bind-data");

    assert!(missing.contains(&BubblewrapFlag::Bind));
    assert!(missing.contains(&BubblewrapFlag::ReadOnlyBind));
    assert!(missing.contains(&BubblewrapFlag::CapabilityDrop));
    assert!(missing.contains(&BubblewrapFlag::DisableUserNamespace));
}

#[test]
fn every_required_help_flag_has_a_typed_explanation() {
    let missing = missing_help_flags("");
    let mut spellings = HashSet::new();

    assert_eq!(missing, BubblewrapFlag::ALL);
    for flag in missing {
        assert!(flag.as_str().starts_with("--"));
        assert!(spellings.insert(flag.as_str()), "duplicate flag {flag}");
        assert!(!flag.purpose().is_empty());
        let error = LinuxBackendError::BubblewrapIncompatible {
            missing: vec![flag],
        };
        let message = error.to_string();
        assert!(message.contains(flag.as_str()));
        assert!(message.contains(flag.purpose()));
        assert!(message.contains("bundled-bubblewrap"));
    }
}

#[test]
fn namespace_plan_always_isolates_system_v_ipc() {
    for proc_mount in [ProcMountPolicy::Required, ProcMountPolicy::Disabled] {
        for network_isolated in [false, true] {
            let args = namespace_args(proc_mount, network_isolated);
            assert!(args.iter().any(|argument| argument == "--unshare-ipc"));
        }
    }
}

#[test]
fn namespace_plan_always_drops_all_linux_capabilities() {
    for proc_mount in [ProcMountPolicy::Required, ProcMountPolicy::Disabled] {
        for network_isolated in [false, true] {
            let args = namespace_args(proc_mount, network_isolated);
            assert!(
                args.windows(2)
                    .any(|arguments| { arguments[0] == "--cap-drop" && arguments[1] == "ALL" })
            );
        }
    }
}

#[test]
fn namespace_plan_always_disables_nested_user_namespaces() {
    for proc_mount in [ProcMountPolicy::Required, ProcMountPolicy::Disabled] {
        for network_isolated in [false, true] {
            let args = namespace_args(proc_mount, network_isolated);
            assert!(args.iter().any(|argument| argument == "--disable-userns"));
        }
    }
}

#[test]
fn namespace_probe_failures_identify_each_required_flag() {
    let temporary = tempfile::tempdir().expect("temporary root");
    let binary = temporary.path().join("bwrap");
    write_program(
        &binary,
        0o755,
        "#!/bin/sh\necho 'namespace creation denied' >&2\nexit 1\n",
    );

    for (namespace, flag, guidance) in [
        (
            LinuxNamespace::User,
            "--unshare-user",
            "unprivileged user namespaces",
        ),
        (LinuxNamespace::Pid, "--unshare-pid", "CLONE_NEWPID"),
        (LinuxNamespace::Ipc, "--unshare-ipc", "CLONE_NEWIPC"),
        (LinuxNamespace::Network, "--unshare-net", "CLONE_NEWNET"),
    ] {
        let error = probe_namespace(&binary, namespace).expect_err("namespace probe must fail");
        assert!(matches!(
            &error,
            LinuxBackendError::NamespaceUnavailable {
                namespace: actual,
                ..
            } if *actual == namespace
        ));
        let message = error.to_string();
        assert!(message.contains(flag), "missing {flag} in {message:?}");
        assert!(
            message.contains(guidance),
            "missing {guidance} in {message:?}"
        );
    }
}

#[test]
fn capability_drop_probe_failure_identifies_the_exact_flag() {
    let temporary = tempfile::tempdir().expect("temporary root");
    let binary = temporary.path().join("bwrap");
    write_program(
        &binary,
        0o755,
        "#!/bin/sh\necho 'capability operation denied' >&2\nexit 1\n",
    );

    let error = probe_capability_drop(&binary).expect_err("capability-drop probe must fail");
    assert!(matches!(
        &error,
        LinuxBackendError::CapabilityDropUnavailable { message }
            if message == "capability operation denied"
    ));
    let message = error.to_string();
    assert!(message.contains("--cap-drop ALL"));
    assert!(message.contains("capability reduction"));
}

#[test]
fn nested_user_namespace_probe_failure_identifies_the_exact_flag() {
    let temporary = tempfile::tempdir().expect("temporary root");
    let binary = temporary.path().join("bwrap");
    write_program(
        &binary,
        0o755,
        "#!/bin/sh\necho 'user namespace lockdown denied' >&2\nexit 1\n",
    );

    let error = probe_nested_user_namespace_isolation(&binary)
        .expect_err("nested-user-namespace probe must fail");
    assert!(matches!(
        &error,
        LinuxBackendError::NestedUserNamespaceIsolationUnavailable { message }
            if message == "user namespace lockdown denied"
    ));
    let message = error.to_string();
    assert!(message.contains("--disable-userns"));
    assert!(message.contains("user.max_user_namespaces"));
}

#[test]
fn proc_mount_probe_failure_identifies_the_exact_flag() {
    let temporary = tempfile::tempdir().expect("temporary root");
    let binary = temporary.path().join("bwrap");
    write_program(
        &binary,
        0o755,
        "#!/bin/sh\necho 'procfs mount denied' >&2\nexit 1\n",
    );

    let error = probe_proc_mount(&binary).expect_err("proc-mount probe must fail");
    assert!(matches!(
        &error,
        LinuxBackendError::ProcMountUnavailable { message }
            if message == "procfs mount denied"
    ));
    let message = error.to_string();
    assert!(message.contains("--proc /proc"));
    assert!(message.contains("procfs mounts"));
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

#[cfg(feature = "bundled-bubblewrap")]
#[test]
fn bundled_feature_materializes_a_private_verified_resource() {
    let resource = materialize_bundled_resource().expect("materialize bundled Bubblewrap");
    let binary = resource.path().join("bwrap");

    assert!(binary.is_file());
    verify_bundled_digest(&binary).expect("verify materialized Bubblewrap");
    assert_eq!(
        fs::metadata(resource.path())
            .expect("resource metadata")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
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
        &LinuxBackendError::NamespaceUnavailable {
            namespace: LinuxNamespace::User,
            message: String::new()
        }
    ));
    assert!(!can_fall_back_to_bundled(
        &LinuxBackendError::CapabilityDropUnavailable {
            message: String::new()
        }
    ));
    assert!(!can_fall_back_to_bundled(
        &LinuxBackendError::NestedUserNamespaceIsolationUnavailable {
            message: String::new()
        }
    ));
}

fn write_program(path: &Path, mode: u32, contents: &str) {
    fs::write(path, contents).expect("write executable fixture");
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("set executable mode");
}
