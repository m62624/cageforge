// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;
use std::path::PathBuf;

use crate::filesystem::MacosFilesystemPlan;
use crate::network::MacosNetworkPlan;

use crate::seatbelt::{SeatbeltProfile, glob_to_seatbelt_regex};

fn filesystem_plan(denied_path: &str) -> MacosFilesystemPlan {
    MacosFilesystemPlan {
        read_roots: vec![PathBuf::from("/workspace")],
        write_roots: vec![PathBuf::from("/workspace")],
        denied_paths: vec![PathBuf::from(denied_path)],
        write_denied_paths: vec![PathBuf::from("/workspace/readonly")],
        denied_globs: vec![
            PathBuf::from("/workspace/**/*.secret")
                .to_string_lossy()
                .into_owned(),
        ],
        unrestricted: false,
    }
}

#[test]
fn write_only_carveouts_remain_readable_in_the_profile() {
    let profile = SeatbeltProfile::build(
        &filesystem_plan("/workspace/private"),
        &MacosNetworkPlan::Disabled {
            unix: Default::default(),
        },
    )
    .expect("profile");
    let policy = profile.policy();

    assert!(policy.contains("(require-not (subpath (param \"WRITE_DENIED_PATH_0\")))"));
    assert!(!policy.contains("(deny file-read* (subpath (param \"WRITE_DENIED_PATH_0\")))"));
    assert!(policy.contains("(deny file-read* (subpath (param \"DENIED_PATH_0\")))"));
    assert!(policy.contains("(deny file-write-unlink (regex #\"^/workspace/"));
    assert!(policy.contains("(deny file-write-unlink (subpath (param \"DENIED_PATH_0\")))"));
}

#[test]
fn base_profile_keeps_dynamic_loader_and_standard_stdio_explicit() {
    let profile = SeatbeltProfile::build(
        &MacosFilesystemPlan::default(),
        &MacosNetworkPlan::Disabled {
            unix: Default::default(),
        },
    )
    .expect("profile");
    let policy = profile.policy();

    assert!(policy.contains("(allow file-map-executable"));
    assert!(policy.contains("(regex \"^/dev/fd/(0|1|2)$\")"));
    assert!(policy.contains("(regex \"^/dev/ttys[0-9]+$\")"));
}

#[test]
fn base_profile_keeps_required_platform_runtime_rules_explicit() {
    let profile = SeatbeltProfile::build(
        &MacosFilesystemPlan::default(),
        &MacosNetworkPlan::Disabled {
            unix: Default::default(),
        },
    )
    .expect("profile");
    let policy = profile.policy();

    assert!(policy.contains("(iokit-registry-entry-class \"RootDomainUserClient\")"));
    assert!(policy.contains("(mac-policy-name \"vnguard\")"));
    assert!(policy.contains("(fsctl-command FSIOC_CAS_BSDFLAGS)"));
    assert!(policy.contains("/__KMP_REGISTERED_LIB_[0-9]+"));
    assert!(policy.contains("com.apple.runningboard"));
    assert!(policy.contains("/private/var/run/syslog"));
}

#[test]
fn definitions_are_unique_when_a_path_is_used_by_multiple_rules() {
    let profile = SeatbeltProfile::build(
        &filesystem_plan("/workspace/private"),
        &MacosNetworkPlan::Direct {
            unix: Default::default(),
        },
    )
    .expect("profile");
    let names = profile
        .definitions()
        .iter()
        .map(|definition| definition.name().to_owned())
        .collect::<Vec<_>>();
    let unique = names.iter().cloned().collect::<BTreeSet<_>>();
    assert_eq!(names.len(), unique.len());
}

#[test]
fn path_exclusions_use_component_boundaries() {
    let plan = filesystem_plan("/workspace-escape");
    let profile = SeatbeltProfile::build(
        &plan,
        &MacosNetworkPlan::Disabled {
            unix: Default::default(),
        },
    )
    .expect("profile");

    assert!(
        !profile
            .policy()
            .contains("(require-not (literal (param \"DENIED_PATH_0\")))")
    );
    assert!(
        profile
            .policy()
            .contains("(deny file-read* (subpath (param \"DENIED_PATH_0\")))")
    );
}

#[test]
fn glob_translation_is_anchored_and_keeps_path_components_bounded() {
    assert_eq!(
        glob_to_seatbelt_regex("/workspace/**/*.secret"),
        r"^/workspace/(.*/)?[^/]*\.secret$"
    );
    assert_eq!(
        glob_to_seatbelt_regex("/workspace/private"),
        r"^/workspace/private(/.*)?$"
    );
}

#[test]
fn missing_proxy_port_is_a_typed_profile_error() {
    let error = SeatbeltProfile::build(
        &MacosFilesystemPlan::default(),
        &MacosNetworkPlan::Proxy {
            unix: Default::default(),
            ingress_port: None,
        },
    )
    .expect_err("missing proxy port");
    assert!(matches!(
        error,
        crate::error::SeatbeltProfileError::InvalidFragment {
            fragment: "proxy ingress port is missing"
        }
    ));
}

#[test]
fn nul_path_and_glob_are_rejected_before_profile_rendering() {
    let mut path_plan = MacosFilesystemPlan::default();
    path_plan
        .read_roots
        .push(PathBuf::from("/workspace\0escape"));
    let path_error = SeatbeltProfile::build(
        &path_plan,
        &MacosNetworkPlan::Disabled {
            unix: Default::default(),
        },
    )
    .expect_err("NUL path");
    assert!(matches!(
        path_error,
        crate::error::SeatbeltProfileError::PathContainsNul { .. }
    ));

    let mut glob_plan = MacosFilesystemPlan::default();
    glob_plan
        .denied_globs
        .push("/workspace/secret\0*".to_owned());
    let glob_error = SeatbeltProfile::build(
        &glob_plan,
        &MacosNetworkPlan::Disabled {
            unix: Default::default(),
        },
    )
    .expect_err("NUL glob");
    assert!(matches!(
        glob_error,
        crate::error::SeatbeltProfileError::GlobContainsNul { .. }
    ));
}
