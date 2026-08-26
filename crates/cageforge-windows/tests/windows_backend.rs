// SPDX-License-Identifier: Apache-2.0

#![cfg(target_os = "windows")]

use std::path::PathBuf;
use std::time::Duration;

use cageforge_windows::{
    WindowsBackendConfig, WindowsBackendConfigError, WindowsSetup, WindowsSetupConfig,
    WindowsSetupStatus,
};
use pretty_assertions::assert_eq;

#[test]
fn backend_configuration_rejects_a_zero_default_timeout() {
    let error = WindowsBackendConfig::new()
        .with_default_timeout(Duration::ZERO)
        .expect_err("zero timeout");

    assert_eq!(error, WindowsBackendConfigError::ZeroDefaultTimeout);
}

#[test]
fn setup_configuration_rejects_relative_security_paths() {
    let state_error = WindowsSetupConfig::new()
        .with_state_directory(PathBuf::from("relative-state"))
        .expect_err("relative state directory");
    let helper_error = WindowsSetupConfig::new()
        .with_setup_helper_path(PathBuf::from("relative-helper.exe"))
        .expect_err("relative helper path");

    assert_eq!(
        state_error,
        WindowsBackendConfigError::RelativeStateDirectory {
            path: PathBuf::from("relative-state"),
        }
    );
    assert_eq!(
        helper_error,
        WindowsBackendConfigError::RelativeSetupHelper {
            path: PathBuf::from("relative-helper.exe"),
        }
    );
}

#[test]
fn absent_setup_is_reported_without_creating_host_state() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let config = WindowsSetupConfig::new()
        .with_state_directory(temporary.path())
        .expect("absolute state directory");
    let setup = WindowsSetup::new(config);
    let state_directory = setup.state_directory().expect("resolved state directory");

    assert!(!state_directory.exists());
    assert_eq!(
        setup.status().expect("setup status"),
        WindowsSetupStatus::Missing {
            marker_path: state_directory.join("setup.json"),
        }
    );
    assert!(!state_directory.exists());
}
