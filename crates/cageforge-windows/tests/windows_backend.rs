// SPDX-License-Identifier: Apache-2.0

#![cfg(target_os = "windows")]

use std::path::PathBuf;
use std::time::Duration;

use cageforge_windows::{
    WindowsBackendConfig, WindowsBackendConfigError, WindowsSetup, WindowsSetupConfig,
    WindowsSetupStatus,
};
use pretty_assertions::assert_eq;

struct SetupCleanup<'a> {
    setup: &'a WindowsSetup,
    armed: bool,
}

impl Drop for SetupCleanup<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.setup.uninstall();
        }
    }
}

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
    let runner_error = WindowsSetupConfig::new()
        .with_command_runner_path(PathBuf::from("relative-runner.exe"))
        .expect_err("relative command runner path");

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
    assert_eq!(
        runner_error,
        WindowsBackendConfigError::RelativeCommandRunner {
            path: PathBuf::from("relative-runner.exe"),
        }
    );
}

#[test]
fn elevated_setup_is_idempotent_fully_verified_and_explicitly_removed() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let helper = PathBuf::from(env!("CARGO_BIN_EXE_cageforge-windows-setup"));
    let runner = PathBuf::from(env!("CARGO_BIN_EXE_cageforge-windows-command-runner"));
    let config = WindowsSetupConfig::new()
        .with_state_directory(temporary.path().join("state"))
        .expect("absolute state directory")
        .with_setup_helper_path(helper)
        .expect("absolute setup helper")
        .with_command_runner_path(runner)
        .expect("absolute command runner");
    let setup = WindowsSetup::new(config);
    let mut cleanup = SetupCleanup {
        setup: &setup,
        armed: true,
    };

    let first = setup.install().expect("first elevated setup");
    assert_ne!(
        first.accounts().offline_sid(),
        first.accounts().online_sid()
    );
    assert_eq!(first.proxy_ports().len(), 2);
    assert!(matches!(
        setup.status().expect("verified setup status"),
        WindowsSetupStatus::Ready(_)
    ));

    let second = setup.install().expect("idempotent elevated setup");
    assert_eq!(first.owner_sid(), second.owner_sid());
    assert_eq!(first.accounts(), second.accounts());
    assert_eq!(first.proxy_ports(), second.proxy_ports());

    setup.uninstall().expect("explicit setup cleanup");
    cleanup.armed = false;
    assert!(matches!(
        setup.status().expect("status after cleanup"),
        WindowsSetupStatus::Missing { .. }
    ));
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
