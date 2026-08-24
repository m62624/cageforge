// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io::Write;
use std::os::fd::FromRawFd;
use std::time::Duration;

use crate::error::LinuxBridgeError;

use super::read_ready_port;

#[test]
fn readiness_wait_has_a_bounded_deadline() {
    let mut descriptors = [0; 2];
    #[allow(unsafe_code)]
    let result = unsafe { libc::pipe(descriptors.as_mut_ptr()) };
    assert_eq!(result, 0);
    #[allow(unsafe_code)]
    let mut reader = unsafe { File::from_raw_fd(descriptors[0]) };
    #[allow(unsafe_code)]
    let _writer = unsafe { File::from_raw_fd(descriptors[1]) };

    assert!(matches!(
        read_ready_port(&mut reader, Duration::from_millis(10)),
        Err(LinuxBridgeError::StartupTimedOut)
    ));
}

#[test]
fn readiness_port_requires_the_complete_frame() {
    let mut descriptors = [0; 2];
    #[allow(unsafe_code)]
    let result = unsafe { libc::pipe(descriptors.as_mut_ptr()) };
    assert_eq!(result, 0);
    #[allow(unsafe_code)]
    let mut reader = unsafe { File::from_raw_fd(descriptors[0]) };
    #[allow(unsafe_code)]
    let mut writer = unsafe { File::from_raw_fd(descriptors[1]) };
    writer.write_all(&[0x12, 0x34]).expect("readiness frame");

    assert!(matches!(
        read_ready_port(&mut reader, Duration::from_secs(1)),
        Ok(0x1234)
    ));
}
