// SPDX-License-Identifier: Apache-2.0

use super::{parse_owner_marker, parse_owner_name, process_start_time};

#[test]
fn owner_marker_requires_pid_and_process_start_time() {
    assert_eq!(parse_owner_marker("42:1234"), Some((42, 1234)));
    assert_eq!(parse_owner_marker("active"), None);
    assert_eq!(parse_owner_marker("42:not-a-number"), None);
}

#[test]
fn owner_name_uses_the_pid_prefix_only() {
    assert_eq!(parse_owner_name("42-7"), Some(42));
    assert_eq!(parse_owner_name("not-a-pid"), None);
}

#[test]
fn current_process_has_a_stable_start_time() {
    let first = process_start_time(std::process::id()).expect("current process stat");
    let second = process_start_time(std::process::id()).expect("current process stat");
    assert_eq!(first, second);
}
