// SPDX-License-Identifier: Apache-2.0

//! Private parent/helper protocol constants shared by the library and helper binary.

pub(crate) const AUTH_FD_ENV: &str = "CAGEFORGE_LINUX_HELPER_AUTH_FD";
// This is a protocol marker, not a secret. The helper authenticates the
// backend through SO_PEERCRED and the PID-namespace boundary before reading it.
pub(crate) const AUTH_TOKEN: &[u8] = b"cageforge-linux-helper-v1";
pub(crate) const RELEASE: &[u8] = b"run";
pub(crate) const HARDENING_REQUIRED_ENV: &str = "CAGEFORGE_LINUX_HARDENING_REQUIRED";
pub(crate) const NETWORK_MODE_ENV: &str = "CAGEFORGE_LINUX_NETWORK_MODE";
pub(crate) const NETWORK_MODE_DISABLED: &str = "disabled";
pub(crate) const NETWORK_MODE_DIRECT_WITHOUT_UNIX: &str = "direct-without-unix";
pub(crate) const NETWORK_MODE_PROXY: &str = "proxy";
pub(crate) const GATEWAY_SOCKET_ENV: &str = "CAGEFORGE_LINUX_GATEWAY_SOCKET";
pub(crate) const GATEWAY_CONNECTION_LIMIT_ENV: &str = "CAGEFORGE_LINUX_GATEWAY_CONNECTION_LIMIT";
pub(crate) const BRIDGE_TOKEN_BYTES: usize = 32;
pub(crate) const ENVIRONMENT_MAGIC: &[u8] = b"CFENV\x01";
pub(crate) const MAX_ENVIRONMENT_ENTRIES: usize = 4096;
pub(crate) const MAX_ENVIRONMENT_VALUE_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_ENVIRONMENT_FRAME_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const STATUS_MAGIC: &[u8] = b"CFSTATUS\x01";
pub(crate) const SETUP_RESULT_MAGIC: &[u8] = b"CFSETUP\x01";
pub(crate) const SETUP_RESULT_READY: u8 = 0;
pub(crate) const SETUP_RESULT_FAILURE: u8 = 1;
pub(crate) const SETUP_RESULT_NO_ERRNO: i32 = i32::MIN;
