// SPDX-License-Identifier: Apache-2.0

//! Private parent/helper protocol constants shared by the library and helper binary.

pub(crate) const AUTH_FD_ENV: &str = "CAGEFORGE_LINUX_HELPER_AUTH_FD";
pub(crate) const AUTH_TOKEN: &[u8] = b"cageforge-linux-helper-v1";
pub(crate) const READY: &[u8] = b"ready";
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
pub(crate) const STATUS_MAGIC: &[u8] = b"CFSTATUS\x01";
