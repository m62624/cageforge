// SPDX-License-Identifier: Apache-2.0

use std::io;

use pretty_assertions::assert_eq;

use super::reply_for_error;
use crate::GatewayError;

#[test]
fn typed_gateway_failures_map_to_stable_socks5_statuses() {
    let cases = [
        (
            GatewayError::PolicyDenied {
                host: "example.com".to_string(),
                port: 443,
            },
            0x02,
        ),
        (
            GatewayError::DnsTimedOut {
                host: "example.com".to_string(),
            },
            0x04,
        ),
        (
            GatewayError::ConnectTimedOut {
                host: "example.com".to_string(),
                port: 443,
            },
            0x06,
        ),
        (
            GatewayError::ConnectFailed {
                host: "example.com".to_string(),
                port: 443,
                source: io::Error::new(io::ErrorKind::ConnectionRefused, "fixture"),
            },
            0x05,
        ),
        (
            GatewayError::InvalidSocksRequest { reason: "fixture" },
            0x01,
        ),
    ];
    for (error, expected) in cases {
        assert_eq!(reply_for_error(&error), expected);
    }
}
