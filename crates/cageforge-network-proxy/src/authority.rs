// SPDX-License-Identifier: Apache-2.0

//! Strict host and port parsing shared by HTTP and SOCKS5.

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use hyper::http::uri::Authority as HttpAuthority;

use crate::GatewayError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Authority {
    host: String,
    port: u16,
}

impl Authority {
    pub(crate) fn parse(value: &str, default_port: Option<u16>) -> Result<Self, GatewayError> {
        if value.contains('@') {
            return Err(GatewayError::InvalidAuthority {
                authority: value.to_string(),
            });
        }
        let parsed =
            HttpAuthority::from_str(value).map_err(|_| GatewayError::InvalidAuthority {
                authority: value.to_string(),
            })?;
        let port = parsed
            .port_u16()
            .or(default_port)
            .filter(|port| *port != 0)
            .ok_or_else(|| GatewayError::InvalidAuthority {
                authority: value.to_string(),
            })?;
        let parsed_host = parsed.host();
        let host = parsed_host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(parsed_host);
        if host.is_empty() {
            return Err(GatewayError::InvalidAuthority {
                authority: value.to_string(),
            });
        }
        Ok(Self {
            host: host.to_string(),
            port,
        })
    }

    pub(crate) fn from_host_port(host: String, port: u16) -> Result<Self, GatewayError> {
        if host.is_empty() || port == 0 {
            return Err(GatewayError::InvalidAuthority {
                authority: format!("{host}:{port}"),
            });
        }
        let display = if host.parse::<std::net::Ipv6Addr>().is_ok() {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        Self::parse(&display, None)
    }

    pub(crate) fn host(&self) -> &str {
        &self.host
    }

    pub(crate) const fn port(&self) -> u16 {
        self.port
    }

    pub(crate) fn literal_address(&self) -> Option<SocketAddr> {
        self.host
            .parse::<IpAddr>()
            .ok()
            .map(|address| SocketAddr::new(address, self.port))
    }

    pub(crate) fn same_endpoint(&self, other: &Self) -> bool {
        canonical_host(&self.host) == canonical_host(&other.host) && self.port == other.port
    }
}

fn canonical_host(host: &str) -> String {
    host.parse::<IpAddr>().map_or_else(
        |_| host.trim_end_matches('.').to_ascii_lowercase(),
        |address| address.to_string(),
    )
}

#[cfg(test)]
#[path = "authority_tests.rs"]
mod tests;
