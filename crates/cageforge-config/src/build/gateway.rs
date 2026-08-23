// SPDX-License-Identifier: Apache-2.0

//! Conversion from private TOML gateway values to the validated proxy model.

use std::num::{NonZeroU64, NonZeroUsize};
use std::time::Duration;

use cageforge_network_proxy::{GatewayConfig, GatewayConfigError};

use crate::ConfigError;
use crate::model::{RawGatewayConfig, RawRelayByteLimit, RawRelayByteLimitMode};

pub(crate) fn build_gateway_config(
    raw: Option<&RawGatewayConfig>,
    profile: &str,
) -> Result<GatewayConfig, ConfigError> {
    let raw = raw.cloned().unwrap_or_default();
    let mut config = GatewayConfig::new();
    if let Some(value) = raw.handshake_timeout_ms {
        config = config
            .with_handshake_timeout(timeout(
                value,
                profile,
                "network.gateway.handshake_timeout_ms",
            )?)
            .map_err(|source| gateway_error(profile, source))?;
    }
    if let Some(value) = raw.dns_timeout_ms {
        config = config
            .with_dns_timeout(timeout(value, profile, "network.gateway.dns_timeout_ms")?)
            .map_err(|source| gateway_error(profile, source))?;
    }
    if let Some(value) = raw.connect_timeout_ms {
        config = config
            .with_connect_timeout(timeout(
                value,
                profile,
                "network.gateway.connect_timeout_ms",
            )?)
            .map_err(|source| gateway_error(profile, source))?;
    }
    if let Some(value) = raw.response_header_timeout_ms {
        config = config
            .with_response_header_timeout(timeout(
                value,
                profile,
                "network.gateway.response_header_timeout_ms",
            )?)
            .map_err(|source| gateway_error(profile, source))?;
    }
    if let Some(value) = raw.relay_idle_timeout_ms {
        config = config
            .with_relay_idle_timeout(timeout(
                value,
                profile,
                "network.gateway.relay_idle_timeout_ms",
            )?)
            .map_err(|source| gateway_error(profile, source))?;
    }
    if let Some(value) = raw.max_concurrent_connections {
        config = config
            .with_max_concurrent_connections(nonzero_usize(
                value,
                profile,
                "network.gateway.max_concurrent_connections",
            )?)
            .map_err(|source| gateway_error(profile, source))?;
    }
    if let Some(value) = raw.max_requests_per_connection {
        config = config.with_max_requests_per_connection(nonzero_usize(
            value,
            profile,
            "network.gateway.max_requests_per_connection",
        )?);
    }
    if let Some(value) = raw.max_resolved_addresses {
        config = config.with_max_resolved_addresses(nonzero_usize(
            value,
            profile,
            "network.gateway.max_resolved_addresses",
        )?);
    }
    if let Some(value) = raw.http_header_bytes {
        config = config
            .with_http_header_bytes(nonzero_usize(
                value,
                profile,
                "network.gateway.http_header_bytes",
            )?)
            .map_err(|source| gateway_error(profile, source))?;
    }
    if let Some(limit) = raw.relay_byte_limit {
        config = match limit {
            RawRelayByteLimit::Bytes(value) => {
                config.with_relay_byte_limit(NonZeroU64::new(value).ok_or_else(|| {
                    invalid_number(profile, "network.gateway.relay_byte_limit", value)
                })?)
            }
            RawRelayByteLimit::Mode(RawRelayByteLimitMode::Unlimited) => {
                config.without_relay_byte_limit()
            }
        };
    }
    Ok(config)
}

fn timeout(value: u64, profile: &str, field: &str) -> Result<Duration, ConfigError> {
    if value == 0 {
        return Err(invalid_number(profile, field, value));
    }
    Ok(Duration::from_millis(value))
}

fn nonzero_usize(value: u64, profile: &str, field: &str) -> Result<NonZeroUsize, ConfigError> {
    let converted = usize::try_from(value).map_err(|_| invalid_number(profile, field, value))?;
    NonZeroUsize::new(converted).ok_or_else(|| invalid_number(profile, field, value))
}

fn invalid_number(profile: &str, field: &str, value: u64) -> ConfigError {
    ConfigError::InvalidValue {
        profile: profile.to_owned(),
        field: field.to_owned(),
        value: format!("{value} must be representable and greater than zero"),
    }
}

fn gateway_error(profile: &str, source: GatewayConfigError) -> ConfigError {
    ConfigError::NetworkGateway {
        profile: profile.to_owned(),
        source,
    }
}
