// SPDX-License-Identifier: Apache-2.0

//! Bounded gateway runtime settings.

use std::num::{NonZeroU64, NonZeroUsize};
use std::time::Duration;

use thiserror::Error;

const MIN_HTTP_HEADER_BYTES: usize = 8 * 1024;
const DEFAULT_RELAY_BYTE_LIMIT: u64 = 1024 * 1024 * 1024;
const MAX_CONCURRENT_CONNECTIONS: usize = usize::MAX >> 3;

#[cfg(feature = "runtime")]
const _: () = assert!(MAX_CONCURRENT_CONNECTIONS == tokio::sync::Semaphore::MAX_PERMITS);

/// Secure resource and timeout settings for one gateway instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayConfig {
    handshake_timeout: Duration,
    dns_timeout: Duration,
    connect_timeout: Duration,
    response_header_timeout: Duration,
    relay_idle_timeout: Duration,
    max_concurrent_connections: NonZeroUsize,
    max_requests_per_connection: NonZeroUsize,
    max_resolved_addresses: NonZeroUsize,
    http_header_bytes: NonZeroUsize,
    relay_byte_limit: Option<NonZeroU64>,
}

/// Invalid gateway configuration.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum GatewayConfigError {
    /// A timeout was zero and would disable the intended bound.
    #[error("{field} timeout must be greater than zero")]
    ZeroTimeout {
        /// Name of the rejected timeout.
        field: &'static str,
    },
    /// Hyper requires at least its minimum HTTP/1 buffer size.
    #[error("HTTP header limit {actual} is below the minimum {minimum}")]
    HttpHeaderLimitTooSmall {
        /// Required minimum.
        minimum: usize,
        /// Rejected value.
        actual: usize,
    },
    /// The concurrency count exceeds Tokio's representable semaphore range.
    #[error("{field} {actual} exceeds the maximum {maximum}")]
    LimitTooLarge {
        /// Name of the rejected setting.
        field: &'static str,
        /// Maximum supported value.
        maximum: usize,
        /// Rejected value.
        actual: usize,
    },
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            handshake_timeout: Duration::from_secs(10),
            dns_timeout: Duration::from_secs(10),
            connect_timeout: Duration::from_secs(10),
            response_header_timeout: Duration::from_secs(30),
            relay_idle_timeout: Duration::from_secs(300),
            max_concurrent_connections: NonZeroUsize::new(128).unwrap_or(NonZeroUsize::MIN),
            max_requests_per_connection: NonZeroUsize::new(64).unwrap_or(NonZeroUsize::MIN),
            max_resolved_addresses: NonZeroUsize::new(64).unwrap_or(NonZeroUsize::MIN),
            http_header_bytes: NonZeroUsize::new(32 * 1024).unwrap_or(NonZeroUsize::MIN),
            relay_byte_limit: NonZeroU64::new(DEFAULT_RELAY_BYTE_LIMIT),
        }
    }
}

impl GatewayConfig {
    /// Creates the secure default configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the authentication and protocol-handshake timeout.
    pub fn with_handshake_timeout(mut self, timeout: Duration) -> Result<Self, GatewayConfigError> {
        validate_timeout("handshake", timeout)?;
        self.handshake_timeout = timeout;
        Ok(self)
    }

    /// Sets the maximum duration of one DNS lookup.
    pub fn with_dns_timeout(mut self, timeout: Duration) -> Result<Self, GatewayConfigError> {
        validate_timeout("DNS", timeout)?;
        self.dns_timeout = timeout;
        Ok(self)
    }

    /// Sets one deadline shared by all exact-address connection attempts.
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Result<Self, GatewayConfigError> {
        validate_timeout("connect", timeout)?;
        self.connect_timeout = timeout;
        Ok(self)
    }

    /// Sets the maximum wait for upstream HTTP response headers.
    pub fn with_response_header_timeout(
        mut self,
        timeout: Duration,
    ) -> Result<Self, GatewayConfigError> {
        validate_timeout("response header", timeout)?;
        self.response_header_timeout = timeout;
        Ok(self)
    }

    /// Sets the maximum period with no traffic in either relay direction.
    pub fn with_relay_idle_timeout(
        mut self,
        timeout: Duration,
    ) -> Result<Self, GatewayConfigError> {
        validate_timeout("relay idle", timeout)?;
        self.relay_idle_timeout = timeout;
        Ok(self)
    }

    /// Sets the number of simultaneously handled ingress connections.
    pub fn with_max_concurrent_connections(
        mut self,
        limit: NonZeroUsize,
    ) -> Result<Self, GatewayConfigError> {
        validate_limit(
            "maximum concurrent connections",
            limit,
            MAX_CONCURRENT_CONNECTIONS,
        )?;
        self.max_concurrent_connections = limit;
        Ok(self)
    }

    /// Sets the number of HTTP requests accepted on one ingress connection.
    pub fn with_max_requests_per_connection(mut self, limit: NonZeroUsize) -> Self {
        self.max_requests_per_connection = limit;
        self
    }

    /// Sets the maximum DNS addresses accepted in one resolution snapshot.
    pub fn with_max_resolved_addresses(mut self, limit: NonZeroUsize) -> Self {
        self.max_resolved_addresses = limit;
        self
    }

    /// Sets the HTTP/1 header buffer limit.
    pub fn with_http_header_bytes(
        mut self,
        limit: NonZeroUsize,
    ) -> Result<Self, GatewayConfigError> {
        if limit.get() < MIN_HTTP_HEADER_BYTES {
            return Err(GatewayConfigError::HttpHeaderLimitTooSmall {
                minimum: MIN_HTTP_HEADER_BYTES,
                actual: limit.get(),
            });
        }
        self.http_header_bytes = limit;
        Ok(self)
    }

    /// Sets a combined byte ceiling for both relay directions.
    pub fn with_relay_byte_limit(mut self, limit: NonZeroU64) -> Self {
        self.relay_byte_limit = Some(limit);
        self
    }

    /// Explicitly removes the relay byte ceiling.
    pub fn without_relay_byte_limit(mut self) -> Self {
        self.relay_byte_limit = None;
        self
    }

    /// Returns the authentication and protocol-handshake timeout.
    pub const fn handshake_timeout(&self) -> Duration {
        self.handshake_timeout
    }

    /// Returns the DNS lookup timeout.
    pub const fn dns_timeout(&self) -> Duration {
        self.dns_timeout
    }

    /// Returns the deadline for all exact-address connection attempts.
    pub const fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    /// Returns the upstream HTTP response-header timeout.
    pub const fn response_header_timeout(&self) -> Duration {
        self.response_header_timeout
    }

    /// Returns the maximum period without relay traffic.
    pub const fn relay_idle_timeout(&self) -> Duration {
        self.relay_idle_timeout
    }

    /// Returns the simultaneous ingress-connection bound.
    pub const fn max_concurrent_connections(&self) -> NonZeroUsize {
        self.max_concurrent_connections
    }

    /// Returns the request bound for one persistent HTTP connection.
    pub const fn max_requests_per_connection(&self) -> NonZeroUsize {
        self.max_requests_per_connection
    }

    /// Returns the DNS snapshot address bound.
    pub const fn max_resolved_addresses(&self) -> NonZeroUsize {
        self.max_resolved_addresses
    }

    /// Returns the HTTP/1 parser buffer bound.
    pub const fn http_header_bytes(&self) -> NonZeroUsize {
        self.http_header_bytes
    }

    /// Returns the combined request/response or tunnel byte ceiling.
    pub const fn relay_byte_limit(&self) -> Option<NonZeroU64> {
        self.relay_byte_limit
    }
}

fn validate_timeout(field: &'static str, timeout: Duration) -> Result<(), GatewayConfigError> {
    if timeout.is_zero() {
        Err(GatewayConfigError::ZeroTimeout { field })
    } else {
        Ok(())
    }
}

fn validate_limit(
    field: &'static str,
    value: NonZeroUsize,
    maximum: usize,
) -> Result<(), GatewayConfigError> {
    if value.get() > maximum {
        Err(GatewayConfigError::LimitTooLarge {
            field,
            maximum,
            actual: value.get(),
        })
    } else {
        Ok(())
    }
}
