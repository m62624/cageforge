// SPDX-License-Identifier: Apache-2.0

//! Typed gateway failures.

use std::io;

use thiserror::Error;

/// Effective network requirement that this TCP gateway cannot own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnsupportedNetworkRequirement {
    /// The policy disables networking and needs no outbound gateway.
    DisabledMode,
    /// Enforcement belongs to a separately trusted external boundary.
    ExternalMode,
}

impl std::fmt::Display for UnsupportedNetworkRequirement {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DisabledMode => formatter.write_str("disabled network mode"),
            Self::ExternalMode => formatter.write_str("external network enforcement"),
        }
    }
}

/// Errors produced by gateway construction or one ingress connection.
#[derive(Debug, Error)]
pub enum GatewayError {
    /// The effective policy requires an enforcement mechanism outside this gateway.
    #[error("network gateway cannot enforce {requirement}")]
    UnsupportedPolicy {
        /// Unsupported requirement.
        requirement: UnsupportedNetworkRequirement,
    },
    /// An ingress authentication key could not be generated.
    #[error("failed to generate gateway ingress authentication key: {source}")]
    AuthenticationKeyGeneration {
        /// Operating-system randomness failure.
        #[source]
        source: getrandom::Error,
    },
    /// The operating-system DNS resolver could not be initialized.
    #[error("failed to initialize the system DNS resolver: {source}")]
    ResolverInitialization {
        /// Resolver initialization failure.
        #[source]
        source: io::Error,
    },
    /// The authentication frame was missing, malformed, or belonged to another gateway.
    #[error("gateway ingress authentication failed")]
    AuthenticationFailed,
    /// The gateway has reached its configured connection bound.
    #[error("gateway concurrent connection limit reached")]
    ConnectionLimitReached,
    /// The ingress authentication or protocol handshake timed out.
    #[error("gateway handshake timed out")]
    HandshakeTimedOut,
    /// HTTP input was malformed or unsupported.
    #[error("invalid HTTP proxy request: {reason}")]
    InvalidHttpRequest {
        /// Rejection reason.
        reason: &'static str,
    },
    /// SOCKS5 input was malformed or unsupported.
    #[error("invalid SOCKS5 request: {reason}")]
    InvalidSocksRequest {
        /// Rejection reason.
        reason: &'static str,
    },
    /// A host and port could not be parsed safely.
    #[error("invalid network authority: {authority}")]
    InvalidAuthority {
        /// Rejected authority spelling.
        authority: String,
    },
    /// DNS exceeded its configured deadline.
    #[error("DNS resolution timed out for {host}")]
    DnsTimedOut {
        /// Requested hostname.
        host: String,
    },
    /// DNS failed.
    #[error("DNS resolution failed for {host}: {source}")]
    DnsFailed {
        /// Requested hostname.
        host: String,
        /// Resolver failure.
        #[source]
        source: io::Error,
    },
    /// DNS returned no address.
    #[error("DNS returned no addresses for {host}")]
    EmptyDnsResult {
        /// Requested hostname.
        host: String,
    },
    /// DNS returned more addresses than the configured snapshot bound.
    #[error("DNS returned more than {limit} addresses for {host}")]
    DnsAddressLimitExceeded {
        /// Requested hostname.
        host: String,
        /// Configured bound.
        limit: usize,
    },
    /// A custom resolver attempted to replace the requested destination port.
    #[error("DNS resolver returned {actual} for {host}, but port {expected} was requested")]
    ResolvedPortMismatch {
        /// Requested hostname.
        host: String,
        /// Port from the HTTP or SOCKS request.
        expected: u16,
        /// Resolver-supplied address with a different port.
        actual: std::net::SocketAddr,
    },
    /// The target could not be represented by the portable policy model.
    #[error("resolved target is invalid: {source}")]
    InvalidResolvedTarget {
        /// Portable policy validation error.
        #[source]
        source: cageforge_policy::PolicyError,
    },
    /// The complete effective policy denied the destination.
    #[error("effective network policy denied {host}:{port}")]
    PolicyDenied {
        /// Requested host.
        host: String,
        /// Requested port.
        port: u16,
    },
    /// The policy delegated enforcement instead of granting a local connection.
    #[error("effective network policy delegates {host}:{port} to an external owner")]
    ExternallyEnforced {
        /// Requested host.
        host: String,
        /// Requested port.
        port: u16,
    },
    /// Exact-address policy evaluation failed.
    #[error("effective network policy evaluation failed: {source}")]
    PolicyEvaluation {
        /// Composition evaluation error.
        #[source]
        source: cageforge_policy_compose::CompositionError,
    },
    /// Every exact-address connection attempt failed.
    #[error("failed to connect to any authorized address for {host}:{port}: {source}")]
    ConnectFailed {
        /// Requested host.
        host: String,
        /// Requested port.
        port: u16,
        /// Last operating-system connection failure.
        #[source]
        source: io::Error,
    },
    /// Every exact-address connection attempt exceeded its deadline.
    #[error("authorized connection attempts timed out for {host}:{port}")]
    ConnectTimedOut {
        /// Requested host.
        host: String,
        /// Requested port.
        port: u16,
    },
    /// An upstream HTTP server did not return response headers in time.
    #[error("upstream HTTP response headers timed out for {host}:{port}")]
    ResponseHeaderTimedOut {
        /// Requested host.
        host: String,
        /// Requested port.
        port: u16,
    },
    /// No traffic crossed the relay before its idle deadline.
    #[error("gateway relay timed out after inactivity")]
    RelayTimedOut,
    /// The explicit combined relay byte ceiling was exceeded.
    #[error("gateway relay exceeded its {limit}-byte limit")]
    RelayByteLimitExceeded {
        /// Configured byte limit.
        limit: u64,
    },
    /// An ingress or upstream stream operation failed.
    #[error("gateway stream I/O failed: {source}")]
    Io {
        /// Stream failure.
        #[source]
        source: io::Error,
    },
    /// Hyper rejected or lost the HTTP/1 connection.
    #[error("HTTP proxy connection failed: {source}")]
    HttpConnection {
        /// Hyper connection failure.
        #[source]
        source: hyper::Error,
    },
    /// Hyper could not complete an HTTP CONNECT upgrade.
    #[error("HTTP CONNECT upgrade failed: {source}")]
    HttpUpgrade {
        /// Upgrade failure.
        #[source]
        source: hyper::Error,
    },
    /// A gateway-owned protocol task was cancelled or panicked.
    #[error("gateway protocol task failed: {source}")]
    ProtocolTask {
        /// Tokio task failure.
        #[source]
        source: tokio::task::JoinError,
    },
}

impl From<io::Error> for GatewayError {
    fn from(source: io::Error) -> Self {
        Self::Io { source }
    }
}
