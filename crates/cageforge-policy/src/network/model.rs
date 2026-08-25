// SPDX-License-Identifier: Apache-2.0

use std::net::SocketAddr;
use std::path::PathBuf;

use globset::GlobMatcher;

/// Network restrictions passed to a platform backend or network proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkPolicy {
    pub(super) mode: NetworkMode,
    pub(super) domain_mode: DomainMode,
    pub(super) unix_socket_mode: UnixSocketMode,
    pub(super) local_network_access: LocalNetworkAccess,
    pub(super) domains: Vec<DomainRule>,
    pub(super) unix_sockets: Vec<UnixSocketRule>,
}

/// A normalized hostname or literal together with the exact addresses a
/// backend resolved for one connection attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedNetworkTarget {
    pub(super) domain: String,
    pub(super) addresses: Vec<SocketAddr>,
}

/// A normalized domain pattern and its access decision.
#[derive(Debug, Clone)]
pub struct DomainRule {
    pub(super) pattern: String,
    pub(super) access: DomainAccess,
    pub(super) matcher: DomainMatcher,
}

/// A Unix socket path and its access decision.
#[derive(Debug, Clone)]
pub struct UnixSocketRule {
    pub(super) path: PathBuf,
    pub(super) access: DomainAccess,
}

/// The result of checking the exact address a backend is about to connect to.
#[derive(Debug, PartialEq, Eq, Hash)]
pub enum ConnectionAuthorization {
    /// The address passed local policy and belongs to the resolution snapshot.
    Allowed(AuthorizedSocketAddr),
    /// The local policy rejects the connection.
    Denied,
    /// Another trusted boundary owns connection enforcement.
    ExternallyEnforced,
}

/// A socket address that has passed the exact resolved-target check.
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct AuthorizedSocketAddr(pub(super) SocketAddr);

#[derive(Debug, Clone)]
pub(super) enum DomainMatcher {
    Any,
    Full(GlobMatcher),
    Suffix {
        labels: Vec<GlobMatcher>,
        include_apex: bool,
    },
}

/// The result of evaluating a complete network policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NetworkDecision {
    /// The local policy allows the destination.
    Allow,
    /// The local policy denies the destination.
    Deny,
    /// A trusted external boundary owns enforcement for the destination.
    ExternallyEnforced,
}

/// Whether a domain or socket is allowed or denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DomainAccess {
    /// Permit the destination.
    Allow,
    /// Deny the destination.
    Deny,
}

/// Controls access to loopback, private, link-local, and otherwise
/// non-public IP addresses reached through a domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LocalNetworkAccess {
    /// Reject non-public destinations unless the caller explicitly opts in.
    Deny,
    /// Permit non-public destinations after the ordinary domain policy allows.
    Allow,
}

/// Default behavior for Unix socket rules when no rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnixSocketMode {
    /// Reject every Unix socket path.
    Disabled,
    /// Allow Unix socket paths by default and apply matching rules as restrictions.
    Enabled,
    /// Reject Unix socket paths by default and allow only matching allow rules.
    Restricted,
}

/// Default behavior for domain rules when no rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DomainMode {
    /// Reject every domain.
    Disabled,
    /// Allow domains by default and apply matching rules as restrictions.
    Enabled,
    /// Reject domains by default and allow only matching allow rules.
    Restricted,
}

/// The enforcement ownership for network access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NetworkMode {
    /// Outbound command networking is disabled unless a rule is explicitly used
    /// by a backend that supports an allowlist.
    Disabled,
    /// Outbound command networking is enabled.
    Enabled,
    /// Another trusted component is responsible for enforcement.
    External,
}
