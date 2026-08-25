// SPDX-License-Identifier: Apache-2.0

//! Domain, resolved-address, and Unix-socket network policy.
//!
//! [`crate::NetworkPolicy`] provides declarative queries and the safe
//! [`crate::NetworkPolicy::authorize_connection`] handoff. The latter consumes
//! a [`crate::ResolvedNetworkTarget`] and returns a non-copyable
//! [`crate::AuthorizedSocketAddr`] so the backend can connect only to the
//! checked address.

use crate::PathSelector;
use crate::PolicyError;
use cageforge_path::{NativePathKey, paths_equal};
use globset::GlobBuilder;
use globset::GlobMatcher;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::path::PathBuf;

mod model;

use model::DomainMatcher;
pub use model::{
    AuthorizedSocketAddr, ConnectionAuthorization, DomainAccess, DomainMode, DomainRule,
    LocalNetworkAccess, NetworkDecision, NetworkMode, NetworkPolicy, ResolvedNetworkTarget,
    UnixSocketMode, UnixSocketRule,
};

impl NetworkDecision {
    pub(crate) const fn is_allowed(self) -> bool {
        matches!(self, Self::Allow)
    }

    /// Returns whether another trusted component owns enforcement.
    pub const fn is_externally_enforced(self) -> bool {
        matches!(self, Self::ExternallyEnforced)
    }
}

impl AuthorizedSocketAddr {
    /// Consumes the authorization and returns the exact checked address.
    ///
    /// The value is intentionally neither `Copy` nor `Clone`: an adapter
    /// should hand it directly to its connection operation instead of keeping
    /// a reusable authorization token.
    ///
    /// ```compile_fail
    /// use cageforge_policy::AuthorizedSocketAddr;
    ///
    /// fn require_clone<T: Clone>() {}
    /// require_clone::<AuthorizedSocketAddr>();
    /// ```
    pub const fn into_socket_addr(self) -> SocketAddr {
        self.0
    }
}

impl ResolvedNetworkTarget {
    /// Creates a target from a host and the addresses resolved for it.
    ///
    /// An empty address list represents failed or timed-out resolution and is
    /// retained so policy evaluation can fail closed with `Deny`.
    pub fn new(
        domain: impl Into<String>,
        addresses: impl IntoIterator<Item = SocketAddr>,
    ) -> Result<Self, PolicyError> {
        let domain = normalize_domain(&domain.into())?;
        let literal = parse_ip_literal(&domain);
        let mut seen = HashSet::new();
        let mut unique_addresses = Vec::new();
        for address in addresses {
            if literal.is_some_and(|literal| literal != address.ip()) {
                return Err(PolicyError::ResolvedAddressMismatch {
                    literal: domain,
                    address,
                });
            }
            if seen.insert(address) {
                unique_addresses.push(address);
            }
        }
        Ok(Self {
            domain,
            addresses: unique_addresses,
        })
    }

    /// Returns the normalized host used for policy matching.
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Returns the exact addresses captured for this resolution attempt.
    pub fn addresses(&self) -> &[SocketAddr] {
        &self.addresses
    }

    /// Returns whether an actual connection address belongs to this snapshot.
    pub fn contains_address(&self, address: SocketAddr) -> bool {
        self.addresses.contains(&address)
    }
}

impl PartialEq for DomainRule {
    fn eq(&self, other: &Self) -> bool {
        self.pattern == other.pattern && self.access == other.access
    }
}

impl Eq for DomainRule {}

impl Hash for DomainRule {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.pattern.hash(state);
        self.access.hash(state);
    }
}

impl DomainRule {
    /// Creates and validates a domain rule.
    pub fn new(pattern: impl Into<String>, access: DomainAccess) -> Result<Self, PolicyError> {
        let pattern = normalize_domain_pattern(&pattern.into())?;
        let matcher = compile_domain_matcher(&pattern)?;
        Ok(Self {
            pattern,
            access,
            matcher,
        })
    }

    /// Returns the normalized pattern.
    pub fn pattern(&self) -> &str {
        &self.pattern
    }

    /// Returns the access decision.
    pub const fn access(&self) -> DomainAccess {
        self.access
    }

    fn matches(&self, domain: &str) -> bool {
        match &self.matcher {
            DomainMatcher::Any => true,
            DomainMatcher::Full(matcher) => matcher.is_match(domain),
            DomainMatcher::Suffix {
                labels,
                include_apex,
            } => {
                let domain_label_count = domain.split('.').count();
                if domain_label_count < labels.len()
                    || (!include_apex && domain_label_count == labels.len())
                {
                    return false;
                }
                domain
                    .rsplit('.')
                    .zip(labels.iter().rev())
                    .all(|(domain, matcher)| matcher.is_match(domain))
            }
        }
    }
}

impl PartialEq for UnixSocketRule {
    fn eq(&self, other: &Self) -> bool {
        NativePathKey::new(&self.path) == NativePathKey::new(&other.path)
            && self.access == other.access
    }
}

impl Eq for UnixSocketRule {}

impl Hash for UnixSocketRule {
    fn hash<H: Hasher>(&self, state: &mut H) {
        NativePathKey::new(&self.path).hash(state);
        self.access.hash(state);
    }
}

impl UnixSocketRule {
    /// Creates an absolute Unix socket rule.
    pub fn new(path: impl Into<PathBuf>, access: DomainAccess) -> Result<Self, PolicyError> {
        let path = path.into();
        PathSelector::absolute(path.clone())?;
        Ok(Self { path, access })
    }

    /// Returns the socket path.
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Returns the access decision.
    pub const fn access(&self) -> DomainAccess {
        self.access
    }
}

impl NetworkPolicy {
    /// Creates a policy with command networking disabled.
    pub const fn disabled() -> Self {
        Self {
            mode: NetworkMode::Disabled,
            domain_mode: DomainMode::Disabled,
            unix_socket_mode: UnixSocketMode::Disabled,
            local_network_access: LocalNetworkAccess::Deny,
            domains: Vec::new(),
            unix_sockets: Vec::new(),
        }
    }

    /// Creates a policy with IP networking enabled and pathname Unix sockets
    /// disabled.
    ///
    /// Call [`Self::with_unix_socket_mode`] explicitly when pathname Unix
    /// sockets should use an allowlist or be unrestricted.
    pub const fn enabled() -> Self {
        Self {
            mode: NetworkMode::Enabled,
            domain_mode: DomainMode::Enabled,
            unix_socket_mode: UnixSocketMode::Disabled,
            local_network_access: LocalNetworkAccess::Deny,
            domains: Vec::new(),
            unix_sockets: Vec::new(),
        }
    }

    /// Creates a network policy with no local restrictions.
    pub const fn unrestricted() -> Self {
        Self {
            mode: NetworkMode::Enabled,
            domain_mode: DomainMode::Enabled,
            unix_socket_mode: UnixSocketMode::Enabled,
            local_network_access: LocalNetworkAccess::Allow,
            domains: Vec::new(),
            unix_sockets: Vec::new(),
        }
    }

    /// Creates a policy whose network boundary is owned externally.
    pub const fn external() -> Self {
        Self {
            mode: NetworkMode::External,
            domain_mode: DomainMode::Disabled,
            unix_socket_mode: UnixSocketMode::Disabled,
            local_network_access: LocalNetworkAccess::Deny,
            domains: Vec::new(),
            unix_sockets: Vec::new(),
        }
    }

    /// Returns the enforcement mode.
    pub const fn mode(&self) -> NetworkMode {
        self.mode
    }

    /// Returns the default behavior for unmatched domains.
    pub const fn domain_mode(&self) -> DomainMode {
        self.domain_mode
    }

    /// Returns the default behavior for unmatched Unix socket paths.
    pub const fn unix_socket_mode(&self) -> UnixSocketMode {
        self.unix_socket_mode
    }

    /// Returns the policy for non-public IP addresses reached through domains.
    pub const fn local_network_access(&self) -> LocalNetworkAccess {
        self.local_network_access
    }

    /// Sets the default behavior for unmatched domains.
    pub const fn with_domain_mode(mut self, mode: DomainMode) -> Self {
        self.domain_mode = mode;
        self
    }

    /// Sets the default behavior for unmatched Unix socket paths.
    pub const fn with_unix_socket_mode(mut self, mode: UnixSocketMode) -> Self {
        self.unix_socket_mode = mode;
        self
    }

    /// Sets whether resolved non-public IP addresses may be reached.
    pub const fn with_local_network_access(mut self, access: LocalNetworkAccess) -> Self {
        self.local_network_access = access;
        self
    }

    /// Returns domain rules in declaration order.
    pub fn domains(&self) -> &[DomainRule] {
        &self.domains
    }

    /// Returns Unix socket rules in declaration order.
    pub fn unix_sockets(&self) -> &[UnixSocketRule] {
        &self.unix_sockets
    }

    /// Adds a domain rule.
    pub fn with_domain(
        mut self,
        pattern: impl Into<String>,
        access: DomainAccess,
    ) -> Result<Self, PolicyError> {
        if self.mode == NetworkMode::External {
            return Err(PolicyError::InvalidRule {
                message: "network rules cannot be added to an external policy".to_string(),
            });
        }
        self.domains.push(DomainRule::new(pattern, access)?);
        Ok(self)
    }

    /// Adds a Unix socket rule.
    ///
    /// Rules are evaluated according to [`Self::unix_socket_mode`]. In
    /// particular, a policy whose socket mode is [`UnixSocketMode::Disabled`]
    /// remains deny-all even when it carries rules.
    pub fn with_unix_socket(
        mut self,
        path: impl Into<PathBuf>,
        access: DomainAccess,
    ) -> Result<Self, PolicyError> {
        if self.mode == NetworkMode::External {
            return Err(PolicyError::InvalidRule {
                message: "network rules cannot be added to an external policy".to_string(),
            });
        }
        self.unix_sockets.push(UnixSocketRule::new(path, access)?);
        Ok(self)
    }

    /// Validates that an externally enforced mode has no local rules.
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.mode == NetworkMode::External
            && (self.domain_mode != DomainMode::Disabled
                || self.unix_socket_mode != UnixSocketMode::Disabled
                || self.local_network_access != LocalNetworkAccess::Deny
                || !self.domains.is_empty()
                || !self.unix_sockets.is_empty())
        {
            return Err(PolicyError::InvalidRule {
                message: "external network policies cannot contain local settings".to_string(),
            });
        }
        Ok(())
    }

    /// Returns a policy with semantically duplicate rules collapsed using
    /// deny precedence.
    pub fn normalized(&self) -> Result<Self, PolicyError> {
        self.validate()?;
        let mut domains: Vec<DomainRule> = Vec::with_capacity(self.domains.len());
        let mut domain_positions: HashMap<String, usize> =
            HashMap::with_capacity(self.domains.len());
        for rule in &self.domains {
            if let Some(&index) = domain_positions.get(rule.pattern()) {
                if rule.access() == DomainAccess::Deny {
                    domains[index].access = DomainAccess::Deny;
                }
            } else {
                domain_positions.insert(rule.pattern().to_owned(), domains.len());
                domains.push(rule.clone());
            }
        }

        let mut unix_sockets: Vec<UnixSocketRule> = Vec::with_capacity(self.unix_sockets.len());
        let mut socket_positions: HashMap<NativePathKey, usize> =
            HashMap::with_capacity(self.unix_sockets.len());
        for rule in &self.unix_sockets {
            let key = NativePathKey::new(rule.path());
            if let Some(&index) = socket_positions.get(&key) {
                if rule.access() == DomainAccess::Deny {
                    unix_sockets[index].access = DomainAccess::Deny;
                }
            } else {
                socket_positions.insert(key, unix_sockets.len());
                unix_sockets.push(rule.clone());
            }
        }

        Ok(Self {
            mode: self.mode,
            domain_mode: self.domain_mode,
            unix_socket_mode: self.unix_socket_mode,
            local_network_access: self.local_network_access,
            domains,
            unix_sockets,
        })
    }

    /// Evaluates a domain against the complete network policy.
    ///
    /// Returns the policy result for a hostname without authorizing a socket
    /// connection. Use a [`ResolvedNetworkTarget`] and the exact connected
    /// address methods for connection checks.
    pub fn decision_for_domain(&self, domain: &str) -> Result<NetworkDecision, PolicyError> {
        let domain = normalize_domain(domain)?;
        match self.mode {
            NetworkMode::Disabled => Ok(NetworkDecision::Deny),
            NetworkMode::External => Ok(NetworkDecision::ExternallyEnforced),
            NetworkMode::Enabled => match self.domain_mode {
                DomainMode::Disabled => Ok(NetworkDecision::Deny),
                DomainMode::Enabled => Ok(
                    if matches!(
                        self.access_for_normalized_domain(&domain),
                        Some(DomainAccess::Deny)
                    ) {
                        NetworkDecision::Deny
                    } else {
                        NetworkDecision::Allow
                    },
                ),
                DomainMode::Restricted => Ok(
                    if matches!(
                        self.access_for_normalized_domain(&domain),
                        Some(DomainAccess::Allow)
                    ) {
                        NetworkDecision::Allow
                    } else {
                        NetworkDecision::Deny
                    },
                ),
            },
        }
    }

    /// Evaluates a resolved target without performing DNS or network I/O.
    ///
    /// This is the safe policy-level entry point for a backend that has
    /// already resolved a host. It checks every captured address and fails
    /// closed for an empty address list.
    fn decision_for_resolved_target(
        &self,
        target: &ResolvedNetworkTarget,
    ) -> Result<NetworkDecision, PolicyError> {
        let resolved_ips: Vec<_> = target.addresses().iter().map(SocketAddr::ip).collect();
        self.decision_for_domain_with_resolved_ips(target.domain(), &resolved_ips)
    }

    /// Evaluates the exact address a backend is about to connect to.
    ///
    /// A locally allowed target is denied when the actual address was not in
    /// the original resolution snapshot. External ownership remains external
    /// because the other enforcement boundary owns the connection check.
    fn decision_for_connected_address(
        &self,
        target: &ResolvedNetworkTarget,
        connected: SocketAddr,
    ) -> Result<NetworkDecision, PolicyError> {
        let decision = self.decision_for_resolved_target(target)?;
        if !decision.is_allowed() {
            return Ok(decision);
        }
        Ok(if target.contains_address(connected) {
            NetworkDecision::Allow
        } else {
            NetworkDecision::Deny
        })
    }

    /// Authorizes the exact socket address a backend is about to connect to.
    ///
    /// The returned [`ConnectionAuthorization::Allowed`] value contains the
    /// only address that passed the policy check. A backend must connect using
    /// that address and must not resolve the hostname again.
    pub fn authorize_connection(
        &self,
        target: &ResolvedNetworkTarget,
        connected: SocketAddr,
    ) -> Result<ConnectionAuthorization, PolicyError> {
        Ok(
            match self.decision_for_connected_address(target, connected)? {
                NetworkDecision::Allow => {
                    ConnectionAuthorization::Allowed(AuthorizedSocketAddr(connected))
                }
                NetworkDecision::Deny => ConnectionAuthorization::Denied,
                NetworkDecision::ExternallyEnforced => ConnectionAuthorization::ExternallyEnforced,
            },
        )
    }

    /// Evaluates a domain together with addresses resolved by a future
    /// network backend.
    ///
    /// This method deliberately performs no DNS lookup. For a hostname, the
    /// backend must resolve the name, pass every result here, and pass an
    /// empty slice when resolution fails or times out. Such an empty hostname
    /// result is denied. Hostnames resolving to any non-public address are
    /// denied by default to prevent DNS rebinding from bypassing the domain
    /// policy. An IP literal does not require DNS results: an empty slice is
    /// valid for the literal itself, while non-public literals still require
    /// an exact literal allow or [`LocalNetworkAccess::Allow`]. Prefer
    /// [`ResolvedNetworkTarget`] and [`Self::authorize_connection`] in backend
    /// code for actual connections. The target must contain the exact socket
    /// address that will be used, so a target with no addresses cannot be
    /// connected through the authorization API.
    pub fn decision_for_domain_with_resolved_ips(
        &self,
        domain: &str,
        resolved_ips: &[IpAddr],
    ) -> Result<NetworkDecision, PolicyError> {
        let normalized_domain = normalize_domain(domain)?;
        let decision = self.decision_for_domain(&normalized_domain)?;
        if !decision.is_allowed() {
            return Ok(decision);
        }

        if let Some(literal) = parse_ip_literal(&normalized_domain) {
            if resolved_ips.iter().any(|ip| *ip != literal) {
                return Ok(NetworkDecision::Deny);
            }
            return Ok(
                if self.has_exact_allow(&normalized_domain)
                    || self.local_network_access == LocalNetworkAccess::Allow
                    || !is_non_public_ip(literal)
                {
                    NetworkDecision::Allow
                } else {
                    NetworkDecision::Deny
                },
            );
        }

        let explicit_localhost_allow =
            normalized_domain == "localhost" && self.has_exact_allow(&normalized_domain);
        if normalized_domain == "localhost"
            && self.local_network_access == LocalNetworkAccess::Deny
            && !explicit_localhost_allow
        {
            return Ok(NetworkDecision::Deny);
        }
        if resolved_ips.is_empty() {
            return Ok(NetworkDecision::Deny);
        }
        if self.local_network_access == LocalNetworkAccess::Deny
            && resolved_ips
                .iter()
                .copied()
                .any(|ip| is_non_public_ip(ip) && !(explicit_localhost_allow && ip.is_loopback()))
        {
            return Ok(NetworkDecision::Deny);
        }
        Ok(NetworkDecision::Allow)
    }

    /// Evaluates a Unix socket path against the complete network policy.
    ///
    /// The path is validated even when enforcement is external so malformed
    /// input cannot be mistaken for a successful handoff.
    pub fn decision_for_unix_socket(&self, path: &Path) -> Result<NetworkDecision, PolicyError> {
        PathSelector::absolute(path.to_path_buf())?;
        if self.mode == NetworkMode::External {
            return Ok(NetworkDecision::ExternallyEnforced);
        }
        if self.mode == NetworkMode::Disabled || self.unix_socket_mode == UnixSocketMode::Disabled {
            return Ok(NetworkDecision::Deny);
        }
        let mut result = None;
        for rule in &self.unix_sockets {
            if paths_equal(path, rule.path()) {
                result = Some(match (result, rule.access()) {
                    (Some(DomainAccess::Deny), _) | (_, DomainAccess::Deny) => DomainAccess::Deny,
                    _ => DomainAccess::Allow,
                });
            }
        }
        let decision = match self.unix_socket_mode {
            UnixSocketMode::Disabled => NetworkDecision::Deny,
            UnixSocketMode::Enabled => {
                if matches!(result, Some(DomainAccess::Deny)) {
                    NetworkDecision::Deny
                } else {
                    NetworkDecision::Allow
                }
            }
            UnixSocketMode::Restricted => {
                if matches!(result, Some(DomainAccess::Allow)) {
                    NetworkDecision::Allow
                } else {
                    NetworkDecision::Deny
                }
            }
        };
        Ok(decision)
    }

    fn access_for_normalized_domain(&self, domain: &str) -> Option<DomainAccess> {
        let mut result = None;
        for rule in &self.domains {
            if rule.matches(domain) {
                result = Some(match (result, rule.access()) {
                    (Some(DomainAccess::Deny), _) | (_, DomainAccess::Deny) => DomainAccess::Deny,
                    _ => DomainAccess::Allow,
                });
            }
        }
        result
    }

    fn has_exact_allow(&self, domain: &str) -> bool {
        self.domains.iter().any(|rule| {
            rule.access() == DomainAccess::Allow
                && !rule.pattern().contains('*')
                && !rule.pattern().contains('?')
                && rule.pattern() == domain
        })
    }
}

fn normalize_domain_pattern(raw: &str) -> Result<String, PolicyError> {
    let raw = raw.trim();
    let invalid_syntax = raw.is_empty()
        || raw.contains("://")
        || raw.contains('/')
        || raw.contains('#')
        || raw.chars().any(char::is_whitespace)
        || raw.chars().any(char::is_control);
    if invalid_syntax {
        return Err(PolicyError::InvalidDomainPattern {
            pattern: raw.to_string(),
        });
    }

    let (prefix, remainder) = if let Some(remainder) = raw.strip_prefix("**.") {
        ("**.", remainder)
    } else if let Some(remainder) = raw.strip_prefix("*.") {
        ("*.", remainder)
    } else {
        ("", raw)
    };
    let remainder = normalize_host(remainder).ok_or_else(|| PolicyError::InvalidDomainPattern {
        pattern: raw.to_string(),
    })?;
    let pattern = if prefix.is_empty() {
        remainder
    } else {
        format!("{prefix}{remainder}")
    };
    if valid_domain_pattern(&pattern) {
        Ok(pattern)
    } else {
        Err(PolicyError::InvalidDomainPattern {
            pattern: raw.to_string(),
        })
    }
}

fn normalize_domain(raw: &str) -> Result<String, PolicyError> {
    let normalized = normalize_domain_pattern(raw)?;
    if !valid_concrete_host(&normalized) {
        return Err(PolicyError::InvalidDomainPattern {
            pattern: raw.to_string(),
        });
    }
    Ok(normalized)
}

fn normalize_host(host: &str) -> Option<String> {
    let host = host.trim();
    if host.starts_with('[') {
        let bracketed = host.strip_prefix('[')?;
        let end = bracketed.find(']')?;
        let inner = &bracketed[..end];
        let suffix = &bracketed[end + 1..];
        if normalize_ip_literal(inner).is_some() {
            if !suffix.is_empty() && !valid_port_suffix(suffix) {
                return None;
            }
            return normalize_ip_literal(inner).map(|ip| normalize_dns_host_or_ip_literal(&ip));
        }
    }
    match host.bytes().filter(|byte| *byte == b':').count() {
        0 => Some(normalize_dns_host_or_ip_literal(host)),
        1 => {
            let (host, port) = host.split_once(':')?;
            if !valid_port(port) {
                return None;
            }
            Some(normalize_dns_host_or_ip_literal(host))
        }
        _ => normalize_ip_literal(host).map(|ip| normalize_dns_host_or_ip_literal(&ip)),
    }
}

fn valid_port_suffix(suffix: &str) -> bool {
    let Some(port) = suffix.strip_prefix(':') else {
        return false;
    };
    valid_port(port)
}

fn valid_port(port: &str) -> bool {
    !port.is_empty()
        && port.bytes().all(|byte| byte.is_ascii_digit())
        && port.parse::<u16>().is_ok()
}

fn normalize_dns_host_or_ip_literal(host: &str) -> String {
    let host = host.to_ascii_lowercase();
    let host = host.trim_end_matches('.');
    if let Some(ip) = normalize_ip_literal(host) {
        return ip;
    }
    host.to_string()
}

fn normalize_ip_literal(host: &str) -> Option<String> {
    if host.parse::<IpAddr>().is_ok() {
        return Some(host.to_string());
    }
    for delimiter in ["%25", "%"] {
        if let Some((ip, scope)) = host.split_once(delimiter)
            && ip.parse::<IpAddr>().is_ok()
        {
            return Some(format!("{ip}%{scope}"));
        }
    }
    None
}

fn parse_ip_literal(host: &str) -> Option<IpAddr> {
    host.split_once('%').map_or_else(
        || host.parse().ok(),
        |(address, _scope)| address.parse().ok(),
    )
}

fn is_non_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(address) => {
            let value = u32::from(address);
            address.is_loopback()
                || address.is_private()
                || address.is_link_local()
                || address.is_unspecified()
                || address.is_multicast()
                || address.is_broadcast()
                || (value & 0xff00_0000) == 0
                || (value & 0xffc0_0000) == 0x6440_0000
                || (value & 0xffff_ff00) == 0xc000_0000
                || (value & 0xffff_ff00) == 0xc000_0200
                || (value & 0xfffe_0000) == 0xc612_0000
                || (value & 0xffff_ff00) == 0xc633_6400
                || (value & 0xffff_ff00) == 0xcb00_7100
                || (value & 0xf000_0000) == 0xf000_0000
        }
        IpAddr::V6(address) => {
            address.is_loopback()
                || address.is_unspecified()
                || address.is_multicast()
                || address.is_unique_local()
                || address.is_unicast_link_local()
                || address
                    .to_ipv4()
                    .is_some_and(|address| is_non_public_ip(IpAddr::V4(address)))
        }
    }
}

fn valid_domain_literal(pattern: &str) -> bool {
    !pattern.is_empty()
        && !pattern.contains('*')
        && !pattern.contains('?')
        && (!pattern.contains(':') || normalize_ip_literal(pattern).is_some())
}

fn valid_domain_pattern(pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if pattern.contains(':') || pattern.contains('%') {
        return valid_domain_literal(pattern);
    }
    let suffix = pattern
        .strip_prefix("**.")
        .or_else(|| pattern.strip_prefix("*."))
        .unwrap_or(pattern);
    !suffix.is_empty()
        && suffix.split('.').all(|label| {
            !label.is_empty()
                && label.chars().all(|character| {
                    !character.is_whitespace()
                        && !character.is_control()
                        && !matches!(character, ':' | '%' | '@')
                })
        })
}

fn valid_concrete_host(host: &str) -> bool {
    if parse_ip_literal(host).is_some() {
        return true;
    }
    host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .chars()
                    .all(|character| character.is_alphanumeric() || matches!(character, '-' | '_'))
        })
}

fn compile_domain_matcher(pattern: &str) -> Result<DomainMatcher, PolicyError> {
    if pattern == "*" {
        return Ok(DomainMatcher::Any);
    }
    if let Some(suffix) = pattern.strip_prefix("**.") {
        return Ok(DomainMatcher::Suffix {
            labels: compile_domain_labels(suffix, pattern)?,
            include_apex: true,
        });
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        return Ok(DomainMatcher::Suffix {
            labels: compile_domain_labels(suffix, pattern)?,
            include_apex: false,
        });
    }
    let matcher = GlobBuilder::new(pattern)
        .case_insensitive(true)
        .build()
        .map_err(|_| PolicyError::InvalidDomainPattern {
            pattern: pattern.to_owned(),
        })?
        .compile_matcher();
    Ok(DomainMatcher::Full(matcher))
}

fn compile_domain_labels(suffix: &str, pattern: &str) -> Result<Vec<GlobMatcher>, PolicyError> {
    suffix
        .split('.')
        .map(|label| {
            GlobBuilder::new(label)
                .case_insensitive(true)
                .build()
                .map(|glob| glob.compile_matcher())
                .map_err(|_| PolicyError::InvalidDomainPattern {
                    pattern: pattern.to_owned(),
                })
        })
        .collect()
}
