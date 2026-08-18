// Copyright 2026 Mansur Azatbek
// SPDX-License-Identifier: Apache-2.0

use crate::PathSelector;
use crate::PolicyError;
use cageforge_path::is_within;
use globset::GlobBuilder;
use std::net::IpAddr;
use std::path::Path;
use std::path::PathBuf;

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

/// Default behavior for domain rules when no rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DomainMode {
    /// Reject every domain.
    Disabled,
    /// Allow domains by default and apply matching rules as restrictions.
    Enabled,
    /// Reject domains by default and allow only matching allow rules.
    Restricted,
}

/// Default behavior for Unix socket rules when no rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum UnixSocketMode {
    /// Reject every Unix socket path.
    Disabled,
    /// Allow Unix socket paths by default and apply matching rules as restrictions.
    Enabled,
    /// Reject Unix socket paths by default and allow only matching allow rules.
    Restricted,
}

/// Controls access to loopback, private, link-local, and otherwise
/// non-public IP addresses reached through a domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum LocalNetworkAccess {
    /// Reject non-public destinations unless the caller explicitly opts in.
    Deny,
    /// Permit non-public destinations after the ordinary domain policy allows.
    Allow,
}

/// Whether a domain or socket is allowed or denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DomainAccess {
    /// Permit the destination.
    Allow,
    /// Deny the destination.
    Deny,
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

impl NetworkDecision {
    /// Returns whether the local policy explicitly allows the destination.
    pub const fn is_allowed(self) -> bool {
        matches!(self, Self::Allow)
    }

    /// Returns whether another trusted component owns enforcement.
    pub const fn is_externally_enforced(self) -> bool {
        matches!(self, Self::ExternallyEnforced)
    }
}

/// A normalized domain pattern and its access decision.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DomainRule {
    pattern: String,
    access: DomainAccess,
}

impl DomainRule {
    /// Creates and validates a domain rule.
    pub fn new(pattern: impl Into<String>, access: DomainAccess) -> Result<Self, PolicyError> {
        let pattern = normalize_domain_pattern(&pattern.into())?;
        Ok(Self { pattern, access })
    }

    /// Returns the normalized pattern.
    pub fn pattern(&self) -> &str {
        &self.pattern
    }

    /// Returns the access decision.
    pub const fn access(&self) -> DomainAccess {
        self.access
    }
}

/// A Unix socket path and its access decision.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UnixSocketRule {
    path: PathBuf,
    access: DomainAccess,
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

/// Network restrictions passed to a platform backend or network proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkPolicy {
    mode: NetworkMode,
    domain_mode: DomainMode,
    unix_socket_mode: UnixSocketMode,
    local_network_access: LocalNetworkAccess,
    domains: Vec<DomainRule>,
    unix_sockets: Vec<UnixSocketRule>,
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

    /// Creates a policy with command networking enabled.
    pub const fn enabled() -> Self {
        Self {
            mode: NetworkMode::Enabled,
            domain_mode: DomainMode::Enabled,
            unix_socket_mode: UnixSocketMode::Enabled,
            local_network_access: LocalNetworkAccess::Deny,
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
            && (!self.domains.is_empty() || !self.unix_sockets.is_empty())
        {
            return Err(PolicyError::InvalidRule {
                message: "external network policies cannot contain local rules".to_string(),
            });
        }
        Ok(())
    }

    /// Returns the strictest matching domain decision, if a rule matches.
    pub fn access_for_domain(&self, domain: &str) -> Result<Option<DomainAccess>, PolicyError> {
        let domain = normalize_domain_pattern(domain)?;
        Ok(self.access_for_normalized_domain(&domain))
    }

    /// Evaluates a domain against the complete network policy.
    ///
    /// Unlike allows_domain, this preserves the distinction between a local
    /// denial and a policy whose enforcement belongs to another trusted
    /// boundary.
    pub fn decision_for_domain(&self, domain: &str) -> Result<NetworkDecision, PolicyError> {
        let domain = normalize_domain_pattern(domain)?;
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

    /// Evaluates a domain together with addresses resolved by a future
    /// network backend.
    ///
    /// This method deliberately performs no DNS lookup. The backend must
    /// resolve the name, pass every result here, and pass an empty slice when
    /// resolution fails or times out. Hostnames resolving to any non-public
    /// address are denied by default to prevent DNS rebinding from bypassing
    /// the domain policy. A literal IP may be allowed by an exact literal
    /// domain rule or by [`LocalNetworkAccess::Allow`].
    pub fn decision_for_domain_with_resolved_ips(
        &self,
        domain: &str,
        resolved_ips: &[IpAddr],
    ) -> Result<NetworkDecision, PolicyError> {
        let normalized_domain = normalize_domain_pattern(domain)?;
        let decision = self.decision_for_domain(&normalized_domain)?;
        if !decision.is_allowed() {
            return Ok(decision);
        }

        if let Some(literal) = parse_ip_literal(&normalized_domain) {
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

        if resolved_ips.is_empty()
            || (self.local_network_access == LocalNetworkAccess::Deny
                && resolved_ips.iter().copied().any(is_non_public_ip))
        {
            return Ok(NetworkDecision::Deny);
        }
        if normalized_domain == "localhost"
            && self.local_network_access == LocalNetworkAccess::Deny
            && !self.has_exact_allow(&normalized_domain)
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
            if is_within(path, rule.path()) {
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

    /// Returns whether a domain is allowed under the complete network mode.
    pub fn allows_domain(&self, domain: &str) -> Result<bool, PolicyError> {
        Ok(self.decision_for_domain(domain)?.is_allowed())
    }

    /// Returns whether a Unix socket path is allowed under the complete network mode.
    pub fn allows_unix_socket(&self, path: &Path) -> bool {
        self.decision_for_unix_socket(path)
            .is_ok_and(NetworkDecision::is_allowed)
    }

    fn access_for_normalized_domain(&self, domain: &str) -> Option<DomainAccess> {
        let mut result = None;
        for rule in &self.domains {
            if domain_matches(rule.pattern(), domain) {
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
    let remainder = normalize_host(remainder);
    let pattern = if prefix.is_empty() {
        remainder
    } else {
        format!("{prefix}{remainder}")
    };
    if valid_domain_pattern(&pattern) && domain_glob_is_valid(&pattern) {
        Ok(pattern)
    } else {
        Err(PolicyError::InvalidDomainPattern {
            pattern: raw.to_string(),
        })
    }
}

fn normalize_host(host: &str) -> String {
    let host = host.trim();
    if host.starts_with('[')
        && let Some(end) = host.find(']')
        && (host[1..end].contains(':') || normalize_ip_literal(&host[1..end]).is_some())
    {
        return normalize_dns_host_or_ip_literal(&host[1..end]);
    }
    if host.bytes().filter(|byte| *byte == b':').count() == 1 {
        let host = host.split(':').next().unwrap_or_default();
        return normalize_dns_host_or_ip_literal(host);
    }
    normalize_dns_host_or_ip_literal(host)
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
                        && !matches!(character, ':' | '%')
                })
        })
}

fn domain_matches(pattern: &str, domain: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("**.") {
        return domain_suffix_matches(suffix, domain, true);
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        return domain_suffix_matches(suffix, domain, false);
    }
    glob_matches(pattern, domain)
}

fn domain_suffix_matches(suffix: &str, domain: &str, include_apex: bool) -> bool {
    let suffix_labels = suffix.split('.').collect::<Vec<_>>();
    let domain_labels = domain.split('.').collect::<Vec<_>>();
    if domain_labels.len() < suffix_labels.len()
        || (!include_apex && domain_labels.len() == suffix_labels.len())
    {
        return false;
    }
    domain_labels[domain_labels.len() - suffix_labels.len()..]
        .iter()
        .zip(suffix_labels)
        .all(|(domain, suffix)| glob_matches(suffix, domain))
}

fn glob_matches(pattern: &str, value: &str) -> bool {
    let Ok(glob) = GlobBuilder::new(pattern).case_insensitive(true).build() else {
        return false;
    };
    glob.compile_matcher().is_match(value)
}

fn domain_glob_is_valid(pattern: &str) -> bool {
    GlobBuilder::new(pattern)
        .case_insensitive(true)
        .build()
        .is_ok()
}
