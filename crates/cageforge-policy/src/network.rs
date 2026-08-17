// Copyright 2026 Mansur Azatbek
// SPDX-License-Identifier: Apache-2.0

use crate::PathSelector;
use crate::PolicyError;
use std::path::Component;
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

/// Whether a domain or socket is allowed or denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DomainAccess {
    /// Permit the destination.
    Allow,
    /// Deny the destination.
    Deny,
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
        let mut result = None;
        for rule in &self.domains {
            if domain_matches(rule.pattern(), &domain) {
                result = Some(match (result, rule.access()) {
                    (Some(DomainAccess::Deny), _) | (_, DomainAccess::Deny) => DomainAccess::Deny,
                    _ => DomainAccess::Allow,
                });
            }
        }
        Ok(result)
    }

    /// Returns whether a domain is allowed under the complete network mode.
    pub fn allows_domain(&self, domain: &str) -> Result<bool, PolicyError> {
        match self.mode {
            NetworkMode::Disabled | NetworkMode::External => Ok(false),
            NetworkMode::Enabled => match self.domain_mode {
                DomainMode::Disabled => Ok(false),
                DomainMode::Enabled => Ok(!matches!(
                    self.access_for_domain(domain)?,
                    Some(DomainAccess::Deny)
                )),
                DomainMode::Restricted => Ok(matches!(
                    self.access_for_domain(domain)?,
                    Some(DomainAccess::Allow)
                )),
            },
        }
    }

    /// Returns whether a Unix socket path is allowed under the complete network mode.
    pub fn allows_unix_socket(&self, path: &Path) -> bool {
        if !path.is_absolute()
            || crate::path::contains_nul(path)
            || path
                .components()
                .any(|component| component == Component::ParentDir)
            || matches!(self.mode, NetworkMode::Disabled | NetworkMode::External)
        {
            return false;
        }
        if self.unix_socket_mode == UnixSocketMode::Disabled {
            return false;
        }
        let mut decision = None;
        for rule in &self.unix_sockets {
            if path.starts_with(rule.path()) {
                decision = Some(match (decision, rule.access()) {
                    (Some(DomainAccess::Deny), _) | (_, DomainAccess::Deny) => DomainAccess::Deny,
                    _ => DomainAccess::Allow,
                });
            }
        }
        match self.unix_socket_mode {
            UnixSocketMode::Disabled => false,
            UnixSocketMode::Enabled => !matches!(decision, Some(DomainAccess::Deny)),
            UnixSocketMode::Restricted => matches!(decision, Some(DomainAccess::Allow)),
        }
    }
}

fn normalize_domain_pattern(raw: &str) -> Result<String, PolicyError> {
    let pattern = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    let valid_wildcard = pattern == "*"
        || pattern.strip_prefix("*.").is_some_and(valid_domain_suffix)
        || pattern.strip_prefix("**.").is_some_and(valid_domain_suffix);
    let valid_literal = !pattern.is_empty()
        && !pattern.contains("://")
        && !pattern.contains('/')
        && !pattern.contains('?')
        && !pattern.contains('#')
        && !pattern.contains('*')
        && !pattern.chars().any(char::is_whitespace)
        && !pattern.chars().any(char::is_control);
    if (valid_wildcard || valid_literal) && !pattern.is_empty() {
        Ok(pattern)
    } else {
        Err(PolicyError::InvalidDomainPattern {
            pattern: raw.to_string(),
        })
    }
}

fn valid_domain_suffix(suffix: &str) -> bool {
    !suffix.is_empty()
        && !suffix.contains('*')
        && !suffix.contains('?')
        && !suffix.contains('/')
        && !suffix.contains(':')
        && !suffix.chars().any(char::is_whitespace)
        && !suffix.chars().any(char::is_control)
}

fn domain_matches(pattern: &str, domain: &str) -> bool {
    match pattern.strip_prefix("**.") {
        Some(suffix) => domain == suffix || domain.ends_with(&format!(".{suffix}")),
        None => match pattern.strip_prefix("*.") {
            Some(suffix) => domain.ends_with(&format!(".{suffix}")) && domain != suffix,
            None => pattern == "*" || pattern == domain,
        },
    }
}
