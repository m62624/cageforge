// SPDX-License-Identifier: Apache-2.0

//! Resolve-once and exact-address outbound connection path.

use std::io;
use std::net::SocketAddr;

use cageforge_policy::{ConnectionAuthorization, NetworkDecision, ResolvedNetworkTarget};
use std::time::Instant;
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::authority::Authority;
use crate::gateway::GatewayInner;
use crate::{GatewayError, NetworkResolver};

impl<R: NetworkResolver> GatewayInner<R> {
    pub(crate) async fn connect(&self, authority: &Authority) -> Result<TcpStream, GatewayError> {
        match self
            .policy
            .decision_for_domain(authority.host())
            .map_err(|source| GatewayError::PolicyEvaluation { source })?
        {
            NetworkDecision::Allow => {}
            NetworkDecision::Deny => {
                return Err(GatewayError::PolicyDenied {
                    host: authority.host().to_string(),
                    port: authority.port(),
                });
            }
            NetworkDecision::ExternallyEnforced => {
                return Err(GatewayError::ExternallyEnforced {
                    host: authority.host().to_string(),
                    port: authority.port(),
                });
            }
        }
        let addresses = self.resolve(authority).await?;
        let target = ResolvedNetworkTarget::new(authority.host(), addresses)
            .map_err(|source| GatewayError::InvalidResolvedTarget { source })?;
        if target.addresses().is_empty() {
            return Err(GatewayError::EmptyDnsResult {
                host: authority.host().to_string(),
            });
        }

        timeout(
            self.config.connect_timeout(),
            self.connect_authorized(authority, &target),
        )
        .await
        .map_err(|_| GatewayError::ConnectTimedOut {
            host: authority.host().to_string(),
            port: authority.port(),
        })?
    }

    async fn connect_authorized(
        &self,
        authority: &Authority,
        target: &ResolvedNetworkTarget,
    ) -> Result<TcpStream, GatewayError> {
        let mut last_failure = None;
        let deadline = Instant::now() + self.config.connect_timeout();
        let mut timed_out = false;
        for (index, candidate) in target.addresses().iter().copied().enumerate() {
            let authorization = self
                .policy
                .authorize_connection(target, candidate)
                .map_err(|source| GatewayError::PolicyEvaluation { source })?;
            let authorized = match authorization {
                ConnectionAuthorization::Allowed(authorized) => authorized,
                ConnectionAuthorization::Denied => {
                    return Err(GatewayError::PolicyDenied {
                        host: authority.host().to_string(),
                        port: authority.port(),
                    });
                }
                ConnectionAuthorization::ExternallyEnforced => {
                    return Err(GatewayError::ExternallyEnforced {
                        host: authority.host().to_string(),
                        port: authority.port(),
                    });
                }
            };
            let exact = authorized.into_socket_addr();
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                timed_out = true;
                break;
            }
            let candidates_left = target.addresses().len() - index;
            let candidate_timeout = remaining / u32::try_from(candidates_left).unwrap_or(u32::MAX);
            match timeout(candidate_timeout, TcpStream::connect(exact)).await {
                Ok(Ok(stream)) => return Ok(stream),
                Ok(Err(source)) => last_failure = Some(source),
                Err(_) => timed_out = true,
            }
        }
        if timed_out {
            return Err(GatewayError::ConnectTimedOut {
                host: authority.host().to_string(),
                port: authority.port(),
            });
        }
        Err(GatewayError::ConnectFailed {
            host: authority.host().to_string(),
            port: authority.port(),
            source: last_failure.unwrap_or_else(|| {
                io::Error::new(io::ErrorKind::ConnectionRefused, "no address connected")
            }),
        })
    }

    async fn resolve(&self, authority: &Authority) -> Result<Vec<SocketAddr>, GatewayError> {
        let addresses = if let Some(literal) = authority.literal_address() {
            vec![literal]
        } else {
            timeout(
                self.config.dns_timeout(),
                self.resolver.resolve(authority.host(), authority.port()),
            )
            .await
            .map_err(|_| GatewayError::DnsTimedOut {
                host: authority.host().to_string(),
            })?
            .map_err(|source| GatewayError::DnsFailed {
                host: authority.host().to_string(),
                source,
            })?
        };
        if let Some(address) = addresses
            .iter()
            .find(|address| address.port() != authority.port())
        {
            return Err(GatewayError::ResolvedPortMismatch {
                host: authority.host().to_string(),
                expected: authority.port(),
                actual: *address,
            });
        }
        let limit = self.config.max_resolved_addresses().get();
        if addresses.len() > limit {
            return Err(GatewayError::DnsAddressLimitExceeded {
                host: authority.host().to_string(),
                limit,
            });
        }
        if addresses.is_empty() {
            return Err(GatewayError::EmptyDnsResult {
                host: authority.host().to_string(),
            });
        }
        Ok(addresses)
    }
}
