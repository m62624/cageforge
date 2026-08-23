// SPDX-License-Identifier: Apache-2.0

//! Gateway construction and authenticated protocol dispatch.

use std::sync::Arc;

use cageforge_policy::NetworkMode;
use cageforge_policy_compose::EffectiveNetworkPolicy;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, BufReader};
use tokio::sync::Semaphore;
use tokio::time::timeout;

use crate::{
    GatewayConfig, GatewayError, GatewayIngressKey, NetworkResolver, SystemResolver,
    UnsupportedNetworkRequirement,
};

pub(crate) struct GatewayInner<R> {
    pub(crate) policy: EffectiveNetworkPolicy,
    pub(crate) resolver: R,
    pub(crate) config: GatewayConfig,
    pub(crate) ingress_key: GatewayIngressKey,
    pub(crate) connections: Arc<Semaphore>,
}

/// Immutable policy-enforcing HTTP and SOCKS5 gateway.
///
/// Clones share the same policy, ingress authentication key, and connection
/// semaphore. Construct a separate gateway when executions must use different
/// effective policies or independent resource budgets.
pub struct NetworkGateway<R> {
    pub(crate) inner: Arc<GatewayInner<R>>,
}

impl<R> Clone for NetworkGateway<R> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<R> std::fmt::Debug for NetworkGateway<R> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NetworkGateway")
            .field("config", &self.inner.config)
            .finish_non_exhaustive()
    }
}

impl<R: NetworkResolver> NetworkGateway<R> {
    /// Creates a gateway from a complete composed network policy.
    pub fn new(
        policy: EffectiveNetworkPolicy,
        resolver: R,
        config: GatewayConfig,
    ) -> Result<Self, GatewayError> {
        let requirements = policy.requirements();
        match requirements.mode() {
            NetworkMode::Disabled => {
                return Err(GatewayError::UnsupportedPolicy {
                    requirement: UnsupportedNetworkRequirement::DisabledMode,
                });
            }
            NetworkMode::External => {
                return Err(GatewayError::UnsupportedPolicy {
                    requirement: UnsupportedNetworkRequirement::ExternalMode,
                });
            }
            NetworkMode::Enabled => {}
        }
        let ingress_key = GatewayIngressKey::generate()?;
        let connections = Arc::new(Semaphore::new(config.max_concurrent_connections().get()));
        Ok(Self {
            inner: Arc::new(GatewayInner {
                policy,
                resolver,
                config,
                ingress_key,
                connections,
            }),
        })
    }

    /// Returns a secret handle for trusted native ingress bridges.
    pub fn ingress_key(&self) -> GatewayIngressKey {
        self.inner.ingress_key.clone()
    }

    /// Authenticates and serves one private ingress stream.
    ///
    /// The stream must begin with [`GatewayIngressKey::authenticate`]. There
    /// is no unauthenticated serving path. The first authenticated protocol
    /// byte selects SOCKS5 when it is `0x05`; all other input is parsed as
    /// HTTP/1.1 and fails closed if malformed.
    pub async fn serve_connection<S>(&self, mut stream: S) -> Result<(), GatewayError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let _permit = Arc::clone(&self.inner.connections)
            .try_acquire_owned()
            .map_err(|_| GatewayError::ConnectionLimitReached)?;
        timeout(
            self.inner.config.handshake_timeout(),
            self.inner.ingress_key.verify(&mut stream),
        )
        .await
        .map_err(|_| GatewayError::HandshakeTimedOut)??;

        let mut stream = BufReader::new(stream);
        let first = timeout(self.inner.config.handshake_timeout(), stream.fill_buf())
            .await
            .map_err(|_| GatewayError::HandshakeTimedOut)??;
        let Some(first) = first.first().copied() else {
            return Err(GatewayError::Io {
                source: std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "authenticated ingress closed before protocol negotiation",
                ),
            });
        };
        if first == 0x05 {
            crate::socks5::serve(self, stream).await
        } else {
            crate::http::serve(self, stream).await
        }
    }
}

impl NetworkGateway<SystemResolver> {
    /// Creates a gateway using the operating system's DNS configuration.
    pub fn with_system_resolver(
        policy: EffectiveNetworkPolicy,
        config: GatewayConfig,
    ) -> Result<Self, GatewayError> {
        let resolver = SystemResolver::new()
            .map_err(|source| GatewayError::ResolverInitialization { source })?;
        Self::new(policy, resolver, config)
    }
}
