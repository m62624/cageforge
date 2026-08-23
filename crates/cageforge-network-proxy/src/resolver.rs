// SPDX-License-Identifier: Apache-2.0

//! Cancellable DNS resolver boundary.

use std::future::Future;
use std::io;
use std::net::SocketAddr;

use hickory_resolver::TokioResolver;

/// Resolves one host and port into the complete candidate snapshot.
///
/// Implementations supply candidates only; they cannot grant access. The
/// gateway validates the complete result through its effective policy and
/// connects only through an exact authorization. Implementations must be
/// cancellation-safe because the gateway drops this future on DNS timeout.
pub trait NetworkResolver: Send + Sync + 'static {
    /// Resolves every candidate address for one host and port.
    fn resolve(
        &self,
        host: &str,
        port: u16,
    ) -> impl Future<Output = io::Result<Vec<SocketAddr>>> + Send;
}

/// DNS resolver built from the operating system's resolver configuration.
#[derive(Clone)]
pub struct SystemResolver {
    inner: TokioResolver,
}

impl std::fmt::Debug for SystemResolver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SystemResolver")
            .finish_non_exhaustive()
    }
}

impl SystemResolver {
    /// Builds a resolver from the current operating-system configuration.
    pub fn new() -> io::Result<Self> {
        let inner = TokioResolver::builder_tokio()
            .map_err(io::Error::other)?
            .build()
            .map_err(io::Error::other)?;
        Ok(Self { inner })
    }
}

impl NetworkResolver for SystemResolver {
    async fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        let lookup = self.inner.lookup_ip(host).await.map_err(io::Error::other)?;
        Ok(lookup
            .iter()
            .map(|address| SocketAddr::new(address, port))
            .collect())
    }
}
