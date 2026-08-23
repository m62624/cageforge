// SPDX-License-Identifier: Apache-2.0

//! Per-gateway ingress authentication.

use std::fmt;
use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::GatewayError;

const MAGIC: &[u8; 5] = b"CGNP\x01";
const KEY_BYTES: usize = 32;

/// Secret proof shared only with trusted native ingress bridges.
///
/// Clones authenticate additional connections to the same gateway instance.
/// The debug representation never includes secret bytes. A key from one
/// gateway cannot authenticate to another gateway.
#[derive(Clone)]
pub struct GatewayIngressKey([u8; KEY_BYTES]);

impl GatewayIngressKey {
    pub(crate) fn generate() -> Result<Self, GatewayError> {
        let mut key = [0; KEY_BYTES];
        getrandom::fill(&mut key)
            .map_err(|source| GatewayError::AuthenticationKeyGeneration { source })?;
        Ok(Self(key))
    }

    /// Writes the versioned authentication frame to a private ingress stream.
    pub async fn authenticate<S>(&self, stream: &mut S) -> io::Result<()>
    where
        S: AsyncWrite + Unpin,
    {
        stream.write_all(MAGIC).await?;
        stream.write_all(&self.0).await?;
        stream.flush().await
    }

    pub(crate) async fn verify<S>(&self, stream: &mut S) -> Result<(), GatewayError>
    where
        S: AsyncRead + Unpin,
    {
        let mut magic = [0; MAGIC.len()];
        let mut supplied = [0; KEY_BYTES];
        stream
            .read_exact(&mut magic)
            .await
            .map_err(|_| GatewayError::AuthenticationFailed)?;
        stream
            .read_exact(&mut supplied)
            .await
            .map_err(|_| GatewayError::AuthenticationFailed)?;
        if magic == *MAGIC && constant_time_equal(&self.0, &supplied) {
            Ok(())
        } else {
            Err(GatewayError::AuthenticationFailed)
        }
    }
}

impl fmt::Debug for GatewayIngressKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GatewayIngressKey([REDACTED])")
    }
}

fn constant_time_equal(left: &[u8; KEY_BYTES], right: &[u8; KEY_BYTES]) -> bool {
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}
