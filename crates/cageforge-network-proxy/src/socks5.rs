// SPDX-License-Identifier: Apache-2.0

//! SOCKS5 no-authentication CONNECT handling.

use std::net::{Ipv4Addr, Ipv6Addr};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

use crate::authority::Authority;
use crate::{GatewayError, NetworkGateway, NetworkResolver};

const VERSION: u8 = 0x05;
const NO_AUTH: u8 = 0x00;
const NO_ACCEPTABLE_METHOD: u8 = 0xff;
const CONNECT: u8 = 0x01;

pub(crate) async fn serve<R, S>(
    gateway: &NetworkGateway<R>,
    mut stream: S,
) -> Result<(), GatewayError>
where
    R: NetworkResolver,
    S: AsyncRead + AsyncWrite + Unpin,
{
    let authority = timeout(
        gateway.inner.config.handshake_timeout(),
        negotiate_and_read_request(&mut stream),
    )
    .await
    .map_err(|_| GatewayError::HandshakeTimedOut)??;
    let upstream = match gateway.inner.connect(&authority).await {
        Ok(upstream) => upstream,
        Err(error) => {
            let _ = write_reply(&mut stream, reply_for_error(&error)).await;
            return Err(error);
        }
    };
    write_reply(&mut stream, 0x00).await?;
    crate::relay::copy_bidirectional(
        stream,
        upstream,
        gateway.inner.config.relay_idle_timeout(),
        gateway.inner.config.relay_byte_limit(),
    )
    .await
}

async fn negotiate_and_read_request<S>(stream: &mut S) -> Result<Authority, GatewayError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut greeting = [0; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting[0] != VERSION || greeting[1] == 0 {
        return Err(GatewayError::InvalidSocksRequest {
            reason: "invalid greeting",
        });
    }
    let mut methods = vec![0; greeting[1] as usize];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&NO_AUTH) {
        stream.write_all(&[VERSION, NO_ACCEPTABLE_METHOD]).await?;
        return Err(GatewayError::InvalidSocksRequest {
            reason: "no supported authentication method",
        });
    }
    stream.write_all(&[VERSION, NO_AUTH]).await?;

    let mut request = [0; 4];
    stream.read_exact(&mut request).await?;
    if request[0] != VERSION || request[2] != 0 {
        write_reply(stream, 0x01).await?;
        return Err(GatewayError::InvalidSocksRequest {
            reason: "invalid SOCKS5 request header",
        });
    }
    if request[1] != CONNECT {
        write_reply(stream, 0x07).await?;
        return Err(GatewayError::InvalidSocksRequest {
            reason: "only SOCKS5 CONNECT is supported",
        });
    }
    let host = match request[3] {
        0x01 => {
            let mut address = [0; 4];
            stream.read_exact(&mut address).await?;
            Ipv4Addr::from(address).to_string()
        }
        0x03 => {
            let length = stream.read_u8().await? as usize;
            if length == 0 {
                return Err(GatewayError::InvalidSocksRequest {
                    reason: "empty domain",
                });
            }
            let mut domain = vec![0; length];
            stream.read_exact(&mut domain).await?;
            String::from_utf8(domain).map_err(|_| GatewayError::InvalidSocksRequest {
                reason: "domain is not UTF-8",
            })?
        }
        0x04 => {
            let mut address = [0; 16];
            stream.read_exact(&mut address).await?;
            Ipv6Addr::from(address).to_string()
        }
        _ => {
            write_reply(stream, 0x08).await?;
            return Err(GatewayError::InvalidSocksRequest {
                reason: "unsupported address type",
            });
        }
    };
    let port = stream.read_u16().await?;
    match Authority::from_host_port(host, port) {
        Ok(authority) => Ok(authority),
        Err(error) => {
            write_reply(stream, 0x01).await?;
            Err(error)
        }
    }
}

async fn write_reply<S>(stream: &mut S, reply: u8) -> Result<(), GatewayError>
where
    S: AsyncWrite + Unpin,
{
    stream
        .write_all(&[VERSION, reply, 0, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    stream.flush().await?;
    Ok(())
}

fn reply_for_error(error: &GatewayError) -> u8 {
    match error {
        GatewayError::PolicyDenied { .. } | GatewayError::ExternallyEnforced { .. } => 0x02,
        GatewayError::DnsFailed { .. }
        | GatewayError::DnsTimedOut { .. }
        | GatewayError::EmptyDnsResult { .. }
        | GatewayError::DnsAddressLimitExceeded { .. } => 0x04,
        GatewayError::ConnectTimedOut { .. } => 0x06,
        GatewayError::ConnectFailed { .. } => 0x05,
        _ => 0x01,
    }
}

#[cfg(test)]
#[path = "socks5_tests.rs"]
mod tests;
