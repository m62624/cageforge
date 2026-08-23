// SPDX-License-Identifier: Apache-2.0

mod support;

use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::time::Duration;

use cageforge_network_proxy::{GatewayConfig, GatewayError, NetworkGateway, SystemResolver};
use cageforge_policy::{DomainAccess, DomainMode, LocalNetworkAccess, NetworkPolicy};
use pretty_assertions::assert_eq;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use support::{StaticResolver, echo_server, effective_network, http_server, read_header};

#[derive(Clone, Copy)]
struct ErrorResolver;

impl cageforge_network_proxy::NetworkResolver for ErrorResolver {
    async fn resolve(&self, _host: &str, _port: u16) -> std::io::Result<Vec<SocketAddr>> {
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "fixture resolver failure",
        ))
    }
}

fn restricted(host: &str, local: LocalNetworkAccess) -> NetworkPolicy {
    NetworkPolicy::enabled()
        .with_domain_mode(DomainMode::Restricted)
        .with_local_network_access(local)
        .with_domain(host, DomainAccess::Allow)
        .expect("valid test domain")
}

#[test]
fn system_resolver_uses_the_host_configuration() {
    SystemResolver::new().expect("system resolver configuration is available");
    let policy = effective_network(NetworkPolicy::unrestricted(), NetworkPolicy::unrestricted());
    NetworkGateway::with_system_resolver(policy, GatewayConfig::new())
        .expect("system-resolver gateway construction");
}

#[tokio::test]
async fn explicit_ip_literal_never_calls_dns() {
    let (address, echo) = echo_server().await;
    let host = address.ip().to_string();
    let resolver = StaticResolver::default();
    let policy = effective_network(
        restricted(&host, LocalNetworkAccess::Deny),
        NetworkPolicy::unrestricted(),
    );
    let gateway = NetworkGateway::new(policy, resolver.clone(), GatewayConfig::new()).unwrap();
    let key = gateway.ingress_key();
    let (mut client, ingress) = tokio::io::duplex(4096);
    let task = tokio::spawn(async move { gateway.serve_connection(ingress).await });
    key.authenticate(&mut client).await.unwrap();
    client
        .write_all(
            format!(
                "CONNECT {host}:{0} HTTP/1.1\r\nHost: {host}:{0}\r\n\r\n",
                address.port()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    assert!(read_header(&mut client).await.starts_with(b"HTTP/1.1 200"));
    client.write_all(b"literal").await.unwrap();
    let mut echoed = [0; 7];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"literal");
    client.shutdown().await.unwrap();
    task.await.unwrap().unwrap();
    echo.await.unwrap();
    assert_eq!(resolver.calls(), 0);
}

#[tokio::test]
async fn failed_candidate_falls_back_only_within_the_same_dns_snapshot() {
    let (address, echo) = echo_server().await;
    let unavailable = SocketAddr::from(([127, 0, 0, 2], address.port()));
    let resolver = StaticResolver::with_answers("allowed.test", vec![unavailable, address]);
    let policy = effective_network(
        restricted("allowed.test", LocalNetworkAccess::Allow),
        NetworkPolicy::unrestricted(),
    );
    let gateway = NetworkGateway::new(policy, resolver.clone(), GatewayConfig::new()).unwrap();
    let key = gateway.ingress_key();
    let (mut client, ingress) = tokio::io::duplex(4096);
    let task = tokio::spawn(async move { gateway.serve_connection(ingress).await });
    key.authenticate(&mut client).await.unwrap();
    client.write_all(&[5, 1, 0]).await.unwrap();
    let mut greeting = [0; 2];
    client.read_exact(&mut greeting).await.unwrap();
    let host = b"allowed.test";
    let mut request = vec![5, 1, 0, 3, u8::try_from(host.len()).unwrap()];
    request.extend_from_slice(host);
    request.extend_from_slice(&address.port().to_be_bytes());
    client.write_all(&request).await.unwrap();
    let mut reply = [0; 10];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0);
    client.shutdown().await.unwrap();
    task.await.unwrap().unwrap();
    echo.await.unwrap();
    assert_eq!(resolver.calls(), 1);
}

#[tokio::test]
async fn dns_snapshot_limit_is_checked_before_policy_or_connect() {
    let addresses = vec![
        SocketAddr::from(([93, 184, 216, 34], 80)),
        SocketAddr::from(([93, 184, 216, 35], 80)),
    ];
    let resolver = StaticResolver::with_answers("allowed.test", addresses);
    let policy = effective_network(
        restricted("allowed.test", LocalNetworkAccess::Deny),
        NetworkPolicy::unrestricted(),
    );
    let config = GatewayConfig::new().with_max_resolved_addresses(NonZeroUsize::new(1).unwrap());
    let gateway = NetworkGateway::new(policy, resolver, config).unwrap();
    let response = raw_http(
        gateway,
        "GET http://allowed.test/ HTTP/1.1\r\nHost: allowed.test\r\n\r\n",
    )
    .await;
    assert!(response.starts_with("HTTP/1.1 502"));
}

#[tokio::test]
async fn resolver_and_connect_failures_remain_distinct_proxy_failures() {
    let policy = effective_network(
        restricted("allowed.test", LocalNetworkAccess::Allow),
        NetworkPolicy::unrestricted(),
    );
    let gateway = NetworkGateway::new(policy, ErrorResolver, GatewayConfig::new()).unwrap();
    let response = raw_http(
        gateway,
        "GET http://allowed.test/ HTTP/1.1\r\nHost: allowed.test\r\n\r\n",
    )
    .await;
    assert!(response.starts_with("HTTP/1.1 502"));

    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let unavailable = listener.local_addr().unwrap();
    drop(listener);
    let policy = effective_network(
        restricted("allowed.test", LocalNetworkAccess::Allow),
        NetworkPolicy::unrestricted(),
    );
    let gateway = NetworkGateway::new(
        policy,
        StaticResolver::one("allowed.test", unavailable),
        GatewayConfig::new(),
    )
    .unwrap();
    let response = raw_http(
        gateway,
        &format!(
            "GET http://allowed.test:{0}/ HTTP/1.1\r\nHost: allowed.test:{0}\r\n\r\n",
            unavailable.port()
        ),
    )
    .await;
    assert!(response.starts_with("HTTP/1.1 502"));
}

#[tokio::test]
async fn handshake_and_idle_relay_have_independent_deadlines() {
    let address = SocketAddr::from(([127, 0, 0, 1], 80));
    let policy = effective_network(
        restricted("allowed.test", LocalNetworkAccess::Allow),
        NetworkPolicy::unrestricted(),
    );
    let config = GatewayConfig::new()
        .with_handshake_timeout(Duration::from_millis(10))
        .unwrap();
    let gateway =
        NetworkGateway::new(policy, StaticResolver::one("allowed.test", address), config).unwrap();
    let (_client, ingress) = tokio::io::duplex(64);
    assert!(matches!(
        gateway.serve_connection(ingress).await,
        Err(GatewayError::HandshakeTimedOut)
    ));

    let (address, echo) = echo_server().await;
    let policy = effective_network(
        restricted("allowed.test", LocalNetworkAccess::Allow),
        NetworkPolicy::unrestricted(),
    );
    let config = GatewayConfig::new()
        .with_relay_idle_timeout(Duration::from_millis(10))
        .unwrap();
    let gateway =
        NetworkGateway::new(policy, StaticResolver::one("allowed.test", address), config).unwrap();
    let key = gateway.ingress_key();
    let (mut client, ingress) = tokio::io::duplex(256);
    let task = tokio::spawn(async move { gateway.serve_connection(ingress).await });
    key.authenticate(&mut client).await.unwrap();
    client.write_all(&[5, 1, 0]).await.unwrap();
    let mut greeting = [0; 2];
    client.read_exact(&mut greeting).await.unwrap();
    let host = b"allowed.test";
    let mut request = vec![5, 1, 0, 3, u8::try_from(host.len()).unwrap()];
    request.extend_from_slice(host);
    request.extend_from_slice(&address.port().to_be_bytes());
    client.write_all(&request).await.unwrap();
    let mut reply = [0; 10];
    client.read_exact(&mut reply).await.unwrap();
    assert!(matches!(
        task.await.unwrap(),
        Err(GatewayError::RelayTimedOut)
    ));
    echo.await.unwrap();
}

#[tokio::test]
async fn upstream_response_header_timeout_becomes_gateway_timeout() {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let _ = read_header(&mut stream).await;
        tokio::time::sleep(Duration::from_secs(60)).await;
    });
    let policy = effective_network(
        restricted("allowed.test", LocalNetworkAccess::Allow),
        NetworkPolicy::unrestricted(),
    );
    let config = GatewayConfig::new()
        .with_response_header_timeout(Duration::from_millis(10))
        .unwrap();
    let gateway =
        NetworkGateway::new(policy, StaticResolver::one("allowed.test", address), config).unwrap();
    let response = raw_http(
        gateway,
        &format!(
            "GET http://allowed.test:{0}/ HTTP/1.1\r\nHost: allowed.test:{0}\r\n\r\n",
            address.port()
        ),
    )
    .await;
    assert!(response.starts_with("HTTP/1.1 504"));
    server.abort();
}

#[tokio::test]
async fn unsupported_http_forms_and_connect_bodies_fail_before_dns() {
    let address = SocketAddr::from(([127, 0, 0, 1], 80));
    for request in [
        "GET https://allowed.test/ HTTP/1.1\r\nHost: allowed.test\r\n\r\n",
        "GET /relative HTTP/1.1\r\nHost: allowed.test\r\n\r\n",
        "CONNECT allowed.test:80 HTTP/1.1\r\nHost: allowed.test:80\r\nContent-Length: 1\r\n\r\nx",
    ] {
        let resolver = StaticResolver::one("allowed.test", address);
        let policy = effective_network(
            restricted("allowed.test", LocalNetworkAccess::Allow),
            NetworkPolicy::unrestricted(),
        );
        let gateway = NetworkGateway::new(policy, resolver.clone(), GatewayConfig::new()).unwrap();
        let response = raw_http(gateway, request).await;
        assert!(response.starts_with("HTTP/1.1 400"));
        assert_eq!(resolver.calls(), 0);
    }
}

#[tokio::test]
async fn socks5_requires_the_no_auth_method() {
    let address = SocketAddr::from(([127, 0, 0, 1], 80));
    let policy = effective_network(
        restricted("allowed.test", LocalNetworkAccess::Allow),
        NetworkPolicy::unrestricted(),
    );
    let gateway = NetworkGateway::new(
        policy,
        StaticResolver::one("allowed.test", address),
        GatewayConfig::new(),
    )
    .unwrap();
    let key = gateway.ingress_key();
    let (mut client, ingress) = tokio::io::duplex(64);
    let task = tokio::spawn(async move { gateway.serve_connection(ingress).await });
    key.authenticate(&mut client).await.unwrap();
    client.write_all(&[5, 1, 2]).await.unwrap();
    let mut reply = [0; 2];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [5, 0xff]);
    assert!(matches!(
        task.await.unwrap(),
        Err(GatewayError::InvalidSocksRequest { .. })
    ));
}

#[tokio::test]
async fn malformed_socks5_address_variants_fail_closed() {
    let address = SocketAddr::from(([127, 0, 0, 1], 80));
    let cases = [
        vec![4, 1, 0, 1, 127, 0, 0, 1, 0, 80],
        vec![5, 1, 1, 1, 127, 0, 0, 1, 0, 80],
        vec![5, 1, 0, 3, 0, 0, 80],
        vec![5, 1, 0, 3, 1, 0xff, 0, 80],
        vec![5, 1, 0, 1, 127, 0, 0, 1, 0, 0],
        {
            let mut value = vec![5, 1, 0, 4];
            value.extend_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
            value.extend_from_slice(&80_u16.to_be_bytes());
            value
        },
    ];
    for request in cases {
        let policy = effective_network(
            restricted("allowed.test", LocalNetworkAccess::Allow),
            NetworkPolicy::unrestricted(),
        );
        let gateway = NetworkGateway::new(
            policy,
            StaticResolver::one("allowed.test", address),
            GatewayConfig::new(),
        )
        .unwrap();
        let key = gateway.ingress_key();
        let (mut client, ingress) = tokio::io::duplex(256);
        let task = tokio::spawn(async move { gateway.serve_connection(ingress).await });
        key.authenticate(&mut client).await.unwrap();
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut greeting = [0; 2];
        client.read_exact(&mut greeting).await.unwrap();
        client.write_all(&request).await.unwrap();
        client.shutdown().await.unwrap();
        assert!(task.await.unwrap().is_err());
    }
}

#[tokio::test]
async fn aborting_a_handler_releases_its_shared_connection_permit() {
    let address = SocketAddr::from(([127, 0, 0, 1], 80));
    let policy = effective_network(
        restricted("allowed.test", LocalNetworkAccess::Allow),
        NetworkPolicy::unrestricted(),
    );
    let config = GatewayConfig::new()
        .with_max_concurrent_connections(NonZeroUsize::new(1).unwrap())
        .unwrap();
    let gateway =
        NetworkGateway::new(policy, StaticResolver::one("allowed.test", address), config).unwrap();
    let key = gateway.ingress_key();
    let (mut first_client, first_ingress) = tokio::io::duplex(64);
    let first_gateway = gateway.clone();
    let first = tokio::spawn(async move { first_gateway.serve_connection(first_ingress).await });
    key.authenticate(&mut first_client).await.unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;
    first.abort();
    let _ = first.await;

    let (mut second_client, second_ingress) = tokio::io::duplex(64);
    let second = tokio::spawn(async move { gateway.serve_connection(second_ingress).await });
    second_client.write_all(b"not authenticated").await.unwrap();
    drop(second_client);
    assert!(matches!(
        second.await.unwrap(),
        Err(GatewayError::AuthenticationFailed)
    ));
}

#[tokio::test]
async fn gateway_instances_keep_independent_policies() {
    let (address, server) = http_server(1).await;
    let allow = effective_network(
        restricted("allowed.test", LocalNetworkAccess::Allow),
        NetworkPolicy::unrestricted(),
    );
    let deny = effective_network(NetworkPolicy::disabled(), NetworkPolicy::unrestricted());
    let allowed = NetworkGateway::new(
        allow,
        StaticResolver::one("allowed.test", address),
        GatewayConfig::new(),
    )
    .unwrap();
    assert!(NetworkGateway::new(deny, StaticResolver::default(), GatewayConfig::new()).is_err());
    let response = raw_http(
        allowed,
        &format!(
            "GET http://allowed.test:{0}/ HTTP/1.1\r\nHost: allowed.test:{0}\r\n\r\n",
            address.port()
        ),
    )
    .await;
    assert!(response.starts_with("HTTP/1.1 200"));
    server.await.unwrap();
}

async fn raw_http<R>(gateway: NetworkGateway<R>, request: &str) -> String
where
    R: cageforge_network_proxy::NetworkResolver,
{
    let key = gateway.ingress_key();
    let (mut client, ingress) = tokio::io::duplex(64 * 1024);
    let task = tokio::spawn(async move { gateway.serve_connection(ingress).await });
    key.authenticate(&mut client).await.unwrap();
    client.write_all(request.as_bytes()).await.unwrap();
    let response = String::from_utf8(read_header(&mut client).await).unwrap();
    client.shutdown().await.unwrap();
    task.await.unwrap().unwrap();
    response
}
