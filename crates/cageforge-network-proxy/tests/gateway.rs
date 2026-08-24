// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "runtime")]

mod support;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::{NonZeroU64, NonZeroUsize};
use std::time::Duration;

use bytes::Bytes;
use cageforge_network_proxy::{
    GatewayConfig, GatewayConfigError, GatewayError, NetworkGateway, UnsupportedNetworkRequirement,
};
use cageforge_policy::{
    DomainAccess, DomainMode, LocalNetworkAccess, NetworkPolicy, UnixSocketMode,
};
use http_body_util::{BodyExt, Empty};
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use pretty_assertions::assert_eq;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use support::{
    StaticResolver, echo_server, effective_external_network, effective_network, http_server,
    read_header,
};

#[cfg(unix)]
const ALLOWED_SOCKET_PATH: &str = "/run/allowed.sock";
#[cfg(windows)]
const ALLOWED_SOCKET_PATH: &str = r"C:\run\allowed.sock";

#[derive(Clone, Copy)]
struct PendingResolver;

impl cageforge_network_proxy::NetworkResolver for PendingResolver {
    async fn resolve(&self, _host: &str, _port: u16) -> std::io::Result<Vec<SocketAddr>> {
        std::future::pending().await
    }
}

fn local_policy(host: &str) -> NetworkPolicy {
    NetworkPolicy::enabled()
        .with_domain_mode(DomainMode::Restricted)
        .with_local_network_access(LocalNetworkAccess::Allow)
        .with_domain(host, DomainAccess::Allow)
        .expect("valid local test domain")
}

fn gateway(host: &str, address: SocketAddr) -> (NetworkGateway<StaticResolver>, StaticResolver) {
    let resolver = StaticResolver::one(host, address);
    let policy = effective_network(local_policy(host), NetworkPolicy::unrestricted());
    let gateway = NetworkGateway::new(policy, resolver.clone(), GatewayConfig::new())
        .expect("valid test gateway");
    (gateway, resolver)
}

#[test]
fn configuration_rejects_unbounded_timeout_and_too_small_http_buffer() {
    assert_eq!(
        GatewayConfig::new().with_dns_timeout(Duration::ZERO),
        Err(GatewayConfigError::ZeroTimeout { field: "DNS" })
    );
    assert_eq!(
        GatewayConfig::new().with_http_header_bytes(NonZeroUsize::new(4096).unwrap()),
        Err(GatewayConfigError::HttpHeaderLimitTooSmall {
            minimum: 8192,
            actual: 4096,
        })
    );
    assert_eq!(
        GatewayConfig::new().relay_byte_limit(),
        NonZeroU64::new(1024 * 1024 * 1024),
        "secure defaults bound sustained transfers"
    );
    assert!(matches!(
        GatewayConfig::new()
            .with_max_concurrent_connections(NonZeroUsize::new(usize::MAX).unwrap()),
        Err(GatewayConfigError::LimitTooLarge { .. })
    ));
}

#[test]
fn every_gateway_setting_has_a_validated_builder_and_accessor() {
    let config = GatewayConfig::new()
        .with_handshake_timeout(Duration::from_secs(1))
        .unwrap()
        .with_dns_timeout(Duration::from_secs(2))
        .unwrap()
        .with_connect_timeout(Duration::from_secs(3))
        .unwrap()
        .with_response_header_timeout(Duration::from_secs(4))
        .unwrap()
        .with_relay_idle_timeout(Duration::from_secs(5))
        .unwrap()
        .with_max_concurrent_connections(NonZeroUsize::new(6).unwrap())
        .unwrap()
        .with_max_requests_per_connection(NonZeroUsize::new(7).unwrap())
        .with_max_resolved_addresses(NonZeroUsize::new(8).unwrap())
        .with_http_header_bytes(NonZeroUsize::new(16 * 1024).unwrap())
        .unwrap()
        .with_relay_byte_limit(NonZeroU64::new(9).unwrap());
    assert_eq!(config.handshake_timeout(), Duration::from_secs(1));
    assert_eq!(config.dns_timeout(), Duration::from_secs(2));
    assert_eq!(config.connect_timeout(), Duration::from_secs(3));
    assert_eq!(config.response_header_timeout(), Duration::from_secs(4));
    assert_eq!(config.relay_idle_timeout(), Duration::from_secs(5));
    assert_eq!(config.max_concurrent_connections().get(), 6);
    assert_eq!(config.max_requests_per_connection().get(), 7);
    assert_eq!(config.max_resolved_addresses().get(), 8);
    assert_eq!(config.http_header_bytes().get(), 16 * 1024);
    assert_eq!(config.relay_byte_limit().unwrap().get(), 9);
    assert_eq!(config.without_relay_byte_limit().relay_byte_limit(), None);
}

#[test]
fn disabled_policy_does_not_create_a_gateway() {
    let policy = effective_network(NetworkPolicy::disabled(), NetworkPolicy::unrestricted());
    let error = NetworkGateway::new(policy, StaticResolver::default(), GatewayConfig::new())
        .expect_err("disabled network needs no gateway");
    assert!(matches!(
        error,
        GatewayError::UnsupportedPolicy {
            requirement: UnsupportedNetworkRequirement::DisabledMode
        }
    ));
}

#[test]
fn externally_owned_policy_does_not_create_a_local_gateway() {
    let error = NetworkGateway::new(
        effective_external_network(),
        StaticResolver::default(),
        GatewayConfig::new(),
    )
    .expect_err("external enforcement cannot become local implicitly");
    assert!(matches!(
        error,
        GatewayError::UnsupportedPolicy {
            requirement: UnsupportedNetworkRequirement::ExternalMode
        }
    ));
    assert_eq!(
        UnsupportedNetworkRequirement::ExternalMode.to_string(),
        "external network enforcement"
    );
    assert_eq!(
        UnsupportedNetworkRequirement::DisabledMode.to_string(),
        "disabled network mode"
    );
}

#[test]
fn unix_socket_rules_do_not_disable_the_independent_tcp_gateway() {
    let requested = local_policy("allowed.test")
        .with_unix_socket_mode(UnixSocketMode::Restricted)
        .with_unix_socket(ALLOWED_SOCKET_PATH, DomainAccess::Allow)
        .expect("valid Unix socket rule");
    let policy = effective_network(requested, NetworkPolicy::unrestricted());
    NetworkGateway::new(policy, StaticResolver::default(), GatewayConfig::new())
        .expect("native backend owns Unix socket enforcement");
}

#[tokio::test]
async fn ingress_key_is_secret_and_bound_to_one_gateway() {
    let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9);
    let (first, _) = gateway("allowed.test", address);
    let (second, _) = gateway("allowed.test", address);
    assert!(format!("{first:?}").contains("GatewayConfig"));
    assert_eq!(
        format!("{:?}", first.ingress_key()),
        "GatewayIngressKey([REDACTED])"
    );

    let (mut client, server) = tokio::io::duplex(256);
    let handle = tokio::spawn(async move { second.serve_connection(server).await });
    first
        .ingress_key()
        .authenticate(&mut client)
        .await
        .expect("write authentication frame");
    client
        .write_all(b"GET /")
        .await
        .expect("write protocol bytes");
    assert!(matches!(
        handle.await.expect("gateway task"),
        Err(GatewayError::AuthenticationFailed)
    ));
}

#[tokio::test]
async fn authenticated_ingress_must_select_a_protocol() {
    let address = SocketAddr::from(([127, 0, 0, 1], 80));
    let (gateway, _) = gateway("allowed.test", address);
    let key = gateway.ingress_key();
    let (mut client, ingress) = tokio::io::duplex(64);
    let task = tokio::spawn(async move { gateway.serve_connection(ingress).await });
    key.authenticate(&mut client).await.unwrap();
    client.shutdown().await.unwrap();
    assert!(matches!(task.await.unwrap(), Err(GatewayError::Io { .. })));
}

#[tokio::test]
async fn ordinary_http_authorizes_each_persistent_request_separately() {
    let (address, server) = http_server(2).await;
    let (gateway, resolver) = gateway("allowed.test", address);
    let key = gateway.ingress_key();
    let (mut client, ingress) = tokio::io::duplex(64 * 1024);
    let gateway_task = tokio::spawn(async move { gateway.serve_connection(ingress).await });
    key.authenticate(&mut client)
        .await
        .expect("authenticate ingress");
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake::<_, Empty<Bytes>>(TokioIo::new(client))
            .await
            .expect("HTTP client handshake");
    let client_task = tokio::spawn(connection);

    for index in 0..2 {
        let request = Request::builder()
            .uri(format!(
                "http://allowed.test:{}/item/{index}",
                address.port()
            ))
            .header("host", format!("allowed.test:{}", address.port()))
            .header("proxy-authorization", "must-not-forward")
            .header("connection", "x-remove")
            .header("x-remove", "secret")
            .body(Empty::<Bytes>::new())
            .expect("valid request");
        let response = sender.send_request(request).await.expect("proxy response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = response
            .into_body()
            .collect()
            .await
            .expect("response body")
            .to_bytes();
        assert_eq!(body, Bytes::from(format!("response-{index}")));
    }
    drop(sender);
    client_task
        .await
        .expect("HTTP client task")
        .expect("clean client close");
    gateway_task
        .await
        .expect("gateway task")
        .expect("clean gateway close");
    let requests = server.await.expect("HTTP fixture task");
    assert_eq!(requests.len(), 2);
    assert!(
        requests
            .iter()
            .all(|request| request.starts_with("GET /item/"))
    );
    assert!(requests.iter().all(|request| !request.contains("x-remove")));
    assert!(
        requests
            .iter()
            .all(|request| !request.contains("proxy-authorization"))
    );
    assert_eq!(resolver.calls(), 2);
}

#[tokio::test]
async fn private_dns_result_is_denied_before_connect() {
    let private = SocketAddr::from(([10, 0, 0, 1], 8080));
    let resolver = StaticResolver::one("private.test", private);
    let requested = NetworkPolicy::enabled()
        .with_domain_mode(DomainMode::Restricted)
        .with_domain("private.test", DomainAccess::Allow)
        .expect("valid domain");
    let policy = effective_network(requested, NetworkPolicy::unrestricted());
    let gateway = NetworkGateway::new(policy, resolver, GatewayConfig::new()).unwrap();
    let key = gateway.ingress_key();
    let (mut client, ingress) = tokio::io::duplex(4096);
    let task = tokio::spawn(async move { gateway.serve_connection(ingress).await });
    key.authenticate(&mut client).await.unwrap();
    client
        .write_all(b"GET http://private.test:8080/ HTTP/1.1\r\nHost: private.test:8080\r\n\r\n")
        .await
        .unwrap();
    let response = String::from_utf8(read_header(&mut client).await).unwrap();
    assert!(response.starts_with("HTTP/1.1 403"));
    client.shutdown().await.unwrap();
    task.await
        .unwrap()
        .expect("HTTP denial is a handled response");
}

#[tokio::test]
async fn denied_hostname_never_reaches_the_resolver() {
    let resolver = StaticResolver::one("denied.test", SocketAddr::from(([203, 0, 113, 10], 8080)));
    let requested = NetworkPolicy::enabled()
        .with_domain_mode(DomainMode::Restricted)
        .with_domain("allowed.test", DomainAccess::Allow)
        .expect("valid domain");
    let policy = effective_network(requested, NetworkPolicy::unrestricted());
    let gateway =
        NetworkGateway::new(policy, resolver.clone(), GatewayConfig::new()).expect("gateway");

    let response = raw_http_status(gateway, "denied.test", 8080).await;
    assert!(response.starts_with("HTTP/1.1 403"));
    assert_eq!(resolver.calls(), 0);
}

#[tokio::test]
async fn absolute_uri_and_host_header_must_name_the_same_endpoint() {
    let address = SocketAddr::from(([127, 0, 0, 1], 8080));
    let (gateway, resolver) = gateway("allowed.test", address);
    let key = gateway.ingress_key();
    let (mut client, ingress) = tokio::io::duplex(4096);
    let task = tokio::spawn(async move { gateway.serve_connection(ingress).await });
    key.authenticate(&mut client).await.unwrap();
    client
        .write_all(
            format!(
                "GET http://allowed.test:{}/ HTTP/1.1\r\nHost: attacker.test:{}\r\n\r\n",
                address.port(),
                address.port()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let response = String::from_utf8(read_header(&mut client).await).unwrap();
    assert!(response.starts_with("HTTP/1.1 400"));
    assert_eq!(resolver.calls(), 0, "ambiguous request must not reach DNS");
    client.shutdown().await.unwrap();
    task.await.unwrap().expect("mismatch is a handled response");
}

#[tokio::test]
async fn empty_dns_result_and_dns_timeout_fail_closed() {
    let requested = local_policy("missing.test");
    let policy = effective_network(requested.clone(), NetworkPolicy::unrestricted());
    let gateway =
        NetworkGateway::new(policy, StaticResolver::default(), GatewayConfig::new()).unwrap();
    let response = raw_http_status(gateway, "missing.test", 80).await;
    assert!(response.starts_with("HTTP/1.1 502"));

    let policy = effective_network(requested, NetworkPolicy::unrestricted());
    let config = GatewayConfig::new()
        .with_dns_timeout(Duration::from_millis(10))
        .unwrap();
    let gateway = NetworkGateway::new(policy, PendingResolver, config).unwrap();
    let response = raw_http_status(gateway, "missing.test", 80).await;
    assert!(response.starts_with("HTTP/1.1 504"));
}

#[tokio::test]
async fn resolver_cannot_replace_the_requested_port() {
    let (address, server) = http_server(1).await;
    let requested_port = address.port().checked_add(1).unwrap_or(address.port() - 1);
    let resolver = StaticResolver::one("allowed.test", address);
    let policy = effective_network(local_policy("allowed.test"), NetworkPolicy::unrestricted());
    let gateway = NetworkGateway::new(policy, resolver, GatewayConfig::new()).unwrap();
    let response = raw_http_status(gateway, "allowed.test", requested_port).await;
    assert!(response.starts_with("HTTP/1.1 502"));
    server.abort();
}

#[tokio::test]
async fn one_private_address_poisoning_a_dns_snapshot_denies_every_candidate() {
    let public = SocketAddr::from(([93, 184, 216, 34], 80));
    let private = SocketAddr::from(([127, 0, 0, 1], 80));
    let resolver = StaticResolver::with_answers("mixed.test", vec![public, private]);
    let requested = NetworkPolicy::enabled()
        .with_domain_mode(DomainMode::Restricted)
        .with_domain("mixed.test", DomainAccess::Allow)
        .unwrap();
    let policy = effective_network(requested, NetworkPolicy::unrestricted());
    let gateway = NetworkGateway::new(policy, resolver, GatewayConfig::new()).unwrap();
    let response = raw_http_status(gateway, "mixed.test", 80).await;
    assert!(response.starts_with("HTTP/1.1 403"));
}

#[tokio::test]
async fn http_connect_relays_only_after_exact_authorization() {
    let (address, echo) = echo_server().await;
    let (gateway, resolver) = gateway("allowed.test", address);
    let key = gateway.ingress_key();
    let (mut client, ingress) = tokio::io::duplex(4096);
    let task = tokio::spawn(async move { gateway.serve_connection(ingress).await });
    key.authenticate(&mut client).await.unwrap();
    client
        .write_all(
            format!(
                "CONNECT allowed.test:{} HTTP/1.1\r\nHost: allowed.test\r\n\r\n",
                address.port()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let response = String::from_utf8(read_header(&mut client).await).unwrap();
    assert!(response.starts_with("HTTP/1.1 200"));
    client.write_all(b"through-connect").await.unwrap();
    let mut echoed = vec![0; b"through-connect".len()];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, b"through-connect");
    client.shutdown().await.unwrap();
    task.await.unwrap().expect("clean CONNECT tunnel");
    echo.await.unwrap();
    assert_eq!(resolver.calls(), 1);
}

#[tokio::test]
async fn socks5_connect_uses_the_same_exact_address_path() {
    let (address, echo) = echo_server().await;
    let (gateway, resolver) = gateway("allowed.test", address);
    let key = gateway.ingress_key();
    let (mut client, ingress) = tokio::io::duplex(4096);
    let task = tokio::spawn(async move { gateway.serve_connection(ingress).await });
    key.authenticate(&mut client).await.unwrap();
    client.write_all(&[5, 1, 0]).await.unwrap();
    let mut greeting = [0; 2];
    client.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [5, 0]);
    let host = b"allowed.test";
    let mut request = vec![5, 1, 0, 3, u8::try_from(host.len()).unwrap()];
    request.extend_from_slice(host);
    request.extend_from_slice(&address.port().to_be_bytes());
    client.write_all(&request).await.unwrap();
    let mut reply = [0; 10];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0);
    client.write_all(b"through-socks").await.unwrap();
    let mut echoed = vec![0; b"through-socks".len()];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, b"through-socks");
    client.shutdown().await.unwrap();
    task.await.unwrap().expect("clean SOCKS tunnel");
    echo.await.unwrap();
    assert_eq!(resolver.calls(), 1);
}

#[tokio::test]
async fn socks5_rejects_unsupported_commands_and_address_types() {
    for (request, expected_reply) in [
        (vec![5, 2, 0, 1, 127, 0, 0, 1, 0, 80], 0x07),
        (vec![5, 1, 0, 9], 0x08),
    ] {
        let address = SocketAddr::from(([127, 0, 0, 1], 80));
        let (gateway, _) = gateway("allowed.test", address);
        let key = gateway.ingress_key();
        let (mut client, ingress) = tokio::io::duplex(256);
        let task = tokio::spawn(async move { gateway.serve_connection(ingress).await });
        key.authenticate(&mut client).await.unwrap();
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut greeting = [0; 2];
        client.read_exact(&mut greeting).await.unwrap();
        client.write_all(&request).await.unwrap();
        let mut reply = [0; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], expected_reply);
        assert!(matches!(
            task.await.unwrap(),
            Err(GatewayError::InvalidSocksRequest { .. })
        ));
    }
}

#[tokio::test]
async fn request_connection_and_relay_limits_are_enforced() {
    let (address, server) = http_server(1).await;
    let resolver = StaticResolver::one("allowed.test", address);
    let policy = effective_network(local_policy("allowed.test"), NetworkPolicy::unrestricted());
    let config =
        GatewayConfig::new().with_max_requests_per_connection(NonZeroUsize::new(1).unwrap());
    let gateway = NetworkGateway::new(policy, resolver, config).unwrap();
    let key = gateway.ingress_key();
    let (mut client, ingress) = tokio::io::duplex(8192);
    let task = tokio::spawn(async move { gateway.serve_connection(ingress).await });
    key.authenticate(&mut client).await.unwrap();
    client
        .write_all(
            format!(
                "GET http://allowed.test:{0}/one HTTP/1.1\r\nHost: allowed.test:{0}\r\n\r\n",
                address.port(),
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let first = read_header(&mut client).await;
    assert!(first.starts_with(b"HTTP/1.1 200"));
    let mut first_body = vec![0; "response-0".len()];
    client.read_exact(&mut first_body).await.unwrap();
    client
        .write_all(
            format!(
                "GET http://allowed.test:{0}/two HTTP/1.1\r\nHost: allowed.test:{0}\r\n\r\n",
                address.port(),
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let second = read_header(&mut client).await;
    assert!(second.starts_with(b"HTTP/1.1 429"));
    client.shutdown().await.unwrap();
    task.await
        .unwrap()
        .expect("request limit is a handled response");
    server.await.unwrap();

    let (address, echo) = echo_server().await;
    let resolver = StaticResolver::one("allowed.test", address);
    let policy = effective_network(local_policy("allowed.test"), NetworkPolicy::unrestricted());
    let config = GatewayConfig::new().with_relay_byte_limit(NonZeroU64::new(3).unwrap());
    let gateway = NetworkGateway::new(policy, resolver, config).unwrap();
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
    client.write_all(b"four").await.unwrap();
    assert!(matches!(
        task.await.unwrap(),
        Err(GatewayError::RelayByteLimitExceeded { limit: 3 })
    ));
    echo.await.unwrap();
}

#[tokio::test]
async fn concurrent_connection_limit_is_shared_by_gateway_clones() {
    let address = SocketAddr::from(([127, 0, 0, 1], 80));
    let resolver = StaticResolver::one("allowed.test", address);
    let policy = effective_network(local_policy("allowed.test"), NetworkPolicy::unrestricted());
    let config = GatewayConfig::new()
        .with_max_concurrent_connections(NonZeroUsize::new(1).unwrap())
        .unwrap();
    let gateway = NetworkGateway::new(policy, resolver, config).unwrap();
    let key = gateway.ingress_key();
    let (mut first_client, first_ingress) = tokio::io::duplex(256);
    let first_gateway = gateway.clone();
    let first = tokio::spawn(async move { first_gateway.serve_connection(first_ingress).await });
    key.authenticate(&mut first_client).await.unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;

    let (_second_client, second_ingress) = tokio::io::duplex(256);
    assert!(matches!(
        gateway.serve_connection(second_ingress).await,
        Err(GatewayError::ConnectionLimitReached)
    ));
    drop(first_client);
    assert!(matches!(first.await.unwrap(), Err(GatewayError::Io { .. })));
}

async fn raw_http_status<R>(gateway: NetworkGateway<R>, host: &str, port: u16) -> String
where
    R: cageforge_network_proxy::NetworkResolver,
{
    let key = gateway.ingress_key();
    let (mut client, ingress) = tokio::io::duplex(4096);
    let task = tokio::spawn(async move { gateway.serve_connection(ingress).await });
    key.authenticate(&mut client).await.unwrap();
    client
        .write_all(
            format!("GET http://{host}:{port}/ HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();
    let response = String::from_utf8(read_header(&mut client).await).unwrap();
    client.shutdown().await.unwrap();
    task.await
        .unwrap()
        .expect("HTTP error is returned as a response");
    response
}
