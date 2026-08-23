// SPDX-License-Identifier: Apache-2.0

mod support;

use std::net::SocketAddr;
use std::time::Duration;

use cageforge_network_proxy::{GatewayConfig, NetworkGateway};
use cageforge_policy::{DomainAccess, DomainMode, LocalNetworkAccess, NetworkPolicy};
use proptest::prelude::*;
use tokio::io::AsyncWriteExt;

use support::{StaticResolver, effective_network, read_header};

fn policy(host: &str) -> cageforge_policy_compose::EffectiveNetworkPolicy {
    let requested = NetworkPolicy::enabled()
        .with_domain_mode(DomainMode::Restricted)
        .with_local_network_access(LocalNetworkAccess::Allow)
        .with_domain(host, DomainAccess::Allow)
        .expect("generated test host is valid");
    effective_network(requested, NetworkPolicy::unrestricted())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn resolver_port_substitution_always_fails_closed(
        requested_port in 1_u16..=u16::MAX,
        resolved_port in 1_u16..=u16::MAX,
    ) {
        prop_assume!(requested_port != resolved_port);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        runtime.block_on(async move {
            let address = SocketAddr::from(([127, 0, 0, 1], resolved_port));
            let resolver = StaticResolver::one("allowed.test", address);
            let gateway = NetworkGateway::new(
                policy("allowed.test"),
                resolver,
                GatewayConfig::new(),
            )
            .expect("valid gateway");
            let key = gateway.ingress_key();
            let (mut client, ingress) = tokio::io::duplex(4096);
            let task = tokio::spawn(async move { gateway.serve_connection(ingress).await });
            key.authenticate(&mut client).await.expect("authenticate ingress");
            client
                .write_all(
                    format!(
                        "GET http://allowed.test:{requested_port}/ HTTP/1.1\r\nHost: allowed.test:{requested_port}\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .expect("write request");
            let response = read_header(&mut client).await;
            prop_assert!(response.starts_with(b"HTTP/1.1 502"));
            client.shutdown().await.expect("close ingress");
            task.await.expect("gateway task").expect("handled proxy response");
            Ok(())
        })?;
    }

    #[test]
    fn arbitrary_bounded_protocol_input_never_panics_or_stalls(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        runtime.block_on(async move {
            let resolver = StaticResolver::default();
            let gateway = NetworkGateway::new(
                policy("allowed.test"),
                resolver,
                GatewayConfig::new()
                    .with_handshake_timeout(Duration::from_millis(20))
                    .expect("valid timeout"),
            )
            .expect("valid gateway");
            let key = gateway.ingress_key();
            let (mut client, ingress) = tokio::io::duplex(1024);
            let task = tokio::spawn(async move { gateway.serve_connection(ingress).await });
            key.authenticate(&mut client).await.expect("authenticate ingress");
            client.write_all(&bytes).await.expect("write generated input");
            client.shutdown().await.expect("close generated ingress");
            let _result = tokio::time::timeout(Duration::from_millis(100), task)
                .await
                .expect("bounded parser completion")
                .expect("gateway task must not panic");
        });
    }
}
