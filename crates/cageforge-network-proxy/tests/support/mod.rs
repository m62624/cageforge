// SPDX-License-Identifier: Apache-2.0

#![allow(
    dead_code,
    reason = "each black-box integration-test binary uses a different support subset"
)]

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use cageforge_command::EnvironmentSpec;
use cageforge_network_proxy::NetworkResolver;
use cageforge_policy::{FilesystemPolicy, NetworkPolicy, SandboxPolicy};
use cageforge_policy_compose::{
    CompositionRequest, EffectiveNetworkPolicy, ExternalOwner, PolicyCeiling, compose,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Clone, Default)]
pub struct StaticResolver {
    answers: Arc<HashMap<String, Vec<SocketAddr>>>,
    calls: Arc<AtomicUsize>,
}

pub fn effective_external_network() -> EffectiveNetworkPolicy {
    let requested = SandboxPolicy::new(FilesystemPolicy::unrestricted(), NetworkPolicy::external());
    let ceiling_policy =
        SandboxPolicy::new(FilesystemPolicy::unrestricted(), NetworkPolicy::external());
    let environment = EnvironmentSpec::empty();
    let owner = ExternalOwner::new();
    let ceiling =
        PolicyCeiling::new(ceiling_policy, environment.clone()).with_external_owner(owner.clone());
    compose(CompositionRequest::new(&requested, &environment, &ceiling).with_external_owner(owner))
        .expect("matching external network owners compose")
        .network()
        .clone()
}

impl StaticResolver {
    pub fn one(host: &str, address: SocketAddr) -> Self {
        Self {
            answers: Arc::new(HashMap::from([(host.to_string(), vec![address])])),
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn with_answers(host: &str, addresses: Vec<SocketAddr>) -> Self {
        Self {
            answers: Arc::new(HashMap::from([(host.to_string(), addresses)])),
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::Relaxed)
    }
}

impl NetworkResolver for StaticResolver {
    async fn resolve(&self, host: &str, _port: u16) -> io::Result<Vec<SocketAddr>> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(self.answers.get(host).cloned().unwrap_or_default())
    }
}

pub fn effective_network(
    requested_network: NetworkPolicy,
    ceiling_network: NetworkPolicy,
) -> EffectiveNetworkPolicy {
    let requested = SandboxPolicy::new(FilesystemPolicy::unrestricted(), requested_network);
    let ceiling_policy = SandboxPolicy::new(FilesystemPolicy::unrestricted(), ceiling_network);
    let environment = EnvironmentSpec::empty();
    let ceiling = PolicyCeiling::new(ceiling_policy, environment.clone());
    compose(CompositionRequest::new(&requested, &environment, &ceiling))
        .expect("valid network policies compose")
        .network()
        .clone()
}

pub async fn http_server(requests: usize) -> (SocketAddr, tokio::task::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind HTTP fixture");
    let address = listener.local_addr().expect("HTTP fixture address");
    let handle = tokio::spawn(async move {
        let mut received = Vec::with_capacity(requests);
        for index in 0..requests {
            let (mut stream, _) = listener.accept().await.expect("accept HTTP fixture");
            let header = read_header(&mut stream).await;
            received.push(String::from_utf8(header).expect("ASCII HTTP request"));
            let body = format!("response-{index}");
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write HTTP fixture response");
        }
        received
    });
    (address, handle)
}

pub async fn echo_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind echo fixture");
    let address = listener.local_addr().expect("echo fixture address");
    let handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept echo fixture");
        let mut buffer = [0; 1024];
        loop {
            let read = stream.read(&mut buffer).await.expect("read echo data");
            if read == 0 {
                break;
            }
            stream
                .write_all(&buffer[..read])
                .await
                .expect("write echo data");
        }
    });
    (address, handle)
}

pub async fn read_header<S>(stream: &mut S) -> Vec<u8>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut bytes = Vec::new();
    loop {
        bytes.push(stream.read_u8().await.expect("read HTTP header byte"));
        if bytes.ends_with(b"\r\n\r\n") {
            return bytes;
        }
        assert!(bytes.len() < 64 * 1024, "HTTP header fixture is bounded");
    }
}
