// SPDX-License-Identifier: Apache-2.0

use std::io::{Read, Write};
use std::num::NonZeroUsize;
use std::os::unix::net::UnixStream;
use std::thread;
use std::time::Duration;

use cageforge_command::EnvironmentSpec;
use cageforge_network_proxy::GatewayConfig;
use cageforge_policy::{FilesystemPolicy, NetworkPolicy, SandboxPolicy};
use cageforge_policy_compose::{CompositionRequest, PolicyCeiling, compose};

use super::GatewayRuntime;

fn effective_network() -> cageforge_policy_compose::EffectiveNetworkPolicy {
    let environment = EnvironmentSpec::inherit_all();
    let requested = SandboxPolicy::new(FilesystemPolicy::unrestricted(), NetworkPolicy::enabled());
    let ceiling = PolicyCeiling::new(SandboxPolicy::full_access(), environment.clone());
    compose(CompositionRequest::new(&requested, &environment, &ceiling))
        .expect("effective sandbox")
        .network()
        .clone()
}

#[test]
fn private_socket_rejects_a_same_user_client_without_the_bridge_token() {
    let mut runtime =
        GatewayRuntime::start(effective_network(), GatewayConfig::new()).expect("gateway runtime");
    let socket = runtime.mount_source().join("gateway.sock");
    let mut client = UnixStream::connect(socket).expect("private socket");
    client
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("read timeout");
    client
        .write_all(b"GET http://127.0.0.1/ HTTP/1.1\r\n\r\n")
        .expect("unauthenticated request");
    let mut response = Vec::new();
    match client.read_to_end(&mut response) {
        Ok(_) => assert!(response.is_empty()),
        Err(error) => assert!(matches!(
            error.kind(),
            std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe
        )),
    }
    runtime.shutdown().expect("gateway shutdown");
}

#[test]
fn dropping_the_runtime_removes_its_private_socket_directory() {
    let runtime =
        GatewayRuntime::start(effective_network(), GatewayConfig::new()).expect("gateway runtime");
    let directory = runtime.mount_source().to_path_buf();
    assert!(directory.join("gateway.sock").exists());
    drop(runtime);
    assert!(!directory.exists());
}

#[test]
fn stalled_bridge_authentication_is_bounded_by_the_handshake_timeout() {
    let config = GatewayConfig::new()
        .with_handshake_timeout(Duration::from_millis(20))
        .expect("handshake timeout");
    let mut runtime = GatewayRuntime::start(effective_network(), config).expect("gateway runtime");
    let socket = runtime.mount_source().join("gateway.sock");
    let mut client = UnixStream::connect(socket).expect("private socket");
    client
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("read timeout");

    assert_private_stream_closed(&mut client);
    runtime.shutdown().expect("gateway shutdown");
}

#[test]
fn unauthenticated_bridge_connections_share_the_instance_connection_limit() {
    let config = GatewayConfig::new()
        .with_handshake_timeout(Duration::from_secs(1))
        .expect("handshake timeout")
        .with_max_concurrent_connections(NonZeroUsize::new(1).expect("non-zero"))
        .expect("connection limit");
    let mut runtime = GatewayRuntime::start(effective_network(), config).expect("gateway runtime");
    let socket = runtime.mount_source().join("gateway.sock");
    let _stalled = UnixStream::connect(&socket).expect("first private socket");
    thread::sleep(Duration::from_millis(20));
    let mut rejected = UnixStream::connect(socket).expect("second private socket");
    rejected
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("read timeout");

    assert_private_stream_closed(&mut rejected);
    runtime.shutdown().expect("gateway shutdown");
}

fn assert_private_stream_closed(stream: &mut UnixStream) {
    let mut byte = [0; 1];
    match stream.read(&mut byte) {
        Ok(0) => {}
        Ok(count) => panic!("private stream returned {count} unexpected bytes"),
        Err(error) => assert!(matches!(
            error.kind(),
            std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe
        )),
    }
}
