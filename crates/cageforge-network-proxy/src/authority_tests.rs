// SPDX-License-Identifier: Apache-2.0

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use super::Authority;

#[test]
fn authority_parser_rejects_ambiguous_and_missing_endpoints() {
    for value in [
        "user@example.com:80",
        "bad host:80",
        "example.com",
        "example.com:0",
    ] {
        assert!(Authority::parse(value, None).is_err(), "accepted {value:?}");
    }
    assert!(Authority::from_host_port(String::new(), 80).is_err());
    assert!(Authority::from_host_port("example.com".to_string(), 0).is_err());
}

#[test]
fn authority_identity_normalizes_host_spelling_but_not_ports() {
    let first = Authority::parse("EXAMPLE.com.:80", None).unwrap();
    let second = Authority::parse("example.com:80", None).unwrap();
    let other_port = Authority::parse("example.com:81", None).unwrap();
    assert!(first.same_endpoint(&second));
    assert!(!first.same_endpoint(&other_port));
}

#[test]
fn ipv6_authorities_roundtrip_as_exact_socket_addresses() {
    let authority = Authority::from_host_port("2001:db8::1".to_string(), 443).unwrap();
    assert_eq!(authority.host(), "2001:db8::1");
    assert_eq!(authority.port(), 443);
    assert_eq!(
        authority.literal_address(),
        Some(SocketAddr::new(
            IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
            443,
        ))
    );
}
