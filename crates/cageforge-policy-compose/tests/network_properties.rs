// SPDX-License-Identifier: Apache-2.0

use cageforge_command::EnvironmentSpec;
use cageforge_policy::{
    ConnectionAuthorization, DomainAccess, LocalNetworkAccess, NetworkDecision, NetworkPolicy,
    ResolvedNetworkTarget, SandboxPolicy,
};
use cageforge_policy_compose::{CompositionRequest, PolicyCeiling, compose};
use proptest::prelude::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

fn public_ip() -> impl Strategy<Value = IpAddr> {
    prop::sample::select(vec![
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)),
    ])
}

fn non_public_ip() -> impl Strategy<Value = IpAddr> {
    prop::sample::select(vec![
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(169, 254, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1)),
        IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
    ])
}

fn network(local_access: LocalNetworkAccess) -> NetworkPolicy {
    NetworkPolicy::enabled()
        .with_local_network_access(local_access)
        .with_domain("service.example", DomainAccess::Allow)
        .expect("valid domain rule")
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn composition_never_widens_resolved_network_targets(
        public in public_ip(),
        local in non_public_ip(),
        requested_allow_local in any::<bool>(),
        ceiling_allow_local in any::<bool>(),
    ) {
        let requested = SandboxPolicy::new(
            cageforge_policy::FilesystemPolicy::restricted([]),
            network(if requested_allow_local {
                LocalNetworkAccess::Allow
            } else {
                LocalNetworkAccess::Deny
            }),
        );
        let ceiling = PolicyCeiling::new(
            SandboxPolicy::new(
                cageforge_policy::FilesystemPolicy::restricted([]),
                network(if ceiling_allow_local {
                    LocalNetworkAccess::Allow
                } else {
                    LocalNetworkAccess::Deny
                }),
            ),
            EnvironmentSpec::empty(),
        );
        let effective = compose(CompositionRequest::new(
            &requested,
            &EnvironmentSpec::empty(),
            &ceiling,
        ))
        .expect("valid policies compose");

        prop_assert_eq!(
            effective
                .network()
                .decision_for_domain_with_resolved_ips("service.example", &[public])
                .expect("valid public target"),
            NetworkDecision::Allow,
        );
        prop_assert_eq!(
            effective
                .network()
                .decision_for_domain_with_resolved_ips("service.example", &[local])
                .expect("valid local target"),
            if requested_allow_local && ceiling_allow_local {
                NetworkDecision::Allow
            } else {
                NetworkDecision::Deny
            },
        );
        prop_assert_eq!(
            effective
                .network()
                .decision_for_domain_with_resolved_ips("service.example", &[])
                .expect("failed resolution"),
            NetworkDecision::Deny,
        );

        let checked = SocketAddr::new(Ipv4Addr::new(8, 8, 8, 8).into(), 443);
        let changed = SocketAddr::new(Ipv4Addr::new(1, 1, 1, 1).into(), 443);
        let target = ResolvedNetworkTarget::new("service.example", [checked])
            .expect("valid resolved target");
        prop_assert_eq!(
            effective
                .network()
                .decision_for_connected_address(&target, checked)
                .expect("checked address"),
            NetworkDecision::Allow,
        );
        prop_assert_eq!(
            effective
                .network()
                .decision_for_connected_address(&target, changed)
                .expect("changed address"),
            NetworkDecision::Deny,
        );
        prop_assert!(matches!(
            effective
                .network()
                .authorize_connection(&target, checked)
                .expect("checked address authorization"),
            ConnectionAuthorization::Allowed(address) if address.socket_addr() == checked
        ));
        prop_assert_eq!(
            effective
                .network()
                .authorize_connection(&target, changed)
                .expect("changed address authorization"),
            ConnectionAuthorization::Denied,
        );
    }
}
