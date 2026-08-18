// Copyright 2026 Mansur Azatbek
// SPDX-License-Identifier: Apache-2.0

use cageforge_policy::{DomainAccess, LocalNetworkAccess, NetworkDecision, NetworkPolicy};
use proptest::prelude::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn public_ip() -> impl Strategy<Value = IpAddr> {
    prop::sample::select(vec![
        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
        IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)),
        IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
    ])
}

fn non_public_ip() -> impl Strategy<Value = IpAddr> {
    prop::sample::select(vec![
        IpAddr::V4(Ipv4Addr::new(0, 1, 2, 3)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(169, 254, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
        IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(240, 0, 0, 1)),
        IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1)),
        IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
        IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)),
        IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x7f00, 1)),
    ])
}

fn resolved_ip() -> impl Strategy<Value = (IpAddr, bool)> {
    prop_oneof![
        public_ip().prop_map(|ip| (ip, false)),
        non_public_ip().prop_map(|ip| (ip, true)),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn hostname_allow_requires_all_resolved_addresses_to_be_public(
        resolved in prop::collection::vec(resolved_ip(), 0..=4),
    ) {
        let policy = NetworkPolicy::enabled()
            .with_domain("service.example", DomainAccess::Allow)
            .expect("valid domain rule");
        let addresses: Vec<IpAddr> = resolved.iter().map(|(ip, _)| *ip).collect();
        let has_non_public = resolved.iter().any(|(_, non_public)| *non_public);
        let expected = if addresses.is_empty() || has_non_public {
            NetworkDecision::Deny
        } else {
            NetworkDecision::Allow
        };

        prop_assert_eq!(
            policy
                .decision_for_domain_with_resolved_ips("service.example", &addresses)
                .expect("valid hostname"),
            expected,
        );
    }

    #[test]
    fn localhost_is_denied_even_when_dns_reports_public_addresses(
        public in public_ip(),
    ) {
        let policy = NetworkPolicy::enabled()
            .with_domain("*", DomainAccess::Allow)
            .expect("valid wildcard domain");

        prop_assert_eq!(
            policy
                .decision_for_domain_with_resolved_ips("localhost", &[public])
                .expect("valid localhost hostname"),
            NetworkDecision::Deny,
        );
    }

    #[test]
    fn explicit_local_opt_in_allows_non_public_results_but_not_failed_resolution(
        local in non_public_ip(),
    ) {
        let policy = NetworkPolicy::enabled()
            .with_local_network_access(LocalNetworkAccess::Allow)
            .with_domain("service.example", DomainAccess::Allow)
            .expect("valid domain rule");

        prop_assert_eq!(
            policy
                .decision_for_domain_with_resolved_ips("service.example", &[local])
                .expect("valid hostname"),
            NetworkDecision::Allow,
        );
        prop_assert_eq!(
            policy
                .decision_for_domain_with_resolved_ips("service.example", &[])
                .expect("valid hostname"),
            NetworkDecision::Deny,
        );
    }

    #[test]
    fn exact_literal_allow_is_the_only_default_local_literal_opt_in(
        local in non_public_ip(),
    ) {
        let literal = local.to_string();
        let allowlisted = NetworkPolicy::enabled()
            .with_domain(literal.clone(), DomainAccess::Allow)
            .expect("valid literal rule");
        let ordinary = NetworkPolicy::enabled();

        prop_assert_eq!(
            allowlisted
                .decision_for_domain_with_resolved_ips(&literal, &[])
                .expect("valid literal"),
            NetworkDecision::Allow,
        );
        prop_assert_eq!(
            ordinary
                .decision_for_domain_with_resolved_ips(&literal, &[])
                .expect("valid literal"),
            NetworkDecision::Deny,
        );
    }
}
