// SPDX-License-Identifier: Apache-2.0

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Eq, PartialEq)]
struct AddressSet {
    ipv4: Vec<(u32, u32)>,
    ipv6: Vec<(u128, u128)>,
}

const DOMAIN_PROFILE: i32 = 1;
const PRIVATE_PROFILE: i32 = 2;
const PUBLIC_PROFILE: i32 = 4;
const KNOWN_PROFILES: i32 = DOMAIN_PROFILE | PRIVATE_PROFILE | PUBLIC_PROFILE;

pub(crate) fn active_firewall_profiles(mask: i32) -> Option<Vec<i32>> {
    if mask == 0 || mask & !KNOWN_PROFILES != 0 {
        return None;
    }
    Some(
        [DOMAIN_PROFILE, PRIVATE_PROFILE, PUBLIC_PROFILE]
            .into_iter()
            .filter(|profile| mask & profile != 0)
            .collect(),
    )
}

pub(crate) fn address_sets_match(actual: &str, expected: &str) -> bool {
    canonical_address_set(actual)
        .zip(canonical_address_set(expected))
        .is_some_and(|(actual, expected)| actual == expected)
}

pub(crate) fn port_sets_match(actual: &str, expected: &str) -> bool {
    canonical_port_set(actual)
        .zip(canonical_port_set(expected))
        .is_some_and(|(actual, expected)| actual == expected)
}

pub(crate) fn local_user_scope_matches(actual: &str, expected_sid: &str) -> bool {
    let Some((_, dacl)) = actual.split_once("D:") else {
        return false;
    };
    let Some(open) = dacl.find('(') else {
        return false;
    };
    if !matches!(dacl[..open].trim(), "" | "P") {
        return false;
    }
    let Some(close) = dacl[open + 1..].find(')').map(|close| open + 1 + close) else {
        return false;
    };
    if !dacl[close + 1..].trim().is_empty() {
        return false;
    }
    let fields = dacl[open + 1..close].split(';').collect::<Vec<_>>();
    fields.len() == 6
        && fields[0].eq_ignore_ascii_case("A")
        && fields[1].is_empty()
        && (fields[2].eq_ignore_ascii_case("CC") || matches!(fields[2], "0x1" | "0X1" | "1"))
        && fields[3].is_empty()
        && fields[4].is_empty()
        && fields[5].eq_ignore_ascii_case(expected_sid)
}

fn canonical_address_set(value: &str) -> Option<AddressSet> {
    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();
    for token in value.split(',').map(str::trim) {
        if token.is_empty() {
            return None;
        }
        if let Some((address, mask)) = token.split_once('/') {
            let address = address.parse::<IpAddr>().ok()?;
            match address {
                IpAddr::V4(address) => {
                    let prefix = ipv4_prefix_length(mask)?;
                    ipv4.push(ipv4_prefix(address, prefix)?);
                }
                IpAddr::V6(address) => {
                    ipv6.push(ipv6_prefix(address, mask.parse::<u8>().ok()?)?);
                }
            }
        } else if let Some((start, end)) = token.split_once('-') {
            match (start.parse::<IpAddr>().ok()?, end.parse::<IpAddr>().ok()?) {
                (IpAddr::V4(start), IpAddr::V4(end)) => {
                    let interval = (u32::from(start), u32::from(end));
                    if interval.0 > interval.1 {
                        return None;
                    }
                    ipv4.push(interval);
                }
                (IpAddr::V6(start), IpAddr::V6(end)) => {
                    let interval = (u128::from(start), u128::from(end));
                    if interval.0 > interval.1 {
                        return None;
                    }
                    ipv6.push(interval);
                }
                _ => return None,
            }
        } else {
            match token.parse::<IpAddr>().ok()? {
                IpAddr::V4(address) => {
                    let address = u32::from(address);
                    ipv4.push((address, address));
                }
                IpAddr::V6(address) => {
                    let address = u128::from(address);
                    ipv6.push((address, address));
                }
            }
        }
    }
    Some(AddressSet {
        ipv4: merge_intervals(ipv4, u32::MAX),
        ipv6: merge_intervals(ipv6, u128::MAX),
    })
}

fn canonical_port_set(value: &str) -> Option<Vec<(u16, u16)>> {
    if value.trim() == "*" {
        return Some(vec![(1, u16::MAX)]);
    }
    let mut intervals = Vec::new();
    for token in value.split(',').map(str::trim) {
        let interval = if let Some((start, end)) = token.split_once('-') {
            (start.parse::<u16>().ok()?, end.parse::<u16>().ok()?)
        } else {
            let port = token.parse::<u16>().ok()?;
            (port, port)
        };
        if interval.0 == 0 || interval.0 > interval.1 {
            return None;
        }
        intervals.push(interval);
    }
    Some(merge_intervals(intervals, u16::MAX))
}

fn ipv4_prefix(address: Ipv4Addr, prefix: u8) -> Option<(u32, u32)> {
    if prefix > 32 {
        return None;
    }
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    let start = u32::from(address) & mask;
    Some((start, start | !mask))
}

fn ipv4_prefix_length(value: &str) -> Option<u8> {
    if let Ok(prefix) = value.parse::<u8>() {
        return (prefix <= 32).then_some(prefix);
    }
    let mask = u32::from(value.parse::<Ipv4Addr>().ok()?);
    let prefix = mask.leading_ones() as u8;
    let canonical = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    (mask == canonical).then_some(prefix)
}

fn ipv6_prefix(address: Ipv6Addr, prefix: u8) -> Option<(u128, u128)> {
    if prefix > 128 {
        return None;
    }
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    let start = u128::from(address) & mask;
    Some((start, start | !mask))
}

fn merge_intervals<T>(mut intervals: Vec<(T, T)>, maximum: T) -> Vec<(T, T)>
where
    T: Copy + Ord + std::ops::Add<Output = T> + From<u8>,
{
    intervals.sort_unstable_by_key(|interval| interval.0);
    let mut merged: Vec<(T, T)> = Vec::with_capacity(intervals.len());
    for (start, end) in intervals {
        if let Some(previous) = merged.last_mut() {
            let adjacent = previous.1 != maximum && start <= previous.1 + T::from(1);
            if start <= previous.1 || adjacent {
                previous.1 = previous.1.max(end);
                continue;
            }
        }
        merged.push((start, end));
    }
    merged
}

#[cfg(test)]
mod tests {
    use super::{
        active_firewall_profiles, address_sets_match, local_user_scope_matches, port_sets_match,
    };

    #[test]
    fn active_firewall_profiles_reject_empty_or_unknown_policy_state() {
        assert_eq!(active_firewall_profiles(0), None);
        assert_eq!(active_firewall_profiles(8), None);
        assert_eq!(active_firewall_profiles(1 | 8), None);
    }

    #[test]
    fn active_firewall_profiles_preserve_every_known_active_profile() {
        assert_eq!(active_firewall_profiles(1), Some(vec![1]));
        assert_eq!(active_firewall_profiles(2 | 4), Some(vec![2, 4]));
        assert_eq!(active_firewall_profiles(1 | 2 | 4), Some(vec![1, 2, 4]));
    }

    #[test]
    fn address_comparison_accepts_equivalent_windows_canonicalization() {
        assert!(address_sets_match(
            "127.0.0.0/255.0.0.0,::/127",
            "127.0.0.0/8,::/127"
        ));
    }

    #[test]
    fn address_comparison_rejects_a_non_contiguous_ipv4_mask() {
        assert!(!address_sets_match(
            "127.0.0.0/255.0.255.0,::/127",
            "127.0.0.0/8,::/127"
        ));
    }

    #[test]
    fn address_comparison_rejects_one_extra_loopback_address() {
        assert!(!address_sets_match(
            "0.0.0.0-126.255.255.255,127.0.0.1,128.0.0.0-255.255.255.255",
            "0.0.0.0-126.255.255.255,128.0.0.0-255.255.255.255"
        ));
    }

    #[test]
    fn port_comparison_uses_the_complete_set() {
        assert!(port_sets_match("1-3,4,6-65535", "1-4,6-65535"));
        assert!(!port_sets_match("1-5,7-65535", "1-4,6-65535"));
    }

    #[test]
    fn local_user_scope_requires_one_exact_allow_ace() {
        let sid = "S-1-5-21-1-2-3-1001";
        assert!(local_user_scope_matches(
            "O:LSD:(A;;CC;;;S-1-5-21-1-2-3-1001)",
            sid
        ));
        assert!(!local_user_scope_matches(
            "O:LSD:(A;;CC;;;S-1-5-21-1-2-3-1001)(A;;CC;;;WD)",
            sid
        ));
        assert!(!local_user_scope_matches(
            "O:LSD:(A;;CC;;;S-1-5-21-1-2-3-10010)",
            sid
        ));
    }
}
