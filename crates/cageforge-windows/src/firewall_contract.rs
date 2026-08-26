// SPDX-License-Identifier: Apache-2.0

use std::ffi::c_void;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use windows_sys::Win32::Foundation::{HLOCAL, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, ConvertStringSidToSidW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, EqualSid, GetAce, GetSecurityDescriptorDacl, IsValidAcl,
    IsValidSecurityDescriptor, IsValidSid, PSECURITY_DESCRIPTOR, PSID,
};
use windows_sys::Win32::System::Com::COM_RIGHTS_EXECUTE;
use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;

#[derive(Eq, PartialEq)]
struct AddressSet {
    ipv4: Vec<(u32, u32)>,
    ipv6: Vec<(u128, u128)>,
}

struct LocalSecurityDescriptor(PSECURITY_DESCRIPTOR);

struct LocalSid(PSID);

#[allow(unsafe_code)]
impl Drop for LocalSecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0 as HLOCAL);
            }
        }
    }
}

#[allow(unsafe_code)]
impl Drop for LocalSid {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0 as HLOCAL);
            }
        }
    }
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

#[allow(unsafe_code)]
pub(crate) fn local_user_scope_matches(actual: &str, expected_sid: &str) -> bool {
    let actual_wide = wide(actual);
    let mut descriptor = std::ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            actual_wide.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    } == 0
        || descriptor.is_null()
    {
        return false;
    }
    let descriptor = LocalSecurityDescriptor(descriptor);
    if unsafe { IsValidSecurityDescriptor(descriptor.0) } == 0 {
        return false;
    }

    let sid_wide = wide(expected_sid);
    let mut sid = std::ptr::null_mut();
    if unsafe { ConvertStringSidToSidW(sid_wide.as_ptr(), &mut sid) } == 0 || sid.is_null() {
        return false;
    }
    let sid = LocalSid(sid);

    let mut present = 0;
    let mut dacl = std::ptr::null_mut();
    let mut defaulted = 0;
    if unsafe { GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut dacl, &mut defaulted) }
        == 0
        || present == 0
        || dacl.is_null()
        || unsafe { IsValidAcl(dacl) } == 0
        || unsafe { (*dacl).AceCount } != 1
    {
        return false;
    }

    let mut raw_ace = std::ptr::null_mut();
    if unsafe { GetAce(dacl, 0, &mut raw_ace) } == 0 || raw_ace.is_null() {
        return false;
    }
    let ace = raw_ace.cast::<ACCESS_ALLOWED_ACE>();
    if unsafe { (*ace).Header.AceType } != ACCESS_ALLOWED_ACE_TYPE as u8
        || unsafe { (*ace).Header.AceFlags } != 0
        || usize::from(unsafe { (*ace).Header.AceSize }) < size_of::<ACCESS_ALLOWED_ACE>()
        || unsafe { (*ace).Mask } != COM_RIGHTS_EXECUTE
    {
        return false;
    }
    let actual_sid = unsafe { (&raw mut (*ace).SidStart).cast::<c_void>() };
    unsafe {
        IsValidSid(actual_sid) != 0 && IsValidSid(sid.0) != 0 && EqualSid(actual_sid, sid.0) != 0
    }
}

fn canonical_address_set(value: &str) -> Option<AddressSet> {
    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();
    for token in value.split(',').map(str::trim) {
        if token.is_empty() {
            return None;
        }
        if let Some((address, prefix)) = token.split_once('/') {
            let address = address.parse::<IpAddr>().ok()?;
            let prefix = prefix.parse::<u8>().ok()?;
            match address {
                IpAddr::V4(address) => ipv4.push(ipv4_prefix(address, prefix)?),
                IpAddr::V6(address) => ipv6.push(ipv6_prefix(address, prefix)?),
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

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::{address_sets_match, port_sets_match};

    #[test]
    fn address_comparison_accepts_equivalent_windows_canonicalization() {
        assert!(address_sets_match(
            "::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff,0.0.0.0/1,128.0.0.0/1,::",
            "0.0.0.0-255.255.255.255,::,::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
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
}
