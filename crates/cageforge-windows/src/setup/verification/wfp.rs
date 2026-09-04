// SPDX-License-Identifier: Apache-2.0

use std::ffi::c_void;
use std::mem::{align_of, offset_of, size_of, zeroed};

use sha2::{Digest, Sha256};
use windows_sys::Win32::Foundation::{HANDLE, HLOCAL, LocalFree};
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_ACTRL_MATCH_FILTER, FWP_MATCH_EQUAL,
    FWP_SECURITY_DESCRIPTOR_TYPE, FWP_UINT8, FWP_UINT16, FWP_UINT32, FWPM_CONDITION_ALE_USER_ID,
    FWPM_CONDITION_IP_PROTOCOL, FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_CONDITION_IP_REMOTE_PORT,
    FWPM_FILTER_CONDITION0, FWPM_FILTER_FLAG_PERSISTENT, FWPM_FILTER0,
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_PROVIDER_FLAG_PERSISTENT,
    FWPM_SESSION0, FWPM_SUBLAYER_FLAG_PERSISTENT, FwpmEngineClose0, FwpmEngineOpen0,
    FwpmFilterGetByKey0, FwpmFreeMemory0, FwpmProviderGetByKey0, FwpmSubLayerGetByKey0,
};
use windows_sys::Win32::Networking::WinSock::IPPROTO_TCP;
use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation, EqualSid,
    GetAce, GetAclInformation, GetSecurityDescriptorDacl, GetSecurityDescriptorLength,
    IsValidSecurityDescriptor, IsValidSid, PSID,
};
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_DEFAULT;
use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;
use windows_sys::Win32::System::Threading::INFINITE;
use windows_sys::core::GUID;

use crate::error::WindowsSetupVerificationError;
use crate::firewall_contract::{
    WFP_BASE_FILTERS, WFP_IPV4_LOOPBACK_HOST_ORDER as IPV4_LOOPBACK_HOST_ORDER,
    WFP_PROVIDER_KEY as PROVIDER_KEY, WFP_SUBLAYER_KEY as SUBLAYER_KEY, WfpBaseCondition,
};
use crate::setup::WindowsSetupDetails;

struct FilterExpectation {
    key: GUID,
    name: String,
    layer_key: GUID,
    action: u32,
    weight: u8,
    conditions: Vec<ConditionExpectation>,
}

enum ConditionExpectation {
    User,
    Protocol(u8),
    RemoteAddressV4(u32),
    RemotePort(u16),
}

struct Engine(HANDLE);

struct LocalSid(PSID);

struct WfpAllocation<T>(*mut T);

#[derive(Clone, Copy)]
struct AclBounds {
    start: usize,
    end: usize,
}

const SID_HEADER_BYTES: usize = 8;

#[allow(unsafe_code)]
impl Drop for Engine {
    fn drop(&mut self) {
        unsafe {
            FwpmEngineClose0(self.0);
        }
    }
}

impl Engine {
    #[allow(unsafe_code)]
    fn open() -> Result<Self, WindowsSetupVerificationError> {
        let name = wide("Cageforge Windows sandbox WFP verification");
        let mut session: FWPM_SESSION0 = unsafe { zeroed() };
        session.displayData.name = name.as_ptr().cast_mut();
        session.txnWaitTimeoutInMSec = INFINITE;
        let mut handle = std::ptr::null_mut();
        let status = unsafe {
            FwpmEngineOpen0(
                std::ptr::null(),
                RPC_C_AUTHN_DEFAULT as u32,
                std::ptr::null(),
                &session,
                &mut handle,
            )
        };
        if status != 0 {
            return Err(WindowsSetupVerificationError::WfpEngineOpen { code: status });
        }
        Ok(Self(handle))
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

impl LocalSid {
    #[allow(unsafe_code)]
    fn parse(value: &str) -> Option<Self> {
        let value = wide(value);
        let mut sid = std::ptr::null_mut();
        if unsafe { ConvertStringSidToSidW(value.as_ptr(), &mut sid) } == 0 {
            None
        } else {
            Some(Self(sid))
        }
    }
}

#[allow(unsafe_code)]
impl<T> Drop for WfpAllocation<T> {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                FwpmFreeMemory0((&raw mut self.0).cast::<*mut c_void>());
            }
        }
    }
}

pub(super) fn verify(details: &WindowsSetupDetails) -> Result<(), WindowsSetupVerificationError> {
    if !details
        .wfp_provider_id()
        .eq_ignore_ascii_case(&guid_string(PROVIDER_KEY))
    {
        return Err(WindowsSetupVerificationError::WfpProvider { code: 0 });
    }
    let engine = Engine::open()?;
    verify_provider(&engine)?;
    verify_sublayer(&engine)?;
    for filter in filter_expectations(details.owner_sid(), details.proxy_ports()) {
        verify_filter(&engine, &filter, details.accounts().offline_sid())?;
    }
    Ok(())
}

#[allow(unsafe_code)]
fn verify_provider(engine: &Engine) -> Result<(), WindowsSetupVerificationError> {
    let mut value = std::ptr::null_mut();
    let status = unsafe { FwpmProviderGetByKey0(engine.0, &PROVIDER_KEY, &mut value) };
    if status != 0 {
        return Err(WindowsSetupVerificationError::WfpProvider { code: status });
    }
    let value = WfpAllocation(value);
    let provider = unsafe { value.0.as_ref() }
        .ok_or(WindowsSetupVerificationError::WfpProvider { code: 0 })?;
    if guid_eq(provider.providerKey, PROVIDER_KEY)
        && provider.flags & FWPM_PROVIDER_FLAG_PERSISTENT != 0
    {
        Ok(())
    } else {
        Err(WindowsSetupVerificationError::WfpProvider { code: 0 })
    }
}

#[allow(unsafe_code)]
fn verify_sublayer(engine: &Engine) -> Result<(), WindowsSetupVerificationError> {
    let mut value = std::ptr::null_mut();
    let status = unsafe { FwpmSubLayerGetByKey0(engine.0, &SUBLAYER_KEY, &mut value) };
    if status != 0 {
        return Err(WindowsSetupVerificationError::WfpSublayer { code: status });
    }
    let value = WfpAllocation(value);
    let sublayer = unsafe { value.0.as_ref() }
        .ok_or(WindowsSetupVerificationError::WfpSublayer { code: 0 })?;
    if guid_eq(sublayer.subLayerKey, SUBLAYER_KEY)
        && sublayer.flags & FWPM_SUBLAYER_FLAG_PERSISTENT != 0
        && !sublayer.providerKey.is_null()
        && guid_eq(unsafe { *sublayer.providerKey }, PROVIDER_KEY)
    {
        Ok(())
    } else {
        Err(WindowsSetupVerificationError::WfpSublayer { code: 0 })
    }
}

#[allow(unsafe_code)]
fn verify_filter(
    engine: &Engine,
    expected: &FilterExpectation,
    offline_sid: &str,
) -> Result<(), WindowsSetupVerificationError> {
    let mut value = std::ptr::null_mut();
    let status = unsafe { FwpmFilterGetByKey0(engine.0, &expected.key, &mut value) };
    if status != 0 {
        return Err(WindowsSetupVerificationError::WfpFilter {
            name: expected.name.clone(),
            code: status,
        });
    }
    let value: WfpAllocation<FWPM_FILTER0> = WfpAllocation(value);
    let filter =
        unsafe { value.0.as_ref() }.ok_or_else(|| WindowsSetupVerificationError::WfpFilter {
            name: expected.name.clone(),
            code: 0,
        })?;
    let header_matches = guid_eq(filter.filterKey, expected.key)
        && filter.flags & FWPM_FILTER_FLAG_PERSISTENT != 0
        && guid_eq(filter.layerKey, expected.layer_key)
        && guid_eq(filter.subLayerKey, SUBLAYER_KEY)
        && !filter.providerKey.is_null()
        && guid_eq(unsafe { *filter.providerKey }, PROVIDER_KEY)
        && filter.action.r#type == expected.action
        && filter.weight.r#type == FWP_UINT8
        && unsafe { filter.weight.Anonymous.uint8 } == expected.weight
        && filter.numFilterConditions == expected.conditions.len() as u32
        && !filter.filterCondition.is_null();
    if !header_matches {
        return Err(WindowsSetupVerificationError::WfpFilter {
            name: expected.name.clone(),
            code: 0,
        });
    }
    let conditions = unsafe {
        std::slice::from_raw_parts(filter.filterCondition, filter.numFilterConditions as usize)
    };
    if conditions
        .iter()
        .zip(&expected.conditions)
        .all(|(actual, expected)| condition_matches(actual, expected, offline_sid))
    {
        Ok(())
    } else {
        Err(WindowsSetupVerificationError::WfpFilter {
            name: expected.name.clone(),
            code: 0,
        })
    }
}

#[allow(unsafe_code)]
fn condition_matches(
    actual: &FWPM_FILTER_CONDITION0,
    expected: &ConditionExpectation,
    offline_sid: &str,
) -> bool {
    if actual.matchType != FWP_MATCH_EQUAL {
        return false;
    }
    match expected {
        ConditionExpectation::User => user_condition_matches(actual, offline_sid),
        ConditionExpectation::Protocol(protocol) => {
            guid_eq(actual.fieldKey, FWPM_CONDITION_IP_PROTOCOL)
                && actual.conditionValue.r#type == FWP_UINT8
                && unsafe { actual.conditionValue.Anonymous.uint8 } == *protocol
        }
        ConditionExpectation::RemoteAddressV4(address) => {
            guid_eq(actual.fieldKey, FWPM_CONDITION_IP_REMOTE_ADDRESS)
                && actual.conditionValue.r#type == FWP_UINT32
                && unsafe { actual.conditionValue.Anonymous.uint32 } == *address
        }
        ConditionExpectation::RemotePort(port) => {
            guid_eq(actual.fieldKey, FWPM_CONDITION_IP_REMOTE_PORT)
                && actual.conditionValue.r#type == FWP_UINT16
                && unsafe { actual.conditionValue.Anonymous.uint16 } == *port
        }
    }
}

#[allow(unsafe_code)]
fn user_condition_matches(actual: &FWPM_FILTER_CONDITION0, offline_sid: &str) -> bool {
    if !guid_eq(actual.fieldKey, FWPM_CONDITION_ALE_USER_ID)
        || actual.conditionValue.r#type != FWP_SECURITY_DESCRIPTOR_TYPE
    {
        return false;
    }
    let Some(blob) = (unsafe { actual.conditionValue.Anonymous.sd.as_ref() }) else {
        return false;
    };
    if blob.size == 0 || blob.data.is_null() {
        return false;
    }
    let descriptor = blob.data.cast::<c_void>();
    if unsafe { IsValidSecurityDescriptor(descriptor) } == 0 {
        return false;
    }
    let descriptor_length = unsafe { GetSecurityDescriptorLength(descriptor) } as usize;
    if descriptor_length == 0 || descriptor_length > blob.size as usize {
        return false;
    }
    let Some(expected_sid) = LocalSid::parse(offline_sid) else {
        return false;
    };
    let mut dacl_present = 0;
    let mut dacl = std::ptr::null_mut();
    let mut dacl_defaulted = 0;
    if unsafe {
        GetSecurityDescriptorDacl(
            descriptor,
            &mut dacl_present,
            &mut dacl,
            &mut dacl_defaulted,
        )
    } == 0
        || dacl_present == 0
        || dacl.is_null()
    {
        return false;
    }
    let Some(bounds) = acl_bounds(dacl) else {
        return false;
    };
    if unsafe { (*dacl).AceCount } != 1 {
        return false;
    }
    let mut raw_ace = std::ptr::null_mut();
    if unsafe { GetAce(dacl, 0, &mut raw_ace) } == 0 || raw_ace.is_null() {
        return false;
    }
    let Some(ace_size) = ace_size(raw_ace, bounds) else {
        return false;
    };
    if ace_size < size_of::<ACCESS_ALLOWED_ACE>() || !sid_fits_ace(raw_ace, ace_size) {
        return false;
    }
    let ace = raw_ace.cast::<ACCESS_ALLOWED_ACE>();
    if unsafe { (*ace).Header.AceType } != ACCESS_ALLOWED_ACE_TYPE as u8
        || unsafe { (*ace).Header.AceFlags } != 0
        || unsafe { (*ace).Mask } != FWP_ACTRL_MATCH_FILTER
    {
        return false;
    }
    let actual_sid = unsafe { (&raw mut (*ace).SidStart).cast::<c_void>() };
    unsafe { IsValidSid(actual_sid) != 0 && EqualSid(actual_sid, expected_sid.0) != 0 }
}

#[allow(unsafe_code)]
fn acl_bounds(dacl: *mut ACL) -> Option<AclBounds> {
    let mut information = ACL_SIZE_INFORMATION::default();
    if unsafe {
        GetAclInformation(
            dacl,
            (&raw mut information).cast(),
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
        || information.AclBytesInUse < size_of::<ACL>() as u32
    {
        return None;
    }
    let start = dacl as usize;
    let end = start.checked_add(information.AclBytesInUse as usize)?;
    Some(AclBounds { start, end })
}

#[allow(unsafe_code)]
fn ace_size(raw: *mut c_void, bounds: AclBounds) -> Option<usize> {
    let start = raw as usize;
    let header_end = start.checked_add(size_of::<ACE_HEADER>())?;
    if !start.is_multiple_of(align_of::<ACE_HEADER>())
        || start < bounds.start
        || header_end > bounds.end
    {
        return None;
    }
    let header = unsafe { &*raw.cast::<ACE_HEADER>() };
    let size = usize::from(header.AceSize);
    let end = start.checked_add(size)?;
    if !start.is_multiple_of(align_of::<ACCESS_ALLOWED_ACE>()) || end > bounds.end {
        return None;
    }
    Some(size)
}

#[allow(unsafe_code)]
fn sid_fits_ace(raw_ace: *mut c_void, ace_size: usize) -> bool {
    let sid_offset = offset_of!(ACCESS_ALLOWED_ACE, SidStart);
    let Some(sid_header_end) = sid_offset.checked_add(SID_HEADER_BYTES) else {
        return false;
    };
    if sid_header_end > ace_size {
        return false;
    }
    let bytes = unsafe { std::slice::from_raw_parts(raw_ace.cast::<u8>(), ace_size) };
    let count = usize::from(bytes[sid_offset + 1]);
    let Some(subauthority_bytes) = count.checked_mul(size_of::<u32>()) else {
        return false;
    };
    let Some(length) = SID_HEADER_BYTES.checked_add(subauthority_bytes) else {
        return false;
    };
    sid_offset
        .checked_add(length)
        .is_some_and(|end| end <= bytes.len())
}

fn filter_expectations(owner_sid: &str, proxy_ports: &[u16]) -> Vec<FilterExpectation> {
    let mut filters = WFP_BASE_FILTERS
        .iter()
        .map(|spec| FilterExpectation {
            key: derived_guid(owner_sid, spec.label),
            name: format!("cageforge_{}_{}", spec.label, owner_key(owner_sid)),
            layer_key: spec.layer.key(),
            action: FWP_ACTION_BLOCK,
            weight: 1,
            conditions: vec![
                ConditionExpectation::User,
                match spec.condition {
                    WfpBaseCondition::Protocol(protocol) => {
                        ConditionExpectation::Protocol(protocol)
                    }
                    WfpBaseCondition::RemotePort(port) => ConditionExpectation::RemotePort(port),
                },
            ],
        })
        .collect::<Vec<_>>();
    for port in proxy_ports {
        let label = format!("proxy-v4-{port}");
        filters.push(FilterExpectation {
            key: derived_guid(owner_sid, &label),
            name: format!("cageforge_{label}_{}", owner_key(owner_sid)),
            layer_key: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            action: FWP_ACTION_PERMIT,
            weight: 2,
            conditions: vec![
                ConditionExpectation::User,
                ConditionExpectation::Protocol(IPPROTO_TCP as u8),
                ConditionExpectation::RemoteAddressV4(IPV4_LOOPBACK_HOST_ORDER),
                ConditionExpectation::RemotePort(*port),
            ],
        });
    }
    for (family, layer_key) in [
        ("v4", FWPM_LAYER_ALE_AUTH_CONNECT_V4),
        ("v6", FWPM_LAYER_ALE_AUTH_CONNECT_V6),
    ] {
        let label = format!("default-deny-{family}");
        filters.push(FilterExpectation {
            key: derived_guid(owner_sid, &label),
            name: format!("cageforge_{label}_{}", owner_key(owner_sid)),
            layer_key,
            action: FWP_ACTION_BLOCK,
            weight: 1,
            conditions: vec![ConditionExpectation::User],
        });
    }
    filters
}

fn derived_guid(owner_sid: &str, label: &str) -> GUID {
    let digest = Sha256::digest(format!("cageforge/windows/wfp/{owner_sid}/{label}").as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    GUID::from_u128(u128::from_be_bytes(bytes))
}

fn owner_key(owner_sid: &str) -> String {
    let digest = Sha256::digest(owner_sid.to_ascii_uppercase().as_bytes());
    digest[..6]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn guid_eq(left: GUID, right: GUID) -> bool {
    left.data1 == right.data1
        && left.data2 == right.data2
        && left.data3 == right.data3
        && left.data4 == right.data4
}

fn guid_string(value: GUID) -> String {
    format!(
        "{{{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}}}",
        value.data1,
        value.data2,
        value.data3,
        value.data4[0],
        value.data4[1],
        value.data4[2],
        value.data4[3],
        value.data4[4],
        value.data4[5],
        value.data4[6],
        value.data4[7]
    )
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
        FWP_ACTION_BLOCK, FWP_ACTION_PERMIT,
    };
    use windows_sys::Win32::Networking::WinSock::IPPROTO_TCP;

    use super::{
        ConditionExpectation, IPV4_LOOPBACK_HOST_ORDER, filter_expectations, sid_fits_ace,
    };

    #[test]
    fn malformed_wfp_user_ace_sid_is_rejected_before_native_validation() {
        let mut ace = [0u8; 20];
        ace[1] = 3;
        assert!(!sid_fits_ace(ace.as_mut_ptr().cast(), ace.len()));
    }

    #[test]
    fn expectations_cover_the_complete_offline_wfp_boundary() {
        let specs = filter_expectations("S-1-5-21-1-2-3-1001", &[40_000, 40_002]);

        assert_eq!(specs.len(), 16);
        assert_eq!(
            specs
                .iter()
                .filter(|spec| spec.action == FWP_ACTION_BLOCK)
                .count(),
            14
        );
        assert_eq!(
            specs
                .iter()
                .filter(|spec| spec.action == FWP_ACTION_PERMIT)
                .count(),
            2
        );
        assert!(
            specs
                .iter()
                .filter(|spec| spec.action == FWP_ACTION_BLOCK)
                .all(|spec| spec.weight == 1)
        );
        assert!(
            specs
                .iter()
                .filter(|spec| spec.action == FWP_ACTION_PERMIT)
                .all(|spec| {
                    spec.weight == 2
                        && matches!(
                            spec.conditions.as_slice(),
                            [
                                ConditionExpectation::User,
                                ConditionExpectation::Protocol(protocol),
                                ConditionExpectation::RemoteAddressV4(address),
                                ConditionExpectation::RemotePort(_),
                            ] if *protocol == IPPROTO_TCP as u8
                                && *address == IPV4_LOOPBACK_HOST_ORDER
                        )
                })
        );
        assert!(
            specs
                .iter()
                .any(|spec| spec.name.contains("default-deny-v4"))
        );
        assert!(
            specs
                .iter()
                .any(|spec| spec.name.contains("default-deny-v6"))
        );
    }
}
