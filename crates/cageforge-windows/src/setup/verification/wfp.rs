// SPDX-License-Identifier: Apache-2.0

use std::ffi::c_void;
use std::mem::zeroed;

use sha2::{Digest, Sha256};
use windows_sys::Win32::Foundation::{HANDLE, HLOCAL, LocalFree};
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_ACTION_BLOCK, FWP_ACTRL_MATCH_FILTER, FWP_MATCH_EQUAL, FWP_SECURITY_DESCRIPTOR_TYPE,
    FWP_UINT8, FWP_UINT16, FWPM_CONDITION_ALE_USER_ID, FWPM_CONDITION_IP_PROTOCOL,
    FWPM_CONDITION_IP_REMOTE_PORT, FWPM_FILTER_CONDITION0, FWPM_FILTER_FLAG_PERSISTENT,
    FWPM_FILTER0, FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4, FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6,
    FWPM_PROVIDER_FLAG_PERSISTENT, FWPM_SESSION0, FWPM_SUBLAYER_FLAG_PERSISTENT, FwpmEngineClose0,
    FwpmEngineOpen0, FwpmFilterGetByKey0, FwpmFreeMemory0, FwpmProviderGetByKey0,
    FwpmSubLayerGetByKey0,
};
use windows_sys::Win32::Networking::WinSock::{IPPROTO_ICMP, IPPROTO_ICMPV6};
use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, EqualSid, GetAce, GetSecurityDescriptorDacl, IsValidSecurityDescriptor,
    IsValidSid, PSID,
};
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_DEFAULT;
use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;
use windows_sys::Win32::System::Threading::INFINITE;
use windows_sys::core::GUID;

use crate::error::WindowsSetupVerificationError;
use crate::setup::WindowsSetupDetails;

const PROVIDER_KEY: GUID = GUID::from_u128(0x6d27a6ef_979d_42bf_97e7_6c7a61c86281);
const SUBLAYER_KEY: GUID = GUID::from_u128(0x199a41a9_8e19_4830_8213_6db9db995224);

struct FilterExpectation {
    key: GUID,
    name: String,
    layer_key: GUID,
    conditions: Vec<ConditionExpectation>,
}

enum ConditionExpectation {
    User,
    Protocol(u8),
    RemotePort(u16),
}

struct Engine(HANDLE);

struct LocalSid(PSID);

struct WfpAllocation<T>(*mut T);

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
    for filter in filter_expectations(details.owner_sid()) {
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
        && filter.action.r#type == FWP_ACTION_BLOCK
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
        || unsafe { (*ace).Mask } != FWP_ACTRL_MATCH_FILTER
    {
        return false;
    }
    let actual_sid = unsafe { (&raw mut (*ace).SidStart).cast::<c_void>() };
    unsafe { IsValidSid(actual_sid) != 0 && EqualSid(actual_sid, expected_sid.0) != 0 }
}

fn filter_expectations(owner_sid: &str) -> Vec<FilterExpectation> {
    let specs: [(&str, GUID, Vec<ConditionExpectation>); 12] = [
        (
            "icmp-connect-v4",
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            vec![
                ConditionExpectation::User,
                ConditionExpectation::Protocol(IPPROTO_ICMP as u8),
            ],
        ),
        (
            "icmp-connect-v6",
            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            vec![
                ConditionExpectation::User,
                ConditionExpectation::Protocol(IPPROTO_ICMPV6 as u8),
            ],
        ),
        (
            "icmp-assign-v4",
            FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4,
            vec![
                ConditionExpectation::User,
                ConditionExpectation::Protocol(IPPROTO_ICMP as u8),
            ],
        ),
        (
            "icmp-assign-v6",
            FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6,
            vec![
                ConditionExpectation::User,
                ConditionExpectation::Protocol(IPPROTO_ICMPV6 as u8),
            ],
        ),
        (
            "dns-53-v4",
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            vec![
                ConditionExpectation::User,
                ConditionExpectation::RemotePort(53),
            ],
        ),
        (
            "dns-53-v6",
            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            vec![
                ConditionExpectation::User,
                ConditionExpectation::RemotePort(53),
            ],
        ),
        (
            "dns-853-v4",
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            vec![
                ConditionExpectation::User,
                ConditionExpectation::RemotePort(853),
            ],
        ),
        (
            "dns-853-v6",
            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            vec![
                ConditionExpectation::User,
                ConditionExpectation::RemotePort(853),
            ],
        ),
        (
            "smb-445-v4",
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            vec![
                ConditionExpectation::User,
                ConditionExpectation::RemotePort(445),
            ],
        ),
        (
            "smb-445-v6",
            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            vec![
                ConditionExpectation::User,
                ConditionExpectation::RemotePort(445),
            ],
        ),
        (
            "smb-139-v4",
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            vec![
                ConditionExpectation::User,
                ConditionExpectation::RemotePort(139),
            ],
        ),
        (
            "smb-139-v6",
            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            vec![
                ConditionExpectation::User,
                ConditionExpectation::RemotePort(139),
            ],
        ),
    ];
    specs
        .into_iter()
        .map(|(label, layer_key, conditions)| FilterExpectation {
            key: derived_guid(owner_sid, label),
            name: format!("cageforge_{label}_{}", owner_key(owner_sid)),
            layer_key,
            conditions,
        })
        .collect()
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
