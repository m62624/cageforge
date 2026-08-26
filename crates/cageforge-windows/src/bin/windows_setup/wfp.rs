// SPDX-License-Identifier: Apache-2.0

use std::ffi::c_void;
use std::mem::zeroed;

use sha2::{Digest, Sha256};
use windows_sys::Win32::Foundation::{
    FWP_E_ALREADY_EXISTS, FWP_E_FILTER_NOT_FOUND, FWP_E_NOT_FOUND, HANDLE, HLOCAL, LocalFree,
};
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_ACTION_BLOCK, FWP_ACTRL_MATCH_FILTER, FWP_BYTE_BLOB, FWP_CONDITION_VALUE0,
    FWP_CONDITION_VALUE0_0, FWP_EMPTY, FWP_MATCH_EQUAL, FWP_SECURITY_DESCRIPTOR_TYPE, FWP_UINT8,
    FWP_UINT16, FWP_VALUE0, FWPM_ACTION0, FWPM_ACTION0_0, FWPM_CONDITION_ALE_USER_ID,
    FWPM_CONDITION_IP_PROTOCOL, FWPM_CONDITION_IP_REMOTE_PORT, FWPM_DISPLAY_DATA0,
    FWPM_FILTER_CONDITION0, FWPM_FILTER_FLAG_PERSISTENT, FWPM_FILTER0, FWPM_FILTER0_0,
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4, FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6,
    FWPM_PROVIDER_FLAG_PERSISTENT, FWPM_PROVIDER0, FWPM_SESSION0, FWPM_SUBLAYER_FLAG_PERSISTENT,
    FWPM_SUBLAYER0, FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterDeleteByKey0,
    FwpmFilterGetByKey0, FwpmFreeMemory0, FwpmProviderAdd0, FwpmProviderGetByKey0,
    FwpmSubLayerAdd0, FwpmSubLayerGetByKey0, FwpmTransactionAbort0, FwpmTransactionBegin0,
    FwpmTransactionCommit0,
};
use windows_sys::Win32::Networking::WinSock::{IPPROTO_ICMP, IPPROTO_ICMPV6};
use windows_sys::Win32::Security::Authorization::{
    BuildExplicitAccessWithNameW, BuildSecurityDescriptorW, ConvertStringSidToSidW,
    EXPLICIT_ACCESS_W, GRANT_ACCESS,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, EqualSid, GetAce, GetSecurityDescriptorDacl, IsValidSecurityDescriptor,
    IsValidSid, PSECURITY_DESCRIPTOR, PSID,
};
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_DEFAULT;
use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;
use windows_sys::Win32::System::Threading::INFINITE;
use windows_sys::core::GUID;

use crate::setup_protocol::{SetupFailureCode, SetupStage};

use super::{NativeSetupFailure, NativeSetupResult};

const PROVIDER_KEY: GUID = GUID::from_u128(0x6d27a6ef_979d_42bf_97e7_6c7a61c86281);
const SUBLAYER_KEY: GUID = GUID::from_u128(0x199a41a9_8e19_4830_8213_6db9db995224);

enum ConditionSpec {
    User,
    Protocol(u8),
    RemotePort(u16),
}

struct FilterSpec {
    key: GUID,
    name: String,
    description: String,
    layer_key: GUID,
    conditions: Vec<ConditionSpec>,
}

struct Engine {
    handle: HANDLE,
}

struct Transaction<'a> {
    engine: &'a Engine,
    committed: bool,
}

struct UserCondition {
    descriptor: PSECURITY_DESCRIPTOR,
    blob: FWP_BYTE_BLOB,
}

struct LocalSid(PSID);

struct WfpAllocation<T>(*mut T);

#[allow(unsafe_code)]
impl Drop for Engine {
    fn drop(&mut self) {
        unsafe {
            FwpmEngineClose0(self.handle);
        }
    }
}

#[allow(unsafe_code)]
impl Drop for Transaction<'_> {
    fn drop(&mut self) {
        if !self.committed {
            unsafe {
                FwpmTransactionAbort0(self.engine.handle);
            }
        }
    }
}

#[allow(unsafe_code)]
impl Drop for UserCondition {
    fn drop(&mut self) {
        if !self.descriptor.is_null() {
            unsafe {
                LocalFree(self.descriptor as HLOCAL);
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

pub(super) fn install_and_verify(
    owner_sid: &str,
    offline_account: &str,
    offline_sid: &str,
) -> NativeSetupResult<String> {
    let engine = Engine::open()?;
    let mut transaction = engine.begin_transaction()?;
    ensure_provider(&engine)?;
    ensure_sublayer(&engine)?;
    let user = UserCondition::new(offline_account)?;
    let specs = filter_specs(owner_sid);
    for spec in &specs {
        replace_filter(&engine, spec, &user)?;
    }
    transaction.commit()?;
    verify_provider(&engine)?;
    verify_sublayer(&engine)?;
    for spec in &specs {
        verify_filter(&engine, spec, offline_sid)?;
    }
    Ok(guid_string(PROVIDER_KEY))
}

#[allow(unsafe_code)]
pub(super) fn remove(owner_sid: &str) -> NativeSetupResult<()> {
    let engine = Engine::open()?;
    let mut transaction = engine.begin_transaction()?;
    for spec in filter_specs(owner_sid) {
        let status = unsafe { FwpmFilterDeleteByKey0(engine.handle, &spec.key) };
        wfp_status_or(
            status,
            &[FWP_E_FILTER_NOT_FOUND as u32, FWP_E_NOT_FOUND as u32],
            SetupFailureCode::Cleanup,
            format!("failed to remove WFP filter {:?}", spec.name),
        )?;
    }
    transaction.commit()
}

impl Engine {
    #[allow(unsafe_code)]
    fn open() -> NativeSetupResult<Self> {
        let session_name = wide("Cageforge Windows sandbox WFP setup");
        let mut session: FWPM_SESSION0 = unsafe { zeroed() };
        session.displayData = FWPM_DISPLAY_DATA0 {
            name: session_name.as_ptr().cast_mut(),
            description: std::ptr::null_mut(),
        };
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
        wfp_status(
            status,
            SetupFailureCode::WfpEngineOpen,
            "failed to open the Windows Filtering Platform engine",
        )?;
        Ok(Self { handle })
    }

    #[allow(unsafe_code)]
    fn begin_transaction(&self) -> NativeSetupResult<Transaction<'_>> {
        let status = unsafe { FwpmTransactionBegin0(self.handle, 0) };
        wfp_status(
            status,
            SetupFailureCode::WfpTransaction,
            "failed to begin the WFP setup transaction",
        )?;
        Ok(Transaction {
            engine: self,
            committed: false,
        })
    }
}

impl Transaction<'_> {
    #[allow(unsafe_code)]
    fn commit(&mut self) -> NativeSetupResult<()> {
        let status = unsafe { FwpmTransactionCommit0(self.engine.handle) };
        wfp_status(
            status,
            SetupFailureCode::WfpTransaction,
            "failed to commit the WFP setup transaction",
        )?;
        self.committed = true;
        Ok(())
    }
}

impl UserCondition {
    #[allow(unsafe_code)]
    fn new(account: &str) -> NativeSetupResult<Self> {
        let account_wide = wide(account);
        let mut access: EXPLICIT_ACCESS_W = unsafe { zeroed() };
        unsafe {
            BuildExplicitAccessWithNameW(
                &mut access,
                account_wide.as_ptr(),
                FWP_ACTRL_MATCH_FILTER,
                GRANT_ACCESS,
                0,
            );
        }
        let mut descriptor = std::ptr::null_mut();
        let mut descriptor_length = 0u32;
        let status = unsafe {
            BuildSecurityDescriptorW(
                std::ptr::null(),
                std::ptr::null(),
                1,
                &access,
                0,
                std::ptr::null(),
                std::ptr::null_mut(),
                &mut descriptor_length,
                &mut descriptor,
            )
        };
        wfp_status(
            status,
            SetupFailureCode::WfpFilter,
            format!("failed to build WFP user condition for {account:?}"),
        )?;
        Ok(Self {
            descriptor,
            blob: FWP_BYTE_BLOB {
                size: descriptor_length,
                data: descriptor.cast::<u8>(),
            },
        })
    }
}

#[allow(unsafe_code)]
fn ensure_provider(engine: &Engine) -> NativeSetupResult<()> {
    let name = wide("Cageforge Windows Sandbox WFP");
    let description = wide("Persistent provider for Cageforge offline identities");
    let provider = FWPM_PROVIDER0 {
        providerKey: PROVIDER_KEY,
        displayData: FWPM_DISPLAY_DATA0 {
            name: name.as_ptr().cast_mut(),
            description: description.as_ptr().cast_mut(),
        },
        flags: FWPM_PROVIDER_FLAG_PERSISTENT,
        providerData: empty_blob(),
        serviceName: std::ptr::null_mut(),
    };
    let status = unsafe { FwpmProviderAdd0(engine.handle, &provider, std::ptr::null_mut()) };
    wfp_status_or(
        status,
        &[FWP_E_ALREADY_EXISTS as u32],
        SetupFailureCode::WfpProvider,
        "failed to install the Cageforge WFP provider",
    )
}

#[allow(unsafe_code)]
fn ensure_sublayer(engine: &Engine) -> NativeSetupResult<()> {
    let name = wide("Cageforge Windows Sandbox WFP");
    let description = wide("Persistent Cageforge offline-account filters");
    let mut provider_key = PROVIDER_KEY;
    let sublayer = FWPM_SUBLAYER0 {
        subLayerKey: SUBLAYER_KEY,
        displayData: FWPM_DISPLAY_DATA0 {
            name: name.as_ptr().cast_mut(),
            description: description.as_ptr().cast_mut(),
        },
        flags: FWPM_SUBLAYER_FLAG_PERSISTENT,
        providerKey: &raw mut provider_key,
        providerData: empty_blob(),
        weight: 0x8000,
    };
    let status = unsafe { FwpmSubLayerAdd0(engine.handle, &sublayer, std::ptr::null_mut()) };
    wfp_status_or(
        status,
        &[FWP_E_ALREADY_EXISTS as u32],
        SetupFailureCode::WfpSublayer,
        "failed to install the Cageforge WFP sublayer",
    )
}

#[allow(unsafe_code)]
fn replace_filter(
    engine: &Engine,
    spec: &FilterSpec,
    user: &UserCondition,
) -> NativeSetupResult<()> {
    let deleted = unsafe { FwpmFilterDeleteByKey0(engine.handle, &spec.key) };
    wfp_status_or(
        deleted,
        &[FWP_E_FILTER_NOT_FOUND as u32, FWP_E_NOT_FOUND as u32],
        SetupFailureCode::WfpFilter,
        format!("failed to replace WFP filter {:?}", spec.name),
    )?;

    let name = wide(&spec.name);
    let description = wide(&spec.description);
    let mut conditions = build_conditions(&spec.conditions, user);
    let mut provider_key = PROVIDER_KEY;
    let filter = FWPM_FILTER0 {
        filterKey: spec.key,
        displayData: FWPM_DISPLAY_DATA0 {
            name: name.as_ptr().cast_mut(),
            description: description.as_ptr().cast_mut(),
        },
        flags: FWPM_FILTER_FLAG_PERSISTENT,
        providerKey: &raw mut provider_key,
        providerData: empty_blob(),
        layerKey: spec.layer_key,
        subLayerKey: SUBLAYER_KEY,
        weight: empty_value(),
        numFilterConditions: conditions.len() as u32,
        filterCondition: conditions.as_mut_ptr(),
        action: FWPM_ACTION0 {
            r#type: FWP_ACTION_BLOCK,
            Anonymous: FWPM_ACTION0_0 {
                filterType: GUID::from_u128(0),
            },
        },
        Anonymous: FWPM_FILTER0_0 { rawContext: 0 },
        reserved: std::ptr::null_mut(),
        filterId: 0,
        effectiveWeight: empty_value(),
    };
    let mut id = 0u64;
    let status = unsafe { FwpmFilterAdd0(engine.handle, &filter, std::ptr::null_mut(), &mut id) };
    wfp_status(
        status,
        SetupFailureCode::WfpFilter,
        format!("failed to install WFP filter {:?}", spec.name),
    )
}

#[allow(unsafe_code)]
fn verify_provider(engine: &Engine) -> NativeSetupResult<()> {
    let mut value = std::ptr::null_mut();
    let status = unsafe { FwpmProviderGetByKey0(engine.handle, &PROVIDER_KEY, &mut value) };
    wfp_status(
        status,
        SetupFailureCode::WfpReadBack,
        "failed to read back the Cageforge WFP provider",
    )?;
    let value = WfpAllocation(value);
    let provider = unsafe { value.0.as_ref() }.ok_or_else(|| wfp_null("provider"))?;
    if !guid_eq(provider.providerKey, PROVIDER_KEY)
        || provider.flags & FWPM_PROVIDER_FLAG_PERSISTENT == 0
    {
        return Err(wfp_mismatch("provider"));
    }
    Ok(())
}

#[allow(unsafe_code)]
fn verify_sublayer(engine: &Engine) -> NativeSetupResult<()> {
    let mut value = std::ptr::null_mut();
    let status = unsafe { FwpmSubLayerGetByKey0(engine.handle, &SUBLAYER_KEY, &mut value) };
    wfp_status(
        status,
        SetupFailureCode::WfpReadBack,
        "failed to read back the Cageforge WFP sublayer",
    )?;
    let value = WfpAllocation(value);
    let sublayer = unsafe { value.0.as_ref() }.ok_or_else(|| wfp_null("sublayer"))?;
    if !guid_eq(sublayer.subLayerKey, SUBLAYER_KEY)
        || sublayer.flags & FWPM_SUBLAYER_FLAG_PERSISTENT == 0
        || sublayer.providerKey.is_null()
        || !guid_eq(unsafe { *sublayer.providerKey }, PROVIDER_KEY)
    {
        return Err(wfp_mismatch("sublayer"));
    }
    Ok(())
}

#[allow(unsafe_code)]
fn verify_filter(engine: &Engine, spec: &FilterSpec, offline_sid: &str) -> NativeSetupResult<()> {
    let mut value = std::ptr::null_mut();
    let status = unsafe { FwpmFilterGetByKey0(engine.handle, &spec.key, &mut value) };
    wfp_status(
        status,
        SetupFailureCode::WfpReadBack,
        format!("failed to read back WFP filter {:?}", spec.name),
    )?;
    let value = WfpAllocation(value);
    let filter = unsafe { value.0.as_ref() }.ok_or_else(|| wfp_null("filter"))?;
    if !guid_eq(filter.filterKey, spec.key)
        || filter.flags & FWPM_FILTER_FLAG_PERSISTENT == 0
        || !guid_eq(filter.layerKey, spec.layer_key)
        || !guid_eq(filter.subLayerKey, SUBLAYER_KEY)
        || filter.providerKey.is_null()
        || !guid_eq(unsafe { *filter.providerKey }, PROVIDER_KEY)
        || filter.action.r#type != FWP_ACTION_BLOCK
        || filter.numFilterConditions != spec.conditions.len() as u32
        || filter.filterCondition.is_null()
    {
        return Err(wfp_mismatch(&format!("filter {:?}", spec.name)));
    }
    let conditions = unsafe {
        std::slice::from_raw_parts(filter.filterCondition, filter.numFilterConditions as usize)
    };
    for (actual, expected) in conditions.iter().zip(&spec.conditions) {
        if !condition_matches(actual, expected, offline_sid) {
            return Err(wfp_mismatch(&format!(
                "filter condition in {:?}",
                spec.name
            )));
        }
    }
    Ok(())
}

fn build_conditions(specs: &[ConditionSpec], user: &UserCondition) -> Vec<FWPM_FILTER_CONDITION0> {
    specs
        .iter()
        .map(|spec| match spec {
            ConditionSpec::User => FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_ALE_USER_ID,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_SECURITY_DESCRIPTOR_TYPE,
                    Anonymous: FWP_CONDITION_VALUE0_0 {
                        sd: (&raw const user.blob).cast_mut(),
                    },
                },
            },
            ConditionSpec::Protocol(protocol) => FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_PROTOCOL,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT8,
                    Anonymous: FWP_CONDITION_VALUE0_0 { uint8: *protocol },
                },
            },
            ConditionSpec::RemotePort(port) => FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_REMOTE_PORT,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT16,
                    Anonymous: FWP_CONDITION_VALUE0_0 { uint16: *port },
                },
            },
        })
        .collect()
}

#[allow(unsafe_code)]
fn condition_matches(
    actual: &FWPM_FILTER_CONDITION0,
    expected: &ConditionSpec,
    offline_sid: &str,
) -> bool {
    if actual.matchType != FWP_MATCH_EQUAL {
        return false;
    }
    match expected {
        ConditionSpec::User => user_condition_matches(actual, offline_sid),
        ConditionSpec::Protocol(protocol) => {
            guid_eq(actual.fieldKey, FWPM_CONDITION_IP_PROTOCOL)
                && actual.conditionValue.r#type == FWP_UINT8
                && unsafe { actual.conditionValue.Anonymous.uint8 } == *protocol
        }
        ConditionSpec::RemotePort(port) => {
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

fn filter_specs(owner_sid: &str) -> Vec<FilterSpec> {
    let specs: [(&str, &str, GUID, Vec<ConditionSpec>); 12] = [
        (
            "icmp-connect-v4",
            "Block ICMP connect v4",
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            vec![
                ConditionSpec::User,
                ConditionSpec::Protocol(IPPROTO_ICMP as u8),
            ],
        ),
        (
            "icmp-connect-v6",
            "Block ICMP connect v6",
            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            vec![
                ConditionSpec::User,
                ConditionSpec::Protocol(IPPROTO_ICMPV6 as u8),
            ],
        ),
        (
            "icmp-assign-v4",
            "Block ICMP resource assignment v4",
            FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4,
            vec![
                ConditionSpec::User,
                ConditionSpec::Protocol(IPPROTO_ICMP as u8),
            ],
        ),
        (
            "icmp-assign-v6",
            "Block ICMP resource assignment v6",
            FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6,
            vec![
                ConditionSpec::User,
                ConditionSpec::Protocol(IPPROTO_ICMPV6 as u8),
            ],
        ),
        (
            "dns-53-v4",
            "Block DNS port 53 v4",
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            vec![ConditionSpec::User, ConditionSpec::RemotePort(53)],
        ),
        (
            "dns-53-v6",
            "Block DNS port 53 v6",
            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            vec![ConditionSpec::User, ConditionSpec::RemotePort(53)],
        ),
        (
            "dns-853-v4",
            "Block DNS over TLS v4",
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            vec![ConditionSpec::User, ConditionSpec::RemotePort(853)],
        ),
        (
            "dns-853-v6",
            "Block DNS over TLS v6",
            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            vec![ConditionSpec::User, ConditionSpec::RemotePort(853)],
        ),
        (
            "smb-445-v4",
            "Block SMB port 445 v4",
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            vec![ConditionSpec::User, ConditionSpec::RemotePort(445)],
        ),
        (
            "smb-445-v6",
            "Block SMB port 445 v6",
            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            vec![ConditionSpec::User, ConditionSpec::RemotePort(445)],
        ),
        (
            "smb-139-v4",
            "Block NetBIOS SMB port 139 v4",
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            vec![ConditionSpec::User, ConditionSpec::RemotePort(139)],
        ),
        (
            "smb-139-v6",
            "Block NetBIOS SMB port 139 v6",
            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            vec![ConditionSpec::User, ConditionSpec::RemotePort(139)],
        ),
    ];
    specs
        .into_iter()
        .map(|(label, description, layer_key, conditions)| FilterSpec {
            key: derived_guid(owner_sid, label),
            name: format!("cageforge_{label}_{}", owner_key(owner_sid)),
            description: format!("Cageforge offline identity - {description}"),
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

fn guid_eq(left: GUID, right: GUID) -> bool {
    left.data1 == right.data1
        && left.data2 == right.data2
        && left.data3 == right.data3
        && left.data4 == right.data4
}

fn wfp_status(
    status: u32,
    code: SetupFailureCode,
    detail: impl Into<String>,
) -> NativeSetupResult<()> {
    wfp_status_or(status, &[], code, detail)
}

fn wfp_status_or(
    status: u32,
    allowed: &[u32],
    code: SetupFailureCode,
    detail: impl Into<String>,
) -> NativeSetupResult<()> {
    if status == 0 || allowed.contains(&status) {
        Ok(())
    } else {
        Err(NativeSetupFailure::new(
            SetupStage::Wfp,
            code,
            Some(status),
            detail,
        ))
    }
}

fn wfp_null(component: &str) -> NativeSetupFailure {
    NativeSetupFailure::new(
        SetupStage::Wfp,
        SetupFailureCode::WfpReadBack,
        None,
        format!("WFP returned a null {component} during read-back"),
    )
}

fn wfp_mismatch(component: &str) -> NativeSetupFailure {
    NativeSetupFailure::new(
        SetupStage::Wfp,
        SetupFailureCode::WfpReadBack,
        None,
        format!("WFP {component} failed complete read-back verification"),
    )
}

fn empty_blob() -> FWP_BYTE_BLOB {
    FWP_BYTE_BLOB {
        size: 0,
        data: std::ptr::null_mut(),
    }
}

#[allow(unsafe_code)]
fn empty_value() -> FWP_VALUE0 {
    FWP_VALUE0 {
        r#type: FWP_EMPTY,
        Anonymous: unsafe { zeroed() },
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{filter_specs, guid_string};

    #[test]
    fn owner_scoped_filter_keys_and_names_are_unique() {
        let specs = filter_specs("S-1-5-21-1-2-3-1001");
        let keys = specs
            .iter()
            .map(|spec| guid_string(spec.key))
            .collect::<BTreeSet<_>>();
        let names = specs
            .iter()
            .map(|spec| spec.name.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(keys.len(), specs.len());
        assert_eq!(names.len(), specs.len());
    }
}
