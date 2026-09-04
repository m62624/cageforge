// SPDX-License-Identifier: Apache-2.0

use std::ffi::c_void;
use std::mem::{align_of, offset_of, size_of, zeroed};

use sha2::{Digest, Sha256};
use windows_sys::Win32::Foundation::{
    FWP_E_ALREADY_EXISTS, FWP_E_FILTER_NOT_FOUND, FWP_E_NOT_FOUND, HANDLE, HLOCAL, LocalFree,
};
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_ACTRL_MATCH_FILTER, FWP_BYTE_BLOB,
    FWP_CONDITION_VALUE0, FWP_CONDITION_VALUE0_0, FWP_EMPTY, FWP_MATCH_EQUAL,
    FWP_SECURITY_DESCRIPTOR_TYPE, FWP_UINT8, FWP_UINT16, FWP_UINT32, FWP_VALUE0, FWP_VALUE0_0,
    FWPM_ACTION0, FWPM_ACTION0_0, FWPM_CONDITION_ALE_USER_ID, FWPM_CONDITION_IP_PROTOCOL,
    FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_CONDITION_IP_REMOTE_PORT, FWPM_DISPLAY_DATA0,
    FWPM_FILTER_CONDITION0, FWPM_FILTER_FLAG_PERSISTENT, FWPM_FILTER0, FWPM_FILTER0_0,
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_PROVIDER_FLAG_PERSISTENT,
    FWPM_PROVIDER0, FWPM_SESSION0, FWPM_SUBLAYER_FLAG_PERSISTENT, FWPM_SUBLAYER0, FwpmEngineClose0,
    FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterDeleteByKey0, FwpmFilterGetByKey0, FwpmFreeMemory0,
    FwpmProviderAdd0, FwpmProviderGetByKey0, FwpmSubLayerAdd0, FwpmSubLayerGetByKey0,
    FwpmTransactionAbort0, FwpmTransactionBegin0, FwpmTransactionCommit0,
};
use windows_sys::Win32::Networking::WinSock::IPPROTO_TCP;
use windows_sys::Win32::Security::Authorization::{
    BuildExplicitAccessWithNameW, BuildSecurityDescriptorW, ConvertStringSidToSidW,
    EXPLICIT_ACCESS_W, GRANT_ACCESS,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation, EqualSid,
    GetAce, GetAclInformation, GetSecurityDescriptorDacl, GetSecurityDescriptorLength,
    IsValidSecurityDescriptor, IsValidSid, PSECURITY_DESCRIPTOR, PSID,
};
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_DEFAULT;
use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;
use windows_sys::Win32::System::Threading::INFINITE;
use windows_sys::core::GUID;

use crate::firewall_contract::{
    WFP_BASE_FILTERS, WFP_IPV4_LOOPBACK_HOST_ORDER as IPV4_LOOPBACK_HOST_ORDER,
    WFP_PROVIDER_KEY as PROVIDER_KEY, WFP_SUBLAYER_KEY as SUBLAYER_KEY, WfpBaseCondition,
};
use crate::setup_protocol::{SetupFailureCode, SetupStage};

use super::{NativeSetupFailure, NativeSetupResult};

struct FilterSpec {
    key: GUID,
    name: String,
    description: String,
    layer_key: GUID,
    action: u32,
    weight: u8,
    conditions: Vec<ConditionSpec>,
}

enum ConditionSpec {
    User,
    Protocol(u8),
    RemoteAddressV4(u32),
    RemotePort(u16),
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
            FwpmEngineClose0(self.handle);
        }
    }
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
    proxy_ports: &[u16],
    progress: &mut dyn FnMut(SetupStage, &str),
) -> NativeSetupResult<String> {
    progress(SetupStage::Wfp, "opening WFP engine");
    let engine = Engine::open()?;
    progress(SetupStage::Wfp, "beginning WFP transaction");
    let mut transaction = engine.begin_transaction()?;
    progress(SetupStage::Wfp, "ensuring WFP provider");
    ensure_provider(&engine)?;
    progress(SetupStage::Wfp, "ensuring WFP sublayer");
    ensure_sublayer(&engine)?;
    progress(SetupStage::Wfp, "building WFP user condition");
    let user = UserCondition::new(offline_account)?;
    let specs = filter_specs(owner_sid, proxy_ports);
    for spec in &specs {
        progress(SetupStage::Wfp, &format!("installing filter {}", spec.name));
        replace_filter(&engine, spec, &user)?;
    }
    progress(SetupStage::Wfp, "committing WFP transaction");
    transaction.commit()?;
    progress(SetupStage::Wfp, "verifying WFP provider");
    verify_provider(&engine)?;
    progress(SetupStage::Wfp, "verifying WFP sublayer");
    verify_sublayer(&engine)?;
    for spec in &specs {
        progress(SetupStage::Wfp, &format!("verifying filter {}", spec.name));
        verify_filter(&engine, spec, offline_sid)?;
    }
    progress(SetupStage::Wfp, "completed WFP verification");
    Ok(guid_string(PROVIDER_KEY))
}

#[allow(unsafe_code)]
pub(super) fn remove(owner_sid: &str, proxy_ports: &[u16]) -> NativeSetupResult<()> {
    let engine = Engine::open()?;
    let mut transaction = engine.begin_transaction()?;
    for spec in filter_specs(owner_sid, proxy_ports) {
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
        weight: weight_value(spec.weight),
        numFilterConditions: conditions.len() as u32,
        filterCondition: conditions.as_mut_ptr(),
        action: FWPM_ACTION0 {
            r#type: spec.action,
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
        || filter.action.r#type != spec.action
        || filter.weight.r#type != FWP_UINT8
        || unsafe { filter.weight.Anonymous.uint8 } != spec.weight
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
    let mut filters = Vec::with_capacity(specs.len());
    for spec in specs {
        let filter = match spec {
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
            ConditionSpec::RemoteAddressV4(address) => FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT32,
                    Anonymous: FWP_CONDITION_VALUE0_0 { uint32: *address },
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
        };
        filters.push(filter);
    }
    filters
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
        ConditionSpec::RemoteAddressV4(address) => {
            guid_eq(actual.fieldKey, FWPM_CONDITION_IP_REMOTE_ADDRESS)
                && actual.conditionValue.r#type == FWP_UINT32
                && unsafe { actual.conditionValue.Anonymous.uint32 } == *address
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

fn filter_specs(owner_sid: &str, proxy_ports: &[u16]) -> Vec<FilterSpec> {
    let mut filters: Vec<_> = WFP_BASE_FILTERS
        .iter()
        .map(|spec| FilterSpec {
            key: derived_guid(owner_sid, spec.label),
            name: format!("cageforge_{}_{}", spec.label, owner_key(owner_sid)),
            description: format!(
                "Cageforge offline identity - {}",
                base_filter_description(spec.label)
            ),
            layer_key: spec.layer.key(),
            action: FWP_ACTION_BLOCK,
            weight: 1,
            conditions: vec![
                ConditionSpec::User,
                match spec.condition {
                    WfpBaseCondition::Protocol(protocol) => ConditionSpec::Protocol(protocol),
                    WfpBaseCondition::RemotePort(port) => ConditionSpec::RemotePort(port),
                },
            ],
        })
        .collect();
    for port in proxy_ports {
        let label = format!("proxy-v4-{port}");
        filters.push(FilterSpec {
            key: derived_guid(owner_sid, &label),
            name: format!("cageforge_{label}_{}", owner_key(owner_sid)),
            description: format!(
                "Cageforge offline identity - permit exact IPv4 loopback proxy port {port}"
            ),
            layer_key: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            action: FWP_ACTION_PERMIT,
            weight: 2,
            conditions: vec![
                ConditionSpec::User,
                ConditionSpec::Protocol(IPPROTO_TCP as u8),
                ConditionSpec::RemoteAddressV4(IPV4_LOOPBACK_HOST_ORDER),
                ConditionSpec::RemotePort(*port),
            ],
        });
    }
    for (family, layer_key) in [
        ("v4", FWPM_LAYER_ALE_AUTH_CONNECT_V4),
        ("v6", FWPM_LAYER_ALE_AUTH_CONNECT_V6),
    ] {
        let label = format!("default-deny-{family}");
        filters.push(FilterSpec {
            key: derived_guid(owner_sid, &label),
            name: format!("cageforge_{label}_{}", owner_key(owner_sid)),
            description: format!(
                "Cageforge offline identity - block all outbound {family} connects"
            ),
            layer_key,
            action: FWP_ACTION_BLOCK,
            weight: 1,
            conditions: vec![ConditionSpec::User],
        });
    }
    filters
}

fn base_filter_description(label: &str) -> &'static str {
    match label {
        "icmp-connect-v4" => "Block ICMP connect v4",
        "icmp-connect-v6" => "Block ICMP connect v6",
        "icmp-assign-v4" => "Block ICMP resource assignment v4",
        "icmp-assign-v6" => "Block ICMP resource assignment v6",
        "dns-53-v4" => "Block DNS port 53 v4",
        "dns-53-v6" => "Block DNS port 53 v6",
        "dns-853-v4" => "Block DNS over TLS v4",
        "dns-853-v6" => "Block DNS over TLS v6",
        "smb-445-v4" => "Block SMB port 445 v4",
        "smb-445-v6" => "Block SMB port 445 v6",
        "smb-139-v4" => "Block NetBIOS SMB port 139 v4",
        "smb-139-v6" => "Block NetBIOS SMB port 139 v6",
        _ => "Cageforge offline identity filter",
    }
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

fn weight_value(weight: u8) -> FWP_VALUE0 {
    FWP_VALUE0 {
        r#type: FWP_UINT8,
        Anonymous: FWP_VALUE0_0 { uint8: weight },
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
        FWP_ACTION_BLOCK, FWP_ACTION_PERMIT,
    };
    use windows_sys::Win32::Networking::WinSock::IPPROTO_TCP;

    use super::{ConditionSpec, IPV4_LOOPBACK_HOST_ORDER, filter_specs, guid_string, sid_fits_ace};

    #[test]
    fn malformed_wfp_user_ace_sid_is_rejected_before_native_validation() {
        let mut ace = [0u8; 20];
        ace[9] = 3;
        assert!(!sid_fits_ace(ace.as_mut_ptr().cast(), ace.len()));
    }

    #[test]
    fn owner_scoped_filter_keys_and_names_are_unique() {
        let specs = filter_specs("S-1-5-21-1-2-3-1001", &[40_000, 40_002]);
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

    #[test]
    fn offline_wfp_default_deny_permits_only_the_exact_loopback_ingress() {
        let specs = filter_specs("S-1-5-21-1-2-3-1001", &[40_000, 40_002]);
        let default_v4 = specs
            .iter()
            .find(|spec| spec.name.contains("default-deny-v4"))
            .expect("IPv4 default-deny filter");
        assert_eq!(default_v4.action, FWP_ACTION_BLOCK);
        assert_eq!(default_v4.weight, 1);
        assert!(matches!(
            default_v4.conditions.as_slice(),
            [ConditionSpec::User]
        ));

        let proxy_v4 = specs
            .iter()
            .find(|spec| spec.name.contains("proxy-v4-40000"))
            .expect("IPv4 loopback proxy permit");
        assert_eq!(proxy_v4.action, FWP_ACTION_PERMIT);
        assert_eq!(proxy_v4.weight, 2);
        assert!(matches!(
            proxy_v4.conditions.as_slice(),
            [
                ConditionSpec::User,
                ConditionSpec::Protocol(protocol),
                ConditionSpec::RemoteAddressV4(address),
                ConditionSpec::RemotePort(40_000),
            ] if *protocol == IPPROTO_TCP as u8
                && *address == IPV4_LOOPBACK_HOST_ORDER
        ));

        assert!(
            specs.iter().all(|spec| !spec.name.contains("proxy-v6-")),
            "IPv6 ingress is not attributable and must remain default-deny"
        );
    }
}
