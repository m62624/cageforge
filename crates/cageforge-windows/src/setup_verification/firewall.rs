// SPDX-License-Identifier: Apache-2.0

use sha2::{Digest, Sha256};
use windows::Win32::Foundation::VARIANT_TRUE;
use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetFwPolicy2, INetFwRule3, NET_FW_ACTION_BLOCK, NET_FW_IP_PROTOCOL_ANY,
    NET_FW_IP_PROTOCOL_TCP, NET_FW_IP_PROTOCOL_UDP, NET_FW_MODIFY_STATE_OK, NET_FW_PROFILE_TYPE2,
    NET_FW_PROFILE2_ALL, NET_FW_RULE_DIR_OUT, NetFwPolicy2,
};
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx,
    CoUninitialize,
};
use windows::core::{BSTR, Interface};

use crate::error::WindowsSetupVerificationError;
use crate::firewall_contract::{
    active_firewall_profiles, address_sets_match, local_user_scope_matches, port_sets_match,
};
use crate::setup::WindowsSetupDetails;

const LOOPBACK_ADDRESSES: &str = "127.0.0.0/8,::/127";
const NON_LOOPBACK_ADDRESSES: &str = "0.0.0.0-126.255.255.255,128.0.0.0-255.255.255.255,::,::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff";

struct RuleExpectation {
    name: String,
    description: &'static str,
    protocol: i32,
    remote_addresses: &'static str,
    remote_ports: Option<String>,
    offline_sid: String,
}

struct ComApartment;

#[allow(unsafe_code)]
impl Drop for ComApartment {
    fn drop(&mut self) {
        unsafe {
            CoUninitialize();
        }
    }
}

#[allow(unsafe_code)]
pub(super) fn verify(details: &WindowsSetupDetails) -> Result<(), WindowsSetupVerificationError> {
    let expected_policy_id = policy_id(details.owner_sid());
    if details.firewall_policy_id() != expected_policy_id {
        return Err(
            WindowsSetupVerificationError::FirewallRulePropertyMismatch {
                name: details.firewall_policy_id().to_string(),
                property: "owner-scoped policy identifier",
                expected: expected_policy_id,
                actual: details.firewall_policy_id().to_string(),
            },
        );
    }
    let _apartment = initialize_com()?;
    let policy: INetFwPolicy2 =
        unsafe { CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER) }.map_err(
            |error| WindowsSetupVerificationError::FirewallPolicyRead {
                code: error.code().0,
            },
        )?;
    let state = unsafe { policy.LocalPolicyModifyState() }.map_err(|error| {
        WindowsSetupVerificationError::FirewallPolicyRead {
            code: error.code().0,
        }
    })?;
    if state != NET_FW_MODIFY_STATE_OK {
        return Err(WindowsSetupVerificationError::FirewallPolicyIneffective { state: state.0 });
    }
    verify_active_profiles_enabled(&policy)?;
    let rules = unsafe { policy.Rules() }.map_err(|error| {
        WindowsSetupVerificationError::FirewallPolicyRead {
            code: error.code().0,
        }
    })?;
    let offline_sid = details.accounts().offline_sid().to_string();
    let specs = [
        RuleExpectation {
            name: format!("{expected_policy_id}.non-loopback"),
            description: "Cageforge offline sandbox - block non-loopback outbound",
            protocol: NET_FW_IP_PROTOCOL_ANY.0,
            remote_addresses: NON_LOOPBACK_ADDRESSES,
            remote_ports: None,
            offline_sid: offline_sid.clone(),
        },
        RuleExpectation {
            name: format!("{expected_policy_id}.loopback-udp"),
            description: "Cageforge offline sandbox - block loopback UDP",
            protocol: NET_FW_IP_PROTOCOL_UDP.0,
            remote_addresses: LOOPBACK_ADDRESSES,
            remote_ports: None,
            offline_sid: offline_sid.clone(),
        },
        RuleExpectation {
            name: format!("{expected_policy_id}.loopback-tcp"),
            description: "Cageforge offline sandbox - block loopback TCP except ingress",
            protocol: NET_FW_IP_PROTOCOL_TCP.0,
            remote_addresses: LOOPBACK_ADDRESSES,
            remote_ports: Some(blocked_port_complement(details.proxy_ports())),
            offline_sid,
        },
    ];
    for spec in &specs {
        let rule = unsafe { rules.Item(&BSTR::from(spec.name.as_str())) }
            .map_err(|_| WindowsSetupVerificationError::FirewallRuleMissing {
                name: spec.name.clone(),
            })?
            .cast::<INetFwRule3>()
            .map_err(|_| rule_mismatch(spec, "COM interface", "INetFwRule3", "unsupported"))?;
        verify_rule(&rule, spec)?;
    }
    Ok(())
}

#[allow(unsafe_code)]
fn verify_active_profiles_enabled(
    policy: &INetFwPolicy2,
) -> Result<(), WindowsSetupVerificationError> {
    let mask = unsafe { policy.CurrentProfileTypes() }.map_err(|error| {
        WindowsSetupVerificationError::FirewallPolicyRead {
            code: error.code().0,
        }
    })?;
    let profiles = active_firewall_profiles(mask)
        .ok_or(WindowsSetupVerificationError::FirewallActiveProfilesInvalid { mask })?;
    for profile in profiles {
        let enabled = unsafe { policy.get_FirewallEnabled(NET_FW_PROFILE_TYPE2(profile)) }
            .map_err(|error| WindowsSetupVerificationError::FirewallPolicyRead {
                code: error.code().0,
            })?;
        if enabled != VARIANT_TRUE {
            return Err(WindowsSetupVerificationError::FirewallProfileDisabled { profile });
        }
    }
    Ok(())
}

#[allow(unsafe_code)]
fn initialize_com() -> Result<ComApartment, WindowsSetupVerificationError> {
    unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) }
        .ok()
        .map_err(
            |error| WindowsSetupVerificationError::FirewallComInitialization {
                code: error.code().0,
            },
        )?;
    Ok(ComApartment)
}

#[allow(unsafe_code)]
fn verify_rule(
    rule: &INetFwRule3,
    expected: &RuleExpectation,
) -> Result<(), WindowsSetupVerificationError> {
    let actual_name = unsafe { rule.Name() }
        .map(|value| value.to_string())
        .map_err(|error| property_read_failure(expected, "name", error.code().0))?;
    require_property(
        expected,
        "name",
        &expected.name,
        &actual_name,
        actual_name == expected.name,
    )?;

    let actual_description = unsafe { rule.Description() }
        .map(|value| value.to_string())
        .map_err(|error| property_read_failure(expected, "description", error.code().0))?;
    require_property(
        expected,
        "description",
        expected.description,
        &actual_description,
        actual_description == expected.description,
    )?;

    let actual_direction = unsafe { rule.Direction() }
        .map_err(|error| property_read_failure(expected, "direction", error.code().0))?;
    require_property(
        expected,
        "direction",
        &NET_FW_RULE_DIR_OUT.0.to_string(),
        &actual_direction.0.to_string(),
        actual_direction == NET_FW_RULE_DIR_OUT,
    )?;

    let actual_action = unsafe { rule.Action() }
        .map_err(|error| property_read_failure(expected, "action", error.code().0))?;
    require_property(
        expected,
        "action",
        &NET_FW_ACTION_BLOCK.0.to_string(),
        &actual_action.0.to_string(),
        actual_action == NET_FW_ACTION_BLOCK,
    )?;

    let actual_enabled = unsafe { rule.Enabled() }
        .map_err(|error| property_read_failure(expected, "enabled", error.code().0))?;
    require_property(
        expected,
        "enabled",
        &VARIANT_TRUE.0.to_string(),
        &actual_enabled.0.to_string(),
        actual_enabled == VARIANT_TRUE,
    )?;

    let actual_profiles = unsafe { rule.Profiles() }
        .map_err(|error| property_read_failure(expected, "profiles", error.code().0))?;
    require_property(
        expected,
        "profiles",
        &NET_FW_PROFILE2_ALL.0.to_string(),
        &actual_profiles.to_string(),
        actual_profiles == NET_FW_PROFILE2_ALL.0,
    )?;

    let actual_protocol = unsafe { rule.Protocol() }
        .map_err(|error| property_read_failure(expected, "protocol", error.code().0))?;
    require_property(
        expected,
        "protocol",
        &expected.protocol.to_string(),
        &actual_protocol.to_string(),
        actual_protocol == expected.protocol,
    )?;

    let actual_addresses = unsafe { rule.RemoteAddresses() }
        .map(|value| value.to_string())
        .map_err(|error| property_read_failure(expected, "remote addresses", error.code().0))?;
    require_property(
        expected,
        "remote addresses",
        expected.remote_addresses,
        &actual_addresses,
        address_sets_match(&actual_addresses, expected.remote_addresses),
    )?;

    if expected.protocol == NET_FW_IP_PROTOCOL_TCP.0
        || expected.protocol == NET_FW_IP_PROTOCOL_UDP.0
    {
        let expected_ports = expected.remote_ports.as_deref().unwrap_or("*");
        let actual_ports = unsafe { rule.RemotePorts() }
            .map(|value| value.to_string())
            .map_err(|error| property_read_failure(expected, "remote ports", error.code().0))?;
        require_property(
            expected,
            "remote ports",
            expected_ports,
            &actual_ports,
            port_sets_match(&actual_ports, expected_ports),
        )?;
    }

    let actual_user = unsafe { rule.LocalUserAuthorizedList() }
        .map(|value| value.to_string())
        .map_err(|error| {
            property_read_failure(expected, "local user authorization", error.code().0)
        })?;
    require_property(
        expected,
        "local user authorization",
        &format!("one COM_RIGHTS_EXECUTE ACE for {}", expected.offline_sid),
        &actual_user,
        local_user_scope_matches(&actual_user, &expected.offline_sid),
    )
}

fn property_read_failure(
    expected: &RuleExpectation,
    property: &'static str,
    code: i32,
) -> WindowsSetupVerificationError {
    rule_mismatch(
        expected,
        property,
        "readable COM property",
        &format!("HRESULT {code:#x}"),
    )
}

fn require_property(
    expected: &RuleExpectation,
    property: &'static str,
    expected_value: &str,
    actual: &str,
    matches: bool,
) -> Result<(), WindowsSetupVerificationError> {
    if matches {
        Ok(())
    } else {
        Err(rule_mismatch(expected, property, expected_value, actual))
    }
}

fn rule_mismatch(
    expected: &RuleExpectation,
    property: &'static str,
    expected_value: &str,
    actual: &str,
) -> WindowsSetupVerificationError {
    WindowsSetupVerificationError::FirewallRulePropertyMismatch {
        name: expected.name.clone(),
        property,
        expected: expected_value.to_string(),
        actual: actual.to_string(),
    }
}

fn blocked_port_complement(allowed_ports: &[u16]) -> String {
    let mut allowed = allowed_ports.to_vec();
    allowed.sort_unstable();
    allowed.dedup();
    let mut ranges = Vec::new();
    let mut start = 1u32;
    for port in allowed {
        let port = u32::from(port);
        if port > start {
            ranges.push(port_range(start, port - 1));
        }
        start = port + 1;
    }
    if start <= u32::from(u16::MAX) {
        ranges.push(port_range(start, u32::from(u16::MAX)));
    }
    ranges.join(",")
}

fn port_range(start: u32, end: u32) -> String {
    if start == end {
        start.to_string()
    } else {
        format!("{start}-{end}")
    }
}

fn policy_id(owner_sid: &str) -> String {
    let digest = Sha256::digest(owner_sid.to_ascii_uppercase().as_bytes());
    let key: String = digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("Cageforge.{key}")
}
