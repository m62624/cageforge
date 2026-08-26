// SPDX-License-Identifier: Apache-2.0

use sha2::{Digest, Sha256};
use windows::Win32::Foundation::VARIANT_TRUE;
use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetFwPolicy2, INetFwRule, INetFwRule3, INetFwRules, NET_FW_ACTION_BLOCK,
    NET_FW_IP_PROTOCOL_ANY, NET_FW_IP_PROTOCOL_TCP, NET_FW_IP_PROTOCOL_UDP, NET_FW_MODIFY_STATE_OK,
    NET_FW_PROFILE2_ALL, NET_FW_RULE_DIR_OUT, NetFwPolicy2, NetFwRule,
};
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx,
    CoUninitialize,
};
use windows::core::{BSTR, Interface};

use crate::firewall_contract::{address_sets_match, local_user_scope_matches, port_sets_match};
use crate::setup_protocol::{SetupFailureCode, SetupRequest, SetupStage};

use super::{NativeSetupFailure, NativeSetupResult};

const LOOPBACK_ADDRESSES: &str = "127.0.0.0/8,::/127";
const NON_LOOPBACK_ADDRESSES: &str = "0.0.0.0-126.255.255.255,128.0.0.0-255.255.255.255,::,::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff";

struct RuleSpec {
    name: String,
    description: String,
    protocol: i32,
    remote_addresses: &'static str,
    remote_ports: Option<String>,
    local_user_sddl: String,
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
pub(super) fn install_and_verify(
    request: &SetupRequest,
    offline_sid: &str,
) -> NativeSetupResult<String> {
    let apartment = initialize_com()?;
    let policy: INetFwPolicy2 =
        unsafe { CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER) }.map_err(
            |error| {
                firewall_error(
                    SetupFailureCode::FirewallPolicyAccess,
                    error.code().0 as u32,
                    format!("failed to open Windows Firewall policy: {error}"),
                )
            },
        )?;
    let modify_state = unsafe { policy.LocalPolicyModifyState() }.map_err(|error| {
        firewall_error(
            SetupFailureCode::FirewallPolicyAccess,
            error.code().0 as u32,
            format!("failed to query effective local firewall policy: {error}"),
        )
    })?;
    if modify_state != NET_FW_MODIFY_STATE_OK {
        return Err(firewall_error(
            SetupFailureCode::FirewallPolicyIneffective,
            modify_state.0 as u32,
            "local firewall rules are overridden or ineffective for an active profile",
        ));
    }
    let rules = unsafe { policy.Rules() }.map_err(|error| {
        firewall_error(
            SetupFailureCode::FirewallPolicyAccess,
            error.code().0 as u32,
            format!("failed to enumerate Windows Firewall rules: {error}"),
        )
    })?;

    let policy_id = firewall_policy_id(&request.owner_sid);
    let local_user_sddl = format!("O:LSD:(A;;CC;;;{offline_sid})");
    let blocked_ports = blocked_port_complement(&request.proxy_ports);
    let specs = [
        RuleSpec {
            name: format!("{policy_id}.non-loopback"),
            description: "Cageforge offline sandbox - block non-loopback outbound".to_string(),
            protocol: NET_FW_IP_PROTOCOL_ANY.0,
            remote_addresses: NON_LOOPBACK_ADDRESSES,
            remote_ports: None,
            local_user_sddl: local_user_sddl.clone(),
            offline_sid: offline_sid.to_string(),
        },
        RuleSpec {
            name: format!("{policy_id}.loopback-udp"),
            description: "Cageforge offline sandbox - block loopback UDP".to_string(),
            protocol: NET_FW_IP_PROTOCOL_UDP.0,
            remote_addresses: LOOPBACK_ADDRESSES,
            remote_ports: None,
            local_user_sddl: local_user_sddl.clone(),
            offline_sid: offline_sid.to_string(),
        },
        RuleSpec {
            name: format!("{policy_id}.loopback-tcp"),
            description: "Cageforge offline sandbox - block loopback TCP except ingress"
                .to_string(),
            protocol: NET_FW_IP_PROTOCOL_TCP.0,
            remote_addresses: LOOPBACK_ADDRESSES,
            remote_ports: Some(blocked_ports),
            local_user_sddl,
            offline_sid: offline_sid.to_string(),
        },
    ];
    for spec in &specs {
        ensure_rule(&rules, spec)?;
    }
    drop(apartment);
    Ok(policy_id)
}

#[allow(unsafe_code)]
pub(super) fn remove(owner_sid: &str) -> NativeSetupResult<()> {
    let apartment = initialize_com()?;
    let policy: INetFwPolicy2 =
        unsafe { CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER) }.map_err(
            |error| {
                firewall_error(
                    SetupFailureCode::Cleanup,
                    error.code().0 as u32,
                    format!("failed to open Windows Firewall for cleanup: {error}"),
                )
            },
        )?;
    let rules = unsafe { policy.Rules() }.map_err(|error| {
        firewall_error(
            SetupFailureCode::Cleanup,
            error.code().0 as u32,
            format!("failed to enumerate Windows Firewall rules for cleanup: {error}"),
        )
    })?;
    let policy_id = firewall_policy_id(owner_sid);
    for suffix in ["non-loopback", "loopback-udp", "loopback-tcp"] {
        let name = format!("{policy_id}.{suffix}");
        let name_bstr = BSTR::from(name.as_str());
        if unsafe { rules.Item(&name_bstr) }.is_ok() {
            unsafe { rules.Remove(&name_bstr) }.map_err(|error| {
                firewall_error(
                    SetupFailureCode::Cleanup,
                    error.code().0 as u32,
                    format!("failed to remove Windows Firewall rule {name:?}: {error}"),
                )
            })?;
        }
    }
    drop(apartment);
    Ok(())
}

#[allow(unsafe_code)]
fn initialize_com() -> NativeSetupResult<ComApartment> {
    unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) }
        .ok()
        .map_err(|error| {
            firewall_error(
                SetupFailureCode::FirewallComInitialization,
                error.code().0 as u32,
                format!("failed to initialize COM for Windows Firewall: {error}"),
            )
        })?;
    Ok(ComApartment)
}

#[allow(unsafe_code)]
fn ensure_rule(rules: &INetFwRules, spec: &RuleSpec) -> NativeSetupResult<()> {
    let name = BSTR::from(spec.name.as_str());
    let rule = match unsafe { rules.Item(&name) } {
        Ok(rule) => rule.cast::<INetFwRule3>().map_err(|error| {
            firewall_error(
                SetupFailureCode::FirewallRuleCreate,
                error.code().0 as u32,
                format!(
                    "existing firewall rule {:?} does not support user scoping: {error}",
                    spec.name
                ),
            )
        })?,
        Err(_) => {
            let rule: INetFwRule3 =
                unsafe { CoCreateInstance(&NetFwRule, None, CLSCTX_INPROC_SERVER) }.map_err(
                    |error| {
                        firewall_error(
                            SetupFailureCode::FirewallRuleCreate,
                            error.code().0 as u32,
                            format!("failed to create firewall rule {:?}: {error}", spec.name),
                        )
                    },
                )?;
            configure_rule(&rule, spec)?;
            let base: INetFwRule = rule.cast().map_err(|error| {
                firewall_error(
                    SetupFailureCode::FirewallRuleCreate,
                    error.code().0 as u32,
                    format!("failed to convert firewall rule {:?}: {error}", spec.name),
                )
            })?;
            unsafe { rules.Add(&base) }.map_err(|error| {
                firewall_error(
                    SetupFailureCode::FirewallRuleCreate,
                    error.code().0 as u32,
                    format!("failed to install firewall rule {:?}: {error}", spec.name),
                )
            })?;
            rule
        }
    };
    configure_rule(&rule, spec)?;
    verify_rule(&rule, spec)
}

#[allow(unsafe_code)]
fn configure_rule(rule: &INetFwRule3, spec: &RuleSpec) -> NativeSetupResult<()> {
    let configure = || -> windows::core::Result<()> {
        unsafe {
            rule.SetName(&BSTR::from(spec.name.as_str()))?;
            rule.SetDescription(&BSTR::from(spec.description.as_str()))?;
            rule.SetDirection(NET_FW_RULE_DIR_OUT)?;
            rule.SetAction(NET_FW_ACTION_BLOCK)?;
            rule.SetEnabled(VARIANT_TRUE)?;
            rule.SetProfiles(NET_FW_PROFILE2_ALL.0)?;
            rule.SetProtocol(spec.protocol)?;
            rule.SetRemoteAddresses(&BSTR::from(spec.remote_addresses))?;
            if spec.protocol == NET_FW_IP_PROTOCOL_TCP.0
                || spec.protocol == NET_FW_IP_PROTOCOL_UDP.0
            {
                rule.SetRemotePorts(&BSTR::from(spec.remote_ports.as_deref().unwrap_or("*")))?;
            }
            rule.SetLocalUserAuthorizedList(&BSTR::from(spec.local_user_sddl.as_str()))?;
        }
        Ok(())
    };
    configure().map_err(|error| {
        firewall_error(
            SetupFailureCode::FirewallRuleConfigure,
            error.code().0 as u32,
            format!("failed to configure firewall rule {:?}: {error}", spec.name),
        )
    })
}

#[allow(unsafe_code)]
fn verify_rule(rule: &INetFwRule3, spec: &RuleSpec) -> NativeSetupResult<()> {
    let actual_name = unsafe { rule.Name() }
        .map(|value| value.to_string())
        .map_err(|error| read_back_failure(spec, "name", error))?;
    require_property(
        spec,
        "name",
        &spec.name,
        &actual_name,
        actual_name == spec.name,
    )?;

    let actual_description = unsafe { rule.Description() }
        .map(|value| value.to_string())
        .map_err(|error| read_back_failure(spec, "description", error))?;
    require_property(
        spec,
        "description",
        &spec.description,
        &actual_description,
        actual_description == spec.description,
    )?;

    let actual_direction =
        unsafe { rule.Direction() }.map_err(|error| read_back_failure(spec, "direction", error))?;
    require_property(
        spec,
        "direction",
        &NET_FW_RULE_DIR_OUT.0.to_string(),
        &actual_direction.0.to_string(),
        actual_direction == NET_FW_RULE_DIR_OUT,
    )?;

    let actual_action =
        unsafe { rule.Action() }.map_err(|error| read_back_failure(spec, "action", error))?;
    require_property(
        spec,
        "action",
        &NET_FW_ACTION_BLOCK.0.to_string(),
        &actual_action.0.to_string(),
        actual_action == NET_FW_ACTION_BLOCK,
    )?;

    let actual_enabled =
        unsafe { rule.Enabled() }.map_err(|error| read_back_failure(spec, "enabled", error))?;
    require_property(
        spec,
        "enabled",
        &VARIANT_TRUE.0.to_string(),
        &actual_enabled.0.to_string(),
        actual_enabled == VARIANT_TRUE,
    )?;

    let actual_profiles =
        unsafe { rule.Profiles() }.map_err(|error| read_back_failure(spec, "profiles", error))?;
    require_property(
        spec,
        "profiles",
        &NET_FW_PROFILE2_ALL.0.to_string(),
        &actual_profiles.to_string(),
        actual_profiles == NET_FW_PROFILE2_ALL.0,
    )?;

    let actual_protocol =
        unsafe { rule.Protocol() }.map_err(|error| read_back_failure(spec, "protocol", error))?;
    require_property(
        spec,
        "protocol",
        &spec.protocol.to_string(),
        &actual_protocol.to_string(),
        actual_protocol == spec.protocol,
    )?;

    let actual_addresses = unsafe { rule.RemoteAddresses() }
        .map(|value| value.to_string())
        .map_err(|error| read_back_failure(spec, "remote addresses", error))?;
    require_property(
        spec,
        "remote addresses",
        spec.remote_addresses,
        &actual_addresses,
        address_sets_match(&actual_addresses, spec.remote_addresses),
    )?;

    if spec.protocol == NET_FW_IP_PROTOCOL_TCP.0 || spec.protocol == NET_FW_IP_PROTOCOL_UDP.0 {
        let expected_ports = spec.remote_ports.as_deref().unwrap_or("*");
        let actual_ports = unsafe { rule.RemotePorts() }
            .map(|value| value.to_string())
            .map_err(|error| read_back_failure(spec, "remote ports", error))?;
        require_property(
            spec,
            "remote ports",
            expected_ports,
            &actual_ports,
            port_sets_match(&actual_ports, expected_ports),
        )?;
    }

    let actual_user = unsafe { rule.LocalUserAuthorizedList() }
        .map(|value| value.to_string())
        .map_err(|error| read_back_failure(spec, "local user authorization", error))?;
    require_property(
        spec,
        "local user authorization",
        &format!("one COM_RIGHTS_EXECUTE ACE for {}", spec.offline_sid),
        &actual_user,
        local_user_scope_matches(&actual_user, &spec.offline_sid),
    )?;
    Ok(())
}

fn read_back_failure(
    spec: &RuleSpec,
    property: &'static str,
    error: windows::core::Error,
) -> NativeSetupFailure {
    firewall_error(
        SetupFailureCode::FirewallRuleReadBack,
        error.code().0 as u32,
        format!(
            "failed to read firewall rule {:?} property {property:?}: {error}",
            spec.name
        ),
    )
}

fn require_property(
    spec: &RuleSpec,
    property: &'static str,
    expected: &str,
    actual: &str,
    matches: bool,
) -> NativeSetupResult<()> {
    if matches {
        Ok(())
    } else {
        Err(firewall_error(
            SetupFailureCode::FirewallRuleReadBack,
            0,
            format!(
                "firewall rule {:?} property {property:?} mismatch: expected {expected:?}, found {actual:?}",
                spec.name
            ),
        ))
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

fn firewall_policy_id(owner_sid: &str) -> String {
    let digest = Sha256::digest(owner_sid.to_ascii_uppercase().as_bytes());
    let key: String = digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("Cageforge.{key}")
}

fn firewall_error(
    code: SetupFailureCode,
    native_code: u32,
    detail: impl Into<String>,
) -> NativeSetupFailure {
    NativeSetupFailure::new(SetupStage::Firewall, code, Some(native_code), detail)
}

#[cfg(test)]
mod tests {
    use super::blocked_port_complement;

    #[test]
    fn proxy_ports_are_the_only_loopback_tcp_holes() {
        assert_eq!(
            blocked_port_complement(&[40000, 40002]),
            "1-39999,40001,40003-65535"
        );
    }
}
