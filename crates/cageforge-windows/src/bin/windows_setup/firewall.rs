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
            if let Some(remote_ports) = &spec.remote_ports {
                rule.SetRemotePorts(&BSTR::from(remote_ports.as_str()))?;
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
    let actual_name = unsafe { rule.Name() };
    let actual_direction = unsafe { rule.Direction() };
    let actual_action = unsafe { rule.Action() };
    let actual_enabled = unsafe { rule.Enabled() };
    let actual_profiles = unsafe { rule.Profiles() };
    let actual_protocol = unsafe { rule.Protocol() };
    let actual_addresses = unsafe { rule.RemoteAddresses() };
    let actual_ports = if spec.remote_ports.is_some() {
        Some(unsafe { rule.RemotePorts() })
    } else {
        None
    };
    let actual_user = unsafe { rule.LocalUserAuthorizedList() };
    let mismatch = actual_name.as_ref().map(BSTR::to_string).ok() != Some(spec.name.clone())
        || actual_direction.ok() != Some(NET_FW_RULE_DIR_OUT)
        || actual_action.ok() != Some(NET_FW_ACTION_BLOCK)
        || actual_enabled.ok() != Some(VARIANT_TRUE)
        || actual_profiles.ok() != Some(NET_FW_PROFILE2_ALL.0)
        || actual_protocol.ok() != Some(spec.protocol)
        || actual_addresses.as_ref().map(BSTR::to_string).ok()
            != Some(spec.remote_addresses.to_string())
        || actual_ports
            .as_ref()
            .map(|value| value.as_ref().map(BSTR::to_string).ok())
            != spec.remote_ports.as_ref().map(|value| Some(value.clone()))
        || !actual_user
            .as_ref()
            .map(BSTR::to_string)
            .is_ok_and(|value| value.contains(&spec.offline_sid));
    if mismatch {
        return Err(firewall_error(
            SetupFailureCode::FirewallRuleReadBack,
            0,
            format!(
                "firewall rule {:?} failed complete read-back verification",
                spec.name
            ),
        ));
    }
    Ok(())
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
