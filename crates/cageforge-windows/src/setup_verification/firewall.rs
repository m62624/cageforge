// SPDX-License-Identifier: Apache-2.0

use sha2::{Digest, Sha256};
use windows::Win32::Foundation::VARIANT_TRUE;
use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetFwPolicy2, INetFwRule3, NET_FW_ACTION_BLOCK, NET_FW_IP_PROTOCOL_ANY,
    NET_FW_IP_PROTOCOL_TCP, NET_FW_IP_PROTOCOL_UDP, NET_FW_MODIFY_STATE_OK, NET_FW_PROFILE2_ALL,
    NET_FW_RULE_DIR_OUT, NetFwPolicy2,
};
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx,
    CoUninitialize,
};
use windows::core::{BSTR, Interface};

use crate::error::WindowsSetupVerificationError;
use crate::setup::WindowsSetupDetails;

const LOOPBACK_ADDRESSES: &str = "127.0.0.0/8,::/127";
const NON_LOOPBACK_ADDRESSES: &str = "0.0.0.0-126.255.255.255,128.0.0.0-255.255.255.255,::,::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff";

struct RuleExpectation {
    name: String,
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
        return Err(WindowsSetupVerificationError::FirewallRuleMismatch {
            name: details.firewall_policy_id().to_string(),
        });
    }
    let apartment = initialize_com()?;
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
    let rules = unsafe { policy.Rules() }.map_err(|error| {
        WindowsSetupVerificationError::FirewallPolicyRead {
            code: error.code().0,
        }
    })?;
    let offline_sid = details.accounts().offline_sid().to_string();
    let specs = [
        RuleExpectation {
            name: format!("{expected_policy_id}.non-loopback"),
            protocol: NET_FW_IP_PROTOCOL_ANY.0,
            remote_addresses: NON_LOOPBACK_ADDRESSES,
            remote_ports: None,
            offline_sid: offline_sid.clone(),
        },
        RuleExpectation {
            name: format!("{expected_policy_id}.loopback-udp"),
            protocol: NET_FW_IP_PROTOCOL_UDP.0,
            remote_addresses: LOOPBACK_ADDRESSES,
            remote_ports: None,
            offline_sid: offline_sid.clone(),
        },
        RuleExpectation {
            name: format!("{expected_policy_id}.loopback-tcp"),
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
            .map_err(|_| WindowsSetupVerificationError::FirewallRuleMismatch {
                name: spec.name.clone(),
            })?;
        verify_rule(&rule, spec)?;
    }
    drop(apartment);
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
    let matches = unsafe { rule.Name() }.is_ok_and(|value| value == expected.name.as_str())
        && unsafe { rule.Direction() }.ok() == Some(NET_FW_RULE_DIR_OUT)
        && unsafe { rule.Action() }.ok() == Some(NET_FW_ACTION_BLOCK)
        && unsafe { rule.Enabled() }.ok() == Some(VARIANT_TRUE)
        && unsafe { rule.Profiles() }.ok() == Some(NET_FW_PROFILE2_ALL.0)
        && unsafe { rule.Protocol() }.ok() == Some(expected.protocol)
        && unsafe { rule.RemoteAddresses() }.is_ok_and(|value| value == expected.remote_addresses)
        && match &expected.remote_ports {
            Some(ports) => unsafe { rule.RemotePorts() }.is_ok_and(|value| value == ports.as_str()),
            None => true,
        }
        && unsafe { rule.LocalUserAuthorizedList() }
            .is_ok_and(|value| value.to_string().contains(&expected.offline_sid));
    if matches {
        Ok(())
    } else {
        Err(WindowsSetupVerificationError::FirewallRuleMismatch {
            name: expected.name.clone(),
        })
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
