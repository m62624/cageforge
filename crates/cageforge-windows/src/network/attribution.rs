// SPDX-License-Identifier: Apache-2.0

//! Exact Windows IPv4 TCP owner and restricted-token attribution.

use std::ffi::c_void;
use std::mem::{offset_of, size_of};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};

use thiserror::Error;
use windows_sys::Win32::Foundation::{
    ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_DATA, FILETIME, GetLastError, NO_ERROR,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, MIB_TCPROW_OWNER_MODULE, MIB_TCPTABLE_OWNER_MODULE,
    TCP_TABLE_OWNER_MODULE_CONNECTIONS,
};
use windows_sys::Win32::Networking::WinSock::AF_INET;
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{
    GetTokenInformation, IsValidSid, SID_AND_ATTRIBUTES, TOKEN_GROUPS, TOKEN_QUERY,
    TokenRestrictedSids,
};
use windows_sys::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

use crate::native_strings::local_sid_string;

const MAX_TCP_TABLE_BYTES: usize = 64 * 1024 * 1024;
const MAX_TCP_TABLE_READ_ATTEMPTS: usize = 8;
const MAX_RESTRICTED_SID_BYTES: usize = 1024 * 1024;
const SID_HEADER_BYTES: usize = 8;

/// Failure while attributing one accepted Windows loopback TCP connection.
#[derive(Debug, Error)]
pub enum WindowsNetworkAttributionError {
    /// Only IPv4 listener and peer addresses are supported by this boundary.
    #[error("Windows proxy attribution accepts only IPv4 connections")]
    NonIpv4Connection,
    /// The accepted listener address was not IPv4 loopback.
    #[error("Windows proxy attribution received non-loopback listener address {address}")]
    NonLoopbackListener {
        /// Rejected accepted local address.
        address: SocketAddrV4,
    },
    /// The accepted client address was not IPv4 loopback.
    #[error("Windows proxy attribution received non-loopback peer address {address}")]
    NonLoopbackPeer {
        /// Rejected accepted peer address.
        address: SocketAddrV4,
    },
    /// The TCP owner-table size query failed.
    #[error("failed to query the Windows IPv4 TCP owner-table size: error {code}")]
    TcpTableSize {
        /// Native Win32 code.
        code: u32,
    },
    /// Windows requested an unsafe or nonsensical owner-table allocation.
    #[error("Windows IPv4 TCP owner-table size {actual} is outside 1..={maximum}")]
    TcpTableSizeInvalid {
        /// Returned byte count.
        actual: usize,
        /// Accepted allocation ceiling.
        maximum: usize,
    },
    /// Reading the TCP owner table failed.
    #[error("failed to read the Windows IPv4 TCP owner table: error {code}")]
    TcpTableRead {
        /// Native Win32 code.
        code: u32,
    },
    /// The owner table kept changing size and could not be captured within the bound.
    #[error("Windows IPv4 TCP owner table changed size during all {attempts} bounded reads")]
    TcpTableUnstable {
        /// Number of attempted table reads.
        attempts: usize,
    },
    /// The returned owner table was truncated or internally inconsistent.
    #[error("Windows returned a malformed IPv4 TCP owner table")]
    TcpTableMalformed,
    /// The accepted reversed four-tuple had no owner row.
    #[error("accepted Windows proxy connection is absent from the IPv4 TCP owner table")]
    ConnectionOwnerMissing,
    /// The accepted reversed four-tuple had multiple owner rows.
    #[error("accepted Windows proxy connection has multiple IPv4 TCP owner rows")]
    ConnectionOwnerDuplicate,
    /// The exact owner changed during process-handle acquisition.
    #[error("accepted Windows proxy connection owner changed during attribution")]
    ConnectionOwnerChanged,
    /// Reading the attributed process creation time failed.
    #[error("failed to read attributed Windows proxy client process times: error {code}")]
    ProcessTimes {
        /// Native Win32 code.
        code: u32,
    },
    /// The process object was created after the TCP context attributed to its reused PID.
    #[error("attributed Windows proxy client PID was reused after the TCP context was created")]
    ProcessIdentityMismatch,
    /// The attributed client process could not be opened.
    #[error("failed to open attributed Windows proxy client process {process_id}: error {code}")]
    ProcessOpen {
        /// Attributed process identifier.
        process_id: u32,
        /// Native Win32 code.
        code: u32,
    },
    /// The attributed process token could not be opened.
    #[error("failed to open attributed Windows proxy client token: error {code}")]
    TokenOpen {
        /// Native Win32 code.
        code: u32,
    },
    /// The size-only restricted-SID query unexpectedly succeeded.
    #[error(
        "Windows unexpectedly completed a size-only restricted-SID query with {byte_length} bytes"
    )]
    RestrictedSidSizeUnexpectedSuccess {
        /// Byte count returned by Windows.
        byte_length: u32,
    },
    /// Querying the restricted-SID buffer size failed.
    #[error("failed to query attributed client restricted-SID size: error {code}")]
    RestrictedSidSize {
        /// Native Win32 code.
        code: u32,
    },
    /// Windows requested an unsafe or nonsensical token allocation.
    #[error("Windows restricted-SID buffer size {actual} is outside 1..={maximum}")]
    RestrictedSidSizeInvalid {
        /// Returned byte count.
        actual: usize,
        /// Accepted allocation ceiling.
        maximum: usize,
    },
    /// Reading the attributed token restricted SIDs failed.
    #[error("failed to read attributed client restricted SIDs: error {code}")]
    RestrictedSidRead {
        /// Native Win32 code.
        code: u32,
    },
    /// The returned restricted-SID record was truncated or inconsistent.
    #[error("Windows returned a malformed restricted-SID token record")]
    RestrictedSidMalformed,
    /// A returned token SID was invalid.
    #[error("Windows returned an invalid restricted SID")]
    RestrictedSidInvalid,
    /// Formatting a restricted SID failed.
    #[error("failed to format an attributed client restricted SID: error {code}")]
    RestrictedSidFormat {
        /// Native Win32 code.
        code: u32,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ConnectionOwner {
    process_id: u32,
    connection_created: i64,
}

pub(crate) fn restricting_sids_for_tcp_connection(
    accepted_local: SocketAddr,
    accepted_peer: SocketAddr,
) -> Result<Vec<String>, WindowsNetworkAttributionError> {
    let (SocketAddr::V4(accepted_local), SocketAddr::V4(accepted_peer)) =
        (accepted_local, accepted_peer)
    else {
        return Err(WindowsNetworkAttributionError::NonIpv4Connection);
    };
    if !accepted_local.ip().is_loopback() {
        return Err(WindowsNetworkAttributionError::NonLoopbackListener {
            address: accepted_local,
        });
    }
    if !accepted_peer.ip().is_loopback() {
        return Err(WindowsNetworkAttributionError::NonLoopbackPeer {
            address: accepted_peer,
        });
    }
    let owner = owning_connection(accepted_local, accepted_peer)?;
    let process = open_process(owner.process_id)?;
    validate_process_identity(owner, process_creation_time(&process)?)?;
    if owning_connection(accepted_local, accepted_peer)? != owner {
        return Err(WindowsNetworkAttributionError::ConnectionOwnerChanged);
    }
    restricting_sids_for_process(&process)
}

fn owning_connection(
    accepted_local: SocketAddrV4,
    accepted_peer: SocketAddrV4,
) -> Result<ConnectionOwner, WindowsNetworkAttributionError> {
    let rows = tcp_owner_rows()?;
    unique_client_owner(&rows, accepted_local, accepted_peer)
}

#[allow(unsafe_code)]
fn tcp_owner_rows() -> Result<Vec<MIB_TCPROW_OWNER_MODULE>, WindowsNetworkAttributionError> {
    let mut byte_length = 0;
    let status = unsafe {
        GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut byte_length,
            0,
            AF_INET as u32,
            TCP_TABLE_OWNER_MODULE_CONNECTIONS,
            0,
        )
    };
    if status != ERROR_INSUFFICIENT_BUFFER {
        return Err(WindowsNetworkAttributionError::TcpTableSize { code: status });
    }
    for _ in 0..MAX_TCP_TABLE_READ_ATTEMPTS {
        let allocation =
            checked_allocation(byte_length, MAX_TCP_TABLE_BYTES).map_err(|actual| {
                WindowsNetworkAttributionError::TcpTableSizeInvalid {
                    actual,
                    maximum: MAX_TCP_TABLE_BYTES,
                }
            })?;
        let mut buffer = vec![0usize; allocation.div_ceil(size_of::<usize>())];
        let status = unsafe {
            GetExtendedTcpTable(
                buffer.as_mut_ptr().cast(),
                &mut byte_length,
                0,
                AF_INET as u32,
                TCP_TABLE_OWNER_MODULE_CONNECTIONS,
                0,
            )
        };
        match status {
            NO_ERROR => return parse_tcp_owner_rows(&buffer, byte_length as usize),
            ERROR_INSUFFICIENT_BUFFER => continue,
            code => return Err(WindowsNetworkAttributionError::TcpTableRead { code }),
        }
    }
    Err(WindowsNetworkAttributionError::TcpTableUnstable {
        attempts: MAX_TCP_TABLE_READ_ATTEMPTS,
    })
}

#[allow(unsafe_code)]
fn parse_tcp_owner_rows(
    buffer: &[usize],
    byte_length: usize,
) -> Result<Vec<MIB_TCPROW_OWNER_MODULE>, WindowsNetworkAttributionError> {
    let rows_offset = offset_of!(MIB_TCPTABLE_OWNER_MODULE, table);
    if byte_length > size_of_val(buffer) || byte_length < rows_offset {
        return Err(WindowsNetworkAttributionError::TcpTableMalformed);
    }
    let count = unsafe { buffer.as_ptr().cast::<u32>().read_unaligned() } as usize;
    let expected = count
        .checked_mul(size_of::<MIB_TCPROW_OWNER_MODULE>())
        .and_then(|rows| rows_offset.checked_add(rows))
        .ok_or(WindowsNetworkAttributionError::TcpTableMalformed)?;
    if expected > byte_length {
        return Err(WindowsNetworkAttributionError::TcpTableMalformed);
    }
    let rows = unsafe {
        std::slice::from_raw_parts(
            buffer
                .as_ptr()
                .cast::<u8>()
                .add(rows_offset)
                .cast::<MIB_TCPROW_OWNER_MODULE>(),
            count,
        )
    };
    Ok(rows.to_vec())
}

fn unique_client_owner(
    rows: &[MIB_TCPROW_OWNER_MODULE],
    accepted_local: SocketAddrV4,
    accepted_peer: SocketAddrV4,
) -> Result<ConnectionOwner, WindowsNetworkAttributionError> {
    let mut matches = rows
        .iter()
        .filter(|row| client_row_matches(row, accepted_local, accepted_peer))
        .map(|row| ConnectionOwner {
            process_id: row.dwOwningPid,
            connection_created: row.liCreateTimestamp,
        });
    let owner = matches
        .next()
        .ok_or(WindowsNetworkAttributionError::ConnectionOwnerMissing)?;
    if matches.next().is_some() {
        Err(WindowsNetworkAttributionError::ConnectionOwnerDuplicate)
    } else {
        Ok(owner)
    }
}

fn client_row_matches(
    row: &MIB_TCPROW_OWNER_MODULE,
    accepted_local: SocketAddrV4,
    accepted_peer: SocketAddrV4,
) -> bool {
    ipv4_matches(row.dwLocalAddr, *accepted_peer.ip())
        && tcp_port(row.dwLocalPort) == accepted_peer.port()
        && ipv4_matches(row.dwRemoteAddr, *accepted_local.ip())
        && tcp_port(row.dwRemotePort) == accepted_local.port()
}

fn ipv4_matches(table_address: u32, socket_address: Ipv4Addr) -> bool {
    table_address.to_ne_bytes() == socket_address.octets()
}

fn tcp_port(table_port: u32) -> u16 {
    u16::from_be(table_port as u16)
}

#[allow(unsafe_code)]
fn open_process(process_id: u32) -> Result<OwnedHandle, WindowsNetworkAttributionError> {
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if handle.is_null() {
        Err(WindowsNetworkAttributionError::ProcessOpen {
            process_id,
            code: unsafe { GetLastError() },
        })
    } else {
        Ok(unsafe { OwnedHandle::from_raw_handle(handle as RawHandle) })
    }
}

#[allow(unsafe_code)]
fn process_creation_time(process: &OwnedHandle) -> Result<u64, WindowsNetworkAttributionError> {
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    if unsafe {
        GetProcessTimes(
            process.as_raw_handle() as _,
            &mut creation,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    } == 0
    {
        return Err(WindowsNetworkAttributionError::ProcessTimes {
            code: unsafe { GetLastError() },
        });
    }
    Ok(u64::from(creation.dwLowDateTime) | (u64::from(creation.dwHighDateTime) << 32))
}

fn validate_process_identity(
    owner: ConnectionOwner,
    process_created: u64,
) -> Result<(), WindowsNetworkAttributionError> {
    let connection_created = u64::try_from(owner.connection_created)
        .map_err(|_| WindowsNetworkAttributionError::ProcessIdentityMismatch)?;
    if process_created > connection_created {
        Err(WindowsNetworkAttributionError::ProcessIdentityMismatch)
    } else {
        Ok(())
    }
}

#[allow(unsafe_code)]
fn restricting_sids_for_process(
    process: &OwnedHandle,
) -> Result<Vec<String>, WindowsNetworkAttributionError> {
    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(process.as_raw_handle() as _, TOKEN_QUERY, &mut token) } == 0 {
        return Err(WindowsNetworkAttributionError::TokenOpen {
            code: unsafe { GetLastError() },
        });
    }
    let token = unsafe { OwnedHandle::from_raw_handle(token as RawHandle) };
    let mut byte_length = 0;
    let queried = unsafe {
        GetTokenInformation(
            token.as_raw_handle() as _,
            TokenRestrictedSids,
            std::ptr::null_mut(),
            0,
            &mut byte_length,
        )
    };
    if queried != 0 {
        return Err(
            WindowsNetworkAttributionError::RestrictedSidSizeUnexpectedSuccess { byte_length },
        );
    }
    let size_error = unsafe { GetLastError() };
    if size_error != ERROR_INSUFFICIENT_BUFFER {
        return Err(WindowsNetworkAttributionError::RestrictedSidSize { code: size_error });
    }
    let allocation =
        checked_allocation(byte_length, MAX_RESTRICTED_SID_BYTES).map_err(|actual| {
            WindowsNetworkAttributionError::RestrictedSidSizeInvalid {
                actual,
                maximum: MAX_RESTRICTED_SID_BYTES,
            }
        })?;
    let mut buffer = vec![0usize; allocation.div_ceil(size_of::<usize>())];
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle() as _,
            TokenRestrictedSids,
            buffer.as_mut_ptr().cast(),
            byte_length,
            &mut byte_length,
        )
    } == 0
    {
        return Err(WindowsNetworkAttributionError::RestrictedSidRead {
            code: unsafe { GetLastError() },
        });
    }
    parse_restricted_sids(&buffer, byte_length as usize)?
        .iter()
        .map(|entry| sid_string(entry.Sid, &buffer, byte_length as usize))
        .collect()
}

#[allow(unsafe_code)]
fn parse_restricted_sids(
    buffer: &[usize],
    byte_length: usize,
) -> Result<&[SID_AND_ATTRIBUTES], WindowsNetworkAttributionError> {
    let groups_offset = offset_of!(TOKEN_GROUPS, Groups);
    if byte_length > size_of_val(buffer) || byte_length < groups_offset {
        return Err(WindowsNetworkAttributionError::RestrictedSidMalformed);
    }
    let count = unsafe { buffer.as_ptr().cast::<u32>().read_unaligned() } as usize;
    let expected = count
        .checked_mul(size_of::<SID_AND_ATTRIBUTES>())
        .and_then(|groups| groups_offset.checked_add(groups))
        .ok_or(WindowsNetworkAttributionError::RestrictedSidMalformed)?;
    if expected > byte_length {
        return Err(WindowsNetworkAttributionError::RestrictedSidMalformed);
    }
    Ok(unsafe {
        std::slice::from_raw_parts(
            buffer
                .as_ptr()
                .cast::<u8>()
                .add(groups_offset)
                .cast::<SID_AND_ATTRIBUTES>(),
            count,
        )
    })
}

#[allow(unsafe_code)]
fn sid_string(
    sid: *mut c_void,
    buffer: &[usize],
    byte_length: usize,
) -> Result<String, WindowsNetworkAttributionError> {
    if sid.is_null() {
        return Err(WindowsNetworkAttributionError::RestrictedSidInvalid);
    }
    let buffer_start = buffer.as_ptr() as usize;
    let buffer_end = buffer_start
        .checked_add(byte_length)
        .ok_or(WindowsNetworkAttributionError::RestrictedSidMalformed)?;
    let sid_start = sid as usize;
    let sid_offset = sid_start
        .checked_sub(buffer_start)
        .filter(|offset| *offset < byte_length)
        .ok_or(WindowsNetworkAttributionError::RestrictedSidMalformed)?;
    let header_end = sid_offset
        .checked_add(SID_HEADER_BYTES)
        .filter(|end| *end <= byte_length)
        .ok_or(WindowsNetworkAttributionError::RestrictedSidMalformed)?;
    let bytes = unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), byte_length) };
    let subauthority_count = bytes[sid_offset + 1] as usize;
    let sid_length = SID_HEADER_BYTES
        .checked_add(
            subauthority_count
                .checked_mul(size_of::<u32>())
                .ok_or(WindowsNetworkAttributionError::RestrictedSidMalformed)?,
        )
        .ok_or(WindowsNetworkAttributionError::RestrictedSidMalformed)?;
    let sid_end = sid_start
        .checked_add(sid_length)
        .filter(|end| *end <= buffer_end)
        .ok_or(WindowsNetworkAttributionError::RestrictedSidMalformed)?;
    if header_end > sid_offset + sid_length
        || sid_end <= sid_start
        || unsafe { IsValidSid(sid) } == 0
    {
        return Err(WindowsNetworkAttributionError::RestrictedSidInvalid);
    }
    let mut value = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut value) } == 0 {
        return Err(WindowsNetworkAttributionError::RestrictedSidFormat {
            code: unsafe { GetLastError() },
        });
    }
    local_sid_string(value).ok_or(WindowsNetworkAttributionError::RestrictedSidFormat {
        code: ERROR_INVALID_DATA,
    })
}

fn checked_allocation(byte_length: u32, maximum: usize) -> Result<usize, usize> {
    let byte_length = byte_length as usize;
    if byte_length == 0 || byte_length > maximum {
        Err(byte_length)
    } else {
        Ok(byte_length)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddrV4};

    use pretty_assertions::assert_eq;
    use windows_sys::Win32::NetworkManagement::IpHelper::MIB_TCPROW_OWNER_MODULE;

    use super::{
        ConnectionOwner, WindowsNetworkAttributionError, unique_client_owner,
        validate_process_identity,
    };

    #[test]
    fn reversed_four_tuple_selects_exactly_one_owner() {
        let listener = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 41000);
        let client = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 51000);
        let rows = [row(client, listener, 42), row(client, listener, 43)];

        assert_eq!(
            unique_client_owner(&rows[..1], listener, client).expect("one owner"),
            ConnectionOwner {
                process_id: 42,
                connection_created: 100,
            }
        );
        assert!(matches!(
            unique_client_owner(&rows, listener, client),
            Err(WindowsNetworkAttributionError::ConnectionOwnerDuplicate)
        ));
    }

    #[test]
    fn unrelated_tuple_is_not_attributed_by_port_alone() {
        let listener = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 41000);
        let client = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 51000);
        let unrelated = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 2), 41000);

        assert!(matches!(
            unique_client_owner(&[row(client, unrelated, 42)], listener, client),
            Err(WindowsNetworkAttributionError::ConnectionOwnerMissing)
        ));
    }

    #[test]
    fn reused_pid_cannot_adopt_an_older_tcp_context() {
        let owner = ConnectionOwner {
            process_id: 42,
            connection_created: 100,
        };

        validate_process_identity(owner, 100).expect("original process identity");
        assert!(matches!(
            validate_process_identity(owner, 101),
            Err(WindowsNetworkAttributionError::ProcessIdentityMismatch)
        ));
        assert!(matches!(
            validate_process_identity(
                ConnectionOwner {
                    process_id: 42,
                    connection_created: -1,
                },
                0,
            ),
            Err(WindowsNetworkAttributionError::ProcessIdentityMismatch)
        ));
    }

    fn row(local: SocketAddrV4, remote: SocketAddrV4, process_id: u32) -> MIB_TCPROW_OWNER_MODULE {
        MIB_TCPROW_OWNER_MODULE {
            dwState: 5,
            dwLocalAddr: u32::from_ne_bytes(local.ip().octets()),
            dwLocalPort: u16::to_be(local.port()) as u32,
            dwRemoteAddr: u32::from_ne_bytes(remote.ip().octets()),
            dwRemotePort: u16::to_be(remote.port()) as u32,
            dwOwningPid: process_id,
            liCreateTimestamp: 100,
            OwningModuleInfo: [0; 16],
        }
    }
}
