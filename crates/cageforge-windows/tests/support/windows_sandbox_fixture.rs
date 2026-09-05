// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsString;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

#[cfg(target_os = "windows")]
use std::os::windows::ffi::OsStrExt;

#[cfg(target_os = "windows")]
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_INSUFFICIENT_BUFFER,
    ERROR_PRIVILEGE_NOT_HELD, GetLastError, WAIT_OBJECT_0,
};
#[cfg(target_os = "windows")]
use windows_sys::Win32::NetworkManagement::Dns::{
    DNS_QUERY_STANDARD, DNS_TYPE_A, DnsFree, DnsFreeRecordList, DnsQuery_W,
};
#[cfg(target_os = "windows")]
use windows_sys::Win32::NetworkManagement::IpHelper::{
    ICMP_ECHO_REPLY, IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho,
};
#[cfg(target_os = "windows")]
use windows_sys::Win32::NetworkManagement::WNet::{
    NETRESOURCEW, RESOURCETYPE_DISK, WNetAddConnection2W, WNetCancelConnection2W,
};
#[cfg(target_os = "windows")]
use windows_sys::Win32::Networking::WinHttp::{
    WINHTTP_ACCESS_TYPE_NO_PROXY, WinHttpCloseHandle, WinHttpConnect, WinHttpOpen,
    WinHttpOpenRequest, WinHttpReceiveResponse, WinHttpSendRequest, WinHttpSetTimeouts,
};
#[cfg(target_os = "windows")]
use windows_sys::Win32::Networking::WinInet::{
    HttpOpenRequestW, HttpSendRequestW, INTERNET_FLAG_NO_CACHE_WRITE, INTERNET_FLAG_RELOAD,
    INTERNET_OPEN_TYPE_DIRECT, INTERNET_OPTION_CONNECT_TIMEOUT, INTERNET_SERVICE_HTTP,
    InternetCloseHandle, InternetConnectW, InternetOpenW, InternetSetOptionW,
};
#[cfg(target_os = "windows")]
use windows_sys::Win32::Security::{TOKEN_DUPLICATE, TOKEN_QUERY};
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::JobObjects::IsProcessInJob;
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::StationsAndDesktops::{
    CloseDesktop, CreateDesktopW, DESKTOP_CREATEWINDOW, GetThreadDesktop,
    GetUserObjectInformationW, UOI_NAME,
};
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Threading::{
    CREATE_PROCESS_LOGON_FLAGS, CREATE_SUSPENDED, CreateProcessWithTokenW, EVENT_MODIFY_STATE,
    GetCurrentProcess, GetCurrentThreadId, GetExitCodeProcess, OpenEventW, OpenProcessToken,
    PROCESS_INFORMATION, ResumeThread, STARTUPINFOW, SetEvent, TerminateProcess,
    WaitForSingleObject,
};
#[cfg(target_os = "windows")]
use windows_sys::Win32::UI::Shell::{SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};

const MODE: &str = "CAGEFORGE_WINDOWS_SANDBOX_FIXTURE_MODE";
const DENIED_READ: &str = "CAGEFORGE_WINDOWS_SANDBOX_FIXTURE_DENIED_READ";
const DENIED_READ_ADS: &str = "CAGEFORGE_WINDOWS_SANDBOX_FIXTURE_DENIED_READ_ADS";
const DENIED_READ_DEVICE: &str = "CAGEFORGE_WINDOWS_SANDBOX_FIXTURE_DENIED_READ_DEVICE";
const DENIED_WRITE: &str = "CAGEFORGE_WINDOWS_SANDBOX_FIXTURE_DENIED_WRITE";
const PROGRESS: &str = "CAGEFORGE_WINDOWS_SANDBOX_FIXTURE_PROGRESS";
const NETWORK_TARGET: &str = "CAGEFORGE_WINDOWS_SANDBOX_FIXTURE_NETWORK_TARGET";
// The backend's launch timeout is 15 seconds. Keep the fixture's socket
// timeout above it so a slow Windows/WFP handshake is reported by the
// sandbox boundary instead of being converted into a misleading empty EOF.
const FIXTURE_IO_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(target_os = "windows")]
const UNRELATED_HANDLE: &str = "CAGEFORGE_WINDOWS_SANDBOX_FIXTURE_UNRELATED_HANDLE";
#[cfg(target_os = "windows")]
const UNRELATED_NAMED_OBJECT: &str = "CAGEFORGE_WINDOWS_SANDBOX_FIXTURE_UNRELATED_NAMED_OBJECT";

fn main() -> ExitCode {
    let result = match std::env::args_os().nth(1).as_deref() {
        Some(argument) if argument == "--process-broker-child" => process_broker_child(),
        Some(argument) if argument == "--shell-activation-child" => shell_activation_child(),
        _ => run(),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("cageforge-windows-test-fixture: {error}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<(), String> {
    let mode = environment(MODE)?.to_string_lossy().into_owned();
    match mode.as_str() {
        "denied-read" => denied_read(),
        "direct-denied" => direct_denied(),
        "direct-udp-denied" => direct_udp_denied(),
        "direct-dns-denied" => direct_dns_denied(),
        "direct-icmp-denied" => direct_icmp_denied(),
        "direct-smb-denied" => direct_smb_denied(),
        "direct-http" => direct_http(),
        "direct-powershell-denied" => direct_powershell_denied(),
        "direct-winhttp-denied" => direct_winhttp_denied(),
        "direct-wininet-denied" => direct_wininet_denied(),
        "http-proxy" => http_proxy(false),
        "http-proxy-denied" => http_proxy(true),
        "socks5" => socks5(false),
        "socks5-denied" => socks5(true),
        "private-desktop" => private_desktop(),
        "process-broker" => process_broker(),
        "shell-activation" => shell_activation(),
        "unrelated-handle" => signal_unrelated_handle(),
        "unrelated-named-object" => signal_unrelated_named_object(),
        _ => Err(format!("unsupported fixture mode {mode:?}")),
    }
}

#[cfg(target_os = "windows")]
#[allow(unsafe_code)]
fn private_desktop() -> Result<(), String> {
    let thread_id = unsafe { GetCurrentThreadId() };
    let desktop = unsafe { GetThreadDesktop(thread_id) };
    if desktop.is_null() {
        return Err(format!(
            "get sandboxed thread desktop: Windows error {}",
            unsafe { GetLastError() }
        ));
    }
    let mut byte_length = 0u32;
    let initial = unsafe {
        GetUserObjectInformationW(desktop, UOI_NAME, std::ptr::null_mut(), 0, &mut byte_length)
    };
    if initial != 0
        || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER
        || byte_length == 0
        || !byte_length.is_multiple_of(2)
    {
        return Err(format!(
            "size sandboxed thread desktop name: result={initial}, bytes={byte_length}, Windows error {}",
            unsafe { GetLastError() }
        ));
    }
    let mut name = vec![0u16; (byte_length / 2) as usize];
    if unsafe {
        GetUserObjectInformationW(
            desktop,
            UOI_NAME,
            name.as_mut_ptr().cast(),
            byte_length,
            &mut byte_length,
        )
    } == 0
    {
        return Err(format!(
            "read sandboxed thread desktop name: Windows error {}",
            unsafe { GetLastError() }
        ));
    }
    let terminator = name
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(name.len());
    let name = String::from_utf16(&name[..terminator])
        .map_err(|error| format!("decode sandboxed thread desktop name: {error}"))?;
    if name.starts_with("Cageforge-") {
        let escape_name = format!("Cageforge-escape-{}", std::process::id());
        let escape_name = escape_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let escape = unsafe {
            CreateDesktopW(
                escape_name.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                DESKTOP_CREATEWINDOW,
                std::ptr::null(),
            )
        };
        if escape.is_null() {
            Ok(())
        } else {
            unsafe { CloseDesktop(escape) };
            Err("sandboxed process created a second desktop despite Job UI isolation".to_string())
        }
    } else {
        Err(format!(
            "sandboxed thread started on host or default desktop {name:?}"
        ))
    }
}

#[cfg(target_os = "windows")]
#[allow(unsafe_code)]
fn process_broker() -> Result<(), String> {
    let executable = std::env::current_exe()
        .map_err(|error| format!("resolve process-broker fixture executable: {error}"))?;
    let executable = executable
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut command_line = "--process-broker-child\0"
        .encode_utf16()
        .collect::<Vec<_>>();
    let mut token = std::ptr::null_mut();
    if unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_DUPLICATE,
            &mut token,
        )
    } == 0
    {
        return Err(format!(
            "process-broker token access failed: Windows error {}",
            unsafe { GetLastError() }
        ));
    }
    let startup = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        ..unsafe { std::mem::zeroed() }
    };
    let mut process_information = unsafe { std::mem::zeroed::<PROCESS_INFORMATION>() };
    let created = unsafe {
        CreateProcessWithTokenW(
            token,
            0 as CREATE_PROCESS_LOGON_FLAGS,
            executable.as_ptr(),
            command_line.as_mut_ptr(),
            CREATE_SUSPENDED,
            std::ptr::null(),
            std::ptr::null(),
            &startup,
            &mut process_information,
        )
    };
    let creation_error = (created == 0).then(|| unsafe { GetLastError() });
    unsafe { CloseHandle(token) };
    if let Some(error) = creation_error {
        if error == ERROR_ACCESS_DENIED || error == ERROR_PRIVILEGE_NOT_HELD {
            return Ok(());
        }
        return Err(format!(
            "CreateProcessWithTokenW failed with an unexpected Windows error {error}"
        ));
    }
    let process = process_information.hProcess;
    let mut in_job = 0;
    let job_query = unsafe { IsProcessInJob(process, std::ptr::null_mut(), &mut in_job) } != 0;
    if unsafe { ResumeThread(process_information.hThread) } == u32::MAX {
        unsafe {
            TerminateProcess(process, 1);
            CloseHandle(process_information.hThread);
            CloseHandle(process);
        }
        return Err(format!(
            "resume of CreateProcessWithTokenW child failed: Windows error {}",
            unsafe { GetLastError() }
        ));
    }
    let wait = unsafe { WaitForSingleObject(process, 10_000) };
    let mut exit_code = 1;
    if wait == WAIT_OBJECT_0 {
        unsafe { GetExitCodeProcess(process, &mut exit_code) };
    } else {
        unsafe { TerminateProcess(process, 1) };
    }
    unsafe {
        CloseHandle(process_information.hThread);
        CloseHandle(process);
    }
    if !job_query || in_job == 0 {
        return Err(
            "CreateProcessWithTokenW launched a process outside the sandbox Job Object".to_string(),
        );
    }
    if wait != WAIT_OBJECT_0 || exit_code != 0 {
        return Err(format!(
            "CreateProcessWithTokenW child did not remain on the private desktop (wait={wait}, exit={exit_code})"
        ));
    }
    Ok(())
}

#[cfg(target_os = "windows")]
#[allow(unsafe_code)]
fn shell_activation() -> Result<(), String> {
    let executable = std::env::current_exe()
        .map_err(|error| format!("resolve shell-activation fixture executable: {error}"))?;
    let executable = executable
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let parameters = "--shell-activation-child\0"
        .encode_utf16()
        .collect::<Vec<_>>();
    let mut execute = unsafe { std::mem::zeroed::<SHELLEXECUTEINFOW>() };
    execute.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
    execute.fMask = SEE_MASK_NOCLOSEPROCESS;
    execute.lpFile = executable.as_ptr();
    execute.lpParameters = parameters.as_ptr();
    execute.nShow = 0;
    if unsafe { ShellExecuteExW(&mut execute) } == 0 {
        let error = unsafe { GetLastError() };
        if error == ERROR_ACCESS_DENIED || error == ERROR_PRIVILEGE_NOT_HELD {
            return Ok(());
        }
        return Err(format!(
            "ShellExecuteExW failed with an unexpected Windows error {error}"
        ));
    }
    let process = execute.hProcess;
    if process.is_null() {
        return Err("ShellExecuteExW reported success without a process handle".to_string());
    }
    let mut in_job = 0;
    let job_query = unsafe { IsProcessInJob(process, std::ptr::null_mut(), &mut in_job) } != 0;
    let wait = unsafe { WaitForSingleObject(process, 10_000) };
    let mut exit_code = 1;
    if wait == WAIT_OBJECT_0 {
        unsafe {
            windows_sys::Win32::System::Threading::GetExitCodeProcess(process, &mut exit_code)
        };
    } else {
        unsafe { TerminateProcess(process, 1) };
    }
    unsafe { CloseHandle(process) };
    if !job_query || in_job == 0 {
        return Err(
            "ShellExecuteExW launched a process outside the sandbox Job Object".to_string(),
        );
    }
    if wait != WAIT_OBJECT_0 || exit_code != 0 {
        return Err(format!(
            "ShellExecuteExW child did not remain on the private desktop (wait={wait}, exit={exit_code})"
        ));
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn process_broker_child() -> Result<(), String> {
    private_desktop()
}

#[cfg(target_os = "windows")]
fn shell_activation_child() -> Result<(), String> {
    private_desktop()
}

#[cfg(not(target_os = "windows"))]
fn process_broker_child() -> Result<(), String> {
    Err("process-broker child probe requires Windows".to_string())
}

#[cfg(not(target_os = "windows"))]
fn shell_activation_child() -> Result<(), String> {
    Err("shell-activation child probe requires Windows".to_string())
}

#[cfg(not(target_os = "windows"))]
fn private_desktop() -> Result<(), String> {
    Err("private desktop probe requires Windows".to_string())
}

#[cfg(not(target_os = "windows"))]
fn process_broker() -> Result<(), String> {
    Err("process-broker probe requires Windows".to_string())
}

#[cfg(not(target_os = "windows"))]
fn shell_activation() -> Result<(), String> {
    Err("shell-activation probe requires Windows".to_string())
}

#[cfg(target_os = "windows")]
#[allow(unsafe_code)]
fn signal_unrelated_handle() -> Result<(), String> {
    let raw_handle = environment(UNRELATED_HANDLE)?
        .to_string_lossy()
        .parse::<isize>()
        .map_err(|error| format!("parse unrelated parent handle: {error}"))?;
    if raw_handle == 0 {
        return Err("unrelated parent handle was null".to_string());
    }
    // HANDLE values are process-local. A numeric value that is invalid in the
    // sandbox can coincidentally identify one of its own handles, so the
    // child-side result is not evidence that the parent's Event crossed the
    // boundary. The parent verifies the only authoritative property: its
    // original Event remains unsignaled before, during, and after this probe.
    let _ = unsafe { SetEvent(raw_handle as *mut _) };
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn signal_unrelated_handle() -> Result<(), String> {
    Err("unrelated-handle probe requires Windows".to_string())
}

#[cfg(target_os = "windows")]
#[allow(unsafe_code)]
fn signal_unrelated_named_object() -> Result<(), String> {
    let name = environment(UNRELATED_NAMED_OBJECT)?;
    let name = name.to_string_lossy();
    let wide = name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let event = unsafe { OpenEventW(EVENT_MODIFY_STATE, 0, wide.as_ptr()) };
    if !event.is_null() {
        unsafe { CloseHandle(event) };
        return Err("sandboxed process opened an unrelated named parent Event".to_string());
    }
    let error = unsafe { GetLastError() };
    if error != ERROR_ACCESS_DENIED && error != ERROR_FILE_NOT_FOUND {
        return Err(format!(
            "reject unrelated named parent Event: Windows error {error}"
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn signal_unrelated_named_object() -> Result<(), String> {
    Err("unrelated-named-object probe requires Windows".to_string())
}

fn denied_read() -> Result<(), String> {
    let denied_read = PathBuf::from(environment(DENIED_READ)?);
    let denied_read_ads = PathBuf::from(environment(DENIED_READ_ADS)?);
    let denied_read_device = PathBuf::from(environment(DENIED_READ_DEVICE)?);
    let denied_write = PathBuf::from(environment(DENIED_WRITE)?);
    let progress = PathBuf::from(environment(PROGRESS)?);
    std::fs::write(&progress, b"before-denied-read")
        .map_err(|error| format!("record denied-read start: {error}"))?;
    match std::fs::read(&denied_read) {
        Ok(_) => Err(format!("read denied host file {denied_read:?}")),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&denied_write)
            {
                Ok(_) => return Err(format!("wrote read-only sandbox path {denied_write:?}")),
                Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {}
                Err(error) => {
                    return Err(format!(
                        "write read-only sandbox path {denied_write:?}: {error}"
                    ));
                }
            }
            std::fs::write(&progress, b"after-denied-read")
                .map_err(|error| format!("record denied-read completion: {error}"))?;
            std::io::stdout()
                .write_all(b"denied")
                .map_err(|error| format!("write denied-read result: {error}"))
        }
        Err(error) => Err(format!("read denied host file: {error}")),
    }?;
    match std::fs::read(&denied_read_ads) {
        Ok(_) => {
            return Err(format!(
                "read denied host alternate data stream {denied_read_ads:?}"
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {}
        Err(error) => {
            return Err(format!(
                "read denied host alternate data stream {denied_read_ads:?}: {error}"
            ));
        }
    };
    match std::fs::read(&denied_read_device) {
        Ok(_) => Err(format!(
            "read denied host device path {denied_read_device:?}"
        )),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => Ok(()),
        Err(error) => Err(format!(
            "read denied host device path {denied_read_device:?}: {error}"
        )),
    }
}

fn direct_denied() -> Result<(), String> {
    match TcpStream::connect_timeout(&network_target()?, Duration::from_secs(2)) {
        Ok(_) => Err("direct network connection unexpectedly succeeded".to_string()),
        Err(_) => Ok(()),
    }
}

fn direct_udp_denied() -> Result<(), String> {
    let socket = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .map_err(|error| format!("bind direct UDP probe: {error}"))?;
    let _ = socket.send_to(b"cageforge-direct-udp-probe", network_target()?);
    Ok(())
}

#[cfg(target_os = "windows")]
#[allow(unsafe_code)]
fn direct_dns_denied() -> Result<(), String> {
    let name = "example.com\0".encode_utf16().collect::<Vec<_>>();
    let mut records = std::ptr::null_mut();
    let status = unsafe {
        DnsQuery_W(
            name.as_ptr(),
            DNS_TYPE_A,
            DNS_QUERY_STANDARD,
            std::ptr::null_mut(),
            &mut records,
            std::ptr::null_mut(),
        )
    };
    if status == 0 && !records.is_null() {
        unsafe { DnsFree(records.cast(), DnsFreeRecordList) };
        return Err(
            "direct DNS query unexpectedly crossed the disabled network boundary".to_string(),
        );
    }
    if !records.is_null() {
        unsafe { DnsFree(records.cast(), DnsFreeRecordList) };
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn direct_dns_denied() -> Result<(), String> {
    Err("direct DNS probe requires Windows".to_string())
}

#[cfg(target_os = "windows")]
#[allow(unsafe_code)]
fn direct_icmp_denied() -> Result<(), String> {
    let handle = unsafe { IcmpCreateFile() };
    if handle.is_null() || handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
        return Err(format!(
            "ICMP probe handle setup failed: Windows error {}",
            unsafe { GetLastError() }
        ));
    }
    let request = b"cageforge-icmp-probe";
    let mut reply = vec![0u8; std::mem::size_of::<ICMP_ECHO_REPLY>() + request.len() + 8];
    let replies = unsafe {
        IcmpSendEcho(
            handle,
            u32::from_be_bytes([127, 0, 0, 1]),
            request.as_ptr().cast(),
            request.len() as u16,
            std::ptr::null(),
            reply.as_mut_ptr().cast(),
            reply.len() as u32,
            2_000,
        )
    };
    unsafe { IcmpCloseHandle(handle) };
    if replies != 0 {
        return Err(
            "direct ICMP query unexpectedly crossed the disabled network boundary".to_string(),
        );
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn direct_icmp_denied() -> Result<(), String> {
    Err("direct ICMP probe requires Windows".to_string())
}

#[cfg(target_os = "windows")]
#[allow(unsafe_code)]
fn direct_smb_denied() -> Result<(), String> {
    let remote_name = r"\\127.0.0.1\IPC$"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let resource = NETRESOURCEW {
        dwScope: 0,
        dwType: RESOURCETYPE_DISK,
        dwDisplayType: 0,
        dwUsage: 0,
        lpLocalName: std::ptr::null_mut(),
        lpRemoteName: remote_name.as_ptr().cast_mut(),
        lpComment: std::ptr::null_mut(),
        lpProvider: std::ptr::null_mut(),
    };
    let status = unsafe { WNetAddConnection2W(&resource, std::ptr::null(), std::ptr::null(), 0) };
    if status == 0 {
        unsafe { WNetCancelConnection2W(remote_name.as_ptr(), 0, 1) };
        return Err(
            "direct SMB connection unexpectedly crossed the disabled network boundary".to_string(),
        );
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn direct_smb_denied() -> Result<(), String> {
    Err("direct SMB probe requires Windows".to_string())
}

#[cfg(target_os = "windows")]
#[allow(unsafe_code)]
fn direct_winhttp_denied() -> Result<(), String> {
    let target = network_target()?;
    let host = target
        .ip()
        .to_string()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let object = [b'/' as u16, 0];
    let agent = [b'c' as u16, b'a' as u16, b'g' as u16, b'e' as u16, 0];
    let session = unsafe {
        WinHttpOpen(
            agent.as_ptr(),
            WINHTTP_ACCESS_TYPE_NO_PROXY,
            std::ptr::null(),
            std::ptr::null(),
            0,
        )
    };
    if session.is_null() {
        return Err(format!(
            "WinHTTP session setup failed before the network probe: Windows error {}",
            unsafe { GetLastError() }
        ));
    }
    let result = (|| {
        if unsafe { WinHttpSetTimeouts(session, 2_000, 2_000, 2_000, 2_000) } == 0 {
            return Err(format!(
                "WinHTTP timeout setup failed: Windows error {}",
                unsafe { GetLastError() }
            ));
        }
        let connection = unsafe { WinHttpConnect(session, host.as_ptr(), target.port(), 0) };
        if connection.is_null() {
            return Err(format!(
                "WinHTTP connection handle setup failed before the network probe: Windows error {}",
                unsafe { GetLastError() }
            ));
        }
        let request = unsafe {
            WinHttpOpenRequest(
                connection,
                std::ptr::null(),
                object.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                0,
            )
        };
        if request.is_null() {
            unsafe { WinHttpCloseHandle(connection) };
            return Err(format!(
                "WinHTTP request setup failed before the network probe: Windows error {}",
                unsafe { GetLastError() }
            ));
        }
        let sent =
            unsafe { WinHttpSendRequest(request, std::ptr::null(), 0, std::ptr::null(), 0, 0, 0) };
        let received =
            sent != 0 && unsafe { WinHttpReceiveResponse(request, std::ptr::null_mut()) } != 0;
        unsafe {
            WinHttpCloseHandle(request);
            WinHttpCloseHandle(connection);
        }
        if received {
            Err(
                "WinHTTP direct request unexpectedly crossed the disabled network boundary"
                    .to_string(),
            )
        } else {
            Ok(())
        }
    })();
    unsafe { WinHttpCloseHandle(session) };
    result
}

#[cfg(not(target_os = "windows"))]
fn direct_winhttp_denied() -> Result<(), String> {
    Err("WinHTTP probe requires Windows".to_string())
}

#[cfg(target_os = "windows")]
#[allow(unsafe_code)]
fn direct_wininet_denied() -> Result<(), String> {
    let target = network_target()?;
    let host = target
        .ip()
        .to_string()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let object = [b'/' as u16, 0];
    let agent = [b'c' as u16, b'a' as u16, b'g' as u16, b'e' as u16, 0];
    let session = unsafe {
        InternetOpenW(
            agent.as_ptr(),
            INTERNET_OPEN_TYPE_DIRECT,
            std::ptr::null(),
            std::ptr::null(),
            0,
        )
    };
    if session.is_null() {
        return Err(format!(
            "WinINet session setup failed before the network probe: Windows error {}",
            unsafe { GetLastError() }
        ));
    }
    let timeout = 2_000u32;
    let result = (|| {
        if unsafe {
            InternetSetOptionW(
                session,
                INTERNET_OPTION_CONNECT_TIMEOUT,
                (&timeout as *const u32).cast(),
                std::mem::size_of_val(&timeout) as u32,
            )
        } == 0
        {
            return Err(format!(
                "WinINet timeout setup failed: Windows error {}",
                unsafe { GetLastError() }
            ));
        }
        let connection = unsafe {
            InternetConnectW(
                session,
                host.as_ptr(),
                target.port(),
                std::ptr::null(),
                std::ptr::null(),
                INTERNET_SERVICE_HTTP,
                0,
                0,
            )
        };
        if connection.is_null() {
            return Err(format!(
                "WinINet connection handle setup failed before the network probe: Windows error {}",
                unsafe { GetLastError() }
            ));
        }
        let request = unsafe {
            HttpOpenRequestW(
                connection,
                std::ptr::null(),
                object.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_RELOAD,
                0,
            )
        };
        if request.is_null() {
            unsafe { InternetCloseHandle(connection) };
            return Err(format!(
                "WinINet request setup failed before the network probe: Windows error {}",
                unsafe { GetLastError() }
            ));
        }
        let sent = unsafe { HttpSendRequestW(request, std::ptr::null(), 0, std::ptr::null(), 0) };
        unsafe {
            InternetCloseHandle(request);
            InternetCloseHandle(connection);
        }
        if sent != 0 {
            Err(
                "WinINet direct request unexpectedly crossed the disabled network boundary"
                    .to_string(),
            )
        } else {
            Ok(())
        }
    })();
    unsafe { InternetCloseHandle(session) };
    result
}

#[cfg(not(target_os = "windows"))]
fn direct_wininet_denied() -> Result<(), String> {
    Err("WinINet probe requires Windows".to_string())
}

#[cfg(target_os = "windows")]
fn direct_powershell_denied() -> Result<(), String> {
    let target = network_target()?;
    let host = target.ip();
    let port = target.port();
    let script = format!(
        "$result = Test-NetConnection -ComputerName '{host}' -Port {port} -InformationLevel Quiet -WarningAction SilentlyContinue; if ($result -eq $true) {{ exit 42 }} else {{ exit 0 }}"
    );
    let status = std::process::Command::new("powershell.exe")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &script,
        ])
        .status()
        .map_err(|error| format!("start PowerShell network probe: {error}"))?;
    match status.code() {
        Some(0) => Ok(()),
        Some(code) => Err(format!(
            "PowerShell direct network probe was not denied (exit code {code})"
        )),
        None => Err("PowerShell network probe was terminated without an exit code".to_string()),
    }
}

#[cfg(not(target_os = "windows"))]
fn direct_powershell_denied() -> Result<(), String> {
    Err("PowerShell probe requires Windows".to_string())
}

fn direct_http() -> Result<(), String> {
    let target = network_target()?;
    let mut stream = connect(target)?;
    send_http_request(&mut stream, target)?;
    require_success_response(&mut stream)
}

fn http_proxy(expect_denial: bool) -> Result<(), String> {
    let target = network_target()?;
    let proxy = proxy_endpoint("HTTP_PROXY")?;
    let mut stream = connect(proxy)?;
    send_http_request(&mut stream, target)?;
    let mut response = Vec::new();
    match stream.read_to_end(&mut response) {
        Ok(_) if expect_denial && !is_success_response(&response) => Ok(()),
        Ok(_) if expect_denial => Err("proxy reached a denied network target".to_string()),
        Ok(_) if is_success_response(&response) => Ok(()),
        Ok(_) => Err(format!(
            "proxy response was not successful: {}",
            String::from_utf8_lossy(&response)
        )),
        Err(_) if expect_denial => Ok(()),
        Err(error) => Err(format!("read proxy response: {error}")),
    }
}

fn socks5(expect_denial: bool) -> Result<(), String> {
    let target = network_target()?;
    let proxy = proxy_endpoint("ALL_PROXY")?;
    let mut stream = connect(proxy)?;
    stream
        .write_all(&[5, 1, 0])
        .map_err(|error| format!("write SOCKS5 greeting: {error}"))?;
    let mut greeting = [0; 2];
    stream
        .read_exact(&mut greeting)
        .map_err(|error| format!("read SOCKS5 greeting: {error}"))?;
    if greeting != [5, 0] {
        return Err(format!(
            "SOCKS5 proxy rejected no-authentication: {greeting:?}"
        ));
    }
    let IpAddr::V4(address) = target.ip() else {
        return Err(format!(
            "SOCKS5 fixture requires an IPv4 target, found {target}"
        ));
    };
    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&address.octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    stream
        .write_all(&request)
        .map_err(|error| format!("write SOCKS5 connect request: {error}"))?;
    let mut response = [0; 10];
    match stream.read_exact(&mut response) {
        Ok(()) if expect_denial && response[1] != 0 => Ok(()),
        Ok(()) if expect_denial => Err("SOCKS5 proxy reached a denied network target".to_string()),
        Ok(()) if response[1] == 0 => {
            write!(
                stream,
                "GET / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
            )
            .map_err(|error| format!("write tunneled HTTP request: {error}"))?;
            require_success_response(&mut stream)
        }
        Ok(()) => Err(format!(
            "SOCKS5 proxy rejected allowed target: {response:?}"
        )),
        Err(_) if expect_denial => Ok(()),
        Err(error) => Err(format!("read SOCKS5 connect response: {error}")),
    }
}

fn network_target() -> Result<SocketAddr, String> {
    environment(NETWORK_TARGET)?
        .to_string_lossy()
        .parse()
        .map_err(|error| format!("parse network target: {error}"))
}

fn proxy_endpoint(name: &str) -> Result<SocketAddr, String> {
    let value = environment(name)?.to_string_lossy().into_owned();
    let authority = value
        .split_once("://")
        .map(|(_, authority)| authority)
        .unwrap_or(value.as_str());
    authority
        .trim_end_matches('/')
        .parse()
        .map_err(|error| format!("parse {name} endpoint: {error}"))
}

fn connect(address: SocketAddr) -> Result<TcpStream, String> {
    let stream = TcpStream::connect_timeout(&address, FIXTURE_IO_TIMEOUT)
        .map_err(|error| format!("connect to {address}: {error}"))?;
    stream
        .set_read_timeout(Some(FIXTURE_IO_TIMEOUT))
        .map_err(|error| format!("set read timeout: {error}"))?;
    stream
        .set_write_timeout(Some(FIXTURE_IO_TIMEOUT))
        .map_err(|error| format!("set write timeout: {error}"))?;
    Ok(stream)
}

fn send_http_request(stream: &mut TcpStream, target: SocketAddr) -> Result<(), String> {
    write!(
        stream,
        "GET http://{target}/ HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
    )
    .map_err(|error| format!("write HTTP request: {error}"))
}

fn require_success_response(stream: &mut TcpStream) -> Result<(), String> {
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(|error| format!("read HTTP response: {error}"))?;
    if is_success_response(&response) {
        Ok(())
    } else {
        Err(format!(
            "HTTP response was not successful: {}",
            String::from_utf8_lossy(&response)
        ))
    }
}

fn is_success_response(response: &[u8]) -> bool {
    response.starts_with(b"HTTP/1.1 200 ") || response.starts_with(b"HTTP/1.0 200 ")
}

fn environment(name: &str) -> Result<OsString, String> {
    std::env::var_os(name).ok_or_else(|| format!("missing required environment variable {name}"))
}
