// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsString;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

const MODE: &str = "CAGEFORGE_WINDOWS_SANDBOX_FIXTURE_MODE";
const DENIED_READ: &str = "CAGEFORGE_WINDOWS_SANDBOX_FIXTURE_DENIED_READ";
const DENIED_WRITE: &str = "CAGEFORGE_WINDOWS_SANDBOX_FIXTURE_DENIED_WRITE";
const PROGRESS: &str = "CAGEFORGE_WINDOWS_SANDBOX_FIXTURE_PROGRESS";
const NETWORK_TARGET: &str = "CAGEFORGE_WINDOWS_SANDBOX_FIXTURE_NETWORK_TARGET";

fn main() -> ExitCode {
    match run() {
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
        "direct-http" => direct_http(),
        "http-proxy" => http_proxy(false),
        "http-proxy-denied" => http_proxy(true),
        "socks5" => socks5(false),
        "socks5-denied" => socks5(true),
        _ => Err(format!("unsupported fixture mode {mode:?}")),
    }
}

fn denied_read() -> Result<(), String> {
    let denied_read = PathBuf::from(environment(DENIED_READ)?);
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
    }
}

fn direct_denied() -> Result<(), String> {
    match TcpStream::connect_timeout(&network_target()?, Duration::from_secs(2)) {
        Ok(_) => Err("direct network connection unexpectedly succeeded".to_string()),
        Err(_) => Ok(()),
    }
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
    let stream = TcpStream::connect_timeout(&address, Duration::from_secs(2))
        .map_err(|error| format!("connect to {address}: {error}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| format!("set read timeout: {error}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
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
