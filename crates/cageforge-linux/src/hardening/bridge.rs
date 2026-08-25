// SPDX-License-Identifier: Apache-2.0

//! Trusted loopback-to-Unix bridge created before user-process seccomp.

use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use crate::error::{LinuxBridgeError, LinuxBridgeOperation};
use crate::helper_protocol::BRIDGE_TOKEN_BYTES;

const LOOPBACK_INTERFACE_NAME: &[u8] = b"lo";
const BRIDGE_STARTUP_TIMEOUT: Duration = Duration::from_secs(10);

pub(super) struct LocalGatewayBridge {
    port: u16,
    pid: libc::pid_t,
}

impl LocalGatewayBridge {
    pub(super) fn start(
        socket_path: &Path,
        max_connections: usize,
        inherited_auth_fd: libc::c_int,
        bridge_token: [u8; BRIDGE_TOKEN_BYTES],
    ) -> Result<Self, LinuxBridgeError> {
        let (read_fd, write_fd) = create_ready_pipe()?;
        let parent_pid = process_id();
        #[allow(unsafe_code)]
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            let error = io::Error::last_os_error();
            close_fd(read_fd)?;
            close_fd(write_fd)?;
            return Err(LinuxBridgeError::Fork { source: error });
        }
        if pid == 0 {
            let _ = close_fd(read_fd);
            let _ = close_fd(inherited_auth_fd);
            let result = run_bridge(
                socket_path,
                write_fd,
                parent_pid,
                max_connections,
                bridge_token,
            );
            #[allow(unsafe_code)]
            unsafe {
                libc::_exit(if result.is_ok() { 0 } else { 1 });
            }
        }

        close_fd(write_fd)?;
        #[allow(unsafe_code)]
        let mut ready = unsafe { File::from_raw_fd(read_fd) };
        let port = match read_ready_port(&mut ready, BRIDGE_STARTUP_TIMEOUT) {
            Ok(port) => port,
            Err(error) => {
                terminate_bridge(pid);
                return Err(error);
            }
        };
        if port == 0 {
            terminate_bridge(pid);
            return Err(LinuxBridgeError::ZeroPort);
        }
        Ok(Self { port, pid })
    }

    pub(super) fn configure_command(&self, command: &mut Command) {
        let http = format!("http://127.0.0.1:{}", self.port);
        let socks = format!("socks5h://127.0.0.1:{}", self.port);
        for key in HTTP_PROXY_ENV_KEYS {
            command.env(key, &http);
            command.env(key.to_ascii_lowercase(), &http);
        }
        command.env("ALL_PROXY", &socks);
        command.env("all_proxy", &socks);
        command.env_remove("NO_PROXY");
        command.env_remove("no_proxy");
    }
}

impl Drop for LocalGatewayBridge {
    fn drop(&mut self) {
        terminate_bridge(self.pid);
    }
}

fn read_ready_port(ready: &mut File, timeout: Duration) -> Result<u16, LinuxBridgeError> {
    set_nonblocking(ready)?;
    let deadline = Instant::now() + timeout;
    let mut bytes = [0_u8; 2];
    let mut offset = 0;
    while offset < bytes.len() {
        match ready.read(&mut bytes[offset..]) {
            Ok(0) => {
                return Err(LinuxBridgeError::Operation {
                    operation: LinuxBridgeOperation::ReadReadyPort,
                    source: io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "bridge child closed the readiness pipe",
                    ),
                });
            }
            Ok(read) => offset += read,
            Err(source) if source.kind() == io::ErrorKind::WouldBlock => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(LinuxBridgeError::StartupTimedOut);
                }
                wait_for_readable(ready, remaining)?;
            }
            Err(source) if source.kind() == io::ErrorKind::Interrupted => {}
            Err(source) => {
                return Err(LinuxBridgeError::Operation {
                    operation: LinuxBridgeOperation::ReadReadyPort,
                    source,
                });
            }
        }
    }
    Ok(u16::from_be_bytes(bytes))
}

fn set_nonblocking(file: &File) -> Result<(), LinuxBridgeError> {
    #[allow(unsafe_code)]
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(LinuxBridgeError::Operation {
            operation: LinuxBridgeOperation::ReadReadyPort,
            source: io::Error::last_os_error(),
        });
    }
    #[allow(unsafe_code)]
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(LinuxBridgeError::Operation {
            operation: LinuxBridgeOperation::ReadReadyPort,
            source: io::Error::last_os_error(),
        });
    }
    Ok(())
}

fn wait_for_readable(file: &File, timeout: Duration) -> Result<(), LinuxBridgeError> {
    let milliseconds = timeout.as_millis().min(i32::MAX as u128) as libc::c_int;
    let mut poll_fd = libc::pollfd {
        fd: file.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        #[allow(unsafe_code)]
        let result = unsafe { libc::poll(&mut poll_fd, 1, milliseconds) };
        if result > 0 {
            return Ok(());
        }
        if result == 0 {
            return Err(LinuxBridgeError::StartupTimedOut);
        }
        if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return Err(LinuxBridgeError::Operation {
                operation: LinuxBridgeOperation::ReadReadyPort,
                source: io::Error::last_os_error(),
            });
        }
    }
}

const HTTP_PROXY_ENV_KEYS: &[&str] = &[
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "WS_PROXY",
    "WSS_PROXY",
    "FTP_PROXY",
    "YARN_HTTP_PROXY",
    "YARN_HTTPS_PROXY",
    "NPM_CONFIG_HTTP_PROXY",
    "NPM_CONFIG_HTTPS_PROXY",
    "NPM_CONFIG_PROXY",
    "BUNDLE_HTTP_PROXY",
    "BUNDLE_HTTPS_PROXY",
    "PIP_PROXY",
    "DOCKER_HTTP_PROXY",
    "DOCKER_HTTPS_PROXY",
];

fn run_bridge(
    socket_path: &Path,
    ready_fd: libc::c_int,
    parent_pid: libc::pid_t,
    max_connections: usize,
    bridge_token: [u8; BRIDGE_TOKEN_BYTES],
) -> Result<(), LinuxBridgeError> {
    harden_bridge_process(parent_pid)?;
    let listener = bind_local_loopback_listener()?;
    let port = listener
        .local_addr()
        .map_err(|source| LinuxBridgeError::Operation {
            operation: LinuxBridgeOperation::ReadListenerAddress,
            source,
        })?
        .port();
    #[allow(unsafe_code)]
    let mut ready = unsafe { File::from_raw_fd(ready_fd) };
    ready
        .write_all(&port.to_be_bytes())
        .map_err(|source| LinuxBridgeError::Operation {
            operation: LinuxBridgeOperation::WriteReadyPort,
            source,
        })?;
    drop(ready);

    let active = Arc::new(AtomicUsize::new(0));
    let bridge_token = Arc::new(bridge_token);
    loop {
        let (tcp_stream, _) = listener
            .accept()
            .map_err(|source| LinuxBridgeError::Operation {
                operation: LinuxBridgeOperation::AcceptConnection,
                source,
            })?;
        if active.fetch_add(1, Ordering::AcqRel) >= max_connections {
            active.fetch_sub(1, Ordering::AcqRel);
            drop(tcp_stream);
            continue;
        }
        let socket_path = socket_path.to_path_buf();
        let bridge_token = Arc::clone(&bridge_token);
        let active_for_thread = Arc::clone(&active);
        if std::thread::Builder::new()
            .name("cageforge-network-bridge".to_string())
            .spawn(move || {
                if let Ok(unix_stream) = UnixStream::connect(socket_path) {
                    let _ = relay(tcp_stream, unix_stream, bridge_token.as_ref());
                }
                active_for_thread.fetch_sub(1, Ordering::AcqRel);
            })
            .is_err()
        {
            active.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

fn bind_local_loopback_listener() -> Result<TcpListener, LinuxBridgeError> {
    match TcpListener::bind((Ipv4Addr::LOCALHOST, 0)) {
        Ok(listener) => Ok(listener),
        Err(error)
            if matches!(
                error.raw_os_error(),
                Some(errno) if errno == libc::EADDRNOTAVAIL || errno == libc::ENETUNREACH
            ) =>
        {
            ensure_loopback_interface_up()?;
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|source| {
                LinuxBridgeError::Operation {
                    operation: LinuxBridgeOperation::BindListener,
                    source,
                }
            })
        }
        Err(source) => Err(LinuxBridgeError::Operation {
            operation: LinuxBridgeOperation::BindListener,
            source,
        }),
    }
}

#[allow(unsafe_code)]
fn ensure_loopback_interface_up() -> Result<(), LinuxBridgeError> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(LinuxBridgeError::Operation {
            operation: LinuxBridgeOperation::HardenProcess,
            source: io::Error::last_os_error(),
        });
    }
    let result = configure_loopback_interface(fd);
    let close_result = close_fd(fd);
    result.and(close_result)
}

#[allow(unsafe_code)]
fn configure_loopback_interface(fd: libc::c_int) -> Result<(), LinuxBridgeError> {
    let mut flags_request = unsafe { std::mem::zeroed::<libc::ifreq>() };
    set_interface_name(&mut flags_request);
    if unsafe { libc::ioctl(fd, libc::SIOCGIFFLAGS as libc::Ioctl, &mut flags_request) } < 0 {
        return Err(LinuxBridgeError::Operation {
            operation: LinuxBridgeOperation::BindListener,
            source: io::Error::last_os_error(),
        });
    }
    let current_flags = unsafe { flags_request.ifr_ifru.ifru_flags };
    let up = libc::IFF_UP as libc::c_short;
    if current_flags & up != up {
        flags_request.ifr_ifru.ifru_flags = current_flags | up;
        if unsafe { libc::ioctl(fd, libc::SIOCSIFFLAGS as libc::Ioctl, &flags_request) } < 0 {
            return Err(LinuxBridgeError::Operation {
                operation: LinuxBridgeOperation::BindListener,
                source: io::Error::last_os_error(),
            });
        }
    }

    let mut address_request = unsafe { std::mem::zeroed::<libc::ifreq>() };
    set_interface_name(&mut address_request);
    let loopback = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: libc::htonl(libc::INADDR_LOOPBACK),
        },
        sin_zero: [0; 8],
    };
    address_request.ifr_ifru.ifru_addr =
        unsafe { *(&loopback as *const libc::sockaddr_in as *const libc::sockaddr) };
    if unsafe { libc::ioctl(fd, libc::SIOCSIFADDR as libc::Ioctl, &address_request) } < 0 {
        let error = io::Error::last_os_error();
        if !matches!(error.raw_os_error(), Some(libc::EEXIST | libc::EPERM)) {
            return Err(LinuxBridgeError::Operation {
                operation: LinuxBridgeOperation::BindListener,
                source: error,
            });
        }
    }
    Ok(())
}

fn set_interface_name(request: &mut libc::ifreq) {
    for (index, byte) in LOOPBACK_INTERFACE_NAME.iter().copied().enumerate() {
        request.ifr_name[index] = byte as libc::c_char;
    }
}

fn relay(
    mut tcp_stream: TcpStream,
    mut unix_stream: UnixStream,
    bridge_token: &[u8; BRIDGE_TOKEN_BYTES],
) -> Result<(), LinuxBridgeError> {
    unix_stream
        .write_all(bridge_token)
        .map_err(|source| LinuxBridgeError::Operation {
            operation: LinuxBridgeOperation::ConnectGateway,
            source,
        })?;
    let mut tcp_reader = tcp_stream
        .try_clone()
        .map_err(|source| LinuxBridgeError::Operation {
            operation: LinuxBridgeOperation::RelayToGateway,
            source,
        })?;
    let mut unix_writer =
        unix_stream
            .try_clone()
            .map_err(|source| LinuxBridgeError::Operation {
                operation: LinuxBridgeOperation::RelayToGateway,
                source,
            })?;
    let tcp_to_unix = std::thread::spawn(move || {
        let result = io::copy(&mut tcp_reader, &mut unix_writer);
        let _ = unix_writer.shutdown(Shutdown::Write);
        result
    });
    let unix_to_tcp =
        io::copy(&mut unix_stream, &mut tcp_stream).map_err(|source| LinuxBridgeError::Operation {
            operation: LinuxBridgeOperation::RelayToClient,
            source,
        });
    // EOF from the host gateway is final for this proxy connection. Closing
    // both TCP halves also wakes the cloned reader when a client deliberately
    // keeps its request half open after a rejected or timed-out handshake.
    let _ = tcp_stream.shutdown(Shutdown::Both);
    tcp_to_unix
        .join()
        .map_err(|_| LinuxBridgeError::RelayPanicked)?
        .map_err(|source| LinuxBridgeError::Operation {
            operation: LinuxBridgeOperation::RelayToGateway,
            source,
        })?;
    unix_to_tcp?;
    Ok(())
}

#[allow(unsafe_code)]
fn harden_bridge_process(expected_parent: libc::pid_t) -> Result<(), LinuxBridgeError> {
    detach_standard_streams()?;
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } != 0 {
        return Err(LinuxBridgeError::Operation {
            operation: LinuxBridgeOperation::HardenProcess,
            source: io::Error::last_os_error(),
        });
    }
    if unsafe { libc::getppid() } != expected_parent {
        return Err(LinuxBridgeError::ParentExited);
    }
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(LinuxBridgeError::Operation {
            operation: LinuxBridgeOperation::HardenProcess,
            source: io::Error::last_os_error(),
        });
    }
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(LinuxBridgeError::Operation {
            operation: LinuxBridgeOperation::HardenProcess,
            source: io::Error::last_os_error(),
        });
    }
    Ok(())
}

#[allow(unsafe_code)]
fn process_id() -> libc::pid_t {
    unsafe { libc::getpid() }
}

#[allow(unsafe_code)]
fn detach_standard_streams() -> Result<(), LinuxBridgeError> {
    let read_fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if read_fd < 0 {
        return Err(LinuxBridgeError::Operation {
            operation: LinuxBridgeOperation::DetachStandardStreams,
            source: io::Error::last_os_error(),
        });
    }
    let read_fd = match move_fd_above_standard_streams(read_fd) {
        Ok(fd) => fd,
        Err(error) => {
            let _ = close_fd(read_fd);
            return Err(error);
        }
    };
    let write_fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
    if write_fd < 0 {
        let error = io::Error::last_os_error();
        let _ = close_fd(read_fd);
        return Err(LinuxBridgeError::Operation {
            operation: LinuxBridgeOperation::DetachStandardStreams,
            source: error,
        });
    }
    let write_fd = match move_fd_above_standard_streams(write_fd) {
        Ok(fd) => fd,
        Err(error) => {
            let _ = close_fd(read_fd);
            let _ = close_fd(write_fd);
            return Err(error);
        }
    };
    for (source, target) in [
        (read_fd, libc::STDIN_FILENO),
        (write_fd, libc::STDOUT_FILENO),
        (write_fd, libc::STDERR_FILENO),
    ] {
        if unsafe { libc::dup2(source, target) } < 0 {
            let error = io::Error::last_os_error();
            let _ = close_fd(read_fd);
            let _ = close_fd(write_fd);
            return Err(LinuxBridgeError::Operation {
                operation: LinuxBridgeOperation::DetachStandardStreams,
                source: error,
            });
        }
    }
    close_fd(read_fd)?;
    close_fd(write_fd)
}

#[allow(unsafe_code)]
fn create_ready_pipe() -> Result<(libc::c_int, libc::c_int), LinuxBridgeError> {
    let mut descriptors = [0; 2];
    if unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(LinuxBridgeError::Operation {
            operation: LinuxBridgeOperation::CreateReadyPipe,
            source: io::Error::last_os_error(),
        });
    }
    let read_fd = match move_fd_above_standard_streams(descriptors[0]) {
        Ok(fd) => fd,
        Err(error) => {
            let _ = close_fd(descriptors[0]);
            let _ = close_fd(descriptors[1]);
            return Err(error);
        }
    };
    let write_fd = match move_fd_above_standard_streams(descriptors[1]) {
        Ok(fd) => fd,
        Err(error) => {
            let _ = close_fd(read_fd);
            let _ = close_fd(descriptors[1]);
            return Err(error);
        }
    };
    Ok((read_fd, write_fd))
}

#[allow(unsafe_code)]
fn move_fd_above_standard_streams(fd: libc::c_int) -> Result<libc::c_int, LinuxBridgeError> {
    if fd > libc::STDERR_FILENO {
        return Ok(fd);
    }
    let relocated = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, libc::STDERR_FILENO + 1) };
    if relocated < 0 {
        return Err(LinuxBridgeError::Operation {
            operation: LinuxBridgeOperation::MoveDescriptor,
            source: io::Error::last_os_error(),
        });
    }
    if let Err(error) = close_fd(fd) {
        let _ = close_fd(relocated);
        return Err(error);
    }
    Ok(relocated)
}

#[allow(unsafe_code)]
fn close_fd(fd: libc::c_int) -> Result<(), LinuxBridgeError> {
    if unsafe { libc::close(fd) } == 0 {
        Ok(())
    } else {
        Err(LinuxBridgeError::Operation {
            operation: LinuxBridgeOperation::CloseDescriptor,
            source: io::Error::last_os_error(),
        })
    }
}

#[allow(unsafe_code)]
fn terminate_bridge(pid: libc::pid_t) {
    unsafe { libc::kill(pid, libc::SIGKILL) };
    loop {
        let result = unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
        if result >= 0 {
            return;
        }
        if io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return;
        }
    }
}

#[cfg(test)]
#[path = "bridge_tests.rs"]
mod tests;
