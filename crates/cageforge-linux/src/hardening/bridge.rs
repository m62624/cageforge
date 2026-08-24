// SPDX-License-Identifier: Apache-2.0

//! Trusted loopback-to-Unix bridge created before user-process seccomp.

use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream};
use std::os::fd::FromRawFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::helper_protocol::BRIDGE_TOKEN_BYTES;

const LOOPBACK_INTERFACE_NAME: &[u8] = b"lo";

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
    ) -> io::Result<Self> {
        let (read_fd, write_fd) = create_ready_pipe()?;
        let parent_pid = process_id();
        #[allow(unsafe_code)]
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            let error = io::Error::last_os_error();
            close_fd(read_fd)?;
            close_fd(write_fd)?;
            return Err(error);
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
        let mut port = [0; 2];
        #[allow(unsafe_code)]
        let mut ready = unsafe { File::from_raw_fd(read_fd) };
        if let Err(error) = ready.read_exact(&mut port) {
            terminate_bridge(pid);
            return Err(error);
        }
        let port = u16::from_be_bytes(port);
        if port == 0 {
            terminate_bridge(pid);
            return Err(io::Error::other("local gateway bridge returned port zero"));
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
) -> io::Result<()> {
    harden_bridge_process(parent_pid)?;
    let listener = bind_local_loopback_listener()?;
    let port = listener.local_addr()?.port();
    #[allow(unsafe_code)]
    let mut ready = unsafe { File::from_raw_fd(ready_fd) };
    ready.write_all(&port.to_be_bytes())?;
    drop(ready);

    let active = Arc::new(AtomicUsize::new(0));
    let bridge_token = Arc::new(bridge_token);
    loop {
        let (tcp_stream, _) = listener.accept()?;
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

fn bind_local_loopback_listener() -> io::Result<TcpListener> {
    match TcpListener::bind((Ipv4Addr::LOCALHOST, 0)) {
        Ok(listener) => Ok(listener),
        Err(error)
            if matches!(
                error.raw_os_error(),
                Some(errno) if errno == libc::EADDRNOTAVAIL || errno == libc::ENETUNREACH
            ) =>
        {
            ensure_loopback_interface_up()?;
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        }
        Err(error) => Err(error),
    }
}

#[allow(unsafe_code)]
fn ensure_loopback_interface_up() -> io::Result<()> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let result = configure_loopback_interface(fd);
    let close_result = close_fd(fd);
    result.and(close_result)
}

#[allow(unsafe_code)]
fn configure_loopback_interface(fd: libc::c_int) -> io::Result<()> {
    let mut flags_request = unsafe { std::mem::zeroed::<libc::ifreq>() };
    set_interface_name(&mut flags_request);
    if unsafe { libc::ioctl(fd, libc::SIOCGIFFLAGS as libc::Ioctl, &mut flags_request) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let current_flags = unsafe { flags_request.ifr_ifru.ifru_flags };
    let up = libc::IFF_UP as libc::c_short;
    if current_flags & up != up {
        flags_request.ifr_ifru.ifru_flags = current_flags | up;
        if unsafe { libc::ioctl(fd, libc::SIOCSIFFLAGS as libc::Ioctl, &flags_request) } < 0 {
            return Err(io::Error::last_os_error());
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
            return Err(error);
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
) -> io::Result<()> {
    unix_stream.write_all(bridge_token)?;
    let mut tcp_reader = tcp_stream.try_clone()?;
    let mut unix_writer = unix_stream.try_clone()?;
    let tcp_to_unix = std::thread::spawn(move || {
        let result = io::copy(&mut tcp_reader, &mut unix_writer);
        let _ = unix_writer.shutdown(Shutdown::Write);
        result
    });
    let unix_to_tcp = io::copy(&mut unix_stream, &mut tcp_stream);
    let _ = tcp_stream.shutdown(Shutdown::Write);
    tcp_to_unix
        .join()
        .map_err(|_| io::Error::other("gateway bridge relay thread panicked"))??;
    unix_to_tcp?;
    Ok(())
}

#[allow(unsafe_code)]
fn harden_bridge_process(expected_parent: libc::pid_t) -> io::Result<()> {
    detach_standard_streams()?;
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::getppid() } != expected_parent {
        return Err(io::Error::other("gateway bridge parent already exited"));
    }
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[allow(unsafe_code)]
fn process_id() -> libc::pid_t {
    unsafe { libc::getpid() }
}

#[allow(unsafe_code)]
fn detach_standard_streams() -> io::Result<()> {
    let read_fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if read_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let write_fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
    if write_fd < 0 {
        let error = io::Error::last_os_error();
        let _ = close_fd(read_fd);
        return Err(error);
    }
    for (source, target) in [
        (read_fd, libc::STDIN_FILENO),
        (write_fd, libc::STDOUT_FILENO),
        (write_fd, libc::STDERR_FILENO),
    ] {
        if unsafe { libc::dup2(source, target) } < 0 {
            let error = io::Error::last_os_error();
            let _ = close_fd(read_fd);
            let _ = close_fd(write_fd);
            return Err(error);
        }
    }
    close_fd(read_fd)?;
    close_fd(write_fd)
}

#[allow(unsafe_code)]
fn create_ready_pipe() -> io::Result<(libc::c_int, libc::c_int)> {
    let mut descriptors = [0; 2];
    if unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
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
fn move_fd_above_standard_streams(fd: libc::c_int) -> io::Result<libc::c_int> {
    if fd > libc::STDERR_FILENO {
        return Ok(fd);
    }
    let relocated = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, libc::STDERR_FILENO + 1) };
    if relocated < 0 {
        return Err(io::Error::last_os_error());
    }
    if let Err(error) = close_fd(fd) {
        let _ = close_fd(relocated);
        return Err(error);
    }
    Ok(relocated)
}

#[allow(unsafe_code)]
fn close_fd(fd: libc::c_int) -> io::Result<()> {
    if unsafe { libc::close(fd) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
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
