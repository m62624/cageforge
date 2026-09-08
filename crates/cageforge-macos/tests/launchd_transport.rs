// SPDX-License-Identifier: Apache-2.0

//! Native admission test for a launchd-owned helper transport. This is not yet
//! the backend's launch path. Every job/client has a finite fixture lifetime.

#![cfg(target_os = "macos")]

use std::{
    ffi::CString,
    fs::{self, File},
    io::Write,
    os::fd::AsRawFd,
    process::Command,
    sync::mpsc,
    time::Duration,
};

use tempfile::TempDir;

const SERVICE_ENV: &str = "CAGEFORGE_TRANSPORT_TEST_SERVICE";
const OWNER_ENV: &str = "CAGEFORGE_TRANSPORT_TEST_OWNER";
const TEST_TIMEOUT: Duration = Duration::from_secs(10);
const PROTOCOL_VERSION: u64 = 1;
const ACCEPTED: u64 = 1;
const REJECTED: u64 = 2;

struct LaunchdJob {
    target: String,
}

impl Drop for LaunchdJob {
    fn drop(&mut self) {
        let _ = Command::new("/bin/launchctl")
            .args(["bootout", &self.target])
            .output();
    }
}

#[test]
fn launchd_mach_service_checks_sender_identity_and_transfers_only_explicit_fds() {
    let temporary = TempDir::new().expect("transport fixture directory");
    let suffix = temporary.path().file_name().expect("unique directory name");
    let service = format!(
        "cageforge-test-transport-{}-{}",
        std::process::id(),
        suffix.to_string_lossy()
    );
    let owner = native::own_identity().expect("parent kernel identity");
    let domain = format!("user/{}", native::user_id());
    let _job = LaunchdJob {
        target: format!("{domain}/{service}"),
    };
    let executable = std::env::current_exe().expect("test executable");
    let helper_log = temporary.path().join("helper.log");
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>{service}</string>
<key>ProgramArguments</key><array><string>{executable}</string>
<string>--exact</string><string>launchd_transport_helper</string><string>--nocapture</string></array>
<key>EnvironmentVariables</key><dict>
<key>{SERVICE_ENV}</key><string>{service}</string>
<key>{OWNER_ENV}</key><string>{pid}:{version}</string></dict>
<key>MachServices</key><dict><key>{service}</key><true/></dict>
<key>RunAtLoad</key><true/>
<key>StandardOutPath</key><string>{log}</string>
<key>StandardErrorPath</key><string>{log}</string>
</dict></plist>"#,
        executable = xml_text(executable.to_str().expect("UTF-8 test executable")),
        pid = owner.0,
        version = owner.1,
        log = xml_text(helper_log.to_str().expect("UTF-8 helper log")),
    );
    let plist_path = temporary.path().join("helper.plist");
    fs::write(&plist_path, plist).expect("write owned launchd fixture");
    let bootstrap = Command::new("/bin/launchctl")
        .args(["bootstrap", &domain])
        .arg(&plist_path)
        .output()
        .expect("bootstrap user Mach service");
    assert!(bootstrap.status.success(), "bootstrap: {bootstrap:?}");

    // This client knows the service and can copy the declared owner fields.
    // Only the kernel's message identity is authoritative.
    let impostor = Command::new(&executable)
        .args(["--exact", "launchd_transport_impostor", "--nocapture"])
        .env(SERVICE_ENV, &service)
        .env(OWNER_ENV, format!("{}:{}", owner.0, owner.1))
        .output()
        .expect("run independent impostor client");
    assert!(
        impostor.status.success(),
        "impostor test: {impostor:?}; helper: {:?}",
        fs::read_to_string(&helper_log)
    );

    let output_path = temporary.path().join("explicit-fd-output");
    let output = File::create(&output_path).expect("explicitly transferred output");
    let client = native::Connection::client(&CString::new(service).expect("service name"));
    let request = native::Message::request(owner, Some(output.as_raw_fd()));
    let reply = client.request(&request).expect("authenticated FD transfer");
    assert_eq!(reply.number(c"version"), PROTOCOL_VERSION);
    assert_eq!(reply.number(c"result"), ACCEPTED);
    assert_eq!(
        fs::read(&output_path).expect("helper FD output"),
        b"fd-proof"
    );
}

#[test]
fn launchd_transport_impostor() {
    let Ok(service) = std::env::var(SERVICE_ENV) else {
        return;
    };
    let owner = declared_owner();
    let connection = native::Connection::client(&CString::new(service).expect("service name"));
    let reply = connection
        .request(&native::Message::request(owner, None))
        .expect("receive typed rejection");
    assert_eq!(reply.number(c"version"), PROTOCOL_VERSION);
    assert_eq!(reply.number(c"result"), REJECTED);
}

#[test]
fn launchd_transport_helper() {
    let Ok(service) = std::env::var(SERVICE_ENV) else {
        return;
    };
    let owner = declared_owner();
    let (sender, receiver) = mpsc::sync_channel(2);
    let _listener =
        native::Connection::listener(&CString::new(service).expect("service name"), sender);
    let mut peers = Vec::new();
    let deadline = std::time::Instant::now() + TEST_TIMEOUT;
    loop {
        let event = receiver
            .recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
            .expect("bounded helper exchange");
        match event {
            native::Event::Peer(peer) => peers.push(peer),
            native::Event::Message(message) => {
                let actual = message.sender_identity();
                let authorized = actual == owner && message.number(c"version") == PROTOCOL_VERSION;
                if authorized {
                    let mut output = message
                        .take_fd()
                        .expect("explicit FD in authorized request");
                    output
                        .write_all(b"fd-proof")
                        .expect("write through explicit FD");
                }
                message
                    .reply(if authorized { ACCEPTED } else { REJECTED })
                    .expect("flush typed response");
                if authorized {
                    return;
                }
            }
        }
    }
}

fn declared_owner() -> (u32, u32) {
    let value = std::env::var(OWNER_ENV).expect("declared fixture owner");
    let (pid, version) = value.split_once(':').expect("owner fields");
    (
        pid.parse().expect("owner PID"),
        version.parse().expect("owner generation"),
    )
}

fn xml_text(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[allow(unsafe_code)]
mod native {
    use super::{PROTOCOL_VERSION, TEST_TIMEOUT};
    use block2::{Block, RcBlock};
    use std::{
        ffi::{CStr, c_void},
        fs::File,
        io,
        os::fd::{FromRawFd, RawFd},
        ptr,
        sync::mpsc::{self, SyncSender},
    };

    const XPC_CONNECTION_MACH_SERVICE_LISTENER: u64 = 1;
    const PROC_PIDUNIQIDENTIFIERINFO: libc::c_int = 17;

    pub enum Event {
        Peer(Connection),
        Message(Message),
    }

    pub struct Connection(Object);
    pub struct Message(Object);
    struct Object(*mut c_void);

    #[repr(C)]
    #[derive(Default)]
    struct NativeIdentity {
        uuid: [u8; 16],
        unique_id: u64,
        parent_unique_id: u64,
        version: i32,
        reserved: u32,
        reserved_more: [u64; 2],
    }

    unsafe extern "C" {
        static _xpc_type_connection: u8;
        static _xpc_type_dictionary: u8;
        fn xpc_retain(object: *mut c_void) -> *mut c_void;
        fn xpc_release(object: *mut c_void);
        fn xpc_get_type(object: *mut c_void) -> *const c_void;
        fn xpc_connection_create_mach_service(
            name: *const libc::c_char,
            queue: *mut c_void,
            flags: u64,
        ) -> *mut c_void;
        fn xpc_connection_set_event_handler(
            connection: *mut c_void,
            block: &Block<dyn Fn(*mut c_void)>,
        );
        fn xpc_connection_resume(connection: *mut c_void);
        fn xpc_connection_cancel(connection: *mut c_void);
        fn xpc_connection_send_message(connection: *mut c_void, message: *mut c_void);
        fn xpc_connection_send_message_with_reply(
            connection: *mut c_void,
            message: *mut c_void,
            queue: *mut c_void,
            block: &Block<dyn Fn(*mut c_void)>,
        );
        fn xpc_connection_send_barrier(connection: *mut c_void, block: &Block<dyn Fn()>);
        fn xpc_dictionary_create(
            keys: *const *const libc::c_char,
            values: *const *mut c_void,
            count: usize,
        ) -> *mut c_void;
        fn xpc_dictionary_set_uint64(message: *mut c_void, key: *const libc::c_char, value: u64);
        fn xpc_dictionary_get_uint64(message: *mut c_void, key: *const libc::c_char) -> u64;
        fn xpc_dictionary_set_fd(message: *mut c_void, key: *const libc::c_char, fd: RawFd);
        fn xpc_dictionary_dup_fd(message: *mut c_void, key: *const libc::c_char) -> RawFd;
        fn xpc_dictionary_get_audit_token(message: *mut c_void, token: *mut [u32; 8]);
        fn xpc_dictionary_create_reply(message: *mut c_void) -> *mut c_void;
        fn xpc_dictionary_get_remote_connection(message: *mut c_void) -> *mut c_void;
    }

    // Retained XPC references may move between threads. No Rust reference to
    // mutable dictionary state is shared; incoming dictionaries are read-only.
    unsafe impl Send for Object {}

    impl Connection {
        pub fn client(name: &CStr) -> Self {
            let object =
                unsafe { xpc_connection_create_mach_service(name.as_ptr(), ptr::null_mut(), 0) };
            assert!(!object.is_null(), "create fixture connection");
            let handler = RcBlock::new(|_event: *mut c_void| {});
            unsafe {
                xpc_connection_set_event_handler(object, &handler);
                xpc_connection_resume(object);
            }
            Self(Object(object))
        }

        pub fn listener(name: &CStr, sender: SyncSender<Event>) -> Self {
            let object = unsafe {
                xpc_connection_create_mach_service(
                    name.as_ptr(),
                    ptr::null_mut(),
                    XPC_CONNECTION_MACH_SERVICE_LISTENER,
                )
            };
            assert!(!object.is_null(), "create fixture listener");
            let handler = RcBlock::new(move |peer: *mut c_void| unsafe {
                if xpc_get_type(peer) != (&raw const _xpc_type_connection).cast() {
                    return;
                }
                let messages = sender.clone();
                let incoming = RcBlock::new(move |message: *mut c_void| {
                    if xpc_get_type(message) == (&raw const _xpc_type_dictionary).cast() {
                        let event = Event::Message(Message(Object(xpc_retain(message))));
                        let _ = messages.try_send(event);
                    }
                });
                let owned = Connection(Object(xpc_retain(peer)));
                xpc_connection_set_event_handler(peer, &incoming);
                // Queue ownership before enabling message delivery. A full
                // queue drops/cancels only this newly received connection.
                if sender.try_send(Event::Peer(owned)).is_ok() {
                    xpc_connection_resume(peer);
                }
            });
            unsafe {
                xpc_connection_set_event_handler(object, &handler);
                xpc_connection_resume(object);
            }
            Self(Object(object))
        }

        pub fn request(&self, request: &Message) -> io::Result<Message> {
            let (sender, receiver) = mpsc::sync_channel(1);
            let handler = RcBlock::new(move |reply: *mut c_void| unsafe {
                let result = if xpc_get_type(reply) == (&raw const _xpc_type_dictionary).cast() {
                    Ok(Message(Object(xpc_retain(reply))))
                } else {
                    Err(io::ErrorKind::ConnectionAborted.into())
                };
                let _ = sender.try_send(result);
            });
            unsafe {
                xpc_connection_send_message_with_reply(
                    self.0.0,
                    request.0.0,
                    ptr::null_mut(),
                    &handler,
                )
            };
            receiver
                .recv_timeout(TEST_TIMEOUT)
                .map_err(|_| io::ErrorKind::TimedOut)?
        }
    }

    impl Drop for Connection {
        fn drop(&mut self) {
            unsafe { xpc_connection_cancel(self.0.0) };
        }
    }

    impl Message {
        pub fn request(owner: (u32, u32), fd: Option<RawFd>) -> Self {
            let raw = unsafe { xpc_dictionary_create(ptr::null(), ptr::null(), 0) };
            assert!(!raw.is_null(), "create request dictionary");
            unsafe {
                xpc_dictionary_set_uint64(raw, c"version".as_ptr(), PROTOCOL_VERSION);
                xpc_dictionary_set_uint64(raw, c"claimed-pid".as_ptr(), owner.0.into());
                xpc_dictionary_set_uint64(raw, c"claimed-generation".as_ptr(), owner.1.into());
                if let Some(fd) = fd {
                    xpc_dictionary_set_fd(raw, c"output".as_ptr(), fd);
                }
            }
            Self(Object(raw))
        }

        pub fn number(&self, key: &CStr) -> u64 {
            unsafe { xpc_dictionary_get_uint64(self.0.0, key.as_ptr()) }
        }

        pub fn sender_identity(&self) -> (u32, u32) {
            let mut audit = [0u32; 8];
            unsafe { xpc_dictionary_get_audit_token(self.0.0, &mut audit) };
            (audit[5], audit[7])
        }

        pub fn take_fd(&self) -> io::Result<File> {
            let fd = unsafe { xpc_dictionary_dup_fd(self.0.0, c"output".as_ptr()) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(unsafe { File::from_raw_fd(fd) })
        }

        pub fn reply(&self, status: u64) -> io::Result<()> {
            let raw = unsafe { xpc_dictionary_create_reply(self.0.0) };
            if raw.is_null() {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let reply = Object(raw);
            let remote = unsafe { xpc_dictionary_get_remote_connection(self.0.0) };
            if remote.is_null() {
                return Err(io::ErrorKind::NotConnected.into());
            }
            let (sender, receiver) = mpsc::sync_channel(1);
            let flushed = RcBlock::new(move || {
                let _ = sender.try_send(());
            });
            unsafe {
                xpc_dictionary_set_uint64(reply.0, c"version".as_ptr(), PROTOCOL_VERSION);
                xpc_dictionary_set_uint64(reply.0, c"result".as_ptr(), status);
                xpc_connection_send_message(remote, reply.0);
                xpc_connection_send_barrier(remote, &flushed);
            }
            receiver
                .recv_timeout(TEST_TIMEOUT)
                .map_err(|_| io::ErrorKind::TimedOut.into())
        }
    }

    impl Drop for Object {
        fn drop(&mut self) {
            unsafe { xpc_release(self.0) };
        }
    }

    pub fn own_identity() -> io::Result<(u32, u32)> {
        let mut info = NativeIdentity::default();
        let size = std::mem::size_of::<NativeIdentity>() as libc::c_int;
        let pid = std::process::id();
        let written = unsafe {
            libc::proc_pidinfo(
                pid as libc::pid_t,
                PROC_PIDUNIQIDENTIFIERINFO,
                0,
                (&mut info as *mut NativeIdentity).cast(),
                size,
            )
        };
        if written != size {
            return Err(io::Error::last_os_error());
        }
        Ok((pid, info.version as u32))
    }

    pub fn user_id() -> u32 {
        unsafe { libc::geteuid() }
    }
}
