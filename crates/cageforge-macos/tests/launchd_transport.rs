// SPDX-License-Identifier: Apache-2.0

//! Native admission test for a launchd-owned helper transport. This is not yet
//! the backend's launch path. Every job/client has a finite fixture lifetime.

#![cfg(target_os = "macos")]

use std::{
    ffi::CString,
    fs::{self, File},
    io::{self, Write},
    net::{SocketAddr, TcpListener},
    os::fd::AsRawFd,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant},
};

use tempfile::TempDir;

const SERVICE_ENV: &str = "CAGEFORGE_TRANSPORT_TEST_SERVICE";
const OWNER_ENV: &str = "CAGEFORGE_TRANSPORT_TEST_OWNER";
const ROOT_ENV: &str = "CAGEFORGE_TRANSPORT_TEST_ROOT";
const TEST_TIMEOUT: Duration = Duration::from_secs(10);
const PROTOCOL_VERSION: u64 = 1;
const ACCEPTED: u64 = 1;
const REJECTED: u64 = 2;
const UNRELATED_FD_LEAKED: u64 = 3;

struct LaunchdJob {
    target: String,
}

struct FixtureChild(Child);

impl Drop for LaunchdJob {
    fn drop(&mut self) {
        let _ = Command::new("/bin/launchctl")
            .args(["bootout", &self.target])
            .output();
    }
}

impl Drop for FixtureChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
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
    let unrelated = File::create(temporary.path().join("unrelated-parent-file"))
        .expect("unrelated descriptor fixture");
    native::make_inheritable(unrelated.as_raw_fd()).expect("inheritable parent-only descriptor");
    let unrelated_metadata = unrelated.metadata().expect("descriptor object identity");
    let _job = bootstrap_helper(
        temporary.path(),
        &service,
        owner,
        "launchd_transport_helper",
    );
    let executable = std::env::current_exe().expect("test executable");
    let helper_log = temporary.path().join("helper.log");

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
    request.describe_unrelated_fd(
        unrelated.as_raw_fd(),
        unrelated_metadata.dev(),
        unrelated_metadata.ino(),
    );
    let reply = client.request(&request).expect("authenticated FD transfer");
    assert_eq!(reply.number(c"version"), PROTOCOL_VERSION);
    assert_eq!(reply.number(c"result"), ACCEPTED);
    assert_eq!(
        fs::read(&output_path).expect("helper FD output"),
        b"fd-proof"
    );
}

#[test]
fn helper_retains_the_ingress_port_after_parent_death_until_owned_process_exit() {
    let temporary = TempDir::new().expect("lifecycle fixture root");
    let root = temporary.path();
    let service = format!(
        "cageforge-test-port-{}-{}",
        std::process::id(),
        root.file_name().expect("unique fixture").to_string_lossy()
    );
    // The outer controller owns removal even when the application is killed
    // without running its Drop implementations.
    let _job = LaunchdJob {
        target: format!("user/{}/{service}", native::user_id()),
    };
    let mut parent = FixtureChild(
        Command::new(std::env::current_exe().expect("fixture executable"))
            .args(["--exact", "launchd_transport_parent", "--nocapture"])
            .env(SERVICE_ENV, &service)
            .env(ROOT_ENV, root)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(File::create(root.join("parent.log")).expect("parent diagnostics"))
            .spawn()
            .expect("own application fixture"),
    );
    wait_for_marker(root, "ready");
    let address: SocketAddr = fs::read_to_string(root.join("ready"))
        .expect("published listener address")
        .parse()
        .expect("native listener address");
    assert!(parent.0.try_wait().expect("parent state").is_none());
    parent.0.kill().expect("abrupt application death");
    parent.0.wait().expect("confirm application death");
    wait_for_marker(root, "owner-gone");
    assert_eq!(
        TcpListener::bind(address)
            .expect_err("helper must retain the authorized port during cleanup")
            .kind(),
        io::ErrorKind::AddrInUse
    );
    // Hold the cleanup at a deterministic stage, instead of trying to hit a
    // millisecond race between parent exit and the helper's child termination.
    fs::write(root.join("release-cleanup"), b"terminate").expect("release helper cleanup");
    wait_for_marker(root, "complete");
    let _reused = TcpListener::bind(address).expect("port reusable after confirmed child exit");
}

#[test]
fn launchd_transport_parent() {
    let Ok(service) = std::env::var(SERVICE_ENV) else {
        return;
    };
    let root = fixture_root();
    let owner = native::own_identity().expect("owner identity");
    let _job = bootstrap_helper(&root, &service, owner, "launchd_transport_lifecycle_helper");
    let reservation = TcpListener::bind(("127.0.0.1", 0)).expect("fixture ingress");
    let client = native::Connection::client(&CString::new(service).expect("service name"));
    let request = native::Message::request(owner, Some(reservation.as_raw_fd()));
    let reply = client
        .request(&request)
        .expect("transfer listener reservation");
    assert_eq!(reply.number(c"version"), PROTOCOL_VERSION);
    assert_eq!(reply.number(c"result"), ACCEPTED);
    fs::write(
        root.join("ready.staging"),
        reservation.local_addr().expect("bound address").to_string(),
    )
    .expect("stage ready marker");
    fs::rename(root.join("ready.staging"), root.join("ready")).expect("publish ready marker");
    std::thread::sleep(TEST_TIMEOUT * 2);
}

#[test]
fn launchd_transport_lifecycle_helper() {
    let Ok(service) = std::env::var(SERVICE_ENV) else {
        return;
    };
    let root = fixture_root();
    let owner = declared_owner();
    let (sender, receiver) = mpsc::sync_channel(2);
    let _listener = native::Connection::listener(&CString::new(service).expect("service"), sender);
    let mut peers = Vec::new();
    let deadline = Instant::now() + TEST_TIMEOUT;
    let request = loop {
        match receiver
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .expect("authorized application request")
        {
            native::Event::Peer(peer) => peers.push(peer),
            native::Event::Message(message) => {
                if message.sender_identity() == owner
                    && message.number(c"version") == PROTOCOL_VERSION
                {
                    break message;
                }
                message.reply(REJECTED).expect("reject unrelated peer");
            }
        }
    };
    let reservation = request.take_fd().expect("receive port reservation");
    native::make_close_on_exec(reservation.as_raw_fd()).expect("helper-only reservation");
    let mut child = FixtureChild(
        Command::new(std::env::current_exe().expect("fixture executable"))
            .args([
                "--exact",
                "launchd_transport_lifecycle_child",
                "--nocapture",
            ])
            .env(ROOT_ENV, &root)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("owned finite child"),
    );
    wait_for_marker(&root, "child-ready");
    request
        .reply(ACCEPTED)
        .expect("confirm acquired reservation");
    let deadline = Instant::now() + TEST_TIMEOUT;
    while native::process_identity(owner.0).expect("query actual owner identity") == Some(owner) {
        assert!(Instant::now() < deadline, "application did not terminate");
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(child.0.try_wait().expect("child is still active").is_none());
    fs::write(root.join("owner-gone"), b"reservation retained").expect("cleanup stage marker");
    wait_for_marker(&root, "release-cleanup");
    child.0.kill().expect("terminate owned child");
    child.0.wait().expect("confirm owned child exit");
    drop(reservation);
    // XPC dictionaries retain the descriptor object as well. Release the
    // received message before asserting that the port can be reused.
    drop(request);
    fs::write(root.join("complete"), b"resources released").expect("completed cleanup marker");
}

#[test]
fn launchd_transport_lifecycle_child() {
    if std::env::var_os(ROOT_ENV).is_none() {
        return;
    }
    // This transport test owns a direct child; detached grandchildren are
    // exercised by the independent coalition test, not claimed by this one.
    #[allow(unsafe_code)]
    let session = unsafe { libc::setsid() };
    assert!(session > 0, "start independent child session");
    fs::write(fixture_root().join("child-ready"), b"active").expect("child readiness");
    std::thread::sleep(TEST_TIMEOUT * 2);
}

fn bootstrap_helper(root: &Path, service: &str, owner: (u32, u32), fixture: &str) -> LaunchdJob {
    let domain = format!("user/{}", native::user_id());
    let job = LaunchdJob {
        target: format!("{domain}/{service}"),
    };
    let executable = std::env::current_exe().expect("fixture executable");
    let helper_log = root.join("helper.log");
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>{service}</string>
<key>ProgramArguments</key><array><string>{executable}</string>
<string>--exact</string><string>{fixture}</string><string>--nocapture</string></array>
<key>EnvironmentVariables</key><dict>
<key>{SERVICE_ENV}</key><string>{service}</string>
<key>{OWNER_ENV}</key><string>{pid}:{version}</string>
<key>{ROOT_ENV}</key><string>{root}</string></dict>
<key>MachServices</key><dict><key>{service}</key><true/></dict>
<key>LimitLoadToSessionType</key><string>Background</string>
<key>RunAtLoad</key><true/>
<key>StandardOutPath</key><string>{log}</string>
<key>StandardErrorPath</key><string>{log}</string>
</dict></plist>"#,
        executable = xml_text(executable.to_str().expect("UTF-8 test executable")),
        pid = owner.0,
        version = owner.1,
        log = xml_text(helper_log.to_str().expect("UTF-8 helper log")),
        root = xml_text(root.to_str().expect("UTF-8 fixture root")),
    );
    let plist_path = root.join("helper.plist");
    fs::write(&plist_path, plist).expect("write owned launchd fixture");
    let validation = Command::new("/usr/bin/plutil")
        .arg("-lint")
        .arg(&plist_path)
        .output()
        .expect("validate native plist");
    assert!(
        validation.status.success(),
        "plist validation: {validation:?}"
    );
    let bootstrap = Command::new("/bin/launchctl")
        .args(["bootstrap", &domain])
        .arg(&plist_path)
        .output()
        .expect("bootstrap user Mach service");
    if !bootstrap.status.success() {
        let metadata = fs::metadata(&plist_path).expect("fixture plist metadata");
        eprintln!(
            "plist uid={} gid={} mode={:o}; caller uid={}",
            metadata.uid(),
            metadata.gid(),
            metadata.mode(),
            native::user_id()
        );
        for scope in [&domain, &format!("gui/{}", native::user_id())] {
            let state = Command::new("/bin/launchctl")
                .args(["print", scope])
                .output()
                .expect("inspect available bootstrap domain");
            // Do not dump domain environments or other users' job definitions.
            eprintln!("bootstrap domain {scope}: {}", state.status);
        }
        let predicate = format!("process == 'launchd' AND eventMessage CONTAINS '{service}'");
        let log = Command::new("/usr/bin/log")
            .args([
                "show",
                "--last",
                "1m",
                "--style",
                "compact",
                "--predicate",
                &predicate,
            ])
            .output()
            .expect("read diagnostics for this fixture label only");
        panic!("bootstrap: {bootstrap:?}; scoped launchd log: {log:?}");
    }

    job
}

fn fixture_root() -> PathBuf {
    std::env::var_os(ROOT_ENV).expect("fixture root").into()
}

fn wait_for_marker(root: &Path, marker: &str) {
    let deadline = Instant::now() + TEST_TIMEOUT;
    while !root.join(marker).exists() {
        assert!(
            Instant::now() < deadline,
            "missing {marker}; parent: {:?}; helper: {:?}",
            fs::read_to_string(root.join("parent.log")),
            fs::read_to_string(root.join("helper.log")),
        );
        std::thread::sleep(Duration::from_millis(5));
    }
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
                if authorized && message.has_unrelated_fd() {
                    message
                        .reply(UNRELATED_FD_LEAKED)
                        .expect("report descriptor leak");
                    return;
                }
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

        pub fn describe_unrelated_fd(&self, fd: RawFd, device: u64, inode: u64) {
            // Send identity metadata only, not an XPC descriptor object.
            unsafe {
                xpc_dictionary_set_uint64(self.0.0, c"unrelated-fd".as_ptr(), fd as u64);
                xpc_dictionary_set_uint64(self.0.0, c"unrelated-device".as_ptr(), device);
                xpc_dictionary_set_uint64(self.0.0, c"unrelated-inode".as_ptr(), inode);
            }
        }

        pub fn has_unrelated_fd(&self) -> bool {
            let fd = RawFd::try_from(self.number(c"unrelated-fd")).expect("fixture FD number");
            let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
            if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
                return false;
            }
            let stat = unsafe { stat.assume_init() };
            // An unrelated object reusing the same numeric FD is not a leak.
            stat.st_dev as u64 == self.number(c"unrelated-device")
                && stat.st_ino == self.number(c"unrelated-inode")
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
        process_identity(std::process::id())?.ok_or_else(|| io::ErrorKind::NotFound.into())
    }

    pub fn process_identity(pid: u32) -> io::Result<Option<(u32, u32)>> {
        let mut info = NativeIdentity::default();
        let size = std::mem::size_of::<NativeIdentity>() as libc::c_int;
        let written = unsafe {
            libc::proc_pidinfo(
                pid as libc::pid_t,
                PROC_PIDUNIQIDENTIFIERINFO,
                0,
                (&mut info as *mut NativeIdentity).cast(),
                size,
            )
        };
        if written <= 0 {
            let error = io::Error::last_os_error();
            return if error.raw_os_error() == Some(libc::ESRCH) {
                Ok(None)
            } else {
                Err(error)
            };
        }
        if written != size {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(Some((pid, info.version as u32)))
    }

    pub fn user_id() -> u32 {
        unsafe { libc::geteuid() }
    }

    pub fn make_inheritable(fd: RawFd) -> io::Result<()> {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub fn make_close_on_exec(fd: RawFd) -> io::Result<()> {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}
