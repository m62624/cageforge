// SPDX-License-Identifier: Apache-2.0

//! Native admission tests for the backend's launchd-owned helper transport.
//! Every job/client has a finite fixture lifetime.

#![cfg(target_os = "macos")]

use std::{
    ffi::CString,
    fs::{self, File},
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener},
    os::fd::AsRawFd,
    os::unix::fs::MetadataExt,
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant},
};

use tempfile::TempDir;

const SERVICE_ENV: &str = "CAGEFORGE_TRANSPORT_TEST_SERVICE";
const OWNER_ENV: &str = "CAGEFORGE_TRANSPORT_TEST_OWNER";
const ROOT_ENV: &str = "CAGEFORGE_TRANSPORT_TEST_ROOT";
#[path = "../src/process/transport.rs"]
mod transport;
use transport::{EXCHANGE_TIMEOUT, PROTOCOL_VERSION};
const TEST_TIMEOUT: Duration = EXCHANGE_TIMEOUT;
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
fn dropping_an_unsent_request_releases_its_descriptor_reservation() {
    // A TCP port is not an object identity: another test can claim it after
    // release, and an immediate rebind also depends on native TCP cleanup.
    // EOF on a private socket pair instead proves that the final reference to
    // exactly the transferred endpoint has been released. Keep a finite wait
    // for native teardown; a retained XPC reference must still fail this test.
    for iteration in 0..32 {
        let (endpoint, mut observer) = UnixStream::pair().expect("private descriptor pair");
        observer.set_nonblocking(true).expect("ownership probe");
        let mut request = transport::Request::new().expect("owned unsent request");
        request.set_fd(c"output", endpoint.as_raw_fd());
        drop(endpoint);
        let mut bytes = Vec::new();
        assert_eq!(
            observer
                .read_to_end(&mut bytes)
                .expect_err("the XPC request must own its duplicated descriptor")
                .kind(),
            io::ErrorKind::WouldBlock,
            "iteration {iteration}"
        );
        drop(request);
        let deadline = Instant::now() + TEST_TIMEOUT;
        loop {
            match observer.read_to_end(&mut bytes) {
                Ok(0) => break,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    assert!(
                        Instant::now() < deadline,
                        "request Drop retained its endpoint, iteration {iteration}: {error}"
                    );
                    std::thread::sleep(Duration::from_millis(1));
                }
                result => panic!("unexpected endpoint result, iteration {iteration}: {result:?}"),
            }
        }
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
    let client = transport::Connection::client(&CString::new(service).expect("service name"))
        .expect("create client");
    let mut request = fixture_request(owner, Some(output.as_raw_fd()));
    // Metadata only: do not attach the parent-only descriptor as an XPC FD.
    request.set_number(c"unrelated-fd", unrelated.as_raw_fd() as u64);
    request.set_number(c"unrelated-device", unrelated_metadata.dev());
    request.set_number(c"unrelated-inode", unrelated_metadata.ino());
    let reply = client.request(request).expect("authenticated FD transfer");
    assert_eq!(
        reply.number(c"version").expect("typed reply number"),
        PROTOCOL_VERSION
    );
    assert_eq!(
        u64::from_le_bytes(
            reply
                .data(c"payload")
                .expect("typed result bytes")
                .try_into()
                .expect("result length")
        ),
        ACCEPTED
    );
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
    let client = transport::Connection::client(&CString::new(service).expect("service name"))
        .expect("create client");
    let request = fixture_request(owner, Some(reservation.as_raw_fd()));
    let reply = client
        .request(request)
        .expect("transfer listener reservation");
    assert_eq!(
        reply.number(c"version").expect("typed reply number"),
        PROTOCOL_VERSION
    );
    assert_eq!(
        u64::from_le_bytes(
            reply
                .data(c"payload")
                .expect("typed result bytes")
                .try_into()
                .expect("result length")
        ),
        ACCEPTED
    );
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
    let _listener = transport::Connection::authenticated_listener(
        &CString::new(service).expect("service"),
        sender,
        owner,
    )
    .expect("listener");
    let mut peers = Vec::new();
    let deadline = Instant::now() + TEST_TIMEOUT;
    let request = loop {
        match receiver
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .expect("authorized application request")
        {
            transport::Event::Peer(peer) => peers.push(peer),
            transport::Event::Message(message) => {
                if message.sender_identity() == owner
                    && matches!(message.number(c"version"), Ok(PROTOCOL_VERSION))
                {
                    break message;
                }
                message
                    .reply_data(&REJECTED.to_le_bytes())
                    .expect("reject unrelated peer");
            }
        }
    };
    let reservation = request
        .take_fd(c"output")
        .expect("receive port reservation");
    assert!(native::is_close_on_exec(reservation.as_raw_fd()).expect("helper-only reservation"));
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
        .reply_data(&ACCEPTED.to_le_bytes())
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
    let connection = transport::Connection::client(&CString::new(service).expect("service name"))
        .expect("create client");
    let result = connection.request(fixture_request(owner, None));
    assert!(
        matches!(result, Err(error) if error.kind() == io::ErrorKind::ConnectionAborted),
        "an unrelated kernel identity must be disconnected before command admission"
    );
}

#[test]
fn launchd_transport_helper() {
    let Ok(service) = std::env::var(SERVICE_ENV) else {
        return;
    };
    let owner = declared_owner();
    let (sender, receiver) = mpsc::sync_channel(2);
    let _listener = transport::Connection::authenticated_listener(
        &CString::new(service).expect("service name"),
        sender,
        owner,
    )
    .expect("listener");
    let mut peers = Vec::new();
    let deadline = std::time::Instant::now() + TEST_TIMEOUT;
    loop {
        let event = receiver
            .recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
            .expect("bounded helper exchange");
        match event {
            transport::Event::Peer(peer) => peers.push(peer),
            transport::Event::Message(message) => {
                let actual = message.sender_identity();
                let authorized =
                    actual == owner && matches!(message.number(c"version"), Ok(PROTOCOL_VERSION));
                if authorized && native::has_unrelated_fd(&message) {
                    message
                        .reply_data(&UNRELATED_FD_LEAKED.to_le_bytes())
                        .expect("report descriptor leak");
                    return;
                }
                if authorized {
                    let mut output = message
                        .take_fd(c"output")
                        .expect("explicit FD in authorized request");
                    assert!(
                        native::is_close_on_exec(output.as_raw_fd()).expect("received FD flags")
                    );
                    output
                        .write_all(b"fd-proof")
                        .expect("write through explicit FD");
                }
                message
                    .reply_data(&(if authorized { ACCEPTED } else { REJECTED }).to_le_bytes())
                    .expect("flush typed response");
                if authorized {
                    return;
                }
            }
        }
    }
}

fn fixture_request(owner: (u32, u32), fd: Option<std::os::fd::RawFd>) -> transport::Request {
    let mut request = transport::Request::new().expect("request dictionary");
    request.set_number(c"claimed-pid", owner.0.into());
    request.set_number(c"claimed-generation", owner.1.into());
    if let Some(fd) = fd {
        request.set_fd(c"output", fd);
    }
    request
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
    use std::{io, os::fd::RawFd};
    const PROC_PIDUNIQIDENTIFIERINFO: libc::c_int = 17;
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

    pub fn is_close_on_exec(fd: RawFd) -> io::Result<bool> {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(flags & libc::FD_CLOEXEC != 0)
    }
    pub fn has_unrelated_fd(message: &super::transport::Message) -> bool {
        let fd = RawFd::try_from(
            message
                .number(c"unrelated-fd")
                .expect("fixture metadata number"),
        )
        .expect("fixture FD number");
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
            return false;
        }
        let stat = unsafe { stat.assume_init() };
        // An unrelated object reusing the same numeric FD is not a leak.
        stat.st_dev as u64
            == message
                .number(c"unrelated-device")
                .expect("fixture metadata number")
            && stat.st_ino
                == message
                    .number(c"unrelated-inode")
                    .expect("fixture metadata number")
    }
}
