// SPDX-License-Identifier: Apache-2.0

//! Per-launch unprivileged launchd service and authenticated process owner.

use std::{
    ffi::CString,
    fs::{self, File},
    io,
    os::fd::{AsRawFd, OwnedFd},
    os::unix::{
        fs::{OpenOptionsExt, PermissionsExt},
        process::{CommandExt, ExitStatusExt},
    },
    path::{Path, PathBuf},
    process::{ChildStderr, ChildStdin, ChildStdout, Command, ExitCode, ExitStatus, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use cageforge_command::{StdioMode, StdioSpec};
use thiserror::Error;

#[path = "launchd/storage.rs"]
mod storage;
pub use storage::StorageError;

use super::{
    coalition::{Coalition, CoalitionError},
    identity::ProcessIdentity,
    protocol::{self, Launch, ProtocolError, Request, Response, Stage},
    transport::{self, Connection, FieldError, Message},
};
use crate::network::GatewayRuntime;

pub(crate) const HELPER_NAME: &str = "cageforge-macos-helper";
/// Internal binary dispatch argument for applications embedding the macOS helper.
pub const MACOS_HELPER_ARGUMENT: &str = "--cageforge-macos-helper";
const LAUNCHCTL: &str = "/bin/launchctl";
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(5);
const RECOVERY_INTERVAL: Duration = Duration::from_secs(1);
const RECOVERY_THREAD_NAME: &str = "cageforge-macos-coalition-recovery";

pub(crate) struct Session {
    resources: Option<Resources>,
    streams: Streams,
    pid: u32,
    completed: Option<(ExitStatus, bool)>,
}

struct Resources {
    connection: Option<Connection>,
    coalition: Coalition,
    job: Option<Job>,
    gateway: Option<GatewayRuntime>,
    finished: bool,
}

struct Streams {
    stdin: Option<ChildStdin>,
    stdout: Option<ChildStdout>,
    stderr: Option<ChildStderr>,
}

struct Job {
    root: storage::Directory,
    target: String,
    service: CString,
    removed: bool,
}

struct HelperBoundary {
    coalition: Coalition,
    child: Option<std::process::Child>,
    reservation: Option<File>,
    deadline: Option<Instant>,
    completion: Option<(i32, bool)>,
    stopping: bool,
    cleaned: bool,
}

/// Failure while registering, authenticating, or supervising a per-launch helper.
#[derive(Debug, Error)]
pub enum LaunchError {
    /// Owned registration files could not be acquired or safely removed.
    #[error(transparent)]
    Storage(#[from] StorageError),
    /// A native operation failed with its original operating-system error.
    #[error("macOS helper {operation:?} failed: {source}")]
    Io {
        /// Operation being performed.
        operation: Operation,
        /// Original operating-system failure.
        source: io::Error,
    },
    /// Command framing or portable validation failed.
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    /// The native XPC message had a missing, mistyped, or oversized field.
    #[error(transparent)]
    Field(#[from] FieldError),
    /// Kernel ownership acquisition, accounting, or termination failed.
    #[error(transparent)]
    Coalition(#[from] CoalitionError),
    /// A per-instance gateway failed; its resources remain owned until cleanup.
    #[error(transparent)]
    Gateway(#[from] crate::error::MacosNetworkError),
    /// The selected helper could not be safely registered with launchd.
    #[error("helper executable path is not a UTF-8 regular absolute file: {path:?}")]
    HelperPath {
        /// Rejected executable path.
        path: PathBuf,
    },
    /// The launchd control program reported failure.
    #[error("launchctl {operation:?} failed: {status}")]
    Launchctl {
        /// Registration or removal operation.
        operation: Operation,
        /// Native control-program exit status.
        status: ExitStatus,
    },
    /// A bounded setup, transport, or cleanup operation did not complete.
    #[error("macOS helper {operation:?} exceeded its deadline")]
    Timeout {
        /// Operation whose deadline expired.
        operation: Operation,
    },
    /// The helper response was incompatible with the current launch phase.
    #[error("macOS helper returned a response incompatible with the current launch phase")]
    UnexpectedResponse,
    /// The authenticated helper reported an operational failure.
    #[error("macOS helper failed at {stage:?} (native code {native_code:?}): {detail}")]
    Remote {
        /// Failed helper lifecycle stage.
        stage: Stage,
        /// Original native errno, when the failure came from an OS call.
        native_code: Option<i32>,
        /// Supplemental diagnostic; it is not interpreted as authorization.
        detail: String,
    },
    /// Ownership has moved to the recovery worker.
    #[error("the macOS helper command is owned by recovery")]
    RecoveryOwned,
}

/// Native operation associated with a macOS helper error.
#[derive(Debug)]
pub enum Operation {
    /// Validate the helper executable and launch configuration.
    Configuration,
    /// Authenticate a kernel PID generation.
    Identity,
    /// Register a per-launch job.
    Bootstrap,
    /// Remove the per-launch job.
    Bootout,
    /// Exchange an authenticated control message.
    Transport,
    /// Create or transfer explicit standard-stream descriptors.
    StandardStreams,
    /// Start the already-lowered Seatbelt command.
    ProcessStart,
    /// Collect the direct command's exit status.
    ProcessWait,
    /// Terminate all coalition members and release enforcement resources.
    Cleanup,
}

impl Session {
    pub(crate) fn launch(
        helper: &Path,
        command: &Command,
        timeout: Option<Duration>,
        stdio: &StdioSpec,
        gateway: Option<GatewayRuntime>,
    ) -> Result<Self, LaunchError> {
        // Encode before registration, so a rejected payload creates no job.
        let payload = protocol::encode(Request::Launch(Launch::capture(command, timeout)?))?;
        let (streams, child_streams) =
            Streams::prepare(stdio).map_err(|source| fail(Operation::StandardStreams, source))?;
        let owner = current_identity()?;
        let job = Job::start(helper, &owner)?;
        let connection = Connection::client(&job.service)
            .map_err(|source| fail(Operation::Transport, source))?;
        let hello = exchange(&connection, Request::Hello)?;
        let identity = hello.sender_identity();
        let helper_identity = ProcessIdentity::authenticated(identity.0, identity.1)
            .map_err(|source| fail(Operation::Identity, source))?;
        let coalition = Coalition::from_authenticated_helper(helper_identity)?;
        if !matches!(decode_response(&hello)?, Response::Ready) {
            return Err(LaunchError::UnexpectedResponse);
        }
        let mut session = Self {
            resources: Some(Resources {
                connection: Some(connection),
                coalition,
                job: Some(job),
                gateway,
                finished: false,
            }),
            streams,
            pid: 0,
            completed: None,
        };
        // Session owns recovery before the request can start an untrusted
        // process, including a timeout while the launch response is in flight.
        let resources = session
            .resources
            .as_ref()
            .ok_or(LaunchError::RecoveryOwned)?;
        let mut request =
            transport::Request::new().map_err(|source| fail(Operation::Transport, source))?;
        request.set_data(c"payload", &payload)?;
        for (key, file) in [c"stdin", c"stdout", c"stderr"]
            .into_iter()
            .zip(&child_streams)
        {
            request.set_fd(key, file.as_raw_fd());
        }
        request.set_number(c"has-reservation", u64::from(resources.gateway.is_some()));
        if let Some(gateway) = resources.gateway.as_ref() {
            request.set_fd(c"reservation", gateway.reservation_fd());
        }
        let connection = resources
            .connection
            .as_ref()
            .ok_or(LaunchError::RecoveryOwned)?;
        let reply = connection
            .request(request)
            .map_err(|source| fail(Operation::Transport, source))?;
        match decode_response(&reply)? {
            Response::Running { pid } => session.pid = pid,
            _ => return Err(LaunchError::UnexpectedResponse),
        }
        // The helper has adopted the only writer copies intended for the
        // command. Neither the caller nor its XPC request retains these FDs.
        drop(child_streams);
        Ok(session)
    }

    pub(crate) fn id(&self) -> u32 {
        self.pid
    }
    pub(crate) fn stdin(&mut self) -> Option<&mut ChildStdin> {
        self.streams.stdin.as_mut()
    }
    pub(crate) fn stdout(&mut self) -> Option<&mut ChildStdout> {
        self.streams.stdout.as_mut()
    }
    pub(crate) fn stderr(&mut self) -> Option<&mut ChildStderr> {
        self.streams.stderr.as_mut()
    }

    pub(crate) fn try_wait(&mut self) -> Result<Option<(ExitStatus, bool)>, LaunchError> {
        if let Some(completed) = self.completed {
            return Ok(Some(completed));
        }
        let resources = self.resources.as_mut().ok_or(LaunchError::RecoveryOwned)?;
        if let Some(gateway) = resources.gateway.as_mut() {
            gateway.check_health()?;
        }
        let connection = resources
            .connection
            .as_ref()
            .ok_or(LaunchError::RecoveryOwned)?;
        let reply = exchange(connection, Request::Poll)?;
        match decode_response(&reply)? {
            Response::Running { .. } => Ok(None),
            Response::Exited {
                raw_status,
                timed_out,
            } => {
                let result = (ExitStatus::from_raw(raw_status), timed_out);
                resources.finish()?;
                self.completed = Some(result);
                self.streams = Streams::empty();
                Ok(Some(result))
            }
            _ => Err(LaunchError::UnexpectedResponse),
        }
    }

    pub(crate) fn kill(&mut self) -> Result<(), LaunchError> {
        let Some(resources) = self.resources.as_mut() else {
            return Ok(());
        };
        if resources.finished {
            return Ok(());
        }
        // Do not depend on an answering helper to terminate its coalition.
        resources.finish()?;
        self.streams = Streams::empty();
        Ok(())
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let Some(mut resources) = self.resources.take() else {
            return;
        };
        if resources.finished {
            return;
        }
        // No blocking launchctl, XPC wait, or gateway join in the API Drop.
        // On thread creation failure Resources::drop retains all guards.
        let _ = thread::Builder::new()
            .name(RECOVERY_THREAD_NAME.to_owned())
            .spawn(move || {
                while resources.finish().is_err() {
                    thread::sleep(RECOVERY_INTERVAL);
                }
            });
    }
}

impl Resources {
    fn finish(&mut self) -> Result<(), LaunchError> {
        if self.finished {
            return Ok(());
        }
        // Stop new launchd activations before accepting an empty coalition.
        // A remaining Mach service could otherwise recreate its helper after
        // a transient zero-task observation. Still attempt termination when
        // deregistration fails; retain ownership and report that failure.
        self.connection = None;
        let removal = self.job.as_mut().map(Job::remove).transpose();
        let deadline = Instant::now() + CLEANUP_TIMEOUT;
        while !self.coalition.terminate_round(false)? {
            if Instant::now() >= deadline {
                return Err(LaunchError::Timeout {
                    operation: Operation::Cleanup,
                });
            }
            thread::sleep(POLL_INTERVAL);
        }
        removal?;
        if let Some(gateway) = self.gateway.as_mut() {
            gateway.shutdown()?;
        }
        self.gateway = None;
        self.connection = None;
        if let Some(job) = self.job.as_ref() {
            job.root.cleanup()?;
        }
        self.finished = true;
        Ok(())
    }
}

impl Drop for Resources {
    fn drop(&mut self) {
        if !self.finished {
            std::mem::forget(self.gateway.take());
            std::mem::forget(self.job.take());
            std::mem::forget(self.connection.take());
        }
    }
}

impl Streams {
    fn empty() -> Self {
        Self {
            stdin: None,
            stdout: None,
            stderr: None,
        }
    }

    fn prepare(spec: &StdioSpec) -> io::Result<(Self, [File; 3])> {
        let (stdin, child_in) = input(spec.stdin())?;
        let (stdout, child_out) = output(spec.stdout(), libc::STDOUT_FILENO)?;
        let (stderr, child_err) = output(spec.stderr(), libc::STDERR_FILENO)?;
        Ok((
            Self {
                stdin: stdin.map(ChildStdin::from),
                stdout: stdout.map(ChildStdout::from),
                stderr: stderr.map(ChildStderr::from),
            },
            [child_in, child_out, child_err],
        ))
    }
}

impl Job {
    fn start(helper: &Path, owner: &ProcessIdentity) -> Result<Self, LaunchError> {
        let metadata = fs::symlink_metadata(helper)
            .map_err(|source| fail(Operation::Configuration, source))?;
        let helper_text = helper
            .to_str()
            .filter(|_| {
                helper.is_absolute() && metadata.is_file() && !metadata.file_type().is_symlink()
            })
            .ok_or_else(|| LaunchError::HelperPath {
                path: helper.to_path_buf(),
            })?;
        let root = tempfile::Builder::new()
            .prefix("cageforge-macos-launch-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .map_err(|source| fail(Operation::Bootstrap, source))?;
        let suffix = root
            .path()
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(LaunchError::UnexpectedResponse)?;
        let service_text = format!("dev.cageforge.{suffix}");
        let service =
            CString::new(service_text.as_bytes()).map_err(|_| LaunchError::UnexpectedResponse)?;
        #[allow(unsafe_code)]
        let target = format!("user/{}/{service_text}", unsafe { libc::geteuid() });
        let args = [
            helper_text.to_owned(),
            MACOS_HELPER_ARGUMENT.to_owned(),
            service_text.clone(),
            owner.pid().to_string(),
            owner.version().to_string(),
            target.clone(),
            root.path()
                .to_str()
                .ok_or(LaunchError::UnexpectedResponse)?
                .to_owned(),
        ];
        let arguments = args
            .iter()
            .map(|arg| format!("<string>{}</string>", xml(arg)))
            .collect::<String>();
        let log = root.path().join(storage::LOG_NAME);
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&log)
            .map_err(|source| fail(Operation::Bootstrap, source))?;
        let log = log.to_str().ok_or(LaunchError::UnexpectedResponse)?;
        let plist = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\"><dict><key>Label</key><string>{service_text}</string><key>ProgramArguments</key><array>{arguments}</array><key>MachServices</key><dict><key>{service_text}</key><true/></dict><key>LimitLoadToSessionType</key><string>Background</string><key>RunAtLoad</key><true/><key>StandardOutPath</key><string>{}</string><key>StandardErrorPath</key><string>{}</string></dict></plist>",
            xml(log),
            xml(log)
        );
        let path = root.path().join(storage::PLIST_NAME);
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|source| fail(Operation::Bootstrap, source))?;
        io::Write::write_all(&mut file, plist.as_bytes())
            .map_err(|source| fail(Operation::Bootstrap, source))?;
        let directory = storage::Directory::capture(root.path())?;
        // From this point cleanup is non-recursive and checks recorded inode
        // identities. TempDir must not remove unexpected command-created data.
        let _ = root.keep();
        let mut job = Self {
            root: directory,
            target,
            service,
            removed: false,
        };
        let domain = job
            .target
            .rsplit_once('/')
            .ok_or(LaunchError::UnexpectedResponse)?
            .0;
        let result = launchctl(
            &["bootstrap".as_ref(), domain.as_ref(), path.as_os_str()],
            Operation::Bootstrap,
        );
        if result.is_err() {
            let _ = job.remove();
        }
        result?;
        Ok(job)
    }

    fn remove(&mut self) -> Result<(), LaunchError> {
        if self.removed {
            return Ok(());
        }
        launchctl(
            &["bootout".as_ref(), self.target.as_ref()],
            Operation::Bootout,
        )?;
        self.removed = true;
        Ok(())
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        if self.remove().is_ok() {
            let _ = self.root.cleanup();
        }
    }
}

impl HelperBoundary {
    fn new(coalition: Coalition) -> Self {
        Self {
            coalition,
            child: None,
            reservation: None,
            deadline: None,
            completion: None,
            stopping: false,
            cleaned: false,
        }
    }

    fn launch(&mut self, launch: Launch, message: &Message) -> Result<u32, LaunchError> {
        let (mut command, timeout) = launch.into_command()?;
        let stdin = message
            .take_fd(c"stdin")
            .map_err(|source| fail(Operation::StandardStreams, source))?;
        let stdout = message
            .take_fd(c"stdout")
            .map_err(|source| fail(Operation::StandardStreams, source))?;
        let stderr = message
            .take_fd(c"stderr")
            .map_err(|source| fail(Operation::StandardStreams, source))?;
        self.reservation = match message.number(c"has-reservation")? {
            0 => None,
            1 => Some(
                message
                    .take_fd(c"reservation")
                    .map_err(|source| fail(Operation::Transport, source))?,
            ),
            _ => return Err(LaunchError::UnexpectedResponse),
        };
        self.deadline = timeout
            .map(|timeout| {
                Instant::now()
                    .checked_add(timeout)
                    .ok_or(LaunchError::Timeout {
                        operation: Operation::Configuration,
                    })
            })
            .transpose()?;
        command.stdin(stdin).stdout(stdout).stderr(stderr);
        #[allow(unsafe_code)]
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                super::close_inherited_fds_except(&[])
            });
        }
        let child = command
            .spawn()
            .map_err(|source| fail(Operation::ProcessStart, source))?;
        let pid = child.id();
        self.child = Some(child);
        Ok(pid)
    }

    fn advance(&mut self) -> Result<(), LaunchError> {
        if self.cleaned {
            return Ok(());
        }
        let expired = self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline);
        if expired {
            self.stopping = true;
        }
        if self.completion.is_none()
            && let Some(child) = self.child.as_mut()
            && let Some(status) = child
                .try_wait()
                .map_err(|source| fail(Operation::ProcessWait, source))?
        {
            self.completion = Some((status.into_raw(), expired));
            self.stopping = true;
        }
        if self.stopping && self.coalition.terminate_round(true)? {
            // No untrusted task remains. Reaping the direct child is now
            // nonblocking; its cached status remains valid across retries.
            if self.completion.is_none()
                && let Some(child) = self.child.as_mut()
            {
                if let Some(status) = child
                    .try_wait()
                    .map_err(|source| fail(Operation::ProcessWait, source))?
                {
                    self.completion = Some((status.into_raw(), expired));
                } else {
                    return Ok(());
                }
            }
            self.child = None;
            self.reservation = None;
            self.cleaned = true;
        }
        Ok(())
    }

    fn response(&self) -> Response {
        if self.cleaned
            && let Some((raw_status, timed_out)) = self.completion
        {
            return Response::Exited {
                raw_status,
                timed_out,
            };
        }
        Response::Running {
            pid: self.child.as_ref().map_or(0, std::process::Child::id),
        }
    }
}

impl Drop for HelperBoundary {
    fn drop(&mut self) {
        // This runs only in the isolated trusted helper process, never in the
        // application's Drop. A failed cleanup keeps the port reservation.
        self.stopping = true;
        while !self.cleaned {
            let _ = self.advance();
            if !self.cleaned {
                thread::sleep(RECOVERY_INTERVAL);
            }
        }
    }
}

/// Runs the internal launchd helper selected by the backend or embedded CLI.
/// This is a binary adapter, not an alternate unsandboxed command-launch API.
pub fn helper_entry() -> ExitCode {
    let result = serve();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // serve attempts a structured response for every established
            // exchange. This line is only bootstrap/direct-invocation output.
            eprintln!("{HELPER_NAME}: {error}");
            ExitCode::from(125)
        }
    }
}

fn serve() -> Result<(), LaunchError> {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    let [mode, service, owner_pid, owner_version, target, root] = arguments.as_slice() else {
        return Err(LaunchError::UnexpectedResponse);
    };
    if mode != MACOS_HELPER_ARGUMENT {
        return Err(LaunchError::UnexpectedResponse);
    }
    let pid = owner_pid
        .to_str()
        .and_then(|value| value.parse::<u32>().ok())
        .ok_or(LaunchError::UnexpectedResponse)?;
    let version = owner_version
        .to_str()
        .and_then(|value| value.parse::<u32>().ok())
        .ok_or(LaunchError::UnexpectedResponse)?;
    let owner = ProcessIdentity::authenticated(pid, version)
        .map_err(|source| fail(Operation::Identity, source))?;
    let owner_id = (pid, version);
    let service = CString::new(std::os::unix::ffi::OsStrExt::as_bytes(service.as_os_str()))
        .map_err(|_| LaunchError::UnexpectedResponse)?;
    let coalition = Coalition::from_authenticated_parent(owner)?;
    // Capture exact file identities before accepting any untrusted command.
    // This owner lives outside the application's address space and therefore
    // survives its SIGKILL without relying on application destructors.
    let directory = storage::Directory::capture(Path::new(root))?;
    let (sender, receiver) = mpsc::sync_channel(8);
    let listener = Connection::authenticated_listener(&service, sender, owner_id)
        .map_err(|source| fail(Operation::Transport, source))?;
    let mut peers = Vec::new();
    let mut boundary = HelperBoundary::new(coalition);
    let mut introduced = false;
    let mut launched = false;
    let mut pending_error = None;
    let startup_deadline = Instant::now() + transport::EXCHANGE_TIMEOUT;
    loop {
        let parent_alive = ProcessIdentity::authenticated(pid, version).is_ok();
        if !parent_alive || (!launched && Instant::now() >= startup_deadline) {
            boundary.stopping = true;
        }
        if let Err(error) = boundary.advance() {
            boundary.stopping = true;
            // Report through the next authenticated exchange. Failed native
            // observation is not completion and must not release reservations.
            pending_error.get_or_insert(error);
        }
        if boundary.cleaned && (!parent_alive || !launched) {
            break;
        }
        match receiver.recv_timeout(POLL_INTERVAL) {
            Ok(transport::Event::Peer(peer)) => {
                if peers.len() < 2 {
                    peers.push(peer);
                }
            }
            Ok(transport::Event::Message(message)) => {
                let result = if let Some(error) = pending_error.take() {
                    Err(error)
                } else {
                    handle_message(
                        &message,
                        owner_id,
                        &mut boundary,
                        &mut introduced,
                        &mut launched,
                    )
                };
                let response = match result {
                    Ok(response) => response,
                    Err(error) => {
                        boundary.stopping = true;
                        Response::Failed {
                            stage: failure_stage(&error),
                            native_code: native_code(&error),
                            detail: error.to_string(),
                        }
                    }
                };
                let encoded = protocol::encode(response)?;
                if let Err(source) = message.reply_data(&encoded) {
                    boundary.stopping = true;
                    return Err(fail(Operation::Transport, source));
                }
                // Dropping the original dictionary here releases its copies
                // of command stdout/stderr, independent of child stdio copies.
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                boundary.stopping = true;
            }
        }
    }
    drop(boundary);
    drop(peers);
    drop(listener);
    if let Err(error) = directory.cleanup() {
        // The owning application is gone, so no authenticated reporting
        // channel remains. Preserve unfamiliar files, but still deregister
        // the now-empty job instead of leaving an activatable Mach service.
        eprintln!("{HELPER_NAME}: {error}");
    }
    // Replace this last trusted task only after all untrusted tasks are gone;
    // do not create another descendant merely to remove the registered job.
    let source = Command::new(LAUNCHCTL)
        .arg("bootout")
        .arg(target)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .exec();
    Err(fail(Operation::Bootout, source))
}

fn handle_message(
    message: &Message,
    owner: (u32, u32),
    boundary: &mut HelperBoundary,
    introduced: &mut bool,
    launched: &mut bool,
) -> Result<Response, LaunchError> {
    if message.sender_identity() != owner
        || message.number(c"version")? != transport::PROTOCOL_VERSION
    {
        return Err(LaunchError::UnexpectedResponse);
    }
    match protocol::decode(message.data(c"payload")?)? {
        Request::Hello if !*launched && !boundary.stopping => {
            *introduced = true;
            Ok(Response::Ready)
        }
        Request::Launch(launch) if *introduced && !*launched && !boundary.stopping => {
            // Mark before any fallible spawn: retrying must not start a second
            // command after a partially delivered response.
            *launched = true;
            let pid = boundary.launch(launch, message)?;
            Ok(Response::Running { pid })
        }
        Request::Poll if *launched => Ok(boundary.response()),
        Request::Terminate if *launched => {
            boundary.stopping = true;
            Ok(boundary.response())
        }
        _ => Err(LaunchError::UnexpectedResponse),
    }
}

fn native_code(error: &LaunchError) -> Option<i32> {
    match error {
        LaunchError::Io { source, .. } => source.raw_os_error(),
        _ => None,
    }
}

fn failure_stage(error: &LaunchError) -> Stage {
    match error {
        LaunchError::Io {
            operation: Operation::ProcessStart,
            ..
        } => Stage::ProcessStart,
        LaunchError::Io {
            operation: Operation::ProcessWait,
            ..
        } => Stage::ProcessWait,
        LaunchError::Io {
            operation: Operation::Identity,
            ..
        } => Stage::Authentication,
        LaunchError::Coalition(_) => Stage::CoalitionCleanup,
        LaunchError::Timeout {
            operation: Operation::Configuration,
        } => Stage::Deadline,
        _ => Stage::Protocol,
    }
}

fn exchange(connection: &Connection, message: Request) -> Result<Message, LaunchError> {
    let mut request =
        transport::Request::new().map_err(|source| fail(Operation::Transport, source))?;
    request.set_data(c"payload", &protocol::encode(message)?)?;
    connection
        .request(request)
        .map_err(|source| fail(Operation::Transport, source))
}

fn decode_response(message: &Message) -> Result<Response, LaunchError> {
    if message.number(c"version")? != transport::PROTOCOL_VERSION {
        return Err(LaunchError::UnexpectedResponse);
    }
    let response = protocol::decode(message.data(c"payload")?)?;
    match response {
        Response::Failed {
            stage,
            native_code,
            detail,
        } => Err(LaunchError::Remote {
            stage,
            native_code,
            detail,
        }),
        response => Ok(response),
    }
}

fn fail(operation: Operation, source: io::Error) -> LaunchError {
    LaunchError::Io { operation, source }
}

fn current_identity() -> Result<ProcessIdentity, LaunchError> {
    ProcessIdentity::capture(std::process::id() as libc::pid_t)
        .map_err(|source| fail(Operation::Identity, source))?
        .ok_or_else(|| fail(Operation::Identity, io::ErrorKind::NotFound.into()))
}

fn launchctl(args: &[&std::ffi::OsStr], operation: Operation) -> Result<(), LaunchError> {
    let mut child = Command::new(LAUNCHCTL)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|source| fail(Operation::Bootstrap, source))?;
    let deadline = Instant::now() + CLEANUP_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(()),
            Ok(Some(status)) => return Err(LaunchError::Launchctl { operation, status }),
            Ok(None) => {}
            Err(source) => {
                let _ = child.kill();
                return Err(fail(operation, source));
            }
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            return Err(LaunchError::Timeout { operation });
        }
        thread::sleep(POLL_INTERVAL);
    }
}

fn input(mode: StdioMode) -> io::Result<(Option<OwnedFd>, File)> {
    match mode {
        StdioMode::Pipe => {
            let (read, write) = io::pipe()?;
            Ok((Some(write.into()), File::from(OwnedFd::from(read))))
        }
        StdioMode::Null => Ok((None, File::open("/dev/null")?)),
        StdioMode::Inherit => Ok((None, duplicate(libc::STDIN_FILENO)?)),
    }
}

fn output(mode: StdioMode, fd: libc::c_int) -> io::Result<(Option<OwnedFd>, File)> {
    match mode {
        StdioMode::Pipe => {
            let (read, write) = io::pipe()?;
            Ok((Some(read.into()), File::from(OwnedFd::from(write))))
        }
        StdioMode::Null => Ok((None, fs::OpenOptions::new().write(true).open("/dev/null")?)),
        StdioMode::Inherit => Ok((None, duplicate(fd)?)),
    }
}

#[allow(unsafe_code)]
fn duplicate(fd: libc::c_int) -> io::Result<File> {
    use std::os::fd::FromRawFd;
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(duplicate) })
}

fn xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
