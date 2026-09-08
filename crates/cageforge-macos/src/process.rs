// SPDX-License-Identifier: Apache-2.0

//! macOS process-group lifecycle for one Seatbelt child.

use std::io;
#[cfg(test)]
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::fd::{OwnedFd, RawFd};
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, ExitStatus};
use std::thread;
use std::time::{Duration, Instant};

use crate::error::MacosBackendError;
use crate::network::GatewayRuntime;

#[path = "process/coalition.rs"]
pub(crate) mod coalition;
#[path = "process/identity.rs"]
pub(crate) mod identity;
#[path = "process/launchd.rs"]
pub(crate) mod launchd;
#[path = "process/protocol.rs"]
pub(crate) mod protocol;
#[path = "process/timeout.rs"]
mod timeout;
#[path = "process/transport.rs"]
pub(crate) mod transport;

use identity::ProcessIdentity;
use timeout::TimeoutWatchdog;

const BOUNDARY_WAIT_TIMEOUT: Duration = Duration::from_secs(5);
const BOUNDARY_POLL_INTERVAL: Duration = Duration::from_millis(5);
const BOUNDARY_RECOVERY_INTERVAL: Duration = Duration::from_secs(1);
const BOUNDARY_RECOVERY_THREAD_NAME: &str = "cageforge-macos-boundary-recovery";
const PROCESS_GROUP_MEMBER_INITIAL_CAPACITY: usize = 16;
#[cfg(test)]
const PARENT_DEATH_FD: RawFd = libc::STDERR_FILENO + 1;

#[cfg(test)]
pub(crate) struct ParentDeathChannel {
    read: OwnedFd,
    write: OwnedFd,
}

/// A command running inside one macOS Seatbelt boundary.
pub struct MacosChild {
    session: Option<launchd::Session>,
    child: Option<Child>,
    child_reaped: bool,
    process_group_id: u32,
    parent_death: Option<OwnedFd>,
    gateway: Option<GatewayRuntime>,
    deadline: Option<Instant>,
    timeout_watchdog: Option<TimeoutWatchdog>,
    recovery_attempted: bool,
}

struct MacosBoundaryRecovery {
    child: Option<Child>,
    child_reaped: bool,
    process_group_id: u32,
    parent_death: Option<OwnedFd>,
    gateway: Option<GatewayRuntime>,
    timeout_watchdog: Option<TimeoutWatchdog>,
    completed: bool,
}

struct ProcessGroupTerminationError {
    child_reaped: bool,
    source: MacosBackendError,
}

impl cageforge_backend_api::SandboxChild for MacosChild {
    type Error = MacosBackendError;

    fn id(&self) -> u32 {
        MacosChild::id(self)
    }

    fn stdin(&mut self) -> Option<&mut dyn std::io::Write> {
        MacosChild::stdin(self).map(|stream| stream as &mut dyn std::io::Write)
    }

    fn stdout(&mut self) -> Option<&mut dyn std::io::Read> {
        MacosChild::stdout(self).map(|stream| stream as &mut dyn std::io::Read)
    }

    fn stderr(&mut self) -> Option<&mut dyn std::io::Read> {
        MacosChild::stderr(self).map(|stream| stream as &mut dyn std::io::Read)
    }

    fn try_wait(&mut self) -> Result<Option<ExitStatus>, Self::Error> {
        MacosChild::try_wait(self)
    }

    fn wait(&mut self) -> Result<ExitStatus, Self::Error> {
        MacosChild::wait(self)
    }

    fn kill(&mut self) -> Result<(), Self::Error> {
        MacosChild::kill(self)
    }
}

impl MacosChild {
    pub(crate) fn from_session(session: launchd::Session) -> Self {
        Self {
            session: Some(session),
            child: None,
            child_reaped: false,
            process_group_id: 0,
            parent_death: None,
            gateway: None,
            deadline: None,
            timeout_watchdog: None,
            recovery_attempted: false,
        }
    }

    /// Returns the process identifier of the Seatbelt boundary.
    pub fn id(&self) -> u32 {
        if let Some(session) = self.session.as_ref() {
            return session.id();
        }
        self.child.as_ref().map_or(0, Child::id)
    }

    /// Returns the child's standard input pipe, if one was requested.
    pub fn stdin(&mut self) -> Option<&mut ChildStdin> {
        if let Some(session) = self.session.as_mut() {
            return session.stdin();
        }
        self.child.as_mut().and_then(|child| child.stdin.as_mut())
    }

    /// Returns the child's standard output pipe, if one was requested.
    pub fn stdout(&mut self) -> Option<&mut ChildStdout> {
        if let Some(session) = self.session.as_mut() {
            return session.stdout();
        }
        self.child.as_mut().and_then(|child| child.stdout.as_mut())
    }

    /// Returns the child's standard error pipe, if one was requested.
    pub fn stderr(&mut self) -> Option<&mut ChildStderr> {
        if let Some(session) = self.session.as_mut() {
            return session.stderr();
        }
        self.child.as_mut().and_then(|child| child.stderr.as_mut())
    }

    /// Checks whether the boundary has exited, enforcing its timeout.
    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>, MacosBackendError> {
        if let Some(session) = self.session.as_mut() {
            return match session.try_wait()? {
                Some((_, true)) => Err(MacosBackendError::ProcessTimedOut),
                Some((status, false)) => Ok(Some(status)),
                None => Ok(None),
            };
        }
        if let Some(watchdog) = self.timeout_watchdog.as_ref()
            && let Err(error) = watchdog.check_health()
        {
            if self.terminate_after_boundary_failure() {
                let _ = self.cleanup_boundaries();
            }
            return Err(error);
        }
        if let Err(error) = self.check_gateway_health() {
            if self.terminate_after_boundary_failure() {
                let _ = self.cleanup_boundaries();
            }
            return Err(error);
        }
        if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            self.terminate_boundary()?;
            self.cleanup_boundaries()?;
            return Err(MacosBackendError::ProcessTimedOut);
        }
        let child = self
            .child
            .as_mut()
            .ok_or(MacosBackendError::BoundaryOwnedByRecovery)?;
        let status = poll_child(child, self.timeout_watchdog.as_ref())?;
        match status {
            Some(status) => self.finish(status).map(Some),
            None => Ok(None),
        }
    }

    /// Waits for the boundary while enforcing the prepared command timeout.
    pub fn wait(&mut self) -> Result<ExitStatus, MacosBackendError> {
        loop {
            if let Some(status) = self.try_wait()? {
                return Ok(status);
            }
            thread::sleep(BOUNDARY_POLL_INTERVAL);
        }
    }

    /// Terminates the complete process group and confirms its disappearance.
    pub fn kill(&mut self) -> Result<(), MacosBackendError> {
        if let Some(session) = self.session.as_mut() {
            return session.kill().map_err(Into::into);
        }
        self.terminate_boundary()?;
        self.cleanup_boundaries()
    }

    fn check_gateway_health(&mut self) -> Result<(), MacosBackendError> {
        let Some(gateway) = self.gateway.as_mut() else {
            return Ok(());
        };
        gateway.check_health().map_err(MacosBackendError::Network)
    }

    fn terminate_after_boundary_failure(&mut self) -> bool {
        self.terminate_boundary().is_ok()
    }

    fn terminate_boundary(&mut self) -> Result<(), MacosBackendError> {
        if self.child.is_none() {
            return Ok(());
        }
        if self.child_reaped {
            terminate_exited_process_group(self.process_group_id)?;
            return confirm_process_group_gone(self.process_group_id);
        }
        let Some(child) = self.child.as_mut() else {
            return Ok(());
        };
        match terminate_process_group(child, self.process_group_id, self.timeout_watchdog.as_ref())
        {
            Ok(()) => {
                self.child_reaped = true;
                Ok(())
            }
            Err(error) => {
                self.child_reaped |= error.child_reaped;
                Err(error.source)
            }
        }
    }

    fn finish(&mut self, status: ExitStatus) -> Result<ExitStatus, MacosBackendError> {
        // `try_wait` already reaped the group leader before calling `finish`.
        // Keep that fact across a later gateway-cleanup failure so recovery
        // never calls waitpid on an already collected child.
        self.child_reaped = true;
        let timed_out = self
            .timeout_watchdog
            .as_ref()
            .map(TimeoutWatchdog::timed_out)
            .transpose()?
            .unwrap_or(false);
        if self.process_group_id != 0 {
            terminate_exited_process_group(self.process_group_id)?;
            confirm_process_group_gone(self.process_group_id)?;
        }
        self.cleanup_boundaries()?;
        if timed_out {
            Err(MacosBackendError::ProcessTimedOut)
        } else {
            Ok(status)
        }
    }

    fn cleanup_boundaries(&mut self) -> Result<(), MacosBackendError> {
        if let Some(watchdog) = self.timeout_watchdog.as_mut() {
            watchdog.shutdown()?;
        }
        self.timeout_watchdog = None;
        if let Some(gateway) = self.gateway.as_mut() {
            gateway.shutdown().map_err(MacosBackendError::Network)?;
        }
        self.gateway = None;
        self.child = None;
        self.parent_death = None;
        Ok(())
    }

    fn transfer_to_recovery(&mut self) {
        if self.recovery_attempted {
            return;
        }
        self.recovery_attempted = true;
        let Some(child) = self.child.take() else {
            return;
        };
        let mut recovery = MacosBoundaryRecovery {
            child: Some(child),
            child_reaped: self.child_reaped,
            process_group_id: self.process_group_id,
            parent_death: self.parent_death.take(),
            gateway: self.gateway.take(),
            timeout_watchdog: self.timeout_watchdog.take(),
            completed: false,
        };
        let _ = thread::Builder::new()
            .name(BOUNDARY_RECOVERY_THREAD_NAME.to_owned())
            .spawn(move || recovery.recover_until_terminated());
    }
}

#[cfg(test)]
pub(crate) fn command_deadline(
    timeout: Option<Duration>,
) -> Result<Option<Instant>, MacosBackendError> {
    timeout
        .map(|timeout| {
            Instant::now()
                .checked_add(timeout)
                .ok_or(MacosBackendError::TimeoutOutOfRange {
                    timeout_ms: timeout.as_millis(),
                })
        })
        .transpose()
}

impl MacosBoundaryRecovery {
    fn recover_until_terminated(&mut self) {
        loop {
            let boundary_terminated = self.recover_boundary();
            let gateway_terminated = boundary_terminated
                && self
                    .gateway
                    .as_mut()
                    .is_none_or(|gateway| gateway.shutdown().is_ok());
            if gateway_terminated {
                if let Some(watchdog) = self.timeout_watchdog.as_mut()
                    && watchdog.shutdown().is_err()
                {
                    thread::sleep(BOUNDARY_RECOVERY_INTERVAL);
                    continue;
                }
                self.timeout_watchdog = None;
                self.child = None;
                self.parent_death = None;
                self.gateway = None;
                self.completed = true;
                return;
            }
            thread::sleep(BOUNDARY_RECOVERY_INTERVAL);
        }
    }

    fn recover_boundary(&mut self) -> bool {
        if self.child_reaped {
            return terminate_exited_process_group(self.process_group_id)
                .and_then(|()| confirm_process_group_gone(self.process_group_id))
                .is_ok();
        }

        let result = self.child.as_mut().map(|child| {
            terminate_process_group(child, self.process_group_id, self.timeout_watchdog.as_ref())
        });
        match result {
            Some(Ok(())) => {
                self.child_reaped = true;
                true
            }
            Some(Err(error)) => {
                self.child_reaped |= error.child_reaped;
                false
            }
            None => true,
        }
    }
}

impl Drop for MacosBoundaryRecovery {
    fn drop(&mut self) {
        if !self.completed {
            // A failed reaper-thread spawn must not block the caller while a
            // boundary may be stuck. Keep the child and every enforcement
            // resource owned until an external recovery path can address it;
            // dropping any of them would release protection while the
            // boundary may still be alive. This is the same fail-closed policy
            // used by the Linux backend.
            std::mem::forget(self.child.take());
            std::mem::forget(self.parent_death.take());
            std::mem::forget(self.gateway.take());
            std::mem::forget(self.timeout_watchdog.take());
        }
    }
}

impl Drop for MacosChild {
    fn drop(&mut self) {
        if self.session.is_some() {
            return;
        }
        if self.child.is_none() {
            let _ = self.cleanup_boundaries();
            return;
        }
        if self.terminate_boundary().is_ok() && self.cleanup_boundaries().is_ok() {
            return;
        }
        self.transfer_to_recovery();
    }
}

#[allow(unsafe_code)]
#[cfg(test)]
pub(crate) fn configure_process_group(command: &mut std::process::Command, parent_death_fd: RawFd) {
    use std::os::unix::process::CommandExt;
    // SAFETY: pre_exec runs in the child between fork and exec; setpgid
    // only changes the child process's own process-group membership.
    unsafe {
        command.pre_exec(move || {
            if libc::setpgid(0, 0) == -1 {
                Err(io::Error::last_os_error())
            } else {
                if parent_death_fd != PARENT_DEATH_FD {
                    if libc::dup2(parent_death_fd, PARENT_DEATH_FD) == -1 {
                        return Err(io::Error::last_os_error());
                    }
                    libc::close(parent_death_fd);
                } else {
                    let flags = libc::fcntl(PARENT_DEATH_FD, libc::F_GETFD);
                    if flags == -1 {
                        return Err(io::Error::last_os_error());
                    }
                    if flags & libc::FD_CLOEXEC != 0
                        && libc::fcntl(PARENT_DEATH_FD, libc::F_SETFD, flags & !libc::FD_CLOEXEC)
                            == -1
                    {
                        return Err(io::Error::last_os_error());
                    }
                }
                // SAFETY: stdio has already been configured by
                // `Command`; this closes unrelated inheritable parent
                // descriptors while preserving Rust's CLOEXEC spawn-error
                // pipe.
                close_inherited_fds_except(&[PARENT_DEATH_FD])?;
                Ok(())
            }
        });
    }
}

#[cfg(test)]
impl ParentDeathChannel {
    #[allow(unsafe_code)]
    pub(crate) fn new() -> io::Result<Self> {
        let mut descriptors = [0; 2];
        // SAFETY: pipe writes two owned descriptors into the stack buffer.
        if unsafe { libc::pipe(descriptors.as_mut_ptr()) } == -1 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: pipe returned two distinct valid descriptors now owned by
        // these OwnedFd values.
        let read = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
        let write = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
        let read = move_fd_above_standard_streams(read)?;
        let write = move_fd_above_standard_streams(write)?;
        Ok(Self { read, write })
    }

    pub(crate) fn read_fd(&self) -> RawFd {
        self.read.as_raw_fd()
    }

    pub(crate) fn into_writer(self) -> OwnedFd {
        let Self { read, write } = self;
        drop(read);
        write
    }
}

#[allow(unsafe_code)]
#[cfg(test)]
fn move_fd_above_standard_streams(fd: OwnedFd) -> io::Result<OwnedFd> {
    if fd.as_raw_fd() > libc::STDERR_FILENO {
        return Ok(fd);
    }
    let relocated = unsafe {
        libc::fcntl(
            fd.as_raw_fd(),
            libc::F_DUPFD_CLOEXEC,
            libc::STDERR_FILENO + 1,
        )
    };
    if relocated < 0 {
        return Err(io::Error::last_os_error());
    }
    drop(fd);
    Ok(unsafe { OwnedFd::from_raw_fd(relocated) })
}

#[allow(unsafe_code)]
fn close_inherited_fds_except(preserved_fds: &[RawFd]) -> io::Result<()> {
    close_inherited_fds_with_query(preserved_fds, |descriptors| {
        // SAFETY: proc_pidinfo writes descriptor records into the stack-owned
        // buffer and does not retain the pointer after returning.
        unsafe {
            libc::proc_pidinfo(
                libc::getpid(),
                libc::PROC_PIDLISTFDS,
                0,
                if descriptors.is_empty() {
                    std::ptr::null_mut()
                } else {
                    descriptors.as_mut_ptr().cast()
                },
                std::mem::size_of_val(descriptors) as libc::c_int,
            )
        }
    })
}

#[allow(unsafe_code)]
fn close_inherited_fds_with_query(
    preserved_fds: &[RawFd],
    mut query: impl FnMut(&mut [libc::proc_fdinfo]) -> libc::c_int,
) -> io::Result<()> {
    let mut descriptors = [libc::proc_fdinfo {
        proc_fd: 0,
        proc_fdtype: 0,
    }; 1024];
    let bytes = query(&mut descriptors);
    // libproc converts a failing proc_info syscall from -1 to zero and leaves
    // errno intact. A zero result must not skip the sweep and permit exec.
    if bytes <= 0 {
        return Err(io::Error::last_os_error());
    }
    let record_size = std::mem::size_of::<libc::proc_fdinfo>();
    if !(bytes as usize).is_multiple_of(record_size) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let close_inheritable = |fd: RawFd| {
        if fd <= libc::STDERR_FILENO || preserved_fds.contains(&fd) {
            return;
        }
        // `std::process` keeps its CLOEXEC pipe open until exec so it can
        // report a pre-exec failure to the parent.
        // SAFETY: fcntl and close operate only on descriptors owned by this
        // post-fork child process.
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFD);
            if flags >= 0 && flags & libc::FD_CLOEXEC == 0 {
                libc::close(fd);
            }
        }
    };

    if (bytes as usize) < std::mem::size_of_val(&descriptors) {
        let count = bytes as usize / std::mem::size_of::<libc::proc_fdinfo>();
        for descriptor in descriptors.iter().take(count) {
            close_inheritable(descriptor.proc_fd);
        }
        return Ok(());
    }

    // XNU's null-buffer query returns the allocated descriptor-table extent
    // plus a margin, not just the number of occupied entries. Existing high
    // descriptors remain valid even if RLIMIT_NOFILE was lowered afterwards.
    // No other thread can extend this post-fork child's descriptor table.
    let table_bytes = query(&mut []);
    if table_bytes <= 0 {
        return Err(io::Error::last_os_error());
    }
    if table_bytes < bytes || !(table_bytes as usize).is_multiple_of(record_size) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    // table_bytes is a positive c_int; dividing it cannot overflow RawFd.
    let upper_bound = (table_bytes as usize / record_size) as RawFd;
    for fd in libc::STDERR_FILENO + 1..upper_bound {
        close_inheritable(fd);
    }
    Ok(())
}

fn terminate_process_group(
    child: &mut Child,
    process_group_id: u32,
    timeout_watchdog: Option<&TimeoutWatchdog>,
) -> Result<(), ProcessGroupTerminationError> {
    terminate_process_group_if_present(process_group_id).map_err(|source| {
        ProcessGroupTerminationError {
            child_reaped: false,
            source,
        }
    })?;
    let deadline = Instant::now() + BOUNDARY_WAIT_TIMEOUT;
    loop {
        match poll_child(child, timeout_watchdog) {
            Ok(Some(_)) => {
                return confirm_process_group_gone(process_group_id).map_err(|source| {
                    ProcessGroupTerminationError {
                        child_reaped: true,
                        source,
                    }
                });
            }
            Ok(None) if Instant::now() < deadline => thread::sleep(BOUNDARY_POLL_INTERVAL),
            Ok(None) => {
                return Err(ProcessGroupTerminationError {
                    child_reaped: false,
                    source: MacosBackendError::BoundaryTerminationUnconfirmed,
                });
            }
            Err(source) => {
                return Err(ProcessGroupTerminationError {
                    child_reaped: false,
                    source,
                });
            }
        }
    }
}

fn poll_child(
    child: &mut Child,
    timeout_watchdog: Option<&TimeoutWatchdog>,
) -> Result<Option<ExitStatus>, MacosBackendError> {
    match timeout_watchdog {
        Some(watchdog) => watchdog.try_wait(child),
        None => child
            .try_wait()
            .map_err(|source| MacosBackendError::ProcessWait { source }),
    }
}

fn terminate_exited_process_group(process_group_id: u32) -> Result<(), MacosBackendError> {
    let process_group_id = libc::pid_t::try_from(process_group_id).map_err(|_| {
        MacosBackendError::ProcessGroupPidOutOfRange {
            pid: process_group_id,
        }
    })?;
    // The group leader has already been reaped when this function is called.
    // Do not send a destructive group-wide signal by PGID: after the last
    // member disappears, that numeric PGID could be reused by an unrelated
    // process group. Enumerate the remaining members and re-check each
    // member's current group before signalling it.
    signal_process_group_members(process_group_id, libc::SIGKILL)
        .map_err(|source| MacosBackendError::ProcessGroup { source })?;
    Ok(())
}

#[allow(unsafe_code)]
fn terminate_process_group_if_present(pid: u32) -> Result<(), MacosBackendError> {
    if pid == 0 {
        return Err(MacosBackendError::ProcessGroupIdInvalid);
    }
    let pid = libc::pid_t::try_from(pid)
        .map_err(|_| MacosBackendError::ProcessGroupPidOutOfRange { pid })?;
    // SAFETY: a negative PID targets exactly the process group whose leader is
    // the Seatbelt boundary; SIGKILL cannot be caught by it.
    let result = unsafe { libc::kill(-pid, libc::SIGKILL) };
    if result == -1 {
        let source = io::Error::last_os_error();
        match source.raw_os_error() {
            Some(libc::ESRCH) => return Ok(()),
            Some(libc::EPERM) => {
                signal_process_group_members(pid, libc::SIGKILL)
                    .map_err(|source| MacosBackendError::ProcessGroup { source })?;
            }
            _ => return Err(MacosBackendError::ProcessGroup { source }),
        }
    }
    Ok(())
}

#[allow(unsafe_code)]
fn signal_process_group_members(
    process_group_id: libc::pid_t,
    signal: libc::c_int,
) -> io::Result<bool> {
    if process_group_id <= 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid macOS process group ID",
        ));
    }
    let mut process_ids = vec![0; PROCESS_GROUP_MEMBER_INITIAL_CAPACITY];
    loop {
        let buffer_size = libc::c_int::try_from(std::mem::size_of_val(process_ids.as_slice()))
            .map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "process group is too large")
            })?;
        let count = unsafe {
            libc::proc_listpgrppids(
                process_group_id,
                process_ids.as_mut_ptr().cast(),
                buffer_size,
            )
        };
        if count < 0 {
            return Err(io::Error::last_os_error());
        }
        let count = usize::try_from(count)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid process count"))?;
        if count < process_ids.len() {
            process_ids.truncate(count);
            break;
        }
        let capacity = process_ids.len().checked_mul(2).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "process group is too large")
        })?;
        process_ids.resize(capacity, 0);
    }

    let mut signalled = false;
    for process_id in process_ids {
        if process_id <= 0 {
            continue;
        }
        let Some(identity) = ProcessIdentity::capture(process_id)? else {
            continue;
        };
        let current_group_id = unsafe { libc::getpgid(process_id) };
        if current_group_id == -1 {
            let source = io::Error::last_os_error();
            if source.raw_os_error() != Some(libc::ESRCH) {
                return Err(source);
            }
            continue;
        }
        if current_group_id != process_group_id {
            continue;
        }
        signalled |= identity.signal(signal)?;
    }
    Ok(signalled)
}

#[cfg(test)]
pub(crate) fn process_group_id(pid: u32) -> Result<u32, MacosBackendError> {
    if pid == 0 {
        return Err(MacosBackendError::ProcessGroupIdInvalid);
    }
    libc::pid_t::try_from(pid).map_err(|_| MacosBackendError::ProcessGroupPidOutOfRange { pid })?;
    // `configure_process_group` makes the boundary call setpgid(0, 0) in
    // pre_exec. Therefore the leader PID is the group ID, and using it
    // directly avoids a getpgid race when a short-lived leader exits before
    // the parent observes it.
    Ok(pid)
}

#[allow(unsafe_code)]
fn confirm_process_group_gone(pid: u32) -> Result<(), MacosBackendError> {
    if pid == 0 {
        return Err(MacosBackendError::ProcessGroupIdInvalid);
    }
    let deadline = Instant::now() + BOUNDARY_WAIT_TIMEOUT;
    loop {
        let pid = libc::pid_t::try_from(pid)
            .map_err(|_| MacosBackendError::ProcessGroupPidOutOfRange { pid })?;
        // SAFETY: signal 0 performs an existence check without changing
        // process state; the negative PID addresses this exact group.
        let state = unsafe { libc::kill(-pid, 0) };
        if state == -1 {
            let source = io::Error::last_os_error();
            if source.raw_os_error() == Some(libc::ESRCH) {
                return Ok(());
            }
            if source.raw_os_error() == Some(libc::EPERM) {
                if Instant::now() >= deadline {
                    return Err(MacosBackendError::BoundaryTerminationUnconfirmed);
                }
            } else {
                return Err(MacosBackendError::ProcessGroup { source });
            }
        } else if Instant::now() >= deadline {
            return Err(MacosBackendError::BoundaryTerminationUnconfirmed);
        }
        thread::sleep(BOUNDARY_POLL_INTERVAL);
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::process::Command;
    use std::time::Duration;

    use super::{MacosChild, command_deadline, signal_process_group_members};
    use crate::error::MacosBackendError;

    #[test]
    fn recovery_owned_boundary_is_reported_as_a_typed_state() {
        let mut child = MacosChild {
            session: None,
            child: None,
            child_reaped: false,
            process_group_id: 1,
            parent_death: None,
            gateway: None,
            deadline: None,
            timeout_watchdog: None,
            recovery_attempted: true,
        };

        assert!(matches!(
            child.try_wait(),
            Err(MacosBackendError::BoundaryOwnedByRecovery)
        ));
    }

    #[test]
    fn process_group_member_fallback_rejects_zero_group_ids() {
        let error = signal_process_group_members(0, libc::SIGKILL)
            .expect_err("zero process group must not be signalled");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn process_group_termination_rejects_zero_group_ids() {
        assert!(matches!(
            super::terminate_process_group_if_present(0),
            Err(MacosBackendError::ProcessGroupIdInvalid)
        ));
        assert!(matches!(
            super::confirm_process_group_gone(0),
            Err(MacosBackendError::ProcessGroupIdInvalid)
        ));
    }

    #[test]
    fn process_group_id_is_the_pre_exec_boundary_pid() {
        assert_eq!(super::process_group_id(42).expect("valid process ID"), 42);
    }

    #[test]
    fn command_deadline_rejects_an_unrepresentable_timeout() {
        let error = command_deadline(Some(Duration::MAX)).expect_err("deadline overflow");
        assert!(matches!(
            error,
            MacosBackendError::TimeoutOutOfRange { timeout_ms } if timeout_ms == Duration::MAX.as_millis()
        ));
    }

    #[test]
    fn recovery_does_not_wait_again_after_the_leader_was_reaped() {
        let parent_death = super::ParentDeathChannel::new().expect("parent-death channel");
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "exit 0"]);
        super::configure_process_group(&mut command, parent_death.read_fd());
        let mut child = command.spawn().expect("recovery fixture");
        let process_group_id = child.id();
        let parent_death = parent_death.into_writer();
        child.wait().expect("reap recovery fixture");

        let mut recovery = super::MacosBoundaryRecovery {
            child: Some(child),
            child_reaped: true,
            process_group_id,
            parent_death: Some(parent_death),
            gateway: None,
            timeout_watchdog: None,
            completed: false,
        };

        recovery.recover_until_terminated();

        assert!(recovery.completed);
        assert!(recovery.child.is_none());
    }

    #[test]
    fn recovery_records_a_reaped_leader_before_retrying_other_cleanup() {
        let parent_death = super::ParentDeathChannel::new().expect("parent-death channel");
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "exit 0"]);
        super::configure_process_group(&mut command, parent_death.read_fd());
        let child = command.spawn().expect("recovery fixture");
        let process_group_id = child.id();
        let parent_death = parent_death.into_writer();

        let mut recovery = super::MacosBoundaryRecovery {
            child: Some(child),
            child_reaped: false,
            process_group_id,
            parent_death: Some(parent_death),
            gateway: None,
            timeout_watchdog: None,
            completed: false,
        };

        assert!(recovery.recover_boundary());
        assert!(recovery.child_reaped);
    }

    #[test]
    fn child_termination_does_not_wait_again_after_the_leader_was_reaped() {
        let parent_death = super::ParentDeathChannel::new().expect("parent-death channel");
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "exit 0"]);
        super::configure_process_group(&mut command, parent_death.read_fd());
        let mut process = command.spawn().expect("reap fixture");
        let process_group_id = process.id();
        let parent_death = parent_death.into_writer();
        process.wait().expect("reap fixture");

        let mut child = super::MacosChild {
            session: None,
            child: Some(process),
            child_reaped: true,
            process_group_id,
            parent_death: Some(parent_death),
            gateway: None,
            deadline: None,
            timeout_watchdog: None,
            recovery_attempted: false,
        };

        child
            .terminate_boundary()
            .expect("reaped child cleanup must not call wait again");
    }

    #[test]
    #[allow(unsafe_code)]
    fn failed_fd_snapshot_aborts_before_exec_with_native_error() {
        use std::os::unix::process::CommandExt;

        let mut command = Command::new("/usr/bin/true");
        // Inject a real libproc error at the native query boundary. The invalid
        // flavor makes libproc return zero and preserve EINVAL, unlike a Unix
        // syscall's usual -1. No unowned process or descriptor is modified.
        unsafe {
            command.pre_exec(|| {
                super::close_inherited_fds_with_query(&[], |descriptors| {
                    libc::proc_pidinfo(
                        libc::getpid(),
                        -1,
                        0,
                        descriptors.as_mut_ptr().cast(),
                        std::mem::size_of_val(descriptors) as libc::c_int,
                    )
                })
            });
        }
        match command.spawn() {
            Err(error) => assert_eq!(error.raw_os_error(), Some(libc::EINVAL)),
            Ok(mut child) => {
                child.wait().expect("collect unexpectedly launched fixture");
                panic!("FD query failure was treated as an empty descriptor list");
            }
        }
    }

    #[test]
    fn incomplete_fd_snapshot_record_is_rejected() {
        let result = super::close_inherited_fds_with_query(&[], |_| 1);
        assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::InvalidData));
    }

    #[test]
    #[allow(unsafe_code)]
    fn failed_fd_table_extent_query_is_not_ignored() {
        let mut calls = 0;
        let result = super::close_inherited_fds_with_query(&[], |descriptors| {
            calls += 1;
            if !descriptors.is_empty() {
                return std::mem::size_of_val(descriptors) as libc::c_int;
            }
            // Force libproc's real zero/EINVAL failure on the fallback query.
            unsafe { libc::proc_pidinfo(libc::getpid(), -1, 0, std::ptr::null_mut(), 0) }
        });
        assert_eq!(calls, 2);
        assert_eq!(
            result.expect_err("failed table query").raw_os_error(),
            Some(libc::EINVAL)
        );
    }

    #[test]
    fn truncated_or_partial_fd_table_extent_is_rejected() {
        for extent in [1, std::mem::size_of::<libc::proc_fdinfo>() as libc::c_int] {
            let result = super::close_inherited_fds_with_query(&[], |descriptors| {
                if descriptors.is_empty() {
                    extent
                } else {
                    std::mem::size_of_val(descriptors) as libc::c_int
                }
            });
            assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::InvalidData));
        }
    }

    #[test]
    #[allow(unsafe_code)]
    fn fd_cleanup_covers_descriptors_above_a_lowered_soft_limit() {
        use std::os::unix::process::CommandExt;

        let mut command = Command::new("/usr/bin/true");
        // All resource-limit changes and extra descriptors are confined to
        // this post-fork child. The test runner and parallel tests are unchanged.
        unsafe {
            command.pre_exec(|| {
                let mut limit = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) != 0 {
                    return Err(io::Error::last_os_error());
                }
                limit.rlim_cur = 4096;
                if libc::setrlimit(libc::RLIMIT_NOFILE, &limit) != 0 {
                    return Err(io::Error::last_os_error());
                }
                let source = libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
                if source < 0 {
                    return Err(io::Error::last_os_error());
                }
                // Fill more records than the 1024-entry native snapshot while
                // leaving low descriptor numbers available for exec machinery.
                for _ in 0..1050 {
                    if libc::fcntl(source, libc::F_DUPFD_CLOEXEC, 512) < 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
                let inherited = libc::fcntl(source, libc::F_DUPFD, 2048);
                if inherited < 0 {
                    return Err(io::Error::last_os_error());
                }
                // Existing high descriptors remain valid after lowering the
                // soft limit. It bounds new allocations, not the current table.
                limit.rlim_cur = 256;
                if libc::setrlimit(libc::RLIMIT_NOFILE, &limit) != 0 {
                    return Err(io::Error::last_os_error());
                }
                super::close_inherited_fds_except(&[])?;
                if libc::fcntl(inherited, libc::F_GETFD) >= 0 {
                    return Err(io::Error::from_raw_os_error(libc::EACCES));
                }
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::EBADF) {
                    return Err(error);
                }
                Ok(())
            });
        }
        let status = command.status().expect("complete FD cleanup before exec");
        assert!(status.success());
    }
}
