// SPDX-License-Identifier: Apache-2.0

//! macOS process-group lifecycle for one Seatbelt child.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, ExitStatus};
use std::thread;
use std::time::{Duration, Instant};

use cageforge_command::StdioMode;

use crate::error::MacosBackendError;
use crate::network::GatewayRuntime;

const BOUNDARY_WAIT_TIMEOUT: Duration = Duration::from_secs(5);
const BOUNDARY_POLL_INTERVAL: Duration = Duration::from_millis(5);
const BOUNDARY_RECOVERY_INTERVAL: Duration = Duration::from_secs(1);
const BOUNDARY_RECOVERY_THREAD_NAME: &str = "cageforge-macos-boundary-recovery";
const PROCESS_GROUP_MEMBER_INITIAL_CAPACITY: usize = 16;
const PARENT_DEATH_FD: RawFd = libc::STDERR_FILENO + 1;
pub(crate) const PARENT_DEATH_WRAPPER: &str = "(
    while read _ <&3; do
        :
    done
    kill -KILL -$$ 2>/dev/null
) 3<&3 </dev/null >/dev/null 2>&1 &
exec 3<&-
exec \"$@\"
";

pub(crate) struct ParentDeathChannel {
    read: OwnedFd,
    write: OwnedFd,
}

/// A command running inside one macOS Seatbelt boundary.
pub struct MacosChild {
    child: Option<Child>,
    process_group_id: u32,
    parent_death: Option<OwnedFd>,
    gateway: Option<GatewayRuntime>,
    deadline: Option<Instant>,
    recovery_attempted: bool,
}

struct MacosBoundaryRecovery {
    child: Option<Child>,
    process_group_id: u32,
    parent_death: Option<OwnedFd>,
    gateway: Option<GatewayRuntime>,
    completed: bool,
}

impl MacosChild {
    pub(crate) fn new(
        child: Child,
        process_group_id: u32,
        parent_death: OwnedFd,
        gateway: Option<GatewayRuntime>,
        timeout: Option<Duration>,
    ) -> Self {
        Self {
            child: Some(child),
            process_group_id,
            parent_death: Some(parent_death),
            gateway,
            deadline: timeout.map(|timeout| Instant::now() + timeout),
            recovery_attempted: false,
        }
    }

    /// Returns the process identifier of the Seatbelt boundary.
    pub fn id(&self) -> u32 {
        self.child.as_ref().map_or(0, Child::id)
    }

    /// Returns the child's standard input pipe, if one was requested.
    pub fn stdin(&mut self) -> Option<&mut ChildStdin> {
        self.child.as_mut().and_then(|child| child.stdin.as_mut())
    }

    /// Returns the child's standard output pipe, if one was requested.
    pub fn stdout(&mut self) -> Option<&mut ChildStdout> {
        self.child.as_mut().and_then(|child| child.stdout.as_mut())
    }

    /// Returns the child's standard error pipe, if one was requested.
    pub fn stderr(&mut self) -> Option<&mut ChildStderr> {
        self.child.as_mut().and_then(|child| child.stderr.as_mut())
    }

    /// Checks whether the boundary has exited, enforcing its timeout.
    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>, MacosBackendError> {
        self.check_gateway_health()?;
        if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            self.terminate_boundary()?;
            self.cleanup_boundaries()?;
            return Err(MacosBackendError::ProcessTimedOut);
        }
        let status = self
            .child_mut()?
            .try_wait()
            .map_err(|source| MacosBackendError::ProcessWait { source })?;
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
        self.terminate_boundary()?;
        self.cleanup_boundaries()
    }

    fn child_mut(&mut self) -> Result<&mut Child, MacosBackendError> {
        self.child
            .as_mut()
            .ok_or(MacosBackendError::BoundaryOwnedByRecovery)
    }

    fn check_gateway_health(&mut self) -> Result<(), MacosBackendError> {
        let Some(gateway) = self.gateway.as_mut() else {
            return Ok(());
        };
        gateway.check_health().map_err(MacosBackendError::Network)
    }

    fn terminate_boundary(&mut self) -> Result<(), MacosBackendError> {
        let Some(child) = self.child.as_mut() else {
            return Ok(());
        };
        terminate_process_group(child, self.process_group_id)
    }

    fn finish(&mut self, status: ExitStatus) -> Result<ExitStatus, MacosBackendError> {
        if self.process_group_id != 0 {
            terminate_process_group_if_present(self.process_group_id)?;
            confirm_process_group_gone(self.process_group_id)?;
        }
        self.cleanup_boundaries()?;
        Ok(status)
    }

    fn cleanup_boundaries(&mut self) -> Result<(), MacosBackendError> {
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
        let recovery = MacosBoundaryRecovery {
            child: Some(child),
            process_group_id: self.process_group_id,
            parent_death: self.parent_death.take(),
            gateway: self.gateway.take(),
            completed: false,
        };
        let _ = thread::Builder::new()
            .name(BOUNDARY_RECOVERY_THREAD_NAME.to_owned())
            .spawn(move || recovery.recover_until_terminated());
    }
}

impl MacosBoundaryRecovery {
    fn recover_until_terminated(mut self) {
        loop {
            let terminated = self
                .child
                .as_mut()
                .is_some_and(|child| terminate_process_group(child, self.process_group_id).is_ok());
            if terminated {
                if let Some(gateway) = self.gateway.as_mut() {
                    let _ = gateway.shutdown();
                }
                self.child = None;
                self.parent_death = None;
                self.gateway = None;
                self.completed = true;
                return;
            }
            thread::sleep(BOUNDARY_RECOVERY_INTERVAL);
        }
    }
}

impl Drop for MacosBoundaryRecovery {
    fn drop(&mut self) {
        if !self.completed {
            // Dropping an unconfirmed boundary would release its parent-death
            // and gateway ownership while the process group may still live.
            // Keep every enforcement resource alive if the recovery thread
            // itself cannot be created or terminates unexpectedly.
            std::mem::forget(self.child.take());
            std::mem::forget(self.parent_death.take());
            std::mem::forget(self.gateway.take());
        }
    }
}

impl Drop for MacosChild {
    fn drop(&mut self) {
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
    let mut descriptors = [libc::proc_fdinfo {
        proc_fd: 0,
        proc_fdtype: 0,
    }; 1024];
    // SAFETY: proc_pidinfo writes descriptor records into the stack-owned
    // buffer and does not retain the pointer after returning.
    let bytes = unsafe {
        libc::proc_pidinfo(
            libc::getpid(),
            libc::PROC_PIDLISTFDS,
            0,
            descriptors.as_mut_ptr().cast(),
            std::mem::size_of_val(&descriptors) as libc::c_int,
        )
    };
    if bytes < 0 {
        return Err(io::Error::last_os_error());
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

    // The fixed stack buffer was not sufficient. Scan the complete descriptor
    // range from the process limit; descriptor numbers are not required to be
    // dense, so the number of records returned above is not an upper fd value.
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes into the stack-owned resource-limit structure.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut limit) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let upper_bound = limit.rlim_cur.min(RawFd::MAX as _) as RawFd;
    for fd in libc::STDERR_FILENO + 1..upper_bound {
        close_inheritable(fd);
    }
    Ok(())
}

pub(crate) fn stream(mode: StdioMode) -> std::process::Stdio {
    match mode {
        StdioMode::Inherit => std::process::Stdio::inherit(),
        StdioMode::Null => std::process::Stdio::null(),
        StdioMode::Pipe => std::process::Stdio::piped(),
    }
}

fn terminate_process_group(
    child: &mut Child,
    process_group_id: u32,
) -> Result<(), MacosBackendError> {
    terminate_process_group_if_present(process_group_id)?;
    let deadline = Instant::now() + BOUNDARY_WAIT_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return confirm_process_group_gone(process_group_id),
            Ok(None) if Instant::now() < deadline => thread::sleep(BOUNDARY_POLL_INTERVAL),
            Ok(None) => return Err(MacosBackendError::BoundaryTerminationUnconfirmed),
            Err(source) => return Err(MacosBackendError::ProcessWait { source }),
        }
    }
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
        if unsafe { libc::kill(process_id, signal) } == 0 {
            signalled = true;
            continue;
        }
        let source = io::Error::last_os_error();
        if source.raw_os_error() != Some(libc::ESRCH) {
            return Err(source);
        }
    }
    Ok(signalled)
}

#[allow(unsafe_code)]
pub(crate) fn process_group_id(pid: u32) -> Result<u32, MacosBackendError> {
    let pid = libc::pid_t::try_from(pid)
        .map_err(|_| MacosBackendError::ProcessGroupPidOutOfRange { pid })?;
    // SAFETY: getpgid only reads process-group state for the freshly spawned
    // boundary process and does not retain any pointer.
    let process_group_id = unsafe { libc::getpgid(pid) };
    if process_group_id == -1 {
        return Err(MacosBackendError::ProcessGroup {
            source: io::Error::last_os_error(),
        });
    }
    if process_group_id == 0 {
        return Err(MacosBackendError::ProcessGroupIdInvalid);
    }
    u32::try_from(process_group_id).map_err(|_| MacosBackendError::ProcessGroup {
        source: io::Error::new(
            io::ErrorKind::InvalidData,
            "macOS sandbox process group ID is outside the public range",
        ),
    })
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

    use super::{MacosChild, signal_process_group_members};
    use crate::error::MacosBackendError;

    #[test]
    fn recovery_owned_boundary_is_reported_as_a_typed_state() {
        let mut child = MacosChild {
            child: None,
            process_group_id: 1,
            parent_death: None,
            gateway: None,
            deadline: None,
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
}
