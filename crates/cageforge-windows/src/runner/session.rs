// SPDX-License-Identifier: Apache-2.0

//! Authenticated parent-runner session and complete process lifecycle.

use std::fs::File;
use std::io::Read;
use std::os::windows::io::AsRawHandle;
use std::process::ExitStatus;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use cageforge_command::StdioSpec;
use thiserror::Error;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::System::Pipes::PeekNamedPipe;

use crate::runner::launch::{RunnerBootstrapStatus, RunnerLaunch, RunnerLaunchError};
use crate::runner::parent::{BoundaryTerminator, ParentBoundaryError};
use crate::runner::protocol::{
    MAX_RUNNER_FRAME_BYTES, RunnerAccount, RunnerBootstrapStage, RunnerMessage, RunnerSpawnRequest,
    RunnerStandardHandles, WindowsRunnerFailure, WindowsRunnerProtocolError, read_frame,
    write_frame,
};
use crate::runner::stdio::{ParentStdio, WindowsStandardStreamError};

const SPAWN_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const RUNNER_EXIT_TIMEOUT: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(2);

pub(crate) struct RunnerSession {
    launch: RunnerLaunch,
    process_id: u32,
    stdin: Option<File>,
    stdout: Option<File>,
    stderr: Option<File>,
    terminal: mpsc::Receiver<RunnerTerminal>,
    dispatcher: Option<JoinHandle<()>>,
    watchdog: Option<TimeoutWatchdog>,
    timed_out: Arc<AtomicBool>,
    explicit_exit_code: Option<u32>,
    finished: bool,
}

pub(crate) struct PendingRunnerSpawnRequest {
    pub(crate) command: Vec<Vec<u16>>,
    pub(crate) working_directory: Vec<u16>,
    pub(crate) environment_block: Vec<u16>,
    pub(crate) capability_sids: Vec<String>,
    pub(crate) route_sid: Option<String>,
    pub(crate) account: RunnerAccount,
}

pub(crate) struct RunnerSessionStartError {
    pub(crate) error: RunnerSessionError,
    pub(crate) boundary: Arc<BoundaryTerminator>,
}

struct TimeoutWatchdog {
    cancel: mpsc::SyncSender<()>,
    join: Option<JoinHandle<()>>,
}

enum RunnerTerminal {
    Exited(u32),
    TimedOut(Result<(), ParentBoundaryError>),
    Failed(RunnerSessionError),
}

#[derive(Clone, Copy)]
enum RunnerHandshakePhase {
    Readiness,
    Spawn,
}

#[derive(Debug, Error)]
pub(crate) enum RunnerSessionError {
    #[error(transparent)]
    Launch(#[from] RunnerLaunchError),
    #[error(transparent)]
    StandardStream(#[from] WindowsStandardStreamError),
    #[error(transparent)]
    Protocol(#[from] WindowsRunnerProtocolError),
    #[error(transparent)]
    Boundary(#[from] ParentBoundaryError),
    #[error("Windows command runner failed during {stage:?}/{code:?} ({native_code:?}): {detail}")]
    RunnerFailure {
        stage: crate::runner::protocol::WindowsRunnerFailureStage,
        code: crate::runner::protocol::WindowsRunnerFailureCode,
        native_code: Option<u32>,
        detail: String,
    },
    #[error(
        "command runner failed during {stage:?} before the spawn handshake completed (Windows error {native_code:?})"
    )]
    RunnerBootstrapFailure {
        stage: RunnerBootstrapStage,
        native_code: Option<u32>,
    },
    #[error("timed out waiting for the authenticated runner spawn response")]
    SpawnHandshakeTimeout,
    #[error("timed out waiting for the authenticated runner readiness response")]
    ReadinessHandshakeTimeout,
    #[error(
        "authenticated runner response pipe failed while checking available data: Windows error {code}"
    )]
    ResponsePeek { code: u32 },
    #[error("authenticated runner response pipe closed during the {phase} handshake")]
    ResponseClosed { phase: &'static str },
    #[error("authenticated runner sent {actual} during the spawn handshake")]
    UnexpectedHandshakeMessage { actual: &'static str },
    #[error("authenticated runner sent {actual} during the readiness handshake")]
    UnexpectedReadinessMessage { actual: &'static str },
    #[error("authenticated runner sent {actual} during the command lifecycle")]
    UnexpectedLifecycleMessage { actual: &'static str },
    #[error("authenticated runner lifecycle channel closed without a terminal result")]
    LifecycleClosed,
    #[error("authenticated runner lifecycle dispatcher panicked")]
    DispatcherPanic,
    #[error("timeout watchdog panicked")]
    WatchdogPanic,
    #[error("the authenticated command runner did not exit after reporting command completion")]
    RunnerExitTimeout,
    #[error("authenticated command runner exited with code {exit_code} after reporting success")]
    RunnerExitMismatch { exit_code: u32 },
    #[error("the sandboxed command exceeded its prepared timeout")]
    TimedOut,
    #[error("the sandboxed command lifecycle was already consumed")]
    LifecycleConsumed,
}

impl RunnerSession {
    pub(crate) fn start(
        launch: RunnerLaunch,
        request: PendingRunnerSpawnRequest,
        stdio_spec: StdioSpec,
        timeout: Option<Duration>,
    ) -> Result<Self, RunnerSessionStartError> {
        let boundary = launch.boundary();
        Self::start_inner(launch, request, stdio_spec, timeout)
            .map_err(|error| RunnerSessionStartError { error, boundary })
    }

    fn start_inner(
        mut launch: RunnerLaunch,
        request: PendingRunnerSpawnRequest,
        stdio_spec: StdioSpec,
        timeout: Option<Duration>,
    ) -> Result<Self, RunnerSessionError> {
        let boundary = launch.boundary();
        let mut response_pipe = launch.take_response()?;
        let readiness = match read_frame_until(
            &mut response_pipe,
            Instant::now() + SPAWN_HANDSHAKE_TIMEOUT,
            RunnerHandshakePhase::Readiness,
        ) {
            Ok(message) => message,
            Err(error) => {
                let error = match runner_bootstrap_failure(&boundary) {
                    Ok(Some(status)) => RunnerSessionError::RunnerBootstrapFailure {
                        stage: status.stage,
                        native_code: status.native_code,
                    },
                    Ok(None) => error,
                    Err(error) => RunnerSessionError::Boundary(error),
                };
                let _ = boundary.terminate(125);
                return Err(error);
            }
        };
        match readiness {
            RunnerMessage::Ready => {}
            RunnerMessage::Failed { failure } => {
                let _ = boundary.terminate(125);
                return Err(runner_failure(failure));
            }
            other => {
                let actual = other.kind();
                let _ = boundary.terminate(125);
                return Err(RunnerSessionError::UnexpectedReadinessMessage { actual });
            }
        }
        let stdio = match ParentStdio::prepare(stdio_spec, &boundary) {
            Ok(stdio) => stdio,
            Err(error) => {
                let _ = boundary.terminate(125);
                return Err(error.into());
            }
        };
        let (standard_handles, stdin, stdout, stderr) = stdio.into_parts();
        let request = request.bind(standard_handles, launch.job_handle);
        let mut request_pipe = launch.take_request()?;
        if let Err(error) = write_frame(&mut request_pipe, RunnerMessage::Spawn { request }) {
            let _ = boundary.terminate(125);
            return Err(error.into());
        }
        drop(request_pipe);
        let message = match read_frame_until(
            &mut response_pipe,
            Instant::now() + SPAWN_HANDSHAKE_TIMEOUT,
            RunnerHandshakePhase::Spawn,
        ) {
            Ok(message) => message,
            Err(error) => {
                let error = match runner_bootstrap_failure(&boundary) {
                    Ok(Some(status)) => RunnerSessionError::RunnerBootstrapFailure {
                        stage: status.stage,
                        native_code: status.native_code,
                    },
                    Ok(None) => error,
                    Err(error) => RunnerSessionError::Boundary(error),
                };
                let _ = boundary.terminate(125);
                return Err(error);
            }
        };
        let process_id = match message {
            RunnerMessage::Spawned { process_id } if process_id != 0 => process_id,
            RunnerMessage::Failed { failure } => {
                let _ = boundary.terminate(125);
                return Err(runner_failure(failure));
            }
            other => {
                let actual = other.kind();
                let _ = boundary.terminate(125);
                return Err(RunnerSessionError::UnexpectedHandshakeMessage { actual });
            }
        };
        if let Err(error) = boundary.verify_child_job_membership(process_id) {
            let _ = boundary.terminate(125);
            return Err(error.into());
        }
        let (terminal_sender, terminal) = mpsc::channel();
        let timed_out = Arc::new(AtomicBool::new(false));
        let watchdog = timeout.map(|duration| {
            TimeoutWatchdog::start(
                duration,
                Arc::clone(&boundary),
                Arc::clone(&timed_out),
                terminal_sender.clone(),
            )
        });
        let watchdog_cancel = watchdog.as_ref().map(|watchdog| watchdog.cancel.clone());
        let dispatcher_timed_out = Arc::clone(&timed_out);
        let dispatcher = std::thread::spawn(move || {
            dispatch_responses(
                response_pipe,
                boundary,
                dispatcher_timed_out,
                watchdog_cancel,
                terminal_sender,
            );
        });
        Ok(Self {
            launch,
            process_id,
            stdin,
            stdout,
            stderr,
            terminal,
            dispatcher: Some(dispatcher),
            watchdog,
            timed_out,
            explicit_exit_code: None,
            finished: false,
        })
    }

    pub(crate) const fn id(&self) -> u32 {
        self.process_id
    }

    pub(crate) fn boundary(&self) -> Arc<BoundaryTerminator> {
        self.launch.boundary()
    }

    pub(crate) const fn finished(&self) -> bool {
        self.finished
    }

    pub(crate) fn stdin(&mut self) -> Option<&mut File> {
        self.stdin.as_mut()
    }

    pub(crate) fn stdout(&mut self) -> Option<&mut File> {
        self.stdout.as_mut()
    }

    pub(crate) fn stderr(&mut self) -> Option<&mut File> {
        self.stderr.as_mut()
    }

    pub(crate) fn close_stdin(&mut self) {
        self.stdin = None;
    }

    pub(crate) fn try_wait(&mut self) -> Result<Option<ExitStatus>, RunnerSessionError> {
        if self.finished {
            return Err(RunnerSessionError::LifecycleConsumed);
        }
        match self.terminal.try_recv() {
            Ok(terminal) => self.finish(terminal).map(Some),
            Err(mpsc::TryRecvError::Empty) => Ok(None),
            Err(mpsc::TryRecvError::Disconnected) => Err(RunnerSessionError::LifecycleClosed),
        }
    }

    pub(crate) fn wait(&mut self) -> Result<ExitStatus, RunnerSessionError> {
        if self.finished {
            return Err(RunnerSessionError::LifecycleConsumed);
        }
        let terminal = self
            .terminal
            .recv()
            .map_err(|_| RunnerSessionError::LifecycleClosed)?;
        self.finish(terminal)
    }

    pub(crate) fn kill(&mut self) -> Result<(), RunnerSessionError> {
        if self.finished {
            return Err(RunnerSessionError::LifecycleConsumed);
        }
        self.close_stdin();
        if let Some(mut watchdog) = self.watchdog.take() {
            watchdog.stop()?;
        }
        self.launch.boundary().terminate(1)?;
        if !self.timed_out.load(Ordering::Acquire) {
            self.explicit_exit_code = Some(1);
        }
        Ok(())
    }

    pub(crate) fn mark_termination_confirmed(&mut self) {
        self.finished = true;
        self.close_stdin();
        if let Some(mut watchdog) = self.watchdog.take() {
            let _ = watchdog.stop();
        }
        if let Some(dispatcher) = self.dispatcher.take() {
            let _ = dispatcher.join();
        }
    }

    fn finish(&mut self, terminal: RunnerTerminal) -> Result<ExitStatus, RunnerSessionError> {
        let result = self.finish_inner(terminal);
        if matches!(&result, Err(RunnerSessionError::TimedOut)) {
            // The watchdog reports this error only after the complete Job
            // Object termination has succeeded. The command result is an
            // error, but the process boundary is already a confirmed
            // terminal state.
            self.finished = true;
        } else if result.is_err() {
            // An error does not prove that the complete process boundary was
            // terminated. Keep Drop responsible for another bounded
            // termination attempt instead of making a failed lifecycle
            // indistinguishable from a confirmed terminal state.
            let _ = self.launch.boundary().terminate(125);
        } else {
            // Only a fully successful lifecycle may suppress the Drop retry.
            self.finished = true;
        }
        result
    }

    fn finish_inner(&mut self, terminal: RunnerTerminal) -> Result<ExitStatus, RunnerSessionError> {
        self.close_stdin();
        if let Some(mut watchdog) = self.watchdog.take() {
            watchdog.stop()?;
        }
        if let Some(dispatcher) = self.dispatcher.take()
            && dispatcher.join().is_err()
        {
            return Err(RunnerSessionError::DispatcherPanic);
        }
        if let Some(exit_code) = self.explicit_exit_code.take() {
            return Ok(exit_status(exit_code));
        }
        match terminal {
            RunnerTerminal::Exited(exit_code) => {
                self.launch.boundary().terminate_job(exit_code)?;
                let Some(runner_exit) = self.launch.boundary().wait_runner(RUNNER_EXIT_TIMEOUT)?
                else {
                    return Err(RunnerSessionError::RunnerExitTimeout);
                };
                if runner_exit != 0 {
                    return Err(RunnerSessionError::RunnerExitMismatch {
                        exit_code: runner_exit,
                    });
                }
                Ok(exit_status(exit_code))
            }
            RunnerTerminal::TimedOut(Ok(())) => Err(RunnerSessionError::TimedOut),
            RunnerTerminal::TimedOut(Err(error)) => Err(error.into()),
            RunnerTerminal::Failed(error) => Err(error),
        }
    }
}

impl PendingRunnerSpawnRequest {
    fn bind(self, standard_handles: RunnerStandardHandles, job_handle: u64) -> RunnerSpawnRequest {
        RunnerSpawnRequest {
            command: self.command,
            working_directory: self.working_directory,
            environment_block: self.environment_block,
            capability_sids: self.capability_sids,
            route_sid: self.route_sid,
            account: self.account,
            standard_handles,
            job_handle,
        }
    }
}

impl TimeoutWatchdog {
    fn start(
        timeout: Duration,
        boundary: Arc<BoundaryTerminator>,
        timed_out: Arc<AtomicBool>,
        terminal: mpsc::Sender<RunnerTerminal>,
    ) -> Self {
        let (cancel, receiver) = mpsc::sync_channel(1);
        let join = std::thread::spawn(move || {
            if matches!(
                receiver.recv_timeout(timeout),
                Err(mpsc::RecvTimeoutError::Timeout)
            ) {
                timed_out.store(true, Ordering::Release);
                let result = boundary.terminate(124);
                let _ = terminal.send(RunnerTerminal::TimedOut(result));
            }
        });
        Self {
            cancel,
            join: Some(join),
        }
    }

    fn stop(&mut self) -> Result<(), RunnerSessionError> {
        let _ = self.cancel.try_send(());
        if self.join.take().is_some_and(|join| join.join().is_err()) {
            Err(RunnerSessionError::WatchdogPanic)
        } else {
            Ok(())
        }
    }
}

impl Drop for RunnerSession {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.launch.boundary().terminate(125);
        }
        self.close_stdin();
        if let Some(mut watchdog) = self.watchdog.take() {
            let _ = watchdog.stop();
        }
        if let Some(dispatcher) = self.dispatcher.take() {
            let _ = dispatcher.join();
        }
    }
}

fn dispatch_responses(
    mut response: File,
    boundary: Arc<BoundaryTerminator>,
    timed_out: Arc<AtomicBool>,
    watchdog_cancel: Option<mpsc::SyncSender<()>>,
    terminal: mpsc::Sender<RunnerTerminal>,
) {
    let message = match read_frame(&mut response) {
        Ok(message) => message,
        Err(error) => {
            if timed_out.load(Ordering::Acquire) {
                return;
            }
            let _ = boundary.terminate(125);
            let _ = terminal.send(RunnerTerminal::Failed(error.into()));
            return;
        }
    };
    if let Some(cancel) = watchdog_cancel {
        let _ = cancel.try_send(());
    }
    if timed_out.load(Ordering::Acquire) {
        return;
    }
    match message {
        RunnerMessage::Exited { exit_code } => {
            let _ = terminal.send(RunnerTerminal::Exited(exit_code));
        }
        RunnerMessage::Failed { failure } => {
            let _ = boundary.terminate(125);
            let _ = terminal.send(RunnerTerminal::Failed(runner_failure(failure)));
        }
        other => {
            let _ = boundary.terminate(125);
            let _ = terminal.send(RunnerTerminal::Failed(
                RunnerSessionError::UnexpectedLifecycleMessage {
                    actual: other.kind(),
                },
            ));
        }
    }
}

fn read_frame_until(
    reader: &mut File,
    deadline: Instant,
    phase: RunnerHandshakePhase,
) -> Result<RunnerMessage, RunnerSessionError> {
    let mut length = [0u8; 4];
    read_exact_until(reader, &mut length, deadline, phase)?;
    let payload_length = u32::from_le_bytes(length) as usize;
    if payload_length > MAX_RUNNER_FRAME_BYTES {
        return Err(WindowsRunnerProtocolError::FrameTooLarge {
            actual: payload_length,
            maximum: MAX_RUNNER_FRAME_BYTES,
        }
        .into());
    }
    let mut frame = Vec::with_capacity(4 + payload_length);
    frame.extend_from_slice(&length);
    frame.resize(4 + payload_length, 0);
    read_exact_until(reader, &mut frame[4..], deadline, phase)?;
    read_frame(&mut frame.as_slice()).map_err(Into::into)
}

#[allow(unsafe_code)]
fn read_exact_until(
    reader: &mut File,
    mut buffer: &mut [u8],
    deadline: Instant,
    phase: RunnerHandshakePhase,
) -> Result<(), RunnerSessionError> {
    while !buffer.is_empty() {
        if Instant::now() >= deadline {
            return Err(match phase {
                RunnerHandshakePhase::Readiness => RunnerSessionError::ReadinessHandshakeTimeout,
                RunnerHandshakePhase::Spawn => RunnerSessionError::SpawnHandshakeTimeout,
            });
        }
        let mut available = 0;
        if unsafe {
            PeekNamedPipe(
                reader.as_raw_handle() as _,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut available,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(RunnerSessionError::ResponsePeek {
                code: unsafe { GetLastError() },
            });
        }
        if available == 0 {
            std::thread::sleep(POLL_INTERVAL);
            continue;
        }
        let length = buffer.len().min(available as usize);
        let read = reader
            .read(&mut buffer[..length])
            .map_err(|source| WindowsRunnerProtocolError::PayloadRead { source })?;
        if read == 0 {
            return Err(RunnerSessionError::ResponseClosed {
                phase: match phase {
                    RunnerHandshakePhase::Readiness => "readiness",
                    RunnerHandshakePhase::Spawn => "spawn",
                },
            });
        }
        buffer = &mut buffer[read..];
    }
    Ok(())
}

fn runner_failure(failure: WindowsRunnerFailure) -> RunnerSessionError {
    RunnerSessionError::RunnerFailure {
        stage: failure.stage(),
        code: failure.code(),
        native_code: failure.native_code(),
        detail: failure.detail().to_string(),
    }
}

fn runner_bootstrap_failure(
    boundary: &BoundaryTerminator,
) -> Result<Option<RunnerBootstrapStatus>, ParentBoundaryError> {
    let Some(exit_code) = boundary.wait_runner(Duration::ZERO)? else {
        return Ok(None);
    };
    Ok(crate::runner::launch::decode_runner_bootstrap_status(
        exit_code,
    ))
}

#[allow(unsafe_code)]
fn exit_status(exit_code: u32) -> ExitStatus {
    use std::os::windows::process::ExitStatusExt;

    ExitStatus::from_raw(exit_code)
}
