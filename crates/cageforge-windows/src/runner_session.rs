// SPDX-License-Identifier: Apache-2.0

//! Authenticated parent-runner session, standard-stream proxying, and lifecycle.

use std::fs::File;
use std::io::{self, Read, Stderr, Stdout, Write};
use std::os::windows::io::AsRawHandle;
use std::process::ExitStatus;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use thiserror::Error;
use windows_sys::Win32::Foundation::{ERROR_NOT_FOUND, GetLastError};
use windows_sys::Win32::System::IO::CancelSynchronousIo;
use windows_sys::Win32::System::Pipes::PeekNamedPipe;

use crate::runner_launch::{RunnerLaunch, RunnerLaunchError};
use crate::runner_parent::{BoundaryTerminator, ParentBoundaryError};
use crate::runner_pipe::duplicate_current_thread_handle;
use crate::runner_protocol::{
    MAX_RUNNER_FRAME_BYTES, MAX_RUNNER_OUTPUT_CHUNK_BYTES, RunnerMessage, RunnerOutputStream,
    RunnerSpawnRequest, RunnerStdioMode, WindowsRunnerFailure, WindowsRunnerProtocolError,
    read_frame, write_frame,
};

const SPAWN_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const RUNNER_EXIT_TIMEOUT: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(2);

pub(crate) struct RunnerSession {
    launch: RunnerLaunch,
    process_id: u32,
    stdin: Option<RunnerInput>,
    stdout: Option<RunnerOutput>,
    stderr: Option<RunnerOutput>,
    inherited_stdin: Option<InheritedStdinForwarder>,
    terminal: mpsc::Receiver<RunnerTerminal>,
    dispatcher: Option<JoinHandle<()>>,
    watchdog: Option<TimeoutWatchdog>,
    finished: bool,
}

pub(crate) struct RunnerInput {
    writer: Option<File>,
}

pub(crate) struct RunnerOutput {
    reader: ChannelReader,
}

struct ChannelReader {
    receiver: mpsc::Receiver<Vec<u8>>,
    current: Vec<u8>,
    offset: usize,
}

struct InheritedStdinForwarder {
    thread_handle: std::os::windows::io::OwnedHandle,
    join: Option<JoinHandle<()>>,
}

struct TimeoutWatchdog {
    cancel: mpsc::SyncSender<()>,
    join: Option<JoinHandle<()>>,
}

enum OutputTarget {
    Pipe(mpsc::Sender<Vec<u8>>),
    InheritStdout(Stdout),
    InheritStderr(Stderr),
    Null,
}

enum RunnerTerminal {
    Exited(u32),
    TimedOut(Result<(), ParentBoundaryError>),
    Failed(RunnerSessionError),
}

#[derive(Debug, Error)]
pub(crate) enum RunnerSessionError {
    #[error(transparent)]
    Launch(#[from] RunnerLaunchError),
    #[error(transparent)]
    Protocol(#[from] WindowsRunnerProtocolError),
    #[error(transparent)]
    Boundary(#[from] ParentBoundaryError),
    #[error("Windows command runner failed during {stage:?}/{code:?} ({native_code:?}): {detail}")]
    RunnerFailure {
        stage: crate::runner_protocol::WindowsRunnerFailureStage,
        code: crate::runner_protocol::WindowsRunnerFailureCode,
        native_code: Option<u32>,
        detail: String,
    },
    #[error("timed out waiting for the authenticated runner spawn response")]
    SpawnHandshakeTimeout,
    #[error(
        "authenticated runner response pipe failed while checking available data: Windows error {code}"
    )]
    ResponsePeek { code: u32 },
    #[error("authenticated runner response pipe closed during the spawn handshake")]
    ResponseClosed,
    #[error("authenticated runner sent {actual} during the spawn handshake")]
    UnexpectedHandshakeMessage { actual: &'static str },
    #[error("authenticated runner sent {actual} during the command lifecycle")]
    UnexpectedLifecycleMessage { actual: &'static str },
    #[error("authenticated runner output for {stream:?} exceeded the protocol chunk bound")]
    OversizedOutput { stream: RunnerOutputStream },
    #[error("failed to forward inherited {stream}: {source}")]
    InheritedOutput {
        stream: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("authenticated runner lifecycle channel closed without a terminal result")]
    LifecycleClosed,
    #[error("authenticated runner lifecycle dispatcher panicked")]
    DispatcherPanic,
    #[error("inherited standard-input forwarder panicked")]
    StdinForwarderPanic,
    #[error("failed to duplicate the inherited-stdin thread handle: Windows error {code}")]
    StdinThreadHandle { code: u32 },
    #[error("inherited-stdin thread ended before publishing its cancellation handle")]
    StdinThreadMissing,
    #[error("failed to cancel inherited standard-input forwarding: Windows error {code}")]
    StdinCancel { code: u32 },
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
        mut launch: RunnerLaunch,
        mut request: RunnerSpawnRequest,
        timeout: Option<Duration>,
    ) -> Result<Self, RunnerSessionError> {
        request.job_handle = launch.job_handle;
        request.desktop_name = launch.desktop_name().to_vec();
        let stdio = request.stdio;
        let boundary = launch.boundary();
        let mut request_pipe = launch.take_request()?;
        if let Err(error) = write_frame(&mut request_pipe, RunnerMessage::Spawn { request }) {
            let _ = boundary.terminate(125);
            return Err(error.into());
        }
        let mut response_pipe = launch.take_response()?;
        let message =
            match read_frame_until(&mut response_pipe, Instant::now() + SPAWN_HANDSHAKE_TIMEOUT) {
                Ok(message) => message,
                Err(error) => {
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
        let (stdout, stdout_target) = output_target(stdio.stdout, RunnerOutputStream::Stdout);
        let (stderr, stderr_target) = output_target(stdio.stderr, RunnerOutputStream::Stderr);
        let (stdin, inherited_stdin) = match stdio.stdin {
            RunnerStdioMode::Pipe => (
                Some(RunnerInput {
                    writer: Some(request_pipe),
                }),
                None,
            ),
            RunnerStdioMode::Inherit => match InheritedStdinForwarder::start(request_pipe) {
                Ok(forwarder) => (None, Some(forwarder)),
                Err(error) => {
                    let _ = boundary.terminate(125);
                    return Err(error);
                }
            },
            RunnerStdioMode::Null => (None, None),
        };
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
        let dispatcher = std::thread::spawn(move || {
            dispatch_responses(
                response_pipe,
                stdout_target,
                stderr_target,
                boundary,
                timed_out,
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
            inherited_stdin,
            terminal,
            dispatcher: Some(dispatcher),
            watchdog,
            finished: false,
        })
    }

    pub(crate) const fn id(&self) -> u32 {
        self.process_id
    }

    pub(crate) fn stdin(&mut self) -> Option<&mut RunnerInput> {
        self.stdin.as_mut()
    }

    pub(crate) fn stdout(&mut self) -> Option<&mut RunnerOutput> {
        self.stdout.as_mut()
    }

    pub(crate) fn stderr(&mut self) -> Option<&mut RunnerOutput> {
        self.stderr.as_mut()
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
        self.launch.boundary().terminate(1)?;
        Ok(())
    }

    fn finish(&mut self, terminal: RunnerTerminal) -> Result<ExitStatus, RunnerSessionError> {
        let result = self.finish_inner(terminal);
        if result.is_err() {
            let _ = self.launch.boundary().terminate(125);
        }
        self.finished = true;
        result
    }

    fn finish_inner(&mut self, terminal: RunnerTerminal) -> Result<ExitStatus, RunnerSessionError> {
        self.stdin = None;
        if let Some(mut forwarder) = self.inherited_stdin.take() {
            forwarder.stop()?;
        }
        if let Some(mut watchdog) = self.watchdog.take() {
            watchdog.stop()?;
        }
        if let Some(dispatcher) = self.dispatcher.take()
            && dispatcher.join().is_err()
        {
            return Err(RunnerSessionError::DispatcherPanic);
        }
        match terminal {
            RunnerTerminal::Exited(exit_code) => {
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

impl Write for RunnerInput {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let length = buffer.len().min(MAX_RUNNER_OUTPUT_CHUNK_BYTES);
        let Some(writer) = self.writer.as_mut() else {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "sandbox stdin is closed",
            ));
        };
        write_frame(
            writer,
            RunnerMessage::Stdin {
                bytes: buffer[..length].to_vec(),
            },
        )
        .map_err(io::Error::other)?;
        Ok(length)
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.writer.as_mut() {
            Some(writer) => writer.flush(),
            None => Ok(()),
        }
    }
}

impl RunnerInput {
    pub(crate) fn close(&mut self) -> Result<(), WindowsRunnerProtocolError> {
        if let Some(mut writer) = self.writer.take() {
            write_frame(&mut writer, RunnerMessage::CloseStdin)?;
        }
        Ok(())
    }
}

impl Read for RunnerOutput {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.reader.read(buffer)
    }
}

impl Read for ChannelReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        while self.offset == self.current.len() {
            match self.receiver.recv() {
                Ok(chunk) => {
                    self.current = chunk;
                    self.offset = 0;
                }
                Err(_) => return Ok(0),
            }
        }
        let length = buffer.len().min(self.current.len() - self.offset);
        buffer[..length].copy_from_slice(&self.current[self.offset..self.offset + length]);
        self.offset += length;
        Ok(length)
    }
}

impl InheritedStdinForwarder {
    fn start(mut writer: File) -> Result<Self, RunnerSessionError> {
        let (handle_sender, handle_receiver) = mpsc::sync_channel(1);
        let join = std::thread::spawn(move || {
            let handle = duplicate_current_thread_handle()
                .map_err(|code| RunnerSessionError::StdinThreadHandle { code });
            if handle_sender.send(handle).is_err() {
                return;
            }
            let mut input = io::stdin();
            let mut buffer = vec![0u8; MAX_RUNNER_OUTPUT_CHUNK_BYTES];
            loop {
                match input.read(&mut buffer) {
                    Ok(0) => {
                        let _ = write_frame(&mut writer, RunnerMessage::CloseStdin);
                        break;
                    }
                    Ok(length) => {
                        if write_frame(
                            &mut writer,
                            RunnerMessage::Stdin {
                                bytes: buffer[..length].to_vec(),
                            },
                        )
                        .is_err()
                        {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });
        let thread_handle = handle_receiver
            .recv()
            .map_err(|_| RunnerSessionError::StdinThreadMissing)??;
        Ok(Self {
            thread_handle,
            join: Some(join),
        })
    }

    #[allow(unsafe_code)]
    fn stop(&mut self) -> Result<(), RunnerSessionError> {
        if unsafe { CancelSynchronousIo(self.thread_handle.as_raw_handle() as _) } == 0 {
            let code = unsafe { GetLastError() };
            if code != ERROR_NOT_FOUND {
                return Err(RunnerSessionError::StdinCancel { code });
            }
        }
        if self.join.take().is_some_and(|join| join.join().is_err()) {
            return Err(RunnerSessionError::StdinForwarderPanic);
        }
        Ok(())
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

impl OutputTarget {
    fn write(&mut self, bytes: Vec<u8>) -> Result<(), RunnerSessionError> {
        match self {
            Self::Pipe(sender) => {
                let _ = sender.send(bytes);
                Ok(())
            }
            Self::InheritStdout(stdout) => stdout
                .write_all(&bytes)
                .and_then(|()| stdout.flush())
                .map_err(|source| RunnerSessionError::InheritedOutput {
                    stream: "stdout",
                    source,
                }),
            Self::InheritStderr(stderr) => stderr
                .write_all(&bytes)
                .and_then(|()| stderr.flush())
                .map_err(|source| RunnerSessionError::InheritedOutput {
                    stream: "stderr",
                    source,
                }),
            Self::Null => Err(RunnerSessionError::UnexpectedLifecycleMessage {
                actual: "output for a null stream",
            }),
        }
    }
}

impl Drop for RunnerSession {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.launch.boundary().terminate(125);
        }
        self.stdin = None;
        if let Some(mut forwarder) = self.inherited_stdin.take() {
            let _ = forwarder.stop();
        }
        if let Some(mut watchdog) = self.watchdog.take() {
            let _ = watchdog.stop();
        }
        if let Some(dispatcher) = self.dispatcher.take() {
            let _ = dispatcher.join();
        }
    }
}

fn output_target(
    mode: RunnerStdioMode,
    stream: RunnerOutputStream,
) -> (Option<RunnerOutput>, OutputTarget) {
    match mode {
        RunnerStdioMode::Pipe => {
            let (sender, receiver) = mpsc::channel();
            (
                Some(RunnerOutput {
                    reader: ChannelReader {
                        receiver,
                        current: Vec::new(),
                        offset: 0,
                    },
                }),
                OutputTarget::Pipe(sender),
            )
        }
        RunnerStdioMode::Inherit => match stream {
            RunnerOutputStream::Stdout => (None, OutputTarget::InheritStdout(io::stdout())),
            RunnerOutputStream::Stderr => (None, OutputTarget::InheritStderr(io::stderr())),
        },
        RunnerStdioMode::Null => (None, OutputTarget::Null),
    }
}

fn dispatch_responses(
    mut response: File,
    mut stdout: OutputTarget,
    mut stderr: OutputTarget,
    boundary: Arc<BoundaryTerminator>,
    timed_out: Arc<AtomicBool>,
    watchdog_cancel: Option<mpsc::SyncSender<()>>,
    terminal: mpsc::Sender<RunnerTerminal>,
) {
    let mut output_error = None;
    loop {
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
        match message {
            RunnerMessage::Output { stream, bytes } => {
                if bytes.len() > MAX_RUNNER_OUTPUT_CHUNK_BYTES {
                    let _ = boundary.terminate(125);
                    let _ = terminal.send(RunnerTerminal::Failed(
                        RunnerSessionError::OversizedOutput { stream },
                    ));
                    return;
                }
                let target = match stream {
                    RunnerOutputStream::Stdout => &mut stdout,
                    RunnerOutputStream::Stderr => &mut stderr,
                };
                if let Err(error) = target.write(bytes)
                    && output_error.is_none()
                {
                    output_error = Some(error);
                }
            }
            RunnerMessage::Exited { exit_code } => {
                if let Some(cancel) = watchdog_cancel {
                    let _ = cancel.try_send(());
                }
                if timed_out.load(Ordering::Acquire) {
                    return;
                }
                let terminal_value = output_error
                    .map(RunnerTerminal::Failed)
                    .unwrap_or(RunnerTerminal::Exited(exit_code));
                let _ = terminal.send(terminal_value);
                return;
            }
            RunnerMessage::Failed { failure } => {
                if let Some(cancel) = watchdog_cancel {
                    let _ = cancel.try_send(());
                }
                if timed_out.load(Ordering::Acquire) {
                    return;
                }
                let _ = boundary.terminate(125);
                let _ = terminal.send(RunnerTerminal::Failed(runner_failure(failure)));
                return;
            }
            other => {
                let _ = boundary.terminate(125);
                let _ = terminal.send(RunnerTerminal::Failed(
                    RunnerSessionError::UnexpectedLifecycleMessage {
                        actual: other.kind(),
                    },
                ));
                return;
            }
        }
    }
}

fn read_frame_until(
    reader: &mut File,
    deadline: Instant,
) -> Result<RunnerMessage, RunnerSessionError> {
    let mut length = [0u8; 4];
    read_exact_until(reader, &mut length, deadline)?;
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
    read_exact_until(reader, &mut frame[4..], deadline)?;
    read_frame(&mut frame.as_slice()).map_err(Into::into)
}

#[allow(unsafe_code)]
fn read_exact_until(
    reader: &mut File,
    mut buffer: &mut [u8],
    deadline: Instant,
) -> Result<(), RunnerSessionError> {
    while !buffer.is_empty() {
        if Instant::now() >= deadline {
            return Err(RunnerSessionError::SpawnHandshakeTimeout);
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
            return Err(RunnerSessionError::ResponseClosed);
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

#[allow(unsafe_code)]
fn exit_status(exit_code: u32) -> ExitStatus {
    use std::os::windows::process::ExitStatusExt;

    ExitStatus::from_raw(exit_code)
}
