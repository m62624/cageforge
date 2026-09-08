// SPDX-License-Identifier: Apache-2.0

use std::{
    error::Error,
    io::{Cursor, Read, Write},
    path::PathBuf,
    process::ExitStatus,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::Duration,
};

use cageforge_backend_api::{
    BackendCapabilities, BackendContractError, BackendIdentity, BackendRequest, DynSandbox,
    PreparedBackendRequest, Sandbox, SandboxBackend, SandboxChild, SandboxExecutionError,
};
use cageforge_command::{CommandRequest, CommandSpec, EnvironmentSpec};
use cageforge_policy::{PathResolutionContext, SandboxPolicy};
use cageforge_policy_compose::{CompositionRequest, EffectiveSandbox, PolicyCeiling, compose};

struct Backend {
    identity: BackendIdentity,
    capabilities: BackendCapabilities,
    state: Arc<State>,
}

struct Child {
    state: Arc<State>,
    id: u32,
    input: Vec<u8>,
    output: Cursor<Vec<u8>>,
    error: Cursor<Vec<u8>>,
    finished: bool,
}

#[derive(Default)]
struct State {
    spawned: AtomicUsize,
    dropped: AtomicUsize,
    fail_spawn: AtomicBool,
    fail_lifecycle: AtomicBool,
}

#[derive(Debug, thiserror::Error)]
enum FixtureError {
    #[error(transparent)]
    Contract(#[from] BackendContractError),
    #[error("injected spawn failure")]
    Spawn,
    #[error("injected lifecycle failure")]
    Lifecycle,
}

impl SandboxBackend for Backend {
    fn identity(&self) -> &BackendIdentity {
        &self.identity
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.capabilities.clone()
    }
}

impl Sandbox for Backend {
    type Child = Child;
    type Error = FixtureError;

    fn prepare<'a>(
        &self,
        request: BackendRequest<'a>,
        context: &PathResolutionContext,
    ) -> Result<PreparedBackendRequest<'a, Self>, Self::Error> {
        Ok(request.prepare_for(self, context)?)
    }

    fn spawn<'a>(
        &self,
        prepared: PreparedBackendRequest<'a, Self>,
    ) -> Result<Self::Child, Self::Error> {
        let command = prepared.command_spec(self)?;
        if self.state.fail_spawn.load(Ordering::SeqCst) {
            return Err(FixtureError::Spawn);
        }
        let id = self.state.spawned.fetch_add(1, Ordering::SeqCst) as u32 + 1;
        Ok(Child {
            state: Arc::clone(&self.state),
            id,
            input: Vec::new(),
            output: Cursor::new(command.program().to_string_lossy().as_bytes().to_vec()),
            error: Cursor::new(b"fixture stderr".to_vec()),
            finished: false,
        })
    }
}

impl SandboxChild for Child {
    type Error = FixtureError;

    fn id(&self) -> u32 {
        self.id
    }

    fn stdin(&mut self) -> Option<&mut dyn Write> {
        Some(&mut self.input)
    }

    fn stdout(&mut self) -> Option<&mut dyn Read> {
        Some(&mut self.output)
    }

    fn stderr(&mut self) -> Option<&mut dyn Read> {
        Some(&mut self.error)
    }

    fn try_wait(&mut self) -> Result<Option<ExitStatus>, Self::Error> {
        if self.state.fail_lifecycle.load(Ordering::SeqCst) {
            return Err(FixtureError::Lifecycle);
        }
        Ok(self.finished.then(ExitStatus::default))
    }

    fn wait(&mut self) -> Result<ExitStatus, Self::Error> {
        self.kill()?;
        Ok(ExitStatus::default())
    }

    fn kill(&mut self) -> Result<(), Self::Error> {
        if self.state.fail_lifecycle.load(Ordering::SeqCst) {
            return Err(FixtureError::Lifecycle);
        }
        self.finished = true;
        Ok(())
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        self.state.dropped.fetch_add(1, Ordering::SeqCst);
    }
}

fn inputs(program: &str) -> (CommandRequest, EffectiveSandbox, PathResolutionContext) {
    let environment = EnvironmentSpec::empty();
    let policy = SandboxPolicy::full_access();
    let ceiling = PolicyCeiling::new(policy.clone(), environment.clone());
    let effective = compose(CompositionRequest::new(&policy, &environment, &ceiling))
        .expect("compose fixture policy");
    let command = CommandRequest::new(CommandSpec::new(program).expect("program"))
        .with_environment(environment);
    let root = if cfg!(target_os = "windows") {
        PathBuf::from(r"C:\workspace")
    } else {
        PathBuf::from("/workspace")
    };
    let context = PathResolutionContext::new()
        .with_current_directory(root)
        .expect("absolute cwd");
    (command, effective, context)
}

fn backend(request: BackendRequest<'_>) -> Backend {
    Backend {
        identity: BackendIdentity::new(),
        capabilities: request.required_capabilities(),
        state: Arc::new(State::default()),
    }
}

#[test]
fn dynamic_launch_rejects_unsupported_capabilities_before_spawn() {
    let (command, effective, context) = inputs("rejected");
    let request = BackendRequest::new(&command, &effective);
    let mut backend = backend(request);
    backend.capabilities = BackendCapabilities::new();
    let dynamic: &dyn DynSandbox = &backend;
    let error = dynamic.launch(request, &context).err().expect("rejection");
    assert!(matches!(error, SandboxExecutionError::Prepare { .. }));
    assert!(matches!(
        error
            .source()
            .and_then(|source| source.downcast_ref::<FixtureError>()),
        Some(FixtureError::Contract(
            BackendContractError::UnsupportedCapability { .. }
        ))
    ));
    assert_eq!(backend.state.spawned.load(Ordering::SeqCst), 0);
}

#[test]
fn dynamic_spawn_preserves_native_error_type() {
    let (command, effective, context) = inputs("failed");
    let request = BackendRequest::new(&command, &effective);
    let backend = backend(request);
    backend.state.fail_spawn.store(true, Ordering::SeqCst);
    let dynamic: Box<dyn DynSandbox> = Box::new(backend);
    let error = dynamic
        .launch(request, &context)
        .err()
        .expect("spawn error");
    assert!(matches!(error, SandboxExecutionError::Spawn { .. }));
    assert!(matches!(
        error
            .source()
            .and_then(|source| source.downcast_ref::<FixtureError>()),
        Some(FixtureError::Spawn)
    ));
}

#[test]
fn dynamic_child_preserves_streams_status_and_native_drop() {
    let (command, effective, context) = inputs("selected-program");
    let request = BackendRequest::new(&command, &effective);
    let backend = backend(request);
    let state = Arc::clone(&backend.state);
    let mut child = backend.launch(request, &context).expect("launch");
    drop(backend);
    assert_eq!(state.dropped.load(Ordering::SeqCst), 0);
    assert_eq!(child.id(), 1);
    assert_eq!(child.try_wait().expect("poll"), None);
    child
        .stdin()
        .expect("stdin")
        .write_all(b"input")
        .expect("write");
    let mut output = String::new();
    child
        .stdout()
        .expect("stdout")
        .read_to_string(&mut output)
        .expect("read");
    assert_eq!(output, "selected-program");
    output.clear();
    child
        .stderr()
        .expect("stderr")
        .read_to_string(&mut output)
        .expect("read");
    assert_eq!(output, "fixture stderr");
    assert!(child.wait().expect("wait").success());
    assert!(
        child
            .try_wait()
            .expect("poll after wait")
            .expect("status")
            .success()
    );
    child.kill().expect("terminate completed child");
    assert_eq!(state.dropped.load(Ordering::SeqCst), 0);
    drop(child);
    assert_eq!(state.dropped.load(Ordering::SeqCst), 1);
}

#[test]
fn lifecycle_errors_retain_the_child_until_drop_or_retry() {
    let (command, effective, context) = inputs("lifecycle");
    let request = BackendRequest::new(&command, &effective);
    let backend = backend(request);
    let mut child = backend.launch(request, &context).expect("launch");
    backend.state.fail_lifecycle.store(true, Ordering::SeqCst);
    let poll = child.try_wait().expect_err("poll failure");
    let wait = child.wait().expect_err("wait failure");
    let kill = child.kill().expect_err("kill failure");
    assert!(matches!(poll, SandboxExecutionError::TryWait { .. }));
    assert!(matches!(wait, SandboxExecutionError::Wait { .. }));
    assert!(matches!(kill, SandboxExecutionError::Kill { .. }));
    for error in [poll, wait, kill] {
        assert!(matches!(
            error
                .source()
                .and_then(|source| source.downcast_ref::<FixtureError>()),
            Some(FixtureError::Lifecycle)
        ));
    }
    assert_eq!(backend.state.dropped.load(Ordering::SeqCst), 0);
    backend.state.fail_lifecycle.store(false, Ordering::SeqCst);
    child.kill().expect("retry termination");
    drop(child);
    assert_eq!(backend.state.dropped.load(Ordering::SeqCst), 1);
}

#[test]
fn shared_dynamic_backend_keeps_concurrent_requests_and_child_ownership_separate() {
    let (command, effective, _) = inputs("template");
    let backend = backend(BackendRequest::new(&command, &effective));
    let state = Arc::clone(&backend.state);
    let shared: Arc<dyn DynSandbox> = Arc::new(backend);
    let (sender, receiver) = mpsc::channel();
    thread::scope(|scope| {
        for index in 0..8 {
            let backend = Arc::clone(&shared);
            let sender = sender.clone();
            scope.spawn(move || {
                let name = format!("command-{index}");
                let (command, effective, context) = inputs(&name);
                let child = backend
                    .launch(BackendRequest::new(&command, &effective), &context)
                    .expect("concurrent launch");
                sender
                    .send((name, child))
                    .unwrap_or_else(|_| panic!("receiver dropped"));
            });
        }
    });
    drop(sender);
    drop(shared);
    assert_eq!(state.spawned.load(Ordering::SeqCst), 8);
    assert_eq!(state.dropped.load(Ordering::SeqCst), 0);
    let mut ids = std::collections::BTreeSet::new();
    for _ in 0..8 {
        let (name, mut child) = receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("child");
        assert!(ids.insert(child.id()));
        let mut output = String::new();
        child
            .stdout()
            .expect("stdout")
            .read_to_string(&mut output)
            .expect("read");
        assert_eq!(output, name);
        drop(child);
    }
    assert_eq!(state.dropped.load(Ordering::SeqCst), 8);
}
