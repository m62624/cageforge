// SPDX-License-Identifier: Apache-2.0

//! Per-instance macOS network lowering and authenticated proxy gateway.

use std::collections::BTreeSet;
use std::fs;
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use cageforge_backend_api::{PreparedBackendRequest, SandboxBackend};
use cageforge_network_proxy::{GatewayConfig, GatewayIngressKey, NetworkGateway, SystemResolver};
use cageforge_path::{NativePathKey, normalize_lexical_path};
use cageforge_policy::{NetworkDecision, NetworkMode, UnixSocketMode};
use cageforge_policy_compose::EffectiveNetworkLowering;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener as TokioTcpListener, TcpStream};
use tokio::sync::{Semaphore, oneshot};
use tokio::task::JoinSet;
use tokio::time::timeout;

use crate::error::MacosNetworkError;

const NETWORK_GATEWAY_THREAD_NAME: &str = "cageforge-macos-network-gateway";
const NETWORK_GATEWAY_RECOVERY_THREAD_NAME: &str = "cageforge-macos-network-gateway-recovery";
const GATEWAY_RELAY_BUFFER_BYTES: usize = 64 * 1024;
const GATEWAY_STARTUP_TIMEOUT: Duration = Duration::from_secs(10);
const GATEWAY_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
const GATEWAY_SHUTDOWN_POLL_INTERVAL: Duration = Duration::from_millis(5);

/// Native network rules for one Seatbelt launch.
#[derive(Debug)]
pub(crate) enum MacosNetworkPlan {
    /// No network access is permitted.
    Disabled { unix: MacosUnixSocketPlan },
    /// Direct network access is permitted by the complete effective policy.
    Direct { unix: MacosUnixSocketPlan },
    /// Only the private per-instance gateway port is permitted.
    Proxy {
        unix: MacosUnixSocketPlan,
        ingress_port: Option<u16>,
    },
}

/// Pathname Unix-socket rules for one Seatbelt launch.
#[derive(Debug, Default)]
pub(crate) struct MacosUnixSocketPlan {
    allow_all: bool,
    allowed: Vec<PathBuf>,
}

/// One host gateway owned by one macOS sandbox instance.
pub(crate) struct GatewayRuntime {
    port: u16,
    // Keep the port reserved in the owning thread as well as in the gateway
    // thread. If the gateway exits unexpectedly while the child is still
    // running, another process must not be able to bind the Seatbelt-allowed
    // port and impersonate the gateway.
    _port_reservation: TcpListener,
    shutdown: Option<oneshot::Sender<()>>,
    thread: Option<JoinHandle<Result<(), MacosNetworkError>>>,
}

struct GatewayThreadRecovery {
    thread: Option<JoinHandle<Result<(), MacosNetworkError>>>,
}

impl MacosNetworkPlan {
    /// Lowers every effective network layer into a native launch plan.
    pub(crate) fn lower<'request, B: SandboxBackend>(
        backend: &B,
        prepared: &PreparedBackendRequest<'request, B>,
    ) -> Result<Self, MacosNetworkError> {
        let sandbox = prepared.sandbox(backend)?;
        let requirements = sandbox.network().requirements();
        if requirements.mode() == NetworkMode::External {
            return Err(MacosNetworkError::ExternalOwnership);
        }
        let lowering = prepared.network_lowering(backend)?;
        let unix = lower_unix_socket_plan(backend, prepared, lowering)?;
        match requirements.mode() {
            NetworkMode::Disabled => Ok(Self::Disabled { unix }),
            NetworkMode::Enabled
                if requirements.domain_rules()
                    || requirements.local_address_restrictions()
                    || requirements.resolved_targets() =>
            {
                Ok(Self::Proxy {
                    unix,
                    ingress_port: None,
                })
            }
            NetworkMode::Enabled => Ok(Self::Direct { unix }),
            NetworkMode::External => Err(MacosNetworkError::ExternalOwnership),
        }
    }

    pub(crate) fn requires_gateway(&self) -> bool {
        matches!(self, Self::Proxy { .. })
    }

    pub(crate) fn with_ingress_port(self, ingress_port: u16) -> Self {
        match self {
            Self::Proxy { unix, .. } => Self::Proxy {
                unix,
                ingress_port: Some(ingress_port),
            },
            other => other,
        }
    }

    pub(crate) fn proxy_port(&self) -> Option<u16> {
        match self {
            Self::Proxy { ingress_port, .. } => *ingress_port,
            Self::Disabled { .. } | Self::Direct { .. } => None,
        }
    }
}

impl MacosUnixSocketPlan {
    pub(crate) fn allow_all(&self) -> bool {
        self.allow_all
    }

    pub(crate) fn allowed(&self) -> &[PathBuf] {
        &self.allowed
    }
}

impl GatewayRuntime {
    pub(crate) fn start(
        policy: cageforge_policy_compose::EffectiveNetworkPolicy,
        config: GatewayConfig,
    ) -> Result<Self, MacosNetworkError> {
        let max_concurrent_connections = config.max_concurrent_connections();
        let relay_idle_timeout = config.relay_idle_timeout();
        let gateway = NetworkGateway::with_system_resolver(policy, config)
            .map_err(|source| MacosNetworkError::Gateway { source })?;
        let ingress_key = gateway.ingress_key();
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .map_err(|source| MacosNetworkError::Listener { source })?;
        listener
            .set_nonblocking(true)
            .map_err(|source| MacosNetworkError::Listener { source })?;
        let reservation = listener
            .try_clone()
            .map_err(|source| MacosNetworkError::Listener { source })?;
        let port = listener
            .local_addr()
            .map_err(|source| MacosNetworkError::Listener { source })?
            .port();
        let (shutdown, shutdown_receiver) = oneshot::channel();
        let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
        let thread = thread::Builder::new()
            .name(NETWORK_GATEWAY_THREAD_NAME.to_owned())
            .spawn(move || {
                run_gateway(
                    listener,
                    gateway,
                    ingress_key,
                    max_concurrent_connections,
                    relay_idle_timeout,
                    shutdown_receiver,
                    ready_sender,
                )
            })
            .map_err(|source| MacosNetworkError::ThreadSpawn { source })?;
        match ready_receiver.recv_timeout(GATEWAY_STARTUP_TIMEOUT) {
            Ok(Ok(())) => Ok(Self {
                port,
                _port_reservation: reservation,
                shutdown: Some(shutdown),
                thread: Some(thread),
            }),
            Ok(Err(source)) => {
                let _ = thread.join();
                Err(source)
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let _ = shutdown.send(());
                retain_gateway_thread(thread);
                Err(MacosNetworkError::StartupTimeout {
                    timeout_ms: GATEWAY_STARTUP_TIMEOUT.as_millis(),
                })
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                let _ = thread.join();
                Err(MacosNetworkError::StartupChannelClosed)
            }
        }
    }

    pub(crate) fn port(&self) -> u16 {
        self.port
    }

    pub(crate) fn check_health(&mut self) -> Result<(), MacosNetworkError> {
        let Some(thread) = self.thread.as_ref() else {
            return Ok(());
        };
        if !thread.is_finished() {
            return Ok(());
        }
        self.shutdown.take();
        let Some(thread) = self.thread.take() else {
            return Ok(());
        };
        match thread.join() {
            Ok(Ok(())) => Err(MacosNetworkError::RuntimeStopped),
            Ok(Err(error)) => Err(error),
            Err(_) => Err(MacosNetworkError::RuntimePanicked),
        }
    }

    pub(crate) fn shutdown(&mut self) -> Result<(), MacosNetworkError> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        self.shutdown_with_timeout(GATEWAY_SHUTDOWN_TIMEOUT)
    }

    fn shutdown_with_timeout(&mut self, timeout: Duration) -> Result<(), MacosNetworkError> {
        let Some(thread) = self.thread.as_ref() else {
            return Ok(());
        };
        let deadline = Instant::now() + timeout;
        while !thread.is_finished() {
            if Instant::now() >= deadline {
                return Err(MacosNetworkError::RuntimeShutdownTimeout {
                    timeout_ms: timeout.as_millis(),
                });
            }
            thread::sleep(GATEWAY_SHUTDOWN_POLL_INTERVAL);
        }
        let Some(thread) = self.thread.take() else {
            return Ok(());
        };
        match thread.join() {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(error),
            Err(_) => Err(MacosNetworkError::RuntimePanicked),
        }
    }
}

impl Drop for GatewayRuntime {
    fn drop(&mut self) {
        if self.shutdown().is_err()
            && let Some(thread) = self.thread.take()
        {
            retain_gateway_thread(thread);
        }
    }
}

fn retain_gateway_thread(thread: JoinHandle<Result<(), MacosNetworkError>>) {
    // The gateway thread remains the owner of its listener and runtime until
    // it exits. Keep joining it in a recovery owner instead of blocking the
    // caller during ordinary cleanup. If the recovery thread cannot be
    // created, its Drop path intentionally retains the live thread.
    let recovery = GatewayThreadRecovery {
        thread: Some(thread),
    };
    let _ = thread::Builder::new()
        .name(NETWORK_GATEWAY_RECOVERY_THREAD_NAME.to_owned())
        .spawn(move || {
            recovery.join();
        });
}

impl GatewayThreadRecovery {
    fn join(mut self) {
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for GatewayThreadRecovery {
    fn drop(&mut self) {
        if let Some(thread) = self.thread.take() {
            // A failed reaper-thread spawn must not block the caller while a
            // gateway may be stuck. Keep the live runtime owned so its
            // listener and policy cannot be released as if shutdown had been
            // confirmed. This mirrors the process-boundary recovery policy.
            std::mem::forget(thread);
        }
    }
}

fn lower_unix_socket_plan<'request, B: SandboxBackend>(
    backend: &B,
    prepared: &PreparedBackendRequest<'request, B>,
    lowering: EffectiveNetworkLowering<'_>,
) -> Result<MacosUnixSocketPlan, MacosNetworkError> {
    let requirements = prepared.sandbox(backend)?.network().requirements();
    if requirements.mode() == NetworkMode::Disabled || requirements.local_ipc_isolation() {
        return Ok(MacosUnixSocketPlan::default());
    }
    // A rule does not itself change the default mode. Two `Enabled` layers
    // still mean "allow all except matching deny rules"; only a `Restricted`
    // layer changes the default to deny. Derive this from both immutable
    // lowering layers instead of from the presence of rules.
    let allow_all = lowering
        .layers()
        .all(|layer| layer.unix_socket_mode() == UnixSocketMode::Enabled);
    let mut allowed = Vec::new();
    let mut allowed_keys = BTreeSet::new();
    for layer in lowering.layers() {
        if layer.mode() == NetworkMode::External {
            return Err(MacosNetworkError::ExternalOwnership);
        }
        for rule in layer.unix_sockets() {
            let path = rule.path().to_path_buf();
            match prepared.network_decision_for_unix_socket(backend, &path)? {
                NetworkDecision::Allow => {
                    let native_path = normalize_unix_socket_path(&path);
                    if !allow_all && allowed_keys.insert(NativePathKey::new(&native_path)) {
                        allowed.push(native_path);
                    }
                }
                NetworkDecision::Deny => {
                    if allow_all {
                        return Err(MacosNetworkError::UnixSocketPolicy {
                            mode: layer.unix_socket_mode(),
                        });
                    }
                }
                NetworkDecision::ExternallyEnforced => {
                    return Err(MacosNetworkError::ExternalOwnership);
                }
            }
        }
    }
    allowed.sort_by_key(|path| NativePathKey::new(path));
    Ok(MacosUnixSocketPlan { allow_all, allowed })
}

fn normalize_unix_socket_path(path: &std::path::Path) -> PathBuf {
    let lexical = normalize_lexical_path(path).into_owned();
    fs::canonicalize(&lexical)
        .map(|canonical| normalize_lexical_path(&canonical).into_owned())
        .unwrap_or(lexical)
}

fn run_gateway(
    listener: TcpListener,
    gateway: NetworkGateway<SystemResolver>,
    ingress_key: GatewayIngressKey,
    max_concurrent_connections: std::num::NonZeroUsize,
    relay_idle_timeout: Duration,
    shutdown: oneshot::Receiver<()>,
    ready: mpsc::SyncSender<Result<(), MacosNetworkError>>,
) -> Result<(), MacosNetworkError> {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(source) => {
            let _ = ready.send(Err(MacosNetworkError::RuntimeConstruction { source }));
            return Ok(());
        }
    };
    runtime.block_on(async move {
        let listener = match TokioTcpListener::from_std(listener) {
            Ok(listener) => listener,
            Err(source) => {
                let _ = ready.send(Err(MacosNetworkError::ListenerRegistration { source }));
                return Ok(());
            }
        };
        ready
            .send(Ok(()))
            .map_err(|_| MacosNetworkError::StartupChannelClosed)?;
        serve_gateway(
            listener,
            gateway,
            ingress_key,
            max_concurrent_connections,
            relay_idle_timeout,
            shutdown,
        )
        .await
    })
}

async fn serve_gateway(
    listener: TokioTcpListener,
    gateway: NetworkGateway<SystemResolver>,
    ingress_key: GatewayIngressKey,
    max_concurrent_connections: std::num::NonZeroUsize,
    relay_idle_timeout: Duration,
    mut shutdown: oneshot::Receiver<()>,
) -> Result<(), MacosNetworkError> {
    let mut connections = JoinSet::new();
    let admission = std::sync::Arc::new(Semaphore::new(max_concurrent_connections.get()));
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            accepted = listener.accept() => {
                let (stream, _) = accepted.map_err(|source| MacosNetworkError::RuntimeListener { source })?;
                let Some(permit) = try_admission(&admission) else {
                    // Refuse excess ingress before creating a relay task or
                    // retaining another socket. The network gateway has its
                    // own limit for direct callers; this admission limit also
                    // bounds the macOS TCP bridge itself.
                    drop(stream);
                    continue;
                };
                connections.spawn(serve_private_stream(
                    stream,
                    gateway.clone(),
                    ingress_key.clone(),
                    permit,
                    relay_idle_timeout,
                ));
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    Ok(())
}

fn try_admission(
    admission: &std::sync::Arc<Semaphore>,
) -> Option<tokio::sync::OwnedSemaphorePermit> {
    admission.clone().try_acquire_owned().ok()
}

async fn serve_private_stream(
    client: TcpStream,
    gateway: NetworkGateway<SystemResolver>,
    ingress_key: GatewayIngressKey,
    _admission: tokio::sync::OwnedSemaphorePermit,
    relay_idle_timeout: Duration,
) {
    let (mut client_side, gateway_side) = tokio::io::duplex(GATEWAY_RELAY_BUFFER_BYTES);
    if ingress_key.authenticate(&mut client_side).await.is_err() {
        return;
    }
    let (private_reader, private_writer) = tokio::io::split(client);
    let (trusted_reader, trusted_writer) = tokio::io::split(client_side);
    let gateway_task = gateway.serve_connection(gateway_side);
    let to_gateway = relay_direction(private_reader, trusted_writer);
    let to_client = relay_direction(trusted_reader, private_writer);
    tokio::pin!(gateway_task);
    tokio::pin!(to_gateway, to_client);
    tokio::select! {
        result = &mut gateway_task => { let _ = result; }
        _ = &mut to_client => (),
        _ = &mut to_gateway => {
            tokio::select! {
                result = &mut gateway_task => { let _ = result; }
                _ = &mut to_client => (),
            }
        }
    }
    // The gateway may finish after writing response bytes into the duplex
    // buffer. Drain the client direction for the same bounded idle period as
    // the Linux bridge before dropping the relay futures.
    let _ = timeout(relay_idle_timeout, &mut to_client).await;
}

async fn relay_direction<R, W>(mut reader: R, mut writer: W) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let copied = tokio::io::copy(&mut reader, &mut writer).await;
    let shutdown = writer.shutdown().await;
    copied.and(shutdown).map(|_| ())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;
    use std::os::unix::net::UnixListener;
    use std::sync::Arc;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    use tempfile::TempDir;
    use tokio::sync::oneshot;

    use super::{GatewayRuntime, normalize_unix_socket_path, try_admission};
    use crate::error::MacosNetworkError;

    #[test]
    fn gateway_shutdown_has_a_bounded_join_and_retains_the_handle() {
        let (release_sender, release_receiver) = mpsc::channel();
        let thread = thread::spawn(move || {
            release_receiver
                .recv()
                .expect("test gateway release signal");
            Ok(())
        });
        let (shutdown, _receiver) = oneshot::channel();
        let reservation = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("reservation");
        let port = reservation
            .local_addr()
            .expect("reservation address")
            .port();
        let mut gateway = GatewayRuntime {
            port,
            _port_reservation: reservation,
            shutdown: Some(shutdown),
            thread: Some(thread),
        };

        let error = gateway
            .shutdown_with_timeout(Duration::from_millis(20))
            .expect_err("a blocked gateway join must be bounded");
        assert!(matches!(
            error,
            MacosNetworkError::RuntimeShutdownTimeout { timeout_ms: 20 }
        ));
        assert!(
            gateway.thread.is_some(),
            "the live thread must remain owned"
        );

        release_sender.send(()).expect("release test gateway");
        gateway
            .shutdown_with_timeout(Duration::from_secs(1))
            .expect("released gateway shutdown");
        assert!(gateway.thread.is_none());
    }

    #[test]
    fn gateway_keeps_its_port_reserved_until_cleanup() {
        let loopback = std::net::Ipv6Addr::LOCALHOST;
        let reservation = std::net::TcpListener::bind((loopback, 0)).expect("reservation");
        let port = reservation
            .local_addr()
            .expect("reservation address")
            .port();
        let (shutdown, _receiver) = oneshot::channel();
        let (release_sender, release_receiver) = mpsc::channel();
        let thread = thread::spawn(move || {
            release_receiver
                .recv()
                .expect("test gateway release signal");
            Ok(())
        });
        let mut gateway = GatewayRuntime {
            port,
            _port_reservation: reservation,
            shutdown: Some(shutdown),
            thread: Some(thread),
        };

        let error = std::net::TcpListener::bind((loopback, port))
            .expect_err("a live gateway port must remain reserved");
        assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse);

        release_sender.send(()).expect("release test gateway");
        gateway
            .shutdown_with_timeout(Duration::from_secs(1))
            .expect("released gateway shutdown");
        std::mem::drop(gateway);
        std::net::TcpListener::bind((loopback, port))
            .expect("gateway port is reusable after confirmed cleanup");
    }

    #[test]
    fn gateway_admission_does_not_retain_more_sockets_than_configured() {
        let admission = Arc::new(tokio::sync::Semaphore::new(1));
        let first = try_admission(&admission).expect("first connection permit");
        assert!(try_admission(&admission).is_none());
        drop(first);
        assert!(try_admission(&admission).is_some());
    }

    #[test]
    fn existing_unix_socket_alias_is_canonicalized_before_seatbelt_lowering() {
        let directory = TempDir::new().expect("socket directory");
        let target = directory.path().join("target.sock");
        let alias = directory.path().join("alias.sock");
        let _listener = UnixListener::bind(&target).expect("socket fixture");
        symlink(&target, &alias).expect("socket alias");

        assert_eq!(
            normalize_unix_socket_path(&alias),
            target.canonicalize().expect("canonical socket target")
        );
    }

    #[test]
    fn missing_unix_socket_keeps_its_lexical_path_for_later_creation() {
        let directory = TempDir::new().expect("socket directory");
        let path = directory.path().join("created-after-preflight.sock");

        assert_eq!(normalize_unix_socket_path(&path), path);
    }
}
