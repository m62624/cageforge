// SPDX-License-Identifier: Apache-2.0

//! Per-instance macOS network lowering and authenticated proxy gateway.

use std::collections::BTreeSet;
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use cageforge_backend_api::{PreparedBackendRequest, SandboxBackend};
use cageforge_network_proxy::{GatewayConfig, GatewayIngressKey, NetworkGateway, SystemResolver};
use cageforge_path::NativePathKey;
use cageforge_policy::{NetworkDecision, NetworkMode, UnixSocketMode};
use cageforge_policy_compose::EffectiveNetworkLowering;
use tokio::net::{TcpListener as TokioTcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinSet;

use crate::error::MacosNetworkError;

const NETWORK_GATEWAY_THREAD_NAME: &str = "cageforge-macos-network-gateway";
const GATEWAY_RELAY_BUFFER_BYTES: usize = 64 * 1024;
const GATEWAY_STARTUP_TIMEOUT: Duration = Duration::from_secs(10);

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
    denied: Vec<PathBuf>,
}

/// One host gateway owned by one macOS sandbox instance.
pub(crate) struct GatewayRuntime {
    port: u16,
    shutdown: Option<oneshot::Sender<()>>,
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
                if requirements.domain_rules() || requirements.local_address_restrictions() =>
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

    pub(crate) fn denied(&self) -> &[PathBuf] {
        &self.denied
    }
}

impl GatewayRuntime {
    pub(crate) fn start(
        policy: cageforge_policy_compose::EffectiveNetworkPolicy,
        config: GatewayConfig,
    ) -> Result<Self, MacosNetworkError> {
        let gateway = NetworkGateway::with_system_resolver(policy, config)
            .map_err(|source| MacosNetworkError::Gateway { source })?;
        let ingress_key = gateway.ingress_key();
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .map_err(|source| MacosNetworkError::Listener { source })?;
        listener
            .set_nonblocking(true)
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
                    shutdown_receiver,
                    ready_sender,
                )
            })
            .map_err(|source| MacosNetworkError::ThreadSpawn { source })?;
        match ready_receiver.recv_timeout(GATEWAY_STARTUP_TIMEOUT) {
            Ok(Ok(())) => Ok(Self {
                port,
                shutdown: Some(shutdown),
                thread: Some(thread),
            }),
            Ok(Err(source)) => {
                let _ = thread.join();
                Err(source)
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let _ = shutdown.send(());
                drop(thread);
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
        let _ = self.shutdown();
    }
}

fn lower_unix_socket_plan<'request, B: SandboxBackend>(
    backend: &B,
    prepared: &PreparedBackendRequest<'request, B>,
    lowering: EffectiveNetworkLowering<'_>,
) -> Result<MacosUnixSocketPlan, MacosNetworkError> {
    let requirements = prepared.sandbox(backend)?.network().requirements();
    if requirements.local_ipc_isolation() {
        return Ok(MacosUnixSocketPlan::default());
    }
    let allow_all = !requirements.local_ipc_rules();
    let mut allowed = Vec::new();
    let mut denied = Vec::new();
    let mut allowed_keys = BTreeSet::new();
    let mut denied_keys = BTreeSet::new();
    for layer in lowering.layers() {
        if layer.mode() == NetworkMode::External {
            return Err(MacosNetworkError::ExternalOwnership);
        }
        if layer.unix_socket_mode() == UnixSocketMode::Enabled && allow_all {
            continue;
        }
        for rule in layer.unix_sockets() {
            let path = rule.path().to_path_buf();
            match prepared.network_decision_for_unix_socket(backend, &path)? {
                NetworkDecision::Allow => {
                    if allowed_keys.insert(NativePathKey::new(&path)) {
                        allowed.push(path);
                    }
                }
                NetworkDecision::Deny => {
                    if denied_keys.insert(NativePathKey::new(&path)) {
                        denied.push(path);
                    }
                }
                NetworkDecision::ExternallyEnforced => {
                    return Err(MacosNetworkError::ExternalOwnership);
                }
            }
        }
    }
    allowed.sort_by_key(|path| NativePathKey::new(path));
    denied.sort_by_key(|path| NativePathKey::new(path));
    Ok(MacosUnixSocketPlan {
        allow_all,
        allowed,
        denied,
    })
}

fn run_gateway(
    listener: TcpListener,
    gateway: NetworkGateway<SystemResolver>,
    ingress_key: GatewayIngressKey,
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
        serve_gateway(listener, gateway, ingress_key, shutdown).await
    })
}

async fn serve_gateway(
    listener: TokioTcpListener,
    gateway: NetworkGateway<SystemResolver>,
    ingress_key: GatewayIngressKey,
    mut shutdown: oneshot::Receiver<()>,
) -> Result<(), MacosNetworkError> {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            accepted = listener.accept() => {
                let (stream, _) = accepted.map_err(|source| MacosNetworkError::RuntimeListener { source })?;
                connections.spawn(serve_private_stream(stream, gateway.clone(), ingress_key.clone()));
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    Ok(())
}

async fn serve_private_stream(
    mut client: TcpStream,
    gateway: NetworkGateway<SystemResolver>,
    ingress_key: GatewayIngressKey,
) {
    let (mut client_side, gateway_side) = tokio::io::duplex(GATEWAY_RELAY_BUFFER_BYTES);
    if ingress_key.authenticate(&mut client_side).await.is_err() {
        return;
    }
    let gateway_task = gateway.serve_connection(gateway_side);
    let relay = tokio::io::copy_bidirectional(&mut client, &mut client_side);
    tokio::pin!(gateway_task);
    tokio::pin!(relay);
    tokio::select! {
        result = &mut gateway_task => {
            if let Err(error) = result {
                if std::env::var_os("CAGEFORGE_DEBUG_SEATBELT_PROFILE").is_some() {
                    eprintln!("Cageforge macOS gateway connection failed: {error}");
                }
            }
        }
        result = &mut relay => {
            if let Err(error) = result {
                if std::env::var_os("CAGEFORGE_DEBUG_SEATBELT_PROFILE").is_some() {
                    eprintln!("Cageforge macOS gateway relay failed: {error}");
                }
            }
        }
    }
}
