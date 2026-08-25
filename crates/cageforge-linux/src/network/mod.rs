// SPDX-License-Identifier: Apache-2.0

//! Host gateway lifecycle for a restricted Linux network namespace.

use std::fs;
use std::io;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use cageforge_network_proxy::{GatewayConfig, GatewayIngressKey, NetworkGateway, SystemResolver};
use cageforge_policy_compose::EffectiveNetworkPolicy;
use tempfile::{Builder, TempDir};
use tokio::io::AsyncReadExt;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::UnixListener;
use tokio::sync::{Semaphore, oneshot};
use tokio::task::JoinSet;
use tokio::time::timeout;

use crate::error::{
    LinuxBackendError, NetworkGatewayIngressError, NetworkGatewayRuntimeError,
    NetworkGatewayRuntimeFailure, NetworkGatewaySetupError, NetworkGatewayTransportError,
};
use crate::helper_protocol::BRIDGE_TOKEN_BYTES;

pub(crate) const IN_SANDBOX_GATEWAY_SOCKET: &str = "/dev/.cageforge-runtime/network/gateway.sock";
const HOST_GATEWAY_SOCKET: &str = "gateway.sock";
const UNIX_SOCKET_PATH_MAX_BYTES: usize = 107;
const AUTHENTICATED_BRIDGE_BUFFER_BYTES: usize = 64 * 1024;

#[derive(Clone)]
struct BridgeIngressToken(Arc<[u8; BRIDGE_TOKEN_BYTES]>);

/// One independently budgeted host gateway owned by one launched process.
pub(crate) struct GatewayRuntime {
    _directory: TempDir,
    socket_directory: PathBuf,
    bridge_token: BridgeIngressToken,
    shutdown: Option<oneshot::Sender<()>>,
    thread: Option<JoinHandle<Result<(), NetworkGatewayRuntimeFailure>>>,
}

struct GatewayServer {
    listener: std::os::unix::net::UnixListener,
    gateway: NetworkGateway<SystemResolver>,
    ingress_key: GatewayIngressKey,
    bridge_token: BridgeIngressToken,
    handshake_timeout: Duration,
    pre_authentication_limit: usize,
}

impl BridgeIngressToken {
    fn generate() -> Result<Self, LinuxBackendError> {
        let mut bytes = [0; BRIDGE_TOKEN_BYTES];
        getrandom::fill(&mut bytes)
            .map_err(|source| LinuxBackendError::NetworkBridgeTokenGeneration { source })?;
        Ok(Self(Arc::new(bytes)))
    }

    fn write_to(&self, writer: &mut impl Write) -> io::Result<()> {
        writer.write_all(self.0.as_slice())
    }

    async fn verify<S: AsyncRead + Unpin>(
        &self,
        stream: &mut S,
    ) -> Result<(), NetworkGatewayIngressError> {
        let mut supplied = [0; BRIDGE_TOKEN_BYTES];
        stream
            .read_exact(&mut supplied)
            .await
            .map_err(|source| NetworkGatewayIngressError::TokenRead { source })?;
        let difference = self
            .0
            .iter()
            .zip(supplied)
            .fold(0_u8, |difference, (expected, supplied)| {
                difference | (expected ^ supplied)
            });
        if difference == 0 {
            Ok(())
        } else {
            Err(NetworkGatewayIngressError::TokenMismatch)
        }
    }
}

impl std::fmt::Debug for GatewayRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GatewayRuntime")
            .field("socket_directory", &self.socket_directory)
            .finish_non_exhaustive()
    }
}

impl GatewayRuntime {
    pub(crate) fn start(
        policy: EffectiveNetworkPolicy,
        config: GatewayConfig,
    ) -> Result<Self, LinuxBackendError> {
        let handshake_timeout = config.handshake_timeout();
        let pre_authentication_limit = config.max_concurrent_connections().get();
        let gateway = NetworkGateway::with_system_resolver(policy, config)
            .map_err(|source| LinuxBackendError::NetworkGatewayInitialization { source })?;
        let ingress_key = gateway.ingress_key();
        let bridge_token = BridgeIngressToken::generate()?;
        let directory = create_socket_directory()
            .map_err(|source| LinuxBackendError::NetworkGatewaySetup { source })?;
        let socket_directory = directory.path().to_path_buf();
        let socket_path = socket_directory.join(HOST_GATEWAY_SOCKET);
        let listener = std::os::unix::net::UnixListener::bind(&socket_path).map_err(|source| {
            LinuxBackendError::NetworkGatewaySetup {
                source: NetworkGatewaySetupError::SocketBind {
                    path: socket_path.clone(),
                    source,
                },
            }
        })?;
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600)).map_err(|source| {
            LinuxBackendError::NetworkGatewaySetup {
                source: NetworkGatewaySetupError::DirectoryPermissions {
                    path: socket_path.clone(),
                    source,
                },
            }
        })?;
        listener.set_nonblocking(true).map_err(|source| {
            LinuxBackendError::NetworkGatewaySetup {
                source: NetworkGatewaySetupError::SocketNonblocking {
                    path: socket_path.clone(),
                    source,
                },
            }
        })?;

        let (shutdown, shutdown_rx) = oneshot::channel();
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let thread = thread::Builder::new()
            .name("cageforge-network-gateway".to_string())
            .spawn({
                let server = GatewayServer {
                    listener,
                    gateway,
                    ingress_key,
                    bridge_token: bridge_token.clone(),
                    handshake_timeout,
                    pre_authentication_limit,
                };
                move || run_gateway(server, shutdown_rx, ready_tx)
            })
            .map_err(|source| LinuxBackendError::NetworkGatewaySetup {
                source: NetworkGatewaySetupError::ThreadSpawn { source },
            })?;
        match ready_rx.recv() {
            Ok(Ok(())) => Ok(Self {
                _directory: directory,
                socket_directory,
                bridge_token,
                shutdown: Some(shutdown),
                thread: Some(thread),
            }),
            Ok(Err(source)) => {
                let _ = thread.join();
                Err(NetworkGatewayRuntimeError::Failed { source }.into())
            }
            Err(_) => {
                let _ = thread.join();
                Err(NetworkGatewayRuntimeError::StartupChannelClosed.into())
            }
        }
    }

    pub(crate) fn mount_source(&self) -> &Path {
        &self.socket_directory
    }

    pub(crate) fn write_bridge_token(
        &self,
        writer: &mut impl Write,
    ) -> Result<(), NetworkGatewayTransportError> {
        self.bridge_token
            .write_to(writer)
            .map_err(|source| NetworkGatewayTransportError::BridgeTokenWrite { source })
    }

    pub(crate) fn check_health(&mut self) -> Result<(), LinuxBackendError> {
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
        Err(thread_failure(thread))
    }

    pub(crate) fn shutdown(&mut self) -> Result<(), LinuxBackendError> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let Some(thread) = self.thread.take() else {
            return Ok(());
        };
        match thread.join() {
            Ok(Ok(())) => Ok(()),
            Ok(Err(source)) => Err(NetworkGatewayRuntimeError::Failed { source }.into()),
            Err(_) => Err(NetworkGatewayRuntimeError::Panicked.into()),
        }
    }
}

impl Drop for GatewayRuntime {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

fn thread_failure(
    thread: JoinHandle<Result<(), NetworkGatewayRuntimeFailure>>,
) -> LinuxBackendError {
    let error = match thread.join() {
        Ok(Ok(())) => NetworkGatewayRuntimeError::Failed {
            source: NetworkGatewayRuntimeFailure::StoppedBeforeProcess,
        },
        Ok(Err(source)) => NetworkGatewayRuntimeError::Failed { source },
        Err(_) => NetworkGatewayRuntimeError::Panicked,
    };
    error.into()
}

fn create_socket_directory() -> Result<TempDir, NetworkGatewaySetupError> {
    let preferred = std::env::temp_dir();
    let fallback = Path::new("/tmp");
    let mut last_error = None;
    for parent in [preferred.as_path(), fallback] {
        match Builder::new()
            .prefix(".cageforge-network-")
            .tempdir_in(parent)
        {
            Ok(directory)
                if directory
                    .path()
                    .join(HOST_GATEWAY_SOCKET)
                    .as_os_str()
                    .as_bytes()
                    .len()
                    <= UNIX_SOCKET_PATH_MAX_BYTES =>
            {
                fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).map_err(
                    |source| NetworkGatewaySetupError::DirectoryPermissions {
                        path: directory.path().to_path_buf(),
                        source,
                    },
                )?;
                return Ok(directory);
            }
            Ok(directory) => {
                last_error = Some(NetworkGatewaySetupError::SocketPathTooLong {
                    path: directory.path().join(HOST_GATEWAY_SOCKET),
                });
            }
            Err(source) => {
                last_error = Some(NetworkGatewaySetupError::TemporaryDirectory {
                    parent: parent.to_path_buf(),
                    source,
                });
            }
        }
        if parent == fallback {
            break;
        }
    }
    Err(last_error.unwrap_or(NetworkGatewaySetupError::NoTemporaryDirectory))
}

fn run_gateway(
    server: GatewayServer,
    shutdown: oneshot::Receiver<()>,
    ready: mpsc::SyncSender<Result<(), NetworkGatewayRuntimeFailure>>,
) -> Result<(), NetworkGatewayRuntimeFailure> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|source| NetworkGatewayRuntimeFailure::RuntimeConstruction { source })?;
    runtime.block_on(async move {
        let listener = UnixListener::from_std(server.listener)
            .map_err(|source| NetworkGatewayRuntimeFailure::ListenerRegistration { source })?;
        ready
            .send(Ok(()))
            .map_err(|_| NetworkGatewayRuntimeFailure::StartupReceiverClosed)?;
        serve_gateway(
            listener,
            server.gateway,
            server.ingress_key,
            server.bridge_token,
            server.handshake_timeout,
            server.pre_authentication_limit,
            shutdown,
        )
        .await
    })
}

async fn serve_gateway(
    listener: UnixListener,
    gateway: NetworkGateway<SystemResolver>,
    ingress_key: GatewayIngressKey,
    bridge_token: BridgeIngressToken,
    handshake_timeout: Duration,
    pre_authentication_limit: usize,
    mut shutdown: oneshot::Receiver<()>,
) -> Result<(), NetworkGatewayRuntimeFailure> {
    let mut connections = JoinSet::new();
    let pre_authentication = Arc::new(Semaphore::new(pre_authentication_limit));
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            accepted = listener.accept() => {
                let (stream, _) = accepted
                    .map_err(|source| NetworkGatewayRuntimeFailure::Listener { source })?;
                let Ok(permit) = Arc::clone(&pre_authentication).try_acquire_owned() else {
                    drop(stream);
                    continue;
                };
                connections.spawn(serve_private_stream(
                    gateway.clone(),
                    ingress_key.clone(),
                    bridge_token.clone(),
                    handshake_timeout,
                    permit,
                    stream,
                ));
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    Ok(())
}

async fn serve_private_stream<S>(
    gateway: NetworkGateway<SystemResolver>,
    ingress_key: GatewayIngressKey,
    bridge_token: BridgeIngressToken,
    handshake_timeout: Duration,
    pre_authentication_permit: tokio::sync::OwnedSemaphorePermit,
    mut private_stream: S,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if !matches!(
        timeout(handshake_timeout, bridge_token.verify(&mut private_stream),).await,
        Ok(Ok(()))
    ) {
        return;
    }
    drop(pre_authentication_permit);
    let (mut trusted_bridge, gateway_stream) = tokio::io::duplex(AUTHENTICATED_BRIDGE_BUFFER_BYTES);
    if ingress_key.authenticate(&mut trusted_bridge).await.is_err() {
        return;
    }
    let gateway_future = gateway.serve_connection(gateway_stream);
    let relay_future = tokio::io::copy_bidirectional(&mut private_stream, &mut trusted_bridge);
    let _ = tokio::join!(gateway_future, relay_future);
}

#[cfg(test)]
#[path = "../network_tests.rs"]
mod tests;
