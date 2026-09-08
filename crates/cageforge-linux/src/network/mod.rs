// SPDX-License-Identifier: Apache-2.0

//! Host gateway lifecycle for a restricted Linux network namespace.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use cageforge_network_proxy::{GatewayConfig, GatewayIngressKey, NetworkGateway, SystemResolver};
use cageforge_policy_compose::EffectiveNetworkPolicy;
use tempfile::{Builder, TempDir};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
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
const NETWORK_GATEWAY_THREAD_NAME: &str = "cageforge-network-gateway";
const NETWORK_GATEWAY_RECOVERY_THREAD_NAME: &str = "cageforge-network-gateway-recovery";
const NETWORK_GATEWAY_STARTUP_TIMEOUT: Duration = Duration::from_secs(10);
const NETWORK_GATEWAY_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
const NETWORK_GATEWAY_SHUTDOWN_POLL_INTERVAL: Duration = Duration::from_millis(5);

#[derive(Clone)]
struct BridgeIngressToken(Arc<[u8; BRIDGE_TOKEN_BYTES]>);

/// One independently budgeted host gateway owned by one launched process.
pub(crate) struct GatewayRuntime {
    directory: Option<TempDir>,
    socket_file: File,
    socket_directory: PathBuf,
    bridge_token: BridgeIngressToken,
    shutdown: Option<oneshot::Sender<()>>,
    thread: Option<JoinHandle<Result<(), NetworkGatewayRuntimeFailure>>>,
}

struct GatewayThreadRecovery {
    directory: Option<TempDir>,
    thread: Option<JoinHandle<Result<(), NetworkGatewayRuntimeFailure>>>,
}

struct GatewayServer {
    listener: std::os::unix::net::UnixListener,
    gateway: NetworkGateway<SystemResolver>,
    ingress_key: GatewayIngressKey,
    bridge_token: BridgeIngressToken,
    timeouts: GatewayTimeouts,
    pre_authentication_limit: usize,
}

#[derive(Debug, Clone, Copy)]
struct GatewayTimeouts {
    handshake: Duration,
    relay_idle: Duration,
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
        let timeouts = GatewayTimeouts {
            handshake: config.handshake_timeout(),
            relay_idle: config.relay_idle_timeout(),
        };
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
        let socket_file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&socket_path)
            .map_err(|source| LinuxBackendError::NetworkGatewaySetup {
                source: NetworkGatewaySetupError::SocketPin {
                    path: socket_path.clone(),
                    source,
                },
            })?;

        let (shutdown, shutdown_rx) = oneshot::channel();
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let thread = thread::Builder::new()
            .name(NETWORK_GATEWAY_THREAD_NAME.to_owned())
            .spawn({
                let server = GatewayServer {
                    listener,
                    gateway,
                    ingress_key,
                    bridge_token: bridge_token.clone(),
                    timeouts,
                    pre_authentication_limit,
                };
                move || run_gateway(server, shutdown_rx, ready_tx)
            })
            .map_err(|source| LinuxBackendError::NetworkGatewaySetup {
                source: NetworkGatewaySetupError::ThreadSpawn { source },
            })?;
        match ready_rx.recv_timeout(NETWORK_GATEWAY_STARTUP_TIMEOUT) {
            Ok(Ok(())) => Ok(Self {
                directory: Some(directory),
                socket_file,
                socket_directory,
                bridge_token,
                shutdown: Some(shutdown),
                thread: Some(thread),
            }),
            Ok(Err(source)) => {
                retain_gateway_thread(thread, Some(directory));
                Err(NetworkGatewayRuntimeError::Failed { source }.into())
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                retain_gateway_thread(thread, Some(directory));
                Err(NetworkGatewayRuntimeError::StartupChannelClosed.into())
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let _ = shutdown.send(());
                retain_gateway_thread(thread, Some(directory));
                Err(NetworkGatewayRuntimeError::StartupTimeout {
                    timeout_ms: NETWORK_GATEWAY_STARTUP_TIMEOUT.as_millis(),
                }
                .into())
            }
        }
    }

    pub(crate) fn mount_source(&self) -> &File {
        &self.socket_file
    }

    pub(crate) fn detach_host_names(&mut self) -> Result<(), LinuxBackendError> {
        let Some(directory) = self.directory.take() else {
            return Ok(());
        };
        // Never recursively remove entries introduced by another actor.
        // Before command release the private mount already pins this inode.
        let path = directory.keep();
        let socket_path = path.join(HOST_GATEWAY_SOCKET);
        let error = |source| LinuxBackendError::NetworkGatewaySetup {
            source: NetworkGatewaySetupError::SocketDetach {
                path: socket_path.clone(),
                source,
            },
        };
        let expected = self.socket_file.metadata().map_err(error)?;
        let actual = fs::symlink_metadata(&socket_path).map_err(error)?;
        if !expected.file_type().is_socket()
            || (actual.dev(), actual.ino()) != (expected.dev(), expected.ino())
        {
            return Err(LinuxBackendError::NetworkGatewaySetup {
                source: NetworkGatewaySetupError::SocketChanged { path: socket_path },
            });
        }
        fs::remove_file(&socket_path).map_err(error)?;
        fs::remove_dir(&path).map_err(|source| LinuxBackendError::NetworkGatewaySetup {
            source: NetworkGatewaySetupError::DirectoryDetach { path, source },
        })?;
        Ok(())
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
        self.shutdown_with_timeout(NETWORK_GATEWAY_SHUTDOWN_TIMEOUT)
    }

    fn shutdown_with_timeout(&mut self, timeout: Duration) -> Result<(), LinuxBackendError> {
        let Some(thread) = self.thread.as_ref() else {
            return Ok(());
        };
        let deadline = std::time::Instant::now() + timeout;
        while !thread.is_finished() {
            if std::time::Instant::now() >= deadline {
                return Err(NetworkGatewayRuntimeError::ShutdownTimeout {
                    timeout_ms: timeout.as_millis(),
                }
                .into());
            }
            thread::sleep(NETWORK_GATEWAY_SHUTDOWN_POLL_INTERVAL);
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
        if self.shutdown().is_err()
            && let Some(thread) = self.thread.take()
        {
            retain_gateway_thread(thread, self.directory.take());
        }
    }
}

fn retain_gateway_thread(
    thread: JoinHandle<Result<(), NetworkGatewayRuntimeFailure>>,
    directory: Option<TempDir>,
) {
    // The gateway thread owns the listener and the socket directory until it
    // exits. Keep both in a recovery owner instead of deleting the directory
    // while a live runtime may still accept authenticated connections.
    let recovery = GatewayThreadRecovery {
        directory,
        thread: Some(thread),
    };
    let _ = thread::Builder::new()
        .name(NETWORK_GATEWAY_RECOVERY_THREAD_NAME.to_owned())
        .spawn(move || recovery.join());
}

impl GatewayThreadRecovery {
    fn join(mut self) {
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        self.directory.take();
    }
}

impl Drop for GatewayThreadRecovery {
    fn drop(&mut self) {
        if self.thread.is_some() {
            // A failed recovery-thread spawn must not release the live
            // listener or its private socket directory.
            std::mem::forget(self.thread.take());
            std::mem::forget(self.directory.take());
        }
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
            server.timeouts,
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
    timeouts: GatewayTimeouts,
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
                    timeouts.handshake,
                    timeouts.relay_idle,
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
    relay_idle_timeout: Duration,
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
    let (private_reader, private_writer) = tokio::io::split(private_stream);
    let (trusted_reader, trusted_writer) = tokio::io::split(trusted_bridge);
    let gateway_future = gateway.serve_connection(gateway_stream);
    let to_gateway = relay_direction(private_reader, trusted_writer);
    let to_client = relay_direction(trusted_reader, private_writer);
    tokio::pin!(gateway_future, to_gateway, to_client);

    tokio::select! {
        _ = &mut gateway_future => {}
        _ = &mut to_client => return,
        _ = &mut to_gateway => {
            tokio::select! {
                _ = &mut gateway_future => {}
                _ = &mut to_client => return,
            }
        }
    }
    let _ = timeout(relay_idle_timeout, &mut to_client).await;
}

async fn relay_direction<R, W>(mut reader: R, mut writer: W) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let copied = tokio::io::copy(&mut reader, &mut writer).await;
    let shutdown = writer.shutdown().await;
    copied.and(shutdown).map(|_| ())
}

#[cfg(test)]
#[path = "../network_tests.rs"]
mod tests;
