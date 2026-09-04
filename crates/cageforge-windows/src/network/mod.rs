// SPDX-License-Identifier: Apache-2.0

//! Process-wide Windows proxy ingress and per-launch route isolation.

pub(crate) mod attribution;

use std::collections::{HashMap, HashSet};
use std::io;
use std::mem::size_of;
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener as StdTcpListener};
use std::os::windows::io::{FromRawSocket, RawSocket};
use std::sync::{Arc, Condvar, LazyLock, Mutex, MutexGuard, Weak, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use cageforge_network_proxy::{
    GatewayConfig, GatewayError, GatewayIngressKey, NetworkGateway, SystemResolver,
};
use cageforge_policy_compose::EffectiveNetworkPolicy;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot};
use tokio::task::JoinSet;
use tokio::time::timeout;
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, IN_ADDR, IN_ADDR_0, INVALID_SOCKET, IPPROTO_TCP, SO_EXCLUSIVEADDRUSE, SOCK_STREAM,
    SOCKADDR, SOCKADDR_IN, SOCKET, SOCKET_ERROR, SOL_SOCKET, SOMAXCONN, WSACleanup, WSADATA,
    WSAGetLastError, WSAStartup, bind, closesocket, listen, setsockopt, socket,
};

use crate::network::attribution::{
    WindowsNetworkAttributionError, restricting_sids_for_tcp_connection,
};

const AUTHENTICATED_BRIDGE_BUFFER_BYTES: usize = 64 * 1024;
const MAX_PRE_ATTRIBUTION_CONNECTIONS: usize = 256;
const MAX_ROUTE_SID_ATTEMPTS: usize = 64;
const WINSOCK_VERSION_2_2: u16 = 0x0202;
const PROXY_INGRESS_THREAD_NAME: &str = "cageforge-windows-proxy-ingress";
const INGRESS_STARTUP_WAIT_TIMEOUT: Duration = Duration::from_secs(15);

pub(crate) struct WindowsProxyIngress {
    identity: IngressIdentity,
    routes: RouteRegistry,
    thread: Mutex<Option<JoinHandle<Result<(), WindowsNetworkRuntimeFailure>>>>,
    shutdown: Mutex<Option<oneshot::Sender<()>>>,
    _winsock: WinsockSession,
}

pub(crate) struct WindowsProxyRoute {
    sid: String,
    services: Arc<RouteServices>,
    ingress: Arc<WindowsProxyIngress>,
}

struct RouteServices {
    gateway: NetworkGateway<SystemResolver>,
    ingress_key: GatewayIngressKey,
    handshake_timeout: Duration,
    relay_idle_timeout: Duration,
}

struct WinsockSession;

struct RawSocketGuard(SOCKET);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct IngressIdentity {
    owner_sid: String,
    addresses: ProxyAddresses,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct ProxyAddresses {
    http: SocketAddrV4,
    socks: SocketAddrV4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProxyProtocol {
    Http,
    Socks5,
}

type RouteRegistry = Arc<Mutex<HashMap<String, Arc<RouteServices>>>>;

#[derive(Default)]
struct SharedIngressRegistry {
    ingresses: HashMap<IngressIdentity, Weak<WindowsProxyIngress>>,
    retiring_ports: HashSet<u16>,
    starting: HashSet<IngressIdentity>,
}

/// Failure while constructing the shared Windows ingress or one isolated route.
#[derive(Debug, Error)]
pub enum WindowsNetworkGatewayError {
    /// Setup did not provide exactly two distinct fixed ports.
    #[error("Windows proxy ingress requires two distinct non-zero ports, found {ports:?}")]
    InvalidProxyPorts {
        /// Rejected setup ports.
        ports: Vec<u16>,
    },
    /// The process-wide ingress registry was poisoned by a panic.
    #[error("process-wide Windows proxy ingress registry is poisoned")]
    SharedRegistryPoisoned,
    /// Another verified setup in this process already owns one required port.
    #[error("Windows proxy ingress port {port} is already owned by another setup identity")]
    PortOwnedByDifferentSetup {
        /// Conflicting fixed loopback port.
        port: u16,
    },
    /// Winsock initialization failed.
    #[error("failed to initialize Winsock 2.2 for Windows proxy ingress: error {code}")]
    WinsockInitialization {
        /// Native Winsock code.
        code: i32,
    },
    /// Winsock returned a different runtime version.
    #[error("Winsock 2.2 is unavailable; runtime reported version {actual:#06x}")]
    WinsockVersion {
        /// Version returned in `WSADATA`.
        actual: u16,
    },
    /// Creating an ingress socket failed.
    #[error("failed to create the Windows {protocol} proxy ingress socket: error {code}")]
    ListenerSocket {
        /// HTTP or SOCKS5 listener.
        protocol: &'static str,
        /// Native Winsock code.
        code: i32,
    },
    /// The listener could not require exclusive address ownership.
    #[error(
        "failed to require exclusive ownership for Windows {protocol} proxy ingress: error {code}"
    )]
    ListenerExclusiveAddress {
        /// HTTP or SOCKS5 listener.
        protocol: &'static str,
        /// Native Winsock code.
        code: i32,
    },
    /// Binding an exact fixed listener failed.
    #[error("failed to bind Windows {protocol} proxy ingress at {address}: error {code}")]
    ListenerBind {
        /// HTTP or SOCKS5 listener.
        protocol: &'static str,
        /// Exact fixed loopback address.
        address: SocketAddrV4,
        /// Native Winsock code.
        code: i32,
    },
    /// Starting the native listener backlog failed.
    #[error("failed to listen on Windows {protocol} proxy ingress at {address}: error {code}")]
    ListenerListen {
        /// HTTP or SOCKS5 listener.
        protocol: &'static str,
        /// Exact fixed loopback address.
        address: SocketAddrV4,
        /// Native Winsock code.
        code: i32,
    },
    /// Switching the listener to asynchronous mode failed.
    #[error("failed to configure Windows {protocol} proxy ingress at {address}: {source}")]
    ListenerNonblocking {
        /// HTTP or SOCKS5 listener.
        protocol: &'static str,
        /// Exact fixed loopback address.
        address: SocketAddrV4,
        /// Operating-system failure.
        #[source]
        source: io::Error,
    },
    /// Starting the dedicated ingress thread failed.
    #[error("failed to start the Windows proxy ingress thread: {source}")]
    ThreadSpawn {
        /// Operating-system failure.
        #[source]
        source: io::Error,
    },
    /// The runtime failed before publishing readiness.
    #[error("Windows proxy ingress failed during startup: {source}")]
    RuntimeStartup {
        /// Exact runtime startup failure.
        #[source]
        source: WindowsNetworkRuntimeFailure,
    },
    /// The startup channel closed without a typed readiness result.
    #[error("Windows proxy ingress startup channel closed unexpectedly")]
    StartupChannelClosed,
    /// Another caller's ingress startup did not publish a result in time.
    #[error("Windows proxy ingress startup did not complete within the safety deadline")]
    StartupWaitTimeout,
    /// The ingress thread panicked during startup.
    #[error("Windows proxy ingress thread panicked during startup")]
    StartupThreadPanicked,
    /// The already-shared ingress is no longer healthy.
    #[error("shared Windows proxy ingress is unavailable: {source}")]
    ExistingRuntime {
        /// Runtime health failure.
        #[source]
        source: WindowsNetworkRuntimeError,
    },
    /// Constructing the exact-target gateway failed.
    #[error("failed to initialize the Windows policy gateway: {source}")]
    GatewayInitialization {
        /// Portable gateway failure.
        #[source]
        source: GatewayError,
    },
    /// Generating a random route SID failed.
    #[error("failed to generate a Windows proxy route SID: {source}")]
    RouteSidGeneration {
        /// Operating-system randomness failure.
        #[source]
        source: getrandom::Error,
    },
    /// Every bounded random candidate collided with an active route.
    #[error("all {attempts} generated Windows proxy route SIDs collided")]
    RouteSidCollisionLimit {
        /// Number of generated candidates.
        attempts: usize,
    },
    /// The per-ingress route registry was poisoned by a panic.
    #[error("Windows proxy route registry is poisoned")]
    RouteRegistryPoisoned,
}

/// Failure detected while a shared Windows ingress is serving active children.
#[derive(Debug, Error)]
pub enum WindowsNetworkRuntimeError {
    /// The runtime thread state lock was poisoned.
    #[error("Windows proxy ingress runtime state is poisoned")]
    StatePoisoned,
    /// The shared ingress stopped with a typed native failure.
    #[error("Windows proxy ingress runtime failed: {source}")]
    Failed {
        /// Exact runtime failure.
        #[source]
        source: WindowsNetworkRuntimeFailure,
    },
    /// The ingress stopped cleanly while a sandbox still depended on it.
    #[error("Windows proxy ingress stopped before the sandboxed process")]
    StoppedBeforeProcess,
    /// The ingress runtime thread panicked.
    #[error("Windows proxy ingress runtime thread panicked")]
    Panicked,
}

/// A typed failure produced by the process-wide Windows ingress thread.
#[derive(Debug, Error)]
pub enum WindowsNetworkRuntimeFailure {
    /// Tokio could not construct the dedicated runtime.
    #[error("failed to construct the Windows proxy ingress runtime: {source}")]
    RuntimeConstruction {
        /// Runtime construction failure.
        #[source]
        source: io::Error,
    },
    /// A reserved listener could not be registered with Tokio.
    #[error("failed to register the Windows {protocol} proxy listener: {source}")]
    ListenerRegistration {
        /// HTTP or SOCKS5 listener.
        protocol: &'static str,
        /// Listener registration failure.
        #[source]
        source: io::Error,
    },
    /// Startup readiness could not reach the constructing thread.
    #[error("Windows proxy ingress startup receiver closed")]
    StartupReceiverClosed,
    /// A listener failed after startup.
    #[error("Windows {protocol} proxy listener failed after startup: {source}")]
    Listener {
        /// HTTP or SOCKS5 listener.
        protocol: &'static str,
        /// Listener failure.
        #[source]
        source: io::Error,
    },
    /// One connection task panicked instead of failing closed normally.
    #[error("Windows proxy ingress connection task panicked")]
    ConnectionTaskPanicked,
}

#[derive(Debug, Error)]
enum WindowsNetworkIngressError {
    #[error("failed to read accepted Windows proxy {endpoint} address: {source}")]
    Address {
        endpoint: &'static str,
        #[source]
        source: io::Error,
    },
    #[error(transparent)]
    Attribution(#[from] WindowsNetworkAttributionError),
    #[error("Windows proxy route registry is poisoned")]
    RouteRegistryPoisoned,
    #[error("proxy client token has no registered route SID")]
    RouteMissing,
    #[error("proxy client token has multiple registered route SIDs")]
    RouteDuplicate,
    #[error("Windows {protocol} proxy protocol negotiation timed out")]
    ProtocolTimeout { protocol: &'static str },
    #[error("failed to inspect Windows {protocol} proxy protocol: {source}")]
    ProtocolRead {
        protocol: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("connection on the Windows {protocol} ingress used another proxy protocol")]
    ProtocolMismatch { protocol: &'static str },
    #[error("failed to authenticate the private Windows gateway bridge: {source}")]
    GatewayAuthentication {
        #[source]
        source: io::Error,
    },
    #[error("Windows policy gateway rejected the connection: {source}")]
    Gateway {
        #[source]
        source: GatewayError,
    },
    #[error("Windows proxy {direction} relay failed: {source}")]
    Relay {
        direction: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("Windows proxy attribution worker panicked or was cancelled")]
    AttributionWorker,
}

static SHARED_INGRESSES: LazyLock<(Mutex<SharedIngressRegistry>, Condvar)> =
    LazyLock::new(|| (Mutex::new(SharedIngressRegistry::default()), Condvar::new()));

impl WindowsProxyIngress {
    pub(crate) fn shared(
        owner_sid: &str,
        ports: &[u16],
    ) -> Result<Arc<Self>, WindowsNetworkGatewayError> {
        let addresses = ProxyAddresses::from_setup_ports(ports)?;
        let identity = IngressIdentity {
            owner_sid: owner_sid.to_string(),
            addresses,
        };
        loop {
            let existing = {
                let (registry, _) = &*SHARED_INGRESSES;
                let mut shared = registry
                    .lock()
                    .map_err(|_| WindowsNetworkGatewayError::SharedRegistryPoisoned)?;
                match shared.ingresses.get(&identity).and_then(Weak::upgrade) {
                    Some(ingress) => Some(ingress),
                    None => {
                        shared.ingresses.remove(&identity);
                        None
                    }
                }
            };
            if let Some(ingress) = existing {
                match ingress.check_health() {
                    Ok(()) => return Ok(ingress),
                    Err(source) => {
                        let (registry, _) = &*SHARED_INGRESSES;
                        let mut shared = registry
                            .lock()
                            .map_err(|_| WindowsNetworkGatewayError::SharedRegistryPoisoned)?;
                        let is_current = shared
                            .ingresses
                            .get(&identity)
                            .and_then(Weak::upgrade)
                            .is_some_and(|registered| Arc::ptr_eq(&registered, &ingress));
                        if is_current {
                            shared.ingresses.remove(&identity);
                        }
                        return Err(WindowsNetworkGatewayError::ExistingRuntime { source });
                    }
                }
            }

            let (registry, ready) = &*SHARED_INGRESSES;
            let mut shared = registry
                .lock()
                .map_err(|_| WindowsNetworkGatewayError::SharedRegistryPoisoned)?;

            // Another caller may have published the ingress after the first
            // short lookup. Re-check before reserving a new startup.
            if shared
                .ingresses
                .get(&identity)
                .and_then(Weak::upgrade)
                .is_some()
            {
                continue;
            }
            if shared.starting.contains(&identity) {
                let deadline = Instant::now() + INGRESS_STARTUP_WAIT_TIMEOUT;
                shared = wait_for_starting_ingress(ready, shared, &identity, deadline)?;
                drop(shared);
                continue;
            }
            shared.ingresses.remove(&identity);
            if let Some(port) = shared
                .ingresses
                .keys()
                .flat_map(|key| [key.addresses.http.port(), key.addresses.socks.port()])
                .chain(shared.retiring_ports.iter().copied())
                .chain(
                    shared
                        .starting
                        .iter()
                        .flat_map(|key| [key.addresses.http.port(), key.addresses.socks.port()]),
                )
                .find(|port| *port == addresses.http.port() || *port == addresses.socks.port())
            {
                return Err(WindowsNetworkGatewayError::PortOwnedByDifferentSetup { port });
            }
            shared.starting.insert(identity.clone());
            drop(shared);

            // Native listener creation and readiness may perform blocking I/O
            // and join a failed startup thread; never do either under the
            // process-wide registry mutex.
            let started = Self::start(identity.clone());
            let mut shared = match registry.lock() {
                Ok(shared) => shared,
                Err(_) => {
                    ready.notify_all();
                    return Err(WindowsNetworkGatewayError::SharedRegistryPoisoned);
                }
            };
            shared.starting.remove(&identity);
            let result = match started {
                Ok(ingress) => {
                    let ingress = Arc::new(ingress);
                    shared
                        .ingresses
                        .insert(ingress.identity.clone(), Arc::downgrade(&ingress));
                    Ok(ingress)
                }
                Err(error) => Err(error),
            };
            ready.notify_all();
            return result;
        }
    }

    pub(crate) fn register_route(
        self: &Arc<Self>,
        policy: EffectiveNetworkPolicy,
        config: GatewayConfig,
    ) -> Result<WindowsProxyRoute, WindowsNetworkGatewayError> {
        self.check_health()
            .map_err(|source| WindowsNetworkGatewayError::ExistingRuntime { source })?;
        let handshake_timeout = config.handshake_timeout();
        let relay_idle_timeout = config.relay_idle_timeout();
        let gateway = NetworkGateway::with_system_resolver(policy, config)
            .map_err(|source| WindowsNetworkGatewayError::GatewayInitialization { source })?;
        let services = Arc::new(RouteServices {
            ingress_key: gateway.ingress_key(),
            gateway,
            handshake_timeout,
            relay_idle_timeout,
        });
        let mut routes = self
            .routes
            .lock()
            .map_err(|_| WindowsNetworkGatewayError::RouteRegistryPoisoned)?;
        for _ in 0..MAX_ROUTE_SID_ATTEMPTS {
            let sid = random_route_sid()?;
            if routes.contains_key(&sid) {
                continue;
            }
            routes.insert(sid.clone(), Arc::clone(&services));
            return Ok(WindowsProxyRoute {
                sid,
                services,
                ingress: Arc::clone(self),
            });
        }
        Err(WindowsNetworkGatewayError::RouteSidCollisionLimit {
            attempts: MAX_ROUTE_SID_ATTEMPTS,
        })
    }

    pub(crate) fn addresses(&self) -> ProxyAddresses {
        self.identity.addresses
    }

    pub(crate) fn check_health(&self) -> Result<(), WindowsNetworkRuntimeError> {
        let handle = {
            let mut thread = self
                .thread
                .lock()
                .map_err(|_| WindowsNetworkRuntimeError::StatePoisoned)?;
            let Some(handle) = thread.as_ref() else {
                return Err(WindowsNetworkRuntimeError::StoppedBeforeProcess);
            };
            if !handle.is_finished() {
                return Ok(());
            }
            thread
                .take()
                .ok_or(WindowsNetworkRuntimeError::StoppedBeforeProcess)?
        };
        match handle.join() {
            Ok(Ok(())) => Err(WindowsNetworkRuntimeError::StoppedBeforeProcess),
            Ok(Err(source)) => Err(WindowsNetworkRuntimeError::Failed { source }),
            Err(_) => Err(WindowsNetworkRuntimeError::Panicked),
        }
    }

    fn start(identity: IngressIdentity) -> Result<Self, WindowsNetworkGatewayError> {
        let winsock = initialize_winsock()?;
        let http = exclusive_listener(ProxyProtocol::Http, identity.addresses.http)?;
        let socks = exclusive_listener(ProxyProtocol::Socks5, identity.addresses.socks)?;
        let routes = Arc::new(Mutex::new(HashMap::new()));
        let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
        let (shutdown_sender, shutdown_receiver) = oneshot::channel();
        let thread = std::thread::Builder::new()
            .name(PROXY_INGRESS_THREAD_NAME.to_owned())
            .spawn({
                let routes = Arc::clone(&routes);
                move || run_ingress(http, socks, routes, ready_sender, shutdown_receiver)
            })
            .map_err(|source| WindowsNetworkGatewayError::ThreadSpawn { source })?;
        match ready_receiver.recv() {
            Ok(Ok(())) => Ok(Self {
                identity,
                routes,
                thread: Mutex::new(Some(thread)),
                shutdown: Mutex::new(Some(shutdown_sender)),
                _winsock: winsock,
            }),
            Ok(Err(source)) => {
                let _ = thread.join();
                Err(WindowsNetworkGatewayError::RuntimeStartup { source })
            }
            Err(_) => match thread.join() {
                Ok(Err(source)) => Err(WindowsNetworkGatewayError::RuntimeStartup { source }),
                Ok(Ok(())) => Err(WindowsNetworkGatewayError::StartupChannelClosed),
                Err(_) => Err(WindowsNetworkGatewayError::StartupThreadPanicked),
            },
        }
    }
}

fn wait_for_starting_ingress<'registry>(
    ready: &Condvar,
    shared: MutexGuard<'registry, SharedIngressRegistry>,
    identity: &IngressIdentity,
    deadline: Instant,
) -> Result<MutexGuard<'registry, SharedIngressRegistry>, WindowsNetworkGatewayError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    let (shared, result) = ready
        .wait_timeout(shared, remaining)
        .map_err(|_| WindowsNetworkGatewayError::SharedRegistryPoisoned)?;
    if result.timed_out() && shared.starting.contains(identity) {
        Err(WindowsNetworkGatewayError::StartupWaitTimeout)
    } else {
        Ok(shared)
    }
}

impl Drop for WindowsProxyIngress {
    fn drop(&mut self) {
        let ports = [
            self.identity.addresses.http.port(),
            self.identity.addresses.socks.port(),
        ];
        // Remove the weak entry and reserve both fixed ports only for this
        // short critical section. The reservation prevents a replacement
        // ingress from racing the old listeners while the runtime is joined,
        // without holding the registry mutex during shutdown or I/O.
        if let Ok(mut registry) = SHARED_INGRESSES.0.lock() {
            registry.ingresses.remove(&self.identity);
            registry.retiring_ports.extend(ports);
        }
        let shutdown_sender = match self.shutdown.get_mut() {
            Ok(sender) => sender.take(),
            Err(poisoned) => poisoned.into_inner().take(),
        };
        if let Some(sender) = shutdown_sender {
            let _ = sender.send(());
        }
        let thread = match self.thread.get_mut() {
            Ok(thread) => thread.take(),
            Err(poisoned) => poisoned.into_inner().take(),
        };
        if let Some(thread) = thread {
            let _ = thread.join();
        }
        if let Ok(mut registry) = SHARED_INGRESSES.0.lock() {
            for port in ports {
                registry.retiring_ports.remove(&port);
            }
        }
    }
}

impl WindowsProxyRoute {
    pub(crate) fn sid(&self) -> &str {
        &self.sid
    }

    pub(crate) fn addresses(&self) -> ProxyAddresses {
        self.ingress.addresses()
    }

    pub(crate) fn check_health(&self) -> Result<(), WindowsNetworkRuntimeError> {
        self.ingress.check_health()
    }
}

impl Drop for WindowsProxyRoute {
    fn drop(&mut self) {
        remove_route_if_owned(&self.ingress.routes, &self.sid, &self.services);
    }
}

fn remove_route_if_owned(
    routes: &Mutex<HashMap<String, Arc<RouteServices>>>,
    sid: &str,
    services: &Arc<RouteServices>,
) {
    // A poisoned registry may contain an incomplete mutation from the
    // panicking holder. Keep this route registered in that case: leaving a
    // stale route is fail-closed, while removing an entry from an uncertain
    // map could detach another launch's policy.
    let Ok(mut routes) = routes.lock() else {
        return;
    };
    if routes
        .get(sid)
        .is_some_and(|registered| Arc::ptr_eq(registered, services))
    {
        routes.remove(sid);
    }
}

impl ProxyAddresses {
    pub(crate) fn from_setup_ports(ports: &[u16]) -> Result<Self, WindowsNetworkGatewayError> {
        if ports.len() != 2 || ports[0] == 0 || ports[1] == 0 || ports[0] == ports[1] {
            return Err(WindowsNetworkGatewayError::InvalidProxyPorts {
                ports: ports.to_vec(),
            });
        }
        Ok(Self {
            http: SocketAddrV4::new(Ipv4Addr::LOCALHOST, ports[0]),
            socks: SocketAddrV4::new(Ipv4Addr::LOCALHOST, ports[1]),
        })
    }

    pub(crate) const fn http(self) -> SocketAddrV4 {
        self.http
    }

    pub(crate) const fn socks(self) -> SocketAddrV4 {
        self.socks
    }
}

impl ProxyProtocol {
    const fn label(self) -> &'static str {
        match self {
            Self::Http => "HTTP",
            Self::Socks5 => "SOCKS5",
        }
    }
}

#[allow(unsafe_code)]
impl Drop for WinsockSession {
    fn drop(&mut self) {
        unsafe {
            WSACleanup();
        }
    }
}

#[allow(unsafe_code)]
impl Drop for RawSocketGuard {
    fn drop(&mut self) {
        if self.0 != INVALID_SOCKET {
            unsafe {
                closesocket(self.0);
            }
        }
    }
}

impl RawSocketGuard {
    fn take(&mut self) -> SOCKET {
        std::mem::replace(&mut self.0, INVALID_SOCKET)
    }
}

#[allow(unsafe_code)]
fn initialize_winsock() -> Result<WinsockSession, WindowsNetworkGatewayError> {
    let mut data = WSADATA::default();
    let status = unsafe { WSAStartup(WINSOCK_VERSION_2_2, &mut data) };
    if status != 0 {
        return Err(WindowsNetworkGatewayError::WinsockInitialization { code: status });
    }
    let session = WinsockSession;
    if data.wVersion != WINSOCK_VERSION_2_2 {
        return Err(WindowsNetworkGatewayError::WinsockVersion {
            actual: data.wVersion,
        });
    }
    Ok(session)
}

#[allow(unsafe_code)]
fn exclusive_listener(
    protocol: ProxyProtocol,
    address: SocketAddrV4,
) -> Result<StdTcpListener, WindowsNetworkGatewayError> {
    let label = protocol.label();
    let socket = unsafe { socket(AF_INET as i32, SOCK_STREAM, IPPROTO_TCP) };
    if socket == INVALID_SOCKET {
        return Err(WindowsNetworkGatewayError::ListenerSocket {
            protocol: label,
            code: unsafe { WSAGetLastError() },
        });
    }
    let mut socket = RawSocketGuard(socket);
    let exclusive = 1_i32;
    if unsafe {
        setsockopt(
            socket.0,
            SOL_SOCKET,
            SO_EXCLUSIVEADDRUSE,
            (&exclusive as *const i32).cast::<u8>(),
            size_of::<i32>() as i32,
        )
    } == SOCKET_ERROR
    {
        return Err(WindowsNetworkGatewayError::ListenerExclusiveAddress {
            protocol: label,
            code: unsafe { WSAGetLastError() },
        });
    }
    let native_address = SOCKADDR_IN {
        sin_family: AF_INET,
        sin_port: address.port().to_be(),
        sin_addr: IN_ADDR {
            S_un: IN_ADDR_0 {
                S_addr: u32::from_ne_bytes(address.ip().octets()),
            },
        },
        sin_zero: [0; 8],
    };
    if unsafe {
        bind(
            socket.0,
            (&native_address as *const SOCKADDR_IN).cast::<SOCKADDR>(),
            size_of::<SOCKADDR_IN>() as i32,
        )
    } == SOCKET_ERROR
    {
        return Err(WindowsNetworkGatewayError::ListenerBind {
            protocol: label,
            address,
            code: unsafe { WSAGetLastError() },
        });
    }
    if unsafe { listen(socket.0, SOMAXCONN as i32) } == SOCKET_ERROR {
        return Err(WindowsNetworkGatewayError::ListenerListen {
            protocol: label,
            address,
            code: unsafe { WSAGetLastError() },
        });
    }
    let listener = unsafe { StdTcpListener::from_raw_socket(socket.take() as RawSocket) };
    listener.set_nonblocking(true).map_err(|source| {
        WindowsNetworkGatewayError::ListenerNonblocking {
            protocol: label,
            address,
            source,
        }
    })?;
    Ok(listener)
}

fn run_ingress(
    http: StdTcpListener,
    socks: StdTcpListener,
    routes: RouteRegistry,
    ready: mpsc::SyncSender<Result<(), WindowsNetworkRuntimeFailure>>,
    shutdown: oneshot::Receiver<()>,
) -> Result<(), WindowsNetworkRuntimeFailure> {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(source) => {
            let _ = ready.send(Err(WindowsNetworkRuntimeFailure::RuntimeConstruction {
                source,
            }));
            return Ok(());
        }
    };
    runtime.block_on(async move {
        let http = match TcpListener::from_std(http) {
            Ok(listener) => listener,
            Err(source) => {
                let _ = ready.send(Err(WindowsNetworkRuntimeFailure::ListenerRegistration {
                    protocol: ProxyProtocol::Http.label(),
                    source,
                }));
                return Ok(());
            }
        };
        let socks = match TcpListener::from_std(socks) {
            Ok(listener) => listener,
            Err(source) => {
                let _ = ready.send(Err(WindowsNetworkRuntimeFailure::ListenerRegistration {
                    protocol: ProxyProtocol::Socks5.label(),
                    source,
                }));
                return Ok(());
            }
        };
        ready
            .send(Ok(()))
            .map_err(|_| WindowsNetworkRuntimeFailure::StartupReceiverClosed)?;
        serve_ingress(http, socks, routes, shutdown).await
    })
}

async fn serve_ingress(
    http: TcpListener,
    socks: TcpListener,
    routes: RouteRegistry,
    mut shutdown: oneshot::Receiver<()>,
) -> Result<(), WindowsNetworkRuntimeFailure> {
    let pre_attribution = Arc::new(Semaphore::new(MAX_PRE_ATTRIBUTION_CONNECTIONS));
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                connections.abort_all();
                while connections.join_next().await.is_some() {}
                return Ok(());
            },
            accepted = http.accept() => {
                let (stream, _) = accepted.map_err(|source| WindowsNetworkRuntimeFailure::Listener {
                    protocol: ProxyProtocol::Http.label(),
                    source,
                })?;
                spawn_connection(
                    &mut connections,
                    Arc::clone(&pre_attribution),
                    Arc::clone(&routes),
                    ProxyProtocol::Http,
                    stream,
                );
            }
            accepted = socks.accept() => {
                let (stream, _) = accepted.map_err(|source| WindowsNetworkRuntimeFailure::Listener {
                    protocol: ProxyProtocol::Socks5.label(),
                    source,
                })?;
                spawn_connection(
                    &mut connections,
                    Arc::clone(&pre_attribution),
                    Arc::clone(&routes),
                    ProxyProtocol::Socks5,
                    stream,
                );
            }
            completed = connections.join_next(), if !connections.is_empty() => {
                if completed.is_some_and(|result| result.is_err()) {
                    return Err(WindowsNetworkRuntimeFailure::ConnectionTaskPanicked);
                }
            }
        }
    }
}

fn spawn_connection(
    connections: &mut JoinSet<()>,
    pre_attribution: Arc<Semaphore>,
    routes: RouteRegistry,
    protocol: ProxyProtocol,
    stream: TcpStream,
) {
    let Ok(permit) = pre_attribution.try_acquire_owned() else {
        return;
    };
    connections.spawn(async move {
        let _ = serve_connection(stream, protocol, routes, permit).await;
    });
}

async fn serve_connection(
    stream: TcpStream,
    protocol: ProxyProtocol,
    routes: RouteRegistry,
    pre_attribution_permit: OwnedSemaphorePermit,
) -> Result<(), WindowsNetworkIngressError> {
    let local = stream
        .local_addr()
        .map_err(|source| WindowsNetworkIngressError::Address {
            endpoint: "local",
            source,
        })?;
    let peer = stream
        .peer_addr()
        .map_err(|source| WindowsNetworkIngressError::Address {
            endpoint: "peer",
            source,
        })?;
    let restricting_sids =
        tokio::task::spawn_blocking(move || restricting_sids_for_tcp_connection(local, peer))
            .await
            .map_err(|_| WindowsNetworkIngressError::AttributionWorker)??;
    let route = registered_route_for_sids(&routes, &restricting_sids)?;
    verify_protocol_while_admitted(
        &stream,
        protocol,
        route.handshake_timeout,
        pre_attribution_permit,
    )
    .await?;
    serve_authenticated_route(stream, route).await
}

fn registered_route_for_sids(
    routes: &RouteRegistry,
    restricting_sids: &[String],
) -> Result<Arc<RouteServices>, WindowsNetworkIngressError> {
    let routes = routes
        .lock()
        .map_err(|_| WindowsNetworkIngressError::RouteRegistryPoisoned)?;
    let mut matches = restricting_sids
        .iter()
        .filter_map(|sid| routes.get(sid).map(Arc::clone));
    let route = matches
        .next()
        .ok_or(WindowsNetworkIngressError::RouteMissing)?;
    if matches.next().is_some() {
        Err(WindowsNetworkIngressError::RouteDuplicate)
    } else {
        Ok(route)
    }
}

async fn verify_protocol(
    stream: &TcpStream,
    protocol: ProxyProtocol,
    handshake_timeout: Duration,
) -> Result<(), WindowsNetworkIngressError> {
    let mut first = [0];
    let read = timeout(handshake_timeout, stream.peek(&mut first))
        .await
        .map_err(|_| WindowsNetworkIngressError::ProtocolTimeout {
            protocol: protocol.label(),
        })?
        .map_err(|source| WindowsNetworkIngressError::ProtocolRead {
            protocol: protocol.label(),
            source,
        })?;
    let matches = match protocol {
        ProxyProtocol::Http => read != 0 && first[0] != 0x05,
        ProxyProtocol::Socks5 => read != 0 && first[0] == 0x05,
    };
    if matches {
        Ok(())
    } else {
        Err(WindowsNetworkIngressError::ProtocolMismatch {
            protocol: protocol.label(),
        })
    }
}

async fn verify_protocol_while_admitted(
    stream: &TcpStream,
    protocol: ProxyProtocol,
    handshake_timeout: Duration,
    pre_attribution_permit: OwnedSemaphorePermit,
) -> Result<(), WindowsNetworkIngressError> {
    let result = verify_protocol(stream, protocol, handshake_timeout).await;
    drop(pre_attribution_permit);
    result
}

async fn serve_authenticated_route(
    stream: TcpStream,
    route: Arc<RouteServices>,
) -> Result<(), WindowsNetworkIngressError> {
    let (mut trusted_bridge, gateway_stream) = tokio::io::duplex(AUTHENTICATED_BRIDGE_BUFFER_BYTES);
    route
        .ingress_key
        .authenticate(&mut trusted_bridge)
        .await
        .map_err(|source| WindowsNetworkIngressError::GatewayAuthentication { source })?;
    let (client_reader, client_writer) = tokio::io::split(stream);
    let (trusted_reader, trusted_writer) = tokio::io::split(trusted_bridge);
    let gateway = route.gateway.serve_connection(gateway_stream);
    let to_gateway = relay_direction("client-to-gateway", client_reader, trusted_writer);
    let to_client = relay_direction("gateway-to-client", trusted_reader, client_writer);
    tokio::pin!(gateway, to_gateway, to_client);
    tokio::select! {
        result = &mut gateway => result.map_err(|source| WindowsNetworkIngressError::Gateway { source })?,
        result = &mut to_client => return result,
        result = &mut to_gateway => {
            result?;
            tokio::select! {
                result = &mut gateway => result.map_err(|source| WindowsNetworkIngressError::Gateway { source })?,
                result = &mut to_client => return result,
            }
        }
    }
    timeout(route.relay_idle_timeout, &mut to_client)
        .await
        .map_err(|_| WindowsNetworkIngressError::ProtocolTimeout {
            protocol: "gateway response relay",
        })??;
    Ok(())
}

async fn relay_direction<R, W>(
    direction: &'static str,
    mut reader: R,
    mut writer: W,
) -> Result<(), WindowsNetworkIngressError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    tokio::io::copy(&mut reader, &mut writer)
        .await
        .map_err(|source| WindowsNetworkIngressError::Relay { direction, source })?;
    writer
        .shutdown()
        .await
        .map_err(|source| WindowsNetworkIngressError::Relay { direction, source })
}

fn random_route_sid() -> Result<String, WindowsNetworkGatewayError> {
    let mut bytes = [0; 16];
    getrandom::fill(&mut bytes)
        .map_err(|source| WindowsNetworkGatewayError::RouteSidGeneration { source })?;
    let [
        first_0,
        first_1,
        first_2,
        first_3,
        second_0,
        second_1,
        second_2,
        second_3,
        third_0,
        third_1,
        third_2,
        third_3,
        fourth_0,
        fourth_1,
        fourth_2,
        fourth_3,
    ] = bytes;
    let first = u32::from_le_bytes([first_0, first_1, first_2, first_3]);
    let second = u32::from_le_bytes([second_0, second_1, second_2, second_3]);
    let third = u32::from_le_bytes([third_0, third_1, third_2, third_3]);
    let fourth = u32::from_le_bytes([fourth_0, fourth_1, fourth_2, fourth_3]);
    Ok(format!(
        "S-1-5-21-{}-{}-{}-{}",
        first, second, third, fourth
    ))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::Ipv4Addr;
    use std::sync::{Arc, Barrier, Condvar, Mutex, mpsc};
    use std::thread;
    use std::time::{Duration, Instant};

    use cageforge_command::EnvironmentSpec;
    use cageforge_network_proxy::{GatewayConfig, NetworkGateway};
    use cageforge_policy::NetworkPolicy;
    use cageforge_policy_compose::{CompositionRequest, PolicyCeiling, compose};
    use pretty_assertions::assert_eq;
    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::Semaphore;
    use tokio::time::timeout;

    use super::{
        IngressIdentity, ProxyAddresses, ProxyProtocol, RouteServices, SHARED_INGRESSES,
        SharedIngressRegistry, WindowsNetworkGatewayError, WindowsNetworkIngressError,
        WindowsProxyIngress, exclusive_listener, initialize_winsock, random_route_sid,
        registered_route_for_sids, remove_route_if_owned, verify_protocol_while_admitted,
        wait_for_starting_ingress,
    };

    #[test]
    fn setup_ports_have_fixed_protocol_roles() {
        let addresses = ProxyAddresses::from_setup_ports(&[49_152, 49_153]).expect("ports");

        assert_eq!(addresses.http().port(), 49_152);
        assert_eq!(addresses.socks().port(), 49_153);
        assert!(matches!(
            ProxyAddresses::from_setup_ports(&[49_152, 49_152]),
            Err(WindowsNetworkGatewayError::InvalidProxyPorts { .. })
        ));
    }

    #[test]
    fn route_selection_requires_exactly_one_registered_sid() {
        let route = route_services();
        let routes = Arc::new(Mutex::new(HashMap::from([
            ("S-1-5-21-1-2-3-4".to_string(), Arc::clone(&route)),
            ("S-1-5-21-5-6-7-8".to_string(), Arc::clone(&route)),
        ])));

        assert!(Arc::ptr_eq(
            &registered_route_for_sids(&routes, &["S-1-5-21-1-2-3-4".to_string()])
                .expect("one route"),
            &route,
        ));
        assert!(matches!(
            registered_route_for_sids(&routes, &["S-1-5-21-9-10-11-12".to_string()]),
            Err(WindowsNetworkIngressError::RouteMissing)
        ));
        assert!(matches!(
            registered_route_for_sids(
                &routes,
                &[
                    "S-1-5-21-1-2-3-4".to_string(),
                    "S-1-5-21-5-6-7-8".to_string(),
                ],
            ),
            Err(WindowsNetworkIngressError::RouteDuplicate)
        ));
    }

    #[test]
    fn poisoned_route_registry_is_not_recovered_during_cleanup() {
        let route = route_services();
        let sid = "S-1-5-21-1-2-3-4";
        let routes = Arc::new(Mutex::new(HashMap::from([(
            sid.to_string(),
            Arc::clone(&route),
        )])));
        let poisoned = Arc::clone(&routes);
        let panic_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = poisoned.lock().expect("unpoisoned route registry");
            panic!("simulate route registry mutation panic");
        }));
        assert!(panic_result.is_err());
        assert!(routes.is_poisoned());

        remove_route_if_owned(&routes, sid, &route);

        let routes = routes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(routes.contains_key(sid));
    }

    #[test]
    fn ingress_replacement_waits_for_old_listeners_to_close() {
        let winsock = initialize_winsock().expect("Winsock for test ingress");
        let first = exclusive_listener(
            ProxyProtocol::Http,
            std::net::SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
        )
        .expect("first test ingress listener");
        let first_port = first.local_addr().expect("first listener address").port();
        let second = exclusive_listener(
            ProxyProtocol::Socks5,
            std::net::SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
        )
        .expect("second test ingress listener");
        let second_port = second.local_addr().expect("second listener address").port();
        let ports = [first_port, second_port];
        let identity = IngressIdentity {
            owner_sid: format!("test-owner-{first_port}-{second_port}"),
            addresses: ProxyAddresses::from_setup_ports(&ports).expect("test ingress ports"),
        };
        let replacement_identity = format!("{}-replacement", identity.owner_sid);
        let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();
        let (shutdown_seen_sender, shutdown_seen_receiver) = mpsc::channel();
        let (release_sender, release_receiver) = mpsc::channel();
        let runtime = thread::spawn(move || {
            let _ = shutdown_receiver.blocking_recv();
            shutdown_seen_sender.send(()).expect("shutdown observer");
            release_receiver.recv().expect("release old listeners");
            drop(first);
            drop(second);
            Ok(())
        });
        let ingress = Arc::new(WindowsProxyIngress {
            identity: identity.clone(),
            routes: Arc::new(Mutex::new(HashMap::new())),
            thread: Mutex::new(Some(runtime)),
            shutdown: Mutex::new(Some(shutdown_sender)),
            _winsock: winsock,
        });
        SHARED_INGRESSES
            .0
            .lock()
            .expect("shared ingress registry")
            .ingresses
            .insert(identity, Arc::downgrade(&ingress));

        let dropper = thread::spawn(move || drop(ingress));
        shutdown_seen_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("old ingress entered shutdown");

        let replacement_identity_for_lookup = replacement_identity.clone();
        let replacement = thread::spawn(move || {
            WindowsProxyIngress::shared(&replacement_identity_for_lookup, &ports)
        });
        let replacement_error = match replacement
            .join()
            .expect("replacement ingress lookup thread")
        {
            Ok(ingress) => {
                drop(ingress);
                panic!("replacement ingress raced old listener shutdown");
            }
            Err(error) => error,
        };
        assert!(matches!(
            replacement_error,
            WindowsNetworkGatewayError::PortOwnedByDifferentSetup { port }
                if ports.contains(&port)
        ));

        release_sender.send(()).expect("release old ingress");
        dropper.join().expect("old ingress drop thread");
        let replacement =
            WindowsProxyIngress::shared(&format!("{replacement_identity}-after"), &ports)
                .expect("replacement ingress starts after old listeners close");
        drop(replacement);
    }

    #[test]
    fn concurrent_shared_calls_coalesce_one_ingress() {
        let _winsock = initialize_winsock().expect("Winsock for concurrent ingress test");
        let http = exclusive_listener(
            ProxyProtocol::Http,
            std::net::SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
        )
        .expect("reserve concurrent HTTP test port");
        let http_port = http
            .local_addr()
            .expect("concurrent HTTP test address")
            .port();
        let socks = exclusive_listener(
            ProxyProtocol::Socks5,
            std::net::SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
        )
        .expect("reserve concurrent SOCKS5 test port");
        let socks_port = socks
            .local_addr()
            .expect("concurrent SOCKS5 test address")
            .port();
        drop(http);
        drop(socks);

        let ports = [http_port, socks_port];
        let owner = format!("concurrent-ingress-test-{http_port}-{socks_port}");
        let barrier = Arc::new(Barrier::new(2));
        let first_barrier = Arc::clone(&barrier);
        let first_owner = owner.clone();
        let first = thread::spawn(move || {
            first_barrier.wait();
            WindowsProxyIngress::shared(&first_owner, &ports)
        });
        let second_barrier = Arc::clone(&barrier);
        let second = thread::spawn(move || {
            second_barrier.wait();
            WindowsProxyIngress::shared(&owner, &ports)
        });
        let first = first
            .join()
            .expect("first concurrent ingress lookup")
            .expect("first concurrent ingress startup");
        let second = second
            .join()
            .expect("second concurrent ingress lookup")
            .expect("second concurrent ingress startup");
        assert!(Arc::ptr_eq(&first, &second));
        drop(first);
        drop(second);

        for (protocol, port) in [
            (ProxyProtocol::Http, http_port),
            (ProxyProtocol::Socks5, socks_port),
        ] {
            let listener = exclusive_listener(
                protocol,
                std::net::SocketAddrV4::new(Ipv4Addr::LOCALHOST, port),
            )
            .expect("coalesced ingress released its listener");
            drop(listener);
        }
    }

    #[test]
    fn starting_ingress_wait_has_a_bounded_deadline() {
        let identity = IngressIdentity {
            owner_sid: "bounded-startup-test".to_string(),
            addresses: ProxyAddresses::from_setup_ports(&[49_152, 49_153])
                .expect("test ingress ports"),
        };
        let registry = Mutex::new(SharedIngressRegistry::default());
        let ready = Condvar::new();
        let mut shared = registry.lock().expect("startup registry");
        shared.starting.insert(identity.clone());

        let result = wait_for_starting_ingress(&ready, shared, &identity, Instant::now());

        assert!(matches!(
            result,
            Err(WindowsNetworkGatewayError::StartupWaitTimeout)
        ));
    }

    #[test]
    fn generated_route_sid_has_four_random_namespace_parts() {
        let sid = random_route_sid().expect("route SID");
        let parts = sid.split('-').collect::<Vec<_>>();

        assert_eq!(&parts[..4], &["S", "1", "5", "21"]);
        assert_eq!(parts.len(), 8);
        assert!(parts[4..].iter().all(|part| part.parse::<u32>().is_ok()));
    }

    #[tokio::test]
    async fn protocol_stalls_remain_inside_the_pre_attribution_connection_limit() {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("loopback listener");
        let address = listener.local_addr().expect("listener address");
        let mut client = TcpStream::connect(address).await.expect("loopback client");
        let (server, _) = listener.accept().await.expect("accepted client");
        let admission = Arc::new(Semaphore::new(1));
        let permit = Arc::clone(&admission)
            .try_acquire_owned()
            .expect("one admission permit");
        let verification = verify_protocol_while_admitted(
            &server,
            ProxyProtocol::Http,
            Duration::from_secs(1),
            permit,
        );
        tokio::pin!(verification);

        assert!(
            timeout(Duration::from_millis(20), &mut verification)
                .await
                .is_err()
        );
        assert_eq!(admission.available_permits(), 0);

        client.write_all(b"G").await.expect("HTTP protocol byte");
        verification.await.expect("protocol verification");
        assert_eq!(admission.available_permits(), 1);
    }

    fn route_services() -> Arc<RouteServices> {
        let policy = effective_network();
        let gateway =
            NetworkGateway::with_system_resolver(policy, GatewayConfig::new()).expect("gateway");
        Arc::new(RouteServices {
            ingress_key: gateway.ingress_key(),
            gateway,
            handshake_timeout: std::time::Duration::from_secs(1),
            relay_idle_timeout: std::time::Duration::from_secs(1),
        })
    }

    fn effective_network() -> cageforge_policy_compose::EffectiveNetworkPolicy {
        let policy = NetworkPolicy::unrestricted();
        let requested = cageforge_policy::SandboxPolicy::new(
            cageforge_policy::FilesystemPolicy::unrestricted(),
            policy.clone(),
        );
        let environment = EnvironmentSpec::empty();
        let ceiling = PolicyCeiling::new(
            cageforge_policy::SandboxPolicy::new(
                cageforge_policy::FilesystemPolicy::unrestricted(),
                policy,
            ),
            EnvironmentSpec::empty(),
        );
        compose(CompositionRequest::new(&requested, &environment, &ceiling))
            .expect("effective sandbox")
            .network()
            .clone()
    }
}
