# Specification 0013: Network Proxy

Status: accepted for implementation; required by native backends that enforce
restricted outbound TCP policy

## 1. Purpose

`cageforge-network-proxy` is the platform-independent outbound gateway used by
native Cageforge backends. It accepts proxy protocol connections from an
already isolated command, resolves requested hosts, applies the complete
effective network policy, and opens only the exact socket address authorized
by that policy.

The crate is independently implemented. Its behavior is reviewed against the
portable security boundaries in OpenAI Codex `network-proxy`, especially its
policy, connect-policy, HTTP proxy, SOCKS5, upstream connector, and Linux proxy
routing consumers. Product MITM, credentials, attribution, telemetry, remote
configuration, and managed control-plane behavior are not part of Cageforge.

## 2. Responsibility boundary

The shared crate owns:

- HTTP/1.1 forward-proxy request handling;
- HTTP `CONNECT` tunneling;
- SOCKS5 `CONNECT` with no unauthenticated protocol extensions;
- one DNS resolution snapshot per outbound connection attempt;
- construction of `ResolvedNetworkTarget` from every resolved address;
- immediate exact-address authorization through the composed policy;
- connection using only the consumed `AuthorizedSocketAddr`;
- bounded handshakes, request counts, concurrency, DNS, connect, and relay
  lifetimes; and
- typed protocol, policy, resolver, connection, and resource-limit errors.

The crate does not own an operating-system sandbox boundary. A native backend
must supply a private ingress and make direct network access impossible. The
backend-specific responsibilities are:

| Backend | Native responsibility |
| --- | --- |
| Linux | Isolated network namespace, private loopback-to-Unix bridge, forced proxy endpoints, and no direct host route |
| macOS | Seatbelt network/socket rules and a private proxy ingress |
| Windows | Restricted process/network boundary and an authenticated private proxy ingress |

Unix-socket destination policy remains a native backend concern. The shared
gateway opens outbound TCP sockets only.

## 3. Dependency and handoff contract

The dependency direction is:

```text
cageforge-policy
        ↓
cageforge-policy-compose
        ↓
cageforge-network-proxy
        ↓
cageforge-linux / cageforge-macos / cageforge-windows
        ↓
cageforge-core
```

`GatewayConfig` and `GatewayConfigError` are available without the crate's
default `runtime` feature. `cageforge-config` uses this feature-disabled model
to build the same validated value from TOML without depending on Tokio, Hyper,
the DNS resolver, or policy composition. Native backends enable `runtime` and
receive the protocol gateway APIs as well.

The gateway accepts an owned `EffectiveNetworkPolicy`. It must never accept a
raw `SandboxPolicy`, one `NetworkPolicy` layer, a hostname-only
`NetworkDecision`, a caller-created `AuthorizedSocketAddr`, or a connector
callback that can ignore exact-address authorization.

`EffectiveNetworkPolicy` retains requested policy and `PolicyCeiling` as one
mandatory conjunction. Its public authorization operation is the only route
from a resolved address to an outbound connection. A native backend obtains
the effective policy only from its backend-bound `PreparedBackendRequest`.

## 4. Public API shape

The public API consists of these concepts:

```text
GatewayConfig
  ├── handshake timeout
  ├── DNS timeout
  ├── one connect deadline shared by all candidates in a DNS snapshot
  ├── upstream response-header timeout
  ├── relay idle timeout
  ├── maximum concurrent connections
  ├── maximum HTTP requests per ingress connection
  ├── maximum addresses in one DNS snapshot
  ├── HTTP/1 parser buffer size
  └── optional relay byte limit

NetworkResolver
  └── resolve(host, port) -> all SocketAddr values

SystemResolver
  └── system-configured cancellable DNS implementation

NetworkGateway<R>
  ├── new(effective_policy, resolver, config)
  ├── ingress_key() -> GatewayIngressKey
  └── serve_connection(private_stream)
```

The resolver trait is injectable for deterministic tests and applications
with an existing DNS boundary. It returns candidates only; it cannot grant
access. Every returned address is still captured in one
`ResolvedNetworkTarget`, checked against both effective policy layers, and
individually authorized immediately before connect.

The gateway owns its policy and resource semaphore. It may be cloned only as
another handle to the same immutable enforcement instance. It must not expose
the effective policy, an unchecked outbound stream, or an API that connects by
hostname.

Every ingress stream begins with a versioned authentication frame containing
an unguessable per-gateway key. `GatewayIngressKey` may be cloned only to place
the same proof into trusted native bridge connections; its `Debug` output must
not reveal the secret. There is no public unauthenticated serve method. Native
filesystem permissions or loopback binding are defense in depth, not a
replacement for this handshake.

The canonical TOML adapter is
`[profiles.<name>.network.gateway]`. It maps positive millisecond and count
values through the public builders. A positive integer selects a relay byte
ceiling; the explicit string `"unlimited"` calls the named API that removes
it. Gateway fields inherit independently, while permission rules remain in the
surrounding `network` section.

## 5. Protocol contract

### HTTP forward proxy

Ordinary HTTP requests must use absolute-form URIs. The gateway parses them
with a maintained HTTP implementation, derives the host and port from the URI,
replaces ambiguous forwarding headers, converts the request target to
origin-form, and creates a new authorized upstream connection for every
request. Persistent ingress connections must not let a later request reuse an
earlier hostname authorization.

Only `http` absolute-form requests are forwarded directly. HTTPS is carried
through `CONNECT`; unsupported schemes fail closed.

### HTTP CONNECT

The authority is validated before a success response is sent. DNS resolution,
policy authorization, and the exact outbound connect all complete first. The
gateway then returns success and relays only that checked stream.

### SOCKS5 CONNECT

The gateway supports version 5, no-authentication negotiation, and TCP
`CONNECT`. Unsupported authentication, commands, address types, malformed
lengths, and invalid UTF-8 domains receive a protocol failure. Domain requests
use the resolver; IPv4 and IPv6 literals create an exact one-address snapshot.

## 6. Exact-address invariant

For every outbound connection:

1. parse one normalized host and port;
2. resolve once, or construct one literal address;
3. reject an empty result;
4. build one `ResolvedNetworkTarget` containing every result;
5. call `EffectiveNetworkPolicy::authorize_connection` for the exact candidate
   immediately before connecting;
6. consume `AuthorizedSocketAddr` into the socket operation; and
7. never resolve the hostname again inside the connector.

If any address in the captured result violates private, loopback, link-local,
or domain policy, the effective policy fails closed for the target. A failed
connect may try another address from the same snapshot, but every attempt
requires a fresh exact authorization.

## 7. Resource and lifecycle contract

Secure defaults must bound parser buffers, concurrent connections, requests
per ingress connection, DNS snapshot size, DNS duration, total candidate
connect duration, response-header duration, relay inactivity, and transferred
bytes. Disabling the default relay-byte ceiling uses a named method rather than
an ambiguous `None` argument.

Connection handlers must be cancellation-safe. Dropping the future closes its
ingress and outbound streams. Native backend shutdown must stop accepting new
connections and wait for or cancel active handlers before deleting bridge
resources. Multiple gateway instances have independent immutable policies and
semaphores; no global mutable allowlist is permitted.

## 8. Errors

`GatewayError` must keep these failure classes distinguishable:

- unsupported effective mode;
- concurrency or request limit reached;
- handshake timeout;
- malformed or unsupported HTTP/SOCKS5 input;
- invalid authority;
- DNS timeout, failure, or empty result;
- policy denial or external ownership;
- outbound connect timeout or failure;
- relay timeout or byte-limit exhaustion; and
- ingress/upstream I/O failure.

Protocol responses may translate these errors to HTTP or SOCKS status codes,
but the Rust API must retain the typed cause where the connection lifecycle
can report it.

## 9. Verification

Black-box integration tests must cover:

- ordinary HTTP requests authorize every request separately;
- HTTP `CONNECT` and SOCKS5 use the same exact-address flow;
- allow and deny domain patterns;
- public, private, loopback, IPv4, IPv6, and empty DNS snapshots;
- a candidate outside the captured snapshot cannot be connected;
- malformed HTTP, authority, SOCKS version, command, and address input;
- missing, malformed, and cross-instance ingress authentication;
- DNS, connect, handshake, and relay timeout paths;
- connection, request, and optional byte limits;
- concurrent gateway instances with different policies do not share state;
- dropping a handler closes resources; and
- all public examples compile as doctests.

Property tests should generate malformed authorities and SOCKS frames, but
must stay bounded for normal CI. Coverage for this crate must remain at least
90 percent before it is connected to a native backend.
