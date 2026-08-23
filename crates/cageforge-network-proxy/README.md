> ⚠️ **Independent project**
>
> Cageforge is not affiliated with, sponsored by, or endorsed by OpenAI.

# cageforge-network-proxy

`cageforge-network-proxy` provides the shared outbound network gateway used by
Cageforge native sandbox backends. It handles HTTP proxy requests, HTTP
`CONNECT`, and SOCKS5 `CONNECT`, resolves each destination once, applies both
layers of an `EffectiveNetworkPolicy`, and connects only to the consumed exact
address authorization.

The gateway is transport-neutral on its ingress side. A native backend gives
it an authenticated private stream and separately prevents the sandboxed
process from reaching the network directly. Linux uses this with an isolated
network namespace and a private loopback-to-Unix bridge; macOS and Windows can
attach their own native ingress boundaries to the same gateway.

## Workspace role

| Crate | Role in the relationship |
| --- | --- |
| `cageforge-policy` | Defines domain, local-address, and exact resolved-target semantics |
| `cageforge-policy-compose` | Produces the mandatory requested-policy ∩ ceiling network value |
| `cageforge-network-proxy` | Parses proxy traffic and performs exact authorized outbound connects |
| Native backend crates | Own private ingress, OS isolation, launch, and lifecycle |
| `cageforge-core` | Will provide the target-selected high-level sandbox API |

Start with [`NetworkGateway`](https://docs.rs/cageforge-network-proxy/latest/cageforge_network_proxy/struct.NetworkGateway.html),
[`GatewayConfig`](https://docs.rs/cageforge-network-proxy/latest/cageforge_network_proxy/struct.GatewayConfig.html),
and [`SystemResolver`](https://docs.rs/cageforge-network-proxy/latest/cageforge_network_proxy/struct.SystemResolver.html).
The crate-level documentation contains the complete integration sequence.

## Constructing a gateway

The gateway accepts only the network side of an already composed sandbox. A
resolver supplies candidates but cannot authorize them; every address still
passes through the complete effective policy immediately before connection.

```rust
use std::future::Future;
use std::io;
use std::net::SocketAddr;

use cageforge_command::EnvironmentSpec;
use cageforge_network_proxy::{GatewayConfig, NetworkGateway, NetworkResolver};
use cageforge_policy::{
    DomainAccess, DomainMode, FilesystemPolicy, NetworkPolicy, SandboxPolicy,
};
use cageforge_policy_compose::{CompositionRequest, PolicyCeiling, compose};

#[derive(Clone)]
struct ApplicationResolver;

impl NetworkResolver for ApplicationResolver {
    fn resolve(
        &self,
        _host: &str,
        _port: u16,
    ) -> impl Future<Output = io::Result<Vec<SocketAddr>>> + Send {
        std::future::ready(Ok(Vec::new()))
    }
}

let network = NetworkPolicy::enabled()
    .with_domain_mode(DomainMode::Restricted)
    .with_domain("downloads.example.com", DomainAccess::Allow)?;
let requested = SandboxPolicy::new(FilesystemPolicy::restricted([]), network);
let ceiling = PolicyCeiling::new(
    SandboxPolicy::full_access(),
    EnvironmentSpec::inherit_core(),
);
let effective = compose(CompositionRequest::new(
    &requested,
    &EnvironmentSpec::inherit_core(),
    &ceiling,
))?;
let gateway = NetworkGateway::new(
    effective.network().clone(),
    ApplicationResolver,
    GatewayConfig::new(),
)?;
let ingress_key = gateway.ingress_key();

// A native backend authenticates each private bridge stream with this key,
// then passes the peer stream to `gateway.serve_connection(...)`.
let _ = ingress_key;
# Ok::<(), Box<dyn std::error::Error>>(())
```

`GatewayConfig` and `GatewayConfigError` are available with
`default-features = false`. The default `runtime` feature adds the resolver,
HTTP/SOCKS gateway, authentication, and relay implementation. This lets a
configuration adapter reuse the canonical settings type without pulling the
async network stack into parsing-only applications.
