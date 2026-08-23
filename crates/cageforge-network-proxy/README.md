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
