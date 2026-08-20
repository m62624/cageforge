> ⚠️ **Independent project**
>
> Cageforge is not affiliated with, sponsored by, or endorsed by OpenAI. This
> crate adapts sandbox boundary ideas from open-source OpenAI Codex into an
> independent library API and contains no copied Codex source.

# cageforge-backend-api

`cageforge-backend-api` is the contract layer between Cageforge's portable
execution values and a native Linux, macOS, or Windows backend.

It does not launch processes, open files or sockets, resolve DNS, allocate a
PTY, or choose an operating-system sandbox. It performs a side-effect-free
preflight check: a backend advertises what it can enforce, and a composed
request is rejected with a typed error when it asks for an unsupported
capability.

## The handoff model

```text
CommandRequest + EffectiveSandbox
                 │
                 ▼
        cageforge-backend-api
       capabilities + preflight
                 │
                 ▼
     native backend lowering/launch
```

`BackendRequest` accepts `CommandRequest` and `EffectiveSandbox`. It does not
accept a raw `SandboxPolicy`, so a backend integration cannot skip the
`PolicyCeiling` intersection. The command's `EnvironmentSpec` must be the same
requested environment that was passed to `CompositionRequest`; the API rejects
mixing values composed from different environment specifications.

```rust
use cageforge_backend_api::{
    BackendCapabilities, BackendRequest, SandboxBackend,
};

struct ExampleBackend {
    capabilities: BackendCapabilities,
}

impl SandboxBackend for ExampleBackend {
    fn capabilities(&self) -> BackendCapabilities {
        self.capabilities.clone()
    }
}

// A real backend constructs its capabilities from the enforcement mechanisms
// it can prove safe, then calls backend.prepare(request) before lowering it to
// native process and filesystem APIs.
```

## Responsibilities

The crate owns:

- `BackendCapability` and `BackendCapabilities`;
- `BackendRequest` and the opaque `PreparedBackendRequest`;
- the synchronous `SandboxBackend` preparation contract; and
- common unsupported-capability and preparation errors.

The native backend owns:

- Landlock, bubblewrap, Seatbelt, Windows ACL/token, or another OS mechanism;
- symlink, junction, reparse-point, mount, and TOCTOU-safe enforcement;
- DNS resolution and exact `SocketAddr` connection authorization;
- platform-specific core environment selection; and
- process launch, stdio, timeout, cancellation, and lifecycle errors.

`cageforge-core` will later provide an ergonomic facade and backend selection.
It is not a dependency of this crate.

## Workspace role

| Crate | Role in the relationship |
| --- | --- |
| `cageforge-command` | Supplies validated command and environment intent. |
| `cageforge-policy-compose` | Supplies the narrowed `EffectiveSandbox`. |
| `cageforge-policy` | Supplies portable policy values used during lowering. |
| `cageforge-path` | Supplies shared native lexical path semantics to integrations. |
| `cageforge-config` | Optional TOML producer; not a backend API dependency. |
| Native backend crates | Implement OS enforcement and process launch after preflight. |

The complete API is documented on
[docs.rs](https://docs.rs/cageforge-backend-api/latest/cageforge_backend_api/).
