> ⚠️ **Independent project**
>
> Cageforge is not affiliated with, sponsored by, or endorsed by OpenAI. This
> crate adapts sandbox boundary ideas from open-source OpenAI Codex into an
> independent library API and contains no copied Codex source.

# cageforge-backend-api

`cageforge-backend-api` is the contract layer between Cageforge's portable
execution values and a native Linux, macOS, or Windows backend. It defines the
typed handoff from a composed command and sandbox policy to the operating-
system integration that will enforce and launch them.

The crate turns a backend's declared enforcement capabilities into a common
preflight contract. `BackendRequest::prepare_for` accepts a request built from
`CommandRequest` and `EffectiveSandbox`, verifies every required capability,
and returns a prepared request or an actionable typed error.

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

`BackendRequest` accepts `CommandRequest` and `EffectiveSandbox`, so policy
composition and the `PolicyCeiling` intersection are completed before the
backend handoff. The command's `EnvironmentSpec` is checked against the
requested environment retained by the composed result, keeping command and
policy construction aligned.

Call `request.prepare_for(&backend, &base_context)` to run the common
capability and working-directory checks. `base_context` must include the
runtime current directory: it is checked even when the command does not set an
explicit cwd, so a child cannot silently inherit an unchecked directory from
the launching process. The backend trait only supplies its capabilities; it
cannot override this preflight with a broader set. The base context is
narrowed to the effective workspace ceiling, and an effective working
directory is rejected when the filesystem policy denies it. After preparation,
use `PreparedBackendRequest::command_spec` for the executable and argv values,
`PreparedBackendRequest::working_directory` for the resolved cwd,
`PreparedBackendRequest::path_context` to inspect the already narrowed
context, and `PreparedBackendRequest::apply_environment` with a
backend-selected `EnvironmentInput`. The filesystem decision helpers use that
same bound context and cannot be given a context from another request. A
symbolic selector is never evaluated without it. Use
`authorize_connection` to receive a decision that already combines the
requested and ceiling sides.

When a request needs an unsupported capability, preparation returns
`BackendContractError::UnsupportedCapability`. The error is matchable by its
`BackendCapability` variant and its display text names the required
enforcement, for example: `filesystem missing-path behavior (error or skip)`.

Capability checks include implicit requirements: a workspace-relative glob
needs `FilesystemScopes` so it is evaluated against the narrowed workspace
context, and every deny glob needs `FilesystemGlobScanDepth` because an absent
explicit depth means unbounded scanning. Concrete scopes also require the
matching selector capability: absolute, workspace, system-root, minimal,
temporary-directory, or slash-tmp. A backend that cannot enforce any required
behavior is rejected before lowering.

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
// it can prove safe, then runs the common preflight before lowering the
// request to native process and filesystem APIs.
```

## Responsibilities

The crate owns:

- `BackendCapability` and `BackendCapabilities`;
- `BackendRequest` and the opaque `PreparedBackendRequest`;
- the synchronous `SandboxBackend` capability contract and common preflight;
- common unsupported-capability and preparation errors.

The native backend owns:

- translating the effective contract to Landlock, bubblewrap, Seatbelt,
  Windows ACL/token, or another OS mechanism;
- symlink, junction, reparse-point, mount, and TOCTOU-safe enforcement;
- DNS resolution and exact `SocketAddr` connection authorization;
- platform-specific core environment selection; and
- process launch, stdio, timeout, cancellation, and lifecycle handling.

`cageforge-core` will provide the ergonomic facade and backend selection that
connect this contract to a concrete execution flow.

## Workspace role

| Crate | Role in the relationship |
| --- | --- |
| `cageforge-command` | Supplies validated command and environment intent. |
| `cageforge-policy-compose` | Supplies the narrowed `EffectiveSandbox`. |
| `cageforge-policy` | Supplies portable policy values and decision types used during lowering. |
| `cageforge-path` | Supplies the shared lexical path semantics used by policy and native integrations. |
| `cageforge-config` | Produces validated TOML-backed command and policy values for the handoff. |
| Native backend crates | Implement OS enforcement and process launch after preflight. |

The complete API is documented on
[docs.rs](https://docs.rs/cageforge-backend-api/latest/cageforge_backend_api/).
