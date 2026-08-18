<!--
⚠️ Cageforge is an independent project. It is not affiliated with, sponsored
by, or endorsed by OpenAI. This crate independently implements a portable
policy-composition API informed by the public sandbox concepts reviewed in
OpenAI Codex.
-->

# cageforge-policy-compose

`cageforge-policy-compose` narrows a requested Cageforge sandbox policy with a
portable `PolicyCeiling`. It is a pure library: it does not know about a
harness, a backend, an operating system, process spawning, or Codex runtime
types.

The result keeps the requested and ceiling policies as separate constraints.
Filesystem and network decisions are allowed only when both sides allow them;
external enforcement is accepted only when both sides delegate that boundary
to an external owner. Environment rules are applied in sequence and cannot
add a variable that was absent from the requested result. Workspace roots must
remain inside the configured ceiling roots.

## Example

```rust
use cageforge_command::EnvironmentSpec;
use cageforge_policy::SandboxPolicy;
use cageforge_policy_compose::{compose, CompositionRequest, PolicyCeiling};

let requested = SandboxPolicy::read_only();
let ceiling = PolicyCeiling::new(
    SandboxPolicy::read_only(),
    EnvironmentSpec::inherit_core(),
);
let effective = compose(CompositionRequest::new(
    &requested,
    &EnvironmentSpec::inherit_core(),
    &[],
    &ceiling,
))?;
assert_eq!(effective.workspace_roots(), &[]);
# Ok::<(), cageforge_policy_compose::CompositionError>(())
```

The crate intentionally does not report native capability support. A future
`cageforge-backend-api` layer will inspect these effective constraints and
return typed unsupported-capability errors before selecting a Linux, macOS, or
Windows backend.

## API guide

- `PolicyCeiling` stores the outer portable maximum policy, environment rules,
  and optional workspace-root limit.
- `CompositionRequest` supplies a requested policy without taking ownership of
  the caller's values.
- `compose` returns `EffectiveSandbox`.
- `EffectiveFilesystemPolicy` and `EffectiveNetworkPolicy` expose decisions
  that are constrained by both policies and retain both inputs for backend
  lowering.
- `EffectiveEnvironment` exposes the least-permissive base and applies both
  environment transformations.

The complete API is documented on [docs.rs](https://docs.rs/) when the crate is
published. Integration coverage lives in [`tests/compose.rs`](tests/compose.rs).

## Project relationship

This crate is part of the Cageforge workspace and is independently authored.
Its portable intersection boundary was designed after reviewing the public
sandbox-policy behavior in OpenAI Codex; it does not import Codex source or
Codex-specific product and legacy APIs.
