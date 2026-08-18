<!--
⚠️ Cageforge is an independent project. It is not affiliated with, sponsored
by, or endorsed by OpenAI. This crate independently implements a portable
policy-composition API informed by the public sandbox concepts reviewed in
OpenAI Codex.
-->

# cageforge-policy-compose

`cageforge-policy-compose` narrows a requested Cageforge sandbox policy with a
portable `PolicyCeiling`. It is the reusable policy-limiting layer for projects
that need to apply an outer safety boundary before execution.

The result keeps the requested and ceiling policies as separate constraints.
Filesystem and network decisions are allowed only when both sides allow them;
external enforcement is accepted only when both sides delegate that boundary
to an external owner. Environment rules are applied in sequence and cannot
add a variable that was absent from the requested result. Workspace roots must
remain inside the configured ceiling roots.

The composition crate works with the public types from `cageforge-policy` and
`cageforge-command`, so an integrating project declares those crates directly
alongside `cageforge-policy-compose`.

## Example

```rust
use cageforge_command::EnvironmentSpec;
use cageforge_policy::{PathSelector, SandboxPolicy};
use cageforge_policy_compose::{compose, CompositionRequest, PolicyCeiling};

let requested = SandboxPolicy::workspace();
let ceiling = PolicyCeiling::new(
    SandboxPolicy::read_only(),
    EnvironmentSpec::inherit_core(),
);
let effective = compose(CompositionRequest::new(
    &requested,
    &EnvironmentSpec::inherit_all(),
    &[],
    &ceiling,
))?;

assert_eq!(
    effective
        .filesystem()
        .access_for(&PathSelector::workspace_root()),
    cageforge_policy::FilesystemDecision::Read
);
# Ok::<(), cageforge_policy_compose::CompositionError>(())
```

After composition, a backend API can inspect the effective constraints, check
native capabilities, and lower them for Linux, macOS, or Windows execution.

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
published.

## Using it in another project

The crate can be used with any configuration source. Construct a
`SandboxPolicy` and `EnvironmentSpec` directly in Rust, or obtain them from
`cageforge-config`, then create a `PolicyCeiling` and call `compose` before
passing the result to the project's execution layer.
