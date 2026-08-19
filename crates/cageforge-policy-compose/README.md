> ⚠️ **Independent project**
>
> Cageforge is not affiliated with, sponsored by, or endorsed by OpenAI. This
> crate adapts sandbox design ideas from open-source OpenAI Codex into an
> independent library API and contains no copied Codex source.

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

## Workspace role

`cageforge-policy-compose` is the optional policy-narrowing layer.

| Crate | Role in the relationship |
|---|---|
| `cageforge-policy` | Supplies filesystem and network constraints to compose. |
| `cageforge-command` | Supplies the environment specification used during composition. |
| `cageforge-config` | Optionally provides requested values from TOML; it is not a dependency of this crate. |
| Backend integrations | Inspect effective constraints and lower them to native execution APIs. |

The dependency direction is deliberate: composition does not depend on a
configuration format or a backend. An application can use TOML, JSON, Rust
builders, or its own configuration system and pass the same validated values
here.

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

`External` is accepted only when both policy sides use the same opaque
`ExternalOwner` proof. The proof is not evidence that an external sandbox
exists, is trusted, or is enforcing anything; it is only a caller-supplied
identity token that prevents two unrelated declarations from being treated as
one boundary:

```rust
use cageforge_policy_compose::ExternalOwner;

let owner = ExternalOwner::new();
assert_eq!(owner.clone(), owner);
assert_ne!(ExternalOwner::new(), owner);
```

## API guide

- `PolicyCeiling` stores the outer portable maximum policy, environment rules,
  and optional workspace-root limit.
- `CompositionRequest` supplies a requested policy without taking ownership of
  the caller's values. Runtime-resolved workspace roots can be added with
  `with_workspace_roots`.
- `compose` returns `EffectiveSandbox`.
- `EffectiveSandbox::path_context` creates the only context accepted by
  effective filesystem path evaluation, so a workspace-root ceiling cannot be
  silently replaced by a broader runtime context.
- `EffectiveFilesystemPolicy` and `EffectiveNetworkPolicy` expose decisions
  that are constrained by both policies and retain both inputs for backend
  lowering. `glob_scan_max_depth` returns the widest depth required by all
  effective deny-glob rules. `EffectiveNetworkPolicy::decision_for_resolved_target`
  and `decision_for_connected_address` apply the same DNS-rebinding-safe
  narrowing to one resolved target and the exact socket address supplied by a
  backend; they perform no DNS lookup themselves. `authorize_connection`
  returns the checked address as a typed value for the backend to connect to.
- `CoreEnvironment` wraps the map selected by a platform backend's core
  environment allowlist. `EnvironmentInput::core` accepts this type instead of
  an arbitrary map, making the selection boundary explicit.
- `EffectiveEnvironment` exposes the least-permissive base and applies both
  environment transformations only to an `EnvironmentInput` whose selected
  base is no broader than the effective base.

The complete API is documented on [docs.rs](https://docs.rs/) when the crate is
published.

## Using it in another project

The crate can be used with any configuration source. Construct a
`SandboxPolicy` and `EnvironmentSpec` directly in Rust, or obtain them from
`cageforge-config`, then create a `PolicyCeiling` and call `compose` before
passing the result to the project's execution layer.
