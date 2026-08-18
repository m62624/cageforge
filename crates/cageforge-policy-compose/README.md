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

| Crate | Role | Runtime dependencies | Used by |
|---|---|---|---|
| `cageforge-policy` | Portable filesystem and network policy semantics | `cageforge-path` | This crate and backend integrations |
| `cageforge-command` | Portable environment specification used during composition | `cageforge-path` | This crate and command/config integrations |
| `cageforge-path` | Shared native path comparison semantics | None | This crate and the other path-bearing layers |
| `cageforge-config` | Optional TOML source for requested values | Not a dependency of this crate | Applications wire its resolved values into this crate |

The dependency direction is deliberate: composition does not depend on a
configuration format. An application can use TOML, JSON, Rust builders, or its
own configuration system and pass the same validated policy values here.

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
`ExternalOwner` proof. The proof is not a harness, OS, process, or network
backend identifier; it only prevents two unrelated external enforcement
boundaries from being treated as one:

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
  effective deny-glob rules. `EffectiveNetworkPolicy::decision_for_domain_with_resolved_ips`
  applies the same DNS-rebinding-safe narrowing to every resolved address
  supplied by a backend; it performs no DNS lookup itself.
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
