> ⚠️ **Independent project**
>
> Cageforge is not affiliated with, sponsored by, or endorsed by OpenAI. This
> crate adapts sandbox design ideas from open-source OpenAI Codex into an
> independent library API and contains no copied Codex source.

# cageforge-policy-compose

`cageforge-policy-compose` narrows a requested Cageforge sandbox policy with a
portable `PolicyCeiling`. It is the reusable policy-limiting layer for projects
that need to apply an outer safety boundary before execution.

The result keeps the requested and ceiling policies as separate internal
constraints. Public effective APIs expose combined decisions, aggregate
backend requirements, and immutable lowering views containing every required
constraint layer, so a consumer cannot select the requested side and
accidentally bypass the ceiling. Filesystem and network decisions are allowed only when both sides allow them;
external enforcement is accepted only when both sides delegate that boundary
to an external owner. Environment rules are applied in sequence and cannot
add a variable that was absent from the requested result. Workspace roots must
remain inside the configured ceiling roots.

The composition crate works with the public types from `cageforge-policy` and
`cageforge-command`, so an integrating project declares those crates directly
alongside `cageforge-policy-compose`.

## When to use it

Use this crate when the requested permissions must be narrowed by another
independent limit: for example, an application-wide default, a workspace
boundary, a tenant restriction, or a caller-provided safety policy.

Do not use it merely to construct a policy. If there is no outer limit,
`cageforge-policy` is enough. Do not treat it as a backend abstraction: it
does not know how Linux, macOS, or Windows will enforce the result.

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
let workspace = std::env::temp_dir().join("cageforge-example-workspace");
let context = effective.path_context(
    &cageforge_policy::PathResolutionContext::new()
        .with_workspace_root(workspace)
        .expect("valid workspace root"),
)?;

assert_eq!(
    effective
        .filesystem()
        .access_for(&PathSelector::workspace_root(), &context)?,
    cageforge_policy::FilesystemDecision::Read
);
# Ok::<(), cageforge_policy_compose::CompositionError>(())
```

After composition, a backend API can inspect the effective constraints, check
native capabilities, and lower them for Linux, macOS, or Windows execution.

The backend handoff must use `EffectiveSandbox`, not the original requested
policy. Its filesystem context, network authorization methods, environment
base, and workspace-root limit are the narrowed contract. A backend may reject
an unsupported capability, but it must not silently replace the effective
constraints with a broader request.

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

Create owners explicitly with `ExternalOwner::new()`. The type deliberately
does not implement `Default`: every newly created owner is a different identity,
so a generic default value must not be mistaken for a shared enforcement
boundary. Cloning an owner preserves its identity.

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
  constrained by both policies plus aggregate requirements for capability
  negotiation. Their `lowering()` views expose every immutable filesystem or
  network constraint layer needed by a native backend, including rules,
  protected paths, glob depth, domain defaults, local-address settings, and
  Unix socket rules. A backend must process every returned layer as a
  conjunction; the layers are not alternative policies and neither input is
  exposed as an independent backend choice. Filesystem selector queries require the
  `EffectivePathContext` created by `EffectiveSandbox::path_context`; its raw
  `PathResolutionContext` is not exposed. The context is bound to that
  composed result and cannot be reused with another one. Use its safe accessors
  or `resolve` method when a backend needs the narrowed runtime paths. A
  selector with no effective runtime paths is denied.
  `glob_scan_max_depth`
  returns the widest depth required by all effective deny-glob rules.
  `EffectiveNetworkPolicy::authorize_connection` applies both policies to one
  `ResolvedNetworkTarget` and the exact socket address supplied by a backend,
  then returns that address as a typed value. It performs no DNS lookup itself.
- `CoreEnvironment` wraps the validated map selected by a platform backend's
  core environment allowlist. `EnvironmentInput::core` accepts this type
  instead of an arbitrary map, making the selection boundary explicit.
- `EffectiveEnvironment` exposes the least-permissive base and applies both
  environment transformations only to an `EnvironmentInput` whose selected
  base is no broader than the effective base. `EnvironmentSpec::apply_to`
  returns a validated snapshot, so the base tag remains attached until the
  process adapter deliberately extracts its variables.

The complete API is documented on
[docs.rs](https://docs.rs/cageforge-policy-compose/latest/cageforge_policy_compose/).

## Using it in another project

The crate can be used with any configuration source. Construct a
`SandboxPolicy` and `EnvironmentSpec` directly in Rust, or obtain them from
`cageforge-config`, then create a `PolicyCeiling` and call `compose` before
passing the result to the project's execution layer.
