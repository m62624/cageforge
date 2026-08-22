# Specification 0010: Effective Policy Composition

Status: accepted; `cageforge-policy-compose` implemented

## Purpose

`cageforge-config` resolves a requested profile. It is not the final security
authority. `cageforge-policy-compose` narrows that request against a neutral
portable `PolicyCeiling`. A future `cageforge-backend-api` then checks native
capabilities and lowers the effective constraints for a selected backend.

```text
requested profile ──┐
                    ├─ cageforge-policy-compose ── effective constraints
policy ceiling ─────┘                                      │
                                                           v
                                             cageforge-backend-api
                                                           │
                                                           v
                                                native OS backend
```

The ceiling is deliberately not named after a harness. It can be supplied by
an application, an embedding library, a remote executor, or another policy
layer without making this crate depend on any of them.

## Composition contract

`compose(CompositionRequest)` validates both policies and returns an
`EffectiveSandbox`. The result retains the requested and ceiling policies as
private components and exposes combined decision and requirement accessors
plus immutable lowering views. It does not concatenate policy rules into a new
allowlist: that
would be unsafe because a restricted policy with no entries means deny-all,
and concatenating it with another policy could accidentally grant access.

- Filesystem decisions are evaluated against both policies. `Deny` is stronger
  than `Read`, and `Read` is stronger than `Write`.
- Network decisions are evaluated independently. A domain or Unix socket is
  allowed only when both policies allow it.
- Resolved domain decisions are evaluated independently with the same complete
  address set on both sides through the typed
  `EffectiveNetworkPolicy::authorize_connection` flow. The composer
  performs no DNS lookup; an empty target snapshot represents failed
  resolution and the default local-network denial remains monotonic.
- `External` ownership is accepted only when both sides use external
  enforcement and the request and ceiling carry the same opaque
  `ExternalOwner` token. A local/external mismatch, missing owner proof, or
  unrelated owner is a typed composition error rather than a silent allow or
  deny conversion.
- Workspace roots are deduplicated and retained only when each requested root
  is inside one of the optional ceiling roots. A ceiling filters explicit and
  runtime roots but never creates a root absent from the request or context.
  Composition accepts only runtime-resolved absolute roots.
  `EffectiveSandbox::path_context` creates an
opaque context whose workspace roots cannot be replaced by a broader caller
context; symlink behavior remains at the backend boundary. The resulting
`EffectivePathContext` exposes only narrowed path accessors and selector
resolution. Its raw `PathResolutionContext` cannot be extracted and reused
with a different policy.
- Environment composition chooses the least permissive base (`None`,
  `Core`, or `All`), applies the requested transformation, then applies the
  ceiling transformation. The caller must pass an `EnvironmentInput` whose
  selected base is no broader than the effective base; a broader input is a
  typed error. The ceiling cannot introduce a variable absent from the
  requested result. The command crate's portable order remains `inherit →
  exclude → set/remove → include`.
- `.git` protection is preserved because every filesystem decision is checked
  against both complete policies. If either side retains the default protected
  path, a write request below it cannot become writable through composition.
  A dangerous opt-out is effective only if both input policies opt out.

The effective types retain the two component policies internally, but do not
expose either side as a public backend choice. They expose decisions that
already combine both sides, aggregate requirements for capability negotiation,
and `lowering()` views that retain every rule-bearing layer required by a
native backend. The backend must process every layer as a conjunction; the
view is not a permission to choose one side. Composition first normalizes both
`SandboxPolicy` values, so the retained filesystem entries have deterministic
duplicate-target semantics.
`EffectiveFilesystemPolicy::glob_scan_max_depth` combines the
depth requirements conservatively: the larger bounded depth wins, and any
relevant unbounded deny-glob makes the result unbounded. The backend must
consume the combined decisions and all reported requirements; it cannot select
one private component policy. The composer does not concatenate them into an
unsafe allowlist. Backend capability checks and typed unsupported-capability
errors belong to `cageforge-backend-api`.

## Ownership boundary

`cageforge-policy-compose` owns:

- monotonic filesystem, network, environment, and workspace-root narrowing;
- external-enforcement owner-proof checks;
- typed composition and policy-evaluation errors;
- exposing combined decisions, aggregate backend requirements, and complete
  immutable lowering views for later native lowering;
- construction of a workspace-root-constrained runtime path context.

Effective symbolic filesystem selectors are evaluated only with that narrowed
context. An empty resolution is denied, so a caller cannot obtain a broad
workspace decision and apply it to roots that the composition excluded.
The context is bound to its originating effective result and cannot be mixed
with another composition.

It does not own:

- TOML parsing, profile inheritance, or schema generation;
- backend capability matrices or OS-specific support checks;
- runtime filesystem discovery, symlink resolution, or path case rules;
- process spawning, PTYs, stdio, timeouts, or network proxying;
- trust, approvals, telemetry, managed configuration, or Codex protocol types.

Those responsibilities remain in `cageforge-config`,
`cageforge-command`, the future `cageforge-backend-api`, or native backend
crates as appropriate.

## Required tests

The crate's black-box integration suite covers:

- requested filesystem write narrowed to read and deny;
- independent network narrowing for domains and external ownership;
- requested roots outside a configured ceiling rejected with a typed error;
- nested roots retained and duplicate declarations removed;
- parent-traversal root declarations rejected;
- environment base narrowing, exclusion precedence, and prevention of
  ceiling-only variable additions;
- default `.git` protection surviving an ordinary writable request;
- explicit external/local ownership mismatch errors;
- matching external ownership remaining externally enforced;
- unrelated external owner proofs rejected;
- workspace-root ceilings enforced by the generated effective path context;
- effective deny-glob decisions and conservative glob scan depth;
- broader-than-effective environment inputs rejected;
- runtime root, minimal, temporary-directory, and `/tmp` context values
  preserved while workspace roots are narrowed.

Portable composition logic must retain at least 90% line coverage. Native
capability and enforcement tests are added to each backend crate on its native
CI runner; they are not simulated in this crate.

## Backend safety contracts

Backends must use `ResolvedNetworkTarget` and the resolved connection flow from
`EffectiveNetworkPolicy`. A hostname is not authorized merely because its rule
matched; the exact connected `SocketAddr` must belong to the checked resolution
snapshot. `EffectiveNetworkPolicy::authorize_connection` returns the checked
address as a typed value; hostname-only decisions are inspection results and
are not connection permissions.

`ExternalOwner` is only an opaque caller identity token. It does not prove
that an external sandbox exists or that it is enforcing anything.

`CoreEnvironment` and `EnvironmentInput::core` form the backend contract: a
backend must create the value only after selecting the platform's core
allowlist. The type does not authorize arbitrary inherited variables by
itself.

Filesystem native enforcement is specified separately in
`specs/0012-native-backend-safety-contract.md`.
