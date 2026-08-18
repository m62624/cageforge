# Specification 0009: Effective Policy Composition

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
private components with read-only accessors. It does not concatenate policy
rules into a new allowlist: that would be unsafe because a restricted policy
with no entries means deny-all, and concatenating it with another policy could
accidentally grant access.

- Filesystem decisions are evaluated against both policies. `Deny` is stronger
  than `Read`, and `Read` is stronger than `Write`.
- Network decisions are evaluated independently. A domain or Unix socket is
  allowed only when both policies allow it.
- Resolved domain decisions are evaluated independently with the same complete
  address set on both sides through
  `EffectiveNetworkPolicy::decision_for_domain_with_resolved_ips`. The
  composer performs no DNS lookup; an empty set represents failed resolution
  and the default local-network denial remains monotonic.
- `External` ownership is accepted only when both sides use external
  enforcement and the request and ceiling carry the same opaque
  `ExternalOwner` token. A local/external mismatch, missing owner proof, or
  unrelated owner is a typed composition error rather than a silent allow or
  deny conversion.
- Workspace roots are deduplicated and retained only when each requested root
  is inside one of the optional ceiling roots. Composition accepts only
  runtime-resolved absolute roots. `EffectiveSandbox::path_context` creates an
  opaque context whose workspace roots cannot be replaced by a broader caller
  context; symlink behavior remains at the backend boundary.
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

The effective types expose the two component policies to a future backend
lowering layer. `EffectiveFilesystemPolicy::glob_scan_max_depth` combines the
depth requirements conservatively: the larger bounded depth wins, and any
relevant unbounded deny-glob makes the result unbounded. The backend must still
preserve both component policies, including their rules and protected paths;
the composer does not concatenate them into an unsafe allowlist. Backend
capability checks and typed unsupported-capability errors belong to
`cageforge-backend-api`.

## Ownership boundary

`cageforge-policy-compose` owns:

- monotonic filesystem, network, environment, and workspace-root narrowing;
- external-enforcement owner-proof checks;
- typed composition and policy-evaluation errors;
- keeping the inputs available for later backend lowering;
- construction of a workspace-root-constrained runtime path context.

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
