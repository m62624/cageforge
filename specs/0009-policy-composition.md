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
- `External` ownership is accepted only when both sides use external
  enforcement. A local/external mismatch is a typed composition error rather
  than a silent allow or deny conversion.
- Workspace roots are deduplicated and retained only when each requested root
  is inside one of the optional ceiling roots. The composer performs lexical
  declaration checks; runtime path resolution and symlink behavior remain at
  the backend/context boundary.
- Environment composition chooses the least permissive base (`None`,
  `Core`, or `All`), applies the requested transformation, then applies the
  ceiling transformation. The ceiling cannot introduce a variable absent from
  the requested result. The command crate's portable order remains
  `inherit → exclude → set/remove → include`.
- `.git` protection is preserved because every filesystem decision is checked
  against both complete policies. If either side retains the default protected
  path, a write request below it cannot become writable through composition.
  A dangerous opt-out is effective only if both input policies opt out.

The effective types expose the two component policies to a future backend
lowering layer. They do not claim that a particular OS can implement every
rule. This is the pure-intersection option: backend capability checks and
typed unsupported-capability errors belong to `cageforge-backend-api`.

## Ownership boundary

`cageforge-policy-compose` owns:

- monotonic filesystem, network, environment, and workspace-root narrowing;
- external-enforcement ownership checks;
- typed composition and policy-evaluation errors;
- keeping the inputs available for later backend lowering.

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
- matching external ownership remaining externally enforced.

Portable composition logic must retain at least 90% line coverage. Native
capability and enforcement tests are added to each backend crate on its native
CI runner; they are not simulated in this crate.
