# Specification 0009: Effective Policy Composition

Status: accepted design; implementation deferred until the backend API

## Purpose

`cageforge-config` resolves a user-requested profile. It is not the final
security authority. A future `cageforge-policy-compose` or
`cageforge-backend-api` layer must combine that request with the capabilities
granted by the harness and the selected native backend.

```text
requested profile + harness grant + backend capabilities
                         |
                         v
                   effective policy
```

The effective policy may only be narrower than the requested policy. A backend
must reject an unsupported or disallowed request rather than silently widening
it or treating an unavailable restriction as successful enforcement.

## Composition rules

- Filesystem capabilities are intersected. `Deny` is stronger than `Read`, and
  `Read` is stronger than `Write`.
- Network access is intersected independently from filesystem access. Domain
  and Unix-socket allowlists are narrowed, and a deny rule cannot be removed by
  a requested profile.
- Profile workspace roots are requests. They are resolved against the runtime
  context, deduplicated, and intersected with roots granted by the harness.
- Environment policy is narrowed by combining base-environment limits and
  filters. Excludes have precedence; includes cannot restore excluded values.
- Mandatory protected metadata paths, initially `.git`, are always retained in
  the effective policy. User configuration may add protections but may not
  remove them.
- `unrestricted` and `external` modes are explicit ownership transfers. They
  require a matching grant from the harness/backend and are not inferred from
  missing rules.

## Ownership boundary

The composer owns capability intersection, runtime root materialization,
backend capability checks, and typed unsupported-policy errors. It does not
parse TOML, discover a user's project trust state, launch a process, or expose
Codex protocol types.

Native backends remain responsible for enforcing the effective result,
including symlink behavior, platform path comparison, process restrictions,
network syscall restrictions, and platform-specific process creation.

## Required tests

Before a composer is implemented, its public integration tests must cover:

- requested write reduced to read or deny by a grant;
- network allowlists narrowed by a grant;
- requested roots outside granted roots rejected or removed with a typed result;
- excluded environment variables never restored by includes or overrides;
- `.git` protection surviving every requested profile;
- explicit rejection of unsupported `unrestricted` and `external` transfers;
- Linux, macOS, and Windows path comparison behavior in native backend tests.
