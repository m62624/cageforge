> ⚠️ **Independent project**
>
> Cageforge is not affiliated with, sponsored by, or endorsed by OpenAI. This
> crate adapts sandbox design ideas from open-source OpenAI Codex into an
> independent library API and contains no copied Codex source.

# cageforge-macos

`cageforge-macos` is the macOS-native backend for Cageforge's library API. It
provides the Seatbelt process boundary used to run potentially untrusted
commands, agents, plugins, build scripts, and mods. The backend accepts the
portable Cageforge command and effective-policy models and creates one
independent OS-enforced boundary for each command tree.

The backend object is reusable: callers may prepare and run multiple commands
concurrently with different policies. Each instance has its own native policy,
process lifecycle, timeout, and network enforcement state.

## Workspace role

| Crate | Role |
|---|---|
| `cageforge-command` | Validated program, arguments, working directory, stdio, timeout, and environment intent. |
| `cageforge-policy` | Portable filesystem and network policy declarations. |
| `cageforge-policy-compose` | Requested-policy and safety-ceiling intersection. |
| `cageforge-backend-api` | Backend-bound preflight and capability contract. |
| `cageforge-network-proxy` | Exact-target gateway for restricted network modes. |
| `cageforge-macos` | Seatbelt process and native lifecycle enforcement. |

The final `cageforge-core` facade will select this backend together with the
Linux and Windows backends. Applications can use this crate directly while
that facade is developed.

## Current API boundary

Constructing `MacosBackend` validates the absolute `/usr/bin/sandbox-exec`
executable. Native command preparation and spawning are being added in the
same backend contract described in Specification 0017. The crate advertises
no execution capability until each corresponding Seatbelt lowering path and
black-box test is complete.

The exact native enforcement correspondence and completion requirements are in
[`specs/0017-macos-backend-implementation.md`](../../specs/0017-macos-backend-implementation.md).
