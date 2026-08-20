> ⚠️ **Independent project**
>
> Cageforge is not affiliated with, sponsored by, or endorsed by OpenAI.

# cageforge-core

`cageforge-core` is reserved for the future ergonomic facade that will join a
validated command, an effective policy, and a selected native backend. It is
not the place where portable policy rules or platform enforcement are defined.

## Current status

The crate is currently an intentionally small workspace placeholder. It does
not yet expose a stable facade API and should not be used as a substitute for
the model crates.

Use the current libraries directly:

- [`cageforge-command`](https://docs.rs/cageforge-command/latest/cageforge_command/)
  for command and environment intent;
- [`cageforge-policy`](https://docs.rs/cageforge-policy/latest/cageforge_policy/)
  for filesystem and network policy;
- [`cageforge-config`](https://docs.rs/cageforge-config/latest/cageforge_config/)
  for TOML profiles;
- [`cageforge-policy-compose`](https://docs.rs/cageforge-policy-compose/latest/cageforge_policy_compose/)
  for an outer policy ceiling.
- [`cageforge-backend-api`](https://docs.rs/cageforge-backend-api/latest/cageforge_backend_api/)
  for capability negotiation and side-effect-free preflight before a native
  backend takes ownership of execution.

Future facade design must preserve the ownership boundaries of these crates:
configuration produces validated values, composition narrows them,
`cageforge-backend-api` checks the resulting contract, and a native backend
performs operating-system enforcement.

Repository: [github.com/m62624/cageforge](https://github.com/m62624/cageforge).
