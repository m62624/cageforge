> ⚠️ **Independent project**
>
> Cageforge is not affiliated with, sponsored by, or endorsed by OpenAI.

# cageforge-linux

`cageforge-linux` is the Linux native execution backend for Cageforge. It
consumes a composed `EffectiveSandbox`, performs the common backend preflight,
lowers the validated request to a Bubblewrap process boundary, and launches
the command only when every requested capability is supported.

The crate is used after the portable layers:

```text
cageforge-config (optional TOML input)
    -> cageforge-command + cageforge-policy
    -> cageforge-policy-compose
    -> cageforge-backend-api
    -> cageforge-linux
```

Linux support is capability-based. The backend rejects a request with a typed
error when it cannot enforce one of the request's filesystem, network,
environment, or process requirements. It never widens a restricted request to
an unrestricted process.

The backend currently uses a system Bubblewrap executable. The executable is
validated and probed during construction; it is not bundled into Cageforge.
See the repository's licensing and native-backend specifications for the
separate decision required before distributing Bubblewrap.

`spawn` is the execution boundary: it accepts only a backend-bound prepared
request and constructs the Bubblewrap plan and authenticated hardening-helper
stage internally. The backend reserves `/dev` for Bubblewrap's device tree,
`/proc` for the fresh PID namespace, and `/dev/shm/cageforge` for the helper,
so policy rules targeting those runtime paths are rejected rather than
shadowed. Filesystem glob rules and network policies that require DNS or exact
socket authorization are also rejected until a native lowering path can
enforce them completely.
