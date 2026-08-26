> ⚠️ **Independent project**
>
> Cageforge is not affiliated with, sponsored by, or endorsed by OpenAI. This
> crate adapts sandbox design ideas from open-source OpenAI Codex into an
> independent library API and contains no copied Codex source.

# cageforge-windows

`cageforge-windows` is the elevated Windows execution backend for Cageforge.
The crate is being assembled in fail-closed layers. Its current API defines
versioned provisioning configuration, deterministic per-user identities, typed
setup failures, and read-only account-state verification. The execution backend
will be exposed only together with the complete restricted-token, ACL,
firewall/WFP, proxy-attribution, private-desktop, Job Object, and child-lifecycle
path.

The completed backend uses the same integration sequence as
`cageforge-linux`:

```text
command + requested policy + PolicyCeiling + runtime paths
                              │
                              ▼
                     EffectiveSandbox
                              │
                              ▼
              WindowsBackend::prepare
                              │
                              ▼
             backend-bound prepared request
                              │
                              ▼
                WindowsBackend::spawn
```

The secure backend requires one administrator-approved provisioning step.
Ordinary launches do not require elevation. Provisioning creates dedicated
offline and online local users, protects their credentials and control state,
and installs account-scoped firewall and WFP rules. Backend construction reads
that state back and reports a typed error instead of falling back to the weaker
current-user restricted-token mode.

Restricted commands run with request-specific restricting capability SIDs,
atomic Job Object assignment, kill-on-close without breakaway, a private
desktop, and an explicit inherited-handle list. Proxy-routed commands also get
a random route SID. The shared IPv4 loopback ingress attributes each accepted
connection by its exact reversed TCP four-tuple and selects exactly one
registered route before entering the Cageforge exact-target gateway.

The crate reuses `cageforge-command`, `cageforge-policy`,
`cageforge-policy-compose`, `cageforge-backend-api`, `cageforge-path`, and
`cageforge-network-proxy`; it does not define a second command or policy model.
See Specification 0016 in the repository for the complete setup, enforcement,
and native test contract.
