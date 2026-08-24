# Specification 0015: Bundled Bubblewrap Build and Resources

Status: accepted

## Purpose

`cageforge-bwrap` is the single workspace component responsible for building
the optional bundled Linux Bubblewrap executable. The Linux backend consumes
the resulting resource but does not compile third-party C source itself.

## Source and licensing

The source is taken directly from the official Bubblewrap project at:

- tag: `v0.11.2`;
- commit: `1b80120ef26a28e065e67f89bfef873f13bdd317`;
- license: LGPL-2.0-or-later.

The source files, copyright headers, `COPYING`, `LICENSE`, README, and
provenance record remain together under
`crates/cageforge-bwrap/vendor/bubblewrap/`. The Cageforge build wrapper is
Apache-2.0, while the bundled Bubblewrap component keeps its own license.

## Build contract

On Linux, the crate invokes the target C compiler directly against the
upstream Bubblewrap sources and links the discovered `libcap` dependency from
`pkg-config`. It does not download source code during a normal build. The
`CAGEFORGE_BWRAP_SOURCE_DIR` variable can select another source checkout only
when the caller deliberately supplies one.

The crate's staging command is:

```text
cargo run -p cageforge-bwrap -- --output <resource-dir>/bwrap
```

It creates an executable `bwrap` and a sibling `bwrap.sha256` manifest. The
resource must be built separately for every Linux target architecture.

## Runtime selection

`cageforge-linux` uses this order by default:

1. find a suitable system `bwrap` outside the current working directory;
2. validate its required flags and namespace probes;
3. if it is missing or incompatible, find `cageforge-resources/bwrap`;
4. verify its executable mode and SHA-256 manifest;
5. run the same capability and namespace probes;
6. return a typed error if no safe executable is available.

The hardening helper uses the application sibling first and the same resource
directory second. An application may select an explicit resource directory or
explicit executable paths.

## Security invariants

- A bundled executable without a valid digest manifest is rejected.
- A digest mismatch is rejected before Bubblewrap is executed.
- A system executable is never accepted merely because it exists; its help
  flags and namespace behavior are probed.
- The resource fallback cannot widen a policy: it only supplies the native
  process boundary used by the already-composed Cageforge request.
- The binary is a release resource next to the application, not a file hidden
  in a Cargo registry directory.
