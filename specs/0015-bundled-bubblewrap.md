# Specification 0015: Bundled Bubblewrap Build and Resources

Status: accepted

## Purpose

`cageforge-bwrap` is the single workspace component responsible for building
the bundled Linux Bubblewrap executable and exposing its reviewed
architecture-specific resources. The Linux backend consumes the resulting
resource but does not compile third-party C source itself.

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

The `build-from-source` feature is the explicit source-builder mode. On Linux,
the crate invokes the target C compiler directly against the upstream
Bubblewrap sources and links the discovered `libcap` dependency from
`pkg-config`. It does not download source code during a normal build. The
`CAGEFORGE_BWRAP_SOURCE_DIR` variable can select another source checkout only
when the caller deliberately supplies one.

The dependency-facing `embedded` feature does not invoke that builder. It
selects one release-generated executable using `cfg(target_arch)`:

- `x86_64` uses `assets/linux-x86_64/bwrap`;
- `aarch64` uses `assets/linux-aarch64/bwrap`.

Each asset has a sibling `bwrap.sha256` manifest. The assets are produced by
the source-builder mode on matching native Linux runners, checked for the
expected ELF architecture and digest, and included in the published package.
The Linux backend enables this mode through its single public
`bundled-bubblewrap` feature with the dependency's default builder features
disabled.

The crate's staging command is:

```text
cargo run -p cageforge-bwrap -- --output <resource-dir>/bwrap
```

It creates an executable `bwrap` and a sibling `bwrap.sha256` manifest. The
resource must be built separately for every Linux target architecture. A
downstream application using the embedded feature does not run this command.

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
- The validated binary is opened and pinned before backend construction
  completes; later spawns execute that descriptor rather than reopening the
  resource path.
- A system executable is never accepted merely because it exists; its help
  flags and namespace behavior are probed.
- The resource fallback cannot widen a policy: it only supplies the native
  process boundary used by the already-composed Cageforge request.
- The binary is a release resource next to the application, not a file hidden
  in a Cargo registry directory.
- Embedding removes the build-time C compiler and target `libcap` sysroot
  requirement, but does not remove Bubblewrap's Linux runtime dependencies or
  kernel prerequisites. Those remain checked by the backend's typed probes.

## Native CI and packaging

The resource build is a matrix over native `x86_64` and `aarch64` Linux
runners. The jobs run when `cageforge-bwrap`, `cageforge-linux`, or one of the
actual shared dependencies of the Linux backend changes, and always on
`main`. Each job builds the pinned source, validates the output architecture,
stages its digest, runs the embedded-resource check, and uploads the
architecture-labelled resource artifact. The release packaging step must
include both assets and their manifests before a crate containing the
`bundled-bubblewrap` feature is published.
