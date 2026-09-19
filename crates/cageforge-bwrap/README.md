> **Independent project:** Cageforge is not affiliated with, sponsored by, or endorsed by OpenAI.

This crate is a supporting component of the [`cageforge`](https://crates.io/crates/cageforge) crate, a cross-platform Rust sandbox for AI agents and untrusted code.

# cageforge-bwrap

Read the shared [configuration guide](https://github.com/m62624/cageforge/blob/main/crates/cageforge-config/examples/CONFIGURATION_GUIDE.md) for TOML profiles, symbolic paths, local IPC, and first-launch resource rules.

`cageforge-bwrap` builds the official upstream Bubblewrap executable used as
the bundled Linux resource for Cageforge and provides the reviewed
architecture-specific bytes to `cageforge-linux`. It keeps the Bubblewrap
implementation separate from Cageforge's Apache-2.0 Rust crates.

The source snapshot is Bubblewrap `0.12.0` at commit
`014a04330642e5c870418beb621532cb896e0002`. Its original LGPL-2.1-or-later
notices are retained under `vendor/bubblewrap/`. The standalone license text
is also available at `licenses/bubblewrap-COPYING` in this crate.

The upstream release includes `--not-a-security-boundary` for callers that
only need filesystem layout changes. Cageforge does not pass that option:
Bubblewrap setup failures remain fatal because Cageforge uses it as a security
boundary.

The `build-from-source` feature is the release-builder mode. On Linux it
requires a C compiler, `pkg-config`, and the development files for `libcap`.
Set `CAGEFORGE_BWRAP_SOURCE_DIR` to build from another reviewed Bubblewrap
source checkout; otherwise the pinned vendor snapshot is used. This mode is
used by Cageforge's native CI and release tooling.

The `embedded` feature supplies the prebuilt target resource selected by
`target_arch`; it does not invoke a C compiler. The supported Linux resources
are built independently for `x86_64` and `aarch64`, then included in the
published package together with their SHA-256 manifests. `cageforge-linux`
materializes and validates the selected bytes privately before using them as a
fallback for a compatible system Bubblewrap executable.

The `cageforge-linux/bundled-bubblewrap` feature enables `embedded`, so an
application does not need a local C toolchain or a separate staging step for
the bundled mode. The embedded executable still has the host's normal Linux
runtime and kernel prerequisites; embedding only removes the build-time
Bubblewrap toolchain requirement.
