⚠️ **Independent project**

`cageforge-bwrap` builds the official upstream Bubblewrap executable used as
the bundled Linux resource for Cageforge and provides the reviewed
architecture-specific bytes to `cageforge-linux`. It keeps the Bubblewrap
implementation separate from Cageforge's Apache-2.0 Rust crates.

The source snapshot is Bubblewrap `0.11.2` at commit
`1b80120ef26a28e065e67f89bfef873f13bdd317`. Its original LGPL-2.0-or-later
notices are retained under `vendor/bubblewrap/`. The standalone license text
is also available at `licenses/bubblewrap-COPYING` in this crate.

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
