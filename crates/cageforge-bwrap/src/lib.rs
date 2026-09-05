// SPDX-License-Identifier: Apache-2.0

//! Bubblewrap builder and embedded Linux resources.

#![deny(missing_docs)]

#[cfg(target_os = "linux")]
mod embedded {
    // These bytes are executables produced from the pinned, original
    // Bubblewrap sources in `vendor/bubblewrap/`; they are not Cageforge Rust
    // code.
    #[cfg(all(feature = "embedded", target_arch = "x86_64"))]
    pub(super) const BINARY: &[u8] = include_bytes!("../assets/linux-x86_64/bwrap");

    #[cfg(all(feature = "embedded", target_arch = "x86_64"))]
    pub(super) const DIGEST: &str = include_str!("../assets/linux-x86_64/bwrap.sha256");

    #[cfg(all(feature = "embedded", target_arch = "aarch64"))]
    pub(super) const BINARY: &[u8] = include_bytes!("../assets/linux-aarch64/bwrap");

    #[cfg(all(feature = "embedded", target_arch = "aarch64"))]
    pub(super) const DIGEST: &str = include_str!("../assets/linux-aarch64/bwrap.sha256");
}

/// Returns the reviewed Bubblewrap executable built for this Linux target.
///
/// The bytes are embedded in the library so a downstream application can
/// materialize the bundled resource without relying on Cargo's private
/// `OUT_DIR` or a local C toolchain after compilation. They are built from the
/// original upstream Bubblewrap sources and remain covered by the accompanying
/// LGPL license.
#[cfg(all(target_os = "linux", feature = "embedded"))]
pub fn bundled_bubblewrap() -> &'static [u8] {
    embedded::BINARY
}

/// Returns the expected SHA-256 digest for the embedded executable.
#[cfg(all(target_os = "linux", feature = "embedded"))]
pub fn bundled_bubblewrap_sha256() -> &'static str {
    embedded::DIGEST.trim()
}
