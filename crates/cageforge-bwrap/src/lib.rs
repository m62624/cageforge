// SPDX-License-Identifier: Apache-2.0

//! Embedded Bubblewrap resource used by Linux application packaging.

#![deny(missing_docs)]

#[cfg(target_os = "linux")]
// The embedded bytes are the executable produced from the pinned, original
// Bubblewrap sources in `vendor/bubblewrap/`; they are not Cageforge Rust code.
static BUNDLED_BUBBLEWRAP: &[u8] = include_bytes!(env!("CAGEFORGE_BUILT_BWRAP"));

/// Returns the reviewed Bubblewrap executable built for this Linux target.
///
/// The bytes are embedded in the library so a downstream application can
/// materialize the bundled resource without relying on Cargo's private
/// `OUT_DIR` after compilation. They are built from the original upstream
/// Bubblewrap sources and remain covered by the accompanying LGPL license.
#[cfg(target_os = "linux")]
pub fn bundled_bubblewrap() -> &'static [u8] {
    BUNDLED_BUBBLEWRAP
}
