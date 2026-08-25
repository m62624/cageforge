// SPDX-License-Identifier: Apache-2.0

//! Embedded Bubblewrap resource used by Linux application packaging.

#![deny(missing_docs)]

#[cfg(target_os = "linux")]
static BUNDLED_BUBBLEWRAP: &[u8] = include_bytes!(env!("CAGEFORGE_BUILT_BWRAP"));

/// Returns the reviewed Bubblewrap executable built for this Linux target.
///
/// The bytes are embedded in the library so a downstream application can
/// materialize the bundled resource without relying on Cargo's private
/// `OUT_DIR` after compilation.
#[cfg(target_os = "linux")]
pub fn bundled_bubblewrap() -> &'static [u8] {
    BUNDLED_BUBBLEWRAP
}
