// SPDX-License-Identifier: Apache-2.0

//! Bounds checks shared by Windows ACL readers.

use std::ffi::c_void;

pub(crate) const SID_HEADER_BYTES: usize = 8;

/// Return the complete byte length encoded by a SID subauthority count.
pub(crate) fn sid_length_from_count(count: u8) -> Option<usize> {
    SID_HEADER_BYTES.checked_add(usize::from(count).checked_mul(size_of::<u32>())?)
}

/// Check that the SID embedded at `sid_offset` is wholly contained in an ACE.
///
/// The caller supplies the size obtained from the owning Windows ACL buffer;
/// this function only performs the additional arithmetic and byte-bound
/// checks needed before interpreting the embedded SID.
#[allow(unsafe_code)]
pub(crate) fn sid_fits_ace(raw_ace: *const c_void, ace_size: usize, sid_offset: usize) -> bool {
    if raw_ace.is_null() {
        return false;
    }
    let Some(bytes) = (sid_offset <= ace_size)
        .then(|| unsafe { std::slice::from_raw_parts(raw_ace.cast::<u8>(), ace_size) })
    else {
        return false;
    };
    sid_fits_ace_bytes(bytes, sid_offset)
}

/// Check an already-bounded ACE byte slice for a complete embedded SID.
pub(crate) fn sid_fits_ace_bytes(ace: &[u8], sid_offset: usize) -> bool {
    let Some(header_end) = sid_offset.checked_add(SID_HEADER_BYTES) else {
        return false;
    };
    if header_end > ace.len() {
        return false;
    }
    let Some(sid_length) = sid_length_from_count(ace[sid_offset + 1]) else {
        return false;
    };
    sid_offset
        .checked_add(sid_length)
        .is_some_and(|end| end <= ace.len())
}

#[cfg(test)]
mod tests {
    use super::{sid_fits_ace, sid_fits_ace_bytes};

    #[test]
    fn sid_bounds_are_checked_before_reading_the_count() {
        let mut ace = [0u8; 20];
        ace[9] = 1;

        assert!(sid_fits_ace(ace.as_ptr().cast(), ace.len(), 2));
        assert!(!sid_fits_ace_bytes(&ace, 16));
        assert!(!sid_fits_ace(std::ptr::null(), ace.len(), 2));
    }

    #[test]
    fn oversized_subauthority_count_fails_closed() {
        let mut ace = [0u8; 20];
        ace[3] = u8::MAX;

        assert!(!sid_fits_ace_bytes(&ace, 2));
    }
}
