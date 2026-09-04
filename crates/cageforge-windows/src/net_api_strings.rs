// SPDX-License-Identifier: Apache-2.0

//! Bounded conversion of UTF-16 strings returned in NetAPI allocations.

use std::mem::{align_of, size_of};

use windows_sys::Win32::NetworkManagement::NetManagement::NetApiBufferSize;

/// Read a UTF-16 string owned by a NetAPI allocation without walking outside
/// the allocation when a returned pointer is malformed or unterminated.
#[allow(unsafe_code)]
pub(crate) fn net_api_wide_string(
    buffer: *const u8,
    value: *const u16,
) -> Result<Option<String>, u32> {
    if buffer.is_null() || value.is_null() {
        return Ok(None);
    }

    Ok(wide_string_within_allocation(
        buffer,
        net_api_buffer_size(buffer)?,
        value,
    ))
}

/// Return the byte length reported for a NetAPI allocation.
#[allow(unsafe_code)]
pub(crate) fn net_api_buffer_size(buffer: *const u8) -> Result<usize, u32> {
    let mut allocation_bytes = 0u32;
    let status =
        unsafe { NetApiBufferSize(buffer.cast(), std::ptr::addr_of_mut!(allocation_bytes)) };
    if status != 0 {
        return Err(status);
    }
    Ok(allocation_bytes as usize)
}

/// Validate an array count against the byte length of its NetAPI allocation.
pub(crate) fn net_api_array_len<T>(allocation_bytes: usize, count: u32) -> Option<usize> {
    let count = usize::try_from(count).ok()?;
    count
        .checked_mul(std::mem::size_of::<T>())
        .filter(|length| *length <= allocation_bytes)
        .map(|_| count)
}

#[allow(unsafe_code)]
fn wide_string_within_allocation(
    buffer: *const u8,
    allocation_bytes: usize,
    value: *const u16,
) -> Option<String> {
    let buffer_start = buffer as usize;
    let buffer_end = buffer_start.checked_add(allocation_bytes);
    let value_start = value as usize;
    let value_offset = value_start.checked_sub(buffer_start);
    let buffer_end = buffer_end?;
    if !value_start.is_multiple_of(align_of::<u16>())
        || value_offset.is_none_or(|offset| !offset.is_multiple_of(size_of::<u16>()))
        || value_start >= buffer_end
        || buffer_end - value_start < size_of::<u16>()
    {
        return None;
    }

    let available_units = (buffer_end - value_start) / size_of::<u16>();
    let units = unsafe { std::slice::from_raw_parts(value, available_units) };
    let length = units.iter().position(|unit| *unit == 0)?;
    String::from_utf16(&units[..length]).ok()
}

#[cfg(test)]
mod tests {
    use super::{net_api_array_len, wide_string_within_allocation};

    #[test]
    fn wide_string_is_bounded_by_the_netapi_allocation() {
        let value = [b'a' as u16, b'b' as u16, 0, b'x' as u16];

        assert_eq!(
            wide_string_within_allocation(
                value.as_ptr().cast(),
                std::mem::size_of_val(&value),
                value.as_ptr(),
            ),
            Some("ab".to_string())
        );
    }

    #[test]
    fn unterminated_or_invalid_netapi_strings_fail_closed() {
        let unterminated = [b'a' as u16, b'b' as u16];
        let invalid_utf16 = [0xd800, 0];

        assert_eq!(
            wide_string_within_allocation(
                unterminated.as_ptr().cast(),
                std::mem::size_of_val(&unterminated),
                unterminated.as_ptr(),
            ),
            None
        );
        assert_eq!(
            wide_string_within_allocation(
                invalid_utf16.as_ptr().cast(),
                std::mem::size_of_val(&invalid_utf16),
                invalid_utf16.as_ptr(),
            ),
            None
        );
    }

    #[test]
    fn pointer_outside_netapi_allocation_is_rejected() {
        let value = [b'a' as u16, 0];

        assert_eq!(
            wide_string_within_allocation(
                value.as_ptr().cast(),
                std::mem::size_of_val(&value),
                value.as_ptr().wrapping_add(value.len()),
            ),
            None
        );
    }

    #[test]
    fn array_count_must_fit_the_netapi_allocation() {
        assert_eq!(net_api_array_len::<u32>(8, 2), Some(2));
        assert_eq!(net_api_array_len::<u32>(7, 2), None);
        assert_eq!(net_api_array_len::<[u8; 8]>(7, 1), None);
    }
}
