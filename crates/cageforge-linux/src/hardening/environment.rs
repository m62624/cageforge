// SPDX-License-Identifier: Apache-2.0

//! Helper-side validation of the final command environment frame.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io::Read;
use std::os::unix::ffi::{OsStrExt, OsStringExt};

use crate::environment_transport::{
    MAX_ENVIRONMENT_ENTRIES, MAX_ENVIRONMENT_FRAME_BYTES, MAX_ENVIRONMENT_VALUE_BYTES,
};
use crate::error::EnvironmentFrameError;
use crate::helper_protocol::ENVIRONMENT_MAGIC;

pub(super) fn read_environment(
    reader: &mut impl Read,
) -> Result<BTreeMap<OsString, OsString>, EnvironmentFrameError> {
    let mut magic = vec![0; ENVIRONMENT_MAGIC.len()];
    reader
        .read_exact(&mut magic)
        .map_err(|source| EnvironmentFrameError::Io {
            operation: "magic read",
            source,
        })?;
    if magic != ENVIRONMENT_MAGIC {
        return Err(EnvironmentFrameError::InvalidMagic);
    }
    let count = read_length(reader)?;
    if count > MAX_ENVIRONMENT_ENTRIES {
        return Err(EnvironmentFrameError::EntryLimitExceeded {
            count,
            maximum: MAX_ENVIRONMENT_ENTRIES,
        });
    }
    let mut environment = BTreeMap::new();
    let mut frame_bytes = 0_usize;
    for _ in 0..count {
        let name = read_os_string(reader)?;
        let value = read_os_string(reader)?;
        frame_bytes = frame_bytes
            .checked_add(name.as_bytes().len())
            .and_then(|total| total.checked_add(value.as_bytes().len()))
            .ok_or(EnvironmentFrameError::FrameLimitExceeded {
                maximum: MAX_ENVIRONMENT_FRAME_BYTES,
            })?;
        if frame_bytes > MAX_ENVIRONMENT_FRAME_BYTES {
            return Err(EnvironmentFrameError::FrameLimitExceeded {
                maximum: MAX_ENVIRONMENT_FRAME_BYTES,
            });
        }
        validate_environment_entry(&name, &value)?;
        if environment.insert(name, value).is_some() {
            return Err(EnvironmentFrameError::DuplicateVariable);
        }
    }
    Ok(environment)
}

fn read_os_string(reader: &mut impl Read) -> Result<OsString, EnvironmentFrameError> {
    let length = read_length(reader)?;
    if length > MAX_ENVIRONMENT_VALUE_BYTES {
        return Err(EnvironmentFrameError::LengthLimitExceeded {
            length,
            maximum: MAX_ENVIRONMENT_VALUE_BYTES,
        });
    }
    let mut value = vec![0; length];
    reader
        .read_exact(&mut value)
        .map_err(|source| EnvironmentFrameError::Io {
            operation: "value read",
            source,
        })?;
    Ok(OsString::from_vec(value))
}

fn read_length(reader: &mut impl Read) -> Result<usize, EnvironmentFrameError> {
    let mut length = [0; 8];
    reader
        .read_exact(&mut length)
        .map_err(|source| EnvironmentFrameError::Io {
            operation: "length read",
            source,
        })?;
    usize::try_from(u64::from_be_bytes(length)).map_err(|_| EnvironmentFrameError::LengthTooLarge)
}

fn validate_environment_entry(name: &OsStr, value: &OsStr) -> Result<(), EnvironmentFrameError> {
    if name.is_empty() || name.as_bytes().contains(&0) || name.as_bytes().contains(&b'=') {
        return Err(EnvironmentFrameError::InvalidName);
    }
    if value.as_bytes().contains(&0) {
        return Err(EnvironmentFrameError::InvalidValue);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn reader_rejects_an_oversized_entry_count_before_allocating() {
        let mut frame = ENVIRONMENT_MAGIC.to_vec();
        frame.extend_from_slice(&((MAX_ENVIRONMENT_ENTRIES + 1) as u64).to_be_bytes());

        assert!(matches!(
            read_environment(&mut Cursor::new(frame)),
            Err(EnvironmentFrameError::EntryLimitExceeded { .. })
        ));
    }

    #[test]
    fn reader_rejects_an_oversized_value_before_allocating() {
        let mut frame = ENVIRONMENT_MAGIC.to_vec();
        frame.extend_from_slice(&1_u64.to_be_bytes());
        frame.extend_from_slice(&3_u64.to_be_bytes());
        frame.extend_from_slice(b"KEY");
        frame.extend_from_slice(&((MAX_ENVIRONMENT_VALUE_BYTES + 1) as u64).to_be_bytes());

        assert!(matches!(
            read_environment(&mut Cursor::new(frame)),
            Err(EnvironmentFrameError::LengthLimitExceeded { .. })
        ));
    }
}
