// SPDX-License-Identifier: Apache-2.0

//! Parent-side serialization of the final command environment.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::os::unix::ffi::OsStrExt;

use crate::error::EnvironmentFrameError;
use crate::helper_protocol::{
    ENVIRONMENT_MAGIC, MAX_ENVIRONMENT_ENTRIES, MAX_ENVIRONMENT_FRAME_BYTES,
    MAX_ENVIRONMENT_VALUE_BYTES,
};

pub(crate) fn write_environment(
    writer: &mut impl Write,
    environment: &BTreeMap<OsString, OsString>,
) -> Result<(), EnvironmentFrameError> {
    if environment.len() > MAX_ENVIRONMENT_ENTRIES {
        return Err(EnvironmentFrameError::EntryLimitExceeded {
            count: environment.len(),
            maximum: MAX_ENVIRONMENT_ENTRIES,
        });
    }
    let frame_bytes = environment
        .iter()
        .try_fold(0_usize, |total, (name, value)| {
            total
                .checked_add(name.as_bytes().len())
                .and_then(|total| total.checked_add(value.as_bytes().len()))
        });
    if frame_bytes.is_none_or(|length| length > MAX_ENVIRONMENT_FRAME_BYTES) {
        return Err(EnvironmentFrameError::FrameLimitExceeded {
            maximum: MAX_ENVIRONMENT_FRAME_BYTES,
        });
    }
    writer
        .write_all(ENVIRONMENT_MAGIC)
        .map_err(|source| EnvironmentFrameError::Io {
            operation: "magic write",
            source,
        })?;
    write_length(writer, environment.len())?;
    for (name, value) in environment {
        write_os_string(writer, name)?;
        write_os_string(writer, value)?;
    }
    Ok(())
}

fn write_os_string(writer: &mut impl Write, value: &OsStr) -> Result<(), EnvironmentFrameError> {
    let bytes = value.as_bytes();
    if bytes.len() > MAX_ENVIRONMENT_VALUE_BYTES {
        return Err(EnvironmentFrameError::LengthLimitExceeded {
            length: bytes.len(),
            maximum: MAX_ENVIRONMENT_VALUE_BYTES,
        });
    }
    write_length(writer, bytes.len())?;
    writer
        .write_all(bytes)
        .map_err(|source| EnvironmentFrameError::Io {
            operation: "value write",
            source,
        })
}

fn write_length(writer: &mut impl Write, length: usize) -> Result<(), EnvironmentFrameError> {
    let length = u64::try_from(length).map_err(|_| EnvironmentFrameError::LengthTooLarge)?;
    writer
        .write_all(&length.to_be_bytes())
        .map_err(|source| EnvironmentFrameError::Io {
            operation: "length write",
            source,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStringExt;

    #[test]
    fn writer_rejects_too_many_environment_entries() {
        let environment = (0..=MAX_ENVIRONMENT_ENTRIES)
            .map(|index| {
                (
                    OsString::from(format!("KEY_{index}")),
                    OsString::from("value"),
                )
            })
            .collect();

        assert!(matches!(
            write_environment(&mut Vec::new(), &environment),
            Err(EnvironmentFrameError::EntryLimitExceeded { .. })
        ));
    }

    #[test]
    fn writer_rejects_an_oversized_environment_value() {
        let environment = BTreeMap::from([(
            OsString::from("KEY"),
            OsString::from_vec(vec![b'x'; MAX_ENVIRONMENT_VALUE_BYTES + 1]),
        )]);

        assert!(matches!(
            write_environment(&mut Vec::new(), &environment),
            Err(EnvironmentFrameError::LengthLimitExceeded { .. })
        ));
    }

    #[test]
    fn writer_rejects_an_oversized_aggregate_frame() {
        let value = OsString::from_vec(vec![b'x'; MAX_ENVIRONMENT_VALUE_BYTES]);
        let environment = (0..=MAX_ENVIRONMENT_FRAME_BYTES / MAX_ENVIRONMENT_VALUE_BYTES)
            .map(|index| (OsString::from(format!("KEY_{index}")), value.clone()))
            .collect();

        assert!(matches!(
            write_environment(&mut Vec::new(), &environment),
            Err(EnvironmentFrameError::FrameLimitExceeded { .. })
        ));
    }
}
