// SPDX-License-Identifier: Apache-2.0

//! Authenticated transport for the sandboxed command's native wait status.

use std::io::Read;
use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;

use crate::error::StatusFrameError;
use crate::helper_protocol::STATUS_MAGIC;

pub(crate) fn read_status(reader: &mut impl Read) -> Result<Option<ExitStatus>, StatusFrameError> {
    let mut magic = [0; STATUS_MAGIC.len()];
    loop {
        match reader.read(&mut magic[..1]) {
            Ok(0) => return Ok(None),
            Ok(1) => break,
            Ok(_) => {
                return Err(StatusFrameError::InvalidPrefixLength);
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(source) => {
                return Err(StatusFrameError::Io {
                    operation: "prefix read",
                    source,
                });
            }
        }
    }
    reader
        .read_exact(&mut magic[1..])
        .map_err(|source| StatusFrameError::Io {
            operation: "magic read",
            source,
        })?;
    if magic != STATUS_MAGIC {
        return Err(StatusFrameError::InvalidMagic);
    }
    let mut raw = [0; size_of::<i32>()];
    reader
        .read_exact(&mut raw)
        .map_err(|source| StatusFrameError::Io {
            operation: "status read",
            source,
        })?;
    Ok(Some(ExitStatus::from_raw(i32::from_ne_bytes(raw))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn invalid_status_magic_is_typed() {
        let frame = [b'x'; STATUS_MAGIC.len() + size_of::<i32>()];

        assert!(matches!(
            read_status(&mut Cursor::new(frame)),
            Err(StatusFrameError::InvalidMagic)
        ));
    }

    #[test]
    fn clean_status_channel_end_is_not_an_error() {
        assert!(matches!(read_status(&mut Cursor::new([])), Ok(None)));
    }
}
