// SPDX-License-Identifier: Apache-2.0

//! Authenticated transport for the sandboxed command's native wait status.

use std::io::{self, Read};
use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;

use crate::helper_protocol::STATUS_MAGIC;

pub(crate) fn read_status(reader: &mut impl Read) -> io::Result<Option<ExitStatus>> {
    let mut magic = [0; STATUS_MAGIC.len()];
    loop {
        match reader.read(&mut magic[..1]) {
            Ok(0) => return Ok(None),
            Ok(1) => break,
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "status transport returned an invalid prefix length",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    reader.read_exact(&mut magic[1..])?;
    if magic != STATUS_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid command status frame",
        ));
    }
    let mut raw = [0; size_of::<i32>()];
    reader.read_exact(&mut raw)?;
    Ok(Some(ExitStatus::from_raw(i32::from_ne_bytes(raw))))
}
