// SPDX-License-Identifier: Apache-2.0

//! Parent-side serialization of the final command environment.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;

use crate::helper_protocol::ENVIRONMENT_MAGIC;

pub(crate) fn write_environment(
    writer: &mut impl Write,
    environment: &BTreeMap<OsString, OsString>,
) -> io::Result<()> {
    writer.write_all(ENVIRONMENT_MAGIC)?;
    write_length(writer, environment.len())?;
    for (name, value) in environment {
        write_os_string(writer, name)?;
        write_os_string(writer, value)?;
    }
    Ok(())
}

fn write_os_string(writer: &mut impl Write, value: &OsStr) -> io::Result<()> {
    write_length(writer, value.as_bytes().len())?;
    writer.write_all(value.as_bytes())
}

fn write_length(writer: &mut impl Write, length: usize) -> io::Result<()> {
    let length = u64::try_from(length)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "frame length is too large"))?;
    writer.write_all(&length.to_be_bytes())
}
