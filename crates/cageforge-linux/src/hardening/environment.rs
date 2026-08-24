// SPDX-License-Identifier: Apache-2.0

//! Helper-side validation of the final command environment frame.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io::{self, Read};
use std::os::unix::ffi::{OsStrExt, OsStringExt};

use crate::helper_protocol::ENVIRONMENT_MAGIC;

pub(super) fn read_environment(reader: &mut impl Read) -> io::Result<BTreeMap<OsString, OsString>> {
    let mut magic = vec![0; ENVIRONMENT_MAGIC.len()];
    reader.read_exact(&mut magic)?;
    if magic != ENVIRONMENT_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid environment frame",
        ));
    }
    let count = read_length(reader)?;
    let mut environment = BTreeMap::new();
    for _ in 0..count {
        let name = read_os_string(reader)?;
        let value = read_os_string(reader)?;
        validate_environment_entry(&name, &value)?;
        if environment.insert(name, value).is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "duplicate environment variable",
            ));
        }
    }
    Ok(environment)
}

fn read_os_string(reader: &mut impl Read) -> io::Result<OsString> {
    let length = read_length(reader)?;
    let mut value = vec![0; length];
    reader.read_exact(&mut value)?;
    Ok(OsString::from_vec(value))
}

fn read_length(reader: &mut impl Read) -> io::Result<usize> {
    let mut length = [0; 8];
    reader.read_exact(&mut length)?;
    usize::try_from(u64::from_be_bytes(length))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "frame length is too large"))
}

fn validate_environment_entry(name: &OsStr, value: &OsStr) -> io::Result<()> {
    if name.is_empty() || name.as_bytes().contains(&0) || name.as_bytes().contains(&b'=') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid environment variable name",
        ));
    }
    if value.as_bytes().contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid environment variable value",
        ));
    }
    Ok(())
}
