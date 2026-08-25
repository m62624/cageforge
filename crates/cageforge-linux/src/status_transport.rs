// SPDX-License-Identifier: Apache-2.0

//! Authenticated transport for the sandboxed command's native wait status.

use std::io::Read;
use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;

use crate::error::{LinuxHelperRuntimeFailure, LinuxHelperRuntimeFailureKind, StatusFrameError};
use crate::helper_protocol::{
    STATUS_MAGIC, STATUS_RESULT_COMMAND, STATUS_RESULT_FAILURE, STATUS_RESULT_NO_ERRNO,
};

#[derive(Debug)]
pub(crate) enum HelperExecutionResult {
    CommandExited(ExitStatus),
    HelperFailed(LinuxHelperRuntimeFailure),
}

pub(crate) fn read_status(
    reader: &mut impl Read,
) -> Result<HelperExecutionResult, StatusFrameError> {
    let mut magic = [0; STATUS_MAGIC.len()];
    loop {
        match reader.read(&mut magic[..1]) {
            Ok(0) => return Err(StatusFrameError::MissingFrame),
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

    let mut tag = [0];
    reader
        .read_exact(&mut tag)
        .map_err(|source| StatusFrameError::Io {
            operation: "result tag read",
            source,
        })?;
    match tag[0] {
        STATUS_RESULT_COMMAND => read_command_status(reader),
        STATUS_RESULT_FAILURE => read_runtime_failure(reader),
        tag => Err(StatusFrameError::InvalidResultTag { tag }),
    }
}

fn read_command_status(reader: &mut impl Read) -> Result<HelperExecutionResult, StatusFrameError> {
    let mut raw = [0; size_of::<i32>()];
    reader
        .read_exact(&mut raw)
        .map_err(|source| StatusFrameError::Io {
            operation: "status read",
            source,
        })?;
    Ok(HelperExecutionResult::CommandExited(ExitStatus::from_raw(
        i32::from_be_bytes(raw),
    )))
}

fn read_runtime_failure(reader: &mut impl Read) -> Result<HelperExecutionResult, StatusFrameError> {
    let mut code = [0; 2];
    reader
        .read_exact(&mut code)
        .map_err(|source| StatusFrameError::Io {
            operation: "failure code read",
            source,
        })?;
    let code = u16::from_be_bytes(code);
    let kind = LinuxHelperRuntimeFailureKind::try_from(code)
        .map_err(|()| StatusFrameError::InvalidFailureCode { code })?;

    let mut raw_os_error = [0; 4];
    reader
        .read_exact(&mut raw_os_error)
        .map_err(|source| StatusFrameError::Io {
            operation: "failure errno read",
            source,
        })?;
    let raw_os_error = i32::from_be_bytes(raw_os_error);
    let raw_os_error = (raw_os_error != STATUS_RESULT_NO_ERRNO).then_some(raw_os_error);
    Ok(HelperExecutionResult::HelperFailed(
        LinuxHelperRuntimeFailure::new(kind, raw_os_error),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn invalid_status_magic_is_typed() {
        let frame = [b'x'; STATUS_MAGIC.len() + 1 + size_of::<i32>()];

        assert!(matches!(
            read_status(&mut Cursor::new(frame)),
            Err(StatusFrameError::InvalidMagic)
        ));
    }

    #[test]
    fn clean_status_channel_end_is_a_typed_error() {
        assert!(matches!(
            read_status(&mut Cursor::new([])),
            Err(StatusFrameError::MissingFrame)
        ));
    }

    #[test]
    fn command_status_frame_preserves_the_native_wait_status() {
        let expected = ExitStatus::from_raw(libc::SIGTERM);
        let mut frame = STATUS_MAGIC.to_vec();
        frame.push(STATUS_RESULT_COMMAND);
        frame.extend_from_slice(&expected.into_raw().to_be_bytes());

        let HelperExecutionResult::CommandExited(actual) =
            read_status(&mut Cursor::new(frame)).expect("command status")
        else {
            panic!("expected command status");
        };
        assert_eq!(actual.into_raw(), libc::SIGTERM);
    }

    #[test]
    fn helper_runtime_failure_retains_category_and_errno() {
        let mut frame = STATUS_MAGIC.to_vec();
        frame.push(STATUS_RESULT_FAILURE);
        frame.extend_from_slice(
            &u16::from(LinuxHelperRuntimeFailureKind::CommandStart).to_be_bytes(),
        );
        frame.extend_from_slice(&libc::ENOENT.to_be_bytes());

        let HelperExecutionResult::HelperFailed(failure) =
            read_status(&mut Cursor::new(frame)).expect("helper failure")
        else {
            panic!("expected helper failure");
        };
        assert_eq!(failure.kind(), LinuxHelperRuntimeFailureKind::CommandStart);
        assert_eq!(failure.raw_os_error(), Some(libc::ENOENT));
    }

    #[test]
    fn unknown_runtime_failure_code_is_rejected() {
        let mut frame = STATUS_MAGIC.to_vec();
        frame.push(STATUS_RESULT_FAILURE);
        frame.extend_from_slice(&u16::MAX.to_be_bytes());
        frame.extend_from_slice(&STATUS_RESULT_NO_ERRNO.to_be_bytes());

        assert!(matches!(
            read_status(&mut Cursor::new(frame)),
            Err(StatusFrameError::InvalidFailureCode { code: u16::MAX })
        ));
    }

    #[test]
    fn unknown_result_tag_is_rejected() {
        let mut frame = STATUS_MAGIC.to_vec();
        frame.push(u8::MAX);

        assert!(matches!(
            read_status(&mut Cursor::new(frame)),
            Err(StatusFrameError::InvalidResultTag { tag: u8::MAX })
        ));
    }
}
