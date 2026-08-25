// SPDX-License-Identifier: Apache-2.0

//! Host-side reader for the authenticated helper setup-result frame.

use std::io::Read;

use crate::error::{LinuxHelperSetupFailure, LinuxHelperSetupFailureKind, SetupHandshakeError};
use crate::helper_protocol::{
    SETUP_RESULT_FAILURE, SETUP_RESULT_MAGIC, SETUP_RESULT_NO_ERRNO, SETUP_RESULT_READY,
};

pub(crate) fn read_setup_result(reader: &mut impl Read) -> Result<(), SetupHandshakeError> {
    let mut magic = vec![0; SETUP_RESULT_MAGIC.len()];
    reader.read_exact(&mut magic)?;
    if magic != SETUP_RESULT_MAGIC {
        return Err(SetupHandshakeError::InvalidReady);
    }

    let mut tag = [0];
    reader.read_exact(&mut tag)?;
    match tag[0] {
        SETUP_RESULT_READY => Ok(()),
        SETUP_RESULT_FAILURE => read_failure(reader),
        tag => Err(SetupHandshakeError::InvalidResultTag { tag }),
    }
}

fn read_failure(reader: &mut impl Read) -> Result<(), SetupHandshakeError> {
    let mut code = [0; 2];
    reader.read_exact(&mut code)?;
    let code = u16::from_be_bytes(code);
    let kind = LinuxHelperSetupFailureKind::try_from(code)
        .map_err(|()| SetupHandshakeError::InvalidFailureCode { code })?;

    let mut raw_os_error = [0; 4];
    reader.read_exact(&mut raw_os_error)?;
    let raw_os_error = i32::from_be_bytes(raw_os_error);
    let raw_os_error = (raw_os_error != SETUP_RESULT_NO_ERRNO).then_some(raw_os_error);
    Err(SetupHandshakeError::HelperRejected {
        failure: LinuxHelperSetupFailure::new(kind, raw_os_error),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn ready_frame_is_accepted() {
        let mut frame = SETUP_RESULT_MAGIC.to_vec();
        frame.push(SETUP_RESULT_READY);

        assert!(read_setup_result(&mut Cursor::new(frame)).is_ok());
    }

    #[test]
    fn typed_failure_retains_category_and_errno() {
        let mut frame = SETUP_RESULT_MAGIC.to_vec();
        frame.push(SETUP_RESULT_FAILURE);
        frame.extend_from_slice(
            &u16::from(LinuxHelperSetupFailureKind::KeyringIsolation).to_be_bytes(),
        );
        frame.extend_from_slice(&libc::EPERM.to_be_bytes());

        let error = read_setup_result(&mut Cursor::new(frame)).expect_err("helper failure");
        let SetupHandshakeError::HelperRejected { failure } = error else {
            panic!("unexpected error: {error}");
        };
        assert_eq!(
            failure.kind(),
            LinuxHelperSetupFailureKind::KeyringIsolation
        );
        assert_eq!(failure.raw_os_error(), Some(libc::EPERM));
    }

    #[test]
    fn unknown_failure_code_is_rejected() {
        let mut frame = SETUP_RESULT_MAGIC.to_vec();
        frame.push(SETUP_RESULT_FAILURE);
        frame.extend_from_slice(&u16::MAX.to_be_bytes());
        frame.extend_from_slice(&SETUP_RESULT_NO_ERRNO.to_be_bytes());

        assert!(matches!(
            read_setup_result(&mut Cursor::new(frame)),
            Err(SetupHandshakeError::InvalidFailureCode { code: u16::MAX })
        ));
    }
}
