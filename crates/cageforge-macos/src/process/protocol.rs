// SPDX-License-Identifier: Apache-2.0

//! Versioned command handoff. Policy lowering remains exclusively in the
//! backend; the helper receives a complete native argv, never shell syntax.

use std::{
    collections::BTreeMap,
    ffi::OsString,
    io::{self, Write},
    os::unix::ffi::{OsStrExt, OsStringExt},
    path::PathBuf,
    process::Command,
    time::Duration,
};

use cageforge_command::{CommandError, CommandRequest, CommandSpec, EnvironmentSpec};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;

use super::transport::{MAX_HELPER_FRAME_BYTES, PROTOCOL_VERSION};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) enum Request {
    Hello,
    Launch(Launch),
    Poll,
    Terminate,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) enum Response {
    Ready,
    Running {
        pid: u32,
    },
    Exited {
        raw_status: i32,
        timed_out: bool,
    },
    Failed {
        stage: Stage,
        native_code: Option<i32>,
        detail: String,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Launch {
    executable: Vec<u8>,
    arguments: Vec<Vec<u8>>,
    directory: Vec<u8>,
    environment: Vec<(Vec<u8>, Vec<u8>)>,
    timeout: Option<Duration>,
}

/// Lifecycle stage reported by an authenticated macOS helper.
#[derive(Debug, Serialize, Deserialize)]
pub enum Stage {
    /// The sender's kernel identity could not be authenticated.
    Authentication,
    /// Message encoding, command validation, or phase sequencing failed.
    Protocol,
    /// The native command could not be created.
    ProcessStart,
    /// The direct command's exit status could not be collected.
    ProcessWait,
    /// Complete descendant termination could not be confirmed.
    CoalitionCleanup,
    /// The prepared deadline could not be represented.
    Deadline,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Frame<T> {
    version: u64,
    message: T,
}

/// Invalid or unrepresentable macOS helper command/control frame.
#[derive(Debug, Error)]
pub enum ProtocolError {
    /// The encoded payload exceeds the IPC allocation budget.
    #[error("helper command frame exceeds {maximum} bytes")]
    TooLarge {
        /// Maximum encoded payload length in bytes.
        maximum: usize,
    },
    /// Serializing the control frame failed.
    #[error("failed to encode helper frame: {source}")]
    Encode {
        /// Original encoder failure.
        source: serde_json::Error,
    },
    /// The received bytes were not a complete supported control frame.
    #[error("failed to decode helper frame: {source}")]
    Decode {
        /// Original decoder failure.
        source: serde_json::Error,
    },
    /// The helper and application implement incompatible wire versions.
    #[error("helper protocol version {actual} is incompatible with {expected}")]
    Version {
        /// Supported wire version.
        expected: u64,
        /// Received wire version.
        actual: u64,
    },
    /// The shared command model rejected an executable, argument, path, or environment value.
    #[error("helper command failed portable validation: {source}")]
    Command {
        /// Original portable validation failure.
        #[from]
        source: CommandError,
    },
    /// Environment assignments contained more than one declaration for a name.
    #[error("helper command environment contains a duplicate name")]
    DuplicateEnvironment,
    /// The working directory was relative instead of fully resolved.
    #[error("helper command working directory is not absolute")]
    RelativeDirectory,
    /// An environment removal was supplied instead of a complete resolved environment.
    #[error("helper command contains an inherited environment removal")]
    EnvironmentRemoval,
    /// No explicit working directory accompanied the lowered command.
    #[error("helper command has no explicit working directory")]
    MissingDirectory,
}

struct LimitedBuffer {
    bytes: Vec<u8>,
    exceeded: bool,
}

impl Launch {
    pub(super) fn capture(
        command: &Command,
        timeout: Option<Duration>,
    ) -> Result<Self, ProtocolError> {
        let environment = command
            .get_envs()
            .map(|(name, value)| {
                value
                    .map(|value| (name.as_bytes().to_vec(), value.as_bytes().to_vec()))
                    .ok_or(ProtocolError::EnvironmentRemoval)
            })
            .collect::<Result<_, _>>()?;
        let directory = command
            .get_current_dir()
            .ok_or(ProtocolError::MissingDirectory)?;
        Ok(Self {
            executable: command.get_program().as_bytes().to_vec(),
            arguments: command
                .get_args()
                .map(|arg| arg.as_bytes().to_vec())
                .collect(),
            directory: directory.as_os_str().as_bytes().to_vec(),
            environment,
            timeout,
        })
    }

    pub(super) fn into_command(self) -> Result<(Command, Option<Duration>), ProtocolError> {
        let spec = CommandSpec::new(OsString::from_vec(self.executable))?
            .with_args(self.arguments.into_iter().map(OsString::from_vec))?;
        let directory = PathBuf::from(OsString::from_vec(self.directory));
        if !directory.is_absolute() {
            return Err(ProtocolError::RelativeDirectory);
        }
        // Reuse portable validation, including traversal and native NUL rules.
        let _validated =
            CommandRequest::new(spec.clone()).with_working_directory(directory.clone())?;
        let mut environment = BTreeMap::new();
        let mut checked = EnvironmentSpec::empty();
        for (name, value) in self.environment {
            let name = OsString::from_vec(name);
            let value = OsString::from_vec(value);
            checked = checked.with_var(name.clone(), value.clone())?;
            if environment.insert(name, value).is_some() {
                return Err(ProtocolError::DuplicateEnvironment);
            }
        }
        let mut command = Command::new(spec.program());
        command
            .args(spec.args())
            .current_dir(directory)
            .env_clear()
            .envs(environment);
        Ok((command, self.timeout))
    }
}

impl Write for LimitedBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_HELPER_FRAME_BYTES.saturating_sub(self.bytes.len()) {
            self.exceeded = true;
            return Err(io::ErrorKind::FileTooLarge.into());
        }
        self.bytes
            .try_reserve(bytes.len())
            .map_err(io::Error::other)?;
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) fn encode<T: Serialize>(message: T) -> Result<Vec<u8>, ProtocolError> {
    let mut buffer = LimitedBuffer {
        bytes: Vec::new(),
        exceeded: false,
    };
    let result = serde_json::to_writer(
        &mut buffer,
        &Frame {
            version: PROTOCOL_VERSION,
            message,
        },
    );
    if buffer.exceeded {
        return Err(ProtocolError::TooLarge {
            maximum: MAX_HELPER_FRAME_BYTES,
        });
    }
    result.map_err(|source| ProtocolError::Encode { source })?;
    Ok(buffer.bytes)
}

pub(super) fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ProtocolError> {
    if bytes.len() > MAX_HELPER_FRAME_BYTES {
        return Err(ProtocolError::TooLarge {
            maximum: MAX_HELPER_FRAME_BYTES,
        });
    }
    let frame: Frame<T> =
        serde_json::from_slice(bytes).map_err(|source| ProtocolError::Decode { source })?;
    if frame.version != PROTOCOL_VERSION {
        return Err(ProtocolError::Version {
            expected: PROTOCOL_VERSION,
            actual: frame.version,
        });
    }
    Ok(frame.message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_command_roundtrip_preserves_bytes_and_explicit_environment() {
        let mut command = Command::new("/bin/echo");
        command
            .arg(OsString::from_vec(vec![0xff, b'x']))
            .arg("")
            .current_dir("/private/tmp")
            .env_clear()
            .env("TOKEN", OsString::from_vec(vec![0xfe]));
        let launch = Launch::capture(&command, Some(Duration::new(1, 23))).expect("capture");
        let decoded: Request =
            decode(&encode(Request::Launch(launch)).expect("encode")).expect("decode");
        let Request::Launch(launch) = decoded else {
            panic!("launch message")
        };
        let (actual, timeout) = launch.into_command().expect("validate");
        assert_eq!(actual.get_program(), command.get_program());
        assert_eq!(
            actual.get_args().collect::<Vec<_>>(),
            command.get_args().collect::<Vec<_>>()
        );
        assert_eq!(
            actual.get_envs().collect::<Vec<_>>(),
            command.get_envs().collect::<Vec<_>>()
        );
        assert_eq!(timeout, Some(Duration::new(1, 23)));
    }

    #[test]
    fn protocol_rejects_unknown_versions_truncation_and_trailing_data() {
        assert!(matches!(
            decode::<Request>(br#"{"version":999,"message":"Hello"}"#),
            Err(ProtocolError::Version { .. })
        ));
        for bytes in [
            &b"{"[..],
            &br#"{"version":1,"message":"Unknown"}"#[..],
            &br#"{"version":1,"message":"Hello"} {}"#[..],
        ] {
            assert!(matches!(
                decode::<Request>(bytes),
                Err(ProtocolError::Decode { .. })
            ));
        }
    }
}
