// SPDX-License-Identifier: Apache-2.0

//! Bounded versioned transport shared by the backend and command runner.

use std::io::{self, Read, Write};

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub(crate) const RUNNER_PROTOCOL_VERSION: u32 = 2;
pub(crate) const MAX_RUNNER_FRAME_BYTES: usize = 8 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
pub(crate) struct RunnerFrame {
    pub(crate) version: u32,
    pub(crate) message: RunnerMessage,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum RunnerMessage {
    Spawn { request: RunnerSpawnRequest },
    Spawned { process_id: u32 },
    Exited { exit_code: u32 },
    Failed { failure: WindowsRunnerFailure },
}

#[derive(Serialize, Deserialize)]
pub(crate) struct RunnerSpawnRequest {
    pub(crate) command: Vec<Vec<u16>>,
    pub(crate) working_directory: Vec<u16>,
    pub(crate) environment_block: Vec<u16>,
    pub(crate) capability_sids: Vec<String>,
    pub(crate) route_sid: Option<String>,
    pub(crate) account: RunnerAccount,
    pub(crate) standard_handles: RunnerStandardHandles,
    pub(crate) job_handle: u64,
    pub(crate) desktop_name: Vec<u16>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct RunnerStandardHandles {
    pub(crate) stdin: u64,
    pub(crate) stdout: u64,
    pub(crate) stderr: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RunnerAccount {
    Offline,
    Online,
}

/// Fixed pre-transport command-runner bootstrap phase.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RunnerBootstrapStage {
    Arguments = 125,
    InstalledIdentity = 126,
    RequestPipe = 127,
    ResponsePipe = 128,
    TransportAuthentication = 129,
}

/// Native command-runner stage that rejected or failed an operation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WindowsRunnerFailureStage {
    /// Protected runner and parent identity authentication.
    Authentication,
    /// Versioned request framing and validation.
    Request,
    /// Restricted primary-token construction.
    Token,
    /// Parent-owned Job Object handle validation or process assignment.
    Job,
    /// User-command process construction.
    Process,
    /// User-command process wait or status collection.
    Wait,
    /// Complete Job Object termination.
    Termination,
}

/// Exact command-runner operation that failed.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WindowsRunnerFailureCode {
    /// The installed runner manifest could not be located beside the executable.
    ManifestPath,
    /// The installed runner manifest or executable could not be opened or read.
    InstalledResourceRead,
    /// The installed runner manifest was malformed or version-incompatible.
    ManifestDecode,
    /// The installed runner or manifest has an unexpected Windows object owner or DACL.
    InstalledResourceSecurity,
    /// The running command-runner executable differs from its manifest digest.
    RunnerDigestMismatch,
    /// A request or response named pipe could not be opened.
    PipeOpen,
    /// The two named-pipe server process identifiers differ.
    PipeServerMismatch,
    /// The named-pipe server process could not be opened.
    ServerProcessOpen,
    /// The named-pipe server token could not be opened.
    ServerTokenOpen,
    /// The named-pipe server token owner differs from the setup owner.
    ServerOwnerMismatch,
    /// The runner token user is neither provisioned sandbox account.
    RunnerAccountMismatch,
    /// A framed request could not be read, decoded, or validated.
    RequestFrame,
    /// The request selected a different provisioned account than the runner token.
    RequestedAccountMismatch,
    /// One command, path, environment, SID, HANDLE, or timeout field is malformed.
    RequestField,
    /// The runner process token could not be opened with the required rights.
    BaseTokenOpen,
    /// A capability or route SID could not be parsed.
    RestrictingSidParse,
    /// `CreateRestrictedToken` rejected the requested restriction set.
    RestrictedTokenCreate,
    /// The restricted token default DACL could not be installed.
    TokenDefaultDacl,
    /// `SeChangeNotifyPrivilege` could not be re-enabled exclusively.
    TokenPrivilege,
    /// The parent-supplied Job Object handle is invalid or over-privileged.
    JobHandleInvalid,
    /// The process attribute list could not be initialized.
    AttributeListCreate,
    /// The explicit standard-handle list could not be installed.
    HandleListApply,
    /// Atomic Job Object assignment could not be installed.
    JobListApply,
    /// A parent-duplicated standard handle was invalid or not inheritable.
    StandardStreamPrepare,
    /// `CreateProcessAsUserW` rejected the prepared process.
    ProcessStart,
    /// Waiting for the user process failed.
    ProcessWait,
    /// Reading the user-process exit code failed.
    ExitCodeRead,
    /// Complete Job Object termination failed.
    JobTerminate,
    /// A structured runner response could not be written.
    ResponseFrame,
}

/// Structured failure returned by the authenticated Windows command runner.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WindowsRunnerFailure {
    pub(crate) stage: WindowsRunnerFailureStage,
    pub(crate) code: WindowsRunnerFailureCode,
    pub(crate) native_code: Option<u32>,
    pub(crate) detail: String,
}

/// Failure while encoding or decoding the bounded command-runner protocol.
#[derive(Debug, Error)]
pub enum WindowsRunnerProtocolError {
    /// The encoded frame exceeds the protocol memory bound.
    #[error("Windows runner frame is too large: {actual} bytes exceeds {maximum}")]
    FrameTooLarge {
        /// Encoded payload size.
        actual: usize,
        /// Maximum accepted payload size.
        maximum: usize,
    },
    /// A frame could not be serialized.
    #[error("failed to encode Windows runner frame: {source}")]
    Encode {
        /// JSON failure.
        #[source]
        source: serde_json::Error,
    },
    /// A frame length could not be read completely.
    #[error("failed to read Windows runner frame length: {source}")]
    LengthRead {
        /// Transport failure.
        #[source]
        source: io::Error,
    },
    /// A frame payload could not be read completely.
    #[error("failed to read Windows runner frame payload: {source}")]
    PayloadRead {
        /// Transport failure.
        #[source]
        source: io::Error,
    },
    /// A complete frame payload was not valid JSON.
    #[error("failed to decode Windows runner frame: {source}")]
    Decode {
        /// JSON failure.
        #[source]
        source: serde_json::Error,
    },
    /// A frame could not be written completely.
    #[error("failed to write Windows runner frame: {source}")]
    Write {
        /// Transport failure.
        #[source]
        source: io::Error,
    },
    /// The peer uses another protocol version.
    #[error("Windows runner protocol version mismatch: expected {expected}, found {actual}")]
    VersionMismatch {
        /// Supported protocol version.
        expected: u32,
        /// Received protocol version.
        actual: u32,
    },
    /// The peer sent a message invalid for the current protocol phase.
    #[error("unexpected Windows runner message during {phase}: {actual}")]
    UnexpectedMessage {
        /// Stable handshake or lifecycle phase.
        phase: &'static str,
        /// Received message kind.
        actual: &'static str,
    },
}

impl RunnerMessage {
    pub(crate) const fn kind(&self) -> &'static str {
        match self {
            Self::Spawn { .. } => "spawn",
            Self::Spawned { .. } => "spawned",
            Self::Exited { .. } => "exited",
            Self::Failed { .. } => "failed",
        }
    }
}

impl WindowsRunnerFailure {
    /// Returns the native runner stage that failed.
    pub const fn stage(&self) -> WindowsRunnerFailureStage {
        self.stage
    }

    /// Returns the exact native runner operation that failed.
    pub const fn code(&self) -> WindowsRunnerFailureCode {
        self.code
    }

    /// Returns the Win32 error code when the failed API supplied one.
    pub const fn native_code(&self) -> Option<u32> {
        self.native_code
    }

    /// Returns the bounded diagnostic supplied by the runner.
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

pub(crate) fn write_frame(
    writer: &mut impl Write,
    message: RunnerMessage,
) -> Result<(), WindowsRunnerProtocolError> {
    let frame = RunnerFrame {
        version: RUNNER_PROTOCOL_VERSION,
        message,
    };
    let encoded = serde_json::to_vec(&frame)
        .map_err(|source| WindowsRunnerProtocolError::Encode { source })?;
    if encoded.len() > MAX_RUNNER_FRAME_BYTES {
        return Err(WindowsRunnerProtocolError::FrameTooLarge {
            actual: encoded.len(),
            maximum: MAX_RUNNER_FRAME_BYTES,
        });
    }
    let length =
        u32::try_from(encoded.len()).map_err(|_| WindowsRunnerProtocolError::FrameTooLarge {
            actual: encoded.len(),
            maximum: MAX_RUNNER_FRAME_BYTES,
        })?;
    writer
        .write_all(&length.to_le_bytes())
        .and_then(|()| writer.write_all(&encoded))
        .and_then(|()| writer.flush())
        .map_err(|source| WindowsRunnerProtocolError::Write { source })
}

pub(crate) fn read_frame(
    reader: &mut impl Read,
) -> Result<RunnerMessage, WindowsRunnerProtocolError> {
    let mut length = [0u8; 4];
    reader
        .read_exact(&mut length)
        .map_err(|source| WindowsRunnerProtocolError::LengthRead { source })?;
    let length = u32::from_le_bytes(length) as usize;
    if length > MAX_RUNNER_FRAME_BYTES {
        return Err(WindowsRunnerProtocolError::FrameTooLarge {
            actual: length,
            maximum: MAX_RUNNER_FRAME_BYTES,
        });
    }
    let mut encoded = vec![0u8; length];
    reader
        .read_exact(&mut encoded)
        .map_err(|source| WindowsRunnerProtocolError::PayloadRead { source })?;
    let frame: RunnerFrame = serde_json::from_slice(&encoded)
        .map_err(|source| WindowsRunnerProtocolError::Decode { source })?;
    if frame.version != RUNNER_PROTOCOL_VERSION {
        return Err(WindowsRunnerProtocolError::VersionMismatch {
            expected: RUNNER_PROTOCOL_VERSION,
            actual: frame.version,
        });
    }
    Ok(frame.message)
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_RUNNER_FRAME_BYTES, RUNNER_PROTOCOL_VERSION, RunnerAccount, RunnerBootstrapStage,
        RunnerFrame, RunnerMessage, RunnerSpawnRequest, RunnerStandardHandles,
        WindowsRunnerProtocolError, read_frame, write_frame,
    };

    #[test]
    fn bootstrap_exit_codes_are_exclusive_and_round_trip() {
        let stages = [
            RunnerBootstrapStage::Arguments,
            RunnerBootstrapStage::InstalledIdentity,
            RunnerBootstrapStage::RequestPipe,
            RunnerBootstrapStage::ResponsePipe,
            RunnerBootstrapStage::TransportAuthentication,
        ];

        for stage in stages {
            assert_eq!(
                u32::from(stage as u8),
                match stage {
                    RunnerBootstrapStage::Arguments => 125,
                    RunnerBootstrapStage::InstalledIdentity => 126,
                    RunnerBootstrapStage::RequestPipe => 127,
                    RunnerBootstrapStage::ResponsePipe => 128,
                    RunnerBootstrapStage::TransportAuthentication => 129,
                }
            );
        }
    }

    #[test]
    fn spawn_request_round_trip_preserves_utf16_and_job_handle() {
        let request = RunnerSpawnRequest {
            command: vec![vec![0xd800], "argument".encode_utf16().collect()],
            working_directory: r"C:\workspace".encode_utf16().collect(),
            environment_block: "Path=value\0\0".encode_utf16().collect(),
            capability_sids: vec!["S-1-5-21-1-2-3-4".to_string()],
            route_sid: Some("S-1-5-21-5-6-7-8".to_string()),
            account: RunnerAccount::Offline,
            standard_handles: RunnerStandardHandles {
                stdin: 0x1111,
                stdout: 0x2222,
                stderr: 0x3333,
            },
            job_handle: 0x1234_5678,
            desktop_name: "Cageforge-test".encode_utf16().collect(),
        };
        let mut encoded = Vec::new();
        write_frame(&mut encoded, RunnerMessage::Spawn { request }).expect("write spawn frame");
        let message = read_frame(&mut encoded.as_slice()).expect("read spawn frame");
        let RunnerMessage::Spawn { request } = message else {
            panic!("expected spawn request");
        };

        assert_eq!(request.command[0], vec![0xd800]);
        assert_eq!(request.job_handle, 0x1234_5678);
        assert_eq!(request.standard_handles.stdin, 0x1111);
        assert_eq!(request.standard_handles.stdout, 0x2222);
        assert_eq!(request.standard_handles.stderr, 0x3333);
        assert_eq!(request.route_sid.as_deref(), Some("S-1-5-21-5-6-7-8"));
    }

    #[test]
    fn oversized_declared_frame_is_rejected_before_allocation() {
        let length = ((MAX_RUNNER_FRAME_BYTES as u32) + 1).to_le_bytes();
        let result = read_frame(&mut length.as_slice());

        assert!(matches!(
            result,
            Err(WindowsRunnerProtocolError::FrameTooLarge { .. })
        ));
    }

    #[test]
    fn protocol_version_mismatch_is_typed() {
        let frame = RunnerFrame {
            version: RUNNER_PROTOCOL_VERSION + 1,
            message: RunnerMessage::Exited { exit_code: 0 },
        };
        let payload = serde_json::to_vec(&frame).expect("encode mismatched frame");
        let mut encoded = (payload.len() as u32).to_le_bytes().to_vec();
        encoded.extend_from_slice(&payload);
        let result = read_frame(&mut encoded.as_slice());

        assert!(matches!(
            result,
            Err(WindowsRunnerProtocolError::VersionMismatch { .. })
        ));
    }
}
