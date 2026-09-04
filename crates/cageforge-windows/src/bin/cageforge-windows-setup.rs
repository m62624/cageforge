// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

#[cfg(target_os = "windows")]
use std::env;
#[cfg(target_os = "windows")]
use std::fs;
#[cfg(target_os = "windows")]
use std::path::PathBuf;
use std::process::ExitCode;

#[cfg(target_os = "windows")]
use setup_protocol::{
    MAX_SETUP_MESSAGE_BYTES, SETUP_PROTOCOL_VERSION, SetupFailureCode, SetupMessageReadError,
    SetupOutcome, SetupRequest, SetupResponse, SetupStage, read_bounded_message,
};

#[cfg(target_os = "windows")]
#[path = "../capability/lock.rs"]
mod capability_lock;
#[cfg(target_os = "windows")]
#[path = "../capability/state.rs"]
mod capability_state;
#[cfg(target_os = "windows")]
#[path = "../capability/state_setup.rs"]
mod capability_state_setup;
#[cfg(target_os = "windows")]
#[path = "../firewall_contract.rs"]
mod firewall_contract;
#[cfg(target_os = "windows")]
#[path = "../native_strings.rs"]
mod native_strings;
#[cfg(target_os = "windows")]
#[path = "../net_api_strings.rs"]
mod net_api_strings;
#[cfg(target_os = "windows")]
#[path = "../owner_identity.rs"]
mod owner_identity;
#[cfg(target_os = "windows")]
#[path = "../runner/manifest.rs"]
mod runner_manifest;
#[cfg(target_os = "windows")]
#[path = "../setup/pinned/setup.rs"]
mod setup_pinned;
#[cfg(target_os = "windows")]
#[path = "../setup/pinned/file.rs"]
mod setup_pinned_file;
#[cfg(target_os = "windows")]
#[path = "../setup/protocol.rs"]
mod setup_protocol;
#[cfg(target_os = "windows")]
#[path = "../setup/state.rs"]
mod setup_state;
#[cfg(target_os = "windows")]
#[path = "../setup/state_path.rs"]
mod setup_state_path;
#[cfg(target_os = "windows")]
mod windows_setup;

#[cfg(target_os = "windows")]
struct Arguments {
    request: PathBuf,
    response: PathBuf,
}

#[cfg(target_os = "windows")]
impl Arguments {
    fn parse() -> Result<Self, String> {
        let mut values = env::args_os().skip(1);
        let request_flag = values.next().ok_or("missing --request")?;
        let request = values.next().ok_or("missing request path")?;
        let response_flag = values.next().ok_or("missing --response")?;
        let response = values.next().ok_or("missing response path")?;
        if request_flag != "--request" || response_flag != "--response" || values.next().is_some() {
            return Err(
                "expected --request <absolute-path> --response <absolute-path>".to_string(),
            );
        }
        let request = PathBuf::from(request);
        let response = PathBuf::from(response);
        if !request.is_absolute() || !response.is_absolute() {
            return Err("setup protocol paths must be absolute".to_string());
        }
        Ok(Self { request, response })
    }
}

#[cfg(target_os = "windows")]
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{}: {error}", env!("CARGO_BIN_NAME"));
            ExitCode::from(125)
        }
    }
}

#[cfg(target_os = "windows")]
fn run() -> Result<(), String> {
    let arguments = Arguments::parse()?;
    let progress_path = arguments.response.with_extension("progress");
    let mut report_progress = |stage: SetupStage, detail: &str| {
        let _ = fs::write(&progress_path, format!("{stage:?}: {detail}"));
    };
    let response = match read_bounded_message(&arguments.request) {
        Ok(request_bytes) => match serde_json::from_slice::<SetupRequest>(&request_bytes) {
            Ok(request) if request.version != SETUP_PROTOCOL_VERSION => SetupResponse {
                version: SETUP_PROTOCOL_VERSION,
                outcome: SetupOutcome::Failed {
                    stage: SetupStage::Request,
                    code: SetupFailureCode::InvalidProtocolVersion,
                    native_code: None,
                    detail: format!(
                        "expected protocol version {SETUP_PROTOCOL_VERSION}, found {}",
                        request.version
                    ),
                },
            },
            Ok(request) => match windows_setup::execute(&request, &mut report_progress) {
                Ok(()) => SetupResponse {
                    version: SETUP_PROTOCOL_VERSION,
                    outcome: SetupOutcome::Complete,
                },
                Err(error) => SetupResponse {
                    version: SETUP_PROTOCOL_VERSION,
                    outcome: SetupOutcome::Failed {
                        stage: error.stage,
                        code: error.code,
                        native_code: error.native_code,
                        detail: error.detail,
                    },
                },
            },
            Err(error) => SetupResponse {
                version: SETUP_PROTOCOL_VERSION,
                outcome: SetupOutcome::Failed {
                    stage: SetupStage::Request,
                    code: SetupFailureCode::RequestDecode,
                    native_code: None,
                    detail: format!("failed to decode setup request: {error}"),
                },
            },
        },
        Err(SetupMessageReadError::TooLarge { actual, maximum }) => SetupResponse {
            version: SETUP_PROTOCOL_VERSION,
            outcome: SetupOutcome::Failed {
                stage: SetupStage::Request,
                code: SetupFailureCode::RequestTooLarge,
                native_code: None,
                detail: format!("setup request is too large: {actual} bytes exceeds {maximum}"),
            },
        },
        Err(SetupMessageReadError::Io { source }) => SetupResponse {
            version: SETUP_PROTOCOL_VERSION,
            outcome: SetupOutcome::Failed {
                stage: SetupStage::Request,
                code: SetupFailureCode::RequestRead,
                native_code: source.raw_os_error().map(|code| code as u32),
                detail: format!(
                    "failed to read setup request {:?}: {source}",
                    arguments.request
                ),
            },
        },
    };
    let success = matches!(response.outcome, SetupOutcome::Complete);
    let response_bytes = serde_json::to_vec(&response)
        .map_err(|error| format!("failed to encode setup response: {error}"))?;
    if response_bytes.len() > MAX_SETUP_MESSAGE_BYTES {
        return Err(format!(
            "encoded setup response is too large: {} bytes exceeds {}",
            response_bytes.len(),
            MAX_SETUP_MESSAGE_BYTES
        ));
    }
    fs::write(&arguments.response, response_bytes).map_err(|error| {
        format!(
            "failed to write setup response {:?}: {error}",
            arguments.response
        )
    })?;
    if success {
        Ok(())
    } else {
        Err("elevated setup failed; inspect the structured response".to_string())
    }
}

#[cfg(not(target_os = "windows"))]
fn main() -> ExitCode {
    eprintln!("{} is only available on Windows", env!("CARGO_BIN_NAME"));
    ExitCode::from(1)
}
