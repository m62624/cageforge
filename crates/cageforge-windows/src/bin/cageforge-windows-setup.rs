// SPDX-License-Identifier: Apache-2.0

#![cfg(target_os = "windows")]
#![cfg_attr(not(test), deny(clippy::expect_used, clippy::unwrap_used))]

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

#[path = "../capability_state.rs"]
mod capability_state;
#[path = "../capability_state_setup.rs"]
mod capability_state_setup;
#[path = "../firewall_contract.rs"]
mod firewall_contract;
#[path = "../runner_manifest.rs"]
mod runner_manifest;
#[path = "../setup_protocol.rs"]
mod setup_protocol;
#[path = "../setup_state.rs"]
mod setup_state;
mod windows_setup;

use setup_protocol::{
    SETUP_PROTOCOL_VERSION, SetupFailureCode, SetupOutcome, SetupRequest, SetupResponse, SetupStage,
};

struct Arguments {
    request: PathBuf,
    response: PathBuf,
}

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

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("cageforge-windows-setup: {error}");
            ExitCode::from(125)
        }
    }
}

fn run() -> Result<(), String> {
    let arguments = Arguments::parse()?;
    let progress_path = arguments.response.with_extension("progress");
    let mut report_progress = |stage: SetupStage, detail: &str| {
        let _ = fs::write(&progress_path, format!("{stage:?}: {detail}"));
    };
    let request_bytes = fs::read(&arguments.request).map_err(|error| {
        format!(
            "failed to read setup request {:?}: {error}",
            arguments.request
        )
    })?;
    let request: SetupRequest = serde_json::from_slice(&request_bytes)
        .map_err(|error| format!("failed to decode setup request: {error}"))?;
    let response = if request.version != SETUP_PROTOCOL_VERSION {
        SetupResponse {
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
        }
    } else {
        match windows_setup::execute(&request, &mut report_progress) {
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
        }
    };
    let success = matches!(response.outcome, SetupOutcome::Complete);
    let response_bytes = serde_json::to_vec(&response)
        .map_err(|error| format!("failed to encode setup response: {error}"))?;
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
