// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsString;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

const MODE: &str = "CAGEFORGE_WINDOWS_SANDBOX_FIXTURE_MODE";
const DENIED_READ: &str = "CAGEFORGE_WINDOWS_SANDBOX_FIXTURE_DENIED_READ";
const DENIED_WRITE: &str = "CAGEFORGE_WINDOWS_SANDBOX_FIXTURE_DENIED_WRITE";
const PROGRESS: &str = "CAGEFORGE_WINDOWS_SANDBOX_FIXTURE_PROGRESS";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("cageforge-windows-test-fixture: {error}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<(), String> {
    let mode = environment(MODE)?;
    if mode != "denied-read" {
        return Err(format!("unsupported fixture mode {mode:?}"));
    }
    let denied_read = PathBuf::from(environment(DENIED_READ)?);
    let denied_write = PathBuf::from(environment(DENIED_WRITE)?);
    let progress = PathBuf::from(environment(PROGRESS)?);
    std::fs::write(&progress, b"before-denied-read")
        .map_err(|error| format!("record denied-read start: {error}"))?;
    match std::fs::read(&denied_read) {
        Ok(_) => Err(format!("read denied host file {denied_read:?}")),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&denied_write)
            {
                Ok(_) => return Err(format!("wrote read-only sandbox path {denied_write:?}")),
                Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {}
                Err(error) => {
                    return Err(format!(
                        "write read-only sandbox path {denied_write:?}: {error}"
                    ));
                }
            }
            std::fs::write(&progress, b"after-denied-read")
                .map_err(|error| format!("record denied-read completion: {error}"))?;
            std::io::stdout()
                .write_all(b"denied")
                .map_err(|error| format!("write denied-read result: {error}"))
        }
        Err(error) => Err(format!("read denied host file: {error}")),
    }
}

fn environment(name: &str) -> Result<OsString, String> {
    std::env::var_os(name).ok_or_else(|| format!("missing required environment variable {name}"))
}
