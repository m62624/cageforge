// SPDX-License-Identifier: Apache-2.0

//! Thin command-line adapter for the public Cageforge facade.
//!
//! [`run`] loads an explicit TOML profile, accepts one explicit argv command,
//! and sends it through the matching OS-native Cageforge backend. The crate
//! owns CLI parsing and presentation only; policy, composition, and native
//! enforcement remain in the existing Cageforge crates.

#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

mod cli;
mod error;
mod execution;

use std::io::{self, Write};
use std::process::ExitCode;

use clap::Parser;

pub use cli::{Cli, Command, RunArgs};
pub use error::CliError;
pub use execution::execute;

/// Parses the process arguments, executes the selected command, and renders
/// a concise diagnostic on failure.
pub fn run() -> ExitCode {
    #[cfg(all(feature = "linux", target_os = "linux"))]
    {
        let mut arguments = std::env::args_os();
        arguments.next();
        if arguments
            .next()
            .is_some_and(|argument| argument == "--apply-hardening")
        {
            return cageforge::run_hardening_helper(std::env::args_os().skip(1));
        }
    }
    let cli = Cli::parse();
    let mut stderr = io::stderr().lock();
    match execute(cli) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            let _ = writeln!(stderr, "cageforge-cli: {error}");
            ExitCode::from(error.exit_code())
        }
    }
}
