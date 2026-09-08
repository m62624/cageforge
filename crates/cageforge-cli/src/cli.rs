// SPDX-License-Identifier: Apache-2.0

//! Clap representation of the small public CLI surface.

use std::ffi::OsString;
use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// Cageforge command-line sandbox launcher.
#[derive(Debug, Parser)]
#[command(
    name = "cageforge-cli",
    version,
    about = "Run an explicit command inside a Cageforge OS sandbox",
    long_about = LONG_ABOUT,
    after_help = AFTER_HELP,
    subcommand_required = true,
    arg_required_else_help = true
)]
pub struct Cli {
    #[command(subcommand)]
    /// The operation to perform.
    pub command: Command,
}

/// Supported CLI operations.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Resolve a TOML profile and run one explicit program.
    Run(RunArgs),
    /// Print the JSON schema for Cageforge TOML profiles.
    Schema,
}

/// Arguments for one sandbox instance.
#[derive(Debug, clap::Args)]
pub struct RunArgs {
    /// TOML configuration file containing the requested profile. The profile
    /// must list the filesystem and network access the command needs.
    #[arg(long, env = "CAGEFORGE_CONFIG", value_name = "PATH")]
    pub config: PathBuf,

    /// Named profile; when omitted, the configuration's default profile is used.
    #[arg(long, value_name = "NAME")]
    pub profile: Option<String>,

    /// Program and native argv values after `--`. Shell syntax is not
    /// interpreted; use an explicit shell executable when one is intended.
    #[arg(
        trailing_var_arg = true,
        value_name = "PROGRAM [ARGS...]",
        help = "Program and argv after `--`; no shell parsing is performed"
    )]
    pub command: Vec<OsString>,
}

const LONG_ABOUT: &str = "Run one explicitly selected program inside the native Cageforge sandbox.\n\nThe TOML profile supplies the access policy: system paths to read, application paths to write, environment rules, network destinations, and timeout. The command after `--` is passed as argv. One invocation creates one boundary around the program and all of its descendants.\n\nBuild this binary with one matching OS feature: `linux`, `windows`, or `macos`. On Linux, `linux-bundled-bubblewrap` also embeds the verified Bubblewrap resource. There is no unsandboxed fallback.";

const AFTER_HELP: &str = "EXAMPLES:\n  cageforge-cli run --config sandbox.toml --profile isolated -- untrusted-program --safe-mode\n  cageforge-cli run --config sandbox.toml --profile build -- cargo test --workspace\n  cageforge-cli schema\n\nThe CLI is a thin adapter. For native host requirements and the library API, see:\n  https://github.com/m62624/cageforge/tree/main/crates/cageforge-linux\n  https://github.com/m62624/cageforge/tree/main/crates/cageforge-windows\n  https://github.com/m62624/cageforge/tree/main/crates/cageforge-macos";
