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
    /// Inspect and revoke host-owned persistent permission grants.
    #[command(subcommand)]
    Permissions(PermissionsCommand),
    /// Provision, inspect, or remove the Windows-native Cageforge setup.
    #[cfg(target_os = "windows")]
    #[command(subcommand)]
    Setup(SetupCommand),
}

/// Persistent permission-store management operations.
#[derive(Debug, Subcommand)]
pub enum PermissionsCommand {
    /// List one page of safe grant summaries.
    List(PermissionsListArgs),
    /// Revoke one grant for future launches.
    Revoke(PermissionsRevokeArgs),
    /// Revoke every grant while retaining the store file.
    RevokeAll(PermissionsRevokeAllArgs),
}

/// Arguments for one persistent-grant page.
#[derive(Debug, clap::Args)]
pub struct PermissionsListArgs {
    /// Host-owned grant store; omitted uses the native per-user default.
    #[arg(long, value_name = "PATH")]
    pub permission_store: Option<PathBuf>,
    /// Number of summaries to return, from 1 through 1000.
    #[arg(long, default_value_t = 50, value_name = "COUNT")]
    pub page_size: usize,
    /// Opaque cursor printed by the preceding page.
    #[arg(long, value_name = "TOKEN")]
    pub cursor: Option<String>,
}

/// Arguments for one persistent-grant revoke operation.
#[derive(Debug, clap::Args)]
pub struct PermissionsRevokeArgs {
    /// Host-owned grant store; omitted uses the native per-user default.
    #[arg(long, value_name = "PATH")]
    pub permission_store: Option<PathBuf>,
    /// Stable 64-character hexadecimal grant ID.
    #[arg(long, value_name = "GRANT_ID")]
    pub id: String,
}

/// Arguments for the explicit all-grants revoke operation.
#[derive(Debug, clap::Args)]
pub struct PermissionsRevokeAllArgs {
    /// Host-owned grant store; omitted uses the native per-user default.
    #[arg(long, value_name = "PATH")]
    pub permission_store: Option<PathBuf>,
    /// Required confirmation for removing every saved approval.
    #[arg(long)]
    pub yes: bool,
}

/// Windows-native setup operations.
#[cfg(target_os = "windows")]
#[derive(Debug, Eq, PartialEq, Subcommand)]
pub enum SetupCommand {
    /// Create or reconcile the persistent elevated Windows setup.
    Install,
    /// Report whether the persistent Windows setup is ready.
    Status,
    /// Remove Cageforge-owned Windows setup objects after all children stop.
    Uninstall,
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

    /// Explicitly approve the displayed preflight request without reading
    /// interactive input. This is intended for a caller that is itself the
    /// trusted approval host.
    #[arg(long)]
    pub approve: bool,

    /// Host-owned grant store. When omitted, uses the current user's native
    /// Cageforge state directory for the target operating system.
    #[arg(long, value_name = "PATH")]
    pub permission_store: Option<PathBuf>,

    /// Program and native argv values after `--`. Shell syntax is not
    /// interpreted; use an explicit shell executable when one is intended.
    #[arg(
        trailing_var_arg = true,
        value_name = "PROGRAM [ARGS...]",
        help = "Program and argv after `--`; no shell parsing is performed"
    )]
    pub command: Vec<OsString>,
}

const LONG_ABOUT: &str = "Run one explicitly selected program inside the native Cageforge sandbox.\n\nThe TOML profile supplies the access policy: system paths to read, application paths to write, environment rules, network destinations, and timeout. The command after `--` is passed as argv. One invocation creates one boundary around the program and all of its descendants.\n\nThe native backend is selected automatically from the target OS. On Linux, `linux-bundled-bubblewrap` also embeds the verified Bubblewrap resource. There is no unsandboxed fallback.\n\nPreflight approval is disabled unless the selected TOML profile sets `approval.mode = \"preflight\"`. In preflight mode the CLI shows the exact command capabilities before launch. `--approve` is for a trusted host and never bypasses the policy ceiling; non-interactive runs without an approval fail closed. Persistent approvals are stored only when the profile selects persistent persistence.\n\nThe `permissions` subcommands list one bounded page or revoke host-owned persistent approvals without changing a running sandbox.";

#[cfg(target_os = "windows")]
const AFTER_HELP: &str = "EXAMPLES:\n  cageforge-cli run --config sandbox.toml --profile isolated -- untrusted-program --safe-mode\n  cageforge-cli run --config sandbox.toml --profile build -- cargo test --workspace\n  cageforge-cli run --config permission-preflight.toml --approve --permission-store /path/to/permissions.json -- tool\n  cageforge-cli permissions list --page-size 50\n  cageforge-cli permissions revoke --id <grant-id>\n  cageforge-cli permissions revoke-all --yes\n  cageforge-cli setup status\n  cageforge-cli schema\n\n`--permission-store PATH` explicitly selects the host-owned persistent grant store and takes priority. Without it, the CLI uses the current user's native Cageforge state directory. The file is created only after a persistent approval; deleting it revokes saved approvals. Listing cursors are valid only while the store document remains unchanged.\n\nOn Windows, run `cageforge-cli setup install` once before the first `run`. It may request UAC and keeps the setup for later launches.\n\nThe CLI is a thin adapter. For native host requirements and the library API, see:\n  https://github.com/m62624/cageforge/tree/main/crates/cageforge-linux\n  https://github.com/m62624/cageforge/tree/main/crates/cageforge-windows\n  https://github.com/m62624/cageforge/tree/main/crates/cageforge-macos";

#[cfg(not(target_os = "windows"))]
const AFTER_HELP: &str = "EXAMPLES:\n  cageforge-cli run --config sandbox.toml --profile isolated -- untrusted-program --safe-mode\n  cageforge-cli run --config sandbox.toml --profile build -- cargo test --workspace\n  cageforge-cli run --config permission-preflight.toml --approve --permission-store /path/to/permissions.json -- tool\n  cageforge-cli permissions list --page-size 50\n  cageforge-cli permissions revoke --id <grant-id>\n  cageforge-cli permissions revoke-all --yes\n  cageforge-cli schema\n\n`--permission-store PATH` explicitly selects the host-owned persistent grant store and takes priority. Without it, the CLI uses the current user's native Cageforge state directory. The file is created only after a persistent approval; deleting it revokes saved approvals. Listing cursors are valid only while the store document remains unchanged.\n\nThe CLI is a thin adapter. For native host requirements and the library API, see:\n  https://github.com/m62624/cageforge/tree/main/crates/cageforge-linux\n  https://github.com/m62624/cageforge/tree/main/crates/cageforge-windows\n  https://github.com/m62624/cageforge/tree/main/crates/cageforge-macos";
