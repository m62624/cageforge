//! Read-only upstream commit and scope review for Cageforge.
//!
//! The tool compares the last adapted Codex commit with another commit or the
//! locally fetched upstream ref. It never fetches, writes files, or updates
//! the tracked commit. Porting remains a deliberate manual change.

use std::env;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use clap::{Parser, Subcommand};
use serde::Deserialize;

const DEFAULT_CONFIG: &str = "upstream-review.toml";

#[derive(Debug, Parser)]
#[command(
    name = "cageforge-review",
    version,
    about = "Review selected upstream changes for Cageforge"
)]
struct Cli {
    /// Path to the repository tracking configuration.
    #[arg(long, default_value = DEFAULT_CONFIG)]
    config: PathBuf,

    #[command(subcommand)]
    command: CommandKind,
}

#[derive(Debug, Subcommand)]
enum CommandKind {
    /// Print the configured commit, scopes, and locally available upstream ref.
    Status,
    /// Validate the configuration without contacting the network.
    Check,
    /// Print a scoped Git diff from the last adapted commit to a target ref.
    Diff {
        /// Commit or ref to compare against. Defaults to the fetched upstream ref.
        #[arg(long)]
        to: Option<String>,

        /// Limit the diff to one configured scope. May be repeated.
        #[arg(long = "scope", value_name = "NAME")]
        scopes: Vec<String>,
    },
}

#[derive(Debug, Deserialize)]
struct Config {
    upstream: Upstream,
    #[serde(default)]
    scope: Vec<Scope>,
}

#[derive(Debug, Deserialize)]
struct Upstream {
    repository: String,
    path: PathBuf,
    branch: String,
    #[serde(default)]
    last_adapted_commit: String,
}

#[derive(Debug, Deserialize)]
struct Scope {
    name: String,
    upstream_paths: Vec<String>,
    #[serde(default)]
    local_paths: Vec<String>,
}

#[derive(Debug)]
struct Repository {
    cageforge_root: PathBuf,
    upstream_root: PathBuf,
    config_path: PathBuf,
    config: Config,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), String> {
    let repository = Repository::load(&cli.config)?;
    validate_config(&repository.config)?;

    match cli.command {
        CommandKind::Status => status(&repository),
        CommandKind::Check => check(&repository),
        CommandKind::Diff { to, scopes } => diff(&repository, to, scopes),
    }
}

impl Repository {
    fn load(config_path: &Path) -> Result<Self, String> {
        let config_path = if config_path.is_absolute() {
            config_path.to_path_buf()
        } else {
            env::current_dir()
                .map_err(|error| format!("cannot determine current directory: {error}"))?
                .join(config_path)
        };
        let config_path = config_path
            .canonicalize()
            .map_err(|error| format!("cannot read {}: {error}", config_path.display()))?;
        let contents = std::fs::read_to_string(&config_path)
            .map_err(|error| format!("cannot read {}: {error}", config_path.display()))?;
        let config: Config = toml::from_str(&contents)
            .map_err(|error| format!("invalid {}: {error}", config_path.display()))?;
        let config_dir = config_path
            .parent()
            .ok_or_else(|| "configuration path has no parent".to_owned())?;
        let cageforge_root = git_output(config_dir, ["rev-parse", "--show-toplevel"])?;
        let upstream_root = config_dir
            .join(&config.upstream.path)
            .canonicalize()
            .map_err(|error| {
                format!(
                    "cannot resolve upstream checkout {}: {error}",
                    config.upstream.path.display()
                )
            })?;
        let upstream_root = PathBuf::from(git_output(
            &upstream_root,
            ["rev-parse", "--show-toplevel"],
        )?);

        Ok(Self {
            cageforge_root: PathBuf::from(cageforge_root),
            upstream_root,
            config_path,
            config,
        })
    }

    fn upstream_ref(&self) -> String {
        self.config.upstream.branch.clone()
    }
}

fn validate_config(config: &Config) -> Result<(), String> {
    if config.upstream.repository.is_empty() {
        return Err("upstream.repository must not be empty".to_owned());
    }
    if config.upstream.path.as_os_str().is_empty() {
        return Err("upstream.path must not be empty".to_owned());
    }
    if config.upstream.branch.is_empty() {
        return Err("upstream.branch must not be empty".to_owned());
    }
    if config.scope.is_empty() {
        return Err("at least one [[scope]] is required".to_owned());
    }

    for (index, scope) in config.scope.iter().enumerate() {
        if scope.name.is_empty() {
            return Err(format!("scope {index} has an empty name"));
        }
        if config
            .scope
            .iter()
            .take(index)
            .any(|other| other.name == scope.name)
        {
            return Err(format!("duplicate scope name: {}", scope.name));
        }
        if scope.upstream_paths.is_empty() {
            return Err(format!("scope {} has no upstream_paths", scope.name));
        }
        for path in &scope.upstream_paths {
            validate_repo_relative_path(path, "upstream path")?;
        }
        for path in &scope.local_paths {
            validate_repo_relative_path(path, "local path")?;
        }
    }

    Ok(())
}

fn validate_repo_relative_path(path: &str, label: &str) -> Result<(), String> {
    let path = Path::new(path);
    if path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(format!("{label} must be repository-relative: {path:?}"));
    }
    Ok(())
}

fn check(repository: &Repository) -> Result<(), String> {
    println!("configuration: {}", repository.config_path.display());
    println!(
        "upstream repository: {}",
        repository.config.upstream.repository
    );
    println!("upstream checkout: {}", repository.upstream_root.display());
    println!("configured scopes: {}", repository.config.scope.len());

    if repository.config.upstream.last_adapted_commit.is_empty() {
        println!("last adapted commit: not selected yet (pre-port state)");
    } else {
        validate_commit(
            &repository.config.upstream.last_adapted_commit,
            "last_adapted_commit",
        )?;
        println!(
            "last adapted commit: {}",
            repository.config.upstream.last_adapted_commit
        );
    }

    println!("configuration: ok");
    Ok(())
}

fn status(repository: &Repository) -> Result<(), String> {
    check(repository)?;
    println!(
        "Cageforge repository root: {}",
        repository.cageforge_root.display()
    );
    println!("upstream branch: {}", repository.upstream_ref());

    let upstream_ref = repository.upstream_ref();
    match git_output(
        &repository.upstream_root,
        ["rev-parse", "--verify", upstream_ref.as_str()],
    ) {
        Ok(commit) => println!("fetched upstream commit: {commit}"),
        Err(_) => println!("upstream branch: unavailable (update the Codex checkout manually)"),
    }

    for scope in &repository.config.scope {
        println!("scope {}:", scope.name);
        for path in &scope.upstream_paths {
            println!("  upstream: {path}");
        }
        for path in &scope.local_paths {
            println!("  local:    {path}");
        }
    }

    Ok(())
}

fn diff(
    repository: &Repository,
    target: Option<String>,
    selected_scopes: Vec<String>,
) -> Result<(), String> {
    let baseline = &repository.config.upstream.last_adapted_commit;
    if baseline.is_empty() {
        return Err(
            "cannot create a diff: upstream.last_adapted_commit is empty; select the first audited commit"
                .to_owned(),
        );
    }
    validate_commit(baseline, "last_adapted_commit")?;

    let scopes = if selected_scopes.is_empty() {
        repository.config.scope.iter().collect::<Vec<_>>()
    } else {
        for selected in &selected_scopes {
            if !repository
                .config
                .scope
                .iter()
                .any(|scope| scope.name == *selected)
            {
                return Err(format!("unknown scope: {selected}"));
            }
        }
        repository
            .config
            .scope
            .iter()
            .filter(|scope| selected_scopes.iter().any(|name| name == &scope.name))
            .collect::<Vec<_>>()
    };
    let target = target.unwrap_or_else(|| repository.upstream_ref());
    let pathspecs = scopes
        .iter()
        .flat_map(|scope| scope.upstream_paths.iter().map(String::as_str))
        .collect::<Vec<_>>();

    println!("diff: {baseline}..{target}");
    println!(
        "scopes: {}",
        scopes
            .iter()
            .map(|scope| scope.name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!();
    run_git_diff(
        &repository.upstream_root,
        baseline,
        &target,
        &pathspecs,
        &["--stat"],
    )?;
    println!();
    run_git_diff(
        &repository.upstream_root,
        baseline,
        &target,
        &pathspecs,
        &["--name-status", "--find-renames"],
    )?;
    println!();
    run_git_diff(
        &repository.upstream_root,
        baseline,
        &target,
        &pathspecs,
        &[],
    )?;

    Ok(())
}

fn validate_commit(commit: &str, label: &str) -> Result<(), String> {
    if commit.len() != 40 || !commit.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("{label} must be a full 40-character commit SHA"));
    }
    Ok(())
}

fn run_git_diff(
    root: &Path,
    baseline: &str,
    target: &str,
    pathspecs: &[&str],
    options: &[&str],
) -> Result<(), String> {
    let mut arguments = vec!["diff".to_owned(), baseline.to_owned(), target.to_owned()];
    arguments.extend(options.iter().map(ToString::to_string));
    arguments.push("--".to_owned());
    arguments.extend(pathspecs.iter().map(ToString::to_string));

    let output = Command::new("git")
        .current_dir(root)
        .args(&arguments)
        .output()
        .map_err(|error| format!("failed to run git diff: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "git diff failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    print!("{}", String::from_utf8_lossy(&output.stdout));
    Ok(())
}

fn git_output<I, S>(directory: &Path, arguments: I) -> Result<String, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = Command::new("git")
        .current_dir(directory)
        .args(arguments)
        .output()
        .map_err(|error| format!("failed to run git: {error}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_owned());
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}
