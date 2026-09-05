// SPDX-License-Identifier: Apache-2.0

//! Bubblewrap discovery, probing, and common namespace arguments.

use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::config::{
    BubblewrapSource, HardeningHelperSource, ProcMountPolicy, ResourceDirectorySource,
};
use crate::error::{
    BubblewrapFlag, ExecutableSnapshotOperation, LinuxBackendError, LinuxExecutable, LinuxNamespace,
};
use crate::resource_names::HARDENING_HELPER_NAME;
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const PROBE_OUTPUT_LIMIT_BYTES: usize = 256 * 1024;
const PROBE_POLL_INTERVAL: Duration = Duration::from_millis(5);
const MFD_EXEC: libc::c_uint = 0x0010;

#[cfg(feature = "bundled-bubblewrap")]
const BUNDLED_RESOURCE_PREFIX: &str = "cageforge-bwrap-";

#[derive(Debug)]
pub(crate) struct BubblewrapSelection {
    pub(crate) path: PathBuf,
    pub(crate) bundled: bool,
    pub(crate) identity: FileIdentity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FileIdentity {
    device: u64,
    inode: u64,
}

#[derive(Debug)]
pub(crate) struct PinnedExecutable {
    pub(crate) path: PathBuf,
    pub(crate) file: File,
}

#[derive(Debug)]
struct ProbeOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

#[derive(Debug)]
enum ProbeError {
    Io(io::Error),
    MissingPipe(&'static str),
    TimedOut,
    OutputLimitExceeded,
}

#[cfg(feature = "bundled-bubblewrap")]
pub(crate) fn materialize_bundled_resource() -> Result<tempfile::TempDir, LinuxBackendError> {
    let bytes = cageforge_bwrap::bundled_bubblewrap();
    let expected = cageforge_bwrap::bundled_bubblewrap_sha256();
    let actual = sha256_bytes(bytes);
    if actual != expected {
        return Err(LinuxBackendError::BubblewrapDigestMismatch {
            path: PathBuf::from("<embedded Bubblewrap>"),
            expected: expected.to_owned(),
            actual,
        });
    }

    let resource = tempfile::Builder::new()
        .prefix(BUNDLED_RESOURCE_PREFIX)
        .tempdir()
        .map_err(
            |source| LinuxBackendError::BundledBubblewrapMaterialization {
                operation: "creating a private resource directory",
                source,
            },
        )?;
    let mut directory_permissions = fs::metadata(resource.path())
        .map_err(
            |source| LinuxBackendError::BundledBubblewrapMaterialization {
                operation: "checking the private resource directory",
                source,
            },
        )?
        .permissions();
    directory_permissions.set_mode(0o700);
    fs::set_permissions(resource.path(), directory_permissions).map_err(|source| {
        LinuxBackendError::BundledBubblewrapMaterialization {
            operation: "restricting the private resource directory",
            source,
        }
    })?;
    let binary = resource.path().join("bwrap");
    fs::write(&binary, bytes).map_err(|source| {
        LinuxBackendError::BundledBubblewrapMaterialization {
            operation: "writing the embedded executable",
            source,
        }
    })?;
    let mut permissions = fs::metadata(&binary)
        .map_err(
            |source| LinuxBackendError::BundledBubblewrapMaterialization {
                operation: "reading the embedded executable metadata",
                source,
            },
        )?
        .permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&binary, permissions).map_err(|source| {
        LinuxBackendError::BundledBubblewrapMaterialization {
            operation: "securing the embedded executable",
            source,
        }
    })?;
    let digest = sha256_file(&binary).map_err(|source| {
        LinuxBackendError::BundledBubblewrapMaterialization {
            operation: "hashing the embedded executable",
            source,
        }
    })?;
    fs::write(resource.path().join("bwrap.sha256"), format!("{digest}\n")).map_err(|source| {
        LinuxBackendError::BundledBubblewrapMaterialization {
            operation: "writing the embedded executable digest",
            source,
        }
    })?;
    Ok(resource)
}

pub(crate) fn discover_hardening_helper(
    source: &HardeningHelperSource,
    resource_directory: Option<&Path>,
) -> Result<PinnedExecutable, LinuxBackendError> {
    let sibling = || {
        std::env::current_exe()
            .ok()
            .and_then(|executable| executable.parent().map(Path::to_path_buf))
            .map(|directory| directory.join(HARDENING_HELPER_NAME))
    };
    let resource = || resource_directory.map(|directory| directory.join(HARDENING_HELPER_NAME));
    let paths = match source {
        HardeningHelperSource::Sibling => vec![sibling()],
        HardeningHelperSource::Resource => vec![resource()],
        HardeningHelperSource::SiblingThenResource => vec![sibling(), resource()],
        HardeningHelperSource::Explicit(path) => vec![Some(path.clone())],
    };
    let executable = paths
        .into_iter()
        .flatten()
        .find_map(|path| {
            let path = fs::canonicalize(path).ok()?;
            let file = File::open(&path).ok()?;
            validate_executable_file(&file)
                .ok()
                .map(|()| PinnedExecutable { path, file })
        })
        .ok_or(LinuxBackendError::HardeningHelperUnavailable)?;
    Ok(PinnedExecutable {
        path: executable.path,
        file: snapshot_executable(&executable.file, LinuxExecutable::HardeningHelper)?,
    })
}

pub(crate) fn discover_and_probe(
    source: &BubblewrapSource,
    resource_directory: Option<&Path>,
    proc_mount: ProcMountPolicy,
) -> Result<BubblewrapSelection, LinuxBackendError> {
    match source {
        BubblewrapSource::System => {
            let path = find_on_path("bwrap").ok_or(LinuxBackendError::BubblewrapUnavailable)?;
            discover_and_probe_one(&path, proc_mount, false)
        }
        BubblewrapSource::Bundled => {
            let path = bundled_path(resource_directory)?;
            discover_and_probe_one(&path, proc_mount, true)
        }
        BubblewrapSource::SystemThenBundled => {
            if let Some(path) = find_on_path("bwrap") {
                match discover_and_probe_one(&path, proc_mount, false) {
                    Ok(path) => return Ok(path),
                    Err(error) if can_fall_back_to_bundled(&error) => {}
                    Err(error) => return Err(error),
                }
            }
            let path = bundled_path(resource_directory)?;
            discover_and_probe_one(&path, proc_mount, true)
        }
        BubblewrapSource::Explicit(path) => discover_and_probe_one(path, proc_mount, false),
    }
}

fn can_fall_back_to_bundled(error: &LinuxBackendError) -> bool {
    matches!(
        error,
        LinuxBackendError::BubblewrapUnavailable
            | LinuxBackendError::BubblewrapIncompatible { .. }
            | LinuxBackendError::BubblewrapProbeFailed { stage: "help", .. }
            | LinuxBackendError::BubblewrapProbeTimedOut { stage: "help" }
            | LinuxBackendError::BubblewrapProbeOutputLimitExceeded { stage: "help", .. }
    )
}

pub(crate) fn open_pinned(selection: &BubblewrapSelection) -> Result<File, LinuxBackendError> {
    let file = File::open(&selection.path).map_err(|_| LinuxBackendError::BubblewrapUnavailable)?;
    if file_identity(&file).map_err(|_| LinuxBackendError::BubblewrapUnavailable)?
        != selection.identity
    {
        return Err(LinuxBackendError::BubblewrapChanged {
            path: selection.path.clone(),
        });
    }
    validate_executable_file(&file)?;
    if selection.bundled {
        verify_bundled_digest_file(&file, &selection.path)?;
    }
    snapshot_executable(&file, LinuxExecutable::Bubblewrap)
}

pub(crate) fn probe_pinned(
    executable: &File,
    proc_mount: ProcMountPolicy,
) -> Result<(), LinuxBackendError> {
    let path = PathBuf::from(format!("/proc/self/fd/{}", executable.as_raw_fd()));
    probe_help(&path)?;
    probe_namespaces(&path)?;
    if proc_mount == ProcMountPolicy::Required {
        probe_proc_mount(&path)?;
    }
    Ok(())
}

pub(crate) fn resource_directory(
    source: &ResourceDirectorySource,
) -> Result<Option<PathBuf>, LinuxBackendError> {
    let path = match source {
        ResourceDirectorySource::Sibling => {
            return Ok(std::env::current_exe()
                .ok()
                .and_then(|executable| executable.parent().map(Path::to_path_buf))
                .map(|directory| directory.join("cageforge-resources"))
                .filter(|path| path.is_dir()));
        }
        ResourceDirectorySource::Explicit(path) => path.clone(),
    };
    let path =
        fs::canonicalize(path).map_err(|_| LinuxBackendError::ResourceDirectoryUnavailable)?;
    if !path.is_dir() {
        return Err(LinuxBackendError::ResourceDirectoryUnavailable);
    }
    Ok(Some(path))
}

fn bundled_path(resource_directory: Option<&Path>) -> Result<PathBuf, LinuxBackendError> {
    resource_directory
        .map(|directory| directory.join("bwrap"))
        .ok_or(LinuxBackendError::BubblewrapUnavailable)
}

fn discover_and_probe_one(
    path: &Path,
    proc_mount: ProcMountPolicy,
    bundled: bool,
) -> Result<BubblewrapSelection, LinuxBackendError> {
    let path = fs::canonicalize(path).map_err(|_| LinuxBackendError::BubblewrapUnavailable)?;
    let file = File::open(&path).map_err(|_| LinuxBackendError::BubblewrapUnavailable)?;
    validate_executable_file(&file)?;
    let identity = file_identity(&file).map_err(|_| LinuxBackendError::BubblewrapUnavailable)?;
    if bundled {
        verify_bundled_digest(&path)?;
    }
    probe_help(&path)?;
    probe_namespaces(&path)?;
    if proc_mount == ProcMountPolicy::Required {
        probe_proc_mount(&path)?;
    }
    Ok(BubblewrapSelection {
        path,
        bundled,
        identity,
    })
}

fn verify_bundled_digest(path: &Path) -> Result<(), LinuxBackendError> {
    let manifest = path.with_file_name("bwrap.sha256");
    let expected = fs::read_to_string(&manifest)
        .map_err(|_| LinuxBackendError::BubblewrapDigestUnavailable {
            path: path.to_path_buf(),
        })?
        .split_whitespace()
        .next()
        .filter(|digest| digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .map(str::to_ascii_lowercase)
        .ok_or_else(|| LinuxBackendError::BubblewrapDigestUnavailable {
            path: path.to_path_buf(),
        })?;
    let actual = sha256_file(path).map_err(|_| LinuxBackendError::BubblewrapUnavailable)?;
    if actual != expected {
        return Err(LinuxBackendError::BubblewrapDigestMismatch {
            path: path.to_path_buf(),
            expected,
            actual,
        });
    }
    Ok(())
}

fn verify_bundled_digest_file(file: &File, path: &Path) -> Result<(), LinuxBackendError> {
    let manifest = path.with_file_name("bwrap.sha256");
    let expected = fs::read_to_string(&manifest)
        .map_err(|_| LinuxBackendError::BubblewrapDigestUnavailable {
            path: path.to_path_buf(),
        })?
        .split_whitespace()
        .next()
        .filter(|digest| digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .map(str::to_ascii_lowercase)
        .ok_or_else(|| LinuxBackendError::BubblewrapDigestUnavailable {
            path: path.to_path_buf(),
        })?;
    let actual = sha256_file_handle(file).map_err(|_| LinuxBackendError::BubblewrapUnavailable)?;
    if actual != expected {
        return Err(LinuxBackendError::BubblewrapDigestMismatch {
            path: path.to_path_buf(),
            expected,
            actual,
        });
    }
    Ok(())
}

fn sha256_file(path: &Path) -> io::Result<String> {
    sha256_file_handle(&fs::File::open(path)?)
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn sha256_file_handle(file: &File) -> io::Result<String> {
    let mut file = file.try_clone()?;
    file.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn snapshot_executable(
    source: &File,
    executable: LinuxExecutable,
) -> Result<File, LinuxBackendError> {
    let mut snapshot = create_executable_memfd().map_err(|source| {
        LinuxBackendError::ExecutableSnapshotFailed {
            executable,
            operation: ExecutableSnapshotOperation::Create,
            source,
        }
    })?;
    let mut source =
        source
            .try_clone()
            .map_err(|source| LinuxBackendError::ExecutableSnapshotFailed {
                executable,
                operation: ExecutableSnapshotOperation::CloneSource,
                source,
            })?;
    source.seek(SeekFrom::Start(0)).map_err(|source| {
        LinuxBackendError::ExecutableSnapshotFailed {
            executable,
            operation: ExecutableSnapshotOperation::RewindSource,
            source,
        }
    })?;
    io::copy(&mut source, &mut snapshot).map_err(|source| {
        LinuxBackendError::ExecutableSnapshotFailed {
            executable,
            operation: ExecutableSnapshotOperation::Copy,
            source,
        }
    })?;
    let mut permissions = snapshot
        .metadata()
        .map_err(|source| LinuxBackendError::ExecutableSnapshotFailed {
            executable,
            operation: ExecutableSnapshotOperation::Permissions,
            source,
        })?
        .permissions();
    permissions.set_mode(0o500);
    snapshot.set_permissions(permissions).map_err(|source| {
        LinuxBackendError::ExecutableSnapshotFailed {
            executable,
            operation: ExecutableSnapshotOperation::Permissions,
            source,
        }
    })?;
    seal_executable(&snapshot).map_err(|source| LinuxBackendError::ExecutableSnapshotFailed {
        executable,
        operation: ExecutableSnapshotOperation::Seal,
        source,
    })?;
    File::open(format!("/proc/self/fd/{}", snapshot.as_raw_fd())).map_err(|source| {
        LinuxBackendError::ExecutableSnapshotFailed {
            executable,
            operation: ExecutableSnapshotOperation::OpenSnapshot,
            source,
        }
    })
}

#[allow(unsafe_code)]
fn create_executable_memfd() -> io::Result<File> {
    let base_flags = libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING;
    let descriptor = unsafe {
        libc::syscall(
            libc::SYS_memfd_create,
            c"cageforge-executable".as_ptr(),
            base_flags | MFD_EXEC,
        )
    };
    let descriptor =
        if descriptor < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) {
            unsafe {
                libc::syscall(
                    libc::SYS_memfd_create,
                    c"cageforge-executable".as_ptr(),
                    base_flags,
                )
            }
        } else {
            descriptor
        };
    if descriptor < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(descriptor as libc::c_int) })
    }
}

#[allow(unsafe_code)]
fn seal_executable(file: &File) -> io::Result<()> {
    let seals = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, seals) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn find_on_path(program: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    let current_directory = std::env::current_dir().ok()?;
    find_in_search_paths(program, std::env::split_paths(&path), &current_directory)
}

fn validate_executable(path: &Path) -> Result<(), LinuxBackendError> {
    let file = File::open(path).map_err(|_| LinuxBackendError::BubblewrapUnavailable)?;
    validate_executable_file(&file)
}

fn validate_executable_file(file: &File) -> Result<(), LinuxBackendError> {
    let metadata = file
        .metadata()
        .map_err(|_| LinuxBackendError::BubblewrapUnavailable)?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err(LinuxBackendError::BubblewrapUnavailable);
    }
    Ok(())
}

pub(crate) fn file_identity(file: &File) -> io::Result<FileIdentity> {
    let metadata = file.metadata()?;
    Ok(FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn probe_help(path: &Path) -> Result<(), LinuxBackendError> {
    let output =
        run_probe(path, &["--help"], PROBE_TIMEOUT).map_err(|error| probe_error("help", error))?;
    let mut help = String::from_utf8_lossy(&output.stdout).into_owned();
    help.push_str(&String::from_utf8_lossy(&output.stderr));
    let missing = missing_help_flags(&help);
    if missing.is_empty() {
        Ok(())
    } else {
        Err(LinuxBackendError::BubblewrapIncompatible { missing })
    }
}

fn missing_help_flags(help: &str) -> Vec<BubblewrapFlag> {
    let available = help
        .split_ascii_whitespace()
        .collect::<std::collections::HashSet<_>>();
    BubblewrapFlag::ALL
        .into_iter()
        .filter(|flag| !available.contains(flag.as_str()))
        .collect()
}

fn probe_namespaces(path: &Path) -> Result<(), LinuxBackendError> {
    probe_namespace(path, LinuxNamespace::User)?;
    probe_capability_drop(path)?;
    probe_nested_user_namespace_isolation(path)?;
    for namespace in [
        LinuxNamespace::Pid,
        LinuxNamespace::Ipc,
        LinuxNamespace::Network,
    ] {
        probe_namespace(path, namespace)?;
    }
    Ok(())
}

fn probe_namespace(path: &Path, namespace: LinuxNamespace) -> Result<(), LinuxBackendError> {
    let mut args = vec!["--die-with-parent", "--unshare-user"];
    match namespace {
        LinuxNamespace::User => {}
        LinuxNamespace::Pid => args.extend(["--unshare-pid", "--as-pid-1"]),
        LinuxNamespace::Ipc => args.push("--unshare-ipc"),
        LinuxNamespace::Network => args.push("--unshare-net"),
    }
    args.extend(["--ro-bind", "/", "/", "/bin/true"]);
    let output = run_probe(path, &args, PROBE_TIMEOUT)
        .map_err(|error| probe_error(namespace.probe_stage(), error))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(LinuxBackendError::NamespaceUnavailable {
            namespace,
            message: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
    }
}

fn probe_capability_drop(path: &Path) -> Result<(), LinuxBackendError> {
    let output = run_probe(
        path,
        &[
            "--die-with-parent",
            "--unshare-user",
            "--cap-drop",
            "ALL",
            "--ro-bind",
            "/",
            "/",
            "/bin/true",
        ],
        PROBE_TIMEOUT,
    )
    .map_err(|error| probe_error("capability drop", error))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(LinuxBackendError::CapabilityDropUnavailable {
            message: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
    }
}

fn probe_nested_user_namespace_isolation(path: &Path) -> Result<(), LinuxBackendError> {
    let output = run_probe(
        path,
        &[
            "--die-with-parent",
            "--unshare-user",
            "--disable-userns",
            "--ro-bind",
            "/",
            "/",
            "/bin/true",
        ],
        PROBE_TIMEOUT,
    )
    .map_err(|error| probe_error("nested user namespace isolation", error))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(LinuxBackendError::NestedUserNamespaceIsolationUnavailable {
            message: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
    }
}

fn probe_proc_mount(path: &Path) -> Result<(), LinuxBackendError> {
    let output = run_probe(
        path,
        &[
            "--die-with-parent",
            "--unshare-user",
            "--unshare-pid",
            "--as-pid-1",
            "--ro-bind",
            "/",
            "/",
            "--proc",
            "/proc",
            "/bin/true",
        ],
        PROBE_TIMEOUT,
    )
    .map_err(|error| probe_error("proc mount", error))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(LinuxBackendError::ProcMountUnavailable {
            message: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
    }
}

fn find_in_search_paths(
    program: &str,
    search_paths: impl IntoIterator<Item = PathBuf>,
    current_directory: &Path,
) -> Option<PathBuf> {
    let current_directory = fs::canonicalize(current_directory).ok()?;
    let current_directory_is_root = current_directory.parent().is_none();
    search_paths.into_iter().find_map(|directory| {
        let candidate = fs::canonicalize(directory.join(program)).ok()?;
        if (!current_directory_is_root && candidate.starts_with(&current_directory))
            || validate_executable(&candidate).is_err()
        {
            None
        } else {
            Some(candidate)
        }
    })
}

fn run_probe(path: &Path, args: &[&str], timeout: Duration) -> Result<ProbeOutput, ProbeError> {
    let mut child = Command::new(path)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(ProbeError::Io)?;
    let result = (|| {
        let mut stdout = child
            .stdout
            .take()
            .ok_or(ProbeError::MissingPipe("stdout"))?;
        let mut stderr = child
            .stderr
            .take()
            .ok_or(ProbeError::MissingPipe("stderr"))?;
        set_nonblocking(stdout.as_raw_fd()).map_err(ProbeError::Io)?;
        set_nonblocking(stderr.as_raw_fd()).map_err(ProbeError::Io)?;
        let deadline = Instant::now() + timeout;
        let mut stdout_bytes = Vec::new();
        let mut stderr_bytes = Vec::new();
        loop {
            if drain_probe_output(&mut stdout, &mut stdout_bytes).map_err(ProbeError::Io)?
                || drain_probe_output(&mut stderr, &mut stderr_bytes).map_err(ProbeError::Io)?
            {
                return Err(ProbeError::OutputLimitExceeded);
            }
            match child.try_wait().map_err(ProbeError::Io)? {
                Some(status) => {
                    if drain_probe_output(&mut stdout, &mut stdout_bytes).map_err(ProbeError::Io)?
                        || drain_probe_output(&mut stderr, &mut stderr_bytes)
                            .map_err(ProbeError::Io)?
                    {
                        return Err(ProbeError::OutputLimitExceeded);
                    }
                    return Ok(ProbeOutput {
                        status,
                        stdout: stdout_bytes,
                        stderr: stderr_bytes,
                    });
                }
                None if Instant::now() >= deadline => return Err(ProbeError::TimedOut),
                None => thread::sleep(PROBE_POLL_INTERVAL),
            }
        }
    })();
    if result.is_err() {
        terminate_probe(&mut child);
    }
    result
}

fn drain_probe_output(reader: &mut impl Read, output: &mut Vec<u8>) -> io::Result<bool> {
    let mut buffer = [0_u8; 8192];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(false),
            Ok(read) => {
                output.extend_from_slice(&buffer[..read]);
                if output.len() > PROBE_OUTPUT_LIMIT_BYTES {
                    return Ok(true);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

fn terminate_probe(child: &mut std::process::Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn probe_error(stage: &'static str, error: ProbeError) -> LinuxBackendError {
    match error {
        ProbeError::Io(source) => LinuxBackendError::BubblewrapProbeFailed { stage, source },
        ProbeError::MissingPipe(stream) => {
            LinuxBackendError::BubblewrapProbePipeMissing { stage, stream }
        }
        ProbeError::TimedOut => LinuxBackendError::BubblewrapProbeTimedOut { stage },
        ProbeError::OutputLimitExceeded => LinuxBackendError::BubblewrapProbeOutputLimitExceeded {
            stage,
            limit: PROBE_OUTPUT_LIMIT_BYTES,
        },
    }
}

#[allow(unsafe_code)]
fn set_nonblocking(fd: std::os::fd::RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
#[path = "bwrap_tests.rs"]
mod tests;

pub(crate) fn namespace_args(
    _proc_mount: ProcMountPolicy,
    network_isolated: bool,
) -> Vec<OsString> {
    let mut args = vec![
        "--die-with-parent".into(),
        "--new-session".into(),
        "--unshare-user".into(),
        "--unshare-pid".into(),
        "--unshare-ipc".into(),
        "--as-pid-1".into(),
        "--cap-drop".into(),
        "ALL".into(),
        "--disable-userns".into(),
    ];
    if network_isolated {
        args.push("--unshare-net".into());
    }
    args
}
