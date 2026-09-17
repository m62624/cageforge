// SPDX-License-Identifier: Apache-2.0

//! Typed preflight requests, opaque approvals, and their host-owned store.
//!
//! A [`PermissionRequest`] is descriptive and has no authority. A
//! [`PermissionGrant`] can only be produced by [`GrantAuthority`] after the
//! trusted host has approved the request or an explicit subset of it. Grants
//! are bound to the request digest, tool identity, platform, and architecture.
//! This crate is deliberately independent of native backends and language
//! bindings.

#![deny(missing_docs)]

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// The supported operating-system families for a resolved Cageforge plan.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum PlatformId {
    /// Linux and Linux-compatible native backend.
    Linux,
    /// Apple macOS native backend.
    Macos,
    /// Microsoft Windows native backend.
    Windows,
}

impl PlatformId {
    /// Returns the platform selected by the compiling target.
    pub const fn current() -> Result<Self, PlatformError> {
        #[cfg(target_os = "linux")]
        {
            return Ok(Self::Linux);
        }
        #[cfg(target_os = "macos")]
        {
            return Ok(Self::Macos);
        }
        #[cfg(target_os = "windows")]
        {
            return Ok(Self::Windows);
        }
        #[allow(unreachable_code)]
        Err(PlatformError::UnsupportedTarget)
    }

    /// Returns the stable serialized platform label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::Macos => "macos",
            Self::Windows => "windows",
        }
    }
}

/// Controls whether a profile participates in host-mediated approval.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum PermissionMode {
    /// Use only the statically resolved policy.
    Disabled,
    /// Ask the trusted host before the first launch.
    Preflight,
    /// Reserve host-mediated requests for a future relaunch operation.
    OnDemand,
    /// Use preflight and future host-mediated relaunch requests.
    PreflightAndOnDemand,
}

/// Action taken when an approval deadline expires.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalTimeoutAction {
    /// Reject the launch.
    Deny,
}

/// Lifetime used when a host persists an approved decision.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalPersistence {
    /// Keep the decision only for one launch.
    Launch,
    /// Keep the decision in the host session.
    Session,
    /// Allow the host to write the decision to its store.
    Persistent,
}

/// Validated approval behavior for one resolved profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ApprovalConfig {
    mode: PermissionMode,
    timeout_ms: u64,
    on_timeout: ApprovalTimeoutAction,
    persistence: ApprovalPersistence,
}

impl Default for ApprovalConfig {
    fn default() -> Self {
        Self {
            mode: PermissionMode::Disabled,
            timeout_ms: 10_000,
            on_timeout: ApprovalTimeoutAction::Deny,
            persistence: ApprovalPersistence::Session,
        }
    }
}

impl ApprovalConfig {
    /// Creates validated approval settings.
    pub fn new(
        mode: PermissionMode,
        timeout_ms: u64,
        on_timeout: ApprovalTimeoutAction,
        persistence: ApprovalPersistence,
    ) -> Result<Self, PermissionError> {
        if timeout_ms == 0 {
            return Err(PermissionError::InvalidTimeout);
        }
        Ok(Self {
            mode,
            timeout_ms,
            on_timeout,
            persistence,
        })
    }

    /// Returns the dynamic approval mode.
    pub const fn mode(self) -> PermissionMode {
        self.mode
    }
    /// Returns the approval timeout in milliseconds.
    pub const fn timeout_ms(self) -> u64 {
        self.timeout_ms
    }
    /// Returns the timeout action.
    pub const fn on_timeout(self) -> ApprovalTimeoutAction {
        self.on_timeout
    }
    /// Returns the persistence requested by the profile.
    pub const fn persistence(self) -> ApprovalPersistence {
        self.persistence
    }
}

impl std::fmt::Display for PlatformId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Errors returned when selecting a host platform.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PlatformError {
    /// The target is not one of Cageforge's supported native families.
    #[error("unsupported host platform")]
    UnsupportedTarget,
}

/// The filesystem operation requested by a tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FilesystemOperation {
    /// Read a file or directory.
    Read,
    /// Create, modify, or remove entries below a path.
    Write,
    /// Explicitly deny access to a path.
    Deny,
}

/// One portable or platform-resolved filesystem capability.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
pub struct FilesystemCapability {
    operation: FilesystemOperation,
    path: String,
}

impl FilesystemCapability {
    /// Creates a capability for a non-empty path declaration.
    pub fn new(
        operation: FilesystemOperation,
        path: impl Into<String>,
    ) -> Result<Self, PermissionError> {
        let path = path.into();
        validate_path(&path)?;
        Ok(Self { operation, path })
    }

    /// Returns the requested operation.
    pub const fn operation(&self) -> FilesystemOperation {
        self.operation
    }

    /// Returns the portable or native path declaration.
    pub fn path(&self) -> &str {
        &self.path
    }
}

/// One network endpoint capability.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
pub struct NetworkCapability {
    endpoint: String,
}

impl NetworkCapability {
    /// Creates a capability for a normalized non-empty endpoint declaration.
    pub fn new(endpoint: impl Into<String>) -> Result<Self, PermissionError> {
        let endpoint = endpoint.into();
        if endpoint.trim().is_empty() || endpoint.contains('\0') {
            return Err(PermissionError::InvalidCapability {
                value: "network endpoint must be non-empty and NUL-free".to_owned(),
            });
        }
        Ok(Self { endpoint })
    }

    /// Returns the endpoint declaration.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
}

/// One child-process capability.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
pub struct ProcessCapability {
    program: String,
}

impl ProcessCapability {
    /// Creates a capability for a non-empty executable declaration.
    pub fn new(program: impl Into<String>) -> Result<Self, PermissionError> {
        let program = program.into();
        if program.trim().is_empty() || program.contains('\0') {
            return Err(PermissionError::InvalidCapability {
                value: "program must be non-empty and NUL-free".to_owned(),
            });
        }
        Ok(Self { program })
    }

    /// Returns the executable declaration.
    pub fn program(&self) -> &str {
        &self.program
    }
}

/// The lifetime requested for an approved grant.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum PermissionScope {
    /// Valid for one launch plan.
    Launch,
    /// Valid while the host session remains active.
    Session,
    /// May be persisted in the host-owned grant store.
    Persistent,
}

impl PermissionScope {
    /// Parses the stable host-facing scope label.
    pub fn parse(value: &str) -> Result<Self, PermissionError> {
        match value {
            "launch" => Ok(Self::Launch),
            "session" => Ok(Self::Session),
            "persistent" => Ok(Self::Persistent),
            _ => Err(PermissionError::InvalidScope {
                value: value.to_owned(),
            }),
        }
    }
}

/// The typed capabilities requested by one tool invocation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionSet {
    filesystem: Vec<FilesystemCapability>,
    network: Vec<NetworkCapability>,
    child_processes: Vec<ProcessCapability>,
}

impl PermissionSet {
    /// Creates an empty capability set.
    pub const fn new() -> Self {
        Self {
            filesystem: Vec::new(),
            network: Vec::new(),
            child_processes: Vec::new(),
        }
    }

    /// Adds a filesystem capability, deduplicating exact declarations.
    pub fn with_filesystem(mut self, capability: FilesystemCapability) -> Self {
        if !self.filesystem.contains(&capability) {
            self.filesystem.push(capability);
            self.filesystem.sort();
        }
        self
    }

    /// Adds a network capability, deduplicating exact declarations.
    pub fn with_network(mut self, capability: NetworkCapability) -> Self {
        if !self.network.contains(&capability) {
            self.network.push(capability);
            self.network.sort();
        }
        self
    }

    /// Adds a child-process capability, deduplicating exact declarations.
    pub fn with_child_process(mut self, capability: ProcessCapability) -> Self {
        if !self.child_processes.contains(&capability) {
            self.child_processes.push(capability);
            self.child_processes.sort();
        }
        self
    }

    /// Returns filesystem capabilities.
    pub fn filesystem(&self) -> &[FilesystemCapability] {
        &self.filesystem
    }

    /// Returns network capabilities.
    pub fn network(&self) -> &[NetworkCapability] {
        &self.network
    }

    /// Returns child-process capabilities.
    pub fn child_processes(&self) -> &[ProcessCapability] {
        &self.child_processes
    }

    fn is_subset_of(&self, request: &Self) -> bool {
        self.filesystem
            .iter()
            .all(|value| request.filesystem.contains(value))
            && self
                .network
                .iter()
                .all(|value| request.network.contains(value))
            && self
                .child_processes
                .iter()
                .all(|value| request.child_processes.contains(value))
    }
}

/// A descriptive, non-authoritative preflight request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionRequest {
    tool_id: String,
    tool_version: String,
    manifest_digest: String,
    config_digest: String,
    platform: PlatformId,
    architecture: String,
    capabilities: PermissionSet,
}

impl PermissionRequest {
    /// Creates and validates a preflight request.
    pub fn new(
        tool_id: impl Into<String>,
        tool_version: impl Into<String>,
        manifest_digest: impl Into<String>,
        config_digest: impl Into<String>,
        platform: PlatformId,
        architecture: impl Into<String>,
        capabilities: PermissionSet,
    ) -> Result<Self, PermissionError> {
        Ok(Self {
            tool_id: validate_identity(tool_id.into(), "tool id")?,
            tool_version: validate_identity(tool_version.into(), "tool version")?,
            manifest_digest: validate_digest(manifest_digest.into(), "manifest digest")?,
            config_digest: validate_digest(config_digest.into(), "config digest")?,
            platform,
            architecture: validate_identity(architecture.into(), "architecture")?,
            capabilities,
        })
    }

    /// Returns the tool identifier.
    pub fn tool_id(&self) -> &str {
        &self.tool_id
    }
    /// Returns the tool version.
    pub fn tool_version(&self) -> &str {
        &self.tool_version
    }
    /// Returns the manifest digest.
    pub fn manifest_digest(&self) -> &str {
        &self.manifest_digest
    }
    /// Returns the configuration digest.
    pub fn config_digest(&self) -> &str {
        &self.config_digest
    }
    /// Returns the target platform.
    pub const fn platform(&self) -> PlatformId {
        self.platform
    }
    /// Returns the target architecture.
    pub fn architecture(&self) -> &str {
        &self.architecture
    }
    /// Returns the requested capabilities.
    pub fn capabilities(&self) -> &PermissionSet {
        &self.capabilities
    }

    /// Computes the canonical request digest used to bind a grant.
    pub fn digest(&self) -> String {
        canonical_digest(self)
    }
}

/// A trusted host's immutable approval of a request or its subset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionGrant {
    request_digest: String,
    approved: PermissionSet,
    scope: PermissionScope,
    expires_at: Option<u64>,
    issued_at: u64,
}

impl PermissionGrant {
    /// Returns the request digest bound to this grant.
    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }
    /// Returns the approved subset.
    pub fn approved(&self) -> &PermissionSet {
        &self.approved
    }
    /// Returns the lifetime selected by the trusted host.
    pub const fn scope(&self) -> PermissionScope {
        self.scope
    }
    /// Returns the optional Unix expiration timestamp.
    pub const fn expires_at(&self) -> Option<u64> {
        self.expires_at
    }
    /// Returns the issuance timestamp in Unix seconds.
    pub const fn issued_at(&self) -> u64 {
        self.issued_at
    }

    /// Checks that the grant belongs to exactly this request.
    pub fn matches(&self, request: &PermissionRequest) -> bool {
        self.request_digest == request.digest() && self.approved.is_subset_of(&request.capabilities)
    }

    /// Returns whether the grant is still usable at the supplied Unix time.
    pub fn is_valid_at(&self, now: u64) -> bool {
        self.expires_at.is_none_or(|expires_at| now < expires_at)
    }
}

/// The trusted host-side issuer for opaque permission grants.
#[derive(Debug, Default, Clone, Copy)]
pub struct GrantAuthority;

impl GrantAuthority {
    /// Creates a host-side issuer.
    pub const fn new() -> Self {
        Self
    }

    /// Approves the complete request.
    pub fn approve(&self, request: &PermissionRequest) -> PermissionGrant {
        self.approve_with(
            request,
            request.capabilities.clone(),
            PermissionScope::Session,
            None,
        )
        .expect("a request is always a subset of itself")
    }

    /// Approves a request with an explicit scope and optional expiration.
    pub fn approve_with(
        &self,
        request: &PermissionRequest,
        approved: PermissionSet,
        scope: PermissionScope,
        expires_at: Option<u64>,
    ) -> Result<PermissionGrant, PermissionError> {
        if expires_at.is_some_and(|expires_at| expires_at == 0) {
            return Err(PermissionError::InvalidExpiration);
        }
        if !approved.is_subset_of(&request.capabilities) {
            return Err(PermissionError::GrantExceedsRequest);
        }
        Ok(PermissionGrant {
            request_digest: request.digest(),
            approved,
            scope,
            expires_at,
            issued_at: unix_timestamp(),
        })
    }

    /// Approves an explicit subset of the requested capabilities.
    pub fn approve_subset(
        &self,
        request: &PermissionRequest,
        approved: PermissionSet,
    ) -> Result<PermissionGrant, PermissionError> {
        self.approve_with(request, approved, PermissionScope::Session, None)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredGrant {
    request_digest: String,
    tool_id: String,
    tool_version: String,
    manifest_digest: String,
    config_digest: String,
    platform: PlatformId,
    architecture: String,
    approved: PermissionSet,
    scope: PermissionScope,
    expires_at: Option<u64>,
    issued_at: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct StoreDocument {
    schema_version: u32,
    #[serde(default)]
    grants: BTreeMap<String, StoredGrant>,
}

/// A versioned host-owned grant store loaded and indexed in memory.
pub struct PermissionStore {
    path: PathBuf,
    document: Mutex<StoreDocument>,
}

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

impl std::fmt::Debug for PermissionStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PermissionStore")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl PermissionStore {
    /// The current on-disk schema version.
    pub const SCHEMA_VERSION: u32 = 2;

    /// Opens an existing store or creates an empty in-memory store.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let path = path.into();
        let document = if path.exists() {
            ensure_owner_only_permissions(&path).map_err(StoreError::write)?;
            let bytes = fs::read(&path).map_err(StoreError::read)?;
            let document: StoreDocument =
                serde_json::from_slice(&bytes).map_err(StoreError::format)?;
            if document.schema_version != Self::SCHEMA_VERSION {
                return Err(StoreError::UnsupportedSchema(document.schema_version));
            }
            document
        } else {
            StoreDocument {
                schema_version: Self::SCHEMA_VERSION,
                grants: BTreeMap::new(),
            }
        };
        Ok(Self {
            path,
            document: Mutex::new(document),
        })
    }

    /// Returns the store path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Looks up a grant for an exact request digest.
    pub fn get(&self, request: &PermissionRequest) -> Result<Option<PermissionGrant>, StoreError> {
        let document = self.document.lock().map_err(|_| StoreError::Poisoned)?;
        Ok(document.grants.get(&request.digest()).and_then(|stored| {
            let metadata_matches = stored.request_digest == request.digest()
                && stored.tool_id == request.tool_id
                && stored.tool_version == request.tool_version
                && stored.manifest_digest == request.manifest_digest
                && stored.config_digest == request.config_digest
                && stored.platform == request.platform
                && stored.architecture == request.architecture;
            let grant = PermissionGrant {
                request_digest: stored.request_digest.clone(),
                approved: stored.approved.clone(),
                scope: stored.scope,
                expires_at: stored.expires_at,
                issued_at: stored.issued_at,
            };
            (metadata_matches
                && stored.scope == PermissionScope::Persistent
                && grant.matches(request)
                && grant.is_valid_at(unix_timestamp()))
            .then_some(grant)
        }))
    }

    /// Stores a grant and atomically replaces the document on disk.
    pub fn put(
        &self,
        grant: &PermissionGrant,
        request: &PermissionRequest,
    ) -> Result<(), StoreError> {
        if !grant.matches(request) {
            return Err(StoreError::GrantMismatch);
        }
        if grant.scope != PermissionScope::Persistent {
            return Err(StoreError::NonPersistentGrant);
        }
        let mut document = self.document.lock().map_err(|_| StoreError::Poisoned)?;
        let _lock = acquire_file_lock(&self.path)?;
        if self.path.exists() {
            let bytes = fs::read(&self.path).map_err(StoreError::read)?;
            let latest: StoreDocument =
                serde_json::from_slice(&bytes).map_err(StoreError::format)?;
            if latest.schema_version != Self::SCHEMA_VERSION {
                return Err(StoreError::UnsupportedSchema(latest.schema_version));
            }
            *document = latest;
        }
        document.grants.insert(
            request.digest(),
            StoredGrant {
                request_digest: grant.request_digest.clone(),
                tool_id: request.tool_id.clone(),
                tool_version: request.tool_version.clone(),
                manifest_digest: request.manifest_digest.clone(),
                config_digest: request.config_digest.clone(),
                platform: request.platform,
                architecture: request.architecture.clone(),
                approved: grant.approved.clone(),
                scope: grant.scope,
                expires_at: grant.expires_at,
                issued_at: grant.issued_at,
            },
        );
        write_document(&self.path, &document)
    }
}

/// Errors returned by request and grant validation.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PermissionError {
    /// A capability contains an unsafe or malformed value.
    #[error("invalid capability: {value}")]
    InvalidCapability {
        /// Explanation of the invalid value.
        value: String,
    },
    /// An identity field is empty or contains a forbidden character.
    #[error("invalid {field}")]
    InvalidIdentity {
        /// The identity field that failed validation.
        field: &'static str,
    },
    /// A digest is not a lowercase hexadecimal SHA-256 value.
    #[error("invalid {field}")]
    InvalidDigest {
        /// The digest field that failed validation.
        field: &'static str,
    },
    /// A host supplied an unknown grant lifetime label.
    #[error("invalid permission scope: {value:?}")]
    InvalidScope {
        /// The unknown scope label.
        value: String,
    },
    /// An approved capability was not part of the request.
    #[error("permission grant exceeds the request")]
    GrantExceedsRequest,
    /// An expiration value cannot be zero.
    #[error("grant expiration must be a non-zero Unix timestamp")]
    InvalidExpiration,
    /// Approval timeout must be positive.
    #[error("approval timeout must be greater than zero")]
    InvalidTimeout,
}

/// Errors returned by the persistent grant store.
#[derive(Debug, Error)]
pub enum StoreError {
    /// The store could not be read.
    #[error("cannot read permission store: {message}")]
    Read {
        /// The underlying I/O message.
        message: String,
    },
    /// The store contained invalid JSON or an invalid document.
    #[error("invalid permission store: {message}")]
    Format {
        /// The parser or validation message.
        message: String,
    },
    /// The store schema is newer than this library understands.
    #[error("unsupported permission store schema version {0}")]
    UnsupportedSchema(u32),
    /// The current process cannot safely use the store lock.
    #[error("permission store lock is poisoned")]
    Poisoned,
    /// The supplied grant does not match the supplied request.
    #[error("permission grant does not match request")]
    GrantMismatch,
    /// Session and launch grants must not be written to persistent storage.
    #[error("only persistent grants may be written to the permission store")]
    NonPersistentGrant,
    /// The store could not be written atomically.
    #[error("cannot write permission store: {message}")]
    Write {
        /// The underlying I/O or serialization message.
        message: String,
    },
}

impl StoreError {
    fn read(error: io::Error) -> Self {
        Self::Read {
            message: error.to_string(),
        }
    }
    fn format(error: serde_json::Error) -> Self {
        Self::Format {
            message: error.to_string(),
        }
    }
    fn write(error: io::Error) -> Self {
        Self::Write {
            message: error.to_string(),
        }
    }
}

fn validate_path(path: &str) -> Result<(), PermissionError> {
    if path.trim().is_empty() || path.contains('\0') {
        return Err(PermissionError::InvalidCapability {
            value: "filesystem path must be non-empty and NUL-free".to_owned(),
        });
    }
    Ok(())
}

fn validate_identity(value: String, field: &'static str) -> Result<String, PermissionError> {
    if value.trim().is_empty() || value.contains('\0') {
        return Err(PermissionError::InvalidIdentity { field });
    }
    Ok(value)
}

fn validate_digest(value: String, field: &'static str) -> Result<String, PermissionError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(PermissionError::InvalidDigest { field });
    }
    Ok(value)
}

fn canonical_digest<T: Serialize>(value: &T) -> String {
    let encoded = serde_json::to_vec(value).expect("permission models are serializable");
    let digest = Sha256::digest(encoded);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn write_document(path: &Path, document: &StoreDocument) -> Result<(), StoreError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(StoreError::write)?;
    let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let temporary = path.with_extension(format!("json.tmp.{}.{}", std::process::id(), counter));
    let bytes = serde_json::to_vec_pretty(document).map_err(StoreError::format)?;
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    let mut file = options.open(&temporary).map_err(StoreError::write)?;
    set_owner_only_permissions(&temporary).map_err(StoreError::write)?;
    file.write_all(&bytes).map_err(StoreError::write)?;
    file.sync_all().map_err(StoreError::write)?;
    drop(file);
    fs::rename(&temporary, path).map_err(StoreError::write)?;
    ensure_owner_only_permissions(path).map_err(StoreError::write)
}

fn acquire_file_lock(path: &Path) -> Result<FileLock, StoreError> {
    let lock_path = path.with_extension("json.lock");
    if let Some(parent) = lock_path.parent() {
        fs::create_dir_all(parent).map_err(StoreError::write)?;
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let file = options.open(&lock_path).map_err(StoreError::write)?;
    set_owner_only_permissions(&lock_path).map_err(StoreError::write)?;
    ensure_owner_only_permissions(&lock_path).map_err(StoreError::write)?;

    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{LOCKFILE_EXCLUSIVE_LOCK, LockFileEx};
        use windows_sys::Win32::System::IO::OVERLAPPED;
        let mut overlapped = OVERLAPPED::default();
        #[allow(unsafe_code)]
        let result = unsafe {
            LockFileEx(
                file.as_raw_handle() as _,
                LOCKFILE_EXCLUSIVE_LOCK,
                0,
                1,
                0,
                &mut overlapped,
            )
        };
        if result == 0 {
            return Err(StoreError::write(io::Error::last_os_error()));
        }
        Ok(FileLock {
            file,
            #[allow(unused_mut)]
            overlapped,
        })
    }
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        #[allow(unsafe_code)]
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if result != 0 {
            return Err(StoreError::write(io::Error::last_os_error()));
        }
        Ok(FileLock { file })
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = file;
        Err(StoreError::write(io::Error::new(
            io::ErrorKind::Unsupported,
            "permission store locking is unsupported on this target",
        )))
    }
}

struct FileLock {
    file: std::fs::File,
    #[cfg(windows)]
    overlapped: windows_sys::Win32::System::IO::OVERLAPPED,
}

#[cfg(unix)]
impl Drop for FileLock {
    fn drop(&mut self) {
        use std::os::unix::io::AsRawFd;
        #[allow(unsafe_code)]
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
impl Drop for FileLock {
    fn drop(&mut self) {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::UnlockFileEx;
        unsafe {
            UnlockFileEx(
                self.file.as_raw_handle() as _,
                0,
                1,
                0,
                &mut self.overlapped,
            );
        }
    }
}

#[cfg(unix)]
fn set_owner_only_permissions(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(unix)]
fn ensure_owner_only_permissions(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(path)?.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "permission store is accessible by group or other users",
        ));
    }
    Ok(())
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn set_owner_only_permissions(path: &Path) -> io::Result<()> {
    use windows_sys::Win32::Foundation::{GetLastError, HLOCAL, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{DACL_SECURITY_INFORMATION, SetFileSecurityW};

    let path = wide_path(path)?;
    let descriptor_text = wide_text("D:P(A;;FA;;;OW)");
    let mut descriptor = std::ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            descriptor_text.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    } == 0
        || descriptor.is_null()
    {
        return Err(io::Error::from_raw_os_error(
            unsafe { GetLastError() } as i32
        ));
    }
    let result =
        if unsafe { SetFileSecurityW(path.as_ptr(), DACL_SECURITY_INFORMATION, descriptor) } == 0 {
            Err(io::Error::from_raw_os_error(
                unsafe { GetLastError() } as i32
            ))
        } else {
            Ok(())
        };
    unsafe {
        LocalFree(descriptor as HLOCAL);
    }
    result
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn ensure_owner_only_permissions(path: &Path) -> io::Result<()> {
    use windows_sys::Win32::Foundation::{GetLastError, HLOCAL, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, GetNamedSecurityInfoW,
        SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;

    let path = wide_path(path)?;
    let mut descriptor = std::ptr::null_mut();
    let error = unsafe {
        GetNamedSecurityInfoW(
            path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if error != 0 || descriptor.is_null() {
        return Err(io::Error::from_raw_os_error(if error != 0 {
            error as i32
        } else {
            unsafe { GetLastError() as i32 }
        }));
    }
    let mut text = std::ptr::null_mut();
    let mut length = 0;
    let converted = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            &mut text,
            &mut length,
        )
    } != 0;
    let value = if converted && !text.is_null() {
        let value = unsafe { std::slice::from_raw_parts(text, length as usize) };
        String::from_utf16_lossy(value)
            .trim_end_matches('\0')
            .to_owned()
    } else {
        String::new()
    };
    unsafe {
        LocalFree(text as HLOCAL);
        LocalFree(descriptor as HLOCAL);
    }
    if !converted {
        return Err(io::Error::from_raw_os_error(
            unsafe { GetLastError() } as i32
        ));
    }
    if value != "D:P(A;;FA;;;OW)" {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "permission store must have an owner-only protected DACL",
        ));
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn set_owner_only_permissions(_path: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "owner-only permission store protection is unsupported on this target",
    ))
}

#[cfg(not(any(unix, windows)))]
fn ensure_owner_only_permissions(_path: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "owner-only permission store protection is unsupported on this target",
    ))
}

#[cfg(windows)]
fn wide_text(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
fn wide_path(path: &Path) -> io::Result<Vec<u16>> {
    let value = path.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "permission store path is not valid Unicode on Windows",
        )
    })?;
    Ok(wide_text(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> PermissionRequest {
        request_with_id("tool")
    }

    fn request_with_id(tool_id: &str) -> PermissionRequest {
        PermissionRequest::new(
            tool_id,
            "1.0.0",
            "a".repeat(64),
            "b".repeat(64),
            PlatformId::Linux,
            "x86_64",
            PermissionSet::new().with_filesystem(
                FilesystemCapability::new(FilesystemOperation::Read, "/etc/tool").unwrap(),
            ),
        )
        .unwrap()
    }

    #[test]
    fn subset_grants_are_bound_to_request() {
        let request = request();
        let authority = GrantAuthority::new();
        let grant = authority.approve(&request);
        assert!(grant.matches(&request));
        let changed = PermissionRequest::new(
            "other",
            "1.0.0",
            "a".repeat(64),
            "b".repeat(64),
            PlatformId::Linux,
            "x86_64",
            request.capabilities().clone(),
        )
        .unwrap();
        assert!(!grant.matches(&changed));
    }

    #[test]
    fn store_loads_and_indexes_grants() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("permissions.json");
        let store = PermissionStore::open(&path).unwrap();
        let request = request();
        let grant = GrantAuthority::new()
            .approve_with(
                &request,
                request.capabilities().clone(),
                PermissionScope::Persistent,
                None,
            )
            .unwrap();
        store.put(&grant, &request).unwrap();
        let reopened = PermissionStore::open(&path).unwrap();
        assert_eq!(reopened.get(&request).unwrap(), Some(grant));
    }

    #[test]
    fn store_rejects_nonpersistent_grants_without_creating_a_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("permissions.json");
        let store = PermissionStore::open(&path).unwrap();
        let request = request();
        let grant = GrantAuthority::new().approve(&request);

        assert!(matches!(
            store.put(&grant, &request),
            Err(StoreError::NonPersistentGrant)
        ));
        assert!(!path.exists());
    }

    #[test]
    fn concurrent_writers_preserve_a_thousand_indexed_records() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("permissions.json");
        let mut workers = Vec::new();
        for worker in 0..4 {
            let path = path.clone();
            workers.push(std::thread::spawn(move || {
                let store = PermissionStore::open(path).unwrap();
                for offset in 0..250 {
                    let request = request_with_id(&format!("tool-{worker}-{offset}"));
                    let grant = GrantAuthority::new()
                        .approve_with(
                            &request,
                            request.capabilities().clone(),
                            PermissionScope::Persistent,
                            None,
                        )
                        .unwrap();
                    store.put(&grant, &request).unwrap();
                }
            }));
        }
        for worker in workers {
            worker.join().unwrap();
        }
        let store = PermissionStore::open(&path).unwrap();
        for worker in 0..4 {
            for offset in 0..250 {
                let request = request_with_id(&format!("tool-{worker}-{offset}"));
                assert!(store.get(&request).unwrap().is_some());
            }
        }
    }
}
