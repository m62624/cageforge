// SPDX-License-Identifier: Apache-2.0

//! Effective filesystem lowering for macOS Seatbelt.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path, PathBuf};

use cageforge_backend_api::{PreparedBackendRequest, SandboxBackend};
use cageforge_path::{NativePathKey, is_within, normalize_lexical_path};
use cageforge_policy::{AccessMode, FilesystemDecision, FilesystemMode, FilesystemTarget};
use cageforge_policy_compose::{EffectiveFilesystemLayer, EffectivePathContext};

use crate::error::MacosFilesystemError;

/// Filesystem rules lowered into one immutable Seatbelt launch plan.
#[derive(Debug, Default)]
pub(crate) struct MacosFilesystemPlan {
    pub(crate) read_roots: Vec<PathBuf>,
    pub(crate) write_roots: Vec<PathBuf>,
    pub(crate) denied_paths: Vec<PathBuf>,
    pub(crate) write_denied_paths: Vec<PathBuf>,
    pub(crate) denied_globs: Vec<String>,
    pub(crate) unrestricted: bool,
}

/// Collects both policy layers before the native profile is rendered.
struct FilesystemCollector<'scope, 'request, B: SandboxBackend> {
    backend: &'scope B,
    prepared: &'scope PreparedBackendRequest<'request, B>,
    context: &'scope EffectivePathContext,
    read_roots: BTreeSet<NativePathKey>,
    write_roots: BTreeSet<NativePathKey>,
    denied_paths: BTreeSet<NativePathKey>,
    write_denied_paths: BTreeSet<NativePathKey>,
    paths: Vec<PathBuf>,
    denied_globs: BTreeSet<String>,
    protected_relative_paths: Vec<PathBuf>,
}

impl MacosFilesystemPlan {
    /// Lowers every effective filesystem layer into concrete Seatbelt inputs.
    pub(crate) fn lower<'request, B: SandboxBackend>(
        backend: &B,
        prepared: &PreparedBackendRequest<'request, B>,
    ) -> Result<Self, MacosFilesystemError> {
        let sandbox = prepared.sandbox(backend)?;
        let mode = sandbox.filesystem().requirements().mode();
        if mode == FilesystemMode::External {
            return Err(MacosFilesystemError::ExternalOwnership);
        }

        let context = prepared.path_context(backend)?;
        let lowering = prepared.filesystem_lowering(backend)?;
        let mut collector = FilesystemCollector::new(backend, prepared, context);
        for layer in lowering.layers() {
            collector.collect_layer(layer)?;
        }
        collector.apply_protected_paths();

        let mut plan = collector.finish();
        plan.unrestricted = mode == FilesystemMode::Unrestricted;
        Ok(plan)
    }

    pub(crate) fn read_roots(&self) -> &[PathBuf] {
        &self.read_roots
    }

    pub(crate) fn write_roots(&self) -> &[PathBuf] {
        &self.write_roots
    }

    pub(crate) fn denied_paths(&self) -> &[PathBuf] {
        &self.denied_paths
    }

    pub(crate) fn write_denied_paths(&self) -> &[PathBuf] {
        &self.write_denied_paths
    }

    pub(crate) fn denied_globs(&self) -> &[String] {
        &self.denied_globs
    }

    pub(crate) const fn unrestricted(&self) -> bool {
        self.unrestricted
    }
}

impl<'scope, 'request, B: SandboxBackend> FilesystemCollector<'scope, 'request, B> {
    fn new(
        backend: &'scope B,
        prepared: &'scope PreparedBackendRequest<'request, B>,
        context: &'scope EffectivePathContext,
    ) -> Self {
        Self {
            backend,
            prepared,
            context,
            read_roots: BTreeSet::new(),
            write_roots: BTreeSet::new(),
            denied_paths: BTreeSet::new(),
            write_denied_paths: BTreeSet::new(),
            paths: Vec::new(),
            denied_globs: BTreeSet::new(),
            protected_relative_paths: Vec::new(),
        }
    }

    fn collect_layer(
        &mut self,
        layer: EffectiveFilesystemLayer<'_>,
    ) -> Result<(), MacosFilesystemError> {
        if layer.mode() == FilesystemMode::External {
            return Err(MacosFilesystemError::ExternalOwnership);
        }

        for rule in layer.entries() {
            match rule.target() {
                FilesystemTarget::Scope(selector) => {
                    for policy_path in self.context.resolve(selector) {
                        let decision = self
                            .prepared
                            .filesystem_access_for_path(self.backend, &policy_path)?;
                        let native_path =
                            self.validate_concrete_path(policy_path, rule.missing_path_behavior())?;
                        let Some(native_path) = native_path else {
                            continue;
                        };
                        match decision {
                            FilesystemDecision::Read => self.insert_read(native_path.clone()),
                            FilesystemDecision::Write => {
                                self.insert_write(native_path.clone());
                                self.collect_read_only_subpaths(
                                    &native_path,
                                    rule.read_only_subpaths(),
                                )?;
                            }
                            FilesystemDecision::Deny => self.insert_denied(native_path),
                            FilesystemDecision::ExternallyEnforced => {
                                return Err(MacosFilesystemError::ExternalOwnership);
                            }
                        }
                    }
                }
                FilesystemTarget::Glob(pattern) => {
                    if rule.access() != AccessMode::Deny {
                        return Err(MacosFilesystemError::NonDenyGlob {
                            pattern: pattern.as_str().to_owned(),
                        });
                    }
                    self.collect_glob(pattern.as_str(), pattern.is_absolute());
                }
            }
        }

        self.protected_relative_paths
            .extend(layer.protected_relative_paths().iter().cloned());
        Ok(())
    }

    fn apply_protected_paths(&mut self) {
        let roots: Vec<PathBuf> = self
            .paths
            .iter()
            .filter(|root| self.write_roots.contains(&NativePathKey::new(root)))
            .cloned()
            .collect();
        let protected = self.protected_relative_paths.clone();
        for root in roots {
            for relative in &protected {
                self.insert_denied(root.join(relative));
            }
        }
    }

    fn collect_read_only_subpaths(
        &mut self,
        write_root: &Path,
        selectors: &[cageforge_policy::PathSelector],
    ) -> Result<(), MacosFilesystemError> {
        for selector in selectors {
            for path in self.context.resolve(selector) {
                let native_path = normalize_macos_system_alias(path);
                if !is_within(&native_path, write_root) {
                    return Err(MacosFilesystemError::ReadOnlyOutsideRoot {
                        path: native_path,
                        root: write_root.to_path_buf(),
                    });
                }
                if self.contains_symlink(&native_path)? {
                    return Err(MacosFilesystemError::Symlink { path: native_path });
                }
                self.insert_write_denied(native_path);
            }
        }
        Ok(())
    }

    fn collect_glob(&mut self, pattern: &str, absolute: bool) {
        if absolute {
            let pattern = normalize_macos_system_alias(PathBuf::from(pattern))
                .to_string_lossy()
                .into_owned();
            self.insert_denied_glob(pattern);
        } else {
            for root in self.context.workspace_roots() {
                let root = normalize_macos_system_alias(root.clone());
                let joined = if pattern.is_empty() {
                    root.to_string_lossy().into_owned()
                } else {
                    root.join(pattern).to_string_lossy().into_owned()
                };
                self.insert_denied_glob(joined);
            }
        }
    }

    fn insert_denied_glob(&mut self, pattern: String) {
        self.denied_globs.insert(pattern.clone());
        if let Some(canonical) = canonicalize_glob_static_prefix(&pattern) {
            self.denied_globs.insert(canonical);
        }
    }

    fn validate_concrete_path(
        &self,
        path: PathBuf,
        missing: cageforge_policy::MissingPathBehavior,
    ) -> Result<Option<PathBuf>, MacosFilesystemError> {
        let path = normalize_macos_system_alias(path);
        if !path.is_absolute() || contains_parent_component(&path) {
            return Err(MacosFilesystemError::InvalidScope { path });
        }
        let Some(existing) = self.first_missing_component(&path)? else {
            let canonical =
                fs::canonicalize(&path).map_err(|source| MacosFilesystemError::Metadata {
                    path: path.clone(),
                    source,
                })?;
            return Ok(Some(normalize_lexical_path(&canonical).into_owned()));
        };
        if existing == path {
            return match missing {
                cageforge_policy::MissingPathBehavior::Error => {
                    Err(MacosFilesystemError::RequiredPathMissing { path })
                }
                cageforge_policy::MissingPathBehavior::Skip => Ok(None),
            };
        }
        match missing {
            cageforge_policy::MissingPathBehavior::Error => {
                Err(MacosFilesystemError::RequiredPathMissing { path })
            }
            cageforge_policy::MissingPathBehavior::Skip => Ok(None),
        }
    }

    fn first_missing_component(
        &self,
        path: &Path,
    ) -> Result<Option<PathBuf>, MacosFilesystemError> {
        let mut current = PathBuf::from("/");
        for component in path.components() {
            let Component::Normal(value) = component else {
                continue;
            };
            current.push(value);
            match fs::symlink_metadata(&current) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err(MacosFilesystemError::Symlink { path: current });
                }
                Ok(_) => {}
                Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(Some(path.to_path_buf()));
                }
                Err(source) => {
                    return Err(MacosFilesystemError::Metadata {
                        path: current,
                        source,
                    });
                }
            }
        }
        Ok(None)
    }

    fn contains_symlink(&self, path: &Path) -> Result<bool, MacosFilesystemError> {
        let mut current = PathBuf::from("/");
        for component in path.components() {
            let Component::Normal(value) = component else {
                continue;
            };
            current.push(value);
            match fs::symlink_metadata(&current) {
                Ok(metadata) if metadata.file_type().is_symlink() => return Ok(true),
                Ok(_) => {}
                Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(false),
                Err(source) => {
                    return Err(MacosFilesystemError::Metadata {
                        path: current,
                        source,
                    });
                }
            }
        }
        Ok(false)
    }

    fn insert_read(&mut self, path: PathBuf) {
        let key = NativePathKey::new(&path);
        self.read_roots.insert(key);
        self.paths.push(path);
    }

    fn insert_write(&mut self, path: PathBuf) {
        let key = NativePathKey::new(&path);
        self.write_roots.insert(key.clone());
        self.read_roots.insert(key);
        self.paths.push(path);
    }

    fn insert_denied(&mut self, path: PathBuf) {
        self.denied_paths.insert(NativePathKey::new(&path));
        self.paths.push(path);
    }

    fn insert_write_denied(&mut self, path: PathBuf) {
        self.write_denied_paths.insert(NativePathKey::new(&path));
        self.paths.push(path);
    }

    fn finish(self) -> MacosFilesystemPlan {
        let mut paths = self.paths;
        paths.sort_by(|left, right| NativePathKey::new(left).cmp(&NativePathKey::new(right)));
        paths.dedup_by(|left, right| NativePathKey::new(left) == NativePathKey::new(right));
        let to_paths = |keys: BTreeSet<NativePathKey>| {
            keys.into_iter()
                .filter_map(|key| paths.iter().find(|path| NativePathKey::new(path) == key))
                .cloned()
                .collect()
        };
        MacosFilesystemPlan {
            read_roots: to_paths(self.read_roots),
            write_roots: to_paths(self.write_roots),
            denied_paths: to_paths(self.denied_paths),
            write_denied_paths: to_paths(self.write_denied_paths),
            denied_globs: self.denied_globs.into_iter().collect(),
            unrestricted: false,
        }
    }
}

fn normalize_macos_system_alias(path: PathBuf) -> PathBuf {
    for (alias, canonical) in [
        ("/bin", "/usr/bin"),
        ("/sbin", "/usr/sbin"),
        ("/lib", "/usr/lib"),
        ("/var", "/private/var"),
        ("/tmp", "/private/tmp"),
        ("/etc", "/private/etc"),
    ] {
        if path == Path::new(alias) {
            return PathBuf::from(canonical);
        }
        if let Ok(relative) = path.strip_prefix(alias) {
            return Path::new(canonical).join(relative);
        }
    }
    path
}

fn contains_parent_component(path: &Path) -> bool {
    path.components()
        .any(|component| component == Component::ParentDir)
}

fn canonicalize_glob_static_prefix(pattern: &str) -> Option<String> {
    let first_glob_index = pattern
        .char_indices()
        .find_map(|(index, character)| matches!(character, '*' | '?' | '[' | ']').then_some(index));
    let Some(first_glob_index) = first_glob_index else {
        let canonical = fs::canonicalize(pattern).ok()?;
        let canonical = normalize_macos_system_alias(canonical)
            .to_string_lossy()
            .into_owned();
        return (canonical != pattern).then_some(canonical);
    };

    let static_prefix = &pattern[..first_glob_index];
    let prefix_end = if static_prefix.ends_with('/') {
        static_prefix.len() - 1
    } else {
        static_prefix.rfind('/').unwrap_or(0)
    };
    if prefix_end == 0 {
        return None;
    }

    let canonical_root = fs::canonicalize(&pattern[..prefix_end]).ok()?;
    let canonical_root = normalize_macos_system_alias(canonical_root)
        .to_string_lossy()
        .into_owned();
    let normalized = format!("{canonical_root}{}", &pattern[prefix_end..]);
    (normalized != pattern).then_some(normalized)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use tempfile::TempDir;

    use super::canonicalize_glob_static_prefix;

    #[test]
    fn canonicalizes_a_glob_static_prefix_through_a_symlink() {
        let root = TempDir::new().expect("root");
        let target = TempDir::new().expect("target");
        let link = root.path().join("link");
        symlink(target.path(), &link).expect("symlink");
        let pattern = format!("{}/**/*.secret", link.display());

        let canonical = canonicalize_glob_static_prefix(&pattern).expect("canonical pattern");
        assert_eq!(
            canonical,
            format!(
                "{}/**/*.secret",
                target
                    .path()
                    .canonicalize()
                    .expect("canonicalize target")
                    .display()
            )
        );
    }
}
