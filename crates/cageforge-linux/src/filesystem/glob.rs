// SPDX-License-Identifier: Apache-2.0

//! Native expansion of validated deny-globs into concrete mount targets.

use std::collections::BTreeMap;
use std::fs;
use std::num::NonZeroUsize;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use cageforge_policy::PathPattern;
use cageforge_policy_compose::EffectivePathContext;

use crate::error::LinuxBackendError;

const MAX_GLOB_MATCHES: usize = 8_192;
const MAX_GLOB_SCAN_ENTRIES: usize = 100_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
}

struct GlobScanner<'a> {
    pattern: &'a PathPattern,
    context: &'a EffectivePathContext,
    max_depth: Option<usize>,
    matches: BTreeMap<PathBuf, bool>,
    entries: usize,
    ancestors: Vec<DirectoryIdentity>,
}

impl DirectoryIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

impl GlobScanner<'_> {
    fn collect(
        &mut self,
        path: &Path,
        metadata: &fs::Metadata,
        depth: usize,
    ) -> Result<(), LinuxBackendError> {
        if pattern_matches_at_depth(self.pattern, self.context, path, depth, self.max_depth) {
            insert_match(self.pattern, path, &mut self.matches)?;
        }
        if !metadata.is_dir() || self.max_depth.is_some_and(|maximum| depth >= maximum) {
            return Ok(());
        }

        let identity = DirectoryIdentity::from_metadata(metadata);
        if self.ancestors.contains(&identity) {
            return Ok(());
        }
        self.ancestors.push(identity);

        let entries = fs::read_dir(path).map_err(|source| LinuxBackendError::GlobScanFailed {
            pattern: self.pattern.as_str().to_string(),
            path: path.to_path_buf(),
            source,
        })?;
        for entry in entries {
            self.entries += 1;
            if self.entries > MAX_GLOB_SCAN_ENTRIES {
                return Err(LinuxBackendError::GlobScanEntryLimitExceeded {
                    pattern: self.pattern.as_str().to_string(),
                    limit: MAX_GLOB_SCAN_ENTRIES,
                });
            }
            let entry = entry.map_err(|source| LinuxBackendError::GlobScanFailed {
                pattern: self.pattern.as_str().to_string(),
                path: path.to_path_buf(),
                source,
            })?;
            let child = entry.path();
            let file_type =
                entry
                    .file_type()
                    .map_err(|source| LinuxBackendError::GlobScanFailed {
                        pattern: self.pattern.as_str().to_string(),
                        path: child.clone(),
                        source,
                    })?;
            if self.context.pattern_matches(self.pattern, &child) {
                insert_match(self.pattern, &child, &mut self.matches)?;
            }
            let metadata = if file_type.is_symlink() {
                match fs::metadata(&child) {
                    Ok(metadata) => Some(metadata),
                    Err(source) if source.kind() == std::io::ErrorKind::NotFound => None,
                    Err(source) => {
                        return Err(LinuxBackendError::GlobScanFailed {
                            pattern: self.pattern.as_str().to_string(),
                            path: child,
                            source,
                        });
                    }
                }
            } else {
                Some(
                    entry
                        .metadata()
                        .map_err(|source| LinuxBackendError::GlobScanFailed {
                            pattern: self.pattern.as_str().to_string(),
                            path: child.clone(),
                            source,
                        })?,
                )
            };
            if let Some(metadata) = metadata.filter(fs::Metadata::is_dir) {
                self.collect(&child, &metadata, depth + 1)?;
            }
        }
        self.ancestors.pop();
        Ok(())
    }
}

pub(super) fn expand(
    pattern: &PathPattern,
    context: &EffectivePathContext,
    max_depth: Option<NonZeroUsize>,
) -> Result<BTreeMap<PathBuf, bool>, LinuxBackendError> {
    let mut scanner = GlobScanner {
        pattern,
        context,
        max_depth: max_depth.map(NonZeroUsize::get),
        matches: BTreeMap::new(),
        entries: 0,
        ancestors: Vec::new(),
    };
    for search_root in context.glob_search_roots(pattern) {
        if search_root.as_os_str().is_empty()
            || !search_root.is_absolute()
            || search_root == Path::new("/")
        {
            return Err(LinuxBackendError::UnsafeGlobScan {
                pattern: pattern.as_str().to_string(),
                search_root,
            });
        }
        let metadata = match fs::metadata(&search_root) {
            Ok(metadata) => metadata,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => continue,
            Err(source) => {
                return Err(LinuxBackendError::GlobScanFailed {
                    pattern: pattern.as_str().to_string(),
                    path: search_root,
                    source,
                });
            }
        };
        scanner.collect(&search_root, &metadata, 0)?;
    }
    Ok(scanner.matches)
}

fn pattern_matches_at_depth(
    pattern: &PathPattern,
    context: &EffectivePathContext,
    path: &Path,
    depth: usize,
    max_depth: Option<usize>,
) -> bool {
    max_depth.is_none_or(|maximum| depth <= maximum) && context.pattern_matches(pattern, path)
}

fn insert_match(
    pattern: &PathPattern,
    path: &Path,
    matches: &mut BTreeMap<PathBuf, bool>,
) -> Result<(), LinuxBackendError> {
    matches.insert(path.to_path_buf(), true);
    let canonical = fs::canonicalize(path).map_err(|source| LinuxBackendError::GlobScanFailed {
        pattern: pattern.as_str().to_string(),
        path: path.to_path_buf(),
        source,
    })?;
    matches.entry(canonical).or_insert(false);
    if matches.len() > MAX_GLOB_MATCHES {
        return Err(LinuxBackendError::GlobMatchLimitExceeded {
            pattern: pattern.as_str().to_string(),
            limit: MAX_GLOB_MATCHES,
        });
    }
    Ok(())
}
