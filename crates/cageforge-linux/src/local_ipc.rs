// SPDX-License-Identifier: Apache-2.0

//! Bounded local-IPC policy transport and Linux pathname matching.

use std::collections::BTreeSet;
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use cageforge_policy::{DomainAccess, NetworkMode, UnixSocketMode};
use cageforge_policy_compose::EffectiveSandbox;
use thiserror::Error;

use crate::helper_protocol::{
    LOCAL_IPC_DEFAULT_ALLOW, LOCAL_IPC_DEFAULT_DENY, LOCAL_IPC_MAGIC, LOCAL_IPC_MAX_PATH_BYTES,
    LOCAL_IPC_MAX_RULES,
};

/// Linux's `sun_path` contains at most 108 bytes including the terminating NUL.
pub(crate) const LINUX_SUN_PATH_BYTES: usize = 107;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LocalIpcPolicy {
    pub(crate) default_allow: bool,
    pub(crate) allowed: Vec<Vec<u8>>,
    pub(crate) denied: Vec<Vec<u8>>,
}

/// Typed failures in the bounded local-IPC helper frame.
#[derive(Debug, Error)]
pub enum LocalIpcFrameError {
    /// A frame read or write failed.
    #[error("local IPC frame I/O failed while {operation}: {source}")]
    Io {
        /// Frame operation being performed.
        ///
        /// This is an internal diagnostic label and is not parsed by callers.
        #[allow(dead_code)]
        operation: &'static str,
        /// Underlying stream failure.
        #[source]
        source: io::Error,
    },
    /// The frame marker was not recognized.
    #[error("local IPC frame magic did not match")]
    InvalidMagic,
    /// The frame default mode was not recognized.
    #[error("local IPC frame has unknown default mode {mode}")]
    InvalidDefaultMode {
        /// Unknown wire value.
        mode: u8,
    },
    /// The frame contained more rules than the bounded protocol allows.
    #[error("local IPC frame contains {count} rules, exceeding {maximum}")]
    RuleLimitExceeded {
        /// Number of received rules.
        count: usize,
        /// Maximum accepted rules.
        maximum: usize,
    },
    /// A pathname exceeded the native Linux socket-address limit.
    #[error("local IPC path is {length} bytes, exceeding {maximum}")]
    PathLengthExceeded {
        /// Number of bytes in the path.
        length: usize,
        /// Maximum accepted path length.
        maximum: usize,
    },
    /// A pathname contained an embedded NUL byte.
    #[error("local IPC path contains NUL")]
    PathContainsNul,
    /// The same endpoint occurred in both allow and deny sets.
    #[error("local IPC frame contains a duplicate path")]
    DuplicatePath,
    /// A pathname was empty.
    #[error("local IPC frame contains an empty path")]
    EmptyPath,
    /// A pathname was not rooted at `/`.
    #[error("local IPC frame contains a non-absolute path")]
    PathNotAbsolute,
}

impl LocalIpcPolicy {
    pub(crate) fn from_sandbox(
        sandbox: &EffectiveSandbox,
    ) -> Result<Option<Self>, LocalIpcFrameError> {
        let requirements = sandbox.network().requirements();
        if !requirements.local_ipc_rules() && !requirements.local_ipc_deny_rules() {
            return Ok(None);
        }

        let mut default_allow = true;
        let mut allowed: Option<BTreeSet<Vec<u8>>> = None;
        let mut denied = BTreeSet::new();

        for layer in sandbox.network().lowering().layers() {
            if layer.mode() != NetworkMode::Enabled {
                default_allow = false;
                allowed = Some(BTreeSet::new());
                continue;
            }
            match layer.unix_socket_mode() {
                UnixSocketMode::Disabled => {
                    default_allow = false;
                    allowed = Some(BTreeSet::new());
                }
                UnixSocketMode::Restricted => {
                    default_allow = false;
                    let layer_allowed = layer
                        .unix_sockets()
                        .iter()
                        .filter(|rule| rule.access() == DomainAccess::Allow)
                        .map(|rule| path_bytes(rule.path()))
                        .collect::<Result<BTreeSet<_>, _>>()?;
                    allowed = Some(match allowed.take() {
                        Some(previous) => previous.intersection(&layer_allowed).cloned().collect(),
                        None => layer_allowed,
                    });
                }
                UnixSocketMode::Enabled => {
                    for rule in layer
                        .unix_sockets()
                        .iter()
                        .filter(|rule| rule.access() == DomainAccess::Deny)
                    {
                        denied.insert(path_bytes(rule.path())?);
                    }
                }
            }
        }

        let denied_paths = denied;
        let allowed = allowed
            .unwrap_or_default()
            .into_iter()
            .filter(|path| !denied_paths.contains(path))
            .collect();
        let denied = denied_paths.into_iter().collect();
        let policy = Self {
            default_allow,
            allowed,
            denied,
        };
        policy.validate()?;
        Ok(Some(policy))
    }

    pub(crate) fn validate(&self) -> Result<(), LocalIpcFrameError> {
        let total = self.allowed.len().checked_add(self.denied.len()).ok_or(
            LocalIpcFrameError::RuleLimitExceeded {
                count: usize::MAX,
                maximum: LOCAL_IPC_MAX_RULES,
            },
        )?;
        if total > LOCAL_IPC_MAX_RULES {
            return Err(LocalIpcFrameError::RuleLimitExceeded {
                count: total,
                maximum: LOCAL_IPC_MAX_RULES,
            });
        }
        let mut paths = BTreeSet::new();
        for path in self.allowed.iter().chain(&self.denied) {
            validate_path_bytes(path)?;
            if !paths.insert(path) {
                return Err(LocalIpcFrameError::DuplicatePath);
            }
        }
        Ok(())
    }

    pub(crate) fn allows(&self, path: &[u8]) -> bool {
        if self.allowed.iter().any(|candidate| candidate == path) {
            return true;
        }
        self.default_allow && !self.denied.iter().any(|candidate| candidate == path)
    }
}

pub(crate) fn write_frame(
    writer: &mut impl Write,
    policy: &LocalIpcPolicy,
) -> Result<(), LocalIpcFrameError> {
    policy.validate()?;
    writer
        .write_all(LOCAL_IPC_MAGIC)
        .and_then(|()| {
            writer.write_all(&[if policy.default_allow {
                LOCAL_IPC_DEFAULT_ALLOW
            } else {
                LOCAL_IPC_DEFAULT_DENY
            }])
        })
        .map_err(|source| LocalIpcFrameError::Io {
            operation: "writing header",
            source,
        })?;
    write_rules(writer, &policy.allowed)?;
    write_rules(writer, &policy.denied)
}

pub(crate) fn read_frame(reader: &mut impl Read) -> Result<LocalIpcPolicy, LocalIpcFrameError> {
    let mut magic = [0; LOCAL_IPC_MAGIC.len()];
    reader
        .read_exact(&mut magic)
        .map_err(|source| LocalIpcFrameError::Io {
            operation: "reading magic",
            source,
        })?;
    if magic != LOCAL_IPC_MAGIC {
        return Err(LocalIpcFrameError::InvalidMagic);
    }
    let mut mode = [0];
    reader
        .read_exact(&mut mode)
        .map_err(|source| LocalIpcFrameError::Io {
            operation: "reading default mode",
            source,
        })?;
    let default_allow = match mode[0] {
        LOCAL_IPC_DEFAULT_ALLOW => true,
        LOCAL_IPC_DEFAULT_DENY => false,
        mode => return Err(LocalIpcFrameError::InvalidDefaultMode { mode }),
    };
    let allowed = read_rules(reader)?;
    let denied = read_rules(reader)?;
    let policy = LocalIpcPolicy {
        default_allow,
        allowed,
        denied,
    };
    policy.validate()?;
    Ok(policy)
}

fn path_bytes(path: &Path) -> Result<Vec<u8>, LocalIpcFrameError> {
    let bytes = path.as_os_str().as_bytes();
    validate_path_bytes(bytes)?;
    Ok(bytes.to_vec())
}

fn validate_path_bytes(path: &[u8]) -> Result<(), LocalIpcFrameError> {
    if path.is_empty() {
        return Err(LocalIpcFrameError::EmptyPath);
    }
    if path.contains(&0) {
        return Err(LocalIpcFrameError::PathContainsNul);
    }
    if path[0] != b'/' {
        return Err(LocalIpcFrameError::PathNotAbsolute);
    }
    if path.len() > LOCAL_IPC_MAX_PATH_BYTES || path.len() > LINUX_SUN_PATH_BYTES {
        return Err(LocalIpcFrameError::PathLengthExceeded {
            length: path.len(),
            maximum: LOCAL_IPC_MAX_PATH_BYTES.min(LINUX_SUN_PATH_BYTES),
        });
    }
    Ok(())
}

fn write_rules(writer: &mut impl Write, paths: &[Vec<u8>]) -> Result<(), LocalIpcFrameError> {
    let count = u32::try_from(paths.len()).map_err(|_| LocalIpcFrameError::RuleLimitExceeded {
        count: paths.len(),
        maximum: LOCAL_IPC_MAX_RULES,
    })?;
    writer
        .write_all(&count.to_be_bytes())
        .map_err(|source| LocalIpcFrameError::Io {
            operation: "writing rule count",
            source,
        })?;
    for path in paths {
        let length =
            u16::try_from(path.len()).map_err(|_| LocalIpcFrameError::PathLengthExceeded {
                length: path.len(),
                maximum: LOCAL_IPC_MAX_PATH_BYTES,
            })?;
        writer
            .write_all(&length.to_be_bytes())
            .and_then(|()| writer.write_all(path))
            .map_err(|source| LocalIpcFrameError::Io {
                operation: "writing rule",
                source,
            })?;
    }
    Ok(())
}

fn read_rules(reader: &mut impl Read) -> Result<Vec<Vec<u8>>, LocalIpcFrameError> {
    let mut count = [0; 4];
    reader
        .read_exact(&mut count)
        .map_err(|source| LocalIpcFrameError::Io {
            operation: "reading rule count",
            source,
        })?;
    let count = u32::from_be_bytes(count) as usize;
    if count > LOCAL_IPC_MAX_RULES {
        return Err(LocalIpcFrameError::RuleLimitExceeded {
            count,
            maximum: LOCAL_IPC_MAX_RULES,
        });
    }
    let mut paths = Vec::with_capacity(count);
    for _ in 0..count {
        let mut length = [0; 2];
        reader
            .read_exact(&mut length)
            .map_err(|source| LocalIpcFrameError::Io {
                operation: "reading rule length",
                source,
            })?;
        let length = u16::from_be_bytes(length) as usize;
        if length > LOCAL_IPC_MAX_PATH_BYTES.min(LINUX_SUN_PATH_BYTES) {
            return Err(LocalIpcFrameError::PathLengthExceeded {
                length,
                maximum: LOCAL_IPC_MAX_PATH_BYTES.min(LINUX_SUN_PATH_BYTES),
            });
        }
        let mut path = vec![0; length];
        reader
            .read_exact(&mut path)
            .map_err(|source| LocalIpcFrameError::Io {
                operation: "reading rule",
                source,
            })?;
        validate_path_bytes(&path)?;
        paths.push(path);
    }
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_round_trip_preserves_exact_path_bytes() {
        let policy = LocalIpcPolicy {
            default_allow: false,
            allowed: vec![b"/run/allowed.sock".to_vec()],
            denied: vec![b"/run/denied.sock".to_vec()],
        };
        let mut frame = Vec::new();
        write_frame(&mut frame, &policy).expect("write frame");
        assert_eq!(
            read_frame(&mut frame.as_slice()).expect("read frame"),
            policy
        );
    }

    #[test]
    fn frame_rejects_duplicate_paths_across_modes() {
        let policy = LocalIpcPolicy {
            default_allow: true,
            allowed: vec![b"/run/socket".to_vec()],
            denied: vec![b"/run/socket".to_vec()],
        };
        assert!(matches!(
            policy.validate(),
            Err(LocalIpcFrameError::DuplicatePath)
        ));
    }

    #[test]
    fn frame_rejects_invalid_magic_before_reading_rules() {
        let mut frame = b"BADIPC".as_slice();
        assert!(matches!(
            read_frame(&mut frame),
            Err(LocalIpcFrameError::InvalidMagic)
        ));
    }

    #[test]
    fn frame_rejects_non_absolute_paths() {
        let policy = LocalIpcPolicy {
            default_allow: false,
            allowed: vec![b"relative.sock".to_vec()],
            denied: Vec::new(),
        };
        assert!(matches!(
            policy.validate(),
            Err(LocalIpcFrameError::PathNotAbsolute)
        ));
    }
}
