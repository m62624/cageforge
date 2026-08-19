// SPDX-License-Identifier: Apache-2.0

//! Platform-independent policy types for Cageforge.
//!
//! This crate describes and resolves the access a sandbox must provide. It does
//! not parse configuration files, launch processes, or call an operating-system
//! sandbox API. Platform backends consume the resolved [`SandboxPolicy`].
//!
//! # Reading this crate
//!
//! Start with [`SandboxPolicy`] for the combined request. Follow its
//! [`FilesystemPolicy`] and [`NetworkPolicy`] fields into the two independent
//! boundary models. Filesystem selectors use [`PathSelector`] and resolve
//! through [`PathResolutionContext`]; network connections use
//! [`ResolvedNetworkTarget`] and [`ConnectionAuthorization`]. All invalid
//! construction and evaluation states use [`PolicyError`].
//!
//! The crate is intentionally a value-and-decision layer. A native backend
//! owns filesystem I/O, DNS, exact connection execution, and operating-system
//! enforcement.

#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

mod access;
mod context;
mod error;
mod filesystem;
mod network;
mod path;
mod policy;

pub use access::AccessMode;
pub use access::FilesystemDecision;
pub use context::PathResolutionContext;
pub use error::PolicyError;
pub use filesystem::FilesystemMode;
pub use filesystem::FilesystemPolicy;
pub use filesystem::FilesystemRule;
pub use filesystem::FilesystemTarget;
pub use filesystem::MissingPathBehavior;
pub use network::DomainAccess;
pub use network::DomainMode;
pub use network::DomainRule;
pub use network::LocalNetworkAccess;
pub use network::NetworkMode;
pub use network::NetworkPolicy;
pub use network::ResolvedNetworkTarget;
pub use network::UnixSocketMode;
pub use network::UnixSocketRule;
pub use network::{AuthorizedSocketAddr, ConnectionAuthorization, NetworkDecision};
pub use path::PathPattern;
pub use path::PathSelector;
pub use policy::SandboxPolicy;
