// Copyright 2026 Mansur Azatbek
// SPDX-License-Identifier: Apache-2.0

//! Platform-independent policy types for Cageforge.
//!
//! This crate describes and resolves the access a sandbox must provide. It does
//! not parse configuration files, launch processes, or call an operating-system
//! sandbox API. Platform backends consume the resolved [`SandboxPolicy`].

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
pub use network::NetworkDecision;
pub use network::NetworkMode;
pub use network::NetworkPolicy;
pub use network::UnixSocketMode;
pub use network::UnixSocketRule;
pub use path::PathPattern;
pub use path::PathSelector;
pub use policy::SandboxPolicy;
