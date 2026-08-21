// SPDX-License-Identifier: Apache-2.0

//! Safe, platform-neutral composition of sandbox policy constraints.
//!
//! The crate computes the effective decision as the intersection of a
//! requested policy and a [`PolicyCeiling`]. It deliberately does not select
//! a backend, inspect an operating system, start a process, or decide whether
//! a native backend supports a particular rule. The result keeps both policy
//! sides available so a later backend can compile the same constraint without
//! accidentally widening it. Network backends should use the resolved-target
//! methods and verify the exact address immediately before connecting.
//!
//! # Reading this crate
//!
//! Start with [`CompositionRequest`] and [`PolicyCeiling`], call [`compose`],
//! and pass the resulting [`EffectiveSandbox`] to the execution integration.
//! Use [`EffectiveSandbox::path_context`] for filesystem selectors,
//! [`EffectiveFilesystemPolicy`] for filesystem decisions,
//! [`EffectiveNetworkPolicy`] for exact-address network authorization, and
//! [`EffectiveEnvironment`] for the narrowed environment transformation.
//! [`ExternalOwner`] is only an identity token for matching external-boundary
//! declarations; it is not proof of native enforcement.

#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

mod compose;
mod context;
mod environment;
mod error;
mod filesystem;
mod model;
mod ownership;

pub use cageforge_command::{CoreEnvironment, EnvironmentInput};
pub use compose::compose;
pub use context::EffectivePathContext;
pub use environment::EffectiveEnvironment;
pub use error::{CompositionBoundary, CompositionError};
pub use filesystem::EffectiveFilesystemPolicy;
pub use model::{CompositionRequest, EffectiveNetworkPolicy, EffectiveSandbox, PolicyCeiling};
pub use ownership::ExternalOwner;
