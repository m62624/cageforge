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

#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

mod compose;
mod context;
mod environment;
mod error;
mod filesystem;
mod model;
mod ownership;

pub use compose::compose;
pub use context::EffectivePathContext;
pub use environment::{CoreEnvironment, EffectiveEnvironment, EnvironmentInput};
pub use error::{CompositionBoundary, CompositionError};
pub use filesystem::EffectiveFilesystemPolicy;
pub use model::{CompositionRequest, EffectiveNetworkPolicy, EffectiveSandbox, PolicyCeiling};
pub use ownership::ExternalOwner;
