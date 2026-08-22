// SPDX-License-Identifier: Apache-2.0

//! Safe, platform-neutral composition of sandbox policy constraints.
//!
//! The crate computes the effective decision as the intersection of a
//! requested policy and a [`PolicyCeiling`]. It deliberately does not select
//! a backend, inspect an operating system, start a process, or decide whether
//! a native backend supports a particular rule. The result keeps both policy
//! sides internally, exposes combined decisions and aggregate requirements,
//! and provides immutable lowering views containing every constraint layer. A
//! later backend must enforce all layers together and cannot accidentally
//! widen the result by selecting one side. Network backends should use the
//! resolved-target methods and verify the exact address immediately before
//! connecting.
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
mod lowering;
mod model;
mod ownership;

pub use cageforge_command::{CoreEnvironment, EnvironmentInput};
pub use compose::compose;
pub use context::EffectivePathContext;
pub use environment::{EffectiveEnvironment, EffectiveEnvironmentRequirements};
pub use error::{CompositionBoundary, CompositionError};
pub use filesystem::{EffectiveFilesystemPolicy, EffectiveFilesystemRequirements};
pub use lowering::{
    EffectiveFilesystemLayer, EffectiveFilesystemLowering, EffectiveNetworkLayer,
    EffectiveNetworkLowering,
};
pub use model::{
    CompositionRequest, EffectiveNetworkPolicy, EffectiveNetworkRequirements, EffectiveSandbox,
    PolicyCeiling,
};
pub use ownership::ExternalOwner;
