// Copyright 2026 Mansur Azatbek
// SPDX-License-Identifier: Apache-2.0

//! Safe, platform-neutral composition of sandbox policy constraints.
//!
//! The crate computes the effective decision as the intersection of a
//! requested policy and a [`PolicyCeiling`]. It deliberately does not select
//! a backend, inspect an operating system, start a process, or decide whether
//! a native backend supports a particular rule. The result keeps both policy
//! sides available so a later backend can compile the same constraint without
//! accidentally widening it.

#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

mod compose;
mod error;
mod model;

pub use compose::compose;
pub use error::{CompositionBoundary, CompositionError};
pub use model::{
    CompositionRequest, EffectiveEnvironment, EffectiveFilesystemPolicy, EffectiveNetworkPolicy,
    EffectiveSandbox, PolicyCeiling,
};
