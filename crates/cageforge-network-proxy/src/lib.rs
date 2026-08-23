// SPDX-License-Identifier: Apache-2.0

//! Shared policy-enforcing outbound gateway for native Cageforge backends.
//!
//! A native backend obtains an [`EffectiveNetworkPolicy`] from its prepared
//! request, constructs a [`NetworkGateway`], and passes only authenticated
//! private ingress streams to [`NetworkGateway::serve_connection`]. Every
//! outbound connection is resolved once and checked immediately before the
//! exact socket operation.
//!
//! [`EffectiveNetworkPolicy`]: cageforge_policy_compose::EffectiveNetworkPolicy

#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

mod config;

#[cfg(feature = "runtime")]
mod authentication;
#[cfg(feature = "runtime")]
mod authority;
#[cfg(feature = "runtime")]
mod body;
#[cfg(feature = "runtime")]
mod connect;
#[cfg(feature = "runtime")]
mod error;
#[cfg(feature = "runtime")]
mod gateway;
#[cfg(feature = "runtime")]
mod http;
#[cfg(feature = "runtime")]
mod relay;
#[cfg(feature = "runtime")]
mod resolver;
#[cfg(feature = "runtime")]
mod socks5;

#[cfg(feature = "runtime")]
pub use authentication::GatewayIngressKey;
pub use config::{GatewayConfig, GatewayConfigError};
#[cfg(feature = "runtime")]
pub use error::{GatewayError, UnsupportedNetworkRequirement};
#[cfg(feature = "runtime")]
pub use gateway::NetworkGateway;
#[cfg(feature = "runtime")]
pub use resolver::{NetworkResolver, SystemResolver};
