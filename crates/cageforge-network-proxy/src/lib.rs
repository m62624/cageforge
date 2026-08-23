// SPDX-License-Identifier: Apache-2.0

//! Validated outbound gateway settings and an optional policy-enforcing
//! HTTP/SOCKS runtime for native Cageforge backends.
//!
//! [`GatewayConfig`] and [`GatewayConfigError`] remain available without
//! default features for configuration-only consumers.

#![cfg_attr(
    feature = "runtime",
    doc = "A native backend obtains an [`EffectiveNetworkPolicy`](cageforge_policy_compose::EffectiveNetworkPolicy) from its prepared request, constructs a [`NetworkGateway`], and passes only authenticated private ingress streams to [`NetworkGateway::serve_connection`]. Every outbound connection is resolved once and checked immediately before the exact socket operation."
)]
#![cfg_attr(feature = "runtime", doc = include_str!("../README.md"))]
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
