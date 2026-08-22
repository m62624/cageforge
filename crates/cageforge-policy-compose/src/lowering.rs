// SPDX-License-Identifier: Apache-2.0

//! Immutable constraint views for native backend lowering.
//!
//! The effective decision APIs are sufficient for dynamic checks, but a
//! native backend also needs the concrete rules, protected paths, and matcher
//! settings from every constraint layer when it builds an operating-system
//! sandbox. These views expose all layers together without exposing a single
//! requested or ceiling policy as an interchangeable enforcement value.

use std::num::NonZeroUsize;

use cageforge_policy::{
    DomainMode, DomainRule, FilesystemMode, FilesystemPolicy, FilesystemRule, LocalNetworkAccess,
    NetworkMode, NetworkPolicy, UnixSocketMode, UnixSocketRule,
};

/// The complete filesystem constraint set required by one effective result.
///
/// Every layer returned by [`Self::layers`] is mandatory input to lowering.
/// A backend must enforce the conjunction of all layers; treating one layer
/// as an alternative policy would widen the effective result.
#[derive(Debug, Clone, Copy)]
pub struct EffectiveFilesystemLowering<'a> {
    layers: [&'a FilesystemPolicy; 2],
    glob_scan_max_depth: Option<NonZeroUsize>,
}

impl<'a> EffectiveFilesystemLowering<'a> {
    pub(crate) fn new(
        requested: &'a FilesystemPolicy,
        ceiling: &'a FilesystemPolicy,
        glob_scan_max_depth: Option<NonZeroUsize>,
    ) -> Self {
        Self {
            layers: [requested, ceiling],
            glob_scan_max_depth,
        }
    }

    /// Returns every filesystem constraint layer that must be enforced.
    ///
    /// The iterator always contains both composition inputs, including when
    /// one of them is unrestricted. It is intentionally the only way to
    /// inspect lowering rules, so callers receive the complete constraint set
    /// instead of choosing a requested or ceiling side through a public
    /// accessor.
    pub fn layers(&self) -> impl ExactSizeIterator<Item = EffectiveFilesystemLayer<'a>> + '_ {
        self.layers.into_iter().map(EffectiveFilesystemLayer::new)
    }

    /// Returns the conservative glob scan depth required by all layers.
    pub const fn glob_scan_max_depth(&self) -> Option<NonZeroUsize> {
        self.glob_scan_max_depth
    }
}

/// One immutable filesystem constraint layer in an effective lowering view.
#[derive(Debug, Clone, Copy)]
pub struct EffectiveFilesystemLayer<'a> {
    policy: &'a FilesystemPolicy,
}

impl<'a> EffectiveFilesystemLayer<'a> {
    fn new(policy: &'a FilesystemPolicy) -> Self {
        Self { policy }
    }

    /// Returns this layer's enforcement ownership mode.
    pub const fn mode(&self) -> FilesystemMode {
        self.policy.mode()
    }

    /// Returns all validated rules in this constraint layer.
    pub fn entries(&self) -> &[FilesystemRule] {
        self.policy.entries()
    }

    /// Returns the layer's configured glob scan depth.
    pub const fn glob_scan_max_depth(&self) -> Option<NonZeroUsize> {
        self.policy.glob_scan_max_depth()
    }

    /// Returns all protected relative paths in this constraint layer.
    pub fn protected_relative_paths(&self) -> &[std::path::PathBuf] {
        self.policy.protected_relative_paths()
    }
}

/// The complete network constraint set required by one effective result.
///
/// Every layer returned by [`Self::layers`] is mandatory input to lowering.
/// Runtime connections must still use the exact-target authorization methods
/// after lowering; these rules are not themselves socket authorization.
#[derive(Debug, Clone, Copy)]
pub struct EffectiveNetworkLowering<'a> {
    layers: [&'a NetworkPolicy; 2],
}

impl<'a> EffectiveNetworkLowering<'a> {
    pub(crate) fn new(requested: &'a NetworkPolicy, ceiling: &'a NetworkPolicy) -> Self {
        Self {
            layers: [requested, ceiling],
        }
    }

    /// Returns every network constraint layer that must be enforced.
    pub fn layers(&self) -> impl ExactSizeIterator<Item = EffectiveNetworkLayer<'a>> + '_ {
        self.layers.into_iter().map(EffectiveNetworkLayer::new)
    }
}

/// One immutable network constraint layer in an effective lowering view.
#[derive(Debug, Clone, Copy)]
pub struct EffectiveNetworkLayer<'a> {
    policy: &'a NetworkPolicy,
}

impl<'a> EffectiveNetworkLayer<'a> {
    fn new(policy: &'a NetworkPolicy) -> Self {
        Self { policy }
    }

    /// Returns this layer's enforcement ownership mode.
    pub const fn mode(&self) -> NetworkMode {
        self.policy.mode()
    }

    /// Returns the default behavior for unmatched domains.
    pub const fn domain_mode(&self) -> DomainMode {
        self.policy.domain_mode()
    }

    /// Returns the default behavior for unmatched Unix socket paths.
    pub const fn unix_socket_mode(&self) -> UnixSocketMode {
        self.policy.unix_socket_mode()
    }

    /// Returns the layer's local-address restriction mode.
    pub const fn local_network_access(&self) -> LocalNetworkAccess {
        self.policy.local_network_access()
    }

    /// Returns all validated domain rules in this constraint layer.
    pub fn domains(&self) -> &[DomainRule] {
        self.policy.domains()
    }

    /// Returns all validated Unix socket rules in this constraint layer.
    pub fn unix_sockets(&self) -> &[UnixSocketRule] {
        self.policy.unix_sockets()
    }
}
