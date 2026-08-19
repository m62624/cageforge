// SPDX-License-Identifier: Apache-2.0

//! Timeout intent for [`crate::CommandRequest`].
//!
//! This module does not own cancellation or process lifecycle. It only keeps
//! the requested timeout state available to the adapter.

use std::time::Duration;

/// Timeout intent for one command request.
///
/// The three variants preserve the distinction used by the execution
/// boundary: use the backend's configured default, impose an explicit limit,
/// or run without an automatic timeout. Cancellation is a separate lifecycle
/// concern and may still terminate a command in any variant.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TimeoutPolicy {
    /// Use the default timeout selected by the backend or resolved profile.
    #[default]
    BackendDefault,
    /// Terminate the command after the given duration.
    Limit(Duration),
    /// Do not apply an automatic timeout.
    Disabled,
}
