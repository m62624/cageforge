// SPDX-License-Identifier: Apache-2.0

//! Elevated-setup construction and inspection of capability state.

use crate::capability_state::{CAPABILITY_STATE_VERSION, CapabilityState, CapabilityStateError};

impl CapabilityState {
    pub(crate) fn fresh() -> Result<Self, CapabilityStateError> {
        let state = Self {
            version: CAPABILITY_STATE_VERSION,
            namespace_sid: random_namespace_sid()?,
            entries: Vec::new(),
            acl_objects: Vec::new(),
            pending_acl_mutation: None,
            materialized_objects: Vec::new(),
            pending_materialization: None,
            pending_materialization_removal: None,
        };
        state.validate()?;
        Ok(state)
    }

    pub(crate) fn filesystem_cleanup_complete(&self) -> bool {
        self.acl_objects.is_empty()
            && self.pending_acl_mutation.is_none()
            && self.materialized_objects.is_empty()
            && self.pending_materialization.is_none()
            && self.pending_materialization_removal.is_none()
    }

    pub(crate) fn setup_reconciliation_safe(&self) -> bool {
        self.pending_acl_mutation.is_none()
            && self.pending_materialization.is_none()
            && self.pending_materialization_removal.is_none()
    }
}

fn random_namespace_sid() -> Result<String, CapabilityStateError> {
    let mut random = [0u8; 16];
    getrandom::fill(&mut random).map_err(|source| CapabilityStateError::Random { source })?;
    let first = u32::from_le_bytes([random[0], random[1], random[2], random[3]]);
    let second = u32::from_le_bytes([random[4], random[5], random[6], random[7]]);
    let third = u32::from_le_bytes([random[8], random[9], random[10], random[11]]);
    let fourth = u32::from_le_bytes([random[12], random[13], random[14], random[15]]);
    Ok(format!("S-1-5-21-{first}-{second}-{third}-{fourth}"))
}
