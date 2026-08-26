// SPDX-License-Identifier: Apache-2.0

//! Deterministic binding between one setup owner and its managed accounts.

use sha2::{Digest, Sha256};

const ACCOUNT_KEY_LENGTH: usize = 12;

pub(crate) struct ManagedAccountNames {
    pub(crate) offline: String,
    pub(crate) online: String,
    pub(crate) group: String,
}

impl ManagedAccountNames {
    pub(crate) fn for_owner(owner_sid: &str) -> Self {
        let key = owner_key(owner_sid);
        let suffix = &key[..ACCOUNT_KEY_LENGTH];
        Self {
            offline: format!("CgfOff_{suffix}"),
            online: format!("CgfOn_{suffix}"),
            group: format!("CgfGrp_{suffix}"),
        }
    }
}

pub(crate) fn owner_key(owner_sid: &str) -> String {
    Sha256::digest(owner_sid.to_ascii_uppercase().as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::ManagedAccountNames;

    #[test]
    fn owner_sid_case_has_one_account_identity() {
        let upper = ManagedAccountNames::for_owner("S-1-5-21-100-200-300-400");
        let lower = ManagedAccountNames::for_owner("s-1-5-21-100-200-300-400");

        assert_eq!(upper.offline, lower.offline);
        assert_eq!(upper.online, lower.online);
        assert_eq!(upper.group, lower.group);
    }

    #[test]
    fn unrelated_account_name_does_not_match_owner_binding() {
        let names = ManagedAccountNames::for_owner("S-1-5-21-100-200-300-400");

        assert_ne!(names.offline, "CgfOff_000000000000");
        assert_ne!(names.online, "CgfOn_000000000000");
    }
}
