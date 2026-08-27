// SPDX-License-Identifier: Apache-2.0

//! Stable owner identity shared by setup state and managed accounts.

use sha2::{Digest, Sha256};

pub(crate) fn owner_key(owner_sid: &str) -> String {
    Sha256::digest(owner_sid.to_ascii_uppercase().as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::owner_key;

    #[test]
    fn owner_key_is_case_insensitive() {
        assert_eq!(
            owner_key("S-1-5-21-100-200-300-400"),
            owner_key("s-1-5-21-100-200-300-400")
        );
    }
}
