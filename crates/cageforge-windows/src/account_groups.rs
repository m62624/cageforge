// SPDX-License-Identifier: Apache-2.0

//! Exact local-group contract for provisioned Windows sandbox accounts.

pub(crate) const BUILTIN_USERS_SID: &str = "S-1-5-32-545";

const PRIVILEGED_GROUP_SIDS: &[&str] = &[
    "S-1-5-32-544",
    "S-1-5-32-548",
    "S-1-5-32-549",
    "S-1-5-32-550",
    "S-1-5-32-551",
    "S-1-5-32-552",
    "S-1-5-32-556",
    "S-1-5-32-578",
];

pub(crate) fn is_allowed_sandbox_group_sid(sid: &str, managed_group_sid: &str) -> bool {
    sid.eq_ignore_ascii_case(BUILTIN_USERS_SID) || sid.eq_ignore_ascii_case(managed_group_sid)
}

pub(crate) fn is_privileged_group_sid(sid: &str) -> bool {
    PRIVILEGED_GROUP_SIDS
        .iter()
        .any(|privileged| sid.eq_ignore_ascii_case(privileged))
}

#[cfg(test)]
mod tests {
    use super::{BUILTIN_USERS_SID, is_allowed_sandbox_group_sid, is_privileged_group_sid};

    #[test]
    fn sandbox_accounts_allow_only_users_and_the_managed_group() {
        let managed = "S-1-5-21-100-200-300-400";

        assert!(is_allowed_sandbox_group_sid(BUILTIN_USERS_SID, managed));
        assert!(is_allowed_sandbox_group_sid(managed, managed));
        assert!(!is_allowed_sandbox_group_sid("S-1-5-32-555", managed));
        assert!(!is_allowed_sandbox_group_sid("S-1-5-32-544", managed));
    }

    #[test]
    fn privileged_group_identity_is_case_insensitive() {
        assert!(is_privileged_group_sid("s-1-5-32-544"));
        assert!(!is_privileged_group_sid(BUILTIN_USERS_SID));
    }
}
