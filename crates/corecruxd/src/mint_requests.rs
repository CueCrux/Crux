// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Daemon facade for the shared fact-backed passport-mint request store.

pub use corecrux_memory::mint_request::{
    file_mint_request, get_mint_request, list_pending_mint_requests, MintRequestError, PendingMintRequest,
    MINT_REQUEST_ENTITY_PREFIX, MINT_REQUEST_RECORD_KEY, MINT_REQUEST_STATUS_PENDING,
};

#[cfg(test)]
mod tests {
    use super::*;
    use corecrux_memory::{FactStore, HorizonClass};

    #[test]
    fn filed_request_round_trips_private_without_minting() -> Result<(), MintRequestError> {
        let mut store = FactStore::new();
        let passports_before = store
            .all_facts()
            .filter(|fact| fact.entity.starts_with("__passport__::"))
            .count();

        let filed = file_mint_request(
            &mut store,
            "codex-work".to_string(),
            "codex-work".to_string(),
            Some("work".to_string()),
            Some("Stamp the existing caller identity".to_string()),
            1_234,
        )?;

        assert!(filed.request_id.starts_with("mr_"));
        assert_eq!(filed.request_id.len(), 35, "mr_ plus a 32-hex simple UUID");
        assert_eq!(filed.requester_id, "codex-work");
        assert_eq!(filed.requested_by_passport, "codex-work");
        assert_eq!(filed.requested_category.as_deref(), Some("work"));
        assert_eq!(filed.reason.as_deref(), Some("Stamp the existing caller identity"));
        assert_eq!(filed.status, MINT_REQUEST_STATUS_PENDING);
        assert_eq!(filed.requested_at_unix_ms, 1_234);
        assert_eq!(filed.resolved_at_unix_ms, None);
        assert_eq!(filed.resolved_by_passport, None);
        assert_eq!(list_pending_mint_requests(&store), vec![filed.clone()]);
        assert_eq!(get_mint_request(&store, &filed.request_id), Some(filed.clone()));

        let request_entity = format!("{MINT_REQUEST_ENTITY_PREFIX}::{}", filed.request_id);
        assert!(store.all_facts().any(|fact| {
            fact.entity == request_entity
                && fact.key == MINT_REQUEST_RECORD_KEY
                && fact.private
                && fact.horizon_class == HorizonClass::None
        }));
        let passports_after = store
            .all_facts()
            .filter(|fact| fact.entity.starts_with("__passport__::"))
            .count();
        assert_eq!(passports_after, passports_before, "filing must mint no passport");
        Ok(())
    }

    #[test]
    fn pending_list_order_is_deterministic_for_equal_timestamps() -> Result<(), MintRequestError> {
        let mut store = FactStore::new();
        let later_a = file_mint_request(
            &mut store,
            "agent-a".to_string(),
            "agent-a".to_string(),
            None,
            None,
            2_000,
        )?;
        let earlier = file_mint_request(
            &mut store,
            "agent-b".to_string(),
            "agent-b".to_string(),
            Some("personal".to_string()),
            None,
            1_000,
        )?;
        let later_b = file_mint_request(
            &mut store,
            "agent-c".to_string(),
            "agent-c".to_string(),
            Some("public".to_string()),
            None,
            2_000,
        )?;

        let mut expected = vec![later_a, earlier, later_b];
        expected.sort_by(|a, b| {
            a.requested_at_unix_ms
                .cmp(&b.requested_at_unix_ms)
                .then_with(|| a.request_id.cmp(&b.request_id))
        });
        assert_eq!(list_pending_mint_requests(&store), expected);
        Ok(())
    }
}
