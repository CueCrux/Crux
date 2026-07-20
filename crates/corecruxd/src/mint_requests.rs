// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Daemon passport-mint request resolution.
//!
//! The shared memory crate owns the request state machine. This module owns
//! the security-sensitive daemon seam that applies an operator-approved
//! category to the requester's daemon passport and only then records the
//! terminal request decision.

use std::path::Path;

use corecrux_memory::FactStore;
use serde::Serialize;

pub use corecrux_memory::mint_request::{
    file_mint_request, get_mint_request, list_pending_mint_requests, resolve_mint_request, MintRequestDecision,
    MintRequestError, PendingMintRequest, MINT_REQUEST_ENTITY_PREFIX, MINT_REQUEST_RECORD_KEY,
    MINT_REQUEST_STATUS_APPROVED, MINT_REQUEST_STATUS_PENDING, MINT_REQUEST_STATUS_REJECTED,
};

/// Successful approval result returned by the HTTP surface.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ApprovedMintRequest {
    pub request_id: String,
    pub requester_id: String,
    pub category: String,
    pub minted: bool,
    pub status: String,
}

#[derive(Debug, thiserror::Error)]
pub enum MintRequestResolutionError {
    #[error("approver_passport must not be empty")]
    MissingApprover,
    #[error("an approved passport mint request requires a category")]
    MissingCategory,
    #[error(transparent)]
    Request(#[from] MintRequestError),
    #[error(transparent)]
    Passport(#[from] crate::passports::PassportsError),
}

fn pending_request(store: &FactStore, request_id: &str) -> Result<PendingMintRequest, MintRequestError> {
    let request =
        get_mint_request(store, request_id).ok_or_else(|| MintRequestError::NotFound(request_id.to_string()))?;
    if request.status != MINT_REQUEST_STATUS_PENDING {
        return Err(MintRequestError::NotPending {
            request_id: request.request_id,
            status: request.status,
        });
    }
    Ok(request)
}

fn validated_approver(approver_passport: String) -> Result<String, MintRequestResolutionError> {
    let approver_passport = approver_passport.trim().to_string();
    if approver_passport.is_empty() {
        return Err(MintRequestResolutionError::MissingApprover);
    }
    Ok(approver_passport)
}

/// Apply an explicit operator approval to a pending request.
///
/// The request is checked before any passport mutation. The operator override
/// wins exactly when present; otherwise the requested category is used. A
/// successful passport create/update is required before the request can move
/// to `approved`.
pub fn approve_mint_request(
    data_dir: &Path,
    store: &mut FactStore,
    request_id: &str,
    approver_passport: String,
    category_override: Option<String>,
    name: Option<String>,
    now_unix_ms: u64,
) -> Result<ApprovedMintRequest, MintRequestResolutionError> {
    let approver_passport = validated_approver(approver_passport)?;
    let request = pending_request(store, request_id)?;
    let final_category = category_override
        .or_else(|| request.requested_category.clone())
        .ok_or(MintRequestResolutionError::MissingCategory)?;
    crate::passports::validate_category(&final_category)?;

    if crate::passports::get_passport(store, &request.requester_id).is_none() {
        crate::passports::create_passport(
            data_dir,
            store,
            crate::passports::CreatePassportInput {
                id: request.requester_id.clone(),
                category: final_category.clone(),
                sponsor_id: None,
                agent_work_gate: false,
                is_default_for_category: false,
                name,
                owner: None,
                position: None,
                company: None,
                notes: None,
            },
            now_unix_ms,
        )?;
    } else {
        crate::passports::update_passport(
            store,
            &request.requester_id,
            crate::passports::UpdatePassportInput {
                category: Some(final_category.clone()),
                agent_work_gate: None,
                is_default_for_category: None,
                sponsor_id: None,
                reputation_tier: None,
                receipt_count: None,
                name: name.map(Some),
                owner: None,
                position: None,
                company: None,
                notes: None,
            },
        )?;
    }

    resolve_mint_request(
        store,
        request_id,
        approver_passport,
        MintRequestDecision::Approved,
        now_unix_ms,
    )?;

    Ok(ApprovedMintRequest {
        request_id: request.request_id,
        requester_id: request.requester_id,
        category: final_category,
        minted: true,
        status: MINT_REQUEST_STATUS_APPROVED.to_string(),
    })
}

/// Reject a pending request without creating or updating any passport.
pub fn reject_mint_request(
    store: &mut FactStore,
    request_id: &str,
    approver_passport: String,
    now_unix_ms: u64,
) -> Result<PendingMintRequest, MintRequestResolutionError> {
    let approver_passport = validated_approver(approver_passport)?;
    Ok(resolve_mint_request(
        store,
        request_id,
        approver_passport,
        MintRequestDecision::Rejected,
        now_unix_ms,
    )?)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use corecrux_memory::{FactStore, HorizonClass};

    fn file_request(store: &mut FactStore, requester_id: &str, requested_category: Option<&str>) -> PendingMintRequest {
        file_mint_request(
            store,
            requester_id.to_string(),
            requester_id.to_string(),
            requested_category.map(str::to_string),
            Some("operator review requested".to_string()),
            100,
        )
        .unwrap()
    }

    fn passport_fact_count(store: &FactStore, passport_id: &str) -> usize {
        let entity = format!("{}::{passport_id}", crate::passports::PASSPORT_ENTITY_PREFIX);
        store
            .all_facts()
            .filter(|fact| fact.entity == entity && fact.key == crate::passports::PASSPORT_RECORD_KEY)
            .count()
    }

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

    #[test]
    fn approve_create_mints_exact_operator_category_and_enforcement_round_trips() {
        let data_dir = tempfile::tempdir().unwrap();
        let mut store = FactStore::new();
        let pending = file_request(&mut store, "create-requester", Some("personal"));

        let approved = approve_mint_request(
            data_dir.path(),
            &mut store,
            &pending.request_id,
            "operator-passport".to_string(),
            Some("work".to_string()),
            Some("Approved Work Agent".to_string()),
            200,
        )
        .unwrap();

        assert_eq!(approved.request_id, pending.request_id);
        assert_eq!(approved.requester_id, "create-requester");
        assert_eq!(approved.category, "work");
        assert!(approved.minted);
        assert_eq!(approved.status, MINT_REQUEST_STATUS_APPROVED);

        let passport = crate::passports::get_passport(&store, "create-requester").unwrap();
        assert_eq!(passport.category, "work");
        assert_eq!(
            crux_mcp::category_enforce::passport_category_for(&store, "create-requester").as_deref(),
            Some("work")
        );
        assert_eq!(passport.name.as_deref(), Some("Approved Work Agent"));
        assert!(data_dir.path().join("passports/create-requester.key").is_file());

        let resolved = get_mint_request(&store, &pending.request_id).unwrap();
        assert_eq!(resolved.status, MINT_REQUEST_STATUS_APPROVED);
        assert_eq!(resolved.resolved_by_passport.as_deref(), Some("operator-passport"));
        assert_eq!(resolved.resolved_at_unix_ms, Some(200));

        assert!(crux_mcp::category_enforce::check_passport_can_write_entity(
            &store,
            Some("create-requester"),
            "work::approved-write",
        )
        .is_ok());
        let denied = crux_mcp::category_enforce::check_passport_can_write_entity(
            &store,
            Some("create-requester"),
            "personal::broader-write",
        );
        assert!(matches!(
            denied,
            Err(crux_mcp::category_enforce::CategoryEnforcementError::CategoryMismatch {
                passport_cat,
                entity_cat,
            }) if passport_cat == "work" && entity_cat == "personal"
        ));
    }

    #[test]
    fn approve_update_stamps_existing_identity_category_and_name() {
        let data_dir = tempfile::tempdir().unwrap();
        let mut store = FactStore::new();
        let original = crate::passports::create_passport(
            data_dir.path(),
            &mut store,
            crate::passports::CreatePassportInput {
                id: "existing-requester".to_string(),
                category: "personal".to_string(),
                sponsor_id: None,
                agent_work_gate: false,
                is_default_for_category: false,
                name: Some("Original Name".to_string()),
                owner: None,
                position: None,
                company: None,
                notes: None,
            },
            50,
        )
        .unwrap();
        let pending = file_request(&mut store, "existing-requester", Some("public"));

        let approved = approve_mint_request(
            data_dir.path(),
            &mut store,
            &pending.request_id,
            "operator-passport".to_string(),
            Some("work".to_string()),
            Some("Operator Approved Name".to_string()),
            200,
        )
        .unwrap();

        assert_eq!(approved.category, "work");
        let updated = crate::passports::get_passport(&store, "existing-requester").unwrap();
        assert_eq!(updated.category, "work");
        assert_eq!(updated.name.as_deref(), Some("Operator Approved Name"));
        assert_eq!(updated.principal_id, original.principal_id);
        assert_eq!(updated.public_key_hex, original.public_key_hex);
        assert_eq!(updated.issued_at_unix_ms, original.issued_at_unix_ms);
        assert_eq!(passport_fact_count(&store, "existing-requester"), 2);
    }

    #[test]
    fn reject_mints_nothing_and_records_operator() {
        let data_dir = tempfile::tempdir().unwrap();
        let mut store = FactStore::new();
        let pending = file_request(&mut store, "rejected-requester", Some("work"));
        let passport_facts_before = passport_fact_count(&store, "rejected-requester");

        let rejected =
            reject_mint_request(&mut store, &pending.request_id, "rejecting-operator".to_string(), 300).unwrap();

        assert_eq!(rejected.status, MINT_REQUEST_STATUS_REJECTED);
        assert_eq!(rejected.resolved_by_passport.as_deref(), Some("rejecting-operator"));
        assert_eq!(rejected.resolved_at_unix_ms, Some(300));
        assert_eq!(passport_fact_count(&store, "rejected-requester"), passport_facts_before);
        assert!(crate::passports::get_passport(&store, "rejected-requester").is_none());
        assert!(!data_dir.path().join("passports/rejected-requester.key").exists());
        assert!(!list_pending_mint_requests(&store)
            .iter()
            .any(|request| request.request_id == pending.request_id));

        let stored = get_mint_request(&store, &pending.request_id).unwrap();
        assert_eq!(stored, rejected);
    }

    #[test]
    fn approve_non_pending_does_not_create_or_update_passports() {
        let data_dir = tempfile::tempdir().unwrap();
        let mut store = FactStore::new();

        let absent_pending = file_request(&mut store, "resolved-without-passport", Some("work"));
        reject_mint_request(
            &mut store,
            &absent_pending.request_id,
            "first-operator".to_string(),
            200,
        )
        .unwrap();
        let absent_retry = approve_mint_request(
            data_dir.path(),
            &mut store,
            &absent_pending.request_id,
            "second-operator".to_string(),
            Some("public".to_string()),
            Some("Must Not Be Created".to_string()),
            300,
        );
        assert!(matches!(
            absent_retry,
            Err(MintRequestResolutionError::Request(MintRequestError::NotPending {
                request_id,
                status,
            })) if request_id == absent_pending.request_id && status == MINT_REQUEST_STATUS_REJECTED
        ));
        assert!(crate::passports::get_passport(&store, "resolved-without-passport").is_none());
        assert!(!data_dir.path().join("passports/resolved-without-passport.key").exists());

        let original = crate::passports::create_passport(
            data_dir.path(),
            &mut store,
            crate::passports::CreatePassportInput {
                id: "resolved-with-passport".to_string(),
                category: "personal".to_string(),
                sponsor_id: None,
                agent_work_gate: false,
                is_default_for_category: false,
                name: Some("Original Name".to_string()),
                owner: None,
                position: None,
                company: None,
                notes: None,
            },
            50,
        )
        .unwrap();
        let existing_pending = file_request(&mut store, "resolved-with-passport", Some("work"));
        reject_mint_request(
            &mut store,
            &existing_pending.request_id,
            "first-operator".to_string(),
            200,
        )
        .unwrap();
        let passport_facts_before = passport_fact_count(&store, "resolved-with-passport");

        let existing_retry = approve_mint_request(
            data_dir.path(),
            &mut store,
            &existing_pending.request_id,
            "second-operator".to_string(),
            Some("work".to_string()),
            Some("Must Not Update".to_string()),
            300,
        );
        assert!(matches!(
            existing_retry,
            Err(MintRequestResolutionError::Request(MintRequestError::NotPending { .. }))
        ));
        assert_eq!(
            passport_fact_count(&store, "resolved-with-passport"),
            passport_facts_before
        );
        assert_eq!(
            crate::passports::get_passport(&store, "resolved-with-passport"),
            Some(original)
        );
    }

    #[test]
    fn missing_category_and_empty_approver_do_not_mutate() {
        let data_dir = tempfile::tempdir().unwrap();
        let mut store = FactStore::new();

        let missing_category = file_request(&mut store, "missing-category", None);
        let facts_before_missing_category = store.count();
        let missing_category_result = approve_mint_request(
            data_dir.path(),
            &mut store,
            &missing_category.request_id,
            "operator-passport".to_string(),
            None,
            Some("Must Not Be Applied".to_string()),
            200,
        );
        assert!(matches!(
            missing_category_result,
            Err(MintRequestResolutionError::MissingCategory)
        ));
        assert_eq!(store.count(), facts_before_missing_category);
        assert_eq!(
            get_mint_request(&store, &missing_category.request_id),
            Some(missing_category)
        );
        assert!(crate::passports::get_passport(&store, "missing-category").is_none());
        assert!(!data_dir.path().join("passports/missing-category.key").exists());

        let empty_approver = file_request(&mut store, "empty-approver", Some("work"));
        let facts_before_empty_approver = store.count();
        let empty_approve = approve_mint_request(
            data_dir.path(),
            &mut store,
            &empty_approver.request_id,
            " \t ".to_string(),
            Some("work".to_string()),
            Some("Must Not Be Applied".to_string()),
            300,
        );
        assert!(matches!(
            empty_approve,
            Err(MintRequestResolutionError::MissingApprover)
        ));
        let empty_reject = reject_mint_request(&mut store, &empty_approver.request_id, "  ".to_string(), 300);
        assert!(matches!(empty_reject, Err(MintRequestResolutionError::MissingApprover)));
        assert_eq!(store.count(), facts_before_empty_approver);
        assert_eq!(
            get_mint_request(&store, &empty_approver.request_id),
            Some(empty_approver)
        );
        assert!(crate::passports::get_passport(&store, "empty-approver").is_none());
        assert!(!data_dir.path().join("passports/empty-approver.key").exists());
    }
}
