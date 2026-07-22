// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Fact-backed pending passport-mint requests.
//!
//! Filing a request records operator-review state only. It does not create or
//! update a passport. Requests live under a daemon-owned, born-private System
//! entity so generic client fact writes cannot forge the self-scoped request.

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::fact_store::{dedup_latest, default_tenant_hash, FactQuery, FactStore, HorizonClass, StoreFact};

/// Daemon-owned entity namespace for passport-mint requests.
pub const MINT_REQUEST_ENTITY_PREFIX: &str = "__mint_request__";
/// Fixed key for the current request record under each request entity.
pub const MINT_REQUEST_RECORD_KEY: &str = "record";
/// Initial request status.
pub const MINT_REQUEST_STATUS_PENDING: &str = "pending";
/// Terminal status for an operator-approved request.
pub const MINT_REQUEST_STATUS_APPROVED: &str = "approved";
/// Terminal status for an operator-rejected request.
pub const MINT_REQUEST_STATUS_REJECTED: &str = "rejected";
/// Maximum UTF-8 payload accepted for the operator-facing reason field.
///
/// This is enforced in the storage seam as well as the MCP surface so future
/// callers cannot turn a pending-request fact into an unbounded allocation.
pub const MAX_MINT_REQUEST_REASON_BYTES: usize = 2_048;
/// Maximum number of unresolved requests retained in the operator queue.
///
/// The per-requester dedupe prevents one authenticated identity from flooding
/// the queue; this global ceiling also bounds a fleet of compromised identities.
pub const MAX_PENDING_MINT_REQUESTS: usize = 1_000;

/// Operator decision for a pending passport-mint request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MintRequestDecision {
    Approved,
    Rejected,
}

impl MintRequestDecision {
    fn status(self) -> &'static str {
        match self {
            Self::Approved => MINT_REQUEST_STATUS_APPROVED,
            Self::Rejected => MINT_REQUEST_STATUS_REJECTED,
        }
    }
}

/// A request for an operator to mint a passport for the requesting identity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingMintRequest {
    /// Stable request id: `mr_<uuid-simple>`.
    pub request_id: String,
    /// Identity the resulting passport would belong to. The MCP surface fixes
    /// this to the authenticated caller; there is no arbitrary-target input.
    pub requester_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_category: Option<String>,
    pub requested_by_passport: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// `pending` until an operator resolves it as `approved` or `rejected`.
    pub status: String,
    pub requested_at_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_at_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_by_passport: Option<String>,
    /// Typed approval-decision receipt that authorized the terminal state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution_receipt_id: Option<String>,
    /// Exact category applied by an approved decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_category: Option<String>,
    /// Whether approval created or updated the requester passport.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passport_operation: Option<String>,
    /// BLAKE3 digest of the normalized passport record authorized by the
    /// receipt. This binds editable metadata without copying it into the
    /// approval receipt's action summary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passport_record_hash: Option<String>,
    /// BLAKE3 digest of the complete normalized passport mutation set,
    /// including any default-passport records changed as a side effect.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passport_mutation_hash: Option<String>,
}

/// Optional audit bindings attached to a terminal mint-request record.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MintRequestResolutionMetadata {
    pub receipt_id: Option<String>,
    pub approved_category: Option<String>,
    pub passport_operation: Option<String>,
    pub passport_record_hash: Option<String>,
    pub passport_mutation_hash: Option<String>,
}

#[derive(Debug, Error)]
pub enum MintRequestError {
    #[error("mint request reason exceeds {max_bytes} bytes (received {actual_bytes})")]
    ReasonTooLong { max_bytes: usize, actual_bytes: usize },
    #[error("requester already has a pending mint request: {requester_id} ({request_id})")]
    AlreadyPending { requester_id: String, request_id: String },
    #[error("pending mint-request queue is full (limit: {max_pending})")]
    QueueFull { max_pending: usize },
    #[error("mint request not found: {0}")]
    NotFound(String),
    #[error("mint request is not pending: {request_id} (status: {status})")]
    NotPending { request_id: String, status: String },
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("mint-request fact-store write failed: {0}")]
    Store(#[from] std::io::Error),
}

/// File a pending request. This function only writes the request fact; it never
/// calls a passport creation or update path.
pub fn file_mint_request(
    store: &mut FactStore,
    requester_id: String,
    requested_by_passport: String,
    requested_category: Option<String>,
    reason: Option<String>,
    now_unix_ms: u64,
) -> Result<PendingMintRequest, MintRequestError> {
    if let Some(reason) = reason.as_deref() {
        if reason.len() > MAX_MINT_REQUEST_REASON_BYTES {
            return Err(MintRequestError::ReasonTooLong {
                max_bytes: MAX_MINT_REQUEST_REASON_BYTES,
                actual_bytes: reason.len(),
            });
        }
    }
    let pending = pending_mint_requests_unbounded(store);
    if let Some(existing) = pending.iter().find(|request| request.requester_id == requester_id) {
        return Err(MintRequestError::AlreadyPending {
            requester_id,
            request_id: existing.request_id.clone(),
        });
    }
    if pending.len() >= MAX_PENDING_MINT_REQUESTS {
        return Err(MintRequestError::QueueFull {
            max_pending: MAX_PENDING_MINT_REQUESTS,
        });
    }

    let request = PendingMintRequest {
        request_id: format!("mr_{}", Uuid::new_v4().simple()),
        requester_id,
        requested_category,
        requested_by_passport,
        reason,
        status: MINT_REQUEST_STATUS_PENDING.to_string(),
        requested_at_unix_ms: now_unix_ms,
        resolved_at_unix_ms: None,
        resolved_by_passport: None,
        resolution_receipt_id: None,
        approved_category: None,
        passport_operation: None,
        passport_record_hash: None,
        passport_mutation_hash: None,
    };
    let value = serde_json::to_string(&request)?;
    let fact = StoreFact {
        tenant_hash: default_tenant_hash(),
        entity: format!("{MINT_REQUEST_ENTITY_PREFIX}::{}", request.request_id),
        key: MINT_REQUEST_RECORD_KEY.to_string(),
        value,
        source_receipt: None,
        confidence: 1.0,
        // Load-bearing even when an operator configures a privacy-policy share
        // override: an unresolved identity request must never become pushable.
        private: true,
        // Identity/governance state remains current until an explicit M2
        // resolution; time-based decay must not hide a pending request.
        horizon_class: Some(HorizonClass::None),
        actor: Some(request.requested_by_passport.clone()),
    };
    store.try_store(fact)?;
    Ok(request)
}

/// Collect every latest pending request before applying any presentation cap.
///
/// Dedupe and queue-cap enforcement are security decisions, so they must not be
/// based on `FactQuery::top_k`: a sufficiently old pending request could
/// otherwise be crowded out by newer terminal records and duplicated.
fn pending_mint_requests_unbounded(store: &FactStore) -> Vec<PendingMintRequest> {
    let entity_prefix = format!("{MINT_REQUEST_ENTITY_PREFIX}::");
    let facts = store
        .all_facts()
        .filter(|fact| !fact.deleted && fact.entity.starts_with(&entity_prefix) && fact.key == MINT_REQUEST_RECORD_KEY)
        .cloned()
        .collect();
    let mut pending: Vec<PendingMintRequest> = dedup_latest(facts)
        .into_iter()
        .filter_map(|fact| serde_json::from_str::<PendingMintRequest>(&fact.value).ok())
        .filter(|request| request.status == MINT_REQUEST_STATUS_PENDING)
        .collect();
    pending.sort_by(|a, b| {
        a.requested_at_unix_ms
            .cmp(&b.requested_at_unix_ms)
            .then_with(|| a.request_id.cmp(&b.request_id))
    });
    pending
}

/// List every latest pending request record in stable chronological order.
///
/// The queue itself is bounded by [`MAX_PENDING_MINT_REQUESTS`], so this
/// administrative view is complete without a second truncation limit.
pub fn list_pending_mint_requests(store: &FactStore) -> Vec<PendingMintRequest> {
    pending_mint_requests_unbounded(store)
}

/// Load the latest request record for `request_id`.
pub fn get_mint_request(store: &FactStore, request_id: &str) -> Option<PendingMintRequest> {
    let result = store.query(&FactQuery {
        min_effective_confidence: None,
        tenant_hash: None,
        query: None,
        entity: Some(format!("{MINT_REQUEST_ENTITY_PREFIX}::{request_id}")),
        entity_prefix: None,
        top_k: 50,
        token_budget: None,
    });
    dedup_latest(result.facts)
        .into_iter()
        .find(|fact| fact.key == MINT_REQUEST_RECORD_KEY)
        .and_then(|fact| serde_json::from_str::<PendingMintRequest>(&fact.value).ok())
}

/// Resolve a pending request without minting or updating a passport.
///
/// The mutable store borrow serializes the read/validate/write transition for
/// in-process callers. [`FactStore::try_store`] durably appends the terminal
/// record before mutating an on-disk-backed store, so a failed write leaves the
/// request pending.
pub fn resolve_mint_request(
    store: &mut FactStore,
    request_id: &str,
    approver_passport: String,
    decision: MintRequestDecision,
    resolved_at_unix_ms: u64,
) -> Result<PendingMintRequest, MintRequestError> {
    let (request, fact) = prepare_mint_request_resolution(
        store,
        request_id,
        approver_passport,
        decision,
        resolved_at_unix_ms,
        MintRequestResolutionMetadata::default(),
    )?;
    store.try_store(fact)?;
    Ok(request)
}

/// Build, but do not persist, a terminal mint-request fact. Approval uses this
/// to commit the authority-changing passport fact and its request decision in
/// one [`FactStore::try_store_bulk`] journal event.
pub fn prepare_mint_request_resolution(
    store: &FactStore,
    request_id: &str,
    approver_passport: String,
    decision: MintRequestDecision,
    resolved_at_unix_ms: u64,
    metadata: MintRequestResolutionMetadata,
) -> Result<(PendingMintRequest, StoreFact), MintRequestError> {
    let mut request =
        get_mint_request(store, request_id).ok_or_else(|| MintRequestError::NotFound(request_id.to_string()))?;
    if request.status != MINT_REQUEST_STATUS_PENDING {
        return Err(MintRequestError::NotPending {
            request_id: request_id.to_string(),
            status: request.status,
        });
    }

    request.status = decision.status().to_string();
    request.resolved_at_unix_ms = Some(resolved_at_unix_ms);
    request.resolved_by_passport = Some(approver_passport.clone());
    request.resolution_receipt_id.clone_from(&metadata.receipt_id);
    request.approved_category = metadata.approved_category;
    request.passport_operation = metadata.passport_operation;
    request.passport_record_hash = metadata.passport_record_hash;
    request.passport_mutation_hash = metadata.passport_mutation_hash;

    let value = serde_json::to_string(&request)?;
    let fact = StoreFact {
        tenant_hash: default_tenant_hash(),
        entity: format!("{MINT_REQUEST_ENTITY_PREFIX}::{request_id}"),
        key: MINT_REQUEST_RECORD_KEY.to_string(),
        value,
        source_receipt: metadata.receipt_id,
        confidence: 1.0,
        private: true,
        horizon_class: Some(HorizonClass::None),
        actor: Some(approver_passport),
    };
    Ok((request, fact))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn raw_request(index: usize, status: &str) -> PendingMintRequest {
        PendingMintRequest {
            request_id: format!("mr_fixture_{index}"),
            requester_id: format!("requester-{index}"),
            requested_category: Some("work".to_string()),
            requested_by_passport: format!("requester-{index}"),
            reason: None,
            status: status.to_string(),
            requested_at_unix_ms: index as u64,
            resolved_at_unix_ms: (status != MINT_REQUEST_STATUS_PENDING).then_some(index as u64 + 1),
            resolved_by_passport: (status != MINT_REQUEST_STATUS_PENDING).then(|| "operator-passport".to_string()),
            resolution_receipt_id: None,
            approved_category: None,
            passport_operation: None,
            passport_record_hash: None,
            passport_mutation_hash: None,
        }
    }

    fn store_raw_request(store: &mut FactStore, request: &PendingMintRequest) {
        store
            .try_store(StoreFact {
                tenant_hash: default_tenant_hash(),
                entity: format!("{MINT_REQUEST_ENTITY_PREFIX}::{}", request.request_id),
                key: MINT_REQUEST_RECORD_KEY.to_string(),
                value: serde_json::to_string(request).unwrap(),
                source_receipt: None,
                confidence: 1.0,
                private: true,
                horizon_class: Some(HorizonClass::None),
                actor: Some(request.requested_by_passport.clone()),
            })
            .unwrap();
    }

    fn pending_request(store: &mut FactStore) -> PendingMintRequest {
        file_mint_request(
            store,
            "requester-passport".to_string(),
            "requester-passport".to_string(),
            Some("work".to_string()),
            Some("needs work memory".to_string()),
            100,
        )
        .unwrap()
    }

    #[test]
    fn resolve_approved_records_terminal_status_and_operator_attribution() {
        let mut store = FactStore::new();
        let pending = pending_request(&mut store);

        let resolved = resolve_mint_request(
            &mut store,
            &pending.request_id,
            "operator-passport".to_string(),
            MintRequestDecision::Approved,
            200,
        )
        .unwrap();

        assert_eq!(resolved.status, MINT_REQUEST_STATUS_APPROVED);
        assert_eq!(resolved.resolved_at_unix_ms, Some(200));
        assert_eq!(resolved.resolved_by_passport.as_deref(), Some("operator-passport"));
        assert!(list_pending_mint_requests(&store).is_empty());
        assert_eq!(get_mint_request(&store, &pending.request_id), Some(resolved));
    }

    #[test]
    fn resolve_rejected_records_terminal_status_without_changing_request_fields() {
        let mut store = FactStore::new();
        let pending = pending_request(&mut store);

        let resolved = resolve_mint_request(
            &mut store,
            &pending.request_id,
            "rejecting-operator".to_string(),
            MintRequestDecision::Rejected,
            300,
        )
        .unwrap();

        assert_eq!(resolved.status, MINT_REQUEST_STATUS_REJECTED);
        assert_eq!(resolved.requester_id, pending.requester_id);
        assert_eq!(resolved.requested_category, pending.requested_category);
        assert_eq!(resolved.reason, pending.reason);
        assert_eq!(resolved.resolved_by_passport.as_deref(), Some("rejecting-operator"));
        assert!(list_pending_mint_requests(&store).is_empty());
    }

    #[test]
    fn prepared_resolution_binds_receipt_actor_and_approval_metadata() {
        let mut store = FactStore::new();
        let pending = pending_request(&mut store);
        let receipt_id = format!("ad_{}", pending.request_id);

        let (resolved, fact) = prepare_mint_request_resolution(
            &store,
            &pending.request_id,
            "operator-passport".to_string(),
            MintRequestDecision::Approved,
            250,
            MintRequestResolutionMetadata {
                receipt_id: Some(receipt_id.clone()),
                approved_category: Some("work".to_string()),
                passport_operation: Some("create".to_string()),
                passport_record_hash: Some("blake3:record".to_string()),
                passport_mutation_hash: Some("blake3:mutation".to_string()),
            },
        )
        .unwrap();

        assert_eq!(resolved.resolution_receipt_id.as_deref(), Some(receipt_id.as_str()));
        assert_eq!(resolved.approved_category.as_deref(), Some("work"));
        assert_eq!(resolved.passport_operation.as_deref(), Some("create"));
        assert_eq!(resolved.passport_record_hash.as_deref(), Some("blake3:record"));
        assert_eq!(resolved.passport_mutation_hash.as_deref(), Some("blake3:mutation"));
        assert_eq!(fact.source_receipt.as_deref(), Some(receipt_id.as_str()));
        assert_eq!(fact.actor.as_deref(), Some("operator-passport"));
        assert!(fact.private);
        assert_eq!(fact.horizon_class, Some(HorizonClass::None));
        assert_eq!(get_mint_request(&store, &pending.request_id), Some(pending));
    }

    #[test]
    fn resolving_missing_or_non_pending_request_does_not_write() {
        let mut store = FactStore::new();
        let missing = resolve_mint_request(
            &mut store,
            "mr_missing",
            "operator-passport".to_string(),
            MintRequestDecision::Approved,
            200,
        );
        assert!(matches!(missing, Err(MintRequestError::NotFound(id)) if id == "mr_missing"));
        assert_eq!(store.count(), 0);

        let pending = pending_request(&mut store);
        resolve_mint_request(
            &mut store,
            &pending.request_id,
            "first-operator".to_string(),
            MintRequestDecision::Rejected,
            300,
        )
        .unwrap();
        let count_after_resolution = store.count();

        let repeated = resolve_mint_request(
            &mut store,
            &pending.request_id,
            "second-operator".to_string(),
            MintRequestDecision::Approved,
            400,
        );
        assert!(matches!(
            repeated,
            Err(MintRequestError::NotPending { request_id, status })
                if request_id == pending.request_id && status == MINT_REQUEST_STATUS_REJECTED
        ));
        assert_eq!(store.count(), count_after_resolution);

        let stored = get_mint_request(&store, &pending.request_id).unwrap();
        assert_eq!(stored.status, MINT_REQUEST_STATUS_REJECTED);
        assert_eq!(stored.resolved_at_unix_ms, Some(300));
        assert_eq!(stored.resolved_by_passport.as_deref(), Some("first-operator"));
    }

    #[test]
    fn resolved_request_survives_fact_store_replay() {
        let dir = tempfile::tempdir().unwrap();
        let request_id;
        {
            let mut store = FactStore::with_persistence(dir.path()).unwrap();
            let pending = pending_request(&mut store);
            request_id = pending.request_id;
            resolve_mint_request(
                &mut store,
                &request_id,
                "operator-passport".to_string(),
                MintRequestDecision::Approved,
                500,
            )
            .unwrap();
        }

        let replayed = FactStore::with_persistence(dir.path()).unwrap();
        let resolved = get_mint_request(&replayed, &request_id).unwrap();
        assert_eq!(resolved.status, MINT_REQUEST_STATUS_APPROVED);
        assert_eq!(resolved.resolved_at_unix_ms, Some(500));
        assert_eq!(resolved.resolved_by_passport.as_deref(), Some("operator-passport"));
        assert!(list_pending_mint_requests(&replayed).is_empty());
    }

    #[test]
    fn filing_rejects_oversized_reason_without_writing() {
        let mut store = FactStore::new();
        let reason = "x".repeat(MAX_MINT_REQUEST_REASON_BYTES + 1);

        let result = file_mint_request(
            &mut store,
            "requester-passport".to_string(),
            "requester-passport".to_string(),
            Some("work".to_string()),
            Some(reason),
            100,
        );

        assert!(matches!(
            result,
            Err(MintRequestError::ReasonTooLong {
                max_bytes: MAX_MINT_REQUEST_REASON_BYTES,
                actual_bytes,
            }) if actual_bytes == MAX_MINT_REQUEST_REASON_BYTES + 1
        ));
        assert_eq!(store.count(), 0);
    }

    #[test]
    fn filing_deduplicates_pending_request_per_requester() {
        let mut store = FactStore::new();
        let first = pending_request(&mut store);
        let count_after_first = store.count();

        let duplicate = file_mint_request(
            &mut store,
            first.requester_id.clone(),
            first.requested_by_passport.clone(),
            Some("public".to_string()),
            Some("second request".to_string()),
            200,
        );

        assert!(matches!(
            duplicate,
            Err(MintRequestError::AlreadyPending {
                requester_id,
                request_id,
            }) if requester_id == first.requester_id && request_id == first.request_id
        ));
        assert_eq!(store.count(), count_after_first);
        assert_eq!(list_pending_mint_requests(&store), vec![first]);
    }

    #[test]
    fn old_pending_request_cannot_be_crowded_out_by_newer_history() {
        let mut store = FactStore::new();
        let first = pending_request(&mut store);
        for index in 0..1_000 {
            store_raw_request(&mut store, &raw_request(index, MINT_REQUEST_STATUS_APPROVED));
        }
        let count_before_duplicate = store.count();

        let duplicate = file_mint_request(
            &mut store,
            first.requester_id.clone(),
            first.requested_by_passport.clone(),
            None,
            None,
            2_000,
        );

        assert!(matches!(
            duplicate,
            Err(MintRequestError::AlreadyPending { request_id, .. }) if request_id == first.request_id
        ));
        assert_eq!(store.count(), count_before_duplicate);
        assert_eq!(list_pending_mint_requests(&store), vec![first]);
    }

    #[test]
    fn filing_refuses_to_exceed_global_pending_queue_cap() {
        let mut store = FactStore::new();
        for index in 0..MAX_PENDING_MINT_REQUESTS {
            store_raw_request(&mut store, &raw_request(index, MINT_REQUEST_STATUS_PENDING));
        }
        let count_at_cap = store.count();

        let result = file_mint_request(
            &mut store,
            "requester-over-cap".to_string(),
            "requester-over-cap".to_string(),
            None,
            None,
            2_000,
        );

        assert!(matches!(
            result,
            Err(MintRequestError::QueueFull {
                max_pending: MAX_PENDING_MINT_REQUESTS,
            })
        ));
        assert_eq!(store.count(), count_at_cap);
        assert_eq!(list_pending_mint_requests(&store).len(), MAX_PENDING_MINT_REQUESTS);
    }

    #[test]
    fn requester_can_file_again_after_terminal_resolution() {
        let mut store = FactStore::new();
        let first = pending_request(&mut store);
        resolve_mint_request(
            &mut store,
            &first.request_id,
            "operator-passport".to_string(),
            MintRequestDecision::Rejected,
            200,
        )
        .unwrap();

        let second = file_mint_request(
            &mut store,
            first.requester_id.clone(),
            first.requested_by_passport,
            Some("personal".to_string()),
            None,
            300,
        )
        .unwrap();

        assert_ne!(second.request_id, first.request_id);
        assert_eq!(list_pending_mint_requests(&store), vec![second]);
    }
}
