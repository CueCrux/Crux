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
}

#[derive(Debug, Error)]
pub enum MintRequestError {
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

/// List the latest pending request records in stable chronological order.
pub fn list_pending_mint_requests(store: &FactStore) -> Vec<PendingMintRequest> {
    let result = store.query(&FactQuery {
        min_effective_confidence: None,
        tenant_hash: None,
        query: None,
        entity: None,
        entity_prefix: Some(format!("{MINT_REQUEST_ENTITY_PREFIX}::")),
        top_k: 1_000,
        token_budget: None,
    });
    let mut pending: Vec<PendingMintRequest> = dedup_latest(result.facts)
        .into_iter()
        .filter(|fact| fact.key == MINT_REQUEST_RECORD_KEY)
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

    let value = serde_json::to_string(&request)?;
    store.try_store(StoreFact {
        tenant_hash: default_tenant_hash(),
        entity: format!("{MINT_REQUEST_ENTITY_PREFIX}::{request_id}"),
        key: MINT_REQUEST_RECORD_KEY.to_string(),
        value,
        source_receipt: None,
        confidence: 1.0,
        private: true,
        horizon_class: Some(HorizonClass::None),
        actor: Some(approver_passport),
    })?;
    Ok(request)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

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
}
