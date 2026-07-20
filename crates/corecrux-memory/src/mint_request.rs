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
/// Initial request status. Resolution transitions are implemented in M2.
pub const MINT_REQUEST_STATUS_PENDING: &str = "pending";

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
    /// `pending` in M1; `approved` and `rejected` are reserved for M2.
    pub status: String,
    pub requested_at_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_at_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_by_passport: Option<String>,
}

#[derive(Debug, Error)]
pub enum MintRequestError {
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
