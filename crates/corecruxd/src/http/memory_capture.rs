// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Gated auto-capture HTTP surface (ExecPlan
//! `crux-daemon-buyer-fit-buildout-2026-07-13`, M1.4).
//!
//! - `POST /v1/memory/extract` — run the deterministic extractor over supplied
//!   text and write review-only candidates (0-LLM, free path).
//! - `GET  /v1/memory/candidates` — the review queue.
//! - `POST /v1/memory/candidates/{id}/promote` — explicit review promotion.
//! - `POST /v1/memory/candidates/{id}/reject` — decline (reversible).
//!
//! Every route is gated behind `CORECRUXD_AUTO_CAPTURE` (default OFF): when the
//! flag is off the routes return 404, exactly like `/v1/context`. A promoted
//! fact is the ONLY way an auto-extracted proposal reaches recall — candidates
//! are born private (see [`crate::candidate_store`]).

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use super::{problem_response, require_http_any_scope, AppState};
use crate::candidate_store::{self, CandidateSource, CandidateStatus, MemoryCandidateV1, PromotionMode};
use crate::memory_extract::{self, ExtractionProfile};

fn disabled() -> Response {
    problem_response(
        StatusCode::NOT_FOUND,
        "auto-capture disabled (set CORECRUXD_AUTO_CAPTURE=1)".to_string(),
    )
    .into_response()
}

/// Sign a candidate body with the daemon passport (best-effort). Returns a
/// `{alg, signed_by, body_hash, signature}` envelope, or `None` if no passport
/// key is available. Mirrors `observations::mint_receipt`.
fn mint_receipt(state: &AppState, body_bytes: &[u8]) -> Option<(serde_json::Value, String)> {
    let key = crux_session::LocalPassportKey::from_path(&state.passport_key_path).ok()?;
    if key.passport_fpr() != state.passport_fpr {
        return None;
    }
    let hash = blake3::hash(body_bytes);
    let body_hash = format!("blake3:{}", hex::encode(hash.as_bytes()));
    let signature = hex::encode(key.sign_hash(hash.as_bytes()));
    let envelope = serde_json::json!({
        "alg": "ed25519",
        "signed_by": state.passport_fpr,
        "body_hash": body_hash,
        "signature": signature,
    });
    Some((envelope, body_hash))
}

fn profile_from_str(s: Option<&str>) -> ExtractionProfile {
    match s.map(str::to_ascii_lowercase).as_deref() {
        Some("money") => ExtractionProfile::Money,
        Some("counts") => ExtractionProfile::Counts,
        Some("dates") => ExtractionProfile::Dates,
        Some("version_chains") => ExtractionProfile::VersionChains,
        _ => ExtractionProfile::Comprehensive,
    }
}

/// Content-addressed candidate id: stable for the same proposal, so re-running
/// extraction over the same text is idempotent and never duplicates.
fn candidate_id_for(entity: &str, key: &str, value: &str, rule: &str) -> String {
    let h = blake3::hash(format!("{entity}\u{1f}{key}\u{1f}{value}\u{1f}{rule}").as_bytes());
    hex::encode(&h.as_bytes()[..12])
}

#[derive(Debug, Deserialize)]
pub(super) struct ExtractRequest {
    /// Raw session/transcript text to mine.
    pub text: String,
    /// Optional session id recorded as candidate provenance.
    #[serde(default)]
    pub session_id: Option<String>,
    /// Extraction profile (comprehensive|money|counts|dates|version_chains).
    #[serde(default)]
    pub profile: Option<String>,
    /// ISO date used to fill the year for month-day dates.
    #[serde(default)]
    pub session_date: Option<String>,
}

#[derive(Debug, Serialize)]
pub(super) struct ExtractResponse {
    pub schema: &'static str,
    pub extracted: usize,
    pub written: usize,
    pub skipped_existing: usize,
    pub candidates: Vec<MemoryCandidateV1>,
}

/// `POST /v1/memory/extract`
pub(super) async fn post_extract(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ExtractRequest>,
) -> Response {
    if !state.auto_capture_enabled {
        return disabled();
    }
    if let Err(problem) = require_http_any_scope(&state.auth, &headers, &["facts:write", "admin:write"]) {
        return problem.into_response();
    }

    let profile = profile_from_str(req.profile.as_deref());
    let facts = memory_extract::extract_facts_from_text(&req.text, &profile, req.session_date.as_deref());
    let extracted = facts.len();
    let now = chrono::Utc::now().to_rfc3339();

    let mut written = 0usize;
    let mut skipped = 0usize;
    let mut out = Vec::new();
    let mut store = state.fact_store.write().await;
    for f in facts {
        let proposed_entity = format!("person:{}", f.subject);
        let proposed_key = f.predicate.clone();
        let proposed_value = f.object.clone();
        let cid = candidate_id_for(&proposed_entity, &proposed_key, &proposed_value, f.rule);
        // Idempotent + decision-preserving: never overwrite an existing
        // candidate (which may already be promoted/rejected).
        if candidate_store::get_candidate(&store, &cid).is_some() {
            skipped += 1;
            continue;
        }
        let mut body = MemoryCandidateV1::new_candidate(
            cid,
            proposed_entity,
            proposed_key,
            proposed_value,
            f.rule.to_string(),
            f.confidence,
            "medium".to_string(),
            CandidateSource {
                session_id: req.session_id.clone(),
                observation_seq: None,
                evidence: Some(f.object.clone()),
            },
            None, // free deterministic path is unscored ⇒ review-only
            None,
            now.clone(),
        );
        // Mint the receipt over the receipt-free body, then embed it.
        let receipt_hash = match serde_json::to_vec(&body).ok().and_then(|b| mint_receipt(&state, &b)) {
            Some((envelope, hash)) => {
                body.receipt = Some(envelope);
                Some(hash)
            }
            None => None,
        };
        match candidate_store::write_candidate(&mut store, &body, receipt_hash) {
            Ok(_) => {
                written += 1;
                out.push(body);
            }
            Err(e) => return problem_response(StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
        }
    }

    Json(ExtractResponse {
        schema: "crux.memory_capture.extract.v1",
        extracted,
        written,
        skipped_existing: skipped,
        candidates: out,
    })
    .into_response()
}

#[derive(Debug, Deserialize)]
pub(super) struct ListQuery {
    #[serde(default)]
    pub status: Option<String>,
}

/// `GET /v1/memory/candidates`
pub(super) async fn get_candidates(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ListQuery>,
) -> Response {
    if !state.auto_capture_enabled {
        return disabled();
    }
    if let Err(problem) = require_http_any_scope(&state.auth, &headers, &["query:read", "admin:read"]) {
        return problem.into_response();
    }
    let status = match q.status.as_deref() {
        Some("candidate") => Some(CandidateStatus::Candidate),
        Some("promoted") => Some(CandidateStatus::Promoted),
        Some("rejected") => Some(CandidateStatus::Rejected),
        Some(other) => {
            return problem_response(StatusCode::BAD_REQUEST, format!("unknown status filter: {other}"))
                .into_response();
        }
        None => None,
    };
    let store = state.fact_store.read().await;
    let candidates = candidate_store::list_candidates(&store, status);
    Json(serde_json::json!({
        "schema": "crux.memory_capture.candidates.v1",
        "count": candidates.len(),
        "candidates": candidates,
    }))
    .into_response()
}

#[derive(Debug, Deserialize)]
pub(super) struct PromoteRequest {
    /// Reviewer identity recorded on the promoted fact.
    #[serde(default)]
    pub reviewer: Option<String>,
    /// If set, an automatic (score-gated) promotion at this threshold instead
    /// of an explicit review. Unscored/below-threshold candidates are refused.
    #[serde(default)]
    pub auto_threshold: Option<f32>,
}

/// `POST /v1/memory/candidates/{id}/promote`
pub(super) async fn post_promote(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<PromoteRequest>,
) -> Response {
    if !state.auto_capture_enabled {
        return disabled();
    }
    if let Err(problem) = require_http_any_scope(&state.auth, &headers, &["facts:write", "admin:write"]) {
        return problem.into_response();
    }
    let mode = match req.auto_threshold {
        Some(t) => PromotionMode::Auto { score_threshold: t },
        None => PromotionMode::Explicit {
            reviewer: req.reviewer.unwrap_or_else(|| "operator".to_string()),
        },
    };
    let now = chrono::Utc::now().to_rfc3339();
    let mut store = state.fact_store.write().await;
    match candidate_store::promote(&mut store, &id, mode, &now) {
        Ok(fact_id) => Json(serde_json::json!({
            "schema": "crux.memory_capture.promote.v1",
            "candidate_id": id,
            "promoted_fact_id": fact_id,
            "status": "promoted",
        }))
        .into_response(),
        Err(candidate_store::ReviewError::NotFound) => {
            problem_response(StatusCode::NOT_FOUND, "candidate not found".to_string()).into_response()
        }
        Err(candidate_store::ReviewError::AlreadyPromoted) => {
            problem_response(StatusCode::CONFLICT, "candidate already promoted".to_string()).into_response()
        }
        Err(candidate_store::ReviewError::FailClosed(why)) => {
            // 422: the request is well-formed but the fail-closed gate refuses it.
            problem_response(StatusCode::UNPROCESSABLE_ENTITY, format!("promotion refused: {why}")).into_response()
        }
        Err(candidate_store::ReviewError::Store(e)) => {
            problem_response(StatusCode::INTERNAL_SERVER_ERROR, e).into_response()
        }
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct RejectRequest {
    pub reason: String,
}

/// `POST /v1/memory/candidates/{id}/reject`
pub(super) async fn post_reject(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<RejectRequest>,
) -> Response {
    if !state.auto_capture_enabled {
        return disabled();
    }
    if let Err(problem) = require_http_any_scope(&state.auth, &headers, &["facts:write", "admin:write"]) {
        return problem.into_response();
    }
    let now = chrono::Utc::now().to_rfc3339();
    let mut store = state.fact_store.write().await;
    match candidate_store::reject(&mut store, &id, &req.reason, &now) {
        Ok(()) => Json(serde_json::json!({
            "schema": "crux.memory_capture.reject.v1",
            "candidate_id": id,
            "status": "rejected",
        }))
        .into_response(),
        Err(candidate_store::ReviewError::NotFound) => {
            problem_response(StatusCode::NOT_FOUND, "candidate not found".to_string()).into_response()
        }
        Err(candidate_store::ReviewError::AlreadyPromoted) => problem_response(
            StatusCode::CONFLICT,
            "candidate is promoted; retract the real fact via supersession".to_string(),
        )
        .into_response(),
        Err(e) => problem_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}
