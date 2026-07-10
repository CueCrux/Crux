// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! HTTP surface for the dual-surface activity log (ExecPlan
//! `crux-dual-surface-activity-log-2026-06-18`).
//!
//! - **M1 (this file):** `POST /v1/activity` ingestion — hooks (or any
//!   passport-attributed caller) append journal entries. Each append strips
//!   reserved-prefix text, stores under `(tenant_id, session_id)`, and emits
//!   an `activity.appended` event so the human-lane SSE and the audit
//!   timeline have a projection row (T.4).
//! - **M2:** `GET /v1/activity` — the cheap, token-budgeted agent pull.
//!
//! Everything is gated by `CORECRUXD_FEATURE_ACTIVITY_LOG` (default OFF). The
//! handlers return a 404 disabled-problem when the flag is off, so the
//! daemon behaves exactly as it does today.

use std::collections::HashMap;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;

use corecrux_memory::events::CruxEvent;

use crate::activity::{self, ActivityReceiptV1, ActivityRow, ActivitySigner, JournalEntry, JournalInput, JournalKind};
use crate::auth::{http_scope_context, require_http_any_scope_for_tenant};

use super::{problem_response, AppState};

/// Co-signs activity appends with the daemon passport key (M2). Mirrors the
/// observe lane's `mint_receipt` — Ed25519 over `blake3(body)` — so the
/// embedded receipt is dataplane-independent and offline-verifiable.
struct PassportSigner {
    key: crux_session::LocalPassportKey,
    fpr: String,
}

impl ActivitySigner for PassportSigner {
    fn sign_body(&self, body: &[u8]) -> ActivityReceiptV1 {
        let hash = blake3::hash(body);
        let signature = self.key.sign_hash(hash.as_bytes());
        ActivityReceiptV1 {
            alg: "ed25519".to_string(),
            signed_by: self.fpr.clone(),
            body_hash: format!("blake3:{}", hex::encode(hash.as_bytes())),
            signature: hex::encode(signature),
        }
    }
}

/// Build the co-signer when signing is enabled and the passport key loads and
/// matches `state.passport_fpr`. Returns `None` (append stays unsigned,
/// best-effort) on any mismatch/failure so a key problem never breaks capture.
fn build_signer(state: &AppState) -> Option<PassportSigner> {
    if !activity::activity_sign_enabled() {
        return None;
    }
    let key = crux_session::LocalPassportKey::from_path(&state.passport_key_path).ok()?;
    if key.passport_fpr() != state.passport_fpr {
        return None;
    }
    Some(PassportSigner {
        fpr: state.passport_fpr.clone(),
        key,
    })
}

/// Write scopes for an activity append — mirrors the observe-audit surface.
const WRITE_SCOPES: &[&str] = &["facts:write", "admin:write"];
/// Read scopes for the agent-lane pull and the human-lane deref.
const READ_SCOPES: &[&str] = &["facts:read", "admin:read"];
/// Default preview length (chars) in the cheap agent-lane projection.
const DEFAULT_PREVIEW_CHARS: usize = 200;
/// Default agent-lane pull cap before budget truncation.
const DEFAULT_TOP_K: usize = 200;

fn activity_disabled_response() -> Response {
    problem_response(
        StatusCode::NOT_FOUND,
        "activity log disabled (set CORECRUXD_FEATURE_ACTIVITY_LOG=1)".to_string(),
    )
}

/// `POST /v1/activity` — append a journal entry (capture layer, M1).
///
/// Body is a [`JournalInput`]. The caller must hold a write scope for the
/// body's `tenant_id` (T.1). The append id is recorded as a receipt
/// reference (T.4) and an `activity.appended` event is broadcast (the cheap
/// projection — never the verbatim text).
pub(super) async fn post_activity(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(mut input): Json<JournalInput>,
) -> Response {
    if !activity::activity_log_enabled() {
        return activity_disabled_response();
    }
    if input.tenant_id.trim().is_empty() {
        return problem_response(StatusCode::BAD_REQUEST, "tenant_id is required".to_string());
    }
    if input.session_id.trim().is_empty() {
        return problem_response(StatusCode::BAD_REQUEST, "session_id is required".to_string());
    }
    if let Err(p) = require_http_any_scope_for_tenant(&state.auth, &headers, WRITE_SCOPES, &input.tenant_id) {
        return p.into_response();
    }

    // Bind the entry's actor to the authenticated passport (T.3); the body
    // cannot spoof a different passport.
    let passport = match http_scope_context(&state.auth, &headers) {
        Ok(ctx) => ctx.passport_id,
        Err(p) => return p.into_response(),
    };
    if passport.is_some() {
        input.actor_passport = passport;
    }

    let signer = build_signer(&state);
    let entry = {
        let mut store = activity::global().lock().await;
        store.append_with_signer(input, signer.as_ref().map(|s| s as &dyn ActivitySigner))
    };

    // T.4 — projection row / live SSE. Ids + kind only, never the text.
    state.event_bus.emit(CruxEvent::ActivityAppended {
        entry_id: entry.entry_id.clone(),
        session_id: entry.session_id.clone(),
        kind: entry.kind.as_str().to_string(),
    });

    (StatusCode::CREATED, Json(serde_json::json!(entry))).into_response()
}

/// Parse a comma-separated `kinds` filter into typed [`JournalKind`]s.
/// Unknown tokens are ignored (forward-compatible). Returns `None` for an
/// empty/absent filter (= all kinds).
fn parse_kinds(raw: Option<&String>) -> Option<Vec<JournalKind>> {
    let raw = raw?;
    let kinds: Vec<JournalKind> = raw
        .split(',')
        .filter_map(|tok| {
            let tok = tok.trim();
            if tok.is_empty() {
                return None;
            }
            serde_json::from_value::<JournalKind>(serde_json::Value::String(tok.to_string())).ok()
        })
        .collect();
    if kinds.is_empty() {
        None
    } else {
        Some(kinds)
    }
}

/// `GET /v1/activity` — the cheap, token-budgeted agent lane (M2).
///
/// Query: `tenant_id` (required), `session` (required), `since` (exclusive
/// seq), `kinds` (csv), `token_budget` (**required**, QC.2). Returns compact
/// rows newest-first, reserved-prefix-stripped and privacy-scoped, trimmed to
/// fit the budget. Missing `token_budget` ⇒ 400.
pub(super) async fn get_activity(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    if !activity::activity_log_enabled() {
        return activity_disabled_response();
    }
    let Some(tenant_id) = params.get("tenant_id").filter(|s| !s.trim().is_empty()) else {
        return problem_response(StatusCode::BAD_REQUEST, "tenant_id is required".to_string());
    };
    // `session` is OPTIONAL: when omitted, return recent activity across ALL
    // sessions for the tenant (powers the human-lane "all activity" pane and
    // the session dropdown). `tenant_id` + `token_budget` stay required.
    let session = params.get("session").map(|s| s.trim()).filter(|s| !s.is_empty());
    // QC.2 — token_budget is mandatory on every retrieval pull.
    let token_budget = match params.get("token_budget") {
        Some(raw) => match raw.trim().parse::<u64>() {
            Ok(n) if n > 0 => n,
            _ => {
                return problem_response(
                    StatusCode::BAD_REQUEST,
                    "token_budget must be a positive integer (QC.2)".to_string(),
                )
            }
        },
        None => {
            return problem_response(
                StatusCode::BAD_REQUEST,
                "token_budget query parameter is required (QC.2)".to_string(),
            )
        }
    };

    if let Err(p) = require_http_any_scope_for_tenant(&state.auth, &headers, READ_SCOPES, tenant_id) {
        return p.into_response();
    }
    let caller_passport = http_scope_context(&state.auth, &headers)
        .ok()
        .and_then(|c| c.passport_id)
        .unwrap_or_else(|| activity::ANON_PASSPORT.to_string());

    let since_seq = params.get("since").and_then(|s| s.trim().parse::<u64>().ok());
    // Infinite-scroll cursor (all-sessions): `before` = an entry `ts_us`;
    // `limit` = page size (clamped). The dash pages down by passing the last
    // row's `cursor` back as `before`.
    let before = params.get("before").and_then(|s| s.trim().parse::<i64>().ok());
    let limit = params
        .get("limit")
        .and_then(|s| s.trim().parse::<usize>().ok())
        .map_or(DEFAULT_TOP_K, |n| n.clamp(1, DEFAULT_TOP_K));
    let kinds = parse_kinds(params.get("kinds"));
    // Optional ExecPlan filter (cross-session view only): `?execplan=<slug>`
    // returns entries tagged `meta.execplan_slug == slug`.
    let execplan = params.get("execplan").map(|s| s.trim()).filter(|s| !s.is_empty());

    let entries = {
        let mut store = activity::global().lock().await;
        match session {
            Some(s) => store.recent(tenant_id, s, &caller_passport, since_seq, kinds.as_deref(), limit),
            None => store.recent_all(tenant_id, &caller_passport, before, kinds.as_deref(), execplan, limit),
        }
    };
    let full_page = entries.len() >= limit;

    // Budget trim using the shared estimator (~4 chars/token) so every
    // budget check in the daemon uses the same yardstick. Always return at
    // least one row so a tight budget can't blank the response.
    let mut rows: Vec<ActivityRow> = Vec::new();
    let mut used: u64 = 0;
    let mut truncated = false;
    for entry in &entries {
        let row = ActivityRow::from_entry(entry, DEFAULT_PREVIEW_CHARS);
        let cost = serde_json::to_value(&row)
            .map(|v| crux_mcp::token_estimate::estimate_tokens(&v))
            .unwrap_or(1);
        if !rows.is_empty() && used.saturating_add(cost) > token_budget {
            truncated = true;
            break;
        }
        used = used.saturating_add(cost);
        rows.push(row);
    }
    truncated = truncated || rows.len() < entries.len();
    let next_cursor = rows.last().map(|r| r.cursor);
    let has_more = full_page || rows.len() < entries.len();

    Json(serde_json::json!({
        "session_id": session,
        "all_sessions": session.is_none(),
        "token_budget": token_budget,
        "returned": rows.len(),
        "truncated": truncated,
        "next_cursor": next_cursor,
        "has_more": has_more,
        "rows": rows,
    }))
    .into_response()
}

/// `GET /v1/activity/turn/{turn_id}` — deref one turn to its full verbatim
/// entries (human-lane row-expand and the agent's full-fidelity pull). Query:
/// `tenant_id` + `session` (both required). Privacy-scoped like the pull.
pub(super) async fn get_activity_turn(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(turn_id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    if !activity::activity_log_enabled() {
        return activity_disabled_response();
    }
    let Some(tenant_id) = params.get("tenant_id").filter(|s| !s.trim().is_empty()) else {
        return problem_response(StatusCode::BAD_REQUEST, "tenant_id is required".to_string());
    };
    let Some(session) = params.get("session").filter(|s| !s.trim().is_empty()) else {
        return problem_response(StatusCode::BAD_REQUEST, "session is required".to_string());
    };
    if let Err(p) = require_http_any_scope_for_tenant(&state.auth, &headers, READ_SCOPES, tenant_id) {
        return p.into_response();
    }
    let caller_passport = http_scope_context(&state.auth, &headers)
        .ok()
        .and_then(|c| c.passport_id)
        .unwrap_or_else(|| activity::ANON_PASSPORT.to_string());

    let entries = {
        let store = activity::global().lock().await;
        store.by_turn(tenant_id, session, &turn_id, &caller_passport)
    };

    Json(serde_json::json!({
        "turn_id": turn_id,
        "session_id": session,
        "entries": entries,
    }))
    .into_response()
}

/// Verify one entry's embedded receipt (M2). Dataplane-independent: it
/// reconstructs the canonical body, blake3-hashes it, and checks the Ed25519
/// signature against the daemon passport public key. Unsigned entries report
/// `status:"recorded"` (the no-regression default), never a failure.
fn verify_entry(entry: &JournalEntry, passport_pubkey_hex: &str) -> serde_json::Value {
    let Some(receipt) = &entry.receipt else {
        return serde_json::json!({
            "entry_id": entry.entry_id, "signed": false, "verified": false, "status": "recorded",
        });
    };
    let body = activity::canonical_signing_bytes(entry);
    let hash = blake3::hash(&body);
    let expect = format!("blake3:{}", hex::encode(hash.as_bytes()));
    let mut errors: Vec<String> = Vec::new();
    if receipt.body_hash != expect {
        errors.push("BODY_HASH_MISMATCH".to_string());
    }
    let sig_ok = (|| -> Option<()> {
        let pk: [u8; 32] = hex::decode(passport_pubkey_hex).ok()?.try_into().ok()?;
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk).ok()?;
        let sig: [u8; 64] = hex::decode(&receipt.signature).ok()?.try_into().ok()?;
        let sig = ed25519_dalek::Signature::from_bytes(&sig);
        ed25519_dalek::Verifier::verify(&vk, hash.as_bytes(), &sig).ok()
    })()
    .is_some();
    if !sig_ok {
        errors.push("SIGNATURE_INVALID".to_string());
    }
    serde_json::json!({
        "entry_id": entry.entry_id,
        "signed": true,
        "verified": errors.is_empty(),
        "signed_by": receipt.signed_by,
        "errors": errors,
    })
}

/// `GET /v1/activity/turn/{turn_id}/verify` — verify the embedded receipts for
/// a turn against the daemon passport key (M2). Reuses the same tenant/session
/// scope as the deref. The console ✓verify badge calls this.
pub(super) async fn get_activity_turn_verify(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(turn_id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    if !activity::activity_log_enabled() {
        return activity_disabled_response();
    }
    let Some(tenant_id) = params.get("tenant_id").filter(|s| !s.trim().is_empty()) else {
        return problem_response(StatusCode::BAD_REQUEST, "tenant_id is required".to_string());
    };
    let Some(session) = params.get("session").filter(|s| !s.trim().is_empty()) else {
        return problem_response(StatusCode::BAD_REQUEST, "session is required".to_string());
    };
    if let Err(p) = require_http_any_scope_for_tenant(&state.auth, &headers, READ_SCOPES, tenant_id) {
        return p.into_response();
    }
    let caller_passport = http_scope_context(&state.auth, &headers)
        .ok()
        .and_then(|c| c.passport_id)
        .unwrap_or_else(|| activity::ANON_PASSPORT.to_string());

    let entries = {
        let store = activity::global().lock().await;
        store.by_turn(tenant_id, session, &turn_id, &caller_passport)
    };
    let results: Vec<serde_json::Value> = entries
        .iter()
        .map(|e| verify_entry(e, &state.passport_public_key_hex))
        .collect();

    Json(serde_json::json!({
        "turn_id": turn_id,
        "session_id": session,
        "signer": state.passport_fpr,
        "entries": results,
    }))
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::activity::{JournalInput, JournalKind, JournalMeta, JournalRefs, JournalStore, SIGN_FLAG_ENV};

    fn signed_entry(text: &str) -> (JournalEntry, String) {
        let key = crux_session::LocalPassportKey::from_seed([7_u8; 32]).expect("seed key");
        let pubkey = key.public_key_hex().to_string();
        let signer = PassportSigner {
            fpr: key.passport_fpr().to_string(),
            key,
        };
        let mut store = JournalStore::default();
        let entry = store.append_with_signer(
            JournalInput {
                tenant_id: "t".to_string(),
                session_id: "s".to_string(),
                turn_id: Some("turn-1".to_string()),
                kind: JournalKind::Answer,
                actor_passport: Some("alice".to_string()),
                text: text.to_string(),
                refs: JournalRefs::default(),
                meta: JournalMeta::default(),
                private: false,
            },
            Some(&signer),
        );
        (entry, pubkey)
    }

    #[test]
    #[serial_test::serial]
    fn verify_entry_round_trip_tamper_and_wrong_key() {
        std::env::set_var(SIGN_FLAG_ENV, "1");
        let (entry, pubkey) = signed_entry("the signed answer");
        // The append embedded a receipt.
        assert!(entry.receipt.is_some(), "sign flag on ⇒ entry carries a receipt");

        // Valid signature verifies green.
        let v = verify_entry(&entry, &pubkey);
        assert_eq!(v["signed"], true);
        assert_eq!(v["verified"], true, "valid receipt must verify: {v}");

        // Tampered text breaks both the body hash and the signature.
        let mut tampered = entry.clone();
        tampered.text = "tampered".to_string();
        let vt = verify_entry(&tampered, &pubkey);
        assert_eq!(vt["verified"], false, "tampered body must fail");

        // A different public key fails the signature check.
        let vk = verify_entry(&entry, &"00".repeat(32));
        assert_eq!(vk["verified"], false, "wrong key must fail");

        std::env::remove_var(SIGN_FLAG_ENV);
    }

    #[test]
    #[serial_test::serial]
    fn unsigned_entry_reports_recorded() {
        std::env::remove_var(SIGN_FLAG_ENV);
        let mut store = JournalStore::default();
        let entry = store.append(JournalInput {
            tenant_id: "t".to_string(),
            session_id: "s".to_string(),
            turn_id: Some("turn-1".to_string()),
            kind: JournalKind::Command,
            actor_passport: Some("alice".to_string()),
            text: "no signing".to_string(),
            refs: JournalRefs::default(),
            meta: JournalMeta::default(),
            private: false,
        });
        assert!(entry.receipt.is_none());
        let v = verify_entry(&entry, &"00".repeat(32));
        assert_eq!(v["signed"], false);
        assert_eq!(v["status"], "recorded");
    }
}
