// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! G19 daemon wiring — stream/context receipt drafts lifted into canonical
//! signed receipts.
//!
//! ExecPlan `context-mediation-injection-2026-06-11`, deferred-by-claim
//! follow-up (plan §GATE PACKAGE item 2). Normative spec:
//! `Streaming-Receipts-Spec.md` §5 ("Daemon HTTP surfaces").
//!
//! Two mint points land here:
//!
//! 1. **`POST /v1/mediation/receipts` accepting the new kinds** — the
//!    `crux llm-shim` (and any harness adapter) POSTs JSON receipt *drafts*
//!    whose field names mirror `corecrux_receipts::stream_v1` body fields.
//!    This module lifts a draft into the canonical deterministic-CBOR body,
//!    signs it with the daemon's Ed25519 passport key
//!    ([`sign_stream_v1`]), and records it
//!    through the signed-observation path (`append_one` — never a raw
//!    store write, T.4).
//! 2. **SSE abort hooks** — [`SseAbortGuard`] is attached to the daemon's
//!    SSE surfaces; when a client disconnects mid-stream the guard's `Drop`
//!    mints a `stream_aborted` receipt, closing the "abandoned streams
//!    leave no trail" gap (spec §3).
//!
//! Gating: `CORECRUXD_STREAM_RECEIPTS=1`, default OFF. When off, the
//! mediation route treats stream-kind drafts exactly as before this module
//! existed (the legacy tool-mediation parse rejects them, so a shim falls
//! back to its local JSONL spool), and the SSE guard is inert.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use corecrux_receipts::{
    build_context_injected_body_v1, build_stream_end_body_v1, sign_stream_v1, ContextInjectedBodyInputV1,
    MemoryUseEntryV1, StreamEndBodyInputV1, StreamEndStateV1, CONTEXT_INJECTED_KIND_V1, STREAM_ABORTED_KIND_V1,
    STREAM_BODY_SCHEMA_V1, STREAM_COMPLETED_KIND_V1,
};
use ed25519_dalek::SigningKey;
use serde::Deserialize;
use serde_json::{json, Value};

use super::observations::{append_one, PostObservationBody};
use super::{problem_response, AppState, HeaderMap};

/// Is `kind` one of the G19 stream/context receipt kinds this module lifts?
pub(super) fn is_stream_receipt_kind(kind: &str) -> bool {
    matches!(
        kind,
        CONTEXT_INJECTED_KIND_V1 | STREAM_COMPLETED_KIND_V1 | STREAM_ABORTED_KIND_V1
    )
}

/// One fact entry inside an injected-side draft (`{fact_id, entity}` —
/// mirrors [`MemoryUseEntryV1`], which
/// does not derive `Deserialize`).
#[derive(Debug, Clone, Deserialize)]
pub(super) struct DraftEntry {
    pub fact_id: String,
    pub entity: String,
}

/// A receipt draft as POSTed by the shim / harness adapters. Field names
/// mirror the `stream_v1` canonical body fields so a spooled shim record can
/// be replayed verbatim. Unknown fields are ignored (shim drafts carry
/// extra observational context like `upstream` / `path`).
#[derive(Debug, Clone, Default, Deserialize)]
pub(super) struct StreamReceiptDraft {
    pub kind: String,
    #[serde(default)]
    pub receipt_id: Option<String>,
    #[serde(default)]
    pub session_id: Option<String>,
    // ── injected side ──
    #[serde(default)]
    pub bundle_version: Option<String>,
    #[serde(default)]
    pub stable_hash: Option<String>,
    #[serde(default)]
    pub injection_point: Option<String>,
    #[serde(default)]
    pub budget_requested: Option<u64>,
    #[serde(default)]
    pub budget_spent_est: Option<u64>,
    #[serde(default)]
    pub entries: Vec<DraftEntry>,
    // ── emitted side ──
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub first_token_at: Option<String>,
    #[serde(default)]
    pub ended_at: Option<String>,
    #[serde(default)]
    pub truncated: Option<bool>,
    #[serde(default)]
    pub abort_reason: Option<String>,
    #[serde(default)]
    pub output_digest: Option<String>,
    #[serde(default)]
    pub injected_stable_hash: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
}

/// Load the daemon's Ed25519 signing key from `passport_key_path` (32-byte
/// hex seed — same on-disk format `crux_session::LocalPassportKey` owns) and
/// assert the derived fingerprint matches the daemon identity, mirroring the
/// guard in `observations::mint_receipt`.
fn load_signing_key(state: &AppState) -> Result<SigningKey, String> {
    let content =
        std::fs::read_to_string(&state.passport_key_path).map_err(|err| format!("passport key load failed: {err}"))?;
    let trimmed = content.trim();
    let decoded = hex::decode(trimmed).map_err(|err| format!("passport key decode failed: {err}"))?;
    let seed: [u8; 32] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| format!("passport key is {} bytes, expected 32", decoded.len()))?;
    let key =
        crux_session::LocalPassportKey::from_seed(seed).map_err(|err| format!("passport key parse failed: {err}"))?;
    if key.passport_fpr() != state.passport_fpr {
        return Err(format!(
            "passport signer mismatch: state={}, key={}",
            state.passport_fpr,
            key.passport_fpr()
        ));
    }
    Ok(SigningKey::from_bytes(&seed))
}

/// Everything a lifted, signed receipt produces — fed both to the HTTP
/// response and to the SSE-abort log line.
#[derive(Debug)]
pub(super) struct MintedStreamReceipt {
    pub receipt_id: String,
    pub kind: String,
    pub body_hash: String,
    pub signature_hex: String,
    pub observation_id: String,
}

/// Lift a draft into a canonical signed `stream_v1` receipt and record it
/// through the signed-observation path. `actor` is the caller's resolved
/// principal (passport id, or the operator tag for anonymous-but-authorized
/// callers — audit-hygiene profile).
pub(super) fn mint_stream_receipt(
    state: &AppState,
    actor: &str,
    draft: &StreamReceiptDraft,
) -> Result<MintedStreamReceipt, (StatusCode, String)> {
    let receipt_id = draft
        .receipt_id
        .clone()
        .unwrap_or_else(|| format!("r_{}", uuid::Uuid::new_v4()));
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let created_at = draft.created_at.clone().unwrap_or_else(|| now.clone());
    let session_id = draft.session_id.clone().unwrap_or_else(|| actor.to_string());
    // Local daemon: single-tenant store, tenant identity rides the scoping
    // already enforced by auth (same posture as the context surface).
    let tenant_id = "local";

    let (body_bytes, body_hash) = match draft.kind.as_str() {
        CONTEXT_INJECTED_KIND_V1 => {
            let stable_hash = draft.stable_hash.as_deref().filter(|s| !s.trim().is_empty()).ok_or((
                StatusCode::BAD_REQUEST,
                "context_injected draft requires stable_hash (the two-sided linkage identity)".to_string(),
            ))?;
            let entries: Vec<MemoryUseEntryV1> = draft
                .entries
                .iter()
                .map(|e| MemoryUseEntryV1 {
                    fact_id: e.fact_id.clone(),
                    entity: e.entity.clone(),
                })
                .collect();
            build_context_injected_body_v1(&ContextInjectedBodyInputV1 {
                tenant_id,
                receipt_id: &receipt_id,
                session_id: &session_id,
                actor_passport: actor,
                bundle_version: draft.bundle_version.as_deref().unwrap_or("context_bundle/v1"),
                stable_hash,
                injection_point: draft.injection_point.as_deref().unwrap_or("unspecified"),
                budget_requested: draft.budget_requested.unwrap_or(0),
                budget_spent_est: draft.budget_spent_est.unwrap_or(0),
                entries: &entries,
                created_at: &created_at,
            })
        }
        STREAM_COMPLETED_KIND_V1 | STREAM_ABORTED_KIND_V1 => {
            let end_state = if draft.kind == STREAM_COMPLETED_KIND_V1 {
                StreamEndStateV1::Completed
            } else {
                StreamEndStateV1::Aborted
            };
            let ended_at = draft.ended_at.clone().unwrap_or_else(|| now.clone());
            build_stream_end_body_v1(&StreamEndBodyInputV1 {
                tenant_id,
                receipt_id: &receipt_id,
                session_id: &session_id,
                actor_passport: actor,
                end_state,
                provider: draft.provider.as_deref().unwrap_or("unknown"),
                model: draft.model.as_deref().unwrap_or("unknown"),
                first_token_at: draft.first_token_at.as_deref(),
                ended_at: &ended_at,
                truncated: draft.truncated,
                abort_reason: draft.abort_reason.as_deref(),
                output_digest: draft.output_digest.as_deref(),
                injected_stable_hash: draft.injected_stable_hash.as_deref(),
                created_at: &created_at,
            })
        }
        other => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("unsupported stream receipt kind '{other}'"),
            ));
        }
    };
    if body_bytes.is_empty() {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "canonical receipt body encoding failed".to_string(),
        ));
    }

    let signing_key = load_signing_key(state).map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err))?;
    let sig = sign_stream_v1(
        &receipt_id,
        &body_bytes,
        body_hash,
        &signing_key,
        &state.passport_fpr,
        &now,
    );

    // T.4: record through the signed-observation path — same per-group log
    // the tool-mediation receipts ride (`mediation::<group>`).
    let scoped = format!("mediation::{session_id}");
    let obs_body = PostObservationBody {
        kind: draft.kind.clone(),
        provider: draft
            .provider
            .clone()
            .unwrap_or_else(|| "crux-stream-receipts".to_string()),
        client_ts: None,
        payload: json!({
            "receipt_id": receipt_id,
            "kind": draft.kind,
            "body_schema": STREAM_BODY_SCHEMA_V1,
            "body_cbor_hex": hex::encode(&body_bytes),
            "body_hash": format!("blake3:{}", hex::encode(body_hash)),
            "sig": {
                "schema": sig.schema,
                "alg": sig.alg,
                "key_id": sig.key_id,
                "signed_at": sig.signed_at,
                "signature_hex": hex::encode(&sig.signature),
            },
            "session_id": session_id,
            "stable_hash": draft.stable_hash,
            "injected_stable_hash": draft.injected_stable_hash,
        }),
    };
    let (resp, _tip) = append_one(state, &scoped, actor, obs_body, None)?;
    Ok(MintedStreamReceipt {
        receipt_id,
        kind: draft.kind.clone(),
        body_hash: format!("blake3:{}", hex::encode(body_hash)),
        signature_hex: hex::encode(&sig.signature),
        observation_id: resp.observation_id,
    })
}

/// Handle a stream-kind draft POSTed to `/v1/mediation/receipts`. The
/// caller (`observations::post_mediation_receipt`) has already checked the
/// `CORECRUXD_STREAM_RECEIPTS` flag and dispatched on `kind`.
pub(super) fn handle_stream_receipt_draft(state: &AppState, headers: &HeaderMap, raw: &Value) -> Response {
    // T.3 + write scope: same posture as direct observation writes.
    let ctx = match super::facts::require_session_write_ctx(state, headers) {
        Ok(ctx) => ctx,
        Err(resp) => return resp,
    };
    let draft: StreamReceiptDraft = match serde_json::from_value(raw.clone()) {
        Ok(d) => d,
        Err(err) => {
            return problem_response(
                StatusCode::BAD_REQUEST,
                format!("malformed stream receipt draft: {err}"),
            );
        }
    };
    let actor = ctx.passport_id.clone().unwrap_or_else(|| "operator".to_string());
    match mint_stream_receipt(state, &actor, &draft) {
        Ok(minted) => (
            StatusCode::CREATED,
            Json(json!({
                "receipt_id": minted.receipt_id,
                "kind": minted.kind,
                "body_hash": minted.body_hash,
                "signature_hex": minted.signature_hex,
                "observation_id": minted.observation_id,
                "signed_by": state.passport_fpr,
            })),
        )
            .into_response(),
        Err((status, msg)) => problem_response(status, msg),
    }
}

/// Drop-guard for SSE surfaces: mints a `stream_aborted` receipt when the
/// stream is torn down by a client disconnect (the only way the daemon's
/// infinite event stream ends). Inert when `CORECRUXD_STREAM_RECEIPTS` is
/// off. Best-effort: a minting failure is logged, never surfaced — receipt
/// emission must not destabilize the stream path.
pub(super) struct SseAbortGuard {
    state: Option<AppState>,
    actor: String,
    surface: &'static str,
}

impl SseAbortGuard {
    pub(super) fn new(state: &AppState, headers: &HeaderMap, surface: &'static str) -> Self {
        if !state.stream_receipts_enabled {
            return Self {
                state: None,
                actor: String::new(),
                surface,
            };
        }
        let actor = crate::auth::http_passport_id(headers).unwrap_or_else(|| "operator".to_string());
        Self {
            state: Some(state.clone()),
            actor,
            surface,
        }
    }
}

impl Drop for SseAbortGuard {
    fn drop(&mut self) {
        let Some(state) = self.state.take() else { return };
        let draft = StreamReceiptDraft {
            kind: STREAM_ABORTED_KIND_V1.to_string(),
            session_id: Some(format!("sse::{}", self.actor)),
            provider: Some("corecruxd".to_string()),
            model: Some(self.surface.to_string()),
            abort_reason: Some("client_disconnect".to_string()),
            ..StreamReceiptDraft::default()
        };
        if let Err((_, msg)) = mint_stream_receipt(&state, &self.actor, &draft) {
            tracing::warn!(target = "stream_receipts", surface = self.surface, error = %msg, "sse abort receipt mint failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::observations::ObservationRecordV1;
    use crate::http::tests::test_app_state;
    use ed25519_dalek::Verifier as _;

    /// test_app_state ships a placeholder fingerprint; give it a real
    /// on-disk seed + the matching fpr so the signing path works.
    fn signing_state() -> AppState {
        let mut state = test_app_state(1);
        let key = crux_session::LocalPassportKey::from_path(&state.passport_key_path).expect("init key");
        state.passport_fpr = key.passport_fpr().to_string();
        state.passport_public_key_hex = key.public_key_hex().to_string();
        state.stream_receipts_enabled = true;
        state
    }

    fn read_mediation_records(state: &AppState, group: &str) -> Vec<ObservationRecordV1> {
        let path = crate::http::observations::observation_file_path(&state.data_dir, &format!("mediation::{group}"));
        let Ok(text) = std::fs::read_to_string(path) else {
            return Vec::new();
        };
        text.lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    }

    fn injected_draft() -> StreamReceiptDraft {
        StreamReceiptDraft {
            kind: CONTEXT_INJECTED_KIND_V1.to_string(),
            session_id: Some("s-1".to_string()),
            bundle_version: Some("context_bundle/v1".to_string()),
            stable_hash: Some("blake3:abc123".to_string()),
            injection_point: Some("llm_shim".to_string()),
            budget_requested: Some(2000),
            budget_spent_est: Some(1500),
            entries: vec![
                DraftEntry {
                    fact_id: "f_pub".to_string(),
                    entity: "execplan:x".to_string(),
                },
                DraftEntry {
                    fact_id: "f_secret".to_string(),
                    entity: "__agent::alpha".to_string(),
                },
            ],
            ..StreamReceiptDraft::default()
        }
    }

    #[test]
    fn lift_signs_canonical_body_and_records_observation() {
        let state = signing_state();
        let minted = mint_stream_receipt(&state, "operator", &injected_draft()).expect("mint");
        assert!(minted.body_hash.starts_with("blake3:"));

        // The recorded observation carries the canonical CBOR + signature;
        // the signature verifies over the canonical bytes with the daemon
        // key, and the reserved-prefix entry was filtered in depth.
        let records = read_mediation_records(&state, "s-1");
        assert_eq!(records.len(), 1);
        let payload = &records[0].payload;
        assert_eq!(payload["kind"], CONTEXT_INJECTED_KIND_V1);
        let body = hex::decode(payload["body_cbor_hex"].as_str().expect("cbor hex")).expect("hex");
        assert!(corecrux_receipts::assert_context_injected_kind_v1(&body));
        // CBOR text strings carry raw UTF-8 — substring checks work on the
        // canonical bytes without a CBOR decoder dependency.
        let body_text = String::from_utf8_lossy(&body);
        assert!(body_text.contains("f_pub"));
        assert!(
            !body_text.contains("f_secret"),
            "reserved-prefix entry must be filtered"
        );

        let sig_hex = payload["sig"]["signature_hex"].as_str().expect("sig hex");
        let sig_bytes: [u8; 64] = hex::decode(sig_hex).expect("hex").try_into().expect("64 bytes");
        let pubkey: [u8; 32] = hex::decode(&state.passport_public_key_hex)
            .expect("pubkey hex")
            .try_into()
            .expect("32 bytes");
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&pubkey).expect("vk");
        vk.verify(&body, &ed25519_dalek::Signature::from_bytes(&sig_bytes))
            .expect("daemon signature verifies over canonical body bytes");
    }

    #[test]
    fn stream_end_kinds_lift_with_linkage() {
        let state = signing_state();
        let draft = StreamReceiptDraft {
            kind: STREAM_ABORTED_KIND_V1.to_string(),
            session_id: Some("s-1".to_string()),
            provider: Some("llm_shim".to_string()),
            model: Some("llama3:8b".to_string()),
            abort_reason: Some("client_disconnect".to_string()),
            injected_stable_hash: Some("blake3:abc123".to_string()),
            ..StreamReceiptDraft::default()
        };
        let minted = mint_stream_receipt(&state, "operator", &draft).expect("mint");
        assert_eq!(minted.kind, STREAM_ABORTED_KIND_V1);

        // Two-sided linkage: the lifted injected + aborted bodies pair up.
        let _ = mint_stream_receipt(&state, "operator", &injected_draft()).expect("mint injected");
        let records = read_mediation_records(&state, "s-1");
        assert_eq!(records.len(), 2);
        let body_of = |kind: &str| -> Vec<u8> {
            let rec = records.iter().find(|r| r.payload["kind"] == kind).expect("record");
            hex::decode(rec.payload["body_cbor_hex"].as_str().expect("hex")).expect("decode")
        };
        assert!(corecrux_receipts::stream_links_injection_v1(
            &body_of(CONTEXT_INJECTED_KIND_V1),
            &body_of(STREAM_ABORTED_KIND_V1),
        ));
    }

    #[test]
    fn injected_draft_without_stable_hash_is_rejected() {
        let state = signing_state();
        let mut draft = injected_draft();
        draft.stable_hash = None;
        let err = mint_stream_receipt(&state, "operator", &draft).expect_err("must reject");
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn sse_guard_mints_stream_aborted_on_drop_when_enabled() {
        let state = signing_state();
        {
            let _guard = SseAbortGuard::new(&state, &HeaderMap::new(), "v1/events/stream");
        }
        let records = read_mediation_records(&state, "sse::operator");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].payload["kind"], STREAM_ABORTED_KIND_V1);
        let body = hex::decode(records[0].payload["body_cbor_hex"].as_str().expect("hex")).expect("decode");
        assert!(corecrux_receipts::assert_stream_end_kind_v1(&body));
    }

    #[test]
    fn sse_guard_is_inert_when_flag_off() {
        let mut state = signing_state();
        state.stream_receipts_enabled = false;
        {
            let _guard = SseAbortGuard::new(&state, &HeaderMap::new(), "v1/events/stream");
        }
        assert!(read_mediation_records(&state, "sse::operator").is_empty());
    }

    #[tokio::test]
    async fn mediation_route_lifts_drafts_when_flag_on_and_rejects_when_off() {
        use axum::extract::State;

        let draft = serde_json::json!({
            "kind": "stream_completed",
            "session_id": "s-route",
            "provider": "llm_shim",
            "model": "llama3:8b",
            "ended_at": "2026-06-12T00:00:09Z",
            "output_digest": "sha256:00",
        });

        // Flag ON → draft is lifted into a signed receipt (201).
        let state = signing_state();
        let resp = crate::http::observations::post_mediation_receipt(
            State(state.clone()),
            HeaderMap::new(),
            Json(draft.clone()),
        )
        .await;
        let status = resp.status();
        if status != StatusCode::CREATED {
            let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.expect("body");
            panic!("unexpected status {status}: {}", String::from_utf8_lossy(&bytes));
        }
        assert_eq!(read_mediation_records(&state, "s-route").len(), 1);

        // Flag OFF → exactly the pre-wiring behavior: the legacy
        // tool-mediation parse rejects the draft, nothing is recorded.
        let mut state_off = signing_state();
        state_off.stream_receipts_enabled = false;
        let resp =
            crate::http::observations::post_mediation_receipt(State(state_off.clone()), HeaderMap::new(), Json(draft))
                .await;
        let status = resp.status();
        if status != StatusCode::UNPROCESSABLE_ENTITY {
            let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.expect("body");
            panic!("unexpected status {status}: {}", String::from_utf8_lossy(&bytes));
        }
        assert!(read_mediation_records(&state_off, "s-route").is_empty());
    }

    #[test]
    fn kind_predicate_matches_exactly_the_three_kinds() {
        assert!(is_stream_receipt_kind("context_injected"));
        assert!(is_stream_receipt_kind("stream_completed"));
        assert!(is_stream_receipt_kind("stream_aborted"));
        assert!(!is_stream_receipt_kind("tool_mediation"));
        assert!(!is_stream_receipt_kind(""));
    }
}
