// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
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
//! 2. **Cloud-witness delivery** — the mediation route recognizes nested
//!    `cuecrux.mediation.witness.v1` envelopes before top-level-kind dispatch,
//!    verifies their Ed25519 signature server-side, and records the
//!    metadata-only envelope through the same `append_one` path. This path is
//!    implemented in `observations::handle_witness_receipt` because witness
//!    records are already signed evidence, not stream-v1 receipt drafts.
//! 3. **SSE abort hooks** — [`SseAbortGuard`] is attached to the daemon's
//!    SSE surfaces; when a client disconnects mid-stream the guard's `Drop`
//!    mints a `stream_aborted` receipt, closing the "abandoned streams
//!    leave no trail" gap (spec §3).
//!
//! Gating: `CORECRUXD_STREAM_RECEIPTS=1`, default OFF. When off, the
//! mediation route treats stream-kind drafts and cloud-witness envelopes
//! exactly as before this wiring existed (the legacy tool-mediation parse
//! rejects them, so a shim falls back to its local JSONL spool), and the SSE
//! guard is inert.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use corecrux_receipts::{
    build_context_injected_body_v1, build_model_invocation_body_v1, build_stream_end_body_v1, build_usage_ping_body_v1,
    sign_model_invocation_v1, sign_stream_v1, sign_usage_ping_v1, ContextInjectedBodyInputV1, MemoryUseEntryV1,
    ModelInvocationBodyInputV1, StreamEndBodyInputV1, StreamEndStateV1, UsageEventClassV1, UsagePingBodyInputV1,
    AUDIT_GAP_BODY_SCHEMA_V1, CONTEXT_INJECTED_KIND_V1, MODEL_INVOCATION_KIND_V1, STREAM_ABORTED_KIND_V1,
    STREAM_BODY_SCHEMA_V1, STREAM_COMPLETED_KIND_V1, USAGE_EVENT_CLASSES_V1, USAGE_PING_BODY_SCHEMA_V1,
    USAGE_PING_KIND_V1,
};
use ed25519_dalek::SigningKey;
use serde::Deserialize;
use serde_json::{json, Value};

use super::observations::{append_one, PostObservationBody};
use super::{problem_response, AppState, HeaderMap};

/// Is `kind` one of the mediation receipt draft kinds this module lifts?
pub(super) fn is_stream_receipt_kind(kind: &str) -> bool {
    matches!(
        kind,
        CONTEXT_INJECTED_KIND_V1 | STREAM_COMPLETED_KIND_V1 | STREAM_ABORTED_KIND_V1 | MODEL_INVOCATION_KIND_V1
    )
}

/// Is `kind` the Phase T opt-in usage-ping adoption receipt? Gated by the
/// separate `CORECRUXD_FEATURE_USAGE_RECEIPTS` flag (NOT
/// `CORECRUXD_STREAM_RECEIPTS`).
pub(super) fn is_usage_receipt_kind(kind: &str) -> bool {
    kind == USAGE_PING_KIND_V1
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
    // ── model invocation provenance ──
    #[serde(default)]
    pub invocation_id: Option<String>,
    #[serde(default)]
    pub model_id: Option<String>,
    #[serde(default)]
    pub model_version: Option<String>,
    #[serde(default)]
    pub provider_request_id: Option<String>,
    #[serde(default)]
    pub prompt_hash: Option<String>,
    #[serde(default)]
    pub retrieval_set_hash: Option<String>,
    #[serde(default)]
    pub output_hash: Option<String>,
    #[serde(default)]
    pub temperature: Option<f64>,
    #[serde(default)]
    pub top_p: Option<f64>,
    #[serde(default)]
    pub seed: Option<i64>,
    #[serde(default)]
    pub max_tokens: Option<u64>,
    #[serde(default)]
    pub started_at: Option<String>,
    #[serde(default)]
    pub completed_at: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
}

/// Load the daemon's Ed25519 signing key from `passport_key_path` (32-byte
/// hex seed — same on-disk format `crux_session::LocalPassportKey` owns) and
/// assert the derived fingerprint matches the daemon identity, mirroring the
/// guard in `observations::mint_receipt`.
pub(super) fn load_signing_key(state: &AppState) -> Result<SigningKey, String> {
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
        MODEL_INVOCATION_KIND_V1 => {
            let invocation_id = draft.invocation_id.as_deref().filter(|s| !s.trim().is_empty()).ok_or((
                StatusCode::BAD_REQUEST,
                "model_invocation draft requires invocation_id".to_string(),
            ))?;
            let prompt_hash = draft.prompt_hash.as_deref().filter(|s| !s.trim().is_empty()).ok_or((
                StatusCode::BAD_REQUEST,
                "model_invocation draft requires prompt_hash".to_string(),
            ))?;
            let started_at = draft.started_at.as_deref().unwrap_or(&created_at);
            let completed_at = draft.completed_at.as_deref().or(draft.ended_at.as_deref());
            build_model_invocation_body_v1(&ModelInvocationBodyInputV1 {
                tenant_id,
                receipt_id: &receipt_id,
                invocation_id,
                actor_passport: actor,
                provider: draft.provider.as_deref().unwrap_or("unknown"),
                model_id: draft
                    .model_id
                    .as_deref()
                    .or(draft.model.as_deref())
                    .unwrap_or("unknown"),
                model_version: draft.model_version.as_deref(),
                provider_request_id: draft.provider_request_id.as_deref(),
                prompt_hash,
                retrieval_set_hash: draft.retrieval_set_hash.as_deref(),
                output_hash: draft.output_hash.as_deref().or(draft.output_digest.as_deref()),
                temperature: draft.temperature,
                top_p: draft.top_p,
                seed: draft.seed,
                max_tokens: draft.max_tokens,
                started_at,
                completed_at,
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
    let sig = if draft.kind == MODEL_INVOCATION_KIND_V1 {
        sign_model_invocation_v1(
            &receipt_id,
            &body_bytes,
            body_hash,
            &signing_key,
            &state.passport_fpr,
            &now,
        )
    } else {
        sign_stream_v1(
            &receipt_id,
            &body_bytes,
            body_hash,
            &signing_key,
            &state.passport_fpr,
            &now,
        )
    };
    let body_schema = if draft.kind == MODEL_INVOCATION_KIND_V1 {
        AUDIT_GAP_BODY_SCHEMA_V1
    } else {
        STREAM_BODY_SCHEMA_V1
    };

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
            "body_schema": body_schema,
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
            "invocation_id": draft.invocation_id,
            "prompt_hash": draft.prompt_hash,
            "retrieval_set_hash": draft.retrieval_set_hash,
            "output_hash": draft.output_hash,
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

// ── Phase T: opt-in usage-ping receipts ─────────────────────────────────
//
// A deliberately metadata-only adoption signal (ExecPlan
// `phase-t-usage-receipts`). M0 is the LOCAL primitive only: build → sign →
// record through the same signed-observation path the stream receipts ride.
// There is NO outbound/network code here — the opt-in, consent-gated
// submitter is M1 — so this keeps `assert-no-phone-home.sh` green.

/// A usage-ping draft as POSTed to `/v1/mediation/receipts`. Metadata only —
/// there is no field through which fact content, query text, or corpus
/// identity could be smuggled. Unknown fields (including the `kind`
/// discriminator, already validated by the recognizer dispatch) are ignored.
#[derive(Debug, Clone, Default, Deserialize)]
pub(super) struct UsagePingDraft {
    #[serde(default)]
    pub receipt_id: Option<String>,
    /// One of `USAGE_EVENT_CLASSES_V1` (`session` / `query` / `daemon_start`).
    /// Defaults to `session`; an unknown value is rejected.
    #[serde(default)]
    pub event_class: Option<String>,
    #[serde(default)]
    pub count: Option<u64>,
    #[serde(default)]
    pub created_at: Option<String>,
}

/// Lift a usage-ping draft into a canonical signed receipt and record it
/// through the signed-observation path (`append_one` — never a raw store
/// write). Local only: this function performs **no** network I/O — it also
/// returns the metadata-only [`crate::usage_submit::UsagePingSubmission`] the
/// caller may (opt-in, consent-gated) hand to the M1 submitter *after* this
/// local persist. Building it here does not send it.
pub(super) fn mint_usage_receipt(
    state: &AppState,
    actor: &str,
    draft: &UsagePingDraft,
) -> Result<(MintedStreamReceipt, crate::usage_submit::UsagePingSubmission), (StatusCode, String)> {
    let receipt_id = draft
        .receipt_id
        .clone()
        .unwrap_or_else(|| format!("r_{}", uuid::Uuid::new_v4()));
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let created_at = draft.created_at.clone().unwrap_or_else(|| now.clone());
    // Local daemon: single-tenant store, tenant identity rides the auth
    // scoping (same posture as the stream/context surfaces).
    let tenant_id = "local";

    let event_class_str = draft.event_class.as_deref().unwrap_or("session");
    let event_class = UsageEventClassV1::parse(event_class_str).ok_or((
        StatusCode::BAD_REQUEST,
        format!("usage_ping draft has unknown event_class '{event_class_str}' (allowed: {USAGE_EVENT_CLASSES_V1:?})"),
    ))?;
    let count = draft.count.unwrap_or(1);

    let (body_bytes, body_hash) = build_usage_ping_body_v1(&UsagePingBodyInputV1 {
        tenant_id,
        receipt_id: &receipt_id,
        passport_fpr: &state.passport_fpr,
        event_class,
        count,
        created_at: &created_at,
    });
    if body_bytes.is_empty() {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "canonical usage_ping body encoding failed".to_string(),
        ));
    }

    let signing_key = load_signing_key(state).map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err))?;
    let sig = sign_usage_ping_v1(
        &receipt_id,
        &body_bytes,
        body_hash,
        &signing_key,
        &state.passport_fpr,
        &now,
    );
    let body_hash_hex = format!("blake3:{}", hex::encode(body_hash));
    let signature_hex = hex::encode(&sig.signature);

    // Record through the signed-observation path — scoped per actor so the M2
    // collector can tally distinct passports.
    let scoped = format!("usage::{actor}");
    let obs_body = PostObservationBody {
        kind: USAGE_PING_KIND_V1.to_string(),
        provider: "crux-usage-receipts".to_string(),
        client_ts: None,
        payload: json!({
            "receipt_id": receipt_id,
            "kind": USAGE_PING_KIND_V1,
            "body_schema": USAGE_PING_BODY_SCHEMA_V1,
            "body_cbor_hex": hex::encode(&body_bytes),
            "body_hash": body_hash_hex.clone(),
            "sig": {
                "schema": sig.schema,
                "alg": sig.alg,
                "key_id": sig.key_id,
                "signed_at": sig.signed_at,
                "signature_hex": signature_hex.clone(),
            },
            "event_class": event_class.as_str(),
            "count": count,
        }),
    };
    let (resp, _tip) = append_one(state, &scoped, actor, obs_body, None)?;

    // Metadata-only submission the caller may forward to the M1 opt-in
    // submitter. Built here from the same signed material, but NOT sent —
    // sending is the caller's consent-gated decision.
    let submission = crate::usage_submit::UsagePingSubmission {
        receipt_id: receipt_id.clone(),
        // The exact signed message: the canonical CBOR body bytes (metadata
        // only, by `build_usage_ping_body_v1` construction). Lets the collector
        // reconstruct the signed message to verify the signature.
        body_cbor_hex: hex::encode(&body_bytes),
        body_hash: body_hash_hex.clone(),
        passport_fpr: state.passport_fpr.clone(),
        // The daemon's Ed25519 public key — non-secret, needed to verify the
        // sig; `passport_fpr == blake3(public_key)[..16]` binds the two.
        public_key_hex: hex::encode(signing_key.verifying_key().to_bytes()),
        event_class: event_class.as_str().to_string(),
        created_at: created_at.clone(),
        sig: crate::usage_submit::UsagePingSubmissionSig {
            alg: sig.alg.clone(),
            key_id: sig.key_id.clone(),
            signed_at: sig.signed_at.clone(),
            signature_hex: signature_hex.clone(),
        },
    };
    Ok((
        MintedStreamReceipt {
            receipt_id,
            kind: USAGE_PING_KIND_V1.to_string(),
            body_hash: body_hash_hex,
            signature_hex,
            observation_id: resp.observation_id,
        },
        submission,
    ))
}

/// Handle a `usage_ping` draft POSTed to `/v1/mediation/receipts`. The caller
/// (`observations::post_mediation_receipt`) has already checked the
/// `CORECRUXD_FEATURE_USAGE_RECEIPTS` flag and dispatched on `kind`.
///
/// After the local signed receipt is persisted, the opt-in, consent-gated M1
/// submitter is offered the metadata-only submission. It is a no-op unless the
/// three-way gate (`CORECRUXD_USAGE_RECEIPTS_SUBMIT` + a set `https://`
/// `..._ENDPOINT` + a recorded `..._CONSENT_AT`) is fully satisfied — so under
/// default config this dials nothing.
///
/// Synchronous: `maybe_spawn_submit` offloads any actual network call onto a
/// blocking task, so this handler never awaits and never blocks the runtime.
pub(super) fn handle_usage_receipt_draft(state: &AppState, headers: &HeaderMap, raw: &Value) -> Response {
    let ctx = match super::facts::require_session_write_ctx(state, headers) {
        Ok(ctx) => ctx,
        Err(resp) => return resp,
    };
    let draft: UsagePingDraft = match serde_json::from_value(raw.clone()) {
        Ok(d) => d,
        Err(err) => {
            return problem_response(StatusCode::BAD_REQUEST, format!("malformed usage_ping draft: {err}"));
        }
    };
    let actor = ctx.passport_id.clone().unwrap_or_else(|| "operator".to_string());
    match mint_usage_receipt(state, &actor, &draft) {
        Ok((minted, submission)) => {
            // Opt-in, consent-gated egress — fired only after local persist,
            // never on boot or a timer. Inert unless the three-way gate holds.
            crate::usage_submit::maybe_spawn_submit(state, submission);
            (
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
                .into_response()
        }
        Err((status, msg)) => problem_response(status, msg),
    }
}

/// M1 daemon-boot auto-emit: mint exactly one `daemon_start` usage ping,
/// keyed to the daemon ROOT passport (`state.passport_fpr`, NOT a per-agent
/// passport), via the same [`mint_usage_receipt`] path the HTTP surface uses,
/// then hand the metadata-only submission to the consent-gated M1 submitter.
///
/// **No-op with ZERO network unless opted in.** The very first line is the
/// three-way consent gate (`active_endpoint().is_some()`): a default install
/// has not opted into submission, so this returns before any mint, any signing
/// key read, and any network task — keeping `assert-no-phone-home.sh` green.
/// Once the operator has opted in, auto-emit on boot is the default (no extra
/// flag), so the ≥25-ping adoption gate self-populates.
///
/// Called once per boot from `main.rs` after the HTTP server is serving.
/// Fire-and-forget: a mint failure is logged, never surfaced — an adoption
/// ping must never destabilize startup.
pub(crate) fn emit_daemon_start_usage_ping(state: &AppState) {
    // ── Consent gate: no opt-in → no mint, no submit, ZERO network ───────
    if state.usage_submit.active_endpoint().is_none() {
        return;
    }
    // Actor = the daemon root passport fingerprint. Distinct passports ==
    // distinct daemons/installs, so the collector counts installs — not the
    // ephemeral per-agent fanout the turnaround F2 flagged.
    let actor = state.passport_fpr.clone();
    let draft = UsagePingDraft {
        event_class: Some(UsageEventClassV1::DaemonStart.as_str().to_string()),
        count: Some(1),
        ..UsagePingDraft::default()
    };
    match mint_usage_receipt(state, &actor, &draft) {
        Ok((minted, submission)) => {
            // Opt-in, consent-gated egress — fired only after the local receipt
            // is persisted. Inert unless the three-way gate holds (already true
            // here). Offloads any network onto a blocking task; never blocks.
            crate::usage_submit::maybe_spawn_submit(state, submission);
            tracing::info!(
                target: "usage_submit",
                receipt_id = %minted.receipt_id,
                passport_fpr = %state.passport_fpr,
                "daemon_start usage ping minted on boot"
            );
        }
        Err((status, msg)) => {
            tracing::warn!(
                target: "usage_submit",
                status = %status,
                error = %msg,
                "daemon_start usage ping mint failed on boot"
            );
        }
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
    fn model_invocation_draft_lifts_with_prompt_retrieval_and_output_hashes() {
        let state = signing_state();
        let draft = StreamReceiptDraft {
            kind: MODEL_INVOCATION_KIND_V1.to_string(),
            session_id: Some("s-model".to_string()),
            invocation_id: Some("inv-1".to_string()),
            provider: Some("openai".to_string()),
            model_id: Some("gpt-5.4".to_string()),
            model_version: Some("2026-06-01".to_string()),
            provider_request_id: Some("req_123".to_string()),
            prompt_hash: Some("blake3:prompt".to_string()),
            retrieval_set_hash: Some("blake3:retrieval".to_string()),
            output_hash: Some("blake3:output".to_string()),
            temperature: Some(0.2),
            top_p: Some(0.9),
            seed: Some(42),
            max_tokens: Some(2048),
            started_at: Some("2026-06-14T10:00:00Z".to_string()),
            completed_at: Some("2026-06-14T10:00:02Z".to_string()),
            ..StreamReceiptDraft::default()
        };
        let minted = mint_stream_receipt(&state, "operator", &draft).expect("mint model invocation");
        assert_eq!(minted.kind, MODEL_INVOCATION_KIND_V1);

        let records = read_mediation_records(&state, "s-model");
        assert_eq!(records.len(), 1);
        let payload = &records[0].payload;
        assert_eq!(payload["kind"], MODEL_INVOCATION_KIND_V1);
        assert_eq!(payload["invocation_id"], "inv-1");
        assert_eq!(payload["prompt_hash"], "blake3:prompt");
        assert_eq!(payload["retrieval_set_hash"], "blake3:retrieval");
        assert_eq!(payload["output_hash"], "blake3:output");

        let body = hex::decode(payload["body_cbor_hex"].as_str().expect("cbor hex")).expect("hex");
        assert!(corecrux_receipts::assert_model_invocation_kind_v1(&body));
        let body_text = String::from_utf8_lossy(&body);
        assert!(body_text.contains("blake3:prompt"));
        assert!(body_text.contains("blake3:retrieval"));
        assert!(body_text.contains("blake3:output"));
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
            "kind": "model_invocation",
            "session_id": "s-route",
            "provider": "llm_shim",
            "model": "llama3:8b",
            "invocation_id": "inv-route",
            "prompt_hash": "blake3:prompt",
            "retrieval_set_hash": "blake3:retrieval",
            "output_hash": "blake3:output",
            "started_at": "2026-06-12T00:00:01Z",
            "completed_at": "2026-06-12T00:00:09Z",
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
    fn kind_predicate_matches_supported_draft_kinds() {
        assert!(is_stream_receipt_kind("context_injected"));
        assert!(is_stream_receipt_kind("stream_completed"));
        assert!(is_stream_receipt_kind("stream_aborted"));
        assert!(is_stream_receipt_kind("model_invocation"));
        assert!(!is_stream_receipt_kind("tool_mediation"));
        assert!(!is_stream_receipt_kind(""));
    }

    // ── Phase T usage-ping tests ────────────────────────────────────────

    fn read_usage_records(state: &AppState, group: &str) -> Vec<ObservationRecordV1> {
        let path = crate::http::observations::observation_file_path(&state.data_dir, &format!("usage::{group}"));
        let Ok(text) = std::fs::read_to_string(path) else {
            return Vec::new();
        };
        text.lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    }

    #[test]
    fn usage_kind_predicate() {
        assert!(is_usage_receipt_kind("usage_ping"));
        assert!(!is_usage_receipt_kind("context_injected"));
        assert!(!is_usage_receipt_kind(""));
        // The usage kind is NOT a stream kind — separate flag, separate path.
        assert!(!is_stream_receipt_kind("usage_ping"));
    }

    #[test]
    fn usage_ping_lifts_signs_and_records_metadata_only() {
        let state = signing_state();
        let draft = UsagePingDraft {
            event_class: Some("session".to_string()),
            count: Some(7),
            ..UsagePingDraft::default()
        };
        let (minted, submission) = mint_usage_receipt(&state, "operator", &draft).expect("mint usage");
        assert_eq!(minted.kind, USAGE_PING_KIND_V1);
        assert!(minted.body_hash.starts_with("blake3:"));

        // The metadata-only submission is built (but NOT sent) alongside the
        // local receipt: it mirrors the signed material and carries no content.
        assert_eq!(submission.receipt_id, minted.receipt_id);
        assert_eq!(submission.body_hash, minted.body_hash);
        assert_eq!(submission.event_class, "session");
        assert_eq!(submission.passport_fpr, state.passport_fpr);
        assert_eq!(submission.sig.signature_hex, minted.signature_hex);

        let records = read_usage_records(&state, "operator");
        assert_eq!(records.len(), 1);
        let payload = &records[0].payload;
        assert_eq!(payload["kind"], USAGE_PING_KIND_V1);
        assert_eq!(payload["event_class"], "session");
        assert_eq!(payload["count"], 7);

        let body = hex::decode(payload["body_cbor_hex"].as_str().expect("cbor hex")).expect("hex");
        assert!(corecrux_receipts::assert_usage_ping_kind_v1(&body));
        // Metadata-only: no content-bearing keys ride the canonical body.
        let body_text = String::from_utf8_lossy(&body);
        for content_key in ["fact_id", "entity", "entries", "prompt_hash", "corpus"] {
            assert!(
                !body_text.contains(content_key),
                "usage body must not carry {content_key}"
            );
        }

        // The daemon signature verifies over the canonical body bytes.
        let sig_hex = payload["sig"]["signature_hex"].as_str().expect("sig hex");
        let sig_bytes: [u8; 64] = hex::decode(sig_hex).expect("hex").try_into().expect("64 bytes");
        let pubkey: [u8; 32] = hex::decode(&state.passport_public_key_hex)
            .expect("pubkey hex")
            .try_into()
            .expect("32 bytes");
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&pubkey).expect("vk");
        vk.verify(&body, &ed25519_dalek::Signature::from_bytes(&sig_bytes))
            .expect("daemon signature verifies over canonical usage body bytes");

        // M1.1: the metadata-only submission now carries everything a collector
        // needs to VERIFY the ping without local access — the signed body bytes
        // (`body_cbor_hex`) and the daemon public key (`public_key_hex`) — and
        // both are consistent with the locally recorded receipt.
        assert_eq!(
            submission.body_cbor_hex,
            hex::encode(&body),
            "submission body_cbor_hex is the exact recorded canonical body"
        );
        let sub_pubkey: [u8; 32] = hex::decode(&submission.public_key_hex)
            .expect("submission pubkey hex")
            .try_into()
            .expect("32 bytes");
        assert_eq!(
            sub_pubkey, pubkey,
            "submission public key matches the daemon signing key"
        );
        // End to end: reconstruct the signed message from body_cbor_hex and
        // verify the signature with public_key_hex — exactly what the collector does.
        let sub_sig: [u8; 64] = hex::decode(&submission.sig.signature_hex)
            .expect("submission sig hex")
            .try_into()
            .expect("64 bytes");
        ed25519_dalek::VerifyingKey::from_bytes(&sub_pubkey)
            .expect("vk from submission pubkey")
            .verify(
                &hex::decode(&submission.body_cbor_hex).expect("body hex"),
                &ed25519_dalek::Signature::from_bytes(&sub_sig),
            )
            .expect("a collector can verify the ping from the submission fields alone");
    }

    #[test]
    fn usage_ping_unknown_event_class_is_rejected() {
        let state = signing_state();
        let draft = UsagePingDraft {
            event_class: Some("telemetry".to_string()),
            ..UsagePingDraft::default()
        };
        let err = mint_usage_receipt(&state, "operator", &draft).expect_err("must reject");
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(read_usage_records(&state, "operator").is_empty());
    }

    // ── M1 daemon-boot auto-emit ────────────────────────────────────────

    /// A fully-satisfied three-way submit gate. The endpoint is `http://` so
    /// that even if the (spawned) submit task runs, `submit_usage_ping` blocks
    /// egress on the https-only rule *before* any byte leaves — the test stays
    /// hermetic while still exercising gate-active → mint-once.
    fn opted_in_usage_submit() -> crate::usage_submit::UsageSubmitConfig {
        crate::usage_submit::UsageSubmitConfig {
            enabled: true,
            endpoint: Some("http://collector.example.com/usage".to_string()),
            consent_at: Some("2026-07-03T00:00:00Z".to_string()),
        }
    }

    #[test]
    fn boot_emit_is_inert_when_not_opted_in() {
        // Default (un-opted-in) config: the boot emit must mint NOTHING and
        // attempt no network — this is what keeps assert-no-phone-home green.
        let state = signing_state();
        assert!(
            state.usage_submit.active_endpoint().is_none(),
            "default config is not opted in"
        );
        emit_daemon_start_usage_ping(&state);
        // Keyed to the root passport fingerprint — assert that group is empty.
        assert!(
            read_usage_records(&state, &state.passport_fpr).is_empty(),
            "un-opted-in boot must not mint a usage receipt"
        );
    }

    #[tokio::test]
    async fn boot_emit_mints_exactly_one_daemon_start_when_opted_in() {
        // With the three-way gate satisfied, boot emits exactly one
        // `daemon_start` ping keyed to the daemon root passport. (tokio runtime
        // present so `maybe_spawn_submit`'s spawn_blocking has a handle; the
        // http:// endpoint means that task performs zero network.)
        let mut state = signing_state();
        state.usage_submit = opted_in_usage_submit();
        assert!(state.usage_submit.active_endpoint().is_some(), "gate is active");

        emit_daemon_start_usage_ping(&state);

        let records = read_usage_records(&state, &state.passport_fpr);
        assert_eq!(records.len(), 1, "exactly one daemon_start ping on boot");
        let payload = &records[0].payload;
        assert_eq!(payload["kind"], USAGE_PING_KIND_V1);
        assert_eq!(payload["event_class"], "daemon_start");

        // Metadata-only, and signed by the daemon over the canonical body.
        let body = hex::decode(payload["body_cbor_hex"].as_str().expect("cbor hex")).expect("hex");
        assert!(corecrux_receipts::assert_usage_ping_kind_v1(&body));

        // Idempotence guard is the caller's (once per boot); a second call would
        // mint a second receipt, so callers must invoke exactly once.
    }

    #[tokio::test]
    async fn usage_route_lifts_when_flag_on_and_rejects_when_off() {
        use axum::extract::State;

        let draft = serde_json::json!({
            "kind": "usage_ping",
            "event_class": "session",
            "count": 1,
        });

        // Flag ON → draft is lifted into a signed local receipt (201).
        let mut state = signing_state();
        state.usage_receipts_enabled = true;
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
        assert_eq!(read_usage_records(&state, "operator").len(), 1);

        // Flag OFF (default) → the usage dispatch is inert; the draft hits the
        // legacy tool-mediation parse and is rejected. Nothing is recorded.
        let mut state_off = signing_state();
        state_off.usage_receipts_enabled = false;
        let resp =
            crate::http::observations::post_mediation_receipt(State(state_off.clone()), HeaderMap::new(), Json(draft))
                .await;
        let status = resp.status();
        if status != StatusCode::UNPROCESSABLE_ENTITY {
            let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.expect("body");
            panic!("unexpected status {status}: {}", String::from_utf8_lossy(&bytes));
        }
        assert!(read_usage_records(&state_off, "operator").is_empty());
    }
    #[test]
    fn local_stream_receipt_verification_roundtrip() {
        let state = signing_state();
        let minted = mint_stream_receipt(&state, "operator", &injected_draft()).expect("mint");

        let found = crate::http::receipts::local_stream_receipt_verification(&state, &minted.receipt_id)
            .expect("resolve")
            .expect("receipt found in mediation logs");
        assert_eq!(found.tenant_id, "local", "stream receipts mint under the local tenant");
        assert!(found.verification.signature_valid, "daemon-signed receipt verifies");
        assert_eq!(found.verification.error_code, "OK");
        assert_eq!(found.verification.receipt_id, minted.receipt_id);

        // Unknown id resolves to None, not an error.
        let missing =
            crate::http::receipts::local_stream_receipt_verification(&state, "r_does-not-exist").expect("resolve");
        assert!(missing.is_none());
    }

    #[test]
    fn local_stream_receipt_verification_rejects_tampered_log() {
        let state = signing_state();
        let minted = mint_stream_receipt(&state, "operator", &injected_draft()).expect("mint");

        // Tamper the persisted body hex on disk: the record's daemon
        // envelope signature no longer matches, so resolution must fail
        // loudly rather than verify attacker-substituted material.
        let path = crate::http::observations::observation_file_path(&state.data_dir, "mediation::s-1");
        let text = std::fs::read_to_string(&path).expect("read log");
        let mut record: serde_json::Value = serde_json::from_str(text.lines().next().expect("one line")).expect("json");
        let body_hex = record["payload"]["body_cbor_hex"].as_str().expect("hex").to_string();
        let flipped = if body_hex.starts_with('a') {
            format!("b{}", &body_hex[1..])
        } else {
            format!("a{}", &body_hex[1..])
        };
        record["payload"]["body_cbor_hex"] = serde_json::Value::String(flipped);
        std::fs::write(&path, format!("{}\n", record)).expect("write tampered log");

        let err = crate::http::receipts::local_stream_receipt_verification(&state, &minted.receipt_id)
            .expect_err("tampered log must not resolve");
        assert!(
            err.contains("observation") || err.contains("chain") || err.contains("binding"),
            "error names the integrity failure: {err}"
        );
    }
}
