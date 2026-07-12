// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Signed Result Envelope import endpoint (W2.D2).
//!
//! `POST /v1/result-envelope/import` accepts a [`ResultEnvelope`], verifies the
//! platform Ed25519 signature against pinned trusted keys, and on success
//! applies the open-format payload through *existing* store surfaces:
//!
//! - `facts[]`  → `FactStore::try_store_bulk` (the `/v1/facts/bulk` path), with
//!   `source_receipt` stamped `result-envelope:<job_id>` when absent.
//! - `entities[]` → `EntityStore::upsert` (the `entity_upsert` surface).
//! - `edges[]`  → `EdgeStore::upsert` (the `edge_upsert` surface).
//!
//! Idempotency: keyed on `job_id`. A prior import receipt for the same job whose
//! recorded content hash matches the incoming envelope short-circuits to a
//! re-ack without re-writing (the upsert/bulk surfaces are themselves
//! upsert-safe, so a retry after a partial import is also safe).
//!
//! Companion artifacts: in v0.1 the envelope carries only out-of-band artefact
//! *descriptors* (`fetch_url`, `art_<blake3>` id, size) — no inline bytes. We
//! record the descriptors in the import receipt; actually fetching and
//! `artefact_put`-ing them is deferred (see the `companion_artifacts` note in
//! the import-receipt value and the module-level TODO below).
//!
//! Spec: `Result-Envelope-Spec-v0_1.md` §3.
//!
//! TODO(W3): pull + `artefact_put` companion blobs (gated by
//! `CORECRUXD_FEATURE_ARTEFACTS`), with the indefinite-TTL class resolved in
//! spec open-question §6.2.

use super::*;
use corecrux_memory::fact_store::StoreFact;
use corecrux_memory::result_envelope::{
    verify_result_envelope, EnvelopeVerifyError, ResultEnvelope, TrustedPlatformKey,
};
use serde_json::json;

/// Env var holding pinned platform verification keys, inline.
/// Format: `key_id:pubkey_hex,key_id2:pubkey_hex2` (whitespace tolerated).
/// `pubkey_hex` is the 64-hex Ed25519 public key.
const TRUSTED_KEYS_ENV: &str = "CORECRUXD_RESULT_ENVELOPE_KEYS";

/// Parse pinned platform keys from the `CORECRUXD_RESULT_ENVELOPE_KEYS` env var.
///
/// Provisioning: ship the active platform key(s) in the daemon's environment
/// (or a systemd `EnvironmentFile`). Rotation = update the env with both the old
/// and new key during the overlap window, then drop the old key. No PKI, no
/// network fetch at verify time — keys are pinned, mirroring the receipts
/// keyring convention (`CORECRUXD_RECEIPTS_KEYRING_PATH`).
fn load_trusted_platform_keys() -> Vec<TrustedPlatformKey> {
    let Ok(raw) = std::env::var(TRUSTED_KEYS_ENV) else {
        return Vec::new();
    };
    raw.split(',')
        .filter_map(|entry| {
            let entry = entry.trim();
            if entry.is_empty() {
                return None;
            }
            let (key_id, pubkey_hex) = entry.split_once(':')?;
            let key_id = key_id.trim();
            let pubkey_hex = pubkey_hex.trim();
            if key_id.is_empty() || pubkey_hex.is_empty() {
                return None;
            }
            Some(TrustedPlatformKey {
                key_id: key_id.to_string(),
                public_key_hex: pubkey_hex.to_string(),
            })
        })
        .collect()
}

/// Entity used for per-job import receipts: `__result_envelope__::<tenant_id>`,
/// `key = <job_id>`, `private: true` (§3.3).
fn import_receipt_entity(tenant_id: &str) -> String {
    format!("__result_envelope__::{tenant_id}")
}

fn verify_status(err: &EnvelopeVerifyError) -> StatusCode {
    match err {
        // A bad *pinned* key is an operator config error.
        EnvelopeVerifyError::MalformedPubkey { .. } => StatusCode::INTERNAL_SERVER_ERROR,
        // Every other case is a rejected (untrusted / malformed) envelope —
        // a client error. `problem_response` only renders a fixed status set
        // (`problem_for_status`); 400 is the supported client-error code, so
        // all envelope-integrity rejections surface as 400 with a precise
        // `detail` rather than collapsing to a generic 500.
        _ => StatusCode::BAD_REQUEST,
    }
}

pub(super) async fn post_result_envelope_import(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(envelope): Json<ResultEnvelope>,
) -> Response {
    // ---- Tenant validation + write authz (reuse the sync-plane gate) -------
    let tenant_id = envelope.tenant_id.clone();
    if tenant_id.trim().is_empty() {
        return problem_response(StatusCode::BAD_REQUEST, "tenant_id must not be empty");
    }
    if tenant_id.contains('/') {
        return problem_response(StatusCode::BAD_REQUEST, "tenant_id must not contain '/'");
    }
    if envelope.job_id.trim().is_empty() || envelope.job_id.len() > 128 {
        return problem_response(StatusCode::BAD_REQUEST, "job_id must be non-empty and <= 128 chars");
    }
    {
        let ctx = match crate::auth::http_scope_context(&state.auth, &headers) {
            Ok(ctx) => ctx,
            Err(err) => return err.into_response(),
        };
        if !ctx.has_scope("admin:write") {
            if let Err(err) = require_http_scopes_for_tenant(&state.auth, &headers, &["facts:write"], &tenant_id) {
                return err.into_response();
            }
        }
    }

    // ---- Passport binding (§2.1 passport_fpr): mismatch → reject ------------
    if let Some(envelope_fpr) = envelope.passport_fpr.as_deref() {
        if envelope_fpr != state.passport_fpr {
            return problem_response(
                StatusCode::FORBIDDEN,
                format!(
                    "passport mismatch: envelope={envelope_fpr}, daemon={}",
                    state.passport_fpr
                ),
            );
        }
    }

    // ---- 1) Verify signature + content hash BEFORE any write ---------------
    let trusted = load_trusted_platform_keys();
    if trusted.is_empty() {
        return problem_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("no trusted platform keys pinned (set {TRUSTED_KEYS_ENV})"),
        );
    }
    let content_hash_bytes = match verify_result_envelope(&envelope, &trusted) {
        Ok(hash) => hash,
        Err(err) => {
            let status = verify_status(&err);
            // Record a private incident fact on signature/hash failure (§5).
            if matches!(
                err,
                EnvelopeVerifyError::BadSignature(_) | EnvelopeVerifyError::HashMismatch { .. }
            ) {
                let mut store = state.fact_store.write().await;
                store.store(StoreFact {
                    tenant_hash: "default".to_string(),
                    entity: format!("__result_envelope_incident__::{tenant_id}"),
                    key: envelope.job_id.clone(),
                    value: json!({
                        "schema": "crux.result_envelope.import_incident.v1",
                        "job_id": envelope.job_id,
                        "reason": err.to_string(),
                        "at": chrono::Utc::now().to_rfc3339(),
                    })
                    .to_string(),
                    source_receipt: Some(format!("result-envelope:{}", envelope.job_id)),
                    confidence: 1.0,
                    private: true,
                    horizon_class: None,
                    actor: Some("platform:extraction".into()),
                });
            }
            return problem_response(status, format!("envelope verification failed: {err}"));
        }
    };
    let content_hash = format!("blake3:{}", hex::encode(content_hash_bytes));

    // ---- Idempotency: prior receipt for this job_id with matching hash ------
    let receipt_entity = import_receipt_entity(&tenant_id);
    {
        let store = state.fact_store.read().await;
        for fact in store.get_by_entity(&receipt_entity) {
            if fact.key != envelope.job_id {
                continue;
            }
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(&fact.value) {
                let prior_hash = value
                    .get("blake3_content_hash")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                if prior_hash == content_hash {
                    return (
                        StatusCode::OK,
                        Json(json!({
                            "schema": "crux.result_envelope.import.v1",
                            "job_id": envelope.job_id,
                            "tenant_id": tenant_id,
                            "status": "already_imported",
                            "blake3_content_hash": content_hash,
                        })),
                    )
                        .into_response();
                }
                return problem_response(
                    StatusCode::CONFLICT,
                    format!(
                        "job_id {} already imported with a different content hash",
                        envelope.job_id
                    ),
                );
            }
        }
    }

    // ---- 2a) Apply facts via the bulk store path ---------------------------
    let facts_in = &envelope.payload.facts;
    if facts_in.iter().any(|f| f.private) {
        return problem_response(
            StatusCode::BAD_REQUEST,
            "envelope facts must not be private (platform never emits private facts)",
        );
    }
    let facts_applied = {
        let mut store = state.fact_store.write().await;
        let reqs: Vec<StoreFact> = facts_in
            .iter()
            .map(|f| StoreFact {
                tenant_hash: "default".to_string(),
                entity: f.entity.clone(),
                key: f.key.clone(),
                value: f.value.clone(),
                source_receipt: Some(
                    f.source_receipt
                        .clone()
                        .unwrap_or_else(|| format!("result-envelope:{}", envelope.job_id)),
                ),
                confidence: f.confidence,
                private: false,
                horizon_class: None,
                actor: Some(f.actor.clone().unwrap_or_else(|| "platform:extraction".into())),
            })
            .collect();
        match store.try_store_bulk(reqs) {
            Ok(stored) => stored.len(),
            Err(err) => {
                return problem_response(StatusCode::INTERNAL_SERVER_ERROR, format!("fact import failed: {err}"))
            }
        }
    };

    // ---- 2b) Apply entities via entity_upsert (import before edges) --------
    let mut entities_applied = 0usize;
    {
        let registry = state.kind_registry.read().await;
        let mut store = state.entity_store.write().await;
        for ent in &envelope.payload.entities {
            if ent.kind.trim().is_empty() || ent.id.trim().is_empty() {
                return problem_response(StatusCode::BAD_REQUEST, "entity kind/id must be non-empty");
            }
            let registry_opt = if registry.is_registered(&ent.kind) {
                Some(&*registry)
            } else {
                None
            };
            match store.upsert(
                &ent.kind,
                &ent.id,
                ent.payload.clone(),
                "platform:extraction",
                registry_opt,
            ) {
                Ok(_) => entities_applied += 1,
                Err(err) => {
                    return problem_response(
                        StatusCode::BAD_REQUEST,
                        format!("entity upsert failed ({}/{}): {err}", ent.kind, ent.id),
                    )
                }
            }
        }
    }

    // ---- 2c) Apply edges via edge_upsert -----------------------------------
    let mut edges_applied = 0usize;
    {
        let mut store = state.edge_store.write().await;
        for edge in &envelope.payload.edges {
            match store.upsert(
                &edge.from_kind,
                &edge.from_id,
                &edge.edge_kind,
                &edge.to_kind,
                &edge.to_id,
                edge.payload.clone(),
                "platform:extraction",
            ) {
                Ok(_) => edges_applied += 1,
                Err(err) => return problem_response(StatusCode::BAD_REQUEST, format!("edge upsert failed: {err}")),
            }
        }
    }

    // ---- 3) Import receipt (private fact, §3.3) ----------------------------
    let companion_summary: Vec<serde_json::Value> = envelope
        .companion_artifacts
        .iter()
        .map(|a| {
            json!({
                "artefact_id": a.artefact_id,
                "size_bytes": a.size_bytes,
                "purpose_tag": a.purpose_tag,
                "sealed": a.sealed,
                // Deferred: descriptors recorded, blob fetch + artefact_put is W3.
                "custody": "descriptor_only_pending_fetch",
            })
        })
        .collect();

    let receipt_value = json!({
        "schema": "crux.result_envelope.import.v1",
        "job_id": envelope.job_id,
        "tenant_id": tenant_id,
        "blake3_content_hash": content_hash,
        "credit_spend_receipt": envelope.credit_spend_receipt,
        "key_id": envelope.platform_signature.key_id,
        "imported_at": chrono::Utc::now().to_rfc3339(),
        "counts": {
            "facts": facts_applied,
            "entities": entities_applied,
            "edges": edges_applied,
            "companion_artifacts": envelope.companion_artifacts.len(),
        },
        "companion_artifacts": companion_summary,
    });
    {
        let mut store = state.fact_store.write().await;
        store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: receipt_entity,
            key: envelope.job_id.clone(),
            value: receipt_value.to_string(),
            source_receipt: Some(format!("result-envelope:{}", envelope.job_id)),
            confidence: 1.0,
            private: true,
            horizon_class: None,
            actor: Some("platform:extraction".into()),
        });
    }

    (
        StatusCode::CREATED,
        Json(json!({
            "schema": "crux.result_envelope.import.v1",
            "job_id": envelope.job_id,
            "tenant_id": tenant_id,
            "status": "imported",
            "blake3_content_hash": content_hash,
            "counts": {
                "facts": facts_applied,
                "entities": entities_applied,
                "edges": edges_applied,
                "companion_artifacts": envelope.companion_artifacts.len(),
            },
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::tests::test_app_state;
    use axum::body::to_bytes;
    use corecrux_memory::result_envelope::{
        result_envelope_content_hash, CompanionArtifact, EnvelopeEdge, EnvelopeEntity, EnvelopeFact, EnvelopePayload,
        PlatformSignature, RESULT_ENVELOPE_SCHEMA_V1,
    };
    use ed25519_dalek::{Signer as _, SigningKey};

    const KEY_ID: &str = "platform-result-test";

    /// The trusted-keys env var is process-wide; serialize every test that
    /// reads or writes it so parallel cases don't clobber each other (mirrors
    /// `OBSERVE_ENV_LOCK` in `observe_audit.rs`).
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct EnvKeyGuard(#[allow(dead_code)] std::sync::MutexGuard<'static, ()>);
    impl Drop for EnvKeyGuard {
        fn drop(&mut self) {
            std::env::remove_var(TRUSTED_KEYS_ENV);
        }
    }

    /// Generate a signing key, pin its pubkey in the env, return the key + guard.
    /// The guard holds the `ENV_LOCK` for the test's duration and clears the var
    /// on drop.
    fn pin_platform_key() -> (SigningKey, EnvKeyGuard) {
        let lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let signing = SigningKey::from_bytes(&[5_u8; 32]);
        let pubkey_hex = hex::encode(signing.verifying_key().to_bytes());
        std::env::set_var(TRUSTED_KEYS_ENV, format!("{KEY_ID}:{pubkey_hex}"));
        (signing, EnvKeyGuard(lock))
    }

    fn build_envelope(signing: &SigningKey, job_id: &str) -> ResultEnvelope {
        let payload = EnvelopePayload {
            facts: vec![EnvelopeFact {
                entity: "business::acme::person::ada".into(),
                key: "role".into(),
                value: "mathematician".into(),
                source_receipt: None,
                confidence: 0.92,
                private: false,
                horizon_class: None,
                actor: None,
            }],
            entities: vec![EnvelopeEntity {
                kind: "person".into(),
                id: "p_ada".into(),
                payload: serde_json::json!({"name": "Ada"}),
            }],
            edges: vec![EnvelopeEdge {
                from_kind: "person".into(),
                from_id: "p_ada".into(),
                edge_kind: "works_at".into(),
                to_kind: "org".into(),
                to_id: "o_acme".into(),
                payload: serde_json::json!({}),
            }],
        };
        let artifacts = vec![CompanionArtifact {
            artefact_id: "art_abc123".into(),
            size_bytes: 4096,
            mime_type: Some("application/x-cuecrux-sealed".into()),
            sealed: true,
            purpose_tag: "projection".into(),
            fetch_url: Some("https://platform.example/a".into()),
        }];
        let content_hash = result_envelope_content_hash(&payload, &artifacts).expect("hash");
        let raw = hex::decode(content_hash.strip_prefix("blake3:").unwrap()).unwrap();
        let mut hash = [0_u8; 32];
        hash.copy_from_slice(&raw);
        let sig = signing.sign(&hash);
        ResultEnvelope {
            schema_version: RESULT_ENVELOPE_SCHEMA_V1.into(),
            job_id: job_id.into(),
            tenant_id: "business::acme".into(),
            passport_fpr: None,
            credit_spend_receipt: Some("crown:r_1".into()),
            payload,
            companion_artifacts: artifacts,
            blake3_content_hash: content_hash,
            platform_signature: PlatformSignature {
                alg: "ed25519".into(),
                key_id: KEY_ID.into(),
                signature: hex::encode(sig.to_bytes()),
            },
        }
    }

    async fn body_json(resp: Response) -> (StatusCode, serde_json::Value) {
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, value)
    }

    #[tokio::test]
    async fn valid_envelope_imports_facts_and_writes_receipt() {
        let (signing, _guard) = pin_platform_key();
        let state = test_app_state(8);
        let envelope = build_envelope(&signing, "job_ok_1");

        let resp = post_result_envelope_import(State(state.clone()), HeaderMap::new(), Json(envelope)).await;
        let (status, body) = body_json(resp).await;
        assert_eq!(status, StatusCode::CREATED, "body={body}");
        assert_eq!(body["status"], "imported");
        assert_eq!(body["counts"]["facts"], 1);
        assert_eq!(body["counts"]["entities"], 1);
        assert_eq!(body["counts"]["edges"], 1);

        // Fact is queryable.
        {
            let store = state.fact_store.read().await;
            let hits = store.get_by_entity("business::acme::person::ada");
            assert_eq!(hits.len(), 1);
            assert_eq!(hits[0].value, "mathematician");
        }
        // Import receipt written, private.
        {
            let store = state.fact_store.read().await;
            let receipts = store.get_by_entity("__result_envelope__::business::acme");
            assert_eq!(receipts.len(), 1);
            assert!(receipts[0].private);
            assert_eq!(receipts[0].key, "job_ok_1");
        }
    }

    #[tokio::test]
    async fn tampered_payload_is_rejected() {
        let (signing, _guard) = pin_platform_key();
        let state = test_app_state(8);
        let mut envelope = build_envelope(&signing, "job_tamper");
        envelope.payload.facts[0].value = "forged".into();

        let resp = post_result_envelope_import(State(state.clone()), HeaderMap::new(), Json(envelope)).await;
        let (status, body) = body_json(resp).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body={body}");
        // No fact written.
        let store = state.fact_store.read().await;
        assert!(store.get_by_entity("business::acme::person::ada").is_empty());
    }

    #[tokio::test]
    async fn wrong_signer_is_rejected() {
        let (_signing, _guard) = pin_platform_key();
        let state = test_app_state(8);
        // Sign with a different key than the pinned one.
        let attacker = SigningKey::from_bytes(&[9_u8; 32]);
        let envelope = build_envelope(&attacker, "job_evil");

        let resp = post_result_envelope_import(State(state.clone()), HeaderMap::new(), Json(envelope)).await;
        let (status, _body) = body_json(resp).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let store = state.fact_store.read().await;
        assert!(store.get_by_entity("business::acme::person::ada").is_empty());
    }

    #[tokio::test]
    async fn reimport_same_job_is_idempotent() {
        let (signing, _guard) = pin_platform_key();
        let state = test_app_state(8);
        let envelope = build_envelope(&signing, "job_idem");

        let r1 = post_result_envelope_import(State(state.clone()), HeaderMap::new(), Json(envelope.clone())).await;
        assert_eq!(r1.status(), StatusCode::CREATED);

        let r2 = post_result_envelope_import(State(state.clone()), HeaderMap::new(), Json(envelope)).await;
        let (status, body) = body_json(r2).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "already_imported");

        // Exactly one fact + one receipt — no duplicates.
        let store = state.fact_store.read().await;
        assert_eq!(store.get_by_entity("business::acme::person::ada").len(), 1);
        assert_eq!(store.get_by_entity("__result_envelope__::business::acme").len(), 1);
    }

    #[tokio::test]
    async fn missing_pinned_keys_is_server_error() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var(TRUSTED_KEYS_ENV);
        let signing = SigningKey::from_bytes(&[5_u8; 32]);
        let state = test_app_state(8);
        let envelope = build_envelope(&signing, "job_nokeys");
        let resp = post_result_envelope_import(State(state), HeaderMap::new(), Json(envelope)).await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
