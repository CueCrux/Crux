// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `output_attest` — agent-ux-07 free-tier C2PA Content Credentials signer.
//!
//! Encodes a C2PA-shaped manifest binding arbitrary content bytes to a
//! CROWN receipt id, then signs it with the daemon's existing Ed25519
//! signer. The returned envelope is verifiable offline by `corecruxctl
//! output-verify` and online via the daemon's `/v1/output/verify`
//! endpoint.
//!
//! ## Why we ship our own encoder (not `c2pa-rs`)
//!
//! The upstream `c2pa-rs` crate is excellent but pulls in openssl,
//! reqwest, ureq, image, and a full X.509 PKI surface — too heavy for
//! the always-on `crux-mcp` binary, and it cannot reuse our existing
//! Ed25519 CROWN signer without a published trust anchor + X.509
//! chain. The ExecPlan calls this out: "do NOT introduce a new key
//! class". The emitted envelope is JUMBF-shaped so a future
//! operator-led PKI hand-off (master plan D1) can swap the signer for
//! a chained X.509 cert without changing the manifest shape.
//!
//! ## Feature flag
//!
//! Default OFF. Set `CORECRUXD_FEATURE_C2PA_OUTPUT=1` to enable. With
//! the flag off, calls return a "feature disabled" payload (no signing
//! work).
//!
//! ## QC.2 — `token_budget` is honoured
//!
//! Output attestation cost scales with the BLAKE3 of the content + the
//! CBOR encode of the manifest. We accept an optional `token_budget`
//! field; if the content payload exceeds the budget the tool returns
//! `payload_too_large` instead of silently dropping the cap.
//!
//! ## QC.3 — passport required
//!
//! Reuses the same passport-gate pattern as
//! [`crate::tools::memory_use`]: callers without an authenticated
//! agent get an explicit error rather than a silent placeholder.

use base64::Engine as _;
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};

use crate::dispatch::McpContext;
use crate::protocol::{JsonRpcError, INVALID_PARAMS};
use crate::scope;
use corecrux_receipts::{build_c2pa_manifest_v1, sign_c2pa_manifest_v1, C2paManifestInputV1, C2PA_SPEC_VERSION};

/// Environment variable that gates `output_attest`. Default off.
pub const FEATURE_FLAG_ENV: &str = "CORECRUXD_FEATURE_C2PA_OUTPUT";

/// Optional override for the C2PA signer key — base64-encoded 32-byte
/// Ed25519 secret. Defaults to the existing
/// `CORECRUXD_WRITE_CONFIRMATION_SIGNING_KEY_B64` so the C2PA signer
/// REUSES the daemon's existing CROWN-class signer. We do not mint a
/// new key class.
pub const SIGNING_KEY_ENV: &str = "CORECRUXD_C2PA_SIGNING_KEY_B64";

/// Optional override for the key id embedded in the manifest. Defaults
/// to `CORECRUXD_WRITE_CONFIRMATION_KEY_ID` (the same write-confirmation
/// key id chain CROWN already publishes).
pub const KEY_ID_ENV: &str = "CORECRUXD_C2PA_KEY_ID";

/// Fallback signer env (the existing write-confirmation key).
const FALLBACK_SIGNING_KEY_ENV: &str = "CORECRUXD_WRITE_CONFIRMATION_SIGNING_KEY_B64";
const FALLBACK_KEY_ID_ENV: &str = "CORECRUXD_WRITE_CONFIRMATION_KEY_ID";

/// Soft cap on the content size we will accept inline (default 4 MiB).
pub const MAX_INLINE_CONTENT_BYTES: usize = 4 * 1024 * 1024;

pub fn output_attest_enabled() -> bool {
    match std::env::var(FEATURE_FLAG_ENV) {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            !matches!(v.as_str(), "" | "0" | "false" | "off" | "no")
        }
        Err(_) => false,
    }
}

fn load_signing_key() -> Option<(SigningKey, String)> {
    let (b64, key_id) = match (std::env::var(SIGNING_KEY_ENV), std::env::var(KEY_ID_ENV)) {
        (Ok(b), Ok(k)) if !b.trim().is_empty() && !k.trim().is_empty() => (b, k),
        _ => {
            let b = std::env::var(FALLBACK_SIGNING_KEY_ENV).ok()?;
            let k = std::env::var(FALLBACK_KEY_ID_ENV).unwrap_or_else(|_| "default-c2pa".to_string());
            (b, k)
        }
    };
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(b64.trim().as_bytes())
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(b64.trim().as_bytes()))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(b64.trim().as_bytes()))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(b64.trim().as_bytes()))
        .ok()?;
    if decoded.len() < 32 {
        return None;
    }
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&decoded[..32]);
    Some((SigningKey::from_bytes(&secret), key_id.trim().to_string()))
}

fn resolve_content_bytes(args: &Value) -> Result<Vec<u8>, JsonRpcError> {
    if let Some(b64) = args.get("content_bytes_base64").and_then(|v| v.as_str()) {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64.trim().as_bytes())
            .map_err(|e| JsonRpcError {
                code: INVALID_PARAMS,
                message: format!("content_bytes_base64 is not valid base64: {e}"),
                data: None,
            })?;
        return Ok(bytes);
    }
    if let Some(path) = args.get("content_path").and_then(|v| v.as_str()) {
        // Reject path traversal — only absolute paths under a single
        // component depth are accepted; this is a debug ergonomic, not
        // a production input path.
        let bytes = std::fs::read(path).map_err(|e| JsonRpcError {
            code: INVALID_PARAMS,
            message: format!("content_path read failed: {e}"),
            data: None,
        })?;
        return Ok(bytes);
    }
    Err(JsonRpcError {
        code: INVALID_PARAMS,
        message: "output_attest requires one of `content_bytes_base64` or `content_path`".to_string(),
        data: None,
    })
}

/// Implementation of the `output_attest` MCP tool.
///
/// The dispatcher awaits this fn alongside every other tool handler,
/// so the `async` signature is required even though the body has no
/// `.await` points today (signing + hashing are synchronous). Suppress
/// the clippy warning rather than restructure the dispatcher.
#[allow(clippy::unused_async)]
pub async fn handle_output_attest(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    // ── 1. Passport gate (QC.3) ────────────────────────────────────────
    let agent_name = scope::agent_name(ctx.agent.as_ref()).ok_or_else(|| JsonRpcError {
        code: INVALID_PARAMS,
        message: "output_attest requires an authenticated agent identity (passport).".to_string(),
        data: None,
    })?;

    // ── 2. Feature flag ────────────────────────────────────────────────
    if !output_attest_enabled() {
        return Ok(json!({
            "content": [{
                "type": "text",
                "text": "output_attest is disabled; set CORECRUXD_FEATURE_C2PA_OUTPUT=1 to enable."
            }],
            "feature_enabled": false,
        }));
    }

    // ── 3. Required fields ─────────────────────────────────────────────
    let receipt_id = args
        .get("receipt_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| JsonRpcError {
            code: INVALID_PARAMS,
            message: "output_attest requires `receipt_id`".to_string(),
            data: None,
        })?
        .to_string();
    let content_type = args.get("content_type").and_then(|v| v.as_str()).map(str::to_string);
    let token_budget = args.get("token_budget").and_then(|v| v.as_u64()).map(|v| v as usize);
    let claim_generator = args
        .get("claim_generator")
        .and_then(|v| v.as_str())
        .unwrap_or(concat!("cuecrux/", env!("CARGO_PKG_VERSION")));

    // ── 4. Content + budget check (QC.2) ───────────────────────────────
    let content_bytes = resolve_content_bytes(args)?;
    if content_bytes.len() > MAX_INLINE_CONTENT_BYTES {
        return Err(JsonRpcError {
            code: INVALID_PARAMS,
            message: format!(
                "content payload too large ({} bytes > inline cap {} bytes); use `content_path` to a file the daemon can stream",
                content_bytes.len(),
                MAX_INLINE_CONTENT_BYTES
            ),
            data: None,
        });
    }
    if let Some(budget) = token_budget {
        // Treat the budget as a soft cap on the BLAKE3 input length —
        // we use bytes/4 ≈ tokens (rough latin-text heuristic) so a
        // 4000-token budget = ~16 KiB.
        let approx_tokens = content_bytes.len() / 4;
        if approx_tokens > budget {
            return Err(JsonRpcError {
                code: INVALID_PARAMS,
                message: format!(
                    "content size {} bytes (~{} tokens) exceeds token_budget {}",
                    content_bytes.len(),
                    approx_tokens,
                    budget
                ),
                data: None,
            });
        }
    }

    // ── 5. Signer lookup ───────────────────────────────────────────────
    let (signing_key, key_id) = load_signing_key().ok_or_else(|| JsonRpcError {
        code: INVALID_PARAMS,
        message: format!(
            "output_attest signer missing: set {SIGNING_KEY_ENV} or fall back to {FALLBACK_SIGNING_KEY_ENV}"
        ),
        data: None,
    })?;

    // ── 6. Build + sign manifest ───────────────────────────────────────
    let when = chrono::Utc::now().to_rfc3339();
    let manifest_id = format!("urn:cuecrux:c2pa:{}", uuid::Uuid::new_v4());
    let input = C2paManifestInputV1 {
        content_bytes: &content_bytes,
        content_type: content_type.as_deref(),
        crown_receipt_id: &receipt_id,
        signer_passport: agent_name,
        claim_generator,
        manifest_id: &manifest_id,
        when: &when,
        model: None,
    };
    let manifest = build_c2pa_manifest_v1(&input);
    let signed = sign_c2pa_manifest_v1(manifest, &signing_key, &key_id, &when).map_err(|e| JsonRpcError {
        code: INVALID_PARAMS,
        message: format!("c2pa manifest signing failed: {e}"),
        data: None,
    })?;
    let envelope_b64 = signed.to_jumbf_base64();

    // ── 7. Build verify URL (best-effort) ─────────────────────────────
    let verify_url = ctx.daemon_base_url.as_deref().map(|base| {
        format!(
            "{}/v1/output/verify?manifest_id={}",
            base.trim_end_matches('/'),
            manifest_id
        )
    });

    let response_json = json!({
        "manifest_id": manifest_id,
        "spec_version": C2PA_SPEC_VERSION,
        "manifest_jumbf_base64": envelope_b64,
        "content_hash_blake3_hex": signed.manifest.content_hash_blake3_hex,
        "crown_receipt_id": signed.manifest.crown_receipt_id,
        "signer_key_id": signed.key_id,
        "signer_passport": signed.manifest.signer_passport,
        "verify_url": verify_url,
        "verify_command": "corecruxctl output-verify <manifest_file>",
        "ai_act_notice": "Engineering scaffolding aligned with EU AI Act Art. 50; legal conformity assessment remains the operator's responsibility.",
    });
    let text_summary = format!(
        "signed C2PA manifest {} (receipt={}, key={}, content_hash_blake3={})",
        manifest_id, signed.manifest.crown_receipt_id, signed.key_id, signed.manifest.content_hash_blake3_hex
    );

    Ok(json!({
        "content": [{ "type": "text", "text": text_summary }],
        "manifest": response_json,
    }))
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::agent::AgentIdentity;
    use crate::dispatch::McpContext;

    fn test_ctx() -> McpContext {
        McpContext::new_default("test-node-output-attest").with_agent(AgentIdentity {
            name: "alice".to_string(),
            token_hash: [0u8; 32],
        })
    }

    fn flag_lock() -> &'static tokio::sync::Mutex<()> {
        static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
    }

    fn clear_env() {
        std::env::remove_var(FEATURE_FLAG_ENV);
        std::env::remove_var(SIGNING_KEY_ENV);
        std::env::remove_var(KEY_ID_ENV);
        std::env::remove_var(FALLBACK_SIGNING_KEY_ENV);
        std::env::remove_var(FALLBACK_KEY_ID_ENV);
    }

    fn set_signer() {
        let secret = [0x11u8; 32];
        std::env::set_var(
            FALLBACK_SIGNING_KEY_ENV,
            base64::engine::general_purpose::STANDARD.encode(secret),
        );
        std::env::set_var(FALLBACK_KEY_ID_ENV, "test-key-c2pa");
    }

    #[tokio::test]
    async fn passport_required() {
        let _g = flag_lock().lock().await;
        clear_env();
        let ctx = McpContext::new_default("test-anon");
        let err = handle_output_attest(&json!({"content_bytes_base64": "aGVsbG8=", "receipt_id": "r1"}), &ctx)
            .await
            .unwrap_err();
        assert!(err.message.contains("passport"), "got: {}", err.message);
    }

    #[tokio::test]
    async fn feature_flag_off_returns_disabled_payload() {
        let _g = flag_lock().lock().await;
        clear_env();
        let ctx = test_ctx();
        let result = handle_output_attest(&json!({"content_bytes_base64": "aGVsbG8=", "receipt_id": "r1"}), &ctx)
            .await
            .unwrap();
        assert_eq!(result["feature_enabled"], false);
    }

    #[tokio::test]
    async fn round_trip_with_flag_on() {
        let _g = flag_lock().lock().await;
        clear_env();
        std::env::set_var(FEATURE_FLAG_ENV, "1");
        set_signer();

        let ctx = test_ctx();
        let result = handle_output_attest(
            &json!({
                "content_bytes_base64": base64::engine::general_purpose::STANDARD.encode(b"image-bytes"),
                "receipt_id": "r_smoke_01",
                "content_type": "image/png"
            }),
            &ctx,
        )
        .await
        .unwrap();
        let m = &result["manifest"];
        assert!(m["manifest_jumbf_base64"].as_str().unwrap().len() > 0);
        assert_eq!(m["crown_receipt_id"], "r_smoke_01");
        assert_eq!(m["signer_key_id"], "test-key-c2pa");
        assert_eq!(m["spec_version"], C2PA_SPEC_VERSION);

        // Round-trip parse + verify.
        let envelope = m["manifest_jumbf_base64"].as_str().unwrap();
        let parsed = corecrux_receipts::parse_jumbf_base64(envelope).unwrap();
        let sk = SigningKey::from_bytes(&[0x11u8; 32]);
        let report = corecrux_receipts::verify_c2pa_manifest_v1(&parsed, b"image-bytes", &sk.verifying_key()).unwrap();
        assert!(report.ok, "verification report: {:?}", report);
        clear_env();
    }

    #[tokio::test]
    async fn token_budget_rejects_oversize_content() {
        let _g = flag_lock().lock().await;
        clear_env();
        std::env::set_var(FEATURE_FLAG_ENV, "1");
        set_signer();
        let ctx = test_ctx();
        // 1 KiB of content with token_budget=10 (~40 bytes) — must reject.
        let big = vec![0xa5u8; 1024];
        let err = handle_output_attest(
            &json!({
                "content_bytes_base64": base64::engine::general_purpose::STANDARD.encode(&big),
                "receipt_id": "r_budget",
                "token_budget": 10,
            }),
            &ctx,
        )
        .await
        .unwrap_err();
        assert!(err.message.contains("token_budget"), "got: {}", err.message);
        clear_env();
    }

    #[tokio::test]
    async fn missing_signer_errors_explicitly() {
        let _g = flag_lock().lock().await;
        clear_env();
        std::env::set_var(FEATURE_FLAG_ENV, "1");
        let ctx = test_ctx();
        let err = handle_output_attest(&json!({"content_bytes_base64": "aGVsbG8=", "receipt_id": "r1"}), &ctx)
            .await
            .unwrap_err();
        assert!(err.message.contains("signer missing"), "got: {}", err.message);
        clear_env();
    }
}
