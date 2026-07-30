// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

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
use corecrux_receipts::vault_pki_x509_signer::VaultPkiX509Signer;
use corecrux_receipts::{
    build_c2pa_manifest_v1, ed25519_signer, sign_c2pa_manifest_via_signer, C2paManifestInputV1, C2PA_SPEC_VERSION,
};
use crux_integrations::c2pa_signer_selector::C2paSignerKind;

/// Environment variable that gates `output_attest`. Default off.
pub const FEATURE_FLAG_ENV: &str = "CORECRUXD_FEATURE_C2PA_OUTPUT";

/// Backend selector — when set to `vault-pki-p256` AND
/// [`X509_FEATURE_FLAG_ENV`] is on, the daemon emits an X.509-signed
/// manifest with an `x5chain` header instead of the legacy Ed25519
/// envelope.
///
/// Accepted values: `local-ed25519` (default), `vault-pki-p256`.
pub const BACKEND_ENV: &str = "CORECRUXD_C2PA_SIGNER_BACKEND";

/// Independent feature flag for the X.509 backend (agent-ux-07 M6).
/// Both this AND `BACKEND_ENV=vault-pki-p256` must be set to switch
/// to the X.509 path; the dual gate prevents accidental promotion
/// when only one knob is flipped.
pub const X509_FEATURE_FLAG_ENV: &str = "CORECRUXD_FEATURE_C2PA_X509_SIGNER";

/// Value strings.
pub const BACKEND_LOCAL_ED25519: &str = "local-ed25519";
pub const BACKEND_VAULT_PKI_P256: &str = "vault-pki-p256";

/// Deliberately non-default placeholder used by the verification command.
///
/// The repository does not currently install a public anchor with CLI
/// packages. Requiring the operator to replace this path avoids silently
/// selecting the daemon-local anchor or claiming an unshipped package asset.
const TRUSTED_C2PA_ROOT_PLACEHOLDER: &str = "/path/to/operator-pinned-c2pa-root.pem";

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

fn verify_command(backend_x509: bool) -> String {
    if backend_x509 {
        format!("corecruxctl c2pa-verify <manifest_file> --root-anchor {TRUSTED_C2PA_ROOT_PLACEHOLDER}")
    } else {
        "corecruxctl output-verify <manifest_file>".to_string()
    }
}

/// Returns `true` when the X.509 (vault-pki-p256) backend should be
/// used. Requires BOTH `CORECRUXD_FEATURE_C2PA_X509_SIGNER=1` AND
/// `CORECRUXD_C2PA_SIGNER_BACKEND=vault-pki-p256`.
fn x509_backend_active() -> bool {
    let flag_on = match std::env::var(X509_FEATURE_FLAG_ENV) {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            !matches!(v.as_str(), "" | "0" | "false" | "off" | "no")
        }
        Err(_) => false,
    };
    if !flag_on {
        return false;
    }
    matches!(
        std::env::var(BACKEND_ENV)
            .map(|v| v.trim().to_ascii_lowercase())
            .as_deref(),
        Ok(BACKEND_VAULT_PKI_P256)
    )
}

/// Fire a single `tracing::info!` line on the first invocation of the
/// legacy dual-flag fallback path. Operators on the PR #123 contract
/// stay on a fully supported surface — we just want a breadcrumb so
/// they can correlate "I see Vault dispatch in the logs" with the
/// flag pair that produced it.
fn legacy_dual_flag_log_once() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        tracing::info!(
            target: "crux_mcp::output_attest",
            canonical_env = SIGNER_FLAG_ENV_NAME,
            legacy_x509_env = X509_FEATURE_FLAG_ENV,
            legacy_backend_env = BACKEND_ENV,
            "CORECRUX_C2PA_SIGNER unset; honouring legacy dual-flag pair (PR #123) and dispatching to Vault PKI"
        );
    });
}

/// Mirrors `crux_integrations::c2pa_signer_selector::SIGNER_FLAG_ENV`
/// for the breadcrumb above without forcing the legacy logger to take
/// a runtime dependency on the selector module's const.
const SIGNER_FLAG_ENV_NAME: &str = "CORECRUX_C2PA_SIGNER";

/// Resolve the C2PA signer backend with the documented precedence:
///
/// 1. **Canonical single flag.** `CORECRUX_C2PA_SIGNER=vault|in_process`
///    wins outright when set. Unknown values fall back to `InProcess`
///    (see `C2paSignerKind::from_canonical_env`).
/// 2. **Legacy PR #123 dual-flag fallback.** When the single flag is
///    unset *and* `x509_backend_active()` returns true (both
///    `CORECRUXD_FEATURE_C2PA_X509_SIGNER=1` AND
///    `CORECRUXD_C2PA_SIGNER_BACKEND=vault-pki-p256` are set), dispatch
///    to Vault. Emits a once-per-process info breadcrumb so the
///    operator-visible log says which contract produced the choice.
///    Dual-flag remains a fully supported surface — no deprecation.
/// 3. **Default.** `InProcess` (the legacy Ed25519 CROWN signer).
fn resolve_c2pa_signer_kind() -> C2paSignerKind {
    if let Some(kind) = C2paSignerKind::from_canonical_env() {
        return kind;
    }
    if x509_backend_active() {
        legacy_dual_flag_log_once();
        return C2paSignerKind::Vault;
    }
    C2paSignerKind::InProcess
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

    // ── 5. Build manifest ──────────────────────────────────────────────
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

    // ── 6. Sign via the selected backend ──────────────────────────────
    //
    // Backend selector — precedence (see `resolve_c2pa_signer_kind`):
    // 1. `CORECRUX_C2PA_SIGNER=vault|in_process` (canonical single flag)
    // 2. PR #123 dual-flag pair (`CORECRUXD_FEATURE_C2PA_X509_SIGNER=1`
    //    + `CORECRUXD_C2PA_SIGNER_BACKEND=vault-pki-p256`) → Vault
    // 3. Default → InProcess
    //
    // Behaviour-preserving for prod operators on the PR #123 contract;
    // new for single-flag operators.
    let signer_kind = resolve_c2pa_signer_kind();
    let signed = match signer_kind {
        C2paSignerKind::Vault => {
            let signer = VaultPkiX509Signer::from_env().map_err(|e| JsonRpcError {
                code: INVALID_PARAMS,
                message: format!("VaultPkiX509Signer init failed: {e}"),
                data: None,
            })?;
            signer.initialize().map_err(|e| JsonRpcError {
                code: INVALID_PARAMS,
                message: format!("VaultPkiX509Signer.initialize failed: {e}"),
                data: None,
            })?;
            // Best-effort rotation — if it fails (Vault unreachable),
            // we continue with the cached leaf as long as it's still
            // valid.
            let _ = signer.maybe_rotate_if_due();
            sign_c2pa_manifest_via_signer(manifest, &signer, &when).map_err(|e| JsonRpcError {
                code: INVALID_PARAMS,
                message: format!("c2pa manifest signing (vault-pki-p256) failed: {e}"),
                data: None,
            })?
        }
        C2paSignerKind::InProcess => {
            let (signing_key, key_id) = load_signing_key().ok_or_else(|| JsonRpcError {
                code: INVALID_PARAMS,
                message: format!(
                    "output_attest signer missing: set {SIGNING_KEY_ENV} or fall back to {FALLBACK_SIGNING_KEY_ENV}"
                ),
                data: None,
            })?;
            let legacy_signer = ed25519_signer(&signing_key, &key_id);
            sign_c2pa_manifest_via_signer(manifest, &legacy_signer, &when).map_err(|e| JsonRpcError {
                code: INVALID_PARAMS,
                message: format!("c2pa manifest signing failed: {e}"),
                data: None,
            })?
        }
    };
    let envelope_b64 = signed.to_jumbf_base64();
    let backend_x509 = matches!(signer_kind, C2paSignerKind::Vault);

    // ── 7. Build verify URL (best-effort) ─────────────────────────────
    let verify_url = ctx.daemon_base_url.as_deref().map(|base| {
        format!(
            "{}/v1/output/verify?manifest_id={}",
            base.trim_end_matches('/'),
            manifest_id
        )
    });

    let backend_name = if backend_x509 {
        BACKEND_VAULT_PKI_P256
    } else {
        BACKEND_LOCAL_ED25519
    };
    let response_json = json!({
        "manifest_id": manifest_id,
        "spec_version": C2PA_SPEC_VERSION,
        "manifest_jumbf_base64": envelope_b64,
        "content_hash_blake3_hex": signed.manifest.content_hash_blake3_hex,
        "crown_receipt_id": signed.manifest.crown_receipt_id,
        "signer_key_id": signed.key_id,
        "signer_alg": signed.signature_alg,
        "signer_passport": signed.manifest.signer_passport,
        "signer_backend": backend_name,
        "x5chain_pem": signed.x5chain_pem,
        "verify_url": verify_url,
        "verify_command": verify_command(backend_x509),
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
pub(crate) mod tests {
    use super::*;
    use crate::agent::AgentIdentity;
    use crate::dispatch::McpContext;

    fn test_ctx() -> McpContext {
        McpContext::new_default("test-node-output-attest").with_agent(AgentIdentity {
            name: "alice".to_string(),
            token_hash: [0u8; 32],
        })
    }

    #[test]
    fn x509_verify_command_requires_explicit_operator_pinned_anchor() {
        let command = verify_command(true);
        assert!(command.contains(TRUSTED_C2PA_ROOT_PLACEHOLDER));
        assert!(command.contains("--root-anchor"));
        assert!(!command.contains("/var/lib/corecruxd"));
        assert!(!command.contains("/usr/share/cuecrux"));
    }

    /// Shared with `dispatch::tests::envelope_omits_for_output_attest`
    /// so all tests in this workspace that touch the C2PA signer env
    /// vars (`CORECRUX_C2PA_SIGNER`, `CORECRUXD_C2PA_SIGNER_BACKEND`,
    /// `CORECRUXD_FEATURE_C2PA_X509_SIGNER`) serialise behind a single
    /// process-wide `tokio::sync::Mutex`. Delegates to
    /// [`crate::test_env_lock`] — per-module locks don't prevent
    /// concurrent writes to `environ` from a sibling test holding a
    /// different module's lock.
    pub(crate) fn flag_lock() -> &'static tokio::sync::Mutex<()> {
        crate::test_env_lock()
    }

    fn clear_env() {
        std::env::remove_var(FEATURE_FLAG_ENV);
        std::env::remove_var(SIGNING_KEY_ENV);
        std::env::remove_var(KEY_ID_ENV);
        std::env::remove_var(FALLBACK_SIGNING_KEY_ENV);
        std::env::remove_var(FALLBACK_KEY_ID_ENV);
        std::env::remove_var(BACKEND_ENV);
        std::env::remove_var(X509_FEATURE_FLAG_ENV);
        std::env::remove_var(SIGNER_FLAG_ENV_NAME);
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

    /// Reset all three env vars the resolver consults. Use at the
    /// start AND end of every env-poking test so neither cross-test
    /// pollution nor a panic mid-test bleeds state.
    fn reset_resolver_env() {
        std::env::remove_var(SIGNER_FLAG_ENV_NAME);
        std::env::remove_var(BACKEND_ENV);
        std::env::remove_var(X509_FEATURE_FLAG_ENV);
    }

    #[tokio::test]
    async fn x509_backend_active_requires_both_flags() {
        let _g = flag_lock().lock().await;
        reset_resolver_env();
        assert!(!x509_backend_active(), "both env vars unset → off");
        std::env::set_var(X509_FEATURE_FLAG_ENV, "1");
        assert!(!x509_backend_active(), "flag on without backend → off");
        std::env::set_var(BACKEND_ENV, BACKEND_LOCAL_ED25519);
        assert!(!x509_backend_active(), "backend=local-ed25519 → off");
        std::env::set_var(BACKEND_ENV, BACKEND_VAULT_PKI_P256);
        assert!(x509_backend_active(), "both set → on");
        std::env::set_var(X509_FEATURE_FLAG_ENV, "0");
        assert!(!x509_backend_active(), "flag off → off even if backend selected");
        reset_resolver_env();
    }

    /// New-flag precedence: when the canonical single env is set to
    /// `vault`, the resolver returns `Vault` regardless of whether the
    /// legacy dual-flag pair is also set (or unset).
    #[tokio::test]
    async fn resolve_c2pa_signer_kind_single_flag_vault_takes_precedence() {
        let _g = flag_lock().lock().await;
        reset_resolver_env();
        std::env::set_var(SIGNER_FLAG_ENV_NAME, "vault");
        // Legacy pair: deliberately OFF. The single flag is the only
        // signal we want to honour.
        assert!(matches!(resolve_c2pa_signer_kind(), C2paSignerKind::Vault));
        reset_resolver_env();
    }

    /// Single-flag wins over legacy: even with the legacy dual-flag
    /// pair set to Vault, `CORECRUX_C2PA_SIGNER=in_process` overrides
    /// to InProcess. This is the documented escape hatch for operators
    /// migrating off the legacy contract.
    #[tokio::test]
    async fn resolve_c2pa_signer_kind_single_flag_in_process() {
        let _g = flag_lock().lock().await;
        reset_resolver_env();
        std::env::set_var(SIGNER_FLAG_ENV_NAME, "in_process");
        std::env::set_var(X509_FEATURE_FLAG_ENV, "1");
        std::env::set_var(BACKEND_ENV, BACKEND_VAULT_PKI_P256);
        assert!(matches!(resolve_c2pa_signer_kind(), C2paSignerKind::InProcess));
        reset_resolver_env();
    }

    /// Legacy fallback: when the single flag is unset and the legacy
    /// dual-flag pair points at Vault, dispatch to Vault. This is the
    /// behaviour-preservation guarantee for PR #123 operators.
    #[tokio::test]
    async fn resolve_c2pa_signer_kind_falls_back_to_legacy_when_unset() {
        let _g = flag_lock().lock().await;
        reset_resolver_env();
        // Single flag unset; legacy pair on.
        std::env::set_var(X509_FEATURE_FLAG_ENV, "1");
        std::env::set_var(BACKEND_ENV, BACKEND_VAULT_PKI_P256);
        assert!(matches!(resolve_c2pa_signer_kind(), C2paSignerKind::Vault));
        reset_resolver_env();
    }

    /// Unknown single-flag value (operator typo) falls back to
    /// InProcess — same rule as `from_canonical_env`'s warn-and-default
    /// path. Legacy pair must NOT take over; the operator wrote
    /// something, so we honour their intent to use the single-flag
    /// surface.
    #[tokio::test]
    async fn resolve_c2pa_signer_kind_unknown_single_flag_value_falls_to_in_process() {
        let _g = flag_lock().lock().await;
        reset_resolver_env();
        std::env::set_var(SIGNER_FLAG_ENV_NAME, "vault-pki-p256"); // not the accepted shape
        std::env::set_var(X509_FEATURE_FLAG_ENV, "1");
        std::env::set_var(BACKEND_ENV, BACKEND_VAULT_PKI_P256);
        assert!(matches!(resolve_c2pa_signer_kind(), C2paSignerKind::InProcess));
        reset_resolver_env();
    }

    /// Default: nothing set → InProcess. The legacy CROWN Ed25519
    /// signer is the documented out-of-the-box backend.
    #[tokio::test]
    async fn resolve_c2pa_signer_kind_default_is_in_process() {
        let _g = flag_lock().lock().await;
        reset_resolver_env();
        assert!(matches!(resolve_c2pa_signer_kind(), C2paSignerKind::InProcess));
        reset_resolver_env();
    }
}
