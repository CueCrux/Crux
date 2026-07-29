// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! `receipt_verify` — agent-ux-04 source-linked traceability tool.
//!
//! One-click "is this receipt really signed by who it claims?" check from
//! chat. The tool calls the daemon's existing
//! `GET /v1/receipts/{id}/verification` route over loopback and re-shapes
//! the verifier's report into a minimal `{verified, signer_passport,
//! errors[]}` payload that a host IDE can render next to a clickable
//! receipt-id badge.
//!
//! ## Design notes
//!
//! - **NOT** opted into the audit envelope (it isn't a memory retrieval —
//!   it produces no `memories_used[]`). See [`crate::tools::tool_emits_envelope`].
//! - **Requires a passport** (QC.3 in the child plan). The audit pattern is
//!   that only the signer or an operator should re-verify; we enforce
//!   "authenticated agent" at the MCP boundary and let the daemon's HTTP
//!   route enforce tenant scope.
//! - **Feature-flagged** behind `CORECRUXD_FEATURE_RECEIPT_VERIFY=1`. Default
//!   OFF — the catalogue entry is always present so listings are stable; with
//!   the flag off, calls return a "feature disabled" payload.
//! - **No envelope-builder is registered** for this tool — the dispatcher's
//!   `maybe_wrap_with_envelope` therefore returns the raw payload even when
//!   the audit-envelope flag is on. This is the right shape for a verifier
//!   call: the envelope's `memories_used` would always be empty.

use serde_json::{json, Value};

use crate::dispatch::McpContext;
use crate::protocol::{JsonRpcError, INTERNAL_ERROR, INVALID_PARAMS};
use crate::scope;
use crate::tools::loopback_auth::loopback_bearer_token;

/// Environment variable that gates the `receipt_verify` tool. Default OFF.
///
/// Same parsing convention as [`crate::envelope::FEATURE_FLAG_ENV`]: any
/// value other than `"0"|"false"|"off"|"no"|""` enables the tool.
pub const FEATURE_FLAG_ENV: &str = "CORECRUXD_FEATURE_RECEIPT_VERIFY";

/// HTTP scopes minted into the loopback bearer for the verification call.
const SCOPES: &str = "receipts:read";

/// Default tenant used when the caller does not pass `tenant_id`.
const DEFAULT_TENANT: &str = "default";

/// Return `true` iff the flag is enabled.
pub fn receipt_verify_enabled() -> bool {
    match std::env::var(FEATURE_FLAG_ENV) {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            !matches!(v.as_str(), "" | "0" | "false" | "off" | "no")
        }
        Err(_) => false,
    }
}

/// Build the verification URL for `(tenant_id, receipt_id)` against the
/// loopback base. Trailing slash on `base_url` is tolerated.
pub fn build_verification_url(base_url: &str, tenant_id: &str, receipt_id: &str) -> String {
    let base = base_url.trim_end_matches('/');
    let receipt_id_enc = urlencoding(receipt_id);
    let tenant_id_enc = urlencoding(tenant_id);
    format!("{base}/v1/receipts/{receipt_id_enc}/verification?tenant_id={tenant_id_enc}")
}

/// RFC 3986 unreserved-only percent-encoding. Mirrors the local helper used
/// by `tools/github.rs` and `tools/coordination.rs` so the crate stays free
/// of an extra `urlencoding` dependency.
fn urlencoding(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
            _ => format!("%{:02X}", c as u8),
        })
        .collect()
}

/// `receipt_verify(receipt_id, tenant_id?)` — re-verify a receipt.
///
/// Returns:
/// ```jsonc
/// {
///   "content": [{"type": "text", "text": "verified | not verified | feature disabled"}],
///   "receipt_id": "...",
///   "verified": true | false,
///   "signer_passport": "key_id-or-pubkey-fingerprint" | null,
///   "errors": ["BODY_HASH_MISMATCH", ...],
///   "feature_enabled": true | false,
///   "report": { ...full VerificationReportV1... } // only when feature_enabled
/// }
/// ```
pub async fn handle_receipt_verify(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    // ── 1. Passport gate (QC.3) ─────────────────────────────────────────
    let _agent_name = scope::agent_name(ctx.agent.as_ref()).ok_or_else(|| JsonRpcError {
        code: INVALID_PARAMS,
        message: "receipt_verify requires an authenticated agent identity (passport). \
                  Only the receipt's signer or an operator should re-verify; \
                  set CRUX_AGENT_TOKEN or CRUX_AGENT_TOKENS and pass a Bearer header."
            .to_string(),
        data: Some(json!({"requires_agent_identity": true})),
    })?;

    // ── 2. Parse args ──────────────────────────────────────────────────
    let receipt_id = args
        .get("receipt_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| JsonRpcError {
            code: INVALID_PARAMS,
            message: "receipt_id is required".to_string(),
            data: None,
        })?
        .trim()
        .to_string();
    if receipt_id.is_empty() {
        return Err(JsonRpcError {
            code: INVALID_PARAMS,
            message: "receipt_id must be a non-empty string".to_string(),
            data: None,
        });
    }
    let tenant_id = args
        .get("tenant_id")
        .and_then(|v| v.as_str())
        .map_or_else(|| DEFAULT_TENANT.to_string(), str::to_string);

    // ── 3. Flag gate ───────────────────────────────────────────────────
    if !receipt_verify_enabled() {
        return Ok(json!({
            "content": [{
                "type": "text",
                "text": format!(
                    "receipt_verify: feature disabled (CORECRUXD_FEATURE_RECEIPT_VERIFY off). \
                     Receipt {receipt_id} not re-verified. Set the flag at deploy time to enable."
                )
            }],
            "receipt_id": receipt_id,
            "tenant_id": tenant_id,
            "feature_enabled": false,
            "verified": false,
            "errors": ["FEATURE_DISABLED"],
        }));
    }

    // ── 4. Loopback HTTP call ──────────────────────────────────────────
    let base_url = ctx.daemon_base_url.as_deref().ok_or_else(|| JsonRpcError {
        code: INTERNAL_ERROR,
        message: "daemon_base_url not configured; receipt_verify requires loopback to corecruxd".to_string(),
        data: None,
    })?;
    let url = build_verification_url(base_url, &tenant_id, &receipt_id);
    let (status, body) = loopback_get(url).await?;

    // ── 5. Re-shape into the public payload ───────────────────────────
    let (verified, signer, errors, report) = parse_verification_report(status, &body);

    let text = if verified {
        format!(
            "verified receipt {receipt_id} (signer={})",
            signer.as_deref().unwrap_or("unknown")
        )
    } else if errors.is_empty() {
        format!("could not verify receipt {receipt_id} (status={status})")
    } else {
        format!("could not verify receipt {receipt_id}: {}", errors.join(", "))
    };

    Ok(json!({
        "content": [{"type": "text", "text": text}],
        "receipt_id": receipt_id,
        "tenant_id": tenant_id,
        "feature_enabled": true,
        "verified": verified,
        "signer_passport": signer,
        "errors": errors,
        "http_status": status,
        "report": report,
    }))
}

/// Parse a verification-report HTTP response.
///
/// Returns `(verified, signer_passport, errors, raw_report_value)`.
/// - `verified` requires HTTP 200 AND `error_code == "OK"` AND
///   `signature_valid == true` AND `integrity.payload_hash_matches == true`.
/// - `signer_passport` is best-effort: prefers `pubkey_fingerprint`, then
///   `signature.key_id`.
/// - `errors` is non-empty whenever `verified == false`.
fn parse_verification_report(status: u16, body: &str) -> (bool, Option<String>, Vec<String>, Value) {
    let raw: Value = serde_json::from_str(body).unwrap_or(Value::Null);

    if status != 200 {
        let mut errors = vec![format!("HTTP_{status}")];
        if let Some(title) = raw.get("title").and_then(|v| v.as_str()) {
            errors.push(title.to_string());
        } else if status == 0 {
            errors.push("loopback_unreachable".to_string());
        }
        return (false, None, errors, raw);
    }

    let signature_valid = raw.get("signature_valid").and_then(Value::as_bool).unwrap_or(false);
    let hash_matches = raw
        .get("integrity")
        .and_then(|i| i.get("payload_hash_matches"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let error_code = raw
        .get("error_code")
        .and_then(Value::as_str)
        .unwrap_or("UNKNOWN")
        .to_string();

    let signer = raw
        .get("pubkey_fingerprint")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| {
            raw.get("signature")
                .and_then(|s| s.get("key_id"))
                .and_then(Value::as_str)
                .map(str::to_string)
        });

    let verified = signature_valid && hash_matches && error_code == "OK";

    let mut errors: Vec<String> = Vec::new();
    if !verified {
        if error_code != "OK" {
            errors.push(error_code);
        }
        if !hash_matches {
            errors.push("PAYLOAD_HASH_MISMATCH".to_string());
        }
        if !signature_valid {
            errors.push("SIGNATURE_INVALID".to_string());
        }
    }

    (verified, signer, errors, raw)
}

async fn loopback_get(url: String) -> Result<(u16, String), JsonRpcError> {
    let bearer = loopback_bearer_token();
    tokio::task::spawn_blocking(move || {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(std::time::Duration::from_secs(10)))
            .build()
            .into();
        let mut req = agent
            .get(&url)
            .header("X-Corecrux-Scopes", SCOPES)
            .header("Accept", "application/json");
        if let Some(token) = &bearer {
            req = req.header("Authorization", &format!("Bearer {token}"));
        }
        match req.call() {
            Ok(mut r) => {
                let status = r.status().as_u16();
                let body = r.body_mut().read_to_string().unwrap_or_default();
                Ok((status, body))
            }
            Err(ureq::Error::StatusCode(code)) => Ok((code, String::new())),
            Err(other) => Err(other.to_string()),
        }
    })
    .await
    .map_err(|e| JsonRpcError {
        code: INTERNAL_ERROR,
        message: format!("loopback join error: {e}"),
        data: None,
    })?
    .map_err(|message| JsonRpcError {
        code: INTERNAL_ERROR,
        message: format!("loopback request failed: {message}"),
        data: None,
    })
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::agent::AgentIdentity;

    fn ctx_with_agent(name: &str) -> McpContext {
        McpContext::new_default("test-rv-node").with_agent(AgentIdentity {
            name: name.to_string(),
            token_hash: [0u8; 32],
        })
    }

    // Serialise the env-var mutation so concurrent tokio tests don't race
    // on CORECRUXD_FEATURE_RECEIPT_VERIFY. Delegates to
    // `crate::test_env_lock` so every env-mutating test in this crate
    // shares one process-wide `tokio::sync::Mutex`.
    fn flag_lock() -> &'static tokio::sync::Mutex<()> {
        crate::test_env_lock()
    }

    #[tokio::test]
    async fn requires_passport() {
        let _g = flag_lock().lock().await;
        std::env::remove_var(FEATURE_FLAG_ENV);
        let ctx = McpContext::new_default("test-rv-node");
        let err = handle_receipt_verify(&json!({"receipt_id": "r_0001"}), &ctx)
            .await
            .expect_err("missing passport must fail");
        assert_eq!(err.code, INVALID_PARAMS);
        assert!(err.message.contains("authenticated agent identity"));
    }

    #[tokio::test]
    async fn requires_receipt_id() {
        let _g = flag_lock().lock().await;
        std::env::remove_var(FEATURE_FLAG_ENV);
        let ctx = ctx_with_agent("alice");
        let err = handle_receipt_verify(&json!({}), &ctx)
            .await
            .expect_err("missing receipt_id must fail");
        assert_eq!(err.code, INVALID_PARAMS);
        assert!(err.message.contains("receipt_id is required"));
    }

    #[tokio::test]
    async fn rejects_empty_receipt_id() {
        let _g = flag_lock().lock().await;
        std::env::remove_var(FEATURE_FLAG_ENV);
        let ctx = ctx_with_agent("alice");
        let err = handle_receipt_verify(&json!({"receipt_id": "   "}), &ctx)
            .await
            .expect_err("empty receipt_id must fail");
        assert_eq!(err.code, INVALID_PARAMS);
    }

    #[tokio::test]
    async fn feature_disabled_returns_payload_without_loopback() {
        let _g = flag_lock().lock().await;
        std::env::remove_var(FEATURE_FLAG_ENV);
        // No daemon_base_url — this would fail at the loopback step if we
        // got that far. Proves the flag short-circuits BEFORE the loopback.
        let ctx = ctx_with_agent("alice");
        let result = handle_receipt_verify(&json!({"receipt_id": "r_0001"}), &ctx)
            .await
            .unwrap();
        assert_eq!(result["feature_enabled"], false);
        assert_eq!(result["verified"], false);
        assert_eq!(result["receipt_id"], "r_0001");
        assert_eq!(result["errors"][0], "FEATURE_DISABLED");
    }

    #[tokio::test]
    async fn flag_on_requires_daemon_base_url() {
        let _g = flag_lock().lock().await;
        std::env::set_var(FEATURE_FLAG_ENV, "1");
        let ctx = ctx_with_agent("alice");
        let err = handle_receipt_verify(&json!({"receipt_id": "r_0001"}), &ctx)
            .await
            .expect_err("missing daemon_base_url must fail when flag is on");
        assert_eq!(err.code, INTERNAL_ERROR);
        assert!(err.message.contains("daemon_base_url not configured"));
        std::env::remove_var(FEATURE_FLAG_ENV);
    }

    #[test]
    fn build_verification_url_encodes_components_and_trims_base_slash() {
        let url = build_verification_url("http://127.0.0.1:14800/", "tenant a", "r 01");
        assert_eq!(
            url,
            "http://127.0.0.1:14800/v1/receipts/r%2001/verification?tenant_id=tenant%20a"
        );
    }

    #[test]
    fn parse_report_verified_when_all_signals_green() {
        let body = json!({
            "schema": "cuecrux.receipt.verify.v1",
            "receipt_id": "r_0001",
            "tenant_id": "default",
            "payload_hash": "00".repeat(32),
            "signature": {"alg": "ed25519", "key_id": "k_abc"},
            "integrity": {"payload_hash_matches": true, "canonical_bytes_parse_ok": true},
            "trace_checks": {},
            "signature_valid": true,
            "pubkey_fingerprint": "fp_deadbeef",
            "error_code": "OK",
            "verified_at": "2026-05-27T00:00:00Z",
            "verifier_build": "test@abc",
        })
        .to_string();
        let (v, s, errs, _raw) = parse_verification_report(200, &body);
        assert!(v);
        assert_eq!(s.as_deref(), Some("fp_deadbeef"));
        assert!(errs.is_empty());
    }

    #[test]
    fn parse_report_not_verified_on_body_hash_mismatch() {
        let body = json!({
            "schema": "cuecrux.receipt.verify.v1",
            "receipt_id": "r_0001",
            "tenant_id": "default",
            "payload_hash": "00".repeat(32),
            "signature": {"alg": "ed25519", "key_id": "k_abc"},
            "integrity": {"payload_hash_matches": false, "canonical_bytes_parse_ok": true},
            "trace_checks": {},
            "signature_valid": false,
            "error_code": "BODY_HASH_MISMATCH",
            "verified_at": "2026-05-27T00:00:00Z",
            "verifier_build": "test@abc",
        })
        .to_string();
        let (v, s, errs, _raw) = parse_verification_report(200, &body);
        assert!(!v);
        // No pubkey_fingerprint, fall back to signature.key_id.
        assert_eq!(s.as_deref(), Some("k_abc"));
        assert!(errs.contains(&"BODY_HASH_MISMATCH".to_string()));
        assert!(errs.contains(&"PAYLOAD_HASH_MISMATCH".to_string()));
        assert!(errs.contains(&"SIGNATURE_INVALID".to_string()));
    }

    #[test]
    fn parse_report_http_404_surfaces_as_error() {
        let (v, s, errs, _raw) = parse_verification_report(404, "");
        assert!(!v);
        assert!(s.is_none());
        assert!(errs.iter().any(|e| e.contains("HTTP_404")));
    }

    /// Contract test: the URL we build must match the route pattern
    /// registered in `corecruxd/src/http/mod.rs`:
    /// `/v1/receipts/{receiptId}/verification`. A future renaming of the
    /// route would break the host-IDE verify badge; this test guards that.
    #[test]
    fn build_verification_url_matches_corecruxd_route_pattern() {
        let url = build_verification_url("http://127.0.0.1:14800", "default", "r_abc");
        // Stable shape: scheme + host + port + literal path + query.
        assert_eq!(
            url,
            "http://127.0.0.1:14800/v1/receipts/r_abc/verification?tenant_id=default"
        );
        // The path segment between `/receipts/` and `/verification` is the
        // receipt id — corecruxd's `Path<String>` extractor reads it here.
        assert!(url.contains("/v1/receipts/"));
        assert!(url.contains("/verification?"));
    }

    #[test]
    fn parse_report_loopback_unreachable_signals_zero_status() {
        let (v, s, errs, _raw) = parse_verification_report(0, "");
        assert!(!v);
        assert!(s.is_none());
        assert!(errs.contains(&"loopback_unreachable".to_string()));
    }
}
