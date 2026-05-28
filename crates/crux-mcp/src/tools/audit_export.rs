// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! BYO Audit Trail (agent-ux-11) — `audit_export_bundle` MCP tool.
//!
//! Builds a self-contained, signed, third-party-verifiable bundle from
//! the FactStore over a time window. The artefact is written to a temp
//! dir under `CORECRUXD_AUDIT_EXPORT_DIR` (default `<tmpdir>/crux-audit-export`).
//!
//! Three callers consume this:
//! 1. The `corecruxctl audit-export` CLI subcommand wraps this tool
//!    (operator-tier free path).
//! 2. The Frontdoor `/export/ai-act` Nuxt page invokes it via the daemon
//!    adapter (paid path).
//! 3. A third party verifies an offline copy via `corecruxctl audit-verify`.
//!
//! Constraints baked into the handler:
//! - Feature flag `CORECRUXD_FEATURE_AUDIT_EXPORT=1`. Default OFF.
//! - `token_budget` is REQUIRED (QC.2). Caps the number of facts swept.
//! - Reserved prefixes (`__agent::*`, `__ops::*`, `__bootstrap__::*`) are
//!   stripped UNLESS the caller is operator-tier (i.e. `scope.include_reserved`
//!   set and an authenticated passport is present). Non-operator callers
//!   silently get the filtered view (T.1, T.4).
//! - `audit_export_bundle` does NOT opt into `tool_emits_envelope` — the
//!   bundle IS the receipts surface; the envelope contract doesn't apply
//!   (see master plan §"Cross-PR envelope-test interaction").

use std::env;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::dispatch::McpContext;
use crate::protocol::{JsonRpcError, INTERNAL_ERROR, INVALID_PARAMS, METHOD_NOT_FOUND};
use crate::scope;
use corecrux_memory::fact_store::Fact;
use corecrux_receipts::{build_bundle_v1, AuditBundleScopeV1, AuditEventV1, AuditReceiptRefV1, BuildBundleInputV1};

/// Feature flag.
pub const FEATURE_FLAG_ENV: &str = "CORECRUXD_FEATURE_AUDIT_EXPORT";
/// Environment variable carrying the base64 ed25519 secret (same shape as
/// `CORECRUXD_WRITE_CONFIRMATION_SIGNING_KEY_B64`). When unset, we
/// auto-generate a one-shot key per bundle — the public key is embedded
/// in the manifest, so verification still works, but the key won't match
/// the daemon's published passport key (operator must wire the env to get
/// passport-attributed audit bundles).
pub const SIGNING_KEY_ENV: &str = "CORECRUXD_AUDIT_EXPORT_SIGNING_KEY_B64";
/// Optional human-readable signer key id (echoed in the manifest).
pub const SIGNING_KEY_ID_ENV: &str = "CORECRUXD_AUDIT_EXPORT_KEY_ID";
/// Directory under which bundle artefacts are written.
pub const EXPORT_DIR_ENV: &str = "CORECRUXD_AUDIT_EXPORT_DIR";

/// Reserved-prefix filter — kept in lockstep with the same constant in
/// `tools::forget` so the two surfaces never diverge.
pub const RESERVED_PREFIXES: &[&str] = &["__agent::", "__ops::", "__bootstrap__::", "__agent_session::"];

fn feature_enabled() -> bool {
    env::var(FEATURE_FLAG_ENV)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn is_reserved(entity: &str) -> bool {
    RESERVED_PREFIXES.iter().any(|p| entity.starts_with(p))
}

fn parse_rfc3339_opt(args: &Value, key: &str) -> Result<Option<DateTime<Utc>>, JsonRpcError> {
    let Some(raw) = args.get(key).and_then(|v| v.as_str()) else {
        return Ok(None);
    };
    let parsed = DateTime::parse_from_rfc3339(raw)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|err| JsonRpcError {
            code: INVALID_PARAMS,
            message: format!("invalid {key}: {err} (RFC3339 / ISO-8601 required)"),
            data: Some(json!({"param": key, "format": "RFC3339"})),
        })?;
    Ok(Some(parsed))
}

fn export_dir() -> PathBuf {
    if let Ok(p) = env::var(EXPORT_DIR_ENV) {
        if !p.trim().is_empty() {
            return PathBuf::from(p);
        }
    }
    std::env::temp_dir().join("crux-audit-export")
}

/// Load the signing key from the env. Falls back to an ephemeral one-shot
/// key when the env is unset — the public key is embedded in the manifest
/// regardless, so offline verification still works.
fn load_signing_key() -> (SigningKey, String) {
    use base64::Engine as _;
    let key_id = env::var(SIGNING_KEY_ID_ENV).unwrap_or_else(|_| String::new());
    if let Ok(b64) = env::var(SIGNING_KEY_ENV) {
        let raw = b64.trim();
        for engine in [
            base64::engine::general_purpose::STANDARD,
            base64::engine::general_purpose::STANDARD_NO_PAD,
            base64::engine::general_purpose::URL_SAFE,
            base64::engine::general_purpose::URL_SAFE_NO_PAD,
        ] {
            if let Ok(decoded) = engine.decode(raw) {
                if decoded.len() >= 32 {
                    let mut secret = [0u8; 32];
                    secret.copy_from_slice(&decoded[..32]);
                    return (SigningKey::from_bytes(&secret), key_id);
                }
            }
        }
    }
    // Ephemeral fallback — deterministic per-bundle is fine because the
    // public key is captured in the manifest.
    let mut secret = [0u8; 32];
    use rand::Rng as _;
    rand::rng().fill_bytes(&mut secret);
    (SigningKey::from_bytes(&secret), key_id)
}

/// `audit_export_bundle` handler. Returns:
///
/// ```json
/// {
///   "content": [{"type": "text", "text": "<human summary>"}],
///   "bundle_id": "bundle-...",
///   "bytes_path": "/abs/path/to/audit-bundle-<bundle_id>.tar.zst",
///   "manifest_signature_b64": "...",
///   "fact_count": <u64>,
///   "receipt_count": <u64>,
///   "scope": {...},
///   "since": "<rfc3339>",
///   "until": "<rfc3339>"
/// }
/// ```
pub async fn handle_audit_export_bundle(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    if !feature_enabled() {
        return Err(JsonRpcError {
            code: METHOD_NOT_FOUND,
            message: format!("audit_export_bundle is disabled (set {FEATURE_FLAG_ENV}=1 to enable)"),
            data: Some(json!({"feature_flag": FEATURE_FLAG_ENV, "enabled": false})),
        });
    }

    // QC.2 — token_budget mandatory.
    let token_budget = args
        .get("token_budget")
        .and_then(|v| v.as_u64())
        .map(|v| v as usize)
        .ok_or_else(|| JsonRpcError {
            code: INVALID_PARAMS,
            message: "audit_export_bundle requires `token_budget` (QC.2)".to_string(),
            data: Some(json!({"param": "token_budget", "required": true})),
        })?;

    let since_dt = parse_rfc3339_opt(args, "since_ts")?;
    let until_dt = parse_rfc3339_opt(args, "until_ts")?;

    let agent_name = scope::agent_name(ctx.agent.as_ref());
    let scope_arg = args.get("scope").cloned().unwrap_or_else(|| json!({}));
    let requested_entity_prefix = scope_arg
        .get("entity_prefix")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let requested_include_reserved = scope_arg
        .get("include_reserved")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // T.1/T.4 — only operator-tier (i.e. authenticated passport) callers
    // may include reserved-prefix entries. Anonymous or non-operator
    // callers silently get the filtered view.
    let include_reserved = requested_include_reserved && agent_name.is_some();

    let now = Utc::now();
    let since_rfc3339 = since_dt.map_or_else(|| "1970-01-01T00:00:00Z".to_string(), |dt| dt.to_rfc3339());
    let until_rfc3339 = until_dt.map_or_else(|| now.to_rfc3339(), |dt| dt.to_rfc3339());

    // Walk the fact store under a read lock. We collect into Vec eagerly
    // so the lock is released before disk I/O.
    let collected: Vec<Fact> = {
        let store = ctx.fact_store.read().await;
        let mut out: Vec<Fact> = Vec::new();
        let mut tokens_used = 0usize;
        // Sort by (stored_at, fact_id) for deterministic bundles.
        let mut all: Vec<&Fact> = store.all_facts().collect();
        all.sort_by(|a, b| a.stored_at.cmp(&b.stored_at).then_with(|| a.fact_id.cmp(&b.fact_id)));
        for fact in all {
            if let Some(since) = since_dt {
                if fact.stored_at < since {
                    continue;
                }
            }
            if let Some(until) = until_dt {
                if fact.stored_at >= until {
                    continue;
                }
            }
            if let Some(prefix) = &requested_entity_prefix {
                if !fact.entity.starts_with(prefix) {
                    continue;
                }
            }
            if is_reserved(&fact.entity) && !include_reserved {
                continue;
            }
            // Visibility — a non-operator caller never sees another
            // agent's private facts.
            if !scope::fact_visible_to_agent(fact, agent_name) && !include_reserved {
                continue;
            }
            if tokens_used.saturating_add(fact.tokens) > token_budget && !out.is_empty() {
                break;
            }
            tokens_used = tokens_used.saturating_add(fact.tokens);
            out.push(fact.clone());
            if tokens_used >= token_budget {
                break;
            }
        }
        out
    };

    let events: Vec<AuditEventV1> = collected
        .iter()
        .map(|f| AuditEventV1 {
            fact_id: f.fact_id.clone(),
            entity: f.entity.clone(),
            key: f.key.clone(),
            value: f.value.clone(),
            source_receipt: f.source_receipt.clone(),
            confidence: f.confidence,
            stored_at: f.stored_at.to_rfc3339(),
            tokens: f.tokens,
            deleted: f.deleted,
            version: f.version,
            supersedes: f.supersedes.clone(),
        })
        .collect();

    let receipt_refs: Vec<AuditReceiptRefV1> = collected
        .iter()
        .filter_map(|f| {
            f.source_receipt.as_ref().map(|rid| AuditReceiptRefV1 {
                fact_id: f.fact_id.clone(),
                receipt_id: rid.clone(),
            })
        })
        .collect();

    let bundle_id = format!("bundle-{}", Uuid::new_v4().simple());
    let scope_record = AuditBundleScopeV1 {
        entity_prefix: requested_entity_prefix,
        include_reserved,
        caller: agent_name.map(str::to_string),
    };

    let (signing_key, signer_key_id) = load_signing_key();
    let built = build_bundle_v1(BuildBundleInputV1 {
        bundle_id: bundle_id.clone(),
        since_rfc3339: since_rfc3339.clone(),
        until_rfc3339: until_rfc3339.clone(),
        generated_at_rfc3339: now.to_rfc3339(),
        scope: scope_record.clone(),
        events,
        receipt_refs,
        signing_key: &signing_key,
        signer_key_id,
    })
    .map_err(|err| JsonRpcError {
        code: INTERNAL_ERROR,
        message: format!("audit bundle build failed: {err}"),
        data: None,
    })?;

    // Persist to disk.
    let dir = export_dir();
    std::fs::create_dir_all(&dir).map_err(|err| JsonRpcError {
        code: INTERNAL_ERROR,
        message: format!("failed to create export dir {}: {err}", dir.display()),
        data: None,
    })?;
    let out_path = dir.join(format!("audit-{bundle_id}.tar.zst"));
    let file = std::fs::File::create(&out_path).map_err(|err| JsonRpcError {
        code: INTERNAL_ERROR,
        message: format!("failed to open {}: {err}", out_path.display()),
        data: None,
    })?;
    built.write_tar_zst(file).map_err(|err| JsonRpcError {
        code: INTERNAL_ERROR,
        message: format!("failed to write bundle: {err}"),
        data: None,
    })?;

    let summary = format!(
        "audit-bundle {bundle_id}: facts={} receipts={} since={} until={} include_reserved={} bytes_path={}",
        built.manifest.fact_count,
        built.manifest.receipt_count,
        built.manifest.since,
        built.manifest.until,
        scope_record.include_reserved,
        out_path.display()
    );

    Ok(json!({
        "content": [{"type": "text", "text": summary}],
        "bundle_id": bundle_id,
        "bytes_path": out_path.to_string_lossy(),
        "manifest_signature_b64": built.manifest.signature_b64,
        "fact_count": built.manifest.fact_count,
        "receipt_count": built.manifest.receipt_count,
        "scope": scope_record,
        "since": built.manifest.since,
        "until": built.manifest.until,
        "events_jsonl_sha256": built.manifest.events_jsonl_sha256,
        "receipts_cbor_sha256": built.manifest.receipts_cbor_sha256,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::AgentIdentity;
    use crate::dispatch::McpContext;
    use crate::tools::facts::handle_store_fact;
    use corecrux_receipts::{verify_bundle_v1, AuditBundleManifestV1};

    // Tests that flip the feature flag must serialise — env-var races
    // are real (see the forget.rs pattern).
    fn flag_lock() -> &'static std::sync::Mutex<()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
    }

    struct FeatureFlagGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
    }
    impl FeatureFlagGuard {
        fn enabled() -> Self {
            let lock = flag_lock().lock().unwrap_or_else(|p| p.into_inner());
            env::set_var(FEATURE_FLAG_ENV, "1");
            Self { _lock: lock }
        }
        fn disabled() -> Self {
            let lock = flag_lock().lock().unwrap_or_else(|p| p.into_inner());
            env::remove_var(FEATURE_FLAG_ENV);
            Self { _lock: lock }
        }
    }
    impl Drop for FeatureFlagGuard {
        fn drop(&mut self) {
            env::remove_var(FEATURE_FLAG_ENV);
        }
    }

    fn agent_ctx(name: &str) -> McpContext {
        let ctx = McpContext::new_default("test-node");
        ctx.with_agent(AgentIdentity {
            name: name.to_string(),
            token_hash: [0u8; 32],
        })
    }

    fn redirect_export_dir(td: &tempfile::TempDir) {
        env::set_var(EXPORT_DIR_ENV, td.path());
    }

    #[tokio::test]
    async fn audit_export_disabled_by_default() {
        let _g = FeatureFlagGuard::disabled();
        let ctx = agent_ctx("alice");
        let err = handle_audit_export_bundle(&json!({"token_budget": 1000}), &ctx)
            .await
            .unwrap_err();
        assert_eq!(err.code, METHOD_NOT_FOUND);
    }

    #[tokio::test]
    async fn audit_export_requires_token_budget() {
        let _g = FeatureFlagGuard::enabled();
        let ctx = agent_ctx("alice");
        let err = handle_audit_export_bundle(&json!({}), &ctx).await.unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
        assert_eq!(err.data.unwrap()["param"], "token_budget");
    }

    #[tokio::test]
    async fn audit_export_builds_self_verifying_bundle() {
        let _g = FeatureFlagGuard::enabled();
        let td = tempfile::tempdir().unwrap();
        redirect_export_dir(&td);

        let ctx = agent_ctx("alice");
        handle_store_fact(&json!({"entity": "project-x", "key": "k", "value": "v1"}), &ctx)
            .await
            .unwrap();
        handle_store_fact(&json!({"entity": "project-y", "key": "k", "value": "v2"}), &ctx)
            .await
            .unwrap();

        let resp = handle_audit_export_bundle(&json!({"token_budget": 1000}), &ctx)
            .await
            .unwrap();
        let bytes_path = resp["bytes_path"].as_str().unwrap();
        assert!(bytes_path.ends_with(".tar.zst"));
        let raw = std::fs::read(bytes_path).unwrap();
        let report = verify_bundle_v1(&raw).unwrap();
        assert!(report.ok, "freshly built bundle should verify: {report:?}");
        assert_eq!(report.fact_count, 2);
    }

    #[tokio::test]
    async fn audit_export_strips_reserved_prefixes_for_non_operator() {
        let _g = FeatureFlagGuard::enabled();
        let td = tempfile::tempdir().unwrap();
        redirect_export_dir(&td);

        // Anonymous caller — must NEVER see reserved-prefix entries.
        let ctx = McpContext::new_default("test-node");
        // Seed both a public and a reserved-prefix fact.
        handle_store_fact(&json!({"entity": "project-x", "key": "k", "value": "v1"}), &ctx)
            .await
            .unwrap();
        handle_store_fact(
            &json!({"entity": "__ops::config-audit", "key": "sha256:abc", "value": "audited"}),
            &ctx,
        )
        .await
        .unwrap();
        handle_store_fact(
            &json!({"entity": "__bootstrap__::pattern:retry", "key": "Retry", "value": "exp"}),
            &ctx,
        )
        .await
        .unwrap();

        let resp = handle_audit_export_bundle(
            &json!({"token_budget": 1000, "scope": {"include_reserved": true}}),
            &ctx,
        )
        .await
        .unwrap();
        // Anonymous caller's `include_reserved=true` is ignored — manifest
        // records the effective value, not the request.
        assert_eq!(resp["scope"]["include_reserved"], false);
        assert_eq!(resp["fact_count"], 1);

        // Decompress + read events.jsonl to confirm none of the reserved
        // entries leaked in.
        let raw = std::fs::read(resp["bytes_path"].as_str().unwrap()).unwrap();
        let decoded = zstd::stream::decode_all(raw.as_slice()).unwrap();
        let mut archive = tar::Archive::new(decoded.as_slice());
        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            let path = entry.path().unwrap().to_string_lossy().to_string();
            if path == "events.jsonl" {
                let mut s = String::new();
                use std::io::Read as _;
                entry.read_to_string(&mut s).unwrap();
                assert!(!s.contains("__ops::"), "leaked __ops:: into non-operator export");
                assert!(
                    !s.contains("__bootstrap__::"),
                    "leaked __bootstrap__:: into non-operator export"
                );
                assert!(s.contains("project-x"));
            }
        }
    }

    #[tokio::test]
    async fn audit_export_operator_sees_reserved_when_requested() {
        let _g = FeatureFlagGuard::enabled();
        let td = tempfile::tempdir().unwrap();
        redirect_export_dir(&td);

        let ctx = agent_ctx("operator-1");
        handle_store_fact(&json!({"entity": "project-x", "key": "k", "value": "v"}), &ctx)
            .await
            .unwrap();
        handle_store_fact(
            &json!({"entity": "__ops::config-audit", "key": "sha256:abc", "value": "ok"}),
            &ctx,
        )
        .await
        .unwrap();

        let resp = handle_audit_export_bundle(
            &json!({"token_budget": 1000, "scope": {"include_reserved": true}}),
            &ctx,
        )
        .await
        .unwrap();
        assert_eq!(resp["scope"]["include_reserved"], true);
        assert_eq!(resp["fact_count"], 2);
    }

    #[tokio::test]
    async fn audit_export_respects_since_until_window() {
        let _g = FeatureFlagGuard::enabled();
        let td = tempfile::tempdir().unwrap();
        redirect_export_dir(&td);

        let ctx = agent_ctx("alice");
        handle_store_fact(&json!({"entity": "p", "key": "k", "value": "v"}), &ctx)
            .await
            .unwrap();

        // Far-future since: should select zero facts.
        let resp = handle_audit_export_bundle(&json!({"token_budget": 1000, "since_ts": "9999-01-01T00:00:00Z"}), &ctx)
            .await
            .unwrap();
        assert_eq!(resp["fact_count"], 0);
    }

    #[tokio::test]
    async fn audit_export_manifest_round_trips() {
        let _g = FeatureFlagGuard::enabled();
        let td = tempfile::tempdir().unwrap();
        redirect_export_dir(&td);

        let ctx = agent_ctx("alice");
        handle_store_fact(
            &json!({"entity": "p", "key": "k", "value": "v", "source_receipt": "r_001"}),
            &ctx,
        )
        .await
        .unwrap();
        let resp = handle_audit_export_bundle(&json!({"token_budget": 100}), &ctx)
            .await
            .unwrap();
        let raw = std::fs::read(resp["bytes_path"].as_str().unwrap()).unwrap();

        // Round-trip the bundle through the offline verifier and confirm
        // the manifest's structured fields match the MCP response.
        let report = verify_bundle_v1(&raw).unwrap();
        assert!(report.ok);
        assert_eq!(report.fact_count as i64, resp["fact_count"].as_i64().unwrap());
        assert_eq!(report.receipt_count, 1);
        assert_eq!(report.bundle_id, resp["bundle_id"].as_str().unwrap());

        // Decode the manifest directly to confirm the structured fields
        // mirror the MCP response.
        let decoded = zstd::stream::decode_all(raw.as_slice()).unwrap();
        let mut archive = tar::Archive::new(decoded.as_slice());
        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            let path = entry.path().unwrap().to_string_lossy().to_string();
            if path == "manifest.json" {
                let mut s = String::new();
                use std::io::Read as _;
                entry.read_to_string(&mut s).unwrap();
                let m: AuditBundleManifestV1 = serde_json::from_str(&s).unwrap();
                assert_eq!(m.bundle_format_version, 1);
                assert_eq!(m.fact_count, 1);
                assert_eq!(m.receipt_count, 1);
                assert!(!m.signature_b64.is_empty());
            }
        }
    }
}
