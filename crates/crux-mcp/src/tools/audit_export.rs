// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

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
use serde_json::{json, Value};
use uuid::Uuid;

use crate::dispatch::McpContext;
use crate::protocol::{JsonRpcError, INTERNAL_ERROR, INVALID_PARAMS, METHOD_NOT_FOUND};
use crate::scope;
use corecrux_memory::fact_store::Fact;
use corecrux_receipts::{
    build_bundle_v1, resolve_audit_export_signing_key, AuditBundleScopeV1, AuditEventV1, AuditReceiptRefV1,
    BuildBundleInputV1,
};

/// Feature flag.
pub const FEATURE_FLAG_ENV: &str = "CORECRUXD_FEATURE_AUDIT_EXPORT";
/// Environment variable carrying the base64 Ed25519 secret. Re-exported from
/// `corecrux-receipts`, which owns the shared env/persistent/ephemeral resolver.
pub const SIGNING_KEY_ENV: &str = corecrux_receipts::AUDIT_EXPORT_SIGNING_KEY_ENV;
/// Optional human-readable signer key id (echoed in the manifest).
pub const SIGNING_KEY_ID_ENV: &str = corecrux_receipts::AUDIT_EXPORT_SIGNING_KEY_ID_ENV;
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
    // agent-passport M5: identity-scoped per-fact visibility so the OWNER of a
    // passport-keyed private fact can export its OWN fact (and a DIFFERENT
    // passport cannot). The raw `agent_name` is still used for the operator
    // `include_reserved` gate and the `caller` manifest field — those name the
    // caller, not the fact owner. Flag-OFF identity == raw name + empty aliases,
    // so the per-fact check below is byte-for-byte the prior agent-scoped path.
    let identity = ctx.scope_identity();
    let id_ref = identity.as_deref();
    let aliases = ctx.scope_aliases();
    let alias_refs: Vec<&str> = aliases.iter().map(String::as_str).collect();
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
        let tenant_hash = ctx.scope_tenant();
        let mut all: Vec<&Fact> = store.all_facts_for_tenant(&tenant_hash).collect();
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
            // agent's private facts. Identity-scoped (M5) so the OWNER can
            // export its own passport-keyed private fact. The `include_reserved`
            // operator bypass is preserved unchanged.
            if !scope::fact_visible_to_identity(fact, id_ref, &alias_refs) && !include_reserved {
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

    // Track W / G1: include witnessed seal-chain inclusion-proofs from the
    // daemon's witness journal so the bundle is independently anchorable. Empty
    // when witnessing is off or no data_dir is wired.
    let witness_proofs = ctx
        .data_dir
        .as_ref()
        .map(|dir| corecrux_receipts::read_witnessed_proofs_jsonl(&dir.join("witness_proofs.jsonl")))
        .unwrap_or_default();

    let resolved_key = resolve_audit_export_signing_key(ctx.data_dir.as_deref()).map_err(|err| JsonRpcError {
        code: INTERNAL_ERROR,
        message: format!("audit bundle signing key resolution failed: {err}"),
        data: None,
    })?;
    let built = build_bundle_v1(BuildBundleInputV1 {
        bundle_id: bundle_id.clone(),
        since_rfc3339: since_rfc3339.clone(),
        until_rfc3339: until_rfc3339.clone(),
        generated_at_rfc3339: now.to_rfc3339(),
        scope: scope_record.clone(),
        events,
        receipt_refs,
        witness_proofs,
        signing_key: &resolved_key.signing_key,
        signer_key_id: resolved_key.signer_key_id,
        key_class: resolved_key.key_class,
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
        "key_class": built.manifest.key_class,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::AgentIdentity;
    use crate::dispatch::McpContext;
    use crate::tools::facts::handle_store_fact;
    use corecrux_receipts::{verify_bundle_v1, AuditBundleManifestV1};

    // Tests that flip the feature flag must serialise on the crate-wide
    // test env lock — env-var races are real (see the forget.rs pattern
    // and the wider traces.rs flake fixed in
    // fix/crux-mcp-tools-traces-test-isolation-2026-05-29).
    fn flag_lock() -> &'static tokio::sync::Mutex<()> {
        crate::test_env_lock()
    }

    /// Deterministic 32-byte export signer for tests that actually build a
    /// bundle. Required since play03 D2: an `McpContext` with no `data_dir`
    /// used to fall back to a throwaway key, and now refuses.
    const TEST_SIGNER_SECRET: [u8; 32] = [0x5a; 32];

    fn test_signer_b64() -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(TEST_SIGNER_SECRET)
    }

    struct FeatureFlagGuard {
        _lock: tokio::sync::MutexGuard<'static, ()>,
    }
    impl FeatureFlagGuard {
        async fn enabled() -> Self {
            let lock = flag_lock().lock().await;
            env::remove_var(SIGNING_KEY_ENV);
            env::remove_var(SIGNING_KEY_ID_ENV);
            env::set_var(FEATURE_FLAG_ENV, "1");
            Self { _lock: lock }
        }

        /// `enabled()` plus a configured export signer — the shape any caller
        /// that means to produce a verifiable bundle must now be in.
        async fn enabled_with_signer() -> Self {
            let guard = Self::enabled().await;
            env::set_var(SIGNING_KEY_ENV, test_signer_b64());
            guard
        }
        async fn disabled() -> Self {
            let lock = flag_lock().lock().await;
            env::remove_var(SIGNING_KEY_ENV);
            env::remove_var(SIGNING_KEY_ID_ENV);
            env::remove_var(FEATURE_FLAG_ENV);
            Self { _lock: lock }
        }
    }
    impl Drop for FeatureFlagGuard {
        fn drop(&mut self) {
            env::remove_var(FEATURE_FLAG_ENV);
            env::remove_var(SIGNING_KEY_ENV);
            env::remove_var(SIGNING_KEY_ID_ENV);
            env::remove_var(EXPORT_DIR_ENV);
        }
    }

    fn agent_ctx(name: &str) -> McpContext {
        let ctx = McpContext::new_default("test-node");
        ctx.with_agent(AgentIdentity {
            name: name.to_string(),
            token_hash: [0u8; 32],
        })
    }

    async fn seed_operator_fact(ctx: &McpContext, entity: &str, key: &str, value: &str) {
        let mut store = ctx.fact_store.write().await;
        store.store(corecrux_memory::fact_store::StoreFact {
            tenant_hash: "default".to_string(),
            entity: entity.to_string(),
            key: key.to_string(),
            value: value.to_string(),
            source_receipt: Some("test:typed-operator-workflow".to_string()),
            confidence: 1.0,
            private: true,
            horizon_class: None,
            actor: Some("daemon:test".to_string()),
        });
    }

    fn redirect_export_dir(td: &tempfile::TempDir) {
        env::set_var(EXPORT_DIR_ENV, td.path());
    }

    #[tokio::test]
    async fn audit_export_disabled_by_default() {
        let _g = FeatureFlagGuard::disabled().await;
        let ctx = agent_ctx("alice");
        let err = handle_audit_export_bundle(&json!({"token_budget": 1000}), &ctx)
            .await
            .unwrap_err();
        assert_eq!(err.code, METHOD_NOT_FOUND);
    }

    #[tokio::test]
    async fn audit_export_requires_token_budget() {
        let _g = FeatureFlagGuard::enabled().await;
        let ctx = agent_ctx("alice");
        let err = handle_audit_export_bundle(&json!({}), &ctx).await.unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
        assert_eq!(err.data.unwrap()["param"], "token_budget");
    }

    #[tokio::test]
    async fn audit_export_builds_self_verifying_bundle() {
        let _g = FeatureFlagGuard::enabled_with_signer().await;
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
        let _g = FeatureFlagGuard::enabled_with_signer().await;
        let td = tempfile::tempdir().unwrap();
        redirect_export_dir(&td);

        // Anonymous caller — must NEVER see reserved-prefix entries.
        let ctx = McpContext::new_default("test-node");
        // Seed both a public and a reserved-prefix fact.
        handle_store_fact(&json!({"entity": "project-x", "key": "k", "value": "v1"}), &ctx)
            .await
            .unwrap();
        seed_operator_fact(&ctx, "__ops::config-audit", "sha256:abc", "audited").await;
        seed_operator_fact(&ctx, "__bootstrap__::pattern:retry", "Retry", "exp").await;

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
        let _g = FeatureFlagGuard::enabled_with_signer().await;
        let td = tempfile::tempdir().unwrap();
        redirect_export_dir(&td);

        let ctx = agent_ctx("operator-1");
        handle_store_fact(&json!({"entity": "project-x", "key": "k", "value": "v"}), &ctx)
            .await
            .unwrap();
        seed_operator_fact(&ctx, "__ops::config-audit", "sha256:abc", "ok").await;

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
        let _g = FeatureFlagGuard::enabled_with_signer().await;
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
        let _g = FeatureFlagGuard::enabled_with_signer().await;
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
                // v2: domain-separated, key-canonical signing input (audit H1).
                assert_eq!(m.bundle_format_version, corecrux_receipts::BUNDLE_FORMAT_VERSION);
                assert_eq!(m.fact_count, 1);
                assert_eq!(m.receipt_count, 1);
                assert_eq!(m.key_class, Some(corecrux_receipts::AuditBundleKeyClassV1::Env));
                assert!(!m.signature_b64.is_empty());
            }
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn persistent_signing_key_is_created_owner_only_and_reused() {
        use std::os::unix::fs::PermissionsExt as _;

        let _g = FeatureFlagGuard::enabled().await;
        let data_dir = tempfile::tempdir().unwrap();
        let first = resolve_audit_export_signing_key(Some(data_dir.path())).unwrap();
        assert_eq!(first.key_class, corecrux_receipts::AuditBundleKeyClassV1::Persistent);

        let key_path = corecrux_receipts::persistent_audit_export_signing_key_path(data_dir.path());
        assert_eq!(
            std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(std::fs::read(&key_path).unwrap(), first.signing_key.to_bytes());

        let second = resolve_audit_export_signing_key(Some(data_dir.path())).unwrap();
        assert_eq!(second.key_class, corecrux_receipts::AuditBundleKeyClassV1::Persistent);
        assert_eq!(second.signing_key.to_bytes(), first.signing_key.to_bytes());
        assert_eq!(second.signing_key.verifying_key(), first.signing_key.verifying_key());
    }

    #[tokio::test]
    async fn environment_signing_key_overrides_persistent_key() {
        use base64::Engine as _;

        let _g = FeatureFlagGuard::enabled().await;
        let data_dir = tempfile::tempdir().unwrap();
        let persistent = resolve_audit_export_signing_key(Some(data_dir.path())).unwrap();

        let env_secret = [0x77_u8; 32];
        env::set_var(
            SIGNING_KEY_ENV,
            base64::engine::general_purpose::STANDARD.encode(env_secret),
        );
        env::set_var(SIGNING_KEY_ID_ENV, "configured-audit-issuer");
        let configured = resolve_audit_export_signing_key(Some(data_dir.path())).unwrap();

        assert_eq!(configured.key_class, corecrux_receipts::AuditBundleKeyClassV1::Env);
        assert_eq!(configured.signing_key.to_bytes(), env_secret);
        assert_eq!(configured.signer_key_id, "configured-audit-issuer");
        assert_ne!(configured.signing_key.to_bytes(), persistent.signing_key.to_bytes());
        assert_eq!(
            std::fs::read(corecrux_receipts::persistent_audit_export_signing_key_path(
                data_dir.path()
            ))
            .unwrap(),
            persistent.signing_key.to_bytes()
        );
    }

    /// play03 D2, red-before-green: this context has no `data_dir` and no
    /// configured signer, which is exactly the shape that used to mint a
    /// one-shot key and hand back a bundle that verifies green. The export is
    /// now refused, and the error names the two ways to configure a real
    /// issuer.
    #[tokio::test]
    async fn audit_export_refuses_an_ephemeral_signing_key() {
        let _g = FeatureFlagGuard::enabled().await;
        let td = tempfile::tempdir().unwrap();
        redirect_export_dir(&td);

        let ctx = agent_ctx("alice");
        handle_store_fact(&json!({"entity": "p", "key": "k", "value": "v"}), &ctx)
            .await
            .unwrap();

        let err = handle_audit_export_bundle(&json!({"token_budget": 1000}), &ctx)
            .await
            .expect_err("an export with no durable signer identity must be refused");
        assert_eq!(err.code, INTERNAL_ERROR);
        assert!(
            err.message.contains(SIGNING_KEY_ENV),
            "refusal must name the remedy, got: {}",
            err.message
        );
        assert!(err.message.contains("data directory"), "got: {}", err.message);
    }

    /// The refusal is not "no key at all" — a configured signer still exports.
    #[tokio::test]
    async fn audit_export_succeeds_once_a_signer_is_configured() {
        let _g = FeatureFlagGuard::enabled_with_signer().await;
        let td = tempfile::tempdir().unwrap();
        redirect_export_dir(&td);

        let ctx = agent_ctx("alice");
        handle_store_fact(&json!({"entity": "p", "key": "k", "value": "v"}), &ctx)
            .await
            .unwrap();

        let resp = handle_audit_export_bundle(&json!({"token_budget": 1000}), &ctx)
            .await
            .unwrap();
        assert_eq!(resp["key_class"], "env");
        let raw = std::fs::read(resp["bytes_path"].as_str().unwrap()).unwrap();
        let report = verify_bundle_v1(&raw).unwrap();
        assert!(report.ok);
        // Unpinned by default: the pass is a consistency result, not a custody one.
        assert_eq!(report.trust_label, corecrux_receipts::EXPORT_TRUST_UNPINNED_LABEL);
    }
}
