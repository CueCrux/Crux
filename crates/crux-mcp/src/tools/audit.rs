// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Config-audit tools: `audit_config`, `check_config_audit`.
//!
//! Operators record approvals of `settings.json` / `.mcp.json` / CLAUDE.md
//! content hashes; agents (typically via the SessionStart hook) ask which
//! paths have unaudited hashes. The hash itself is the audit unit — paths
//! are advisory metadata. Records live under the `__ops::config-audit`
//! entity, keyed by `sha256:<full_hash>`, so a single fact covers every
//! path/machine that produced the same content.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::dispatch::McpContext;
use crate::protocol::{JsonRpcError, INVALID_PARAMS};
use corecrux_memory::fact_store::{FactQuery, StoreFact};

/// Entity that holds all config-audit records. One fact per unique sha256;
/// the value records the most recent attestation (path, auditor, timestamp).
const AUDIT_ENTITY: &str = "__ops::config-audit";

/// Key prefix used to index audit records by content hash.
const AUDIT_KEY_PREFIX: &str = "sha256:";

/// SHA-256 hex digests are 64 lowercase hex characters.
const SHA256_HEX_LEN: usize = 64;

/// Persisted audit record (fact value).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuditRecord {
    /// File path observed at audit time. Advisory only — the hash is the
    /// canonical identity. A second path with the same content matches the
    /// same record.
    path: String,
    /// Caller-provided auditor identity (passport id, email, or free text).
    auditor: String,
    /// Caller-provided context for the audit (PR link, ticket, etc.).
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<String>,
    /// RFC3339 timestamp of the attestation.
    audited_at: String,
}

// ── Handlers ──────────────────────────────────────────────────────────────

/// `audit_config` — record an attestation that a config file's content hash
/// has been reviewed. Idempotent on `sha256` — re-auditing the same hash
/// updates the record's path/auditor/timestamp.
pub async fn handle_audit_config(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let path = require_str(args, "path")?;
    let sha256 = normalise_sha256(require_str(args, "sha256")?)?;
    let auditor = require_str(args, "auditor")?;
    let note = args
        .get("note")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    let record = AuditRecord {
        path: path.to_string(),
        auditor: auditor.to_string(),
        note,
        audited_at: chrono::Utc::now().to_rfc3339(),
    };
    let canonical = serde_json::to_string(&record).unwrap_or_default();

    let req = StoreFact {
        tenant_hash: "default".to_string(),
        entity: AUDIT_ENTITY.to_string(),
        key: format!("{AUDIT_KEY_PREFIX}{sha256}"),
        value: canonical,
        source_receipt: None,
        confidence: 1.0,
        private: false,
        horizon_class: None,
        actor: None,
    };

    let mut store = ctx.fact_store.write().await;
    store.store(req);

    Ok(json!({
        "content": [{
            "type": "text",
            "text": format!(
                "config audited: path={} sha256={} auditor={}",
                path,
                &sha256[..16],
                auditor
            )
        }]
    }))
}

/// `check_config_audit` — given a list of `{path, sha256}` pairs, return
/// which entries are unaudited (the typical SessionStart hook payload).
pub async fn handle_check_config_audit(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let paths = args
        .get("paths")
        .and_then(|v| v.as_array())
        .ok_or_else(|| JsonRpcError {
            code: INVALID_PARAMS,
            message: "missing required param: paths (array of {path, sha256})".to_string(),
            data: Some(json!({"param": "paths", "required": true})),
        })?;

    // Load all audit records once; lookup by exact key.
    let q = FactQuery {
        tenant_hash: None,
        query: None,
        entity: Some(AUDIT_ENTITY.to_string()),
        entity_prefix: None,
        top_k: 1000,
        token_budget: None,
    };
    let store = ctx.fact_store.read().await;
    let result = store.query(&q);

    // Pick the highest-version record per hash (re-audit produces a new
    // version per (entity, key); the latest attestation wins). The store
    // retains older versions for the audit trail; we just report the most
    // recent one to callers.
    let mut audited_hashes: std::collections::HashMap<String, (u32, AuditRecord)> = std::collections::HashMap::new();
    for fact in &result.facts {
        if fact.deleted {
            continue;
        }
        let Some(rest) = fact.key.strip_prefix(AUDIT_KEY_PREFIX) else {
            continue;
        };
        if rest.len() != SHA256_HEX_LEN {
            continue;
        }
        let Ok(record) = serde_json::from_str::<AuditRecord>(&fact.value) else {
            continue;
        };
        let hash = rest.to_lowercase();
        match audited_hashes.get(&hash) {
            Some((prior, _)) if *prior >= fact.version => {}
            _ => {
                audited_hashes.insert(hash, (fact.version, record));
            }
        }
    }
    let audited_hashes: std::collections::HashMap<String, AuditRecord> =
        audited_hashes.into_iter().map(|(k, (_, v))| (k, v)).collect();

    let mut unaudited: Vec<Value> = Vec::new();
    let mut audited: Vec<Value> = Vec::new();

    for entry in paths {
        let Some(obj) = entry.as_object() else {
            return Err(JsonRpcError {
                code: INVALID_PARAMS,
                message: "each `paths` entry must be an object with `path` and `sha256`".to_string(),
                data: Some(json!({"param": "paths", "got": entry})),
            });
        };
        let Some(path) = obj.get("path").and_then(|v| v.as_str()) else {
            return Err(JsonRpcError {
                code: INVALID_PARAMS,
                message: "each `paths` entry must include `path`".to_string(),
                data: Some(json!({"entry": entry})),
            });
        };
        let raw_sha = obj.get("sha256").and_then(|v| v.as_str()).unwrap_or("");
        let sha256 = match normalise_sha256(raw_sha) {
            Ok(s) => s,
            Err(err) => return Err(err),
        };

        match audited_hashes.get(&sha256) {
            Some(rec) => audited.push(json!({
                "path": path,
                "sha256": sha256,
                "audited_at": rec.audited_at,
                "auditor": rec.auditor,
                "audited_path": rec.path,
            })),
            None => unaudited.push(json!({
                "path": path,
                "sha256": sha256,
            })),
        }
    }

    let text = if unaudited.is_empty() {
        format!("all {} config path(s) audited", audited.len())
    } else {
        let paths: Vec<String> = unaudited
            .iter()
            .filter_map(|v| {
                Some(format!(
                    "  {} (sha256={})",
                    v.get("path")?.as_str()?,
                    &v.get("sha256")?.as_str()?[..16]
                ))
            })
            .collect();
        format!(
            "{} of {} config path(s) unaudited:\n{}",
            unaudited.len(),
            unaudited.len() + audited.len(),
            paths.join("\n")
        )
    };

    Ok(json!({
        "content": [{ "type": "text", "text": text }],
        "unaudited": unaudited,
        "audited": audited,
    }))
}

// ── Helpers ───────────────────────────────────────────────────────────────

/// Validate + lowercase a SHA-256 hex digest.
fn normalise_sha256(raw: &str) -> Result<String, JsonRpcError> {
    let trimmed = raw.trim();
    if trimmed.len() != SHA256_HEX_LEN || !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(JsonRpcError {
            code: INVALID_PARAMS,
            message: format!("invalid sha256: expected {SHA256_HEX_LEN} hex chars, got {:?}", trimmed),
            data: Some(json!({"param": "sha256"})),
        });
    }
    Ok(trimmed.to_lowercase())
}

fn require_str<'a>(args: &'a Value, field: &str) -> Result<&'a str, JsonRpcError> {
    args.get(field).and_then(|v| v.as_str()).ok_or_else(|| JsonRpcError {
        code: INVALID_PARAMS,
        message: format!("missing required param: {field}"),
        data: Some(json!({"param": field, "required": true})),
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::dispatch::McpContext;

    fn test_ctx() -> McpContext {
        McpContext::new_default("test-node")
    }

    const HASH_A: &str = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678901234567890abcdef123456";
    const HASH_B: &str = "deadbeef0000000000000000000000000000000000000000000000000000cafe";

    #[tokio::test]
    async fn audit_config_writes_and_check_finds_it() {
        let ctx = test_ctx();
        handle_audit_config(
            &json!({
                "path": "/home/u/.claude/settings.json",
                "sha256": HASH_A,
                "auditor": "passport:abc123",
                "note": "reviewed for PR #42",
            }),
            &ctx,
        )
        .await
        .unwrap();

        let result = handle_check_config_audit(
            &json!({
                "paths": [
                    {"path": "/home/u/.claude/settings.json", "sha256": HASH_A},
                    {"path": "/home/u/.mcp.json", "sha256": HASH_B},
                ]
            }),
            &ctx,
        )
        .await
        .unwrap();

        let unaudited = result["unaudited"].as_array().unwrap();
        let audited = result["audited"].as_array().unwrap();
        assert_eq!(audited.len(), 1);
        assert_eq!(unaudited.len(), 1);
        assert_eq!(audited[0]["path"].as_str().unwrap(), "/home/u/.claude/settings.json");
        assert_eq!(unaudited[0]["path"].as_str().unwrap(), "/home/u/.mcp.json");
        assert_eq!(audited[0]["auditor"].as_str().unwrap(), "passport:abc123");
    }

    #[tokio::test]
    async fn audit_config_case_insensitive_hash() {
        let ctx = test_ctx();
        let upper = HASH_A.to_uppercase();
        handle_audit_config(
            &json!({
                "path": "/etc/foo",
                "sha256": upper,
                "auditor": "ops",
            }),
            &ctx,
        )
        .await
        .unwrap();

        let result = handle_check_config_audit(&json!({"paths": [{"path": "/etc/foo", "sha256": HASH_A}]}), &ctx)
            .await
            .unwrap();
        assert_eq!(result["audited"].as_array().unwrap().len(), 1);
        assert_eq!(result["unaudited"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn audit_config_rejects_short_hash() {
        let ctx = test_ctx();
        let err = handle_audit_config(
            &json!({
                "path": "/etc/foo",
                "sha256": "abc123",
                "auditor": "ops",
            }),
            &ctx,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
        assert!(err.message.contains("invalid sha256"));
    }

    #[tokio::test]
    async fn audit_config_rejects_non_hex() {
        let ctx = test_ctx();
        let bad = "g".repeat(64);
        let err = handle_audit_config(
            &json!({
                "path": "/etc/foo",
                "sha256": bad,
                "auditor": "ops",
            }),
            &ctx,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
    }

    #[tokio::test]
    async fn audit_config_missing_auditor() {
        let ctx = test_ctx();
        let err = handle_audit_config(
            &json!({
                "path": "/etc/foo",
                "sha256": HASH_A,
            }),
            &ctx,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
        assert!(err.message.contains("auditor"));
    }

    #[tokio::test]
    async fn check_config_audit_empty_paths() {
        let ctx = test_ctx();
        let result = handle_check_config_audit(&json!({"paths": []}), &ctx).await.unwrap();
        assert_eq!(result["audited"].as_array().unwrap().len(), 0);
        assert_eq!(result["unaudited"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn check_config_audit_rejects_missing_paths_array() {
        let ctx = test_ctx();
        let err = handle_check_config_audit(&json!({}), &ctx).await.unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
        assert!(err.message.contains("paths"));
    }

    #[tokio::test]
    async fn check_config_audit_rejects_malformed_entry() {
        let ctx = test_ctx();
        let err = handle_check_config_audit(&json!({"paths": [{"path": "/etc/foo"}]}), &ctx)
            .await
            .unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
    }

    #[tokio::test]
    async fn reaudit_same_hash_updates_record() {
        let ctx = test_ctx();
        handle_audit_config(&json!({"path": "/p1", "sha256": HASH_A, "auditor": "alice"}), &ctx)
            .await
            .unwrap();
        handle_audit_config(
            &json!({"path": "/p2", "sha256": HASH_A, "auditor": "bob", "note": "second review"}),
            &ctx,
        )
        .await
        .unwrap();

        let result = handle_check_config_audit(&json!({"paths": [{"path": "/p2", "sha256": HASH_A}]}), &ctx)
            .await
            .unwrap();
        let audited = result["audited"].as_array().unwrap();
        assert_eq!(audited.len(), 1);
        // The most recent record wins (bob, /p2, with note).
        assert_eq!(audited[0]["auditor"].as_str().unwrap(), "bob");
        assert_eq!(audited[0]["audited_path"].as_str().unwrap(), "/p2");
    }
}
