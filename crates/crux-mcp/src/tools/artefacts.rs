// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Artefact MCP tool handlers (ExecPlan
//! `agent-ux-12-calm-deferred-output-2026-05-27`).
//!
//! Three tools, all passport-attributed:
//!
//! - `artefact_put`  — base64 bytes IN → `{artefact_id, size_bytes, ...}` OUT.
//!   The id is `art_<blake3_hex>`, so two writers of identical content
//!   coalesce. Sibling Wave 2/3 tools (`audit_export_bundle`, `output_attest`)
//!   are expected to call this internally and return only the id to the
//!   user — the "calm" half of calm-deferred-output.
//! - `artefact_get`  — id IN → `{content_base64, mime_type, ...}` OUT. Cross-
//!   passport reads return `CAPABILITY_DENIED` (QC.3).
//! - `artefact_list` — metadata-only listing scoped to the caller's passport.
//!   Reserved-prefix mime entries are filtered out (T.1). This is the read
//!   surface the console `/artefacts` panel calls.
//!
//! Feature flag: `CORECRUXD_FEATURE_ARTEFACTS=1`. Default OFF so the surface
//! ships dark until the operator opts in.
//!
//! TTL policy (enforced here, not in the store): default 7 days, max 90 days.
//! The store records exactly what we pass; capping is a policy decision and
//! belongs at the tool layer.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde_json::{json, Value};

use crate::dispatch::{McpContext, CAPABILITY_DENIED};
use crate::envelope::{AutonomyConsumed, Envelope, EnvelopeLinks, MemoryUsed};
use crate::protocol::{JsonRpcError, INVALID_PARAMS};
use crate::scope;
use corecrux_memory::artefact_store::{mime_is_reserved, ArtefactError, ArtefactMetadata, ArtefactRecord, PutArtefact};

/// Environment flag gating the entire artefact MCP surface. Default OFF.
pub const FEATURE_FLAG_ENV: &str = "CORECRUXD_FEATURE_ARTEFACTS";

/// Default TTL applied when the caller omits `ttl_seconds`. Aligns with
/// `default 7d` from the ExecPlan constraints section.
pub const DEFAULT_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;

/// Hard cap (free tier) on caller-supplied TTL. 90 days per the ExecPlan.
pub const MAX_TTL_SECONDS: u64 = 90 * 24 * 60 * 60;

/// Shared lock for tests that mutate the `CORECRUXD_FEATURE_ARTEFACTS` env
/// var. Delegates to [`crate::test_env_lock`] so every env-mutating test
/// in this crate shares one process-wide `tokio::sync::Mutex` — per-module
/// locks don't prevent concurrent writes to `environ` from a sibling test
/// holding a different module's lock.
#[doc(hidden)]
pub fn artefact_flag_lock() -> &'static tokio::sync::Mutex<()> {
    crate::test_env_lock()
}

pub fn artefacts_enabled() -> bool {
    match std::env::var(FEATURE_FLAG_ENV) {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            !matches!(v.as_str(), "" | "0" | "false" | "off" | "no")
        }
        Err(_) => false,
    }
}

fn feature_disabled_response(tool: &str) -> Value {
    json!({
        "content": [{
            "type": "text",
            "text": format!(
                "{tool} disabled: set {FEATURE_FLAG_ENV}=1 on the daemon to enable"
            )
        }],
        "structuredContent": {
            "feature_enabled": false,
            "feature_flag": FEATURE_FLAG_ENV,
            "tool": tool,
        }
    })
}

fn require_str<'a>(args: &'a Value, field: &str) -> Result<&'a str, JsonRpcError> {
    args.get(field).and_then(|v| v.as_str()).ok_or_else(|| JsonRpcError {
        code: INVALID_PARAMS,
        message: format!("missing required param: {field}"),
        data: Some(json!({"param": field, "required": true})),
    })
}

fn require_passport(ctx: &McpContext, tool: &str) -> Result<String, JsonRpcError> {
    scope::agent_name(ctx.agent.as_ref())
        .map(str::to_string)
        .ok_or_else(|| JsonRpcError {
            code: INVALID_PARAMS,
            message: format!("{tool} requires an authenticated agent identity (passport)"),
            data: Some(json!({"requires_agent_identity": true})),
        })
}

fn resolve_ttl(raw: Option<u64>) -> Result<Option<u64>, JsonRpcError> {
    let ttl = raw.unwrap_or(DEFAULT_TTL_SECONDS);
    if ttl == 0 {
        // 0 → caller wants no expiry (only callable; the policy cap above
        // still applies if they pass a positive value).
        return Ok(None);
    }
    if ttl > MAX_TTL_SECONDS {
        return Err(JsonRpcError {
            code: INVALID_PARAMS,
            message: format!("ttl_seconds={ttl} exceeds max {MAX_TTL_SECONDS} (90 days)"),
            data: Some(json!({"ttl_seconds": ttl, "max_ttl_seconds": MAX_TTL_SECONDS})),
        });
    }
    Ok(Some(ttl))
}

fn metadata_to_json(m: &ArtefactMetadata) -> Value {
    json!({
        "artefact_id":   m.artefact_id,
        "mime_type":     m.mime_type,
        "tool_origin":   m.tool_origin,
        "size_bytes":    m.size_bytes,
        "created_at":    m.created_at.to_rfc3339(),
        "expires_at":    m.expires_at.map(|e| e.to_rfc3339()),
    })
}

fn record_to_metadata_json(r: &ArtefactRecord) -> Value {
    metadata_to_json(&r.to_metadata())
}

// ── artefact_put ───────────────────────────────────────────────────────────

/// `artefact_put` — store a content blob under a passport-owned, BLAKE3-keyed
/// id. Returns metadata only (the content is fetched separately via
/// `artefact_get`). This is the "park the big payload" side of calm-deferred
/// output.
pub async fn handle_artefact_put(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    if !artefacts_enabled() {
        return Ok(feature_disabled_response("artefact_put"));
    }
    let passport = require_passport(ctx, "artefact_put")?;
    let mime_type = require_str(args, "mime_type")?.to_string();
    let tool_origin = args.get("tool_origin").and_then(|v| v.as_str()).map(str::to_string);
    let ttl_seconds = args.get("ttl_seconds").and_then(|v| v.as_u64());
    let ttl_seconds = resolve_ttl(ttl_seconds)?;

    // Either base64 inline content OR (future) a content_path. Inline only in
    // this revision; the path variant requires content-addressed disk storage
    // (companion-lane registration) which is out of scope.
    let content_b64 = require_str(args, "content_bytes_base64")?;
    let content = B64.decode(content_b64.as_bytes()).map_err(|e| JsonRpcError {
        code: INVALID_PARAMS,
        message: format!("content_bytes_base64 is not valid base64: {e}"),
        data: Some(json!({"param": "content_bytes_base64"})),
    })?;
    if content.is_empty() {
        return Err(JsonRpcError {
            code: INVALID_PARAMS,
            message: "content_bytes_base64 decoded to zero bytes".to_string(),
            data: Some(json!({"param": "content_bytes_base64"})),
        });
    }

    let req = PutArtefact {
        owner_passport: passport,
        mime_type,
        tool_origin,
        content,
        ttl_seconds,
    };
    let mut store = ctx.artefact_store.write().await;
    let record = store.put(req).map_err(|e| JsonRpcError {
        code: INVALID_PARAMS,
        message: format!("artefact_put failed: {e}"),
        data: Some(json!({"error": e.to_string()})),
    })?;
    drop(store);

    Ok(json!({
        "content": [{
            "type": "text",
            "text": format!("stored artefact {} ({} bytes)", record.artefact_id, record.size_bytes)
        }],
        "structuredContent": record_to_metadata_json(&record),
    }))
}

// ── artefact_get ───────────────────────────────────────────────────────────

/// `artefact_get` — fetch the content of a previously-`put` artefact. Cross-
/// passport access returns `CAPABILITY_DENIED` so the operator can audit.
pub async fn handle_artefact_get(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    if !artefacts_enabled() {
        return Ok(feature_disabled_response("artefact_get"));
    }
    let passport = require_passport(ctx, "artefact_get")?;
    let artefact_id = require_str(args, "artefact_id")?;

    let store = ctx.artefact_store.read().await;
    let record = store.get(artefact_id, &passport).map_err(|e| match e {
        ArtefactError::Forbidden => JsonRpcError {
            code: CAPABILITY_DENIED,
            message: "artefact owned by another passport".to_string(),
            data: Some(json!({"artefact_id": artefact_id, "reason": "cross_passport"})),
        },
        ArtefactError::NotFound => JsonRpcError {
            code: INVALID_PARAMS,
            message: "artefact not found or expired".to_string(),
            data: Some(json!({"artefact_id": artefact_id})),
        },
        ArtefactError::EmptyContent => JsonRpcError {
            code: INVALID_PARAMS,
            message: "artefact had empty content (corrupt store row)".to_string(),
            data: Some(json!({"artefact_id": artefact_id})),
        },
    })?;
    let content_b64 = B64.encode(&record.content);
    drop(store);

    Ok(json!({
        "content": [{
            "type": "text",
            "text": format!("artefact {} ({} bytes, mime={})", record.artefact_id, record.size_bytes, record.mime_type)
        }],
        "structuredContent": {
            "artefact_id":     record.artefact_id,
            "mime_type":       record.mime_type,
            "tool_origin":     record.tool_origin,
            "size_bytes":      record.size_bytes,
            "created_at":      record.created_at.to_rfc3339(),
            "expires_at":      record.expires_at.map(|e| e.to_rfc3339()),
            "content_base64":  content_b64,
        }
    }))
}

// ── artefact_list ──────────────────────────────────────────────────────────

/// `artefact_list` — paginated metadata listing scoped to the caller's
/// passport. Reserved-prefix mime entries are filtered (T.1). This is the
/// surface the console `/artefacts` panel calls.
pub async fn handle_artefact_list(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    if !artefacts_enabled() {
        return Ok(feature_disabled_response("artefact_list"));
    }
    let passport = require_passport(ctx, "artefact_list")?;
    let top_k = args.get("top_k").and_then(|v| v.as_u64()).unwrap_or(20) as usize;
    let scope_filter = args.get("scope").and_then(|v| v.as_str()).map(str::to_string);

    let store = ctx.artefact_store.read().await;
    let mut items = store.list(&passport, top_k);
    drop(store);

    // Optional `scope` argument acts as a mime_type substring filter so a
    // caller can ask "only my audit_export_bundle artefacts".
    if let Some(scope) = scope_filter {
        items.retain(|m| m.mime_type.contains(&scope) || m.tool_origin.as_deref() == Some(scope.as_str()));
    }

    let json_items: Vec<Value> = items.iter().map(metadata_to_json).collect();
    Ok(json!({
        "content": [{
            "type": "text",
            "text": format!("{} artefact(s) for passport {}", items.len(), passport)
        }],
        "structuredContent": {
            "artefacts": json_items,
            "count": items.len(),
        }
    }))
}

// ── envelope builder ──────────────────────────────────────────────────────

/// Build the audit envelope for `artefact_list`. Mirrors the
/// `query_facts` / `memory_acknowledge_use` pattern: surface artefact ids as
/// `memories_used[]` entries so the host can render "I parked this for you"
/// affordances next to the chat turn. Reserved-prefix mime types are stripped
/// (the same rule the underlying `list` enforces; this is a defence-in-depth
/// repetition for T.1 in case a future list variant relaxes the filter).
pub async fn build_envelope_for_artefact_list(args: &Value, ctx: &McpContext) -> Envelope {
    let passport_opt = scope::agent_name(ctx.agent.as_ref()).map(str::to_string);
    let top_k = args.get("top_k").and_then(|v| v.as_u64()).unwrap_or(20) as usize;

    let memories_used: Vec<MemoryUsed> = match passport_opt.as_deref() {
        Some(passport) => {
            let store = ctx.artefact_store.read().await;
            let items = store.list(passport, top_k);
            drop(store);
            let now = chrono::Utc::now();
            items
                .into_iter()
                .filter(|m| !mime_is_reserved(&m.mime_type))
                .map(|m| {
                    let age_days = (now - m.created_at).num_days();
                    let age_days = if age_days < 0 { None } else { Some(age_days) };
                    let age_hours = (now - m.created_at).num_hours();
                    let age_hours = if age_hours < 0 { None } else { Some(age_hours) };
                    MemoryUsed {
                        fact_id: m.artefact_id.clone(),
                        topic: m.mime_type.clone(),
                        age_days,
                        age_hours,
                        freshness: crate::envelope::Freshness::from_age_days(age_days),
                    }
                })
                .collect()
        }
        None => Vec::new(),
    };

    let scope_str = passport_opt
        .as_deref()
        .map_or_else(|| format!("node:{}", ctx.node_id), |name| format!("agent:{name}"));

    Envelope {
        receipts_used: Vec::new(),
        memories_used,
        autonomy_consumed: AutonomyConsumed {
            capability: "artefacts:read".to_string(),
            cost_credits: 0,
            scope: scope_str,
        },
        predicted_effects: Vec::new(),
        links: EnvelopeLinks::default(),
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::agent::AgentIdentity;
    use crate::dispatch::McpContext;

    fn test_ctx_with_agent(name: &str) -> McpContext {
        McpContext::new_default("test-artefact").with_agent(AgentIdentity {
            name: name.to_string(),
            token_hash: [0u8; 32],
        })
    }

    fn flag_lock() -> &'static tokio::sync::Mutex<()> {
        artefact_flag_lock()
    }

    fn enable_flag() {
        std::env::set_var(FEATURE_FLAG_ENV, "1");
    }
    fn disable_flag() {
        std::env::remove_var(FEATURE_FLAG_ENV);
    }

    #[tokio::test]
    async fn put_requires_agent_identity() {
        let _g = flag_lock().lock().await;
        enable_flag();
        let ctx = McpContext::new_default("no-agent");
        let err = handle_artefact_put(
            &json!({
                "mime_type": "text/plain",
                "content_bytes_base64": B64.encode(b"hi"),
            }),
            &ctx,
        )
        .await
        .unwrap_err();
        assert!(err.message.contains("authenticated agent identity"));
        disable_flag();
    }

    #[tokio::test]
    async fn put_returns_deterministic_id_for_identical_bytes() {
        let _g = flag_lock().lock().await;
        enable_flag();
        let ctx = test_ctx_with_agent("alice");
        let r1 = handle_artefact_put(
            &json!({
                "mime_type": "text/plain",
                "content_bytes_base64": B64.encode(b"hello-art"),
            }),
            &ctx,
        )
        .await
        .unwrap();
        let r2 = handle_artefact_put(
            &json!({
                "mime_type": "text/plain",
                "content_bytes_base64": B64.encode(b"hello-art"),
            }),
            &ctx,
        )
        .await
        .unwrap();
        let id1 = r1["structuredContent"]["artefact_id"].as_str().unwrap();
        let id2 = r2["structuredContent"]["artefact_id"].as_str().unwrap();
        assert_eq!(id1, id2);
        assert!(id1.starts_with("art_"));
        disable_flag();
    }

    #[tokio::test]
    async fn get_returns_original_bytes() {
        let _g = flag_lock().lock().await;
        enable_flag();
        let ctx = test_ctx_with_agent("alice");
        let bytes = b"opaque content goes here".to_vec();
        let put = handle_artefact_put(
            &json!({
                "mime_type": "application/octet-stream",
                "content_bytes_base64": B64.encode(&bytes),
            }),
            &ctx,
        )
        .await
        .unwrap();
        let id = put["structuredContent"]["artefact_id"].as_str().unwrap();
        let got = handle_artefact_get(&json!({"artefact_id": id}), &ctx).await.unwrap();
        let b64 = got["structuredContent"]["content_base64"].as_str().unwrap();
        assert_eq!(B64.decode(b64).unwrap(), bytes);
        disable_flag();
    }

    #[tokio::test]
    async fn cross_passport_get_returns_capability_denied() {
        let _g = flag_lock().lock().await;
        enable_flag();
        let alice = test_ctx_with_agent("alice");
        let put = handle_artefact_put(
            &json!({
                "mime_type": "text/plain",
                "content_bytes_base64": B64.encode(b"alice-only"),
            }),
            &alice,
        )
        .await
        .unwrap();
        let id = put["structuredContent"]["artefact_id"].as_str().unwrap().to_string();

        // Use the SAME context's underlying store but a DIFFERENT agent
        // identity. The cleanest way (also matches the with_agent pattern):
        // build a sibling ctx that shares the artefact store.
        let eve = alice.with_agent(AgentIdentity {
            name: "eve".to_string(),
            token_hash: [0u8; 32],
        });
        let err = handle_artefact_get(&json!({"artefact_id": id}), &eve)
            .await
            .unwrap_err();
        assert_eq!(err.code, CAPABILITY_DENIED);
        disable_flag();
    }

    #[tokio::test]
    async fn list_only_shows_callers_artefacts_and_filters_reserved() {
        let _g = flag_lock().lock().await;
        enable_flag();
        let alice = test_ctx_with_agent("alice");
        // Public mime
        handle_artefact_put(
            &json!({
                "mime_type": "text/plain",
                "content_bytes_base64": B64.encode(b"alpha"),
            }),
            &alice,
        )
        .await
        .unwrap();
        // Reserved mime — must NOT surface in list (T.1)
        handle_artefact_put(
            &json!({
                "mime_type": "__ops::secret",
                "content_bytes_base64": B64.encode(b"do-not-show"),
            }),
            &alice,
        )
        .await
        .unwrap();
        // Bob's artefact in the same store — alice's list must not show it
        let bob = alice.with_agent(AgentIdentity {
            name: "bob".to_string(),
            token_hash: [0u8; 32],
        });
        handle_artefact_put(
            &json!({
                "mime_type": "text/plain",
                "content_bytes_base64": B64.encode(b"bob-only"),
            }),
            &bob,
        )
        .await
        .unwrap();

        let listed = handle_artefact_list(&json!({"top_k": 20}), &alice).await.unwrap();
        let items = listed["structuredContent"]["artefacts"].as_array().unwrap();
        assert_eq!(items.len(), 1, "expected 1, got {items:?}");
        assert_eq!(items[0]["mime_type"], "text/plain");
        disable_flag();
    }

    #[tokio::test]
    async fn ttl_expiry_makes_artefact_unreadable() {
        let _g = flag_lock().lock().await;
        enable_flag();
        let ctx = test_ctx_with_agent("alice");
        let put = handle_artefact_put(
            &json!({
                "mime_type": "text/plain",
                "ttl_seconds": 60,
                "content_bytes_base64": B64.encode(b"ephemeral"),
            }),
            &ctx,
        )
        .await
        .unwrap();
        let id = put["structuredContent"]["artefact_id"].as_str().unwrap().to_string();
        // Force expiry into the past.
        {
            let mut store = ctx.artefact_store.write().await;
            store.set_expires_at_for_test(&id, chrono::Utc::now() - chrono::Duration::seconds(5));
        }
        let err = handle_artefact_get(&json!({"artefact_id": &id}), &ctx)
            .await
            .unwrap_err();
        assert!(err.message.contains("not found or expired"));
        disable_flag();
    }

    #[tokio::test]
    async fn ttl_caps_at_max() {
        let _g = flag_lock().lock().await;
        enable_flag();
        let ctx = test_ctx_with_agent("alice");
        let err = handle_artefact_put(
            &json!({
                "mime_type": "text/plain",
                "ttl_seconds": MAX_TTL_SECONDS + 1,
                "content_bytes_base64": B64.encode(b"x"),
            }),
            &ctx,
        )
        .await
        .unwrap_err();
        assert!(err.message.contains("exceeds max"));
        disable_flag();
    }

    #[tokio::test]
    async fn feature_disabled_returns_friendly_message() {
        let _g = flag_lock().lock().await;
        disable_flag();
        let ctx = test_ctx_with_agent("alice");
        let r = handle_artefact_put(&json!({"mime_type":"t","content_bytes_base64": B64.encode(b"x")}), &ctx)
            .await
            .unwrap();
        let text = r["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("disabled"));
        assert!(text.contains("CORECRUXD_FEATURE_ARTEFACTS"));
    }
}
