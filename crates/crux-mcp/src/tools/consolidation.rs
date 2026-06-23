// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Contradiction-surfacing + safe consolidation MCP tool handlers.
//!
//! Audit II gap-closure M4 (operator surfacing of the M1/M2 memory passes
//! that already live in `corecrux_memory::fact_store`).
//!
//! Two tools:
//!
//! - `memory_contradictions` (read) — runs the deterministic, NON-mutating
//!   [`FactStore::contradiction_candidates_v1`] pass and returns ranked
//!   `{entity, key, reason, fact_ids, values, …}` candidates. It only
//!   DETECTS + SURFACES; it never resolves anything. Honours
//!   `token_budget` (default 500, QC.2).
//! - `memory_consolidate` (write, passport-required) — drives the safe
//!   [`FactStore::consolidate_facts_v1`] pass. This is the EXPLICIT resolve
//!   step: it creates a canonical fact, supersedes the named targets, and
//!   emits a consolidation receipt — but only after the store's protection
//!   guards reject pinned / receipt-linked / private / high-confidence /
//!   deleted / out-of-(entity,key) targets. History is preserved (targets
//!   are superseded, never hard-deleted).
//!
//! Resolution is deliberately split from detection: the read tool (and the
//! background scheduler in `corecruxd::consolidation_scheduler`) only
//! surfaces candidates; mutation happens solely through this explicit
//! write tool or the console `POST /v1/console/review/consolidations`
//! route, both of which require an authenticated actor.

use serde_json::{json, Value};

use corecrux_memory::fact_store::{ConsolidationErrorV1, ConsolidationRequestV1, HorizonClass};

use crate::dispatch::McpContext;
use crate::protocol::{JsonRpcError, INVALID_PARAMS};
use crate::scope;

/// Environment flag that gates the consolidation read/write surfaces.
///
/// Enabled by default (opt-out), mirroring
/// [`crate::tools::freshness::FEATURE_FLAG_ENV`]: only an explicit
/// `""`/`0`/`false`/`off`/`no` value disables both handlers, so the
/// surface can ship behind a kill switch via
/// `CORECRUXD_FEATURE_CONSOLIDATION=0`.
pub const FEATURE_FLAG_ENV: &str = "CORECRUXD_FEATURE_CONSOLIDATION";

/// Returns true if the consolidation feature flag is enabled.
///
/// Default-on (opt-out): an UNSET env var means enabled. Only an explicit
/// `""`/`0`/`false`/`off`/`no` (case-insensitive) disables the surface.
pub fn consolidation_enabled() -> bool {
    match std::env::var(FEATURE_FLAG_ENV) {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            !matches!(v.as_str(), "" | "0" | "false" | "off" | "no")
        }
        Err(_) => true,
    }
}

fn feature_disabled_error() -> JsonRpcError {
    JsonRpcError {
        code: crate::dispatch::CAPABILITY_DENIED,
        message: format!(
            "consolidation feature explicitly disabled (unset {FEATURE_FLAG_ENV} to re-enable; it is on by default)"
        ),
        data: Some(json!({"flag": FEATURE_FLAG_ENV})),
    }
}

fn require_passport(ctx: &McpContext, tool: &str) -> Result<String, JsonRpcError> {
    match scope::agent_name(ctx.agent.as_ref()) {
        Some(name) => Ok(name.to_string()),
        None => Err(JsonRpcError {
            code: crate::dispatch::CAPABILITY_DENIED,
            message: format!("{tool} requires an authenticated passport (anonymous calls rejected)"),
            data: Some(json!({"tool": tool, "requires_passport": true})),
        }),
    }
}

/// `memory_contradictions` — read-only contradiction-candidate pass.
///
/// Surfaces active, non-superseded facts that share `(entity, key)` and
/// carry opposite deterministic polarity classes. NON-mutating — it only
/// emits candidates, never decisions. Passport-optional; `token_budget`
/// (default 500, QC.2) caps the rows emitted.
pub async fn handle_memory_contradictions(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    if !consolidation_enabled() {
        return Err(feature_disabled_error());
    }

    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(50).min(500) as usize;
    let token_budget = args.get("token_budget").and_then(|v| v.as_u64()).unwrap_or(500) as usize;

    let store = ctx.fact_store.read().await;
    // The pass itself is bounded by `limit`; we additionally trim by the
    // mandatory token budget so a contradiction-heavy store can't blow the
    // output-token budget (QC.2 primary defence).
    let candidates = store.contradiction_candidates_v1(limit);
    drop(store);

    let mut rows: Vec<Value> = Vec::new();
    let mut used_tokens: usize = 0;
    for c in &candidates {
        let row = json!({
            "entity": c.entity,
            "key": c.key,
            "reason": c.reason,
            "polarity_a": c.polarity_a,
            "polarity_b": c.polarity_b,
            "fact_ids": c.fact_ids,
            "values": c.values,
        });
        used_tokens += crate::token_estimate::estimate_tokens(&row) as usize;
        if used_tokens > token_budget && !rows.is_empty() {
            crate::ledger::record_truncation("memory_contradictions", "token_budget");
            break;
        }
        rows.push(row);
    }

    let text = if rows.is_empty() {
        "no contradiction candidates (no active opposite-polarity facts sharing entity+key)".to_string()
    } else {
        format!(
            "{} contradiction candidate(s) detected; see structured `candidates` — read-only, nothing was mutated. \
             Resolve explicitly via memory_consolidate (or the console review surface).",
            rows.len()
        )
    };

    Ok(json!({
        "content": [{ "type": "text", "text": text }],
        "structuredContent": {
            "candidates": rows,
            "count": rows.len(),
            "limit": limit,
            "dry_run": true,
        }
    }))
}

/// `memory_consolidate` — explicit safe consolidation (write).
///
/// Creates a canonical fact under `(entity, key)` and supersedes each
/// named target, emitting a consolidation receipt. Passport-required.
/// The store's [`ConsolidationRequestV1`] guards reject any protected
/// target (pinned via `protected_fact_ids`, receipt-linked, private,
/// confidence ≥ `protected_confidence_floor`, deleted, or outside the
/// requested `(entity, key)`) — so a pinned / recent-high-confidence /
/// receipt-referenced fact is never lost. History is preserved.
pub async fn handle_memory_consolidate(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    if !consolidation_enabled() {
        return Err(feature_disabled_error());
    }
    let actor = require_passport(ctx, "memory_consolidate")?;

    let entity = require_str(args, "entity")?.to_string();
    let key = require_str(args, "key")?.to_string();
    let canonical_value = require_str(args, "canonical_value")?.to_string();

    let target_fact_ids = string_array(args, "target_fact_ids");
    if target_fact_ids.is_empty() {
        return Err(JsonRpcError {
            code: INVALID_PARAMS,
            message: "target_fact_ids must be a non-empty array".to_string(),
            data: Some(json!({"param": "target_fact_ids", "required": true})),
        });
    }
    let protected_fact_ids = string_array(args, "protected_fact_ids");

    let consolidation_id = args
        .get("consolidation_id")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map_or_else(|| format!("mcp-{}", uuid::Uuid::new_v4()), str::to_string);

    let confidence = args.get("confidence").and_then(|v| v.as_f64()).map(|c| c as f32);
    let protected_confidence_floor = args
        .get("protected_confidence_floor")
        .and_then(|v| v.as_f64())
        .map(|c| c as f32);
    let horizon_class = args
        .get("horizon_class")
        .and_then(|v| v.as_str())
        .and_then(HorizonClass::parse);

    // Build the request, letting serde defaults fill the optional floors when
    // the caller omits them (matches the console route's behaviour).
    let mut req = ConsolidationRequestV1 {
        consolidation_id: consolidation_id.clone(),
        entity,
        key,
        canonical_value,
        target_fact_ids: target_fact_ids.clone(),
        protected_fact_ids,
        confidence: confidence.unwrap_or(1.0),
        source_receipt: Some(format!("consolidation:{consolidation_id}")),
        actor: Some(actor),
        horizon_class,
        protected_confidence_floor: protected_confidence_floor.unwrap_or(0.99),
    };
    if confidence.is_none() {
        // `default_confidence()` is 1.0; preserve that explicitly.
        req.confidence = 1.0;
    }

    let report = {
        let mut store = ctx.fact_store.write().await;
        store.consolidate_facts_v1(req)
    };

    match report {
        Ok(report) => Ok(json!({
            "content": [{
                "type": "text",
                "text": format!(
                    "consolidated {} target(s) into canonical fact {} (receipt {}); history preserved",
                    report.receipt.superseded_fact_ids.len(),
                    report.receipt.canonical_fact_id,
                    report.receipt.consolidation_id,
                ),
            }],
            "structuredContent": {
                "status": report.status,
                "receipt": report.receipt,
            }
        })),
        Err(err) => Err(consolidation_error_to_rpc(err)),
    }
}

/// Map a [`ConsolidationErrorV1`] onto a JSON-RPC error, preserving the
/// protection-class reason so the operator sees WHY a target was refused
/// (mirrors the console route's HTTP status mapping).
fn consolidation_error_to_rpc(err: ConsolidationErrorV1) -> JsonRpcError {
    let (code, reason) = match &err {
        ConsolidationErrorV1::NoTargets | ConsolidationErrorV1::TargetOutsideEntityKey(_) => {
            (INVALID_PARAMS, "invalid_request")
        }
        ConsolidationErrorV1::TargetNotFound(_) => (INVALID_PARAMS, "target_not_found"),
        ConsolidationErrorV1::TargetDeleted(_) => (crate::dispatch::CAPABILITY_DENIED, "target_deleted"),
        ConsolidationErrorV1::TargetPinned(_) => (crate::dispatch::CAPABILITY_DENIED, "target_pinned"),
        ConsolidationErrorV1::TargetPrivate(_) => (crate::dispatch::CAPABILITY_DENIED, "target_private"),
        ConsolidationErrorV1::TargetReceiptLinked(_) => (crate::dispatch::CAPABILITY_DENIED, "target_receipt_linked"),
        ConsolidationErrorV1::TargetHighConfidence { .. } => {
            (crate::dispatch::CAPABILITY_DENIED, "target_high_confidence")
        }
        ConsolidationErrorV1::Journal(_) => (crate::protocol::INTERNAL_ERROR, "journal_error"),
    };
    JsonRpcError {
        code,
        message: err.to_string(),
        data: Some(json!({"reason": reason, "protected": true})),
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────

fn require_str<'a>(args: &'a Value, field: &str) -> Result<&'a str, JsonRpcError> {
    args.get(field).and_then(|v| v.as_str()).ok_or_else(|| JsonRpcError {
        code: INVALID_PARAMS,
        message: format!("missing required param: {field}"),
        data: Some(json!({"param": field, "required": true})),
    })
}

fn string_array(args: &Value, field: &str) -> Vec<String> {
    args.get(field)
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::agent::AgentIdentity;
    use crate::tools::facts::handle_store_fact;

    fn enable() {
        std::env::set_var(FEATURE_FLAG_ENV, "1");
    }
    fn disable() {
        std::env::remove_var(FEATURE_FLAG_ENV);
    }
    fn disable_explicit() {
        std::env::set_var(FEATURE_FLAG_ENV, "0");
    }

    fn test_ctx() -> McpContext {
        McpContext::new_default("test-consolidation")
    }

    fn agent_ctx(name: &str) -> McpContext {
        test_ctx().with_agent(AgentIdentity {
            name: name.to_string(),
            token_hash: [0u8; 32],
        })
    }

    fn flag_lock() -> &'static tokio::sync::Mutex<()> {
        crate::test_env_lock()
    }

    /// Pull the freshly-minted fact_id out of a `store_fact` text response.
    fn fact_id_of(resp: &Value) -> String {
        resp["content"][0]["text"]
            .as_str()
            .unwrap()
            .split_whitespace()
            .nth(2)
            .unwrap()
            .to_string()
    }

    #[tokio::test]
    async fn flag_default_on_contract() {
        let _g = flag_lock().lock().await;
        disable();
        assert!(consolidation_enabled(), "unset env must default to enabled");
        for v in ["0", "false", "off", "no", ""] {
            std::env::set_var(FEATURE_FLAG_ENV, v);
            assert!(!consolidation_enabled(), "value {v:?} must disable");
        }
        enable();
        assert!(consolidation_enabled(), "=1 must enable");
        disable();
    }

    #[tokio::test]
    async fn contradictions_disabled_returns_capability_denied() {
        let _g = flag_lock().lock().await;
        disable_explicit();
        let ctx = test_ctx();
        let err = handle_memory_contradictions(&json!({}), &ctx).await.unwrap_err();
        assert_eq!(err.code, crate::dispatch::CAPABILITY_DENIED);
        disable();
    }

    #[tokio::test]
    async fn contradictions_detects_opposite_polarity_without_mutating() {
        let _g = flag_lock().lock().await;
        enable();
        let alice = agent_ctx("alice");

        // Two active, opposite-polarity facts under the same (entity, key).
        // The second store would normally auto-supersede the first (same
        // entity+key version chain), so clear that to simulate an unresolved
        // conflict — exactly what the M1 pass is designed to surface.
        let a = handle_store_fact(
            &json!({"entity": "service:api", "key": "enabled", "value": "enabled"}),
            &alice,
        )
        .await
        .unwrap();
        let a_id = fact_id_of(&a);
        handle_store_fact(
            &json!({"entity": "service:api", "key": "enabled", "value": "disabled"}),
            &alice,
        )
        .await
        .unwrap();
        {
            let mut store = alice.fact_store.write().await;
            assert!(store.clear_superseded(&a_id), "simulate unresolved conflict");
        }

        let res = handle_memory_contradictions(&json!({"token_budget": 2000}), &alice)
            .await
            .unwrap();
        assert_eq!(res["structuredContent"]["dry_run"], true);
        let cands = res["structuredContent"]["candidates"].as_array().unwrap();
        assert_eq!(cands.len(), 1, "one contradiction expected");
        assert_eq!(cands[0]["entity"], "service:api");
        assert_eq!(cands[0]["reason"], "opposite_polarity_same_entity_key");

        // Read-only: both facts remain present, neither newly deleted.
        let store = alice.fact_store.read().await;
        assert!(store.get(&a_id).is_some(), "contradiction pass must not delete facts");
        disable();
    }

    #[tokio::test]
    async fn consolidate_requires_passport() {
        let _g = flag_lock().lock().await;
        enable();
        let ctx = test_ctx();
        let err = handle_memory_consolidate(
            &json!({"entity": "e", "key": "k", "canonical_value": "v", "target_fact_ids": ["f_x"]}),
            &ctx,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, crate::dispatch::CAPABILITY_DENIED);
        disable();
    }

    #[tokio::test]
    async fn consolidate_supersedes_targets_and_emits_receipt() {
        let _g = flag_lock().lock().await;
        enable();
        let alice = agent_ctx("alice");

        let old = handle_store_fact(
            &json!({"entity": "proj", "key": "status", "value": "blocked", "confidence": 0.4}),
            &alice,
        )
        .await
        .unwrap();
        let old_id = old["structuredContent"]["fact_id"]
            .as_str()
            .map(str::to_string)
            .unwrap_or_else(|| fact_id_of(&old));
        let newer = handle_store_fact(
            &json!({"entity": "proj", "key": "status", "value": "active", "confidence": 0.5}),
            &alice,
        )
        .await
        .unwrap();
        let newer_id = newer["structuredContent"]["fact_id"]
            .as_str()
            .map(str::to_string)
            .unwrap_or_else(|| fact_id_of(&newer));
        {
            let mut store = alice.fact_store.write().await;
            assert!(store.clear_superseded(&old_id), "make both targets active");
        }

        let res = handle_memory_consolidate(
            &json!({
                "entity": "proj",
                "key": "status",
                "canonical_value": "active",
                "target_fact_ids": [old_id, newer_id],
                "confidence": 0.8,
            }),
            &alice,
        )
        .await
        .unwrap();
        assert_eq!(res["structuredContent"]["status"], "consolidated");
        let canonical = res["structuredContent"]["receipt"]["canonical_fact_id"]
            .as_str()
            .unwrap()
            .to_string();

        // Targets superseded by the canonical fact; history preserved (3 versions).
        let store = alice.fact_store.read().await;
        assert_eq!(
            store.get(&old_id).unwrap().superseded_by.as_deref(),
            Some(canonical.as_str())
        );
        let history = store.fact_history("proj", "status");
        assert_eq!(history.len(), 3, "consolidation must preserve version history");
        disable();
    }

    #[tokio::test]
    async fn consolidate_rejects_receipt_linked_target() {
        let _g = flag_lock().lock().await;
        enable();
        let alice = agent_ctx("alice");

        // A fact carrying a source_receipt is receipt-linked → protected.
        let linked = handle_store_fact(
            &json!({"entity": "proj", "key": "decision", "value": "approved", "source_receipt": "receipt:r1"}),
            &alice,
        )
        .await
        .unwrap();
        let linked_id = linked["structuredContent"]["fact_id"]
            .as_str()
            .map(str::to_string)
            .unwrap_or_else(|| fact_id_of(&linked));

        let err = handle_memory_consolidate(
            &json!({
                "entity": "proj",
                "key": "decision",
                "canonical_value": "approved",
                "target_fact_ids": [linked_id.clone()],
            }),
            &alice,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, crate::dispatch::CAPABILITY_DENIED);
        assert_eq!(err.data.as_ref().unwrap()["reason"], "target_receipt_linked");

        // The protected fact was NOT superseded.
        let store = alice.fact_store.read().await;
        assert!(store.get(&linked_id).unwrap().superseded_by.is_none());
        disable();
    }

    #[tokio::test]
    async fn consolidate_rejects_high_confidence_target() {
        let _g = flag_lock().lock().await;
        enable();
        let alice = agent_ctx("alice");

        // A high-confidence (>= floor 0.99) fact is protected from collapse.
        let pinned = handle_store_fact(
            &json!({"entity": "proj", "key": "fact", "value": "active", "confidence": 1.0}),
            &alice,
        )
        .await
        .unwrap();
        let pinned_id = pinned["structuredContent"]["fact_id"]
            .as_str()
            .map(str::to_string)
            .unwrap_or_else(|| fact_id_of(&pinned));

        let err = handle_memory_consolidate(
            &json!({
                "entity": "proj",
                "key": "fact",
                "canonical_value": "active",
                "target_fact_ids": [pinned_id.clone()],
            }),
            &alice,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, crate::dispatch::CAPABILITY_DENIED);
        assert_eq!(err.data.as_ref().unwrap()["reason"], "target_high_confidence");
        disable();
    }
}
