// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Freshness + decay MCP tool handlers.
//!
//! Wave-1 child plan `agent-ux-03-freshness-decay-2026-05-27` M3.
//!
//! Three tools:
//!
//! - `memory_freshness` (read) — list facts with their decay state.
//!   Accepts `token_budget` (mandatory per QC.2 default 500).
//! - `memory_set_horizon` (write) — pin/override a fact's
//!   [`HorizonClass`]. Requires passport.
//! - `memory_reverify` (write) — re-anchor a fact's decay clock without
//!   rewriting the value; emits a `Reverify` CROWN receipt. Requires
//!   passport.
//!
//! All three filter out facts with reserved entity prefixes
//! (`__agent::`, `__ops::`, `__bootstrap__::`) so cross-agent / ops
//! state never leaks via this surface — matches the envelope-spike
//! invariant tested in `dispatch::tests::envelope_on_query_facts_omits_reserved_prefix_entries`.

use chrono::Utc;
use serde_json::{json, Value};

use corecrux_memory::fact_store::HorizonClass;
use corecrux_projections::decay;

use crate::dispatch::McpContext;
use crate::envelope::is_reserved_entity;
use crate::protocol::{JsonRpcError, INVALID_PARAMS};
use crate::scope;

/// Environment flag that gates freshness write/read surfaces.
///
/// When unset/`0`/`false`, all three MCP handlers return a "feature
/// disabled" error so freshness can ship behind a kill switch.
pub const FEATURE_FLAG_ENV: &str = "CORECRUXD_FEATURE_FRESHNESS";

/// Receipt class string used on the `Reverify` CROWN receipts emitted
/// by `memory_reverify`. Verifies under CROWN exactly like other
/// receipt classes; tamper of the body bytes will fail verification.
pub const REVERIFY_RECEIPT_CLASS: &str = "Reverify";

/// Returns true if the freshness feature flag is enabled.
pub fn freshness_enabled() -> bool {
    match std::env::var(FEATURE_FLAG_ENV) {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            !matches!(v.as_str(), "" | "0" | "false" | "off" | "no")
        }
        Err(_) => false,
    }
}

fn feature_disabled_error() -> JsonRpcError {
    JsonRpcError {
        code: crate::dispatch::CAPABILITY_DENIED,
        message: format!("freshness feature disabled (set {FEATURE_FLAG_ENV}=1 to enable)"),
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

/// `memory_freshness` — list (or query) facts with per-fact decay
/// state. Read-only, passport-optional, token-budget mandatory.
///
/// Returns one row per visible fact (reserved-prefix entities are
/// always filtered) with `fact_id`, `entity`, `key`, `horizon_class`,
/// `age_hours`, `freshness`, and `reverified_at`. Useful as the data
/// source for the console `/freshness` panel and the `corecruxctl
/// memory freshness` CLI.
pub async fn handle_memory_freshness(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    if !freshness_enabled() {
        return Err(feature_disabled_error());
    }

    let entity = args.get("entity").and_then(|v| v.as_str()).map(|s| s.to_string());
    let key = args.get("key").and_then(|v| v.as_str()).map(|s| s.to_string());
    let top_k = args.get("top_k").and_then(|v| v.as_u64()).unwrap_or(20).min(500) as usize;
    let token_budget = args.get("token_budget").and_then(|v| v.as_u64()).unwrap_or(500) as usize;
    let agent_name = scope::agent_name(ctx.agent.as_ref());
    let policy = decay::DecayPolicy::from_env();
    let now = Utc::now();

    let store = ctx.fact_store.read().await;
    let mut rows: Vec<Value> = Vec::new();
    let mut used_tokens: usize = 0;

    let mut candidates: Vec<&corecrux_memory::Fact> = store
        .all_facts()
        .filter(|f| !f.deleted)
        .filter(|f| scope::fact_visible_to_agent(f, agent_name))
        .filter(|f| !is_reserved_entity(&f.entity))
        .filter(|f| entity.as_deref().is_none_or(|e| f.entity == e))
        .filter(|f| key.as_deref().is_none_or(|k| f.key == k))
        .collect();

    // Stalest first — sort by age descending (older = higher priority).
    candidates.sort_by(|a, b| a.stored_at.cmp(&b.stored_at));

    for f in candidates.iter().take(top_k) {
        let anchor = f.reverified_at.unwrap_or(f.stored_at);
        let class = projection_class_of(f.horizon_class);
        let fresh = decay::apply_at_chrono(class, f.stored_at, f.reverified_at, now, policy);
        let age_hours = (now - anchor).num_hours().max(0);
        let topic = scope::visible_entity_for_agent(f, agent_name).unwrap_or_else(|| f.entity.clone());
        let row = json!({
            "fact_id": f.fact_id,
            "entity": topic,
            "key": f.key,
            "horizon_class": f.horizon_class.as_str(),
            "freshness": fresh.as_str(),
            "age_hours": age_hours,
            "stored_at": f.stored_at.to_rfc3339(),
            "reverified_at": f.reverified_at.map(|d| d.to_rfc3339()),
        });
        used_tokens += f.tokens.max(8); // floor — even tiny rows cost ~8 tok
        if used_tokens > token_budget && !rows.is_empty() {
            break;
        }
        rows.push(row);
    }

    Ok(json!({
        "content": [{
            "type": "text",
            "text": render_freshness_text(&rows),
        }],
        "structuredContent": {
            "rows": rows,
            "policy": {
                "volatile_stale_hours": policy.volatile_stale_hours,
                "medium_stale_days": policy.medium_stale_days,
                "stable_stale_days": policy.stable_stale_days,
            },
            "now": now.to_rfc3339(),
        }
    }))
}

/// `memory_set_horizon` — pin / override a fact's horizon class.
/// Write, passport-required.
pub async fn handle_memory_set_horizon(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    if !freshness_enabled() {
        return Err(feature_disabled_error());
    }
    let _agent = require_passport(ctx, "memory_set_horizon")?;
    let fact_id = require_str(args, "fact_id")?;
    let class_str = require_str(args, "horizon_class")?;
    let class = HorizonClass::parse(class_str).ok_or_else(|| JsonRpcError {
        code: INVALID_PARAMS,
        message: format!("invalid horizon_class: {class_str}"),
        data: Some(json!({"param": "horizon_class", "allowed": ["volatile", "medium", "stable", "none"]})),
    })?;

    let mut store = ctx.fact_store.write().await;
    // Guard: refuse to set horizon on reserved-prefix entities even with
    // a passport — these are ops/internal state and shouldn't be
    // re-classified by the agent surface.
    if let Some(f) = store.get(fact_id) {
        if is_reserved_entity(&f.entity) {
            return Err(JsonRpcError {
                code: crate::dispatch::CAPABILITY_DENIED,
                message: format!("cannot set horizon on reserved-prefix fact {fact_id}"),
                data: Some(json!({"fact_id": fact_id, "reserved": true})),
            });
        }
    } else {
        return Ok(json!({
            "content": [{
                "type": "text",
                "text": format!("fact not found: {fact_id}"),
            }],
            "isError": false,
        }));
    }
    let ok = store.set_horizon(fact_id, class);

    Ok(json!({
        "content": [{
            "type": "text",
            "text": if ok {
                format!("set horizon_class={} on fact {fact_id}", class.as_str())
            } else {
                format!("fact not found: {fact_id}")
            },
        }],
        "structuredContent": {
            "fact_id": fact_id,
            "horizon_class": class.as_str(),
            "ok": ok,
        }
    }))
}

/// `memory_reverify` — re-anchor a fact's decay clock without
/// rewriting the value. Emits a `Reverify` receipt-class entry under
/// `__reverify_receipts__::<fact_id>` so the CROWN audit chain still
/// has a verifiable handle on the event.
///
/// Write, passport-required.
pub async fn handle_memory_reverify(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    if !freshness_enabled() {
        return Err(feature_disabled_error());
    }
    let agent = require_passport(ctx, "memory_reverify")?;
    let fact_id = require_str(args, "fact_id")?;
    let now = Utc::now();

    let mut store = ctx.fact_store.write().await;
    // Reserved-prefix guard mirrors memory_set_horizon.
    if let Some(f) = store.get(fact_id) {
        if is_reserved_entity(&f.entity) {
            return Err(JsonRpcError {
                code: crate::dispatch::CAPABILITY_DENIED,
                message: format!("cannot reverify reserved-prefix fact {fact_id}"),
                data: Some(json!({"fact_id": fact_id, "reserved": true})),
            });
        }
    } else {
        return Ok(json!({
            "content": [{ "type": "text", "text": format!("fact not found: {fact_id}") }],
            "isError": false,
        }));
    }

    let ok = store.reverify(fact_id, now);
    if !ok {
        return Ok(json!({
            "content": [{ "type": "text", "text": format!("fact not found: {fact_id}") }],
            "isError": false,
        }));
    }
    drop(store);

    // Emit a 'Reverify' receipt fact — append-only, verifiable under
    // CROWN by virtue of being a normal fact write (existing receipt
    // chain). The body carries the class string so audit tooling can
    // filter for it.
    let receipt_id = format!("rev_{}", uuid::Uuid::new_v4().simple());
    let receipt_body = json!({
        "class": REVERIFY_RECEIPT_CLASS,
        "fact_id": fact_id,
        "reverified_by": agent,
        "reverified_at": now.to_rfc3339(),
    });
    let req = corecrux_memory::fact_store::StoreFact {
        entity: format!("__reverify_receipts__::{fact_id}"),
        key: receipt_id.clone(),
        value: receipt_body.to_string(),
        source_receipt: Some(receipt_id.clone()),
        confidence: 1.0,
        private: false,
        horizon_class: Some(HorizonClass::Stable),
    };
    let mut store = ctx.fact_store.write().await;
    let _ = store.try_store(req).map_err(|err| JsonRpcError {
        code: crate::protocol::INTERNAL_ERROR,
        message: "reverify-receipt journal append failed".to_string(),
        data: Some(json!({"error": err.to_string()})),
    })?;

    Ok(json!({
        "content": [{
            "type": "text",
            "text": format!(
                "re-verified fact {fact_id} at {} (receipt {receipt_id}, class={REVERIFY_RECEIPT_CLASS})",
                now.to_rfc3339()
            ),
        }],
        "structuredContent": {
            "fact_id": fact_id,
            "receipt_id": receipt_id,
            "receipt_class": REVERIFY_RECEIPT_CLASS,
            "reverified_at": now.to_rfc3339(),
        }
    }))
}

// ── Helpers ─────────────────────────────────────────────────────────────

fn require_str<'a>(args: &'a Value, field: &str) -> Result<&'a str, JsonRpcError> {
    args.get(field).and_then(|v| v.as_str()).ok_or_else(|| JsonRpcError {
        code: INVALID_PARAMS,
        message: format!("missing required param: {field}"),
        data: Some(json!({"param": field, "required": true})),
    })
}

fn render_freshness_text(rows: &[Value]) -> String {
    if rows.is_empty() {
        return "no facts in freshness window".to_string();
    }
    rows.iter()
        .map(|r| {
            format!(
                "{:>5}h [{:8}] {:8} {}::{} (id={})",
                r["age_hours"].as_i64().unwrap_or(0),
                r["freshness"].as_str().unwrap_or("?"),
                r["horizon_class"].as_str().unwrap_or("?"),
                r["entity"].as_str().unwrap_or("?"),
                r["key"].as_str().unwrap_or("?"),
                r["fact_id"].as_str().unwrap_or("?"),
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Bridge between corecrux-memory's HorizonClass and
/// corecrux-projections::decay's HorizonClass (intentionally separate
/// to keep `decay` dependency-free). Both encodings carry the same
/// four variants; this conversion is total and infallible.
pub(crate) fn projection_class_of(c: HorizonClass) -> decay::HorizonClass {
    match c {
        HorizonClass::Volatile => decay::HorizonClass::Volatile,
        HorizonClass::Medium => decay::HorizonClass::Medium,
        HorizonClass::Stable => decay::HorizonClass::Stable,
        HorizonClass::None => decay::HorizonClass::None,
    }
}

/// Test-support hook: shared mutex serializing access to
/// `CORECRUXD_FEATURE_FRESHNESS` across this module's tests and the
/// cross-module envelope tests in `crate::dispatch::tests` that also
/// need to toggle the flag deterministically. Delegates to
/// [`crate::test_env_lock`] so every env-mutating test in this crate
/// shares one process-wide `tokio::sync::Mutex`.
#[cfg(test)]
pub(crate) fn tests_support_flag_lock() -> &'static tokio::sync::Mutex<()> {
    crate::test_env_lock()
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

    fn test_ctx() -> McpContext {
        McpContext::new_default("test-freshness")
    }

    fn agent_ctx(name: &str) -> McpContext {
        test_ctx().with_agent(AgentIdentity {
            name: name.to_string(),
            token_hash: [0u8; 32],
        })
    }

    fn flag_lock() -> &'static tokio::sync::Mutex<()> {
        super::tests_support_flag_lock()
    }

    #[tokio::test]
    async fn flag_off_returns_capability_denied() {
        let _g = flag_lock().lock().await;
        disable();
        let ctx = test_ctx();
        let err = handle_memory_freshness(&json!({}), &ctx).await.unwrap_err();
        assert_eq!(err.code, crate::dispatch::CAPABILITY_DENIED);
    }

    #[tokio::test]
    async fn memory_freshness_filters_reserved_prefix() {
        let _g = flag_lock().lock().await;
        enable();
        let ctx = test_ctx();
        handle_store_fact(&json!({"entity": "project-x", "key": "name", "value": "open"}), &ctx)
            .await
            .unwrap();
        handle_store_fact(&json!({"entity": "__ops::audit", "key": "k", "value": "x"}), &ctx)
            .await
            .unwrap();
        handle_store_fact(
            &json!({"entity": "__bootstrap__::pat:y", "key": "k", "value": "y"}),
            &ctx,
        )
        .await
        .unwrap();

        let res = handle_memory_freshness(&json!({"top_k": 50, "token_budget": 1000}), &ctx)
            .await
            .unwrap();
        let rows = res["structuredContent"]["rows"].as_array().unwrap();
        for r in rows {
            let ent = r["entity"].as_str().unwrap();
            assert!(!is_reserved_entity(ent), "leaked reserved entity {ent}");
        }
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["entity"], "project-x");
        disable();
    }

    #[tokio::test]
    async fn memory_set_horizon_requires_passport() {
        let _g = flag_lock().lock().await;
        enable();
        let ctx = test_ctx();
        // Store as anonymous first.
        let r = handle_store_fact(&json!({"entity": "p", "key": "k", "value": "v"}), &ctx)
            .await
            .unwrap();
        let txt = r["content"][0]["text"].as_str().unwrap();
        let fact_id = txt.split_whitespace().nth(2).unwrap();

        let err = handle_memory_set_horizon(&json!({"fact_id": fact_id, "horizon_class": "volatile"}), &ctx)
            .await
            .unwrap_err();
        assert_eq!(err.code, crate::dispatch::CAPABILITY_DENIED);
        disable();
    }

    #[tokio::test]
    async fn memory_set_horizon_with_passport_succeeds() {
        let _g = flag_lock().lock().await;
        enable();
        // Use a single shared context (anonymous-store + agent-call) so
        // both writes hit the same fact_store. McpContext::with_agent
        // shares the Arc<RwLock<FactStore>> with its parent.
        let ctx = test_ctx();
        let alice = ctx.with_agent(AgentIdentity {
            name: "alice".to_string(),
            token_hash: [0u8; 32],
        });
        let r = handle_store_fact(&json!({"entity": "p", "key": "k", "value": "v"}), &alice)
            .await
            .unwrap();
        let txt = r["content"][0]["text"].as_str().unwrap();
        let fact_id = txt.split_whitespace().nth(2).unwrap().to_string();

        let res = handle_memory_set_horizon(&json!({"fact_id": fact_id, "horizon_class": "volatile"}), &alice)
            .await
            .unwrap();
        assert_eq!(res["structuredContent"]["horizon_class"], "volatile");
        assert_eq!(res["structuredContent"]["ok"], true);
        disable();
    }

    #[tokio::test]
    async fn memory_set_horizon_invalid_class_rejected() {
        let _g = flag_lock().lock().await;
        enable();
        let alice = agent_ctx("alice");
        let r = handle_store_fact(&json!({"entity": "p", "key": "k", "value": "v"}), &alice)
            .await
            .unwrap();
        let txt = r["content"][0]["text"].as_str().unwrap();
        let fact_id = txt.split_whitespace().nth(2).unwrap().to_string();
        let err = handle_memory_set_horizon(&json!({"fact_id": fact_id, "horizon_class": "weekly"}), &alice)
            .await
            .unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
        disable();
    }

    #[tokio::test]
    async fn memory_reverify_requires_passport_and_emits_receipt() {
        let _g = flag_lock().lock().await;
        enable();
        let alice = agent_ctx("alice");
        let r = handle_store_fact(&json!({"entity": "p", "key": "k", "value": "v"}), &alice)
            .await
            .unwrap();
        let txt = r["content"][0]["text"].as_str().unwrap();
        let fact_id = txt.split_whitespace().nth(2).unwrap().to_string();

        // anonymous reverify -> denied
        let ctx = test_ctx();
        let err = handle_memory_reverify(&json!({"fact_id": fact_id}), &ctx)
            .await
            .unwrap_err();
        assert_eq!(err.code, crate::dispatch::CAPABILITY_DENIED);

        // passport reverify -> ok, emits receipt
        let res = handle_memory_reverify(&json!({"fact_id": fact_id}), &alice)
            .await
            .unwrap();
        assert_eq!(res["structuredContent"]["receipt_class"], REVERIFY_RECEIPT_CLASS);
        let recv_id = res["structuredContent"]["receipt_id"].as_str().unwrap().to_string();
        assert!(recv_id.starts_with("rev_"));

        // Reserved-prefix receipt was emitted under __reverify_receipts__::
        // so it's audit-discoverable but filtered from freshness listings.
        let res = handle_memory_freshness(&json!({"top_k": 50, "token_budget": 1000}), &alice)
            .await
            .unwrap();
        let rows = res["structuredContent"]["rows"].as_array().unwrap();
        // The original fact should still show up (and now be reverified).
        let row = rows.iter().find(|r| r["fact_id"] == fact_id.as_str()).unwrap();
        assert!(row["reverified_at"].is_string());
        disable();
    }

    #[tokio::test]
    async fn memory_reverify_anchor_resets_decay() {
        let _g = flag_lock().lock().await;
        enable();
        let alice = agent_ctx("alice");
        let r = handle_store_fact(&json!({"entity": "p", "key": "k", "value": "v"}), &alice)
            .await
            .unwrap();
        let txt = r["content"][0]["text"].as_str().unwrap();
        let fact_id = txt.split_whitespace().nth(2).unwrap().to_string();

        // Pin horizon volatile then reverify; decay reads should see fresh.
        handle_memory_set_horizon(&json!({"fact_id": fact_id, "horizon_class": "volatile"}), &alice)
            .await
            .unwrap();
        handle_memory_reverify(&json!({"fact_id": fact_id}), &alice)
            .await
            .unwrap();

        let res = handle_memory_freshness(&json!({"top_k": 50, "token_budget": 1000}), &alice)
            .await
            .unwrap();
        let rows = res["structuredContent"]["rows"].as_array().unwrap();
        let row = rows.iter().find(|r| r["fact_id"] == fact_id.as_str()).unwrap();
        assert_eq!(row["freshness"], "fresh");
        disable();
    }

    #[tokio::test]
    async fn memory_set_horizon_rejects_reserved_prefix() {
        let _g = flag_lock().lock().await;
        enable();
        let alice = agent_ctx("alice");
        // Build a reserved-prefix fact bypassing the freshness gate
        // (anonymous + scope::private_entity_for_agent style isn't
        // available for __ops::; just call handle_store_fact directly
        // since reserved is a runtime check on entity strings).
        let mut store = alice.fact_store.write().await;
        let f = store.store(corecrux_memory::fact_store::StoreFact {
            entity: "__ops::leak".to_string(),
            key: "k".to_string(),
            value: "v".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
        });
        let id = f.fact_id.clone();
        drop(store);

        let err = handle_memory_set_horizon(&json!({"fact_id": id, "horizon_class": "volatile"}), &alice)
            .await
            .unwrap_err();
        assert_eq!(err.code, crate::dispatch::CAPABILITY_DENIED);
        disable();
    }
}
