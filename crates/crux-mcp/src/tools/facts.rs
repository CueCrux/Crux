// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Fact store tool handlers: `store_fact`, `query_facts`, `delete_fact`,
//! `list_entities`, `get_bootstrap`.

use std::collections::BTreeSet;

use serde_json::{json, Value};

use chrono::Utc;

use crate::dispatch::McpContext;
use crate::protocol::{JsonRpcError, INTERNAL_ERROR, INVALID_PARAMS};
use crate::scope;
use corecrux_memory::fact_store::{Fact, FactQuery, HorizonClass, StoreFact};
use corecrux_projections::decay;

/// Parse an operator's free-text `freshness_horizon:` line into a
/// [`HorizonClass`]. Conservative by design: anything unrecognised maps
/// to [`HorizonClass::None`] (never decays) rather than guessing.
///
/// Rules (first match wins, case-insensitive):
/// - contains "hour" -> volatile
/// - "stable"/"frozen"/"immutable"/"historical" -> stable
/// - "architect" -> stable
/// - "year" -> stable
/// - "month" -> medium
/// - "week" -> medium
/// - "day"/"days" preceded by a number <= 2 -> volatile, else -> medium
/// - anything else -> none
///
/// Note: M2/M3 (`HorizonClass::default_for_entity`) still applies when
/// neither this nor an explicit `horizon_class` is supplied — this parser
/// only runs when `freshness_horizon` text is provided and `horizon_class`
/// is absent.
pub(crate) fn parse_freshness_horizon(text: &str) -> HorizonClass {
    let lower = text.to_ascii_lowercase();

    if lower.contains("hour") {
        return HorizonClass::Volatile;
    }
    if lower.contains("stable")
        || lower.contains("frozen")
        || lower.contains("immutable")
        || lower.contains("historical")
        || lower.contains("architect")
        || lower.contains("year")
    {
        return HorizonClass::Stable;
    }
    if lower.contains("month") {
        return HorizonClass::Medium;
    }
    if lower.contains("week") {
        return HorizonClass::Medium;
    }
    if lower.contains("day") {
        // Find a number adjacent to a "day"/"days" mention; <= 2 days is
        // volatile, otherwise it reads as a roughly-weekly cadence.
        if let Some(n) = nearest_day_count(&lower) {
            return if n <= 2 {
                HorizonClass::Volatile
            } else {
                HorizonClass::Medium
            };
        }
        // "day" without a parseable count -> medium (conservative,
        // doesn't claim sub-day volatility).
        return HorizonClass::Medium;
    }
    HorizonClass::None
}

/// Extract the integer that qualifies a "day"/"days" mention, if any.
/// Returns the first standalone number found in the text (operator lines
/// like "re-verify before relying after 3 days" put the count before the
/// unit). `None` when no number is present.
fn nearest_day_count(lower: &str) -> Option<u64> {
    lower
        .split(|c: char| !c.is_ascii_digit())
        .filter(|tok| !tok.is_empty())
        .find_map(|tok| tok.parse::<u64>().ok())
}

/// `store_fact` — persist a key-value fact against an entity.
///
/// If `private: true` and the caller has an authenticated agent identity, the
/// entity is automatically prefixed with `__agent::{agent_name}::` to scope
/// visibility.
pub async fn handle_store_fact(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let entity_raw = require_str(args, "entity")?;
    let key = require_str(args, "key")?;
    let value = require_str(args, "value")?;
    let source_receipt = args
        .get("source_receipt")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let confidence = args.get("confidence").and_then(|v| v.as_f64()).unwrap_or(1.0) as f32;
    let private = args.get("private").and_then(|v| v.as_bool()).unwrap_or(false);
    let agent_name = scope::agent_name(ctx.agent.as_ref());

    // Freshness horizon (M4): an explicit `horizon_class` always wins; if
    // absent, parse the operator's free-text `freshness_horizon` line; if
    // both are absent leave `None` so the entity-prefix default (M2/M3)
    // applies — strict backwards-compat for callers that send neither.
    let horizon_class: Option<HorizonClass> = match args.get("horizon_class").and_then(|v| v.as_str()) {
        Some(s) => Some(HorizonClass::parse(s).ok_or_else(|| JsonRpcError {
            code: INVALID_PARAMS,
            message: format!("invalid horizon_class: {s}"),
            data: Some(json!({
                "param": "horizon_class",
                "allowed": ["volatile", "medium", "stable", "none"],
            })),
        })?),
        None => args
            .get("freshness_horizon")
            .and_then(|v| v.as_str())
            .map(parse_freshness_horizon),
    };

    let entity = match (private, agent_name) {
        (true, Some(agent_name)) => scope::private_entity_for_agent(agent_name, entity_raw),
        (true, None) => {
            return Err(JsonRpcError {
                code: INVALID_PARAMS,
                message: "private facts require an authenticated agent identity".to_string(),
                data: Some(json!({"param": "private", "requires_agent_identity": true})),
            });
        }
        (false, _) => entity_raw.to_string(),
    };

    // Durable authorship (agent-passport M1). FLAG-GATED:
    // * Flag OFF (default): `actor = None` — byte-for-byte the pre-M1 path.
    // * Flag ON: resolve the agent token-name (`anthropic`, `openai`, …) to a
    //   passport_id (`claude-work`, `codex-work`, …) via the context map. If
    //   the name is unmapped we fall back to the RAW agent name so a flag-ON
    //   write is NEVER anonymous (QC.3); only a truly unauthenticated caller
    //   (no agent identity) leaves `actor = None`.
    let actor: Option<String> = if ctx.agent_passports_enabled {
        agent_name.map(|name| {
            crate::agent_passport::resolve_agent_passport(name, &ctx.agent_passport_map)
                .unwrap_or_else(|| name.to_string())
        })
    } else {
        None
    };

    let req = StoreFact {
        entity,
        key: key.to_string(),
        value: value.to_string(),
        source_receipt,
        confidence,
        private,
        horizon_class,
        actor,
    };

    let mut store = ctx.fact_store.write().await;
    // M3.5 NOTE (updated by agent-passport M1): the agent→passport mapping
    // now exists behind `CORECRUXD_AGENT_PASSPORTS` — see
    // `crate::agent_passport`. When that flag is on, the resolved passport_id
    // is stamped onto the fact as `actor` above (attribution only). We still
    // deliberately do NOT call
    // `category_enforce::check_passport_can_write_entity` here: enforcement
    // (403-ing a passport that may not write a given tenant-category entity)
    // is tracked in M5 and stays gated behind its own switch so M1 can ship
    // attribution without risking blocking operator MCP writes.
    let fact = store.try_store(req).map_err(|err| JsonRpcError {
        code: INTERNAL_ERROR,
        message: "fact journal append failed".to_string(),
        data: Some(json!({"error": err.to_string()})),
    })?;

    // M6 cross-entity supersession: if `supersedes` named existing fact_ids,
    // EXPLICITLY retire each one (reversible soft-state) now that the new
    // fact has a stable id. Every referenced fact MUST exist AND be visible
    // to the caller (T.1 no cross-tenant retirement; T.3 passport-attributed
    // write). We do NOT silently skip bad refs — we collect them and reject
    // the whole batch with a clear error so the caller knows what failed.
    // The new fact itself is already persisted; the supersession marks are
    // additive soft-state, so a rejection here leaves the store consistent
    // (target facts unchanged) and the new fact simply doesn't retire
    // anything.
    let supersedes_refs: Vec<String> = match args.get("supersedes") {
        Some(Value::Array(items)) => {
            let mut refs = Vec::with_capacity(items.len());
            for item in items {
                match item.as_str() {
                    Some(s) => refs.push(s.to_string()),
                    None => {
                        return Err(JsonRpcError {
                            code: INVALID_PARAMS,
                            message: "supersedes must be an array of fact_id strings".to_string(),
                            data: Some(json!({"param": "supersedes"})),
                        });
                    }
                }
            }
            refs
        }
        Some(Value::Null) | None => Vec::new(),
        Some(_) => {
            return Err(JsonRpcError {
                code: INVALID_PARAMS,
                message: "supersedes must be an array of fact_id strings".to_string(),
                data: Some(json!({"param": "supersedes"})),
            });
        }
    };

    let mut superseded_ok: Vec<String> = Vec::new();
    if !supersedes_refs.is_empty() {
        // First pass: validate every ref is visible + exists. Reject the
        // whole batch before mutating so a single bad ref can't leave a
        // partial retirement.
        let mut bad: Vec<String> = Vec::new();
        for r in &supersedes_refs {
            if r == &fact.fact_id {
                bad.push(r.clone());
                continue;
            }
            match store.get(r) {
                Some(target) if scope::fact_visible_to_agent(target, agent_name) => {}
                _ => bad.push(r.clone()),
            }
        }
        if !bad.is_empty() {
            return Err(JsonRpcError {
                code: INVALID_PARAMS,
                message: "one or more supersedes fact_ids do not exist or are not visible to you".to_string(),
                data: Some(json!({"param": "supersedes", "invalid_refs": bad})),
            });
        }
        // Second pass: all refs validated — apply the retirement.
        for r in &supersedes_refs {
            if store.mark_superseded(r, &fact.fact_id) {
                superseded_ok.push(r.clone());
            }
        }
    }

    let display_entity = scope::visible_entity_for_agent(&fact, agent_name).unwrap_or_else(|| fact.entity.clone());

    let supersedes_msg = match &fact.supersedes {
        Some(prev) => format!(", supersedes={prev}, version={}", fact.version),
        None => format!(", version={}", fact.version),
    };
    let retired_msg = if superseded_ok.is_empty() {
        String::new()
    } else {
        format!(", retired={}", superseded_ok.join(","))
    };

    Ok(json!({
        "content": [{
            "type": "text",
            "text": format!(
                "stored fact {} (entity={}, key={}{}{})",
                fact.fact_id, display_entity, fact.key, supersedes_msg, retired_msg
            )
        }],
        "structuredContent": {
            "fact_id": fact.fact_id,
            "entity": display_entity,
            "key": fact.key,
            "version": fact.version,
            "superseded_fact_ids": superseded_ok,
        }
    }))
}

/// `fact_history` — return the full version chain for a given (entity, key) pair.
pub async fn handle_fact_history(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let entity = require_str(args, "entity")?;
    let key = require_str(args, "key")?;
    let agent_name = scope::agent_name(ctx.agent.as_ref());

    let store = ctx.fact_store.read().await;
    let mut history: Vec<&Fact> = store
        .all_facts()
        .filter(|fact| fact.key == key)
        .filter(|fact| scope::entity_matches_for_agent(fact, entity, agent_name))
        .filter(|fact| scope::fact_visible_to_agent(fact, agent_name))
        .collect();
    history.sort_by_key(|fact| fact.version);

    if history.is_empty() {
        return Ok(json!({
            "content": [{ "type": "text", "text": format!("no history for entity={entity}, key={key}") }]
        }));
    }

    let text = history
        .iter()
        .map(|f| {
            let status = if f.deleted { " [deleted]" } else { "" };
            let sup = f.supersedes.as_deref().unwrap_or("-");
            // M3: attribution surfaced on read. "-" for legacy/flag-off writes.
            let actor = f.actor.as_deref().unwrap_or("-");
            let display_entity = scope::visible_entity_for_agent(f, agent_name).unwrap_or_else(|| f.entity.clone());
            format!(
                "v{}: [{}] {} = {} (confidence={:.2}, stored_at={}, supersedes={}, actor={}){}",
                f.version, display_entity, f.fact_id, f.value, f.confidence, f.stored_at, sup, actor, status
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    Ok(json!({
        "content": [{ "type": "text", "text": text }]
    }))
}

/// `query_facts` — search the fact store by keyword, entity, or both.
///
/// Results are filtered to exclude private facts owned by other agents.
pub async fn handle_query_facts(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let query = args.get("query").and_then(|v| v.as_str()).map(|s| s.to_string());
    let entity = args.get("entity").and_then(|v| v.as_str()).map(|s| s.to_string());
    let top_k = args.get("top_k").and_then(|v| v.as_u64()).unwrap_or(10) as usize;
    let token_budget = args.get("token_budget").and_then(|v| v.as_u64()).map(|v| v as usize);
    // M6: superseded (cross-entity retired) facts are hidden from recall by
    // default; opt back in with `include_superseded: true`.
    let include_superseded = args
        .get("include_superseded")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let agent_name = scope::agent_name(ctx.agent.as_ref());

    let q = FactQuery {
        query,
        entity,
        entity_prefix: None,
        top_k,
        token_budget,
    };

    let store = ctx.fact_store.read().await;
    let visible = query_visible_facts_opts(&store, &q, agent_name, include_superseded);

    if visible.is_empty() {
        return Ok(json!({
            "content": [{ "type": "text", "text": "no facts found" }]
        }));
    }

    // M4: compute freshness at recall time using the SAME decay logic as
    // `memory_freshness`. M5: results are now ranked by effective_confidence
    // (see `query_visible_facts`); here we surface both the STORED
    // `confidence` (unchanged) and the recall-time `effective_confidence`
    // so the demotion is visible/explainable to the caller.
    let policy = decay::DecayPolicy::from_env();
    let now = Utc::now();

    let mut lines: Vec<String> = Vec::with_capacity(visible.len());
    let mut rows: Vec<Value> = Vec::with_capacity(visible.len());
    for f in &visible {
        let entity = scope::visible_entity_for_agent(f, agent_name).unwrap_or_else(|| f.entity.clone());
        let class = crate::tools::freshness::projection_class_of(f.horizon_class);
        let fresh = decay::apply_at_chrono(class, f.stored_at, f.reverified_at, now, policy);
        let effective_confidence = decay::effective_confidence(f.confidence as f64, fresh);
        let anchor = f.reverified_at.unwrap_or(f.stored_at);
        let age_hours = (now - anchor).num_hours().max(0);
        lines.push(format!(
            "[{}] {} = {} (confidence={:.2}, effective_confidence={:.2}, freshness={}, age_hours={})",
            entity,
            f.key,
            f.value,
            f.confidence,
            effective_confidence,
            fresh.as_str(),
            age_hours
        ));
        rows.push(json!({
            "fact_id": f.fact_id,
            "entity": entity,
            "key": f.key,
            "value": f.value,
            "confidence": f.confidence,
            "effective_confidence": effective_confidence,
            "horizon_class": f.horizon_class.as_str(),
            "freshness": fresh.as_str(),
            "age_hours": age_hours,
            // M6: present (non-null) only when this fact has been retired
            // and the caller opted in via include_superseded.
            "superseded_by": f.superseded_by,
            // M3: attribution surfaced on read. Null for legacy/flag-off
            // writes; the stored actor (never inferred or backfilled).
            "actor": f.actor,
        }));
    }

    Ok(json!({
        "content": [{ "type": "text", "text": lines.join("\n") }],
        "structuredContent": { "rows": rows }
    }))
}

/// `delete_fact` — soft-delete a fact by its ID.
pub async fn handle_delete_fact(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let fact_id = require_str(args, "fact_id")?;
    let agent_name = scope::agent_name(ctx.agent.as_ref());

    let mut store = ctx.fact_store.write().await;
    let deleted = store
        .get(fact_id)
        .is_some_and(|fact| scope::fact_visible_to_agent(fact, agent_name))
        && store.try_delete(fact_id).map_err(|err| JsonRpcError {
            code: INTERNAL_ERROR,
            message: "fact journal append failed".to_string(),
            data: Some(json!({"error": err.to_string()})),
        })?;

    if deleted {
        Ok(json!({
            "content": [{
                "type": "text",
                "text": format!("deleted fact {fact_id}")
            }]
        }))
    } else {
        Ok(json!({
            "content": [{
                "type": "text",
                "text": format!("fact not found: {fact_id}")
            }],
            "isError": false
        }))
    }
}

/// `list_entities` — discover all entity names in the fact store.
pub async fn handle_list_entities(_args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let store = ctx.fact_store.read().await;
    let agent_name = scope::agent_name(ctx.agent.as_ref());
    let entities: Vec<String> = store
        .all_facts()
        .filter(|fact| !fact.deleted)
        .filter_map(|fact| scope::visible_entity_for_agent(fact, agent_name))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();

    if entities.is_empty() {
        return Ok(json!({
            "content": [{ "type": "text", "text": "no entities found" }]
        }));
    }

    let text = entities.join("\n");
    Ok(json!({
        "content": [{
            "type": "text",
            "text": text
        }]
    }))
}

/// Crate-internal alias of [`query_visible_facts`] reused by
/// [`crate::envelope`] so the envelope builder applies exactly the same
/// visibility + budget rules as the real `query_facts` handler (no extra
/// surface, no chance of leaking facts the caller couldn't query
/// directly).
pub(crate) fn envelope_query_visible_facts(
    store: &corecrux_memory::FactStore,
    q: &FactQuery,
    agent_name: Option<&str>,
) -> Vec<Fact> {
    // Envelope mirrors query_facts' DEFAULT recall surface: superseded
    // (cross-entity retired) facts are excluded.
    query_visible_facts(store, q, agent_name)
}

fn query_visible_facts(store: &corecrux_memory::FactStore, q: &FactQuery, agent_name: Option<&str>) -> Vec<Fact> {
    query_visible_facts_opts(store, q, agent_name, false)
}

/// As [`query_visible_facts`] but with an explicit `include_superseded`
/// toggle (M6). When `false` (the default recall behaviour), facts whose
/// `superseded_by` marker is set are excluded — they've been explicitly
/// retired by a newer fact (possibly under a different entity).
fn query_visible_facts_opts(
    store: &corecrux_memory::FactStore,
    q: &FactQuery,
    agent_name: Option<&str>,
    include_superseded: bool,
) -> Vec<Fact> {
    let mut results: Vec<&Fact> = store
        .all_facts()
        .filter(|fact| !fact.deleted)
        .filter(|fact| include_superseded || fact.superseded_by.is_none())
        .filter(|fact| scope::fact_visible_to_agent(fact, agent_name))
        .filter(|fact| {
            q.entity_prefix
                .as_ref()
                .is_none_or(|prefix| scope::entity_prefix_matches_for_agent(fact, prefix, agent_name))
        })
        .filter(|fact| {
            q.entity
                .as_ref()
                .is_none_or(|entity| scope::entity_matches_for_agent(fact, entity, agent_name))
        })
        .filter(|fact| match &q.query {
            Some(query) => fact_matches_query(fact, query, agent_name),
            None => true,
        })
        .collect();

    // M5: rank by a time-decayed EFFECTIVE confidence rather than the raw
    // stored confidence, so a stale fact sinks below an equally-confident
    // fresh one. The STORED confidence is never mutated — this is purely a
    // sort key, computed at recall time from the same decay logic
    // (`apply_at_chrono` + `projection_class_of`) used elsewhere. Tie-break
    // on `stored_at` desc so the most-recent fact wins on equal effective
    // confidence.
    let policy = decay::DecayPolicy::from_env();
    let now = Utc::now();
    let eff = |fact: &Fact| -> f64 {
        let class = crate::tools::freshness::projection_class_of(fact.horizon_class);
        let fresh = decay::apply_at_chrono(class, fact.stored_at, fact.reverified_at, now, policy);
        decay::effective_confidence(fact.confidence as f64, fresh)
    };
    results.sort_by(|left, right| {
        eff(right)
            .partial_cmp(&eff(left))
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| right.stored_at.cmp(&left.stored_at))
    });

    if let Some(budget) = q.token_budget {
        let mut used = 0usize;
        let mut selected = Vec::new();
        for fact in results {
            if used + fact.tokens > budget && !selected.is_empty() {
                break;
            }
            used += fact.tokens;
            selected.push(fact.clone());
            if used >= budget {
                break;
            }
        }
        return selected;
    }

    results.truncate(q.top_k);
    results.into_iter().cloned().collect()
}

fn fact_matches_query(fact: &Fact, query: &str, agent_name: Option<&str>) -> bool {
    let query_lower = query.to_lowercase();
    let terms: Vec<&str> = query_lower.split_whitespace().collect();
    let value_lower = fact.value.to_lowercase();
    let key_lower = fact.key.to_lowercase();
    let entity_lower = scope::visible_entity_for_agent(fact, agent_name)
        .unwrap_or_else(|| fact.entity.clone())
        .to_lowercase();

    terms
        .iter()
        .any(|term| value_lower.contains(term) || key_lower.contains(term) || entity_lower.contains(term))
}

/// Bootstrap entity prefix.
const BOOTSTRAP_PREFIX: &str = "__bootstrap__::";

/// `get_bootstrap` — query bootstrap knowledge at runtime.
///
/// Accepts an optional `topic` parameter ("patterns", "docs", "errors") to
/// filter bootstrap facts by sub-entity, plus an optional `query` term to
/// narrow the result set.
pub async fn handle_get_bootstrap(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let topic = args.get("topic").and_then(|v| v.as_str()).map(|s| s.to_string());
    let query = args.get("query").and_then(|v| v.as_str()).map(|s| s.to_string());

    let prefix = match &topic {
        Some(t) => format!("{BOOTSTRAP_PREFIX}{}:", normalize_bootstrap_topic(t)),
        None => BOOTSTRAP_PREFIX.to_string(),
    };

    let q = FactQuery {
        query,
        entity: None,
        entity_prefix: Some(prefix),
        top_k: 100,
        token_budget: None,
    };

    let store = ctx.fact_store.read().await;
    let result = store.query(&q);

    if result.facts.is_empty() {
        let msg = match &topic {
            Some(t) => format!("no bootstrap knowledge for topic '{t}'"),
            None => "no bootstrap knowledge found".to_string(),
        };
        return Ok(json!({
            "content": [{ "type": "text", "text": msg }]
        }));
    }

    let text = result
        .facts
        .iter()
        .map(|f| format!("[{}] {} = {}", f.entity, f.key, f.value))
        .collect::<Vec<_>>()
        .join("\n");

    Ok(json!({
        "content": [{ "type": "text", "text": text }]
    }))
}

fn normalize_bootstrap_topic(topic: &str) -> String {
    let trimmed = topic.trim();
    match trimmed.to_ascii_lowercase().as_str() {
        "doc" | "docs" => "doc".to_string(),
        "pattern" | "patterns" => "pattern".to_string(),
        "error" | "errors" | "resolution" | "resolutions" => "resolution".to_string(),
        "tool" | "tool-output" | "tool-outputs" => "tool-output".to_string(),
        _ => trimmed.to_string(),
    }
}

/// Extract a required string parameter or return an INVALID_PARAMS error.
fn require_str<'a>(args: &'a Value, field: &str) -> Result<&'a str, JsonRpcError> {
    args.get(field).and_then(|v| v.as_str()).ok_or_else(|| JsonRpcError {
        code: INVALID_PARAMS,
        message: format!("missing required param: {field}"),
        data: Some(json!({"param": field, "required": true})),
    })
}

// ── Tests ────────────────────────────────────────────���────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::agent::AgentIdentity;
    use crate::dispatch::McpContext;

    fn test_ctx() -> McpContext {
        McpContext::new_default("test-node")
    }

    #[tokio::test]
    async fn store_fact_basic() {
        let ctx = test_ctx();
        let result = handle_store_fact(&json!({"entity": "proj", "key": "name", "value": "CueCrux"}), &ctx)
            .await
            .unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.starts_with("stored fact f_"));
        assert!(text.contains("entity=proj"));
    }

    #[tokio::test]
    async fn store_fact_missing_entity() {
        let ctx = test_ctx();
        let err = handle_store_fact(&json!({"key": "k", "value": "v"}), &ctx)
            .await
            .unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
    }

    // ── agent-passport M1: actor attribution ────────────────────────────

    /// Read the persisted `actor` for the fact returned by a store_fact call.
    async fn stored_actor(ctx: &McpContext, result: &Value) -> Option<String> {
        let fid = result["structuredContent"]["fact_id"].as_str().unwrap();
        let store = ctx.fact_store.read().await;
        store.get(fid).and_then(|f| f.actor.clone())
    }

    #[tokio::test]
    async fn store_fact_flag_on_anthropic_maps_to_claude_work() {
        // Flag ON + built-in default map + anthropic-named agent → claude-work.
        let map = crate::agent_passport::AgentPassportMap::builtin_default();
        let ctx = test_ctx().with_agent_passports(true, map).with_agent(AgentIdentity {
            name: "anthropic".to_string(),
            token_hash: [0u8; 32],
        });
        let result = handle_store_fact(&json!({"entity": "proj", "key": "k", "value": "v"}), &ctx)
            .await
            .unwrap();
        assert_eq!(stored_actor(&ctx, &result).await, Some("claude-work".to_string()));
    }

    #[tokio::test]
    async fn store_fact_flag_on_openai_maps_to_codex_work() {
        let map = crate::agent_passport::AgentPassportMap::builtin_default();
        let ctx = test_ctx().with_agent_passports(true, map).with_agent(AgentIdentity {
            name: "openai".to_string(),
            token_hash: [2u8; 32],
        });
        let result = handle_store_fact(&json!({"entity": "proj", "key": "k", "value": "v"}), &ctx)
            .await
            .unwrap();
        assert_eq!(stored_actor(&ctx, &result).await, Some("codex-work".to_string()));
    }

    #[tokio::test]
    async fn store_fact_flag_on_unmapped_agent_falls_back_to_raw_name() {
        // QC.3: flag-ON writes are never anonymous — an unmapped name stamps
        // the raw agent name rather than None.
        let map = crate::agent_passport::AgentPassportMap::builtin_default();
        let ctx = test_ctx().with_agent_passports(true, map).with_agent(AgentIdentity {
            name: "windows-host".to_string(),
            token_hash: [3u8; 32],
        });
        let result = handle_store_fact(&json!({"entity": "proj", "key": "k", "value": "v"}), &ctx)
            .await
            .unwrap();
        assert_eq!(stored_actor(&ctx, &result).await, Some("windows-host".to_string()));
    }

    #[tokio::test]
    async fn store_fact_flag_off_records_no_actor() {
        // Proves no behaviour change: with the flag OFF, the SAME anthropic
        // agent records actor = None (byte-for-byte the pre-M1 path).
        let ctx = test_ctx().with_agent(AgentIdentity {
            name: "anthropic".to_string(),
            token_hash: [0u8; 32],
        });
        assert!(!ctx.agent_passports_enabled, "flag must default OFF");
        let result = handle_store_fact(&json!({"entity": "proj", "key": "k", "value": "v"}), &ctx)
            .await
            .unwrap();
        assert_eq!(stored_actor(&ctx, &result).await, None);
    }

    // ── agent-passport M3: attribution surfaced on read ────────────────

    /// Two distinct actors (claude-work, codex-work) write facts via the
    /// flag-ON path; a third writes with the flag OFF (legacy actor=None).
    /// `query_facts` rows must carry the correct `actor` per fact, and the
    /// legacy fact must show `actor: null`. Shared visibility is intact —
    /// all three non-private facts are visible from a single shared read.
    #[tokio::test]
    async fn query_facts_rows_carry_actor_per_writer_and_null_for_legacy() {
        let map = crate::agent_passport::AgentPassportMap::builtin_default();

        // Shared base context (single fact store, Arc-shared by every
        // derived context below). `base` stays valid for the shared read.
        let base = test_ctx();

        // claude-work writes a decision (flag ON, anthropic → claude-work).
        let claude = base
            .with_agent(AgentIdentity { name: "anthropic".to_string(), token_hash: [0u8; 32] })
            .with_agent_passports(true, map.clone());
        handle_store_fact(
            &json!({"entity": "execplan:x", "key": "decision:topic", "value": "needle-claude"}),
            &claude,
        )
        .await
        .unwrap();

        // codex-work writes a bench fact (flag ON, openai → codex-work), same
        // shared (non-private) pool / same underlying fact store.
        let codex = base
            .with_agent(AgentIdentity { name: "openai".to_string(), token_hash: [2u8; 32] })
            .with_agent_passports(true, map.clone());
        handle_store_fact(
            &json!({"entity": "bench:y", "key": "metric", "value": "needle-codex"}),
            &codex,
        )
        .await
        .unwrap();

        // Legacy / flag-OFF write — actor must be null on read.
        let legacy = base.with_agent(AgentIdentity { name: "legacy".to_string(), token_hash: [9u8; 32] });
        assert!(!legacy.agent_passports_enabled, "legacy write must be flag-OFF");
        handle_store_fact(
            &json!({"entity": "legacy:z", "key": "k", "value": "needle-legacy"}),
            &legacy,
        )
        .await
        .unwrap();

        // Single shared read sees all three (shared visibility intact).
        let res = handle_query_facts(&json!({"query": "needle", "token_budget": 500}), &base)
            .await
            .unwrap();
        let rows = res["structuredContent"]["rows"].as_array().unwrap();

        let actor_for = |value: &str| -> Value {
            rows.iter()
                .find(|r| r["value"].as_str() == Some(value))
                .unwrap_or_else(|| panic!("row for {value} missing — shared visibility regressed"))
                ["actor"]
                .clone()
        };

        assert_eq!(actor_for("needle-claude"), json!("claude-work"));
        assert_eq!(actor_for("needle-codex"), json!("codex-work"));
        // Legacy fact: actor serialized as JSON null.
        assert_eq!(actor_for("needle-legacy"), Value::Null);

        // Shared visibility re-confirmed: all three present from one read.
        assert_eq!(rows.len(), 3);
    }

    #[tokio::test]
    async fn fact_history_text_includes_actor() {
        let map = crate::agent_passport::AgentPassportMap::builtin_default();
        let claude = test_ctx()
            .with_agent_passports(true, map)
            .with_agent(AgentIdentity { name: "anthropic".to_string(), token_hash: [0u8; 32] });
        handle_store_fact(&json!({"entity": "execplan:h", "key": "decision:x", "value": "v1"}), &claude)
            .await
            .unwrap();

        let res = handle_fact_history(&json!({"entity": "execplan:h", "key": "decision:x"}), &claude)
            .await
            .unwrap();
        let text = res["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("actor=claude-work"), "history line should attribute the writer: {text}");

        // Legacy / flag-off fact shows actor=-.
        let legacy = test_ctx();
        handle_store_fact(&json!({"entity": "legacy:h", "key": "k", "value": "v"}), &legacy)
            .await
            .unwrap();
        let res = handle_fact_history(&json!({"entity": "legacy:h", "key": "k"}), &legacy)
            .await
            .unwrap();
        let text = res["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("actor=-"), "legacy history line shows no actor: {text}");
    }

    #[tokio::test]
    async fn store_and_query_roundtrip() {
        let ctx = test_ctx();
        handle_store_fact(&json!({"entity": "alpha", "key": "status", "value": "active"}), &ctx)
            .await
            .unwrap();

        let result = handle_query_facts(&json!({"query": "active", "entity": "alpha"}), &ctx)
            .await
            .unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("active"));
    }

    #[tokio::test]
    async fn query_facts_empty_store() {
        let ctx = test_ctx();
        let result = handle_query_facts(&json!({}), &ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert_eq!(text, "no facts found");
    }

    #[tokio::test]
    async fn private_fact_scoped_to_agent() {
        let ctx = test_ctx();
        let agent_ctx = ctx.with_agent(AgentIdentity {
            name: "alice".to_string(),
            token_hash: [0u8; 32],
        });

        // Store a private fact as alice.
        handle_store_fact(
            &json!({"entity": "notes", "key": "secret", "value": "hidden", "private": true}),
            &agent_ctx,
        )
        .await
        .unwrap();

        // alice can see it.
        let result = handle_query_facts(&json!({"query": "hidden"}), &agent_ctx)
            .await
            .unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("hidden"));
        assert!(text.contains("[notes]"));

        // Bob cannot see it.
        let bob_ctx = ctx.with_agent(AgentIdentity {
            name: "bob".to_string(),
            token_hash: [1u8; 32],
        });
        let result = handle_query_facts(&json!({"query": "hidden"}), &bob_ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert_eq!(text, "no facts found");
    }

    #[tokio::test]
    async fn private_fact_without_agent_is_rejected() {
        let ctx = test_ctx(); // no agent
        let err = handle_store_fact(
            &json!({"entity": "notes", "key": "k", "value": "v", "private": true}),
            &ctx,
        )
        .await
        .unwrap_err();

        assert_eq!(err.code, INVALID_PARAMS);
        assert_eq!(err.data.unwrap()["requires_agent_identity"], true);
    }

    // ── delete_fact tests ───────────────────────────────────────────

    #[tokio::test]
    async fn delete_fact_existing() {
        let ctx = test_ctx();
        let result = handle_store_fact(&json!({"entity": "e", "key": "k", "value": "v"}), &ctx)
            .await
            .unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        // Extract fact_id from "stored fact f_..."
        let fact_id = text.split_whitespace().nth(2).unwrap();

        let result = handle_delete_fact(&json!({"fact_id": fact_id}), &ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("deleted fact"));
    }

    #[tokio::test]
    async fn delete_fact_nonexistent() {
        let ctx = test_ctx();
        let result = handle_delete_fact(&json!({"fact_id": "f_nope"}), &ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("fact not found"));
    }

    #[tokio::test]
    async fn delete_fact_missing_param() {
        let ctx = test_ctx();
        let err = handle_delete_fact(&json!({}), &ctx).await.unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
        assert!(err.data.is_some());
        assert_eq!(err.data.unwrap()["param"], "fact_id");
    }

    // ── list_entities tests ─────────────────────────────────────────

    #[tokio::test]
    async fn list_entities_empty_store() {
        let ctx = test_ctx();
        let result = handle_list_entities(&json!({}), &ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert_eq!(text, "no entities found");
    }

    #[tokio::test]
    async fn list_entities_returns_sorted_unique() {
        let ctx = test_ctx();
        handle_store_fact(&json!({"entity": "beta", "key": "k", "value": "v"}), &ctx)
            .await
            .unwrap();
        handle_store_fact(&json!({"entity": "alpha", "key": "k", "value": "v"}), &ctx)
            .await
            .unwrap();
        handle_store_fact(&json!({"entity": "alpha", "key": "k2", "value": "v2"}), &ctx)
            .await
            .unwrap();

        let result = handle_list_entities(&json!({}), &ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines, vec!["alpha", "beta"]);
    }

    #[tokio::test]
    async fn list_entities_hides_other_agents_private_entities() {
        let ctx = test_ctx();
        let alice_ctx = ctx.with_agent(AgentIdentity {
            name: "alice".to_string(),
            token_hash: [0u8; 32],
        });
        let bob_ctx = ctx.with_agent(AgentIdentity {
            name: "bob".to_string(),
            token_hash: [1u8; 32],
        });

        handle_store_fact(
            &json!({"entity": "notes", "key": "secret", "value": "hidden", "private": true}),
            &alice_ctx,
        )
        .await
        .unwrap();

        let alice = handle_list_entities(&json!({}), &alice_ctx).await.unwrap();
        assert_eq!(alice["content"][0]["text"].as_str().unwrap(), "notes");

        let bob = handle_list_entities(&json!({}), &bob_ctx).await.unwrap();
        assert_eq!(bob["content"][0]["text"].as_str().unwrap(), "no entities found");
    }

    // ── get_bootstrap tests ─────────────────────────────────────────

    #[tokio::test]
    async fn get_bootstrap_empty() {
        let ctx = test_ctx();
        let result = handle_get_bootstrap(&json!({}), &ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("no bootstrap knowledge found"));
    }

    #[tokio::test]
    async fn get_bootstrap_with_topic_empty() {
        let ctx = test_ctx();
        let result = handle_get_bootstrap(&json!({"topic": "patterns"}), &ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("no bootstrap knowledge for topic 'patterns'"));
    }

    #[tokio::test]
    async fn get_bootstrap_returns_matching_facts() {
        let ctx = test_ctx();
        // Store bootstrap facts.
        handle_store_fact(
            &json!({"entity": "__bootstrap__::pattern:retry", "key": "Retry Pattern", "value": "exponential backoff"}),
            &ctx,
        )
        .await
        .unwrap();
        handle_store_fact(
            &json!({"entity": "__bootstrap__::resolution:oom", "key": "OOM Recovery", "value": "increase memory"}),
            &ctx,
        )
        .await
        .unwrap();
        handle_store_fact(
            &json!({"entity": "__bootstrap__::doc:onboarding", "key": "Human-Assisted Integration", "value": "share the HTTP and MCP endpoints with the operator"}),
            &ctx,
        )
        .await
        .unwrap();
        // Non-bootstrap fact should not appear.
        handle_store_fact(&json!({"entity": "project", "key": "name", "value": "CueCrux"}), &ctx)
            .await
            .unwrap();

        // Query all bootstrap.
        let result = handle_get_bootstrap(&json!({}), &ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("exponential backoff"));
        assert!(text.contains("increase memory"));
        assert!(!text.contains("CueCrux"));

        // Query filtered by topic.
        let result = handle_get_bootstrap(&json!({"topic": "patterns"}), &ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("exponential backoff"));
        assert!(!text.contains("increase memory"));

        let result = handle_get_bootstrap(&json!({"topic": "docs", "query": "Human-Assisted"}), &ctx)
            .await
            .unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("Human-Assisted Integration"));
        assert!(!text.contains("exponential backoff"));
    }

    // ── structured error data test ──────────────────────────────────

    #[tokio::test]
    async fn store_fact_missing_entity_has_structured_data() {
        let ctx = test_ctx();
        let err = handle_store_fact(&json!({"key": "k", "value": "v"}), &ctx)
            .await
            .unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
        let data = err.data.unwrap();
        assert_eq!(data["param"], "entity");
        assert_eq!(data["required"], true);
    }

    // ── M4: freshness horizon at write time ─────────────────────────

    #[test]
    fn parse_freshness_horizon_table() {
        use HorizonClass::*;
        let cases: &[(&str, HorizonClass)] = &[
            // hours -> volatile
            ("re-verify in 6 hours", Volatile),
            ("every hour", Volatile),
            // small-day counts -> volatile
            ("re-verify before relying after 1 day", Volatile),
            ("re-verify before relying after 2 days", Volatile),
            ("re-verify before relying after 3 days", Medium),
            ("after 7 days", Medium),
            ("day", Medium), // "day" w/o a number -> medium (conservative)
            // weeks / months -> medium
            ("re-check weekly", Medium),
            ("good for about a week", Medium),
            ("re-verify each month", Medium),
            ("monthly", Medium),
            // years / architectural / stable words -> stable
            ("architectural count", Stable),
            ("re-verify after a year", Stable),
            ("stable historical run", Stable),
            ("baseline frozen", Stable),
            ("immutable identity fact", Stable),
            ("historical run", Stable),
            // unrecognised -> none (do NOT guess)
            ("", None),
            ("some opaque note", None),
            ("re-verify before relying", None),
            ("forever", None),
        ];
        for (text, expected) in cases {
            assert_eq!(
                parse_freshness_horizon(text),
                *expected,
                "freshness_horizon parse mismatch for {text:?}"
            );
        }
    }

    #[tokio::test]
    async fn store_fact_explicit_horizon_class_persists() {
        let ctx = test_ctx();
        let r = handle_store_fact(
            &json!({"entity": "deploy", "key": "state", "value": "live", "horizon_class": "VOLATILE"}),
            &ctx,
        )
        .await
        .unwrap();
        let txt = r["content"][0]["text"].as_str().unwrap();
        let fact_id = txt.split_whitespace().nth(2).unwrap();
        let store = ctx.fact_store.read().await;
        let fact = store.get(fact_id).unwrap();
        assert_eq!(fact.horizon_class, HorizonClass::Volatile);
    }

    #[tokio::test]
    async fn store_fact_invalid_horizon_class_rejected() {
        let ctx = test_ctx();
        let err = handle_store_fact(
            &json!({"entity": "e", "key": "k", "value": "v", "horizon_class": "weekly"}),
            &ctx,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
        assert_eq!(err.data.unwrap()["param"], "horizon_class");
    }

    #[tokio::test]
    async fn store_fact_freshness_horizon_parsed_when_class_absent() {
        let ctx = test_ctx();
        let r = handle_store_fact(
            &json!({
                "entity": "deploy", "key": "state", "value": "live",
                "freshness_horizon": "re-verify before relying after 1 day"
            }),
            &ctx,
        )
        .await
        .unwrap();
        let txt = r["content"][0]["text"].as_str().unwrap();
        let fact_id = txt.split_whitespace().nth(2).unwrap();
        let store = ctx.fact_store.read().await;
        assert_eq!(store.get(fact_id).unwrap().horizon_class, HorizonClass::Volatile);
    }

    #[tokio::test]
    async fn store_fact_explicit_class_wins_over_freshness_horizon() {
        let ctx = test_ctx();
        let r = handle_store_fact(
            &json!({
                "entity": "e", "key": "k", "value": "v",
                "horizon_class": "stable",
                "freshness_horizon": "re-verify in 6 hours"
            }),
            &ctx,
        )
        .await
        .unwrap();
        let txt = r["content"][0]["text"].as_str().unwrap();
        let fact_id = txt.split_whitespace().nth(2).unwrap();
        let store = ctx.fact_store.read().await;
        assert_eq!(store.get(fact_id).unwrap().horizon_class, HorizonClass::Stable);
    }

    #[tokio::test]
    async fn store_fact_no_horizon_params_unchanged() {
        // Backward-compat: omitting both params leaves horizon_class at the
        // entity-prefix default (None for a plain entity).
        let ctx = test_ctx();
        let r = handle_store_fact(&json!({"entity": "plain", "key": "k", "value": "v"}), &ctx)
            .await
            .unwrap();
        let txt = r["content"][0]["text"].as_str().unwrap();
        let fact_id = txt.split_whitespace().nth(2).unwrap();
        let store = ctx.fact_store.read().await;
        assert_eq!(store.get(fact_id).unwrap().horizon_class, HorizonClass::None);
    }

    #[tokio::test]
    async fn query_facts_rows_include_freshness_and_age() {
        let ctx = test_ctx();
        handle_store_fact(&json!({"entity": "alpha", "key": "status", "value": "active"}), &ctx)
            .await
            .unwrap();

        let result = handle_query_facts(&json!({"query": "active", "entity": "alpha"}), &ctx)
            .await
            .unwrap();
        // Text still carries the legacy fields plus the new annotation.
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("active"));
        assert!(text.contains("confidence="));
        assert!(text.contains("freshness="));
        assert!(text.contains("age_hours="));
        // Structured rows carry the computed fields.
        let rows = result["structuredContent"]["rows"].as_array().unwrap();
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row["freshness"], "fresh"); // horizon=none -> always fresh
        assert!(row["age_hours"].is_number());
        assert_eq!(row["key"], "status");
        assert_eq!(row["value"], "active");
        assert_eq!(row["horizon_class"], "none");
    }

    #[test]
    fn backdated_volatile_fact_classifies_stale() {
        // Decay is computed via the SAME decay::apply_at_chrono path that
        // query_facts/memory_freshness use. Construct a volatile fact
        // stored 48h ago; the default 24h volatile threshold -> stale.
        use chrono::Duration;
        let policy = decay::DecayPolicy::default_const();
        let now = Utc::now();
        let stored_at = now - Duration::hours(48);
        let class = crate::tools::freshness::projection_class_of(HorizonClass::Volatile);
        let fresh = decay::apply_at_chrono(class, stored_at, None, now, policy);
        assert_eq!(fresh, decay::Freshness::Stale);

        // A fresh (just-stored) volatile fact is still fresh.
        let fresh_now = decay::apply_at_chrono(class, now, None, now, policy);
        assert_eq!(fresh_now, decay::Freshness::Fresh);
    }

    // ── M5: stale facts are demoted in ranking ──────────────────────

    use chrono::{DateTime, Duration};
    use corecrux_memory::fact_store::Fact;

    /// Build a fact directly (all fields public) and inject it via
    /// `store_synced` so we can backdate `stored_at` — mirrors the M4
    /// backdated-construction approach since `stored_at` isn't settable
    /// through the public store API.
    fn synth_fact(
        fact_id: &str,
        entity: &str,
        value: &str,
        confidence: f32,
        horizon_class: HorizonClass,
        stored_at: DateTime<Utc>,
        reverified_at: Option<DateTime<Utc>>,
    ) -> Fact {
        Fact {
            fact_id: fact_id.to_string(),
            entity: entity.to_string(),
            key: "state".to_string(),
            value: value.to_string(),
            source_receipt: None,
            confidence,
            stored_at,
            tokens: 8,
            deleted: false,
            version: 1,
            supersedes: None,
            private: false,
            horizon_class,
            reverified_at,
            superseded_by: None,
            actor: None,
        }
    }

    #[tokio::test]
    async fn query_facts_demotes_stale_below_equal_confidence_fresh() {
        let ctx = test_ctx();
        let now = Utc::now();
        {
            let mut store = ctx.fact_store.write().await;
            // STALE: volatile, stored 48h ago (> 24h threshold), conf 1.0.
            store.store_synced(synth_fact(
                "f_stale",
                "deploy",
                "old-state",
                1.0,
                HorizonClass::Volatile,
                now - Duration::hours(48),
                None,
            ));
            // FRESH: volatile, stored just now, equal stored confidence 1.0.
            store.store_synced(synth_fact(
                "f_fresh",
                "deploy",
                "new-state",
                1.0,
                HorizonClass::Volatile,
                now,
                None,
            ));
        }

        let result = handle_query_facts(&json!({"entity": "deploy"}), &ctx).await.unwrap();
        let rows = result["structuredContent"]["rows"].as_array().unwrap();
        assert_eq!(rows.len(), 2);
        // Fresh fact ranks first despite equal STORED confidence.
        assert_eq!(rows[0]["fact_id"], "f_fresh");
        assert_eq!(rows[0]["freshness"], "fresh");
        assert_eq!(rows[1]["fact_id"], "f_stale");
        assert_eq!(rows[1]["freshness"], "stale");
        // STORED confidence is preserved (not mutated); only the
        // recall-time effective_confidence is demoted on the stale row.
        assert_eq!(rows[1]["confidence"], 1.0);
        assert_eq!(rows[1]["effective_confidence"], 0.5);
        assert_eq!(rows[0]["confidence"], 1.0);
        assert_eq!(rows[0]["effective_confidence"], 1.0);
    }

    #[tokio::test]
    async fn query_facts_reverified_stale_regains_rank() {
        let ctx = test_ctx();
        let now = Utc::now();
        {
            let mut store = ctx.fact_store.write().await;
            // Stored 48h ago BUT reverified just now -> decay clock
            // re-anchored -> treated fresh again, regains its rank.
            store.store_synced(synth_fact(
                "f_reverified",
                "deploy",
                "re-anchored-state",
                1.0,
                HorizonClass::Volatile,
                now - Duration::hours(48),
                Some(now),
            ));
            // A fresh competitor with LOWER stored confidence: the
            // reverified fact should now outrank it (full effective conf).
            store.store_synced(synth_fact(
                "f_lower",
                "deploy",
                "other-state",
                0.6,
                HorizonClass::Volatile,
                now,
                None,
            ));
        }

        let result = handle_query_facts(&json!({"entity": "deploy"}), &ctx).await.unwrap();
        let rows = result["structuredContent"]["rows"].as_array().unwrap();
        assert_eq!(rows.len(), 2);
        // Reverified fact is fresh again and outranks the lower-confidence
        // fresh fact.
        assert_eq!(rows[0]["fact_id"], "f_reverified");
        assert_eq!(rows[0]["freshness"], "fresh");
        assert_eq!(rows[0]["effective_confidence"], 1.0);
        assert_eq!(rows[1]["fact_id"], "f_lower");
    }

    #[tokio::test]
    async fn query_facts_text_exposes_effective_confidence() {
        let ctx = test_ctx();
        handle_store_fact(&json!({"entity": "alpha", "key": "state", "value": "active"}), &ctx)
            .await
            .unwrap();
        let result = handle_query_facts(&json!({"entity": "alpha"}), &ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("effective_confidence="));
    }

    // ── M6: cross-entity supersession ───────────────────────────────

    /// Extract a fact_id from a `store_fact` text response.
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
    async fn store_fact_supersedes_marks_and_query_hides_then_shows() {
        let ctx = test_ctx();
        // Old baseline under one entity.
        let old = handle_store_fact(
            &json!({"entity": "bench:lme-s", "key": "baseline", "value": "86.8 percent"}),
            &ctx,
        )
        .await
        .unwrap();
        let old_id = fact_id_of(&old);

        // New baseline under a DIFFERENT entity, retiring the old one.
        let new = handle_store_fact(
            &json!({
                "entity": "bench:lme-s-v2", "key": "baseline", "value": "90.0 percent",
                "supersedes": [old_id]
            }),
            &ctx,
        )
        .await
        .unwrap();
        let new_id = fact_id_of(&new);
        // Response surfaces what it retired.
        assert!(new["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains(&format!("retired={old_id}")));
        assert_eq!(new["structuredContent"]["superseded_fact_ids"][0], old_id.as_str());

        // Default query OMITS the superseded old fact.
        let res = handle_query_facts(&json!({"query": "percent"}), &ctx).await.unwrap();
        let rows = res["structuredContent"]["rows"].as_array().unwrap();
        let ids: Vec<&str> = rows.iter().map(|r| r["fact_id"].as_str().unwrap()).collect();
        assert!(ids.contains(&new_id.as_str()), "new fact should be present");
        assert!(
            !ids.contains(&old_id.as_str()),
            "superseded fact must be hidden by default"
        );

        // include_superseded=true brings it back WITH superseded_by set.
        let res = handle_query_facts(&json!({"query": "percent", "include_superseded": true}), &ctx)
            .await
            .unwrap();
        let rows = res["structuredContent"]["rows"].as_array().unwrap();
        let old_row = rows.iter().find(|r| r["fact_id"] == old_id.as_str()).unwrap();
        assert_eq!(old_row["superseded_by"], new_id.as_str());
    }

    #[tokio::test]
    async fn store_fact_supersedes_nonexistent_ref_errors_and_leaves_targets_unchanged() {
        let ctx = test_ctx();
        // A real fact we will NOT touch.
        let real = handle_store_fact(&json!({"entity": "e", "key": "k", "value": "v"}), &ctx)
            .await
            .unwrap();
        let real_id = fact_id_of(&real);

        let err = handle_store_fact(
            &json!({
                "entity": "e2", "key": "k", "value": "v2",
                "supersedes": [real_id, "f_does_not_exist"]
            }),
            &ctx,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
        let invalid = err.data.unwrap()["invalid_refs"].as_array().unwrap().clone();
        assert!(invalid.iter().any(|v| v == "f_does_not_exist"));

        // The valid ref was NOT marked — whole batch rejected, no partial state.
        let store = ctx.fact_store.read().await;
        assert!(store.get(&real_id).unwrap().superseded_by.is_none());
    }

    #[tokio::test]
    async fn store_fact_cannot_supersede_other_agents_private_fact() {
        // T.1: you can only supersede facts you can see. Alice's private
        // fact is invisible to Bob, so Bob's supersede ref is rejected.
        let ctx = test_ctx();
        let alice = ctx.with_agent(AgentIdentity {
            name: "alice".to_string(),
            token_hash: [0u8; 32],
        });
        let bob = ctx.with_agent(AgentIdentity {
            name: "bob".to_string(),
            token_hash: [1u8; 32],
        });

        let secret = handle_store_fact(
            &json!({"entity": "notes", "key": "s", "value": "hidden", "private": true}),
            &alice,
        )
        .await
        .unwrap();
        let secret_id = fact_id_of(&secret);

        let err = handle_store_fact(
            &json!({"entity": "pub", "key": "k", "value": "v", "supersedes": [secret_id]}),
            &bob,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
        let invalid = err.data.unwrap()["invalid_refs"].as_array().unwrap().clone();
        assert!(invalid.iter().any(|v| v == secret_id.as_str()));

        // Alice's fact is untouched.
        let store = ctx.fact_store.read().await;
        assert!(store.get(&secret_id).unwrap().superseded_by.is_none());
    }

    #[tokio::test]
    async fn store_fact_supersedes_wrong_type_rejected() {
        let ctx = test_ctx();
        let err = handle_store_fact(
            &json!({"entity": "e", "key": "k", "value": "v", "supersedes": "not-an-array"}),
            &ctx,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
        assert_eq!(err.data.unwrap()["param"], "supersedes");
    }
}
