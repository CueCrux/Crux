// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Fact store tool handlers: `store_fact`, `query_facts`, `delete_fact`,
//! `list_entities`, `get_bootstrap`.

use std::collections::BTreeSet;

use serde_json::{json, Value};

use chrono::{DateTime, Utc};

use crate::dispatch::McpContext;
use crate::protocol::{JsonRpcError, INTERNAL_ERROR, INVALID_PARAMS};
use crate::scope;
use corecrux_memory::fact_store::{Fact, FactQuery, HorizonClass, StoreFact};
use corecrux_projections::decay;

/// M2 salience switch. When `CORECRUXD_MEMORY_SALIENCE` is set to a truthy
/// value (`1`/`true`/`yes`/`on`, case-insensitive) the recall path records
/// per-fact access counts so frequently-recalled facts decay slower. Default
/// OFF keeps recall strictly read-only and byte-identical to pre-M2.
fn salience_enabled() -> bool {
    std::env::var("CORECRUXD_MEMORY_SALIENCE")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

/// Resolve the (scope_identity, aliases) pair for `ctx` (agent-passport M5).
///
/// Flag-OFF: identity is the raw agent name and aliases is empty — every
/// `scope::*_for_identity` call below then behaves byte-for-byte like the prior
/// `scope::*_for_agent(agent_name)` call. Flag-ON: identity is the passport_id
/// and aliases carries the caller's own raw name for legacy-private back-compat.
fn scope_ctx(ctx: &McpContext) -> (Option<String>, Vec<String>) {
    (ctx.scope_identity(), ctx.scope_aliases())
}

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
    if let Some(prefix) = corecrux_memory::fact_privacy::generic_create_reserved_entity_prefix(entity_raw) {
        return Err(JsonRpcError {
            code: INVALID_PARAMS,
            message: format!("entity uses create-reserved prefix `{prefix}`"),
            data: Some(json!({
                "error_code": "RESERVED_ENTITY_PREFIX",
                "param": "entity",
                "entity": entity_raw,
                "reserved_prefix": prefix,
            })),
        });
    }
    let source_receipt = args
        .get("source_receipt")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let confidence = args.get("confidence").and_then(|v| v.as_f64()).unwrap_or(1.0) as f32;
    let private = args.get("private").and_then(|v| v.as_bool()).unwrap_or(false);

    // agent-passport M5: the *scope identity* is what private facts are keyed
    // by and matched against. Flag-OFF it is exactly `agent_name` (raw token-
    // name) — byte-for-byte the pre-M5 path. Flag-ON it is the resolved
    // passport_id (e.g. `claude-work`), so a private fact's owner key agrees
    // with the M1 `actor` stamp. `scope_aliases` carries the caller's OWN raw
    // name so its legacy (flag-off-written) private facts stay visible.
    let scope_identity = ctx.scope_identity();
    let scope_id_ref = scope_identity.as_deref();
    let aliases = ctx.scope_aliases();
    let alias_refs: Vec<&str> = aliases.iter().map(String::as_str).collect();

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

    // agent-passport M5: key a private fact by the scope identity. Flag-OFF
    // `scope_id_ref == agent_name` so this is identical to the prior
    // `private_entity_for_agent(agent_name, …)` call.
    let entity = match (private, scope_id_ref) {
        (true, Some(owner)) => scope::private_entity_for_agent(owner, entity_raw),
        (true, None) => {
            return Err(JsonRpcError {
                code: INVALID_PARAMS,
                message: "private facts require an authenticated agent identity".to_string(),
                data: Some(json!({"param": "private", "requires_agent_identity": true})),
            });
        }
        (false, _) => entity_raw.to_string(),
    };

    // Durable authorship (agent-passport M1 + transport authority):
    // * A transport-bound principal is already authenticated and always wins.
    // * Flag OFF (default): `actor = None` — byte-for-byte the pre-M1 path.
    // * Flag ON: resolve the agent token-name (`anthropic`, `openai`, …) to a
    //   passport_id (`claude-work`, `codex-work`, …) via the context map. If
    //   the name is unmapped we fall back to the RAW agent name so a flag-ON
    //   write is NEVER anonymous (QC.3); only a truly unauthenticated caller
    //   (no agent identity) leaves `actor = None`.
    let actor = ctx.fact_actor();

    // agent-passport M5: the entity the category check runs against. For a
    // private fact use the LOGICAL (pre-`__agent::`-prefix) entity; otherwise
    // the stored entity. Computed BEFORE `entity` is moved into `req`.
    let enforce_entity: String = if private {
        entity_raw.to_string()
    } else {
        entity.clone()
    };

    let mut req = StoreFact {
        tenant_hash: ctx.scope_tenant(),
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

    // agent-passport M5: tenant-category WRITE ENFORCEMENT. FLAG-GATED.
    //   * Flag OFF (default): skipped entirely — byte-for-byte the prior path
    //     (this closes the M3.5 NOTE without changing flag-off behaviour).
    //   * Flag ON: resolve the caller's passport_id and reject a write whose
    //     entity category is incompatible with the passport category (e.g. a
    //     `work` passport writing a `personal` entity). System entities
    //     (`__*__`, including the `__agent::` prefix of a private fact) are
    //     exempt inside `check_passport_can_write_entity`, so private writes
    //     and daemon bookkeeping are never blocked. On violation we return a
    //     JsonRpcError and DO NOT store.
    if ctx.agent_passports_enabled {
        if let Some(pid) = &scope_identity {
            // Enforce against the LOGICAL (pre-private-prefix) entity for a
            // private fact, and the stored entity otherwise. A private fact's
            // stored entity is `__agent::…` which classifies System (exempt)
            // either way; using the logical entity keeps the check meaningful
            // if private-prefixing ever changes.
            if let Err(e) = crate::category_enforce::check_passport_can_write_entity(
                &store,
                Some(pid.as_str()),
                enforce_entity.as_str(),
            ) {
                return Err(JsonRpcError {
                    code: INVALID_PARAMS,
                    message: e.to_string(),
                    data: Some(json!({
                        "param": "entity",
                        "category_enforcement": true,
                        "passport_id": pid,
                        "entity": enforce_entity,
                    })),
                });
            }
        }
    }

    // Validate every cross-entity retirement before the new fact is stored.
    // This keeps the operation atomic on bad references and prevents a generic
    // writer from retiring a legacy daemon control row by fact_id.
    let tenant_hash = ctx.scope_tenant();
    let mut bad_refs = Vec::new();
    let mut reserved_refs = Vec::new();
    let mut consolidation_refs = Vec::new();
    for fact_id in &supersedes_refs {
        match store.get_for_tenant(fact_id, &tenant_hash) {
            Some(target) if scope::fact_visible_to_identity(target, scope_id_ref, &alias_refs) => {
                if store.is_active_consolidation_source_for_tenant(fact_id, &tenant_hash) {
                    consolidation_refs.push(fact_id.clone());
                    continue;
                }
                let policy_entity = scope::visible_entity_for_identity(target, scope_id_ref, &alias_refs)
                    .unwrap_or_else(|| target.entity.clone());
                if let Some(prefix) = corecrux_memory::fact_privacy::daemon_owned_entity_prefix(&policy_entity) {
                    reserved_refs.push(json!({
                        "fact_id": fact_id,
                        "entity": policy_entity,
                        "reserved_prefix": prefix,
                    }));
                }
            }
            _ => bad_refs.push(fact_id.clone()),
        }
    }
    if !consolidation_refs.is_empty() {
        return Err(JsonRpcError {
            code: crate::dispatch::CAPABILITY_DENIED,
            message: "active consolidation source edges are immutable until dedicated undo".to_string(),
            data: Some(json!({
                "error_code": "CONSOLIDATION_SOURCE_REQUIRES_UNDO",
                "param": "supersedes",
                "fact_ids": consolidation_refs,
            })),
        });
    }
    if !reserved_refs.is_empty() {
        return Err(JsonRpcError {
            code: INVALID_PARAMS,
            message: "daemon-owned control facts cannot be superseded through store_fact".to_string(),
            data: Some(json!({
                "error_code": "RESERVED_SUPERSEDES_TARGET",
                "param": "supersedes",
                "reserved_refs": reserved_refs,
            })),
        });
    }
    if !bad_refs.is_empty() {
        return Err(JsonRpcError {
            code: INVALID_PARAMS,
            message: "one or more supersedes fact_ids do not exist or are not visible to you".to_string(),
            data: Some(json!({"param": "supersedes", "invalid_refs": bad_refs})),
        });
    }

    corecrux_memory::fact_privacy::enforce_global(&mut req);
    let fact = store.try_store(req).map_err(|err| JsonRpcError {
        code: INTERNAL_ERROR,
        message: "fact journal append failed".to_string(),
        data: Some(json!({"error": err.to_string()})),
    })?;

    // M6 cross-entity supersession: all references were validated under this
    // same write lock before the new fact was persisted.
    let mut superseded_ok: Vec<String> = Vec::new();
    if !supersedes_refs.is_empty() {
        for r in &supersedes_refs {
            if store.mark_superseded(&tenant_hash, r, &fact.fact_id) {
                superseded_ok.push(r.clone());
            }
        }
    }

    let display_entity =
        scope::visible_entity_for_identity(&fact, scope_id_ref, &alias_refs).unwrap_or_else(|| fact.entity.clone());

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
    let (identity, aliases) = scope_ctx(ctx);
    let id_ref = identity.as_deref();
    let alias_refs: Vec<&str> = aliases.iter().map(String::as_str).collect();

    let store = ctx.fact_store.read().await;
    let tenant_hash = ctx.scope_tenant();
    let mut history: Vec<&Fact> = store
        .all_facts_for_tenant(&tenant_hash)
        .filter(|fact| fact.key == key)
        .filter(|fact| scope::entity_matches_for_identity(fact, entity, id_ref, &alias_refs))
        .filter(|fact| scope::fact_visible_to_identity(fact, id_ref, &alias_refs))
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
            let display_entity =
                scope::visible_entity_for_identity(f, id_ref, &alias_refs).unwrap_or_else(|| f.entity.clone());
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
    // P2 confidence floor: drop facts whose recall-time effective confidence is
    // below this. Absent ⇒ no floor (behaviour unchanged). Validate BEFORE the
    // f32 cast so an out-of-range / non-finite value is rejected, not silently
    // turned into "all kept / all filtered".
    let min_effective_confidence = match args.get("min_effective_confidence") {
        Some(v) => {
            let f = v
                .as_f64()
                .filter(|f| crate::tools::freshness::valid_confidence_floor(*f))
                .ok_or_else(|| JsonRpcError {
                    code: INVALID_PARAMS,
                    message: "min_effective_confidence must be a number in 0.0..=1.0".to_string(),
                    data: None,
                })?;
            Some(f as f32)
        }
        None => None,
    };
    // M6: superseded (cross-entity retired) facts are hidden from recall by
    // default; opt back in with `include_superseded: true`.
    let include_superseded = args
        .get("include_superseded")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    // Bi-temporal as-of (M1): only facts true in the world at this instant.
    // Reject an unparseable timestamp rather than silently dropping the filter.
    let as_of = match args.get("as_of").and_then(|v| v.as_str()) {
        Some(raw) => Some(
            DateTime::parse_from_rfc3339(raw)
                .map(|dt| dt.with_timezone(&Utc))
                .map_err(|_| JsonRpcError {
                    code: INVALID_PARAMS,
                    message: "as_of must be an RFC 3339 timestamp (e.g. 2026-01-15T00:00:00Z)".to_string(),
                    data: None,
                })?,
        ),
        None => None,
    };
    let (identity, aliases) = scope_ctx(ctx);
    let id_ref = identity.as_deref();
    let alias_refs: Vec<&str> = aliases.iter().map(String::as_str).collect();

    // CO-4 live holdout: a sampled fraction of requests run UNSHAPED (control).
    // When unshaped, force the efficiency flags OFF for this request so the
    // control arm pays the full (legacy) cost. No-op when CRUX_OUTPUT_HOLDOUT=0.
    let unshaped = crate::holdout::request_is_control(&args.to_string());
    // M1 part 2/3 — reversible overflow on the fact path (unconditional since CO-5,
    // but only for the CRC-v1 surface — the legacy text path has no epitome tier to
    // demote into, so it keeps its budget-drop). When active, the store query does
    // NOT budget-drop overflow facts (it returns the full ranked top_k); the CRC-v1
    // reshape below demotes the over-budget tail to epitome-only pointers and caps
    // the emitted tier to budget. Legacy contract OR holdout control (`unshaped`) ⇒
    // legacy budget-drop.
    let reversible = !unshaped && token_budget.is_some() && crate::crc_v1::enabled(args);
    let q = FactQuery {
        min_effective_confidence,
        tenant_hash: Some(ctx.scope_tenant()),
        // cloned so `query`/`entity` remain available for the CRC-v1 reshape below
        query: query.clone(),
        entity: entity.clone(),
        entity_prefix: None,
        top_k,
        // Suppress the store-level drop under reversible mode; the demotion
        // boundary is computed from the full ranked set below.
        token_budget: if reversible { None } else { token_budget },
    };

    let store = ctx.fact_store.read().await;
    let (visible, filtered_below_threshold) =
        query_visible_facts_opts_as_of(&store, &q, id_ref, &alias_refs, include_superseded, as_of);
    drop(store);

    // M2 salience: record that these facts were just recalled so they decay
    // slower on subsequent reads. Default-OFF (env `CORECRUXD_MEMORY_SALIENCE`)
    // because it takes a brief write lock on the otherwise read-only recall
    // path; when off the recall path is byte-identical to pre-M2.
    if salience_enabled() && !visible.is_empty() {
        let ids: Vec<&str> = visible.iter().map(|f| f.fact_id.as_str()).collect();
        ctx.fact_store.write().await.record_access(&ids);
    }

    if visible.is_empty() {
        // P2: distinguish "genuinely nothing" from "everything was below the
        // confidence floor" so the caller can fall back to a non-LLM path
        // instead of padding context with junk. `filtered_below_threshold` is
        // surfaced in both the text and structured surfaces.
        let text = if filtered_below_threshold > 0 {
            format!("no facts above confidence floor ({filtered_below_threshold} below threshold)")
        } else {
            "no facts found".to_string()
        };
        return Ok(json!({
            "content": [{ "type": "text", "text": text }],
            "structuredContent": { "rows": [], "filtered_below_threshold": filtered_below_threshold }
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
        let entity = scope::visible_entity_for_identity(f, id_ref, &alias_refs).unwrap_or_else(|| f.entity.clone());
        let class = crate::tools::freshness::projection_class_of(f.horizon_class);
        // Salience-aware (M2): the surfaced freshness/effective_confidence
        // matches the ranking key computed in `query_visible_facts_opts`.
        let fresh = decay::apply_at_chrono_salient(class, f.stored_at, f.reverified_at, f.access_count, now, policy);
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

    // CRC-v1 (kind=fact addressed recall) when negotiated. We KEEP the legacy
    // `structuredContent.rows` and nest the envelope under `structuredContent.crc_v1`
    // so the dispatch audit-envelope wrapper (which overwrites
    // `structuredContent.envelope`) composes without collision. content[text]
    // carries the CRC-v1 envelope for text-reading agents. Absent contract →
    // legacy shape, byte-identical.
    if crate::crc_v1::enabled(args) {
        // M1 part 2/3: under reversible mode, hydrate `full_count` facts full and
        // demote the rest to epitome-only — but **budget the emitted tier** (M1
        // pt3 / CO-6): emit only `emit_count` pointers (full + epitomes that fit
        // the budget), drop the rest, and disclose the full count via
        // `total_candidates` so the agent re-queries for the remainder. This keeps
        // the emitted payload within `token_budget` (QC.2), which the uncapped
        // pt2 path violated by emitting a pointer for every candidate.
        let crc = if reversible {
            let costs: Vec<usize> = visible.iter().map(|f| f.tokens).collect();
            let budget = token_budget.unwrap_or(0);
            let (full_count, emit_count) = crate::budget::fact_emit_within_budget(&costs, budget);
            let total = rows.len();
            let emitted = &rows[..emit_count.min(rows.len())];
            crate::crc_v1::wrap_facts_tiered(emitted, entity.as_deref(), query.as_deref(), full_count, total)
        } else {
            crate::crc_v1::wrap_facts(&rows, entity.as_deref(), query.as_deref())
        };
        // M3: minified text surface unconditionally (since CO-5); the structured
        // `crc_v1` Value below is unchanged. CO-4: unshaped control forces pretty.
        let compact = !unshaped;
        let text = crate::payload::serialize_with(&crc, compact);
        crate::holdout::record_sample(unshaped, crate::token_estimate::estimate_tokens_str(&text));
        crate::holdout::sample_compaction(&args.to_string(), &crc); // CO-5 compaction-only
        return Ok(json!({
            "content": [{ "type": "text", "text": text }],
            "structuredContent": { "rows": rows, "crc_v1": crc, "filtered_below_threshold": filtered_below_threshold }
        }));
    }

    Ok(json!({
        "content": [{ "type": "text", "text": lines.join("\n") }],
        "structuredContent": { "rows": rows, "filtered_below_threshold": filtered_below_threshold }
    }))
}

/// `delete_fact` — soft-delete a fact by its ID.
pub async fn handle_delete_fact(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let fact_id = require_str(args, "fact_id")?;
    let (identity, aliases) = scope_ctx(ctx);
    let id_ref = identity.as_deref();
    let alias_refs: Vec<&str> = aliases.iter().map(String::as_str).collect();

    let mut store = ctx.fact_store.write().await;
    let tenant_hash = ctx.scope_tenant();
    let existing = store.get_for_tenant(fact_id, &tenant_hash);
    let visible_fact = existing.filter(|fact| scope::fact_visible_to_identity(fact, id_ref, &alias_refs));
    let policy_entity = visible_fact.and_then(|fact| {
        if fact.entity.starts_with(crate::scope::AGENT_PRIVATE_ENTITY_PREFIX) {
            scope::visible_entity_for_identity(fact, id_ref, &alias_refs)
        } else {
            Some(fact.entity.clone())
        }
    });
    if let Some((entity, prefix)) = policy_entity.as_deref().and_then(|entity| {
        corecrux_memory::fact_privacy::daemon_owned_entity_prefix(entity).map(|prefix| (entity, prefix))
    }) {
        return Err(JsonRpcError {
            code: crate::dispatch::CAPABILITY_DENIED,
            message: format!("fact belongs to reserved daemon-owned prefix `{prefix}`"),
            data: Some(json!({
                "error_code": "RESERVED_ENTITY_PREFIX",
                "fact_id": fact_id,
                "entity": entity,
                "reserved_prefix": prefix,
            })),
        });
    }
    if visible_fact.is_some() && store.is_consolidation_canonical_for_tenant(fact_id, &tenant_hash) {
        return Err(JsonRpcError {
            code: crate::dispatch::CAPABILITY_DENIED,
            message: format!(
                "fact {fact_id} is a consolidation canonical; use the dedicated consolidation undo surface"
            ),
            data: Some(json!({
                "error_code": "CONSOLIDATION_CANONICAL_REQUIRES_UNDO",
                "fact_id": fact_id,
            })),
        });
    }
    let deleted = visible_fact.is_some()
        && store.try_delete(&tenant_hash, fact_id).map_err(|err| JsonRpcError {
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
    let (identity, aliases) = scope_ctx(ctx);
    let id_ref = identity.as_deref();
    let alias_refs: Vec<&str> = aliases.iter().map(String::as_str).collect();
    let entities: Vec<String> = store
        .all_facts_for_tenant(&ctx.scope_tenant())
        .filter(|fact| !fact.deleted)
        .filter_map(|fact| scope::visible_entity_for_identity(fact, id_ref, &alias_refs))
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
    // Agent-only callers (the envelope builder) are NOT passport-rekeyed:
    // pass an empty alias set, so this reduces to the raw agent_name check.
    query_visible_facts_opts(store, q, agent_name, &[], false)
}

/// As [`query_visible_facts`] but with an explicit `include_superseded`
/// toggle (M6) and the M5 identity/alias scoping. `identity` is the resolved
/// scope identity (flag-OFF: the raw agent name; flag-ON: the passport_id);
/// `aliases` carries the caller's own legacy names for back-compat (empty
/// flag-OFF). When `include_superseded` is `false` (the default recall
/// behaviour), facts whose `superseded_by` marker is set are excluded.
fn query_visible_facts_opts(
    store: &corecrux_memory::FactStore,
    q: &FactQuery,
    identity: Option<&str>,
    aliases: &[&str],
    include_superseded: bool,
) -> Vec<Fact> {
    // Envelope/internal callers never set a confidence floor; discard the count.
    query_visible_facts_opts_as_of(store, q, identity, aliases, include_superseded, None).0
}

/// As [`query_visible_facts_opts`] with an optional bi-temporal `as_of` filter
/// (M1): when set, only facts valid in the world at that instant are returned.
fn query_visible_facts_opts_as_of(
    store: &corecrux_memory::FactStore,
    q: &FactQuery,
    identity: Option<&str>,
    aliases: &[&str],
    include_superseded: bool,
    as_of: Option<DateTime<Utc>>,
) -> (Vec<Fact>, usize) {
    let mut results: Vec<&Fact> = store
        .all_facts()
        .filter(|fact| !fact.deleted)
        .filter(|fact| as_of.is_none_or(|instant| fact.valid_at(instant)))
        .filter(|fact| include_superseded || fact.superseded_by.is_none())
        .filter(|fact| scope::fact_visible_to_identity(fact, identity, aliases))
        .filter(|fact| q.tenant_hash.as_ref().is_none_or(|tenant| fact.tenant_hash == *tenant))
        .filter(|fact| {
            q.entity_prefix
                .as_ref()
                .is_none_or(|prefix| scope::entity_prefix_matches_for_identity(fact, prefix, identity, aliases))
        })
        .filter(|fact| {
            q.entity
                .as_ref()
                .is_none_or(|entity| scope::entity_matches_for_identity(fact, entity, identity, aliases))
        })
        .filter(|fact| match &q.query {
            Some(query) => fact_matches_query(fact, query, identity, aliases),
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
    // M2 salience: a frequently-recalled fact decays slower, so it resists the
    // stale demotion longer. `access_count == 0` (every fact until salience is
    // enabled and accrues recalls) makes this identical to `apply_at_chrono`.
    let eff = |fact: &Fact| -> f64 { crate::tools::freshness::fact_effective_confidence(fact, now, policy) };
    results.sort_by(|left, right| {
        eff(right)
            .partial_cmp(&eff(left))
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| right.stored_at.cmp(&left.stored_at))
    });

    // P2 confidence floor: drop facts whose recall-time effective confidence is
    // below the requested threshold, and count how many were dropped so the
    // caller can tell "no facts" apart from "nothing above threshold". Counted
    // over the full matched set BEFORE the budget/top_k cut so an empty result
    // still reports the true below-threshold count.
    let mut filtered_below_threshold = 0usize;
    if let Some(floor) = q.min_effective_confidence {
        let floor = floor as f64;
        results.retain(|fact| {
            let keep = eff(fact) >= floor;
            if !keep {
                filtered_below_threshold += 1;
            }
            keep
        });
    }

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
        return (selected, filtered_below_threshold);
    }

    results.truncate(q.top_k);
    (results.into_iter().cloned().collect(), filtered_below_threshold)
}

fn fact_matches_query(fact: &Fact, query: &str, identity: Option<&str>, aliases: &[&str]) -> bool {
    let query_lower = query.to_lowercase();
    let terms: Vec<&str> = query_lower.split_whitespace().collect();
    let value_lower = fact.value.to_lowercase();
    let key_lower = fact.key.to_lowercase();
    let entity_lower = scope::visible_entity_for_identity(fact, identity, aliases)
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
        min_effective_confidence: None,
        tenant_hash: None,
        query,
        entity: None,
        entity_prefix: Some(prefix),
        top_k: 100,
        token_budget: None,
    };

    let store = ctx.fact_store.read().await;
    let result = store.query(&q);

    let mut lines: Vec<String> = result
        .facts
        .iter()
        .map(|f| format!("[{}] {} = {}", f.entity, f.key, f.value))
        .collect();

    // M4 (CRC-v1 self-describing schema layer): the `tool-output` topic is
    // served on demand from the canonical CRC-v1 schema — no persisted
    // boot-seed required. Synthesized entries are appended to any operator-
    // written tool-output facts.
    if topic.as_deref().map(normalize_bootstrap_topic).as_deref() == Some("tool-output") {
        for (entity, key, value) in crate::crc_v1::tool_output_catalogue() {
            lines.push(format!("[{entity}] {key} = {value}"));
        }
    }

    if lines.is_empty() {
        let msg = match &topic {
            Some(t) => format!("no bootstrap knowledge for topic '{t}'"),
            None => "no bootstrap knowledge found".to_string(),
        };
        return Ok(json!({
            "content": [{ "type": "text", "text": msg }]
        }));
    }

    Ok(json!({
        "content": [{ "type": "text", "text": lines.join("\n") }]
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

    // ── M1 part 2 — fact-path reversible overflow ──────────────────────────

    #[tokio::test]
    async fn query_facts_reversible_demotes_overflow_instead_of_dropping() {
        let _g = crate::test_env_lock().lock().await;
        let ctx = test_ctx();
        {
            let mut store = ctx.fact_store.write().await;
            // Six facts with longish values so a tight budget cuts the tail.
            for i in 0..6 {
                store.store(StoreFact {
                    tenant_hash: "default".to_string(),
                    entity: "proj".to_string(),
                    key: format!("k{i}"),
                    value: format!("needle {}", "lorem ipsum dolor sit amet ".repeat(8)),
                    source_receipt: None,
                    confidence: 1.0,
                    private: false,
                    horizon_class: None,
                    actor: None,
                });
            }
        }
        let args = json!({"query": "needle", "token_budget": 80, "top_k": 50});

        // Unshaped (holdout=1 ⇒ every request is control, since CO-5 removed the
        // reversible flag): legacy budget-drop — overflow facts vanish.
        std::env::set_var(crate::holdout::HOLDOUT_ENV, "1");
        let off = handle_query_facts(&args, &ctx).await.unwrap();
        let off_rows = off["structuredContent"]["rows"].as_array().unwrap().len();
        let off_crc = &off["structuredContent"]["crc_v1"];
        assert_eq!(off_crc["hydrate_tier"], "full");
        assert!(off_crc["meta"].get("demoted").is_none(), "unshaped must not demote");
        assert!(off_rows < 6, "unshaped drops overflow (kept {off_rows} of 6)");

        // Shaped (holdout=0 ⇒ reversible): M1 pt3 budgets the emitted tier —
        // hydrate the within-budget head full, demote some to epitome if the
        // budget allows, and DROP the rest beyond the cap (disclosed via
        // total_candidates).
        std::env::set_var(crate::holdout::HOLDOUT_ENV, "0");
        let on = handle_query_facts(&args, &ctx).await.unwrap();
        let on_crc = &on["structuredContent"]["crc_v1"];
        std::env::remove_var(crate::holdout::HOLDOUT_ENV);
        crate::holdout::accumulator().lock().unwrap().clear_for_test();

        let pointers = on_crc["pointers"].as_array().unwrap().len() as u64;
        let content = on_crc["content"].as_array().unwrap().len() as u64;
        let emitted_full = on_crc["meta"]["emitted_full"].as_u64().unwrap();
        let capped = on_crc["meta"]["capped"].as_u64().unwrap_or(0);
        assert_eq!(on_crc["meta"]["total_candidates"], 6);
        // QC.2 — the emitted tier is BUDGETED, so at this tight budget it does NOT
        // emit all 6; the overflow is capped (dropped beyond budget), not emitted.
        assert!(
            pointers < 6 && capped > 0,
            "cap must engage: emitted {pointers}, capped {capped}"
        );
        // Conservation: emitted + capped == all candidates (nothing silently lost).
        assert_eq!(pointers + capped, 6);
        // content[] is exactly the full hydrations; the rest of the emitted tier
        // (if any) are epitome pointers.
        assert_eq!(content, emitted_full);
        // Drop→demote parity: the full-hydration count == the legacy drop count.
        assert_eq!(
            emitted_full as usize, off_rows,
            "emitted_full must match the legacy drop count"
        );
        // Recall is still ≥ the legacy drop (cap only drops what won't fit budget).
        assert!(pointers >= off_rows as u64, "reversible recall ≥ legacy drop");
    }

    // ── D1: bi-temporal as_of on query_facts ────────────────────────

    #[tokio::test]
    async fn query_facts_as_of_filters_by_valid_time() {
        let ctx = test_ctx();
        let ts = |s: &str| DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc);

        handle_store_fact(&json!({"entity": "person:zoe", "key": "city", "value": "London"}), &ctx)
            .await
            .unwrap();
        handle_store_fact(&json!({"entity": "person:zoe", "key": "city", "value": "Berlin"}), &ctx)
            .await
            .unwrap();

        // Zoe lived in London Jan–Jun 2026, then Berlin from Jun on.
        {
            let mut store = ctx.fact_store.write().await;
            let facts: Vec<(String, String)> = store
                .get_by_entity("person:zoe")
                .into_iter()
                .map(|f| (f.fact_id.clone(), f.value.clone()))
                .collect();
            for (id, value) in facts {
                if value == "London" {
                    store.set_validity(&id, Some(ts("2026-01-01T00:00:00Z")), Some(ts("2026-06-01T00:00:00Z")));
                } else if value == "Berlin" {
                    store.set_validity(&id, Some(ts("2026-06-01T00:00:00Z")), None);
                }
            }
        }

        // include_superseded so the version chain doesn't hide the prior value;
        // the as_of filter is what should select the world-true fact.
        let march = handle_query_facts(
            &json!({"entity": "person:zoe", "as_of": "2026-03-01T00:00:00Z", "include_superseded": true, "token_budget": 500}),
            &ctx,
        )
        .await
        .unwrap();
        let march_txt = serde_json::to_string(&march).unwrap();
        assert!(march_txt.contains("London"), "as-of March should surface London");
        assert!(!march_txt.contains("Berlin"), "as-of March must not surface Berlin");

        let sept = handle_query_facts(
            &json!({"entity": "person:zoe", "as_of": "2026-09-01T00:00:00Z", "include_superseded": true, "token_budget": 500}),
            &ctx,
        )
        .await
        .unwrap();
        let sept_txt = serde_json::to_string(&sept).unwrap();
        assert!(sept_txt.contains("Berlin"), "as-of September should surface Berlin");
        assert!(!sept_txt.contains("London"), "as-of September must not surface London");
    }

    #[tokio::test]
    async fn query_facts_rejects_bad_as_of() {
        let ctx = test_ctx();
        let err = handle_query_facts(&json!({"query": "x", "as_of": "not-a-timestamp"}), &ctx)
            .await
            .unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
        assert!(err.message.contains("as_of"));
    }

    /// agent-passport M5: seed a passport record so the flag-ON write
    /// enforcement (`check_passport_can_write_entity`) can resolve a category.
    /// Without this, a flag-ON write by a mapped agent is rejected as
    /// `LegacyOrMissingPassport` — which is the correct, designed behaviour for
    /// an unminted passport, but the M1/M3 attribution tests below want a
    /// *successful* write, so they mint the passport first.
    async fn seed_passport(ctx: &McpContext, id: &str, category: &str) {
        let record = json!({
            "id": id,
            "principal_id": format!("test::{id}"),
            "public_key_hex": "deadbeef",
            "category": category,
            "issued_at_unix_ms": 1u64,
        });
        let mut store = ctx.fact_store.write().await;
        store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: format!("__passport__::{id}"),
            key: "record".to_string(),
            value: record.to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: true,
            horizon_class: None,
            actor: None,
        });
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
        let store = ctx.fact_store.read().await;
        assert!(store.all_facts().all(|fact| fact.tenant_hash == "default"));
    }

    #[tokio::test]
    async fn store_fact_born_private_reserved_prefix() {
        let ctx = test_ctx();
        let result = handle_store_fact(
            &json!({"entity": "github::CueCrux/Crux::issue/1", "key": "record", "value": "x"}),
            &ctx,
        )
        .await
        .unwrap();

        let fact_id = result["structuredContent"]["fact_id"].as_str().unwrap();
        let store = ctx.fact_store.read().await;
        let fact = store.get(fact_id).unwrap();
        assert!(fact.private, "reserved-prefix facts must be born private");
    }

    #[tokio::test]
    async fn store_fact_passport_rejects_every_create_reserved_entity_prefix() {
        let map = crate::agent_passport::AgentPassportMap::builtin_default();
        let ctx = test_ctx().with_agent_passports(true, map).with_agent(AgentIdentity {
            name: "openai".to_string(),
            token_hash: [7u8; 32],
        });
        seed_passport(&ctx, "codex-work", "work").await;
        let before_ids: std::collections::BTreeSet<String> = ctx
            .fact_store
            .read()
            .await
            .all_facts()
            .map(|fact| fact.fact_id.clone())
            .collect();

        for prefix in corecrux_memory::fact_privacy::DAEMON_OWNED_ENTITY_PREFIXES
            .iter()
            .chain(corecrux_memory::fact_privacy::GENERIC_CREATE_RESERVED_PREFIXES)
        {
            let entity = format!("{prefix}attacker");
            let err = handle_store_fact(&json!({"entity": entity, "key": "state", "value": "attacker"}), &ctx)
                .await
                .unwrap_err();
            assert_eq!(err.code, INVALID_PARAMS);
            assert_eq!(
                err.data.as_ref().and_then(|data| data["error_code"].as_str()),
                Some("RESERVED_ENTITY_PREFIX")
            );
            assert_eq!(
                err.data.as_ref().and_then(|data| data["entity"].as_str()),
                Some(entity.as_str())
            );
        }

        let after_ids: std::collections::BTreeSet<String> = ctx
            .fact_store
            .read()
            .await
            .all_facts()
            .map(|fact| fact.fact_id.clone())
            .collect();
        assert_eq!(after_ids, before_ids, "client attempts must not persist any facts");
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
        // M5: a flag-ON write requires a minted passport with a category.
        seed_passport(&ctx, "claude-work", "work").await;
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
        seed_passport(&ctx, "codex-work", "work").await;
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
        // Unmapped agent → identity falls back to the raw name `windows-host`;
        // mint that passport so the M5 enforcement can resolve its category.
        seed_passport(&ctx, "windows-host", "work").await;
        let result = handle_store_fact(&json!({"entity": "proj", "key": "k", "value": "v"}), &ctx)
            .await
            .unwrap();
        assert_eq!(stored_actor(&ctx, &result).await, Some("windows-host".to_string()));
    }

    #[tokio::test]
    async fn store_fact_two_aliased_tokens_resolve_to_one_principal() {
        // Continuity-substrate M0 gate (crux-agent-passport-binding M0.2/M0.3):
        // two DISTINCT agent tokens (distinct names, distinct token hashes)
        // aliased to ONE passport_id must stamp the SAME principal on their
        // facts — the lever that makes the cross-provider demo prove
        // provider-portability rather than a same-token tautology. A third,
        // differently-mapped token must stay distinct (no accidental collision).
        let map = crate::agent_passport::AgentPassportMap::from_pairs_str(
            "anthropic:demo-principal:work,openai:demo-principal:work,tailnet:other-principal:work",
        );

        let base = test_ctx();
        seed_passport(&base, "demo-principal", "work").await;
        seed_passport(&base, "other-principal", "work").await;

        let token_a = base
            .with_agent(AgentIdentity {
                name: "anthropic".to_string(),
                token_hash: [0u8; 32],
            })
            .with_agent_passports(true, map.clone());
        let token_b = base
            .with_agent(AgentIdentity {
                name: "openai".to_string(),
                token_hash: [2u8; 32],
            })
            .with_agent_passports(true, map.clone());
        let token_c = base
            .with_agent(AgentIdentity {
                name: "tailnet".to_string(),
                token_hash: [4u8; 32],
            })
            .with_agent_passports(true, map);

        // Both aliased tokens resolve to one scope identity (private-fact
        // ownership) and stamp one actor (fact attribution).
        assert_eq!(token_a.scope_identity().as_deref(), Some("demo-principal"));
        assert_eq!(token_a.scope_identity(), token_b.scope_identity());
        assert_ne!(token_b.scope_identity(), token_c.scope_identity());

        let result_a = handle_store_fact(&json!({"entity": "proj", "key": "ka", "value": "va"}), &token_a)
            .await
            .unwrap();
        let result_b = handle_store_fact(&json!({"entity": "proj", "key": "kb", "value": "vb"}), &token_b)
            .await
            .unwrap();
        let result_c = handle_store_fact(&json!({"entity": "proj", "key": "kc", "value": "vc"}), &token_c)
            .await
            .unwrap();

        let actor_a = stored_actor(&token_a, &result_a).await;
        let actor_b = stored_actor(&token_b, &result_b).await;
        let actor_c = stored_actor(&token_c, &result_c).await;
        assert_eq!(actor_a, Some("demo-principal".to_string()));
        assert_eq!(actor_a, actor_b, "two aliased tokens must share one principal");
        assert_eq!(
            actor_c,
            Some("other-principal".to_string()),
            "a differently-mapped token must stay distinct"
        );
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

    /// Two distinct actors (claude-work, codex-work) write facts into their
    /// shared `work` tenant via the flag-ON path; a third writes with the flag
    /// OFF into `default` (legacy actor=None). `query_facts` rows must carry
    /// the correct actor without crossing the tenant boundary.
    #[tokio::test]
    async fn query_facts_rows_carry_actor_and_preserve_tenant_isolation() {
        let map = crate::agent_passport::AgentPassportMap::builtin_default();

        // Shared base context (single fact store, Arc-shared by every
        // derived context below). `base` stays valid for the shared read.
        let base = test_ctx();
        // M5: mint the two work passports so their flag-ON writes pass
        // enforcement. Both write `work`-category entities (the default).
        seed_passport(&base, "claude-work", "work").await;
        seed_passport(&base, "codex-work", "work").await;

        // claude-work writes a decision (flag ON, anthropic → claude-work).
        let claude = base
            .with_agent(AgentIdentity {
                name: "anthropic".to_string(),
                token_hash: [0u8; 32],
            })
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
            .with_agent(AgentIdentity {
                name: "openai".to_string(),
                token_hash: [2u8; 32],
            })
            .with_agent_passports(true, map.clone());
        handle_store_fact(
            &json!({"entity": "bench:y", "key": "metric", "value": "needle-codex"}),
            &codex,
        )
        .await
        .unwrap();

        // Legacy / flag-OFF write — actor must be null on read.
        let legacy = base.with_agent(AgentIdentity {
            name: "legacy".to_string(),
            token_hash: [9u8; 32],
        });
        assert!(!legacy.agent_passports_enabled, "legacy write must be flag-OFF");
        handle_store_fact(
            &json!({"entity": "legacy:z", "key": "k", "value": "needle-legacy"}),
            &legacy,
        )
        .await
        .unwrap();

        // A work-tenant read sees both attributed collaborators, but not the
        // legacy fact in `default`.
        let res = handle_query_facts(&json!({"query": "needle", "token_budget": 500}), &claude)
            .await
            .unwrap();
        let rows = res["structuredContent"]["rows"].as_array().unwrap();

        let actor_for = |value: &str| -> Value {
            rows.iter()
                .find(|r| r["value"].as_str() == Some(value))
                .unwrap_or_else(|| panic!("row for {value} missing — shared visibility regressed"))["actor"]
                .clone()
        };

        assert_eq!(actor_for("needle-claude"), json!("claude-work"));
        assert_eq!(actor_for("needle-codex"), json!("codex-work"));
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|row| row["value"] != "needle-legacy"));

        // The legacy/default read sees only its own fact, with actor null.
        let res = handle_query_facts(&json!({"query": "needle", "token_budget": 500}), &base)
            .await
            .unwrap();
        let rows = res["structuredContent"]["rows"].as_array().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["value"], "needle-legacy");
        assert_eq!(rows[0]["actor"], Value::Null);
    }

    #[tokio::test]
    async fn fact_history_text_includes_actor() {
        let map = crate::agent_passport::AgentPassportMap::builtin_default();
        let claude = test_ctx().with_agent_passports(true, map).with_agent(AgentIdentity {
            name: "anthropic".to_string(),
            token_hash: [0u8; 32],
        });
        seed_passport(&claude, "claude-work", "work").await;
        handle_store_fact(
            &json!({"entity": "execplan:h", "key": "decision:x", "value": "v1"}),
            &claude,
        )
        .await
        .unwrap();

        let res = handle_fact_history(&json!({"entity": "execplan:h", "key": "decision:x"}), &claude)
            .await
            .unwrap();
        let text = res["content"][0]["text"].as_str().unwrap();
        assert!(
            text.contains("actor=claude-work"),
            "history line should attribute the writer: {text}"
        );

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
        let result = handle_query_facts(&json!({"query": "hidden", "contract": "legacy"}), &agent_ctx)
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
    async fn delete_fact_hides_invisible_control_record() {
        let ctx = test_ctx();
        let fact_id = {
            let mut store = ctx.fact_store.write().await;
            store
                .store(StoreFact {
                    tenant_hash: "default".to_string(),
                    entity: "__passport__::victim".to_string(),
                    key: "record".to_string(),
                    value: "trusted".to_string(),
                    source_receipt: None,
                    confidence: 1.0,
                    private: true,
                    horizon_class: None,
                    actor: None,
                })
                .fact_id
        };

        let result = handle_delete_fact(&json!({"fact_id": fact_id}), &ctx)
            .await
            .expect("hidden records use not-found behavior");
        assert!(result["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("fact not found"));
        assert!(!ctx.fact_store.read().await.get(&fact_id).unwrap().deleted);
    }

    #[tokio::test]
    async fn delete_fact_rejects_visible_wrapped_control_record() {
        let ctx = test_ctx();
        let alice = ctx.with_agent(AgentIdentity {
            name: "alice".to_string(),
            token_hash: [0u8; 32],
        });
        let fact_id = {
            let mut store = ctx.fact_store.write().await;
            store
                .store(StoreFact {
                    tenant_hash: "default".to_string(),
                    entity: "__agent::alice::__passport__::victim".to_string(),
                    key: "record".to_string(),
                    value: "trusted".to_string(),
                    source_receipt: None,
                    confidence: 1.0,
                    private: true,
                    horizon_class: None,
                    actor: None,
                })
                .fact_id
        };

        let err = handle_delete_fact(&json!({"fact_id": fact_id}), &alice)
            .await
            .expect_err("generic delete must not mutate logical control records");
        assert_eq!(err.code, crate::dispatch::CAPABILITY_DENIED);
        assert_eq!(
            err.data.as_ref().and_then(|data| data["error_code"].as_str()),
            Some("RESERVED_ENTITY_PREFIX")
        );
        assert!(!ctx.fact_store.read().await.get(&fact_id).unwrap().deleted);
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
        // Bootstrap knowledge is seeded by the owning daemon workflow, not
        // through the generic store_fact boundary.
        {
            let mut store = ctx.fact_store.write().await;
            for (entity, key, value) in [
                ("__bootstrap__::pattern:retry", "Retry Pattern", "exponential backoff"),
                ("__bootstrap__::resolution:oom", "OOM Recovery", "increase memory"),
                (
                    "__bootstrap__::doc:onboarding",
                    "Human-Assisted Integration",
                    "share the HTTP and MCP endpoints with the operator",
                ),
            ] {
                store.store(StoreFact {
                    tenant_hash: "default".to_string(),
                    entity: entity.to_string(),
                    key: key.to_string(),
                    value: value.to_string(),
                    source_receipt: None,
                    confidence: 1.0,
                    private: true,
                    horizon_class: None,
                    actor: Some("daemon:bootstrap".to_string()),
                });
            }
        }
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

        let result = handle_query_facts(
            &json!({"query": "active", "entity": "alpha", "contract": "legacy"}),
            &ctx,
        )
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
            tenant_hash: "default".to_string(),
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
            valid_from: None,
            valid_to: None,
            access_count: 0,
            last_accessed_at: None,
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

    // ── M7 (P2): min_effective_confidence floor + filtered_below_threshold ──

    #[tokio::test]
    async fn query_facts_min_effective_confidence_filters_stale_and_counts() {
        let ctx = test_ctx();
        let now = Utc::now();
        {
            let mut store = ctx.fact_store.write().await;
            // STALE conf 1.0 → effective 0.5 (below a 0.6 floor).
            store.store_synced(synth_fact(
                "f_stale",
                "deploy",
                "old",
                1.0,
                HorizonClass::Volatile,
                now - Duration::hours(48),
                None,
            ));
            // FRESH conf 1.0 → effective 1.0 (above the floor).
            store.store_synced(synth_fact(
                "f_fresh",
                "deploy",
                "new",
                1.0,
                HorizonClass::Volatile,
                now,
                None,
            ));
        }

        let result = handle_query_facts(&json!({"entity": "deploy", "min_effective_confidence": 0.6}), &ctx)
            .await
            .unwrap();
        let rows = result["structuredContent"]["rows"].as_array().unwrap();
        assert_eq!(rows.len(), 1, "only the fresh fact clears the 0.6 floor");
        assert_eq!(rows[0]["fact_id"], "f_fresh");
        assert_eq!(result["structuredContent"]["filtered_below_threshold"], 1);
    }

    #[tokio::test]
    async fn query_facts_all_below_floor_reports_count_not_empty() {
        let ctx = test_ctx();
        let now = Utc::now();
        {
            let mut store = ctx.fact_store.write().await;
            store.store_synced(synth_fact("f_a", "deploy", "a", 0.4, HorizonClass::None, now, None));
            store.store_synced(synth_fact("f_b", "deploy", "b", 0.3, HorizonClass::None, now, None));
        }

        // Floor above every fact → zero rows, but the count says WHY (2 facts
        // existed, all below threshold) so the caller can skip the LLM path.
        let result = handle_query_facts(&json!({"entity": "deploy", "min_effective_confidence": 0.5}), &ctx)
            .await
            .unwrap();
        assert!(result["structuredContent"]["rows"].as_array().unwrap().is_empty());
        assert_eq!(result["structuredContent"]["filtered_below_threshold"], 2);
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(
            text.contains("below threshold"),
            "text explains the empty result: {text}"
        );
    }

    #[tokio::test]
    async fn query_facts_without_floor_reports_zero_filtered() {
        let ctx = test_ctx();
        let now = Utc::now();
        {
            let mut store = ctx.fact_store.write().await;
            // A very low-confidence fact that WOULD be filtered by a floor, but
            // no floor is set — so it is returned and nothing is filtered.
            store.store_synced(synth_fact("f_low", "deploy", "up", 0.1, HorizonClass::None, now, None));
        }
        let result = handle_query_facts(&json!({"entity": "deploy"}), &ctx).await.unwrap();
        assert_eq!(result["structuredContent"]["rows"].as_array().unwrap().len(), 1);
        assert_eq!(result["structuredContent"]["filtered_below_threshold"], 0);
    }

    #[tokio::test]
    async fn query_facts_rejects_out_of_range_floor() {
        let ctx = test_ctx();
        for bad in [json!(1.5), json!(-0.1)] {
            let err = handle_query_facts(&json!({"entity": "deploy", "min_effective_confidence": bad}), &ctx)
                .await
                .unwrap_err();
            assert_eq!(err.code, INVALID_PARAMS, "floor {bad} must be rejected");
        }
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
        let result = handle_query_facts(&json!({"entity": "alpha", "contract": "legacy"}), &ctx)
            .await
            .unwrap();
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
        assert!(store.get_by_entity("e2").is_empty());
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
    async fn store_fact_cannot_supersede_visible_wrapped_daemon_control_fact() {
        let ctx = test_ctx();
        let alice = ctx.with_agent(AgentIdentity {
            name: "alice".to_string(),
            token_hash: [0u8; 32],
        });
        let control = {
            let mut store = ctx.fact_store.write().await;
            store.store(StoreFact {
                tenant_hash: "default".to_string(),
                entity: "__agent::alice::__passport__::control-record".to_string(),
                key: "state".to_string(),
                value: "trusted".to_string(),
                source_receipt: Some("test:typed-daemon-workflow".to_string()),
                confidence: 1.0,
                private: true,
                horizon_class: None,
                actor: Some("daemon:test".to_string()),
            })
        };

        let err = handle_store_fact(
            &json!({
                "entity": "safe-new-fact",
                "key": "state",
                "value": "attacker-controlled",
                "supersedes": [control.fact_id],
            }),
            &alice,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
        assert_eq!(err.data.as_ref().unwrap()["error_code"], "RESERVED_SUPERSEDES_TARGET");

        let store = ctx.fact_store.read().await;
        assert!(store.get(&control.fact_id).unwrap().superseded_by.is_none());
        assert!(
            store.get_by_entity("safe-new-fact").is_empty(),
            "invalid supersession must reject the new write atomically"
        );
    }

    #[tokio::test]
    async fn store_fact_can_supersede_own_ordinary_private_fact() {
        let ctx = test_ctx();
        let alice = ctx.with_agent(AgentIdentity {
            name: "alice".to_string(),
            token_hash: [0u8; 32],
        });
        let original = handle_store_fact(
            &json!({
                "entity": "notes",
                "key": "state",
                "value": "draft",
                "private": true,
            }),
            &alice,
        )
        .await
        .unwrap();
        let original_id = fact_id_of(&original);

        handle_store_fact(
            &json!({
                "entity": "notes-v2",
                "key": "state",
                "value": "final",
                "private": true,
                "supersedes": [original_id],
            }),
            &alice,
        )
        .await
        .expect("owner can supersede an ordinary private fact");

        assert!(ctx
            .fact_store
            .read()
            .await
            .get(&original_id)
            .unwrap()
            .superseded_by
            .is_some());
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
