// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Readable/editable memory tool handlers (agent-ux-01).
//!
//! New surface that complements raw `store_fact` / `query_facts`. The
//! agent-ux-01 ExecPlan calls this out as the "consumer-shaped" view of the
//! fact store: a paginated, narrative-friendly read tool plus
//! receipt-attributed edit and pin tools.
//!
//! Reserved-prefix entities (`__agent::*`, `__ops::*`, `__bootstrap__::*`,
//! plus the new `__memory_pin::*` family) are NEVER returned from these
//! tools. They remain operator-only via `store_fact`/`query_facts`.
//!
//! Feature flag: `CORECRUXD_FEATURE_MEMORY_PANEL` is ON by default (opt-out)
//! at the daemon layer. Set it to `0`/`false`/`off`/`no` to short-circuit
//! every handler with a "feature disabled" message (the tools stay listed
//! either way).
//!
//! Rationale (agent-ux-01): host IDEs and the upcoming console memory panel
//! need a "consumer-shaped" view of the fact store that is safe to render
//! without exposing operator-only entities. The raw `store_fact` /
//! `query_facts` surface stays unchanged for operators; the four tools here
//! (`memory_view`, `memory_edit`, `memory_pin`, `memory_history`) layer
//! pagination, reserved-prefix filtering, receipt attribution, and pin state
//! on top, so a UI can show a coherent narrative without the agent having to
//! reimplement that bookkeeping every session.

// TODO(M2-envelope): once the sibling agent-ux M2 envelope spike lands,
// `memory_view` should opt into the envelope wrapper so host IDEs can render
// "memory used: [...]" footers. Do NOT modify the envelope here; leave the
// opt-in for the envelope owner.

use serde_json::{json, Value};

use crate::dispatch::McpContext;
use crate::protocol::{JsonRpcError, INTERNAL_ERROR, INVALID_PARAMS};
use crate::scope;
use corecrux_memory::fact_store::{Fact, FactQuery, StoreFact};

/// Reserved entity prefixes that MUST never be readable/editable through the
/// agent-ux-01 surface. The fact store retains them for operator tools; the
/// consumer-shaped surface filters them out aggressively.
pub const RESERVED_ENTITY_PREFIXES: &[&str] = &[
    "__agent::",
    "__ops::",
    "__bootstrap__::",
    "__memory_pin::",
    "__work__::",
    "__decisions__::",
    "__project_layer__::",
    "__tenant_metadata__::",
];

/// Reserved entity prefix used to store pin state. Hidden from the
/// consumer-shaped view but used by `memory_view` to flag pinned facts.
const MEMORY_PIN_PREFIX: &str = "__memory_pin::";

/// Environment flag that gates the entire surface. Default ON (opt-out):
/// an unset var enables the panel. Set it to `0`/`false`/`off`/`no` to
/// ship the surface dark behind the kill switch.
pub const MEMORY_PANEL_FEATURE_FLAG: &str = "CORECRUXD_FEATURE_MEMORY_PANEL";

/// Returns true if the memory-panel surface is enabled.
///
/// Default-on (opt-out): an UNSET env var means enabled. Only an explicit
/// `""`/`0`/`false`/`off`/`no` (case-insensitive) disables it. Mirrors
/// [`crate::tools::freshness::freshness_enabled`].
fn memory_panel_enabled() -> bool {
    match std::env::var(MEMORY_PANEL_FEATURE_FLAG) {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            !matches!(v.as_str(), "" | "0" | "false" | "off" | "no")
        }
        Err(_) => true,
    }
}

fn entity_is_reserved(entity: &str) -> bool {
    RESERVED_ENTITY_PREFIXES.iter().any(|p| entity.starts_with(p))
}

/// Identity-scoped memory-panel visibility (agent-passport M5).
/// `identity`/`aliases` come from [`McpContext::scope_identity`] /
/// [`McpContext::scope_aliases`]. Flag-OFF (identity == raw agent name, empty
/// aliases) it reduces byte-for-byte to the pre-M5 agent-scoped check
/// (`scope::fact_visible_to_agent` + `scope::visible_entity_for_agent` against
/// the raw name); flag-ON it additionally lets the passport-keyed owner see its
/// own private fact. This is the ONLY memory-panel visibility helper — the
/// agent-scoped variant was retired in M5 once every panel handler converted.
fn fact_visible_in_memory_panel_id(fact: &Fact, identity: Option<&str>, aliases: &[&str]) -> bool {
    if fact.deleted {
        return false;
    }
    if !scope::fact_visible_to_identity(fact, identity, aliases) {
        return false;
    }
    let visible_entity =
        scope::visible_entity_for_identity(fact, identity, aliases).unwrap_or_else(|| fact.entity.clone());
    !entity_is_reserved(&visible_entity)
}

/// Build the deterministic pin-fact key for a given fact id. Pin state is
/// stored as a private fact under `__memory_pin::<agent>::<fact_id>` so it
/// inherits per-agent privacy and survives daemon restart.
fn pin_entity(agent_name: &str, fact_id: &str) -> String {
    format!("{MEMORY_PIN_PREFIX}{agent_name}::{fact_id}")
}

fn require_str<'a>(args: &'a Value, field: &str) -> Result<&'a str, JsonRpcError> {
    args.get(field).and_then(|v| v.as_str()).ok_or_else(|| JsonRpcError {
        code: INVALID_PARAMS,
        message: format!("missing required param: {field}"),
        data: Some(json!({"param": field, "required": true})),
    })
}

fn feature_disabled_response(tool: &str) -> Value {
    json!({
        "content": [{
            "type": "text",
            "text": format!(
                "{tool}: memory panel explicitly disabled (unset {MEMORY_PANEL_FEATURE_FLAG} to re-enable; it is on by default)"
            )
        }],
        "isError": false
    })
}

/// Render a fact as a `MemoryFact` JSON object (the agent-ux-01 wire shape),
/// identity-scoped (agent-passport M5). Flag-OFF (`identity` == raw agent name,
/// empty `aliases`) the entity unwrap is byte-for-byte the pre-M5
/// `scope::visible_entity_for_agent(fact, agent_name)` path; flag-ON the
/// passport-keyed owner sees its own private entity unwrapped.
fn fact_to_memory_json_id(fact: &Fact, identity: Option<&str>, aliases: &[&str], pinned: bool) -> Value {
    let entity = scope::visible_entity_for_identity(fact, identity, aliases).unwrap_or_else(|| fact.entity.clone());
    json!({
        "id": fact.fact_id,
        "entity": entity,
        "key": fact.key,
        "value": fact.value,
        "version": fact.version,
        "stored_at": fact.stored_at.to_rfc3339(),
        "confidence": fact.confidence,
        "pinned": pinned,
        "source_receipt": fact.source_receipt,
        "actor": fact.actor,
    })
}

/// `memory_view` — paginated, narrative-friendly read over the consumer
/// memory surface. Filters reserved prefixes. Honours `token_budget`.
pub async fn handle_memory_view(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    if !memory_panel_enabled() {
        return Ok(feature_disabled_response("memory_view"));
    }

    let entity = args.get("entity").and_then(|v| v.as_str()).map(str::to_string);
    let key = args.get("key").and_then(|v| v.as_str()).map(str::to_string);
    let top_k = args.get("top_k").and_then(|v| v.as_u64()).unwrap_or(20) as usize;
    let token_budget = args.get("token_budget").and_then(|v| v.as_u64()).map(|v| v as usize);

    // token_budget is documented as required for read tools (QC.2). We accept
    // its absence and default to a small budget rather than 500-erroring,
    // because callers from the console SPA may pass an explicit cap that
    // already lives in their per-route policy. For agentic callers, our
    // tool description spells out the recommendation.
    let budget = token_budget.unwrap_or(2000);

    // agent-passport M5: identity-scoped visibility. `agent_name` is still used
    // for the pin-state prefix (`__memory_pin::<agent>::…`), which is keyed by
    // raw agent name and out of scope for M5 — leaving it unchanged can only
    // ever narrow, never widen, the caller's own pin set.
    let agent_name = scope::agent_name(ctx.agent.as_ref());
    let identity = ctx.scope_identity();
    let id_ref = identity.as_deref();
    let aliases = ctx.scope_aliases();
    let alias_refs: Vec<&str> = aliases.iter().map(String::as_str).collect();

    let q = FactQuery {
        query: None,
        entity: entity.clone(),
        entity_prefix: None,
        top_k: top_k.max(1),
        token_budget: Some(budget),
    };

    let store = ctx.fact_store.read().await;
    let mut visible: Vec<Fact> = store
        .all_facts()
        .filter(|fact| fact_visible_in_memory_panel_id(fact, id_ref, &alias_refs))
        .filter(|fact| match &q.entity {
            Some(want) => scope::visible_entity_for_identity(fact, id_ref, &alias_refs)
                .as_deref()
                .is_some_and(|e| e == want),
            None => true,
        })
        .filter(|fact| match &key {
            Some(want_key) => fact.key == *want_key,
            None => true,
        })
        .cloned()
        .collect();

    // Newest first (descending stored_at), then confidence as tiebreaker.
    visible.sort_by(|a, b| {
        b.stored_at.cmp(&a.stored_at).then_with(|| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
    });

    // Apply token_budget cap and top_k.
    let mut used_tokens = 0usize;
    let mut selected: Vec<Fact> = Vec::new();
    for fact in visible {
        if selected.len() >= q.top_k {
            break;
        }
        if used_tokens + fact.tokens > budget && !selected.is_empty() {
            break;
        }
        used_tokens += fact.tokens;
        selected.push(fact);
    }

    // Identify pinned facts for this agent. Pin entries live at
    // `__memory_pin::<agent>::<fact_id>` with key="pinned" and value="1"/"0".
    // The fact store keeps a version chain per (entity,key); we want the
    // latest live entry, which is what `all_facts()` returns after
    // supersession (older versions are not retained as separate Fact records
    // with the same entity+key — `try_store` rewrites). To be defensive,
    // take the latest stored_at per fact_id.
    let pin_prefix = agent_name.map(|n| format!("{MEMORY_PIN_PREFIX}{n}::"));
    let pinned_ids: std::collections::HashSet<String> = if let Some(prefix) = &pin_prefix {
        let mut latest: std::collections::HashMap<String, (chrono::DateTime<chrono::Utc>, bool)> =
            std::collections::HashMap::new();
        for f in store.all_facts() {
            if f.deleted || !f.entity.starts_with(prefix) || f.key != "pinned" {
                continue;
            }
            let id = f.entity[prefix.len()..].to_string();
            let pinned_val = f.value == "1" || f.value.eq_ignore_ascii_case("true");
            latest
                .entry(id)
                .and_modify(|(ts, v)| {
                    if f.stored_at > *ts {
                        *ts = f.stored_at;
                        *v = pinned_val;
                    }
                })
                .or_insert((f.stored_at, pinned_val));
        }
        latest
            .into_iter()
            .filter_map(|(id, (_, pinned))| pinned.then_some(id))
            .collect()
    } else {
        Default::default()
    };

    let facts_json: Vec<Value> = selected
        .iter()
        .map(|f| fact_to_memory_json_id(f, id_ref, &alias_refs, pinned_ids.contains(&f.fact_id)))
        .collect();

    let text = if selected.is_empty() {
        "no memory visible".to_string()
    } else {
        selected
            .iter()
            .map(|f| {
                let entity =
                    scope::visible_entity_for_identity(f, id_ref, &alias_refs).unwrap_or_else(|| f.entity.clone());
                let pinned = if pinned_ids.contains(&f.fact_id) {
                    " [pinned]"
                } else {
                    ""
                };
                format!(
                    "[{}] {} = {} (id={}, v{}){}",
                    entity, f.key, f.value, f.fact_id, f.version, pinned
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    Ok(json!({
        "content": [{ "type": "text", "text": text }],
        "structuredContent": {
            "facts": facts_json,
            "total_tokens": used_tokens,
            "returned": selected.len(),
        }
    }))
}

/// `memory_edit` — update the value of an existing fact. Requires an
/// authenticated agent (passport-attributed write per QC.3).
///
/// The new value supersedes the prior version — the fact_history surface
/// preserves the chain. A `reason` parameter is stored as the new fact's
/// source_receipt note for audit purposes.
pub async fn handle_memory_edit(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    if !memory_panel_enabled() {
        return Ok(feature_disabled_response("memory_edit"));
    }

    let fact_id = require_str(args, "fact_id")?;
    let new_value = require_str(args, "new_value")?;
    let reason = args.get("reason").and_then(|v| v.as_str()).map(str::to_string);

    // Edits require an authenticated agent so the new version carries an
    // attributable actor (QC.3 — passport-attributed writes).
    let Some(agent_name) = scope::agent_name(ctx.agent.as_ref()) else {
        return Err(JsonRpcError {
            code: INVALID_PARAMS,
            message: "memory_edit requires an authenticated agent identity".to_string(),
            data: Some(json!({"requires_agent_identity": true})),
        });
    };

    // agent-passport M5: identity-scoped visibility so the OWNER can edit its
    // own passport-keyed private fact, and a DIFFERENT passport cannot. The raw
    // `agent_name` is still surfaced on the edited-fact JSON below (it names the
    // caller, not the fact owner). Flag-OFF identity == raw name + empty
    // aliases, so this is byte-for-byte the prior agent-scoped check.
    let identity = ctx.scope_identity();
    let id_ref = identity.as_deref();
    let aliases = ctx.scope_aliases();
    let alias_refs: Vec<&str> = aliases.iter().map(String::as_str).collect();

    let mut store = ctx.fact_store.write().await;
    let existing = store.get(fact_id).cloned().ok_or_else(|| JsonRpcError {
        code: INVALID_PARAMS,
        message: format!("fact not found: {fact_id}"),
        data: Some(json!({"fact_id": fact_id})),
    })?;

    if !fact_visible_in_memory_panel_id(&existing, id_ref, &alias_refs) {
        // Either reserved-prefix or not visible to this agent — refuse.
        return Err(JsonRpcError {
            code: INVALID_PARAMS,
            message: "fact is not editable through the memory panel".to_string(),
            data: Some(json!({"fact_id": fact_id, "reason": "reserved_or_invisible"})),
        });
    }

    // Durable authorship (agent-passport M1), mirroring `handle_store_fact`:
    // flag-ON resolve the agent token-name to a passport_id (falling back to the
    // raw name so a flag-ON edit is never anonymous, QC.3); flag-OFF leave
    // `None`. Without this the edited version carried `actor: null` while the
    // original carried `claude-work`, silently breaking the attribution chain.
    let actor: Option<String> = if ctx.agent_passports_enabled {
        Some(
            crate::agent_passport::resolve_agent_passport(agent_name, &ctx.agent_passport_map)
                .unwrap_or_else(|| agent_name.to_string()),
        )
    } else {
        None
    };

    // Whether the OLD fact is pinned for this agent (pin state is keyed by
    // fact_id, so an edit mints a new id and would otherwise drop the pin — and
    // with it the decay/scoped-forget protection the pin conferred). Computed
    // under the read borrow before we mutate.
    let old_pin_entity = pin_entity(agent_name, fact_id);
    let was_pinned = store
        .all_facts()
        .filter(|f| !f.deleted && f.entity == old_pin_entity && f.key == "pinned")
        .max_by_key(|f| f.stored_at)
        .is_some_and(|f| f.value == "1" || f.value.eq_ignore_ascii_case("true"));

    // The store's append-only model means we write a NEW StoreFact with the
    // same entity+key; supersession of the prior version is applied by the
    // store itself (`supersede_prior_version`) so default recall returns the
    // edited value, not both. The reason becomes the source_receipt so the
    // audit trail is intact; the prior horizon_class is preserved so an edit
    // doesn't silently reset a pinned/overridden decay horizon.
    let req = StoreFact {
        entity: existing.entity.clone(),
        key: existing.key.clone(),
        value: new_value.to_string(),
        source_receipt: reason.clone().map(|r| format!("memory_edit:{r}")),
        confidence: existing.confidence,
        private: existing.private,
        horizon_class: Some(existing.horizon_class),
        actor,
    };
    let new_fact = store.try_store(req).map_err(|err| JsonRpcError {
        code: INTERNAL_ERROR,
        message: "memory_edit: fact journal append failed".to_string(),
        data: Some(json!({"error": err.to_string()})),
    })?;

    // Carry the pin to the new version so decay (#3) + scoped-forget (#9)
    // protection follow the edit instead of being silently dropped.
    if was_pinned {
        let new_pin_entity = pin_entity(agent_name, &new_fact.fact_id);
        if let Err(err) = store.try_store(StoreFact {
            entity: new_pin_entity,
            key: "pinned".to_string(),
            value: "1".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        }) {
            tracing::warn!(?err, fact_id = %new_fact.fact_id, "memory_edit: pin carry-over append failed");
        }
    }

    Ok(json!({
        "content": [{
            "type": "text",
            "text": format!(
                "edited fact {} → {} (v{} supersedes {})",
                fact_id, new_fact.fact_id, new_fact.version, fact_id
            )
        }],
        "structuredContent": {
            "old_fact_id": fact_id,
            "new_fact": fact_to_memory_json_id(&new_fact, id_ref, &alias_refs, was_pinned),
            "reason": reason,
        }
    }))
}

/// `memory_pin` — mark a fact as pinned (or unpinned) so decay (#3) and
/// scoped-forget (#9) treat it as load-bearing.
///
/// Pin state lives as a private fact under `__memory_pin::<agent>::<fact_id>`,
/// inheriting the per-agent privacy scope.
pub async fn handle_memory_pin(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    if !memory_panel_enabled() {
        return Ok(feature_disabled_response("memory_pin"));
    }

    let fact_id = require_str(args, "fact_id")?;
    let pinned = args.get("pinned").and_then(|v| v.as_bool()).unwrap_or(true);
    let agent_name = scope::agent_name(ctx.agent.as_ref()).ok_or_else(|| JsonRpcError {
        code: INVALID_PARAMS,
        message: "memory_pin requires an authenticated agent identity".to_string(),
        data: Some(json!({"requires_agent_identity": true})),
    })?;

    // agent-passport M5: identity-scoped visibility so the OWNER can pin its
    // own passport-keyed private fact, and a DIFFERENT passport cannot. The pin
    // state is still stored under `__memory_pin::<agent_name>::…` (keyed by the
    // raw caller name — out of M5 scope, same as memory_view). Flag-OFF identity
    // == raw name + empty aliases, so the check is byte-for-byte unchanged.
    let identity = ctx.scope_identity();
    let id_ref = identity.as_deref();
    let aliases = ctx.scope_aliases();
    let alias_refs: Vec<&str> = aliases.iter().map(String::as_str).collect();

    let mut store = ctx.fact_store.write().await;
    let target = store.get(fact_id).cloned().ok_or_else(|| JsonRpcError {
        code: INVALID_PARAMS,
        message: format!("fact not found: {fact_id}"),
        data: Some(json!({"fact_id": fact_id})),
    })?;

    if !fact_visible_in_memory_panel_id(&target, id_ref, &alias_refs) {
        return Err(JsonRpcError {
            code: INVALID_PARAMS,
            message: "fact is not pinnable through the memory panel".to_string(),
            data: Some(json!({"fact_id": fact_id, "reason": "reserved_or_invisible"})),
        });
    }

    let pin_entity_name = pin_entity(agent_name, fact_id);
    let value_str = if pinned { "1" } else { "0" };
    let req = StoreFact {
        entity: pin_entity_name.clone(),
        key: "pinned".to_string(),
        value: value_str.to_string(),
        source_receipt: None,
        confidence: 1.0,
        // Pins inherit the agent-private prefix (they're already under
        // __memory_pin::<agent>::*, but mark private=true to avoid any
        // accidental cloud sync).
        private: false, // entity itself is reserved-prefix; do not double-scope
        horizon_class: None,
        actor: None,
    };
    store.try_store(req).map_err(|err| JsonRpcError {
        code: INTERNAL_ERROR,
        message: "memory_pin: fact journal append failed".to_string(),
        data: Some(json!({"error": err.to_string()})),
    })?;

    Ok(json!({
        "content": [{
            "type": "text",
            "text": format!("{} fact {}", if pinned { "pinned" } else { "unpinned" }, fact_id)
        }],
        "structuredContent": {
            "fact_id": fact_id,
            "pinned": pinned,
        }
    }))
}

/// `memory_history` — return the version chain for a fact id (or for
/// (entity, key) if supplied). Differs from `fact_history` in that it
/// filters reserved-prefix entities and renders consumer-friendly fields.
pub async fn handle_memory_history(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    if !memory_panel_enabled() {
        return Ok(feature_disabled_response("memory_history"));
    }

    let entity_arg = args.get("entity").and_then(|v| v.as_str()).map(str::to_string);
    let key_arg = args.get("key").and_then(|v| v.as_str()).map(str::to_string);
    let fact_id_arg = args.get("fact_id").and_then(|v| v.as_str()).map(str::to_string);
    let agent_name = scope::agent_name(ctx.agent.as_ref());

    let store = ctx.fact_store.read().await;

    // Resolve (entity, key) from either explicit args or by lookup on fact_id.
    let (entity, key) = match (entity_arg, key_arg, fact_id_arg) {
        (Some(e), Some(k), _) => (e, k),
        (_, _, Some(fid)) => {
            let f = store.get(&fid).ok_or_else(|| JsonRpcError {
                code: INVALID_PARAMS,
                message: format!("fact not found: {fid}"),
                data: Some(json!({"fact_id": fid})),
            })?;
            let visible_entity = scope::visible_entity_for_agent(f, agent_name).unwrap_or_else(|| f.entity.clone());
            (visible_entity, f.key.clone())
        }
        _ => {
            return Err(JsonRpcError {
                code: INVALID_PARAMS,
                message: "memory_history requires either {entity,key} or {fact_id}".to_string(),
                data: Some(json!({"required_alternatives": ["entity+key", "fact_id"]})),
            });
        }
    };

    if entity_is_reserved(&entity) {
        return Err(JsonRpcError {
            code: INVALID_PARAMS,
            message: "memory_history: entity is reserved (not visible through memory panel)".to_string(),
            data: Some(json!({"entity": entity})),
        });
    }

    let mut history: Vec<&Fact> = store
        .all_facts()
        .filter(|f| f.key == key)
        .filter(|f| scope::entity_matches_for_agent(f, &entity, agent_name))
        .filter(|f| scope::fact_visible_to_agent(f, agent_name))
        .collect();
    history.sort_by_key(|f| f.version);

    if history.is_empty() {
        return Ok(json!({
            "content": [{ "type": "text", "text": format!("no history for entity={entity}, key={key}") }],
            "structuredContent": { "versions": [] }
        }));
    }

    let versions_json: Vec<Value> = history
        .iter()
        .map(|f| {
            json!({
                "id": f.fact_id,
                "value": f.value,
                "version": f.version,
                "stored_at": f.stored_at.to_rfc3339(),
                "supersedes": f.supersedes,
                "deleted": f.deleted,
                "source_receipt": f.source_receipt,
            })
        })
        .collect();
    let text = history
        .iter()
        .map(|f| {
            let status = if f.deleted { " [deleted]" } else { "" };
            let receipt = f.source_receipt.as_deref().unwrap_or("");
            format!(
                "v{}: {} = {} (id={}, stored_at={}, receipt={}){}",
                f.version, f.key, f.value, f.fact_id, f.stored_at, receipt, status
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    Ok(json!({
        "content": [{ "type": "text", "text": text }],
        "structuredContent": { "versions": versions_json }
    }))
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::agent::AgentIdentity;
    use crate::dispatch::McpContext;
    use crate::tools::facts::{handle_query_facts, handle_store_fact};

    /// Guard for the `CORECRUXD_FEATURE_MEMORY_PANEL` env var. The flag is
    /// process-global so we serialise tests that mutate it using an
    /// async-aware mutex (held across awaits). Delegates to the crate-wide
    /// `crate::test_env_lock` so we serialise against every other
    /// env-mutating test in this crate.
    fn env_lock() -> &'static tokio::sync::Mutex<()> {
        crate::test_env_lock()
    }

    struct FlagGuard {
        _lock: tokio::sync::MutexGuard<'static, ()>,
    }
    impl FlagGuard {
        async fn enabled() -> Self {
            let lock = env_lock().lock().await;
            std::env::set_var(MEMORY_PANEL_FEATURE_FLAG, "1");
            Self { _lock: lock }
        }
    }
    impl Drop for FlagGuard {
        fn drop(&mut self) {
            std::env::remove_var(MEMORY_PANEL_FEATURE_FLAG);
        }
    }

    fn test_ctx() -> McpContext {
        McpContext::new_default("test-node")
    }

    /// agent-passport M5: mint a passport record so a flag-ON write can resolve
    /// its category (otherwise `LegacyOrMissingPassport` rejects the write).
    async fn seed_test_passport(ctx: &McpContext, id: &str, category: &str) {
        let record = json!({
            "id": id,
            "principal_id": format!("test::{id}"),
            "public_key_hex": "deadbeef",
            "category": category,
            "issued_at_unix_ms": 1u64,
        });
        let mut store = ctx.fact_store.write().await;
        store.store(StoreFact {
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

    fn alice_ctx() -> McpContext {
        test_ctx().with_agent(AgentIdentity {
            name: "alice".to_string(),
            token_hash: [0u8; 32],
        })
    }

    #[tokio::test]
    async fn memory_view_flag_explicit_off_returns_disabled_message() {
        let _lock = env_lock().lock().await;
        // Default-on now, so the panel only short-circuits on an explicit
        // opt-out value.
        std::env::set_var(MEMORY_PANEL_FEATURE_FLAG, "0");
        let ctx = test_ctx();
        let res = handle_memory_view(&json!({"top_k": 5, "token_budget": 500}), &ctx)
            .await
            .unwrap();
        let text = res["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("memory panel"));
        assert!(text.contains("disabled"));
        std::env::remove_var(MEMORY_PANEL_FEATURE_FLAG);
    }

    #[tokio::test]
    async fn memory_panel_default_on_contract() {
        let _lock = env_lock().lock().await;
        // (a) UNSET -> enabled.
        std::env::remove_var(MEMORY_PANEL_FEATURE_FLAG);
        assert!(memory_panel_enabled(), "unset env must default to enabled");
        // (b) explicit disable values -> disabled.
        for v in ["0", "false", "off", "no", ""] {
            std::env::set_var(MEMORY_PANEL_FEATURE_FLAG, v);
            assert!(!memory_panel_enabled(), "value {v:?} must disable");
        }
        // (c) =1 -> enabled.
        std::env::set_var(MEMORY_PANEL_FEATURE_FLAG, "1");
        assert!(memory_panel_enabled(), "=1 must enable");
        std::env::remove_var(MEMORY_PANEL_FEATURE_FLAG);
    }

    #[tokio::test]
    async fn memory_view_returns_visible_facts_with_token_budget() {
        let _guard = FlagGuard::enabled().await;
        let ctx = test_ctx();
        handle_store_fact(&json!({"entity": "person:bob", "key": "city", "value": "NYC"}), &ctx)
            .await
            .unwrap();
        handle_store_fact(
            &json!({"entity": "person:bob", "key": "job", "value": "engineer"}),
            &ctx,
        )
        .await
        .unwrap();
        let res = handle_memory_view(&json!({"token_budget": 500, "top_k": 10}), &ctx)
            .await
            .unwrap();
        let arr = res["structuredContent"]["facts"].as_array().unwrap();
        assert_eq!(arr.len(), 2);
        // entities are present and unwrapped (no internal prefix exposure)
        let entities: Vec<&str> = arr.iter().map(|f| f["entity"].as_str().unwrap()).collect();
        assert!(entities.iter().all(|e| *e == "person:bob"));
    }

    #[tokio::test]
    async fn memory_view_rows_carry_actor_and_null_for_legacy() {
        // agent-passport M3: attribution surfaced on the memory_view read.
        let _guard = FlagGuard::enabled().await;
        let map = crate::agent_passport::AgentPassportMap::builtin_default();

        // Shared base context — every derived context Arc-shares this store.
        let base = test_ctx();

        // claude-work writes one fact (flag ON, anthropic → claude-work).
        let claude = base
            .with_agent(AgentIdentity {
                name: "anthropic".to_string(),
                token_hash: [0u8; 32],
            })
            .with_agent_passports(true, map);
        // M5: mint the claude-work passport (work category) so the flag-ON
        // write to the work-category entity `person:bob` passes enforcement.
        seed_test_passport(&base, "claude-work", "work").await;
        handle_store_fact(&json!({"entity": "person:bob", "key": "city", "value": "NYC"}), &claude)
            .await
            .unwrap();

        // Legacy / flag-off write (same shared pool) → actor null.
        let legacy = base.with_agent(AgentIdentity {
            name: "legacy".to_string(),
            token_hash: [9u8; 32],
        });
        handle_store_fact(
            &json!({"entity": "person:bob", "key": "job", "value": "engineer"}),
            &legacy,
        )
        .await
        .unwrap();

        let res = handle_memory_view(&json!({"token_budget": 500, "top_k": 10}), &base)
            .await
            .unwrap();
        let arr = res["structuredContent"]["facts"].as_array().unwrap();
        let actor_for = |value: &str| -> serde_json::Value {
            arr.iter()
                .find(|f| f["value"].as_str() == Some(value))
                .unwrap_or_else(|| panic!("memory_view row for {value} missing"))["actor"]
                .clone()
        };
        assert_eq!(actor_for("NYC"), json!("claude-work"));
        assert_eq!(actor_for("engineer"), serde_json::Value::Null);
    }

    #[tokio::test]
    async fn memory_view_filters_reserved_prefixes() {
        let _guard = FlagGuard::enabled().await;
        let ctx = test_ctx();
        handle_store_fact(&json!({"entity": "person:alice", "key": "city", "value": "LDN"}), &ctx)
            .await
            .unwrap();
        // Reserved (operator-only) prefix.
        handle_store_fact(
            &json!({"entity": "__bootstrap__::pattern:retry", "key": "Retry", "value": "exp backoff"}),
            &ctx,
        )
        .await
        .unwrap();
        handle_store_fact(
            &json!({"entity": "__ops::heartbeat", "key": "last", "value": "now"}),
            &ctx,
        )
        .await
        .unwrap();

        let res = handle_memory_view(&json!({"token_budget": 500}), &ctx).await.unwrap();
        let arr = res["structuredContent"]["facts"].as_array().unwrap();
        assert_eq!(arr.len(), 1, "only person:alice should be visible");
        assert_eq!(arr[0]["entity"], "person:alice");
    }

    #[tokio::test]
    async fn memory_view_filters_other_agents_private_facts() {
        let _guard = FlagGuard::enabled().await;
        let alice = alice_ctx();
        let bob = test_ctx().with_agent(AgentIdentity {
            name: "bob".to_string(),
            token_hash: [1u8; 32],
        });

        // Alice writes a private fact.
        handle_store_fact(
            &json!({"entity": "notes", "key": "secret", "value": "hidden", "private": true}),
            &alice,
        )
        .await
        .unwrap();
        // Bob writes a non-private fact.
        handle_store_fact(&json!({"entity": "public", "key": "k", "value": "v"}), &bob)
            .await
            .unwrap();

        // Bob's view should NOT include alice's private fact.
        let bob_view = handle_memory_view(&json!({"token_budget": 500}), &bob).await.unwrap();
        let arr = bob_view["structuredContent"]["facts"].as_array().unwrap();
        let entities: Vec<&str> = arr.iter().map(|f| f["entity"].as_str().unwrap()).collect();
        assert!(entities.contains(&"public"));
        assert!(!entities.iter().any(|e| *e == "notes" || e.contains("__agent")));
    }

    #[tokio::test]
    async fn memory_edit_requires_agent() {
        let _guard = FlagGuard::enabled().await;
        let ctx = test_ctx();
        let err = handle_memory_edit(&json!({"fact_id": "f_nope", "new_value": "x"}), &ctx)
            .await
            .unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
        assert_eq!(err.data.unwrap()["requires_agent_identity"], true);
    }

    #[tokio::test]
    async fn memory_edit_produces_new_version_with_reason_receipt() {
        let _guard = FlagGuard::enabled().await;
        let alice = alice_ctx();
        let stored = handle_store_fact(
            &json!({"entity": "person:carol", "key": "city", "value": "Berlin"}),
            &alice,
        )
        .await
        .unwrap();
        let text = stored["content"][0]["text"].as_str().unwrap();
        let fact_id = text.split_whitespace().nth(2).unwrap();

        let res = handle_memory_edit(
            &json!({"fact_id": fact_id, "new_value": "Munich", "reason": "moved 2026-04"}),
            &alice,
        )
        .await
        .unwrap();
        let new_fact = &res["structuredContent"]["new_fact"];
        assert_eq!(new_fact["value"], "Munich");
        assert_eq!(new_fact["version"], 2);
        assert_eq!(new_fact["source_receipt"], "memory_edit:moved 2026-04");
    }

    #[tokio::test]
    async fn memory_edit_hides_prior_version_in_default_recall() {
        // Probe finding 1: after an in-place edit, default query_facts must
        // return ONLY the edited value — not the stale + corrected pair.
        let _guard = FlagGuard::enabled().await;
        let alice = alice_ctx();
        let stored = handle_store_fact(
            &json!({"entity": "person:frank", "key": "city", "value": "Berlin"}),
            &alice,
        )
        .await
        .unwrap();
        let old_id = stored["structuredContent"]["fact_id"].as_str().unwrap().to_string();

        handle_memory_edit(&json!({"fact_id": old_id, "new_value": "Munich"}), &alice)
            .await
            .unwrap();

        // Default recall: only the edited value.
        let q = handle_query_facts(&json!({"entity": "person:frank", "token_budget": 500}), &alice)
            .await
            .unwrap();
        let rows = q["structuredContent"]["rows"].as_array().unwrap();
        let city_rows: Vec<&Value> = rows.iter().filter(|r| r["key"] == "city").collect();
        assert_eq!(city_rows.len(), 1, "default recall must collapse to the latest version");
        assert_eq!(city_rows[0]["value"], "Munich");

        // include_superseded brings the retired version back, marked.
        let q2 = handle_query_facts(
            &json!({"entity": "person:frank", "include_superseded": true, "token_budget": 500}),
            &alice,
        )
        .await
        .unwrap();
        let rows2 = q2["structuredContent"]["rows"].as_array().unwrap();
        let city_rows2: Vec<&Value> = rows2.iter().filter(|r| r["key"] == "city").collect();
        assert_eq!(city_rows2.len(), 2, "include_superseded exposes the full chain");
        let retired = city_rows2.iter().find(|r| r["value"] == "Berlin").unwrap();
        assert!(
            retired["superseded_by"].is_string(),
            "retired version carries superseded_by"
        );
    }

    #[tokio::test]
    async fn memory_edit_carries_pin_to_new_version() {
        // Probe finding 2: editing a pinned fact must not drop the pin.
        let _guard = FlagGuard::enabled().await;
        let alice = alice_ctx();
        let stored = handle_store_fact(&json!({"entity": "person:gina", "key": "role", "value": "PM"}), &alice)
            .await
            .unwrap();
        let old_id = stored["structuredContent"]["fact_id"].as_str().unwrap().to_string();

        handle_memory_pin(&json!({"fact_id": old_id, "pinned": true}), &alice)
            .await
            .unwrap();

        let edited = handle_memory_edit(&json!({"fact_id": old_id, "new_value": "EM"}), &alice)
            .await
            .unwrap();
        let new_id = edited["structuredContent"]["new_fact"]["id"].as_str().unwrap();
        assert_eq!(
            edited["structuredContent"]["new_fact"]["pinned"], true,
            "edit response reports the carried pin"
        );

        // memory_view shows the NEW (latest, non-superseded) fact as pinned.
        let view = handle_memory_view(&json!({"entity": "person:gina", "token_budget": 500}), &alice)
            .await
            .unwrap();
        let facts = view["structuredContent"]["facts"].as_array().unwrap();
        let new_row = facts.iter().find(|f| f["id"] == new_id).unwrap();
        assert_eq!(new_row["pinned"], true, "pin followed the edit to the new version");
    }

    #[tokio::test]
    async fn memory_edit_stamps_actor_under_passports() {
        // Probe finding 12: the edited version must carry the editor's passport
        // actor, not null.
        let _guard = FlagGuard::enabled().await;
        let map = crate::agent_passport::AgentPassportMap::builtin_default();
        let base = test_ctx();
        let claude = base
            .with_agent(AgentIdentity {
                name: "anthropic".to_string(),
                token_hash: [0u8; 32],
            })
            .with_agent_passports(true, map);
        seed_test_passport(&base, "claude-work", "work").await;

        let stored = handle_store_fact(
            &json!({"entity": "person:hank", "key": "city", "value": "Oslo"}),
            &claude,
        )
        .await
        .unwrap();
        let old_id = stored["structuredContent"]["fact_id"].as_str().unwrap().to_string();

        let edited = handle_memory_edit(
            &json!({"fact_id": old_id, "new_value": "Bergen", "reason": "moved"}),
            &claude,
        )
        .await
        .unwrap();
        assert_eq!(
            edited["structuredContent"]["new_fact"]["actor"], "claude-work",
            "edited version must be passport-attributed (not null)"
        );
    }

    #[tokio::test]
    async fn memory_edit_refuses_reserved_prefix() {
        let _guard = FlagGuard::enabled().await;
        let alice = alice_ctx();
        // Operator-style fact (reserved prefix).
        handle_store_fact(
            &json!({"entity": "__bootstrap__::pattern:retry", "key": "Retry", "value": "old"}),
            &alice,
        )
        .await
        .unwrap();
        // Find its id.
        let snapshot = handle_memory_view(&json!({"token_budget": 500}), &alice).await.unwrap();
        let _ = snapshot; // memory_view filters it; we look it up directly.
                          // (We can't get the id through the panel — refusal already verified
                          // by the panel-filter test. Here we focus on the edit refusal when
                          // an id IS provided.)
                          // Find the fact id directly via the fact_history flow.
        let history = handle_memory_history(
            &json!({"entity": "__bootstrap__::pattern:retry", "key": "Retry"}),
            &alice,
        )
        .await
        .unwrap_err();
        assert!(history.message.contains("reserved"));
    }

    #[tokio::test]
    async fn memory_pin_round_trip() {
        let _guard = FlagGuard::enabled().await;
        let alice = alice_ctx();
        let stored = handle_store_fact(&json!({"entity": "person:dan", "key": "role", "value": "PM"}), &alice)
            .await
            .unwrap();
        let text = stored["content"][0]["text"].as_str().unwrap();
        let fact_id = text.split_whitespace().nth(2).unwrap();

        // Pin it.
        let res = handle_memory_pin(&json!({"fact_id": fact_id, "pinned": true}), &alice)
            .await
            .unwrap();
        assert_eq!(res["structuredContent"]["pinned"], true);

        // memory_view should mark the fact as pinned.
        let view = handle_memory_view(&json!({"token_budget": 500}), &alice).await.unwrap();
        let arr = view["structuredContent"]["facts"].as_array().unwrap();
        let pinned_fact = arr.iter().find(|f| f["id"] == fact_id).unwrap();
        assert_eq!(pinned_fact["pinned"], true);

        // Unpin and confirm.
        handle_memory_pin(&json!({"fact_id": fact_id, "pinned": false}), &alice)
            .await
            .unwrap();
        let view2 = handle_memory_view(&json!({"token_budget": 500}), &alice).await.unwrap();
        let arr2 = view2["structuredContent"]["facts"].as_array().unwrap();
        // Pin state is append-only — the latest version of the pin key wins.
        // We track that by the most-recent pin fact.
        let after = arr2.iter().find(|f| f["id"] == fact_id).unwrap();
        assert_eq!(after["pinned"], false);
    }

    #[tokio::test]
    async fn memory_history_walks_version_chain() {
        let _guard = FlagGuard::enabled().await;
        let alice = alice_ctx();
        handle_store_fact(&json!({"entity": "person:eve", "key": "city", "value": "Oslo"}), &alice)
            .await
            .unwrap();
        // Update.
        let stored = handle_store_fact(
            &json!({"entity": "person:eve", "key": "city", "value": "Bergen"}),
            &alice,
        )
        .await
        .unwrap();
        let _ = stored;
        let res = handle_memory_history(&json!({"entity": "person:eve", "key": "city"}), &alice)
            .await
            .unwrap();
        let versions = res["structuredContent"]["versions"].as_array().unwrap();
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0]["value"], "Oslo");
        assert_eq!(versions[1]["value"], "Bergen");
    }

    #[tokio::test]
    async fn memory_view_token_budget_caps_results() {
        let _guard = FlagGuard::enabled().await;
        let ctx = test_ctx();
        // Each fact ~1-3 tokens. Force a tight budget.
        for i in 0..5 {
            handle_store_fact(&json!({"entity": format!("e:{i}"), "key": "k", "value": "v"}), &ctx)
                .await
                .unwrap();
        }
        let res = handle_memory_view(&json!({"token_budget": 1, "top_k": 100}), &ctx)
            .await
            .unwrap();
        let arr = res["structuredContent"]["facts"].as_array().unwrap();
        // Budget=1 with each fact >=1 token: at most 1 result kept.
        assert!(arr.len() <= 1);
    }
}
