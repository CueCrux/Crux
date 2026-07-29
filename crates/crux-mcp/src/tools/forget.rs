// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Scoped-forget MCP tools: `memory_forget` (mutating) and
//! `memory_forget_dry_run` (read-only preview).
//!
//! Both tools take a TYPED scope enum (`ForgetScopeV1`) — never free-form
//! jq/SQL — and emit a `Forget` receipt body (CBOR, BLAKE3-hashed) at
//! commit time. The downstream v3 dataplane attaches the Ed25519
//! signature event via the existing receipt pipeline.
//!
//! Constraints (ExecPlan agent-ux-09-scoped-forget-2026-05-27):
//! - Scope is the typed enum only.
//! - Passport (i.e. authenticated agent identity at this layer) required
//!   for `memory_forget`. Anonymous callers are rejected with
//!   INVALID_PARAMS so the failure surfaces structured data the operator
//!   can act on.
//! - Reserved prefixes (`__agent::*`, `__ops::*`, `__bootstrap__::*`,
//!   `__agent_session::*`) are filtered out of every scope. Operator-only
//!   override is explicitly out of scope for this child plan.
//! - Dry-run reads only and respects `token_budget` (QC.2).
//! - Feature flag `CORECRUXD_FEATURE_SCOPED_FORGET=1` gates the mutating
//!   tool. Dry-run is always available so users can preview before the
//!   flag flip.

use std::env;

use chrono::{DateTime, Duration, Utc};
use serde_json::{json, Value};

use crate::dispatch::McpContext;
use crate::protocol::{JsonRpcError, INTERNAL_ERROR, INVALID_PARAMS, METHOD_NOT_FOUND};
use crate::scope;
use corecrux_memory::fact_store::Fact;
use corecrux_receipts::{
    blake3_hex, encode_forget_body_v1, ForgetFactRefV1, ForgetReceiptBodyV1, ForgetScopeV1, SCHEMA_FORGET_BODY_V1,
};

/// Feature flag for the mutating `memory_forget` tool.
pub const FEATURE_FLAG_ENV: &str = "CORECRUXD_FEATURE_SCOPED_FORGET";

/// Application error used when an otherwise-valid forget is blocked by a
/// governance legal hold. JSON-RPC reserves -32000..=-32099 for server errors.
const LEGAL_HOLD_ACTIVE_ERROR: i32 = -32044;

/// Reserved entity prefixes that scoped-forget MUST NOT touch through
/// the user-facing surface. Operator-only override is out of scope here.
/// `__memory_pin::` is included so a scope can never erase the pin records
/// themselves (which would defeat the pin-survives-forget guarantee).
const RESERVED_PREFIXES: &[&str] = &[
    "__agent::",
    "__ops::",
    "__bootstrap__::",
    "__agent_session::",
    "__memory_pin::",
];

/// Reserved entity prefix under which per-agent pin state lives. Mirrors
/// [`crate::tools::memory`]'s `MEMORY_PIN_PREFIX`. Pin records are
/// `__memory_pin::<agent>::<fact_id>` with key `"pinned"` and value `"1"`/`"0"`.
const MEMORY_PIN_PREFIX: &str = "__memory_pin::";

/// Default recovery window (free tier) before `PermanentPurge`. Override
/// per-tenant via `CORECRUXD_FORGET_RECOVERY_WINDOW_DAYS`.
const DEFAULT_RECOVERY_WINDOW_DAYS: i64 = 7;

fn feature_enabled() -> bool {
    // Launch default ON — scoped forget (GDPR Art. 17 surface) is available
    // out of the box. It requires an authenticated passport and soft-deletes
    // within a recovery window. Explicit `CORECRUXD_FEATURE_SCOPED_FORGET=0`
    // disables the mutating tool.
    env::var(FEATURE_FLAG_ENV)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(true)
}

fn recovery_window() -> Duration {
    let days = env::var("CORECRUXD_FORGET_RECOVERY_WINDOW_DAYS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(DEFAULT_RECOVERY_WINDOW_DAYS);
    Duration::days(days.max(1))
}

fn parse_scope(args: &Value) -> Result<ForgetScopeV1, JsonRpcError> {
    let scope_val = args.get("scope").ok_or_else(|| JsonRpcError {
        code: INVALID_PARAMS,
        message: "missing required param: scope".to_string(),
        data: Some(json!({"param": "scope", "required": true})),
    })?;
    serde_json::from_value::<ForgetScopeV1>(scope_val.clone()).map_err(|err| JsonRpcError {
        code: INVALID_PARAMS,
        message: format!("invalid scope: {err}"),
        data: Some(json!({
            "param": "scope",
            "accepted_types": [
                "entity_prefix",
                "key_glob",
                "passport_id",
                "before_timestamp",
                "tenant_id",
            ],
            "error": err.to_string(),
        })),
    })
}

fn is_reserved(entity: &str) -> bool {
    RESERVED_PREFIXES.iter().any(|p| entity.starts_with(p))
}

fn glob_matches(glob: &str, candidate: &str) -> bool {
    // Minimal glob: `*` matches any run; literals match literally.
    // Anchored at both ends so the user-visible semantics are
    // unambiguous (no implicit substring match).
    let parts: Vec<&str> = glob.split('*').collect();
    if parts.len() == 1 {
        return candidate == glob;
    }
    let mut idx = 0usize;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if i == 0 {
            if !candidate[idx..].starts_with(part) {
                return false;
            }
            idx += part.len();
        } else if i == parts.len() - 1 {
            if !candidate[idx..].ends_with(part) {
                return false;
            }
        } else {
            match candidate[idx..].find(part) {
                Some(p) => idx += p + part.len(),
                None => return false,
            }
        }
    }
    true
}

fn parse_before_ts(value: &str) -> Result<DateTime<Utc>, JsonRpcError> {
    DateTime::parse_from_rfc3339(value)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|err| JsonRpcError {
            code: INVALID_PARAMS,
            message: format!("before_timestamp must be RFC3339: {err}"),
            data: Some(json!({"param": "scope.value", "format": "RFC3339 / ISO-8601"})),
        })
}

/// Apply a scope filter to a fact. Caller is responsible for filtering by
/// agent visibility *before* this is invoked.
fn scope_matches(scope: &ForgetScopeV1, fact: &Fact, before_ts: Option<DateTime<Utc>>) -> bool {
    match scope {
        ForgetScopeV1::EntityPrefix { value } => fact.entity.starts_with(value),
        ForgetScopeV1::KeyGlob { value } => glob_matches(value, &fact.key),
        ForgetScopeV1::PassportId { value } => {
            // Passport attribution at the FactStore layer is recorded via
            // the `__agent::<name>::` private-entity prefix today. Match
            // facts whose entity is owned by the named agent. (When the
            // agent→passport mapping ExecPlan lands, this widens to a
            // proper passport_id field on Fact.)
            fact.entity.starts_with(&format!("__agent::{value}::"))
        }
        ForgetScopeV1::BeforeTimestamp { .. } => before_ts.is_some_and(|cutoff| fact.stored_at < cutoff),
        ForgetScopeV1::TenantId { value } => {
            // Tenant scope today is encoded into the entity name via
            // `tenant:<id>::` or `personal::<id>::` / `business::<id>::`
            // prefixes. Match either flavour.
            fact.entity.starts_with(&format!("tenant:{value}::"))
                || fact.entity.starts_with(&format!("personal::{value}::"))
                || fact.entity.starts_with(&format!("business::{value}::"))
        }
    }
}

/// Fact ids the caller has pinned (latest pin state == pinned). Pins live
/// under `__memory_pin::<agent>::<fact_id>` (key `"pinned"`), keyed by the
/// caller's RAW agent name (the same keying `memory_pin`/`memory_view` use —
/// out of agent-passport M5 scope). Returns empty for an unauthenticated
/// caller. Used to honour the pin-survives-scoped-forget guarantee.
fn pinned_fact_ids(store: &corecrux_memory::FactStore, agent_name: Option<&str>) -> std::collections::HashSet<String> {
    let Some(agent) = agent_name else {
        return std::collections::HashSet::new();
    };
    let prefix = format!("{MEMORY_PIN_PREFIX}{agent}::");
    let mut latest: std::collections::HashMap<String, (chrono::DateTime<chrono::Utc>, bool)> =
        std::collections::HashMap::new();
    for f in store.all_facts() {
        if f.deleted || !f.entity.starts_with(&prefix) || f.key != "pinned" {
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
    latest.into_iter().filter_map(|(id, (_, p))| p.then_some(id)).collect()
}

#[allow(clippy::too_many_arguments)]
fn resolve_scope<'a>(
    store: &'a corecrux_memory::FactStore,
    scope: &ForgetScopeV1,
    identity: Option<&str>,
    aliases: &[&str],
    agent_name: Option<&str>,
    include_pinned: bool,
    token_budget: Option<usize>,
) -> Vec<&'a Fact> {
    let before_ts = match scope {
        ForgetScopeV1::BeforeTimestamp { value } => parse_before_ts(value).ok(),
        _ => None,
    };
    // agent-passport M5: forget can only ever touch what the caller can SEE —
    // the visibility check is identity-scoped so the OWNER of a passport-keyed
    // private fact can forget its OWN fact, and a DIFFERENT passport still
    // cannot. Flag-OFF `identity` is the raw agent name and `aliases` is empty,
    // so this is byte-for-byte the prior `scope::fact_visible_to_agent` call.
    let mut matches: Vec<&Fact> = store
        .all_facts()
        .filter(|fact| !fact.deleted)
        .filter(|fact| !is_reserved(&fact.entity))
        .filter(|fact| scope::fact_visible_to_identity(fact, identity, aliases))
        .filter(|fact| scope_matches(scope, fact, before_ts))
        .collect();

    // Pinned facts survive scoped-forget (#9) by default: the pin marks a fact
    // load-bearing. `include_pinned: true` overrides this for a true GDPR
    // Art.17 erasure (a pin protects convenience, not a legal-erasure block).
    if !include_pinned {
        let pinned = pinned_fact_ids(store, agent_name);
        if !pinned.is_empty() {
            matches.retain(|fact| !pinned.contains(&fact.fact_id));
        }
    }

    matches.sort_by(|left, right| left.stored_at.cmp(&right.stored_at));

    if let Some(budget) = token_budget {
        let mut used = 0usize;
        let mut selected = Vec::new();
        for fact in matches {
            if used + fact.tokens > budget && !selected.is_empty() {
                break;
            }
            used += fact.tokens;
            selected.push(fact);
            if used >= budget {
                break;
            }
        }
        return selected;
    }
    matches
}

/// Build the `Forget` receipt body for a resolved set of facts.
fn build_receipt_body(
    scope: &ForgetScopeV1,
    passport_id: &str,
    reason: &str,
    facts: &[&Fact],
    tenant_id: &str,
    now: DateTime<Utc>,
) -> ForgetReceiptBodyV1 {
    let recovery_end = now + recovery_window();
    let hash_input = format!(
        "{}|{}|{}|{}|{}",
        passport_id,
        tenant_id,
        scope.render(),
        facts.len(),
        now.to_rfc3339()
    );
    let digest = blake3::hash(hash_input.as_bytes()).to_hex();
    let receipt_id = format!("r_forget_{}", &digest.as_str()[..16]);

    let facts_affected = facts
        .iter()
        .map(|f| ForgetFactRefV1 {
            fact_id: f.fact_id.clone(),
            pre_forget_value_hash_hex: blake3_hex(f.value.as_bytes()),
            entity: f.entity.clone(),
            key: f.key.clone(),
        })
        .collect();

    ForgetReceiptBodyV1 {
        schema: SCHEMA_FORGET_BODY_V1.to_string(),
        receipt_id,
        tenant_id: tenant_id.to_string(),
        passport_id: passport_id.to_string(),
        reason: reason.to_string(),
        scope: scope.clone(),
        facts_affected,
        initiated_at: now.to_rfc3339(),
        recovery_window_ends_at: recovery_end.to_rfc3339(),
    }
}

/// `memory_forget_dry_run` — return the facts a forget call would affect,
/// WITHOUT mutating the store.
pub async fn handle_memory_forget_dry_run(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let scope = parse_scope(args)?;
    let token_budget = args.get("token_budget").and_then(|v| v.as_u64()).map(|v| v as usize);
    let include_pinned = args.get("include_pinned").and_then(|v| v.as_bool()).unwrap_or(false);
    // agent-passport M5: identity-scoped visibility (flag-OFF == raw name).
    let identity = ctx.scope_identity();
    let id_ref = identity.as_deref();
    let aliases = ctx.scope_aliases();
    let alias_refs: Vec<&str> = aliases.iter().map(String::as_str).collect();
    // Raw agent name drives the pin lookup (pins are keyed by raw name). Dry-run
    // mirrors the live forget's pin exclusion so preview == effect.
    let agent_name = scope::agent_name(ctx.agent.as_ref());

    let store = ctx.fact_store.read().await;
    let matches = resolve_scope(
        &store,
        &scope,
        id_ref,
        &alias_refs,
        agent_name,
        include_pinned,
        token_budget,
    );
    let count = matches.len();

    let preview: Vec<Value> = matches
        .iter()
        .map(|f| {
            let entity = scope::visible_entity_for_identity(f, id_ref, &alias_refs).unwrap_or_else(|| f.entity.clone());
            json!({
                "fact_id": f.fact_id,
                "entity": entity,
                "key": f.key,
                "stored_at": f.stored_at.to_rfc3339(),
                "tokens": f.tokens,
            })
        })
        .collect();

    let text = if count == 0 {
        format!("dry-run: no facts match scope ({})", scope.render())
    } else {
        format!(
            "dry-run: {count} facts would be forgotten ({}); see structured `facts_that_would_be_affected`",
            scope.render()
        )
    };

    // The structured payload lives under `structuredContent` so MCP clients
    // actually receive it — sibling top-level keys are dropped by the protocol
    // envelope (probe finding 10: the array was referenced in the text but
    // never reached the caller).
    Ok(json!({
        "content": [{ "type": "text", "text": text }],
        "structuredContent": {
            "scope": scope,
            "count": count,
            "facts_that_would_be_affected": preview,
            "dry_run": true,
        }
    }))
}

/// `memory_forget` — soft-delete every fact matching the scope, emit a
/// `Forget` receipt body, and return the receipt id + affected count.
pub async fn handle_memory_forget(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    handle_memory_forget_after_resolution(args, ctx, std::future::ready(())).await
}

async fn handle_memory_forget_after_resolution<F>(
    args: &Value,
    ctx: &McpContext,
    after_resolution: F,
) -> Result<Value, JsonRpcError>
where
    F: std::future::Future<Output = ()>,
{
    if !feature_enabled() {
        return Err(JsonRpcError {
            code: METHOD_NOT_FOUND,
            message: format!("memory_forget is disabled (set {FEATURE_FLAG_ENV}=1 to enable)"),
            data: Some(json!({"feature_flag": FEATURE_FLAG_ENV, "enabled": false})),
        });
    }

    let agent_name = scope::agent_name(ctx.agent.as_ref()).ok_or_else(|| JsonRpcError {
        code: INVALID_PARAMS,
        message: "memory_forget requires an authenticated agent identity (passport)".to_string(),
        data: Some(json!({"param": "passport", "requires_agent_identity": true})),
    })?;
    // agent-passport M5: the *scope identity* (passport_id flag-ON; raw name
    // flag-OFF) drives visibility, so the OWNER can forget its own passport-
    // keyed private facts and a DIFFERENT passport cannot. The receipt's
    // `passport_id` is stamped with the resolved scope identity for consistent
    // attribution (flag-OFF this is exactly the raw `agent_name`).
    let identity = ctx.scope_identity();
    let id_ref = identity.as_deref();
    let aliases = ctx.scope_aliases();
    let alias_refs: Vec<&str> = aliases.iter().map(String::as_str).collect();
    let passport_id = identity.clone().unwrap_or_else(|| agent_name.to_string());

    let scope = parse_scope(args)?;
    let reason = args.get("reason").and_then(|v| v.as_str()).unwrap_or("").to_string();
    if reason.trim().is_empty() {
        return Err(JsonRpcError {
            code: INVALID_PARAMS,
            message: "memory_forget requires a non-empty `reason`".to_string(),
            data: Some(json!({"param": "reason", "required": true})),
        });
    }
    let tenant_id = args
        .get("tenant_id")
        .and_then(|v| v.as_str())
        .unwrap_or("default")
        .to_string();
    let token_budget = args.get("token_budget").and_then(|v| v.as_u64()).map(|v| v as usize);
    // Pinned facts survive by default; `include_pinned: true` is the explicit
    // GDPR Art.17 override that erases them too.
    let include_pinned = args.get("include_pinned").and_then(|v| v.as_bool()).unwrap_or(false);

    // Resolve matches under a read lock first so we can compute the
    // pre-forget value hashes before we mutate (the value disappears on
    // soft-delete + journal append).
    let to_forget: Vec<Fact> = {
        let store = ctx.fact_store.read().await;
        resolve_scope(
            &store,
            &scope,
            id_ref,
            &alias_refs,
            Some(agent_name),
            include_pinned,
            token_budget,
        )
        .into_iter()
        .cloned()
        .collect()
    };

    // Kept as an injectable future so the regression test can deterministically
    // place a hold in the former read-lock/write-lock gap while exercising this
    // exact handler path. Production supplies an immediately-ready future.
    after_resolution.await;

    let now = Utc::now();
    let body = build_receipt_body(
        &scope,
        &passport_id,
        &reason,
        &to_forget.iter().collect::<Vec<&Fact>>(),
        &tenant_id,
        now,
    );
    let body_bytes = encode_forget_body_v1(&body).map_err(|err| JsonRpcError {
        code: INTERNAL_ERROR,
        message: format!("forget receipt encode failed: {err}"),
        data: None,
    })?;
    let body_hash_hex = blake3::hash(&body_bytes).to_hex().to_string();

    // Re-check every governance guard after acquiring the same write lock
    // that performs the delete. A hold placed after scope resolution must be
    // observed before any fact is mutated (fail closed against TOCTOU).
    let mut store = ctx.fact_store.write().await;
    let forgotten = forget_resolved_facts_under_lock(&mut store, &to_forget, id_ref, &alias_refs)?;
    drop(store);

    let recovery_window_seconds = recovery_window().num_seconds();

    Ok(json!({
        "content": [{
            "type": "text",
            "text": format!(
                "forget receipt {} emitted: {} facts soft-deleted (scope={}); recovery window ends {}",
                body.receipt_id,
                forgotten,
                scope.render(),
                body.recovery_window_ends_at,
            ),
        }],
        "forget_receipt_id": body.receipt_id,
        "facts_affected": forgotten,
        "recovery_window_seconds": recovery_window_seconds,
        "recovery_window_ends_at": body.recovery_window_ends_at,
        "receipt_body_cbor_hex": hex::encode(&body_bytes),
        "receipt_body_hash_hex": body_hash_hex,
        "scope": scope,
        "passport_id": passport_id,
    }))
}

fn forget_resolved_facts_under_lock(
    store: &mut corecrux_memory::FactStore,
    facts: &[Fact],
    identity: Option<&str>,
    aliases: &[&str],
) -> Result<usize, JsonRpcError> {
    let blocking_holds = blocking_legal_holds(store, facts);
    if !blocking_holds.is_empty() {
        return Err(legal_hold_active_error(facts, &blocking_holds));
    }

    let mut forgotten = 0usize;
    for fact in facts {
        // Re-check visibility under the write lock; another concurrent
        // forget could have already soft-deleted this fact_id.
        let still_visible = store
            .get(&fact.fact_id)
            .is_some_and(|current| !current.deleted && scope::fact_visible_to_identity(current, identity, aliases));
        if still_visible
            && store.try_delete(&fact.fact_id).map_err(|err| JsonRpcError {
                code: INTERNAL_ERROR,
                message: "fact journal append failed".to_string(),
                data: Some(json!({"error": err.to_string()})),
            })?
        {
            forgotten += 1;
        }
    }
    Ok(forgotten)
}

fn blocking_legal_holds(store: &corecrux_memory::FactStore, facts: &[Fact]) -> Vec<corecrux_memory::LegalHold> {
    let mut holds = std::collections::BTreeMap::new();
    for fact in facts {
        for hold in store.covering_legal_holds(&fact.tenant_hash, &fact.entity) {
            holds.insert(hold.hold_id.clone(), hold);
        }
    }
    holds.into_values().collect()
}

fn legal_hold_active_error(facts: &[Fact], blocking_holds: &[corecrux_memory::LegalHold]) -> JsonRpcError {
    JsonRpcError {
        code: LEGAL_HOLD_ACTIVE_ERROR,
        message: format!(
            "memory_forget refused: {} active legal hold(s) cover the requested facts",
            blocking_holds.len()
        ),
        data: Some(json!({
            "error": "LEGAL_HOLD_ACTIVE",
            "hold_ids": blocking_holds.iter().map(|hold| hold.hold_id.as_str()).collect::<Vec<_>>(),
            "holds": blocking_holds.iter().map(|hold| json!({
                "hold_id": hold.hold_id,
                "tenant_id": hold.tenant_id,
                "entity_prefixes": hold.entity_prefixes,
                "reason": hold.reason,
            })).collect::<Vec<_>>(),
            "facts_blocked": facts.len(),
        })),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::agent::AgentIdentity;
    use crate::dispatch::McpContext;
    use crate::tools::facts::{handle_query_facts, handle_store_fact};
    use crate::tools::memory::handle_memory_pin;

    // Tests that flip CORECRUXD_FEATURE_SCOPED_FORGET serialise on the
    // crate-wide test env lock; cargo test runs the suite in parallel
    // so env-var manipulation between tests must take this lock or the
    // flag value races (observed: 2 spurious failures under parallel
    // run, and the wider traces.rs flake fixed in
    // fix/crux-mcp-tools-traces-test-isolation-2026-05-29).
    fn flag_lock() -> &'static tokio::sync::Mutex<()> {
        crate::test_env_lock()
    }

    struct FeatureFlagGuard {
        prior: Option<String>,
        _lock: tokio::sync::MutexGuard<'static, ()>,
    }
    impl FeatureFlagGuard {
        async fn enabled() -> Self {
            let lock = flag_lock().lock().await;
            let prior = env::var(FEATURE_FLAG_ENV).ok();
            env::set_var(FEATURE_FLAG_ENV, "1");
            Self { prior, _lock: lock }
        }
        async fn disabled() -> Self {
            let lock = flag_lock().lock().await;
            let prior = env::var(FEATURE_FLAG_ENV).ok();
            // Launch default is ON, so disabling now means an explicit opt-out
            // rather than an unset var.
            env::set_var(FEATURE_FLAG_ENV, "0");
            Self { prior, _lock: lock }
        }
    }
    impl Drop for FeatureFlagGuard {
        fn drop(&mut self) {
            match &self.prior {
                Some(v) => env::set_var(FEATURE_FLAG_ENV, v),
                None => env::remove_var(FEATURE_FLAG_ENV),
            }
        }
    }

    fn agent_ctx(name: &str) -> McpContext {
        let ctx = McpContext::new_default("test-node");
        ctx.with_agent(AgentIdentity {
            name: name.to_string(),
            token_hash: [0u8; 32],
        })
    }

    #[test]
    fn glob_matches_basic() {
        assert!(glob_matches("foo", "foo"));
        assert!(!glob_matches("foo", "foobar"));
        assert!(glob_matches("foo*", "foobar"));
        assert!(glob_matches("*bar", "foobar"));
        assert!(glob_matches("foo*bar", "fooXXXbar"));
        assert!(!glob_matches("foo*bar", "foo"));
        assert!(glob_matches("*", "anything"));
    }

    #[test]
    fn reserved_prefix_filter() {
        assert!(is_reserved("__agent::alice::notes"));
        assert!(is_reserved("__ops::config-audit"));
        assert!(is_reserved("__bootstrap__::pattern:retry"));
        assert!(is_reserved("__agent_session::alice::s1"));
        assert!(!is_reserved("project-alpha"));
        assert!(!is_reserved("personal::bob::contact"));
    }

    #[tokio::test]
    async fn parse_scope_typed_enum_only() {
        let err = parse_scope(&json!({"scope": {"type": "raw_sql", "value": "DROP TABLE"}})).unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);

        let ok = parse_scope(&json!({"scope": {"type": "entity_prefix", "value": "x-"}})).unwrap();
        assert!(matches!(ok, ForgetScopeV1::EntityPrefix { .. }));
    }

    #[tokio::test]
    async fn dry_run_does_not_mutate() {
        let _guard = FeatureFlagGuard::disabled().await;
        let ctx = agent_ctx("alice");
        handle_store_fact(&json!({"entity": "test-fixture-a", "key": "k", "value": "v"}), &ctx)
            .await
            .unwrap();
        handle_store_fact(&json!({"entity": "test-fixture-b", "key": "k", "value": "v"}), &ctx)
            .await
            .unwrap();
        handle_store_fact(&json!({"entity": "production-x", "key": "k", "value": "v"}), &ctx)
            .await
            .unwrap();

        let resp = handle_memory_forget_dry_run(
            &json!({"scope": {"type": "entity_prefix", "value": "test-fixture-"}}),
            &ctx,
        )
        .await
        .unwrap();
        assert_eq!(resp["structuredContent"]["count"], 2);
        assert_eq!(resp["structuredContent"]["dry_run"], true);

        // post-check: facts still queryable
        let q = handle_query_facts(&json!({"entity": "test-fixture-a"}), &ctx)
            .await
            .unwrap();
        assert!(q["content"][0]["text"].as_str().unwrap().contains("test-fixture-a"));
    }

    #[tokio::test]
    async fn dry_run_filters_reserved_prefixes() {
        let ctx = agent_ctx("alice");
        // Reserved prefix; user-facing dry-run must skip it even if the
        // scope would otherwise include it.
        handle_store_fact(
            &json!({"entity": "__bootstrap__::pattern:test", "key": "k", "value": "v"}),
            &ctx,
        )
        .await
        .unwrap();
        let resp = handle_memory_forget_dry_run(
            &json!({"scope": {"type": "entity_prefix", "value": "__bootstrap__::"}}),
            &ctx,
        )
        .await
        .unwrap();
        assert_eq!(resp["structuredContent"]["count"], 0);
    }

    #[tokio::test]
    async fn memory_forget_requires_feature_flag() {
        let _guard = FeatureFlagGuard::disabled().await;
        let ctx = agent_ctx("alice");
        let err = handle_memory_forget(
            &json!({"scope": {"type": "entity_prefix", "value": "x"}, "reason": "test"}),
            &ctx,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, METHOD_NOT_FOUND);
    }

    #[tokio::test]
    async fn memory_forget_requires_passport() {
        let _guard = FeatureFlagGuard::enabled().await;
        let ctx = McpContext::new_default("test-node"); // anonymous
        let err = handle_memory_forget(
            &json!({"scope": {"type": "entity_prefix", "value": "x"}, "reason": "t"}),
            &ctx,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
        assert_eq!(err.data.unwrap()["requires_agent_identity"], true);
    }

    #[tokio::test]
    async fn memory_forget_requires_reason() {
        let _guard = FeatureFlagGuard::enabled().await;
        let ctx = agent_ctx("alice");
        let err = handle_memory_forget(&json!({"scope": {"type": "entity_prefix", "value": "x-"}}), &ctx)
            .await
            .unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
        assert_eq!(err.data.unwrap()["param"], "reason");
    }

    #[tokio::test]
    async fn memory_forget_soft_deletes_matching_facts() {
        let _guard = FeatureFlagGuard::enabled().await;
        let ctx = agent_ctx("alice");
        handle_store_fact(&json!({"entity": "test-fixture-a", "key": "k1", "value": "v1"}), &ctx)
            .await
            .unwrap();
        handle_store_fact(&json!({"entity": "test-fixture-b", "key": "k2", "value": "v2"}), &ctx)
            .await
            .unwrap();
        handle_store_fact(&json!({"entity": "production-x", "key": "k", "value": "v"}), &ctx)
            .await
            .unwrap();

        let resp = handle_memory_forget(
            &json!({
                "scope": {"type": "entity_prefix", "value": "test-fixture-"},
                "reason": "cleanup",
            }),
            &ctx,
        )
        .await
        .unwrap();
        assert_eq!(resp["facts_affected"], 2);
        assert!(resp["forget_receipt_id"].as_str().unwrap().starts_with("r_forget_"));
        assert!(resp["receipt_body_cbor_hex"].as_str().unwrap().len() > 32);
        let hash = resp["receipt_body_hash_hex"].as_str().unwrap();
        assert_eq!(hash.len(), 64); // BLAKE3 hex digest

        // Affected facts no longer match the query, but production-x is untouched.
        let q = handle_query_facts(&json!({"entity": "test-fixture-a"}), &ctx)
            .await
            .unwrap();
        assert_eq!(q["content"][0]["text"].as_str().unwrap(), "no facts found");
        let q = handle_query_facts(&json!({"entity": "production-x"}), &ctx)
            .await
            .unwrap();
        assert!(q["content"][0]["text"].as_str().unwrap().contains("production-x"));
    }

    #[tokio::test]
    async fn memory_forget_refuses_when_newest_legal_hold_state_is_malformed() {
        let _guard = FeatureFlagGuard::enabled().await;
        let ctx = agent_ctx("alice");
        handle_store_fact(
            &json!({"entity": "case-client-42", "key": "pii", "value": "retain"}),
            &ctx,
        )
        .await
        .unwrap();
        let hold_id = {
            let mut store = ctx.fact_store.write().await;
            let placed = store
                .place_legal_hold(corecrux_memory::PlaceLegalHold {
                    tenant_id: "default".to_string(),
                    entity_prefixes: vec!["case-client-42".to_string()],
                    reason: "active litigation".to_string(),
                    actor: Some("p_dpo".to_string()),
                })
                .unwrap()
                .hold;
            let hold_id = placed.hold_id;
            let malformed = store.store(corecrux_memory::fact_store::StoreFact {
                tenant_hash: "default".to_string(),
                entity: format!("{}{hold_id}", corecrux_memory::LEGAL_HOLD_ENTITY_PREFIX),
                key: "state".to_string(),
                value: "{malformed-json".to_string(),
                source_receipt: None,
                confidence: 1.0,
                private: true,
                horizon_class: Some(corecrux_memory::HorizonClass::None),
                actor: Some("bypass-attempt".to_string()),
            });
            assert_eq!(malformed.version, 2);
            hold_id
        };

        let err = handle_memory_forget(
            &json!({
                "scope": {"type": "entity_prefix", "value": "case-client-42"},
                "reason": "user request",
                "include_pinned": true,
            }),
            &ctx,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, LEGAL_HOLD_ACTIVE_ERROR);
        let data = err.data.unwrap();
        assert_eq!(data["error"], "LEGAL_HOLD_ACTIVE");
        assert_eq!(data["hold_ids"][0], hold_id);
        assert_eq!(data["facts_blocked"], 1);

        let q = handle_query_facts(&json!({"entity": "case-client-42"}), &ctx)
            .await
            .unwrap();
        assert!(q["content"][0]["text"].as_str().unwrap().contains("retain"));
    }

    #[tokio::test]
    async fn hold_placed_between_scope_resolution_and_delete_is_refused() {
        let _guard = FeatureFlagGuard::enabled().await;
        let ctx = agent_ctx("alice");
        handle_store_fact(
            &json!({"entity": "case-client-race", "key": "pii", "value": "retain"}),
            &ctx,
        )
        .await
        .unwrap();

        // The injected future runs after the public handler has resolved its
        // target set and before it acquires the mutating lock. This is the
        // exact interleaving that previously bypassed a newly placed hold.
        let fact_store = std::sync::Arc::clone(&ctx.fact_store);
        let place_hold_in_gap = async move {
            fact_store
                .write()
                .await
                .place_legal_hold(corecrux_memory::PlaceLegalHold {
                    tenant_id: "default".to_string(),
                    entity_prefixes: vec!["case-client-race".to_string()],
                    reason: "hold won the race".to_string(),
                    actor: Some("p_dpo".to_string()),
                })
                .unwrap();
        };
        let err = handle_memory_forget_after_resolution(
            &json!({
                "scope": {"type": "entity_prefix", "value": "case-client-race"},
                "reason": "user request",
                "include_pinned": true,
            }),
            &ctx,
            place_hold_in_gap,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, LEGAL_HOLD_ACTIVE_ERROR);
        let store = ctx.fact_store.read().await;
        let hold_id = store.active_legal_holds()[0].hold_id.clone();
        assert_eq!(err.data.as_ref().unwrap()["hold_ids"][0], hold_id);
        let retained = store
            .all_facts()
            .find(|fact| fact.entity == "case-client-race")
            .unwrap();
        assert!(!retained.deleted);
    }

    #[tokio::test]
    async fn forget_skips_pinned_fact_by_default() {
        // Probe finding 3: a pinned fact must survive scoped-forget.
        let _guard = FeatureFlagGuard::enabled().await;
        let ctx = agent_ctx("alice");
        let keep = handle_store_fact(&json!({"entity": "test-fixture-pin-a", "key": "k", "value": "v"}), &ctx)
            .await
            .unwrap();
        let keep_id = keep["structuredContent"]["fact_id"].as_str().unwrap().to_string();
        handle_store_fact(&json!({"entity": "test-fixture-pin-b", "key": "k", "value": "v"}), &ctx)
            .await
            .unwrap();
        handle_memory_pin(&json!({"fact_id": keep_id, "pinned": true}), &ctx)
            .await
            .unwrap();

        let resp = handle_memory_forget(
            &json!({"scope": {"type": "entity_prefix", "value": "test-fixture-pin-"}, "reason": "cleanup"}),
            &ctx,
        )
        .await
        .unwrap();
        assert_eq!(resp["facts_affected"], 1, "only the UNpinned fact is forgotten");

        // Pinned fact survives; unpinned is gone.
        let kept = handle_query_facts(&json!({"entity": "test-fixture-pin-a"}), &ctx)
            .await
            .unwrap();
        assert!(kept["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("test-fixture-pin-a"));
        let gone = handle_query_facts(&json!({"entity": "test-fixture-pin-b"}), &ctx)
            .await
            .unwrap();
        assert_eq!(gone["content"][0]["text"].as_str().unwrap(), "no facts found");
    }

    #[tokio::test]
    async fn forget_include_pinned_erases_pinned_fact() {
        // GDPR Art.17 override: include_pinned erases even pinned facts.
        let _guard = FeatureFlagGuard::enabled().await;
        let ctx = agent_ctx("alice");
        let pinned = handle_store_fact(&json!({"entity": "test-fixture-ip", "key": "k", "value": "v"}), &ctx)
            .await
            .unwrap();
        let pid = pinned["structuredContent"]["fact_id"].as_str().unwrap().to_string();
        handle_memory_pin(&json!({"fact_id": pid, "pinned": true}), &ctx)
            .await
            .unwrap();

        let resp = handle_memory_forget(
            &json!({
                "scope": {"type": "entity_prefix", "value": "test-fixture-ip"},
                "reason": "gdpr erasure",
                "include_pinned": true,
            }),
            &ctx,
        )
        .await
        .unwrap();
        assert_eq!(resp["facts_affected"], 1, "include_pinned overrides the pin guard");
    }

    #[tokio::test]
    async fn dry_run_mirrors_pin_exclusion_and_include_pinned_override() {
        let _guard = FeatureFlagGuard::enabled().await;
        let ctx = agent_ctx("alice");
        let pinned = handle_store_fact(&json!({"entity": "test-fixture-dp", "key": "k", "value": "v"}), &ctx)
            .await
            .unwrap();
        let pid = pinned["structuredContent"]["fact_id"].as_str().unwrap().to_string();
        handle_memory_pin(&json!({"fact_id": pid, "pinned": true}), &ctx)
            .await
            .unwrap();

        let preview = handle_memory_forget_dry_run(
            &json!({"scope": {"type": "entity_prefix", "value": "test-fixture-dp"}}),
            &ctx,
        )
        .await
        .unwrap();
        assert_eq!(
            preview["structuredContent"]["count"], 0,
            "dry-run excludes the pinned fact (preview == effect)"
        );

        let preview2 = handle_memory_forget_dry_run(
            &json!({"scope": {"type": "entity_prefix", "value": "test-fixture-dp"}, "include_pinned": true}),
            &ctx,
        )
        .await
        .unwrap();
        assert_eq!(
            preview2["structuredContent"]["count"], 1,
            "include_pinned exposes the pinned fact"
        );
    }

    #[tokio::test]
    async fn memory_forget_skips_reserved_prefixes_even_with_matching_scope() {
        let _guard = FeatureFlagGuard::enabled().await;
        let ctx = agent_ctx("alice");
        handle_store_fact(
            &json!({"entity": "__ops::config-audit", "key": "k", "value": "v"}),
            &ctx,
        )
        .await
        .unwrap();
        let resp = handle_memory_forget(
            &json!({
                "scope": {"type": "entity_prefix", "value": "__ops::"},
                "reason": "should not work",
            }),
            &ctx,
        )
        .await
        .unwrap();
        assert_eq!(resp["facts_affected"], 0);
    }

    #[tokio::test]
    async fn memory_forget_receipt_body_decodes_back_to_typed_struct() {
        // CROWN-verifier compatibility check: the CBOR we hand back must
        // round-trip through `decode_forget_body_v1` (the same path the
        // v3 verifier uses to extract the body index).
        let _guard = FeatureFlagGuard::enabled().await;
        let ctx = agent_ctx("alice");
        handle_store_fact(&json!({"entity": "tx-1", "key": "k", "value": "v"}), &ctx)
            .await
            .unwrap();
        let resp = handle_memory_forget(
            &json!({
                "scope": {"type": "entity_prefix", "value": "tx-"},
                "reason": "audit",
            }),
            &ctx,
        )
        .await
        .unwrap();
        let cbor_hex = resp["receipt_body_cbor_hex"].as_str().unwrap();
        let cbor_bytes = hex::decode(cbor_hex).unwrap();
        let decoded = corecrux_receipts::decode_forget_body_v1(&cbor_bytes).unwrap();
        assert_eq!(decoded.passport_id, "alice");
        assert_eq!(decoded.facts_affected.len(), 1);
        assert_eq!(decoded.reason, "audit");
    }

    #[tokio::test]
    async fn memory_forget_cross_tenant_visibility_guard() {
        // T.1: forget cannot delete another agent's private facts even if
        // a scope would otherwise match. Alice stores a private fact;
        // Bob's forget under the same logical-entity scope must affect
        // zero facts.
        let _guard = FeatureFlagGuard::enabled().await;
        let alice = agent_ctx("alice");
        let bob = agent_ctx("bob");
        handle_store_fact(
            &json!({"entity": "secret", "key": "k", "value": "v", "private": true}),
            &alice,
        )
        .await
        .unwrap();
        let resp = handle_memory_forget(
            &json!({
                "scope": {"type": "entity_prefix", "value": "secret"},
                "reason": "cross-tenant probe",
            }),
            &bob,
        )
        .await
        .unwrap();
        assert_eq!(resp["facts_affected"], 0);

        // Alice's private fact survives.
        let q = handle_query_facts(&json!({"entity": "secret"}), &alice).await.unwrap();
        assert!(q["content"][0]["text"].as_str().unwrap().contains("secret"));
    }

    #[tokio::test]
    async fn dry_run_respects_token_budget() {
        let ctx = agent_ctx("alice");
        for i in 0..20 {
            handle_store_fact(
                &json!({"entity": format!("budget-{i}"), "key": "k", "value": "value"}),
                &ctx,
            )
            .await
            .unwrap();
        }
        let resp = handle_memory_forget_dry_run(
            &json!({
                "scope": {"type": "entity_prefix", "value": "budget-"},
                "token_budget": 5,
            }),
            &ctx,
        )
        .await
        .unwrap();
        // budget=5 with ~1-token-per-fact stored values trims well under 20.
        assert!((resp["structuredContent"]["count"].as_u64().unwrap()) < 20);
    }
}
