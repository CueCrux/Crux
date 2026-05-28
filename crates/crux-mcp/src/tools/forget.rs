// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

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

/// Reserved entity prefixes that scoped-forget MUST NOT touch through
/// the user-facing surface. Operator-only override is out of scope here.
const RESERVED_PREFIXES: &[&str] = &["__agent::", "__ops::", "__bootstrap__::", "__agent_session::"];

/// Default recovery window (free tier) before `PermanentPurge`. Override
/// per-tenant via `CORECRUXD_FORGET_RECOVERY_WINDOW_DAYS`.
const DEFAULT_RECOVERY_WINDOW_DAYS: i64 = 7;

fn feature_enabled() -> bool {
    env::var(FEATURE_FLAG_ENV)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
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

fn resolve_scope<'a>(
    store: &'a corecrux_memory::FactStore,
    scope: &ForgetScopeV1,
    agent_name: Option<&str>,
    token_budget: Option<usize>,
) -> Vec<&'a Fact> {
    let before_ts = match scope {
        ForgetScopeV1::BeforeTimestamp { value } => parse_before_ts(value).ok(),
        _ => None,
    };
    let mut matches: Vec<&Fact> = store
        .all_facts()
        .filter(|fact| !fact.deleted)
        .filter(|fact| !is_reserved(&fact.entity))
        .filter(|fact| scope::fact_visible_to_agent(fact, agent_name))
        .filter(|fact| scope_matches(scope, fact, before_ts))
        .collect();
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
    let agent_name = scope::agent_name(ctx.agent.as_ref());

    let store = ctx.fact_store.read().await;
    let matches = resolve_scope(&store, &scope, agent_name, token_budget);
    let count = matches.len();

    let preview: Vec<Value> = matches
        .iter()
        .map(|f| {
            let entity = scope::visible_entity_for_agent(f, agent_name).unwrap_or_else(|| f.entity.clone());
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

    Ok(json!({
        "content": [{ "type": "text", "text": text }],
        "scope": scope,
        "count": count,
        "facts_that_would_be_affected": preview,
        "dry_run": true,
    }))
}

/// `memory_forget` — soft-delete every fact matching the scope, emit a
/// `Forget` receipt body, and return the receipt id + affected count.
pub async fn handle_memory_forget(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
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
    let passport_id = agent_name.to_string();

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

    // Resolve matches under a read lock first so we can compute the
    // pre-forget value hashes before we mutate (the value disappears on
    // soft-delete + journal append).
    let to_forget: Vec<Fact> = {
        let store = ctx.fact_store.read().await;
        resolve_scope(&store, &scope, Some(agent_name), token_budget)
            .into_iter()
            .cloned()
            .collect()
    };

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

    // Mutate.
    let mut store = ctx.fact_store.write().await;
    let mut forgotten = 0usize;
    for f in &to_forget {
        // Re-check visibility under the write lock; another concurrent
        // forget could have already soft-deleted this fact_id.
        let still_visible = store
            .get(&f.fact_id)
            .is_some_and(|cur| !cur.deleted && scope::fact_visible_to_agent(cur, Some(agent_name)));
        if still_visible
            && store.try_delete(&f.fact_id).map_err(|err| JsonRpcError {
                code: INTERNAL_ERROR,
                message: "fact journal append failed".to_string(),
                data: Some(json!({"error": err.to_string()})),
            })?
        {
            forgotten += 1;
        }
    }
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::agent::AgentIdentity;
    use crate::dispatch::McpContext;
    use crate::tools::facts::{handle_query_facts, handle_store_fact};

    // Tests that flip CORECRUXD_FEATURE_SCOPED_FORGET serialise on this
    // mutex; cargo test runs the suite in parallel so env-var
    // manipulation between tests must take a lock or the flag value
    // races (observed: 2 spurious failures under parallel run).
    fn flag_lock() -> &'static std::sync::Mutex<()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
    }

    struct FeatureFlagGuard {
        prior: Option<String>,
        _lock: std::sync::MutexGuard<'static, ()>,
    }
    impl FeatureFlagGuard {
        fn enabled() -> Self {
            let lock = flag_lock().lock().unwrap_or_else(|p| p.into_inner());
            let prior = env::var(FEATURE_FLAG_ENV).ok();
            env::set_var(FEATURE_FLAG_ENV, "1");
            Self { prior, _lock: lock }
        }
        fn disabled() -> Self {
            let lock = flag_lock().lock().unwrap_or_else(|p| p.into_inner());
            let prior = env::var(FEATURE_FLAG_ENV).ok();
            env::remove_var(FEATURE_FLAG_ENV);
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
        let _guard = FeatureFlagGuard::disabled();
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
        assert_eq!(resp["count"], 2);
        assert_eq!(resp["dry_run"], true);

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
        assert_eq!(resp["count"], 0);
    }

    #[tokio::test]
    async fn memory_forget_requires_feature_flag() {
        let _guard = FeatureFlagGuard::disabled();
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
        let _guard = FeatureFlagGuard::enabled();
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
        let _guard = FeatureFlagGuard::enabled();
        let ctx = agent_ctx("alice");
        let err = handle_memory_forget(&json!({"scope": {"type": "entity_prefix", "value": "x-"}}), &ctx)
            .await
            .unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
        assert_eq!(err.data.unwrap()["param"], "reason");
    }

    #[tokio::test]
    async fn memory_forget_soft_deletes_matching_facts() {
        let _guard = FeatureFlagGuard::enabled();
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
    async fn memory_forget_skips_reserved_prefixes_even_with_matching_scope() {
        let _guard = FeatureFlagGuard::enabled();
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
        let _guard = FeatureFlagGuard::enabled();
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
        let _guard = FeatureFlagGuard::enabled();
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
        assert!((resp["count"].as_u64().unwrap()) < 20);
    }
}
