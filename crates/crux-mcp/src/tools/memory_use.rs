// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! `memory_acknowledge_use` — agent-ux-02 free-tier acknowledgement tool.
//!
//! Lets an agent declare, at turn close, the list of stored fact ids it
//! consulted while producing the turn. The tool:
//!
//! 1. Requires an authenticated agent identity (passport — T.3 in the
//!    child plan).
//! 2. Filters reserved-prefix entries (`__agent::*`, `__ops::*`,
//!    `__bootstrap__::*`) from the supplied fact list (T.1).
//! 3. Resolves each surviving id against the fact store so an agent
//!    can't ack a fact it didn't actually have visibility on.
//! 4. Records a per-session pending-ack buffer entry so the per-turn
//!    audit envelope (`build_envelope_for_memory_acknowledge_use`) can
//!    expose `memories_used[]` on the response without re-querying.
//! 5. Returns the acknowledgement payload (turn_id + filtered ids + a
//!    receipt placeholder).
//!
//! The actual CROWN receipt body is built by
//! [`corecrux_receipts::build_memory_use_body_v1`]; the signing path is
//! deferred to the daemon HTTP layer (which has the Ed25519 passport
//! key). The MCP tool itself returns a deterministic `receipt_ref`
//! string that the host can pass back to the verifier later.
//!
//! ## Feature flag
//!
//! Default OFF. Set `CORECRUXD_FEATURE_MEMORY_ACK=1` to enable the
//! tool's side effects (recording into the pending-ack buffer). The
//! tool is always registered in `list_tools` so the catalogue is
//! stable across deploys; with the flag off, calls return a
//! "feature disabled" payload (no buffer write, no receipt scaffold).

use std::sync::Arc;

use serde_json::{json, Value};
use tokio::sync::Mutex;

use crate::dispatch::McpContext;
use crate::envelope::{is_reserved_entity, AutonomyConsumed, Envelope, EnvelopeLinks, MemoryUsed};
use crate::protocol::{JsonRpcError, INVALID_PARAMS};
use crate::scope;
use corecrux_receipts::{is_reserved_entity_prefix as receipts_is_reserved, MemoryUseIntentV1};

/// Environment variable that gates `memory_acknowledge_use`. Default off.
///
/// Same convention as
/// [`crate::envelope::FEATURE_FLAG_ENV`]: any value other than
/// `"0"|"false"|"off"|"no"|""` enables the flag.
pub const FEATURE_FLAG_ENV: &str = "CORECRUXD_FEATURE_MEMORY_ACK";

/// In-process per-session pending-ack buffer.
///
/// `turn_id` → list of fact entries (id + entity) acknowledged for that
/// turn. Bounded growth: turns are evicted FIFO when the buffer exceeds
/// [`MAX_BUFFERED_TURNS`].
#[derive(Debug, Clone)]
pub struct AckBufferEntry {
    pub turn_id: String,
    pub actor: String,
    pub fact_entries: Vec<AckFactEntry>,
    pub intent: String,
    pub created_at_unix_ms: i64,
}

#[derive(Debug, Clone)]
pub struct AckFactEntry {
    pub fact_id: String,
    pub entity: String,
    pub topic: String,
    pub age_days: Option<i64>,
}

/// Cap on the number of buffered turns held in memory per process.
/// Tuned for an interactive session (a few hundred turns is plenty);
/// older entries are evicted FIFO.
pub const MAX_BUFFERED_TURNS: usize = 1024;

/// Lazy global ack buffer. We use a global because the MCP context is
/// re-built per request in the loopback test path; a per-context buffer
/// would lose state between requests.
fn ack_buffer() -> &'static Arc<Mutex<Vec<AckBufferEntry>>> {
    use std::sync::OnceLock;
    static BUFFER: OnceLock<Arc<Mutex<Vec<AckBufferEntry>>>> = OnceLock::new();
    BUFFER.get_or_init(|| Arc::new(Mutex::new(Vec::new())))
}

/// Return `true` iff the flag is enabled. Mirrors the parsing rule of
/// [`crate::envelope::envelope_enabled`].
pub fn ack_enabled() -> bool {
    match std::env::var(FEATURE_FLAG_ENV) {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            !matches!(v.as_str(), "" | "0" | "false" | "off" | "no")
        }
        Err(_) => false,
    }
}

/// Get a snapshot of the buffered ack for `turn_id`, if any. Used by
/// the envelope builder to attach `memories_used[]` to the tool
/// response without re-querying the fact store.
pub async fn buffered_ack_for_turn(turn_id: &str) -> Option<AckBufferEntry> {
    let buf = ack_buffer().lock().await;
    buf.iter().rev().find(|e| e.turn_id == turn_id).cloned()
}

/// Test helper — clear the buffer between tests. Hidden from docs.
#[doc(hidden)]
pub async fn _reset_ack_buffer_for_tests() {
    let mut buf = ack_buffer().lock().await;
    buf.clear();
}

/// Implementation of the `memory_acknowledge_use` MCP tool.
pub async fn handle_memory_acknowledge_use(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    // ── 1. Passport gate (T.3) ─────────────────────────────────────────
    let agent_name = scope::agent_name(ctx.agent.as_ref()).ok_or_else(|| JsonRpcError {
        code: INVALID_PARAMS,
        message: "memory_acknowledge_use requires an authenticated agent identity \
                  (passport). Set CRUX_AGENT_TOKEN or CRUX_AGENT_TOKENS and pass a Bearer header."
            .to_string(),
        data: Some(json!({"requires_agent_identity": true})),
    })?;

    // ── 2. Parse args ──────────────────────────────────────────────────
    let turn_id = args
        .get("turn_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| JsonRpcError {
            code: INVALID_PARAMS,
            message: "turn_id is required (opaque per-host turn identifier)".to_string(),
            data: None,
        })?
        .to_string();
    let intent_str = args.get("intent").and_then(|v| v.as_str()).unwrap_or("answer");
    let intent = MemoryUseIntentV1::parse(intent_str);

    let fact_ids: Vec<String> = match args.get("fact_ids") {
        Some(Value::Array(arr)) => arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect(),
        Some(_) => {
            return Err(JsonRpcError {
                code: INVALID_PARAMS,
                message: "fact_ids must be an array of strings".to_string(),
                data: None,
            });
        }
        None => Vec::new(),
    };

    // ── 3. Flag gate ───────────────────────────────────────────────────
    if !ack_enabled() {
        return Ok(json!({
            "content": [{
                "type": "text",
                "text": format!(
                    "memory_acknowledge_use: feature disabled (CORECRUXD_FEATURE_MEMORY_ACK off). \
                     Turn {turn_id} not recorded. Set the flag at deploy time to enable."
                )
            }],
            "turn_id": turn_id,
            "feature_enabled": false,
            "memories_used": [],
            "filtered_count": 0,
        }));
    }

    // ── 4. Resolve + filter ────────────────────────────────────────────
    //
    // For each declared fact_id:
    //   - skip ids the agent can't see (scope::fact_visible_to_agent)
    //   - skip ids whose entity has a reserved prefix
    //   - record entity + topic + age for the envelope renderer
    // agent-passport M5: identity-scoped visibility so the OWNER can ack its
    // own passport-keyed private facts, and a DIFFERENT passport cannot. The
    // raw `agent_name` is still used for receipt_ref / buffer actor / envelope
    // scope (out of M5 scope — those name the caller, not a fact owner).
    // Flag-OFF the identity is the raw agent name and aliases is empty, so the
    // `scope::*_for_identity` calls below are byte-for-byte the prior
    // `scope::*_for_agent(Some(agent_name))` path.
    let identity = ctx.scope_identity();
    let id_ref = identity.as_deref();
    let aliases = ctx.scope_aliases();
    let alias_refs: Vec<&str> = aliases.iter().map(String::as_str).collect();

    let store = ctx.fact_store.read().await;
    let now = chrono::Utc::now();
    let mut filtered_entries: Vec<AckFactEntry> = Vec::with_capacity(fact_ids.len());
    let mut redacted_count = 0usize;
    let mut not_found_count = 0usize;
    let mut not_visible_count = 0usize;

    for fid in &fact_ids {
        let Some(fact) = store.get(fid) else {
            not_found_count += 1;
            continue;
        };
        if fact.deleted {
            not_found_count += 1;
            continue;
        }
        if !scope::fact_visible_to_identity(fact, id_ref, &alias_refs) {
            not_visible_count += 1;
            continue;
        }
        // Belt-and-braces: filter on BOTH the local envelope check and the
        // receipts-crate check. They're declared independently in the two
        // crates so they're proven not to drift.
        if is_reserved_entity(&fact.entity) || receipts_is_reserved(&fact.entity) {
            redacted_count += 1;
            continue;
        }
        let age_days = (now - fact.stored_at).num_days();
        let age_days = if age_days < 0 { None } else { Some(age_days) };
        let topic =
            scope::visible_entity_for_identity(fact, id_ref, &alias_refs).unwrap_or_else(|| fact.entity.clone());
        filtered_entries.push(AckFactEntry {
            fact_id: fact.fact_id.clone(),
            entity: fact.entity.clone(),
            topic,
            age_days,
        });
    }
    drop(store);

    let filtered_count = filtered_entries.len();
    let receipt_ref = format!("mu_{}_{}", agent_name, turn_id);

    // ── 5. Record into pending-ack buffer ─────────────────────────────
    {
        let mut buf = ack_buffer().lock().await;
        // Replace any prior entry for the same turn (idempotent — agents
        // may re-ack after a clarification).
        buf.retain(|e| e.turn_id != turn_id);
        buf.push(AckBufferEntry {
            turn_id: turn_id.clone(),
            actor: agent_name.to_string(),
            fact_entries: filtered_entries.clone(),
            intent: intent.as_str().to_string(),
            created_at_unix_ms: now.timestamp_millis(),
        });
        if buf.len() > MAX_BUFFERED_TURNS {
            let drop_n = buf.len() - MAX_BUFFERED_TURNS;
            buf.drain(0..drop_n);
        }
    }

    // ── 6. Return the public payload ──────────────────────────────────
    let memories_used: Vec<Value> = filtered_entries
        .iter()
        .map(|e| {
            json!({
                "fact_id": e.fact_id,
                "topic": e.topic,
                "age_days": e.age_days,
            })
        })
        .collect();

    Ok(json!({
        "content": [{
            "type": "text",
            "text": format!(
                "acknowledged {filtered_count} memories for turn {turn_id} \
                 (intent={intent_str}, actor={agent_name}, receipt_ref={receipt_ref}, \
                  redacted={redacted_count}, not_found={not_found_count}, \
                  not_visible={not_visible_count})"
            )
        }],
        "turn_id": turn_id,
        "intent": intent.as_str(),
        "feature_enabled": true,
        "receipt_ref": receipt_ref,
        "memories_used": memories_used,
        "filtered_count": filtered_count,
        "redacted_count": redacted_count,
        "not_found_count": not_found_count,
        "not_visible_count": not_visible_count,
    }))
}

/// Envelope builder for `memory_acknowledge_use`.
///
/// Reads from the just-written pending-ack buffer (the handler above
/// records into it before returning) and emits an envelope whose
/// `memories_used[]` mirrors the public payload. Reserved-prefix
/// entries are stripped by the handler before reaching the buffer, so
/// the envelope can never expose a redacted fact. The envelope also
/// reports `autonomy_consumed = "memory:acknowledge"` so the audit
/// trail can distinguish ack writes from regular fact writes.
pub async fn build_envelope_for_memory_acknowledge_use(args: &Value, ctx: &McpContext) -> Envelope {
    let turn_id = args.get("turn_id").and_then(|v| v.as_str()).unwrap_or("");
    let scope_str = scope::agent_name(ctx.agent.as_ref())
        .map_or_else(|| format!("node:{}", ctx.node_id), |name| format!("agent:{name}"));

    let mut memories_used: Vec<MemoryUsed> = Vec::new();
    if let Some(entry) = buffered_ack_for_turn(turn_id).await {
        for f in entry.fact_entries {
            // Belt-and-braces — the handler already filtered, but if a
            // future path ever inserts a reserved entry into the buffer
            // (e.g. a buggy code change), the envelope still strips it.
            if is_reserved_entity(&f.entity) {
                continue;
            }
            memories_used.push(MemoryUsed {
                fact_id: f.fact_id,
                topic: f.topic,
                age_days: f.age_days,
                // The ack buffer only tracked day precision; derive hours from it
                // so the field is populated consistently (24× the day count).
                age_hours: f.age_days.map(|d| d * 24),
                freshness: crate::envelope::Freshness::from_age_days(f.age_days),
            });
        }
    }

    Envelope {
        receipts_used: Vec::new(),
        memories_used,
        autonomy_consumed: AutonomyConsumed {
            capability: "memory:acknowledge".to_string(),
            cost_credits: 0,
            scope: scope_str,
        },
        predicted_effects: Vec::new(),
        links: EnvelopeLinks::default(),
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::agent::AgentIdentity;
    use crate::tools::facts::handle_store_fact;

    fn ctx_with_agent(name: &str) -> McpContext {
        McpContext::new_default("test-mu-node").with_agent(AgentIdentity {
            name: name.to_string(),
            token_hash: [0u8; 32],
        })
    }

    // Serialise the env-var lock so concurrent tokio tests don't race
    // on CORECRUXD_FEATURE_MEMORY_ACK. Delegates to
    // `crate::test_env_lock` so every env-mutating test in this crate
    // shares one process-wide `tokio::sync::Mutex`.
    fn ack_env_lock() -> &'static tokio::sync::Mutex<()> {
        crate::test_env_lock()
    }

    #[tokio::test]
    async fn requires_passport() {
        let _g = ack_env_lock().lock().await;
        std::env::set_var(FEATURE_FLAG_ENV, "1");
        // No agent identity attached
        let ctx = McpContext::new_default("test-mu-nopass");
        let err = handle_memory_acknowledge_use(&json!({"turn_id": "t1"}), &ctx)
            .await
            .unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
        assert!(err.message.contains("passport") || err.message.contains("authenticated"));
        std::env::remove_var(FEATURE_FLAG_ENV);
    }

    #[tokio::test]
    async fn requires_turn_id() {
        let _g = ack_env_lock().lock().await;
        std::env::set_var(FEATURE_FLAG_ENV, "1");
        let ctx = ctx_with_agent("alice");
        let err = handle_memory_acknowledge_use(&json!({}), &ctx).await.unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
        assert!(err.message.contains("turn_id"));
        std::env::remove_var(FEATURE_FLAG_ENV);
    }

    #[tokio::test]
    async fn flag_off_returns_disabled_marker_no_buffer_write() {
        let _g = ack_env_lock().lock().await;
        std::env::remove_var(FEATURE_FLAG_ENV);
        _reset_ack_buffer_for_tests().await;
        let ctx = ctx_with_agent("alice");
        let res = handle_memory_acknowledge_use(&json!({"turn_id": "t-flag-off"}), &ctx)
            .await
            .unwrap();
        assert_eq!(res["feature_enabled"], false);
        let buffered = buffered_ack_for_turn("t-flag-off").await;
        assert!(
            buffered.is_none(),
            "buffer must stay empty while the feature flag is off"
        );
    }

    #[tokio::test]
    async fn reserved_prefix_entries_filtered_in_ack_and_envelope() {
        let _g = ack_env_lock().lock().await;
        std::env::set_var(FEATURE_FLAG_ENV, "1");
        _reset_ack_buffer_for_tests().await;
        let ctx = ctx_with_agent("alice");

        // Seed three facts: one public, two reserved.
        let f_pub = handle_store_fact(
            &json!({"entity": "project-x", "key": "status", "value": "shipped"}),
            &ctx,
        )
        .await
        .unwrap();
        let f_ops = handle_store_fact(
            &json!({"entity": "__ops::config-audit", "key": "sha256:abc", "value": "shipped"}),
            &ctx,
        )
        .await
        .unwrap();
        let f_boot = handle_store_fact(
            &json!({"entity": "__bootstrap__::pattern:x", "key": "Retry", "value": "shipped"}),
            &ctx,
        )
        .await
        .unwrap();

        fn extract_fact_id(v: &Value) -> String {
            let text = v["content"][0]["text"].as_str().unwrap();
            // Format: "stored fact f_xxx (entity=..., key=..., ..."
            let rest = text.trim_start_matches("stored fact ").to_string();
            rest.split_whitespace().next().unwrap_or("").to_string()
        }

        let id_pub = extract_fact_id(&f_pub);
        let id_ops = extract_fact_id(&f_ops);
        let id_boot = extract_fact_id(&f_boot);

        let res = handle_memory_acknowledge_use(
            &json!({
                "turn_id": "t-redact",
                "intent": "answer",
                "fact_ids": [id_pub, id_ops, id_boot],
            }),
            &ctx,
        )
        .await
        .unwrap();

        assert_eq!(res["feature_enabled"], true);
        assert_eq!(res["filtered_count"], 1, "only project-x must survive filtering");
        // Post-C6, reserved-prefix facts are born-private, matching the HTTP write path,
        // so they are excluded at the visibility layer rather than the redaction layer.
        // Redaction remains defense-in-depth for any still-public reserved fact (for
        // example, one written before migration).
        assert_eq!(res["not_visible_count"], 2, "ops + bootstrap entries must be hidden");
        assert_eq!(res["redacted_count"], 0, "born-private facts must not reach redaction");
        assert_eq!(res["not_found_count"], 0, "all supplied fact IDs must resolve");
        let mems = res["memories_used"].as_array().unwrap();
        assert_eq!(mems.len(), 1);
        assert_eq!(mems[0]["topic"], "project-x");
        let serialized_mems = serde_json::to_string(mems).unwrap();
        assert!(!serialized_mems.contains("__ops::config-audit"));
        assert!(!serialized_mems.contains("__bootstrap__::pattern:x"));
        for m in mems {
            let topic = m["topic"].as_str().unwrap();
            assert!(!topic.starts_with("__"), "ack must not expose reserved entity {topic}");
        }

        // Envelope must mirror the ack payload, also reserved-stripped.
        let env = build_envelope_for_memory_acknowledge_use(&json!({"turn_id": "t-redact"}), &ctx).await;
        assert_eq!(env.memories_used.len(), 1);
        assert_eq!(env.memories_used[0].topic, "project-x");
        assert_eq!(env.autonomy_consumed.capability, "memory:acknowledge");
        std::env::remove_var(FEATURE_FLAG_ENV);
    }

    #[tokio::test]
    async fn unknown_or_deleted_fact_ids_counted_not_acknowledged() {
        let _g = ack_env_lock().lock().await;
        std::env::set_var(FEATURE_FLAG_ENV, "1");
        _reset_ack_buffer_for_tests().await;
        let ctx = ctx_with_agent("alice");

        let res = handle_memory_acknowledge_use(
            &json!({
                "turn_id": "t-missing",
                "intent": "answer",
                "fact_ids": ["f_does_not_exist_001"],
            }),
            &ctx,
        )
        .await
        .unwrap();

        assert_eq!(res["filtered_count"], 0);
        assert_eq!(res["not_found_count"], 1);
        std::env::remove_var(FEATURE_FLAG_ENV);
    }

    #[tokio::test]
    async fn idempotent_re_ack_replaces_buffer_entry() {
        let _g = ack_env_lock().lock().await;
        std::env::set_var(FEATURE_FLAG_ENV, "1");
        _reset_ack_buffer_for_tests().await;
        let ctx = ctx_with_agent("alice");

        let stored = handle_store_fact(&json!({"entity": "p", "key": "k", "value": "v"}), &ctx)
            .await
            .unwrap();
        let id = stored["content"][0]["text"]
            .as_str()
            .unwrap()
            .trim_start_matches("stored fact ")
            .split_whitespace()
            .next()
            .unwrap()
            .to_string();

        // First ack: empty
        handle_memory_acknowledge_use(&json!({"turn_id": "t-idem", "fact_ids": []}), &ctx)
            .await
            .unwrap();
        assert_eq!(buffered_ack_for_turn("t-idem").await.unwrap().fact_entries.len(), 0);

        // Second ack: same turn, now references the stored fact.
        handle_memory_acknowledge_use(&json!({"turn_id": "t-idem", "fact_ids": [id]}), &ctx)
            .await
            .unwrap();
        let entry = buffered_ack_for_turn("t-idem").await.unwrap();
        assert_eq!(entry.fact_entries.len(), 1, "re-ack must replace, not duplicate");
        std::env::remove_var(FEATURE_FLAG_ENV);
    }

    #[tokio::test]
    async fn fact_ids_must_be_array() {
        let _g = ack_env_lock().lock().await;
        std::env::set_var(FEATURE_FLAG_ENV, "1");
        let ctx = ctx_with_agent("alice");
        let err = handle_memory_acknowledge_use(&json!({"turn_id": "t-bad", "fact_ids": "not-an-array"}), &ctx)
            .await
            .unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
        std::env::remove_var(FEATURE_FLAG_ENV);
    }
}
