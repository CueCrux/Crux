// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Per-turn audit envelope wrapper (master plan §"The audit-envelope wrapper").
//!
//! Master ExecPlan: `agent-ux-best-in-class-master-2026-05-27` (M2 spike).
//!
//! ## What this is
//!
//! Every MCP tool that opts in returns a response of shape
//!
//! ```jsonc
//! {
//!   "payload": { ... existing tool result ... },
//!   "envelope": {
//!     "receipts_used": ["receipt-id-1", ...],
//!     "memories_used": [
//!       {"fact_id": "...", "topic": "...", "age_days": 4, "freshness": "fresh|stale|unknown"}
//!     ],
//!     "autonomy_consumed": {"capability": "facts:read", "cost_credits": 0, "scope": "tenant:foo"},
//!     "predicted_effects": [{"kind": "fact_write", "entity": "...", "key": "..."}],
//!     "links": {"verify": "https://.../v1/receipts/.../verification", "open_in_console": "..."}
//!   }
//! }
//! ```
//!
//! Older agents that ignore `envelope` keep working; the `payload` shape is
//! unchanged from the pre-envelope era. This is enforced by
//! [`crate::dispatch`]: when the feature flag is off, or the tool has not
//! opted in via [`crate::tools::tool_emits_envelope`], the dispatcher
//! returns the unwrapped payload directly (no `envelope` key, no
//! `payload` indirection).
//!
//! ## Opting a tool in
//!
//! 1. Add the tool name to [`crate::tools::tool_emits_envelope`] so the
//!    dispatcher knows it participates in envelope wrapping.
//! 2. Add a match arm in [`build_envelope_for_tool`] that constructs an
//!    [`Envelope`] from the tool's args + [`crate::dispatch::McpContext`].
//!    Keep the builder cheap (target < 2 ms for a 10-fact result; benched
//!    in this module's tests).
//! 3. Never include entries whose source entity has a reserved prefix
//!    (`__agent::`, `__ops::`, `__bootstrap__::`) — use
//!    [`is_reserved_entity`] to filter.
//!
//! ## Feature flag
//!
//! The wrapper is gated by `CORECRUXD_FEATURE_AUDIT_ENVELOPE=1`. Default
//! OFF. See [`envelope_enabled`].

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::dispatch::McpContext;
use crate::scope;
use corecrux_memory::fact_store::FactQuery;

/// Environment variable that gates envelope emission. Default off.
pub const FEATURE_FLAG_ENV: &str = "CORECRUXD_FEATURE_AUDIT_ENVELOPE";

/// Reserved entity prefixes — facts under any of these MUST NOT appear in
/// the envelope's `memories_used`. Mirrors the workspace privacy rule for
/// `__agent::*`, `__ops::*`, `__bootstrap__::*`.
pub const RESERVED_PREFIXES: &[&str] = &["__agent::", "__ops::", "__bootstrap__::"];

/// Number of days after which a fact is considered "stale" by default. The
/// freshness primitive proper (child plan #3 — Freshness + decay) will
/// allow per-fact horizons; for the M2 spike we use a single conservative
/// horizon so we have a non-trivial three-valued freshness signal.
pub const DEFAULT_STALE_AFTER_DAYS: i64 = 30;

/// Return true if envelope emission is enabled via the feature flag.
///
/// Treat any value other than `"0"`, `"false"`, `"off"`, or empty as
/// enabled — matches the convention used elsewhere in `corecruxd`.
pub fn envelope_enabled() -> bool {
    match std::env::var(FEATURE_FLAG_ENV) {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            !matches!(v.as_str(), "" | "0" | "false" | "off" | "no")
        }
        Err(_) => false,
    }
}

/// Return true if the given entity name starts with any reserved prefix.
pub fn is_reserved_entity(entity: &str) -> bool {
    RESERVED_PREFIXES.iter().any(|p| entity.starts_with(p))
}

/// Freshness classifier for a single memory entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Freshness {
    Fresh,
    Stale,
    Unknown,
}

impl Freshness {
    /// Heuristic for the M2 spike: facts younger than
    /// [`DEFAULT_STALE_AFTER_DAYS`] are fresh; older are stale; missing
    /// timestamps fall back to unknown.
    pub fn from_age_days(age_days: Option<i64>) -> Self {
        match age_days {
            Some(d) if d < 0 => Self::Unknown,
            Some(d) if d <= DEFAULT_STALE_AFTER_DAYS => Self::Fresh,
            Some(_) => Self::Stale,
            None => Self::Unknown,
        }
    }
}

/// A single memory the tool consulted to produce its payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryUsed {
    pub fact_id: String,
    pub topic: String,
    pub age_days: Option<i64>,
    pub freshness: Freshness,
}

/// The autonomy "cost" the calling agent spent on this turn. For the M2
/// spike we always emit a zero-cost read entry; later waves wire
/// capability tokens + credit metering.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutonomyConsumed {
    pub capability: String,
    pub cost_credits: u64,
    pub scope: String,
}

/// A side-effect the tool predicts it WOULD perform if invoked with the
/// same args. Read-side tools emit an empty vec.
///
/// ## Backwards compat
///
/// `ts_us` (microseconds since UNIX epoch) is OPTIONAL and skipped on
/// serialisation when absent. Wave-1 (`agent-ux-best-in-class-master`
/// M2 spike) wrote entries without a timestamp; child plan #06
/// (`agent-ux-06-typed-action-traces`) adds the field so the typed-trace
/// ring buffer can render a chronological timeline. Older parsers that
/// don't know about `ts_us` ignore the extra key per serde's default
/// behaviour.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PredictedEffect {
    pub kind: String,
    pub entity: String,
    pub key: String,
    /// Microseconds since UNIX epoch when this effect was recorded.
    /// Omitted when the effect was synthesised from a pre-trace builder
    /// (e.g. the original M2 spike).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ts_us: Option<i64>,
}

impl PredictedEffect {
    /// Construct a trace-aware effect stamped with the current wall clock.
    pub fn now(kind: impl Into<String>, entity: impl Into<String>, key: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            entity: entity.into(),
            key: key.into(),
            ts_us: Some(Utc::now().timestamp_micros()),
        }
    }
}

/// Hyperlinks the host can render to let the user verify / open the
/// resulting receipt or memory in a UI.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnvelopeLinks {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verify: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub open_in_console: Option<String>,
}

/// The full per-turn audit envelope. See module docs for the wire shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub receipts_used: Vec<String>,
    pub memories_used: Vec<MemoryUsed>,
    pub autonomy_consumed: AutonomyConsumed,
    pub predicted_effects: Vec<PredictedEffect>,
    pub links: EnvelopeLinks,
}

impl Envelope {
    /// Wrap an existing payload value into the public envelope shape.
    ///
    /// `payload` should be the tool's existing response value (the same
    /// thing it would return when the feature flag is off).
    pub fn wrap_payload(self, payload: Value) -> Value {
        let envelope = serde_json::to_value(&self).unwrap_or_else(|_| {
            json!({
                "receipts_used": [],
                "memories_used": [],
                "autonomy_consumed": {"capability": "unknown", "cost_credits": 0, "scope": ""},
                "predicted_effects": [],
                "links": {},
            })
        });
        json!({ "payload": payload, "envelope": envelope })
    }
}

// ── per-tool builders ─────────────────────────────────────────────────────

/// Build an envelope for a tool call.
///
/// Returns `None` for tools that do not have a builder yet — the
/// dispatcher then returns the raw payload as if envelope were off for
/// that call (still backwards-compatible).
pub async fn build_envelope_for_tool(name: &str, args: &Value, ctx: &McpContext) -> Option<Envelope> {
    match name {
        "query_facts" => Some(build_envelope_for_query_facts(args, ctx).await),
        // agent-ux-02 (Acknowledged Memory Use): the ack tool emits an
        // envelope whose memories_used[] mirrors the just-written
        // pending-ack buffer entry. Built by the tool module so the
        // envelope wrapper itself stays free of tool-specific state.
        "memory_acknowledge_use" => {
            Some(crate::tools::memory_use::build_envelope_for_memory_acknowledge_use(args, ctx).await)
        }
        // memory_freshness (child plan agent-ux-03 M3) opts in to the
        // same envelope shape as query_facts. The freshness tool's own
        // payload already carries per-fact freshness; the envelope's
        // memories_used[] gives non-freshness readers (audit
        // consumers) the same reserved-prefix-safe view.
        "memory_freshness" => Some(build_envelope_for_query_facts(args, ctx).await),
        // agent-ux-12: artefact_list surfaces parked artefact ids as
        // memories_used[] entries so the host can render "I parked this for
        // you" affordances. Reserved-prefix mime types are stripped by the
        // builder (defence-in-depth — the underlying list filter already
        // enforces T.1).
        "artefact_list" => Some(crate::tools::artefacts::build_envelope_for_artefact_list(args, ctx).await),
        _ => None,
    }
}

/// Builder for `query_facts`. Mirrors the visibility filter used by the
/// real handler (`scope::fact_visible_to_agent`) so the envelope never
/// reveals a fact the caller couldn't query directly. Reserved-prefix
/// entities are additionally stripped so the envelope can never leak
/// `__agent::*` / `__ops::*` / `__bootstrap__::*` even though those
/// entities can be legitimately written.
pub async fn build_envelope_for_query_facts(args: &Value, ctx: &McpContext) -> Envelope {
    let query = args.get("query").and_then(|v| v.as_str()).map(|s| s.to_string());
    let entity = args.get("entity").and_then(|v| v.as_str()).map(|s| s.to_string());
    let top_k = args.get("top_k").and_then(|v| v.as_u64()).unwrap_or(10) as usize;
    let token_budget = args.get("token_budget").and_then(|v| v.as_u64()).map(|v| v as usize);
    let agent_name = scope::agent_name(ctx.agent.as_ref());

    let q = FactQuery {
        query,
        entity,
        entity_prefix: None,
        top_k,
        token_budget,
    };

    let store = ctx.fact_store.read().await;
    let facts = crate::tools::facts::envelope_query_visible_facts(&store, &q, agent_name);
    drop(store);

    let now = Utc::now();
    // Decay policy is process-env-derived; same inputs -> same output
    // so re-querying the envelope on the same fact set is replay-safe.
    let policy = corecrux_projections::decay::DecayPolicy::from_env();
    let mut memories_used: Vec<MemoryUsed> = Vec::with_capacity(facts.len());
    let mut receipts_used: Vec<String> = Vec::new();
    for f in &facts {
        if is_reserved_entity(&f.entity) {
            continue;
        }
        let age_days = (now - f.stored_at).num_days();
        let age_days = if age_days < 0 { None } else { Some(age_days) };
        let topic = scope::visible_entity_for_agent(f, agent_name).unwrap_or_else(|| f.entity.clone());
        // Master ExecPlan M3 "envelope nudge": prefer the per-fact
        // horizon_class -> decay::apply_at_chrono signal over the
        // single-horizon spike heuristic. Falls back to the spike
        // heuristic when the fact predates the freshness primitive
        // (HorizonClass::None on a still-fresh fact would otherwise
        // mask the staleness everyone wants to see).
        let proj_class = crate::tools::freshness::projection_class_of(f.horizon_class);
        let decay_signal =
            corecrux_projections::decay::apply_at_chrono(proj_class, f.stored_at, f.reverified_at, now, policy);
        let freshness = if matches!(f.horizon_class, corecrux_memory::HorizonClass::None) {
            Freshness::from_age_days(age_days)
        } else {
            match decay_signal {
                corecrux_projections::decay::Freshness::Fresh => Freshness::Fresh,
                corecrux_projections::decay::Freshness::Stale => Freshness::Stale,
                corecrux_projections::decay::Freshness::Unknown => Freshness::Unknown,
            }
        };
        memories_used.push(MemoryUsed {
            fact_id: f.fact_id.clone(),
            topic,
            age_days,
            freshness,
        });
        if let Some(receipt) = &f.source_receipt {
            if !receipts_used.contains(receipt) {
                receipts_used.push(receipt.clone());
            }
        }
    }

    let scope = scope::agent_name(ctx.agent.as_ref())
        .map_or_else(|| format!("node:{}", ctx.node_id), |name| format!("agent:{name}"));

    // agent-ux-04 (source-linked traceability): when at least one receipt id
    // landed in `receipts_used` AND the daemon's loopback base is known, point
    // `links.verify` at the FIRST receipt's verification endpoint. The host
    // IDE can render a one-click "verify ↗" badge from this URL alone; the
    // full list of receipts is still available in `receipts_used[]` so a
    // multi-receipt drawer can fan out further verify links itself.
    let links = if let (Some(first), Some(base)) = (receipts_used.first(), ctx.daemon_base_url.as_deref()) {
        EnvelopeLinks {
            verify: Some(crate::tools::receipt_verify::build_verification_url(
                base, "default", first,
            )),
            open_in_console: None,
        }
    } else {
        EnvelopeLinks::default()
    };

    Envelope {
        receipts_used,
        memories_used,
        autonomy_consumed: AutonomyConsumed {
            capability: "facts:read".to_string(),
            cost_credits: 0,
            scope,
        },
        // query_facts is read-only — no side effects to predict.
        predicted_effects: Vec::new(),
        links,
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::dispatch::McpContext;
    use crate::tools::facts::handle_store_fact;

    fn test_ctx() -> McpContext {
        McpContext::new_default("test-node-envelope")
    }

    #[test]
    fn envelope_flag_default_off() {
        // Use a unique env var probe — don't mutate FEATURE_FLAG_ENV here
        // because other tests may run in parallel. Just assert that absent
        // env, envelope_enabled() returns false.
        std::env::remove_var(FEATURE_FLAG_ENV);
        assert!(!envelope_enabled());
    }

    #[test]
    fn reserved_prefix_detection() {
        assert!(is_reserved_entity("__agent::alice::notes"));
        assert!(is_reserved_entity("__ops::config-audit"));
        assert!(is_reserved_entity("__bootstrap__::pattern:retry"));
        assert!(!is_reserved_entity("project-alpha"));
        assert!(!is_reserved_entity("agent::not-reserved"));
    }

    #[test]
    fn freshness_classifier_three_valued() {
        assert_eq!(Freshness::from_age_days(Some(0)), Freshness::Fresh);
        assert_eq!(Freshness::from_age_days(Some(7)), Freshness::Fresh);
        assert_eq!(
            Freshness::from_age_days(Some(DEFAULT_STALE_AFTER_DAYS)),
            Freshness::Fresh
        );
        assert_eq!(
            Freshness::from_age_days(Some(DEFAULT_STALE_AFTER_DAYS + 1)),
            Freshness::Stale
        );
        assert_eq!(Freshness::from_age_days(None), Freshness::Unknown);
        assert_eq!(Freshness::from_age_days(Some(-1)), Freshness::Unknown);
    }

    #[tokio::test]
    async fn envelope_excludes_reserved_prefix_entries() {
        let ctx = test_ctx();
        // A normal fact AND a reserved-prefix fact, both matching the query.
        handle_store_fact(
            &json!({"entity": "project-alpha", "key": "status", "value": "shipped"}),
            &ctx,
        )
        .await
        .unwrap();
        handle_store_fact(
            &json!({"entity": "__ops::config-audit", "key": "sha256:abc", "value": "shipped"}),
            &ctx,
        )
        .await
        .unwrap();
        handle_store_fact(
            &json!({"entity": "__bootstrap__::pattern:x", "key": "Retry", "value": "shipped"}),
            &ctx,
        )
        .await
        .unwrap();

        let envelope = build_envelope_for_query_facts(&json!({"query": "shipped"}), &ctx).await;
        // Only project-alpha should appear.
        assert_eq!(envelope.memories_used.len(), 1);
        assert_eq!(envelope.memories_used[0].topic, "project-alpha");
        for m in &envelope.memories_used {
            assert!(
                !is_reserved_entity(&m.topic),
                "envelope leaked reserved entity {}",
                m.topic
            );
        }
    }

    #[tokio::test]
    async fn envelope_carries_receipt_ids_dedup() {
        let ctx = test_ctx();
        handle_store_fact(
            &json!({"entity": "p", "key": "a", "value": "x", "source_receipt": "r_001"}),
            &ctx,
        )
        .await
        .unwrap();
        handle_store_fact(
            &json!({"entity": "p", "key": "b", "value": "x", "source_receipt": "r_001"}),
            &ctx,
        )
        .await
        .unwrap();
        handle_store_fact(
            &json!({"entity": "p", "key": "c", "value": "x", "source_receipt": "r_002"}),
            &ctx,
        )
        .await
        .unwrap();

        let envelope = build_envelope_for_query_facts(&json!({"query": "x"}), &ctx).await;
        assert_eq!(envelope.memories_used.len(), 3);
        let mut receipts = envelope.receipts_used.clone();
        receipts.sort();
        assert_eq!(receipts, vec!["r_001", "r_002"]);
    }

    #[tokio::test]
    async fn envelope_freshness_marks_fresh_for_just_stored_facts() {
        let ctx = test_ctx();
        handle_store_fact(&json!({"entity": "p", "key": "k", "value": "v"}), &ctx)
            .await
            .unwrap();
        let envelope = build_envelope_for_query_facts(&json!({"query": "v"}), &ctx).await;
        assert_eq!(envelope.memories_used.len(), 1);
        assert_eq!(envelope.memories_used[0].freshness, Freshness::Fresh);
        // The fact was just stored — age should be 0 days.
        assert_eq!(envelope.memories_used[0].age_days, Some(0));
    }

    #[tokio::test]
    async fn envelope_wrap_preserves_payload_shape() {
        let env = Envelope {
            receipts_used: vec!["r1".to_string()],
            memories_used: vec![],
            autonomy_consumed: AutonomyConsumed {
                capability: "facts:read".to_string(),
                cost_credits: 0,
                scope: "node:test".to_string(),
            },
            predicted_effects: vec![],
            links: EnvelopeLinks::default(),
        };
        let payload = json!({"content": [{"type": "text", "text": "hi"}]});
        let wrapped = env.wrap_payload(payload.clone());
        assert_eq!(wrapped["payload"], payload);
        assert_eq!(wrapped["envelope"]["receipts_used"][0], "r1");
        assert_eq!(wrapped["envelope"]["autonomy_consumed"]["capability"], "facts:read");
        assert!(wrapped["envelope"]["memories_used"].is_array());
        assert!(wrapped["envelope"]["predicted_effects"].is_array());
        assert!(wrapped["envelope"]["links"].is_object());
    }

    #[tokio::test]
    async fn envelope_build_latency_under_2ms_for_10_facts() {
        // Acceptance test: master plan M2 requires envelope build < 2 ms
        // for a 10-fact result.
        let ctx = test_ctx();
        for i in 0..10 {
            handle_store_fact(&json!({"entity": "p", "key": format!("k{i}"), "value": "needle"}), &ctx)
                .await
                .unwrap();
        }
        // Warm one call to pay any per-process init cost (string interning,
        // tokio waker setup) before measuring.
        let _ = build_envelope_for_query_facts(&json!({"query": "needle"}), &ctx).await;

        let start = std::time::Instant::now();
        let env = build_envelope_for_query_facts(&json!({"query": "needle"}), &ctx).await;
        let elapsed = start.elapsed();
        assert_eq!(env.memories_used.len(), 10);
        eprintln!(
            "envelope_build_latency_under_2ms_for_10_facts: build took {} us ({elapsed:?})",
            elapsed.as_micros()
        );
        assert!(
            elapsed < std::time::Duration::from_millis(2),
            "envelope build for 10 facts took {elapsed:?}, expected < 2ms",
        );
    }

    #[tokio::test]
    async fn envelope_empty_when_no_facts() {
        let ctx = test_ctx();
        let env = build_envelope_for_query_facts(&json!({"query": "nothing"}), &ctx).await;
        assert!(env.memories_used.is_empty());
        assert!(env.receipts_used.is_empty());
        assert!(env.predicted_effects.is_empty());
        assert_eq!(env.autonomy_consumed.capability, "facts:read");
    }

    /// agent-ux-04: when query_facts surfaces a fact with a `source_receipt`
    /// AND the dispatcher has a `daemon_base_url`, the envelope's `links.verify`
    /// must point at `/v1/receipts/<id>/verification` for the first receipt.
    /// This is the load-bearing wiring for the host-IDE "verify ↗" badge.
    #[tokio::test]
    async fn envelope_links_verify_populated_when_receipt_present() {
        let ctx = test_ctx().with_daemon_base_url("http://127.0.0.1:14800");
        handle_store_fact(
            &json!({"entity": "p", "key": "a", "value": "linkable", "source_receipt": "r_ux04_001"}),
            &ctx,
        )
        .await
        .unwrap();
        let env = build_envelope_for_query_facts(&json!({"query": "linkable"}), &ctx).await;
        assert_eq!(env.receipts_used, vec!["r_ux04_001"]);
        let verify = env.links.verify.as_deref().expect("links.verify must be populated");
        assert!(
            verify.starts_with("http://127.0.0.1:14800/v1/receipts/r_ux04_001/verification"),
            "verify link must hit the existing route; got {verify}"
        );
        assert!(
            verify.contains("tenant_id=default"),
            "verify link must carry tenant_id query param; got {verify}"
        );
    }

    /// Without a `daemon_base_url`, the envelope still emits receipt ids in
    /// `receipts_used[]` but `links.verify` is omitted (host falls back to
    /// `corecruxctl receipts verify <id>` per the child plan's free-tier
    /// offline-verify hint).
    #[tokio::test]
    async fn envelope_links_verify_absent_when_no_daemon_base_url() {
        let ctx = test_ctx(); // no daemon_base_url
        handle_store_fact(
            &json!({"entity": "p", "key": "a", "value": "off", "source_receipt": "r_offline"}),
            &ctx,
        )
        .await
        .unwrap();
        let env = build_envelope_for_query_facts(&json!({"query": "off"}), &ctx).await;
        assert_eq!(env.receipts_used, vec!["r_offline"]);
        assert!(
            env.links.verify.is_none(),
            "verify link must be absent without a loopback base"
        );
    }

    /// If the result has no receipts, `links.verify` stays absent regardless
    /// of `daemon_base_url`.
    #[tokio::test]
    async fn envelope_links_verify_absent_when_no_receipts() {
        let ctx = test_ctx().with_daemon_base_url("http://127.0.0.1:14800");
        handle_store_fact(&json!({"entity": "p", "key": "a", "value": "no-receipt"}), &ctx)
            .await
            .unwrap();
        let env = build_envelope_for_query_facts(&json!({"query": "no-receipt"}), &ctx).await;
        assert!(env.receipts_used.is_empty());
        assert!(env.links.verify.is_none());
    }

    #[tokio::test]
    async fn build_envelope_for_unknown_tool_returns_none() {
        let ctx = test_ctx();
        let env = build_envelope_for_tool("not_a_tool", &json!({}), &ctx).await;
        assert!(env.is_none());
    }

    // ── agent-ux-06: predicted_effects.ts_us is backwards-compatible ─────
    //
    // Older payloads (M2 spike) shipped without `ts_us`. New consumers
    // must still parse them, and old consumers must still parse new ones.

    #[test]
    fn predicted_effect_legacy_payload_parses_without_ts_us() {
        // Legacy shape: {kind, entity, key} only.
        let legacy = json!({"kind": "fact_write", "entity": "p", "key": "k"});
        let parsed: PredictedEffect = serde_json::from_value(legacy).unwrap();
        assert_eq!(parsed.kind, "fact_write");
        assert_eq!(parsed.entity, "p");
        assert_eq!(parsed.key, "k");
        assert!(parsed.ts_us.is_none());
    }

    #[test]
    fn predicted_effect_serialises_without_ts_us_when_absent() {
        let eff = PredictedEffect {
            kind: "fact_read".to_string(),
            entity: "e".to_string(),
            key: "k".to_string(),
            ts_us: None,
        };
        let s = serde_json::to_string(&eff).unwrap();
        assert!(!s.contains("ts_us"), "ts_us must be omitted when None: {s}");
    }

    #[test]
    fn predicted_effect_serialises_with_ts_us_when_present() {
        let eff = PredictedEffect::now("fact_write", "alpha", "status");
        assert!(eff.ts_us.is_some());
        let s = serde_json::to_string(&eff).unwrap();
        assert!(s.contains("ts_us"), "ts_us must be present in JSON: {s}");
    }
}
