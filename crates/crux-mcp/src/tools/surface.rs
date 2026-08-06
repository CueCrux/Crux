// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Tool-surface shaping — graph-driven dynamic tool surface (M1–M4).
//!
//! ExecPlan: `crux-mcp-dynamic-tool-surface-2026-06-08`.
//!
//! The full MCP surface serialises to ~27.8k tokens (~100 tools), re-sent on
//! every API turn. This module shrinks the *advertised* surface without
//! removing capability: a tool dropped from `tools/list` stays callable via
//! `tools/call` (dispatch is by-name and gated only by
//! `enforce_rcx_tool_capability`, not by the surface),
//! and remains discoverable through the `cuecrux_session` capability graph.
//!
//! Modes (process flag `CORECRUXD_TOOL_SURFACE`, default `full`):
//! - `full` — unchanged ~100-tool surface (byte-for-byte the pre-M1 behaviour).
//! - `minimal` (M1) — the [`CORE_FLOOR`] only (~16 tools), so a cold agent can
//!   still bootstrap (discover → retrieve → remember → session continuity) and
//!   reach everything else by name.
//! - `dynamic` (M2/M3/M4) — the floor plus up to [`DYNAMIC_TOP_N`] tools scored
//!   by the agent's last declared intent (captured from `cuecrux_session(intent=…)`
//!   via [`record_intent`], persisted per passport) blended with recent tool-use
//!   from the trace ring ([`trace_boosts_from_recent`], M4). No intent and no
//!   recent activity ⇒ floor only. The base `POST /mcp` transport is
//!   request/response, so shaping is read on the next `tools/list`; a client that
//!   opens the `GET /mcp` SSE stream (M3.5, see [`crate::sse`]) additionally gets
//!   a live `tools/list_changed` push when the intent changes.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use crux_session::intent::default_intent_table;

use super::ToolDefinition;
use crate::traces::TraceEntry;

/// Count of intent-relevant tools surfaced *beyond* the [`CORE_FLOOR`] in
/// `dynamic` mode. Floor (~16) + this ≈ a ~28-tool intent-targeted surface —
/// still a large cut from the full ~95, but with the right tools for the task.
pub const DYNAMIC_TOP_N: usize = 12;

/// How long a declared intent keeps shaping the surface (seconds). A stale
/// intent must not pin an old shape forever; matches the default session TTL.
const INTENT_TTL_SECONDS: i64 = 3600;

/// Always-surfaced core set (ExecPlan C4). Lets an agent with zero prior calls
/// run the core loop — discover (`cuecrux_session`), retrieve (`query*`),
/// remember (`store_fact`/`query_facts`/`get_bootstrap`/`memory_view`), keep
/// session continuity (`save_session`/`get_session`), self-identify
/// (`get_agent_identity`/`get_passport`), verify a receipt (`receipt_verify`),
/// and read sync posture (`sync_status`). Every name here is asserted to exist
/// in the full surface by the `core_floor_names_exist_in_full_surface` test, so
/// a typo fails the build rather than silently shrinking the floor.
pub const CORE_FLOOR: &[&str] = &[
    "cuecrux_session", // discovery — the collapsed-surface entry point (always first)
    "query",
    "query_scan",
    "query_expand",
    "store_fact",
    "query_facts",
    "get_bootstrap",
    "memory_view",
    "save_session",
    "get_session",
    "get_agent_identity",
    "get_passport",   // identity — bootstrap passport/tier without knowing the tool name
    "receipt_verify", // proof — verify a CROWN receipt offline
    "sync_status",    // ops — daemon sync posture (local_only/degraded) for cold-start decisions
    // Coordination — cross-session handoff must be discoverable on the
    // collapsed surface: clients only call advertised tools, and the Phase T
    // S1 faithful-handoff measurement (`CORECRUXD_HANDOFF_OBSERVATIONS`)
    // records nothing if no client ever surfaces these.
    "create_handoff",
    "accept_handoff",
];

/// How the `tools/list` surface is shaped before serialisation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ToolSurfaceMode {
    /// Full surface — current behaviour. The default so flag-off is a no-op.
    #[default]
    Full,
    /// Core floor only (static).
    Minimal,
    /// Floor + weighted top-N (M3). Interim: behaves as [`Self::Minimal`].
    Dynamic,
}

impl ToolSurfaceMode {
    /// Read the mode from `CORECRUXD_TOOL_SURFACE` (case-insensitive). Any
    /// unrecognised or unset value is [`Self::Full`] so a stray value can never
    /// silently shrink a production surface.
    pub fn from_env() -> Self {
        match std::env::var("CORECRUXD_TOOL_SURFACE") {
            Ok(v) => Self::from_str_lenient(&v),
            Err(_) => Self::Full,
        }
    }

    fn from_str_lenient(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "minimal" => Self::Minimal,
            "dynamic" => Self::Dynamic,
            _ => Self::Full,
        }
    }

    /// Stable lowercase wire string (ledger `agent.tools_offered.v1` events).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Minimal => "minimal",
            Self::Dynamic => "dynamic",
        }
    }
}

/// Shape an authorisation-filtered tool list according to `mode`.
///
/// **Invariant:** the input is already the authz-allowed set (this composes
/// *after* the RCX router). Shaping only ever *removes* advertisements; it never
/// adds a tool, so it cannot widen authorisation. `Full` is the identity.
pub fn apply_surface_mode(tools: Vec<ToolDefinition>, mode: ToolSurfaceMode) -> Vec<ToolDefinition> {
    match mode {
        ToolSurfaceMode::Full => tools,
        // Minimal = the floor. Dynamic with no intent context also collapses to
        // the floor (the real intent-weighted path is `shape_dynamic`, called by
        // `list_tools_json_for_context` which has the passport key).
        ToolSurfaceMode::Minimal | ToolSurfaceMode::Dynamic => tools
            .into_iter()
            .filter(|t| CORE_FLOOR.contains(&t.name.as_str()))
            .collect(),
    }
}

// ── M2: intent capture (persisted per-passport interaction signal) ──────────
//
// The MCP transport is stateless HTTP POST (one request → one response, no
// server→client channel), so `tools/list_changed` cannot be pushed. Instead the
// agent's declared intent is persisted here, keyed by passport, and read on the
// *next* `tools/list` to shape the surface. Mirrors the process-global pattern
// of [`crate::traces`] — no `McpContext` field churn.

#[derive(Clone)]
struct IntentRecord {
    intent: String,
    set_at_unix: i64,
}

fn intent_store() -> &'static Mutex<HashMap<String, IntentRecord>> {
    static STORE: OnceLock<Mutex<HashMap<String, IntentRecord>>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn now_unix() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Record the intent an agent declared via `cuecrux_session(intent=…)`, keyed
/// by passport. An empty/blank intent clears any prior record (back to floor).
pub fn record_intent(passport: &str, intent: &str) {
    let mut store = intent_store().lock().unwrap_or_else(|p| p.into_inner());
    let trimmed = intent.trim();
    if trimmed.is_empty() {
        store.remove(passport);
    } else {
        store.insert(
            passport.to_string(),
            IntentRecord {
                intent: trimmed.to_string(),
                set_at_unix: now_unix(),
            },
        );
    }
}

/// The agent's current (non-expired) intent, if any. Expired records are
/// evicted on read so a long-idle passport falls back to the floor.
pub fn current_intent(passport: &str) -> Option<String> {
    let mut store = intent_store().lock().unwrap_or_else(|p| p.into_inner());
    match store.get(passport) {
        Some(rec) if now_unix().saturating_sub(rec.set_at_unix) <= INTENT_TTL_SECONDS => Some(rec.intent.clone()),
        Some(_) => {
            store.remove(passport);
            None
        }
        None => None,
    }
}

// ── M3: intent-weighted dynamic shaping ─────────────────────────────────────

/// Best-effort affinity tag for a tool, used to bias the dynamic surface by the
/// declared intent (reusing `crux_session`'s intent→affinity table so the tool
/// ranker and the capability-graph ranker stay consistent). Tools with no clear
/// affinity return `""` (bias 0 — never surfaced beyond the floor). Advertisement
/// only; never an auth/rate-limit input.
pub fn tool_affinity(tool: &str) -> &'static str {
    match tool {
        "query" | "query_scan" | "query_expand" | "get_gaps" => "retrieval",
        "store_fact"
        | "query_facts"
        | "delete_fact"
        | "fact_history"
        | "get_bootstrap"
        | "list_entities"
        | "memory_view"
        | "memory_edit"
        | "memory_pin"
        | "memory_history"
        | "memory_freshness"
        | "memory_forget"
        | "memory_forget_dry_run"
        | "memory_sweep_candidates"
        | "memory_set_horizon"
        | "memory_reverify"
        | "memory_acknowledge_use"
        | "artefact_put"
        | "artefact_get"
        | "artefact_list"
        // Substrate CRUD: entities, edges and the kind registry. The whole
        // family had no entry, so every one scored 0 and was reachable only by
        // an agent that already knew the name — `tools/list` advertises the
        // floor, and none of them are in it. That is not theoretical: a session
        // reconciling the Feature Registry's capability graph read `tools/list`,
        // concluded the daemon had no `edge_delete`, and recorded a stale edge
        // as permanently unfixable. It had been there the whole time.
        //
        // "memory" because that is exactly what they are — `corecrux-memory`
        // owns entities, edges and the kind registry alongside the fact store,
        // and `list_entities` was already tagged this way.
        | "entity_upsert"
        | "entity_get"
        | "entity_list"
        | "entity_delete"
        | "entity_history"
        | "edge_upsert"
        | "edge_get"
        | "edge_list"
        | "edge_delete"
        | "kind_get"
        | "kind_list" => "memory",
        "save_session"
        | "get_session"
        | "list_sessions"
        | "delete_session"
        | "archive_session"
        | "unarchive_session"
        | "cuecrux_session"
        | "create_handoff"
        | "accept_handoff"
        | "get_workspace_storyline"
        | "register_repo"
        | "list_repos"
        // Context graph (storybook + dossiers). These belong beside
        // create_handoff/accept_handoff rather than under "memory": a dossier IS
        // the cross-session handoff of what an agent worked out, and the
        // storybook is the project state a resuming session reads first.
        // Without an entry here they score 0 and never surface beyond the floor
        // in ANY intent, so an agent could only reach them by already knowing
        // their names — which is the discovery problem they were built to solve.
        | "get_project_storybook"
        | "generate_project_storybook"
        | "diff_project_storybook"
        | "get_project_dossiers"
        | "generate_project_dossier"
        | "publish_project_dossier"
        | "reconcile_project_dossiers"
        | "diff_project_dossiers" => "session",
        "audit_config"
        | "check_config_audit"
        | "audit_export_bundle"
        | "record_decision"
        | "declare_constraint"
        | "get_constraints"
        | "check_constraints"
        | "list_observations"
        | "get_observation"
        | "verify_observation"
        | "tool_trace_recent"
        | "learn"
        | "token_savings" => "audit",
        "proof_verify" | "receipt_verify" | "output_attest" => "proof",
        _ => "",
    }
}

/// Shape the surface for `dynamic` mode: the [`CORE_FLOOR`] (always, in floor
/// order) plus up to `top_n` intent-relevant tools, ranked by the declared
/// intent's affinity bias (deterministic, stable tie-break by original order).
///
/// `intent = None` or an unknown intent ⇒ floor only (identical to `minimal`),
/// so a cold start or a free-text intent the table doesn't know degrades
/// gracefully. Only tools with a positive intent bias are added — the surface
/// never pads with irrelevant tools, preserving the token win.
pub fn shape_dynamic(tools: Vec<ToolDefinition>, intent: Option<&str>, top_n: usize) -> Vec<ToolDefinition> {
    shape_dynamic_weighted(tools, intent, &HashMap::new(), top_n)
}

/// Each occurrence of a tool in the recent trace window adds this much score…
const TRACE_BOOST_PER_HIT: i32 = 4;
/// …capped here, so a heavily-used tool can outrank a weak/absent intent signal
/// but never a strong one (intent affinity bias tops out at 30).
const TRACE_BOOST_CAP: i32 = 12;

/// Per-tool recency boost from recent dispatch history (M4 "what the agent just
/// did" signal): each occurrence in the trace window adds `TRACE_BOOST_PER_HIT`,
/// capped at `TRACE_BOOST_CAP`. Floor tools are skipped (already pinned).
pub fn trace_boosts_from_recent(entries: &[TraceEntry]) -> HashMap<String, i32> {
    let mut boosts: HashMap<String, i32> = HashMap::new();
    for e in entries {
        if CORE_FLOOR.contains(&e.tool.as_str()) {
            continue;
        }
        let slot = boosts.entry(e.tool.clone()).or_insert(0);
        *slot = (*slot + TRACE_BOOST_PER_HIT).min(TRACE_BOOST_CAP);
    }
    boosts
}

/// Like [`shape_dynamic`], but combines the declared-intent affinity bias (M3)
/// with a per-tool recency boost from the trace ring (M4):
/// `score(tool) = intent_bias(affinity(tool)) + trace_boost(tool)`. Only
/// `score > 0` tools are added beyond the floor, top-`top_n` by score
/// (deterministic, stable tie-break by original order — C5).
///
/// **Authz-non-expansion (C2):** the output is always a subset of the input —
/// shaping only re-orders and truncates the already-authorised set; a tool named
/// in `trace_boosts` but absent from `tools` is never surfaced.
pub fn shape_dynamic_weighted(
    tools: Vec<ToolDefinition>,
    intent: Option<&str>,
    trace_boosts: &HashMap<String, i32>,
    top_n: usize,
) -> Vec<ToolDefinition> {
    let (mut floor, rest): (Vec<ToolDefinition>, Vec<ToolDefinition>) =
        tools.into_iter().partition(|t| CORE_FLOOR.contains(&t.name.as_str()));
    floor.sort_by_key(|t| {
        CORE_FLOOR
            .iter()
            .position(|f| *f == t.name.as_str())
            .unwrap_or(usize::MAX)
    });

    // Intent affinity bias (0 when intent is None or unknown). Reuses the
    // capability-graph intent table so the tool ranker ≡ the graph ranker.
    let table = default_intent_table();
    let biases = intent.and_then(|key| table.get(key));
    let intent_bias =
        |affinity: &str| -> i32 { biases.map_or(0, |b| b.iter().find(|(a, _)| *a == affinity).map_or(0, |(_, x)| *x)) };

    let mut ranked: Vec<(i32, usize, ToolDefinition)> = rest
        .into_iter()
        .enumerate()
        .map(|(i, t)| {
            let score = intent_bias(tool_affinity(&t.name)) + trace_boosts.get(&t.name).copied().unwrap_or(0);
            (score, i, t)
        })
        .collect();
    // Highest score first; stable by original order on ties (deterministic, C5).
    ranked.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));

    let picked = ranked
        .into_iter()
        .filter(|(score, _, _)| *score > 0)
        .take(top_n)
        .map(|(_, _, t)| t);
    floor.into_iter().chain(picked).collect()
}

#[cfg(test)]
pub fn clear_intent_for_test(passport: &str) {
    intent_store()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(passport);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::list_tools;

    #[test]
    fn core_floor_names_exist_in_full_surface() {
        let full: Vec<String> = list_tools().into_iter().map(|t| t.name).collect();
        for name in CORE_FLOOR {
            assert!(
                full.iter().any(|n| n == name),
                "CORE_FLOOR tool `{name}` is not in the full surface (typo or removed)"
            );
        }
    }

    #[test]
    fn core_floor_has_no_duplicates_and_leads_with_session() {
        assert_eq!(
            CORE_FLOOR[0], "cuecrux_session",
            "discovery entry point must lead the floor"
        );
        let mut seen = std::collections::HashSet::new();
        for n in CORE_FLOOR {
            assert!(seen.insert(*n), "duplicate floor tool `{n}`");
        }
    }

    #[test]
    fn full_mode_is_identity() {
        let before = list_tools();
        let n = before.len();
        let after = apply_surface_mode(before, ToolSurfaceMode::Full);
        assert_eq!(after.len(), n, "Full mode must not change the surface");
    }

    #[test]
    fn minimal_mode_returns_exactly_the_floor_intersection() {
        let shaped = apply_surface_mode(list_tools(), ToolSurfaceMode::Minimal);
        let names: Vec<&str> = shaped.iter().map(|t| t.name.as_str()).collect();
        // Every shaped tool is a floor tool …
        for n in &names {
            assert!(CORE_FLOOR.contains(n), "minimal surfaced a non-floor tool `{n}`");
        }
        // … and the whole floor is present (it all exists in the full surface).
        assert_eq!(names.len(), CORE_FLOOR.len(), "minimal must surface the entire floor");
        assert!(
            shaped.len() < list_tools().len(),
            "minimal must be strictly smaller than full"
        );
        assert_eq!(names[0], "cuecrux_session", "cuecrux_session stays first");
    }

    #[test]
    fn shape_dynamic_no_intent_is_floor_only() {
        let shaped = shape_dynamic(list_tools(), None, DYNAMIC_TOP_N);
        let names: Vec<&str> = shaped.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names.len(), CORE_FLOOR.len(), "no intent ⇒ floor only");
        assert_eq!(names[0], "cuecrux_session");
        for n in &names {
            assert!(CORE_FLOOR.contains(n));
        }
    }

    #[test]
    fn shape_dynamic_unknown_intent_is_floor_only() {
        let shaped = shape_dynamic(list_tools(), Some("not_a_known_intent"), DYNAMIC_TOP_N);
        assert_eq!(shaped.len(), CORE_FLOOR.len(), "unknown intent degrades to floor");
    }

    #[test]
    fn shape_dynamic_audit_review_surfaces_audit_and_proof_tools() {
        let shaped = shape_dynamic(list_tools(), Some("audit_review"), DYNAMIC_TOP_N);
        let names: Vec<&str> = shaped.iter().map(|t| t.name.as_str()).collect();
        // Floor still present and first.
        assert_eq!(names[0], "cuecrux_session");
        for f in CORE_FLOOR {
            assert!(names.contains(f), "floor tool `{f}` dropped");
        }
        // Intent-relevant audit tools are surfaced (audit has the top bias=30,
        // so audit-affinity tools dominate the top-N) …
        assert!(
            names.contains(&"audit_config"),
            "audit intent should surface audit_config"
        );
        // … plus at least one proof tool (bias=20) makes the cut …
        assert!(
            names.contains(&"output_attest") || names.contains(&"receipt_verify"),
            "audit intent should surface a proof tool"
        );
        // … and clearly-irrelevant tools (bias 0) are NOT.
        assert!(
            !names.contains(&"github_search"),
            "irrelevant tool must not be surfaced"
        );
        assert!(!names.contains(&"list_work"), "irrelevant tool must not be surfaced");
        assert!(names.len() <= CORE_FLOOR.len() + DYNAMIC_TOP_N, "respects top_n cap");
        assert!(names.len() < list_tools().len(), "still far smaller than full");
    }

    #[test]
    fn shape_dynamic_is_deterministic() {
        let a = shape_dynamic(list_tools(), Some("knowledge_query"), DYNAMIC_TOP_N);
        let b = shape_dynamic(list_tools(), Some("knowledge_query"), DYNAMIC_TOP_N);
        let an: Vec<&str> = a.iter().map(|t| t.name.as_str()).collect();
        let bn: Vec<&str> = b.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(an, bn, "shaped surface must be reproducible (C5)");
    }

    #[test]
    fn shape_dynamic_caps_beyond_floor_at_top_n() {
        let shaped = shape_dynamic(list_tools(), Some("audit_review"), 2);
        assert!(
            shaped.len() <= CORE_FLOOR.len() + 2,
            "must not exceed floor + top_n, got {}",
            shaped.len()
        );
    }

    #[test]
    fn tool_affinity_maps_known_tools_and_defaults_empty() {
        assert_eq!(tool_affinity("query"), "retrieval");
        assert_eq!(tool_affinity("memory_view"), "memory");
        assert_eq!(tool_affinity("audit_config"), "audit");
        assert_eq!(tool_affinity("receipt_verify"), "proof");
        assert_eq!(tool_affinity("save_session"), "session");
        assert_eq!(tool_affinity("github_search"), "", "unmapped tool ⇒ no affinity");
    }

    /// An unmapped tool scores 0 and is unreachable beyond the floor in every
    /// intent. That is correct for a tool an agent would never want surfaced,
    /// and wrong for one whose whole purpose is to be found — so the
    /// context-graph family is asserted mapped, by name, rather than left to be
    /// silently forgotten the next time a tool is added.
    #[test]
    fn every_context_graph_tool_has_an_affinity() {
        for tool in [
            "get_project_storybook",
            "generate_project_storybook",
            "diff_project_storybook",
            "get_project_dossiers",
            "generate_project_dossier",
            "publish_project_dossier",
            "reconcile_project_dossiers",
            "diff_project_dossiers",
        ] {
            assert_eq!(
                tool_affinity(tool),
                "session",
                "{tool} must carry an affinity or it can never be surfaced beyond the floor"
            );
        }
    }

    /// Same reasoning as the context-graph family, learned the hard way. The
    /// substrate CRUD tools carried no affinity at all, so they scored 0 in
    /// every intent and never appeared beyond the 16-tool floor. An agent
    /// reconciling the Feature Registry's capability graph read `tools/list`,
    /// saw no `edge_delete`, and concluded a stale edge could never be
    /// retracted — the tool existed and worked. Asserted by name so the next
    /// tool added to this family cannot be silently forgotten.
    #[test]
    fn every_substrate_tool_has_an_affinity() {
        for tool in [
            "entity_upsert",
            "entity_get",
            "entity_list",
            "entity_delete",
            "entity_history",
            "edge_upsert",
            "edge_get",
            "edge_list",
            "edge_delete",
            "kind_get",
            "kind_list",
        ] {
            assert_eq!(
                tool_affinity(tool),
                "memory",
                "{tool} must carry an affinity or it can never be surfaced beyond the floor"
            );
        }
    }

    /// The pairing an agent actually needs must be reachable from a declared
    /// intent, not only by knowing the names.
    #[test]
    fn session_review_intent_surfaces_the_context_graph_tools() {
        let shaped = shape_dynamic(list_tools(), Some("session_review"), DYNAMIC_TOP_N);
        let names: Vec<&str> = shaped.iter().map(|t| t.name.as_str()).collect();
        assert!(
            names
                .iter()
                .any(|n| n.starts_with("get_project_dossiers") || n.starts_with("get_project_storybook")),
            "a session_review intent must surface at least one context-graph read; got {names:?}"
        );
    }

    #[test]
    fn intent_record_and_current_roundtrip() {
        let pk = "__test_intent_roundtrip__";
        clear_intent_for_test(pk);
        assert_eq!(current_intent(pk), None, "no intent initially");
        record_intent(pk, "audit_review");
        assert_eq!(current_intent(pk).as_deref(), Some("audit_review"));
        // Blank intent clears it.
        record_intent(pk, "  ");
        assert_eq!(current_intent(pk), None, "blank intent clears");
        clear_intent_for_test(pk);
    }

    #[test]
    fn intent_is_passport_scoped() {
        let (a, b) = ("__test_intent_pa__", "__test_intent_pb__");
        clear_intent_for_test(a);
        clear_intent_for_test(b);
        record_intent(a, "audit_review");
        assert_eq!(current_intent(a).as_deref(), Some("audit_review"));
        assert_eq!(current_intent(b), None, "intent must not leak across passports");
        clear_intent_for_test(a);
    }

    fn trace_entry(tool: &str) -> TraceEntry {
        TraceEntry {
            tool: tool.to_string(),
            turn_id: None,
            ts_us: 0,
            predicted_effects: vec![],
            outcome: crate::traces::TraceOutcome::Ok,
            signature: None,
            response_tokens: None,
        }
    }

    #[test]
    fn trace_boosts_count_cap_and_skip_floor() {
        let entries = vec![
            trace_entry("list_work"),
            trace_entry("list_work"),
            trace_entry("list_work"),
            trace_entry("list_work"), // 4 hits → capped at TRACE_BOOST_CAP (12)
            trace_entry("github_search"),
            trace_entry("query"), // floor → ignored
        ];
        let boosts = trace_boosts_from_recent(&entries);
        assert_eq!(
            boosts.get("list_work"),
            Some(&TRACE_BOOST_CAP),
            "hits cap at TRACE_BOOST_CAP"
        );
        assert_eq!(
            boosts.get("github_search"),
            Some(&TRACE_BOOST_PER_HIT),
            "single hit = one boost"
        );
        assert!(!boosts.contains_key("query"), "floor tools are not boosted");
    }

    #[test]
    fn trace_boost_surfaces_recently_used_tool_without_intent() {
        // No declared intent, but the agent has been hammering `list_work`.
        let boosts = HashMap::from([("list_work".to_string(), TRACE_BOOST_CAP)]);
        let shaped = shape_dynamic_weighted(list_tools(), None, &boosts, DYNAMIC_TOP_N);
        let names: Vec<&str> = shaped.iter().map(|t| t.name.as_str()).collect();
        assert!(
            names.contains(&"list_work"),
            "recently-used tool should surface even with no intent"
        );
        assert!(names.contains(&"cuecrux_session"), "floor still present");
    }

    #[test]
    fn trace_and_intent_combine() {
        // Both signals contribute to score>0. Use a generous top_n so the test
        // isolates the *combine* property from truncation (a strong intent with
        // many relevant tools would otherwise correctly crowd out a +12 trace
        // boost — that dominance is asserted in `strong_intent_dominates_a_trace_boost`).
        let boosts = HashMap::from([("github_search".to_string(), TRACE_BOOST_CAP)]);
        let shaped = shape_dynamic_weighted(list_tools(), Some("audit_review"), &boosts, 30);
        let names: Vec<&str> = shaped.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"audit_config"), "intent signal still present");
        assert!(
            names.contains(&"github_search"),
            "trace signal lifts an otherwise-irrelevant tool when there is room"
        );
    }

    #[test]
    fn strong_intent_dominates_a_trace_boost() {
        // A +12 trace boost must NOT outrank a high-bias intent tool (audit=30):
        // with a tight top_n every beyond-floor slot goes to a bias-30 audit
        // tool, and the trace-only tool is crowded out.
        let boosts = HashMap::from([("github_search".to_string(), TRACE_BOOST_CAP)]);
        let shaped = shape_dynamic_weighted(list_tools(), Some("audit_review"), &boosts, 3);
        let names: Vec<&str> = shaped.iter().map(|t| t.name.as_str()).collect();
        let beyond_floor: Vec<&str> = names.iter().copied().filter(|n| !CORE_FLOOR.contains(n)).collect();
        assert_eq!(beyond_floor.len(), 3, "exactly top_n beyond the floor");
        for n in &beyond_floor {
            assert_eq!(
                tool_affinity(n),
                "audit",
                "tight-cap slots go to top-bias audit tools, got `{n}`"
            );
        }
        assert!(
            !names.contains(&"github_search"),
            "a +12 trace boost must not displace bias-30 intent tools under a tight cap"
        );
    }

    #[test]
    fn shaping_never_expands_beyond_input_even_with_huge_boost() {
        // Authz-non-expansion (C2): a tool named in trace_boosts but absent from
        // the input must never appear in the output.
        let boosts = HashMap::from([("totally_fake_tool_xyz".to_string(), 9999)]);
        let input_names: std::collections::HashSet<String> = list_tools().into_iter().map(|t| t.name).collect();
        let shaped = shape_dynamic_weighted(list_tools(), Some("audit_review"), &boosts, DYNAMIC_TOP_N);
        for t in &shaped {
            assert!(
                input_names.contains(&t.name),
                "shaped tool `{}` was not in the authorised input",
                t.name
            );
        }
        assert!(
            !shaped.iter().any(|t| t.name == "totally_fake_tool_xyz"),
            "a boosted-but-unauthorised tool must never be surfaced"
        );
    }

    #[test]
    fn from_env_parsing_is_lenient_and_defaults_full() {
        assert_eq!(ToolSurfaceMode::from_str_lenient("minimal"), ToolSurfaceMode::Minimal);
        assert_eq!(
            ToolSurfaceMode::from_str_lenient("  Dynamic "),
            ToolSurfaceMode::Dynamic
        );
        assert_eq!(ToolSurfaceMode::from_str_lenient("FULL"), ToolSurfaceMode::Full);
        assert_eq!(ToolSurfaceMode::from_str_lenient("nonsense"), ToolSurfaceMode::Full);
        assert_eq!(ToolSurfaceMode::from_str_lenient(""), ToolSurfaceMode::Full);
    }
}
