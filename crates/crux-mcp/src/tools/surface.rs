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

use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, OnceLock};

use crux_session::intent::default_intent_table;

use super::ToolDefinition;
use crate::traces::TraceEntry;

/// Count of intent-relevant tools surfaced *beyond* the [`CORE_FLOOR`] in
/// `dynamic` mode. Floor (~16) + this ≈ a ~28-tool intent-targeted surface —
/// still a large cut from the full ~95, but with the right tools for the task.
pub const DYNAMIC_TOP_N: usize = 12;

/// How long a declared intent keeps *boosting* the surface (seconds). A stale
/// intent must not pin an old shape forever; matches the default session TTL.
///
/// **prompt-cache M1:** expiry stops the intent from *promoting* new tools; it
/// no longer removes anything. The monotone per-session union
/// ([`merge_offered`]) keeps every tool the session was already offered, so a
/// session that idles past this TTL sees the same `tools/list` it saw before
/// rather than collapsing back to [`CORE_FLOOR`] — which is what rewrote
/// 311,754 cached tokens in one measured event on corpus
/// `drivew-host-claude-transcripts-2026-09`.
pub const INTENT_TTL_SECONDS: i64 = 3600;

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
// The base MCP transport is request/response over `POST /mcp`, so the declared
// intent is persisted here, keyed by passport, and read on the *next*
// `tools/list` to shape the surface. A client that opened the M3.5 `GET /mcp`
// SSE stream additionally gets a `tools/list_changed` push (see
// [`crate::sse`]). Mirrors the process-global pattern of [`crate::traces`] —
// no `McpContext` field churn.

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
/// evicted on read so a long-idle passport stops *boosting*.
///
/// `now_unix_seconds` is injected by the caller (the `tools/list` serve path
/// already receives the request clock), so the expiry edge is testable without
/// sleeping an hour.
///
/// **prompt-cache M1:** losing the intent no longer shrinks the listing — see
/// [`INTENT_TTL_SECONDS`] and [`merge_offered`].
pub fn current_intent(passport: &str, now_unix_seconds: i64) -> Option<String> {
    let mut store = intent_store().lock().unwrap_or_else(|p| p.into_inner());
    match store.get(passport) {
        Some(rec) if now_unix_seconds.saturating_sub(rec.set_at_unix) <= INTENT_TTL_SECONDS => Some(rec.intent.clone()),
        Some(_) => {
            store.remove(passport);
            None
        }
        None => None,
    }
}

// ── prompt-cache M1: monotone per-session offered set ───────────────────────
//
// ExecPlan `crux-prompt-cache-1h-ttl-2026-09-17` M1. Claude Code caches the
// prompt prefix for an hour; a `tools/list` that returns a PROPER SUBSET of
// what the same `Mcp-Session-Id` already saw invalidates that prefix and the
// whole conversation is re-billed at 2x. Additions never invalidated in the
// measured corpus (`drivew-host-claude-transcripts-2026-09`); removals always
// did. So the offered set is made monotone per session: it may grow, it may
// never shrink.
//
// Capability withdrawal (RCX token expiry, tier change) is NOT expressed by
// removing the advertisement any more. The tool stays listed and
// `enforce_rcx_tool_capability` refuses the `tools/call` with the existing
// `denied:capability_not_permitted` structured refusal. That is a deliberate
// widening of *advertisement* only — never of authorisation, which is still
// decided per call by the router.

/// Feature flag for the monotone surface. **Default ON**; `0`/`false`/`off`
/// restores the pre-M1 shrink-capable behaviour for one release
/// (`Rollout/rollback` in the ExecPlan), after which the flag is removed.
pub const MONOTONE_ENV: &str = "CORECRUXD_SURFACE_MONOTONE";

/// Read [`MONOTONE_ENV`]. Unset ⇒ enabled.
pub fn monotone_enabled() -> bool {
    match std::env::var(MONOTONE_ENV) {
        Ok(raw) => {
            let v = raw.trim();
            !(v == "0" || v.eq_ignore_ascii_case("false") || v.eq_ignore_ascii_case("off"))
        }
        Err(_) => true,
    }
}

/// Ceiling on a `dynamic` session's offered set. A long session that keeps
/// declaring new intents would otherwise grow to the whole ~132-tool catalogue
/// and give back the token win the dynamic surface exists for. At the cap the
/// surface stops *adding*; it never starts removing.
pub fn monotone_growth_cap() -> usize {
    CORE_FLOOR.len() + 2 * DYNAMIC_TOP_N
}

/// The cap that applies to `mode`. `Full` is the whole catalogue and `Minimal`
/// is a fixed floor — neither can grow past its own natural bound, so capping
/// them would only truncate a surface that was never the problem.
fn growth_cap_for(mode: ToolSurfaceMode) -> Option<usize> {
    match mode {
        ToolSurfaceMode::Dynamic => Some(monotone_growth_cap()),
        ToolSurfaceMode::Full | ToolSurfaceMode::Minimal => None,
    }
}

/// Most sessions a single process tracks before the least-recently-listed one
/// is evicted. Mirrors `crate::sse`'s registry bound; an evicted session simply
/// starts its union again (it is a cache, not a ledger).
const MAX_TRACKED_SESSIONS: usize = 1024;

#[derive(Default)]
struct SessionSurface {
    /// `CORECRUXD_TOOL_SURFACE` as read on this session's FIRST listing. Read
    /// once per session, not per request, so a mid-session env change cannot
    /// reshape a live client's prefix.
    mode: Option<ToolSurfaceMode>,
    /// The union, in first-offer order. Order is pinned because a reordered
    /// tools array is a different prefix and busts the cache just as a removal
    /// would.
    offered: Vec<String>,
    offered_set: HashSet<String>,
    /// What the previous `tools/list` actually returned, for the ledger delta.
    last_returned: Vec<String>,
    /// Monotonic touch counter driving LRU eviction.
    touched: u64,
}

fn surface_store() -> &'static Mutex<HashMap<String, SessionSurface>> {
    static STORE: OnceLock<Mutex<HashMap<String, SessionSurface>>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn next_touch() -> u64 {
    static TICK: OnceLock<std::sync::atomic::AtomicU64> = OnceLock::new();
    TICK.get_or_init(|| std::sync::atomic::AtomicU64::new(0))
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

fn evict_if_needed(store: &mut HashMap<String, SessionSurface>) {
    while store.len() > MAX_TRACKED_SESSIONS {
        let Some(oldest) = store.iter().min_by_key(|(_, s)| s.touched).map(|(k, _)| k.clone()) else {
            return;
        };
        store.remove(&oldest);
    }
}

/// What one `tools/list` offered relative to the previous one for the same
/// session. Recorded on `agent.tools_offered.v1` so the M0 cache ledger can
/// prove `removed` is always empty while the monotone flag is on.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OfferedDelta {
    /// Final offered names, in listing order.
    pub names: Vec<String>,
    /// Names in `names` that the previous listing for this session did not have.
    pub added: Vec<String>,
    /// Names the previous listing had that `names` does not. Always empty while
    /// [`monotone_enabled`] is true — that is the M1 invariant.
    pub removed: Vec<String>,
    /// True when `added` is non-empty, i.e. a `tools/list_changed` push is
    /// warranted. A re-list that offers the same set is not worth a push.
    pub grew: bool,
}

/// Surface mode for this session, read from the environment ONCE (on the
/// session's first listing) and reused thereafter.
///
/// Per-request `from_env()` meant a deploy-time or operator env change could
/// reshape a live client's tool surface mid-conversation, which is precisely
/// the invalidation M1 exists to stop.
pub fn session_mode(session_key: &str) -> ToolSurfaceMode {
    let mut store = surface_store().lock().unwrap_or_else(|p| p.into_inner());
    let touched = next_touch();
    let entry = store.entry(session_key.to_string()).or_default();
    entry.touched = touched;
    let mode = *entry.mode.get_or_insert_with(ToolSurfaceMode::from_env);
    evict_if_needed(&mut store);
    mode
}

/// Fold `shaped` (this request's freshly-computed surface) into the session's
/// running union and return the set to serve.
///
/// With the flag on the result is `previously_offered ∪ shaped`, in first-offer
/// order, capped by [`monotone_growth_cap`] in `dynamic` mode (`full` and
/// `minimal` are bounded by their own shape and are not capped). With the flag
/// off the result is
/// `shaped` unchanged — the delta is still recorded so `removed[]` stays
/// honest and the rollback path is observable.
pub fn merge_offered(session_key: &str, mode: ToolSurfaceMode, shaped: &[String]) -> OfferedDelta {
    let monotone = monotone_enabled();
    let cap = growth_cap_for(mode);
    let mut store = surface_store().lock().unwrap_or_else(|p| p.into_inner());
    let touched = next_touch();
    let entry = store.entry(session_key.to_string()).or_default();
    entry.touched = touched;
    entry.mode.get_or_insert(mode);

    for name in shaped {
        if entry.offered_set.contains(name) {
            continue;
        }
        if cap.is_some_and(|c| entry.offered.len() >= c) {
            // At the cap: stop adding. Never start removing.
            continue;
        }
        entry.offered.push(name.clone());
        entry.offered_set.insert(name.clone());
    }

    let names: Vec<String> = if monotone {
        entry.offered.clone()
    } else {
        shaped.to_vec()
    };

    let previous: HashSet<&str> = entry.last_returned.iter().map(String::as_str).collect();
    let current: HashSet<&str> = names.iter().map(String::as_str).collect();
    let added: Vec<String> = names
        .iter()
        .filter(|n| !previous.contains(n.as_str()))
        .cloned()
        .collect();
    let removed: Vec<String> = entry
        .last_returned
        .iter()
        .filter(|n| !current.contains(n.as_str()))
        .cloned()
        .collect();

    entry.last_returned.clone_from(&names);
    let grew = !added.is_empty();
    evict_if_needed(&mut store);
    OfferedDelta {
        names,
        added,
        removed,
        grew,
    }
}

/// Would serving `shaped` to `session_key` grow its offered set? Read-only —
/// used to decide whether a `notifications/tools/list_changed` push is worth
/// sending, without recording an offer that never reached the client.
pub fn would_grow(session_key: &str, shaped: &[String]) -> bool {
    let store = surface_store().lock().unwrap_or_else(|p| p.into_inner());
    let Some(entry) = store.get(session_key) else {
        return true; // nothing offered yet — the first listing is always new
    };
    if entry.last_returned.is_empty() {
        return true;
    }
    let cap = entry.mode.and_then(growth_cap_for);
    if cap.is_some_and(|c| entry.offered.len() >= c) {
        return false; // capped: nothing more can be added
    }
    let served: HashSet<&str> = entry.last_returned.iter().map(String::as_str).collect();
    shaped.iter().any(|n| !served.contains(n.as_str()))
}

/// Re-project a name list back onto tool definitions.
///
/// `shaped` supplies the definitions for everything this request computed;
/// `catalogue` is the pre-authz build catalogue, consulted only for a name the
/// session was already offered but that this request's authz filter dropped
/// (an expired RCX token, a tier change). A name in neither is skipped — a tool
/// deleted from the binary cannot be listed, and that is a deploy boundary, not
/// a mid-session change.
pub fn project_to_names(
    names: &[String],
    shaped: Vec<ToolDefinition>,
    catalogue: &[ToolDefinition],
) -> Vec<ToolDefinition> {
    let mut by_name: HashMap<String, ToolDefinition> = shaped.into_iter().map(|t| (t.name.clone(), t)).collect();
    names
        .iter()
        .filter_map(|n| {
            by_name
                .remove(n)
                .or_else(|| catalogue.iter().find(|t| &t.name == n).cloned())
        })
        .collect()
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
        // Work board + coordination plane. Same argument as the context-graph
        // block above, and the same one CORE_FLOOR makes for the handoff pair:
        // clients only call advertised tools. Coordination that no client can
        // invoke detects no collisions — on 2026-08-06 two live sessions
        // overlapped on one checkout and one deleted the other's file, with
        // `coord_announce` deployed and unreachable from both.
        "list_work"
        | "create_work"
        | "update_work_state"
        | "comment_on_work"
        | "coord_announce"
        | "coord_status"
        | "punch_in"
        | "punch_out"
        | "check_punchcard"
        | "list_punchcards"
        | "execplan_write"
        | "execplan_gate" => "work",
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

/// Drop a session's monotone union so an in-crate test can re-drive the same
/// key from a clean slate. Integration tests use a unique session id instead.
#[cfg(test)]
pub fn clear_session_for_test(session_key: &str) {
    surface_store()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(session_key);
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
        // `list_work` carries the `work` affinity, which `audit_review` does not
        // bias — so it still scores 0 here. Affinity alone never surfaces a tool;
        // an intent has to ask for it.
        assert!(
            !names.contains(&"list_work"),
            "work-affinity tool must not surface under an intent that does not bias it"
        );
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

    /// The twelve tools an agent executing an ExecPlan has to reach. Every one
    /// was unmapped before 2026-08-06 and therefore scored 0 in *every* intent —
    /// the collision detection and board reads documented in the workspace guide
    /// were uninvokable from the client that was told to use them.
    const WORK_TOOLS: &[&str] = &[
        "list_work",
        "create_work",
        "update_work_state",
        "comment_on_work",
        "coord_announce",
        "coord_status",
        "punch_in",
        "punch_out",
        "check_punchcard",
        "list_punchcards",
        "execplan_write",
        "execplan_gate",
    ];

    #[test]
    fn work_tools_all_carry_the_work_affinity() {
        for t in WORK_TOOLS {
            assert_eq!(
                tool_affinity(t),
                "work",
                "{t} must carry an affinity — unmapped means bias 0 in every intent"
            );
        }
    }

    /// Guards the half that is easy to get wrong: an affinity tag is inert
    /// unless some intent biases it. Both halves of the M1 fix, asserted together.
    #[test]
    fn execplan_execution_intent_surfaces_the_coordination_plane() {
        let shaped = shape_dynamic(list_tools(), Some("execplan_execution"), DYNAMIC_TOP_N);
        let names: Vec<&str> = shaped.iter().map(|t| t.name.as_str()).collect();
        for t in ["coord_announce", "list_work"] {
            assert!(names.contains(&t), "execplan_execution must surface {t}; got {names:?}");
        }
        assert!(
            names.len() <= CORE_FLOOR.len() + DYNAMIC_TOP_N,
            "must respect the top_n cap, got {}",
            names.len()
        );
        assert!(names.len() < list_tools().len(), "still far smaller than full");
    }

    /// Flag-off proof: adding an affinity arm and an intent entry must not move
    /// the no-intent surface, which is what a cold agent gets.
    #[test]
    fn work_affinity_does_not_leak_into_the_no_intent_floor() {
        let shaped = shape_dynamic(list_tools(), None, DYNAMIC_TOP_N);
        let names: Vec<&str> = shaped.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names.len(), CORE_FLOOR.len(), "no intent ⇒ floor only");
        for t in WORK_TOOLS {
            assert!(
                !names.contains(t),
                "{t} must not reach the floor without a declared intent"
            );
        }
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
        assert_eq!(current_intent(pk, now_unix()), None, "no intent initially");
        record_intent(pk, "audit_review");
        assert_eq!(current_intent(pk, now_unix()).as_deref(), Some("audit_review"));
        // Blank intent clears it.
        record_intent(pk, "  ");
        assert_eq!(current_intent(pk, now_unix()), None, "blank intent clears");
        clear_intent_for_test(pk);
    }

    #[test]
    fn intent_is_passport_scoped() {
        let (a, b) = ("__test_intent_pa__", "__test_intent_pb__");
        clear_intent_for_test(a);
        clear_intent_for_test(b);
        record_intent(a, "audit_review");
        assert_eq!(current_intent(a, now_unix()).as_deref(), Some("audit_review"));
        assert_eq!(
            current_intent(b, now_unix()),
            None,
            "intent must not leak across passports"
        );
        clear_intent_for_test(a);
    }

    // ── prompt-cache M1: monotone union ────────────────────────────────────

    fn names(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn merge_offered_never_shrinks_and_reports_no_removals() {
        let key = "__test_monotone_never_shrinks__";
        clear_session_for_test(key);
        let first = merge_offered(key, ToolSurfaceMode::Dynamic, &names(&["a", "b", "c"]));
        assert_eq!(first.names, names(&["a", "b", "c"]));
        assert_eq!(first.added, names(&["a", "b", "c"]));
        assert!(first.grew);

        // The shaper drops `b` and `c` (intent expired) and promotes `d`.
        let second = merge_offered(key, ToolSurfaceMode::Dynamic, &names(&["a", "d"]));
        assert_eq!(
            second.names,
            names(&["a", "b", "c", "d"]),
            "union in first-offer order — a reordered array busts the prefix too"
        );
        assert_eq!(second.added, names(&["d"]));
        assert!(second.removed.is_empty(), "M1 invariant");
        assert!(second.grew);

        // A re-list with nothing new is not a growth event.
        let third = merge_offered(key, ToolSurfaceMode::Dynamic, &names(&["a"]));
        assert_eq!(third.names, names(&["a", "b", "c", "d"]));
        assert!(third.added.is_empty());
        assert!(third.removed.is_empty());
        assert!(!third.grew);
        clear_session_for_test(key);
    }

    #[test]
    fn merge_offered_is_session_scoped() {
        let (a, b) = ("__test_monotone_sess_a__", "__test_monotone_sess_b__");
        clear_session_for_test(a);
        clear_session_for_test(b);
        merge_offered(a, ToolSurfaceMode::Dynamic, &names(&["x", "y"]));
        let other = merge_offered(b, ToolSurfaceMode::Dynamic, &names(&["z"]));
        assert_eq!(other.names, names(&["z"]), "one session's union must not leak");
        clear_session_for_test(a);
        clear_session_for_test(b);
    }

    #[test]
    fn merge_offered_caps_growth_without_removing() {
        let key = "__test_monotone_cap__";
        clear_session_for_test(key);
        let cap = monotone_growth_cap();
        let wide: Vec<String> = (0..cap + 25).map(|i| format!("t{i}")).collect();
        let first = merge_offered(key, ToolSurfaceMode::Dynamic, &wide);
        assert_eq!(first.names.len(), cap, "capped at CORE_FLOOR + 2 * DYNAMIC_TOP_N");

        // At the cap a brand-new tool is refused entry — and nothing is evicted
        // to make room for it.
        let second = merge_offered(key, ToolSurfaceMode::Dynamic, &names(&["late_arrival"]));
        assert_eq!(second.names.len(), cap);
        assert!(!second.names.iter().any(|n| n == "late_arrival"));
        assert!(second.removed.is_empty(), "the cap must never cause a removal");
        clear_session_for_test(key);
    }

    #[test]
    fn full_and_minimal_modes_are_not_capped() {
        let key = "__test_monotone_full_uncapped__";
        clear_session_for_test(key);
        let wide: Vec<String> = (0..monotone_growth_cap() + 25).map(|i| format!("t{i}")).collect();
        let listed = merge_offered(key, ToolSurfaceMode::Full, &wide);
        assert_eq!(
            listed.names.len(),
            wide.len(),
            "`full` is the whole catalogue — capping it would regress a surface that was already monotone"
        );
        clear_session_for_test(key);
    }

    #[test]
    fn would_grow_is_read_only_and_matches_merge() {
        let key = "__test_monotone_would_grow__";
        clear_session_for_test(key);
        assert!(would_grow(key, &names(&["a"])), "first listing is always new");
        merge_offered(key, ToolSurfaceMode::Dynamic, &names(&["a", "b"]));
        assert!(!would_grow(key, &names(&["a"])), "a subset adds nothing");
        assert!(!would_grow(key, &names(&["a", "b"])), "the same set adds nothing");
        assert!(would_grow(key, &names(&["c"])), "a new name would grow the union");
        // The preview must not have recorded anything.
        let after = merge_offered(key, ToolSurfaceMode::Dynamic, &names(&["a"]));
        assert_eq!(after.names, names(&["a", "b"]), "would_grow must not record");
        clear_session_for_test(key);
    }

    #[test]
    fn project_to_names_recovers_definitions_dropped_by_authz() {
        let catalogue = list_tools();
        let dropped = catalogue
            .iter()
            .find(|t| t.name == "store_fact")
            .cloned()
            .expect("store_fact exists");
        // `shaped` no longer carries `store_fact` (its RCX capability lapsed),
        // but the session was already offered it, so it stays listed and is
        // refused at `tools/call` instead.
        let shaped: Vec<ToolDefinition> = catalogue.iter().filter(|t| t.name != "store_fact").cloned().collect();
        let projected = project_to_names(&names(&["cuecrux_session", "store_fact"]), shaped, &catalogue);
        let got: Vec<&str> = projected.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(got, vec!["cuecrux_session", "store_fact"]);
        assert_eq!(
            projected[1].description, dropped.description,
            "recovered definition must be byte-identical to the catalogue's"
        );
    }

    #[test]
    fn project_to_names_skips_a_name_in_neither_source() {
        let catalogue = list_tools();
        let projected = project_to_names(
            &names(&["cuecrux_session", "tool_deleted_in_a_later_build"]),
            vec![],
            &catalogue,
        );
        let got: Vec<&str> = projected.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(got, vec!["cuecrux_session"]);
    }

    #[test]
    fn intent_expiry_stops_boosting_but_removes_nothing() {
        let pk = "__test_intent_expiry_edge__";
        clear_intent_for_test(pk);
        record_intent(pk, "audit_review");
        // `record_intent` stamps wall-clock now; drive the edge off that stamp.
        let set_at = now_unix();
        assert_eq!(
            current_intent(pk, set_at + INTENT_TTL_SECONDS).as_deref(),
            Some("audit_review"),
            "still boosting at the TTL boundary"
        );
        assert_eq!(
            current_intent(pk, set_at + INTENT_TTL_SECONDS + 1),
            None,
            "one second past the TTL the intent stops boosting"
        );

        // …and the shaped surface collapsing to the floor is NOT what the
        // client sees, because the union keeps the earlier offer.
        let key = "__test_intent_expiry_edge_session__";
        clear_session_for_test(key);
        let boosted: Vec<String> = shape_dynamic(list_tools(), Some("audit_review"), DYNAMIC_TOP_N)
            .into_iter()
            .map(|t| t.name)
            .collect();
        merge_offered(key, ToolSurfaceMode::Dynamic, &boosted);
        let floor_only: Vec<String> = shape_dynamic(list_tools(), None, DYNAMIC_TOP_N)
            .into_iter()
            .map(|t| t.name)
            .collect();
        let after = merge_offered(key, ToolSurfaceMode::Dynamic, &floor_only);
        assert_eq!(after.names, boosted, "expiry must not shrink the listing");
        assert!(after.removed.is_empty());
        clear_intent_for_test(pk);
        clear_session_for_test(key);
    }

    #[tokio::test]
    async fn monotone_flag_defaults_on_and_reads_falsey_values() {
        let _g = crate::test_env_lock().lock().await;
        std::env::remove_var(MONOTONE_ENV);
        assert!(monotone_enabled(), "launch default is ON");
        for falsey in ["0", "false", "FALSE", " off "] {
            std::env::set_var(MONOTONE_ENV, falsey);
            assert!(!monotone_enabled(), "`{falsey}` must disable the monotone surface");
        }
        for truthy in ["1", "true", "yes", ""] {
            std::env::set_var(MONOTONE_ENV, truthy);
            assert!(monotone_enabled(), "only an explicit falsey value rolls back");
        }
        std::env::remove_var(MONOTONE_ENV);
    }

    #[tokio::test]
    async fn session_mode_is_read_once_per_session() {
        let _g = crate::test_env_lock().lock().await;
        let key = "__test_session_mode_pinned__";
        clear_session_for_test(key);
        std::env::set_var("CORECRUXD_TOOL_SURFACE", "dynamic");
        assert_eq!(session_mode(key), ToolSurfaceMode::Dynamic);
        // Changing the process flag mid-session must NOT reshape a live
        // client's surface — that reshape is itself a prefix invalidation.
        std::env::set_var("CORECRUXD_TOOL_SURFACE", "full");
        assert_eq!(session_mode(key), ToolSurfaceMode::Dynamic, "pinned for the session");
        // A NEW session picks up the new value.
        let fresh = "__test_session_mode_pinned_fresh__";
        clear_session_for_test(fresh);
        assert_eq!(session_mode(fresh), ToolSurfaceMode::Full);
        std::env::remove_var("CORECRUXD_TOOL_SURFACE");
        clear_session_for_test(key);
        clear_session_for_test(fresh);
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
