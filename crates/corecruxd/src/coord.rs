// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Multi-agent coordination plane — "who is live on this project right now,
//! what is each session doing" for concurrent agent sessions sharing one
//! source tree.
//!
//! Design (see the ExecPlan `crux-agent-presence-coordination-2026-06-11`):
//!
//! - **Polled board, not a pub/sub bus.** Agents are turn-based and read at
//!   tool-call boundaries; the daemon owns a board assembled at read time
//!   from surfaces that already exist — the presence tracker
//!   ([`crate::presence`]), session bindings ([`crate::session_bindings`]),
//!   punchcard leases (`http/punchcards.rs` /
//!   [`crate::agentgraph_kinds::PUNCHCARD_KIND`]), kanban work items
//!   ([`crate::work`]) — plus the one thing none of them carry: the
//!   session's *declared intent* ([`CoordIntent`], stored here).
//! - **Leases are punchcards.** This module does NOT mint its own
//!   claim/lease records; advisory/enforced path leases already live on
//!   `/v1/punchcards/*` with TTL self-sweep and a PreToolUse hook
//!   (`crux-hook observe-pre`). The active view joins them by passport.
//! - **Auto-enrollment.** A session enters the pool when its binding is
//!   minted; liveness is the passive presence heartbeat. No registration
//!   endpoint, no heartbeat endpoint.
//!
//! Storage (everything-as-facts, born private via [`crate::fact_privacy`]):
//!
//! - `__coord__::{project_id}::{session_id_hex}` key=`intent` — the
//!   session's declared focus ([`CoordIntent`]). Re-announcing supersedes
//!   (same entity+key → higher version wins); expiry is read-time via
//!   `expires_at_unix_ms`, so no sweeper is needed.
//!
//! Gated by `CORECRUXD_COORD=1` (default OFF;
//! [`crate::config::Config::coord_enabled`]).

use corecrux_memory::fact_store::{FactQuery, FactStore, StoreFact};
use serde::{Deserialize, Serialize};

pub const COORD_ENTITY_PREFIX: &str = "__coord__";
pub const INTENT_KEY: &str = "intent";

/// Default liveness horizon: a session is "active" while its passport was
/// seen within this window. Overridable via `CORECRUXD_COORD_PRESENCE_TTL_SECS`.
pub const DEFAULT_PRESENCE_TTL_SECS: u64 = 900;

/// Default intent TTL (4 h) — a declared focus usually outlives a single
/// presence window but should not linger across days. Callers can pass
/// `ttl_seconds: 0` to clear their intent immediately.
pub const DEFAULT_INTENT_TTL_SECS: u64 = 14_400;

/// Hard cap on intent / presence TTLs (24 h) so a typo'd `ttl_seconds`
/// can't pin a stale row on the board for a month.
pub const MAX_TTL_SECS: u64 = 86_400;

#[derive(Debug, thiserror::Error)]
pub enum CoordError {
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

/// A session's declared focus — "what I am working on right now".
/// Re-announcing replaces the previous intent (latest version wins via
/// `dedup_latest`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoordIntent {
    pub project_id: String,
    pub session_id_hex: String,
    pub passport_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execplan_slug: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub milestone: Option<String>,
    /// Repo-relative paths (files or directory prefixes) the session expects
    /// to touch. Informational — enforceable leases are punchcards.
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub announced_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

impl CoordIntent {
    pub fn is_live(&self, now_unix_ms: u64) -> bool {
        now_unix_ms < self.expires_at_unix_ms
    }
}

/// Write (or replace) a session's intent fact. Born private via the global
/// privacy policy (`__coord__::` is a reserved prefix); attributed to the
/// announcing passport via the fact's `actor` field.
pub fn write_intent(store: &mut FactStore, intent: &CoordIntent) -> Result<(), CoordError> {
    let value = serde_json::to_string(intent)?;
    let mut sf = StoreFact {
        entity: format!(
            "{COORD_ENTITY_PREFIX}::{}::{}",
            intent.project_id, intent.session_id_hex
        ),
        key: INTENT_KEY.to_string(),
        value,
        source_receipt: None,
        confidence: 1.0,
        private: false,
        horizon_class: None,
        actor: Some(intent.passport_id.clone()),
    };
    crate::fact_privacy::enforce_global(&mut sf);
    store.store(sf);
    Ok(())
}

/// List the latest intent per session, optionally scoped to one project.
/// Includes expired intents — callers filter with [`CoordIntent::is_live`]
/// (the active view does; an audit reader may want the stale ones).
pub fn list_intents(store: &FactStore, project_id: Option<&str>) -> Vec<CoordIntent> {
    let prefix = match project_id {
        Some(pid) => format!("{COORD_ENTITY_PREFIX}::{pid}::"),
        None => format!("{COORD_ENTITY_PREFIX}::"),
    };
    let result = store.query(&FactQuery {
        query: None,
        entity: None,
        entity_prefix: Some(prefix),
        top_k: 500,
        token_budget: None,
    });
    let mut out = Vec::new();
    for fact in crate::fact_helpers::dedup_latest(result.facts) {
        if fact.key != INTENT_KEY {
            continue;
        }
        if let Ok(intent) = serde_json::from_str::<CoordIntent>(&fact.value) {
            out.push(intent);
        }
    }
    out.sort_by(|a, b| b.announced_at_unix_ms.cmp(&a.announced_at_unix_ms));
    out
}

/// `true` when two repo-relative paths overlap: equal, or one is a
/// path-component prefix of the other (`src/work` covers `src/work/item.rs`
/// but not `src/work.rs`). Trailing slashes are normalised. Mirrors the
/// punchcard `path_contains` containment rule.
pub fn paths_overlap(a: &str, b: &str) -> bool {
    let a = a.trim_end_matches('/');
    let b = b.trim_end_matches('/');
    if a.is_empty() || b.is_empty() {
        return false;
    }
    if a == b {
        return true;
    }
    let (shorter, longer) = if a.len() < b.len() { (a, b) } else { (b, a) };
    longer.starts_with(shorter) && longer.as_bytes().get(shorter.len()) == Some(&b'/')
}

/// Strip a punchcard resource URI (`file://p`, `tree://p`) down to its path
/// for comparison against intent paths. Unknown schemes pass through.
fn lease_resource_path(resource: &str) -> &str {
    resource
        .split_once("://")
        .map_or(resource, |(_, rest)| rest)
        .trim_start_matches('/')
}

/// An advisory overlap between a session's announced focus and a peer's
/// declared intent or held lease. Returned from `announce` so the moment a
/// session declares an execplan it learns who it collides with. Never
/// blocking — coordination signal only.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct OverlapWarning {
    pub peer_session_id_hex: String,
    pub peer_passport_id: String,
    /// `execplan` | `intent_path` | `lease`
    pub kind: String,
    /// The peer's overlapping thing (slug, path, or lease resource).
    pub theirs: String,
    /// The announced thing it overlaps with.
    pub yours: String,
}

/// Compute advisory overlaps between `announced` and the other live
/// sessions' intents + held punchcard leases. Self-overlap (same session,
/// or a lease held by the announcing passport) is excluded.
pub fn find_overlaps(
    announced: &CoordIntent,
    peer_intents: &[CoordIntent],
    leases: &[LeaseSummary],
    now_unix_ms: u64,
) -> Vec<OverlapWarning> {
    let mut out = Vec::new();
    for peer in peer_intents {
        if peer.session_id_hex == announced.session_id_hex || !peer.is_live(now_unix_ms) {
            continue;
        }
        if let (Some(mine), Some(theirs)) = (announced.execplan_slug.as_deref(), peer.execplan_slug.as_deref()) {
            if mine == theirs {
                out.push(OverlapWarning {
                    peer_session_id_hex: peer.session_id_hex.clone(),
                    peer_passport_id: peer.passport_id.clone(),
                    kind: "execplan".to_string(),
                    theirs: theirs.to_string(),
                    yours: mine.to_string(),
                });
            }
        }
        for mine in &announced.paths {
            for theirs in &peer.paths {
                if paths_overlap(mine, theirs) {
                    out.push(OverlapWarning {
                        peer_session_id_hex: peer.session_id_hex.clone(),
                        peer_passport_id: peer.passport_id.clone(),
                        kind: "intent_path".to_string(),
                        theirs: theirs.clone(),
                        yours: mine.clone(),
                    });
                }
            }
        }
    }
    for lease in leases {
        if lease.holder_passport == announced.passport_id {
            continue;
        }
        let lease_path = lease_resource_path(&lease.resource);
        for mine in &announced.paths {
            if paths_overlap(mine.trim_start_matches('/'), lease_path) {
                out.push(OverlapWarning {
                    peer_session_id_hex: String::new(),
                    peer_passport_id: lease.holder_passport.clone(),
                    kind: "lease".to_string(),
                    theirs: lease.resource.clone(),
                    yours: mine.clone(),
                });
            }
        }
    }
    out
}

/// A live punchcard lease, summarised for the active view. Sourced from the
/// substrate entity store (`PUNCHCARD_KIND`) — punchcards are passport-held,
/// so the join key is `holder_passport`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct LeaseSummary {
    pub punchcard_id: String,
    pub resource: String,
    pub mode: String,
    pub holder_passport: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub expires_at_unix_ms: i64,
}

/// One live session row in the active view: the binding joined with the
/// passport's presence heartbeat plus (when present) its declared intent
/// and the punchcard leases its passport holds.
#[derive(Debug, Clone, Serialize)]
pub struct CoordSessionView {
    pub session_id_hex: String,
    pub passport_id: String,
    pub tenant_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    pub bound_at_unix_ms: u64,
    /// Passport-level heartbeat. Presence is tracked per passport, not per
    /// session — two sessions on one passport share a heartbeat. Consumers
    /// should treat liveness as "this identity is around", with the intent
    /// freshness as the per-session signal.
    pub last_seen_at_unix_ms: u64,
    pub active_until_unix_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intent: Option<CoordIntent>,
    /// Punchcard leases held by this session's passport (passport-level,
    /// like the heartbeat).
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub leases: Vec<LeaseSummary>,
}

/// The merged read served by `GET /v1/coord/active`.
#[derive(Debug, Clone, Serialize)]
pub struct CoordActiveView {
    pub now_unix_ms: u64,
    pub presence_ttl_secs: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    /// Sessions whose passport heartbeat is within the presence TTL.
    pub active_sessions: Vec<CoordSessionView>,
    /// Kanban work items in `in_progress` / `blocked` for the project.
    pub work_in_flight: Vec<crate::work::WorkItem>,
}

/// Pure assembly of the active view — testable without HTTP or stores.
///
/// `presence_by_passport` maps passport_id → last_seen_at_unix_ms.
/// Sessions are included when their passport was seen within
/// `presence_ttl_secs` AND (when `project_id` is given) their binding either
/// matches the project or carries no project at all — a session that never
/// declared a project is still a potential writer on the tree.
#[allow(clippy::too_many_arguments)] // assembly point for five independent surfaces; a builder would obscure the join
pub fn assemble_active(
    bindings: &[crate::session_bindings::SessionBinding],
    presence_by_passport: &std::collections::BTreeMap<String, u64>,
    intents: &[CoordIntent],
    leases: &[LeaseSummary],
    work_in_flight: Vec<crate::work::WorkItem>,
    project_id: Option<&str>,
    presence_ttl_secs: u64,
    now_unix_ms: u64,
) -> CoordActiveView {
    let ttl_ms = presence_ttl_secs.saturating_mul(1000);
    let mut active_sessions = Vec::new();
    for b in bindings {
        let Some(&last_seen) = presence_by_passport.get(&b.passport_id) else {
            continue;
        };
        let active_until = last_seen.saturating_add(ttl_ms);
        if now_unix_ms >= active_until {
            continue;
        }
        if let Some(pid) = project_id {
            if b.project_id.as_deref().is_some_and(|bp| bp != pid) {
                continue;
            }
        }
        let intent = intents
            .iter()
            .find(|i| i.session_id_hex == b.session_id_hex && i.is_live(now_unix_ms))
            .cloned();
        // Per-session recency gate. Presence is passport-level and bindings
        // are kept forever (newest per session), so "passport live" alone
        // would resurrect every binding that passport ever minted — the
        // v0.4.4 dogfood put 200 historical boots on the board. A session
        // row is live only when the session itself shows recent life:
        // a live declared intent, or a binding minted within the presence
        // window (a fresh boot that hasn't announced yet).
        let recently_bound = now_unix_ms < b.bound_at_unix_ms.saturating_add(ttl_ms);
        if intent.is_none() && !recently_bound {
            continue;
        }
        let session_leases: Vec<LeaseSummary> = leases
            .iter()
            .filter(|l| l.holder_passport == b.passport_id)
            .cloned()
            .collect();
        active_sessions.push(CoordSessionView {
            session_id_hex: b.session_id_hex.clone(),
            passport_id: b.passport_id.clone(),
            tenant_id: b.tenant_id.clone(),
            project_id: b.project_id.clone(),
            bound_at_unix_ms: b.bound_at_unix_ms,
            last_seen_at_unix_ms: last_seen,
            active_until_unix_ms: active_until,
            intent,
            leases: session_leases,
        });
    }
    // Most-recently-seen first, then newest binding — the "who else is here"
    // glance order.
    active_sessions.sort_by(|a, b| {
        b.last_seen_at_unix_ms
            .cmp(&a.last_seen_at_unix_ms)
            .then(b.bound_at_unix_ms.cmp(&a.bound_at_unix_ms))
    });
    CoordActiveView {
        now_unix_ms,
        presence_ttl_secs,
        project_id: project_id.map(str::to_string),
        active_sessions,
        work_in_flight,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session_bindings::SessionBinding;
    use std::collections::BTreeMap;

    fn binding(session: &str, passport: &str, project: Option<&str>, bound_at: u64) -> SessionBinding {
        SessionBinding {
            session_id_hex: session.to_string(),
            project_id: project.map(str::to_string),
            tenant_id: "personal".to_string(),
            passport_id: passport.to_string(),
            passport_category: "personal".to_string(),
            agent_work_gate: false,
            bound_at_unix_ms: bound_at,
        }
    }

    fn intent(session: &str, slug: &str, expires_at: u64) -> CoordIntent {
        CoordIntent {
            project_id: "proj".to_string(),
            session_id_hex: session.to_string(),
            passport_id: "p".to_string(),
            execplan_slug: Some(slug.to_string()),
            milestone: None,
            paths: vec![],
            note: None,
            announced_at_unix_ms: 0,
            expires_at_unix_ms: expires_at,
        }
    }

    fn lease(holder: &str, resource: &str) -> LeaseSummary {
        LeaseSummary {
            punchcard_id: format!("pc_{holder}"),
            resource: resource.to_string(),
            mode: "modify".to_string(),
            holder_passport: holder.to_string(),
            reason: None,
            expires_at_unix_ms: i64::MAX,
        }
    }

    #[test]
    fn intent_roundtrip_is_born_private_and_latest_wins() {
        let mut store = corecrux_memory::FactStore::new();
        let mut first = intent("aaaa", "plan-one", 10_000);
        first.passport_id = "p1".to_string();
        write_intent(&mut store, &first).expect("write 1");
        let mut second = first.clone();
        second.execplan_slug = Some("plan-two".to_string());
        second.announced_at_unix_ms = 5;
        write_intent(&mut store, &second).expect("write 2");

        // Latest version wins; only one intent per (project, session).
        let listed = list_intents(&store, Some("proj"));
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].execplan_slug.as_deref(), Some("plan-two"));

        // Project scoping.
        assert!(list_intents(&store, Some("other-proj")).is_empty());

        // T.1: coord facts are born private (never sync). The global policy
        // is env-derived and includes `__coord__::` by default.
        let fact = store
            .all_facts()
            .find(|f| f.entity.starts_with("__coord__::"))
            .expect("coord fact stored");
        assert!(fact.private, "__coord__:: facts must be born private");
        assert_eq!(fact.actor.as_deref(), Some("p1"), "attributed to the passport");
    }

    #[test]
    fn assemble_filters_by_presence_ttl() {
        let now: u64 = 10_000_000;
        let bindings = vec![
            binding("aaaa", "p1", None, now - 5_000),
            binding("bbbb", "p2", None, now - 5_000),
        ];
        let mut presence = BTreeMap::new();
        presence.insert("p1".to_string(), now - 10_000); // 10s ago — live
        presence.insert("p2".to_string(), now - 2_000_000); // long gone (>15 min)
        let view = assemble_active(&bindings, &presence, &[], &[], vec![], None, 900, now);
        assert_eq!(view.active_sessions.len(), 1);
        assert_eq!(view.active_sessions[0].session_id_hex, "aaaa");
        assert_eq!(view.active_sessions[0].active_until_unix_ms, now - 10_000 + 900_000);
    }

    #[test]
    fn assemble_drops_sessions_with_no_presence_row() {
        let bindings = vec![binding("aaaa", "p1", None, 100)];
        let presence = BTreeMap::new();
        let view = assemble_active(&bindings, &presence, &[], &[], vec![], None, 900, 1_000);
        assert!(view.active_sessions.is_empty());
    }

    #[test]
    fn assemble_project_filter_keeps_unscoped_sessions() {
        let now: u64 = 1_000_000;
        let bindings = vec![
            binding("aaaa", "p1", Some("proj"), now - 1_000),
            binding("bbbb", "p2", Some("other"), now - 1_000),
            binding("cccc", "p3", None, now - 1_000),
        ];
        let mut presence = BTreeMap::new();
        for p in ["p1", "p2", "p3"] {
            presence.insert(p.to_string(), now - 1_000);
        }
        let view = assemble_active(&bindings, &presence, &[], &[], vec![], Some("proj"), 900, now);
        let ids: Vec<&str> = view.active_sessions.iter().map(|s| s.session_id_hex.as_str()).collect();
        assert!(ids.contains(&"aaaa"), "project match kept");
        assert!(ids.contains(&"cccc"), "unscoped session kept");
        assert!(!ids.contains(&"bbbb"), "other-project session dropped");
    }

    #[test]
    fn assemble_joins_live_intent_and_passport_leases() {
        let now: u64 = 1_000_000;
        let bindings = vec![
            binding("aaaa", "p1", None, now - 1_000),
            binding("bbbb", "p2", None, now - 1_000),
        ];
        let mut presence = BTreeMap::new();
        presence.insert("p1".to_string(), now - 1_000);
        presence.insert("p2".to_string(), now - 1_000);
        let intents = vec![
            intent("aaaa", "live-plan", now + 100_000),
            intent("bbbb", "expired-plan", now - 1), // expired — must not surface
        ];
        let leases = vec![lease("p1", "file://src/a.rs"), lease("p2", "tree://src/b")];
        let view = assemble_active(&bindings, &presence, &intents, &leases, vec![], None, 900, now);
        let a = view
            .active_sessions
            .iter()
            .find(|s| s.session_id_hex == "aaaa")
            .expect("aaaa live");
        let b = view
            .active_sessions
            .iter()
            .find(|s| s.session_id_hex == "bbbb")
            .expect("bbbb live");
        assert_eq!(
            a.intent.as_ref().and_then(|i| i.execplan_slug.as_deref()),
            Some("live-plan")
        );
        assert!(b.intent.is_none(), "expired intent hidden");
        assert_eq!(a.leases.len(), 1);
        assert_eq!(a.leases[0].resource, "file://src/a.rs");
        assert_eq!(b.leases[0].resource, "tree://src/b");
    }

    #[test]
    fn stale_bindings_of_a_live_passport_stay_off_the_board() {
        // Regression for the v0.4.4 dogfood flood: one live passport
        // resurrected ~200 historical boot bindings. An old binding with no
        // live intent must be dropped; the same binding with a live intent
        // stays.
        let now: u64 = 1_000_000_000;
        let old_bound = now - 86_400_000; // a day-old boot
        let bindings = vec![
            binding("old1", "p1", None, old_bound),
            binding("old2", "p1", None, old_bound),
            binding("fresh", "p1", None, now - 1_000),
        ];
        let mut presence = BTreeMap::new();
        presence.insert("p1".to_string(), now - 1_000); // passport is live
                                                        // No intents: only the fresh boot shows.
        let view = assemble_active(&bindings, &presence, &[], &[], vec![], None, 900, now);
        let ids: Vec<&str> = view.active_sessions.iter().map(|s| s.session_id_hex.as_str()).collect();
        assert_eq!(ids, vec!["fresh"], "stale bindings dropped: {ids:?}");

        // A live intent revives exactly that old session.
        let intents = vec![intent("old1", "still-working", now + 100_000)];
        let view = assemble_active(&bindings, &presence, &intents, &[], vec![], None, 900, now);
        let ids: Vec<&str> = view.active_sessions.iter().map(|s| s.session_id_hex.as_str()).collect();
        assert!(ids.contains(&"old1"), "live intent keeps old session: {ids:?}");
        assert!(!ids.contains(&"old2"), "intent-less old session still dropped");
    }

    #[test]
    fn paths_overlap_component_aware() {
        assert!(paths_overlap("src/work.rs", "src/work.rs"));
        assert!(paths_overlap("src/work", "src/work/item.rs"));
        assert!(paths_overlap("src/work/item.rs", "src/work"));
        assert!(paths_overlap("src/work/", "src/work/item.rs"));
        // Sibling that shares a string prefix is NOT an overlap.
        assert!(!paths_overlap("src/work", "src/work.rs"));
        assert!(!paths_overlap("src/work.rs", "src/worker.rs"));
        assert!(!paths_overlap("", "src/a"));
    }

    #[test]
    fn find_overlaps_flags_execplan_paths_and_leases_but_not_self() {
        let now: u64 = 1_000_000;
        let mut mine = intent("aaaa", "shared-plan", now + 100_000);
        mine.passport_id = "p1".to_string();
        mine.paths = vec!["crates/corecruxd/src".to_string()];

        let mut peer = intent("bbbb", "shared-plan", now + 100_000);
        peer.passport_id = "p2".to_string();
        peer.paths = vec!["crates/corecruxd/src/coord.rs".to_string()];

        let mut expired_peer = intent("cccc", "shared-plan", now - 1);
        expired_peer.paths = vec!["crates/corecruxd/src".to_string()];

        let leases = vec![
            lease("p2", "tree://crates/corecruxd/src/http"), // peer lease — overlaps
            lease("p1", "tree://crates/corecruxd"),          // own lease — excluded
            lease("p3", "file://README.md"),                 // disjoint
        ];

        let warnings = find_overlaps(&mine, &[mine.clone(), peer, expired_peer], &leases, now);
        let kinds: Vec<&str> = warnings.iter().map(|w| w.kind.as_str()).collect();
        assert!(kinds.contains(&"execplan"), "same slug flagged: {warnings:?}");
        assert!(kinds.contains(&"intent_path"), "path containment flagged");
        assert!(kinds.contains(&"lease"), "peer lease flagged");
        assert_eq!(
            warnings.len(),
            3,
            "self, expired, own-lease, disjoint all excluded: {warnings:?}"
        );
        let lease_w = warnings.iter().find(|w| w.kind == "lease").expect("lease warning");
        assert_eq!(lease_w.peer_passport_id, "p2");
        assert_eq!(lease_w.theirs, "tree://crates/corecruxd/src/http");
    }

    #[test]
    fn assemble_sorts_most_recent_heartbeat_first() {
        let now: u64 = 1_000_000;
        let bindings = vec![
            binding("aaaa", "p1", None, now - 2_000),
            binding("bbbb", "p2", None, now - 1_000),
        ];
        let mut presence = BTreeMap::new();
        presence.insert("p1".to_string(), now - 50_000);
        presence.insert("p2".to_string(), now - 1_000);
        let view = assemble_active(&bindings, &presence, &[], &[], vec![], None, 900, now);
        assert_eq!(view.active_sessions[0].session_id_hex, "bbbb");
    }
}
