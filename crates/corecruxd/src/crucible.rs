// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Board crucible — a periodic, deterministic digest of the ExecPlan board.
//!
//! The board carries more open plans than any one session can read. The daemon
//! already derives the expensive parts ([`crate::work_execplans::rank_open`]:
//! dependency depth, cycles, inverted orchestrator edges) but nothing ever
//! *reads* them on a cadence, so the analysis only exists when a human asks.
//! This module runs that pass on a timer and surfaces one append-only fact.
//!
//! Shape copied deliberately from [`crate::consolidation_scheduler`]:
//!
//! - **Surface only — never act.** The crucible never edits a plan, never
//!   changes a work state, never resolves a finding. It appends one
//!   `__board_digest__::<run_id>` fact and stops. Everything it reports is a
//!   claim for an operator (or an agent) to act on.
//! - **Deterministic and offline.** No model call, no network egress, no
//!   credentials. Every field is computed from the fact store plus the
//!   ExecPlan markdown already on disk. This is what lets the same binary run
//!   the same pass on a laptop and on a server (the LLM enrichment layer is a
//!   separate, opt-in concern — see the plan's M1b).
//! - **Reserved entity prefix.** `__board_digest__::` is born private via
//!   [`crate::fact_privacy`], so digests stay out of the agent-facing memory
//!   panel and freshness listings.
//!
//! Gated by `CORECRUXD_CRUCIBLE=1` (default OFF;
//! [`crate::config::Config::crucible_enabled`]). Interval is config-driven via
//! `CORECRUXD_CRUCIBLE_INTERVAL_SECS` (default daily).

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, RwLock};

use corecrux_memory::fact_store::StoreFact;
use corecrux_memory::FactStore;

use crate::coord::paths_overlap;
use crate::work::WorkItem;
use crate::work_execplans::{self, EXECPLAN_ENTITY_PREFIX};

/// Receipt-fact entity prefix each run is written under. Reserved (`__…__::`)
/// so it is born private.
pub const DIGEST_ENTITY_PREFIX: &str = "__board_digest__::";

/// Fact key under the run entity.
pub const DIGEST_KEY: &str = "digest";

/// Default tick interval if the config clamp yields zero: daily. A board digest
/// is a "what changed while I was away" artefact, not a monitor — hourly would
/// be noise.
const DEFAULT_INTERVAL_SECS: u64 = 86_400;

/// How many ready / blocked rows the digest carries. The point is to be
/// readable; the full board is one HTTP call away for anyone who wants it.
const TOP_N: usize = 20;

/// Upper bound on plans considered for path clustering. The comparison is
/// pairwise, so cost grows with the square of this number.
/// ponytail: O(n²) over open plans — fine at board scale (~200 open, ~40k
/// cheap string comparisons). If the board ever outgrows this, index paths
/// into a map<path, Vec<slug>> and group by bucket instead of comparing pairs.
const MAX_PLANS_FOR_CLUSTERING: usize = 400;

/// Upper bound on declared paths read per plan, so one pathological plan
/// cannot dominate the pass.
const MAX_PATHS_PER_PLAN: usize = 40;

/// A plan and the repo-relative paths its own markdown declares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanPaths {
    pub slug: String,
    pub paths: Vec<String>,
}

/// One board row in the digest, trimmed to what a reader needs to decide.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DigestItem {
    pub id: String,
    pub state: String,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_milestone: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_path: Option<String>,
    /// Open plans holding this one back. Empty = ready to start now.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blocked_by: Vec<String>,
}

/// Two open plans whose markdown names at least one path in common. A weak
/// signal by construction — it is a statement about documents, not about what
/// anyone is doing — but it is the only duplicate-work signal that needs no
/// announcement and no lease.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DuplicateCluster {
    pub slugs: Vec<String>,
    /// The overlapping paths that put these plans together.
    pub shared_paths: Vec<String>,
}

/// The full digest for one run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct BoardDigest {
    pub generated_at_unix_ms: u64,
    /// Total open items on the board (not just the ones listed below).
    pub open_count: usize,
    /// Ready-to-start work, in the daemon's recommended order. Blocked items
    /// are deliberately excluded here — see `blocked`.
    pub ready: Vec<DigestItem>,
    /// Items that cannot be started because an open plan blocks them.
    pub blocked: Vec<DigestItem>,
    /// Slugs in a dependency cycle. Ordering is undefined for these, so they
    /// are reported rather than silently resolved.
    pub cycles: Vec<String>,
    /// Orchestrator plans whose `Depends on` should read `Extended by`.
    /// Actionable: it names the edge to reverse.
    pub inverted_orchestrator_edges: Vec<String>,
    /// Open plans naming the same files — candidate duplicate work.
    pub duplicate_clusters: Vec<DuplicateCluster>,
}

impl BoardDigest {
    /// True when the run found nothing an operator would want to read. Used to
    /// skip writing a fact for an empty board, so a quiet week does not
    /// accumulate identical digests.
    pub fn is_empty(&self) -> bool {
        self.ready.is_empty()
            && self.blocked.is_empty()
            && self.cycles.is_empty()
            && self.inverted_orchestrator_edges.is_empty()
            && self.duplicate_clusters.is_empty()
    }
}

fn to_item(item: &WorkItem, blocked_by: Vec<String>) -> DigestItem {
    DigestItem {
        id: item.id.clone(),
        state: item.state.clone(),
        title: item.title.clone(),
        current_milestone: item.current_milestone.clone(),
        plan_path: item.plan_path.clone(),
        blocked_by,
    }
}

/// Pairwise path-overlap clustering over the open plans.
///
/// Emits one cluster per overlapping PAIR rather than trying to merge
/// transitively: A-B and B-C overlapping does not make A-C the same work, and
/// silently merging them would invent a three-plan cluster no evidence
/// supports.
pub fn cluster_by_shared_paths(plans: &[PlanPaths]) -> Vec<DuplicateCluster> {
    let considered = plans.len().min(MAX_PLANS_FOR_CLUSTERING);
    let mut out: Vec<DuplicateCluster> = Vec::new();
    for i in 0..considered {
        for j in (i + 1)..considered {
            let (a, b) = (&plans[i], &plans[j]);
            let mut shared: BTreeSet<String> = BTreeSet::new();
            for pa in a.paths.iter().take(MAX_PATHS_PER_PLAN) {
                for pb in b.paths.iter().take(MAX_PATHS_PER_PLAN) {
                    if paths_overlap(pa, pb) {
                        // Record the more specific of the two so the reader
                        // sees the actual file, not just a shared ancestor.
                        shared.insert(if pa.len() >= pb.len() { pa.clone() } else { pb.clone() });
                    }
                }
            }
            if !shared.is_empty() {
                let mut slugs = vec![a.slug.clone(), b.slug.clone()];
                slugs.sort();
                out.push(DuplicateCluster {
                    slugs,
                    shared_paths: shared.into_iter().collect(),
                });
            }
        }
    }
    out.sort_by(|x, y| x.slugs.cmp(&y.slugs));
    out
}

/// Pure digest construction — no I/O, no clock, no store. Factored out so the
/// whole pass is testable without a running task or a populated data dir.
pub fn build_digest(items: &[WorkItem], plans: &[PlanPaths], now_unix_ms: u64) -> BoardDigest {
    let ranked = work_execplans::rank_open(items);

    let mut ready = Vec::new();
    let mut blocked = Vec::new();
    for (rank, &idx) in ranked.order.iter().enumerate() {
        let blockers = ranked.blocked_by.get(rank).cloned().unwrap_or_default();
        let row = to_item(&items[idx], blockers.clone());
        if blockers.is_empty() {
            if ready.len() < TOP_N {
                ready.push(row);
            }
        } else if blocked.len() < TOP_N {
            blocked.push(row);
        }
    }

    BoardDigest {
        generated_at_unix_ms: now_unix_ms,
        open_count: ranked.order.len(),
        ready,
        blocked,
        cycles: ranked.cycles,
        inverted_orchestrator_edges: ranked.inverted_orchestrator_edges,
        duplicate_clusters: cluster_by_shared_paths(plans),
    }
}

/// Write one digest as an append-only reserved fact. Returns the entity written.
async fn persist_digest(store: &Arc<RwLock<FactStore>>, digest: &BoardDigest, run_id: &str) -> Option<String> {
    let value = serde_json::to_string(digest).ok()?;
    let entity = format!("{DIGEST_ENTITY_PREFIX}{run_id}");
    let mut sf = StoreFact {
        tenant_hash: "default".to_string(),
        entity: entity.clone(),
        key: DIGEST_KEY.to_string(),
        value,
        source_receipt: None,
        confidence: 1.0,
        private: false,
        horizon_class: None,
        actor: Some(work_execplans::VIRTUAL_PASSPORT.to_string()),
    };
    crate::fact_privacy::enforce_global(&mut sf);
    let mut guard = store.write().await;
    guard.store(sf);
    Some(entity)
}

/// Run one crucible pass. Returns the digest when one was written.
///
/// Returns `None` — without writing — when the ExecPlan projection is not
/// configured (`CRUX_EXECPLANS_ROOT` unset) or the board is empty. A digest
/// asserting an empty board would be indistinguishable from a digest of a
/// board the daemon simply cannot see, so we decline to make the claim.
pub async fn run_crucible_once(store: &Arc<RwLock<FactStore>>, now_unix_ms: u64) -> Option<BoardDigest> {
    let root = work_execplans::execplans_root_from_env()?;
    let files = work_execplans::walk_execplans_root(&root).ok()?;

    let items = {
        let guard = store.read().await;
        work_execplans::list_execplans(&guard, &root, now_unix_ms).ok()?
    };

    let open: BTreeSet<&str> = items
        .iter()
        .filter(|i| work_execplans::is_open_state(&i.state))
        .filter_map(|i| i.id.strip_prefix(EXECPLAN_ENTITY_PREFIX))
        .collect();

    let plans: Vec<PlanPaths> = files
        .iter()
        .filter(|f| open.contains(f.slug.as_str()))
        .map(|f| PlanPaths {
            slug: f.slug.clone(),
            paths: crate::http::coord::extract_declared_paths(&f.content),
        })
        .filter(|p| !p.paths.is_empty())
        .collect();

    let open_items: Vec<WorkItem> = items
        .into_iter()
        .filter(|i| work_execplans::is_open_state(&i.state))
        .collect();

    let digest = build_digest(&open_items, &plans, now_unix_ms);
    if digest.is_empty() {
        return None;
    }
    persist_digest(store, &digest, &now_unix_ms.to_string()).await?;
    Some(digest)
}

/// Spawn the background crucible task, mirroring
/// [`crate::consolidation_scheduler::spawn_consolidation_scheduler`].
///
/// Gated at spawn: only started when `enabled` is true. The flag + interval are
/// read once at boot (toggling requires a restart — same convention as the
/// other `CORECRUXD_*` background-task flags).
pub fn spawn_board_crucible(
    enabled: bool,
    interval_secs: u64,
    store: Arc<RwLock<FactStore>>,
    mut shutdown: broadcast::Receiver<()>,
) {
    if !enabled {
        return;
    }
    let interval_secs = if interval_secs == 0 {
        DEFAULT_INTERVAL_SECS
    } else {
        interval_secs
    };
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(StdDuration::from_secs(interval_secs));
        // Skip the immediate first tick so we do not sweep mid-boot before the
        // store has finished replaying.
        interval.tick().await;
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |d| d.as_millis() as u64);
                    if let Some(d) = run_crucible_once(&store, now).await {
                        tracing::info!(
                            open = d.open_count,
                            ready = d.ready.len(),
                            blocked = d.blocked.len(),
                            cycles = d.cycles.len(),
                            clusters = d.duplicate_clusters.len(),
                            "board-crucible-digest-written"
                        );
                    }
                }
                _ = shutdown.recv() => break,
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Build a `WorkItem` through serde so the test does not have to enumerate
    /// every field of a 25-field struct (and does not silently rot when one is
    /// added).
    fn item(id: &str, state: &str, depends_on: &[&str]) -> WorkItem {
        serde_json::from_value(json!({
            "id": format!("execplan:{id}"),
            "project_id": "execplans",
            "state": state,
            "title": id,
            "body": "",
            "created_at_unix_ms": 1_000_u64,
            "updated_at_unix_ms": 2_000_u64,
            "created_by_passport": "test",
            "depends_on": depends_on,
        }))
        .expect("WorkItem fixture must deserialize")
    }

    fn plan(slug: &str, paths: &[&str]) -> PlanPaths {
        PlanPaths {
            slug: slug.to_string(),
            paths: paths.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// POSITIVE CONTROL. An all-negative suite cannot catch an inverted
    /// overlap guard: flipping `paths_overlap` would still return "no cluster"
    /// for unrelated plans and only break the case that matters. This asserts
    /// the overlap we expect to be *found* is actually found.
    #[test]
    fn shared_path_produces_a_cluster() {
        let clusters = cluster_by_shared_paths(&[
            plan("alpha", &["crates/corecruxd/src/coord.rs"]),
            plan("beta", &["crates/corecruxd/src/coord.rs"]),
        ]);
        assert_eq!(clusters.len(), 1, "identical declared path must cluster");
        assert_eq!(clusters[0].slugs, vec!["alpha".to_string(), "beta".to_string()]);
        assert_eq!(
            clusters[0].shared_paths,
            vec!["crates/corecruxd/src/coord.rs".to_string()]
        );
    }

    /// Directory containment counts as overlap, and the reported path is the
    /// more specific of the two — a reader needs the file, not the ancestor.
    #[test]
    fn directory_prefix_overlaps_and_reports_the_specific_path() {
        let clusters = cluster_by_shared_paths(&[
            plan("alpha", &["crates/corecruxd/src"]),
            plan("beta", &["crates/corecruxd/src/coord.rs"]),
        ]);
        assert_eq!(clusters.len(), 1);
        assert_eq!(
            clusters[0].shared_paths,
            vec!["crates/corecruxd/src/coord.rs".to_string()]
        );
    }

    #[test]
    fn unrelated_paths_do_not_cluster() {
        let clusters = cluster_by_shared_paths(&[
            plan("alpha", &["crates/corecruxd/src/coord.rs"]),
            plan("beta", &["docs/readme.md"]),
        ]);
        assert!(clusters.is_empty());
    }

    /// A sibling file under a shared ancestor is NOT an overlap — `src/work`
    /// covers `src/work/item.rs` but must not match `src/work.rs`.
    #[test]
    fn sibling_files_are_not_an_overlap() {
        let clusters = cluster_by_shared_paths(&[plan("alpha", &["src/work.rs"]), plan("beta", &["src/work/item.rs"])]);
        assert!(clusters.is_empty());
    }

    /// A-B and B-C overlapping must not invent an A-C cluster: transitive
    /// merging would assert duplicate work no evidence supports.
    #[test]
    fn clustering_is_pairwise_not_transitive() {
        let clusters = cluster_by_shared_paths(&[
            plan("a", &["one.rs"]),
            plan("b", &["one.rs", "two.rs"]),
            plan("c", &["two.rs"]),
        ]);
        let pairs: Vec<&Vec<String>> = clusters.iter().map(|c| &c.slugs).collect();
        assert_eq!(clusters.len(), 2, "expected exactly a-b and b-c, got {pairs:?}");
        assert!(pairs.iter().all(|p| p.len() == 2));
        assert!(
            !clusters
                .iter()
                .any(|c| c.slugs == vec!["a".to_string(), "c".to_string()]),
            "a and c share no path and must not be clustered"
        );
    }

    /// Blocked work must not appear in `ready` — recommending work that cannot
    /// be started is the defect the daemon's ranking exists to avoid.
    #[test]
    fn blocked_items_are_separated_from_ready() {
        let items = vec![
            item("foundation", "in_progress", &[]),
            item("dependent", "planned", &["foundation"]),
        ];
        let d = build_digest(&items, &[], 5_000);

        assert_eq!(d.open_count, 2);
        let ready_ids: Vec<&str> = d.ready.iter().map(|i| i.id.as_str()).collect();
        let blocked_ids: Vec<&str> = d.blocked.iter().map(|i| i.id.as_str()).collect();

        assert_eq!(ready_ids, vec!["execplan:foundation"], "unblocked work is ready");
        assert_eq!(blocked_ids, vec!["execplan:dependent"], "an open dependency blocks");
        assert_eq!(d.blocked[0].blocked_by, vec!["foundation".to_string()]);
        assert!(d.ready[0].blocked_by.is_empty());
    }

    /// An edge to a plan that is not open is satisfied history, so the
    /// dependent is ready. (Only open items are passed to `build_digest`.)
    #[test]
    fn dependency_on_a_closed_plan_does_not_block() {
        let items = vec![item("dependent", "planned", &["already-shipped"])];
        let d = build_digest(&items, &[], 5_000);
        assert_eq!(d.ready.len(), 1, "closed dependency must not block");
        assert!(d.blocked.is_empty());
    }

    /// The empty-board guard: a digest with nothing in it is not written, so a
    /// quiet week does not accumulate identical facts.
    #[test]
    fn empty_board_yields_an_empty_digest() {
        let d = build_digest(&[], &[], 5_000);
        assert!(d.is_empty());
        assert_eq!(d.open_count, 0);
    }

    /// A digest that found anything at all must not be reported empty.
    #[test]
    fn digest_with_findings_is_not_empty() {
        let d = build_digest(&[item("solo", "planned", &[])], &[], 5_000);
        assert!(!d.is_empty(), "one ready item is a finding");
    }

    #[test]
    fn digest_round_trips_through_json() {
        let d = build_digest(
            &[item("solo", "planned", &[])],
            &[plan("x", &["a.rs"]), plan("y", &["a.rs"])],
            7_000,
        );
        let encoded = serde_json::to_string(&d).expect("digest serializes");
        let decoded: BoardDigest = serde_json::from_str(&encoded).expect("digest round-trips");
        assert_eq!(decoded, d);
    }
}
