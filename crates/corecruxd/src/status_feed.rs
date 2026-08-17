// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Unified 6-state status feed (Open Engine M3).
//!
//! A read-only projection that maps the work board's lifecycle audit
//! (`WorkTransition` records) into Nate Jones's six-word glance vocabulary —
//! `CLAIMED / BLOCKED / HUMAN_HOLD / RESUMED / DONE / FAILED` — so a human can
//! *watch* a session work instead of commanding it (audit §2.2, §3).
//!
//! It is a **pure projection over existing events** (no independent state): each
//! emitted [`StatusEvent`] links back to the transition row it came from, and
//! the feed never asserts beyond what the work board already recorded. Crypto
//! provenance (CROWN receipts, signed activity log) is untouched — the feed is a
//! glance layer *on top of*, not a replacement for, `receipt_verify` (R3).
//!
//! `HUMAN_HOLD` is the normalized verb for M1's `needs_approval` blocker kind;
//! this is why M3 depends on M1.
//!
//! The projection function ([`status_feed`]) is always callable (so the mapping
//! is unit-testable without the flag). *Exposure* of the feed — the HTTP route
//! and the MCP tool — is gated behind [`status_feed_enabled`] (default OFF),
//! mirroring the `context_custody_audit` / `audit_export_bundle` handler-gate
//! idiom: flag off → a short disabled notice, not an error.

use serde::{Deserialize, Serialize};

use crate::work::{BlockerKind, WorkTransition, WORK_TRANSITION_ENTITY_PREFIX};
use corecrux_memory::fact_store::{FactQuery, FactStore};

/// Env var gating *exposure* of the status feed. **Default OFF** — the daemon
/// is byte-identical when unset. Same truthiness vocabulary as the other
/// `CORECRUXD_FEATURE_*` flags.
pub const STATUS_FEED_FLAG_ENV: &str = "CORECRUXD_FEATURE_STATUS_FEED";

/// True when the status-feed surface is enabled for this process. **Default
/// OFF.** Empty / `0` / `false` / `off` / `no` all count as off.
pub fn status_feed_enabled() -> bool {
    match std::env::var(STATUS_FEED_FLAG_ENV) {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            !matches!(v.as_str(), "" | "0" | "false" | "off" | "no")
        }
        Err(_) => false,
    }
}

/// The six normalized lifecycle verbs. Serialized as the SCREAMING_SNAKE glance
/// vocabulary so the wire form matches the essay's feed verbatim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StatusVerb {
    /// Work picked up for the first time (`planned`/`drafting` → `in_progress`).
    Claimed,
    /// Paused waiting on an answer about the task (M1 `needs_info`).
    Blocked,
    /// Paused waiting on an owner's go/no-go (M1 `needs_approval`).
    HumanHold,
    /// Picked back up after a block (`blocked` → `in_progress`).
    Resumed,
    /// Finished (`complete` / `deployed`).
    Done,
    /// Abandoned while still active — archived from a non-finished state, or a
    /// rejected gate.
    Failed,
}

/// One projected lifecycle event, linked to its source transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusEvent {
    pub work_id: String,
    pub verb: StatusVerb,
    /// The source transition's id — the row this verb is projected from.
    pub transition_id: String,
    pub from_state: String,
    pub to_state: String,
    pub by_passport: String,
    pub at_unix_ms: u64,
}

/// Map a single work transition to a normalized verb, or `None` when the
/// transition does not correspond to a glanceable lifecycle change (e.g.
/// `complete` → `archive` filing, which is already `DONE`).
pub fn verb_for_transition(t: &WorkTransition) -> Option<StatusVerb> {
    // A rejected gated action is a failure regardless of target.
    if t.gate_status == "rejected" {
        return Some(StatusVerb::Failed);
    }
    let finished = |s: &str| matches!(s, "complete" | "deployed");
    match t.to_state.as_str() {
        "in_progress" => {
            if t.from_state == "blocked" {
                Some(StatusVerb::Resumed)
            } else {
                Some(StatusVerb::Claimed)
            }
        }
        "blocked" => match t.blocker_kind {
            Some(BlockerKind::NeedsApproval) => Some(StatusVerb::HumanHold),
            // `needs_info` or unspecified (legacy / default).
            _ => Some(StatusVerb::Blocked),
        },
        "complete" | "deployed" => Some(StatusVerb::Done),
        // Archiving a finished item is just filing (already DONE); archiving an
        // unfinished one is abandonment.
        "archive" if !finished(&t.from_state) => Some(StatusVerb::Failed),
        _ => None,
    }
}

/// Build the status feed by projecting work-board transitions into the 6-verb
/// vocabulary, newest last. When `work_id` is `Some`, only that item's lane is
/// returned; otherwise the feed spans every work item. `limit` caps the number
/// of returned events (most recent kept).
pub fn status_feed(store: &FactStore, work_id: Option<&str>, limit: usize) -> Vec<StatusEvent> {
    let prefix = match work_id {
        Some(id) => format!("{WORK_TRANSITION_ENTITY_PREFIX}::{id}::"),
        None => format!("{WORK_TRANSITION_ENTITY_PREFIX}::"),
    };
    let result = store.query(&FactQuery {
        min_effective_confidence: None,
        tenant_hash: None,
        query: None,
        entity: None,
        entity_prefix: Some(prefix),
        top_k: 2000,
        token_budget: None,
    });

    let mut events: Vec<StatusEvent> = Vec::new();
    for fact in crate::fact_helpers::dedup_latest(result.facts) {
        if fact.key != crate::work::RECORD_KEY {
            continue;
        }
        let Ok(t) = serde_json::from_str::<WorkTransition>(&fact.value) else {
            continue;
        };
        if let Some(verb) = verb_for_transition(&t) {
            events.push(StatusEvent {
                work_id: t.work_id,
                verb,
                transition_id: t.id,
                from_state: t.from_state,
                to_state: t.to_state,
                by_passport: t.by_passport,
                at_unix_ms: t.at_unix_ms,
            });
        }
    }

    // Oldest → newest, tie-broken by transition id for determinism.
    events.sort_by(|a, b| {
        a.at_unix_ms
            .cmp(&b.at_unix_ms)
            .then_with(|| a.transition_id.cmp(&b.transition_id))
    });

    if events.len() > limit {
        // Keep the most recent `limit` events.
        events = events.split_off(events.len() - limit);
    }
    events
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::work::{create_work, update_work, BlockerKind, CreateWorkInput, UpdateWorkContext, UpdateWorkInput};
    use corecrux_memory::fact_store::FactStore;

    fn seeded_store() -> FactStore {
        // Passport seeding writes a key envelope to disk; use a throwaway dir.
        let dir = std::env::temp_dir().join(format!("status_feed_seed_{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let mut store = FactStore::new();
        crate::passports::seed_defaults_if_missing(&dir, &mut store, 1).expect("passport seed");
        crate::projects::seed_default_if_missing(&mut store, 1).expect("project seed");
        store
    }

    fn mk_work(store: &mut FactStore) -> String {
        create_work(
            store,
            CreateWorkInput {
                project_id: "default".to_string(),
                title: "t".to_string(),
                body: None,
                state: None,
                assignee_passport: None,
                tenant_id: None,
                linked_pr: None,
                linked_issue: None,
                created_by_passport: "personal-default".to_string(),
            },
            1_000,
        )
        .expect("create")
        .id
    }

    fn move_to(
        store: &mut FactStore,
        id: &str,
        state: &str,
        kind: Option<BlockerKind>,
        reason: Option<&str>,
        now: u64,
    ) {
        update_work(
            store,
            id,
            UpdateWorkInput {
                title: None,
                body: None,
                state: Some(state.to_string()),
                assignee_passport: None,
                tenant_id: None,
                linked_pr: None,
                linked_issue: None,
                blocker_reason: reason.map(|r| Some(r.to_string())),
                blocker_kind: kind,
            },
            UpdateWorkContext {
                by_passport: "personal-default".to_string(),
                passport_gated: false,
                now_unix_ms: now,
            },
        )
        .expect("update");
    }

    #[test]
    fn flag_defaults_off() {
        // The exposure flag is off unless explicitly set (we never set it here).
        // Guard against a polluted env by only asserting the unset case.
        if std::env::var(STATUS_FEED_FLAG_ENV).is_err() {
            assert!(!status_feed_enabled());
        }
    }

    #[test]
    fn synthetic_timeline_maps_to_six_verbs() {
        let mut store = seeded_store();
        let id = mk_work(&mut store);

        // claim → human-hold → resume → done
        move_to(&mut store, &id, "in_progress", None, None, 2_000);
        move_to(
            &mut store,
            &id,
            "blocked",
            Some(BlockerKind::NeedsApproval),
            Some("needs sign-off"),
            3_000,
        );
        move_to(&mut store, &id, "in_progress", None, None, 4_000);
        move_to(&mut store, &id, "complete", None, None, 5_000);

        let verbs: Vec<StatusVerb> = status_feed(&store, Some(&id), 100).iter().map(|e| e.verb).collect();
        assert_eq!(
            verbs,
            vec![
                StatusVerb::Claimed,
                StatusVerb::HumanHold,
                StatusVerb::Resumed,
                StatusVerb::Done
            ],
        );
    }

    #[test]
    fn needs_info_block_maps_to_blocked_not_human_hold() {
        let mut store = seeded_store();
        let id = mk_work(&mut store);
        move_to(&mut store, &id, "in_progress", None, None, 2_000);
        move_to(&mut store, &id, "blocked", None, Some("waiting on infra"), 3_000); // defaults needs_info

        let verbs: Vec<StatusVerb> = status_feed(&store, Some(&id), 100).iter().map(|e| e.verb).collect();
        assert_eq!(verbs, vec![StatusVerb::Claimed, StatusVerb::Blocked]);
    }

    #[test]
    fn abandoned_item_maps_to_failed_but_filed_completion_does_not() {
        let mut store = seeded_store();

        // Abandoned: in_progress → archive ⇒ FAILED.
        let a = mk_work(&mut store);
        move_to(&mut store, &a, "in_progress", None, None, 2_000);
        move_to(&mut store, &a, "archive", None, None, 3_000);
        let a_verbs: Vec<StatusVerb> = status_feed(&store, Some(&a), 100).iter().map(|e| e.verb).collect();
        assert_eq!(a_verbs, vec![StatusVerb::Claimed, StatusVerb::Failed]);

        // Filed completion: complete → archive ⇒ DONE only (no spurious FAILED).
        let b = mk_work(&mut store);
        move_to(&mut store, &b, "complete", None, None, 2_000);
        move_to(&mut store, &b, "archive", None, None, 3_000);
        let b_verbs: Vec<StatusVerb> = status_feed(&store, Some(&b), 100).iter().map(|e| e.verb).collect();
        assert_eq!(b_verbs, vec![StatusVerb::Done]);
    }

    #[test]
    fn feed_without_work_id_spans_all_items_sorted_by_time() {
        let mut store = seeded_store();
        let a = mk_work(&mut store);
        let b = mk_work(&mut store);
        move_to(&mut store, &a, "in_progress", None, None, 2_000);
        move_to(&mut store, &b, "in_progress", None, None, 2_500);

        let events = status_feed(&store, None, 100);
        // Two CLAIMED events across both items, time-ordered.
        let claimed: Vec<&StatusEvent> = events.iter().filter(|e| e.verb == StatusVerb::Claimed).collect();
        assert_eq!(claimed.len(), 2);
        assert!(claimed[0].at_unix_ms <= claimed[1].at_unix_ms);
    }

    #[test]
    fn verb_serializes_as_screaming_snake() {
        assert_eq!(serde_json::to_string(&StatusVerb::HumanHold).unwrap(), "\"HUMAN_HOLD\"");
        assert_eq!(serde_json::to_string(&StatusVerb::Claimed).unwrap(), "\"CLAIMED\"");
    }
}
