// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Case-based procedural memory — a "case bank" for the Crux Daemon.
//!
//! Where [`crate::fact_store::FactStore`] remembers *declarative* facts
//! (`entity/key/value`), this store remembers *procedural* experience: a
//! **case** is a `(task, action, outcome)` triple recording what an agent did
//! in a situation and how it turned out. At the start of a new task an agent
//! retrieves analogous past cases and reuses the ones that worked — learning
//! from experience **without any model fine-tuning**, which is exactly the
//! constraint the CPU-only daemon operates under.
//!
//! This adapts the *Memento / case-based reasoning* line from the
//! Awesome-Agent-Memory survey (execplan
//! `agent-memory-improvements-2026-06-26`, M3) to Crux's existing append-only,
//! replay-on-startup store shape (mirrors [`crate::session_store`]).
//!
//! Retrieval is lexical (token-overlap) today and embedding-ready: the same
//! shape that lets [`FactStore`](crate::fact_store::FactStore) layer dense
//! cosine ranking over BM25 applies here. Like fact salience (M2), the
//! `times_reused` counter is an in-memory ranking hint and is deliberately not
//! journaled.

use std::collections::{HashMap, HashSet};
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Journal event for case persistence.
#[allow(clippy::large_enum_variant)]
#[derive(Serialize, Deserialize)]
#[serde(tag = "op")]
enum CaseJournalEvent {
    #[serde(rename = "record")]
    Record { case: Case },
    #[serde(rename = "delete")]
    Delete { case_id: String },
}

/// A single procedural-memory case: what was attempted for a task and how it
/// turned out.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Case {
    pub case_id: String,
    /// The task / situation this case addresses. This is the primary retrieval
    /// key — `retrieve_similar` matches a new task against it.
    pub task: String,
    /// Optional extra context about the situation (constraints, environment).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    /// The action / approach / solution that was taken.
    pub action: String,
    /// What resulted — the observed outcome of the action.
    pub outcome: String,
    /// Whether the action succeeded. Drives "retrieve only successful
    /// precedents" so an agent reuses what worked, not what failed.
    pub success: bool,
    /// Scalar quality in `[0.0, 1.0]` — higher is a better precedent. Used as a
    /// secondary rank key after lexical similarity.
    pub reward: f32,
    /// Free-form tags for coarse filtering / extra match signal.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Optional provenance receipt (e.g. the CROWN receipt of the run).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_receipt: Option<String>,
    pub created_at: DateTime<Utc>,
    /// How many times this case has been returned by retrieval. In-memory only
    /// (re-derivable ranking hint, not journaled — same rationale as fact
    /// salience): bumped by [`CaseStore::mark_reused`].
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub times_reused: u32,
}

fn is_zero_u32(n: &u32) -> bool {
    *n == 0
}

/// Request to record a new case.
#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
pub struct RecordCase {
    pub task: String,
    #[serde(default)]
    pub context: Option<String>,
    pub action: String,
    pub outcome: String,
    /// Defaults to `true`: most recorded cases are precedents worth reusing.
    #[serde(default = "default_success")]
    pub success: bool,
    /// Defaults to `1.0` (clamped to `[0,1]` on store).
    #[serde(default = "default_reward")]
    pub reward: f32,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub source_receipt: Option<String>,
}

fn default_success() -> bool {
    true
}

fn default_reward() -> f32 {
    1.0
}

/// In-memory case-based memory store with optional JSONL persistence.
#[derive(Debug, Default)]
pub struct CaseStore {
    cases: HashMap<String, Case>,
    /// Path to the JSONL journal file. `None` for pure in-memory mode.
    journal_path: Option<PathBuf>,
}

impl CaseStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a case store backed by a JSONL journal in `data_dir`.
    ///
    /// If `data_dir/cases.jsonl` exists, it is replayed to rebuild in-memory
    /// state. Subsequent `record_case`/`delete` calls append to the journal.
    pub fn with_persistence(data_dir: &Path) -> std::io::Result<Self> {
        std::fs::create_dir_all(data_dir)?;
        let journal_path = data_dir.join("cases.jsonl");
        let mut store = Self {
            cases: HashMap::new(),
            journal_path: Some(journal_path.clone()),
        };
        if journal_path.exists() {
            store.replay_journal(&journal_path)?;
        }
        Ok(store)
    }

    fn append_journal(&self, event: &CaseJournalEvent) -> std::io::Result<()> {
        if let Some(path) = &self.journal_path {
            let mut file = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
            let line = serde_json::to_string(event).map_err(std::io::Error::other)?;
            writeln!(file, "{}", line)?;
        }
        Ok(())
    }

    /// Replay a JSONL journal file to rebuild in-memory state.
    /// Corrupted or blank lines are skipped with a warning.
    fn replay_journal(&mut self, path: &Path) -> std::io::Result<()> {
        let file = std::fs::File::open(path)?;
        let reader = std::io::BufReader::new(file);
        for (line_no, line) in reader.lines().enumerate() {
            let line = line?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            match serde_json::from_str::<CaseJournalEvent>(trimmed) {
                Ok(CaseJournalEvent::Record { case }) => {
                    self.cases.insert(case.case_id.clone(), case);
                }
                Ok(CaseJournalEvent::Delete { case_id }) => {
                    self.cases.remove(&case_id);
                }
                Err(err) => {
                    tracing::warn!(line_no = line_no + 1, ?err, "case-journal-parse-skip");
                }
            }
        }
        Ok(())
    }

    /// Record a new case. `reward` is clamped to `[0.0, 1.0]`. Journaled so the
    /// case bank survives a restart. Returns the stored [`Case`].
    pub fn record_case(&mut self, req: RecordCase) -> Case {
        let case = Case {
            case_id: format!("c_{}", uuid::Uuid::new_v4().to_string().replace('-', "")),
            task: req.task,
            context: req.context,
            action: req.action,
            outcome: req.outcome,
            success: req.success,
            reward: req.reward.clamp(0.0, 1.0),
            tags: req.tags,
            source_receipt: req.source_receipt,
            created_at: Utc::now(),
            times_reused: 0,
        };
        if let Err(err) = self.append_journal(&CaseJournalEvent::Record { case: case.clone() }) {
            tracing::warn!(?err, "case-journal-append-failed");
        }
        self.cases.insert(case.case_id.clone(), case.clone());
        case
    }

    /// Soft-free a case by id. Returns true if it existed. (Hard removal: the
    /// in-memory entry is dropped and a `Delete` tombstone journaled so replay
    /// does not resurrect it.)
    pub fn delete(&mut self, case_id: &str) -> bool {
        if !self.cases.contains_key(case_id) {
            return false;
        }
        if let Err(err) = self.append_journal(&CaseJournalEvent::Delete {
            case_id: case_id.to_string(),
        }) {
            tracing::warn!(?err, "case-journal-append-failed");
        }
        self.cases.remove(case_id).is_some()
    }

    /// Get a single case by id.
    pub fn get(&self, case_id: &str) -> Option<&Case> {
        self.cases.get(case_id)
    }

    /// Total number of stored cases.
    pub fn count(&self) -> usize {
        self.cases.len()
    }

    /// Iterate over all stored cases.
    pub fn all_cases(&self) -> impl Iterator<Item = &Case> {
        self.cases.values()
    }

    /// Retrieve the cases most analogous to `task`, best first.
    ///
    /// Similarity is the Jaccard overlap between the query's word tokens and
    /// each case's `task` + `tags` tokens — a CPU-only, embedding-ready
    /// baseline (cosine reranking can layer on top later, exactly as the fact
    /// store does over BM25). Ranking: similarity desc, then `reward` desc,
    /// then recency desc. Cases with zero overlap are excluded. When
    /// `only_success` is true, failed cases are filtered out so an agent reuses
    /// what worked.
    ///
    /// Pure (`&self`): retrieval never mutates. Use [`Self::mark_reused`] on the
    /// returned ids to record reuse for ranking.
    pub fn retrieve_similar(&self, task: &str, top_k: usize, only_success: bool) -> Vec<Case> {
        let query = tokenize(task);
        if query.is_empty() {
            return Vec::new();
        }
        let mut scored: Vec<(f64, &Case)> = self
            .cases
            .values()
            .filter(|c| !only_success || c.success)
            .map(|c| (similarity(&query, c), c))
            .filter(|(s, _)| *s > 0.0)
            .collect();
        scored.sort_by(|a, b| {
            b.0.partial_cmp(&a.0)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| b.1.reward.partial_cmp(&a.1.reward).unwrap_or(std::cmp::Ordering::Equal))
                .then_with(|| b.1.created_at.cmp(&a.1.created_at))
        });
        scored.into_iter().take(top_k).map(|(_, c)| c.clone()).collect()
    }

    /// Record that the given cases were reused (returned by retrieval and acted
    /// on). Increments `times_reused`; in-memory only (not journaled), mirroring
    /// fact salience. Returns the number of cases updated.
    pub fn mark_reused(&mut self, case_ids: &[&str]) -> usize {
        let mut updated = 0usize;
        for case_id in case_ids {
            if let Some(case) = self.cases.get_mut(*case_id) {
                case.times_reused = case.times_reused.saturating_add(1);
                updated += 1;
            }
        }
        updated
    }
}

/// Lowercased word-token set: alphanumeric runs of length >= 2. Keeps the
/// similarity signal robust to punctuation/case without pulling in a tokenizer
/// dependency.
fn tokenize(text: &str) -> HashSet<String> {
    text.split(|ch: char| !ch.is_alphanumeric())
        .filter(|t| t.len() >= 2)
        .map(|t| t.to_lowercase())
        .collect()
}

/// Jaccard overlap of the query tokens with the case's `task` + `tags` tokens.
fn similarity(query: &HashSet<String>, case: &Case) -> f64 {
    let mut case_terms = tokenize(&case.task);
    for tag in &case.tags {
        case_terms.extend(tokenize(tag));
    }
    if case_terms.is_empty() {
        return 0.0;
    }
    let intersection = query.intersection(&case_terms).count() as f64;
    let union = query.union(&case_terms).count() as f64;
    if union == 0.0 {
        0.0
    } else {
        intersection / union
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(task: &str, action: &str, success: bool, reward: f32) -> RecordCase {
        RecordCase {
            task: task.to_string(),
            context: None,
            action: action.to_string(),
            outcome: "done".to_string(),
            success,
            reward,
            tags: Vec::new(),
            source_receipt: None,
        }
    }

    #[test]
    fn record_and_get_roundtrip() {
        let mut store = CaseStore::new();
        let c = store.record_case(rec("fix flaky CI test", "added retry with backoff", true, 0.9));
        assert_eq!(store.count(), 1);
        let got = store.get(&c.case_id).unwrap();
        assert_eq!(got.task, "fix flaky CI test");
        assert_eq!(got.action, "added retry with backoff");
        assert!(got.success);
        assert_eq!(got.times_reused, 0);
    }

    #[test]
    fn reward_is_clamped() {
        let mut store = CaseStore::new();
        let hi = store.record_case(rec("t", "a", true, 5.0));
        let lo = store.record_case(rec("t2", "a", true, -2.0));
        assert_eq!(hi.reward, 1.0);
        assert_eq!(lo.reward, 0.0);
    }

    #[test]
    fn retrieve_similar_ranks_by_overlap_then_reward() {
        let mut store = CaseStore::new();
        // Identical task text -> identical similarity to the query, so the
        // `reward` desc tie-break decides order (0.9 ahead of 0.5).
        store.record_case(rec("deploy daemon to gpu host", "ran cargo-deploy", true, 0.5));
        store.record_case(rec("deploy daemon to gpu host", "ran cargo-deploy --flags", true, 0.9));
        store.record_case(rec("write a blog post about cats", "wrote prose", true, 1.0));

        let hits = store.retrieve_similar("deploy daemon to gpu host", 5, false);
        // The two deploy cases match; the (higher-reward) cat post does not
        // overlap and is excluded.
        assert_eq!(hits.len(), 2);
        assert!(
            hits[0].action.contains("--flags"),
            "equal similarity -> higher reward wins"
        );
        assert_eq!(hits[1].reward, 0.5);
        assert!(hits.iter().all(|c| !c.action.contains("prose")));
    }

    #[test]
    fn retrieve_ranks_higher_overlap_above_higher_reward() {
        let mut store = CaseStore::new();
        // A: lower reward but exact task overlap. B: max reward but weaker
        // overlap. Similarity dominates -> A first.
        store.record_case(rec("rebuild the bm25 segment index", "ran segment rebuild", true, 0.3));
        store.record_case(rec("rebuild index quickly", "did something", true, 1.0));
        let hits = store.retrieve_similar("rebuild the bm25 segment index", 5, false);
        assert!(
            hits[0].action.contains("segment rebuild"),
            "higher similarity outranks higher reward"
        );
    }

    #[test]
    fn retrieve_only_success_filters_failures() {
        let mut store = CaseStore::new();
        store.record_case(rec(
            "migrate the fact store backend",
            "flipped flag, broke prod",
            false,
            0.0,
        ));
        store.record_case(rec(
            "migrate the fact store backend",
            "staged shadow then cutover",
            true,
            1.0,
        ));

        let all = store.retrieve_similar("migrate fact store backend", 5, false);
        assert_eq!(all.len(), 2);
        let ok = store.retrieve_similar("migrate fact store backend", 5, true);
        assert_eq!(ok.len(), 1);
        assert!(ok[0].success);
        assert!(ok[0].action.contains("staged"));
    }

    #[test]
    fn retrieve_empty_query_returns_nothing() {
        let mut store = CaseStore::new();
        store.record_case(rec("something", "did it", true, 1.0));
        assert!(store.retrieve_similar("   ", 5, false).is_empty());
        assert!(store.retrieve_similar("!! ?? @@", 5, false).is_empty());
    }

    #[test]
    fn mark_reused_increments_in_memory() {
        let mut store = CaseStore::new();
        let c = store.record_case(rec("t", "a", true, 1.0));
        assert_eq!(store.mark_reused(&[c.case_id.as_str()]), 1);
        assert_eq!(store.mark_reused(&[c.case_id.as_str()]), 1);
        assert_eq!(store.get(&c.case_id).unwrap().times_reused, 2);
        assert_eq!(store.mark_reused(&["c_nope"]), 0);
    }

    #[test]
    fn record_persists_and_replays() {
        let dir = tempfile::tempdir().unwrap();
        let case_id: String;
        {
            let mut store = CaseStore::with_persistence(dir.path()).unwrap();
            let c = store.record_case(rec("resize the dense lane mmap", "raised OOM flags", true, 0.8));
            case_id = c.case_id.clone();
            // Reuse is NOT journaled.
            store.mark_reused(&[case_id.as_str()]);
        }
        let store = CaseStore::with_persistence(dir.path()).unwrap();
        let c = store.get(&case_id).unwrap();
        assert_eq!(c.task, "resize the dense lane mmap");
        assert_eq!(c.reward, 0.8);
        // times_reused resets across restart (in-memory hint).
        assert_eq!(c.times_reused, 0);
    }

    #[test]
    fn delete_tombstone_survives_replay() {
        let dir = tempfile::tempdir().unwrap();
        let case_id: String;
        {
            let mut store = CaseStore::with_persistence(dir.path()).unwrap();
            let c = store.record_case(rec("temp", "x", true, 1.0));
            case_id = c.case_id.clone();
            assert!(store.delete(&case_id));
            assert_eq!(store.count(), 0);
            assert!(!store.delete("c_nope"));
        }
        let store = CaseStore::with_persistence(dir.path()).unwrap();
        assert!(store.get(&case_id).is_none());
        assert_eq!(store.count(), 0);
    }
}
