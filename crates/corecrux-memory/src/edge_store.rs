// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Edge store for the Crux substrate.
//!
//! Stores directed labelled edges between substrate entities:
//! `(from_kind, from_id, edge_kind, to_kind, to_id, payload)`. Uniqueness is
//! on the five-tuple; re-upserting the same edge updates `payload`,
//! `updated_at`, and bumps `version`. Persistence is via an append-only
//! JSONL journal at `data_dir/substrate-edges.jsonl` (distinct from the
//! existing `relations.jsonl` used by `corecrux-projections`).
//!
//! Secondary indexes:
//! - `from_index`: `(from_kind, from_id)` → list of edge IDs
//! - `to_index`: `(to_kind, to_id)` → list of edge IDs
//! - `kind_index`: `edge_kind` → list of edge IDs

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EdgeRecord {
    pub edge_id: String,
    pub from_kind: String,
    pub from_id: String,
    pub edge_kind: String,
    pub to_kind: String,
    pub to_id: String,
    #[serde(default)]
    pub payload: Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub version: u32,
    #[serde(default)]
    pub deleted: bool,
    #[serde(default = "default_actor")]
    pub actor: String,
}

fn default_actor() -> String {
    "system".into()
}

fn edge_id(from_kind: &str, from_id: &str, edge_kind: &str, to_kind: &str, to_id: &str) -> String {
    format!("{from_kind}/{from_id}|{edge_kind}|{to_kind}/{to_id}")
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op")]
enum JournalEvent {
    #[serde(rename = "upsert")]
    Upsert { record: Box<EdgeRecord> },
    #[serde(rename = "delete")]
    Delete {
        edge_id: String,
        deleted_at: DateTime<Utc>,
        actor: String,
        version: u32,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum EdgeError {
    #[error("edge {0} not found")]
    NotFound(String),
    #[error("journal io error: {0}")]
    Io(String),
}

#[derive(Debug, Default, Clone)]
pub struct EdgeQuery {
    pub from_kind: Option<String>,
    pub from_id: Option<String>,
    pub to_kind: Option<String>,
    pub to_id: Option<String>,
    pub edge_kind: Option<String>,
    pub limit: Option<usize>,
    pub include_deleted: bool,
}

#[derive(Debug, Default)]
pub struct EdgeStore {
    by_id: HashMap<String, EdgeRecord>,
    from_index: HashMap<(String, String), Vec<String>>,
    to_index: HashMap<(String, String), Vec<String>>,
    kind_index: HashMap<String, Vec<String>>,
    journal_path: Option<PathBuf>,
}

impl EdgeStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_persistence(data_dir: &Path) -> Result<Self, EdgeError> {
        let journal_path = data_dir.join("substrate-edges.jsonl");
        let mut store = Self {
            by_id: HashMap::new(),
            from_index: HashMap::new(),
            to_index: HashMap::new(),
            kind_index: HashMap::new(),
            journal_path: Some(journal_path.clone()),
        };
        if journal_path.exists() {
            store.replay_journal(&journal_path)?;
        }
        Ok(store)
    }

    fn replay_journal(&mut self, path: &Path) -> Result<(), EdgeError> {
        let f = std::fs::File::open(path).map_err(|e| EdgeError::Io(e.to_string()))?;
        let reader = BufReader::new(f);
        for line in reader.lines() {
            let line = line.map_err(|e| EdgeError::Io(e.to_string()))?;
            if line.trim().is_empty() {
                continue;
            }
            let evt: JournalEvent = match serde_json::from_str(&line) {
                Ok(e) => e,
                Err(err) => {
                    tracing::warn!("edge journal: skipping malformed line: {}", err);
                    continue;
                }
            };
            self.apply(evt);
        }
        Ok(())
    }

    fn write_journal(&self, evt: &JournalEvent) -> Result<(), EdgeError> {
        let Some(path) = &self.journal_path else { return Ok(()) };
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| EdgeError::Io(e.to_string()))?;
        let line = serde_json::to_string(evt).map_err(|e| EdgeError::Io(e.to_string()))?;
        f.write_all(line.as_bytes()).map_err(|e| EdgeError::Io(e.to_string()))?;
        f.write_all(b"\n").map_err(|e| EdgeError::Io(e.to_string()))?;
        Ok(())
    }

    fn apply(&mut self, evt: JournalEvent) {
        match evt {
            JournalEvent::Upsert { record } => {
                let id = record.edge_id.clone();
                let already = self.by_id.contains_key(&id);
                if !already {
                    self.from_index
                        .entry((record.from_kind.clone(), record.from_id.clone()))
                        .or_default()
                        .push(id.clone());
                    self.to_index
                        .entry((record.to_kind.clone(), record.to_id.clone()))
                        .or_default()
                        .push(id.clone());
                    self.kind_index
                        .entry(record.edge_kind.clone())
                        .or_default()
                        .push(id.clone());
                }
                self.by_id.insert(id, *record);
            }
            JournalEvent::Delete {
                edge_id,
                deleted_at,
                actor,
                version,
            } => {
                if let Some(rec) = self.by_id.get_mut(&edge_id) {
                    rec.deleted = true;
                    rec.updated_at = deleted_at;
                    rec.actor = actor;
                    rec.version = version;
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)] // five-tuple is the edge identity; collapsing into a struct would be a worse API.
    pub fn upsert(
        &mut self,
        from_kind: &str,
        from_id: &str,
        edge_kind: &str,
        to_kind: &str,
        to_id: &str,
        payload: Value,
        actor: &str,
    ) -> Result<EdgeRecord, EdgeError> {
        let id = edge_id(from_kind, from_id, edge_kind, to_kind, to_id);
        let now = Utc::now();
        let (created_at, version) = match self.by_id.get(&id) {
            Some(prev) => (prev.created_at, prev.version + 1),
            None => (now, 1),
        };
        let record = EdgeRecord {
            edge_id: id.clone(),
            from_kind: from_kind.into(),
            from_id: from_id.into(),
            edge_kind: edge_kind.into(),
            to_kind: to_kind.into(),
            to_id: to_id.into(),
            payload,
            created_at,
            updated_at: now,
            version,
            deleted: false,
            actor: actor.into(),
        };
        let evt = JournalEvent::Upsert {
            record: Box::new(record.clone()),
        };
        self.write_journal(&evt)?;
        self.apply(evt);
        Ok(record)
    }

    pub fn get(
        &self,
        from_kind: &str,
        from_id: &str,
        edge_kind: &str,
        to_kind: &str,
        to_id: &str,
    ) -> Option<&EdgeRecord> {
        let id = edge_id(from_kind, from_id, edge_kind, to_kind, to_id);
        self.by_id.get(&id).filter(|r| !r.deleted)
    }

    pub fn delete(
        &mut self,
        from_kind: &str,
        from_id: &str,
        edge_kind: &str,
        to_kind: &str,
        to_id: &str,
        actor: &str,
    ) -> Result<EdgeRecord, EdgeError> {
        let id = edge_id(from_kind, from_id, edge_kind, to_kind, to_id);
        let next_version = self
            .by_id
            .get(&id)
            .map(|r| r.version + 1)
            .ok_or_else(|| EdgeError::NotFound(id.clone()))?;
        let now = Utc::now();
        let evt = JournalEvent::Delete {
            edge_id: id.clone(),
            deleted_at: now,
            actor: actor.into(),
            version: next_version,
        };
        self.write_journal(&evt)?;
        self.apply(evt);
        // Just-applied delete; record is guaranteed present.
        self.by_id
            .get(&id)
            .cloned()
            .ok_or_else(|| EdgeError::Io("delete apply did not persist record".into()))
    }

    pub fn list(&self, q: &EdgeQuery) -> Vec<&EdgeRecord> {
        // Pick the most-selective index to drive iteration.
        let candidates: Vec<&EdgeRecord> = if let (Some(fk), Some(fi)) = (&q.from_kind, &q.from_id) {
            self.from_index
                .get(&(fk.clone(), fi.clone()))
                .map(|ids| ids.iter().filter_map(|id| self.by_id.get(id)).collect())
                .unwrap_or_default()
        } else if let (Some(tk), Some(ti)) = (&q.to_kind, &q.to_id) {
            self.to_index
                .get(&(tk.clone(), ti.clone()))
                .map(|ids| ids.iter().filter_map(|id| self.by_id.get(id)).collect())
                .unwrap_or_default()
        } else if let Some(ek) = &q.edge_kind {
            self.kind_index
                .get(ek)
                .map(|ids| ids.iter().filter_map(|id| self.by_id.get(id)).collect())
                .unwrap_or_default()
        } else {
            self.by_id.values().collect()
        };

        let mut out: Vec<&EdgeRecord> = candidates
            .into_iter()
            .filter(|r| q.include_deleted || !r.deleted)
            .filter(|r| q.from_kind.as_deref().is_none_or(|k| r.from_kind == k))
            .filter(|r| q.from_id.as_deref().is_none_or(|i| r.from_id == i))
            .filter(|r| q.to_kind.as_deref().is_none_or(|k| r.to_kind == k))
            .filter(|r| q.to_id.as_deref().is_none_or(|i| r.to_id == i))
            .filter(|r| q.edge_kind.as_deref().is_none_or(|k| r.edge_kind == k))
            .collect();
        out.sort_by(|a, b| a.edge_id.cmp(&b.edge_id));
        if let Some(limit) = q.limit {
            out.truncate(limit);
        }
        out
    }

    pub fn count(&self) -> usize {
        self.by_id.values().filter(|r| !r.deleted).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::TempDir;

    #[test]
    fn upsert_and_get() {
        let mut s = EdgeStore::new();
        let r = s
            .upsert("capability", "A", "depends_on", "capability", "B", json!({}), "t")
            .unwrap();
        assert_eq!(r.version, 1);
        assert!(s.get("capability", "A", "depends_on", "capability", "B").is_some());
    }

    #[test]
    fn upsert_idempotent_bumps_version() {
        let mut s = EdgeStore::new();
        s.upsert("c", "A", "d", "c", "B", json!({}), "t").unwrap();
        let r2 = s.upsert("c", "A", "d", "c", "B", json!({"note":"x"}), "t").unwrap();
        assert_eq!(r2.version, 2);
        let got = s.get("c", "A", "d", "c", "B").unwrap();
        assert_eq!(got.payload["note"], "x");
    }

    #[test]
    fn list_by_from_uses_index() {
        let mut s = EdgeStore::new();
        s.upsert("c", "A", "d", "c", "B", json!({}), "t").unwrap();
        s.upsert("c", "A", "d", "c", "C", json!({}), "t").unwrap();
        s.upsert("c", "X", "d", "c", "Y", json!({}), "t").unwrap();
        let q = EdgeQuery {
            from_kind: Some("c".into()),
            from_id: Some("A".into()),
            ..Default::default()
        };
        assert_eq!(s.list(&q).len(), 2);
    }

    #[test]
    fn delete_marks_deleted_and_excludes_from_list() {
        let mut s = EdgeStore::new();
        s.upsert("c", "A", "d", "c", "B", json!({}), "t").unwrap();
        s.delete("c", "A", "d", "c", "B", "t").unwrap();
        assert!(s.get("c", "A", "d", "c", "B").is_none());
        let q = EdgeQuery::default();
        assert_eq!(s.list(&q).len(), 0);
        let q_incl = EdgeQuery {
            include_deleted: true,
            ..Default::default()
        };
        assert_eq!(s.list(&q_incl).len(), 1);
    }

    #[test]
    fn journal_replay_round_trip() {
        let dir = TempDir::new().unwrap();
        {
            let mut s = EdgeStore::with_persistence(dir.path()).unwrap();
            s.upsert("c", "A", "d", "c", "B", json!({"v":1}), "t").unwrap();
            s.upsert("c", "A", "d", "c", "B", json!({"v":2}), "t").unwrap();
            s.upsert("c", "X", "d", "c", "Y", json!({}), "t").unwrap();
            s.delete("c", "X", "d", "c", "Y", "t").unwrap();
        }
        let s2 = EdgeStore::with_persistence(dir.path()).unwrap();
        let got = s2.get("c", "A", "d", "c", "B").unwrap();
        assert_eq!(got.payload["v"], 2);
        assert_eq!(got.version, 2);
        assert!(s2.get("c", "X", "d", "c", "Y").is_none());
    }
}
