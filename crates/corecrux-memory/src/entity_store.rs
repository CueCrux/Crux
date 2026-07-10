// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Entity store for the Crux substrate.
//!
//! Stores `EntityRecord { kind, id, payload, created_at, updated_at, version,
//! deleted }` tuples. Persistence mirrors `fact_store.rs` — an in-memory
//! `HashMap<(kind,id), EntityRecord>` plus an append-only JSONL journal at
//! `data_dir/entities.jsonl`. Replay-on-startup reconstructs state.
//!
//! Schema validation is delegated to a `KindRegistry` passed in by the
//! caller; the store itself is schema-agnostic so unit tests can exercise
//! the journal independently.

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::kind_registry::{KindError, KindRegistry};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EntityRecord {
    pub kind: String,
    pub id: String,
    pub payload: Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub version: u32,
    #[serde(default)]
    pub deleted: bool,
    /// Actor that produced this revision. Populated by the HTTP/MCP layer
    /// from the authenticated identity; defaults to `"system"` for internal
    /// writes.
    #[serde(default = "default_actor")]
    pub actor: String,
}

fn default_actor() -> String {
    "system".into()
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op")]
enum JournalEvent {
    #[serde(rename = "upsert")]
    Upsert { record: EntityRecord },
    #[serde(rename = "delete")]
    Delete {
        kind: String,
        id: String,
        deleted_at: DateTime<Utc>,
        actor: String,
        version: u32,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum EntityError {
    #[error("kind validation failed: {0}")]
    Kind(#[from] KindError),
    #[error("entity {kind}/{id} not found")]
    NotFound { kind: String, id: String },
    #[error("journal io error: {0}")]
    Io(String),
}

#[derive(Debug, Default, Clone)]
pub struct EntityQuery {
    pub kind: Option<String>,
    pub limit: Option<usize>,
    pub include_deleted: bool,
}

#[derive(Debug, Default)]
pub struct EntityStore {
    by_id: HashMap<(String, String), EntityRecord>,
    by_kind: HashMap<String, Vec<(String, String)>>,
    /// Full version chain per `(kind, id)`. Each upsert/delete appends here so
    /// `history(kind, id)` can return the receipt-grade audit trail without
    /// re-scanning the journal. M2: this is the substrate's receipt surface.
    history: HashMap<(String, String), Vec<EntityRecord>>,
    journal_path: Option<PathBuf>,
}

impl EntityStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach to an on-disk journal. Replays any pre-existing journal on the
    /// way in.
    pub fn with_persistence(data_dir: &Path) -> Result<Self, EntityError> {
        let journal_path = data_dir.join("entities.jsonl");
        let mut store = Self {
            by_id: HashMap::new(),
            by_kind: HashMap::new(),
            history: HashMap::new(),
            journal_path: Some(journal_path.clone()),
        };
        if journal_path.exists() {
            store.replay_journal(&journal_path)?;
        }
        Ok(store)
    }

    fn replay_journal(&mut self, path: &Path) -> Result<(), EntityError> {
        let f = std::fs::File::open(path).map_err(|e| EntityError::Io(e.to_string()))?;
        let reader = BufReader::new(f);
        for line in reader.lines() {
            let line = line.map_err(|e| EntityError::Io(e.to_string()))?;
            if line.trim().is_empty() {
                continue;
            }
            let evt: JournalEvent = match serde_json::from_str(&line) {
                Ok(e) => e,
                Err(err) => {
                    tracing::warn!("entity journal: skipping malformed line: {}", err);
                    continue;
                }
            };
            self.apply(evt);
        }
        Ok(())
    }

    fn apply(&mut self, evt: JournalEvent) {
        match evt {
            JournalEvent::Upsert { record } => {
                let key = (record.kind.clone(), record.id.clone());
                let kind = record.kind.clone();
                let already = self.by_id.contains_key(&key);
                self.history.entry(key.clone()).or_default().push(record.clone());
                self.by_id.insert(key.clone(), record);
                if !already {
                    self.by_kind.entry(kind).or_default().push(key);
                }
            }
            JournalEvent::Delete {
                kind,
                id,
                deleted_at,
                actor,
                version,
            } => {
                let key = (kind.clone(), id.clone());
                let snapshot = if let Some(rec) = self.by_id.get_mut(&key) {
                    rec.deleted = true;
                    rec.updated_at = deleted_at;
                    actor.clone_into(&mut rec.actor);
                    rec.version = version;
                    Some(rec.clone())
                } else {
                    None
                };
                if let Some(snap) = snapshot {
                    self.history.entry(key).or_default().push(snap);
                }
            }
        }
    }

    fn write_journal(&self, evt: &JournalEvent) -> Result<(), EntityError> {
        let Some(path) = &self.journal_path else { return Ok(()) };
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| EntityError::Io(e.to_string()))?;
        let line = serde_json::to_string(evt).map_err(|e| EntityError::Io(e.to_string()))?;
        f.write_all(line.as_bytes())
            .map_err(|e| EntityError::Io(e.to_string()))?;
        f.write_all(b"\n").map_err(|e| EntityError::Io(e.to_string()))?;
        Ok(())
    }

    /// Upsert an entity. If `registry` is Some, the payload is validated.
    pub fn upsert(
        &mut self,
        kind: &str,
        id: &str,
        payload: Value,
        actor: &str,
        registry: Option<&KindRegistry>,
    ) -> Result<EntityRecord, EntityError> {
        if let Some(reg) = registry {
            reg.validate(kind, &payload)?;
        }
        let now = Utc::now();
        let key = (kind.to_string(), id.to_string());
        let (created_at, version) = match self.by_id.get(&key) {
            Some(prev) => (prev.created_at, prev.version + 1),
            None => (now, 1),
        };
        let record = EntityRecord {
            kind: kind.to_string(),
            id: id.to_string(),
            payload,
            created_at,
            updated_at: now,
            version,
            deleted: false,
            actor: actor.to_string(),
        };
        let evt = JournalEvent::Upsert { record: record.clone() };
        self.write_journal(&evt)?;
        self.apply(evt);
        Ok(record)
    }

    pub fn get(&self, kind: &str, id: &str) -> Option<&EntityRecord> {
        let key = (kind.to_string(), id.to_string());
        self.by_id.get(&key).filter(|r| !r.deleted)
    }

    pub fn get_including_deleted(&self, kind: &str, id: &str) -> Option<&EntityRecord> {
        let key = (kind.to_string(), id.to_string());
        self.by_id.get(&key)
    }

    pub fn delete(&mut self, kind: &str, id: &str, actor: &str) -> Result<EntityRecord, EntityError> {
        let key = (kind.to_string(), id.to_string());
        let next_version = self
            .by_id
            .get(&key)
            .map(|r| r.version + 1)
            .ok_or_else(|| EntityError::NotFound {
                kind: kind.into(),
                id: id.into(),
            })?;
        let now = Utc::now();
        let evt = JournalEvent::Delete {
            kind: kind.into(),
            id: id.into(),
            deleted_at: now,
            actor: actor.into(),
            version: next_version,
        };
        self.write_journal(&evt)?;
        self.apply(evt);
        // Just-applied delete; the record is guaranteed present.
        self.by_id
            .get(&key)
            .cloned()
            .ok_or_else(|| EntityError::Io("delete apply did not persist record".into()))
    }

    pub fn list(&self, q: &EntityQuery) -> Vec<&EntityRecord> {
        let iter: Box<dyn Iterator<Item = &EntityRecord>> = match &q.kind {
            Some(k) => match self.by_kind.get(k) {
                Some(keys) => Box::new(keys.iter().filter_map(|key| self.by_id.get(key))),
                None => Box::new(std::iter::empty()),
            },
            None => Box::new(self.by_id.values()),
        };
        let mut out: Vec<&EntityRecord> = iter.filter(|r| q.include_deleted || !r.deleted).collect();
        out.sort_by(|a, b| a.kind.cmp(&b.kind).then_with(|| a.id.cmp(&b.id)));
        if let Some(limit) = q.limit {
            out.truncate(limit);
        }
        out
    }

    pub fn count(&self) -> usize {
        self.by_id.values().filter(|r| !r.deleted).count()
    }

    /// Return the full version chain (oldest → newest) for an entity. M2
    /// receipts integration: this is the substrate's audit trail.
    pub fn history(&self, kind: &str, id: &str) -> Vec<&EntityRecord> {
        let key = (kind.to_string(), id.to_string());
        self.history.get(&key).map(|v| v.iter().collect()).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::TempDir;

    #[test]
    fn upsert_get_list_in_memory() {
        let mut s = EntityStore::new();
        let r = s
            .upsert("capability", "X", json!({"name":"x"}), "tester", None)
            .unwrap();
        assert_eq!(r.version, 1);
        assert!(s.get("capability", "X").is_some());
        let q = EntityQuery {
            kind: Some("capability".into()),
            ..Default::default()
        };
        assert_eq!(s.list(&q).len(), 1);
    }

    #[test]
    fn upsert_bumps_version() {
        let mut s = EntityStore::new();
        s.upsert("capability", "X", json!({"name":"x1"}), "t", None).unwrap();
        let r = s.upsert("capability", "X", json!({"name":"x2"}), "t", None).unwrap();
        assert_eq!(r.version, 2);
        let got = s.get("capability", "X").unwrap();
        assert_eq!(got.payload["name"], "x2");
    }

    #[test]
    fn delete_marks_deleted() {
        let mut s = EntityStore::new();
        s.upsert("capability", "X", json!({"name":"x"}), "t", None).unwrap();
        s.delete("capability", "X", "t").unwrap();
        assert!(s.get("capability", "X").is_none());
        assert!(s.get_including_deleted("capability", "X").unwrap().deleted);
    }

    #[test]
    fn delete_missing_errors() {
        let mut s = EntityStore::new();
        assert!(matches!(
            s.delete("capability", "ghost", "t"),
            Err(EntityError::NotFound { .. })
        ));
    }

    #[test]
    fn journal_replay_round_trip() {
        let dir = TempDir::new().unwrap();
        {
            let mut s = EntityStore::with_persistence(dir.path()).unwrap();
            s.upsert("capability", "A", json!({"v":1}), "t", None).unwrap();
            s.upsert("capability", "B", json!({"v":2}), "t", None).unwrap();
            s.upsert("capability", "A", json!({"v":3}), "t", None).unwrap();
            s.delete("capability", "B", "t").unwrap();
        }
        let s2 = EntityStore::with_persistence(dir.path()).unwrap();
        assert_eq!(s2.get("capability", "A").unwrap().payload["v"], 3);
        assert_eq!(s2.get("capability", "A").unwrap().version, 2);
        assert!(s2.get("capability", "B").is_none());
        assert!(s2.get_including_deleted("capability", "B").unwrap().deleted);
    }

    #[test]
    fn validation_via_registry() {
        use crate::kind_registry::{KindRegistration, KindRegistry};
        let mut reg = KindRegistry::new();
        reg.register(KindRegistration {
            kind: "capability".into(),
            json_schema: json!({"type":"object","required":["name"]}),
            allowed_outgoing_edges: vec![],
            allowed_incoming_edges: vec![],
            description: String::new(),
        })
        .unwrap();
        let mut s = EntityStore::new();
        assert!(s
            .upsert("capability", "X", json!({"name":"ok"}), "t", Some(&reg))
            .is_ok());
        assert!(s
            .upsert("capability", "Y", json!({"missing":"name"}), "t", Some(&reg))
            .is_err());
    }

    #[test]
    fn history_records_full_version_chain() {
        let mut s = EntityStore::new();
        s.upsert("capability", "X", json!({"v": 1}), "a", None).unwrap();
        s.upsert("capability", "X", json!({"v": 2}), "b", None).unwrap();
        s.upsert("capability", "X", json!({"v": 3}), "c", None).unwrap();
        let h = s.history("capability", "X");
        assert_eq!(h.len(), 3, "three upserts should yield three versions");
        assert_eq!(h[0].version, 1);
        assert_eq!(h[0].actor, "a");
        assert_eq!(h[2].payload["v"], 3);
        assert_eq!(h[2].actor, "c");
    }

    #[test]
    fn history_includes_delete_event() {
        let mut s = EntityStore::new();
        s.upsert("capability", "X", json!({}), "a", None).unwrap();
        s.delete("capability", "X", "deleter").unwrap();
        let h = s.history("capability", "X");
        assert_eq!(h.len(), 2);
        assert!(h.last().unwrap().deleted);
        assert_eq!(h.last().unwrap().actor, "deleter");
    }

    #[test]
    fn list_filters_by_kind_and_limits() {
        let mut s = EntityStore::new();
        for i in 0..5 {
            s.upsert("capability", &format!("C{i}"), json!({"i":i}), "t", None)
                .unwrap();
        }
        for i in 0..3 {
            s.upsert("repo", &format!("R{i}"), json!({"i":i}), "t", None).unwrap();
        }
        assert_eq!(
            s.list(&EntityQuery {
                kind: Some("capability".into()),
                ..Default::default()
            })
            .len(),
            5
        );
        assert_eq!(
            s.list(&EntityQuery {
                kind: None,
                ..Default::default()
            })
            .len(),
            8
        );
        assert_eq!(
            s.list(&EntityQuery {
                kind: None,
                limit: Some(2),
                ..Default::default()
            })
            .len(),
            2
        );
    }
}
