// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Scoped session state store.
//!
//! Each session holds structured key-value state that an agent can accumulate
//! and resume later without replaying the full conversation history.

use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Journal event for session persistence.
#[derive(Serialize, Deserialize)]
#[serde(tag = "op")]
enum SessionJournalEvent {
    #[serde(rename = "store")]
    Store { session: SessionState },
    #[serde(rename = "delete")]
    Delete { session_id: String },
}

/// Session state container.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SessionState {
    pub session_id: String,
    pub state: serde_json::Value,
    pub updated_at: DateTime<Utc>,
    pub total_tokens: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// In-memory session store with optional JSONL persistence.
#[derive(Debug, Default)]
pub struct SessionStore {
    sessions: HashMap<String, SessionState>,
    /// Path to the JSONL journal file. `None` for pure in-memory mode.
    journal_path: Option<PathBuf>,
    /// Optional event bus for real-time mutation notifications.
    event_bus: Option<crate::events::EventBus>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach an event bus so that `put()` and `delete()` emit real-time events.
    pub fn set_event_bus(&mut self, bus: crate::events::EventBus) {
        self.event_bus = Some(bus);
    }

    /// Create a session store backed by a JSONL journal in `data_dir`.
    ///
    /// If `data_dir/sessions.jsonl` exists, it is replayed to rebuild in-memory
    /// state. Subsequent `put()` and `delete()` calls append to the journal.
    pub fn with_persistence(data_dir: &Path) -> std::io::Result<Self> {
        std::fs::create_dir_all(data_dir)?;
        let journal_path = data_dir.join("sessions.jsonl");
        let mut store = Self {
            sessions: HashMap::new(),
            journal_path: Some(journal_path.clone()),
            event_bus: None,
        };
        if journal_path.exists() {
            store.replay_journal(&journal_path)?;
        }
        Ok(store)
    }

    /// Append a journal event to the JSONL file. Best-effort: logs a warning
    /// on IO error but never panics or propagates the error.
    fn append_journal(&self, event: &SessionJournalEvent) {
        if let Some(path) = &self.journal_path {
            let result = (|| -> std::io::Result<()> {
                let mut file = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
                let line = serde_json::to_string(event).map_err(std::io::Error::other)?;
                writeln!(file, "{}", line)?;
                Ok(())
            })();
            if let Err(err) = result {
                tracing::warn!(?err, path = %path.display(), "session-journal-append-failed");
            }
        }
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
            match serde_json::from_str::<SessionJournalEvent>(trimmed) {
                Ok(SessionJournalEvent::Store { session }) => {
                    self.sessions.insert(session.session_id.clone(), session);
                }
                Ok(SessionJournalEvent::Delete { session_id }) => {
                    self.sessions.remove(&session_id);
                }
                Err(err) => {
                    tracing::warn!(line_no = line_no + 1, ?err, "session-journal-parse-skip");
                }
            }
        }
        Ok(())
    }

    /// Create or update session state.
    ///
    /// If `ttl_seconds` is `Some`, the session will expire after the given
    /// duration and be reaped on the next cleanup pass.
    pub fn put(&mut self, session_id: &str, state: serde_json::Value, ttl_seconds: Option<u64>) -> SessionState {
        let tokens = estimate_tokens(&state);
        let expires_at = ttl_seconds.map(|secs| Utc::now() + chrono::Duration::seconds(secs as i64));

        let session = SessionState {
            session_id: session_id.to_string(),
            state,
            updated_at: Utc::now(),
            total_tokens: tokens,
            expires_at,
        };

        self.sessions.insert(session_id.to_string(), session.clone());

        self.append_journal(&SessionJournalEvent::Store {
            session: session.clone(),
        });

        if let Some(bus) = &self.event_bus {
            bus.emit(crate::events::CruxEvent::SessionStored {
                session_id: session.session_id.clone(),
            });
        }

        session
    }

    /// Get session state by ID.
    pub fn get(&self, session_id: &str) -> Option<&SessionState> {
        self.sessions.get(session_id)
    }

    /// Delete a session.
    pub fn delete(&mut self, session_id: &str) -> bool {
        let removed = self.sessions.remove(session_id).is_some();
        if removed {
            self.append_journal(&SessionJournalEvent::Delete {
                session_id: session_id.to_string(),
            });
            if let Some(bus) = &self.event_bus {
                bus.emit(crate::events::CruxEvent::SessionDeleted {
                    session_id: session_id.to_string(),
                });
            }
        }
        removed
    }

    /// List all session IDs.
    pub fn list(&self) -> Vec<&str> {
        self.sessions.keys().map(|s| s.as_str()).collect()
    }

    /// Total number of active sessions.
    pub fn count(&self) -> usize {
        self.sessions.len()
    }

    /// Remove all sessions whose `expires_at` has passed. Returns the number
    /// of sessions reaped.
    pub fn reap_expired(&mut self) -> usize {
        let now = Utc::now();
        let expired: Vec<String> = self
            .sessions
            .iter()
            .filter(|(_, s)| s.expires_at.is_some_and(|exp| now >= exp))
            .map(|(id, _)| id.clone())
            .collect();
        let count = expired.len();
        for id in expired {
            self.sessions.remove(&id);
        }
        count
    }

    /// Test helper: override `expires_at` for a session.
    #[cfg(test)]
    pub fn set_expires_at_for_test(&mut self, id: &str, at: DateTime<Utc>) {
        if let Some(session) = self.sessions.get_mut(id) {
            session.expires_at = Some(at);
        }
    }
}

/// Estimate tokens from a JSON value (serialized bytes / 4).
fn estimate_tokens(value: &serde_json::Value) -> usize {
    let bytes = serde_json::to_string(value).map(|s| s.len()).unwrap_or(0);
    bytes.div_ceil(4)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn store_and_retrieve_session() {
        let mut store = SessionStore::new();

        let state = json!({
            "decisions_made": ["chose canary over blue-green"],
            "open_questions": ["GPU timing"],
            "context_summary": "Building community edition."
        });

        let session = store.put("sess_001", state.clone(), None);
        assert_eq!(session.session_id, "sess_001");
        assert!(session.total_tokens > 0);
        assert!(session.expires_at.is_none());

        let retrieved = store.get("sess_001").unwrap();
        assert_eq!(retrieved.state, state);
    }

    #[test]
    fn update_session_overwrites() {
        let mut store = SessionStore::new();

        store.put("sess_001", json!({"step": 1}), None);
        store.put("sess_001", json!({"step": 2, "done": true}), None);

        let session = store.get("sess_001").unwrap();
        assert_eq!(session.state["step"], 2);
        assert_eq!(session.state["done"], true);
    }

    #[test]
    fn delete_session() {
        let mut store = SessionStore::new();
        store.put("sess_001", json!({}), None);
        assert_eq!(store.count(), 1);
        store.delete("sess_001");
        assert_eq!(store.count(), 0);
    }

    #[test]
    fn list_sessions() {
        let mut store = SessionStore::new();
        assert!(store.list().is_empty());

        store.put("sess_a", json!({"a": 1}), None);
        store.put("sess_b", json!({"b": 2}), None);

        let mut ids = store.list();
        ids.sort_unstable();
        assert_eq!(ids, vec!["sess_a", "sess_b"]);
    }

    #[test]
    fn count_empty_store() {
        let store = SessionStore::new();
        assert_eq!(store.count(), 0);
    }

    #[test]
    fn get_nonexistent_session() {
        let store = SessionStore::new();
        assert!(store.get("no_such_session").is_none());
    }

    #[test]
    fn delete_nonexistent_returns_false() {
        let mut store = SessionStore::new();
        assert!(!store.delete("nonexistent"));
    }

    #[test]
    fn session_state_serde_roundtrip() {
        let mut store = SessionStore::new();
        let state = json!({"decisions": ["a", "b"], "count": 42});
        let session = store.put("sess_rt", state.clone(), None);

        let json_str = serde_json::to_string(&session).unwrap();
        let deserialized: SessionState = serde_json::from_str(&json_str).unwrap();
        assert_eq!(deserialized.session_id, "sess_rt");
        assert_eq!(deserialized.state, state);
        assert!(deserialized.total_tokens > 0);
    }

    #[test]
    fn put_updates_token_count() {
        let mut store = SessionStore::new();

        store.put("sess_t", json!("short"), None);
        let t1 = store.get("sess_t").unwrap().total_tokens;

        store.put(
            "sess_t",
            json!({"a_much_longer_value": "with more content to increase token count significantly"}),
            None,
        );
        let t2 = store.get("sess_t").unwrap().total_tokens;

        assert!(t2 > t1);
    }

    #[test]
    fn list_after_delete() {
        let mut store = SessionStore::new();
        store.put("s1", json!({}), None);
        store.put("s2", json!({}), None);
        store.delete("s1");

        let ids = store.list();
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0], "s2");
    }

    // ── Session TTL tests ──────────────────────────────────────────

    #[test]
    fn put_with_ttl_sets_expires_at() {
        let mut store = SessionStore::new();
        let before = Utc::now();
        let session = store.put("ttl_test", json!({"x": 1}), Some(3600));
        let after = Utc::now();

        let exp = session.expires_at.expect("expires_at should be set");
        // Should be roughly 1 hour from now.
        assert!(exp >= before + chrono::Duration::seconds(3600));
        assert!(exp <= after + chrono::Duration::seconds(3600));
    }

    #[test]
    fn put_without_ttl_has_no_expiry() {
        let mut store = SessionStore::new();
        let session = store.put("no_ttl", json!({"y": 2}), None);
        assert!(session.expires_at.is_none());
    }

    #[test]
    fn reap_expired_removes_old() {
        let mut store = SessionStore::new();
        store.put("expired", json!({}), Some(3600));
        store.set_expires_at_for_test("expired", Utc::now() - chrono::Duration::seconds(10));

        let reaped = store.reap_expired();
        assert_eq!(reaped, 1);
        assert!(store.get("expired").is_none());
    }

    #[test]
    fn reap_expired_keeps_valid() {
        let mut store = SessionStore::new();
        store.put("still_valid", json!({}), Some(3600));

        let reaped = store.reap_expired();
        assert_eq!(reaped, 0);
        assert!(store.get("still_valid").is_some());
    }

    #[test]
    fn reap_expired_ignores_no_ttl() {
        let mut store = SessionStore::new();
        store.put("no_ttl", json!({}), None);

        let reaped = store.reap_expired();
        assert_eq!(reaped, 0);
        assert!(store.get("no_ttl").is_some());
    }

    // ── Persistence tests ─────────────────────────────────────────

    #[test]
    fn test_persistence_roundtrip() {
        let dir = tempfile::tempdir().unwrap();

        {
            let mut store = SessionStore::with_persistence(dir.path()).unwrap();
            store.put("s1", json!({"step": 1}), None);
            store.put("s2", json!({"decisions": ["a", "b"]}), None);
            store.put("s3", json!({"context": "building CE"}), Some(3600));
            assert_eq!(store.count(), 3);
        }

        {
            let store = SessionStore::with_persistence(dir.path()).unwrap();
            assert_eq!(store.count(), 3);
            assert_eq!(store.get("s1").unwrap().state, json!({"step": 1}));
            assert_eq!(store.get("s2").unwrap().state, json!({"decisions": ["a", "b"]}));
            assert_eq!(store.get("s3").unwrap().state, json!({"context": "building CE"}));
            assert!(store.get("s3").unwrap().expires_at.is_some());
        }
    }

    #[test]
    fn test_persistence_delete_roundtrip() {
        let dir = tempfile::tempdir().unwrap();

        {
            let mut store = SessionStore::with_persistence(dir.path()).unwrap();
            store.put("s1", json!({"x": 1}), None);
            store.put("s2", json!({"y": 2}), None);
            store.delete("s1");
            assert_eq!(store.count(), 1);
        }

        {
            let store = SessionStore::with_persistence(dir.path()).unwrap();
            assert_eq!(store.count(), 1);
            assert!(store.get("s1").is_none());
            assert!(store.get("s2").is_some());
        }
    }

    #[test]
    fn test_persistence_update_overwrites() {
        let dir = tempfile::tempdir().unwrap();

        {
            let mut store = SessionStore::with_persistence(dir.path()).unwrap();
            store.put("s1", json!({"step": 1}), None);
            store.put("s1", json!({"step": 2, "done": true}), None);
            assert_eq!(store.count(), 1);
        }

        {
            let store = SessionStore::with_persistence(dir.path()).unwrap();
            assert_eq!(store.count(), 1);
            let s = store.get("s1").unwrap();
            assert_eq!(s.state["step"], 2);
            assert_eq!(s.state["done"], true);
        }
    }

    #[test]
    fn test_in_memory_mode_no_file() {
        let dir = tempfile::tempdir().unwrap();
        let journal_path = dir.path().join("sessions.jsonl");

        let mut store = SessionStore::new();
        store.put("s1", json!({}), None);
        store.delete("nonexistent");

        assert!(!journal_path.exists(), "in-memory mode should not create journal files");
    }
}
