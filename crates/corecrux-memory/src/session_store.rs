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
    /// Soft, reversible archive flag. Archived sessions are preserved in full
    /// but hidden from the default session listings (MCP `list_sessions` and the
    /// console Sessions panel). `#[serde(default)]` keeps pre-archive journal
    /// lines replay-safe (they deserialize as `archived = false`).
    #[serde(default)]
    pub archived: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archived_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive_reason: Option<String>,
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

    /// Append a journal event to the JSONL file.
    fn append_journal(&self, event: &SessionJournalEvent) -> std::io::Result<()> {
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
        let session = self.build_session(session_id, state, ttl_seconds);

        self.sessions.insert(session_id.to_string(), session.clone());

        if let Err(err) = self.append_journal(&SessionJournalEvent::Store {
            session: session.clone(),
        }) {
            tracing::warn!(?err, "session-journal-append-failed");
        }

        self.emit_session_stored(&session);

        session
    }

    /// Create or update session state only after its journal event has been durably appended.
    pub fn try_put(
        &mut self,
        session_id: &str,
        state: serde_json::Value,
        ttl_seconds: Option<u64>,
    ) -> std::io::Result<SessionState> {
        let session = self.build_session(session_id, state, ttl_seconds);
        self.append_journal(&SessionJournalEvent::Store {
            session: session.clone(),
        })?;
        self.sessions.insert(session_id.to_string(), session.clone());
        self.emit_session_stored(&session);
        Ok(session)
    }

    #[allow(clippy::unused_self)]
    fn build_session(&self, session_id: &str, state: serde_json::Value, ttl_seconds: Option<u64>) -> SessionState {
        let tokens = estimate_tokens(&state);
        let expires_at = ttl_seconds.map(|secs| Utc::now() + chrono::Duration::seconds(secs as i64));

        SessionState {
            session_id: session_id.to_string(),
            state,
            updated_at: Utc::now(),
            total_tokens: tokens,
            expires_at,
            archived: false,
            archived_at: None,
            archive_reason: None,
        }
    }

    fn emit_session_stored(&self, session: &SessionState) {
        if let Some(bus) = &self.event_bus {
            bus.emit(crate::events::CruxEvent::SessionStored {
                session_id: session.session_id.clone(),
            });
        }
    }

    /// Get session state by ID.
    pub fn get(&self, session_id: &str) -> Option<&SessionState> {
        self.sessions.get(session_id)
    }

    /// Delete a session.
    pub fn delete(&mut self, session_id: &str) -> bool {
        let removed = self.sessions.remove(session_id).is_some();
        if removed {
            if let Err(err) = self.append_journal(&SessionJournalEvent::Delete {
                session_id: session_id.to_string(),
            }) {
                tracing::warn!(?err, "session-journal-append-failed");
            }
            if let Some(bus) = &self.event_bus {
                bus.emit(crate::events::CruxEvent::SessionDeleted {
                    session_id: session_id.to_string(),
                });
            }
        }
        removed
    }

    /// Delete a session only after its tombstone has been durably appended.
    pub fn try_delete(&mut self, session_id: &str) -> std::io::Result<bool> {
        if !self.sessions.contains_key(session_id) {
            return Ok(false);
        }
        self.append_journal(&SessionJournalEvent::Delete {
            session_id: session_id.to_string(),
        })?;
        let removed = self.sessions.remove(session_id).is_some();
        if removed {
            if let Some(bus) = &self.event_bus {
                bus.emit(crate::events::CruxEvent::SessionDeleted {
                    session_id: session_id.to_string(),
                });
            }
        }
        Ok(removed)
    }

    /// Set (or clear) the archive flag on a session, preserving its `state`.
    ///
    /// Unlike [`delete`](Self::delete), archiving is non-destructive and
    /// reversible: the session is retained in full but hidden from the default
    /// listings. Returns the updated session, or `None` if the id is unknown.
    /// The mutation is journalled as a `Store` event so it survives replay.
    pub fn set_archived(&mut self, session_id: &str, archived: bool, reason: Option<String>) -> Option<SessionState> {
        let session = self.apply_archive(session_id, archived, reason)?;
        if let Err(err) = self.append_journal(&SessionJournalEvent::Store {
            session: session.clone(),
        }) {
            tracing::warn!(?err, "session-journal-append-failed");
        }
        self.emit_session_archived(&session);
        Some(session)
    }

    /// Archive/restore a session only after its journal event has been durably appended.
    pub fn try_set_archived(
        &mut self,
        session_id: &str,
        archived: bool,
        reason: Option<String>,
    ) -> std::io::Result<Option<SessionState>> {
        // Build the mutated session without committing it to memory first, so a
        // failed journal append leaves the in-memory state untouched.
        let Some(mut session) = self.sessions.get(session_id).cloned() else {
            return Ok(None);
        };
        session.archived = archived;
        session.archived_at = archived.then(Utc::now);
        session.archive_reason = if archived { reason } else { None };
        session.updated_at = Utc::now();
        self.append_journal(&SessionJournalEvent::Store {
            session: session.clone(),
        })?;
        self.sessions.insert(session_id.to_string(), session.clone());
        self.emit_session_archived(&session);
        Ok(Some(session))
    }

    /// Apply the archive mutation in memory and return the updated session.
    fn apply_archive(&mut self, session_id: &str, archived: bool, reason: Option<String>) -> Option<SessionState> {
        let session = self.sessions.get_mut(session_id)?;
        session.archived = archived;
        session.archived_at = archived.then(Utc::now);
        session.archive_reason = if archived { reason } else { None };
        session.updated_at = Utc::now();
        Some(session.clone())
    }

    fn emit_session_archived(&self, session: &SessionState) {
        if let Some(bus) = &self.event_bus {
            bus.emit(crate::events::CruxEvent::SessionArchived {
                session_id: session.session_id.clone(),
                archived: session.archived,
            });
        }
    }

    /// List all session IDs (including archived).
    pub fn list(&self) -> Vec<&str> {
        self.sessions.keys().map(|s| s.as_str()).collect()
    }

    /// List session IDs, optionally including archived ones. When
    /// `include_archived` is false, archived sessions are omitted.
    pub fn list_filtered(&self, include_archived: bool) -> Vec<&str> {
        self.sessions
            .iter()
            .filter(|(_, s)| include_archived || !s.archived)
            .map(|(id, _)| id.as_str())
            .collect()
    }

    /// True if the session exists and is currently archived.
    pub fn is_archived(&self, session_id: &str) -> bool {
        self.sessions.get(session_id).is_some_and(|s| s.archived)
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

    /// Remove expired sessions only after writing tombstones to the journal.
    pub fn try_reap_expired(&mut self) -> std::io::Result<usize> {
        let now = Utc::now();
        let expired: Vec<String> = self
            .sessions
            .iter()
            .filter(|(_, s)| s.expires_at.is_some_and(|exp| now >= exp))
            .map(|(id, _)| id.clone())
            .collect();
        for id in &expired {
            self.append_journal(&SessionJournalEvent::Delete { session_id: id.clone() })?;
        }
        let count = expired.len();
        for id in expired {
            if self.sessions.remove(&id).is_some() {
                if let Some(bus) = &self.event_bus {
                    bus.emit(crate::events::CruxEvent::SessionDeleted { session_id: id });
                }
            }
        }
        Ok(count)
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
            "context_summary": "Building Crux Daemon."
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
            store.put("s3", json!({"context": "building Crux Daemon"}), Some(3600));
            assert_eq!(store.count(), 3);
        }

        {
            let store = SessionStore::with_persistence(dir.path()).unwrap();
            assert_eq!(store.count(), 3);
            assert_eq!(store.get("s1").unwrap().state, json!({"step": 1}));
            assert_eq!(store.get("s2").unwrap().state, json!({"decisions": ["a", "b"]}));
            assert_eq!(
                store.get("s3").unwrap().state,
                json!({"context": "building Crux Daemon"})
            );
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
    fn try_reap_expired_persists_delete_tombstone() {
        let dir = tempfile::tempdir().unwrap();

        {
            let mut store = SessionStore::with_persistence(dir.path()).unwrap();
            store.try_put("expired", json!({"x": 1}), Some(3600)).unwrap();
            store.set_expires_at_for_test("expired", Utc::now() - chrono::Duration::seconds(10));
            let reaped = store.try_reap_expired().unwrap();
            assert_eq!(reaped, 1);
            assert!(store.get("expired").is_none());
        }

        {
            let store = SessionStore::with_persistence(dir.path()).unwrap();
            assert!(store.get("expired").is_none());
            assert_eq!(store.count(), 0);
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

    // ── Archive tests ──────────────────────────────────────────────

    #[test]
    fn new_session_is_not_archived() {
        let mut store = SessionStore::new();
        let s = store.put("s1", json!({"x": 1}), None);
        assert!(!s.archived);
        assert!(s.archived_at.is_none());
        assert!(s.archive_reason.is_none());
    }

    #[test]
    fn archive_preserves_state_and_sets_metadata() {
        let mut store = SessionStore::new();
        store.put("s1", json!({"keep": "this"}), None);

        let archived = store.set_archived("s1", true, Some("done".to_string())).unwrap();
        assert!(archived.archived);
        assert!(archived.archived_at.is_some());
        assert_eq!(archived.archive_reason.as_deref(), Some("done"));
        // State is preserved, not destroyed (unlike delete).
        assert_eq!(archived.state, json!({"keep": "this"}));
        assert!(store.get("s1").is_some());
        assert!(store.is_archived("s1"));
    }

    #[test]
    fn unarchive_clears_metadata() {
        let mut store = SessionStore::new();
        store.put("s1", json!({}), None);
        store.set_archived("s1", true, Some("done".to_string()));

        let restored = store.set_archived("s1", false, None).unwrap();
        assert!(!restored.archived);
        assert!(restored.archived_at.is_none());
        assert!(restored.archive_reason.is_none());
        assert!(!store.is_archived("s1"));
    }

    #[test]
    fn set_archived_unknown_session_returns_none() {
        let mut store = SessionStore::new();
        assert!(store.set_archived("nope", true, None).is_none());
    }

    #[test]
    fn list_filtered_hides_archived_by_default() {
        let mut store = SessionStore::new();
        store.put("active", json!({}), None);
        store.put("done", json!({}), None);
        store.set_archived("done", true, None);

        let mut active = store.list_filtered(false);
        active.sort_unstable();
        assert_eq!(active, vec!["active"]);

        let mut all = store.list_filtered(true);
        all.sort_unstable();
        assert_eq!(all, vec!["active", "done"]);

        // count() and list() remain whole-store.
        assert_eq!(store.count(), 2);
        assert_eq!(store.list().len(), 2);
    }

    #[test]
    fn archive_survives_journal_replay() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut store = SessionStore::with_persistence(dir.path()).unwrap();
            store.try_put("s1", json!({"v": 1}), None).unwrap();
            store.try_set_archived("s1", true, Some("shipped".to_string())).unwrap();
        }
        {
            let store = SessionStore::with_persistence(dir.path()).unwrap();
            let s = store.get("s1").unwrap();
            assert!(s.archived);
            assert_eq!(s.archive_reason.as_deref(), Some("shipped"));
            assert_eq!(s.state, json!({"v": 1}));
            assert!(store.list_filtered(false).is_empty());
        }
    }

    #[test]
    fn pre_archive_journal_line_replays_as_not_archived() {
        // A journal line written before the archive fields existed has no
        // `archived`/`archived_at`/`archive_reason` keys. `#[serde(default)]`
        // must let it replay as `archived = false`.
        let dir = tempfile::tempdir().unwrap();
        let journal = dir.path().join("sessions.jsonl");
        std::fs::create_dir_all(dir.path()).unwrap();
        let legacy = r#"{"op":"store","session":{"session_id":"legacy","state":{"a":1},"updated_at":"2026-01-01T00:00:00Z","total_tokens":3}}"#;
        std::fs::write(&journal, format!("{legacy}\n")).unwrap();

        let store = SessionStore::with_persistence(dir.path()).unwrap();
        let s = store.get("legacy").expect("legacy session replays");
        assert!(!s.archived);
        assert!(s.archived_at.is_none());
        assert_eq!(s.state, json!({"a": 1}));
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
