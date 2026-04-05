// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Scoped session state store.
//!
//! Each session holds structured key-value state that an agent can accumulate
//! and resume later without replaying the full conversation history.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Session state container.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionState {
    pub session_id: String,
    pub state: serde_json::Value,
    pub updated_at: DateTime<Utc>,
    pub total_tokens: usize,
}

/// In-memory session store.
#[derive(Debug, Default)]
pub struct SessionStore {
    sessions: HashMap<String, SessionState>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create or update session state.
    pub fn put(&mut self, session_id: &str, state: serde_json::Value) -> SessionState {
        let tokens = estimate_tokens(&state);

        let session = SessionState {
            session_id: session_id.to_string(),
            state,
            updated_at: Utc::now(),
            total_tokens: tokens,
        };

        self.sessions.insert(session_id.to_string(), session.clone());
        session
    }

    /// Get session state by ID.
    pub fn get(&self, session_id: &str) -> Option<&SessionState> {
        self.sessions.get(session_id)
    }

    /// Delete a session.
    pub fn delete(&mut self, session_id: &str) -> bool {
        self.sessions.remove(session_id).is_some()
    }

    /// List all session IDs.
    pub fn list(&self) -> Vec<&str> {
        self.sessions.keys().map(|s| s.as_str()).collect()
    }

    /// Total number of active sessions.
    pub fn count(&self) -> usize {
        self.sessions.len()
    }
}

/// Estimate tokens from a JSON value (serialized bytes / 4).
fn estimate_tokens(value: &serde_json::Value) -> usize {
    let bytes = serde_json::to_string(value).map(|s| s.len()).unwrap_or(0);
    (bytes + 3) / 4
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

        let session = store.put("sess_001", state.clone());
        assert_eq!(session.session_id, "sess_001");
        assert!(session.total_tokens > 0);

        let retrieved = store.get("sess_001").unwrap();
        assert_eq!(retrieved.state, state);
    }

    #[test]
    fn update_session_overwrites() {
        let mut store = SessionStore::new();

        store.put("sess_001", json!({"step": 1}));
        store.put("sess_001", json!({"step": 2, "done": true}));

        let session = store.get("sess_001").unwrap();
        assert_eq!(session.state["step"], 2);
        assert_eq!(session.state["done"], true);
    }

    #[test]
    fn delete_session() {
        let mut store = SessionStore::new();
        store.put("sess_001", json!({}));
        assert_eq!(store.count(), 1);
        store.delete("sess_001");
        assert_eq!(store.count(), 0);
    }

    #[test]
    fn list_sessions() {
        let mut store = SessionStore::new();
        assert!(store.list().is_empty());

        store.put("sess_a", json!({"a": 1}));
        store.put("sess_b", json!({"b": 2}));

        let mut ids = store.list();
        ids.sort();
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
        let session = store.put("sess_rt", state.clone());

        let json_str = serde_json::to_string(&session).unwrap();
        let deserialized: SessionState = serde_json::from_str(&json_str).unwrap();
        assert_eq!(deserialized.session_id, "sess_rt");
        assert_eq!(deserialized.state, state);
        assert!(deserialized.total_tokens > 0);
    }

    #[test]
    fn put_updates_token_count() {
        let mut store = SessionStore::new();

        store.put("sess_t", json!("short"));
        let t1 = store.get("sess_t").unwrap().total_tokens;

        store.put("sess_t", json!({"a_much_longer_value": "with more content to increase token count significantly"}));
        let t2 = store.get("sess_t").unwrap().total_tokens;

        assert!(t2 > t1);
    }

    #[test]
    fn list_after_delete() {
        let mut store = SessionStore::new();
        store.put("s1", json!({}));
        store.put("s2", json!({}));
        store.delete("s1");

        let ids = store.list();
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0], "s2");
    }
}
