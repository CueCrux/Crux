// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Sync client — pull facts from a remote CoreCrux instance and push local
//! facts back. Uses cursor-based pagination and best-effort error handling.

use std::io::Write;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::fact_store::{Fact, FactStore};

/// Client that synchronises facts between a local FactStore and a remote
/// CoreCrux HTTP API.
pub struct SyncClient {
    remote_url: String,
    api_key: String,
    cursor_path: PathBuf,
}

/// Persisted cursor tracking pull/push progress.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SyncCursor {
    pub last_pull_at: Option<String>,
    pub last_pull_cursor: Option<String>,
    pub last_push_at: Option<String>,
    pub pull_count: u64,
    pub push_count: u64,
}

/// Result of a pull operation.
#[derive(Debug)]
pub struct SyncPullResult {
    pub facts_pulled: usize,
    pub new_cursor: Option<String>,
}

/// Result of a push operation.
#[derive(Debug)]
pub struct SyncPushResult {
    pub facts_pushed: usize,
}

impl SyncClient {
    /// Create a new sync client.
    ///
    /// * `remote_url` — base URL of the remote CoreCrux instance (e.g. `http://host:14800`)
    /// * `api_key` — bearer token for authentication
    /// * `data_dir` — directory where `sync-cursor.json` is persisted
    pub fn new(remote_url: &str, api_key: &str, data_dir: &std::path::Path) -> Self {
        Self {
            remote_url: remote_url.trim_end_matches('/').to_string(),
            api_key: api_key.to_string(),
            cursor_path: data_dir.join("sync-cursor.json"),
        }
    }

    // ── Cursor persistence ───────────────────────────────────────────

    /// Load the sync cursor from disk, returning a default if the file is
    /// missing or unreadable.
    pub fn load_cursor(&self) -> SyncCursor {
        if !self.cursor_path.exists() {
            return SyncCursor::default();
        }
        match std::fs::read_to_string(&self.cursor_path) {
            Ok(contents) => serde_json::from_str(&contents).unwrap_or_default(),
            Err(err) => {
                tracing::warn!(?err, path = %self.cursor_path.display(), "sync-cursor-load-failed");
                SyncCursor::default()
            }
        }
    }

    /// Atomically save the sync cursor (write to temp file + rename).
    pub fn save_cursor(&self, cursor: &SyncCursor) {
        let result = (|| -> std::io::Result<()> {
            let tmp = self.cursor_path.with_extension("json.tmp");
            let data = serde_json::to_string_pretty(cursor).map_err(std::io::Error::other)?;
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(data.as_bytes())?;
            f.sync_all()?;
            std::fs::rename(&tmp, &self.cursor_path)?;
            Ok(())
        })();
        if let Err(err) = result {
            tracing::warn!(?err, path = %self.cursor_path.display(), "sync-cursor-save-failed");
        }
    }

    // ── Pull ─────────────────────────────────────────────────────────

    /// Pull facts from the remote export endpoint into the local store.
    ///
    /// Resumes from the last pull cursor. Pulled facts are tagged with a
    /// `source_receipt` starting with `sync:` so they are not pushed back.
    pub fn pull(&self, store: &mut FactStore) -> Result<SyncPullResult, String> {
        let cursor = self.load_cursor();
        let mut total_pulled = 0usize;
        let mut current_cursor = cursor.last_pull_cursor.clone();
        let since = cursor.last_pull_at.clone();

        loop {
            let mut url = format!("{}/v1/facts/export?limit=1000", self.remote_url);
            if let Some(ref s) = since {
                url.push_str(&format!("&since={}", s));
            }
            if let Some(ref c) = current_cursor {
                url.push_str(&format!("&cursor={}", c));
            }

            let resp = ureq::get(&url)
                .set("Authorization", &format!("Bearer {}", self.api_key))
                .call()
                .map_err(|e| format!("sync pull failed: {e}"))?;

            let body: serde_json::Value = resp.into_json().map_err(|e| format!("sync pull parse error: {e}"))?;

            let facts: Vec<Fact> =
                serde_json::from_value(body["facts"].clone()).map_err(|e| format!("sync facts parse: {e}"))?;

            for mut fact in facts {
                // Tag as synced so we don't push it back
                fact.source_receipt = Some(format!("sync:{}:{}", self.remote_url, fact.fact_id));
                store.store_synced(fact);
                total_pulled += 1;
            }

            let has_more = body["has_more"].as_bool().unwrap_or(false);
            current_cursor = body["next_cursor"].as_str().map(String::from);

            if !has_more {
                break;
            }
        }

        // Update cursor
        let mut cursor = self.load_cursor();
        cursor.last_pull_at = Some(Utc::now().to_rfc3339());
        cursor.last_pull_cursor = current_cursor.clone();
        cursor.pull_count += total_pulled as u64;
        self.save_cursor(&cursor);

        Ok(SyncPullResult {
            facts_pulled: total_pulled,
            new_cursor: current_cursor,
        })
    }

    // ── Push ─────────────────────────────────────────────────────────

    /// Push local-only facts to the remote `/v1/facts/bulk` endpoint.
    ///
    /// Only non-deleted facts that were NOT received via sync (i.e. whose
    /// `source_receipt` does not start with `sync:`) are pushed.
    pub fn push(&self, store: &FactStore) -> Result<SyncPushResult, String> {
        let cursor = self.load_cursor();
        let since = cursor
            .last_push_at
            .as_deref()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc));

        // Get local-only facts (source_receipt doesn't start with "sync:")
        let local_facts: Vec<&Fact> = store
            .all_facts()
            .filter(|f| !f.deleted)
            .filter(|f| f.source_receipt.as_deref().map_or(true, |r| !r.starts_with("sync:")))
            .filter(|f| since.map_or(true, |s| f.stored_at > s))
            .collect();

        if local_facts.is_empty() {
            return Ok(SyncPushResult { facts_pushed: 0 });
        }

        // Convert to StoreFact-compatible JSON for bulk upload
        let store_facts: Vec<serde_json::Value> = local_facts
            .iter()
            .map(|f| {
                serde_json::json!({
                    "entity": f.entity,
                    "key": f.key,
                    "value": f.value,
                    "confidence": f.confidence,
                    "source_receipt": f.source_receipt,
                })
            })
            .collect();

        // Push in batches of 500
        let mut pushed = 0;
        for batch in store_facts.chunks(500) {
            ureq::put(&format!("{}/v1/facts/bulk", self.remote_url))
                .set("Authorization", &format!("Bearer {}", self.api_key))
                .send_json(serde_json::Value::Array(batch.to_vec()))
                .map_err(|e| format!("sync push failed: {e}"))?;
            pushed += batch.len();
        }

        // Update cursor
        let mut cursor = self.load_cursor();
        cursor.last_push_at = Some(Utc::now().to_rfc3339());
        cursor.push_count += pushed as u64;
        self.save_cursor(&cursor);

        Ok(SyncPushResult { facts_pushed: pushed })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fact_store::StoreFact;

    #[test]
    fn test_sync_cursor_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let client = SyncClient::new("http://localhost:14800", "test-key", dir.path());

        // Default cursor
        let cursor = client.load_cursor();
        assert!(cursor.last_pull_at.is_none());
        assert!(cursor.last_pull_cursor.is_none());
        assert!(cursor.last_push_at.is_none());
        assert_eq!(cursor.pull_count, 0);
        assert_eq!(cursor.push_count, 0);

        // Save and reload
        let cursor = SyncCursor {
            last_pull_at: Some("2026-04-07T12:00:00+00:00".to_string()),
            last_pull_cursor: Some("f_abc123".to_string()),
            last_push_at: Some("2026-04-07T11:00:00+00:00".to_string()),
            pull_count: 42,
            push_count: 10,
        };
        client.save_cursor(&cursor);

        let loaded = client.load_cursor();
        assert_eq!(loaded.last_pull_at, cursor.last_pull_at);
        assert_eq!(loaded.last_pull_cursor, cursor.last_pull_cursor);
        assert_eq!(loaded.last_push_at, cursor.last_push_at);
        assert_eq!(loaded.pull_count, 42);
        assert_eq!(loaded.push_count, 10);
    }

    #[test]
    fn test_store_synced_preserves_identity() {
        let mut store = FactStore::new();

        let original_id = "f_remote_abc123".to_string();
        let original_stored_at = Utc::now() - chrono::Duration::hours(1);

        let fact = Fact {
            fact_id: original_id.clone(),
            entity: "proj".to_string(),
            key: "status".to_string(),
            value: "active".to_string(),
            source_receipt: Some("sync:http://remote:14800:f_remote_abc123".to_string()),
            confidence: 0.95,
            stored_at: original_stored_at,
            tokens: 2,
            deleted: false,
            version: 3,
            supersedes: Some("f_remote_prev".to_string()),
        };

        store.store_synced(fact);

        // The fact should be retrievable with its original identity
        let retrieved = store.get(&original_id).unwrap();
        assert_eq!(retrieved.fact_id, original_id);
        assert_eq!(retrieved.version, 3);
        assert_eq!(retrieved.supersedes, Some("f_remote_prev".to_string()));
        assert_eq!(retrieved.stored_at, original_stored_at);
        assert_eq!(retrieved.entity, "proj");
        assert_eq!(retrieved.key, "status");
        assert_eq!(retrieved.value, "active");
        assert_eq!(retrieved.confidence, 0.95);
    }

    #[test]
    fn test_store_synced_persists_to_journal() {
        let dir = tempfile::tempdir().unwrap();
        let original_id = "f_synced_persist".to_string();

        {
            let mut store = FactStore::with_persistence(dir.path()).unwrap();
            let fact = Fact {
                fact_id: original_id.clone(),
                entity: "e".to_string(),
                key: "k".to_string(),
                value: "v".to_string(),
                source_receipt: Some("sync:http://remote:14800:f_synced_persist".to_string()),
                confidence: 1.0,
                stored_at: Utc::now(),
                tokens: 1,
                deleted: false,
                version: 1,
                supersedes: None,
            };
            store.store_synced(fact);
            assert_eq!(store.count(), 1);
        }

        // Rebuild from journal — synced fact should survive
        {
            let store = FactStore::with_persistence(dir.path()).unwrap();
            assert_eq!(store.count(), 1);
            let retrieved = store.get(&original_id).unwrap();
            assert_eq!(retrieved.fact_id, original_id);
            assert_eq!(retrieved.value, "v");
        }
    }

    #[test]
    fn test_sync_cursor_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let client = SyncClient::new("http://localhost:14800", "key", dir.path());
        // No file saved — should return default
        let cursor = client.load_cursor();
        assert_eq!(cursor.pull_count, 0);
        assert_eq!(cursor.push_count, 0);
    }

    #[test]
    fn test_sync_cursor_corrupt_file() {
        let dir = tempfile::tempdir().unwrap();
        let cursor_path = dir.path().join("sync-cursor.json");
        std::fs::write(&cursor_path, "not valid json!!!").unwrap();

        let client = SyncClient::new("http://localhost:14800", "key", dir.path());
        let cursor = client.load_cursor();
        // Should fall back to default
        assert_eq!(cursor.pull_count, 0);
    }

    #[test]
    fn test_push_filters_synced_facts() {
        let mut store = FactStore::new();

        // Store a local fact
        store.store(StoreFact {
            entity: "local".to_string(),
            key: "k".to_string(),
            value: "v".to_string(),
            source_receipt: None,
            confidence: 1.0,
        });

        // Store a synced fact (should be excluded from push)
        let synced = Fact {
            fact_id: "f_synced_remote".to_string(),
            entity: "remote".to_string(),
            key: "k".to_string(),
            value: "v".to_string(),
            source_receipt: Some("sync:http://remote:14800:f_synced_remote".to_string()),
            confidence: 1.0,
            stored_at: Utc::now(),
            tokens: 1,
            deleted: false,
            version: 1,
            supersedes: None,
        };
        store.store_synced(synced);

        // Verify: all_facts should see both, but local-only filter sees 1
        assert_eq!(store.all_facts().count(), 2);

        let local_only: Vec<_> = store
            .all_facts()
            .filter(|f| !f.deleted)
            .filter(|f| f.source_receipt.as_deref().map_or(true, |r| !r.starts_with("sync:")))
            .collect();
        assert_eq!(local_only.len(), 1);
        assert_eq!(local_only[0].entity, "local");
    }
}
