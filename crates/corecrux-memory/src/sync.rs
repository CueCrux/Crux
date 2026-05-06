// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Sync client — pull facts from a remote CoreCrux instance and push local
//! facts back. Uses cursor-based pagination and best-effort error handling.

use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::fact_store::{Fact, FactStore};

/// Default entity prefixes that are never pushed to remote. Users can add
/// more via `CORECRUXD_SYNC_PRIVATE_PREFIXES`.
const DEFAULT_PRIVATE_PREFIXES: &[&str] = &[
    "finance:",
    "health:",
    "medical:",
    "personal:",
    "private:",
    "salary:",
    "tax:",
    "password:",
    "credential:",
    "secret:",
    "ssn:",
    "bank:",
    "__ops__::",
    "__bootstrap__::",
];

/// Client that synchronises facts between a local FactStore and a remote
/// CoreCrux HTTP API.
pub struct SyncClient {
    remote_url: String,
    api_key: String,
    cursor_path: PathBuf,
    /// Entity prefixes that are never pushed to the remote.
    private_prefixes: Vec<String>,
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

/// Preview of what a push would send — no data leaves the machine.
#[derive(Debug)]
pub struct SyncPushPreview {
    /// Number of facts that would be pushed.
    pub pushable_count: usize,
    /// Number of facts skipped because they are private (flag or prefix).
    pub private_count: usize,
    /// Number of facts skipped because they came from sync (not locally created).
    pub synced_count: usize,
    /// Summary of entities that would be pushed (entity name → count).
    pub entity_summary: Vec<(String, usize)>,
}

/// Runtime sync posture exposed to operators and agents.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncRuntimeStatus {
    /// High-level operating mode: `local_only`, `manual_sync`, `sync_enabled`, or `degraded`.
    pub mode: String,
    /// Whether the remote sync target is fully configured.
    pub configured: bool,
    /// Whether the daemon background sync loop is enabled.
    pub background_sync_enabled: bool,
    /// Remote CoreCrux base URL when configured.
    pub remote_url: String,
    /// Whether an API key is configured for remote sync.
    pub api_key_configured: bool,
    /// Best-effort remote platform reachability probe result.
    pub platform_online: Option<bool>,
    /// Whether the node is operating in a degraded sync mode.
    pub degraded: bool,
    /// Human-readable reason when operating in a degraded or local-only mode.
    pub degraded_reason: Option<String>,
}

impl SyncRuntimeStatus {
    pub fn from_settings(background_sync_enabled: bool, remote_url: Option<&str>, api_key_configured: bool) -> Self {
        let remote_url = remote_url.unwrap_or_default().trim().to_string();
        let has_remote = !remote_url.is_empty();

        if !has_remote {
            return Self {
                mode: "local_only".to_string(),
                configured: false,
                background_sync_enabled,
                remote_url,
                api_key_configured,
                platform_online: None,
                degraded: false,
                degraded_reason: Some(
                    "remote sync is not configured; continuing with the local fact and session store only".to_string(),
                ),
            };
        }

        if !api_key_configured {
            return Self {
                mode: "degraded".to_string(),
                configured: false,
                background_sync_enabled,
                remote_url,
                api_key_configured,
                platform_online: None,
                degraded: true,
                degraded_reason: Some(
                    "sync remote is configured but CORECRUXD_SYNC_API_KEY is missing; continuing local-only"
                        .to_string(),
                ),
            };
        }

        Self {
            mode: if background_sync_enabled {
                "sync_enabled".to_string()
            } else {
                "manual_sync".to_string()
            },
            configured: true,
            background_sync_enabled,
            remote_url,
            api_key_configured,
            platform_online: None,
            degraded: false,
            degraded_reason: None,
        }
    }

    pub fn with_probe_result(mut self, probe: Result<(), String>) -> Self {
        if self.remote_url.is_empty() {
            return self;
        }

        match probe {
            Ok(()) => {
                self.platform_online = Some(true);
            }
            Err(err) => {
                self.platform_online = Some(false);
                self.mode = "degraded".to_string();
                self.degraded = true;
                self.degraded_reason = Some(format!(
                    "remote platform health check failed: {err}; continuing with the local fact and session store"
                ));
            }
        }
        self
    }
}

/// Best-effort health probe for a remote CoreCrux node.
pub fn probe_remote_health(remote_url: &str) -> Result<(), String> {
    let health_url = format!("{}/healthz", remote_url.trim_end_matches('/'));
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_connect(Some(Duration::from_secs(2)))
        .timeout_recv_response(Some(Duration::from_secs(2)))
        .timeout_recv_body(Some(Duration::from_secs(2)))
        .build()
        .into();
    agent.get(&health_url).call().map(|_| ()).map_err(|err| err.to_string())
}

impl SyncClient {
    /// Create a new sync client.
    ///
    /// * `remote_url` — base URL of the remote CoreCrux instance (e.g. `http://host:14800`)
    /// * `api_key` — bearer token for authentication
    /// * `data_dir` — directory where `sync-cursor.json` is persisted
    pub fn new(remote_url: &str, api_key: &str, data_dir: &std::path::Path) -> Self {
        // Merge default private prefixes with user-configured ones.
        let mut prefixes: Vec<String> = DEFAULT_PRIVATE_PREFIXES.iter().map(|s| (*s).to_string()).collect();
        if let Ok(extra) = std::env::var("CORECRUXD_SYNC_PRIVATE_PREFIXES") {
            for p in extra.split(',') {
                let p = p.trim();
                if !p.is_empty() {
                    prefixes.push(p.to_string());
                }
            }
        }
        Self {
            remote_url: remote_url.trim_end_matches('/').to_string(),
            api_key: api_key.to_string(),
            cursor_path: data_dir.join("sync-cursor.json"),
            private_prefixes: prefixes,
        }
    }

    /// Check whether a fact should be excluded from sync push.
    fn is_private(&self, fact: &Fact) -> bool {
        // Explicit private flag
        if fact.private {
            return true;
        }
        // Entity prefix blocklist
        let entity_lower = fact.entity.to_lowercase();
        self.private_prefixes
            .iter()
            .any(|prefix| entity_lower.starts_with(&prefix.to_lowercase()))
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
                use std::fmt::Write;
                let _ = write!(url, "&since={s}");
            }
            if let Some(ref c) = current_cursor {
                use std::fmt::Write;
                let _ = write!(url, "&cursor={c}");
            }

            let mut resp = ureq::get(&url)
                .header("Authorization", &format!("Bearer {}", self.api_key))
                .call()
                .map_err(|e| format!("sync pull failed: {e}"))?;

            let body: serde_json::Value = resp
                .body_mut()
                .read_json()
                .map_err(|e| format!("sync pull parse error: {e}"))?;

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
        cursor.last_pull_cursor.clone_from(&current_cursor);
        cursor.pull_count += total_pulled as u64;
        self.save_cursor(&cursor);

        Ok(SyncPullResult {
            facts_pulled: total_pulled,
            new_cursor: current_cursor,
        })
    }

    // ── Push ─────────────────────────────────────────────────────────

    /// Preview what a push would send. No data leaves the machine.
    pub fn push_preview(&self, store: &FactStore) -> SyncPushPreview {
        let cursor = self.load_cursor();
        let since = cursor
            .last_push_at
            .as_deref()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc));

        let mut pushable_count = 0usize;
        let mut private_count = 0usize;
        let mut synced_count = 0usize;
        let mut entity_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

        for fact in store.all_facts() {
            if fact.deleted {
                continue;
            }
            if since.is_some_and(|s| fact.stored_at <= s) {
                continue;
            }
            if fact.source_receipt.as_deref().is_some_and(|r| r.starts_with("sync:")) {
                synced_count += 1;
                continue;
            }
            if self.is_private(fact) {
                private_count += 1;
                continue;
            }
            pushable_count += 1;
            *entity_counts.entry(fact.entity.clone()).or_default() += 1;
        }

        let mut entity_summary: Vec<(String, usize)> = entity_counts.into_iter().collect();
        entity_summary.sort_by(|a, b| b.1.cmp(&a.1));

        SyncPushPreview {
            pushable_count,
            private_count,
            synced_count,
            entity_summary,
        }
    }

    /// Push local-only facts to the remote `/v1/facts/bulk` endpoint.
    ///
    /// Only non-deleted facts that were NOT received via sync (i.e. whose
    /// `source_receipt` does not start with `sync:`) are pushed.
    pub fn push(&self, store: &FactStore) -> Result<SyncPushResult, String> {
        let local_facts = self.pushable_facts(store);
        self.push_facts(&local_facts)
    }

    /// Snapshot pushable facts while the caller holds any store lock.
    pub fn pushable_facts(&self, store: &FactStore) -> Vec<Fact> {
        let cursor = self.load_cursor();
        let since = cursor
            .last_push_at
            .as_deref()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc));

        store
            .all_facts()
            .filter(|f| !f.deleted)
            .filter(|f| !self.is_private(f))
            .filter(|f| f.source_receipt.as_deref().is_none_or(|r| !r.starts_with("sync:")))
            .filter(|f| since.is_none_or(|s| f.stored_at > s))
            .cloned()
            .collect()
    }

    /// Push an already-snapshotted set of facts without touching the store.
    pub fn push_facts(&self, local_facts: &[Fact]) -> Result<SyncPushResult, String> {
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
                .header("Authorization", &format!("Bearer {}", self.api_key))
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
            private: false,
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
                private: false,
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
            private: false,
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
            private: false,
        };
        store.store_synced(synced);

        // Verify: all_facts should see both, but local-only filter sees 1
        assert_eq!(store.all_facts().count(), 2);

        let local_only: Vec<_> = store
            .all_facts()
            .filter(|f| !f.deleted)
            .filter(|f| f.source_receipt.as_deref().is_none_or(|r| !r.starts_with("sync:")))
            .collect();
        assert_eq!(local_only.len(), 1);
        assert_eq!(local_only[0].entity, "local");
    }
}
