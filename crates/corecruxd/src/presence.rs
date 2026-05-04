// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Multi-agent presence — daemon-level "who's around right now" tracker.
//!
//! Every authenticated request that carries `X-Corecrux-Passport-Id` updates
//! the presence map for that passport. The map is in-memory only (lives for
//! the lifetime of the daemon process) and never touches disk — presence is
//! ephemeral by definition. Bound is a soft cap of 256 entries; oldest are
//! evicted past that to keep memory tiny.
//!
//! Surface: `GET /v1/passports/presence` returns the current snapshot.
//! Consumers (the AX cockpit, mostly) use this to show "agent X is also
//! active in this project right now" coordination signals.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde::Serialize;
use tokio::sync::RwLock;

const PRESENCE_CAP: usize = 256;

#[derive(Debug, Clone, Serialize)]
pub struct PresenceEntry {
    pub passport_id: String,
    pub last_seen_at_unix_ms: u64,
    pub last_route: String,
    pub last_method: String,
    pub call_count: u64,
}

#[derive(Debug, Default, Clone)]
pub struct PresenceTracker {
    inner: Arc<RwLock<BTreeMap<String, PresenceEntry>>>,
}

impl PresenceTracker {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(BTreeMap::new())),
        }
    }

    pub async fn touch(&self, passport_id: &str, method: &str, route: &str) {
        if passport_id.is_empty() {
            return;
        }
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64);
        let mut map = self.inner.write().await;
        let entry = map.entry(passport_id.to_string()).or_insert_with(|| PresenceEntry {
            passport_id: passport_id.to_string(),
            last_seen_at_unix_ms: now_ms,
            last_route: route.to_string(),
            last_method: method.to_string(),
            call_count: 0,
        });
        entry.last_seen_at_unix_ms = now_ms;
        entry.last_route = route.to_string();
        entry.last_method = method.to_string();
        entry.call_count = entry.call_count.saturating_add(1);

        // Soft cap: evict the least-recently-seen entry if we exceeded the bound.
        if map.len() > PRESENCE_CAP {
            if let Some((oldest_id, _)) = map
                .iter()
                .min_by_key(|(_, e)| e.last_seen_at_unix_ms)
                .map(|(id, e)| (id.clone(), e.clone()))
            {
                map.remove(&oldest_id);
            }
        }
    }

    pub async fn snapshot(&self) -> Vec<PresenceEntry> {
        let map = self.inner.read().await;
        let mut out: Vec<PresenceEntry> = map.values().cloned().collect();
        out.sort_by(|a, b| b.last_seen_at_unix_ms.cmp(&a.last_seen_at_unix_ms));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn empty_tracker_returns_empty_snapshot() {
        let t = PresenceTracker::new();
        assert!(t.snapshot().await.is_empty());
    }

    #[tokio::test]
    async fn touch_records_passport_and_route() {
        let t = PresenceTracker::new();
        t.touch("personal-default", "GET", "/v1/console/summary").await;
        let snap = t.snapshot().await;
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].passport_id, "personal-default");
        assert_eq!(snap[0].last_method, "GET");
        assert_eq!(snap[0].last_route, "/v1/console/summary");
        assert_eq!(snap[0].call_count, 1);
    }

    #[tokio::test]
    async fn touch_increments_call_count_and_updates_route() {
        let t = PresenceTracker::new();
        t.touch("p", "GET", "/a").await;
        t.touch("p", "POST", "/b").await;
        let snap = t.snapshot().await;
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].call_count, 2);
        assert_eq!(snap[0].last_method, "POST");
        assert_eq!(snap[0].last_route, "/b");
    }

    #[tokio::test]
    async fn empty_passport_id_is_ignored() {
        let t = PresenceTracker::new();
        t.touch("", "GET", "/x").await;
        assert!(t.snapshot().await.is_empty());
    }

    #[tokio::test]
    async fn snapshot_is_sorted_most_recent_first() {
        let t = PresenceTracker::new();
        t.touch("a", "GET", "/x").await;
        // Sleep so the second touch has a strictly-later ms tick on most clocks.
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        t.touch("b", "GET", "/y").await;
        let snap = t.snapshot().await;
        assert_eq!(snap[0].passport_id, "b");
        assert_eq!(snap[1].passport_id, "a");
    }
}
