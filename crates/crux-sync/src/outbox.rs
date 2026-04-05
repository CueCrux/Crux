// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Local outbox for contribution sync.
//!
//! Contributions are written to a local append-only outbox before being
//! synced to VaultCrux. The outbox survives restarts and network failures.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// An entry in the local outbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboxEntry {
    pub id: String,
    pub contribution: serde_json::Value,
    pub created_at: String,
    pub synced: bool,
}

/// Local outbox backed by a JSON lines file.
pub struct Outbox {
    path: PathBuf,
}

impl Outbox {
    pub fn new(data_dir: &str) -> Self {
        Self {
            path: PathBuf::from(data_dir).join("sync-outbox.jsonl"),
        }
    }

    /// Append a contribution to the outbox.
    pub fn append(&self, contribution: serde_json::Value) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let id = format!("out_{}", uuid::Uuid::new_v4().to_string().replace('-', ""));
        let entry = OutboxEntry {
            id: id.clone(),
            contribution,
            created_at: chrono::Utc::now().to_rfc3339(),
            synced: false,
        };

        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        let line = serde_json::to_string(&entry)?;
        writeln!(file, "{}", line)?;

        Ok(id)
    }

    /// Read all unsynced entries.
    pub fn pending(&self) -> Result<Vec<OutboxEntry>, Box<dyn std::error::Error + Send + Sync>> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }

        let content = std::fs::read_to_string(&self.path)?;
        let entries: Vec<OutboxEntry> = content
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .filter(|e: &OutboxEntry| !e.synced)
            .collect();

        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn append_and_read_pending() {
        let dir = tempfile::tempdir().unwrap();
        let outbox = Outbox::new(dir.path().to_str().unwrap());

        let id = outbox.append(json!({"type": "fact", "body": "hello"})).unwrap();
        assert!(id.starts_with("out_"));

        let pending = outbox.pending().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, id);
        assert!(!pending[0].synced);
        assert_eq!(pending[0].contribution["type"], "fact");
    }

    #[test]
    fn pending_on_nonexistent_file() {
        let dir = tempfile::tempdir().unwrap();
        let outbox = Outbox::new(dir.path().to_str().unwrap());

        let pending = outbox.pending().unwrap();
        assert!(pending.is_empty());
    }

    #[test]
    fn multiple_appends() {
        let dir = tempfile::tempdir().unwrap();
        let outbox = Outbox::new(dir.path().to_str().unwrap());

        let id1 = outbox.append(json!({"n": 1})).unwrap();
        let id2 = outbox.append(json!({"n": 2})).unwrap();
        let id3 = outbox.append(json!({"n": 3})).unwrap();

        assert_ne!(id1, id2);
        assert_ne!(id2, id3);

        let pending = outbox.pending().unwrap();
        assert_eq!(pending.len(), 3);
    }

    #[test]
    fn synced_entries_are_filtered() {
        let dir = tempfile::tempdir().unwrap();
        let outbox = Outbox::new(dir.path().to_str().unwrap());

        // Append a normal entry
        outbox.append(json!({"n": 1})).unwrap();

        // Manually write a synced entry to the file
        use std::io::Write;
        let path = std::path::PathBuf::from(dir.path()).join("sync-outbox.jsonl");
        let mut file = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        let synced = OutboxEntry {
            id: "out_synced".to_string(),
            contribution: json!({"n": 2}),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            synced: true,
        };
        writeln!(file, "{}", serde_json::to_string(&synced).unwrap()).unwrap();

        let pending = outbox.pending().unwrap();
        assert_eq!(pending.len(), 1);
        assert_ne!(pending[0].id, "out_synced");
    }

    #[test]
    fn outbox_entry_serde_roundtrip() {
        let entry = OutboxEntry {
            id: "out_abc123".to_string(),
            contribution: json!({"key": "value"}),
            created_at: "2026-04-01T12:00:00Z".to_string(),
            synced: false,
        };

        let json_str = serde_json::to_string(&entry).unwrap();
        let deserialized: OutboxEntry = serde_json::from_str(&json_str).unwrap();
        assert_eq!(deserialized.id, "out_abc123");
        assert_eq!(deserialized.contribution["key"], "value");
        assert!(!deserialized.synced);
    }

    #[test]
    fn outbox_path_construction() {
        let outbox = Outbox::new("/tmp/test-dir");
        assert_eq!(outbox.path, std::path::PathBuf::from("/tmp/test-dir/sync-outbox.jsonl"));
    }

    #[test]
    fn outbox_entry_clone_and_debug() {
        let entry = OutboxEntry {
            id: "out_clone".to_string(),
            contribution: json!({"x": 1}),
            created_at: "2026-04-01T00:00:00Z".to_string(),
            synced: false,
        };

        let cloned = entry.clone();
        assert_eq!(cloned.id, entry.id);
        assert_eq!(cloned.contribution, entry.contribution);
        assert_eq!(cloned.created_at, entry.created_at);
        assert_eq!(cloned.synced, entry.synced);

        // Exercise Debug
        let debug_str = format!("{:?}", entry);
        assert!(debug_str.contains("out_clone"));
    }

    #[test]
    fn append_to_nonexistent_parent_dir_fails() {
        let outbox = Outbox::new("/nonexistent/path/that/does/not/exist");
        let result = outbox.append(json!({"n": 1}));
        assert!(result.is_err());
    }

    #[test]
    fn pending_with_only_synced_entries() {
        let dir = tempfile::tempdir().unwrap();
        let outbox = Outbox::new(dir.path().to_str().unwrap());

        // Write only synced entries
        use std::io::Write;
        let path = std::path::PathBuf::from(dir.path()).join("sync-outbox.jsonl");
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .unwrap();
        let synced = OutboxEntry {
            id: "out_done".to_string(),
            contribution: json!({"n": 1}),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            synced: true,
        };
        writeln!(file, "{}", serde_json::to_string(&synced).unwrap()).unwrap();

        let pending = outbox.pending().unwrap();
        assert!(pending.is_empty());
    }

    #[test]
    fn malformed_lines_are_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let outbox = Outbox::new(dir.path().to_str().unwrap());

        // Append a valid entry
        outbox.append(json!({"n": 1})).unwrap();

        // Write a malformed line
        use std::io::Write;
        let path = std::path::PathBuf::from(dir.path()).join("sync-outbox.jsonl");
        let mut file = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        writeln!(file, "this is not valid json").unwrap();

        let pending = outbox.pending().unwrap();
        assert_eq!(pending.len(), 1);
    }
}
