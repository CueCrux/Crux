// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Durable store of seal-chain heads and their witness proofs (Track W / G1).
//!
//! Each sealed chain head is enqueued `Pending` at seal time and moved to
//! `Witnessed` once a [`crate::witness_submit::Witness`] returns a verified
//! RFC6962 inclusion proof. The pending set doubles as the **retry queue**
//! drained by the M2 background task and the source of the
//! `crux_witness_unwitnessed_heads` gauge. Persisting to an append-only
//! `data_dir/witness_proofs.jsonl` (replayed on startup, mirroring
//! `relations.jsonl`) is what guarantees a head is **never dropped** across a
//! restart: a head that was sealed but not yet witnessed comes back `Pending`.
//!
//! This is a standalone daemon-level store, not a sealed-segment companion, so
//! it carries no storage-allowlist / quarantine-on-restart concern.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::witness_submit::{Witness, WitnessError, WitnessProofV1};

#[derive(Debug, thiserror::Error)]
pub enum WitnessProofStoreError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

/// A seal-chain head awaiting witnessing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingHeadV1 {
    /// Lowercase-hex seal-chain head hash (the latest `material_hash()`).
    pub head_hash: String,
    /// Sequence of the segment whose seal produced this head, if known.
    pub segment_seq: Option<u64>,
    /// Unix seconds the head was enqueued for witnessing.
    pub enqueued_at_unix: i64,
}

/// Append-only journal record. Replay folds these into the live state.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum WitnessProofRecordV1 {
    /// A head was sealed and now awaits witnessing.
    Pending(PendingHeadV1),
    /// A previously-pending head was witnessed; carries the verified proof.
    Witnessed {
        head_hash: String,
        // Boxed: WitnessProofV1 is much larger than the Pending variant.
        proof: Box<WitnessProofV1>,
        witnessed_at_unix: i64,
    },
}

/// Durable record of seal-chain heads and their witness proofs.
///
/// In-memory when constructed via [`Default`]; durable when constructed via
/// [`WitnessProofStore::with_persistence`].
#[derive(Debug, Default)]
pub struct WitnessProofStore {
    journal_path: Option<PathBuf>,
    pending: BTreeMap<String, PendingHeadV1>,
    witnessed: BTreeMap<String, WitnessProofV1>,
}

impl WitnessProofStore {
    /// Open (or create) the store under `data_dir`, replaying any prior
    /// `witness_proofs.jsonl` so pending and witnessed heads survive restarts.
    pub fn with_persistence(data_dir: &Path) -> Result<Self, WitnessProofStoreError> {
        fs::create_dir_all(data_dir)?;
        let journal_path = jsonl_path(data_dir);
        let mut store = Self {
            journal_path: Some(journal_path.clone()),
            pending: BTreeMap::new(),
            witnessed: BTreeMap::new(),
        };
        if journal_path.exists() {
            store.replay(&journal_path)?;
        }
        Ok(store)
    }

    /// Enqueue a freshly-sealed head for witnessing. Idempotent: returns `false`
    /// if the head is already pending or already witnessed (no duplicate
    /// record is written).
    pub fn enqueue(
        &mut self,
        head_hash: impl Into<String>,
        segment_seq: Option<u64>,
    ) -> Result<bool, WitnessProofStoreError> {
        let head_hash = head_hash.into();
        if self.pending.contains_key(&head_hash) || self.witnessed.contains_key(&head_hash) {
            return Ok(false);
        }
        let pending = PendingHeadV1 {
            head_hash: head_hash.clone(),
            segment_seq,
            enqueued_at_unix: now_unix(),
        };
        self.append(&WitnessProofRecordV1::Pending(pending.clone()))?;
        self.pending.insert(head_hash, pending);
        Ok(true)
    }

    /// Record a verified proof for `head_hash`, moving it from pending to
    /// witnessed.
    pub fn record_witnessed(
        &mut self,
        head_hash: impl Into<String>,
        proof: WitnessProofV1,
    ) -> Result<(), WitnessProofStoreError> {
        let head_hash = head_hash.into();
        self.append(&WitnessProofRecordV1::Witnessed {
            head_hash: head_hash.clone(),
            proof: Box::new(proof.clone()),
            witnessed_at_unix: now_unix(),
        })?;
        self.pending.remove(&head_hash);
        self.witnessed.insert(head_hash, proof);
        Ok(())
    }

    /// Snapshot of heads still awaiting witnessing — the drain task copies this
    /// out so it never holds the store lock during network I/O.
    pub fn pending_heads(&self) -> Vec<PendingHeadV1> {
        self.pending.values().cloned().collect()
    }

    /// Number of heads sealed but not yet witnessed (the gauge value).
    pub fn unwitnessed_count(&self) -> usize {
        self.pending.len()
    }

    /// All witnessed `(head_hash, proof)` pairs, for audit-bundle inclusion.
    #[allow(dead_code)] // Read API consumed by audit-bundle inclusion (M3, paired with proof verification).
    pub fn witnessed_proofs(&self) -> Vec<(String, WitnessProofV1)> {
        self.witnessed.iter().map(|(h, p)| (h.clone(), p.clone())).collect()
    }

    /// Whether a head is already known (pending or witnessed).
    #[allow(dead_code)] // Read API consumed by audit-bundle inclusion (M3); exercised by tests.
    pub fn is_known(&self, head_hash: &str) -> bool {
        self.pending.contains_key(head_hash) || self.witnessed.contains_key(head_hash)
    }

    fn append(&self, record: &WitnessProofRecordV1) -> Result<(), WitnessProofStoreError> {
        if let Some(path) = &self.journal_path {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut file = OpenOptions::new().create(true).append(true).open(path)?;
            let mut line = serde_json::to_vec(record)?;
            line.push(b'\n');
            file.write_all(&line)?;
        }
        Ok(())
    }

    fn replay(&mut self, path: &Path) -> Result<(), WitnessProofStoreError> {
        let file = fs::File::open(path)?;
        for (line_no, line) in BufReader::new(file).lines().enumerate() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<WitnessProofRecordV1>(&line) {
                Ok(WitnessProofRecordV1::Pending(pending)) => {
                    // A head witnessed later in the log wins; don't resurrect it.
                    if !self.witnessed.contains_key(&pending.head_hash) {
                        self.pending.insert(pending.head_hash.clone(), pending);
                    }
                }
                Ok(WitnessProofRecordV1::Witnessed { head_hash, proof, .. }) => {
                    self.pending.remove(&head_hash);
                    self.witnessed.insert(head_hash, *proof);
                }
                Err(err) => {
                    tracing::warn!(?err, line_no, "skipping malformed witness_proofs record during reload");
                }
            }
        }
        Ok(())
    }
}

fn jsonl_path(data_dir: &Path) -> PathBuf {
    data_dir.join("witness_proofs.jsonl")
}

/// Submit every pending head to `witness`, returning a per-head outcome keyed by
/// `head_hash`. Pure and blocking: the daemon task runs it inside
/// `spawn_blocking`, then records the `Ok` proofs via
/// [`WitnessProofStore::record_witnessed`]. Failures are left in the outcome so
/// the caller leaves those heads pending to retry on the next tick — nothing is
/// dropped. A malformed (non-32-byte-hex) head surfaces as
/// [`WitnessError::Inconsistent`] rather than silently skipping.
pub fn drain_once(
    pending: &[PendingHeadV1],
    witness: &dyn Witness,
) -> Vec<(String, Result<WitnessProofV1, WitnessError>)> {
    pending
        .iter()
        .map(|head| {
            let result = decode_head(&head.head_hash)
                .ok_or_else(|| WitnessError::Inconsistent(format!("head_hash is not 32-byte hex: {}", head.head_hash)))
                .and_then(|bytes| witness.submit(&bytes));
            (head.head_hash.clone(), result)
        })
        .collect()
}

fn decode_head(hex_str: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(hex_str).ok()?;
    <[u8; 32]>::try_from(bytes.as_slice()).ok()
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos());
        let dir = std::env::temp_dir().join(format!("corecruxd-witness-proofs-{name}-{nanos}"));
        fs::create_dir_all(&dir).expect("mkdir");
        dir
    }

    fn sample_proof(head: &str) -> WitnessProofV1 {
        WitnessProofV1 {
            transparency_log: "rekor".to_string(),
            log_url: "https://rekor.example".to_string(),
            rekor_uuid: Some(format!("uuid-{head}")),
            leaf_hash: format!("leaf{head}"),
            log_index: 0,
            tree_size: 1,
            root_hash: format!("leaf{head}"),
            inclusion_proof: vec![],
            checkpoint: None,
            integrated_time: "1700000000".to_string(),
            head_hash: String::new(),
            entry_body_b64: String::new(),
        }
    }

    #[test]
    fn enqueue_then_reload_keeps_pending() {
        let dir = temp_dir("pending-survives");
        {
            let mut store = WitnessProofStore::with_persistence(&dir).expect("open");
            assert!(store.enqueue("aa11", Some(7)).expect("enqueue"));
            assert_eq!(store.unwitnessed_count(), 1);
        }
        // Restart: a sealed-but-unwitnessed head must come back pending.
        let store = WitnessProofStore::with_persistence(&dir).expect("reopen");
        assert_eq!(store.unwitnessed_count(), 1, "pending head survives restart");
        assert!(store.is_known("aa11"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn enqueue_is_idempotent() {
        let dir = temp_dir("idempotent");
        let mut store = WitnessProofStore::with_persistence(&dir).expect("open");
        assert!(store.enqueue("bb22", None).expect("first"));
        assert!(
            !store.enqueue("bb22", None).expect("second"),
            "duplicate enqueue is a no-op"
        );
        assert_eq!(store.unwitnessed_count(), 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn witnessing_moves_pending_to_witnessed_and_persists() {
        let dir = temp_dir("witnessed");
        {
            let mut store = WitnessProofStore::with_persistence(&dir).expect("open");
            store.enqueue("cc33", Some(9)).expect("enqueue");
            store.record_witnessed("cc33", sample_proof("cc33")).expect("witness");
            assert_eq!(store.unwitnessed_count(), 0);
            assert_eq!(store.witnessed_proofs().len(), 1);
        }
        let store = WitnessProofStore::with_persistence(&dir).expect("reopen");
        assert_eq!(
            store.unwitnessed_count(),
            0,
            "witnessed head is not pending after restart"
        );
        let witnessed = store.witnessed_proofs();
        assert_eq!(witnessed.len(), 1);
        assert_eq!(witnessed[0].0, "cc33");
        assert_eq!(witnessed[0].1.rekor_uuid.as_deref(), Some("uuid-cc33"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn never_drop_a_head_across_failed_submit_then_retry() {
        let dir = temp_dir("never-drop");
        // Seal enqueues the head; the submit fails so it is never witnessed.
        {
            let mut store = WitnessProofStore::with_persistence(&dir).expect("open");
            store.enqueue("dd44", Some(11)).expect("enqueue");
        }
        // Daemon restarts mid-flight: the head is still pending, retried later.
        {
            let store = WitnessProofStore::with_persistence(&dir).expect("reopen");
            assert_eq!(store.pending_heads().len(), 1);
            assert_eq!(store.pending_heads()[0].head_hash, "dd44");
            assert_eq!(store.pending_heads()[0].segment_seq, Some(11));
        }
        // A later retry succeeds.
        {
            let mut store = WitnessProofStore::with_persistence(&dir).expect("reopen2");
            store.record_witnessed("dd44", sample_proof("dd44")).expect("witness");
            assert_eq!(store.unwitnessed_count(), 0);
        }
        let store = WitnessProofStore::with_persistence(&dir).expect("reopen3");
        assert_eq!(store.unwitnessed_count(), 0);
        assert_eq!(store.witnessed_proofs().len(), 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn reload_skips_malformed_lines() {
        let dir = temp_dir("malformed");
        let path = jsonl_path(&dir);
        fs::write(
            &path,
            b"not json\n{\"kind\":\"pending\",\"head_hash\":\"ee55\",\"segment_seq\":null,\"enqueued_at_unix\":1}\n",
        )
        .expect("seed");
        let store = WitnessProofStore::with_persistence(&dir).expect("reload");
        assert_eq!(store.unwitnessed_count(), 1);
        assert!(store.is_known("ee55"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn in_memory_store_does_not_persist() {
        let mut store = WitnessProofStore::default();
        assert!(store.enqueue("ff66", None).expect("enqueue in-memory"));
        assert_eq!(store.unwitnessed_count(), 1);
    }

    /// A witness that echoes a proof for any head — stands in for Rekor.
    struct OkWitness;
    impl Witness for OkWitness {
        fn submit(&self, head: &[u8; 32]) -> Result<WitnessProofV1, WitnessError> {
            Ok(sample_proof(&hex::encode(head)))
        }
    }

    fn head_hex(byte: u8) -> String {
        hex::encode([byte; 32])
    }

    #[test]
    fn drain_once_witnesses_valid_heads() {
        let pending = vec![
            PendingHeadV1 {
                head_hash: head_hex(0x01),
                segment_seq: Some(1),
                enqueued_at_unix: 0,
            },
            PendingHeadV1 {
                head_hash: head_hex(0x02),
                segment_seq: Some(2),
                enqueued_at_unix: 0,
            },
        ];
        let outcomes = drain_once(&pending, &OkWitness);
        assert_eq!(outcomes.len(), 2);
        assert!(outcomes.iter().all(|(_, r)| r.is_ok()));

        // The Ok proofs feed straight back into the store.
        let mut store = WitnessProofStore::default();
        for head in &pending {
            store
                .enqueue(head.head_hash.clone(), head.segment_seq)
                .expect("enqueue");
        }
        for (head_hash, result) in outcomes {
            store.record_witnessed(head_hash, result.expect("ok")).expect("record");
        }
        assert_eq!(store.unwitnessed_count(), 0);
        assert_eq!(store.witnessed_proofs().len(), 2);
    }

    #[test]
    fn drain_once_flags_malformed_head_without_dropping() {
        let pending = vec![PendingHeadV1 {
            head_hash: "not-hex".to_string(),
            segment_seq: None,
            enqueued_at_unix: 0,
        }];
        let outcomes = drain_once(&pending, &OkWitness);
        assert_eq!(outcomes.len(), 1);
        assert!(matches!(outcomes[0].1, Err(WitnessError::Inconsistent(_))));
    }
}
