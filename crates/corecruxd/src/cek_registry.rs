// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Per-subject content-encryption-key (CEK) registry for at-rest crypto-shred
//! erasure (Track E / G3, M5/M6).
//!
//! Each subject (a `Fact.entity`) gets a **random** 256-bit CEK — random, not
//! derived, because a derived key is always re-derivable and therefore could
//! never be destroyed. The CEK is wrapped under a key derived from the
//! daemon-root passport (`crate::encrypted_secrets`) and persisted to
//! `data_dir/cek_registry.jsonl`, replayed at startup. Destroying a subject's
//! CEK removes the wrapped key from the registry; any fact payload sealed under
//! it then becomes cryptographically unrecoverable — that is the crypto-shred.
//!
//! Default OFF: only constructed when `CORECRUXD_FACT_ENCRYPTION=1`. This module
//! is the key store; sealing/opening fact payloads under these CEKs lands with
//! the fact cipher (M5 wiring). The gated forget/destroy-marker flow (M6) calls
//! [`CekRegistry::destroy`].

#![allow(dead_code)] // Wired into the fact write/read path + AppState in the M5 cipher step.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rand::Rng as _;
use serde::{Deserialize, Serialize};

use crate::encrypted_secrets::{self, EncryptedEnvelope};

#[derive(Debug, thiserror::Error)]
pub enum CekRegistryError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("subject {0} CEK was destroyed (crypto-shredded)")]
    Destroyed(String),
}

/// Append-only registry record. Replay folds these into the live key set.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum CekRecordV1 {
    /// A fresh random CEK was minted for a subject, wrapped under the root key.
    Create {
        subject_id: String,
        subject_cek_id: String,
        wrapped_cek: EncryptedEnvelope,
        created_at_unix: i64,
    },
    /// A subject's CEK was destroyed — the wrapped key is dropped from the live
    /// set so its ciphertext can never be opened again.
    Destroy { subject_id: String, destroyed_at_unix: i64 },
}

/// Stable CEK identifier for a subject (entity).
pub fn subject_cek_id(subject: &str) -> String {
    format!("cek:entity:{subject}:v1")
}

/// Subject → random CEK, wrapped at rest under the daemon root key.
#[derive(Debug)]
pub struct CekRegistry {
    journal_path: Option<PathBuf>,
    wrap_key: [u8; 32],
    ceks: BTreeMap<String, [u8; 32]>,
    destroyed: BTreeSet<String>,
}

impl CekRegistry {
    /// Open (or create) the registry under `data_dir`, wrapping CEKs under
    /// `wrap_key` (derive this from the daemon root passport key). Replays
    /// `cek_registry.jsonl`; CEKs that cannot be unwrapped (e.g. the passport
    /// rotated) are skipped, not fatal.
    pub fn with_persistence(data_dir: &Path, wrap_key: [u8; 32]) -> Result<Self, CekRegistryError> {
        fs::create_dir_all(data_dir)?;
        let journal_path = jsonl_path(data_dir);
        let mut registry = Self {
            journal_path: Some(journal_path.clone()),
            wrap_key,
            ceks: BTreeMap::new(),
            destroyed: BTreeSet::new(),
        };
        if journal_path.exists() {
            registry.replay(&journal_path)?;
        }
        Ok(registry)
    }

    /// In-memory registry (no persistence) — for tests and the disabled path.
    pub fn in_memory(wrap_key: [u8; 32]) -> Self {
        Self {
            journal_path: None,
            wrap_key,
            ceks: BTreeMap::new(),
            destroyed: BTreeSet::new(),
        }
    }

    /// The CEK for `subject`, minting + persisting a fresh random one if absent.
    /// Errors if the subject's CEK was destroyed (do not resurrect a shredded
    /// subject under a new key).
    pub fn get_or_create(&mut self, subject: &str) -> Result<[u8; 32], CekRegistryError> {
        if self.destroyed.contains(subject) {
            return Err(CekRegistryError::Destroyed(subject.to_string()));
        }
        if let Some(cek) = self.ceks.get(subject) {
            return Ok(*cek);
        }
        let mut cek = [0u8; 32];
        rand::rng().fill_bytes(&mut cek);
        let wrapped = encrypted_secrets::seal(&cek, &self.wrap_key);
        self.append(&CekRecordV1::Create {
            subject_id: subject.to_string(),
            subject_cek_id: subject_cek_id(subject),
            wrapped_cek: wrapped,
            created_at_unix: now_unix(),
        })?;
        self.ceks.insert(subject.to_string(), cek);
        Ok(cek)
    }

    /// The CEK for `subject` if present and not destroyed (read path; never mints).
    pub fn get(&self, subject: &str) -> Option<[u8; 32]> {
        if self.destroyed.contains(subject) {
            return None;
        }
        self.ceks.get(subject).copied()
    }

    /// Whether the subject's CEK has been destroyed (crypto-shredded).
    pub fn is_destroyed(&self, subject: &str) -> bool {
        self.destroyed.contains(subject)
    }

    /// Destroy the subject's CEK: drop the wrapped key so payloads sealed under
    /// it can never be opened again. Irreversible. Returns `false` if already
    /// destroyed. The gated forget/destroy-marker flow (M6) drives this.
    pub fn destroy(&mut self, subject: &str) -> Result<bool, CekRegistryError> {
        if self.destroyed.contains(subject) {
            return Ok(false);
        }
        self.append(&CekRecordV1::Destroy {
            subject_id: subject.to_string(),
            destroyed_at_unix: now_unix(),
        })?;
        self.ceks.remove(subject);
        self.destroyed.insert(subject.to_string());
        Ok(true)
    }

    fn append(&self, record: &CekRecordV1) -> Result<(), CekRegistryError> {
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

    fn replay(&mut self, path: &Path) -> Result<(), CekRegistryError> {
        let file = fs::File::open(path)?;
        for (line_no, line) in BufReader::new(file).lines().enumerate() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<CekRecordV1>(&line) {
                Ok(CekRecordV1::Create {
                    subject_id,
                    wrapped_cek,
                    ..
                }) => {
                    // A destroy later in the log wins; don't resurrect.
                    if self.destroyed.contains(&subject_id) {
                        continue;
                    }
                    match encrypted_secrets::open(&wrapped_cek, &self.wrap_key) {
                        Ok(bytes) => match <[u8; 32]>::try_from(bytes.as_slice()) {
                            Ok(cek) => {
                                self.ceks.insert(subject_id, cek);
                            }
                            Err(_) => {
                                tracing::warn!(subject = %subject_id, "cek_registry: unwrapped CEK is not 32 bytes; skipping");
                            }
                        },
                        Err(err) => {
                            tracing::warn!(?err, subject = %subject_id, "cek_registry: cannot unwrap CEK (passport rotated?); skipping");
                        }
                    }
                }
                Ok(CekRecordV1::Destroy { subject_id, .. }) => {
                    self.ceks.remove(&subject_id);
                    self.destroyed.insert(subject_id);
                }
                Err(err) => tracing::warn!(?err, line_no, "cek_registry: skipping malformed record during reload"),
            }
        }
        Ok(())
    }
}

fn jsonl_path(data_dir: &Path) -> PathBuf {
    data_dir.join("cek_registry.jsonl")
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
        let dir = std::env::temp_dir().join(format!("corecruxd-cek-{name}-{nanos}"));
        fs::create_dir_all(&dir).expect("mkdir");
        dir
    }

    const WRAP: [u8; 32] = [0x5a; 32];

    #[test]
    fn cek_is_stable_and_survives_reload() {
        let dir = temp_dir("stable");
        let cek = {
            let mut reg = CekRegistry::with_persistence(&dir, WRAP).expect("open");
            let a = reg.get_or_create("person:alice").expect("mint");
            let b = reg.get_or_create("person:alice").expect("same");
            assert_eq!(a, b, "same subject -> same CEK");
            a
        };
        // Reload: the wrapped CEK unwraps to the same key.
        let reg = CekRegistry::with_persistence(&dir, WRAP).expect("reopen");
        assert_eq!(reg.get("person:alice"), Some(cek), "CEK survives restart");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn destroy_makes_the_cek_unrecoverable_across_reload() {
        let dir = temp_dir("destroy");
        let cek;
        {
            let mut reg = CekRegistry::with_persistence(&dir, WRAP).expect("open");
            cek = reg.get_or_create("person:bob").expect("mint");
            assert!(reg.destroy("person:bob").expect("destroy"));
            assert!(reg.get("person:bob").is_none());
            assert!(reg.is_destroyed("person:bob"));
            // Cannot resurrect under a new key.
            assert!(matches!(
                reg.get_or_create("person:bob"),
                Err(CekRegistryError::Destroyed(_))
            ));
        }
        // Reload: still destroyed; the CEK is gone for good.
        let reg = CekRegistry::with_persistence(&dir, WRAP).expect("reopen");
        assert!(reg.is_destroyed("person:bob"));
        assert!(reg.get("person:bob").is_none());

        // The crypto-shred property: a payload sealed under the old CEK cannot be
        // opened, because the key no longer exists anywhere.
        use corecrux_receipts::{open_crypto_shred_payload_v1, seal_crypto_shred_payload_v1, CryptoShredSealInputV1};
        let env = seal_crypto_shred_payload_v1(
            &CryptoShredSealInputV1 {
                tenant_id: "t",
                subject_type: "entity",
                subject_id: "person:bob",
                subject_cek_id: &subject_cek_id("person:bob"),
                created_at: "2026-06-24T00:00:00Z",
            },
            b"bob's private data",
            &cek,
            &[1u8; 24],
        )
        .expect("seal");
        assert!(
            reg.get("person:bob").is_none(),
            "no CEK available to open the retained ciphertext"
        );
        // (With the right CEK it would open — proving destruction, not corruption.)
        assert_eq!(
            open_crypto_shred_payload_v1(&env, &cek).expect("control"),
            b"bob's private data"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn wrong_wrap_key_skips_cek_on_reload() {
        let dir = temp_dir("rotated");
        {
            let mut reg = CekRegistry::with_persistence(&dir, WRAP).expect("open");
            reg.get_or_create("person:carol").expect("mint");
        }
        // Simulate a rotated passport: a different wrap key cannot unwrap the CEK.
        let reg = CekRegistry::with_persistence(&dir, [0x11; 32]).expect("reopen");
        assert!(reg.get("person:carol").is_none(), "rotated wrap key -> CEK skipped");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn in_memory_does_not_persist() {
        let mut reg = CekRegistry::in_memory(WRAP);
        let a = reg.get_or_create("x").expect("mint");
        assert_eq!(reg.get("x"), Some(a));
    }
}
