// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Session registry trait + in-memory reference implementation.
//!
//! The registry is a hot cache. The authoritative store is the CoreCrux
//! segment log (M2). A cache miss on lookup must be satisfiable by walking
//! the log and rehydrating — the trait is shaped to allow either.
//!
//! Hosted uses a Postgres-backed implementation (M1 TS side). CE uses the
//! in-memory implementation here (sufficient because CoreCrux-segment-log
//! persistence lands in M2).

use std::collections::HashMap;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use crate::plan::{SessionPlan, HASH_LEN};

#[derive(Debug, Clone)]
pub struct RegistryEntry {
    pub session_id: [u8; 16],
    pub principal_id: String,
    pub capability_graph_hash: [u8; HASH_LEN],
    pub plan_receipt_hash: [u8; HASH_LEN],
    pub minted_at: u64,
    pub expires_at: u64,
    pub origin: String,
    pub origin_install: Option<[u8; HASH_LEN]>,
    pub plan_cbor: Vec<u8>,
    pub closed: bool,
    pub close_reason: Option<String>,
}

impl RegistryEntry {
    pub fn from_plan(plan: &SessionPlan, plan_cbor: Vec<u8>) -> Self {
        Self {
            session_id: plan.session_id,
            principal_id: plan.passport.principal_id.clone(),
            capability_graph_hash: plan.capability_graph_hash,
            plan_receipt_hash: plan.receipt.hash,
            minted_at: plan.minted_at,
            expires_at: plan.minted_at + plan.session_ttl_s * 1000,
            origin: plan.origin.clone(),
            origin_install: plan.origin_install,
            plan_cbor,
            closed: false,
            close_reason: None,
        }
    }

    pub fn is_live(&self, now_ms: u64) -> bool {
        !self.closed && now_ms < self.expires_at
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("registry lock poisoned")]
    Poisoned,
    #[error("session not found")]
    NotFound,
    #[error("io error: {0}")]
    Io(String),
}

impl<T> From<PoisonError<T>> for RegistryError {
    fn from(_: PoisonError<T>) -> Self {
        Self::Poisoned
    }
}

pub trait SessionRegistry: Send + Sync {
    fn insert(&self, entry: RegistryEntry) -> Result<(), RegistryError>;
    fn get(&self, session_id: &[u8; 16]) -> Result<Option<RegistryEntry>, RegistryError>;
    fn close(&self, session_id: &[u8; 16], reason: &str) -> Result<(), RegistryError>;
    fn active_count(&self) -> Result<usize, RegistryError>;

    /// Reverse lookup by plan-receipt hash. Used by the invocation
    /// verifier when a receipt references its parent by hash and we need
    /// the full plan (to inspect the capability graph, compare channels,
    /// etc.). Default: linear scan — registries with an index can
    /// override for efficiency.
    fn get_by_plan_hash(
        &self,
        plan_receipt_hash: &[u8; HASH_LEN],
    ) -> Result<Option<RegistryEntry>, RegistryError> {
        // Default impl: the trait has no iteration API without changing
        // its shape. Concrete impls override; the default returns None so
        // a registry without the index fails safe (verifier reports
        // parent-plan-not-found rather than asserting truth).
        let _ = plan_receipt_hash;
        Ok(None)
    }
}

#[derive(Default)]
pub struct InMemoryRegistry {
    inner: Mutex<HashMap<[u8; 16], RegistryEntry>>,
}

impl InMemoryRegistry {
    pub fn new() -> Self {
        Self::default()
    }
}

impl SessionRegistry for InMemoryRegistry {
    fn insert(&self, entry: RegistryEntry) -> Result<(), RegistryError> {
        let mut map = self.inner.lock()?;
        map.insert(entry.session_id, entry);
        Ok(())
    }

    fn get(&self, session_id: &[u8; 16]) -> Result<Option<RegistryEntry>, RegistryError> {
        let map = self.inner.lock()?;
        Ok(map.get(session_id).cloned())
    }

    fn close(&self, session_id: &[u8; 16], reason: &str) -> Result<(), RegistryError> {
        let mut map = self.inner.lock()?;
        let entry = map.get_mut(session_id).ok_or(RegistryError::NotFound)?;
        entry.closed = true;
        entry.close_reason = Some(reason.to_string());
        Ok(())
    }

    fn active_count(&self) -> Result<usize, RegistryError> {
        let map = self.inner.lock()?;
        Ok(map.values().filter(|e| !e.closed).count())
    }

    fn get_by_plan_hash(
        &self,
        plan_receipt_hash: &[u8; HASH_LEN],
    ) -> Result<Option<RegistryEntry>, RegistryError> {
        let map = self.inner.lock()?;
        Ok(map
            .values()
            .find(|e| &e.plan_receipt_hash == plan_receipt_hash)
            .cloned())
    }
}

// ─── File-backed registry (M6) ─────────────────────────────────────────────

/// CE durable registry: one JSON file per session under `{root}/sessions/`.
///
/// The file format is intentionally human-readable — a CE operator can
/// `cat data_dir/sessions/*.json | jq` to inspect live sessions without
/// spinning up a database. Bytes fields are stored as hex strings; the
/// raw canonical-CBOR plan body is hex-encoded too.
///
/// Every mutation writes to a temp file and renames atomically so a
/// crashed write never leaves a half-written row. An in-memory cache
/// mirrors the on-disk state so reads are O(1) after first load.
pub struct FileSessionRegistry {
    root: PathBuf,
    cache: Mutex<HashMap<[u8; 16], RegistryEntry>>,
}

impl FileSessionRegistry {
    pub fn open(data_dir: &Path) -> Result<Self, RegistryError> {
        let root = data_dir.join("sessions");
        fs::create_dir_all(&root)
            .map_err(|e| RegistryError::Io(format!("create sessions dir: {e}")))?;
        let cache = load_all_entries(&root)?;
        Ok(Self {
            root,
            cache: Mutex::new(cache),
        })
    }

    fn path_for(&self, session_id: &[u8; 16]) -> PathBuf {
        self.root.join(format!("{}.json", hex::encode(session_id)))
    }

    fn write_entry(&self, entry: &RegistryEntry) -> Result<(), RegistryError> {
        let path = self.path_for(&entry.session_id);
        let tmp = path.with_extension("json.tmp");
        let wire = wire_from_entry(entry);
        let bytes = serde_json::to_vec_pretty(&wire)
            .map_err(|e| RegistryError::Io(format!("serialise entry: {e}")))?;
        fs::write(&tmp, bytes).map_err(|e| RegistryError::Io(format!("write temp: {e}")))?;
        fs::rename(&tmp, &path).map_err(|e| RegistryError::Io(format!("atomic rename: {e}")))?;
        Ok(())
    }
}

impl SessionRegistry for FileSessionRegistry {
    fn insert(&self, entry: RegistryEntry) -> Result<(), RegistryError> {
        self.write_entry(&entry)?;
        let mut cache = self.cache.lock()?;
        cache.insert(entry.session_id, entry);
        Ok(())
    }

    fn get(&self, session_id: &[u8; 16]) -> Result<Option<RegistryEntry>, RegistryError> {
        let cache = self.cache.lock()?;
        Ok(cache.get(session_id).cloned())
    }

    fn close(&self, session_id: &[u8; 16], reason: &str) -> Result<(), RegistryError> {
        let mut cache = self.cache.lock()?;
        let entry = cache.get_mut(session_id).ok_or(RegistryError::NotFound)?;
        entry.closed = true;
        entry.close_reason = Some(reason.to_string());
        let snapshot = entry.clone();
        drop(cache);
        self.write_entry(&snapshot)?;
        Ok(())
    }

    fn active_count(&self) -> Result<usize, RegistryError> {
        let cache = self.cache.lock()?;
        Ok(cache.values().filter(|e| !e.closed).count())
    }

    fn get_by_plan_hash(
        &self,
        plan_receipt_hash: &[u8; HASH_LEN],
    ) -> Result<Option<RegistryEntry>, RegistryError> {
        let cache = self.cache.lock()?;
        Ok(cache
            .values()
            .find(|e| &e.plan_receipt_hash == plan_receipt_hash)
            .cloned())
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct RegistryEntryWire {
    session_id: String,
    principal_id: String,
    capability_graph_hash: String,
    plan_receipt_hash: String,
    minted_at: u64,
    expires_at: u64,
    origin: String,
    origin_install: Option<String>,
    plan_cbor: String,
    closed: bool,
    close_reason: Option<String>,
}

fn wire_from_entry(entry: &RegistryEntry) -> RegistryEntryWire {
    RegistryEntryWire {
        session_id: hex::encode(entry.session_id),
        principal_id: entry.principal_id.clone(),
        capability_graph_hash: hex::encode(entry.capability_graph_hash),
        plan_receipt_hash: hex::encode(entry.plan_receipt_hash),
        minted_at: entry.minted_at,
        expires_at: entry.expires_at,
        origin: entry.origin.clone(),
        origin_install: entry.origin_install.map(hex::encode),
        plan_cbor: hex::encode(&entry.plan_cbor),
        closed: entry.closed,
        close_reason: entry.close_reason.clone(),
    }
}

fn entry_from_wire(wire: RegistryEntryWire) -> Result<RegistryEntry, RegistryError> {
    fn hex_fixed<const N: usize>(s: &str, field: &str) -> Result<[u8; N], RegistryError> {
        let bytes = hex::decode(s).map_err(|e| RegistryError::Io(format!("{field} hex: {e}")))?;
        if bytes.len() != N {
            return Err(RegistryError::Io(format!(
                "{field} length {} != {}",
                bytes.len(),
                N
            )));
        }
        let mut out = [0u8; N];
        out.copy_from_slice(&bytes);
        Ok(out)
    }

    Ok(RegistryEntry {
        session_id: hex_fixed::<16>(&wire.session_id, "session_id")?,
        principal_id: wire.principal_id,
        capability_graph_hash: hex_fixed::<HASH_LEN>(
            &wire.capability_graph_hash,
            "capability_graph_hash",
        )?,
        plan_receipt_hash: hex_fixed::<HASH_LEN>(&wire.plan_receipt_hash, "plan_receipt_hash")?,
        minted_at: wire.minted_at,
        expires_at: wire.expires_at,
        origin: wire.origin,
        origin_install: wire
            .origin_install
            .map(|s| hex_fixed::<HASH_LEN>(&s, "origin_install"))
            .transpose()?,
        plan_cbor: hex::decode(&wire.plan_cbor)
            .map_err(|e| RegistryError::Io(format!("plan_cbor hex: {e}")))?,
        closed: wire.closed,
        close_reason: wire.close_reason,
    })
}

fn load_all_entries(root: &Path) -> Result<HashMap<[u8; 16], RegistryEntry>, RegistryError> {
    let mut out = HashMap::new();
    let entries = match fs::read_dir(root) {
        Ok(e) => e,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(RegistryError::Io(format!("read_dir: {e}"))),
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                return Err(RegistryError::Io(format!("read {:?}: {e}", path)));
            }
        };
        let wire: RegistryEntryWire = serde_json::from_slice(&bytes)
            .map_err(|e| RegistryError::Io(format!("parse {:?}: {e}", path)))?;
        let parsed = entry_from_wire(wire)?;
        out.insert(parsed.session_id, parsed);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry(session_id: [u8; 16]) -> RegistryEntry {
        RegistryEntry {
            session_id,
            principal_id: "ce:abc:user".into(),
            capability_graph_hash: [0u8; HASH_LEN],
            plan_receipt_hash: [1u8; HASH_LEN],
            minted_at: 1_000,
            expires_at: 5_000_000,
            origin: "ce".into(),
            origin_install: None,
            plan_cbor: vec![0xa0],
            closed: false,
            close_reason: None,
        }
    }

    #[test]
    fn insert_and_get_roundtrip() {
        let reg = InMemoryRegistry::new();
        let entry = sample_entry([1u8; 16]);
        reg.insert(entry.clone()).unwrap();
        let loaded = reg.get(&[1u8; 16]).unwrap().unwrap();
        assert_eq!(loaded.principal_id, "ce:abc:user");
    }

    #[test]
    fn close_marks_entry_inactive() {
        let reg = InMemoryRegistry::new();
        reg.insert(sample_entry([2u8; 16])).unwrap();
        assert_eq!(reg.active_count().unwrap(), 1);
        reg.close(&[2u8; 16], "ttl_expired").unwrap();
        assert_eq!(reg.active_count().unwrap(), 0);
        let loaded = reg.get(&[2u8; 16]).unwrap().unwrap();
        assert!(loaded.closed);
        assert_eq!(loaded.close_reason.as_deref(), Some("ttl_expired"));
    }

    // ─── FileSessionRegistry ──────────────────────────────────────────

    #[test]
    fn file_registry_persists_across_reopens() {
        let tmp = std::env::temp_dir().join(format!("crux-session-file-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&tmp).unwrap();

        let entry = sample_entry([0xAB; 16]);
        {
            let reg = FileSessionRegistry::open(&tmp).unwrap();
            reg.insert(entry.clone()).unwrap();
            reg.close(&[0xAB; 16], "ttl_expired").unwrap();
        }
        // Reopen and verify the state survived.
        let reg = FileSessionRegistry::open(&tmp).unwrap();
        let loaded = reg.get(&[0xAB; 16]).unwrap().expect("persisted");
        assert_eq!(loaded.principal_id, entry.principal_id);
        assert!(loaded.closed);
        assert_eq!(loaded.close_reason.as_deref(), Some("ttl_expired"));
        assert_eq!(reg.active_count().unwrap(), 0);

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn file_registry_get_by_plan_hash_finds_entry() {
        let tmp = std::env::temp_dir().join(format!("crux-session-file-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&tmp).unwrap();

        let reg = FileSessionRegistry::open(&tmp).unwrap();
        let entry = sample_entry([0xCD; 16]);
        let plan_hash = entry.plan_receipt_hash;
        reg.insert(entry).unwrap();

        let found = reg.get_by_plan_hash(&plan_hash).unwrap().expect("found");
        assert_eq!(found.session_id, [0xCD; 16]);

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn file_registry_ignores_malformed_files() {
        let tmp = std::env::temp_dir().join(format!("crux-session-file-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&tmp.join("sessions")).unwrap();
        // Drop a garbage non-json file + a json file with invalid JSON.
        std::fs::write(tmp.join("sessions/README.txt"), b"ignored").unwrap();
        std::fs::write(tmp.join("sessions/bad.json"), b"not json").unwrap();
        let result = FileSessionRegistry::open(&tmp);
        // The bad .json is an error; but README.txt must be skipped. The
        // registry open fails here — documenting the behaviour: partial
        // corruption is a hard error, not silent data loss.
        assert!(result.is_err(), "invalid json should fail open");
        std::fs::remove_dir_all(&tmp).ok();
    }
}
