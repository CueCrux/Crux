// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Session registry trait + in-memory reference implementation.
//!
//! The registry is a hot cache. The authoritative store is the CoreCrux
//! segment log (M2). A cache miss on lookup must be satisfiable by walking
//! the log and rehydrating — the trait is shaped to allow either.
//!
//! Hosted uses a Postgres-backed implementation (M1 TS side). Crux Daemon
//! uses the in-memory implementation here (sufficient because
//! CoreCrux-segment-log persistence lands in M2).

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

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
    /// Keyed, domain-separated admission identity. Optional so pre-M13 rows
    /// remain readable; raw credential principals are never persisted here.
    pub admission_principal_key: Option<String>,
    /// Keyed, domain-separated effective-client-IP identity.
    pub admission_ip_key: Option<String>,
}

impl RegistryEntry {
    pub fn from_plan(plan: &SessionPlan, plan_cbor: Vec<u8>) -> Self {
        Self {
            session_id: plan.session_id,
            principal_id: plan.passport.principal_id.clone(),
            capability_graph_hash: plan.capability_graph_hash,
            plan_receipt_hash: plan.receipt.hash,
            minted_at: plan.minted_at,
            expires_at: plan.minted_at.saturating_add(plan.session_ttl_s.saturating_mul(1_000)),
            origin: plan.origin.clone(),
            origin_install: plan.origin_install,
            plan_cbor,
            closed: false,
            close_reason: None,
            admission_principal_key: None,
            admission_ip_key: None,
        }
    }

    pub fn is_live(&self, now_ms: u64) -> bool {
        !self.closed && now_ms < self.expires_at
    }

    /// A closed row retains its quota slot until expiry. Otherwise callers
    /// could churn close/create operations to bypass admission bounds.
    pub fn is_retained(&self, now_ms: u64) -> bool {
        now_ms < self.expires_at
    }

    pub fn with_admission_keys(mut self, principal_key: String, ip_key: String) -> Self {
        self.admission_principal_key = Some(principal_key);
        self.admission_ip_key = Some(ip_key);
        self
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
    #[error("{resource} capacity exceeded: limit={limit} current={current} attempted={attempted}")]
    Capacity {
        resource: &'static str,
        limit: u64,
        current: u64,
        attempted: u64,
    },
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
    /// Physically remove rows whose TTL has elapsed. The append-only sealed
    /// event log remains the historical source of truth.
    fn prune_expired(&self, now_ms: u64) -> Result<PruneReport, RegistryError>;
    /// Exact retained-slot and byte usage for linearizable admission checks.
    fn admission_usage(&self, now_ms: u64, principal_key: &str, ip_key: &str) -> Result<AdmissionUsage, RegistryError>;
    /// Bytes this backend would persist for a new row.
    fn entry_storage_bytes(&self, entry: &RegistryEntry) -> Result<u64, RegistryError>;

    /// Reverse lookup by plan-receipt hash. Used by the invocation
    /// verifier when a receipt references its parent by hash and we need
    /// the full plan (to inspect the capability graph, compare channels,
    /// etc.). Default: linear scan — registries with an index can
    /// override for efficiency.
    fn get_by_plan_hash(&self, plan_receipt_hash: &[u8; HASH_LEN]) -> Result<Option<RegistryEntry>, RegistryError> {
        // Default impl: the trait has no iteration API without changing
        // its shape. Concrete impls override; the default returns None so
        // a registry without the index fails safe (verifier reports
        // parent-plan-not-found rather than asserting truth).
        let _ = plan_receipt_hash;
        Ok(None)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PruneReport {
    pub removed: usize,
    pub session_ids: Vec<[u8; 16]>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AdmissionUsage {
    pub retained_total: usize,
    pub retained_for_principal: usize,
    pub retained_for_ip: usize,
    pub next_total_expiry_ms: Option<u64>,
    pub next_principal_expiry_ms: Option<u64>,
    pub next_ip_expiry_ms: Option<u64>,
    pub storage_bytes: u64,
}

pub struct InMemoryRegistry {
    inner: Mutex<HashMap<[u8; 16], RegistryEntry>>,
    max_bytes: u64,
    max_entries: usize,
}

impl Default for InMemoryRegistry {
    fn default() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            max_bytes: u64::MAX,
            max_entries: usize::MAX,
        }
    }
}

impl InMemoryRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn new_bounded(max_bytes: u64) -> Self {
        Self::new_with_limits(max_bytes, usize::MAX)
    }

    pub fn new_with_limits(max_bytes: u64, max_entries: usize) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            max_bytes,
            max_entries,
        }
    }
}

impl SessionRegistry for InMemoryRegistry {
    fn insert(&self, entry: RegistryEntry) -> Result<(), RegistryError> {
        let mut map = self.inner.lock()?;
        if !map.contains_key(&entry.session_id) && map.len() >= self.max_entries {
            return Err(RegistryError::Capacity {
                resource: "session registry entries",
                limit: u64::try_from(self.max_entries).unwrap_or(u64::MAX),
                current: u64::try_from(map.len()).unwrap_or(u64::MAX),
                attempted: 1,
            });
        }
        let current = map_storage_bytes(&map)?;
        let replacing = map
            .get(&entry.session_id)
            .map(entry_serialized_len)
            .transpose()?
            .unwrap_or(0);
        let attempted = entry_serialized_len(&entry)?;
        let projected = current
            .saturating_sub(replacing)
            .checked_add(attempted)
            .unwrap_or(u64::MAX);
        if projected > self.max_bytes {
            return Err(RegistryError::Capacity {
                resource: "session registry",
                limit: self.max_bytes,
                current,
                attempted,
            });
        }
        map.insert(entry.session_id, entry);
        Ok(())
    }

    fn get(&self, session_id: &[u8; 16]) -> Result<Option<RegistryEntry>, RegistryError> {
        let map = self.inner.lock()?;
        Ok(map.get(session_id).cloned())
    }

    fn close(&self, session_id: &[u8; 16], reason: &str) -> Result<(), RegistryError> {
        let mut map = self.inner.lock()?;
        let existing = map.get(session_id).ok_or(RegistryError::NotFound)?;
        let mut updated = existing.clone();
        updated.closed = true;
        updated.close_reason = Some(reason.to_string());
        let current = map_storage_bytes(&map)?;
        let replacing = entry_serialized_len(existing)?;
        let attempted = entry_serialized_len(&updated)?;
        let projected = current
            .saturating_sub(replacing)
            .checked_add(attempted)
            .unwrap_or(u64::MAX);
        if projected > self.max_bytes {
            return Err(RegistryError::Capacity {
                resource: "session registry",
                limit: self.max_bytes,
                current,
                attempted,
            });
        }
        map.insert(*session_id, updated);
        Ok(())
    }

    fn active_count(&self) -> Result<usize, RegistryError> {
        let map = self.inner.lock()?;
        Ok(map.values().filter(|e| !e.closed).count())
    }

    fn prune_expired(&self, now_ms: u64) -> Result<PruneReport, RegistryError> {
        let mut map = self.inner.lock()?;
        let session_ids: Vec<[u8; 16]> = map
            .values()
            .filter(|entry| !entry.is_retained(now_ms))
            .map(|entry| entry.session_id)
            .collect();
        for session_id in &session_ids {
            map.remove(session_id);
        }
        Ok(PruneReport {
            removed: session_ids.len(),
            session_ids,
        })
    }

    fn admission_usage(&self, now_ms: u64, principal_key: &str, ip_key: &str) -> Result<AdmissionUsage, RegistryError> {
        let map = self.inner.lock()?;
        Ok(usage_from_entries(
            map.values(),
            now_ms,
            principal_key,
            ip_key,
            map_storage_bytes(&map)?,
        ))
    }

    fn entry_storage_bytes(&self, entry: &RegistryEntry) -> Result<u64, RegistryError> {
        entry_serialized_len(entry)
    }

    fn get_by_plan_hash(&self, plan_receipt_hash: &[u8; HASH_LEN]) -> Result<Option<RegistryEntry>, RegistryError> {
        let map = self.inner.lock()?;
        Ok(map
            .values()
            .find(|e| &e.plan_receipt_hash == plan_receipt_hash)
            .cloned())
    }
}

// ─── File-backed registry (M6) ─────────────────────────────────────────────

/// Crux Daemon durable registry: one JSON file per session under `{root}/sessions/`.
///
/// The file format is intentionally human-readable — a local operator can
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
    max_bytes: u64,
    max_entries: usize,
}

impl FileSessionRegistry {
    pub fn open(data_dir: &Path) -> Result<Self, RegistryError> {
        Self::open_bounded_at(data_dir, u64::MAX, usize::MAX, 0)
    }

    pub fn open_bounded(data_dir: &Path, max_bytes: u64, max_entries: usize) -> Result<Self, RegistryError> {
        Self::open_bounded_at(data_dir, max_bytes, max_entries, unix_now_ms()?)
    }

    fn open_bounded_at(
        data_dir: &Path,
        max_bytes: u64,
        max_entries: usize,
        now_ms: u64,
    ) -> Result<Self, RegistryError> {
        let root = data_dir.join("sessions");
        fs::create_dir_all(&root).map_err(|e| RegistryError::Io(format!("create sessions dir: {e}")))?;
        remove_stale_temp_files(&root)?;
        let cache = load_all_entries_bounded(&root, max_bytes, max_entries, now_ms)?;
        Ok(Self {
            root,
            cache: Mutex::new(cache),
            max_bytes,
            max_entries,
        })
    }

    fn path_for(&self, session_id: &[u8; 16]) -> PathBuf {
        self.root.join(format!("{}.json", hex::encode(session_id)))
    }

    fn write_entry_bytes(&self, entry: &RegistryEntry, bytes: &[u8]) -> Result<(), RegistryError> {
        let path = self.path_for(&entry.session_id);
        let tmp = path.with_extension("json.tmp");
        if let Err(error) = fs::write(&tmp, bytes) {
            let _ = fs::remove_file(&tmp);
            return Err(RegistryError::Io(format!("write temp: {error}")));
        }
        if let Err(error) = fs::rename(&tmp, &path) {
            let _ = fs::remove_file(&tmp);
            return Err(RegistryError::Io(format!("atomic rename: {error}")));
        }
        Ok(())
    }

    fn storage_bytes_locked(&self, cache: &HashMap<[u8; 16], RegistryEntry>) -> Result<u64, RegistryError> {
        let mut total = 0u64;
        for session_id in cache.keys() {
            let path = self.path_for(session_id);
            let len = fs::metadata(&path)
                .map_err(|e| RegistryError::Io(format!("stat {}: {e}", path.display())))?
                .len();
            total = total.checked_add(len).unwrap_or(u64::MAX);
        }
        Ok(total)
    }
}

impl SessionRegistry for FileSessionRegistry {
    fn insert(&self, entry: RegistryEntry) -> Result<(), RegistryError> {
        let mut cache = self.cache.lock()?;
        if !cache.contains_key(&entry.session_id) && cache.len() >= self.max_entries {
            return Err(RegistryError::Capacity {
                resource: "session registry entries",
                limit: u64::try_from(self.max_entries).unwrap_or(u64::MAX),
                current: u64::try_from(cache.len()).unwrap_or(u64::MAX),
                attempted: 1,
            });
        }
        let bytes = serialize_entry(&entry)?;
        let current = self.storage_bytes_locked(&cache)?;
        let attempted = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        // Atomic replacement needs both the old row and temp file to coexist.
        // Bound peak physical bytes, not only the post-rename projection.
        if current.checked_add(attempted).unwrap_or(u64::MAX) > self.max_bytes {
            return Err(RegistryError::Capacity {
                resource: "session registry",
                limit: self.max_bytes,
                current,
                attempted,
            });
        }
        self.write_entry_bytes(&entry, &bytes)?;
        cache.insert(entry.session_id, entry);
        Ok(())
    }

    fn get(&self, session_id: &[u8; 16]) -> Result<Option<RegistryEntry>, RegistryError> {
        let cache = self.cache.lock()?;
        Ok(cache.get(session_id).cloned())
    }

    fn close(&self, session_id: &[u8; 16], reason: &str) -> Result<(), RegistryError> {
        let mut cache = self.cache.lock()?;
        let existing = cache.get(session_id).ok_or(RegistryError::NotFound)?;
        let mut updated = existing.clone();
        updated.closed = true;
        updated.close_reason = Some(reason.to_string());
        let bytes = serialize_entry(&updated)?;
        let current = self.storage_bytes_locked(&cache)?;
        let attempted = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if current.checked_add(attempted).unwrap_or(u64::MAX) > self.max_bytes {
            return Err(RegistryError::Capacity {
                resource: "session registry",
                limit: self.max_bytes,
                current,
                attempted,
            });
        }
        self.write_entry_bytes(&updated, &bytes)?;
        cache.insert(*session_id, updated);
        Ok(())
    }

    fn active_count(&self) -> Result<usize, RegistryError> {
        let cache = self.cache.lock()?;
        Ok(cache.values().filter(|e| !e.closed).count())
    }

    fn prune_expired(&self, now_ms: u64) -> Result<PruneReport, RegistryError> {
        let mut cache = self.cache.lock()?;
        let session_ids: Vec<[u8; 16]> = cache
            .values()
            .filter(|entry| !entry.is_retained(now_ms))
            .map(|entry| entry.session_id)
            .collect();
        let mut removed = Vec::with_capacity(session_ids.len());
        for session_id in session_ids {
            let path = self.path_for(&session_id);
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(err) if err.kind() == ErrorKind::NotFound => {}
                Err(err) => return Err(RegistryError::Io(format!("remove expired {}: {err}", path.display()))),
            }
            cache.remove(&session_id);
            removed.push(session_id);
        }
        Ok(PruneReport {
            removed: removed.len(),
            session_ids: removed,
        })
    }

    fn admission_usage(&self, now_ms: u64, principal_key: &str, ip_key: &str) -> Result<AdmissionUsage, RegistryError> {
        let cache = self.cache.lock()?;
        Ok(usage_from_entries(
            cache.values(),
            now_ms,
            principal_key,
            ip_key,
            self.storage_bytes_locked(&cache)?,
        ))
    }

    fn entry_storage_bytes(&self, entry: &RegistryEntry) -> Result<u64, RegistryError> {
        entry_serialized_len(entry)
    }

    fn get_by_plan_hash(&self, plan_receipt_hash: &[u8; HASH_LEN]) -> Result<Option<RegistryEntry>, RegistryError> {
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    admission_principal_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    admission_ip_key: Option<String>,
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
        admission_principal_key: entry.admission_principal_key.clone(),
        admission_ip_key: entry.admission_ip_key.clone(),
    }
}

fn serialize_entry(entry: &RegistryEntry) -> Result<Vec<u8>, RegistryError> {
    serde_json::to_vec_pretty(&wire_from_entry(entry)).map_err(|e| RegistryError::Io(format!("serialise entry: {e}")))
}

fn entry_serialized_len(entry: &RegistryEntry) -> Result<u64, RegistryError> {
    Ok(u64::try_from(serialize_entry(entry)?.len()).unwrap_or(u64::MAX))
}

fn map_storage_bytes(map: &HashMap<[u8; 16], RegistryEntry>) -> Result<u64, RegistryError> {
    let mut total = 0u64;
    for entry in map.values() {
        total = total.checked_add(entry_serialized_len(entry)?).unwrap_or(u64::MAX);
    }
    Ok(total)
}

fn usage_from_entries<'a>(
    entries: impl Iterator<Item = &'a RegistryEntry>,
    now_ms: u64,
    principal_key: &str,
    ip_key: &str,
    storage_bytes: u64,
) -> AdmissionUsage {
    let mut usage = AdmissionUsage {
        storage_bytes,
        ..AdmissionUsage::default()
    };
    for entry in entries.filter(|entry| entry.is_retained(now_ms)) {
        usage.retained_total += 1;
        usage.next_total_expiry_ms = Some(
            usage
                .next_total_expiry_ms
                .map_or(entry.expires_at, |value| value.min(entry.expires_at)),
        );
        if entry.admission_principal_key.as_deref() == Some(principal_key) {
            usage.retained_for_principal += 1;
            usage.next_principal_expiry_ms = Some(
                usage
                    .next_principal_expiry_ms
                    .map_or(entry.expires_at, |value| value.min(entry.expires_at)),
            );
        }
        if entry.admission_ip_key.as_deref() == Some(ip_key) {
            usage.retained_for_ip += 1;
            usage.next_ip_expiry_ms = Some(
                usage
                    .next_ip_expiry_ms
                    .map_or(entry.expires_at, |value| value.min(entry.expires_at)),
            );
        }
    }
    usage
}

fn entry_from_wire(wire: RegistryEntryWire) -> Result<RegistryEntry, RegistryError> {
    fn hex_fixed<const N: usize>(s: &str, field: &str) -> Result<[u8; N], RegistryError> {
        let bytes = hex::decode(s).map_err(|e| RegistryError::Io(format!("{field} hex: {e}")))?;
        if bytes.len() != N {
            return Err(RegistryError::Io(format!("{field} length {} != {}", bytes.len(), N)));
        }
        let mut out = [0u8; N];
        out.copy_from_slice(&bytes);
        Ok(out)
    }

    Ok(RegistryEntry {
        session_id: hex_fixed::<16>(&wire.session_id, "session_id")?,
        principal_id: wire.principal_id,
        capability_graph_hash: hex_fixed::<HASH_LEN>(&wire.capability_graph_hash, "capability_graph_hash")?,
        plan_receipt_hash: hex_fixed::<HASH_LEN>(&wire.plan_receipt_hash, "plan_receipt_hash")?,
        minted_at: wire.minted_at,
        expires_at: wire.expires_at,
        origin: wire.origin,
        origin_install: wire
            .origin_install
            .map(|s| hex_fixed::<HASH_LEN>(&s, "origin_install"))
            .transpose()?,
        plan_cbor: hex::decode(&wire.plan_cbor).map_err(|e| RegistryError::Io(format!("plan_cbor hex: {e}")))?,
        closed: wire.closed,
        close_reason: wire.close_reason,
        admission_principal_key: wire.admission_principal_key,
        admission_ip_key: wire.admission_ip_key,
    })
}

fn unix_now_ms() -> Result<u64, RegistryError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| RegistryError::Io(format!("system clock before unix epoch: {error}")))?;
    Ok(u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
}

fn load_all_entries_bounded(
    root: &Path,
    max_bytes: u64,
    max_entries: usize,
    now_ms: u64,
) -> Result<HashMap<[u8; 16], RegistryEntry>, RegistryError> {
    let mut out = HashMap::new();
    let mut retained_bytes = 0u64;
    let entries = match fs::read_dir(root) {
        Ok(e) => e,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(RegistryError::Io(format!("read_dir: {e}"))),
    };
    for entry in entries {
        let entry = entry.map_err(|error| RegistryError::Io(format!("read sessions dir entry: {error}")))?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }

        let file_type = entry
            .file_type()
            .map_err(|error| RegistryError::Io(format!("stat {}: {error}", path.display())))?;
        if !file_type.is_file() {
            return Err(RegistryError::Io(format!(
                "session row is not a regular file: {}",
                path.display()
            )));
        }
        let file_len = entry
            .metadata()
            .map_err(|error| RegistryError::Io(format!("stat {}: {error}", path.display())))?
            .len();
        if file_len > max_bytes {
            return Err(RegistryError::Capacity {
                resource: "session registry",
                limit: max_bytes,
                current: retained_bytes,
                attempted: file_len,
            });
        }
        let capacity = usize::try_from(file_len).map_err(|_| RegistryError::Capacity {
            resource: "session registry",
            limit: max_bytes,
            current: retained_bytes,
            attempted: file_len,
        })?;
        let file = File::open(&path).map_err(|error| RegistryError::Io(format!("read {}: {error}", path.display())))?;
        let mut bytes = Vec::with_capacity(capacity);
        file.take(file_len.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|error| RegistryError::Io(format!("read {}: {error}", path.display())))?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) != file_len {
            return Err(RegistryError::Io(format!(
                "session row changed while reading: {}",
                path.display()
            )));
        }
        let wire: RegistryEntryWire =
            serde_json::from_slice(&bytes).map_err(|e| RegistryError::Io(format!("parse {}: {e}", path.display())))?;
        let parsed = entry_from_wire(wire)?;
        let expected_name = format!("{}.json", hex::encode(parsed.session_id));
        if path.file_name().and_then(|name| name.to_str()) != Some(expected_name.as_str()) {
            return Err(RegistryError::Io(format!(
                "session row filename does not match embedded session_id: {}",
                path.display()
            )));
        }
        if !parsed.is_retained(now_ms) {
            fs::remove_file(&path)
                .map_err(|error| RegistryError::Io(format!("remove expired {}: {error}", path.display())))?;
            continue;
        }
        let projected = retained_bytes.checked_add(file_len).unwrap_or(u64::MAX);
        if projected > max_bytes {
            return Err(RegistryError::Capacity {
                resource: "session registry",
                limit: max_bytes,
                current: retained_bytes,
                attempted: file_len,
            });
        }
        if out.len() >= max_entries {
            return Err(RegistryError::Capacity {
                resource: "session registry entries",
                limit: u64::try_from(max_entries).unwrap_or(u64::MAX),
                current: u64::try_from(out.len()).unwrap_or(u64::MAX),
                attempted: 1,
            });
        }
        if out.insert(parsed.session_id, parsed).is_some() {
            return Err(RegistryError::Io(format!(
                "duplicate session id in registry: {}",
                path.display()
            )));
        }
        retained_bytes = projected;
    }
    Ok(out)
}

fn remove_stale_temp_files(root: &Path) -> Result<(), RegistryError> {
    let entries = fs::read_dir(root).map_err(|e| RegistryError::Io(format!("read sessions dir: {e}")))?;
    for entry in entries {
        let entry = entry.map_err(|e| RegistryError::Io(format!("read sessions dir entry: {e}")))?;
        let path = entry.path();
        let Some(stem) = path
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_suffix(".json.tmp"))
        else {
            continue;
        };
        if stem.len() != 32 || !stem.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            continue;
        }
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => {
                return Err(RegistryError::Io(format!(
                    "remove stale session temp {}: {error}",
                    path.display()
                )));
            }
        }
    }
    Ok(())
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
            admission_principal_key: None,
            admission_ip_key: None,
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

    #[test]
    fn closed_entries_retain_quota_until_expiry_then_prune() {
        let reg = InMemoryRegistry::new();
        let entry = sample_entry([3u8; 16]).with_admission_keys("principal-key".into(), "ip-key".into());
        reg.insert(entry).unwrap();
        reg.close(&[3u8; 16], "client_closed").unwrap();

        let retained = reg.admission_usage(4_999_999, "principal-key", "ip-key").unwrap();
        assert_eq!(retained.retained_total, 1);
        assert_eq!(retained.retained_for_principal, 1);
        assert_eq!(retained.retained_for_ip, 1);

        let report = reg.prune_expired(5_000_000).unwrap();
        assert_eq!(report.session_ids, vec![[3u8; 16]]);
        assert!(reg.get(&[3u8; 16]).unwrap().is_none());
    }

    #[test]
    fn in_memory_registry_capacity_rejects_without_overrun() {
        let entry = sample_entry([4u8; 16]);
        let required = entry_serialized_len(&entry).unwrap();
        let reg = InMemoryRegistry::new_bounded(required.saturating_sub(1));

        assert!(matches!(
            reg.insert(entry),
            Err(RegistryError::Capacity {
                resource: "session registry",
                ..
            })
        ));
        assert_eq!(reg.admission_usage(0, "p", "i").unwrap().storage_bytes, 0);
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
    fn file_registry_loads_legacy_rows_and_counts_them_globally() {
        let tmp = std::env::temp_dir().join(format!("crux-session-file-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&tmp).unwrap();
        {
            let reg = FileSessionRegistry::open(&tmp).unwrap();
            reg.insert(sample_entry([0xCE; 16])).unwrap();
        }

        let reg = FileSessionRegistry::open_bounded_at(&tmp, u64::MAX, usize::MAX, 2_000).unwrap();
        let usage = reg.admission_usage(2_000, "new-principal", "new-ip").unwrap();
        assert_eq!(usage.retained_total, 1);
        assert_eq!(usage.retained_for_principal, 0);
        assert_eq!(usage.retained_for_ip, 0);
        assert!(usage.storage_bytes > 0);

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn file_registry_prune_removes_expired_file_across_reopen() {
        let tmp = std::env::temp_dir().join(format!("crux-session-file-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&tmp).unwrap();
        let session_id = [0xDD; 16];
        let path = tmp.join("sessions").join(format!("{}.json", hex::encode(session_id)));
        let reg = FileSessionRegistry::open(&tmp).unwrap();
        reg.insert(sample_entry(session_id)).unwrap();
        assert!(path.is_file());

        let report = reg.prune_expired(5_000_000).unwrap();
        assert_eq!(report.removed, 1);
        assert!(!path.exists());
        drop(reg);

        let reopened = FileSessionRegistry::open(&tmp).unwrap();
        assert!(reopened.get(&session_id).unwrap().is_none());
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn file_registry_capacity_rejects_without_writing_a_row() {
        let tmp = std::env::temp_dir().join(format!("crux-session-file-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&tmp).unwrap();
        let entry = sample_entry([0xEF; 16]);
        let required = entry_serialized_len(&entry).unwrap();
        let reg = FileSessionRegistry::open_bounded_at(&tmp, required.saturating_sub(1), usize::MAX, 2_000).unwrap();

        assert!(matches!(
            reg.insert(entry),
            Err(RegistryError::Capacity {
                resource: "session registry",
                ..
            })
        ));
        assert_eq!(std::fs::read_dir(tmp.join("sessions")).unwrap().count(), 0);
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn file_registry_open_removes_only_managed_stale_temp_rows() {
        let tmp = std::env::temp_dir().join(format!("crux-session-file-{}", rand::random::<u64>()));
        let sessions = tmp.join("sessions");
        std::fs::create_dir_all(&sessions).unwrap();
        let stale = sessions.join(format!("{}.json.tmp", "ab".repeat(16)));
        let unrelated = sessions.join("operator-notes.json.tmp");
        std::fs::write(&stale, vec![0u8; 2048]).unwrap();
        std::fs::write(&unrelated, b"leave me").unwrap();

        let _registry = FileSessionRegistry::open_bounded_at(&tmp, 1, 0, 2_000).unwrap();
        assert!(!stale.exists());
        assert!(unrelated.exists());
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn file_registry_rejects_preexisting_rows_over_cumulative_byte_cap() {
        let tmp = std::env::temp_dir().join(format!("crux-session-file-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&tmp).unwrap();
        {
            let registry = FileSessionRegistry::open(&tmp).unwrap();
            registry.insert(sample_entry([0x11; 16])).unwrap();
            registry.insert(sample_entry([0x22; 16])).unwrap();
        }
        let sessions = tmp.join("sessions");
        let total = std::fs::read_dir(&sessions)
            .unwrap()
            .map(|entry| entry.unwrap().metadata().unwrap().len())
            .sum::<u64>();

        let result = FileSessionRegistry::open_bounded_at(&tmp, total - 1, usize::MAX, 2_000);
        assert!(matches!(
            result,
            Err(RegistryError::Capacity {
                resource: "session registry",
                ..
            })
        ));
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn file_registry_charges_physical_bytes_and_rejects_before_parsing_oversized_row() {
        let tmp = std::env::temp_dir().join(format!("crux-session-file-{}", rand::random::<u64>()));
        let sessions = tmp.join("sessions");
        std::fs::create_dir_all(&sessions).unwrap();
        let path = sessions.join(format!("{}.json", "00".repeat(16)));
        std::fs::write(&path, vec![b'!'; 128]).unwrap();

        let result = FileSessionRegistry::open_bounded_at(&tmp, 64, usize::MAX, 2_000);
        assert!(matches!(
            result,
            Err(RegistryError::Capacity {
                resource: "session registry",
                limit: 64,
                current: 0,
                attempted: 128,
            })
        ));
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn file_registry_prunes_expired_rows_before_entry_limit_but_retains_closed_rows() {
        let tmp = std::env::temp_dir().join(format!("crux-session-file-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&tmp).unwrap();
        {
            let registry = FileSessionRegistry::open(&tmp).unwrap();
            registry.insert(sample_entry([0x31; 16])).unwrap();
        }
        let pruned = FileSessionRegistry::open_bounded_at(&tmp, u64::MAX, 0, 5_000_000).unwrap();
        assert!(pruned.get(&[0x31; 16]).unwrap().is_none());
        drop(pruned);

        {
            let registry = FileSessionRegistry::open(&tmp).unwrap();
            registry.insert(sample_entry([0x32; 16])).unwrap();
            registry.close(&[0x32; 16], "client_closed").unwrap();
        }
        let retained = FileSessionRegistry::open_bounded_at(&tmp, u64::MAX, 0, 2_000);
        assert!(matches!(
            retained,
            Err(RegistryError::Capacity {
                resource: "session registry entries",
                limit: 0,
                current: 0,
                attempted: 1,
            })
        ));
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn file_registry_rejects_filename_session_id_mismatch() {
        let tmp = std::env::temp_dir().join(format!("crux-session-file-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&tmp).unwrap();
        let original = tmp.join("sessions").join(format!("{}.json", "41".repeat(16)));
        let renamed = tmp.join("sessions").join(format!("{}.json", "42".repeat(16)));
        {
            let registry = FileSessionRegistry::open(&tmp).unwrap();
            registry.insert(sample_entry([0x41; 16])).unwrap();
        }
        std::fs::rename(original, renamed).unwrap();

        let result = FileSessionRegistry::open_bounded_at(&tmp, u64::MAX, usize::MAX, 2_000);
        assert!(matches!(result, Err(RegistryError::Io(message)) if message.contains("filename")));
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn file_registry_ignores_malformed_files() {
        let tmp = std::env::temp_dir().join(format!("crux-session-file-{}", rand::random::<u64>()));
        std::fs::create_dir_all(tmp.join("sessions")).unwrap();
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
