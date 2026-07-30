// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Pluggable session-event sealer (master-plan §7 "Always-Store").
//!
//! The handshake pipeline calls `PlanSealer::seal_plan(...)` BEFORE writing
//! to the registry. If the seal fails, the handshake fails closed — the
//! registry is never polluted with rows that have no durable event.
//!
//! M2 ships two implementations:
//!
//! - [`NoopSealer`]: used by existing tests and for backwards compatibility
//!   during rollout. Silently succeeds; the "always-store" property is not
//!   enforced. Disabled behind the default; production paths must wire a
//!   real sealer.
//! - [`InMemorySealer`]: records every sealed event in a `Vec`. Used by
//!   M2 integration tests and by local-daemon installs running without a full
//!   CoreCrux dataplane. Rebuildable on startup by replaying the Vec.
//!
//! A `DataplaneSealer` that calls `http_dataplane::append_batch(...)`
//! lands as follow-up work inside M2/M3; the trait below is what it will
//! implement.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use crate::error::SessionError;

/// Serialized sealed event. The encoding is binary per
/// `corecrux-projections::events::SessionPlanSealedV1::encode_bin()`.
#[derive(Debug, Clone)]
pub struct SealedEvent {
    pub event_type: &'static str,
    pub content_type: &'static str,
    pub tenant_id: String,
    pub stream_type: String,
    pub stream_id: String,
    pub payload: Vec<u8>,
}

pub trait PlanSealer: Send + Sync {
    /// Append the event to the durable log. Must not return `Ok(())` until
    /// the event is safely on disk (or otherwise durable). The caller only
    /// writes to the session registry after this returns successfully.
    fn seal(&self, event: &SealedEvent) -> Result<(), SessionError>;
    /// Bytes currently retained by this backend.
    fn storage_bytes(&self) -> Result<u64, SessionError>;
    /// Bytes this backend would add for `event`.
    fn event_storage_bytes(&self, event: &SealedEvent) -> Result<u64, SessionError>;
}

/// Does nothing. Used only in legacy paths until the always-store rule is
/// enforced everywhere.
#[derive(Debug, Default, Clone)]
pub struct NoopSealer;

impl PlanSealer for NoopSealer {
    fn seal(&self, _event: &SealedEvent) -> Result<(), SessionError> {
        Ok(())
    }

    fn storage_bytes(&self) -> Result<u64, SessionError> {
        Ok(0)
    }

    fn event_storage_bytes(&self, _event: &SealedEvent) -> Result<u64, SessionError> {
        Ok(0)
    }
}

/// Records every sealed event in a `Vec<SealedEvent>`. Thread-safe.
pub struct InMemorySealer {
    events: Mutex<Vec<SealedEvent>>,
    max_bytes: u64,
}

impl Default for InMemorySealer {
    fn default() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
            max_bytes: u64::MAX,
        }
    }
}

impl InMemorySealer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn new_bounded(max_bytes: u64) -> Self {
        Self {
            events: Mutex::new(Vec::new()),
            max_bytes,
        }
    }

    /// Snapshot of all events ever sealed into this instance, in order.
    pub fn events(&self) -> Result<Vec<SealedEvent>, SessionError> {
        let guard = self
            .events
            .lock()
            .map_err(|_: PoisonError<_>| SessionError::Encode("sealer mutex poisoned".into()))?;
        Ok(guard.clone())
    }

    pub fn len(&self) -> usize {
        self.events.lock().map(|g| g.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl PlanSealer for InMemorySealer {
    fn seal(&self, event: &SealedEvent) -> Result<(), SessionError> {
        let mut guard = self
            .events
            .lock()
            .map_err(|_: PoisonError<_>| SessionError::Encode("sealer mutex poisoned".into()))?;
        let current = events_storage_bytes(&guard);
        let attempted = in_memory_event_bytes(event);
        if current.checked_add(attempted).unwrap_or(u64::MAX) > self.max_bytes {
            return Err(SessionError::Capacity {
                resource: "session event log",
                limit: self.max_bytes,
                current,
                attempted,
            });
        }
        guard.push(event.clone());
        Ok(())
    }

    fn storage_bytes(&self) -> Result<u64, SessionError> {
        let guard = self
            .events
            .lock()
            .map_err(|_: PoisonError<_>| SessionError::Encode("sealer mutex poisoned".into()))?;
        Ok(events_storage_bytes(&guard))
    }

    fn event_storage_bytes(&self, event: &SealedEvent) -> Result<u64, SessionError> {
        Ok(in_memory_event_bytes(event))
    }
}

fn in_memory_event_bytes(event: &SealedEvent) -> u64 {
    [
        event.event_type.len(),
        event.content_type.len(),
        event.tenant_id.len(),
        event.stream_type.len(),
        event.stream_id.len(),
        event.payload.len(),
    ]
    .into_iter()
    .fold(0u64, |total, len| {
        total.saturating_add(u64::try_from(len).unwrap_or(u64::MAX))
    })
}

fn events_storage_bytes(events: &[SealedEvent]) -> u64 {
    events
        .iter()
        .fold(0u64, |total, event| total.saturating_add(in_memory_event_bytes(event)))
}

// ─── FileSealer (M6): durable append-only event log on disk ──────────────
//
// Writes each sealed event as one JSON line in
// `{data_dir}/session-events.jsonl`. This is the local-daemon stand-in for
// the full CoreCrux segment log; the wire format is looser (JSON vs the
// binary `SessionPlanSealedV1::encode_bin`) but the durability and
// append-only semantics are identical. Rebuilding the projection after
// a crash is a one-pass scan of the file.

/// Crux Daemon durable sealer: appends one JSON line per sealed event.
pub struct FileSealer {
    path: PathBuf,
    max_bytes: u64,
    /// Protects concurrent appenders. Each `seal` opens the file,
    /// appends, fsyncs, and closes — coarse but adequate at local-daemon scale
    /// (hundreds of events per session, not millions).
    write_lock: Mutex<()>,
}

impl FileSealer {
    pub fn open(data_dir: &Path) -> Result<Self, SessionError> {
        Self::open_bounded(data_dir, u64::MAX)
    }

    pub fn open_bounded(data_dir: &Path, max_bytes: u64) -> Result<Self, SessionError> {
        fs::create_dir_all(data_dir).map_err(|e| SessionError::Encode(format!("create data_dir: {e}")))?;
        let path = data_dir.join("session-events.jsonl");
        let current = match fs::metadata(&path) {
            Ok(metadata) => metadata.len(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
            Err(error) => return Err(SessionError::Encode(format!("stat event log: {error}"))),
        };
        if current > max_bytes {
            return Err(SessionError::Capacity {
                resource: "session event log",
                limit: max_bytes,
                current,
                attempted: 0,
            });
        }
        Ok(Self {
            path,
            max_bytes,
            write_lock: Mutex::new(()),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Read every sealed event from the log in order. Used for projection
    /// rebuild / operator introspection. Returns a `StoredEvent` rather
    /// than `SealedEvent` because the on-disk `event_type` has no way to
    /// re-acquire the original `&'static str` lifetime.
    pub fn read_all(&self) -> Result<Vec<StoredEvent>, SessionError> {
        let content = match fs::read_to_string(&self.path) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
            Err(e) => return Err(SessionError::Encode(format!("read events file: {e}"))),
        };
        let mut out = Vec::new();
        for (i, line) in content.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let wire: SealedEventWire = serde_json::from_str(line)
                .map_err(|e| SessionError::Decode(format!("line {} of events log: {e}", i + 1)))?;
            out.push(StoredEvent {
                event_type: wire.event_type,
                content_type: wire.content_type,
                tenant_id: wire.tenant_id,
                stream_type: wire.stream_type,
                stream_id: wire.stream_id,
                payload: hex::decode(&wire.payload_hex)
                    .map_err(|e| SessionError::Decode(format!("payload hex: {e}")))?,
            });
        }
        Ok(out)
    }
}

/// An event read back from the durable log. Same shape as
/// [`SealedEvent`] but with owned `event_type` / `content_type` since
/// those came from JSON rather than a static catalogue.
#[derive(Debug, Clone)]
pub struct StoredEvent {
    pub event_type: String,
    pub content_type: String,
    pub tenant_id: String,
    pub stream_type: String,
    pub stream_id: String,
    pub payload: Vec<u8>,
}

impl PlanSealer for FileSealer {
    fn seal(&self, event: &SealedEvent) -> Result<(), SessionError> {
        let line = encode_event_line(event)?;
        let _guard = self
            .write_lock
            .lock()
            .map_err(|_: PoisonError<_>| SessionError::Encode("sealer write-lock poisoned".into()))?;
        let current = file_len_or_zero(&self.path)?;
        let attempted = u64::try_from(line.len()).unwrap_or(u64::MAX).saturating_add(1);
        if current.checked_add(attempted).unwrap_or(u64::MAX) > self.max_bytes {
            return Err(SessionError::Capacity {
                resource: "session event log",
                limit: self.max_bytes,
                current,
                attempted,
            });
        }
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| SessionError::Encode(format!("open events file: {e}")))?;
        writeln!(f, "{line}").map_err(|e| SessionError::Encode(format!("write event: {e}")))?;
        f.sync_all()
            .map_err(|e| SessionError::Encode(format!("fsync events file: {e}")))?;
        Ok(())
    }

    fn storage_bytes(&self) -> Result<u64, SessionError> {
        let _guard = self
            .write_lock
            .lock()
            .map_err(|_: PoisonError<_>| SessionError::Encode("sealer write-lock poisoned".into()))?;
        file_len_or_zero(&self.path)
    }

    fn event_storage_bytes(&self, event: &SealedEvent) -> Result<u64, SessionError> {
        Ok(u64::try_from(encode_event_line(event)?.len())
            .unwrap_or(u64::MAX)
            .saturating_add(1))
    }
}

fn encode_event_line(event: &SealedEvent) -> Result<String, SessionError> {
    let wire = SealedEventWire {
        event_type: event.event_type.to_string(),
        content_type: event.content_type.to_string(),
        tenant_id: event.tenant_id.clone(),
        stream_type: event.stream_type.clone(),
        stream_id: event.stream_id.clone(),
        payload_hex: hex::encode(&event.payload),
    };
    serde_json::to_string(&wire).map_err(|e| SessionError::Encode(format!("serialise event: {e}")))
}

fn file_len_or_zero(path: &Path) -> Result<u64, SessionError> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(metadata.len()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(err) => Err(SessionError::Encode(format!("stat {}: {err}", path.display()))),
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SealedEventWire {
    event_type: String,
    content_type: String,
    tenant_id: String,
    stream_type: String,
    stream_id: String,
    payload_hex: String,
}

/// A sealer that always returns an error. Used to test the fail-closed
/// handshake semantics — segment seal fails → handshake rejects.
#[derive(Debug, Default, Clone)]
pub struct FailingSealer;

impl PlanSealer for FailingSealer {
    fn seal(&self, _event: &SealedEvent) -> Result<(), SessionError> {
        Err(SessionError::Encode("segment seal forced to fail".into()))
    }

    fn storage_bytes(&self) -> Result<u64, SessionError> {
        Ok(0)
    }

    fn event_storage_bytes(&self, event: &SealedEvent) -> Result<u64, SessionError> {
        Ok(in_memory_event_bytes(event))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event() -> SealedEvent {
        SealedEvent {
            event_type: "corecrux.session.plan_sealed.v1",
            content_type: "application/x-corecrux-session-bin-v1",
            tenant_id: "ce".into(),
            stream_type: "session-plans".into(),
            stream_id: "ce:abc12345:tester".into(),
            payload: vec![0xAA, 0xBB, 0xCC],
        }
    }

    #[test]
    fn in_memory_sealer_records_events_in_order() {
        let sealer = InMemorySealer::new();
        for _ in 0..10 {
            sealer.seal(&sample_event()).unwrap();
        }
        assert_eq!(sealer.len(), 10);
        let all = sealer.events().unwrap();
        assert!(all.iter().all(|e| e.event_type == "corecrux.session.plan_sealed.v1"));
    }

    #[test]
    fn in_memory_sealer_capacity_is_hard_and_non_overrunning() {
        let event = sample_event();
        let attempted = in_memory_event_bytes(&event);
        let sealer = InMemorySealer::new_bounded(attempted);
        sealer.seal(&event).unwrap();

        assert!(matches!(
            sealer.seal(&event),
            Err(SessionError::Capacity {
                resource: "session event log",
                ..
            })
        ));
        assert_eq!(sealer.storage_bytes().unwrap(), attempted);
        assert_eq!(sealer.len(), 1);
    }

    #[test]
    fn failing_sealer_returns_error() {
        let sealer = FailingSealer;
        assert!(sealer.seal(&sample_event()).is_err());
    }

    #[test]
    fn noop_sealer_succeeds() {
        let sealer = NoopSealer;
        assert!(sealer.seal(&sample_event()).is_ok());
    }

    #[test]
    fn file_sealer_appends_and_read_all_roundtrips() {
        let tmp = std::env::temp_dir().join(format!("crux-session-sealer-{}", rand::random::<u64>()));
        let sealer = FileSealer::open(&tmp).unwrap();
        for _ in 0..5 {
            sealer.seal(&sample_event()).unwrap();
        }
        let events = sealer.read_all().unwrap();
        assert_eq!(events.len(), 5);
        assert!(events.iter().all(|e| e.event_type == "corecrux.session.plan_sealed.v1"));
        assert_eq!(events[0].payload, vec![0xAA, 0xBB, 0xCC]);
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn file_sealer_read_all_is_empty_when_file_missing() {
        let tmp = std::env::temp_dir().join(format!("crux-session-sealer-{}", rand::random::<u64>()));
        let sealer = FileSealer::open(&tmp).unwrap();
        // Don't seal anything; read_all should return an empty Vec, not error.
        let events = sealer.read_all().unwrap();
        assert!(events.is_empty());
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn file_sealer_survives_reopen() {
        let tmp = std::env::temp_dir().join(format!("crux-session-sealer-{}", rand::random::<u64>()));
        {
            let sealer = FileSealer::open(&tmp).unwrap();
            for _ in 0..3 {
                sealer.seal(&sample_event()).unwrap();
            }
        }
        // Reopen and verify events are still there.
        let sealer = FileSealer::open(&tmp).unwrap();
        sealer.seal(&sample_event()).unwrap();
        let events = sealer.read_all().unwrap();
        assert_eq!(events.len(), 4);
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn file_sealer_capacity_is_hard_and_non_overrunning() {
        let tmp = std::env::temp_dir().join(format!("crux-session-sealer-{}", rand::random::<u64>()));
        let event = sample_event();
        let sizing = FileSealer::open(&tmp).unwrap();
        let attempted = sizing.event_storage_bytes(&event).unwrap();
        drop(sizing);

        let sealer = FileSealer::open_bounded(&tmp, attempted).unwrap();
        sealer.seal(&event).unwrap();
        assert!(matches!(
            sealer.seal(&event),
            Err(SessionError::Capacity {
                resource: "session event log",
                ..
            })
        ));
        assert_eq!(sealer.storage_bytes().unwrap(), attempted);
        assert_eq!(sealer.read_all().unwrap().len(), 1);
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn file_sealer_rejects_preexisting_log_over_cap() {
        let tmp = std::env::temp_dir().join(format!("crux-session-sealer-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("session-events.jsonl"), b"already too large").unwrap();

        let result = FileSealer::open_bounded(&tmp, 4);
        assert!(matches!(
            result,
            Err(SessionError::Capacity {
                resource: "session event log",
                limit: 4,
                current: 17,
                attempted: 0,
            })
        ));
        std::fs::remove_dir_all(&tmp).ok();
    }
}
