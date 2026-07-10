// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `/v1/admin/control` state — valves (pause-ingest, throttle, read-only, etc.) persisted to `CONTROL.json`.

use std::path::{Path, PathBuf};

use corecrux_types::{
    ControlStateDigestV1, ControlStateMutationV1, ControlValveStateV1, KnowledgeAuthorityChangeV1,
    KnowledgeAuthorityV1, ValveChangeV1,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValveV1 {
    pub enabled: bool,
    pub actor: String,
    pub reason: String,
    #[serde(rename = "updatedAtUnixNs")]
    pub updated_at_unix_ns: u64,
    #[serde(rename = "retryAfterMs", skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u32>,
    // Throttle parameters (only meaningful for the throttle valve).
    #[serde(rename = "eventsPerSec", skip_serializing_if = "Option::is_none")]
    pub events_per_sec: Option<u64>,
    #[serde(rename = "bytesPerSec", skip_serializing_if = "Option::is_none")]
    pub bytes_per_sec: Option<u64>,
    #[serde(rename = "maxInFlight", skip_serializing_if = "Option::is_none")]
    pub max_in_flight: Option<u32>,
}

impl ValveV1 {
    fn disabled() -> Self {
        Self {
            enabled: false,
            actor: String::new(),
            reason: String::new(),
            updated_at_unix_ns: 0,
            retry_after_ms: None,
            events_per_sec: None,
            bytes_per_sec: None,
            max_in_flight: None,
        }
    }

    pub fn set(&mut self, enabled: bool, actor: &str, reason: &str, now_unix_ns: u64) {
        self.enabled = enabled;
        self.actor = actor.to_string();
        self.reason = reason.to_string();
        self.updated_at_unix_ns = now_unix_ns;
    }

    pub fn set_retry_after_ms(&mut self, retry_after_ms: Option<u32>) {
        self.retry_after_ms = retry_after_ms;
    }

    pub fn set_throttle_params(
        &mut self,
        events_per_sec: Option<u64>,
        bytes_per_sec: Option<u64>,
        max_in_flight: Option<u32>,
    ) {
        self.events_per_sec = events_per_sec;
        self.bytes_per_sec = bytes_per_sec;
        self.max_in_flight = max_in_flight;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValvesV1 {
    #[serde(rename = "pauseIngest")]
    pub pause_ingest: ValveV1,
    #[serde(rename = "pauseCompaction")]
    pub pause_compaction: ValveV1,
    pub throttle: ValveV1,
    #[serde(rename = "readOnly")]
    pub read_only: ValveV1,
    #[serde(rename = "emergencyBrake")]
    pub emergency_brake: ValveV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TenantThrottleV1 {
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    #[serde(rename = "eventsPerSec", skip_serializing_if = "Option::is_none")]
    pub events_per_sec: Option<u64>,
    #[serde(rename = "bytesPerSec", skip_serializing_if = "Option::is_none")]
    pub bytes_per_sec: Option<u64>,
    #[serde(rename = "maxInFlight", skip_serializing_if = "Option::is_none")]
    pub max_in_flight: Option<u64>,
}

impl Default for ValvesV1 {
    fn default() -> Self {
        Self {
            pause_ingest: ValveV1::disabled(),
            pause_compaction: ValveV1::disabled(),
            throttle: ValveV1::disabled(),
            read_only: ValveV1::disabled(),
            emergency_brake: ValveV1::disabled(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ControlV1 {
    pub v: u32,
    #[serde(rename = "updatedAtUnixNs")]
    pub updated_at_unix_ns: u64,
    pub valves: ValvesV1,
    #[serde(rename = "tenantThrottles", default, skip_serializing_if = "Vec::is_empty")]
    pub tenant_throttles: Vec<TenantThrottleV1>,
    #[serde(rename = "knowledgeAuthority")]
    pub knowledge_authority: KnowledgeAuthorityV1,
}

impl Default for ControlV1 {
    fn default() -> Self {
        Self {
            v: 1,
            updated_at_unix_ns: 0,
            valves: ValvesV1::default(),
            tenant_throttles: Vec::new(),
            knowledge_authority: KnowledgeAuthorityV1::default(),
        }
    }
}

#[derive(Debug)]
pub struct ControlHandle {
    pub state: ControlV1,
}

impl ControlHandle {
    pub fn load_or_init(path: PathBuf) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let state = if path.exists() {
            let bytes = std::fs::read(&path)?;
            serde_json::from_slice::<ControlV1>(&bytes)?
        } else {
            let s = ControlV1::default();
            write_control_atomic(&path, &s)?;
            s
        };
        Ok(Self { state })
    }
}

pub fn now_unix_ns() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

pub fn checkpoint_control_bytes_v1(state: &ControlV1) -> Vec<u8> {
    serde_json::to_vec_pretty(state).unwrap_or_else(|_| b"{}".to_vec())
}

pub fn write_control_atomic(path: &Path, state: &ControlV1) -> std::io::Result<()> {
    let tmp = path.with_extension("json.tmp");
    let bytes = checkpoint_control_bytes_v1(state);
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)?;
    // Best-effort: establish durability for the parent directory.
    if let Some(parent) = path.parent() {
        #[cfg(unix)]
        {
            if let Ok(dir) = std::fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
    }
    Ok(())
}

pub fn canonical_control_bytes_v1(state: &ControlV1) -> Vec<u8> {
    serde_json::to_vec(state).unwrap_or_default()
}

pub fn control_hash_blake3_hex(state: &ControlV1) -> String {
    blake3::hash(&canonical_control_bytes_v1(state)).to_hex().to_string()
}

pub fn control_state_digest_v1(state: &ControlV1) -> ControlStateDigestV1 {
    ControlStateDigestV1 {
        control_version: state.v,
        updated_at_unix_ns: state.updated_at_unix_ns,
        control_hash_blake3: control_hash_blake3_hex(state),
    }
}

pub fn valve_state_v1(valve: &ValveV1) -> ControlValveStateV1 {
    ControlValveStateV1 {
        enabled: valve.enabled,
        actor: valve.actor.clone(),
        reason: valve.reason.clone(),
        updated_at_unix_ns: valve.updated_at_unix_ns,
        retry_after_ms: valve.retry_after_ms,
        events_per_sec: valve.events_per_sec,
        bytes_per_sec: valve.bytes_per_sec,
        max_in_flight: valve.max_in_flight,
    }
}

pub fn valve_changes_v1(before: &ControlV1, after: &ControlV1) -> Vec<ValveChangeV1> {
    let candidates = [
        ("pause_ingest", &before.valves.pause_ingest, &after.valves.pause_ingest),
        (
            "pause_compaction",
            &before.valves.pause_compaction,
            &after.valves.pause_compaction,
        ),
        ("throttle", &before.valves.throttle, &after.valves.throttle),
        ("read_only", &before.valves.read_only, &after.valves.read_only),
        (
            "emergency_brake",
            &before.valves.emergency_brake,
            &after.valves.emergency_brake,
        ),
    ];

    candidates
        .into_iter()
        .filter_map(|(name, before_valve, after_valve)| {
            if before_valve == after_valve {
                None
            } else {
                Some(ValveChangeV1 {
                    valve: name.to_string(),
                    before: valve_state_v1(before_valve),
                    after: valve_state_v1(after_valve),
                })
            }
        })
        .collect()
}

pub fn knowledge_authority_change_v1(before: &ControlV1, after: &ControlV1) -> Option<KnowledgeAuthorityChangeV1> {
    if before.knowledge_authority == after.knowledge_authority {
        None
    } else {
        Some(KnowledgeAuthorityChangeV1 {
            before: before.knowledge_authority.clone(),
            after: after.knowledge_authority.clone(),
        })
    }
}

fn valve_state_mut<'a>(state: &'a mut ControlV1, valve: &str) -> Result<&'a mut ValveV1, String> {
    match valve {
        "pause_ingest" => Ok(&mut state.valves.pause_ingest),
        "pause_compaction" => Ok(&mut state.valves.pause_compaction),
        "throttle" => Ok(&mut state.valves.throttle),
        "read_only" => Ok(&mut state.valves.read_only),
        "emergency_brake" => Ok(&mut state.valves.emergency_brake),
        other => Err(format!("unknown control valve '{other}'")),
    }
}

fn apply_valve_state_v1(target: &mut ValveV1, value: &ControlValveStateV1) {
    target.enabled = value.enabled;
    target.actor.clone_from(&value.actor);
    target.reason.clone_from(&value.reason);
    target.updated_at_unix_ns = value.updated_at_unix_ns;
    target.retry_after_ms = value.retry_after_ms;
    target.events_per_sec = value.events_per_sec;
    target.bytes_per_sec = value.bytes_per_sec;
    target.max_in_flight = value.max_in_flight;
}

fn apply_knowledge_authority_change_v1(state: &mut ControlV1, change: &KnowledgeAuthorityChangeV1) {
    state.knowledge_authority = change.after.clone();
}

pub fn apply_control_state_mutation_v1(state: &mut ControlV1, mutation: &ControlStateMutationV1) -> Result<(), String> {
    let before = control_state_digest_v1(state);
    if before != mutation.control_before {
        return Err(format!(
            "control mutation before digest mismatch: have {} expected {}",
            before.control_hash_blake3, mutation.control_before.control_hash_blake3
        ));
    }

    for change in &mutation.valve_changes {
        let target = valve_state_mut(state, &change.valve)?;
        apply_valve_state_v1(target, &change.after);
    }
    if let Some(change) = mutation.knowledge_authority_change.as_ref() {
        apply_knowledge_authority_change_v1(state, change);
    }
    state.v = mutation.control_after.control_version;
    state.updated_at_unix_ns = mutation.control_after.updated_at_unix_ns;

    let after = control_state_digest_v1(state);
    if after != mutation.control_after {
        return Err(format!(
            "control mutation after digest mismatch: computed {} expected {}",
            after.control_hash_blake3, mutation.control_after.control_hash_blake3
        ));
    }

    Ok(())
}

#[derive(Debug)]
#[allow(dead_code)] // Fields read by proprietary edition gRPC handlers.
pub struct ValveDecision {
    pub allow_ingest: bool,
    pub ingest_error: Option<(String, u32)>, // (code, retry_after_ms)
    pub allow_compaction: bool,
    pub allow_storage_writes: bool,
}

impl ValveDecision {
    pub fn from_control(c: &ControlV1) -> Self {
        // Precedence: emergency_brake > read_only > pause_ingest > throttle.
        if c.valves.emergency_brake.enabled {
            return Self {
                allow_ingest: false,
                ingest_error: Some(("VALVE_EMERGENCY_BRAKE".to_string(), 0)),
                allow_compaction: false,
                allow_storage_writes: false,
            };
        }
        if c.valves.read_only.enabled {
            return Self {
                allow_ingest: false,
                ingest_error: Some(("VALVE_READ_ONLY".to_string(), 0)),
                allow_compaction: false,
                allow_storage_writes: false,
            };
        }
        if c.valves.pause_ingest.enabled {
            return Self {
                allow_ingest: false,
                ingest_error: Some(("VALVE_PAUSE_INGEST".to_string(), 0)),
                allow_compaction: !c.valves.pause_compaction.enabled,
                allow_storage_writes: true,
            };
        }
        Self {
            allow_ingest: true,
            ingest_error: None,
            allow_compaction: !c.valves.pause_compaction.enabled,
            allow_storage_writes: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use corecrux_types::{
        BuildInfo, ControlStateMutationV1, EvidenceAuthContextV1, EvidenceNodeContextV1, EvidenceRequestContextV1,
    };

    use super::*;

    #[test]
    fn control_digest_is_canonical_and_valve_changes_are_filtered() {
        let before = ControlV1::default();
        let mut after = before.clone();
        after.updated_at_unix_ns = 42;
        after.valves.throttle.set(true, "operator", "maintenance", 42);
        after.valves.throttle.set_retry_after_ms(Some(250));
        after
            .valves
            .throttle
            .set_throttle_params(Some(100), Some(2048), Some(8));

        let digest = control_state_digest_v1(&after);
        assert_eq!(digest.control_version, 1);
        assert_eq!(digest.updated_at_unix_ns, 42);
        assert_eq!(digest.control_hash_blake3.len(), 64);

        let changes = valve_changes_v1(&before, &after);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].valve, "throttle");
        assert_eq!(changes[0].after.events_per_sec, Some(100));
    }

    #[test]
    fn apply_control_state_mutation_updates_state_and_validates_chain() {
        let before = ControlV1::default();
        let mut after = before.clone();
        after.updated_at_unix_ns = 44;
        after.valves.read_only.set(true, "operator", "maintenance", 44);
        after.valves.throttle.set(true, "operator", "maintenance", 44);
        after.valves.throttle.set_throttle_params(Some(12), Some(2048), Some(4));

        let mutation = ControlStateMutationV1 {
            schema: "corecrux.control.state_mutation.v1".to_string(),
            action_id: "act-1".to_string(),
            mutation_type: "set_valves".to_string(),
            applied_at_unix_ms: 1,
            actor: "operator".to_string(),
            reason: "maintenance".to_string(),
            auth: EvidenceAuthContextV1 {
                mode: "dev_scopes".to_string(),
                subject: None,
                tenant_binding: None,
                scopes: vec!["admin:write".to_string()],
            },
            request: EvidenceRequestContextV1::default(),
            node: EvidenceNodeContextV1 {
                node_id: "node-a".to_string(),
                build: BuildInfo {
                    version: "test".to_string(),
                    commit: "test".to_string(),
                },
                http_listen_addr: None,
                grpc_listen_addr: None,
            },
            control_before: control_state_digest_v1(&before),
            control_after: control_state_digest_v1(&after),
            valve_changes: valve_changes_v1(&before, &after),
            knowledge_authority_change: None,
            result: None,
        };

        let mut rebuilt = before.clone();
        apply_control_state_mutation_v1(&mut rebuilt, &mutation).expect("apply mutation");
        assert_eq!(rebuilt, after);
    }

    #[test]
    fn apply_control_state_mutation_rejects_broken_chain() {
        let mut state = ControlV1::default();
        state.updated_at_unix_ns = 7;

        let mutation = ControlStateMutationV1 {
            schema: "corecrux.control.state_mutation.v1".to_string(),
            action_id: "act-2".to_string(),
            mutation_type: "set_valves".to_string(),
            applied_at_unix_ms: 1,
            actor: "operator".to_string(),
            reason: "maintenance".to_string(),
            auth: EvidenceAuthContextV1 {
                mode: "dev_scopes".to_string(),
                subject: None,
                tenant_binding: None,
                scopes: vec!["admin:write".to_string()],
            },
            request: EvidenceRequestContextV1::default(),
            node: EvidenceNodeContextV1 {
                node_id: "node-a".to_string(),
                build: BuildInfo {
                    version: "test".to_string(),
                    commit: "test".to_string(),
                },
                http_listen_addr: None,
                grpc_listen_addr: None,
            },
            control_before: control_state_digest_v1(&ControlV1::default()),
            control_after: control_state_digest_v1(&ControlV1::default()),
            valve_changes: Vec::new(),
            knowledge_authority_change: None,
            result: None,
        };

        let err =
            apply_control_state_mutation_v1(&mut state, &mutation).expect_err("mismatched before digest must fail");
        assert!(err.contains("before digest mismatch"));
    }

    #[test]
    fn load_or_init_creates_default_when_no_file() {
        let dir = std::env::temp_dir().join(format!("corecrux_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("control_new.json");
        let _ = std::fs::remove_file(&path); // ensure clean

        let handle = ControlHandle::load_or_init(path.clone()).expect("load_or_init");
        assert_eq!(handle.state, ControlV1::default());

        // File should have been written
        let bytes = std::fs::read(&path).expect("read file");
        let loaded: ControlV1 = serde_json::from_slice(&bytes).expect("parse");
        assert_eq!(loaded, ControlV1::default());

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn load_or_init_loads_existing_file() {
        let dir = std::env::temp_dir().join(format!("corecrux_test_load_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("control_existing.json");

        let mut state = ControlV1::default();
        state.updated_at_unix_ns = 999;
        state.valves.pause_ingest.set(true, "test", "testing", 999);
        let bytes = serde_json::to_vec_pretty(&state).unwrap();
        std::fs::write(&path, bytes).unwrap();

        let handle = ControlHandle::load_or_init(path.clone()).expect("load_or_init");
        assert_eq!(handle.state.updated_at_unix_ns, 999);
        assert!(handle.state.valves.pause_ingest.enabled);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn write_control_atomic_creates_file_and_removes_tmp() {
        let dir = std::env::temp_dir().join(format!("corecrux_test_atomic_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("control_atomic.json");
        let tmp_path = path.with_extension("json.tmp");

        let state = ControlV1::default();
        write_control_atomic(&path, &state).expect("write");

        assert!(path.exists());
        assert!(!tmp_path.exists(), "tmp file should be renamed away");

        let loaded: ControlV1 = serde_json::from_slice(&std::fs::read(&path).unwrap()).expect("parse");
        assert_eq!(loaded, state);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn checkpoint_control_bytes_v1_produces_valid_json() {
        let state = ControlV1::default();
        let bytes = checkpoint_control_bytes_v1(&state);
        let parsed: ControlV1 = serde_json::from_slice(&bytes).expect("valid json");
        assert_eq!(parsed, state);
    }

    #[test]
    fn canonical_control_bytes_v1_produces_compact_json() {
        let state = ControlV1::default();
        let bytes = canonical_control_bytes_v1(&state);
        let json_str = std::str::from_utf8(&bytes).expect("valid utf8");
        // Canonical (compact) should not contain newlines
        assert!(!json_str.contains('\n'));
        let parsed: ControlV1 = serde_json::from_slice(&bytes).expect("valid json");
        assert_eq!(parsed, state);
    }

    #[test]
    fn control_hash_blake3_hex_is_deterministic() {
        let state = ControlV1::default();
        let h1 = control_hash_blake3_hex(&state);
        let h2 = control_hash_blake3_hex(&state);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // blake3 hex is 64 chars
    }

    #[test]
    fn knowledge_authority_change_v1_none_when_equal() {
        let before = ControlV1::default();
        let after = ControlV1::default();
        assert!(knowledge_authority_change_v1(&before, &after).is_none());
    }

    #[test]
    fn knowledge_authority_change_v1_some_when_changed() {
        let before = ControlV1::default();
        let mut after = before.clone();
        after.knowledge_authority.mode = corecrux_types::KnowledgeAuthorityModeV1::Authoritative;

        let change = knowledge_authority_change_v1(&before, &after);
        assert!(change.is_some());
        let change = change.unwrap();
        assert_eq!(change.before, before.knowledge_authority);
        assert_eq!(change.after, after.knowledge_authority);
    }

    #[test]
    fn valve_changes_v1_returns_empty_when_no_changes() {
        let state = ControlV1::default();
        let changes = valve_changes_v1(&state, &state);
        assert!(changes.is_empty());
    }

    #[test]
    fn valve_changes_v1_detects_all_five_valves() {
        let before = ControlV1::default();
        let mut after = before.clone();
        after.valves.pause_ingest.set(true, "a", "r", 1);
        after.valves.pause_compaction.set(true, "a", "r", 2);
        after.valves.throttle.set(true, "a", "r", 3);
        after.valves.read_only.set(true, "a", "r", 4);
        after.valves.emergency_brake.set(true, "a", "r", 5);

        let changes = valve_changes_v1(&before, &after);
        assert_eq!(changes.len(), 5);
        let names: Vec<&str> = changes.iter().map(|c| c.valve.as_str()).collect();
        assert!(names.contains(&"pause_ingest"));
        assert!(names.contains(&"pause_compaction"));
        assert!(names.contains(&"throttle"));
        assert!(names.contains(&"read_only"));
        assert!(names.contains(&"emergency_brake"));
    }

    #[test]
    fn valve_state_mut_rejects_unknown_valve() {
        let mut state = ControlV1::default();
        let err = valve_state_mut(&mut state, "nonexistent").expect_err("should fail");
        assert!(err.contains("unknown control valve"));
    }

    #[test]
    fn valve_decision_emergency_brake_blocks_everything() {
        let mut c = ControlV1::default();
        c.valves.emergency_brake.set(true, "admin", "fire", 1);
        let d = ValveDecision::from_control(&c);
        assert!(!d.allow_ingest);
        assert!(!d.allow_compaction);
        assert!(!d.allow_storage_writes);
        assert_eq!(
            d.ingest_error.as_ref().map(|(code, _)| code.as_str()),
            Some("VALVE_EMERGENCY_BRAKE")
        );
    }

    #[test]
    fn valve_decision_read_only_blocks_writes() {
        let mut c = ControlV1::default();
        c.valves.read_only.set(true, "admin", "maint", 1);
        let d = ValveDecision::from_control(&c);
        assert!(!d.allow_ingest);
        assert!(!d.allow_compaction);
        assert!(!d.allow_storage_writes);
        assert_eq!(
            d.ingest_error.as_ref().map(|(code, _)| code.as_str()),
            Some("VALVE_READ_ONLY")
        );
    }

    #[test]
    fn valve_decision_pause_ingest_allows_compaction() {
        let mut c = ControlV1::default();
        c.valves.pause_ingest.set(true, "admin", "pause", 1);
        let d = ValveDecision::from_control(&c);
        assert!(!d.allow_ingest);
        assert!(d.allow_compaction);
        assert!(d.allow_storage_writes);
        assert_eq!(
            d.ingest_error.as_ref().map(|(code, _)| code.as_str()),
            Some("VALVE_PAUSE_INGEST")
        );
    }

    #[test]
    fn valve_decision_pause_ingest_plus_compaction() {
        let mut c = ControlV1::default();
        c.valves.pause_ingest.set(true, "admin", "pause", 1);
        c.valves.pause_compaction.set(true, "admin", "pause", 1);
        let d = ValveDecision::from_control(&c);
        assert!(!d.allow_ingest);
        assert!(!d.allow_compaction);
        assert!(d.allow_storage_writes);
    }

    #[test]
    fn valve_decision_default_allows_all() {
        let c = ControlV1::default();
        let d = ValveDecision::from_control(&c);
        assert!(d.allow_ingest);
        assert!(d.allow_compaction);
        assert!(d.allow_storage_writes);
        assert!(d.ingest_error.is_none());
    }

    #[test]
    fn valve_decision_only_compaction_paused() {
        let mut c = ControlV1::default();
        c.valves.pause_compaction.set(true, "admin", "pause", 1);
        let d = ValveDecision::from_control(&c);
        assert!(d.allow_ingest);
        assert!(!d.allow_compaction);
        assert!(d.allow_storage_writes);
        assert!(d.ingest_error.is_none());
    }

    #[test]
    fn valve_v1_set_retry_after_ms() {
        let mut v = ValveV1::disabled();
        assert!(v.retry_after_ms.is_none());
        v.set_retry_after_ms(Some(500));
        assert_eq!(v.retry_after_ms, Some(500));
        v.set_retry_after_ms(None);
        assert!(v.retry_after_ms.is_none());
    }

    #[test]
    fn valve_v1_set_throttle_params() {
        let mut v = ValveV1::disabled();
        v.set_throttle_params(Some(10), Some(1024), Some(4));
        assert_eq!(v.events_per_sec, Some(10));
        assert_eq!(v.bytes_per_sec, Some(1024));
        assert_eq!(v.max_in_flight, Some(4));
    }

    #[test]
    fn now_unix_ns_returns_nonzero() {
        let ns = super::now_unix_ns();
        assert!(ns > 0);
    }

    #[test]
    fn apply_mutation_with_knowledge_authority_change() {
        let before = ControlV1::default();
        let mut after = before.clone();
        after.updated_at_unix_ns = 100;
        after.knowledge_authority.mode = corecrux_types::KnowledgeAuthorityModeV1::Authoritative;

        let mutation = ControlStateMutationV1 {
            schema: "corecrux.control.state_mutation.v1".to_string(),
            action_id: "act-ka".to_string(),
            mutation_type: "set_knowledge_authority".to_string(),
            applied_at_unix_ms: 1,
            actor: "operator".to_string(),
            reason: "promotion".to_string(),
            auth: EvidenceAuthContextV1 {
                mode: "dev_scopes".to_string(),
                subject: None,
                tenant_binding: None,
                scopes: vec!["admin:write".to_string()],
            },
            request: EvidenceRequestContextV1::default(),
            node: EvidenceNodeContextV1 {
                node_id: "node-a".to_string(),
                build: BuildInfo {
                    version: "test".to_string(),
                    commit: "test".to_string(),
                },
                http_listen_addr: None,
                grpc_listen_addr: None,
            },
            control_before: control_state_digest_v1(&before),
            control_after: control_state_digest_v1(&after),
            valve_changes: Vec::new(),
            knowledge_authority_change: knowledge_authority_change_v1(&before, &after),
            result: None,
        };

        let mut rebuilt = before;
        apply_control_state_mutation_v1(&mut rebuilt, &mutation).expect("apply mutation");
        assert_eq!(rebuilt, after);
    }

    #[test]
    fn apply_mutation_rejects_after_digest_mismatch() {
        let before = ControlV1::default();
        let mut after = before.clone();
        after.updated_at_unix_ns = 50;
        after.valves.pause_ingest.set(true, "op", "test", 50);

        // Build a mutation that applies the correct valve changes but claims a
        // different after-digest (from a state with read_only enabled too).
        let mut wrong_after = after.clone();
        wrong_after.valves.read_only.set(true, "op", "extra", 50);

        let mutation = ControlStateMutationV1 {
            schema: "corecrux.control.state_mutation.v1".to_string(),
            action_id: "act-bad".to_string(),
            mutation_type: "set_valves".to_string(),
            applied_at_unix_ms: 1,
            actor: "operator".to_string(),
            reason: "test".to_string(),
            auth: EvidenceAuthContextV1 {
                mode: "dev_scopes".to_string(),
                subject: None,
                tenant_binding: None,
                scopes: vec!["admin:write".to_string()],
            },
            request: EvidenceRequestContextV1::default(),
            node: EvidenceNodeContextV1 {
                node_id: "node-a".to_string(),
                build: BuildInfo {
                    version: "test".to_string(),
                    commit: "test".to_string(),
                },
                http_listen_addr: None,
                grpc_listen_addr: None,
            },
            control_before: control_state_digest_v1(&before),
            // Claim the after-digest is for wrong_after (which has read_only=true)
            // but only supply valve_changes for pause_ingest (not read_only).
            control_after: control_state_digest_v1(&wrong_after),
            valve_changes: valve_changes_v1(&before, &after),
            knowledge_authority_change: None,
            result: None,
        };

        let mut rebuilt = before;
        let err =
            apply_control_state_mutation_v1(&mut rebuilt, &mutation).expect_err("after digest mismatch must fail");
        assert!(err.contains("after digest mismatch"));
    }

    #[test]
    fn apply_mutation_rejects_unknown_valve() {
        let before = ControlV1::default();

        let mutation = ControlStateMutationV1 {
            schema: "corecrux.control.state_mutation.v1".to_string(),
            action_id: "act-unk".to_string(),
            mutation_type: "set_valves".to_string(),
            applied_at_unix_ms: 1,
            actor: "operator".to_string(),
            reason: "test".to_string(),
            auth: EvidenceAuthContextV1 {
                mode: "dev_scopes".to_string(),
                subject: None,
                tenant_binding: None,
                scopes: vec!["admin:write".to_string()],
            },
            request: EvidenceRequestContextV1::default(),
            node: EvidenceNodeContextV1 {
                node_id: "node-a".to_string(),
                build: BuildInfo {
                    version: "test".to_string(),
                    commit: "test".to_string(),
                },
                http_listen_addr: None,
                grpc_listen_addr: None,
            },
            control_before: control_state_digest_v1(&before),
            control_after: control_state_digest_v1(&before), // doesn't matter, will fail before
            valve_changes: vec![corecrux_types::ValveChangeV1 {
                valve: "bogus_valve".to_string(),
                before: valve_state_v1(&ValveV1::disabled()),
                after: valve_state_v1(&ValveV1::disabled()),
            }],
            knowledge_authority_change: None,
            result: None,
        };

        let mut rebuilt = before;
        let err = apply_control_state_mutation_v1(&mut rebuilt, &mutation).expect_err("unknown valve must fail");
        assert!(err.contains("unknown control valve"));
    }

    #[test]
    fn tenant_throttle_serde_roundtrip() {
        let tt = TenantThrottleV1 {
            tenant_id: "t1".to_string(),
            events_per_sec: Some(50),
            bytes_per_sec: None,
            max_in_flight: Some(10),
        };
        let json = serde_json::to_string(&tt).unwrap();
        let parsed: TenantThrottleV1 = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.tenant_id, "t1");
        assert_eq!(parsed.events_per_sec, Some(50));
        assert!(parsed.bytes_per_sec.is_none());
        assert_eq!(parsed.max_in_flight, Some(10));
    }
}
