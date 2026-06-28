// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! In-process relation graph persisted as JSONL.
//!
//! Crux Daemon ships the `corecrux-projections` graph_expand algorithm but no
//! event-driven population path (that lives in the proprietary dataplane). This
//! module gives the open daemon a minimal relation-edge surface so the graph
//! algorithm has something to walk: callers POST edges, the daemon stores them
//! in a `ProjectionState` and appends to `data_dir/relations.jsonl`. The file
//! is replayed on startup so the graph survives container restarts.

#![allow(clippy::type_complexity)] // BTreeMap<(String,String,String), Vec<RelationFact>> is the natural shape; alias would obscure

use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use corecrux_projections::{
    quantize_confidence_q16, tenant_hash_xxhash64, ProjectionState, RelationEdgeV1, RelationTypeV1,
};

#[derive(Debug, thiserror::Error)]
pub enum RelationsError {
    #[error("invalid edge type '{0}'")]
    InvalidEdgeType(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct RelationRecord {
    pub tenant_id: String,
    pub from_id: u32,
    pub to_id: u32,
    pub edge_type: String,
    /// 0..=10000 → divides by 10_000 to get f32 confidence in [0.0, 1.0].
    /// Stored as integer to keep JSONL byte-identical across reads/writes.
    pub confidence_bp: u16,
    pub created_at_micros: i64,
    pub updated_at_micros: i64,
}

impl RelationRecord {
    pub fn confidence_f32(&self) -> f32 {
        (self.confidence_bp as f32 / 10_000.0).clamp(0.0, 1.0)
    }

    fn parse_edge_type(&self) -> Result<RelationTypeV1, RelationsError> {
        RelationTypeV1::from_engine_str(&self.edge_type)
            .ok_or_else(|| RelationsError::InvalidEdgeType(self.edge_type.clone()))
    }

    fn into_edge(self) -> Result<((u64, u32, u32, u8), RelationEdgeV1), RelationsError> {
        let etype = self.parse_edge_type()?;
        let key = (
            tenant_hash_xxhash64(&self.tenant_id),
            self.from_id,
            self.to_id,
            etype.to_u8(),
        );
        let edge = RelationEdgeV1 {
            confidence_q16: quantize_confidence_q16(self.confidence_f32()),
            evidence_ref_hash16: [0u8; 16],
            created_at_micros: self.created_at_micros,
            updated_at_micros: self.updated_at_micros,
        };
        Ok((key, edge))
    }
}

pub fn load_into_state(data_dir: &Path, state: &mut ProjectionState) -> Result<usize, RelationsError> {
    let path = jsonl_path(data_dir);
    if !path.exists() {
        return Ok(0);
    }
    let file = fs::File::open(&path)?;
    let reader = BufReader::new(file);
    let mut count = 0usize;
    for (line_no, line) in reader.lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<RelationRecord>(&line) {
            Ok(record) => match record.into_edge() {
                Ok((key, edge)) => {
                    state.relations.insert(key, edge);
                    count += 1;
                }
                Err(err) => {
                    tracing::warn!(?err, line_no, "skipping unparseable relation edge type during reload");
                }
            },
            Err(err) => {
                tracing::warn!(?err, line_no, "skipping malformed relation record during reload");
            }
        }
    }
    Ok(count)
}

pub fn append_record(data_dir: &Path, record: &RelationRecord) -> Result<(), RelationsError> {
    let path = jsonl_path(data_dir);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
    let mut line = serde_json::to_vec(record)?;
    line.push(b'\n');
    file.write_all(&line)?;
    Ok(())
}

/// Validate + apply a record to the in-memory state. Caller is expected to also
/// `append_record` to persist on success.
pub fn apply_record(state: &mut ProjectionState, record: &RelationRecord) -> Result<(), RelationsError> {
    let (key, edge) = record.clone().into_edge()?;
    state.relations.insert(key, edge);
    Ok(())
}

pub fn list_outgoing(
    state: &ProjectionState,
    tenant_hash: u64,
    from_id: u32,
) -> Vec<((u64, u32, u32, u8), &RelationEdgeV1)> {
    state
        .relations
        .range((tenant_hash, from_id, 0u32, 0u8)..=(tenant_hash, from_id, u32::MAX, u8::MAX))
        .map(|(k, v)| (*k, v))
        .collect()
}

fn jsonl_path(data_dir: &Path) -> PathBuf {
    data_dir.join("relations.jsonl")
}

pub fn supported_edge_types() -> &'static [&'static str] {
    &[
        "supports",
        "contradicts",
        "supersedes",
        "duplicates",
        "elaborates",
        "derived_from",
        "cites",
        "about_same_entity",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Self-cleaning temp dir: the returned [`tempfile::TempDir`] removes itself
    /// on Drop (even on panic), so tests bind it to a guard for their lifetime
    /// instead of leaking a `corecruxd-relations-*` dir into `/tmp` every run.
    /// Prefix retained for debuggability.
    fn temp_dir(name: &str) -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix(&format!("corecruxd-relations-{name}-"))
            .tempdir()
            .expect("mkdir")
    }

    fn sample(tenant: &str, from: u32, to: u32, edge: &str) -> RelationRecord {
        RelationRecord {
            tenant_id: tenant.to_string(),
            from_id: from,
            to_id: to,
            edge_type: edge.to_string(),
            confidence_bp: 9000,
            created_at_micros: 1,
            updated_at_micros: 2,
        }
    }

    #[test]
    fn append_then_reload_round_trip() {
        let tmp = temp_dir("roundtrip");
        let dir = tmp.path().to_path_buf();
        let r1 = sample("alpha", 1, 2, "supports");
        let r2 = sample("alpha", 2, 3, "elaborates");
        append_record(&dir, &r1).expect("append r1");
        append_record(&dir, &r2).expect("append r2");

        let mut state = ProjectionState::default();
        let loaded = load_into_state(&dir, &mut state).expect("reload");
        assert_eq!(loaded, 2);
        assert_eq!(state.relations.len(), 2);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn list_outgoing_filters_by_tenant_and_source() {
        let tmp = temp_dir("listout");
        let dir = tmp.path().to_path_buf();
        let mut state = ProjectionState::default();
        for record in [
            sample("alpha", 1, 2, "supports"),
            sample("alpha", 1, 3, "cites"),
            sample("alpha", 5, 2, "elaborates"),
            sample("beta", 1, 2, "supports"),
        ] {
            apply_record(&mut state, &record).expect("apply");
        }
        let alpha_hash = tenant_hash_xxhash64("alpha");
        let outgoing_from_1 = list_outgoing(&state, alpha_hash, 1);
        assert_eq!(outgoing_from_1.len(), 2, "two outgoing edges from alpha:1");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn invalid_edge_type_rejected_on_apply() {
        let mut state = ProjectionState::default();
        let bad = sample("alpha", 1, 2, "loves");
        let err = apply_record(&mut state, &bad).expect_err("should reject");
        assert!(matches!(err, RelationsError::InvalidEdgeType(_)));
    }

    #[test]
    fn missing_jsonl_returns_zero() {
        let tmp = temp_dir("missing");
        let dir = tmp.path().to_path_buf();
        let mut state = ProjectionState::default();
        let n = load_into_state(&dir, &mut state).expect("load empty");
        assert_eq!(n, 0);
        assert_eq!(state.relations.len(), 0);
    }

    #[test]
    fn reload_skips_malformed_lines_without_failing() {
        let tmp = temp_dir("malformed");
        let dir = tmp.path().to_path_buf();
        let path = dir.join("relations.jsonl");
        fs::write(&path, b"not json\n{\"tenant_id\":\"a\",\"from_id\":1,\"to_id\":2,\"edge_type\":\"supports\",\"confidence_bp\":9000,\"created_at_micros\":1,\"updated_at_micros\":2}\n").expect("seed");
        let mut state = ProjectionState::default();
        let n = load_into_state(&dir, &mut state).expect("reload");
        assert_eq!(n, 1);
        let _ = fs::remove_dir_all(&dir);
    }
}
