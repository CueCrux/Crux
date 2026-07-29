// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

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
use std::io::{BufRead, BufReader, BufWriter, Write};
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
    append_records(data_dir, std::slice::from_ref(record))
}

pub fn append_records(data_dir: &Path, records: &[RelationRecord]) -> Result<(), RelationsError> {
    if records.is_empty() {
        return Ok(());
    }
    let path = jsonl_path(data_dir);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let file = OpenOptions::new().create(true).append(true).open(&path)?;
    let mut writer = BufWriter::new(file);
    for record in records {
        let mut line = serde_json::to_vec(record)?;
        line.push(b'\n');
        writer.write_all(&line)?;
    }
    writer.flush()?;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IncomingCursor {
    pub from_id: u32,
    pub edge_type_u8: u8,
}

impl IncomingCursor {
    pub fn encode(self) -> String {
        format!("{}:{}", self.from_id, self.edge_type_u8)
    }
}

pub fn parse_incoming_cursor(raw: Option<&str>) -> Result<Option<IncomingCursor>, String> {
    let Some(raw) = raw.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let Some((from_id, edge_type_u8)) = raw.split_once(':') else {
        return Err("cursor must be '<from_id>:<edge_type_u8>'".to_string());
    };
    let from_id = from_id
        .parse::<u32>()
        .map_err(|_| "cursor from_id must be a u32".to_string())?;
    let edge_type_u8 = edge_type_u8
        .parse::<u8>()
        .map_err(|_| "cursor edge_type_u8 must be a u8".to_string())?;
    if RelationTypeV1::from_u8(edge_type_u8).is_none() {
        return Err(format!("cursor edge_type_u8 '{edge_type_u8}' is not supported"));
    }
    Ok(Some(IncomingCursor { from_id, edge_type_u8 }))
}

pub struct IncomingPage<'a> {
    pub rows: Vec<((u64, u32, u32, u8), &'a RelationEdgeV1)>,
    pub next_cursor: Option<IncomingCursor>,
}

pub fn list_incoming(
    state: &ProjectionState,
    tenant_hash: u64,
    to_id: u32,
    edge_type: Option<RelationTypeV1>,
    cursor: Option<IncomingCursor>,
    limit: usize,
) -> Vec<((u64, u32, u32, u8), &RelationEdgeV1)> {
    let edge_type_u8 = edge_type.map(RelationTypeV1::to_u8);
    state
        .relations
        .range((tenant_hash, 0u32, 0u32, 0u8)..=(tenant_hash, u32::MAX, u32::MAX, u8::MAX))
        .filter(|((_, from_id, candidate_to_id, candidate_edge_type), _)| {
            let candidate_cursor = (*from_id, *candidate_edge_type);
            *candidate_to_id == to_id
                && cursor.is_none_or(|last| candidate_cursor > (last.from_id, last.edge_type_u8))
                && edge_type_u8.is_none_or(|wanted| *candidate_edge_type == wanted)
        })
        .take(limit)
        .map(|(k, v)| (*k, v))
        .collect()
}

pub fn list_incoming_page(
    state: &ProjectionState,
    tenant_hash: u64,
    to_id: u32,
    edge_type: Option<RelationTypeV1>,
    cursor: Option<IncomingCursor>,
    limit: usize,
) -> IncomingPage<'_> {
    let mut rows = list_incoming(state, tenant_hash, to_id, edge_type, cursor, limit.saturating_add(1));
    let has_more = rows.len() > limit;
    if has_more {
        rows.truncate(limit);
    }
    let next_cursor = if has_more {
        rows.last().map(|((_, from_id, _, edge_type_u8), _)| IncomingCursor {
            from_id: *from_id,
            edge_type_u8: *edge_type_u8,
        })
    } else {
        None
    };
    IncomingPage { rows, next_cursor }
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
        "calls",
        "imports",
        "defines",
        "depends_on",
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
    fn list_incoming_paginates_by_source_id() {
        let mut state = ProjectionState::default();
        for from_id in 1u32..=5 {
            apply_record(&mut state, &sample("alpha", from_id, 99, "depends_on")).expect("apply");
        }
        apply_record(&mut state, &sample("alpha", 6, 99, "calls")).expect("apply calls");
        apply_record(&mut state, &sample("beta", 7, 99, "depends_on")).expect("apply beta");

        let alpha_hash = tenant_hash_xxhash64("alpha");
        let page1 = list_incoming(&state, alpha_hash, 99, Some(RelationTypeV1::DependsOn), None, 2);
        let page1_from_ids: Vec<u32> = page1.iter().map(|((_, from_id, _, _), _)| *from_id).collect();
        assert_eq!(page1_from_ids, vec![1, 2]);

        let page2 = list_incoming(
            &state,
            alpha_hash,
            99,
            Some(RelationTypeV1::DependsOn),
            Some(IncomingCursor {
                from_id: 2,
                edge_type_u8: RelationTypeV1::DependsOn.to_u8(),
            }),
            10,
        );
        let page2_from_ids: Vec<u32> = page2.iter().map(|((_, from_id, _, _), _)| *from_id).collect();
        assert_eq!(page2_from_ids, vec![3, 4, 5]);
    }

    #[test]
    fn list_incoming_cursor_keeps_same_source_different_edge_types() {
        let mut state = ProjectionState::default();
        apply_record(&mut state, &sample("alpha", 5, 99, "calls")).expect("apply calls");
        apply_record(&mut state, &sample("alpha", 5, 99, "depends_on")).expect("apply depends_on");

        let alpha_hash = tenant_hash_xxhash64("alpha");
        let page1 = list_incoming(&state, alpha_hash, 99, None, None, 1);
        assert_eq!(page1.len(), 1);
        let ((_, page1_from_id, _, page1_edge_type), _) = page1[0];
        assert_eq!(page1_from_id, 5);

        let page2 = list_incoming(
            &state,
            alpha_hash,
            99,
            None,
            Some(IncomingCursor {
                from_id: page1_from_id,
                edge_type_u8: page1_edge_type,
            }),
            1,
        );
        assert_eq!(page2.len(), 1);

        let seen: std::collections::BTreeSet<_> = page1
            .into_iter()
            .chain(page2)
            .map(|((_, from_id, _, edge_type), _)| (from_id, edge_type))
            .collect();
        let expected = std::collections::BTreeSet::from([
            (5, RelationTypeV1::Calls.to_u8()),
            (5, RelationTypeV1::DependsOn.to_u8()),
        ]);
        assert_eq!(seen, expected);
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
