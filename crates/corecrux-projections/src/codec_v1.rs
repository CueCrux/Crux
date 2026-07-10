// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! v1 binary codecs for living-row, hot-pointer, relations, dependents, and pressure-row blocks inside `.ccxs` companions.

// SAFETY: All .try_into().unwrap() in decode functions below operate on fixed-size
// sub-slices carved from chunks_exact(STRIDE). The slice lengths are compile-time
// constants that match the target array size, so the conversion is infallible.
#![allow(clippy::unwrap_used)]
use std::collections::BTreeMap;

use crate::state::{DependentEdgeV1, LivingStateRowV1, PressureEventRowV1, RelationEdgeV1};
use crate::{ProjectionError, Result};

pub const LIVING_ROW_STRIDE_V1: usize = 64;
pub const RELATION_EDGE_STRIDE_V1: usize = 64;
pub const DEPENDENT_EDGE_STRIDE_V1: usize = 64;
pub const PRESSURE_ROW_STRIDE_V1: usize = 96;
pub const HOT_PTR_ENTRY_STRIDE_V1: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HotPtrEntryV1 {
    pub edge_count: u32,
    pub block_len: u32,
    pub codec: u32,
    pub blake3: [u8; 32],
}

pub fn encode_hot_ptrs_v1(ptrs: &BTreeMap<(u64, u32), HotPtrEntryV1>) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(ptrs.len() * HOT_PTR_ENTRY_STRIDE_V1);
    for ((tenant_hash, artifact_id), p) in ptrs {
        let mut rec = [0u8; HOT_PTR_ENTRY_STRIDE_V1];
        rec[0..8].copy_from_slice(&tenant_hash.to_le_bytes());
        rec[8..12].copy_from_slice(&artifact_id.to_le_bytes());
        rec[12..16].copy_from_slice(&p.edge_count.to_le_bytes());
        rec[16..20].copy_from_slice(&p.block_len.to_le_bytes());
        rec[20..24].copy_from_slice(&p.codec.to_le_bytes());
        rec[24..56].copy_from_slice(&p.blake3);
        out.extend_from_slice(&rec);
    }
    out
}

pub fn decode_hot_ptrs_v1(input: &[u8]) -> Result<BTreeMap<(u64, u32), HotPtrEntryV1>> {
    if !input.len().is_multiple_of(HOT_PTR_ENTRY_STRIDE_V1) {
        return Err(ProjectionError::InvalidEvent {
            msg: "hot ptr snapshot block length is not a multiple of entry stride".to_string(),
        });
    }
    let mut out: BTreeMap<(u64, u32), HotPtrEntryV1> = BTreeMap::new();
    for chunk in input.chunks_exact(HOT_PTR_ENTRY_STRIDE_V1) {
        let tenant_hash = u64::from_le_bytes(chunk[0..8].try_into().unwrap());
        let artifact_id = u32::from_le_bytes(chunk[8..12].try_into().unwrap());
        let edge_count = u32::from_le_bytes(chunk[12..16].try_into().unwrap());
        let block_len = u32::from_le_bytes(chunk[16..20].try_into().unwrap());
        let codec = u32::from_le_bytes(chunk[20..24].try_into().unwrap());
        if codec != 0 {
            return Err(ProjectionError::InvalidEvent {
                msg: format!("unsupported hot ptr codec {}", codec),
            });
        }
        let mut blake3 = [0u8; 32];
        blake3.copy_from_slice(&chunk[24..56]);
        out.insert(
            (tenant_hash, artifact_id),
            HotPtrEntryV1 {
                edge_count,
                block_len,
                codec,
                blake3,
            },
        );
    }
    Ok(out)
}

pub fn encode_living_rows_v1(rows: &BTreeMap<(u64, u32), LivingStateRowV1>) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(rows.len() * LIVING_ROW_STRIDE_V1);
    for ((tenant_hash, artifact_id), row) in rows {
        let mut rec = [0u8; LIVING_ROW_STRIDE_V1];
        rec[0..8].copy_from_slice(&tenant_hash.to_le_bytes());
        rec[8..12].copy_from_slice(&artifact_id.to_le_bytes());
        rec[12] = row.living_status.to_u8();
        rec[13..15].copy_from_slice(&row.confidence_q16.to_le_bytes());
        rec[15..23].copy_from_slice(&row.last_validated_at_micros.to_le_bytes());
        rec[23..31].copy_from_slice(&row.next_review_at_micros.to_le_bytes());
        rec[31] = row.pressure_level;
        rec[32..36].copy_from_slice(&row.pressure_reasons_mask.to_le_bytes());
        rec[36] = row.trunk_tier;
        rec[37..41].copy_from_slice(&row.relations_out_count.to_le_bytes());
        rec[41..45].copy_from_slice(&row.relations_in_count.to_le_bytes());
        rec[45..49].copy_from_slice(&row.dependents_count.to_le_bytes());
        rec[49..57].copy_from_slice(&row.updated_at_micros.to_le_bytes());
        out.extend_from_slice(&rec);
    }
    out
}

pub fn decode_living_rows_v1(input: &[u8]) -> Result<BTreeMap<(u64, u32), LivingStateRowV1>> {
    if !input.len().is_multiple_of(LIVING_ROW_STRIDE_V1) {
        return Err(ProjectionError::InvalidEvent {
            msg: "living snapshot block length is not a multiple of row stride".to_string(),
        });
    }
    let mut out: BTreeMap<(u64, u32), LivingStateRowV1> = BTreeMap::new();
    for chunk in input.chunks_exact(LIVING_ROW_STRIDE_V1) {
        let tenant_hash = u64::from_le_bytes(chunk[0..8].try_into().unwrap());
        let artifact_id = u32::from_le_bytes(chunk[8..12].try_into().unwrap());
        let living_status = crate::state::LivingStatusV1::from_u8(chunk[12]);
        let confidence_q16 = u16::from_le_bytes(chunk[13..15].try_into().unwrap());
        let last_validated_at_micros = i64::from_le_bytes(chunk[15..23].try_into().unwrap());
        let next_review_at_micros = i64::from_le_bytes(chunk[23..31].try_into().unwrap());
        let pressure_level = chunk[31];
        let pressure_reasons_mask = u32::from_le_bytes(chunk[32..36].try_into().unwrap());
        let trunk_tier = chunk[36];
        let relations_out_count = i32::from_le_bytes(chunk[37..41].try_into().unwrap());
        let relations_in_count = i32::from_le_bytes(chunk[41..45].try_into().unwrap());
        let dependents_count = i32::from_le_bytes(chunk[45..49].try_into().unwrap());
        let updated_at_micros = i64::from_le_bytes(chunk[49..57].try_into().unwrap());
        out.insert(
            (tenant_hash, artifact_id),
            LivingStateRowV1 {
                living_status,
                confidence_q16,
                last_validated_at_micros,
                next_review_at_micros,
                pressure_level,
                pressure_reasons_mask,
                trunk_tier,
                relations_out_count,
                relations_in_count,
                dependents_count,
                updated_at_micros,
            },
        );
    }
    Ok(out)
}

#[allow(dead_code)] // Full-collection variant kept for wire-compat; filtered variant used in production.
pub fn encode_relations_edges_v1(edges: &BTreeMap<(u64, u32, u32, u8), RelationEdgeV1>) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(edges.len() * RELATION_EDGE_STRIDE_V1);
    for ((tenant_hash, src, dst, relation_type), edge) in edges {
        let mut rec = [0u8; RELATION_EDGE_STRIDE_V1];
        rec[0..8].copy_from_slice(&tenant_hash.to_le_bytes());
        rec[8..12].copy_from_slice(&src.to_le_bytes());
        rec[12..16].copy_from_slice(&dst.to_le_bytes());
        rec[16] = *relation_type;
        rec[17..19].copy_from_slice(&edge.confidence_q16.to_le_bytes());
        rec[19..35].copy_from_slice(&edge.evidence_ref_hash16);
        rec[35..43].copy_from_slice(&edge.created_at_micros.to_le_bytes());
        rec[43..51].copy_from_slice(&edge.updated_at_micros.to_le_bytes());
        out.extend_from_slice(&rec);
    }
    out
}

pub fn encode_relations_edges_for_src_v1(
    edges: &BTreeMap<(u64, u32, u32, u8), RelationEdgeV1>,
    tenant_hash: u64,
    src_artifact_id: u32,
) -> Vec<u8> {
    let start = (tenant_hash, src_artifact_id, 0u32, 0u8);
    let end = (tenant_hash, src_artifact_id, u32::MAX, u8::MAX);
    let it = edges.range(start..=end);

    let mut out: Vec<u8> = Vec::new();
    for ((tenant_hash, src, dst, relation_type), edge) in it {
        let mut rec = [0u8; RELATION_EDGE_STRIDE_V1];
        rec[0..8].copy_from_slice(&tenant_hash.to_le_bytes());
        rec[8..12].copy_from_slice(&src.to_le_bytes());
        rec[12..16].copy_from_slice(&dst.to_le_bytes());
        rec[16] = *relation_type;
        rec[17..19].copy_from_slice(&edge.confidence_q16.to_le_bytes());
        rec[19..35].copy_from_slice(&edge.evidence_ref_hash16);
        rec[35..43].copy_from_slice(&edge.created_at_micros.to_le_bytes());
        rec[43..51].copy_from_slice(&edge.updated_at_micros.to_le_bytes());
        out.extend_from_slice(&rec);
    }
    out
}

pub fn decode_relations_edges_v1(input: &[u8]) -> Result<BTreeMap<(u64, u32, u32, u8), RelationEdgeV1>> {
    if !input.len().is_multiple_of(RELATION_EDGE_STRIDE_V1) {
        return Err(ProjectionError::InvalidEvent {
            msg: "relations snapshot block length is not a multiple of edge stride".to_string(),
        });
    }
    let mut out: BTreeMap<(u64, u32, u32, u8), RelationEdgeV1> = BTreeMap::new();
    for chunk in input.chunks_exact(RELATION_EDGE_STRIDE_V1) {
        let tenant_hash = u64::from_le_bytes(chunk[0..8].try_into().unwrap());
        let src = u32::from_le_bytes(chunk[8..12].try_into().unwrap());
        let dst = u32::from_le_bytes(chunk[12..16].try_into().unwrap());
        let relation_type = chunk[16];
        let confidence_q16 = u16::from_le_bytes(chunk[17..19].try_into().unwrap());
        let mut evidence_ref_hash16 = [0u8; 16];
        evidence_ref_hash16.copy_from_slice(&chunk[19..35]);
        let created_at_micros = i64::from_le_bytes(chunk[35..43].try_into().unwrap());
        let updated_at_micros = i64::from_le_bytes(chunk[43..51].try_into().unwrap());
        out.insert(
            (tenant_hash, src, dst, relation_type),
            RelationEdgeV1 {
                confidence_q16,
                evidence_ref_hash16,
                created_at_micros,
                updated_at_micros,
            },
        );
    }
    Ok(out)
}

#[allow(dead_code)] // Full-collection variant kept for wire-compat; filtered variant used in production.
pub fn encode_dependents_edges_v1(edges: &BTreeMap<(u64, u32, u8, uuid::Uuid), DependentEdgeV1>) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(edges.len() * DEPENDENT_EDGE_STRIDE_V1);
    for ((tenant_hash, artifact_id, dependent_type, dependent_id), edge) in edges {
        let mut rec = [0u8; DEPENDENT_EDGE_STRIDE_V1];
        rec[0..8].copy_from_slice(&tenant_hash.to_le_bytes());
        rec[8..12].copy_from_slice(&artifact_id.to_le_bytes());
        rec[12] = *dependent_type;
        rec[13..29].copy_from_slice(dependent_id.as_bytes());
        rec[29..37].copy_from_slice(&edge.last_seen_at_micros.to_le_bytes());
        rec[37..39].copy_from_slice(&edge.usage_weight_q16.to_le_bytes());
        out.extend_from_slice(&rec);
    }
    out
}

pub fn encode_dependents_edges_for_artifact_v1(
    edges: &BTreeMap<(u64, u32, u8, uuid::Uuid), DependentEdgeV1>,
    tenant_hash: u64,
    artifact_id: u32,
) -> Vec<u8> {
    let uuid_min = uuid::Uuid::from_bytes([0u8; 16]);
    let uuid_max = uuid::Uuid::from_bytes([0xFFu8; 16]);
    let start = (tenant_hash, artifact_id, 0u8, uuid_min);
    let end = (tenant_hash, artifact_id, u8::MAX, uuid_max);

    let mut out: Vec<u8> = Vec::new();
    for ((tenant_hash, artifact_id, dependent_type, dependent_id), edge) in edges.range(start..=end) {
        let mut rec = [0u8; DEPENDENT_EDGE_STRIDE_V1];
        rec[0..8].copy_from_slice(&tenant_hash.to_le_bytes());
        rec[8..12].copy_from_slice(&artifact_id.to_le_bytes());
        rec[12] = *dependent_type;
        rec[13..29].copy_from_slice(dependent_id.as_bytes());
        rec[29..37].copy_from_slice(&edge.last_seen_at_micros.to_le_bytes());
        rec[37..39].copy_from_slice(&edge.usage_weight_q16.to_le_bytes());
        out.extend_from_slice(&rec);
    }
    out
}

pub fn decode_dependents_edges_v1(input: &[u8]) -> Result<BTreeMap<(u64, u32, u8, uuid::Uuid), DependentEdgeV1>> {
    if !input.len().is_multiple_of(DEPENDENT_EDGE_STRIDE_V1) {
        return Err(ProjectionError::InvalidEvent {
            msg: "dependents snapshot block length is not a multiple of edge stride".to_string(),
        });
    }
    let mut out: BTreeMap<(u64, u32, u8, uuid::Uuid), DependentEdgeV1> = BTreeMap::new();
    for chunk in input.chunks_exact(DEPENDENT_EDGE_STRIDE_V1) {
        let tenant_hash = u64::from_le_bytes(chunk[0..8].try_into().unwrap());
        let artifact_id = u32::from_le_bytes(chunk[8..12].try_into().unwrap());
        let dependent_type = chunk[12];
        let mut buf = [0u8; 16];
        buf.copy_from_slice(&chunk[13..29]);
        let dependent_id = uuid::Uuid::from_bytes(buf);
        let last_seen_at_micros = i64::from_le_bytes(chunk[29..37].try_into().unwrap());
        let usage_weight_q16 = u16::from_le_bytes(chunk[37..39].try_into().unwrap());
        out.insert(
            (tenant_hash, artifact_id, dependent_type, dependent_id),
            DependentEdgeV1 {
                last_seen_at_micros,
                usage_weight_q16,
            },
        );
    }
    Ok(out)
}

pub fn encode_pressure_rows_v1(rows: &BTreeMap<(u64, u32, uuid::Uuid), PressureEventRowV1>) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(rows.len() * PRESSURE_ROW_STRIDE_V1);
    for ((tenant_hash, artifact_id, pressure_event_id), row) in rows {
        let mut rec = [0u8; PRESSURE_ROW_STRIDE_V1];
        rec[0..8].copy_from_slice(&tenant_hash.to_le_bytes());
        rec[8..12].copy_from_slice(&artifact_id.to_le_bytes());
        rec[12..28].copy_from_slice(pressure_event_id.as_bytes());
        rec[28..30].copy_from_slice(&row.pressure_code_id.to_le_bytes());
        rec[30] = row.severity;
        rec[31..39].copy_from_slice(&row.observed_at_micros.to_le_bytes());
        rec[39..47].copy_from_slice(&row.acknowledged_at_micros.to_le_bytes());
        rec[47..55].copy_from_slice(&row.resolved_at_micros.to_le_bytes());
        if let Some(rid) = row.receipt_id {
            rec[55..71].copy_from_slice(rid.as_bytes());
        }
        out.extend_from_slice(&rec);
    }
    out
}

pub fn decode_pressure_rows_v1(input: &[u8]) -> Result<BTreeMap<(u64, u32, uuid::Uuid), PressureEventRowV1>> {
    if !input.len().is_multiple_of(PRESSURE_ROW_STRIDE_V1) {
        return Err(ProjectionError::InvalidEvent {
            msg: "pressure snapshot block length is not a multiple of row stride".to_string(),
        });
    }
    let mut out: BTreeMap<(u64, u32, uuid::Uuid), PressureEventRowV1> = BTreeMap::new();
    for chunk in input.chunks_exact(PRESSURE_ROW_STRIDE_V1) {
        let tenant_hash = u64::from_le_bytes(chunk[0..8].try_into().unwrap());
        let artifact_id = u32::from_le_bytes(chunk[8..12].try_into().unwrap());
        let mut eid = [0u8; 16];
        eid.copy_from_slice(&chunk[12..28]);
        let pressure_event_id = uuid::Uuid::from_bytes(eid);
        let pressure_code_id = u16::from_le_bytes(chunk[28..30].try_into().unwrap());
        let severity = chunk[30];
        let observed_at_micros = i64::from_le_bytes(chunk[31..39].try_into().unwrap());
        let acknowledged_at_micros = i64::from_le_bytes(chunk[39..47].try_into().unwrap());
        let resolved_at_micros = i64::from_le_bytes(chunk[47..55].try_into().unwrap());
        let receipt_id = {
            let mut rid = [0u8; 16];
            rid.copy_from_slice(&chunk[55..71]);
            if rid.iter().all(|b| *b == 0) {
                None
            } else {
                Some(uuid::Uuid::from_bytes(rid))
            }
        };
        out.insert(
            (tenant_hash, artifact_id, pressure_event_id),
            PressureEventRowV1 {
                pressure_code_id,
                severity,
                observed_at_micros,
                acknowledged_at_micros,
                resolved_at_micros,
                receipt_id,
            },
        );
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{DependentEdgeV1, LivingStateRowV1, LivingStatusV1, PressureEventRowV1, RelationEdgeV1};
    use uuid::Uuid;

    // ---- Hot Pointers ----

    #[test]
    fn hot_ptrs_roundtrip_empty() {
        let ptrs = BTreeMap::new();
        let encoded = encode_hot_ptrs_v1(&ptrs);
        assert!(encoded.is_empty());
        let decoded = decode_hot_ptrs_v1(&encoded).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn hot_ptrs_roundtrip_single() {
        let mut ptrs = BTreeMap::new();
        ptrs.insert(
            (12345u64, 42u32),
            HotPtrEntryV1 {
                edge_count: 3,
                block_len: 192,
                codec: 0,
                blake3: [0xAA; 32],
            },
        );
        let encoded = encode_hot_ptrs_v1(&ptrs);
        assert_eq!(encoded.len(), HOT_PTR_ENTRY_STRIDE_V1);
        let decoded = decode_hot_ptrs_v1(&encoded).unwrap();
        assert_eq!(decoded, ptrs);
    }

    #[test]
    fn hot_ptrs_roundtrip_multiple() {
        let mut ptrs = BTreeMap::new();
        for i in 0..5u32 {
            ptrs.insert(
                (100u64 + i as u64, i),
                HotPtrEntryV1 {
                    edge_count: i,
                    block_len: i * 64,
                    codec: 0,
                    blake3: [i as u8; 32],
                },
            );
        }
        let encoded = encode_hot_ptrs_v1(&ptrs);
        assert_eq!(encoded.len(), 5 * HOT_PTR_ENTRY_STRIDE_V1);
        let decoded = decode_hot_ptrs_v1(&encoded).unwrap();
        assert_eq!(decoded, ptrs);
    }

    #[test]
    fn hot_ptrs_decode_bad_length() {
        let bad = vec![0u8; HOT_PTR_ENTRY_STRIDE_V1 + 1];
        assert!(decode_hot_ptrs_v1(&bad).is_err());
    }

    #[test]
    fn hot_ptrs_decode_unsupported_codec() {
        let mut ptrs = BTreeMap::new();
        ptrs.insert(
            (1u64, 1u32),
            HotPtrEntryV1 {
                edge_count: 1,
                block_len: 64,
                codec: 0,
                blake3: [0; 32],
            },
        );
        let mut encoded = encode_hot_ptrs_v1(&ptrs);
        // Corrupt codec field (bytes 20..24) to non-zero.
        encoded[20] = 1;
        assert!(decode_hot_ptrs_v1(&encoded).is_err());
    }

    // ---- Living Rows ----

    #[test]
    fn living_rows_roundtrip_empty() {
        let rows = BTreeMap::new();
        let encoded = encode_living_rows_v1(&rows);
        assert!(encoded.is_empty());
        let decoded = decode_living_rows_v1(&encoded).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn living_rows_roundtrip_single() {
        let mut rows = BTreeMap::new();
        rows.insert(
            (999u64, 7u32),
            LivingStateRowV1 {
                living_status: LivingStatusV1::Active,
                confidence_q16: 40000,
                last_validated_at_micros: 1_000_000,
                next_review_at_micros: 2_000_000,
                pressure_level: 2,
                pressure_reasons_mask: 0x0F,
                trunk_tier: 3,
                relations_out_count: 5,
                relations_in_count: 2,
                dependents_count: 1,
                updated_at_micros: 3_000_000,
            },
        );
        let encoded = encode_living_rows_v1(&rows);
        assert_eq!(encoded.len(), LIVING_ROW_STRIDE_V1);
        let decoded = decode_living_rows_v1(&encoded).unwrap();
        assert_eq!(decoded, rows);
    }

    #[test]
    fn living_rows_roundtrip_all_statuses() {
        let statuses = [
            LivingStatusV1::Dormant,
            LivingStatusV1::Active,
            LivingStatusV1::Stale,
            LivingStatusV1::Contested,
            LivingStatusV1::Superseded,
            LivingStatusV1::Deprecated,
        ];
        let mut rows = BTreeMap::new();
        for (i, status) in statuses.iter().enumerate() {
            rows.insert(
                (1u64, i as u32),
                LivingStateRowV1 {
                    living_status: *status,
                    confidence_q16: (i as u16) * 1000,
                    last_validated_at_micros: 0,
                    next_review_at_micros: 0,
                    pressure_level: 0,
                    pressure_reasons_mask: 0,
                    trunk_tier: 0,
                    relations_out_count: 0,
                    relations_in_count: 0,
                    dependents_count: 0,
                    updated_at_micros: 0,
                },
            );
        }
        let encoded = encode_living_rows_v1(&rows);
        let decoded = decode_living_rows_v1(&encoded).unwrap();
        assert_eq!(decoded, rows);
    }

    #[test]
    fn living_rows_decode_bad_length() {
        let bad = vec![0u8; LIVING_ROW_STRIDE_V1 + 3];
        assert!(decode_living_rows_v1(&bad).is_err());
    }

    // ---- Relation Edges ----

    #[test]
    fn relation_edges_roundtrip_empty() {
        let edges = BTreeMap::new();
        let encoded = encode_relations_edges_v1(&edges);
        assert!(encoded.is_empty());
        let decoded = decode_relations_edges_v1(&encoded).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn relation_edges_roundtrip_single() {
        let mut edges = BTreeMap::new();
        edges.insert(
            (100u64, 1u32, 2u32, 0u8),
            RelationEdgeV1 {
                confidence_q16: 50000,
                evidence_ref_hash16: [7u8; 16],
                created_at_micros: 100_000,
                updated_at_micros: 200_000,
            },
        );
        let encoded = encode_relations_edges_v1(&edges);
        assert_eq!(encoded.len(), RELATION_EDGE_STRIDE_V1);
        let decoded = decode_relations_edges_v1(&encoded).unwrap();
        assert_eq!(decoded, edges);
    }

    #[test]
    fn relation_edges_decode_bad_length() {
        let bad = vec![0u8; RELATION_EDGE_STRIDE_V1 * 2 + 1];
        assert!(decode_relations_edges_v1(&bad).is_err());
    }

    #[test]
    fn relation_edges_for_src_filters_correctly() {
        let mut edges = BTreeMap::new();
        let th = 42u64;
        // src=1, dst=2
        edges.insert(
            (th, 1u32, 2u32, 0u8),
            RelationEdgeV1 {
                confidence_q16: 100,
                evidence_ref_hash16: [0; 16],
                created_at_micros: 0,
                updated_at_micros: 0,
            },
        );
        // src=1, dst=3
        edges.insert(
            (th, 1u32, 3u32, 0u8),
            RelationEdgeV1 {
                confidence_q16: 200,
                evidence_ref_hash16: [0; 16],
                created_at_micros: 0,
                updated_at_micros: 0,
            },
        );
        // src=5, dst=6 (different src)
        edges.insert(
            (th, 5u32, 6u32, 0u8),
            RelationEdgeV1 {
                confidence_q16: 300,
                evidence_ref_hash16: [0; 16],
                created_at_micros: 0,
                updated_at_micros: 0,
            },
        );

        let filtered = encode_relations_edges_for_src_v1(&edges, th, 1);
        let decoded = decode_relations_edges_v1(&filtered).unwrap();
        assert_eq!(decoded.len(), 2);
        assert!(decoded.contains_key(&(th, 1, 2, 0)));
        assert!(decoded.contains_key(&(th, 1, 3, 0)));
        assert!(!decoded.contains_key(&(th, 5, 6, 0)));
    }

    #[test]
    fn relation_edges_for_src_empty_when_no_match() {
        let edges = BTreeMap::new();
        let encoded = encode_relations_edges_for_src_v1(&edges, 99, 1);
        assert!(encoded.is_empty());
    }

    // ---- Dependent Edges ----

    #[test]
    fn dependent_edges_roundtrip_empty() {
        let edges = BTreeMap::new();
        let encoded = encode_dependents_edges_v1(&edges);
        assert!(encoded.is_empty());
        let decoded = decode_dependents_edges_v1(&encoded).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn dependent_edges_roundtrip_single() {
        let dep_id = Uuid::parse_str("a1b2c3d4-e5f6-7890-abcd-ef1234567890").unwrap();
        let mut edges = BTreeMap::new();
        edges.insert(
            (50u64, 10u32, 1u8, dep_id),
            DependentEdgeV1 {
                last_seen_at_micros: 5_000_000,
                usage_weight_q16: 12345,
            },
        );
        let encoded = encode_dependents_edges_v1(&edges);
        assert_eq!(encoded.len(), DEPENDENT_EDGE_STRIDE_V1);
        let decoded = decode_dependents_edges_v1(&encoded).unwrap();
        assert_eq!(decoded, edges);
    }

    #[test]
    fn dependent_edges_decode_bad_length() {
        let bad = vec![0u8; DEPENDENT_EDGE_STRIDE_V1 + 7];
        assert!(decode_dependents_edges_v1(&bad).is_err());
    }

    #[test]
    fn dependent_edges_for_artifact_filters_correctly() {
        let th = 77u64;
        let uid_a = Uuid::parse_str("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").unwrap();
        let uid_b = Uuid::parse_str("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb").unwrap();
        let mut edges = BTreeMap::new();
        edges.insert(
            (th, 10u32, 0u8, uid_a),
            DependentEdgeV1 {
                last_seen_at_micros: 100,
                usage_weight_q16: 50,
            },
        );
        edges.insert(
            (th, 20u32, 0u8, uid_b),
            DependentEdgeV1 {
                last_seen_at_micros: 200,
                usage_weight_q16: 60,
            },
        );

        let filtered = encode_dependents_edges_for_artifact_v1(&edges, th, 10);
        let decoded = decode_dependents_edges_v1(&filtered).unwrap();
        assert_eq!(decoded.len(), 1);
        assert!(decoded.contains_key(&(th, 10, 0, uid_a)));
    }

    // ---- Pressure Rows ----

    #[test]
    fn pressure_rows_roundtrip_empty() {
        let rows = BTreeMap::new();
        let encoded = encode_pressure_rows_v1(&rows);
        assert!(encoded.is_empty());
        let decoded = decode_pressure_rows_v1(&encoded).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn pressure_rows_roundtrip_with_receipt() {
        let eid = Uuid::parse_str("11111111-2222-3333-4444-555555555555").unwrap();
        let rid = Uuid::parse_str("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
        let mut rows = BTreeMap::new();
        rows.insert(
            (10u64, 5u32, eid),
            PressureEventRowV1 {
                pressure_code_id: 1001,
                severity: 4,
                observed_at_micros: 10_000_000,
                acknowledged_at_micros: 20_000_000,
                resolved_at_micros: 0,
                receipt_id: Some(rid),
            },
        );
        let encoded = encode_pressure_rows_v1(&rows);
        assert_eq!(encoded.len(), PRESSURE_ROW_STRIDE_V1);
        let decoded = decode_pressure_rows_v1(&encoded).unwrap();
        assert_eq!(decoded, rows);
    }

    #[test]
    fn pressure_rows_roundtrip_without_receipt() {
        let eid = Uuid::parse_str("22222222-3333-4444-5555-666666666666").unwrap();
        let mut rows = BTreeMap::new();
        rows.insert(
            (20u64, 10u32, eid),
            PressureEventRowV1 {
                pressure_code_id: 500,
                severity: 2,
                observed_at_micros: 100,
                acknowledged_at_micros: 0,
                resolved_at_micros: 0,
                receipt_id: None,
            },
        );
        let encoded = encode_pressure_rows_v1(&rows);
        let decoded = decode_pressure_rows_v1(&encoded).unwrap();
        assert_eq!(decoded, rows);
    }

    #[test]
    fn pressure_rows_decode_bad_length() {
        let bad = vec![0u8; PRESSURE_ROW_STRIDE_V1 + 2];
        assert!(decode_pressure_rows_v1(&bad).is_err());
    }

    // ---- Multi-row roundtrip ----

    #[test]
    fn living_rows_roundtrip_multiple() {
        let mut rows = BTreeMap::new();
        for i in 0..10u32 {
            rows.insert(
                (1u64, i),
                LivingStateRowV1 {
                    living_status: LivingStatusV1::from_u8((i % 6) as u8),
                    confidence_q16: i as u16 * 6553,
                    last_validated_at_micros: i as i64 * 1000,
                    next_review_at_micros: i as i64 * 2000,
                    pressure_level: (i % 4) as u8,
                    pressure_reasons_mask: i,
                    trunk_tier: (i % 5) as u8,
                    relations_out_count: i as i32,
                    relations_in_count: -(i as i32),
                    dependents_count: i as i32 * 2,
                    updated_at_micros: i as i64 * 3000,
                },
            );
        }
        let encoded = encode_living_rows_v1(&rows);
        assert_eq!(encoded.len(), 10 * LIVING_ROW_STRIDE_V1);
        let decoded = decode_living_rows_v1(&encoded).unwrap();
        assert_eq!(decoded, rows);
    }

    #[test]
    fn pressure_rows_roundtrip_multiple() {
        let mut rows = BTreeMap::new();
        for i in 0..5u32 {
            let eid = Uuid::from_bytes([i as u8; 16]);
            let receipt = if i % 2 == 0 {
                Some(Uuid::from_bytes([i as u8 + 0x10; 16]))
            } else {
                None
            };
            rows.insert(
                (1u64, i, eid),
                PressureEventRowV1 {
                    pressure_code_id: i as u16 * 100,
                    severity: (i % 5) as u8,
                    observed_at_micros: i as i64 * 1000,
                    acknowledged_at_micros: i as i64 * 500,
                    resolved_at_micros: if i % 3 == 0 { i as i64 * 2000 } else { 0 },
                    receipt_id: receipt,
                },
            );
        }
        let encoded = encode_pressure_rows_v1(&rows);
        let decoded = decode_pressure_rows_v1(&encoded).unwrap();
        assert_eq!(decoded, rows);
    }
}
