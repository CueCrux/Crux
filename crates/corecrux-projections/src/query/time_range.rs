// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Temporal range scan over projection state.
//!
//! Filters artifacts and relations by `updated_at_micros` / `created_at_micros`
//! within a time window. Operates purely on in-memory `ProjectionState`.

use std::collections::{BTreeMap, BTreeSet};

use crate::state::{dequantize_confidence_f32, LivingStateRowV1, ProjectionState, RelationTypeV1};

/// Request for temporal range scan.
#[derive(Debug, Clone)]
pub struct TimeRangeRequest {
    pub tenant_hash: u64,
    /// Start of time window (inclusive), microseconds since epoch.
    pub start_micros: i64,
    /// End of time window (exclusive), microseconds since epoch.
    pub end_micros: i64,
    /// Optional: scope to specific artifacts. Empty = scan all for tenant.
    pub artifact_ids: Vec<u32>,
    /// Include relations that changed in the window.
    pub include_relations: bool,
    /// Maximum artifacts to return. Clamped to 1..=500.
    pub limit: usize,
}

impl Default for TimeRangeRequest {
    fn default() -> Self {
        Self {
            tenant_hash: 0,
            start_micros: 0,
            end_micros: i64::MAX,
            artifact_ids: Vec::new(),
            include_relations: false,
            limit: 100,
        }
    }
}

/// A changed relation within the time window.
#[derive(Debug, Clone)]
pub struct TimeRangeRelation {
    pub src_artifact_id: u32,
    pub dst_artifact_id: u32,
    pub relation_type: RelationTypeV1,
    pub confidence: f32,
    pub created_at_micros: i64,
    pub updated_at_micros: i64,
}

/// An artifact that changed within the time window.
#[derive(Debug, Clone)]
pub struct TimeRangeArtifact {
    pub artifact_id: u32,
    pub current_state: LivingStateRowV1,
    pub relations_changed: Vec<TimeRangeRelation>,
    /// Number of relation changes for this artifact in the window.
    pub relation_change_count: u32,
}

/// Scan statistics.
#[derive(Debug, Clone, Default)]
pub struct TimeRangeStats {
    pub artifacts_scanned: u32,
    pub relations_scanned: u64,
    pub total_changes: u32,
}

/// Result of temporal range scan.
#[derive(Debug, Clone)]
pub struct TimeRangeResponse {
    pub artifacts: Vec<TimeRangeArtifact>,
    pub stats: TimeRangeStats,
}

/// Execute temporal range scan over projection state.
pub fn time_range_scan(state: &ProjectionState, req: &TimeRangeRequest) -> TimeRangeResponse {
    let limit = req.limit.clamp(1, 500);

    let scoped_ids: BTreeSet<u32> = req.artifact_ids.iter().copied().collect();
    let scope_all = scoped_ids.is_empty();

    let mut stats = TimeRangeStats::default();

    // Phase 1: Find artifacts whose living state was updated in the window.
    let mut changed_artifacts: BTreeMap<u32, LivingStateRowV1> = BTreeMap::new();

    if scope_all {
        // Scan all artifacts for this tenant. BTreeMap key is (tenant_hash, artifact_id).
        let start_key = (req.tenant_hash, 0u32);
        let end_key = (req.tenant_hash, u32::MAX);
        for ((_th, aid), row) in state.living.range(start_key..=end_key) {
            stats.artifacts_scanned += 1;
            if row.updated_at_micros >= req.start_micros && row.updated_at_micros < req.end_micros {
                changed_artifacts.insert(*aid, row.clone());
            }
        }
    } else {
        for &aid in &scoped_ids {
            stats.artifacts_scanned += 1;
            if let Some(row) = state.living.get(&(req.tenant_hash, aid)) {
                if row.updated_at_micros >= req.start_micros && row.updated_at_micros < req.end_micros {
                    changed_artifacts.insert(aid, row.clone());
                }
            }
        }
    }

    // Phase 2: Find relations that changed in the window (if requested).
    // Also discover artifacts that had relation changes even if their living state
    // wasn't updated in the window.
    let mut relation_changes: BTreeMap<u32, Vec<TimeRangeRelation>> = BTreeMap::new();

    if req.include_relations {
        let rel_start = (req.tenant_hash, 0u32, 0u32, 0u8);
        let rel_end = (req.tenant_hash, u32::MAX, u32::MAX, u8::MAX);

        for ((_th, src, dst, rt), edge) in state.relations.range(rel_start..=rel_end) {
            stats.relations_scanned += 1;

            // Check if this relation was created or updated in the window
            let in_window = (edge.updated_at_micros >= req.start_micros && edge.updated_at_micros < req.end_micros)
                || (edge.created_at_micros >= req.start_micros && edge.created_at_micros < req.end_micros);

            if !in_window {
                continue;
            }

            // If scoped, only include relations touching scoped artifacts
            if !scope_all && !scoped_ids.contains(src) && !scoped_ids.contains(dst) {
                continue;
            }

            let rt_enum = match RelationTypeV1::from_u8(*rt) {
                Some(t) => t,
                None => continue,
            };

            let rel = TimeRangeRelation {
                src_artifact_id: *src,
                dst_artifact_id: *dst,
                relation_type: rt_enum,
                confidence: dequantize_confidence_f32(edge.confidence_q16),
                created_at_micros: edge.created_at_micros,
                updated_at_micros: edge.updated_at_micros,
            };

            // Associate with src artifact
            relation_changes.entry(*src).or_default().push(rel.clone());
            // Also associate with dst if different
            if src != dst {
                relation_changes.entry(*dst).or_default().push(rel);
            }

            // Ensure src and dst are in the changed_artifacts map
            if !changed_artifacts.contains_key(src) {
                if let Some(row) = state.living.get(&(req.tenant_hash, *src)) {
                    changed_artifacts.insert(*src, row.clone());
                }
            }
            if !changed_artifacts.contains_key(dst) {
                if let Some(row) = state.living.get(&(req.tenant_hash, *dst)) {
                    changed_artifacts.insert(*dst, row.clone());
                }
            }
        }
    }

    // Phase 3: Assemble results, sorted by most recently updated first.
    let mut results: Vec<(u32, LivingStateRowV1, Vec<TimeRangeRelation>)> = changed_artifacts
        .into_iter()
        .map(|(aid, row)| {
            let rels = relation_changes.remove(&aid).unwrap_or_default();
            (aid, row, rels)
        })
        .collect();

    // Sort by updated_at_micros descending (most recent first)
    results.sort_by(|a, b| b.1.updated_at_micros.cmp(&a.1.updated_at_micros));
    results.truncate(limit);

    let total_changes = results.len() as u32;

    let artifacts: Vec<TimeRangeArtifact> = results
        .into_iter()
        .map(|(aid, row, rels)| {
            let rel_count = rels.len() as u32;
            TimeRangeArtifact {
                artifact_id: aid,
                current_state: row,
                relations_changed: rels,
                relation_change_count: rel_count,
            }
        })
        .collect();

    stats.total_changes = total_changes;

    TimeRangeResponse { artifacts, stats }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::*;

    fn make_temporal_state() -> ProjectionState {
        let mut state = ProjectionState::default();
        let th: u64 = 12345;

        // Create artifacts with different timestamps (in micros)
        // Jan 2024: 1704067200_000000
        // Feb 2024: 1706745600_000000
        // Mar 2024: 1709251200_000000
        let jan = 1_704_067_200_000_000i64;
        let feb = 1_706_745_600_000_000i64;
        let mar = 1_709_251_200_000_000i64;

        state.living.insert(
            (th, 1),
            LivingStateRowV1 {
                living_status: LivingStatusV1::Active,
                confidence_q16: quantize_confidence_q16(0.9),
                updated_at_micros: jan,
                ..Default::default()
            },
        );
        state.living.insert(
            (th, 2),
            LivingStateRowV1 {
                living_status: LivingStatusV1::Contested,
                confidence_q16: quantize_confidence_q16(0.6),
                updated_at_micros: feb,
                ..Default::default()
            },
        );
        state.living.insert(
            (th, 3),
            LivingStateRowV1 {
                living_status: LivingStatusV1::Active,
                confidence_q16: quantize_confidence_q16(0.95),
                updated_at_micros: mar,
                ..Default::default()
            },
        );

        // Relation created in Feb, updated in Mar
        state.relations.insert(
            (th, 1, 2, RelationTypeV1::Contradicts.to_u8()),
            RelationEdgeV1 {
                confidence_q16: quantize_confidence_q16(0.78),
                evidence_ref_hash16: [0u8; 16],
                created_at_micros: feb,
                updated_at_micros: mar,
            },
        );

        // Relation created and updated in Jan
        state.relations.insert(
            (th, 2, 3, RelationTypeV1::Supports.to_u8()),
            RelationEdgeV1 {
                confidence_q16: quantize_confidence_q16(0.85),
                evidence_ref_hash16: [0u8; 16],
                created_at_micros: jan,
                updated_at_micros: jan,
            },
        );

        state
    }

    #[test]
    fn test_scan_full_range() {
        let state = make_temporal_state();
        let req = TimeRangeRequest {
            tenant_hash: 12345,
            start_micros: 0,
            end_micros: i64::MAX,
            include_relations: true,
            limit: 100,
            ..Default::default()
        };

        let resp = time_range_scan(&state, &req);
        assert_eq!(resp.artifacts.len(), 3);
        assert!(resp.stats.artifacts_scanned >= 3);
    }

    #[test]
    fn test_scan_feb_only() {
        let state = make_temporal_state();
        let feb_start = 1_706_745_600_000_000i64;
        let feb_end = 1_709_251_200_000_000i64; // Mar start

        let req = TimeRangeRequest {
            tenant_hash: 12345,
            start_micros: feb_start,
            end_micros: feb_end,
            include_relations: false,
            limit: 100,
            ..Default::default()
        };

        let resp = time_range_scan(&state, &req);
        // Only artifact 2 was updated in Feb
        assert_eq!(resp.artifacts.len(), 1);
        assert_eq!(resp.artifacts[0].artifact_id, 2);
    }

    #[test]
    fn test_scan_with_relations() {
        let state = make_temporal_state();
        let feb_start = 1_706_745_600_000_000i64;

        let req = TimeRangeRequest {
            tenant_hash: 12345,
            start_micros: feb_start,
            end_micros: i64::MAX,
            include_relations: true,
            limit: 100,
            ..Default::default()
        };

        let resp = time_range_scan(&state, &req);
        // Artifacts 2 (feb) and 3 (mar) updated in window
        // Relation 1->2 was created in feb, updated in mar => in window
        // Relation 2->3 was in jan => NOT in window
        let ids: BTreeSet<u32> = resp.artifacts.iter().map(|a| a.artifact_id).collect();
        assert!(ids.contains(&2));
        assert!(ids.contains(&3));

        // Check relation 1->2 contradicts appears
        let has_contradicts = resp.artifacts.iter().any(|a| {
            a.relations_changed.iter().any(|r| {
                r.src_artifact_id == 1
                    && r.dst_artifact_id == 2
                    && matches!(r.relation_type, RelationTypeV1::Contradicts)
            })
        });
        assert!(has_contradicts, "should find the contradicts relation");
    }

    #[test]
    fn test_scoped_artifacts() {
        let state = make_temporal_state();
        let req = TimeRangeRequest {
            tenant_hash: 12345,
            start_micros: 0,
            end_micros: i64::MAX,
            artifact_ids: vec![1, 3],
            include_relations: false,
            limit: 100,
            ..Default::default()
        };

        let resp = time_range_scan(&state, &req);
        let ids: BTreeSet<u32> = resp.artifacts.iter().map(|a| a.artifact_id).collect();
        assert!(ids.contains(&1));
        assert!(ids.contains(&3));
        assert!(!ids.contains(&2), "artifact 2 not in scope");
    }

    #[test]
    fn test_limit() {
        let state = make_temporal_state();
        let req = TimeRangeRequest {
            tenant_hash: 12345,
            start_micros: 0,
            end_micros: i64::MAX,
            limit: 1,
            ..Default::default()
        };

        let resp = time_range_scan(&state, &req);
        assert_eq!(resp.artifacts.len(), 1);
        // Should be the most recently updated (artifact 3, Mar)
        assert_eq!(resp.artifacts[0].artifact_id, 3);
    }

    #[test]
    fn test_empty_window() {
        let state = make_temporal_state();
        let far_future = 2_000_000_000_000_000i64;
        let req = TimeRangeRequest {
            tenant_hash: 12345,
            start_micros: far_future,
            end_micros: far_future + 1000,
            limit: 100,
            ..Default::default()
        };

        let resp = time_range_scan(&state, &req);
        assert!(resp.artifacts.is_empty());
    }

    #[test]
    fn test_different_tenant_isolated() {
        let state = make_temporal_state();
        let req = TimeRangeRequest {
            tenant_hash: 99999,
            start_micros: 0,
            end_micros: i64::MAX,
            limit: 100,
            ..Default::default()
        };

        let resp = time_range_scan(&state, &req);
        assert!(resp.artifacts.is_empty());
    }

    #[test]
    fn test_relations_discover_new_artifacts() {
        let state = make_temporal_state();
        // Scan starting from Mar — artifact 3 is in window via living state.
        // Relation 1->2 updated in Mar should pull in artifacts 1 and 2.
        let mar = 1_709_251_200_000_000i64;
        let req = TimeRangeRequest {
            tenant_hash: 12345,
            start_micros: mar,
            end_micros: i64::MAX,
            include_relations: true,
            limit: 100,
            ..Default::default()
        };

        let resp = time_range_scan(&state, &req);
        let ids: BTreeSet<u32> = resp.artifacts.iter().map(|a| a.artifact_id).collect();
        // Artifact 3 in window via living state
        assert!(ids.contains(&3));
        // Artifacts 1 and 2 discovered via the 1->2 relation updated in Mar
        assert!(ids.contains(&1));
        assert!(ids.contains(&2));
    }
}
