// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Graph signal — boosts BM25 scores based on entity/relation overlap.
//!
//! The graph signal is computed from entity facts stored in CoreCrux projections.
//! Documents that contain entities matching the query receive a configurable boost.
//! Related documents (via relation edges) also receive a confidence-weighted boost.

use crate::bm25::MergedBm25Hit;

/// Graph boost parameters.
#[derive(Debug, Clone, Copy)]
pub struct GraphParams {
    /// Weight for entity overlap boost (0-1).
    pub entity_weight: f32,
    /// Weight for relation edge boost (0-1).
    pub relation_weight: f32,
}

impl Default for GraphParams {
    fn default() -> Self {
        Self {
            entity_weight: 0.3,
            relation_weight: 0.2,
        }
    }
}

/// An entity match from the projection state.
#[derive(Debug, Clone)]
pub struct EntityMatch {
    /// The document/frame this entity was found in (as frame_offset from .ccxi DocEntry).
    pub frame_offset: u32,
    /// Number of entity overlaps with the query.
    pub overlap_count: u32,
    /// Max confidence of the matching entity facts.
    pub confidence: f32,
}

/// A relation edge from the projection state.
#[derive(Debug, Clone)]
pub struct RelationEdge {
    /// Source document frame_offset.
    pub src_frame_offset: u32,
    /// Destination document frame_offset.
    pub dst_frame_offset: u32,
    /// Relation confidence (0-1).
    pub confidence: f32,
}

/// Apply graph boost to BM25 hits based on entity matches and relation edges.
///
/// Documents with entity overlap get `entity_weight * (overlap_count / max_overlap) * confidence`.
/// Documents reached via relations from top-scored docs get `relation_weight * edge_confidence`.
pub fn apply_graph_boost(
    hits: &mut [MergedBm25Hit],
    entity_matches: &[EntityMatch],
    relation_edges: &[RelationEdge],
    params: &GraphParams,
) {
    if entity_matches.is_empty() && relation_edges.is_empty() {
        return;
    }

    // Build frame_offset → entity overlap map
    let max_overlap = entity_matches.iter().map(|m| m.overlap_count).max().unwrap_or(1).max(1) as f32;

    let entity_boost_by_offset: std::collections::HashMap<u32, f32> = entity_matches
        .iter()
        .map(|m| {
            let boost = params.entity_weight * (m.overlap_count as f32 / max_overlap) * m.confidence;
            (m.frame_offset, boost)
        })
        .collect();

    // Build src_frame_offset → dst boosts from relations
    // First, identify top-K frame_offsets from BM25 hits (seed for relation expansion)
    let seed_offsets: std::collections::HashSet<u32> = hits
        .iter()
        .take(10) // only expand from top-10 BM25 hits
        .map(|h| h.frame_offset)
        .collect();

    let mut relation_boost_by_offset: std::collections::HashMap<u32, f32> = std::collections::HashMap::new();
    for edge in relation_edges {
        if seed_offsets.contains(&edge.src_frame_offset) {
            let boost = params.relation_weight * edge.confidence;
            let entry = relation_boost_by_offset.entry(edge.dst_frame_offset).or_insert(0.0);
            *entry = entry.max(boost); // take max boost from any relation
        }
    }

    // Apply boosts to hits
    for hit in hits.iter_mut() {
        let entity_boost = entity_boost_by_offset.get(&hit.frame_offset).copied().unwrap_or(0.0);
        let relation_boost = relation_boost_by_offset.get(&hit.frame_offset).copied().unwrap_or(0.0);
        hit.score += entity_boost + relation_boost;
    }

    // Re-sort by boosted score
    hits.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entity_boost_raises_matched_docs() {
        let mut hits = vec![
            MergedBm25Hit {
                segment_index: 0,
                doc_id: 0,
                score: 1.0,
                tenant_hash_lo16: 0,
                tenant_hash_full: 0,
                frame_offset: 0,
                doc_length_tokens: 100,
            },
            MergedBm25Hit {
                segment_index: 0,
                doc_id: 1,
                score: 0.8,
                tenant_hash_lo16: 0,
                tenant_hash_full: 0,
                frame_offset: 100,
                doc_length_tokens: 100,
            },
            MergedBm25Hit {
                segment_index: 0,
                doc_id: 2,
                score: 0.6,
                tenant_hash_lo16: 0,
                tenant_hash_full: 0,
                frame_offset: 200,
                doc_length_tokens: 100,
            },
        ];

        let entity_matches = vec![EntityMatch {
            frame_offset: 200,
            overlap_count: 3,
            confidence: 0.9,
        }];

        apply_graph_boost(&mut hits, &entity_matches, &[], &GraphParams::default());

        // Doc 2 (frame_offset=200) should have been boosted above doc 1
        assert_eq!(hits[0].doc_id, 0); // still top (score 1.0)
        assert!(hits[1].score > 0.8); // doc 2 boosted
    }

    #[test]
    fn relation_boost_promotes_linked_doc() {
        let mut hits = vec![
            MergedBm25Hit {
                segment_index: 0,
                doc_id: 0,
                score: 1.0,
                tenant_hash_lo16: 0,
                tenant_hash_full: 0,
                frame_offset: 0,
                doc_length_tokens: 100,
            },
            MergedBm25Hit {
                segment_index: 0,
                doc_id: 1,
                score: 0.3,
                tenant_hash_lo16: 0,
                tenant_hash_full: 0,
                frame_offset: 100,
                doc_length_tokens: 100,
            },
        ];

        let relations = vec![RelationEdge {
            src_frame_offset: 0,
            dst_frame_offset: 100,
            confidence: 0.95,
        }];

        apply_graph_boost(&mut hits, &[], &relations, &GraphParams::default());

        // Doc 1 should be boosted via relation from doc 0
        assert!(hits[1].score > 0.3);
    }

    #[test]
    fn no_boost_when_empty() {
        let mut hits = vec![MergedBm25Hit {
            segment_index: 0,
            doc_id: 0,
            score: 1.0,
            tenant_hash_lo16: 0,
            tenant_hash_full: 0,
            frame_offset: 0,
            doc_length_tokens: 100,
        }];

        apply_graph_boost(&mut hits, &[], &[], &GraphParams::default());

        assert_eq!(hits[0].score, 1.0); // unchanged
    }
}
