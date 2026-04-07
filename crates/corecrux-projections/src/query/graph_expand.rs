// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Multi-hop graph traversal over projection relation edges.
//!
//! Inspired by Hindsight's Link Expansion pattern: three parallel signals
//! (entity co-occurrence, relation chain, elaboration) merged into a single
//! ranked result set. Operates purely on in-memory `ProjectionState`.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use crate::state::{dequantize_confidence_f32, LivingStateRowV1, ProjectionState, RelationTypeV1};

/// Request for graph expansion.
#[derive(Debug, Clone)]
pub struct GraphExpandRequest {
    pub tenant_hash: u64,
    pub seed_artifact_ids: Vec<u32>,
    /// Filter to specific edge types. Empty = all types.
    pub edge_types: Vec<RelationTypeV1>,
    /// Maximum hops from seeds. Clamped to 1..=5.
    pub max_hops: u32,
    /// Maximum artifacts to return. Clamped to 1..=200.
    pub budget: usize,
    /// Minimum confidence (0.0..=1.0) for edges to traverse. Default 0.0.
    pub min_confidence: f32,
    /// Include living state in results.
    pub include_state: bool,
}

impl Default for GraphExpandRequest {
    fn default() -> Self {
        Self {
            tenant_hash: 0,
            seed_artifact_ids: Vec::new(),
            edge_types: Vec::new(),
            max_hops: 2,
            budget: 50,
            min_confidence: 0.0,
            include_state: false,
        }
    }
}

/// A single artifact in the expansion result.
#[derive(Debug, Clone)]
pub struct GraphExpandArtifact {
    pub artifact_id: u32,
    pub score: f32,
    pub hop_distance: u32,
    pub edge_types_used: Vec<RelationTypeV1>,
    pub state: Option<LivingStateRowV1>,
}

/// Traversal statistics.
#[derive(Debug, Clone, Default)]
pub struct GraphExpandStats {
    pub nodes_visited: u32,
    pub hops_used: u32,
    pub budget_remaining: usize,
    pub edges_traversed: u64,
}

/// Result of graph expansion.
#[derive(Debug, Clone)]
pub struct GraphExpandResponse {
    pub artifacts: Vec<GraphExpandArtifact>,
    pub stats: GraphExpandStats,
}

/// Per-node activation state during BFS.
#[derive(Debug, Clone)]
struct NodeActivation {
    score: f32,
    hop_distance: u32,
    edge_types: BTreeSet<RelationTypeV1>,
}

/// Decay factor per hop.
const HOP_DECAY: f32 = 0.8;

/// Causal edge types get a propagation boost.
fn edge_boost(rt: RelationTypeV1) -> f32 {
    match rt {
        RelationTypeV1::Supports | RelationTypeV1::Contradicts => 1.5,
        RelationTypeV1::Supersedes | RelationTypeV1::DerivedFrom => 1.3,
        RelationTypeV1::Cites => 1.2,
        RelationTypeV1::AboutSameEntity => 1.4,
        RelationTypeV1::Elaborates | RelationTypeV1::Duplicates => 1.0,
    }
}

/// Execute graph expansion over projection state.
pub fn graph_expand(state: &ProjectionState, req: &GraphExpandRequest) -> GraphExpandResponse {
    let max_hops = req.max_hops.clamp(1, 5);
    let budget = req.budget.clamp(1, 200);
    let min_conf_q16 = (req.min_confidence.clamp(0.0, 1.0) * 65535.0) as u16;

    let edge_filter: BTreeSet<u8> = req.edge_types.iter().map(|t| t.to_u8()).collect();
    let filter_edges = !edge_filter.is_empty();

    // Activation map: artifact_id -> NodeActivation
    let mut activations: BTreeMap<u32, NodeActivation> = BTreeMap::new();
    let seed_set: BTreeSet<u32> = req.seed_artifact_ids.iter().cloned().collect();

    // Initialize seeds with score 1.0
    for &seed_id in &req.seed_artifact_ids {
        activations.insert(
            seed_id,
            NodeActivation {
                score: 1.0,
                hop_distance: 0,
                edge_types: BTreeSet::new(),
            },
        );
    }

    // BFS frontier: current layer of nodes to expand
    let mut frontier: BTreeSet<u32> = seed_set.clone();
    let mut visited: BTreeSet<u32> = seed_set.clone();
    let mut total_edges_traversed: u64 = 0;
    let mut hops_used: u32 = 0;

    for hop in 0..max_hops {
        if frontier.is_empty() {
            break;
        }
        hops_used = hop + 1;
        let mut next_frontier: BTreeSet<u32> = BTreeSet::new();

        for &src_id in &frontier {
            let parent_score = activations.get(&src_id).map(|a| a.score).unwrap_or(0.0);
            if parent_score < 0.01 {
                continue;
            }

            // Traverse outgoing edges from src_id
            let start = (req.tenant_hash, src_id, 0u32, 0u8);
            let end = (req.tenant_hash, src_id, u32::MAX, u8::MAX);

            for ((_t, _src, dst, rt), edge) in state.relations.range(start..=end) {
                total_edges_traversed += 1;

                if filter_edges && !edge_filter.contains(rt) {
                    continue;
                }
                if edge.confidence_q16 < min_conf_q16 {
                    continue;
                }

                let rt_enum = match RelationTypeV1::from_u8(*rt) {
                    Some(t) => t,
                    None => continue,
                };

                let conf = dequantize_confidence_f32(edge.confidence_q16);
                let propagated = parent_score * conf * edge_boost(rt_enum) * HOP_DECAY;

                let activation = activations.entry(*dst).or_insert_with(|| NodeActivation {
                    score: 0.0,
                    hop_distance: hop + 1,
                    edge_types: BTreeSet::new(),
                });

                // Take the max score (not additive — avoids explosion)
                if propagated > activation.score {
                    activation.score = propagated;
                    activation.hop_distance = hop + 1;
                }
                activation.edge_types.insert(rt_enum);

                if !visited.contains(dst) {
                    visited.insert(*dst);
                    next_frontier.insert(*dst);
                }
            }

            // Also traverse incoming edges (reverse direction)
            // Incoming edges require a scan since BTreeMap key is (tenant, src, dst, rt)
            // We limit this to a bounded scan for performance
            let tenant_start = (req.tenant_hash, 0u32, src_id, 0u8);
            let tenant_end = (req.tenant_hash, u32::MAX, src_id, u8::MAX);
            for ((_t, other_src, dst, rt), edge) in state.relations.range(tenant_start..=tenant_end) {
                if *dst != src_id {
                    continue;
                }
                total_edges_traversed += 1;

                if filter_edges && !edge_filter.contains(rt) {
                    continue;
                }
                if edge.confidence_q16 < min_conf_q16 {
                    continue;
                }

                let rt_enum = match RelationTypeV1::from_u8(*rt) {
                    Some(t) => t,
                    None => continue,
                };

                let conf = dequantize_confidence_f32(edge.confidence_q16);
                // Incoming edges get slightly less boost (0.9x) to prefer forward traversal
                let propagated = parent_score * conf * edge_boost(rt_enum) * HOP_DECAY * 0.9;

                let activation = activations.entry(*other_src).or_insert_with(|| NodeActivation {
                    score: 0.0,
                    hop_distance: hop + 1,
                    edge_types: BTreeSet::new(),
                });

                if propagated > activation.score {
                    activation.score = propagated;
                    activation.hop_distance = hop + 1;
                }
                activation.edge_types.insert(rt_enum);

                if !visited.contains(other_src) {
                    visited.insert(*other_src);
                    next_frontier.insert(*other_src);
                }
            }
        }

        frontier = next_frontier;

        // Early termination if we've visited more than budget * 2
        if visited.len() > budget * 3 {
            break;
        }
    }

    // Remove seeds from results (caller already has them)
    for seed_id in &seed_set {
        activations.remove(seed_id);
    }

    // Select top-K by score using a min-heap (collect all into sorted vec is simpler for <200 items)
    let mut scored: Vec<(u32, &NodeActivation)> = activations.iter().map(|(&k, v)| (k, v)).collect();
    scored.sort_by(|a, b| b.1.score.partial_cmp(&a.1.score).unwrap_or(Ordering::Equal));
    scored.truncate(budget);

    let artifacts: Vec<GraphExpandArtifact> = scored
        .into_iter()
        .map(|(artifact_id, activation)| {
            let artifact_state = if req.include_state {
                state.living.get(&(req.tenant_hash, artifact_id)).cloned()
            } else {
                None
            };

            GraphExpandArtifact {
                artifact_id,
                score: activation.score,
                hop_distance: activation.hop_distance,
                edge_types_used: activation.edge_types.iter().cloned().collect(),
                state: artifact_state,
            }
        })
        .collect();

    let stats = GraphExpandStats {
        nodes_visited: visited.len() as u32,
        hops_used,
        budget_remaining: budget.saturating_sub(artifacts.len()),
        edges_traversed: total_edges_traversed,
    };

    GraphExpandResponse { artifacts, stats }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::*;

    fn make_state_with_chain() -> ProjectionState {
        let mut state = ProjectionState::default();
        let th: u64 = 12345;

        // Create a chain: 1 -> 2 -> 3 -> 4 -> 5
        // With a branch: 2 -> 6, and 1 -> 7 (about_same_entity)
        let edges = vec![
            (1u32, 2u32, RelationTypeV1::Supports, 0.9f32),
            (2, 3, RelationTypeV1::DerivedFrom, 0.8),
            (3, 4, RelationTypeV1::Cites, 0.7),
            (4, 5, RelationTypeV1::Elaborates, 0.6),
            (2, 6, RelationTypeV1::Contradicts, 0.85),
            (1, 7, RelationTypeV1::AboutSameEntity, 0.95),
        ];

        for (src, dst, rt, conf) in &edges {
            state.relations.insert(
                (th, *src, *dst, rt.to_u8()),
                RelationEdgeV1 {
                    confidence_q16: quantize_confidence_q16(*conf),
                    evidence_ref_hash16: [0u8; 16],
                    created_at_micros: 1_000_000,
                    updated_at_micros: 1_000_000,
                },
            );
        }

        // Add living states
        for id in 1..=7 {
            state.living.insert(
                (th, id),
                LivingStateRowV1 {
                    living_status: LivingStatusV1::Active,
                    confidence_q16: quantize_confidence_q16(0.9),
                    updated_at_micros: 1_000_000,
                    ..Default::default()
                },
            );
        }

        state
    }

    #[test]
    fn test_basic_expansion_from_seed() {
        let state = make_state_with_chain();
        let req = GraphExpandRequest {
            tenant_hash: 12345,
            seed_artifact_ids: vec![1],
            max_hops: 2,
            budget: 50,
            include_state: true,
            ..Default::default()
        };

        let resp = graph_expand(&state, &req);

        // From seed 1, hop 1 reaches: 2 (supports), 7 (about_same_entity)
        // Hop 2 from 2 reaches: 3 (derived_from), 6 (contradicts)
        assert!(!resp.artifacts.is_empty());
        let ids: BTreeSet<u32> = resp.artifacts.iter().map(|a| a.artifact_id).collect();
        assert!(ids.contains(&2), "should reach artifact 2");
        assert!(ids.contains(&7), "should reach artifact 7");
        assert!(ids.contains(&3), "should reach artifact 3 at hop 2");
        assert!(ids.contains(&6), "should reach artifact 6 at hop 2");

        // Artifact 2 should have highest score (direct supports from seed)
        let art2 = resp.artifacts.iter().find(|a| a.artifact_id == 2).unwrap();
        let art7 = resp.artifacts.iter().find(|a| a.artifact_id == 7).unwrap();
        assert!(art2.score > 0.5);
        assert!(art7.score > 0.5);
        assert_eq!(art2.hop_distance, 1);

        // State should be included
        assert!(art2.state.is_some());

        // Seeds should not appear in results
        assert!(!ids.contains(&1));
    }

    #[test]
    fn test_budget_limit() {
        let state = make_state_with_chain();
        let req = GraphExpandRequest {
            tenant_hash: 12345,
            seed_artifact_ids: vec![1],
            max_hops: 5,
            budget: 2,
            ..Default::default()
        };

        let resp = graph_expand(&state, &req);
        assert!(resp.artifacts.len() <= 2);
        assert!(resp.stats.budget_remaining <= 2);
    }

    #[test]
    fn test_edge_type_filter() {
        let state = make_state_with_chain();
        let req = GraphExpandRequest {
            tenant_hash: 12345,
            seed_artifact_ids: vec![1],
            edge_types: vec![RelationTypeV1::AboutSameEntity],
            max_hops: 3,
            budget: 50,
            ..Default::default()
        };

        let resp = graph_expand(&state, &req);
        // Only about_same_entity edges: 1 -> 7
        let ids: BTreeSet<u32> = resp.artifacts.iter().map(|a| a.artifact_id).collect();
        assert!(ids.contains(&7));
        // Should NOT reach 2 (that's via supports)
        assert!(!ids.contains(&2));
    }

    #[test]
    fn test_min_confidence_filter() {
        let state = make_state_with_chain();
        let req = GraphExpandRequest {
            tenant_hash: 12345,
            seed_artifact_ids: vec![1],
            max_hops: 5,
            budget: 50,
            min_confidence: 0.85,
            ..Default::default()
        };

        let resp = graph_expand(&state, &req);
        // Only edges with confidence >= 0.85: supports(0.9), about_same_entity(0.95), contradicts(0.85)
        // From seed 1: reach 2 (0.9), 7 (0.95)
        // From 2: reach 6 (0.85)
        // 3 is via derived_from at 0.8 — filtered out
        let ids: BTreeSet<u32> = resp.artifacts.iter().map(|a| a.artifact_id).collect();
        assert!(ids.contains(&2));
        assert!(ids.contains(&7));
        assert!(ids.contains(&6));
        assert!(!ids.contains(&3), "0.8 confidence should be filtered");
    }

    #[test]
    fn test_empty_graph() {
        let state = ProjectionState::default();
        let req = GraphExpandRequest {
            tenant_hash: 12345,
            seed_artifact_ids: vec![1],
            max_hops: 3,
            budget: 50,
            ..Default::default()
        };

        let resp = graph_expand(&state, &req);
        assert!(resp.artifacts.is_empty());
        assert_eq!(resp.stats.edges_traversed, 0);
    }

    #[test]
    fn test_empty_seeds() {
        let state = make_state_with_chain();
        let req = GraphExpandRequest {
            tenant_hash: 12345,
            seed_artifact_ids: vec![],
            max_hops: 3,
            budget: 50,
            ..Default::default()
        };

        let resp = graph_expand(&state, &req);
        assert!(resp.artifacts.is_empty());
    }

    #[test]
    fn test_score_decay_across_hops() {
        let state = make_state_with_chain();
        let req = GraphExpandRequest {
            tenant_hash: 12345,
            seed_artifact_ids: vec![1],
            max_hops: 3,
            budget: 50,
            ..Default::default()
        };

        let resp = graph_expand(&state, &req);
        let art2 = resp.artifacts.iter().find(|a| a.artifact_id == 2).unwrap();
        let art3 = resp.artifacts.iter().find(|a| a.artifact_id == 3).unwrap();

        // Score should decrease with distance
        assert!(
            art2.score > art3.score,
            "hop-1 artifact should score higher than hop-2: {} vs {}",
            art2.score,
            art3.score
        );
    }

    #[test]
    fn test_different_tenant_isolated() {
        let state = make_state_with_chain();
        let req = GraphExpandRequest {
            tenant_hash: 99999, // different tenant
            seed_artifact_ids: vec![1],
            max_hops: 3,
            budget: 50,
            ..Default::default()
        };

        let resp = graph_expand(&state, &req);
        assert!(resp.artifacts.is_empty(), "wrong tenant should see nothing");
    }
}
