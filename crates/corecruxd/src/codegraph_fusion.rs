// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Code-graph boost closure for fused retrieval.
//!
//! The daemon does not yet persist a `.ccxi` doc-id → code-node-id association,
//! so this module is a small, testable fusion primitive rather than a live
//! production retrieval lane. Callers that have that association can build the
//! closure shape accepted by `corecrux_retrieval::fused::fused_retrieve`.

#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use corecrux_projections::{ProjectionState, RelationTypeV1};

pub(crate) type CodeGraphBoostFn = Box<dyn Fn(u32, usize) -> (f32, u32) + Send + Sync + 'static>;

const CODEGRAPH_FUSION_ENV: &str = "CORECRUXD_CODEGRAPH_FUSION";

#[derive(Debug, Clone)]
pub(crate) struct CodeGraphBoostInput {
    pub tenant_hash: u64,
    pub doc_to_code_node: BTreeMap<(u32, usize), u32>,
    pub seed_code_nodes: BTreeSet<u32>,
    pub max_hops: u32,
    pub edge_types: BTreeSet<RelationTypeV1>,
}

pub(crate) fn enabled_from_env() -> bool {
    std::env::var(CODEGRAPH_FUSION_ENV).ok().is_some_and(|v| {
        let v = v.trim().to_ascii_lowercase();
        !(v.is_empty() || v == "0" || v == "false" || v == "off" || v == "no")
    })
}

pub(crate) fn default_codegraph_fusion_edge_types() -> BTreeSet<RelationTypeV1> {
    [RelationTypeV1::Calls, RelationTypeV1::Imports, RelationTypeV1::Defines]
        .into_iter()
        .collect()
}

pub(crate) fn build_codegraph_boost_fn(
    state: &ProjectionState,
    input: CodeGraphBoostInput,
) -> Option<CodeGraphBoostFn> {
    if input.doc_to_code_node.is_empty() || input.seed_code_nodes.is_empty() || input.max_hops == 0 {
        return None;
    }
    let edge_types = if input.edge_types.is_empty() {
        default_codegraph_fusion_edge_types()
    } else {
        input.edge_types
    };
    let adjacency = tenant_code_adjacency(state, input.tenant_hash, &edge_types);
    if adjacency.is_empty() {
        return None;
    }
    let distances = bfs_distances(&adjacency, &input.seed_code_nodes, input.max_hops);
    if distances.is_empty() {
        return None;
    }
    let doc_to_code_node = input.doc_to_code_node;
    Some(Box::new(move |doc_id, segment_index| {
        let Some(node_id) = doc_to_code_node.get(&(doc_id, segment_index)) else {
            return (0.0, 0);
        };
        let Some(hop) = distances.get(node_id).copied() else {
            return (0.0, 0);
        };
        (score_for_hop(hop), hop)
    }))
}

pub(crate) fn warm_graph_node_count(state: &ProjectionState, tenant_hash: u64) -> usize {
    let edge_types = default_codegraph_fusion_edge_types();
    tenant_code_adjacency(state, tenant_hash, &edge_types).len()
}

fn tenant_code_adjacency(
    state: &ProjectionState,
    tenant_hash: u64,
    edge_types: &BTreeSet<RelationTypeV1>,
) -> BTreeMap<u32, BTreeSet<u32>> {
    let mut adjacency: BTreeMap<u32, BTreeSet<u32>> = BTreeMap::new();
    let start = (tenant_hash, 0u32, 0u32, 0u8);
    let end = (tenant_hash, u32::MAX, u32::MAX, u8::MAX);
    for ((_tenant, src, dst, rt), _edge) in state.relations.range(start..=end) {
        let Some(relation_type) = RelationTypeV1::from_u8(*rt) else {
            continue;
        };
        if !edge_types.contains(&relation_type) {
            continue;
        }
        adjacency.entry(*src).or_default().insert(*dst);
        adjacency.entry(*dst).or_default().insert(*src);
    }
    adjacency
}

fn bfs_distances(adjacency: &BTreeMap<u32, BTreeSet<u32>>, seeds: &BTreeSet<u32>, max_hops: u32) -> BTreeMap<u32, u32> {
    let mut distances = BTreeMap::new();
    let mut queue = VecDeque::new();
    for seed in seeds {
        distances.insert(*seed, 0);
        queue.push_back((*seed, 0));
    }
    while let Some((node, hop)) = queue.pop_front() {
        if hop >= max_hops {
            continue;
        }
        let Some(neighbors) = adjacency.get(&node) else {
            continue;
        };
        for neighbor in neighbors {
            if distances.contains_key(neighbor) {
                continue;
            }
            let next_hop = hop + 1;
            distances.insert(*neighbor, next_hop);
            queue.push_back((*neighbor, next_hop));
        }
    }
    distances
}

fn score_for_hop(hop: u32) -> f32 {
    if hop == 0 {
        1.0
    } else {
        1.0 / (hop as f32 + 1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use corecrux_index::CcxiBuilder;
    use corecrux_projections::{quantize_confidence_q16, tenant_hash_xxhash64, RelationEdgeV1};
    use corecrux_retrieval::fused::{fused_retrieve, FusedRetrieveRequest, FusionWeights};
    use corecrux_retrieval::IndexManager;

    fn test_index(tenant_hash: u64) -> IndexManager {
        let mut builder = CcxiBuilder::new(0, 1, 100);
        builder.add_document(0, "alpha alpha alpha seed caller", 0, tenant_hash);
        builder.add_document(1, "alpha neighbor callee", 100, tenant_hash);
        builder.add_document(2, "alpha alpha unrelated", 200, tenant_hash);
        let bytes = builder.build();
        let mut mgr = IndexManager::new();
        mgr.load_ccxi_bytes(&bytes).expect("load ccxi");
        mgr
    }

    fn request(graph_node_count: usize) -> FusedRetrieveRequest {
        FusedRetrieveRequest {
            tenant_id: "tenant-codegraph".to_string(),
            query: "alpha".to_string(),
            query_embedding: None,
            top_k: 3,
            weights: FusionWeights {
                bm25: 0.4,
                graph: 0.6,
                dense: 0.0,
                sparse: 0.0,
            },
            graph_hops: 2,
            min_confidence: 0.0,
            include_state: false,
            graph_node_count,
            graph_cold_start_threshold: 100,
        }
    }

    fn state_with_call_edge(tenant_hash: u64) -> ProjectionState {
        let mut state = ProjectionState::default();
        state.relations.insert(
            (tenant_hash, 10, 20, RelationTypeV1::Calls.to_u8()),
            RelationEdgeV1 {
                confidence_q16: quantize_confidence_q16(1.0),
                evidence_ref_hash16: [0u8; 16],
                created_at_micros: 1,
                updated_at_micros: 1,
            },
        );
        state
    }

    #[test]
    fn codegraph_boost_reorders_neighbor_above_unrelated_baseline() {
        let tenant_hash = tenant_hash_xxhash64("tenant-codegraph");
        let mgr = test_index(tenant_hash);
        let baseline = fused_retrieve(&mgr, &request(1_000), None, None).expect("baseline fused");
        let baseline_docs: Vec<u32> = baseline.results.iter().map(|hit| hit.doc_id).collect();
        assert!(
            baseline_docs.iter().position(|doc| *doc == 2) < baseline_docs.iter().position(|doc| *doc == 1),
            "without graph boost, unrelated doc C should rank above neighbor doc B by BM25"
        );

        let mut doc_to_code_node = BTreeMap::new();
        doc_to_code_node.insert((0, 0), 10);
        doc_to_code_node.insert((1, 0), 20);
        doc_to_code_node.insert((2, 0), 30);
        let state = state_with_call_edge(tenant_hash);
        assert_eq!(warm_graph_node_count(&state, tenant_hash), 2);
        let boost = build_codegraph_boost_fn(
            &state,
            CodeGraphBoostInput {
                tenant_hash,
                doc_to_code_node,
                seed_code_nodes: [10].into_iter().collect(),
                max_hops: 2,
                edge_types: default_codegraph_fusion_edge_types(),
            },
        )
        .expect("boost closure");
        assert_eq!(boost(1, 0), (0.5, 1));
        assert_eq!(boost(2, 0), (0.0, 0));

        let boosted = fused_retrieve(&mgr, &request(1_000), Some(&boost), None).expect("boosted fused");
        let boosted_docs: Vec<u32> = boosted.results.iter().map(|hit| hit.doc_id).collect();
        assert!(
            boosted_docs.iter().position(|doc| *doc == 1) < boosted_docs.iter().position(|doc| *doc == 2),
            "with codegraph boost, calls-neighbor doc B should rank above unrelated doc C"
        );
        let b = boosted.results.iter().find(|hit| hit.doc_id == 1).expect("doc B");
        assert_eq!(b.hop_distance, 1);
        assert!(b.score_breakdown.graph > 0.0);
    }

    #[test]
    fn codegraph_fusion_flag_defaults_off() {
        std::env::remove_var(CODEGRAPH_FUSION_ENV);
        assert!(!enabled_from_env());
    }
}
