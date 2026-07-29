// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Metered service scopes + upgrade hints (ExecPlan
//! `dense-lane-and-extraction-upsell-2026-06-26`, M3).
//!
//! The free, local capabilities — BM25, graph, and **local dense search** — are
//! ungated and carry NO scope here. Only CueCrux-serviced, metered value-add
//! capabilities (better dense + extraction over already-ingested data) are
//! scoped. When one of those is denied, [`upgrade_hint`] produces a structured
//! upsell so the caller sees a clear path to Pro/Compliance rather than an opaque
//! denial. Constraint C4: we meter only CueCrux-side compute; local retrieval is
//! never gated through these scopes.

use serde_json::{json, Value};

/// Metered "better dense" service: reranking over fused results.
pub const SCOPE_DENSE_RERANK: &str = "crux-mcp.dense_rerank";
/// Metered "better dense" service: CueCrux-hosted / superior embeddings.
pub const SCOPE_DENSE_MANAGED: &str = "crux-mcp.dense_managed";
/// Metered extraction: entity extraction over ingested data.
pub const SCOPE_EXTRACT_ENTITIES: &str = "crux-mcp.extract_entities";
/// Metered extraction: relation extraction over ingested data.
pub const SCOPE_EXTRACT_RELATIONS: &str = "crux-mcp.extract_relations";
/// Metered extraction: fact distillation over ingested data.
pub const SCOPE_EXTRACT_FACTS: &str = "crux-mcp.extract_facts";

/// All metered service scopes. The free local lanes (BM25, graph, dense search)
/// are intentionally absent — they are never gated by a scope.
pub const SERVICE_SCOPES: &[&str] = &[
    SCOPE_DENSE_RERANK,
    SCOPE_DENSE_MANAGED,
    SCOPE_EXTRACT_ENTITIES,
    SCOPE_EXTRACT_RELATIONS,
    SCOPE_EXTRACT_FACTS,
];

/// True if `capability` is a metered CueCrux service (not a free local lane).
pub fn is_service_scope(capability: &str) -> bool {
    SERVICE_SCOPES.contains(&capability)
}

/// Structured upsell for a denied metered service capability.
///
/// Returns `None` for any non-service capability: ordinary capability denials are
/// not upsell moments, and free local dense/BM25/graph are never routed here.
pub fn upgrade_hint(capability: &str) -> Option<Value> {
    let (tier, unlocks) = match capability {
        SCOPE_DENSE_RERANK => ("pro", "reranked results (bge-reranker-v2-m3) over your fused matches"),
        SCOPE_DENSE_MANAGED => (
            "pro",
            "CueCrux-hosted superior embeddings (BGE-M3) for your ingested data",
        ),
        SCOPE_EXTRACT_ENTITIES => ("pro", "LLM entity extraction that auto-populates your knowledge graph"),
        SCOPE_EXTRACT_RELATIONS => ("pro", "LLM relation extraction that links entities in your graph"),
        SCOPE_EXTRACT_FACTS => ("pro", "LLM fact distillation from your raw ingested data"),
        _ => return None,
    };
    Some(json!({
        "kind": "upgrade_available",
        "capability": capability,
        "tier": tier,
        "unlocks": unlocks,
        "metering": "metered on CueCrux-side compute only",
        "still_free": "local BM25 + graph + dense search remain fully available, uncapped",
        "deploy": "available managed or in-boundary (compliance-grade)",
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_scopes_are_recognised() {
        for s in SERVICE_SCOPES {
            assert!(is_service_scope(s), "{s} should be a service scope");
            assert!(upgrade_hint(s).is_some(), "{s} should yield an upgrade hint");
        }
    }

    #[test]
    fn free_local_capabilities_are_not_scoped() {
        // The free local lanes and ordinary tools must NOT be treated as metered
        // services — no scope, no upgrade hint.
        for cap in [
            "crux-mcp.query_facts",
            "crux-mcp.store_fact",
            "facts:read",
            "crux-mcp.dense_search", // hypothetical local dense tool — stays free
        ] {
            assert!(!is_service_scope(cap), "{cap} must not be a service scope");
            assert!(upgrade_hint(cap).is_none(), "{cap} must not yield an upgrade hint");
        }
    }

    #[test]
    fn upgrade_hint_shape_names_free_alternative() {
        let h = upgrade_hint(SCOPE_DENSE_RERANK).unwrap();
        assert_eq!(h["kind"], "upgrade_available");
        assert_eq!(h["tier"], "pro");
        // The hint must always reassure that local retrieval stays free (C1/C4).
        assert!(h["still_free"].as_str().unwrap().contains("uncapped"));
        assert!(h["metering"].as_str().unwrap().contains("CueCrux-side"));
    }
}
