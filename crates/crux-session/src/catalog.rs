// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Built-in capability catalog.
//!
//! The catalog lists every capability the CueCrux platform surfaces. Each
//! entry declares the required affinity tag, minimum tier, cost class, and
//! the local + Core `impl_path`. The generator at [`crate::generator`] filters
//! this catalog per passport.
//!
//! This module is the single source of truth for what capabilities exist.
//! When adding a new capability to the platform, add it here; the generator
//! picks it up automatically on both Crux Daemon and hosted.

use crate::plan::{Capability, ImplPath};

/// Static description of a catalog entry. Expanded into a [`Capability`] by
/// the generator after per-passport filtering.
#[derive(Debug, Clone)]
pub struct CatalogEntry {
    pub cap: &'static str,
    pub affinity: &'static str,
    pub prefer_bulk: bool,
    pub shape: &'static str,
    pub min_tier: Option<&'static str>,
    pub cost_class: &'static str,
    pub ce_path: Option<&'static str>,
    pub core_path: Option<&'static str>,
    /// Feature flag that must be enabled for this capability to be surfaced.
    /// `None` = always enabled.
    pub feature_flag: Option<&'static str>,
}

impl CatalogEntry {
    pub fn to_capability(&self, prefer_bulk_mode: bool) -> Capability {
        let prefer = if self.prefer_bulk && prefer_bulk_mode {
            "bulk"
        } else {
            "mcp"
        };
        Capability {
            cap: self.cap.to_string(),
            prefer: prefer.to_string(),
            shape: self.shape.to_string(),
            min_tier: self.min_tier.map(String::from),
            cost_class: self.cost_class.to_string(),
            impl_path: ImplPath {
                ce: self.ce_path.map(String::from),
                core: self.core_path.map(String::from),
            },
        }
    }
}

/// The built-in catalog.
///
/// Affinity tags in use: `retrieval`, `proof`, `audit`, `memory`, `economy`,
/// `session`, `journal`.
pub const DEFAULT_CATALOG: &[CatalogEntry] = &[
    CatalogEntry {
        cap: "retrieve",
        affinity: "retrieval",
        prefer_bulk: true,
        shape: "stream<Chunk>",
        min_tier: Some("free"),
        cost_class: "metered",
        ce_path: Some("retrieve_local"),
        core_path: Some("/v2/retrieve"),
        feature_flag: None,
    },
    CatalogEntry {
        cap: "session_context",
        affinity: "session",
        prefer_bulk: true,
        shape: "Snapshot",
        min_tier: None,
        cost_class: "free",
        ce_path: Some("session_ctx_local"),
        core_path: Some("/v2/session/context"),
        feature_flag: None,
    },
    CatalogEntry {
        cap: "journal_append",
        affinity: "journal",
        prefer_bulk: false,
        shape: "Receipt",
        min_tier: None,
        cost_class: "free",
        ce_path: Some("journal_local"),
        core_path: Some("/mcp/vault#journal_append"),
        feature_flag: None,
    },
    CatalogEntry {
        cap: "journal_stream",
        affinity: "journal",
        prefer_bulk: true,
        shape: "stream<Event>",
        min_tier: Some("starter"),
        cost_class: "free",
        ce_path: Some("journal_stream_local"),
        core_path: Some("/v2/journal/stream"),
        feature_flag: None,
    },
    CatalogEntry {
        cap: "proof_document",
        affinity: "proof",
        prefer_bulk: true,
        shape: "Receipt",
        min_tier: Some("starter"),
        cost_class: "heavy",
        ce_path: Some("proof_local"),
        core_path: Some("/v2/proof"),
        feature_flag: None,
    },
    CatalogEntry {
        cap: "proof_verify",
        affinity: "proof",
        prefer_bulk: false,
        shape: "VerifyResult",
        min_tier: None,
        cost_class: "free",
        ce_path: Some("proof_verify_local"),
        core_path: Some("/mcp/vault#proof_verify"),
        feature_flag: None,
    },
    CatalogEntry {
        cap: "annotation_add",
        affinity: "memory",
        prefer_bulk: false,
        shape: "Receipt",
        min_tier: Some("free"),
        cost_class: "free",
        ce_path: Some("annotation_local"),
        core_path: Some("/mcp/vault#annotation_add"),
        feature_flag: None,
    },
    CatalogEntry {
        cap: "memory_get",
        affinity: "memory",
        prefer_bulk: true,
        shape: "Snapshot",
        min_tier: Some("free"),
        cost_class: "free",
        ce_path: Some("memory_get_local"),
        core_path: Some("/v2/memory/get"),
        feature_flag: None,
    },
    CatalogEntry {
        cap: "memory_put",
        affinity: "memory",
        prefer_bulk: false,
        shape: "Receipt",
        min_tier: Some("free"),
        cost_class: "metered",
        ce_path: Some("memory_put_local"),
        core_path: Some("/mcp/memory#put"),
        feature_flag: None,
    },
    CatalogEntry {
        cap: "audit_replay",
        affinity: "audit",
        prefer_bulk: true,
        shape: "stream<Event>",
        min_tier: Some("pro"),
        cost_class: "heavy",
        ce_path: Some("audit_replay_local"),
        core_path: Some("/v2/audit/replay"),
        feature_flag: None,
    },
    CatalogEntry {
        cap: "get_counterfactual_summary",
        affinity: "audit",
        prefer_bulk: false,
        shape: "Report",
        min_tier: Some("pro"),
        cost_class: "heavy",
        ce_path: None,
        core_path: Some("/mcp/audit#get_counterfactual_summary"),
        feature_flag: None,
    },
    CatalogEntry {
        cap: "economy_quote",
        affinity: "economy",
        prefer_bulk: false,
        shape: "Quote",
        min_tier: Some("starter"),
        cost_class: "free",
        ce_path: None,
        core_path: Some("/mcp/economy#quote"),
        feature_flag: None,
    },
    CatalogEntry {
        cap: "economy_spend",
        affinity: "economy",
        prefer_bulk: false,
        shape: "Receipt",
        min_tier: Some("team"),
        cost_class: "metered",
        ce_path: None,
        core_path: Some("/mcp/economy#spend"),
        feature_flag: None,
    },
];

/// Ordered list of tier names, lowest to highest. Used by the tier filter.
pub const TIER_ORDER: &[&str] = &["local", "free", "starter", "pro", "team", "enterprise"];

pub fn tier_rank(tier: &str) -> Option<usize> {
    TIER_ORDER.iter().position(|t| *t == tier)
}

pub fn tier_meets(actual: &str, required: &str) -> bool {
    match (tier_rank(actual), tier_rank(required)) {
        (Some(a), Some(r)) => a >= r,
        _ => false,
    }
}
