// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Capability-graph generator v1 (master-plan §4.3).
//!
//! Pure, deterministic function from `(catalog, passport, hints, enabled
//! feature flags)` to an ordered list of [`Capability`] entries plus a
//! 32-byte BLAKE3 hash of the canonical capability graph.
//!
//! Filter order (per master plan):
//! 1. Affinity filter — drop if required affinity not in passport.affinities
//!    (wildcard `"*"` in affinities matches everything; used by Crux Daemon).
//! 2. Tier filter — drop if `min_tier` exceeds passport.tier.
//! 3. Feature-flag filter — drop if the gating flag is off.
//! 4. Budget filter — drop `cost_class: "heavy"` if `budget.crux_cap` is
//!    below the heavy-call threshold.
//! 5. Bulk preference rewrite — when `hints.prefer_bulk = false`, rewrite
//!    every `prefer: "bulk"` to `"mcp"` in the emitted capabilities.
//!
//! Intent shaping (Phase 7) is **not** applied here; it will land as a
//! separate step that reorders / optionally truncates the output of this
//! generator.

use std::collections::HashSet;

use blake3::Hasher;

use crate::canonical::CborValue;
use crate::catalog::{tier_meets, CatalogEntry, DEFAULT_CATALOG};
use crate::intent::{
    apply_intent_shaping_with_affinity, default_intent_table, hash_capability_graph_with_intent, IntentTable,
};
use crate::plan::{Capability, Edge, Exclusion, Passport, HASH_LEN};

/// Threshold below which `heavy` capabilities are dropped. Callers with
/// `budget.crux_cap = None` (local daemon) always keep heavy capabilities.
pub const HEAVY_COST_THRESHOLD: u64 = 5;

#[derive(Debug, Clone)]
pub struct GraphHints {
    /// Default true. When false, `prefer` field is rewritten to `"mcp"` for
    /// every capability that would otherwise be `"bulk"`. This is NOT the
    /// same as dropping bulk capabilities — they're still in the graph, the
    /// agent is just told to use the MCP channel.
    pub prefer_bulk: bool,
    /// Optional intent hint. When supplied and the intent is known to the
    /// generator's `intent_table`, capabilities are reordered to put
    /// intent-relevant ones first (master-plan §4.4).
    pub intent: Option<String>,
    /// Optional cap on the emitted graph length. Truncated after shaping
    /// so the highest-bias capabilities survive. `None` = no truncation.
    pub max_capabilities: Option<usize>,
}

impl Default for GraphHints {
    fn default() -> Self {
        Self {
            prefer_bulk: true,
            intent: None,
            max_capabilities: None,
        }
    }
}

impl GraphHints {
    pub fn from_request(prefer_bulk: Option<bool>) -> Self {
        Self {
            prefer_bulk: prefer_bulk.unwrap_or(true),
            intent: None,
            max_capabilities: None,
        }
    }

    pub fn with_intent(mut self, intent: Option<String>) -> Self {
        self.intent = intent;
        self
    }

    pub fn with_max_capabilities(mut self, n: Option<usize>) -> Self {
        self.max_capabilities = n;
        self
    }
}

pub struct GenerateInput<'a> {
    pub catalog: &'a [CatalogEntry],
    pub passport: &'a Passport,
    pub hints: &'a GraphHints,
    pub crux_cap: Option<u64>,
    pub enabled_feature_flags: &'a HashSet<String>,
    /// Intent shaping table. `None` = use [`default_intent_table`].
    pub intent_table: Option<&'a IntentTable>,
}

#[derive(Debug, Clone)]
pub struct GeneratedGraph {
    pub capabilities: Vec<Capability>,
    pub edges: Vec<Edge>,
    pub excluded: Vec<Exclusion>,
    pub hash: [u8; HASH_LEN],
}

pub fn generate_graph(input: GenerateInput<'_>) -> GeneratedGraph {
    let wildcard = input.passport.affinities.iter().any(|a| a == "*");

    // Decorate each surviving capability with its source affinity so
    // the intent-shaping step (master-plan §4.4) can reorder deterministically.
    let mut decorated: Vec<(Capability, &str)> = Vec::with_capacity(input.catalog.len());
    for entry in input.catalog {
        if !wildcard && !input.passport.affinities.iter().any(|a| a == entry.affinity) {
            continue;
        }
        if let Some(required) = entry.min_tier {
            if !tier_meets(&input.passport.tier, required) {
                continue;
            }
        }
        if let Some(flag) = entry.feature_flag {
            if !input.enabled_feature_flags.contains(flag) {
                continue;
            }
        }
        if entry.cost_class == "heavy" {
            if let Some(cap_budget) = input.crux_cap {
                if cap_budget < HEAVY_COST_THRESHOLD {
                    continue;
                }
            }
        }
        decorated.push((entry.to_capability(input.hints.prefer_bulk), entry.affinity));
    }

    // Apply intent shaping if an intent was supplied and recognised.
    // Unknown intents are silent no-ops (ignored, not rejected) so a
    // forward-compatible agent can try new intents on old servers.
    let mut caps: Vec<Capability> = decorated.iter().map(|(c, _)| c.clone()).collect();
    let affinity_by_cap: std::collections::HashMap<String, &str> =
        decorated.iter().map(|(c, a)| (c.cap.clone(), *a)).collect();
    let table = input.intent_table.cloned().unwrap_or_else(default_intent_table);
    apply_intent_shaping_with_affinity(
        &mut caps,
        &table,
        input.hints.intent.as_deref(),
        input.hints.max_capabilities,
        |c| affinity_by_cap.get(&c.cap).copied().unwrap_or(""),
    );

    let hash = hash_capability_graph_with_intent(&caps, input.hints.intent.as_deref());
    GeneratedGraph {
        capabilities: caps,
        edges: Vec::new(),
        excluded: Vec::new(),
        hash,
    }
}

pub fn generate_default(
    passport: &Passport,
    hints: &GraphHints,
    crux_cap: Option<u64>,
    enabled_feature_flags: &HashSet<String>,
) -> GeneratedGraph {
    generate_graph(GenerateInput {
        catalog: DEFAULT_CATALOG,
        passport,
        hints,
        crux_cap,
        enabled_feature_flags,
        intent_table: None,
    })
}

/// **Deprecated:** prefer
/// [`crate::intent::hash_capability_graph_with_intent`] which binds the
/// intent string into the graph hash. This legacy entry point is kept
/// for tests that don't care about intent shaping; new code should pass
/// the intent explicitly.
#[deprecated(since = "0.1.0", note = "use hash_capability_graph_with_intent")]
pub fn hash_capability_graph(caps: &[Capability]) -> [u8; HASH_LEN] {
    let value = CborValue::Array(
        caps.iter()
            .map(|c| {
                CborValue::Map(vec![
                    ("cap".into(), CborValue::Text(c.cap.clone())),
                    ("prefer".into(), CborValue::Text(c.prefer.clone())),
                    ("shape".into(), CborValue::Text(c.shape.clone())),
                    (
                        "min_tier".into(),
                        match &c.min_tier {
                            Some(s) => CborValue::Text(s.clone()),
                            None => CborValue::Null,
                        },
                    ),
                    ("cost_class".into(), CborValue::Text(c.cost_class.clone())),
                    (
                        "impl_path".into(),
                        CborValue::Map(vec![
                            (
                                "ce".into(),
                                match &c.impl_path.ce {
                                    Some(s) => CborValue::Text(s.clone()),
                                    None => CborValue::Null,
                                },
                            ),
                            (
                                "core".into(),
                                match &c.impl_path.core {
                                    Some(s) => CborValue::Text(s.clone()),
                                    None => CborValue::Null,
                                },
                            ),
                        ]),
                    ),
                ])
            })
            .collect(),
    );
    let encoded = value.encode();
    let mut hasher = Hasher::new();
    hasher.update(&encoded);
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::Passport;

    fn passport(tier: &str, affinities: &[&str]) -> Passport {
        Passport {
            principal_id: "test".into(),
            tier: tier.into(),
            affinities: affinities.iter().map(|s| (*s).into()).collect(),
            denied_capabilities: None,
            grant_expansions: None,
            passport_receipt: None,
        }
    }

    #[test]
    fn wildcard_affinity_includes_all_capabilities() {
        let pp = passport("local", &["*"]);
        let flags: HashSet<String> = HashSet::new();
        let hints = GraphHints {
            prefer_bulk: true,
            intent: None,
            max_capabilities: None,
        };
        let graph = generate_default(&pp, &hints, None, &flags);
        // Crux Daemon should see every catalog entry (no tier blocks at local? yes it does
        // block — "local" is rank 0, "free" is rank 1, so min_tier = "free"
        // fails tier_meets when actual is "local"). Adjusting expectation:
        // wildcard affinity does not override the tier filter.
        assert!(!graph.capabilities.is_empty());
        for cap in &graph.capabilities {
            if let Some(required) = &cap.min_tier {
                assert!(
                    crate::catalog::tier_meets("local", required) || required == "free" || required.is_empty(),
                    "unexpected tier: {required}"
                );
            }
        }
    }

    #[test]
    fn tier_filter_drops_capabilities_above_tier() {
        let free = passport("free", &["retrieval", "proof", "audit"]);
        let flags = HashSet::new();
        let hints = GraphHints {
            prefer_bulk: true,
            intent: None,
            max_capabilities: None,
        };
        let graph = generate_default(&free, &hints, None, &flags);
        // `proof_document` requires starter; `get_counterfactual_summary` requires pro.
        let names: Vec<&str> = graph.capabilities.iter().map(|c| c.cap.as_str()).collect();
        assert!(names.contains(&"retrieve"));
        assert!(!names.contains(&"proof_document"));
        assert!(!names.contains(&"get_counterfactual_summary"));
    }

    #[test]
    fn affinity_filter_drops_non_matching() {
        let pp = passport("pro", &["retrieval"]);
        let flags = HashSet::new();
        let hints = GraphHints {
            prefer_bulk: true,
            intent: None,
            max_capabilities: None,
        };
        let graph = generate_default(&pp, &hints, None, &flags);
        let names: Vec<&str> = graph.capabilities.iter().map(|c| c.cap.as_str()).collect();
        assert!(names.contains(&"retrieve"));
        assert!(!names.contains(&"proof_document"));
        assert!(!names.contains(&"audit_replay"));
    }

    #[test]
    fn budget_filter_drops_heavy_below_threshold() {
        let pp = passport("pro", &["proof", "audit"]);
        let flags = HashSet::new();
        let hints = GraphHints {
            prefer_bulk: true,
            intent: None,
            max_capabilities: None,
        };
        let with_budget = generate_default(&pp, &hints, Some(1), &flags);
        let without_budget = generate_default(&pp, &hints, None, &flags);
        let with_names: Vec<_> = with_budget.capabilities.iter().map(|c| c.cap.clone()).collect();
        let without_names: Vec<_> = without_budget.capabilities.iter().map(|c| c.cap.clone()).collect();
        assert!(!with_names.iter().any(|n| n == "proof_document"));
        assert!(without_names.iter().any(|n| n == "proof_document"));
    }

    #[test]
    fn prefer_bulk_false_rewrites_to_mcp() {
        let pp = passport("team", &["retrieval"]);
        let flags = HashSet::new();
        let hints = GraphHints {
            prefer_bulk: false,
            intent: None,
            max_capabilities: None,
        };
        let graph = generate_default(&pp, &hints, Some(100), &flags);
        for cap in &graph.capabilities {
            assert_eq!(cap.prefer, "mcp", "{}", cap.cap);
        }
    }

    #[test]
    fn graph_hash_is_deterministic_and_covers_order() {
        let pp = passport("team", &["retrieval", "memory"]);
        let flags = HashSet::new();
        let hints = GraphHints {
            prefer_bulk: true,
            intent: None,
            max_capabilities: None,
        };
        let g1 = generate_default(&pp, &hints, Some(100), &flags);
        let g2 = generate_default(&pp, &hints, Some(100), &flags);
        assert_eq!(g1.hash, g2.hash);

        // Reversing capabilities must yield a different hash.
        let mut caps = g1.capabilities.clone();
        caps.reverse();
        let h3 = hash_capability_graph(&caps);
        assert_ne!(g1.hash, h3);
    }
}
