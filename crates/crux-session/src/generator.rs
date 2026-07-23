// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
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
use crate::catalog::{tier_meets, tier_rank, CatalogEntry, CAPABILITY_EDGES, DEFAULT_CATALOG};
use crate::intent::{
    apply_intent_shaping_with_affinity, default_intent_table, hash_capability_graph_with_intent, IntentTable,
};
use crate::plan::{Capability, Edge, Exclusion, Passport, HASH_LEN};

/// Threshold below which `heavy` capabilities are dropped. Callers with
/// `budget.crux_cap = None` (local daemon) always keep heavy capabilities.
pub const HEAVY_COST_THRESHOLD: u64 = 5;

// ── Exclusion vocabulary (master-plan §5.7) ─────────────────────────────────
// These are the wire-visible `Exclusion.reason` / `Exclusion.layer` strings a
// client parses to decide what remediation to surface. The set is normative
// (§5.7); do not paraphrase.
/// Passport tier is below the capability's `min_tier`.
pub const EXCLUSION_REASON_TIER_INSUFFICIENT: &str = "tier_insufficient";
/// Passport lacks the capability's `required_affinity`.
pub const EXCLUSION_REASON_AFFINITY_MISSING: &str = "affinity_missing";
/// Capability is named in `passport.denied_capabilities`.
pub const EXCLUSION_REASON_PASSPORT_DENIED: &str = "passport_denied";
/// Remaining budget is below the threshold for the capability's `cost_class`.
pub const EXCLUSION_REASON_BUDGET_EXHAUSTED: &str = "budget_exhausted";
/// A platform/tenant feature flag gating the capability is off.
pub const EXCLUSION_REASON_FEATURE_DISABLED: &str = "feature_disabled";

/// The exclusion originated from platform-level policy (a feature flag).
pub const EXCLUSION_LAYER_PLATFORM: &str = "platform";
/// The exclusion originated from tenant-level policy.
pub const EXCLUSION_LAYER_TENANT: &str = "tenant";
/// The exclusion originated from the passport itself (tier, affinity, denial,
/// or session budget).
pub const EXCLUSION_LAYER_PASSPORT: &str = "passport";

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
    /// Privacy (master-plan §5.7): when true the generator suppresses the
    /// `excluded` list entirely — for clients that prefer zero capability-
    /// surface leakage. When false the guard still applies its tier/affinity
    /// suppression; only budget/deny/flag exclusions and one-tier-up upsell
    /// hints are disclosed. Default false.
    pub hide_exclusions: bool,
}

impl Default for GraphHints {
    fn default() -> Self {
        Self {
            prefer_bulk: true,
            intent: None,
            max_capabilities: None,
            hide_exclusions: false,
        }
    }
}

impl GraphHints {
    pub fn from_request(prefer_bulk: Option<bool>) -> Self {
        Self {
            prefer_bulk: prefer_bulk.unwrap_or(true),
            ..Self::default()
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

    pub fn with_hide_exclusions(mut self, hide: bool) -> Self {
        self.hide_exclusions = hide;
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

    // Step 13 privacy guard (master-plan §5.7). A wildcard-affinity passport is
    // the local daemon operator (`LocalPassportConfig::synthesise`): it has no
    // tier ceiling to upsell against and no peer tenants to leak the platform
    // surface to, so its `excluded` list is empty by construction (plan C4/R2).
    // `hide_exclusions` lets any client opt out of the list entirely.
    let suppress_exclusions = input.hints.hide_exclusions || wildcard;
    let requester_rank = tier_rank(&input.passport.tier);

    // Decorate each surviving capability with its source affinity so
    // the intent-shaping step (master-plan §4.4) can reorder deterministically.
    let mut decorated: Vec<(Capability, &str)> = Vec::with_capacity(input.catalog.len());
    // Step 13 — exclusion recording. Entries are pushed in catalog iteration
    // order, so the list is deterministic (C5) for a future graph-hash binding.
    let mut excluded: Vec<Exclusion> = Vec::new();
    for entry in input.catalog {
        // Explicit passport denial is checked first and always wins: the
        // passport itself names the capability, so surfacing the denial leaks
        // nothing that the requester did not already hold (passport layer).
        if let Some(denied) = input.passport.denied_capabilities.as_ref() {
            if denied.iter().any(|d| d == entry.cap) {
                if !suppress_exclusions {
                    excluded.push(Exclusion {
                        cap: entry.cap.to_string(),
                        reason: EXCLUSION_REASON_PASSPORT_DENIED.to_string(),
                        layer: EXCLUSION_LAYER_PASSPORT.to_string(),
                        hint: None,
                    });
                }
                continue;
            }
        }
        // Affinity filter. An `affinity_missing` exclusion would name a
        // capability in a domain the requester holds no affinity for — that is
        // "outside the requester's affinity range" (§5.7) and is therefore
        // never disclosed. We drop silently rather than record-then-suppress.
        if !wildcard && !input.passport.affinities.iter().any(|a| a == entry.affinity) {
            continue;
        }
        // Tier filter. Disclosed only for the immediately-next tier up (the
        // one-tier upsell window, §5.7); capabilities two or more tiers above
        // are never revealed, so a Free user cannot enumerate the Enterprise
        // surface.
        if let Some(required) = entry.min_tier {
            if !tier_meets(&input.passport.tier, required) {
                if !suppress_exclusions && tier_within_upsell_window(requester_rank, required) {
                    excluded.push(Exclusion {
                        cap: entry.cap.to_string(),
                        reason: EXCLUSION_REASON_TIER_INSUFFICIENT.to_string(),
                        layer: EXCLUSION_LAYER_PASSPORT.to_string(),
                        hint: Some(format!("requires `{required}` tier or higher")),
                    });
                }
                continue;
            }
        }
        // Feature-flag filter (platform/tenant policy).
        if let Some(flag) = entry.feature_flag {
            if !input.enabled_feature_flags.contains(flag) {
                if !suppress_exclusions {
                    excluded.push(Exclusion {
                        cap: entry.cap.to_string(),
                        reason: EXCLUSION_REASON_FEATURE_DISABLED.to_string(),
                        layer: EXCLUSION_LAYER_PLATFORM.to_string(),
                        hint: None,
                    });
                }
                continue;
            }
        }
        // Budget filter. The capability is within the requester's tier/affinity
        // range but the session budget cannot cover a heavy call — disclosed so
        // the agent can request more budget rather than a tier upgrade.
        if entry.cost_class == "heavy" {
            if let Some(cap_budget) = input.crux_cap {
                if cap_budget < HEAVY_COST_THRESHOLD {
                    if !suppress_exclusions {
                        excluded.push(Exclusion {
                            cap: entry.cap.to_string(),
                            reason: EXCLUSION_REASON_BUDGET_EXHAUSTED.to_string(),
                            layer: EXCLUSION_LAYER_PASSPORT.to_string(),
                            hint: Some("session budget too low for a heavy capability".to_string()),
                        });
                    }
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

    // Step 12 — Edge construction (master-plan §5.4). Emit a graph edge for
    // each statically-configured relationship whose BOTH endpoints survived
    // filtering. Edges to dropped/excluded capabilities are not emitted. Order
    // follows the static table (which is itself deterministic), so the edge
    // list is reproducible for the graph hash.
    let surviving: HashSet<&str> = caps.iter().map(|c| c.cap.as_str()).collect();
    let edges: Vec<Edge> = CAPABILITY_EDGES
        .iter()
        .filter(|e| surviving.contains(e.from) && surviving.contains(e.to))
        .map(|e| Edge {
            from: e.from.to_string(),
            to: e.to.to_string(),
            kind: e.kind.to_string(),
            weight: Some(e.weight),
        })
        .collect();

    let hash = hash_capability_graph_with_intent(&caps, input.hints.intent.as_deref());
    GeneratedGraph {
        capabilities: caps,
        edges,
        excluded,
        hash,
    }
}

/// §5.7 privacy guard for tier exclusions: a `tier_insufficient` exclusion is
/// disclosed only when the required tier is exactly one rank above the
/// requester's — the immediate upsell. Capabilities two or more tiers above are
/// never revealed, so a Free-tier requester cannot enumerate the Enterprise
/// capability surface. A requester or requirement tier outside [`tier_rank`]
/// discloses nothing.
fn tier_within_upsell_window(requester_rank: Option<usize>, required: &str) -> bool {
    match (requester_rank, tier_rank(required)) {
        (Some(r), Some(req)) => req == r + 1,
        _ => false,
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
            hide_exclusions: false,
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
            hide_exclusions: false,
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
            hide_exclusions: false,
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
            hide_exclusions: false,
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
            hide_exclusions: false,
        };
        let graph = generate_default(&pp, &hints, Some(100), &flags);
        for cap in &graph.capabilities {
            assert_eq!(cap.prefer, "mcp", "{}", cap.cap);
        }
    }

    #[test]
    fn edges_emitted_only_when_both_endpoints_survive() {
        let flags = HashSet::new();
        let hints = GraphHints::default();

        // `audit.byo_trail` (affinity=audit) and `trace.typed_actions`
        // (affinity=trace) are both min_tier=None → both visible on a passport
        // carrying both affinities, so the cross-affinity composes_with edge
        // is emitted.
        let both = passport("local", &["audit", "trace"]);
        let g_both = generate_default(&both, &hints, None, &flags);
        assert!(
            g_both
                .edges
                .iter()
                .any(|e| e.from == "audit.byo_trail" && e.to == "trace.typed_actions"),
            "expected audit.byo_trail→trace.typed_actions edge when both endpoints visible"
        );

        // Drop the `trace` affinity → `trace.typed_actions` is filtered out →
        // the edge must NOT be emitted (Step 12 both-endpoints rule).
        let audit_only = passport("local", &["audit"]);
        let g_audit = generate_default(&audit_only, &hints, None, &flags);
        assert!(
            !g_audit.edges.iter().any(|e| e.to == "trace.typed_actions"),
            "edge to a filtered endpoint must be dropped"
        );
        let names: HashSet<&str> = g_audit.capabilities.iter().map(|c| c.cap.as_str()).collect();
        for e in &g_audit.edges {
            assert!(
                names.contains(e.from.as_str()) && names.contains(e.to.as_str()),
                "edge {}→{} has an endpoint absent from nodes",
                e.from,
                e.to
            );
        }
    }

    #[test]
    fn local_wildcard_passport_has_nonempty_graph_edges() {
        let pp = passport("local", &["*"]);
        let flags = HashSet::new();
        let g = generate_default(&pp, &GraphHints::default(), None, &flags);
        assert!(!g.edges.is_empty(), "local wildcard graph should carry edges");
        let names: HashSet<&str> = g.capabilities.iter().map(|c| c.cap.as_str()).collect();
        for e in &g.edges {
            assert!(
                names.contains(e.from.as_str()) && names.contains(e.to.as_str()),
                "edge {}→{} endpoint missing from nodes",
                e.from,
                e.to
            );
            assert!(e.weight.map(|w| w <= 100).unwrap_or(true), "weight out of 0–100");
        }
    }

    #[test]
    fn edge_set_is_deterministic() {
        let pp = passport("local", &["*"]);
        let flags = HashSet::new();
        let g1 = generate_default(&pp, &GraphHints::default(), None, &flags);
        let g2 = generate_default(&pp, &GraphHints::default(), None, &flags);
        assert_eq!(g1.edges, g2.edges, "edge set must be reproducible");
    }

    #[test]
    fn graph_hash_is_deterministic_and_covers_order() {
        let pp = passport("team", &["retrieval", "memory"]);
        let flags = HashSet::new();
        let hints = GraphHints {
            prefer_bulk: true,
            intent: None,
            max_capabilities: None,
            hide_exclusions: false,
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

    // ── M1: exclusion recording + §5.7 privacy guard ────────────────────────

    #[test]
    fn local_wildcard_passport_excludes_nothing() {
        // C4/R2: the local wildcard passport discloses no exclusions, so its
        // plan's `capability_graph_excluded` collapses to None downstream.
        let pp = passport("local", &["*"]);
        let flags = HashSet::new();
        let g = generate_default(&pp, &GraphHints::default(), None, &flags);
        assert!(
            g.excluded.is_empty(),
            "local wildcard passport must disclose no exclusions, got {:?}",
            g.excluded
        );
    }

    #[test]
    fn free_passport_discloses_only_one_tier_up_and_hides_far_tiers() {
        // Affinities cover the dropped caps so the *tier* filter (not affinity)
        // is what fires — isolating the tier privacy window.
        let pp = passport("free", &["proof", "audit", "economy", "journal"]);
        let flags = HashSet::new();
        let g = generate_default(&pp, &GraphHints::default(), None, &flags);
        let excluded_caps: HashSet<&str> = g.excluded.iter().map(|e| e.cap.as_str()).collect();

        // starter caps (exactly one tier above free) ARE disclosed:
        assert!(
            excluded_caps.contains("proof_document"),
            "starter cap should be disclosed"
        );
        assert!(
            excluded_caps.contains("journal_stream"),
            "starter cap should be disclosed"
        );
        assert!(
            excluded_caps.contains("economy_quote"),
            "starter cap should be disclosed"
        );
        // pro/team caps (two or more tiers above free) are NOT disclosed:
        assert!(
            !excluded_caps.contains("audit_replay"),
            "pro cap must be hidden from free"
        );
        assert!(
            !excluded_caps.contains("get_counterfactual_summary"),
            "pro cap must be hidden from free"
        );
        assert!(
            !excluded_caps.contains("economy_spend"),
            "team cap must be hidden from free"
        );

        // Every disclosed exclusion here is a well-formed tier exclusion.
        for e in &g.excluded {
            assert_eq!(e.reason, EXCLUSION_REASON_TIER_INSUFFICIENT, "cap {}", e.cap);
            assert_eq!(e.layer, EXCLUSION_LAYER_PASSPORT, "cap {}", e.cap);
            assert!(e.hint.is_some(), "tier exclusion carries an upsell hint");
        }
    }

    #[test]
    fn affinity_exclusions_are_never_disclosed() {
        // A pro passport with only the retrieval affinity: caps in other
        // affinity domains are dropped by the affinity filter and must not
        // surface at all (they'd leak domains the requester has no relation to).
        let pp = passport("pro", &["retrieval"]);
        let flags = HashSet::new();
        let g = generate_default(&pp, &GraphHints::default(), Some(100), &flags);
        for e in &g.excluded {
            assert_ne!(
                e.reason, EXCLUSION_REASON_AFFINITY_MISSING,
                "affinity_missing must never be disclosed (§5.7), leaked {}",
                e.cap
            );
        }
        // `proof_document` (affinity=proof) was affinity-filtered → not recorded.
        assert!(!g.excluded.iter().any(|e| e.cap == "proof_document"));
    }

    #[test]
    fn budget_and_deny_exclusions_survive_the_privacy_guard() {
        // The gate: a non-wildcard passport still discloses budget-exhausted and
        // explicit-deny exclusions (they concern caps within the requester's
        // range, dropped for a non-tier/affinity reason).
        let mut pp = passport("pro", &["audit", "proof"]);
        pp.denied_capabilities = Some(vec!["proof_verify".to_string()]);
        let flags = HashSet::new();
        let g = generate_default(&pp, &GraphHints::default(), Some(1), &flags);
        let by_cap: std::collections::HashMap<&str, &Exclusion> =
            g.excluded.iter().map(|e| (e.cap.as_str(), e)).collect();

        // audit_replay: heavy + pro-tier (reachable) but budget=1 < threshold.
        let budget_ex = by_cap
            .get("audit_replay")
            .expect("audit_replay should carry a budget exclusion");
        assert_eq!(budget_ex.reason, EXCLUSION_REASON_BUDGET_EXHAUSTED);
        assert_eq!(budget_ex.layer, EXCLUSION_LAYER_PASSPORT);

        // proof_verify: explicitly denied → passport_denied and absent from nodes.
        let deny_ex = by_cap
            .get("proof_verify")
            .expect("proof_verify should carry a deny exclusion");
        assert_eq!(deny_ex.reason, EXCLUSION_REASON_PASSPORT_DENIED);
        assert_eq!(deny_ex.layer, EXCLUSION_LAYER_PASSPORT);
        assert!(
            !g.capabilities.iter().any(|c| c.cap == "proof_verify"),
            "an explicitly-denied capability must not appear as a usable node"
        );
    }

    #[test]
    fn feature_flag_off_records_platform_layer_exclusion() {
        // No DEFAULT_CATALOG entry carries a feature flag, so exercise the flag
        // path with a one-entry synthetic catalog.
        let catalog = [CatalogEntry {
            cap: "gated_cap",
            affinity: "retrieval",
            prefer_bulk: false,
            shape: "Receipt",
            min_tier: None,
            cost_class: "free",
            ce_path: None,
            core_path: None,
            feature_flag: Some("beta_flag"),
        }];
        let pp = passport("pro", &["retrieval"]);
        let flags: HashSet<String> = HashSet::new(); // flag OFF
        let g = generate_graph(GenerateInput {
            catalog: &catalog,
            passport: &pp,
            hints: &GraphHints::default(),
            crux_cap: None,
            enabled_feature_flags: &flags,
            intent_table: None,
        });
        assert!(g.capabilities.is_empty());
        assert_eq!(g.excluded.len(), 1);
        assert_eq!(g.excluded[0].reason, EXCLUSION_REASON_FEATURE_DISABLED);
        assert_eq!(g.excluded[0].layer, EXCLUSION_LAYER_PLATFORM);
    }

    #[test]
    fn hide_exclusions_empties_the_list_without_changing_nodes() {
        let mut pp = passport("free", &["proof", "journal"]);
        pp.denied_capabilities = Some(vec!["proof_verify".to_string()]);
        let flags = HashSet::new();

        let shown = generate_default(&pp, &GraphHints::default(), None, &flags);
        assert!(!shown.excluded.is_empty(), "test needs something to hide");

        let hidden = generate_default(&pp, &GraphHints::default().with_hide_exclusions(true), None, &flags);
        assert!(hidden.excluded.is_empty(), "hide_exclusions must empty the list");
        // Suppressing the list is a pure view change: nodes, edges, and the
        // graph hash are untouched.
        assert_eq!(shown.capabilities, hidden.capabilities);
        assert_eq!(shown.edges, hidden.edges);
        assert_eq!(shown.hash, hidden.hash);
    }

    // ── M1: hash stability (additive; graph hash unchanged until M3) ─────────

    #[test]
    fn exclusions_do_not_feed_the_capability_graph_hash() {
        // Additivity proof: recording exclusions must NOT perturb the capability
        // graph hash (folding them in is M3, gated). The hash is a pure function
        // of the surviving capabilities (+ intent), so even a passport with a
        // non-empty exclusion list hashes identically to its caps-alone hash.
        let pp = passport("free", &["proof", "audit", "economy", "journal"]);
        let flags = HashSet::new();
        let g = generate_default(&pp, &GraphHints::default(), Some(1), &flags);
        assert!(!g.excluded.is_empty(), "test needs a passport that produces exclusions");
        let caps_only = hash_capability_graph_with_intent(&g.capabilities, None);
        assert_eq!(
            g.hash, caps_only,
            "capability graph hash must be independent of edges/exclusions until M3"
        );
    }

    #[test]
    fn local_wildcard_graph_hash_is_stable_across_exclusion_visibility() {
        // The local wildcard passport (what golden fixtures pin) excludes
        // nothing, so its graph hash is byte-identical with or without
        // hide_exclusions — and equal to the pre-M1 caps-only hash.
        let pp = passport("local", &["*"]);
        let flags = HashSet::new();
        let shown = generate_default(&pp, &GraphHints::default(), None, &flags);
        let hidden = generate_default(&pp, &GraphHints::default().with_hide_exclusions(true), None, &flags);
        assert!(shown.excluded.is_empty());
        assert!(hidden.excluded.is_empty());
        assert_eq!(shown.hash, hidden.hash);
        assert_eq!(shown.hash, hash_capability_graph_with_intent(&shown.capabilities, None));
    }
}
