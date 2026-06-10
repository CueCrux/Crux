// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Canonical tier ladder + tier→capability mapping — the single source the
//! Crux daemon and the external MCP gateway agree on.
//!
//! B1 seeds the tier ladder + the cumulative tier→capability grants used by
//! [`crate::principal`]. B3 extends this module with the per-tool capability
//! *requirements* and the read endpoint that lets the gateway fetch the policy
//! so both sides authorize against one source of truth.

/// Reputation tiers, lowest → highest privilege. Mirrors the receipt-count
/// thresholds in [`crate::passports::resolve_tier`] and the crux-mcp
/// `tier_rank` ordering (`elite`=4 … `unverified`=0). This slice is the
/// canonical ordering both the daemon and the gateway rank against.
pub const TIER_LADDER: &[&str] = &["unverified", "basic", "established", "trusted", "elite"];

/// Numeric rank of a tier (higher = more privileged). Unknown tiers rank 0,
/// matching the crux-mcp `tier_rank` fallback.
pub fn tier_rank(tier: &str) -> u8 {
    TIER_LADDER.iter().position(|t| *t == tier).map_or(0, |i| i as u8)
}

/// Capability tokens granted to a principal at a given tier, cumulative up the
/// ladder. A mediator (the gateway) authorizes a proxied tool call against
/// these capability tokens rather than the raw tier name — which sidesteps the
/// daemon/gateway tier-vocabulary mismatch (daemon: `unverified..elite`;
/// gateway prototype: `local..admin`). The per-tool *required* capability is
/// defined in B3 (`tool_required_capability`).
pub fn capabilities_for_tier(tier: &str) -> Vec<String> {
    let rank = tier_rank(tier);
    let mut caps = vec!["tool:list".to_string()];
    if rank >= tier_rank("basic") {
        caps.push("tool:invoke:read".to_string());
    }
    if rank >= tier_rank("established") {
        caps.push("tool:invoke:side_effect".to_string());
    }
    if rank >= tier_rank("trusted") {
        caps.push("tool:invoke:metered".to_string());
    }
    if rank >= tier_rank("elite") {
        caps.push("tool:invoke:destructive".to_string());
    }
    caps
}

// ── Per-tool risk → required capability (B3: the single source) ───────────

/// Risk classes for a proxied tool, lowest → highest privilege. Each maps to
/// the capability a principal must hold to invoke a tool of that class.
pub const RISK_CLASSES: &[&str] = &["read", "side_effect", "metered", "destructive"];

/// The capability a principal must hold to invoke a tool of the given risk
/// class. `None` for an unknown risk class (caller should default-deny).
pub fn risk_required_capability(risk: &str) -> Option<&'static str> {
    match risk {
        "read" => Some("tool:invoke:read"),
        "side_effect" => Some("tool:invoke:side_effect"),
        "metered" => Some("tool:invoke:metered"),
        "destructive" => Some("tool:invoke:destructive"),
        _ => None,
    }
}

/// The lowest tier whose [`capabilities_for_tier`] grants `capability`, or
/// `None` if no tier grants it.
pub fn min_tier_for_capability(capability: &str) -> Option<&'static str> {
    TIER_LADDER
        .iter()
        .copied()
        .find(|t| capabilities_for_tier(t).iter().any(|c| c == capability))
}

/// Reconcile the **gateway prototype's** tier-ladder labels
/// (`local|basic|trusted|privileged|admin` — a different vocabulary from the
/// daemon's `unverified..elite`) to the canonical required capability. The
/// gateway's per-tool `min_tier` uses these labels; this single mapping lets the
/// gateway authorize against the capability tokens emitted by `resolve_principal`
/// without changing its registry format. Both sides therefore agree via ONE
/// source — this function (exposed at `GET /v1/policy/capabilities`).
pub fn gateway_min_tier_required_capability(gateway_min_tier: &str) -> Option<&'static str> {
    match gateway_min_tier {
        "local" => Some("tool:list"),
        "basic" => Some("tool:invoke:read"),
        "trusted" => Some("tool:invoke:side_effect"),
        "privileged" => Some("tool:invoke:metered"),
        "admin" => Some("tool:invoke:destructive"),
        _ => None,
    }
}

/// The full canonical policy document, serialised for the read endpoint so the
/// gateway (and any other mediator) fetch ONE source of truth instead of
/// hard-coding a ladder that can drift.
pub fn policy_document() -> serde_json::Value {
    let tier_capabilities: serde_json::Map<String, serde_json::Value> = TIER_LADDER
        .iter()
        .map(|t| ((*t).to_string(), serde_json::json!(capabilities_for_tier(t))))
        .collect();
    let risk_required: serde_json::Map<String, serde_json::Value> = RISK_CLASSES
        .iter()
        .filter_map(|r| risk_required_capability(r).map(|c| ((*r).to_string(), serde_json::json!(c))))
        .collect();
    let gateway_map: serde_json::Map<String, serde_json::Value> = ["local", "basic", "trusted", "privileged", "admin"]
        .iter()
        .filter_map(|t| gateway_min_tier_required_capability(t).map(|c| ((*t).to_string(), serde_json::json!(c))))
        .collect();
    let min_tier_for_cap: serde_json::Map<String, serde_json::Value> = [
        "tool:list",
        "tool:invoke:read",
        "tool:invoke:side_effect",
        "tool:invoke:metered",
        "tool:invoke:destructive",
    ]
    .iter()
    .filter_map(|c| min_tier_for_capability(c).map(|t| ((*c).to_string(), serde_json::json!(t))))
    .collect();
    serde_json::json!({
        "schema": "crux.tool_policy.v1",
        "tier_ladder": TIER_LADDER,
        "risk_classes": RISK_CLASSES,
        "tier_capabilities": tier_capabilities,
        "risk_required_capability": risk_required,
        "min_tier_for_capability": min_tier_for_cap,
        "gateway_min_tier_required_capability": gateway_map,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ladder_ranks_are_monotonic() {
        assert_eq!(tier_rank("unverified"), 0);
        assert_eq!(tier_rank("basic"), 1);
        assert_eq!(tier_rank("established"), 2);
        assert_eq!(tier_rank("trusted"), 3);
        assert_eq!(tier_rank("elite"), 4);
        assert_eq!(tier_rank("nonsense"), 0, "unknown tiers floor to 0");
    }

    #[test]
    fn capabilities_are_cumulative() {
        assert_eq!(capabilities_for_tier("unverified"), vec!["tool:list".to_string()]);

        let basic = capabilities_for_tier("basic");
        assert!(basic.contains(&"tool:invoke:read".to_string()));
        assert!(!basic.contains(&"tool:invoke:metered".to_string()));

        let trusted = capabilities_for_tier("trusted");
        assert!(trusted.contains(&"tool:invoke:read".to_string()));
        assert!(trusted.contains(&"tool:invoke:side_effect".to_string()));
        assert!(trusted.contains(&"tool:invoke:metered".to_string()));
        assert!(!trusted.contains(&"tool:invoke:destructive".to_string()));

        let elite = capabilities_for_tier("elite");
        assert!(elite.contains(&"tool:invoke:destructive".to_string()));
    }

    #[test]
    fn every_risk_class_maps_to_a_reachable_capability() {
        for r in RISK_CLASSES {
            let cap = risk_required_capability(r).expect("risk maps to a capability");
            assert!(min_tier_for_capability(cap).is_some(), "{cap} granted by some tier");
        }
        assert!(risk_required_capability("nonsense").is_none());
    }

    #[test]
    fn min_tier_for_capability_picks_lowest() {
        assert_eq!(min_tier_for_capability("tool:list"), Some("unverified"));
        assert_eq!(min_tier_for_capability("tool:invoke:read"), Some("basic"));
        assert_eq!(min_tier_for_capability("tool:invoke:side_effect"), Some("established"));
        assert_eq!(min_tier_for_capability("tool:invoke:metered"), Some("trusted"));
        assert_eq!(min_tier_for_capability("tool:invoke:destructive"), Some("elite"));
        assert_eq!(min_tier_for_capability("tool:invoke:nope"), None);
    }

    #[test]
    fn gateway_ladder_reconciles_without_drift() {
        // Every gateway-prototype tier label maps to a canonical capability some
        // daemon tier actually grants — the two ladders agree via one source.
        for t in ["local", "basic", "trusted", "privileged", "admin"] {
            let cap = gateway_min_tier_required_capability(t).expect("gateway tier maps");
            assert!(min_tier_for_capability(cap).is_some(), "{t}->{cap} reachable");
        }
        assert!(gateway_min_tier_required_capability("bogus").is_none());
        // The gateway's privilege ordering matches the daemon's tier ranks.
        let rank =
            |t: &str| tier_rank(min_tier_for_capability(gateway_min_tier_required_capability(t).unwrap()).unwrap());
        assert!(rank("local") <= rank("basic"));
        assert!(rank("basic") <= rank("trusted"));
        assert!(rank("trusted") <= rank("privileged"));
        assert!(rank("privileged") <= rank("admin"));
    }

    #[test]
    fn policy_document_is_well_formed() {
        let doc = policy_document();
        assert_eq!(doc["schema"], "crux.tool_policy.v1");
        assert_eq!(doc["tier_ladder"][0], "unverified");
        assert_eq!(doc["risk_required_capability"]["metered"], "tool:invoke:metered");
        assert_eq!(doc["min_tier_for_capability"]["tool:invoke:metered"], "trusted");
        assert_eq!(
            doc["gateway_min_tier_required_capability"]["trusted"],
            "tool:invoke:side_effect"
        );
    }
}
