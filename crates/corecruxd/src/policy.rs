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
}
