// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Agent→passport resolution (agent-passport M1).
//!
//! MCP agents authenticate under short token-names (`anthropic`, `openai`,
//! `windows-host`, `tailnet`) that do NOT match the passport_ids the
//! substrate uses for authorship and (eventually, M5) tenant-category
//! enforcement (`claude-work`, `codex-work`, `personal-default`, …). This
//! module owns the stable mapping between the two.
//!
//! The mapping is loaded from the env var `CRUX_AGENT_PASSPORTS` in the
//! `name:passport[:tenant]` comma-separated shape (a backward-compatible
//! extension of the M1 `name:passport` form — the `tenant` segment is
//! optional and defaults to `work` when the flag is on). When the
//! `CORECRUXD_AGENT_PASSPORTS` feature flag is ON and no env override is
//! supplied, a small built-in default map is used (see
//! [`AgentPassportMap::builtin_default`]).
//!
//! **Tenant-as-group (agent-passport M4):** every mapped agent carries BOTH a
//! passport_id (its authorship stamp) and a *tenant-group* (its collaboration
//! boundary / shared pool). The default groups both first-party coding agents
//! under tenant `work` — this is the operator's "claude-work + codex-work
//! grouped as work" model. M4 only *records* the group (so M5 can enforce on
//! it and `get_passport` can surface it); it does NOT change any visibility
//! behaviour. See `crate::scope` — untouched by M4.
//!
//! **Flag-OFF guarantee:** this module is never consulted unless the flag is
//! on. With the flag off, `store_fact` writes `actor = None` exactly as
//! before — no mapping is loaded or applied, and no group is recorded.

use std::collections::BTreeMap;
use std::env;

/// Env var holding the agent→passport mapping, e.g.
/// `CRUX_AGENT_PASSPORTS=anthropic:claude-work:work,openai:codex-work:work`.
pub const AGENT_PASSPORTS_ENV: &str = "CRUX_AGENT_PASSPORTS";

/// Default tenant-group applied to a mapped agent when the env entry omits the
/// optional `:tenant` segment (and for the built-in default map). Chosen as
/// `work` to match the operator's grouping of the first-party coding agents.
pub const DEFAULT_AGENT_TENANT: &str = "work";

/// The resolved identity of a mapped agent: its authorship `passport` plus the
/// `tenant` collaboration-group it belongs to.
///
/// `tenant` is the *group* (shared pool); `passport` is the per-agent author
/// stamp. Two agents in the same `tenant` share the pool yet remain
/// individually attributed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentGroup {
    pub passport: String,
    pub tenant: String,
}

/// Immutable map from MCP agent token-name to its [`AgentGroup`]
/// (passport_id + tenant-group).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AgentPassportMap {
    map: BTreeMap<String, AgentGroup>,
}

impl AgentPassportMap {
    /// An empty map — resolves nothing. This is the value threaded into
    /// contexts when the feature flag is OFF (and the default in
    /// `McpContext::new_default`), so no behaviour change can leak from a
    /// stray map.
    pub fn empty() -> Self {
        Self { map: BTreeMap::new() }
    }

    /// Built-in default mapping, used ONLY when the feature flag is ON and no
    /// `CRUX_AGENT_PASSPORTS` override is set. Intentionally minimal and
    /// documented: the two first-party coding agents map to their work
    /// passports. Operators override via the env var for anything else.
    pub fn builtin_default() -> Self {
        let mut map = BTreeMap::new();
        map.insert(
            "anthropic".to_string(),
            AgentGroup {
                passport: "claude-work".to_string(),
                tenant: DEFAULT_AGENT_TENANT.to_string(),
            },
        );
        map.insert(
            "openai".to_string(),
            AgentGroup {
                passport: "codex-work".to_string(),
                tenant: DEFAULT_AGENT_TENANT.to_string(),
            },
        );
        Self { map }
    }

    /// Parse a comma-separated `name:passport[:tenant]` string into a map.
    /// Mirrors [`crate::agent::AgentRegistry::from_pairs_str`]: empty entries
    /// and malformed pairs (no delimiter, empty name, or empty passport) are
    /// skipped silently rather than rejected, so a single typo never wedges
    /// startup.
    ///
    /// Backward-compatible with the M1 `name:passport` form: the third
    /// `:tenant` segment is optional and defaults to [`DEFAULT_AGENT_TENANT`]
    /// (`work`). A present-but-empty tenant segment (`name:passport:`) also
    /// falls back to the default rather than erroring.
    pub fn from_pairs_str(pairs: &str) -> Self {
        let map = pairs
            .split(',')
            .filter(|s| !s.is_empty())
            .filter_map(|pair| {
                // Split into at most three fields: name, passport, tenant.
                let mut parts = pair.splitn(3, ':');
                let name = parts.next()?.trim();
                let passport = parts.next()?.trim();
                let tenant = parts.next().map(str::trim).filter(|t| !t.is_empty());
                if name.is_empty() || passport.is_empty() {
                    return None;
                }
                Some((
                    name.to_string(),
                    AgentGroup {
                        passport: passport.to_string(),
                        tenant: tenant.unwrap_or(DEFAULT_AGENT_TENANT).to_string(),
                    },
                ))
            })
            .collect();
        Self { map }
    }

    /// Load the map for an ENABLED feature flag: prefer the
    /// `CRUX_AGENT_PASSPORTS` env override; fall back to the built-in
    /// default when the env var is absent or parses to nothing.
    ///
    /// Callers MUST only invoke this when `CORECRUXD_AGENT_PASSPORTS` is on —
    /// the flag-OFF path uses [`AgentPassportMap::empty`].
    pub fn from_env_or_default() -> Self {
        if let Ok(val) = env::var(AGENT_PASSPORTS_ENV) {
            let parsed = Self::from_pairs_str(&val);
            if !parsed.is_empty() {
                return parsed;
            }
        }
        Self::builtin_default()
    }

    /// Look up the passport_id for an agent token-name. `None` when the name
    /// isn't mapped (caller decides the fallback policy).
    pub fn get(&self, agent_name: &str) -> Option<&str> {
        self.map.get(agent_name).map(|g| g.passport.as_str())
    }

    /// Look up the full [`AgentGroup`] (passport + tenant-group) for an agent
    /// token-name. `None` when the name isn't mapped.
    pub fn get_group(&self, agent_name: &str) -> Option<&AgentGroup> {
        self.map.get(agent_name)
    }

    /// Look up just the tenant-group for an agent token-name. `None` when the
    /// name isn't mapped.
    pub fn tenant_for(&self, agent_name: &str) -> Option<&str> {
        self.map.get(agent_name).map(|g| g.tenant.as_str())
    }

    /// Number of mappings.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// True when no mappings are present.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

/// Pure resolver: map an agent token-name to its passport_id via `mapping`.
///
/// Returns `Some(passport_id)` for a known name, `None` for an unknown or
/// empty name. This is intentionally side-effect-free and flag-agnostic —
/// the caller (`handle_store_fact`) is responsible for only consulting it
/// when the feature flag is on, and for choosing the unmapped-fallback
/// policy (M1 prefers the raw agent name so flag-ON writes are never
/// anonymous; see QC.3).
pub fn resolve_agent_passport(agent_name: &str, mapping: &AgentPassportMap) -> Option<String> {
    if agent_name.is_empty() {
        return None;
    }
    mapping.get(agent_name).map(str::to_string)
}

/// Pure resolver: map an agent token-name to its full [`AgentGroup`]
/// (passport_id + tenant-group) via `mapping`.
///
/// Returns `Some(AgentGroup)` for a known name, `None` for an unknown or empty
/// name. Side-effect-free and flag-agnostic — the caller is responsible for
/// only consulting it when the feature flag is on. Used by the M2 auto-issue
/// path to record the agent's tenant-group on the minted passport (agent-
/// passport M4). It records ONLY; it changes no visibility (see scope.rs,
/// untouched by M4).
pub fn resolve_agent_group(agent_name: &str, mapping: &AgentPassportMap) -> Option<AgentGroup> {
    if agent_name.is_empty() {
        return None;
    }
    mapping.get_group(agent_name).cloned()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parses_name_passport_pairs() {
        let m = AgentPassportMap::from_pairs_str("anthropic:claude-work,openai:codex-work");
        assert_eq!(m.len(), 2);
        assert_eq!(m.get("anthropic"), Some("claude-work"));
        assert_eq!(m.get("openai"), Some("codex-work"));
        // M4: a `name:passport` entry (no tenant segment) defaults to `work`.
        assert_eq!(m.tenant_for("anthropic"), Some("work"));
        assert_eq!(m.tenant_for("openai"), Some("work"));
    }

    #[test]
    fn parses_name_passport_tenant_triples() {
        // M4: explicit `:tenant` segment is honoured.
        let m = AgentPassportMap::from_pairs_str("anthropic:claude-work:work,openai:codex-work:research");
        assert_eq!(m.len(), 2);
        assert_eq!(m.get("anthropic"), Some("claude-work"));
        assert_eq!(m.tenant_for("anthropic"), Some("work"));
        assert_eq!(m.get("openai"), Some("codex-work"));
        assert_eq!(m.tenant_for("openai"), Some("research"));
        let g = m.get_group("openai").unwrap();
        assert_eq!(g.passport, "codex-work");
        assert_eq!(g.tenant, "research");
    }

    #[test]
    fn parse_mixed_with_and_without_tenant() {
        // Backward-compatibility: a triple and a pair can coexist.
        let m = AgentPassportMap::from_pairs_str("anthropic:claude-work:research,openai:codex-work");
        assert_eq!(m.tenant_for("anthropic"), Some("research"));
        assert_eq!(m.tenant_for("openai"), Some("work")); // default
    }

    #[test]
    fn parse_empty_tenant_segment_defaults_to_work() {
        // `name:passport:` (trailing colon, empty tenant) falls back to default.
        let m = AgentPassportMap::from_pairs_str("anthropic:claude-work:");
        assert_eq!(m.get("anthropic"), Some("claude-work"));
        assert_eq!(m.tenant_for("anthropic"), Some("work"));
    }

    #[test]
    fn parser_skips_malformed_pairs() {
        let m = AgentPassportMap::from_pairs_str("good:p_x,,nodelim,:empty_name,empty_pass:");
        assert_eq!(m.len(), 1);
        assert_eq!(m.get("good"), Some("p_x"));
    }

    #[test]
    fn parser_empty_string_is_empty_map() {
        let m = AgentPassportMap::from_pairs_str("");
        assert!(m.is_empty());
    }

    #[test]
    fn builtin_default_maps_first_party_agents() {
        let m = AgentPassportMap::builtin_default();
        assert_eq!(m.get("anthropic"), Some("claude-work"));
        assert_eq!(m.get("openai"), Some("codex-work"));
        // M4: both first-party agents are grouped under tenant `work`.
        assert_eq!(m.tenant_for("anthropic"), Some("work"));
        assert_eq!(m.tenant_for("openai"), Some("work"));
    }

    #[test]
    fn resolve_agent_group_returns_passport_and_tenant() {
        let m = AgentPassportMap::builtin_default();
        let g = resolve_agent_group("anthropic", &m).unwrap();
        assert_eq!(g.passport, "claude-work");
        assert_eq!(g.tenant, "work");
        assert_eq!(resolve_agent_group("windows-host", &m), None);
        assert_eq!(resolve_agent_group("", &m), None);
    }

    #[test]
    fn resolver_known_name_maps() {
        let m = AgentPassportMap::from_pairs_str("anthropic:claude-work");
        assert_eq!(resolve_agent_passport("anthropic", &m), Some("claude-work".to_string()));
    }

    #[test]
    fn resolver_unknown_name_is_none() {
        let m = AgentPassportMap::from_pairs_str("anthropic:claude-work");
        assert_eq!(resolve_agent_passport("windows-host", &m), None);
    }

    #[test]
    fn resolver_empty_name_is_none() {
        let m = AgentPassportMap::builtin_default();
        assert_eq!(resolve_agent_passport("", &m), None);
    }

    #[test]
    fn resolver_against_empty_map_is_none() {
        let m = AgentPassportMap::empty();
        assert_eq!(resolve_agent_passport("anthropic", &m), None);
    }
}
