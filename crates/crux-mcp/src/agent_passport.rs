// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Agent→passport resolution (agent-passport M1).
//!
//! MCP agents authenticate under short token-names (`anthropic`, `openai`,
//! `windows-host`, `tailnet`) that do NOT match the passport_ids the
//! substrate uses for authorship and (eventually, M5) tenant-category
//! enforcement (`claude-work`, `codex-work`, `personal-default`, …). This
//! module owns the stable mapping between the two.
//!
//! The mapping is loaded from the env var `CRUX_AGENT_PASSPORTS` in the
//! same comma-separated `name:passport` shape that
//! [`crate::agent::AgentRegistry::from_pairs_str`] parses for
//! `CRUX_AGENT_TOKENS`. When the `CORECRUXD_AGENT_PASSPORTS` feature flag is
//! ON and no env override is supplied, a small built-in default map is used
//! (see [`AgentPassportMap::builtin_default`]).
//!
//! **Flag-OFF guarantee:** this module is never consulted unless the flag is
//! on. With the flag off, `store_fact` writes `actor = None` exactly as
//! before — no mapping is loaded or applied.

use std::collections::BTreeMap;
use std::env;

/// Env var holding the agent→passport mapping, e.g.
/// `CRUX_AGENT_PASSPORTS=anthropic:claude-work,openai:codex-work`.
pub const AGENT_PASSPORTS_ENV: &str = "CRUX_AGENT_PASSPORTS";

/// Immutable map from MCP agent token-name to passport_id.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AgentPassportMap {
    map: BTreeMap<String, String>,
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
        map.insert("anthropic".to_string(), "claude-work".to_string());
        map.insert("openai".to_string(), "codex-work".to_string());
        Self { map }
    }

    /// Parse a comma-separated `name:passport` string into a map. Mirrors
    /// [`crate::agent::AgentRegistry::from_pairs_str`]: empty entries and
    /// malformed pairs (no delimiter, empty name, or empty passport) are
    /// skipped silently rather than rejected, so a single typo never wedges
    /// startup.
    pub fn from_pairs_str(pairs: &str) -> Self {
        let map = pairs
            .split(',')
            .filter(|s| !s.is_empty())
            .filter_map(|pair| {
                let (name, passport) = pair.split_once(':')?;
                let name = name.trim();
                let passport = passport.trim();
                if name.is_empty() || passport.is_empty() {
                    return None;
                }
                Some((name.to_string(), passport.to_string()))
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
        self.map.get(agent_name).map(String::as_str)
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
