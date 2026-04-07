// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Agent identity and registry.
//!
//! Agents authenticate via bearer tokens. Tokens are never stored in plaintext;
//! only their BLAKE3 hashes are retained. The registry is populated from
//! environment variables at startup.

use std::env;

/// A registered agent identity.
#[derive(Debug, Clone)]
pub struct AgentIdentity {
    /// Human-readable agent name (e.g. "alice", "default").
    pub name: String,
    /// BLAKE3 hash of the bearer token.
    pub token_hash: [u8; 32],
}

/// Registry of known agent identities.
#[derive(Debug, Clone)]
pub struct AgentRegistry {
    /// Registered agent identities (token hashes only, no plaintext).
    agents: Vec<AgentIdentity>,
}

impl AgentRegistry {
    /// Build a registry from environment variables.
    ///
    /// Supports two formats:
    ///
    /// - `CRUX_AGENT_TOKENS=alice:crux_at_abc,bob:crux_at_def`
    ///   — multiple named agents, comma-separated `name:token` pairs.
    ///
    /// - `CRUX_AGENT_TOKEN=crux_at_abc`
    ///   — single agent named `"default"`.
    ///
    /// If neither variable is set, returns an empty registry (single-user mode).
    pub fn from_env() -> Self {
        // Try multi-agent first.
        if let Ok(val) = env::var("CRUX_AGENT_TOKENS") {
            return Self::from_pairs_str(&val);
        }

        // Try single-agent fallback.
        if let Ok(token) = env::var("CRUX_AGENT_TOKEN") {
            return Self::from_single_token(&token);
        }

        Self::empty()
    }

    /// Parse a comma-separated `name:token` string into a registry.
    pub fn from_pairs_str(pairs: &str) -> Self {
        let agents = pairs
            .split(',')
            .filter(|s| !s.is_empty())
            .filter_map(|pair| {
                let (name, token) = pair.split_once(':')?;
                if name.is_empty() || token.is_empty() {
                    return None;
                }
                Some(AgentIdentity {
                    name: name.to_string(),
                    token_hash: blake3::hash(token.as_bytes()).into(),
                })
            })
            .collect();
        Self { agents }
    }

    /// Build a single-agent registry from a raw token (agent name = "default").
    pub fn from_single_token(token: &str) -> Self {
        if token.is_empty() {
            return Self::empty();
        }
        Self {
            agents: vec![AgentIdentity {
                name: "default".to_string(),
                token_hash: blake3::hash(token.as_bytes()).into(),
            }],
        }
    }

    /// Create an empty registry (single-user / no-auth mode).
    pub fn empty() -> Self {
        Self { agents: Vec::new() }
    }

    /// Look up an agent by raw bearer token.
    ///
    /// Hashes the provided token with BLAKE3 and compares against all
    /// registered hashes.
    pub fn lookup(&self, token: &str) -> Option<&AgentIdentity> {
        let hash: [u8; 32] = blake3::hash(token.as_bytes()).into();
        self.agents.iter().find(|a| a.token_hash == hash)
    }

    /// Returns `true` if no agents are registered (single-user mode).
    pub fn is_empty(&self) -> bool {
        self.agents.is_empty()
    }

    /// Number of registered agents.
    pub fn len(&self) -> usize {
        self.agents.len()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn single_token_creates_default_agent() {
        let reg = AgentRegistry::from_single_token("crux_at_abc");
        assert_eq!(reg.len(), 1);
        assert_eq!(reg.agents[0].name, "default");
    }

    #[test]
    fn single_token_empty_returns_empty_registry() {
        let reg = AgentRegistry::from_single_token("");
        assert!(reg.is_empty());
    }

    #[test]
    fn multiple_tokens_from_pairs() {
        let reg = AgentRegistry::from_pairs_str("alice:crux_at_aaa,bob:crux_at_bbb");
        assert_eq!(reg.len(), 2);
        assert_eq!(reg.agents[0].name, "alice");
        assert_eq!(reg.agents[1].name, "bob");
    }

    #[test]
    fn pairs_str_skips_malformed() {
        let reg = AgentRegistry::from_pairs_str("good:crux_at_x,,badnodelim,:empty_name,empty_tok:");
        assert_eq!(reg.len(), 1);
        assert_eq!(reg.agents[0].name, "good");
    }

    #[test]
    fn lookup_success() {
        let reg = AgentRegistry::from_single_token("crux_at_secret");
        let found = reg.lookup("crux_at_secret");
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "default");
    }

    #[test]
    fn lookup_failure() {
        let reg = AgentRegistry::from_single_token("crux_at_secret");
        assert!(reg.lookup("crux_at_wrong").is_none());
    }

    #[test]
    fn lookup_empty_registry() {
        let reg = AgentRegistry::empty();
        assert!(reg.lookup("anything").is_none());
    }

    #[test]
    fn empty_registry() {
        let reg = AgentRegistry::empty();
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
    }
}
