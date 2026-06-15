// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Agent identity and registry.
//!
//! Agents authenticate via bearer tokens. Tokens are never stored in plaintext;
//! only their BLAKE3 hashes are retained. The registry is populated from
//! environment variables at startup.

use std::env;

const MIN_AGENT_TOKEN_BYTES: usize = 32;
const MAX_AGENT_TOKEN_BYTES: usize = 256;
const MAX_AGENT_NAME_BYTES: usize = 64;

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
    /// - `CRUX_AGENT_TOKENS=alice:<32-byte-token>,bob:<32-byte-token>`
    ///   — multiple named agents, comma-separated `name:token` pairs.
    ///
    /// - `CRUX_AGENT_TOKEN=<32-byte-token>`
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
                let name = name.trim();
                let token = token.trim();
                if !is_safe_agent_name(name) || !is_safe_agent_token(token) {
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
        let token = token.trim();
        if !is_safe_agent_token(token) {
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
        self.agents
            .iter()
            .find(|agent| constant_time_eq(&agent.token_hash, &hash))
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

fn is_safe_agent_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_AGENT_NAME_BYTES
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn is_safe_agent_token(token: &str) -> bool {
    (MIN_AGENT_TOKEN_BYTES..=MAX_AGENT_TOKEN_BYTES).contains(&token.len())
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'~' | b'-'))
}

fn constant_time_eq<const N: usize>(left: &[u8; N], right: &[u8; N]) -> bool {
    left.iter().zip(right.iter()).fold(0_u8, |diff, (a, b)| diff | (a ^ b)) == 0
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const TOKEN_A: &str = "crux_at_0123456789abcdef01234567";
    const TOKEN_B: &str = "crux_at_89abcdef0123456789abcdef";

    #[test]
    fn single_token_creates_default_agent() {
        let reg = AgentRegistry::from_single_token(TOKEN_A);
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
        let reg = AgentRegistry::from_pairs_str(&format!("alice:{TOKEN_A},bob:{TOKEN_B}"));
        assert_eq!(reg.len(), 2);
        assert_eq!(reg.agents[0].name, "alice");
        assert_eq!(reg.agents[1].name, "bob");
    }

    #[test]
    fn pairs_str_skips_malformed() {
        let reg = AgentRegistry::from_pairs_str(&format!(
            "good:{TOKEN_A},,badnodelim,:empty_name,empty_tok:,bad-name!:{TOKEN_B},short:tiny"
        ));
        assert_eq!(reg.len(), 1);
        assert_eq!(reg.agents[0].name, "good");
    }

    #[test]
    fn agent_token_policy() {
        assert!(AgentRegistry::from_single_token("short-token").is_empty());
        assert!(AgentRegistry::from_single_token("contains whitespace 0123456789abcdef").is_empty());
        assert!(AgentRegistry::from_single_token("contains:colon:0123456789abcdef").is_empty());
        assert_eq!(AgentRegistry::from_single_token(TOKEN_A).len(), 1);
    }

    #[test]
    fn lookup_success() {
        let reg = AgentRegistry::from_single_token(TOKEN_A);
        let found = reg.lookup(TOKEN_A);
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "default");
    }

    #[test]
    fn lookup_failure() {
        let reg = AgentRegistry::from_single_token(TOKEN_A);
        assert!(reg.lookup(TOKEN_B).is_none());
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
