// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Agent identity and registry.
//!
//! Agents authenticate via bearer tokens. Tokens are never stored in plaintext;
//! only their BLAKE3 hashes are retained. The registry is populated from
//! environment variables at startup.

use std::env;

use subtle::ConstantTimeEq;

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

/// Why building an [`AgentRegistry`] from environment failed.
///
/// Returned only when an agent-token env var is *present but invalid*: the
/// caller must fail closed rather than silently fall back to no-auth MCP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentRegistryError {
    /// Operator-facing explanation (which var, what was wrong).
    pub message: String,
}

impl std::fmt::Display for AgentRegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for AgentRegistryError {}

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
    /// Fail-closed semantics:
    ///
    /// - Neither variable set → `Ok(empty)` (legitimate single-user / no-auth mode).
    /// - A variable is set but **any** entry is malformed, too short, or otherwise
    ///   fails the token policy → `Err(AgentRegistryError)`. The caller must abort
    ///   startup; a typo or weak token must never silently degrade enforced MCP auth
    ///   into no-auth MCP.
    pub fn from_env() -> Result<Self, AgentRegistryError> {
        // Try multi-agent first.
        if let Ok(val) = env::var("CRUX_AGENT_TOKENS") {
            return Self::from_pairs_str_checked(&val);
        }

        // Try single-agent fallback.
        if let Ok(token) = env::var("CRUX_AGENT_TOKEN") {
            let reg = Self::from_single_token(&token);
            if reg.is_empty() {
                return Err(AgentRegistryError {
                    message: "CRUX_AGENT_TOKEN is set but the token fails the policy \
                              (need 32..=256 bytes, charset [A-Za-z0-9._~-])"
                        .to_string(),
                });
            }
            return Ok(reg);
        }

        Ok(Self::empty())
    }

    /// Strict variant of [`Self::from_pairs_str`]: every non-empty `name:token`
    /// segment must parse, and at least one must be present. Returns an error
    /// (not a silently-shorter registry) on the first invalid entry, so a typo
    /// in one of several tokens fails startup rather than dropping that agent.
    fn from_pairs_str_checked(pairs: &str) -> Result<Self, AgentRegistryError> {
        let mut agents = Vec::new();
        for raw in pairs.split(',') {
            let pair = raw.trim();
            if pair.is_empty() {
                continue;
            }
            let invalid = |what: &str| AgentRegistryError {
                message: format!(
                    "CRUX_AGENT_TOKENS contains an invalid entry ({what}); \
                     expected comma-separated name:token pairs, token 32..=256 bytes, \
                     charset [A-Za-z0-9._~-]"
                ),
            };
            let (name, token) = pair.split_once(':').ok_or_else(|| invalid("missing ':' delimiter"))?;
            let name = name.trim();
            let token = token.trim();
            if !is_safe_agent_name(name) {
                return Err(invalid("bad agent name"));
            }
            if !is_safe_agent_token(token) {
                return Err(invalid("token fails length/charset policy"));
            }
            agents.push(AgentIdentity {
                name: name.to_string(),
                token_hash: blake3::hash(token.as_bytes()).into(),
            });
        }
        if agents.is_empty() {
            return Err(AgentRegistryError {
                message: "CRUX_AGENT_TOKENS is set but contained no valid name:token pairs".to_string(),
            });
        }
        Ok(Self { agents })
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
            .find(|agent| bool::from(agent.token_hash.ct_eq(&hash)))
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

    fn clear_agent_token_env() {
        std::env::remove_var("CRUX_AGENT_TOKEN");
        std::env::remove_var("CRUX_AGENT_TOKENS");
    }

    #[test]
    fn mcp_no_token_env_allows_single_user_mode() {
        let _g = crate::test_env_lock().blocking_lock();
        clear_agent_token_env();
        let reg = AgentRegistry::from_env().expect("no token env is single-user mode");
        assert!(reg.is_empty());
    }

    #[test]
    fn mcp_env_token_present_but_invalid_fails_startup() {
        let _g = crate::test_env_lock().blocking_lock();
        clear_agent_token_env();
        std::env::set_var("CRUX_AGENT_TOKEN", "too-short");
        let result = AgentRegistry::from_env();
        clear_agent_token_env();
        assert!(result.is_err(), "weak single token must fail closed, got {result:?}");
    }

    #[test]
    fn mcp_valid_single_token_env_parses() {
        let _g = crate::test_env_lock().blocking_lock();
        clear_agent_token_env();
        std::env::set_var("CRUX_AGENT_TOKEN", TOKEN_A);
        let result = AgentRegistry::from_env();
        clear_agent_token_env();
        assert_eq!(result.expect("valid token parses").len(), 1);
    }

    #[test]
    fn mcp_multi_token_any_invalid_fails_startup() {
        let _g = crate::test_env_lock().blocking_lock();
        clear_agent_token_env();
        // First token is valid, second is too short: must fail closed rather
        // than silently registering only the good one.
        std::env::set_var("CRUX_AGENT_TOKENS", &format!("alice:{TOKEN_A},bob:tiny"));
        let result = AgentRegistry::from_env();
        clear_agent_token_env();
        assert!(
            result.is_err(),
            "one bad token in the list must fail closed, got {result:?}"
        );
    }

    #[test]
    fn mcp_multi_token_all_valid_parses() {
        let _g = crate::test_env_lock().blocking_lock();
        clear_agent_token_env();
        std::env::set_var("CRUX_AGENT_TOKENS", &format!("alice:{TOKEN_A},bob:{TOKEN_B}"));
        let result = AgentRegistry::from_env();
        clear_agent_token_env();
        assert_eq!(result.expect("all valid parses").len(), 2);
    }

    #[test]
    fn mcp_multi_token_only_empty_segments_fails() {
        let _g = crate::test_env_lock().blocking_lock();
        clear_agent_token_env();
        std::env::set_var("CRUX_AGENT_TOKENS", ",, ,");
        let result = AgentRegistry::from_env();
        clear_agent_token_env();
        assert!(result.is_err(), "no valid pairs must fail closed");
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
