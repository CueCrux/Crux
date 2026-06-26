// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! MCP-local scoping helpers for agent-private facts and sessions.

use corecrux_memory::fact_store::Fact;

use crate::agent::AgentIdentity;

pub const AGENT_PRIVATE_ENTITY_PREFIX: &str = "__agent::";
pub const AGENT_SESSION_PREFIX: &str = "__agent_session::";

pub fn agent_name(agent: Option<&AgentIdentity>) -> Option<&str> {
    agent.map(|identity| identity.name.as_str())
}

pub fn private_entity_for_agent(agent_name: &str, logical_entity: &str) -> String {
    format!("{AGENT_PRIVATE_ENTITY_PREFIX}{agent_name}::{logical_entity}")
}

pub fn split_private_entity(entity: &str) -> Option<(&str, &str)> {
    let rest = entity.strip_prefix(AGENT_PRIVATE_ENTITY_PREFIX)?;
    rest.split_once("::")
}

pub fn visible_entity_for_agent(fact: &Fact, agent_name: Option<&str>) -> Option<String> {
    if let Some((owner, logical)) = split_private_entity(&fact.entity) {
        return (agent_name == Some(owner)).then(|| logical.to_string());
    }
    if fact.private {
        return None;
    }
    Some(fact.entity.clone())
}

/// Flag-ON (agent-passport M5) variant of [`visible_entity_for_agent`] that
/// matches a private fact's `__agent::<owner>::` key against EITHER the
/// caller's resolved scope-identity (passport_id, e.g. `claude-work`) OR a set
/// of legacy alias names (the raw agent token-name, e.g. `anthropic`).
///
/// The alias set exists purely for **back-compat**: a private fact written
/// while the flag was OFF is keyed under the raw agent name; once the flag is
/// flipped on the same agent now resolves to a passport_id, so without the
/// alias its own legacy private facts would be stranded (owner `anthropic` vs
/// identity `claude-work`). Including the raw name in `aliases` keeps those
/// facts visible to their original owner and ONLY their original owner.
///
/// Visibility is still **owning-identity-ONLY**: a DIFFERENT passport
/// (`codex-work`/`openai`) matches neither the owner's passport_id nor the
/// owner's raw name, so it is denied. This deliberately does NOT implement
/// group-shared private visibility (see scope.rs module note / M5 report):
/// proving group-sharing safe across all read paths is deferred.
///
/// Non-private facts are unaffected (shared pool, visible to all).
pub fn visible_entity_for_identity(fact: &Fact, identity: Option<&str>, aliases: &[&str]) -> Option<String> {
    if let Some((owner, logical)) = split_private_entity(&fact.entity) {
        let owned = identity == Some(owner) || aliases.contains(&owner);
        return owned.then(|| logical.to_string());
    }
    if fact.private {
        return None;
    }
    Some(fact.entity.clone())
}

/// Flag-ON companion to [`fact_visible_to_agent`]. See
/// [`visible_entity_for_identity`].
pub fn fact_visible_to_identity(fact: &Fact, identity: Option<&str>, aliases: &[&str]) -> bool {
    visible_entity_for_identity(fact, identity, aliases).is_some()
}

pub fn fact_visible_to_agent(fact: &Fact, agent_name: Option<&str>) -> bool {
    visible_entity_for_agent(fact, agent_name).is_some()
}

pub fn entity_matches_for_agent(fact: &Fact, requested_entity: &str, agent_name: Option<&str>) -> bool {
    fact.entity == requested_entity
        || visible_entity_for_agent(fact, agent_name)
            .as_deref()
            .is_some_and(|entity| entity == requested_entity)
}

pub fn entity_prefix_matches_for_agent(fact: &Fact, requested_prefix: &str, agent_name: Option<&str>) -> bool {
    fact.entity.starts_with(requested_prefix)
        || visible_entity_for_agent(fact, agent_name)
            .as_deref()
            .is_some_and(|entity| entity.starts_with(requested_prefix))
}

/// Flag-ON (M5) identity-scoped variant of [`entity_matches_for_agent`].
pub fn entity_matches_for_identity(
    fact: &Fact,
    requested_entity: &str,
    identity: Option<&str>,
    aliases: &[&str],
) -> bool {
    // NOTE: the bare `fact.entity == requested_entity` arm is preserved for
    // parity with the agent-scoped version, but a private fact's STORED entity
    // is `__agent::<owner>::…` which only equals `requested_entity` if the
    // caller literally asked for that scoped name — they never do via the
    // logical API. The owner check below is what enforces T.1.
    fact.entity == requested_entity
        || visible_entity_for_identity(fact, identity, aliases)
            .as_deref()
            .is_some_and(|entity| entity == requested_entity)
}

/// Flag-ON (M5) identity-scoped variant of [`entity_prefix_matches_for_agent`].
pub fn entity_prefix_matches_for_identity(
    fact: &Fact,
    requested_prefix: &str,
    identity: Option<&str>,
    aliases: &[&str],
) -> bool {
    fact.entity.starts_with(requested_prefix)
        || visible_entity_for_identity(fact, identity, aliases)
            .as_deref()
            .is_some_and(|entity| entity.starts_with(requested_prefix))
}

pub fn scoped_session_id(agent_name: Option<&str>, logical_session_id: &str) -> String {
    agent_name.map_or_else(
        || logical_session_id.to_string(),
        |name| format!("{AGENT_SESSION_PREFIX}{name}::{logical_session_id}"),
    )
}

pub fn split_scoped_session_id(stored_session_id: &str) -> Option<(&str, &str)> {
    let rest = stored_session_id.strip_prefix(AGENT_SESSION_PREFIX)?;
    rest.split_once("::")
}

pub fn visible_session_for_agent(stored_session_id: &str, agent_name: Option<&str>) -> Option<String> {
    if let Some((owner, logical)) = split_scoped_session_id(stored_session_id) {
        return (agent_name == Some(owner)).then(|| logical.to_string());
    }
    agent_name.is_none().then(|| stored_session_id.to_string())
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;

    fn sample_fact(entity: &str, private: bool) -> Fact {
        Fact {
            fact_id: "f_test".to_string(),
            entity: entity.to_string(),
            key: "k".to_string(),
            value: "v".to_string(),
            source_receipt: None,
            confidence: 1.0,
            stored_at: Utc::now(),
            tokens: 1,
            deleted: false,
            version: 1,
            supersedes: None,
            private,
            horizon_class: corecrux_memory::HorizonClass::None,
            reverified_at: None,
            superseded_by: None,
            actor: None,
            valid_from: None,
            valid_to: None,
            access_count: 0,
            last_accessed_at: None,
        }
    }

    #[test]
    fn private_entity_visible_only_to_owner() {
        let fact = sample_fact("__agent::alice::notes", true);
        assert_eq!(visible_entity_for_agent(&fact, Some("alice")).as_deref(), Some("notes"));
        assert!(visible_entity_for_agent(&fact, Some("bob")).is_none());
        assert!(visible_entity_for_agent(&fact, None).is_none());
    }

    #[test]
    fn anonymous_private_fact_hidden_from_authenticated_agents() {
        let fact = sample_fact("legacy-private", true);
        assert!(visible_entity_for_agent(&fact, None).is_none());
        assert!(visible_entity_for_agent(&fact, Some("alice")).is_none());
    }

    #[test]
    fn scoped_session_ids_roundtrip_for_owner() {
        let stored = scoped_session_id(Some("alice"), "sess-42");
        assert_eq!(stored, "__agent_session::alice::sess-42");
        assert_eq!(
            visible_session_for_agent(&stored, Some("alice")).as_deref(),
            Some("sess-42")
        );
        assert!(visible_session_for_agent(&stored, Some("bob")).is_none());
    }
}
