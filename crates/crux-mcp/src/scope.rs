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
