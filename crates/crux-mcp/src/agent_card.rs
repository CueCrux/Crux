// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Agent-card discovery (passport-revocation-and-agent-card-discovery M5).
//!
//! An A2A / GB-Z-185.4-style self-description of this daemon, so an external
//! agent can discover its identity, access method, authentication requirement,
//! and headline skills without an authenticated call. The HTTP `.well-known`
//! route is M6 (public, flag-gated `CRUX_AGENT_CARD=1`); this module is the
//! daemon-agnostic *builder* so the same card can mount on either surface.
//!
//! The card describes the **service**, not a specific caller — it carries no
//! per-agent passport and is safe to serve unauthenticated (only already-public
//! identity + the advertised tool surface, never private facts or tokens).

use serde::{Deserialize, Serialize};

use crate::dispatch::McpContext;

/// Schema tag for the card payload (bump on a breaking field change).
pub const AGENT_CARD_SCHEMA: &str = "cuecrux.agent-card.v1";
/// Canonical discovery path.
pub const AGENT_CARD_WELL_KNOWN_PATH: &str = "/.well-known/agent-card";

/// A2A / GB-Z-185.4-style agent card.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AgentCard {
    pub schema: String,
    pub name: String,
    pub provider: String,
    pub description: String,
    pub version: String,
    pub access: AgentAccess,
    pub authentication: AgentAuth,
    pub skills: Vec<AgentSkill>,
}

/// How to reach the agent (185.4 "access address / access method").
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AgentAccess {
    /// Daemon loopback/base URL when known (`None` if not configured).
    pub base_url: Option<String>,
    /// Wire protocols this surface speaks (e.g. `mcp`, `http`).
    pub protocols: Vec<String>,
    /// Where this very card is published.
    pub well_known: String,
}

/// Authentication requirement (185.3 trust hint, not the credential itself).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AgentAuth {
    pub required: bool,
    pub scheme: String,
    pub modes: Vec<String>,
}

/// A headline capability (185.4 "skills with tags").
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AgentSkill {
    pub name: String,
    pub description: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

/// Build the agent card from a daemon context. Pure + sync: reads only the
/// context's static fields, the always-surfaced [`CORE_FLOOR`] tools, and the
/// OAuth posture — no fact-store read, no caller identity.
///
/// [`CORE_FLOOR`]: crate::tools::surface::CORE_FLOOR
pub fn build_agent_card(ctx: &McpContext) -> AgentCard {
    build_agent_card_with_auth_posture(ctx, crate::oauth::introspection_enabled())
}

pub(crate) fn build_agent_card_with_auth_posture(ctx: &McpContext, oauth: bool) -> AgentCard {
    let static_bearer = !ctx.agent_registry.is_empty();
    let auth_required = crate::agent::mcp_authentication_configured(&ctx.agent_registry, oauth);

    let mut modes = Vec::new();
    if static_bearer {
        modes.push("bearer-token".to_string());
    }
    if oauth {
        modes.push("oauth2".to_string());
    }
    let scheme = if static_bearer && oauth {
        "oauth2+bearer"
    } else if oauth {
        "oauth2"
    } else if static_bearer {
        "bearer"
    } else {
        "none"
    }
    .to_string();

    let mut protocols = vec!["mcp".to_string()];
    if ctx.daemon_base_url.is_some() {
        protocols.push("http".to_string());
    }

    // Headline skills = the always-surfaced CORE_FLOOR (~14 tools), not the full
    // catalogue — what an external peer needs to know it can rely on.
    let skills = crate::tools::list_tools()
        .into_iter()
        .filter(|t| crate::tools::surface::CORE_FLOOR.contains(&t.name.as_str()))
        .map(|t| AgentSkill {
            name: t.name,
            description: truncate_desc(&t.description, 200),
            tags: Vec::new(),
        })
        .collect();

    AgentCard {
        schema: AGENT_CARD_SCHEMA.to_string(),
        name: format!("crux-daemon:{}", ctx.node_id),
        provider: "CueCrux".to_string(),
        description: "CueCrux local-first memory, retrieval, and receipts daemon (MCP surface).".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        access: AgentAccess {
            base_url: ctx.daemon_base_url.clone(),
            protocols,
            well_known: AGENT_CARD_WELL_KNOWN_PATH.to_string(),
        },
        authentication: AgentAuth {
            required: auth_required,
            scheme,
            modes,
        },
        skills,
    }
}

/// Truncate a tool description to `max` chars (skills stay terse in the card).
fn truncate_desc(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max).collect();
        t.push('…');
        t
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::agent::AgentRegistry;
    use crate::dispatch::McpContext;

    #[test]
    fn card_no_auth_when_registry_empty() {
        let ctx = McpContext::new_default("node-x");
        let card = build_agent_card_with_auth_posture(&ctx, false);
        assert_eq!(card.schema, AGENT_CARD_SCHEMA);
        assert_eq!(card.provider, "CueCrux");
        assert!(card.name.contains("node-x"));
        assert!(!card.authentication.required);
        assert_eq!(card.authentication.scheme, "none");
        assert!(card.authentication.modes.is_empty());
        assert!(!card.skills.is_empty(), "core-floor skills must be present");
        assert_eq!(card.access.well_known, AGENT_CARD_WELL_KNOWN_PATH);
        assert!(card.access.protocols.contains(&"mcp".to_string()));
    }

    #[test]
    fn card_requires_bearer_when_registry_nonempty() {
        let mut ctx = McpContext::new_default("node-y");
        ctx.agent_registry = AgentRegistry::from_single_token("crux_at_0123456789abcdef01234567");
        let card = build_agent_card_with_auth_posture(&ctx, false);
        assert!(card.authentication.required);
        assert_eq!(card.authentication.scheme, "bearer");
        assert!(card.authentication.modes.contains(&"bearer-token".to_string()));
    }

    #[test]
    fn card_requires_oauth_when_registry_empty() {
        let ctx = McpContext::new_default("node-oauth");
        let card = build_agent_card_with_auth_posture(&ctx, true);
        assert!(card.authentication.required);
        assert_eq!(card.authentication.scheme, "oauth2");
        assert_eq!(card.authentication.modes, vec!["oauth2"]);
    }

    #[test]
    fn card_advertises_both_authentication_rails() {
        let mut ctx = McpContext::new_default("node-both");
        ctx.agent_registry = AgentRegistry::from_single_token("crux_at_0123456789abcdef01234567");
        let card = build_agent_card_with_auth_posture(&ctx, true);
        assert!(card.authentication.required);
        assert_eq!(card.authentication.scheme, "oauth2+bearer");
        assert_eq!(card.authentication.modes, vec!["bearer-token", "oauth2"]);
    }

    #[test]
    fn card_advertises_http_when_base_url_set() {
        let ctx = McpContext::new_default("n").with_daemon_base_url("http://127.0.0.1:14800");
        let card = build_agent_card_with_auth_posture(&ctx, false);
        assert!(card.access.protocols.contains(&"http".to_string()));
        assert_eq!(card.access.base_url.as_deref(), Some("http://127.0.0.1:14800"));
    }

    #[test]
    fn card_serializes_camelcase_and_omits_empty_tags() {
        let ctx = McpContext::new_default("n");
        let v = serde_json::to_value(build_agent_card_with_auth_posture(&ctx, false)).unwrap();
        assert!(v.get("schema").is_some());
        assert!(v["access"].get("wellKnown").is_some(), "camelCase wellKnown");
        assert!(v.get("authentication").is_some());
        assert!(v["skills"].is_array());
        // tags is empty -> skip_serializing_if drops it.
        let first = &v["skills"][0];
        assert!(first.get("tags").is_none(), "empty tags omitted");
    }
}
