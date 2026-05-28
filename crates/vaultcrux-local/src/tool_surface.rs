// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! MCP tool tier classification for the daemon-local VaultCrux surface.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolTier {
    Local,
    HostedGated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolSurfaceEntry {
    pub name: &'static str,
    pub tier: ToolTier,
    pub marker: &'static str,
}

pub const HOSTED_BACKEND_ID: &str = "hosted.vaultcrux.com";

pub const TOOL_SURFACE: &[ToolSurfaceEntry] = &[
    ToolSurfaceEntry {
        name: "cuecrux_session",
        tier: ToolTier::Local,
        marker: "[local]",
    },
    ToolSurfaceEntry {
        name: "query",
        tier: ToolTier::Local,
        marker: "[local]",
    },
    ToolSurfaceEntry {
        name: "query_scan",
        tier: ToolTier::Local,
        marker: "[local]",
    },
    ToolSurfaceEntry {
        name: "query_expand",
        tier: ToolTier::Local,
        marker: "[local]",
    },
    ToolSurfaceEntry {
        name: "store_fact",
        tier: ToolTier::Local,
        marker: "[local]",
    },
    ToolSurfaceEntry {
        name: "fact_history",
        tier: ToolTier::Local,
        marker: "[local]",
    },
    // agent-ux-01 readable/editable memory panel — free-tier local surface.
    ToolSurfaceEntry {
        name: "memory_view",
        tier: ToolTier::Local,
        marker: "[local]",
    },
    ToolSurfaceEntry {
        name: "memory_edit",
        tier: ToolTier::Local,
        marker: "[local]",
    },
    ToolSurfaceEntry {
        name: "memory_pin",
        tier: ToolTier::Local,
        marker: "[local]",
    },
    ToolSurfaceEntry {
        name: "memory_history",
        tier: ToolTier::Local,
        marker: "[local]",
    },
    ToolSurfaceEntry {
        name: "query_facts",
        tier: ToolTier::Local,
        marker: "[local]",
    },
    ToolSurfaceEntry {
        name: "delete_fact",
        tier: ToolTier::Local,
        marker: "[local]",
    },
    ToolSurfaceEntry {
        name: "list_entities",
        tier: ToolTier::Local,
        marker: "[local]",
    },
    ToolSurfaceEntry {
        name: "get_bootstrap",
        tier: ToolTier::Local,
        marker: "[local]",
    },
    ToolSurfaceEntry {
        name: "get_gaps",
        tier: ToolTier::Local,
        marker: "[local]",
    },
    ToolSurfaceEntry {
        name: "record_decision",
        tier: ToolTier::Local,
        marker: "[local]",
    },
    ToolSurfaceEntry {
        name: "declare_constraint",
        tier: ToolTier::Local,
        marker: "[local]",
    },
    ToolSurfaceEntry {
        name: "get_constraints",
        tier: ToolTier::Local,
        marker: "[local]",
    },
    ToolSurfaceEntry {
        name: "check_constraints",
        tier: ToolTier::Local,
        marker: "[local]",
    },
    ToolSurfaceEntry {
        name: "get_session",
        tier: ToolTier::Local,
        marker: "[local]",
    },
    ToolSurfaceEntry {
        name: "save_session",
        tier: ToolTier::Local,
        marker: "[local]",
    },
    ToolSurfaceEntry {
        name: "list_sessions",
        tier: ToolTier::Local,
        marker: "[local]",
    },
    ToolSurfaceEntry {
        name: "delete_session",
        tier: ToolTier::Local,
        marker: "[local]",
    },
    ToolSurfaceEntry {
        name: "create_handoff",
        tier: ToolTier::Local,
        marker: "[local]",
    },
    ToolSurfaceEntry {
        name: "accept_handoff",
        tier: ToolTier::Local,
        marker: "[local]",
    },
    ToolSurfaceEntry {
        name: "get_agent_identity",
        tier: ToolTier::Local,
        marker: "[local]",
    },
    ToolSurfaceEntry {
        name: "get_passport",
        tier: ToolTier::Local,
        marker: "[local]",
    },
    ToolSurfaceEntry {
        name: "sync_status",
        tier: ToolTier::Local,
        marker: "[local]",
    },
    ToolSurfaceEntry {
        name: "update_status",
        tier: ToolTier::Local,
        marker: "[local]",
    },
    // Identity continuity (agent-ux-08) — free-tier local surface.
    ToolSurfaceEntry {
        name: "passport_split",
        tier: ToolTier::Local,
        marker: "[local]",
    },
    ToolSurfaceEntry {
        name: "passport_merge",
        tier: ToolTier::Local,
        marker: "[local]",
    },
    ToolSurfaceEntry {
        name: "passport_link_device",
        tier: ToolTier::Local,
        marker: "[local]",
    },
    ToolSurfaceEntry {
        name: "issue_passport",
        tier: ToolTier::HostedGated,
        marker: "[hosted]",
    },
    ToolSurfaceEntry {
        name: "sync_pull",
        tier: ToolTier::HostedGated,
        marker: "[hosted]",
    },
    ToolSurfaceEntry {
        name: "sync_push",
        tier: ToolTier::HostedGated,
        marker: "[hosted]",
    },
];

pub fn tool_tier(name: &str) -> ToolTier {
    TOOL_SURFACE
        .iter()
        .find(|entry| entry.name == name)
        .map_or(ToolTier::Local, |entry| entry.tier)
}

pub fn marker_for_tool(name: &str) -> &'static str {
    TOOL_SURFACE
        .iter()
        .find(|entry| entry.name == name)
        .map_or("[local]", |entry| entry.marker)
}

pub fn is_local_tool(name: &str) -> bool {
    tool_tier(name) == ToolTier::Local
}

pub fn is_hosted_gated_tool(name: &str) -> bool {
    tool_tier(name) == ToolTier::HostedGated
}

pub fn hosted_gated_tool_names() -> Vec<&'static str> {
    TOOL_SURFACE
        .iter()
        .filter_map(|entry| (entry.tier == ToolTier::HostedGated).then_some(entry.name))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_and_issue_tools_are_hosted_gated() {
        assert!(is_hosted_gated_tool("issue_passport"));
        assert!(is_hosted_gated_tool("sync_pull"));
        assert!(is_hosted_gated_tool("sync_push"));
        assert!(!is_hosted_gated_tool("sync_status"));
    }

    #[test]
    fn unknown_tools_default_local_for_backward_compatibility() {
        assert_eq!(tool_tier("future_local_tool"), ToolTier::Local);
        assert_eq!(marker_for_tool("future_local_tool"), "[local]");
    }
}
