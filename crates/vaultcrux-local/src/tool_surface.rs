// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! MCP tool tier classification for the daemon-local VaultCrux surface.
//!
//! # What the marker means (and what it does not)
//!
//! The marker prefixed to each tool's description (`[tier:local]` / `[tier:hosted]`)
//! answers exactly one question: **which install tier can call this tool.** It is an
//! entitlement classification, not a routing one.
//!
//! It says nothing about *where the data goes*. Every tool — `[tier:local]` included —
//! executes against whichever daemon the MCP client is connected to, which is set by the
//! client's own config (`.mcp.json` `url`). A `[tier:local]` tool pointed at a remote
//! daemon reads and writes on that remote daemon.
//!
//! The markers were previously the bare words `[local]` / `[hosted]`, which read as a
//! claim about storage locality rather than tier — an agent concluded that `[local]
//! store_fact` wrote to its own machine and hand-rolled an HTTP call to reach the host it
//! was already connected to. The `tier:` prefix exists to make the misreading impossible.
//!
//! Related but independent, and easy to conflate:
//! - `sync_status` reporting `local_only` describes **remote fact mirroring**, not whether
//!   the MCP client can reach a daemon.
//! - A boot banner reporting the daemon `unreachable` describes **this session's MCP
//!   binding**, not the daemon's health. Probe `/readyz` before believing it.

/// Which install tier may call a tool. **Not** a statement about where data is stored —
/// see the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolTier {
    /// Callable on a free/local-tier install. Still executes against whatever daemon the
    /// MCP client is connected to, local or remote.
    Local,
    /// Requires the hosted control plane; refused on a local-tier install.
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
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "query",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "query_scan",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "query_expand",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "store_fact",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "fact_history",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    // agent-ux-01 readable/editable memory panel — free-tier local surface.
    ToolSurfaceEntry {
        name: "memory_view",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "memory_edit",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "memory_pin",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "memory_history",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "query_facts",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "delete_fact",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "list_entities",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "get_bootstrap",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "get_gaps",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "record_decision",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "declare_constraint",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "get_constraints",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "check_constraints",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "get_session",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "save_session",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "list_sessions",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "delete_session",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "create_handoff",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "accept_handoff",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "get_agent_identity",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "get_passport",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "request_passport_mint",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "sync_status",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "update_status",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    // Identity continuity (agent-ux-08) — free-tier local surface.
    ToolSurfaceEntry {
        name: "passport_split",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "passport_merge",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "passport_link_device",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "issue_passport",
        tier: ToolTier::HostedGated,
        marker: "[tier:hosted]",
    },
    ToolSurfaceEntry {
        name: "sync_pull",
        tier: ToolTier::HostedGated,
        marker: "[tier:hosted]",
    },
    ToolSurfaceEntry {
        name: "sync_push",
        tier: ToolTier::HostedGated,
        marker: "[tier:hosted]",
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
        .map_or("[tier:local]", |entry| entry.marker)
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
        assert_eq!(marker_for_tool("future_local_tool"), "[tier:local]");
    }

    #[test]
    fn passport_mint_request_is_explicitly_local() {
        assert!(is_local_tool("request_passport_mint"));
        assert_eq!(marker_for_tool("request_passport_mint"), "[tier:local]");
    }
}
