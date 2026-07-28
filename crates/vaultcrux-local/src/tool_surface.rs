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
    // ── Context graph — storybook readout + agent dossier exchange ──────────
    // Local tier: every one of these executes against the project graph, the
    // workspace scan and the fact store of whichever daemon the client is
    // connected to. No hosted control plane is involved, which is also why they
    // declare `x-crux-min-tier: free`.
    //
    // Without an entry here `is_local_tool` is false, so the capability
    // `crux-mcp.<tool>` never enters `rcx_local_capabilities`, and the RCX
    // router refuses every call with `denied:capability_not_permitted`. Absent
    // from this table a tool is not merely unadvertised — it is DEAD on any
    // RCX-gated daemon, which is what host `crux` runs.
    ToolSurfaceEntry {
        name: "get_project_storybook",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "generate_project_storybook",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "diff_project_storybook",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "get_project_dossiers",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "generate_project_dossier",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "publish_project_dossier",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "reconcile_project_dossiers",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "diff_project_dossiers",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    // ── The remaining catalogue, all Local tier ────────────────────────────
    //
    // Classified against the rule the existing table already encodes: HostedGated
    // means the tool REQUIRES the hosted control plane. Only three do —
    // `issue_passport` (identity minted by a remote authority) and
    // `sync_pull`/`sync_push` (facts moved to and from the remote plane), which
    // `sync_and_issue_tools_are_hosted_gated` locks in. Every tool below runs
    // against the project graph, fact store, entity store, receipts, coordination
    // plane or integration credentials of whichever daemon the client is connected
    // to, so none of them can be hosted-gated without changing what the tier means.
    //
    // `github_*` egress to GitHub through the daemon's own stored PAT. That is
    // external egress, not the hosted CueCrux plane, and the tier is an
    // install-tier entitlement rather than an egress classification — see the
    // module docs. Egress is carried separately by `data_egress_classes`.
    //
    // This also matches the standing commercial rule: what runs on the operator's
    // own silicon over their own data ships Free (dense-lane-and-extraction-upsell
    // -2026-06-26). Flag-gated tools (`reuse_check`, `engram_resolve`, …) stay
    // flag-gated — that is orthogonal to tier and unchanged here.
    //
    // Until 2026-07-28 these 85 had no entry at all, so `rcx_local_capabilities`
    // never emitted `crux-mcp.<name>` and the RCX router refused every call with
    // `denied:capability_not_permitted`. They were not degraded; they were dead.
    ToolSurfaceEntry {
        name: "activity_recent",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "approval_decide",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "approval_request",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "archive_session",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "artefact_get",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "artefact_list",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "artefact_put",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "attach_to_orchestrator",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "audit_config",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "audit_export_bundle",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "auth_posture_audit",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "autonomy_contract",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "check_config_audit",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "check_punchcard",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    // Runtime code intelligence (crux-codemap-agent-surface M1). Local because
    // each one proxies a /v1/code-intel/* route on whichever daemon the client
    // is already connected to, reading that daemon's own workspace scan and
    // trace store — no hosted control plane is involved. The Pro surface these
    // could sit behind is specified in that plan's M5 and deliberately not
    // built, so HostedGated would gate them on a plane that does not exist.
    ToolSurfaceEntry {
        name: "code_blast_radius",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "code_dead_code",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "code_liveness",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "code_path",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "code_trace_diff",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "comment_on_work",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "context_custody_audit",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "coord_announce",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "coord_status",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "create_orchestrator",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "create_work",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "detach_from_orchestrator",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "edge_delete",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "edge_get",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "edge_list",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "edge_upsert",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "egress_policy_check",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "engram_resolve",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "enrich_action",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "entity_delete",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "entity_get",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "entity_history",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "entity_list",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "entity_upsert",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "execplan_gate",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "feature_coverage_report",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "feature_file_search",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "feature_suggest_next",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "feature_trigger_audit",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "force_release",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "get_observation",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "get_project_context",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "get_workspace_storyline",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "github_comments_since",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "github_open_issues",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "github_open_prs",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "github_recent_commits",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "github_search",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "kind_get",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "kind_list",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "learn",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "list_observations",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "list_orchestrators",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "list_projects",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "list_punchcards",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "list_repos",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "list_work",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "memory_acknowledge_use",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "memory_consolidate",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "memory_contradictions",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "memory_forget",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "memory_forget_dry_run",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "memory_freshness",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "memory_reverify",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "memory_set_horizon",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "memory_sweep_candidates",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "output_attest",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "punch_in",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "punch_out",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "receipt_verify",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "register_repo",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "resolve_principal",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "reuse_check",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "revoke_passport",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "route_access_matrix",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "session_checkpoint",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "session_token_usage",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "status_feed",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "token_savings",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "tool_trace_recent",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "unarchive_session",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "update_orchestrator",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "update_work_state",
        tier: ToolTier::Local,
        marker: "[tier:local]",
    },
    ToolSurfaceEntry {
        name: "verify_observation",
        tier: ToolTier::Local,
        marker: "[tier:local]",
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
