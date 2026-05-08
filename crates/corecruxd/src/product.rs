// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

use corecrux_memory::sync::{SyncRuntimeStatus, SYNC_COLLECTIONS};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatingMode {
    FreeLocal,
    ProLocalFirst,
    ProCloudOnly,
    ProHybrid,
    MaxPrivate,
}

impl Default for OperatingMode {
    fn default() -> Self {
        Self::FreeLocal
    }
}

impl OperatingMode {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().replace('-', "_").as_str() {
            "free_local" | "free" | "local" => Some(Self::FreeLocal),
            "pro_local_first" | "pro_local" | "local_first" => Some(Self::ProLocalFirst),
            "pro_cloud_only" | "cloud_only" => Some(Self::ProCloudOnly),
            "pro_hybrid" | "hybrid" | "pro" => Some(Self::ProHybrid),
            "max_private" | "max" | "private" | "onsite" | "on_site" => Some(Self::MaxPrivate),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::FreeLocal => "free_local",
            Self::ProLocalFirst => "pro_local_first",
            Self::ProCloudOnly => "pro_cloud_only",
            Self::ProHybrid => "pro_hybrid",
            Self::MaxPrivate => "max_private",
        }
    }

    fn tier(self) -> &'static str {
        match self {
            Self::FreeLocal => "free",
            Self::ProLocalFirst | Self::ProCloudOnly | Self::ProHybrid => "pro",
            Self::MaxPrivate => "max",
        }
    }

    fn includes_pro(self) -> bool {
        !matches!(self, Self::FreeLocal)
    }
}

pub const FREE_CAPABILITY_CLAIMS: &[&str] = &[
    "daemon:local",
    "mcp:basic",
    "facts:local",
    "sessions:local",
    "scoping:private",
    "workspace:storyline_basic",
    "project:basic",
    "verify:basic",
    "constraints:basic",
    "action_enrichment:basic",
    "projection:revisioning",
    "receipts:local",
    "tenant:isolation",
    "store:durable",
];

pub const PRO_CAPABILITY_CLAIMS: &[&str] = &[
    "memorycrux:tenant",
    "gpu1:answer",
    "gpu1:rerank",
    "gpu1:enrich",
    "gpu1:coverage",
    "gpu1:developer",
    "sync:mirror",
    "sync:promote",
    "sync:managed_backup",
    "replay:answer",
    "agent_brief:pro",
    "context_pack:budgeted",
    "impact:preflight",
    "ledger:history",
    "audit:triage",
    "audit:central_retention",
    "reasoning:timeline",
    "handoff:v2",
    "route_probe:lab",
    "api_drift:check",
    "policy:simulate",
    "policy_packs:team",
    "decision_memory:shared",
    "sso:rbac",
    "passport_policy:org",
    "exports:compliance",
    "enrichers:first_party",
    "enrichers:custom",
    "materiality:custom",
    "console:workbench",
    "control_plane:hosted",
    "credits:pooled",
    "tenant:business_offboarding",
];

pub const DAEMON_IMPLEMENTED_PRO_CLAIMS: &[&str] = &[
    "gpu1:answer",
    "gpu1:rerank",
    "gpu1:enrich",
    "gpu1:coverage",
    "gpu1:developer",
    "sync:mirror",
    "sync:promote",
    "replay:answer",
    "agent_brief:pro",
    "context_pack:budgeted",
    "impact:preflight",
    "ledger:history",
    "audit:triage",
    "reasoning:timeline",
    "handoff:v2",
    "route_probe:lab",
    "api_drift:check",
    "policy:simulate",
    "enrichers:first_party",
    "console:workbench",
    "tenant:business_offboarding",
];

pub const HOSTED_CONTROL_PLANE_PRO_CLAIMS: &[&str] = &[
    "memorycrux:tenant",
    "sync:managed_backup",
    "audit:central_retention",
    "policy_packs:team",
    "decision_memory:shared",
    "sso:rbac",
    "passport_policy:org",
    "exports:compliance",
    "enrichers:custom",
    "materiality:custom",
    "control_plane:hosted",
    "credits:pooled",
];

pub const MAX_CAPABILITY_CLAIMS: &[&str] = &[
    "gpu:onsite",
    "tenant_infra:private",
    "registry:private_mirror",
    "replay_archive:airgapped",
];

#[derive(Debug, Clone, Serialize)]
pub struct CapabilityCatalog {
    pub free: Vec<&'static str>,
    pub pro: Vec<&'static str>,
    pub max: Vec<&'static str>,
    pub pro_claim_placements: Vec<ProClaimPlacement>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProClaimPlacement {
    pub claim: &'static str,
    pub implementation: &'static str,
    pub daemon_implemented: bool,
    pub hosted_control_plane: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProductPosture {
    pub mode: &'static str,
    pub tier: &'static str,
    pub enabled_capability_claims: Vec<&'static str>,
    pub enabled_pro_services: Vec<String>,
    pub configured_pro_services: Vec<String>,
    pub capability_catalog: CapabilityCatalog,
    pub daemon_implemented_pro_claims: Vec<&'static str>,
    pub hosted_control_plane_pro_claims: Vec<&'static str>,
    pub free_safety_baseline_active: bool,
}

impl ProductPosture {
    pub fn new(mode: OperatingMode, configured_pro_services: &[String]) -> Self {
        let enabled_capability_claims = enabled_capability_claims(mode);
        let enabled_pro_services = configured_pro_services
            .iter()
            .filter(|service| mode.includes_pro() && contains_claim(PRO_CAPABILITY_CLAIMS, service))
            .cloned()
            .collect();

        Self {
            mode: mode.as_str(),
            tier: mode.tier(),
            enabled_capability_claims,
            enabled_pro_services,
            configured_pro_services: configured_pro_services.to_vec(),
            capability_catalog: CapabilityCatalog {
                free: FREE_CAPABILITY_CLAIMS.to_vec(),
                pro: PRO_CAPABILITY_CLAIMS.to_vec(),
                max: MAX_CAPABILITY_CLAIMS.to_vec(),
                pro_claim_placements: pro_claim_placements(),
            },
            daemon_implemented_pro_claims: DAEMON_IMPLEMENTED_PRO_CLAIMS.to_vec(),
            hosted_control_plane_pro_claims: HOSTED_CONTROL_PLANE_PRO_CLAIMS.to_vec(),
            free_safety_baseline_active: true,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CloudPosture {
    pub tenant_connectivity: &'static str,
    pub local_mirror_state: &'static str,
    pub configured: bool,
    pub background_sync_enabled: bool,
    pub remote_url: String,
    pub api_key_configured: bool,
    pub platform_online: Option<bool>,
    pub degraded: bool,
    pub degraded_reason: Option<String>,
}

impl CloudPosture {
    pub fn from_sync(status: &SyncRuntimeStatus) -> Self {
        let tenant_connectivity = if status.degraded {
            "degraded"
        } else if status.configured {
            match status.platform_online {
                Some(true) => "online",
                Some(false) => "offline",
                None => "configured",
            }
        } else if status.remote_url.is_empty() {
            "not_configured"
        } else {
            "incomplete"
        };

        let local_mirror_state = if status.degraded {
            "degraded"
        } else if status.configured && status.background_sync_enabled {
            "enabled"
        } else if status.configured {
            "manual"
        } else {
            "disabled"
        };

        Self {
            tenant_connectivity,
            local_mirror_state,
            configured: status.configured,
            background_sync_enabled: status.background_sync_enabled,
            remote_url: status.remote_url.clone(),
            api_key_configured: status.api_key_configured,
            platform_online: status.platform_online,
            degraded: status.degraded,
            degraded_reason: status.degraded_reason.clone(),
        }
    }
}

pub const CLOUD_ACCESS_CONTRACT_SCHEMA: &str = "crux.cloud_access_contract.v1";

#[derive(Debug, Clone, Serialize)]
pub struct CloudAccessContract {
    pub schema: &'static str,
    pub mode: &'static str,
    pub tier: &'static str,
    pub cloud_only_entitled: bool,
    pub cloud_only_active: bool,
    pub local_daemon_required_for_current_mode: bool,
    pub mode_switching_supported: bool,
    pub configured_rest_base_url: Option<String>,
    pub hosted_mcp: HostedMcpContract,
    pub hosted_rest: HostedRestContract,
    pub tenant_memory_model: TenantMemoryModelContract,
    pub receipt_model: ReceiptModelContract,
    pub semantic_profile_model: SemanticProfileModelContract,
    pub pro_gpu_services: Vec<ProGpuServiceContract>,
    pub pro_claim_placements: Vec<ProClaimPlacement>,
    pub tradeoffs: Vec<CloudAccessTradeoff>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostedMcpContract {
    pub contract: &'static str,
    pub transports: Vec<&'static str>,
    pub session_tool: &'static str,
    pub tool_catalog: Vec<&'static str>,
    pub auth: Vec<&'static str>,
    pub local_daemon_required: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostedRestContract {
    pub contract: &'static str,
    pub base_url_configured: bool,
    pub endpoints: Vec<RestEndpointContract>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RestEndpointContract {
    pub name: &'static str,
    pub method: &'static str,
    pub hosted_path: &'static str,
    pub local_path: Option<&'static str>,
    pub scopes: Vec<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TenantMemoryModelContract {
    pub tenant_categories: Vec<&'static str>,
    pub collections: Vec<&'static str>,
    pub canonical_record_model: &'static str,
    pub cloud_to_local_mirror: &'static str,
    pub local_to_cloud_promotion: &'static str,
    pub business_offboarding: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReceiptModelContract {
    pub local_export_paths: Vec<&'static str>,
    pub hosted_export_paths: Vec<&'static str>,
    pub deterministic_replay: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct SemanticProfileModelContract {
    pub canonical_profile_field: &'static str,
    pub local_profile_field: &'static str,
    pub score_merge_rule: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProGpuServiceContract {
    pub capability: &'static str,
    pub operation: &'static str,
    pub status: &'static str,
    pub payload_policy: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct CloudAccessTradeoff {
    pub mode: &'static str,
    pub local_daemon_required: bool,
    pub offline_continuity: bool,
    pub local_workspace_context: &'static str,
    pub best_for: &'static str,
}

impl CloudAccessContract {
    pub fn new(mode: OperatingMode, configured_pro_services: &[String], cloud: &CloudPosture) -> Self {
        let cloud_only_entitled = matches!(
            mode,
            OperatingMode::ProLocalFirst | OperatingMode::ProCloudOnly | OperatingMode::ProHybrid
        );
        let cloud_only_active = matches!(mode, OperatingMode::ProCloudOnly | OperatingMode::ProHybrid);
        let local_daemon_required_for_current_mode = matches!(
            mode,
            OperatingMode::FreeLocal | OperatingMode::ProLocalFirst | OperatingMode::MaxPrivate
        );
        let enabled = ProductPosture::new(mode, configured_pro_services).enabled_pro_services;

        Self {
            schema: CLOUD_ACCESS_CONTRACT_SCHEMA,
            mode: mode.as_str(),
            tier: mode.tier(),
            cloud_only_entitled,
            cloud_only_active,
            local_daemon_required_for_current_mode,
            mode_switching_supported: cloud_only_entitled,
            configured_rest_base_url: (!cloud.remote_url.is_empty()).then(|| cloud.remote_url.clone()),
            hosted_mcp: HostedMcpContract {
                contract: "cuecrux.hosted_mcp.v1",
                transports: vec!["streamable_http", "sse"],
                session_tool: "cuecrux_session",
                tool_catalog: vec![
                    "cuecrux_session",
                    "query",
                    "query_scan",
                    "query_expand",
                    "store_fact",
                    "query_facts",
                    "delete_fact",
                    "fact_history",
                    "get_session",
                    "save_session",
                    "list_sessions",
                    "sync_status",
                    "sync_pull",
                    "sync_push",
                ],
                auth: vec!["bearer_jwt", "api_key"],
                local_daemon_required: false,
            },
            hosted_rest: HostedRestContract {
                contract: "cuecrux.hosted_rest.v1",
                base_url_configured: !cloud.remote_url.is_empty(),
                endpoints: hosted_rest_endpoints(),
            },
            tenant_memory_model: TenantMemoryModelContract {
                tenant_categories: vec!["personal", "business"],
                collections: SYNC_COLLECTIONS.to_vec(),
                canonical_record_model: "tenant_id + collection + entity/key/value + content_hash + provenance",
                cloud_to_local_mirror: "pull shared tenant collections by manifest/cursor/hash",
                local_to_cloud_promotion: "explicit preview/confirm with allowlist; no blind local upload",
                business_offboarding: "revoke membership, stop sync, delete local mirror data, emit signed wipe proof",
            },
            receipt_model: ReceiptModelContract {
                local_export_paths: vec![
                    "/v1/replay/answers/{answerId}",
                    "/v1/replay/answers/{answerId}/validity",
                    "/v1/replay/exports/receipts/{receiptId}",
                    "/v1/replay/exports/answers/{answerId}",
                    "/v1/replay/exports/actions/{actionId}",
                    "/v1/replay/exports/streams/{streamType}/{streamId}",
                ],
                hosted_export_paths: vec![
                    "/v1/replay/answers/{answerId}",
                    "/v1/replay/answers/{answerId}/validity",
                    "/v1/replay/exports/receipts/{receiptId}",
                    "/v1/replay/exports/answers/{answerId}",
                    "/v1/replay/exports/actions/{actionId}",
                    "/v1/replay/exports/streams/{streamType}/{streamId}",
                ],
                deterministic_replay: "historical replay renders stored answer/evidence without the original agent or LLM; current validity is a separate drift check",
            },
            semantic_profile_model: SemanticProfileModelContract {
                canonical_profile_field: "semantic_profile_id",
                local_profile_field: "local_semantic_profile_id",
                score_merge_rule: "rank fusion or rerank only; never compare raw cosine scores across different profiles",
            },
            pro_gpu_services: pro_gpu_services(&enabled, cloud_only_entitled),
            pro_claim_placements: pro_claim_placements(),
            tradeoffs: vec![
                CloudAccessTradeoff {
                    mode: "cloud_only",
                    local_daemon_required: false,
                    offline_continuity: false,
                    local_workspace_context: "only via connected cloud integrations or uploaded context",
                    best_for: "customers that want agents and systems to connect directly to hosted tenant memory",
                },
                CloudAccessTradeoff {
                    mode: "local_first",
                    local_daemon_required: true,
                    offline_continuity: true,
                    local_workspace_context: "native daemon workspace scan, local facts, sessions, and private agent state",
                    best_for: "developers who want offline work and rich local repo/process context",
                },
                CloudAccessTradeoff {
                    mode: "hybrid",
                    local_daemon_required: false,
                    offline_continuity: true,
                    local_workspace_context: "local daemons add private workspace context; cloud clients use shared tenant memory directly",
                    best_for: "teams mixing local agents, hosted agents, and direct system integrations",
                },
            ],
        }
    }
}

fn hosted_rest_endpoints() -> Vec<RestEndpointContract> {
    vec![
        RestEndpointContract {
            name: "session_plan",
            method: "POST",
            hosted_path: "/v1/session",
            local_path: Some("/session"),
            scopes: vec!["sessions:write"],
        },
        RestEndpointContract {
            name: "tenant_manifest",
            method: "GET",
            hosted_path: "/v1/sync/tenants/{tenantId}/manifest",
            local_path: Some("/v1/sync/tenants/{tenantId}/manifest"),
            scopes: vec!["facts:read"],
        },
        RestEndpointContract {
            name: "tenant_collection_page",
            method: "GET",
            hosted_path: "/v1/sync/tenants/{tenantId}/collections/{collection}",
            local_path: Some("/v1/sync/tenants/{tenantId}/collections/{collection}"),
            scopes: vec!["facts:read"],
        },
        RestEndpointContract {
            name: "tenant_promotion_preview",
            method: "POST",
            hosted_path: "/v1/sync/tenants/{tenantId}/promotions/preview",
            local_path: Some("/v1/sync/tenants/{tenantId}/promotions/preview"),
            scopes: vec!["facts:read"],
        },
        RestEndpointContract {
            name: "tenant_promotion_confirm",
            method: "POST",
            hosted_path: "/v1/sync/tenants/{tenantId}/promotions/confirm",
            local_path: Some("/v1/sync/tenants/{tenantId}/promotions/confirm"),
            scopes: vec!["facts:write"],
        },
        RestEndpointContract {
            name: "fact_memory",
            method: "PUT/GET/DELETE",
            hosted_path: "/v1/facts",
            local_path: Some("/v1/facts"),
            scopes: vec!["facts:write", "query:read"],
        },
        RestEndpointContract {
            name: "engram_resolution",
            method: "POST",
            hosted_path: "/v1/memory/engrams/resolve",
            local_path: Some("/v1/memory/engrams/resolve"),
            scopes: vec!["query:read"],
        },
        RestEndpointContract {
            name: "action_enrichment",
            method: "POST",
            hosted_path: "/v1/actions/enrich",
            local_path: Some("/v1/actions/enrich"),
            scopes: vec!["query:read", "enrichers:first_party"],
        },
        RestEndpointContract {
            name: "agent_workbench_contract",
            method: "GET",
            hosted_path: "/v1/workbench/contract",
            local_path: Some("/v1/workbench/contract"),
            scopes: vec!["query:read"],
        },
        RestEndpointContract {
            name: "agent_brief_pro",
            method: "GET",
            hosted_path: "/v1/workbench/brief",
            local_path: Some("/v1/workbench/brief"),
            scopes: vec!["agent_brief:pro"],
        },
        RestEndpointContract {
            name: "context_pack",
            method: "POST",
            hosted_path: "/v1/workbench/context-pack",
            local_path: Some("/v1/workbench/context-pack"),
            scopes: vec!["context_pack:budgeted"],
        },
        RestEndpointContract {
            name: "change_impact_preflight",
            method: "POST",
            hosted_path: "/v1/workbench/impact-preflight",
            local_path: Some("/v1/workbench/impact-preflight"),
            scopes: vec!["impact:preflight"],
        },
        RestEndpointContract {
            name: "command_test_ledger",
            method: "GET/POST",
            hosted_path: "/v1/workbench/command-ledger",
            local_path: Some("/v1/workbench/command-ledger"),
            scopes: vec!["ledger:history"],
        },
        RestEndpointContract {
            name: "audit_triage_mode",
            method: "GET",
            hosted_path: "/v1/workbench/audit-triage",
            local_path: Some("/v1/workbench/audit-triage"),
            scopes: vec!["audit:triage"],
        },
        RestEndpointContract {
            name: "reasoning_timeline",
            method: "GET",
            hosted_path: "/v1/workbench/reasoning-timeline",
            local_path: Some("/v1/workbench/reasoning-timeline"),
            scopes: vec!["reasoning:timeline"],
        },
        RestEndpointContract {
            name: "handoff_v2",
            method: "POST",
            hosted_path: "/v1/workbench/handoff-v2",
            local_path: Some("/v1/workbench/handoff-v2"),
            scopes: vec!["handoff:v2"],
        },
        RestEndpointContract {
            name: "route_probe_lab",
            method: "POST",
            hosted_path: "/v1/workbench/route-probe",
            local_path: Some("/v1/workbench/route-probe"),
            scopes: vec!["route_probe:lab"],
        },
        RestEndpointContract {
            name: "api_scope_drift_checker",
            method: "GET",
            hosted_path: "/v1/workbench/api-drift",
            local_path: Some("/v1/workbench/api-drift"),
            scopes: vec!["api_drift:check"],
        },
        RestEndpointContract {
            name: "semantic_policy_simulation",
            method: "POST",
            hosted_path: "/v1/workbench/policy-simulation",
            local_path: Some("/v1/workbench/policy-simulation"),
            scopes: vec!["policy:simulate"],
        },
        RestEndpointContract {
            name: "semantic_profile_posture",
            method: "GET",
            hosted_path: "/v1/admin/segments/fingerprints",
            local_path: Some("/v1/admin/segments/fingerprints"),
            scopes: vec!["admin:read"],
        },
        RestEndpointContract {
            name: "projection_modules",
            method: "GET",
            hosted_path: "/v1/admin/projections/modules",
            local_path: Some("/v1/admin/projections/modules"),
            scopes: vec!["admin:read"],
        },
        RestEndpointContract {
            name: "receipt_export",
            method: "GET",
            hosted_path: "/v1/replay/exports/{kind}/{id}",
            local_path: Some("/v1/replay/exports/{kind}/{id}"),
            scopes: vec!["exports:read", "receipts:read"],
        },
        RestEndpointContract {
            name: "answer_replay",
            method: "GET",
            hosted_path: "/v1/replay/answers/{answerId}",
            local_path: Some("/v1/replay/answers/{answerId}"),
            scopes: vec!["replay:answer"],
        },
        RestEndpointContract {
            name: "answer_replay_validity",
            method: "GET",
            hosted_path: "/v1/replay/answers/{answerId}/validity",
            local_path: Some("/v1/replay/answers/{answerId}/validity"),
            scopes: vec!["replay:answer"],
        },
        RestEndpointContract {
            name: "gpu1_answer",
            method: "POST",
            hosted_path: "/v1/query/answer",
            local_path: Some("/v1/gpu1/answer"),
            scopes: vec!["gpu1:answer"],
        },
        RestEndpointContract {
            name: "gpu1_rerank",
            method: "POST",
            hosted_path: "/v1/query/rerank",
            local_path: Some("/v1/gpu1/rerank"),
            scopes: vec!["gpu1:rerank"],
        },
        RestEndpointContract {
            name: "gpu1_enrich",
            method: "POST",
            hosted_path: "/v1/actions/enrich",
            local_path: Some("/v1/gpu1/enrich"),
            scopes: vec!["gpu1:enrich"],
        },
        RestEndpointContract {
            name: "gpu1_coverage",
            method: "POST",
            hosted_path: "/v1/query/coverage",
            local_path: Some("/v1/gpu1/coverage"),
            scopes: vec!["gpu1:coverage"],
        },
        RestEndpointContract {
            name: "gpu1_developer",
            method: "POST",
            hosted_path: "/v1/developer/surface",
            local_path: Some("/v1/gpu1/developer"),
            scopes: vec!["gpu1:developer"],
        },
    ]
}

fn pro_gpu_services(enabled: &[String], cloud_only_entitled: bool) -> Vec<ProGpuServiceContract> {
    [
        ("gpu1:answer", "answer"),
        ("gpu1:rerank", "rerank"),
        ("gpu1:enrich", "enrich"),
        ("gpu1:coverage", "coverage"),
        ("gpu1:developer", "developer"),
    ]
    .into_iter()
    .map(|(capability, operation)| {
        let status = if enabled.iter().any(|service| service == capability) {
            "enabled"
        } else if cloud_only_entitled {
            "entitled_not_configured"
        } else {
            "pro_required"
        };
        ProGpuServiceContract {
            capability,
            operation,
            status,
            payload_policy: "send task-shaped context, selected evidence, profile IDs, and hashes; do not upload the whole local store",
        }
    })
    .collect()
}

fn enabled_capability_claims(mode: OperatingMode) -> Vec<&'static str> {
    let mut claims = FREE_CAPABILITY_CLAIMS.to_vec();
    if mode.includes_pro() {
        claims.extend_from_slice(PRO_CAPABILITY_CLAIMS);
    }
    if matches!(mode, OperatingMode::MaxPrivate) {
        claims.extend_from_slice(MAX_CAPABILITY_CLAIMS);
    }
    claims
}

fn pro_claim_placements() -> Vec<ProClaimPlacement> {
    PRO_CAPABILITY_CLAIMS
        .iter()
        .map(|claim| {
            let daemon = contains_claim(DAEMON_IMPLEMENTED_PRO_CLAIMS, *claim);
            let hosted = contains_claim(HOSTED_CONTROL_PLANE_PRO_CLAIMS, *claim);
            let implementation = match (daemon, hosted) {
                (true, true) => "daemon_and_hosted_control_plane",
                (true, false) => "daemon",
                (false, true) => "hosted_control_plane",
                (false, false) => "contracted_external",
            };
            ProClaimPlacement {
                claim: *claim,
                implementation,
                daemon_implemented: daemon,
                hosted_control_plane: hosted,
            }
        })
        .collect()
}

fn contains_claim(claims: &[&str], value: &str) -> bool {
    claims.iter().any(|claim| claim == &value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operating_mode_parse_accepts_public_spellings() {
        assert_eq!(OperatingMode::parse("free_local"), Some(OperatingMode::FreeLocal));
        assert_eq!(
            OperatingMode::parse("pro-local-first"),
            Some(OperatingMode::ProLocalFirst)
        );
        assert_eq!(OperatingMode::parse("cloud_only"), Some(OperatingMode::ProCloudOnly));
        assert_eq!(OperatingMode::parse("pro"), Some(OperatingMode::ProHybrid));
        assert_eq!(OperatingMode::parse("onsite"), Some(OperatingMode::MaxPrivate));
    }

    #[test]
    fn free_mode_keeps_safety_baseline_without_pro_claims() {
        let posture = ProductPosture::new(OperatingMode::FreeLocal, &[]);

        for required in FREE_CAPABILITY_CLAIMS {
            assert!(
                posture.enabled_capability_claims.contains(required),
                "missing Free baseline capability {required}"
            );
        }
        for gated in PRO_CAPABILITY_CLAIMS {
            assert!(
                !posture.enabled_capability_claims.contains(gated),
                "Free mode must not enable Pro claim {gated}"
            );
        }
        assert!(posture.free_safety_baseline_active);
        assert_eq!(posture.enabled_pro_services, Vec::<String>::new());
    }

    #[test]
    fn pro_mode_enables_free_and_pro_but_not_max_claims() {
        let configured = vec![
            "gpu1:answer".to_string(),
            "sync:mirror".to_string(),
            "gpu:onsite".to_string(),
            "unknown:service".to_string(),
        ];
        let posture = ProductPosture::new(OperatingMode::ProHybrid, &configured);

        assert!(posture.enabled_capability_claims.contains(&"daemon:local"));
        assert!(posture.enabled_capability_claims.contains(&"gpu1:answer"));
        assert!(!posture.enabled_capability_claims.contains(&"gpu:onsite"));
        assert_eq!(posture.enabled_pro_services, vec!["gpu1:answer", "sync:mirror"]);
    }

    #[test]
    fn pro_claims_are_labelled_by_implementation_placement() {
        let posture = ProductPosture::new(OperatingMode::ProHybrid, &[]);

        assert!(posture.daemon_implemented_pro_claims.contains(&"impact:preflight"));
        assert!(posture.hosted_control_plane_pro_claims.contains(&"sso:rbac"));
        let placements = posture.capability_catalog.pro_claim_placements;
        assert!(placements.iter().any(|placement| {
            placement.claim == "impact:preflight"
                && placement.implementation == "daemon"
                && placement.daemon_implemented
                && !placement.hosted_control_plane
        }));
        assert!(placements.iter().any(|placement| {
            placement.claim == "sso:rbac"
                && placement.implementation == "hosted_control_plane"
                && !placement.daemon_implemented
                && placement.hosted_control_plane
        }));
    }

    #[test]
    fn max_mode_adds_private_placement_claims() {
        let posture = ProductPosture::new(OperatingMode::MaxPrivate, &[]);

        assert!(posture.enabled_capability_claims.contains(&"gpu1:answer"));
        assert!(posture.enabled_capability_claims.contains(&"gpu:onsite"));
        assert!(posture.enabled_capability_claims.contains(&"tenant_infra:private"));
    }

    #[test]
    fn cloud_posture_maps_sync_status_to_customer_language() {
        let status = SyncRuntimeStatus::from_settings(true, Some("https://memory.example"), true);
        let posture = CloudPosture::from_sync(&status);

        assert_eq!(posture.tenant_connectivity, "configured");
        assert_eq!(posture.local_mirror_state, "enabled");

        let local = SyncRuntimeStatus::from_settings(false, None, false);
        let posture = CloudPosture::from_sync(&local);
        assert_eq!(posture.tenant_connectivity, "not_configured");
        assert_eq!(posture.local_mirror_state, "disabled");
    }

    #[test]
    fn cloud_access_contract_marks_cloud_only_as_no_daemon_required() {
        let sync = SyncRuntimeStatus::from_settings(false, Some("https://memory.example"), true);
        let cloud = CloudPosture::from_sync(&sync);
        let contract = CloudAccessContract::new(OperatingMode::ProCloudOnly, &["gpu1:answer".to_string()], &cloud);

        assert_eq!(contract.schema, CLOUD_ACCESS_CONTRACT_SCHEMA);
        assert!(contract.cloud_only_entitled);
        assert!(contract.cloud_only_active);
        assert!(!contract.local_daemon_required_for_current_mode);
        assert_eq!(
            contract.configured_rest_base_url,
            Some("https://memory.example".to_string())
        );
        assert!(contract.tenant_memory_model.collections.contains(&"facts"));
        assert!(contract.tenant_memory_model.collections.contains(&"semantic_profiles"));
        assert_eq!(contract.hosted_mcp.local_daemon_required, false);
        assert!(contract
            .hosted_rest
            .endpoints
            .iter()
            .any(|endpoint| endpoint.hosted_path == "/v1/session" && endpoint.local_path == Some("/session")));
        assert_eq!(contract.pro_gpu_services[0].status, "enabled");
    }

    #[test]
    fn free_cloud_access_contract_is_visible_but_not_entitled() {
        let sync = SyncRuntimeStatus::from_settings(false, None, false);
        let cloud = CloudPosture::from_sync(&sync);
        let contract = CloudAccessContract::new(OperatingMode::FreeLocal, &[], &cloud);

        assert!(!contract.cloud_only_entitled);
        assert!(!contract.cloud_only_active);
        assert!(contract.local_daemon_required_for_current_mode);
        assert_eq!(contract.pro_gpu_services[0].status, "pro_required");
        assert!(contract
            .tradeoffs
            .iter()
            .any(|tradeoff| tradeoff.mode == "cloud_only" && !tradeoff.local_daemon_required));
    }
}
