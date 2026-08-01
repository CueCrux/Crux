// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Product-tier metadata + sync-runtime status types — feeds `/v1/version` and onboarding probes.

use corecrux_memory::sync::{SyncRuntimeStatus, SYNC_COLLECTIONS};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatingMode {
    FreeLocal,
    ProLocalFirst,
    ProCloudOnly,
    ProHybrid,
    /// Governance tier. Reachable from a verified `RcxTier::Governance`
    /// capability token; `ProCloudOnly` and `ProHybrid` are not reachable from any
    /// tier mapping and are retained for explicitly configured hosted deployments.
    GovernanceHosted,
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
            "governance_hosted" | "governance" => Some(Self::GovernanceHosted),
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
            Self::GovernanceHosted => "governance_hosted",
            Self::MaxPrivate => "max_private",
        }
    }

    fn tier(self) -> &'static str {
        match self {
            Self::FreeLocal => "free",
            Self::ProLocalFirst | Self::ProCloudOnly | Self::ProHybrid => "pro",
            Self::GovernanceHosted => "governance",
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

/// A claim listed here is **sold**, and `require_surface_enabled` will let a
/// paying tenant reach the surface behind it. So a claim earns its place by
/// delivering something, not by having an implemented route.
///
/// `ledger:history` is deliberately absent. `/v1/workbench/command-ledger` is
/// implemented in both directions and still served — but no CLI, MCP tool or
/// hook has ever written a record to it, so the capability could only ever
/// render an empty page. Do not re-add it without landing a producer first;
/// the surface returns `402 pro_service_not_enabled` until then, and
/// `workbench_command_ledger_is_not_a_sold_claim_without_a_producer` pins
/// that. Removing it from [`DAEMON_IMPLEMENTED_PRO_CLAIMS`] alone would have
/// been worse than leaving it: `pro_claim_placements` would then report it as
/// `contracted_external`, asserting an outside implementer that does not
/// exist. See ExecPlan `crux-command-ledger-claim-truth-2026-07-30`.
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_capabilities: Option<RuntimeCapabilityDescriptor>,
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
            runtime_capabilities: None,
        }
    }

    pub fn with_runtime_capabilities(mut self, runtime_capabilities: RuntimeCapabilityDescriptor) -> Self {
        self.runtime_capabilities = Some(runtime_capabilities);
        self
    }
}

pub const RUNTIME_CAPABILITY_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeCapabilityDescriptor {
    pub schema_version: u32,
    pub capabilities: RuntimeCapabilities,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeCapabilities {
    pub append: RuntimeCapability,
    pub local_embedders: RuntimeCapability,
    pub embedding_delegation: RuntimeCapability,
    pub rerank_gpu: RuntimeCapability,
    pub hosted_sync: RuntimeCapability,
    pub projection_queries: RuntimeCapability,
    pub graph_expand: RuntimeCapability,
    /// The CoreCrux link-graph console mediation proxy (`/v1/console/corecrux/graph/*`).
    /// `configured` ⇔ the graph upstream base URL env is set on this daemon; the
    /// unified-shell console gates its six-degrees link-graph pane on this signal
    /// (render from the capability plan, never the route registry). See ExecPlan
    /// `wikicrux-link-graph-explorer-2026-07-23` (M4).
    pub console_link_graph: RuntimeCapability,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeCapability {
    pub availability: &'static str,
    pub reason_code: &'static str,
    pub reason: &'static str,
    pub compiled: bool,
    pub configured: bool,
    pub initialized: bool,
    pub entitled: bool,
    pub degraded: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct RuntimeCapabilityInputs {
    pub http_dataplane_enabled: bool,
    pub local_embedder_configured: bool,
    pub local_embedder_initialized: bool,
    pub embedding_delegation: EmbeddingDelegationRuntimeState,
    pub rerank_endpoint_configured: bool,
    pub graph_expand_configured: bool,
    /// The CoreCrux link-graph console mediation proxy is configured (graph
    /// upstream base URL env set). Sourced from `http::console` at `/v1/version`.
    pub console_link_graph_configured: bool,
}

/// Safe, public projection of the delegation client's live breaker state.
/// Raw transport errors and endpoint details never enter `/v1/version`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmbeddingDelegationRuntimeState {
    NotConfigured,
    Available,
    CircuitOpen,
    HalfOpen,
    SemanticProfileMismatch,
    Degraded,
}

#[derive(Debug, Clone, Copy)]
struct RuntimeCapabilityStages {
    compiled: bool,
    configured: bool,
    initialized: bool,
    entitled: bool,
    degraded: bool,
}

impl RuntimeCapabilityDescriptor {
    pub fn from_runtime(
        mode: OperatingMode,
        configured_pro_services: &[String],
        sync: &SyncRuntimeStatus,
        inputs: RuntimeCapabilityInputs,
    ) -> Self {
        let rerank_enabled = configured_pro_services.iter().any(|service| service == "gpu1:rerank");
        let sync_enabled = configured_pro_services.iter().any(|service| service == "sync:mirror");
        let pro_entitled = mode.includes_pro();
        let rerank_compiled = cfg!(feature = "hosted-surfaces");
        let append_stages = RuntimeCapabilityStages {
            compiled: true,
            configured: inputs.http_dataplane_enabled,
            initialized: inputs.http_dataplane_enabled,
            entitled: true,
            degraded: false,
        };
        let local_embedder_stages = RuntimeCapabilityStages {
            compiled: true,
            configured: inputs.local_embedder_configured,
            initialized: inputs.local_embedder_initialized,
            entitled: true,
            degraded: false,
        };
        let embedding_delegation_configured = !matches!(
            inputs.embedding_delegation,
            EmbeddingDelegationRuntimeState::NotConfigured
        );
        let embedding_delegation_degraded = matches!(
            inputs.embedding_delegation,
            EmbeddingDelegationRuntimeState::CircuitOpen
                | EmbeddingDelegationRuntimeState::HalfOpen
                | EmbeddingDelegationRuntimeState::SemanticProfileMismatch
                | EmbeddingDelegationRuntimeState::Degraded
        );
        let embedding_delegation_stages = RuntimeCapabilityStages {
            compiled: true,
            configured: embedding_delegation_configured,
            initialized: embedding_delegation_configured,
            entitled: true,
            degraded: embedding_delegation_degraded,
        };
        let rerank_stages = RuntimeCapabilityStages {
            compiled: rerank_compiled,
            configured: inputs.rerank_endpoint_configured,
            initialized: rerank_compiled && rerank_enabled && inputs.rerank_endpoint_configured,
            entitled: pro_entitled,
            degraded: rerank_enabled && !inputs.rerank_endpoint_configured,
        };
        let sync_stages = RuntimeCapabilityStages {
            compiled: true,
            configured: sync.configured,
            initialized: sync.background_sync_enabled && !sync.remote_url.is_empty(),
            entitled: pro_entitled,
            degraded: sync.degraded,
        };
        let graph_stages = RuntimeCapabilityStages {
            compiled: true,
            configured: inputs.graph_expand_configured,
            initialized: inputs.http_dataplane_enabled,
            entitled: true,
            degraded: false,
        };

        let append = if inputs.http_dataplane_enabled {
            RuntimeCapability::available(append_stages)
        } else {
            RuntimeCapability::unavailable(
                "http_dataplane_disabled",
                "The HTTP dataplane is not initialised, so event append is unavailable.",
                append_stages,
            )
        };
        let projection_queries = if inputs.http_dataplane_enabled {
            RuntimeCapability::available(append_stages)
        } else {
            RuntimeCapability::unavailable(
                "http_dataplane_disabled",
                "The HTTP dataplane is not initialised, so projection queries are unavailable.",
                append_stages,
            )
        };
        let local_embedders = if inputs.local_embedder_configured && inputs.local_embedder_initialized {
            RuntimeCapability::available(local_embedder_stages)
        } else if embedding_delegation_configured {
            RuntimeCapability::unavailable(
                "delegated_to_remote",
                "Embedding inference is delegated to a remote daemon; no in-process embedder is initialised.",
                local_embedder_stages,
            )
        } else {
            RuntimeCapability::unavailable(
                "local_embedder_unavailable",
                "No in-process embedder is initialised in this daemon's local fact store.",
                local_embedder_stages,
            )
        };
        let embedding_delegation = match inputs.embedding_delegation {
            EmbeddingDelegationRuntimeState::NotConfigured => RuntimeCapability::unavailable(
                "embedding_delegation_not_configured",
                "Authenticated daemon-to-daemon embedding delegation is not configured.",
                embedding_delegation_stages,
            ),
            EmbeddingDelegationRuntimeState::Available => RuntimeCapability::available(embedding_delegation_stages),
            EmbeddingDelegationRuntimeState::CircuitOpen => RuntimeCapability::degraded(
                "embedding_delegation_circuit_open",
                "Embedding delegation is degraded because its circuit breaker is open.",
                embedding_delegation_stages,
            ),
            EmbeddingDelegationRuntimeState::HalfOpen => RuntimeCapability::degraded(
                "embedding_delegation_half_open",
                "Embedding delegation is degraded while its circuit breaker probes recovery.",
                embedding_delegation_stages,
            ),
            EmbeddingDelegationRuntimeState::SemanticProfileMismatch => RuntimeCapability::degraded(
                "embedding_semantic_profile_mismatch",
                "The remote embedding provider is incompatible with the expected or persisted semantic profile.",
                embedding_delegation_stages,
            ),
            EmbeddingDelegationRuntimeState::Degraded => RuntimeCapability::degraded(
                "embedding_delegation_degraded",
                "Embedding delegation is configured but remote compute is currently degraded.",
                embedding_delegation_stages,
            ),
        };
        let rerank_gpu = if !rerank_compiled {
            RuntimeCapability::unavailable(
                "rerank_not_compiled",
                "This daemon was built without the hosted GPU rerank bridge.",
                rerank_stages,
            )
        } else if !pro_entitled {
            RuntimeCapability::unavailable(
                "rerank_not_entitled",
                "GPU rerank is not enabled for this product posture.",
                rerank_stages,
            )
        } else if !rerank_enabled {
            RuntimeCapability::unavailable(
                "rerank_not_enabled",
                "GPU rerank is entitled but is not enabled in this daemon configuration.",
                rerank_stages,
            )
        } else if !inputs.rerank_endpoint_configured {
            RuntimeCapability::degraded(
                "rerank_endpoint_not_configured",
                "GPU rerank is entitled, but its remote compute endpoint is not configured.",
                rerank_stages,
            )
        } else {
            RuntimeCapability::available(rerank_stages)
        };
        let hosted_sync = if !pro_entitled {
            RuntimeCapability::unavailable(
                "hosted_sync_not_entitled",
                "Hosted sync is not enabled for this product posture.",
                sync_stages,
            )
        } else if !sync_enabled {
            RuntimeCapability::unavailable(
                "hosted_sync_not_enabled",
                "Hosted sync is entitled but is not enabled in this daemon configuration.",
                sync_stages,
            )
        } else if sync.degraded {
            RuntimeCapability::degraded(
                "hosted_sync_degraded",
                "Hosted sync configuration is incomplete; the daemon is continuing local-only.",
                sync_stages,
            )
        } else if !sync.configured {
            RuntimeCapability::unavailable(
                "hosted_sync_not_configured",
                "Hosted sync is entitled but no complete remote target is configured.",
                sync_stages,
            )
        } else if !sync.background_sync_enabled {
            RuntimeCapability::available_with_reason(
                "hosted_sync_manual",
                "Hosted sync is configured for manual operation; its background loop is not initialised.",
                sync_stages,
            )
        } else {
            RuntimeCapability::available(sync_stages)
        };
        let graph_expand = if !inputs.graph_expand_configured {
            RuntimeCapability::unavailable(
                "graph_expand_not_configured",
                "Graph expansion is disabled in this daemon configuration.",
                graph_stages,
            )
        } else if !inputs.http_dataplane_enabled {
            RuntimeCapability::unavailable(
                "http_dataplane_disabled",
                "The HTTP dataplane is not initialised, so graph expansion is unavailable.",
                graph_stages,
            )
        } else {
            RuntimeCapability::available(graph_stages)
        };
        // The link-graph console proxy is a stateless GET-only mediation surface:
        // once the graph upstream base URL env is set it is both configured and
        // ready (no in-process init). Available ⇔ configured.
        let console_link_graph_stages = RuntimeCapabilityStages {
            compiled: true,
            configured: inputs.console_link_graph_configured,
            initialized: inputs.console_link_graph_configured,
            entitled: true,
            degraded: false,
        };
        let console_link_graph = if inputs.console_link_graph_configured {
            RuntimeCapability::available(console_link_graph_stages)
        } else {
            RuntimeCapability::unavailable(
                "console_link_graph_not_configured",
                "The CoreCrux link-graph mediation proxy is not configured; set CORECRUXD_CORECRUX_GRAPH_BASE_URL on the Crux daemon.",
                console_link_graph_stages,
            )
        };

        Self {
            schema_version: RUNTIME_CAPABILITY_SCHEMA_VERSION,
            capabilities: RuntimeCapabilities {
                append,
                local_embedders,
                embedding_delegation,
                rerank_gpu,
                hosted_sync,
                projection_queries,
                graph_expand,
                console_link_graph,
            },
        }
    }
}

impl RuntimeCapability {
    fn available(stages: RuntimeCapabilityStages) -> Self {
        Self::available_with_reason("available", "Capability is available.", stages)
    }

    fn available_with_reason(reason_code: &'static str, reason: &'static str, stages: RuntimeCapabilityStages) -> Self {
        Self {
            availability: "available",
            reason_code,
            reason,
            compiled: stages.compiled,
            configured: stages.configured,
            initialized: stages.initialized,
            entitled: stages.entitled,
            degraded: stages.degraded,
        }
    }

    fn unavailable(reason_code: &'static str, reason: &'static str, stages: RuntimeCapabilityStages) -> Self {
        Self {
            availability: "unavailable",
            reason_code,
            reason,
            compiled: stages.compiled,
            configured: stages.configured,
            initialized: stages.initialized,
            entitled: stages.entitled,
            degraded: stages.degraded,
        }
    }

    fn degraded(reason_code: &'static str, reason: &'static str, stages: RuntimeCapabilityStages) -> Self {
        Self {
            availability: "degraded",
            reason_code,
            reason,
            compiled: stages.compiled,
            configured: stages.configured,
            initialized: stages.initialized,
            entitled: stages.entitled,
            degraded: stages.degraded,
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
        // GPU-1 local-path pointers name the hosted-surface routes
        // (`/v1/gpu1/*`) that are compiled out of the default Community Edition
        // binary (ExecPlan crux-external-findings-remediation M4). Advertise
        // them only when those routes are actually mounted.
        #[cfg(feature = "hosted-surfaces")]
        RestEndpointContract {
            name: "gpu1_answer",
            method: "POST",
            hosted_path: "/v1/query/answer",
            local_path: Some("/v1/gpu1/answer"),
            scopes: vec!["gpu1:answer"],
        },
        #[cfg(feature = "hosted-surfaces")]
        RestEndpointContract {
            name: "gpu1_rerank",
            method: "POST",
            hosted_path: "/v1/query/rerank",
            local_path: Some("/v1/gpu1/rerank"),
            scopes: vec!["gpu1:rerank"],
        },
        #[cfg(feature = "hosted-surfaces")]
        RestEndpointContract {
            name: "gpu1_enrich",
            method: "POST",
            hosted_path: "/v1/actions/enrich",
            local_path: Some("/v1/gpu1/enrich"),
            scopes: vec!["gpu1:enrich"],
        },
        #[cfg(feature = "hosted-surfaces")]
        RestEndpointContract {
            name: "gpu1_coverage",
            method: "POST",
            hosted_path: "/v1/query/coverage",
            local_path: Some("/v1/gpu1/coverage"),
            scopes: vec!["gpu1:coverage"],
        },
        #[cfg(feature = "hosted-surfaces")]
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
            let daemon = contains_claim(DAEMON_IMPLEMENTED_PRO_CLAIMS, claim);
            let hosted = contains_claim(HOSTED_CONTROL_PLANE_PRO_CLAIMS, claim);
            let implementation = match (daemon, hosted) {
                (true, true) => "daemon_and_hosted_control_plane",
                (true, false) => "daemon",
                (false, true) => "hosted_control_plane",
                (false, false) => "contracted_external",
            };
            ProClaimPlacement {
                claim,
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
    fn runtime_capability_stages_remain_independent_of_entitlement() {
        let configured = vec!["gpu1:rerank".to_string(), "sync:mirror".to_string()];
        let sync = SyncRuntimeStatus::from_settings(true, Some("https://memory.example"), true);
        let descriptor = RuntimeCapabilityDescriptor::from_runtime(
            OperatingMode::FreeLocal,
            &configured,
            &sync,
            RuntimeCapabilityInputs {
                http_dataplane_enabled: true,
                local_embedder_configured: true,
                local_embedder_initialized: true,
                embedding_delegation: EmbeddingDelegationRuntimeState::NotConfigured,
                rerank_endpoint_configured: true,
                graph_expand_configured: true,
                console_link_graph_configured: false,
            },
        );

        assert!(descriptor.capabilities.rerank_gpu.configured);
        assert!(!descriptor.capabilities.rerank_gpu.entitled);
        assert!(descriptor.capabilities.hosted_sync.configured);
        assert!(descriptor.capabilities.hosted_sync.initialized);
        assert!(!descriptor.capabilities.hosted_sync.entitled);
        assert_eq!(descriptor.capabilities.hosted_sync.availability, "unavailable");
        assert_eq!(
            descriptor.capabilities.hosted_sync.reason_code,
            "hosted_sync_not_entitled"
        );

        let missing_endpoint = RuntimeCapabilityDescriptor::from_runtime(
            OperatingMode::FreeLocal,
            &configured,
            &sync,
            RuntimeCapabilityInputs {
                http_dataplane_enabled: true,
                local_embedder_configured: true,
                local_embedder_initialized: true,
                embedding_delegation: EmbeddingDelegationRuntimeState::NotConfigured,
                rerank_endpoint_configured: false,
                graph_expand_configured: true,
                console_link_graph_configured: false,
            },
        );
        assert!(!missing_endpoint.capabilities.rerank_gpu.configured);
        assert!(!missing_endpoint.capabilities.rerank_gpu.entitled);
        assert!(missing_endpoint.capabilities.rerank_gpu.degraded);
    }

    #[test]
    fn manual_hosted_sync_is_available_without_an_initialised_background_loop() {
        let configured = vec!["sync:mirror".to_string()];
        let sync = SyncRuntimeStatus::from_settings(false, Some("https://memory.example"), true);
        let descriptor = RuntimeCapabilityDescriptor::from_runtime(
            OperatingMode::ProHybrid,
            &configured,
            &sync,
            RuntimeCapabilityInputs {
                http_dataplane_enabled: true,
                local_embedder_configured: false,
                local_embedder_initialized: false,
                embedding_delegation: EmbeddingDelegationRuntimeState::NotConfigured,
                rerank_endpoint_configured: false,
                graph_expand_configured: true,
                console_link_graph_configured: false,
            },
        );
        let hosted_sync = descriptor.capabilities.hosted_sync;

        assert_eq!(hosted_sync.availability, "available");
        assert_eq!(hosted_sync.reason_code, "hosted_sync_manual");
        assert!(hosted_sync.configured);
        assert!(!hosted_sync.initialized);
        assert!(hosted_sync.entitled);
        assert!(!hosted_sync.degraded);
    }

    #[test]
    fn embedding_delegation_is_distinct_from_local_embedding_and_tracks_breaker_state() {
        let sync = SyncRuntimeStatus::from_settings(false, None, false);
        let available = RuntimeCapabilityDescriptor::from_runtime(
            OperatingMode::FreeLocal,
            &[],
            &sync,
            RuntimeCapabilityInputs {
                http_dataplane_enabled: true,
                local_embedder_configured: false,
                local_embedder_initialized: false,
                embedding_delegation: EmbeddingDelegationRuntimeState::Available,
                rerank_endpoint_configured: false,
                graph_expand_configured: true,
                console_link_graph_configured: false,
            },
        );

        assert_eq!(available.schema_version, 1);
        assert_eq!(available.capabilities.local_embedders.availability, "unavailable");
        assert_eq!(
            available.capabilities.local_embedders.reason_code,
            "delegated_to_remote"
        );
        assert_eq!(available.capabilities.embedding_delegation.availability, "available");
        assert!(available.capabilities.embedding_delegation.configured);
        assert!(!available.capabilities.embedding_delegation.degraded);

        let circuit_open = RuntimeCapabilityDescriptor::from_runtime(
            OperatingMode::FreeLocal,
            &[],
            &sync,
            RuntimeCapabilityInputs {
                http_dataplane_enabled: true,
                local_embedder_configured: false,
                local_embedder_initialized: false,
                embedding_delegation: EmbeddingDelegationRuntimeState::CircuitOpen,
                rerank_endpoint_configured: false,
                graph_expand_configured: true,
                console_link_graph_configured: false,
            },
        );
        assert_eq!(circuit_open.capabilities.embedding_delegation.availability, "degraded");
        assert_eq!(
            circuit_open.capabilities.embedding_delegation.reason_code,
            "embedding_delegation_circuit_open"
        );
        assert!(circuit_open.capabilities.embedding_delegation.degraded);
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
