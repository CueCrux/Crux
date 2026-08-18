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

/// Where each [`DAEMON_IMPLEMENTED_PRO_CLAIMS`] entry is actually enforced.
///
/// `pro_claim_placements` derives `implementation: "daemon"` from list
/// membership alone — it never checks that a gate exists — so adding a string
/// to two arrays is enough to make the daemon report a capability as
/// implemented. The M4 vow audit found four claims in exactly that state.
///
/// This table is the missing check. A claim earns `daemon_implemented` by
/// naming the `file:line` that refuses it, and
/// `daemon_implemented_pro_claims_have_a_gate_site` fails the build if the two
/// lists drift apart in either direction.
///
/// `None` means **sold, declared daemon-implemented, and enforced nowhere**.
/// Do not add a `None` row to make a new claim compile. The four below are
/// recorded findings awaiting the M5 human gate, not a pattern to follow —
/// and note the `ledger:history` trap above: dropping one from
/// `DAEMON_IMPLEMENTED_PRO_CLAIMS` alone re-labels it `contracted_external`,
/// asserting an outside implementer that does not exist. They leave both lists
/// together or not at all.
///
/// The classification behind the four, for the record: of the twenty claims
/// declared daemon-implemented, five egress (the GPU-1 bridge, the only Pro
/// handler that reaches the network), eleven are local compute that answers on
/// a network-severed daemon, and these four have no gate and no handler at all.
#[cfg(test)]
const DAEMON_CLAIM_GATE_SITES: &[(&str, Option<&str>)] = &[
    ("gpu1:answer", Some("http/gpu1.rs:801 service_enabled")),
    ("gpu1:rerank", Some("http/gpu1.rs:801 service_enabled")),
    ("gpu1:enrich", Some("http/gpu1.rs:801 service_enabled")),
    ("gpu1:coverage", Some("http/gpu1.rs:801 service_enabled")),
    ("gpu1:developer", Some("http/gpu1.rs:801 service_enabled")),
    ("replay:answer", Some("http/replay.rs:214")),
    ("agent_brief:pro", Some("http/workbench.rs:875 require_surface_enabled")),
    (
        "context_pack:budgeted",
        Some("http/workbench.rs:875 require_surface_enabled"),
    ),
    (
        "impact:preflight",
        Some("http/workbench.rs:875 require_surface_enabled"),
    ),
    ("audit:triage", Some("http/workbench.rs:875 require_surface_enabled")),
    (
        "reasoning:timeline",
        Some("http/workbench.rs:875 require_surface_enabled"),
    ),
    ("handoff:v2", Some("http/workbench.rs:875 require_surface_enabled")),
    ("route_probe:lab", Some("http/workbench.rs:875 require_surface_enabled")),
    ("api_drift:check", Some("http/workbench.rs:875 require_surface_enabled")),
    ("policy:simulate", Some("http/workbench.rs:875 require_surface_enabled")),
    ("enrichers:first_party", Some("http/actions.rs:59")),
    // M4 findings — no gate, no handler, claim string occurs only in the
    // PRO_CAPABILITY_CLAIMS / DAEMON_IMPLEMENTED_PRO_CLAIMS arrays.
    ("sync:mirror", None),
    ("sync:promote", None),
    ("console:workbench", None),
    ("tenant:business_offboarding", None),
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
    /// Who produced the companions this daemon is serving. `degraded` when any
    /// segment is unattested or refused — and when the check itself is off,
    /// because "we turned the alarm off" has to be visible.
    pub companion_provenance: RuntimeCapability,
    /// Whether a human can resolve a gated work transition on THIS deployment,
    /// and by which evidence rung. Every oversight surface derives its Approve
    /// affordance from this rather than hardcoding a flow — a control that
    /// renders as actionable when the daemon would refuse is the defect this
    /// capability exists to make impossible (issue #705). `detail.rung` names
    /// the selected rung; `reason` names the remedy when there is none.
    pub work_gate_resolution: RuntimeCapability,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeCapability {
    pub availability: &'static str,
    pub reason_code: &'static str,
    pub reason: &'static str,
    /// Capability-specific counts. Omitted entirely when absent, so every
    /// existing consumer of this shape is unaffected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<serde_json::Value>,
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
    /// Live companion-provenance tallies, read from the retrieval index.
    pub companion_provenance: CompanionProvenanceRuntime,
    /// Which evidence rungs this daemon can actually offer for a human gate
    /// decision. See [`GateResolutionInputs`].
    pub gate_resolution: GateResolutionInputs,
}

/// Runtime facts the gate-resolution ladder selects over. Deliberately plain
/// booleans read at `/v1/version` time so the ladder itself is pure and can be
/// exhaustively tested against the posture matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GateResolutionInputs {
    /// `CORECRUXD_AUTH_MODE=off` — a local, unverified deployment. Gate
    /// resolution works here through the asserted-approver branch, recorded as
    /// `operator:unverified:<passport>`.
    pub auth_off: bool,
    /// `CORECRUXD_TS_IDENTITY_ENABLED`.
    pub identity_rail_enabled: bool,
    /// At least one allowlist entry carries a `#<passport>` binding. Without
    /// one the rail issues unbound tokens, which cannot resolve a gate.
    pub identity_rail_has_passport: bool,
    /// `CORECRUXD_DEVICE_GRANT_ENABLED`.
    pub device_grant_enabled: bool,
    /// The daemon can mint (a JWT-mode HS256 secret is present). Both issuance
    /// rails 503 without it.
    pub can_mint: bool,
}

/// The evidence rung a deployment resolves gates by, strongest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateResolutionRung {
    /// A proxy-asserted verified identity, mapped to a passport by allowlist.
    IdentityHeader,
    /// An already-trusted admin vouched for this device and bound their passport.
    DeviceGrant,
    /// The human at the machine on an unverified local daemon.
    LocalUnverified,
}

impl GateResolutionRung {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IdentityHeader => "identity_header",
            Self::DeviceGrant => "device_grant",
            Self::LocalUnverified => "local_unverified",
        }
    }
}

/// Outcome of the ladder: the rung selected, or why none is available.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateResolutionSelection {
    Selected(GateResolutionRung),
    /// A rung is configured but cannot issue. We deliberately do NOT fall
    /// through to a weaker rung: a misconfiguration must surface, not quietly
    /// downgrade the strength of human oversight while the receipt still looks
    /// identical.
    Blocked {
        rung: GateResolutionRung,
        reason_code: &'static str,
        reason: &'static str,
    },
    None {
        reason_code: &'static str,
        reason: &'static str,
    },
}

/// Select the strongest rung this deployment is *configured* for.
///
/// The no-silent-downgrade rule is the load-bearing half: a configured rung that
/// cannot issue returns `Blocked`, never a weaker `Selected`.
pub fn select_gate_resolution(inputs: GateResolutionInputs) -> GateResolutionSelection {
    if inputs.identity_rail_enabled {
        if !inputs.can_mint {
            return GateResolutionSelection::Blocked {
                rung: GateResolutionRung::IdentityHeader,
                reason_code: "gate_rail_cannot_mint",
                reason: "The identity rail is enabled but the daemon cannot mint tokens; set CORECRUXD_JWT_HS256_SECRET and run in jwt_hs256 mode.",
            };
        }
        if !inputs.identity_rail_has_passport {
            return GateResolutionSelection::Blocked {
                rung: GateResolutionRung::IdentityHeader,
                reason_code: "gate_rail_no_passport_mapping",
                reason: "The identity rail is enabled but no allowlist entry binds a passport; append `#<passport>` to the entry for each human who may approve.",
            };
        }
        return GateResolutionSelection::Selected(GateResolutionRung::IdentityHeader);
    }
    if inputs.device_grant_enabled {
        if !inputs.can_mint {
            return GateResolutionSelection::Blocked {
                rung: GateResolutionRung::DeviceGrant,
                reason_code: "gate_rail_cannot_mint",
                reason: "The device grant is enabled but the daemon cannot mint tokens; set CORECRUXD_JWT_HS256_SECRET and run in jwt_hs256 mode.",
            };
        }
        return GateResolutionSelection::Selected(GateResolutionRung::DeviceGrant);
    }
    if inputs.auth_off {
        return GateResolutionSelection::Selected(GateResolutionRung::LocalUnverified);
    }
    GateResolutionSelection::None {
        reason_code: "gate_no_identity_rung",
        reason: "No rung can name a human on this daemon: enable the device grant (CORECRUXD_DEVICE_GRANT_ENABLED) or the identity rail (CORECRUXD_TS_IDENTITY_ENABLED) with a passport-bound allowlist.",
    }
}

/// Build the declared capability from the ladder's verdict.
fn work_gate_resolution_capability(inputs: GateResolutionInputs) -> RuntimeCapability {
    let selection = select_gate_resolution(inputs);
    let any_rail_configured = inputs.identity_rail_enabled || inputs.device_grant_enabled || inputs.auth_off;
    let stages = RuntimeCapabilityStages {
        compiled: true,
        configured: any_rail_configured,
        initialized: inputs.auth_off || inputs.can_mint,
        entitled: true,
        degraded: matches!(selection, GateResolutionSelection::Blocked { .. }),
    };
    let mut capability = match selection {
        GateResolutionSelection::Selected(rung) => {
            let mut c = RuntimeCapability::available(stages);
            c.detail = Some(serde_json::json!({ "rung": rung.as_str() }));
            c
        }
        GateResolutionSelection::Blocked {
            rung,
            reason_code,
            reason,
        } => {
            let mut c = RuntimeCapability::degraded(reason_code, reason, stages);
            // Name the rung that is stuck. Falling through to a weaker one would
            // have hidden exactly this.
            c.detail = Some(serde_json::json!({ "blocked_rung": rung.as_str() }));
            c
        }
        GateResolutionSelection::None { reason_code, reason } => {
            RuntimeCapability::unavailable(reason_code, reason, stages)
        }
    };
    if capability.detail.is_none() {
        capability.detail = Some(serde_json::json!({}));
    }
    capability
}

/// Snapshot of companion provenance across the loaded corpus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompanionProvenanceRuntime {
    /// `off` | `warn` | `enforce`.
    pub mode: &'static str,
    pub platform: usize,
    pub local: usize,
    pub none: usize,
    pub invalid: usize,
    /// Segments whose provenance cost them their lanes (still erasable).
    pub refused: usize,
}

impl Default for CompanionProvenanceRuntime {
    /// An empty corpus under the ship default. Notably `mode: "warn"`, not `""`:
    /// a default that reads as "no mode" would report the capability as
    /// configured-off and quietly mark a healthy daemon degraded.
    fn default() -> Self {
        Self {
            mode: "warn",
            platform: 0,
            local: 0,
            none: 0,
            invalid: 0,
            refused: 0,
        }
    }
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
                companion_provenance: companion_provenance_capability(inputs.companion_provenance),
                work_gate_resolution: work_gate_resolution_capability(inputs.gate_resolution),
            },
        }
    }
}

/// Surface 2 of 4 — the machine-readable one the console reads.
///
/// `degraded` is the honest state for all three bad outcomes: companions from
/// nowhere, companions that fail their own digests, and a daemon told not to
/// look. The last is deliberate — an operator inheriting a box must be able to
/// see that the alarm was disabled, so `off` reports itself rather than
/// reporting clean.
fn companion_provenance_capability(runtime: CompanionProvenanceRuntime) -> RuntimeCapability {
    let stages = RuntimeCapabilityStages {
        compiled: true,
        configured: runtime.mode != "off",
        initialized: true,
        entitled: true,
        degraded: runtime.mode == "off" || runtime.invalid > 0 || runtime.none > 0,
    };
    let detail = serde_json::json!({
        "mode": runtime.mode,
        "platform": runtime.platform,
        "local": runtime.local,
        "none": runtime.none,
        "invalid": runtime.invalid,
        "refused": runtime.refused,
    });

    let mut capability = if runtime.mode == "off" {
        RuntimeCapability::degraded(
            "companion_attestation_off",
            "Companion attestation is disabled; missing provenance is not reported.",
            stages,
        )
    } else if runtime.invalid > 0 {
        RuntimeCapability::degraded(
            "companion_attestation_invalid",
            "Some companions do not match their signed digests and were refused their lanes.",
            stages,
        )
    } else if runtime.none > 0 {
        RuntimeCapability::degraded(
            "companion_unattested",
            "Some segments carry no companion attestation.",
            stages,
        )
    } else {
        RuntimeCapability::available(stages)
    };
    capability.detail = Some(detail);
    capability
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
            detail: None,
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
            detail: None,
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
            detail: None,
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
mod gate_resolution_ladder_tests {
    use super::*;

    fn inputs() -> GateResolutionInputs {
        GateResolutionInputs::default()
    }

    // ── the posture matrix ────────────────────────────────────────────────

    #[test]
    fn local_only_resolves_by_the_unverified_rung() {
        let got = select_gate_resolution(GateResolutionInputs {
            auth_off: true,
            ..inputs()
        });
        assert_eq!(
            got,
            GateResolutionSelection::Selected(GateResolutionRung::LocalUnverified)
        );
    }

    #[test]
    fn device_grant_is_selected_when_it_can_mint() {
        let got = select_gate_resolution(GateResolutionInputs {
            device_grant_enabled: true,
            can_mint: true,
            ..inputs()
        });
        assert_eq!(got, GateResolutionSelection::Selected(GateResolutionRung::DeviceGrant));
    }

    #[test]
    fn identity_header_outranks_the_device_grant() {
        // Strongest CONFIGURED rung wins: a proxy-asserted per-human identity is
        // stronger evidence than an admin vouching for a device.
        let got = select_gate_resolution(GateResolutionInputs {
            identity_rail_enabled: true,
            identity_rail_has_passport: true,
            device_grant_enabled: true,
            can_mint: true,
            ..inputs()
        });
        assert_eq!(
            got,
            GateResolutionSelection::Selected(GateResolutionRung::IdentityHeader)
        );
    }

    #[test]
    fn nothing_configured_is_honestly_unavailable() {
        match select_gate_resolution(inputs()) {
            GateResolutionSelection::None { reason_code, reason } => {
                assert_eq!(reason_code, "gate_no_identity_rung");
                // The reason must name the remedy, not just the problem.
                assert!(reason.contains("CORECRUXD_DEVICE_GRANT_ENABLED"));
                assert!(reason.contains("CORECRUXD_TS_IDENTITY_ENABLED"));
            }
            other => panic!("expected None, got {other:?}"),
        }
    }

    // ── no silent downgrade — the load-bearing half ───────────────────────

    #[test]
    fn an_identity_rail_without_a_passport_mapping_blocks_rather_than_downgrading() {
        // The device grant is ALSO configured and could issue. Falling through
        // to it would quietly weaken oversight while the receipt looked
        // identical, and would hide the misconfiguration the operator needs to
        // see. Block instead.
        let got = select_gate_resolution(GateResolutionInputs {
            identity_rail_enabled: true,
            identity_rail_has_passport: false,
            device_grant_enabled: true,
            can_mint: true,
            ..inputs()
        });
        match got {
            GateResolutionSelection::Blocked {
                rung,
                reason_code,
                reason,
            } => {
                assert_eq!(rung, GateResolutionRung::IdentityHeader);
                assert_eq!(reason_code, "gate_rail_no_passport_mapping");
                assert!(reason.contains("#<passport>"), "the reason must name the fix");
            }
            other => panic!("expected Blocked, got {other:?}"),
        }
    }

    #[test]
    fn a_rail_that_cannot_mint_blocks_rather_than_downgrading_to_auth_off() {
        let got = select_gate_resolution(GateResolutionInputs {
            device_grant_enabled: true,
            can_mint: false,
            auth_off: true,
            ..inputs()
        });
        match got {
            GateResolutionSelection::Blocked { rung, reason_code, .. } => {
                assert_eq!(rung, GateResolutionRung::DeviceGrant);
                assert_eq!(reason_code, "gate_rail_cannot_mint");
            }
            other => panic!("expected Blocked, got {other:?}"),
        }
    }

    // ── the declaration must not lie ──────────────────────────────────────

    #[test]
    fn the_declared_capability_agrees_with_the_ladder_for_every_posture() {
        // Exhaustive over the 5 boolean inputs: whatever the ladder decides,
        // the capability the console reads says the same thing. A capability
        // that declares `available` where a real attempt would refuse rebuilds
        // the inert button with more confidence than before — so this is
        // asserted in both directions rather than spot-checked.
        for bits in 0u8..32 {
            let i = GateResolutionInputs {
                auth_off: bits & 1 != 0,
                identity_rail_enabled: bits & 2 != 0,
                identity_rail_has_passport: bits & 4 != 0,
                device_grant_enabled: bits & 8 != 0,
                can_mint: bits & 16 != 0,
            };
            let selection = select_gate_resolution(i);
            let capability = work_gate_resolution_capability(i);
            match selection {
                GateResolutionSelection::Selected(rung) => {
                    assert_eq!(capability.availability, "available", "inputs {i:?}");
                    assert_eq!(
                        capability.detail.as_ref().and_then(|d| d["rung"].as_str()),
                        Some(rung.as_str()),
                        "the declaration must name the rung it selected, inputs {i:?}"
                    );
                }
                GateResolutionSelection::Blocked { rung, .. } => {
                    assert_eq!(capability.availability, "degraded", "inputs {i:?}");
                    assert!(capability.degraded, "inputs {i:?}");
                    assert_eq!(
                        capability.detail.as_ref().and_then(|d| d["blocked_rung"].as_str()),
                        Some(rung.as_str()),
                        "a blocked declaration must name the stuck rung, inputs {i:?}"
                    );
                }
                GateResolutionSelection::None { .. } => {
                    assert_eq!(capability.availability, "unavailable", "inputs {i:?}");
                }
            }
            // Whatever the verdict, the contract the console validates holds.
            assert!(!capability.reason_code.is_empty() || capability.availability == "available");
        }
    }
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

    /// A claim may not be sold as daemon-implemented without a gate that
    /// refuses it.
    ///
    /// `pro_claim_placements` reports `implementation: "daemon"` from list
    /// membership, so without this the only thing standing between "we built
    /// it" and "we added a string to an array" is review. M4 found four claims
    /// that had crossed that line.
    #[test]
    fn daemon_implemented_pro_claims_have_a_gate_site() {
        for claim in DAEMON_IMPLEMENTED_PRO_CLAIMS {
            assert!(
                DAEMON_CLAIM_GATE_SITES.iter().any(|(name, _)| name == claim),
                "{claim} is declared daemon-implemented but has no DAEMON_CLAIM_GATE_SITES row. \
                 Add the file:line of the gate that refuses it — or, if nothing enforces it, do not \
                 declare it daemon-implemented."
            );
        }

        for (claim, _) in DAEMON_CLAIM_GATE_SITES {
            assert!(
                contains_claim(DAEMON_IMPLEMENTED_PRO_CLAIMS, claim),
                "{claim} has a gate-site row but is no longer in DAEMON_IMPLEMENTED_PRO_CLAIMS; \
                 drop the stale row so the table keeps meaning what it says"
            );
        }
    }

    /// The four ungated claims are pinned by name so that fixing one is a
    /// deliberate edit to this list rather than a silent drift, and so that a
    /// *fifth* cannot appear unnoticed.
    ///
    /// This asserts a known defect, not a desired state. It goes away at M5,
    /// which is a human gate because it changes what is sold.
    #[test]
    fn the_only_ungated_daemon_claims_are_the_four_m4_found() {
        let ungated: Vec<&str> = DAEMON_CLAIM_GATE_SITES
            .iter()
            .filter_map(|(claim, gate)| gate.is_none().then_some(*claim))
            .collect();

        assert_eq!(
            ungated,
            vec![
                "sync:mirror",
                "sync:promote",
                "console:workbench",
                "tenant:business_offboarding",
            ],
            "the set of sold-but-unenforced Pro claims changed. If you added one, don't — wire a \
             gate. If you removed one, remove it from PRO_CAPABILITY_CLAIMS too (see the \
             ledger:history note) and update this assertion."
        );
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
                gate_resolution: GateResolutionInputs::default(),
                http_dataplane_enabled: true,
                local_embedder_configured: true,
                local_embedder_initialized: true,
                embedding_delegation: EmbeddingDelegationRuntimeState::NotConfigured,
                rerank_endpoint_configured: true,
                graph_expand_configured: true,
                console_link_graph_configured: false,
                companion_provenance: CompanionProvenanceRuntime::default(),
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
                gate_resolution: GateResolutionInputs::default(),
                http_dataplane_enabled: true,
                local_embedder_configured: true,
                local_embedder_initialized: true,
                embedding_delegation: EmbeddingDelegationRuntimeState::NotConfigured,
                rerank_endpoint_configured: false,
                graph_expand_configured: true,
                console_link_graph_configured: false,
                companion_provenance: CompanionProvenanceRuntime::default(),
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
                gate_resolution: GateResolutionInputs::default(),
                http_dataplane_enabled: true,
                local_embedder_configured: false,
                local_embedder_initialized: false,
                embedding_delegation: EmbeddingDelegationRuntimeState::NotConfigured,
                rerank_endpoint_configured: false,
                graph_expand_configured: true,
                console_link_graph_configured: false,
                companion_provenance: CompanionProvenanceRuntime::default(),
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
                gate_resolution: GateResolutionInputs::default(),
                http_dataplane_enabled: true,
                local_embedder_configured: false,
                local_embedder_initialized: false,
                embedding_delegation: EmbeddingDelegationRuntimeState::Available,
                rerank_endpoint_configured: false,
                graph_expand_configured: true,
                console_link_graph_configured: false,
                companion_provenance: CompanionProvenanceRuntime::default(),
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
                gate_resolution: GateResolutionInputs::default(),
                http_dataplane_enabled: true,
                local_embedder_configured: false,
                local_embedder_initialized: false,
                embedding_delegation: EmbeddingDelegationRuntimeState::CircuitOpen,
                rerank_endpoint_configured: false,
                graph_expand_configured: true,
                console_link_graph_configured: false,
                companion_provenance: CompanionProvenanceRuntime::default(),
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
