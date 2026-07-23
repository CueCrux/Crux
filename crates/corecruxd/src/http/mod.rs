// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Top-level HTTP module: composes the axum `Router`, defines `AppState`, declares all `/v1/*` route handlers.

mod actions;
mod activity;
mod admin;
mod agent_usage;
mod append;
mod auth_device;
mod auth_rails;
mod cases;
// Hosted-service HTTP surface (ExecPlan crux-external-findings-remediation M4):
// Pro cloud access posture (`GET /v1/cloud/access-contract`). Compiled out of
// the default Community Edition binary; see the `hosted-surfaces` feature.
#[cfg(feature = "hosted-surfaces")]
mod cloud;
mod compute;
mod console;
mod consolidation_receipt;
mod context_surface;
mod coord;
mod cost;
mod credit_meter;
mod dataplane;
mod dossier;
mod engine_console;
mod engrams;
mod entities;
mod events;
mod extensions;
mod facts;
mod features;
mod memory_capture;
// Hosted-service HTTP surface (ExecPlan crux-external-findings-remediation M4):
// Pro GPU-1 compute bridge (`/v1/gpu1/*`). Compiled out of the default
// Community Edition binary; see the `hosted-surfaces` feature.
mod audit_verify;
#[cfg(feature = "hosted-surfaces")]
mod gpu1;
mod health;
mod identity_links;
mod incidents;
mod infra;
pub mod ingress;
mod integrations_github;
mod integrations_openai;
pub mod invocation;
mod legal_holds;
mod local_ingest;
mod memory_import;
pub(crate) mod observations;
mod observe;
mod observe_audit;
mod openai_shim;
mod openapi;
mod orchestrators;
mod passports;
mod planes;
mod policy;
mod principal;
mod projections;
mod projects;
mod provenance;
mod punchcards;
mod query;
mod quota;
mod rcx_publish;
mod receipts;
mod relations;
mod replay;
mod repos;
mod result_envelope;
mod route_auth;
mod routing;
pub mod session;
mod storybook;
mod stream_receipts;
mod sync;
mod witness;
mod work;
mod workbench;
mod workspace;
// session_metrics: Prometheus register!() at init — safe, panics only on
// duplicate registration (programmer error caught in tests). Mirrors the
// allow on `mod metrics` in main.rs.
#[allow(clippy::unwrap_used, clippy::expect_used)]
pub mod session_metrics;

pub(crate) use admin::AdminActionRecord;
pub(crate) use repos::RepoScanJob;
// Phase T M1 daemon-boot auto-emit — called once per boot from main.rs after
// the HTTP server is serving.
pub(crate) use stream_receipts::emit_daemon_start_usage_ping;
// HttpDataplane trait re-exported for test fakes (FakeHttpDataplane in tests.rs).
#[allow(unused_imports)]
pub(crate) use dataplane::{pool_backed_http_dataplane, HttpDataplane, HttpDataplaneError, SharedHttpDataplane};
// Receipt export helpers (build_lineage_json_v1, etc.) only used by proprietary ExportReceiptBundle.
#[allow(unused_imports)]
pub(crate) use receipts::{build_lineage_json_v1, build_subject_links_json_v1, build_trace_summary_json_v1};

use std::io::Write as _;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::{routing::get, Json, Router};
use base64::Engine as _;
use corecrux_proto::dataplane_v1::AppendEvent;
use tokio::sync::RwLock;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::timeout::TimeoutLayer;

use corecrux_frame::compute_header_hash;
use corecrux_frame::stream_hash_xxhash64;
use corecrux_receipts::{
    build_receipt_export_v1, resolve_subject_receipt_id_v1, ExportFormatV1, ExportRedactionV1, ReceiptExportIncludeV1,
    ReceiptExportOptionsV1, SubjectResolveModeV1, EVT_RECEIPT_BODY_V1, EVT_RECEIPT_SIG_V1, STREAM_TYPE_RECEIPT,
};
use corecrux_types::{
    format_u64_hex, CompatContract, ControlAdminActionFinishedV1, ControlAdminActionSubmittedV1,
    ControlCheckpointMaterializedV1, ControlStateMutationV1, EvidenceAuthContextV1, EvidenceNodeContextV1,
    EvidenceRequestContextV1, KnowledgeAuthorityModeV1, KnowledgeParityOutcomeV1, KnowledgeParityStatusV1,
    KnowledgeRolloutStageV1, ProblemDetails, RoutingInfo, ShardMapV1, CONTROL_EVIDENCE_CONTENT_TYPE_V1,
    EVT_CONTROL_ADMIN_ACTION_FINISHED_V1, EVT_CONTROL_ADMIN_ACTION_SUBMITTED_V1,
    EVT_CONTROL_CHECKPOINT_MATERIALIZED_V1, EVT_CONTROL_STATE_MUTATION_V1,
};
use corecrux_types::{ValveInfo, ValvesInfo};

use crate::config::CommitLevel;
use crate::metrics::Metrics;
use crate::problem::ProblemResponse;
use crate::shard_map::RoutingTable;
use crate::structured_log::{CorrelationIds, ErrorCode, StructuredOpLog};

use crate::auth::{
    describe_http_evidence, http_scope_context, require_http_any_scope, require_http_any_scope_for_tenant,
    require_http_scopes, require_http_scopes_for_tenant, Authz,
};
use crate::control::{self, ValveDecision};
use crate::dataplane_store::AppendError;

/// Lifetime advertised for server-issued peer-handshake challenges.
pub(crate) const SYNC_HANDSHAKE_NONCE_TTL_SECONDS: u64 = 120;

#[derive(Debug, Clone)]
#[allow(clippy::struct_field_names)] // Fields share the "control_evidence" domain prefix intentionally
pub struct Readiness {
    pub control_evidence_hosted: bool,
    pub control_evidence_ok: bool,
    pub control_evidence_error: Option<String>,
}

impl Default for Readiness {
    fn default() -> Self {
        Self {
            control_evidence_hosted: false,
            control_evidence_ok: true,
            control_evidence_error: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CapacityState {
    pub total_bytes: u64,
    pub free_bytes: u64,
    pub free_ratio: f64,
    #[allow(dead_code)] // Exposed in /healthz response; read path planned for capacity alerting.
    pub warning_free_ratio: f64,
    #[allow(dead_code)] // Exposed in /healthz response; read path planned for capacity alerting.
    pub critical_free_ratio: f64,
    pub emergency_free_ratio: f64,
    pub auto_paused: bool,
    pub error: Option<String>,
}

impl Default for CapacityState {
    fn default() -> Self {
        Self {
            total_bytes: 0,
            free_bytes: 0,
            free_ratio: 1.0,
            warning_free_ratio: 0.20,
            critical_free_ratio: 0.10,
            emergency_free_ratio: 0.10,
            auto_paused: false,
            error: None,
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    pub lock_held: bool,
    pub build: corecrux_types::BuildInfo,
    pub compat: CompatContract,
    pub sdk_version: String,
    pub auth: Authz,
    pub rcx_router: Option<Arc<crux_router::RcxRouter>>,
    pub data_dir: PathBuf,
    /// Require the M2a Ed25519 peer handshake on every tenant sync endpoint.
    /// Default OFF (`CORECRUXD_SYNC_MUTUAL_AUTH=1`). When enabled, the
    /// handshake replaces scope auth; even admin scopes cannot bypass it.
    pub sync_mutual_auth: bool,
    /// Issuer Ed25519 public key used to validate peer capability tokens.
    pub sync_peer_trust_root: Option<Vec<u8>>,
    /// Enforce holder caveats on attenuated peer tokens at the sync boundary
    /// (macaroon attenuation, R3). Default OFF (`CORECRUXD_SYNC_CAVEAT_ENFORCE=1`).
    /// OFF rejects any caveat-bearing token (fail-closed); un-attenuated tokens
    /// are unaffected either way.
    pub sync_caveat_enforce: bool,
    /// Shared single-use challenge state across cloned Axum application state.
    pub sync_handshake_nonces: Arc<std::sync::Mutex<crux_sync::peer_handshake::NonceCache>>,
    pub witness: crate::witness::WitnessRuntimeConfigV1,
    pub witness_proofs: Arc<RwLock<crate::witness_proofs::WitnessProofStore>>,
    /// Ephemeral, bounded replay keys for verified cloud-witness records.
    pub cloud_witness_replay_cache: Arc<std::sync::Mutex<std::collections::HashMap<String, std::time::Instant>>>,
    pub mcp_enabled: bool,
    pub console_enabled: bool,
    /// Agent-requested passport mint approval surface. Default OFF
    /// (`CORECRUXD_FEATURE_PASSPORT_MINT_REQUESTS`); approve/reject handlers
    /// return 404 without touching state while disabled.
    pub passport_mint_requests_enabled: bool,
    /// Multi-agent coordination plane (`/v1/coord/*`). Default ON; explicit
    /// `CORECRUXD_COORD=0` disables it and makes coord routes return 404.
    pub coord_enabled: bool,
    /// Liveness horizon for the coord active view, in seconds.
    pub coord_presence_ttl_secs: u64,
    /// Periodic consolidation review scheduler (`consolidation_scheduler`).
    /// Detect-and-surface only — never auto-resolves. Default OFF
    /// (`CORECRUXD_CONSOLIDATION_SCHEDULER=1`). Carried here so `/v1/version`
    /// can report its enabled state without re-parsing the environment.
    pub consolidation_scheduler_enabled: bool,
    /// Provider-agnostic injection-bundle surface (`/v1/context`). Default
    /// OFF (`CORECRUXD_CONTEXT_SURFACE=1`); when off, routes return 404.
    pub context_surface_enabled: bool,
    /// Authenticated daemon-to-daemon embedding provider
    /// (`POST /v1/compute/embed`). Default OFF
    /// (`CORECRUXD_COMPUTE_PROVIDER=1`); the route remains mounted while off
    /// so clients receive an explicit capability-disabled response.
    pub compute_provider_enabled: bool,
    /// Local CPU prose-ingest door (`/v1/local/ingest`). Seals pre-formatted
    /// prose payloads into local segments served over BM25 — no GPU dataplane.
    /// Default ON; `CORECRUXD_LOCAL_INGEST=0` or `false` disables it and makes
    /// the route return 404.
    pub local_ingest_enabled: bool,
    /// Gated auto-capture surface (`/v1/memory/extract` + candidate review).
    /// Default OFF (`CORECRUXD_AUTO_CAPTURE=1`); when off, the routes return
    /// 404. Auto-extracted facts land as review-only candidates and only reach
    /// recall via an explicit promotion (see `crate::candidate_store`).
    pub auto_capture_enabled: bool,
    /// G19 stream/context receipt wiring (`Streaming-Receipts-Spec` §5):
    /// `/v1/mediation/receipts` lifts `context_injected` /
    /// `stream_completed` / `stream_aborted` drafts into canonical signed
    /// receipts, verifies nested cloud-witness v1 envelopes into signed
    /// mediation observations, and SSE surfaces mint `stream_aborted` on
    /// disconnect.
    /// Default OFF (`CORECRUXD_STREAM_RECEIPTS=1`).
    pub stream_receipts_enabled: bool,
    /// Phase T opt-in usage-ping receipts: `/v1/mediation/receipts` accepts a
    /// `usage_ping` metadata-only draft and lifts it into a local signed
    /// receipt. No egress in M0. Default OFF
    /// (`CORECRUXD_FEATURE_USAGE_RECEIPTS=1`); when off the draft hits the
    /// legacy tool-mediation parse and is rejected, exactly as before.
    pub usage_receipts_enabled: bool,
    /// Phase T S1 faithful handoff measurement. Default OFF
    /// (`CORECRUXD_HANDOFF_OBSERVATIONS=1`); when enabled,
    /// `/v1/workbench/handoff-v2` writes a local signed `kind="handoff"`
    /// observation with source/target vendor passport attribution.
    pub handoff_observations_enabled: bool,
    /// Phase T (M1) consent-gated opt-in usage-ping *submitter* config — the
    /// daemon's only sanctioned outbound signal. Default-absent on every leg
    /// (`CORECRUXD_USAGE_RECEIPTS_SUBMIT` / `_ENDPOINT` / `_CONSENT_AT`); the
    /// submitter fires only on an explicit `usage_ping` mint, after local
    /// persist, and only when all three are set. See `crate::usage_submit`.
    pub usage_submit: crate::usage_submit::UsageSubmitConfig,
    /// Phase T (M2) version-notify — the last `latest_version` release string
    /// the consent-gated usage submitter saw in a collector 2xx response, if
    /// any. Written by the submit task (`crate::usage_submit`), read by
    /// `/v1/version` to surface an "update available" notice. `None` until the
    /// first successful submit whose response carried `latest_version`; never
    /// populated on a default (un-opted-in) install, since the submitter never
    /// runs there.
    pub latest_release: Arc<std::sync::RwLock<Option<String>>>,
    /// G20 per-surface request quota (`GET /v1/quota` + middleware over
    /// `crux_router::quota::QuotaLedger`). Default OFF
    /// (`CORECRUXD_QUOTA=1`); when off the middleware passes through and
    /// the route returns 404. Local compute is never rate-limited.
    pub quota_enabled: bool,
    /// Path prefixes classified as hosted surfaces for quota purposes
    /// (`CORECRUXD_QUOTA_HOSTED_SURFACES`, comma-separated). Empty default
    /// = every surface is local compute = unlimited.
    pub quota_hosted_surfaces: Arc<Vec<String>>,
    /// Token-bucket ledger, one bucket per (passport, surface).
    /// Deliberately ephemeral: a restart refills everyone (errs toward
    /// the user).
    pub quota_ledger: Arc<std::sync::Mutex<crux_router::quota::QuotaLedger>>,
    /// Persistent comped-wallet credit ledger. Default OFF
    /// (`CORECRUXD_CREDIT_METER=1`); when absent `/v1/credits/spend` returns
    /// 404 and metered capability paths preserve their legacy no-burn shape.
    /// A poisoned mutex deliberately fails every metered request closed with
    /// 500 until restart; recovering potentially inconsistent money-path state
    /// could otherwise permit an untracked debit or compute without a debit.
    pub credit_meter: Option<Arc<std::sync::Mutex<crate::credit_meter::CreditMeterStore>>>,
    /// G21b assembly cache over
    /// `corecrux_projections::assembly_cache::AssemblyCache` — memoizes
    /// assembled `/v1/context` bundles keyed by
    /// (passport, session, facts-chain-head). `None` unless
    /// `CORECRUXD_ASSEMBLY_CACHE=1` (default OFF); invalidation is
    /// structural (any fact write moves the chain head). Ephemeral by
    /// design: restart = cold = always safe.
    pub assembly_cache: Option<Arc<std::sync::Mutex<corecrux_projections::assembly_cache::AssemblyCache>>>,
    /// OpenAI function-calling shim over the MCP tool surface
    /// (`/v1/openai/tools.json` + `/v1/openai/invoke`). Default OFF
    /// (`CORECRUXD_OPENAI_SHIM=1`); when off, routes return 404.
    pub openai_shim_enabled: bool,
    /// `.cruxpack` import surface (`POST /v1/memory/import`). Default OFF
    /// (`CRUX_MEMORY_IMPORT=1`); when off, the route returns 404.
    pub memory_import_enabled: bool,
    /// Identity-federation links + resolver extension
    /// (`/v1/identity/links*`; `/v1/principal/resolve` follows
    /// `identity_link` edges). Default OFF (`CORECRUXD_IDENTITY_LINKS=1`).
    pub identity_links_enabled: bool,
    /// Shared MCP dispatch context for the OpenAI shim — one source for the
    /// MCP server (:14801) and the shim (:14800). `None` when MCP disabled.
    pub mcp_context: Option<Arc<crux_mcp::dispatch::McpContext>>,
    pub integrations_enabled: bool,
    pub integrations_safe_mode: bool,
    pub integrations_allow_executable_helpers: bool,
    pub operating_mode: crate::product::OperatingMode,
    pub enabled_pro_services: Vec<String>,
    pub read_retry_failed_readyz_threshold: u64,
    pub commit_level: CommitLevel,
    pub metrics: Metrics,
    pub node_id: String,
    pub passport_key_path: PathBuf,
    pub passport_fpr: String,
    pub passport_public_key_hex: String,
    pub mcp_agent_count: usize,
    pub routing: Arc<RwLock<RoutingTable>>,
    pub routing_errors: Arc<RwLock<Vec<String>>>,
    pub dataplane_pool: Option<crate::pool::DataPlanePool>,
    pub http_dataplane: SharedHttpDataplane,
    pub readiness: Arc<RwLock<Readiness>>,
    pub control: Arc<RwLock<control::ControlV1>>,
    pub control_path: PathBuf,
    pub action_max_pending: usize,
    pub action_timeout_secs: u64,
    pub repo_scan_max_pending: usize,
    pub scrub_scope: String,
    pub scrub_mode: String,
    pub scrub_sample_rate: f64,
    pub admin_actions: Arc<RwLock<std::collections::BTreeMap<String, AdminActionRecord>>>,
    pub repo_scan_jobs: Arc<RwLock<std::collections::BTreeMap<String, RepoScanJob>>>,
    pub repo_scan_semaphore: Arc<tokio::sync::Semaphore>,
    pub corruption_detected: Arc<RwLock<bool>>,
    pub capacity: Arc<RwLock<CapacityState>>,
    pub admin_force_seal_enabled: bool,
    /// Serializes local prose-ingest seals (`/v1/local/ingest`). Each seal opens
    /// the shard's exclusive `ShardStorage` handle; this mutex prevents two
    /// concurrent ingests from racing on that lock. Ingest is a batch/occasional
    /// path, so serialization is not on any hot query path.
    pub local_ingest_lock: Arc<tokio::sync::Mutex<()>>,
    /// Fact-store retention window in days (launch-gate 5.1 / W2.E2). `None` =
    /// retention off; the `compact-facts` admin action then only scrubs already
    /// soft-deleted facts. Sourced from `CORECRUXD_RETENTION_DAYS`.
    pub retention_days: Option<u32>,
    /// CoreCrux v5: loaded .ccxi companion indexes for BM25 text retrieval.
    pub retrieval_index: Arc<RwLock<corecrux_retrieval::IndexManager>>,
    /// Crux Daemon fact store (receipted entity memory).
    pub fact_store: Arc<RwLock<corecrux_memory::FactStore>>,
    /// Optional active repository watcher. `None` unless
    /// `CORECRUXD_REPO_WATCH` is truthy at daemon startup.
    pub repo_watch: Option<crate::repo_watch::RepoWatchService>,
    /// Process-wide rate-limit table for community-extension dispatch
    /// (M4 Phase A). Sliding 60-second window keyed by
    /// (extension_id, passport_fpr); cap is per-grant or daemon default.
    pub extension_rate_table: Arc<crate::extension_outbound::RateTable>,
    /// Long-lived wasmtime engine + epoch-tick thread for `kind: wasm`
    /// extensions (M6.3 of the community-extensions ExecPlan). Built
    /// lazily at startup when the `wasm-extensions` feature is enabled;
    /// `None` otherwise (the HTTP path returns 501 in that case).
    #[cfg(feature = "wasm-extensions")]
    pub wasm_engine: Option<Arc<crate::wasm_host::WasmEngine>>,
    /// Crux Daemon session store (scoped state per session).
    pub session_store: Arc<RwLock<corecrux_memory::SessionStore>>,
    /// Cached git-based update posture for humans and agents.
    pub update_status: Arc<RwLock<corecrux_types::UpdateStatus>>,
    /// Real-time event bus for SSE streaming of store mutations.
    pub event_bus: corecrux_memory::events::EventBus,
    /// Session-handshake services (M1). `None` disables `POST /session`,
    /// which then returns 503. Hosted and local-daemon deployments populate
    /// this differently; see [`session::SessionServices::local_default`] for
    /// the local out-of-the-box wiring.
    pub session: Option<Arc<session::SessionServices>>,
    /// stateful-extraction-flywheel M1.b — in-memory materializer for the
    /// `extraction_cache_current` projection. Updated by the append handler
    /// when it observes `corecrux.proj.extraction.*` events; read by the
    /// `/v1/projections/lookup` handler. Shared across router clones; the
    /// RwLock is cheap because reads dominate writes (every chunk ingest is
    /// one write + many reads across the pilot).
    ///
    /// CE-friendly: lives entirely in-process, no proprietary storage
    /// dependency. Proprietary deployments can swap this for an event-sourced
    /// replay-from-log implementation without changing the HTTP contract.
    pub extraction_cache: Arc<RwLock<corecrux_projections::ExtractionCacheMaterializer>>,
    /// Persisted first-run state for the embedded console.
    pub onboarding: Arc<RwLock<crate::onboarding::OnboardingState>>,
    /// `true` if the HTTP listener bound to a loopback address. Onboarding
    /// uses this to decide whether `auth_mode = off` is allowed.
    pub http_bind_loopback: bool,
    /// Mirror of `CORECRUXD_ALLOW_INSECURE_DEV_AUTH_BIND`. When `true`, the
    /// onboarding flow allows `auth_mode = off` even on a non-loopback bind.
    pub allow_insecure_dev_auth_bind: bool,
    /// In-memory graph projection state. Populated from `data_dir/relations.jsonl`
    /// on startup; the `/v1/relations` and `/v1/query/graph-expand` endpoints
    /// read and mutate it. Replaces the dataplane-stub graph surface in the
    /// open Crux Daemon distribution.
    pub projection_state: Arc<RwLock<corecrux_projections::ProjectionState>>,
    /// 32-byte symmetric key derived from the daemon-root passport via
    /// `LocalPassportKey::derive_subkey`. Used to seal/open integration
    /// secrets at rest (GitHub PATs initially; future API keys). Rotating the
    /// passport invalidates existing envelopes and forces re-connect — by
    /// design.
    pub integration_encryption_key: Arc<[u8; 32]>,
    /// Multi-agent presence tracker (#9). Updated by middleware on every
    /// request that carries `X-Corecrux-Passport-Id`; read by
    /// `GET /v1/passports/presence`.
    pub presence: crate::presence::PresenceTracker,
    /// Belt-and-braces privacy gate (see `fact_privacy`). Every fact write
    /// path runs `fact_privacy::enforce(&state.privacy_policy, &mut fact)`
    /// before `store.store(fact)`, ensuring entities under reserved
    /// prefixes are born `private=true` and never leak via `sync_push`.
    pub privacy_policy: crate::fact_privacy::PrivacyPolicy,
    /// Substrate entity store (M1: Crux as domain substrate).
    pub entity_store: Arc<RwLock<corecrux_memory::EntityStore>>,
    /// Substrate edge store (M1).
    pub edge_store: Arc<RwLock<corecrux_memory::EdgeStore>>,
    /// Substrate kind registry. Lens crates register at startup.
    pub kind_registry: Arc<RwLock<corecrux_memory::KindRegistry>>,
    /// Content-addressed artefact store (agent-ux-12, calm deferred output).
    pub artefact_store: Arc<RwLock<corecrux_memory::ArtefactStore>>,
}

pub fn router(state: AppState, case_store: self::cases::SharedCaseStore) -> Router {
    // Route-authorization posture is read ONCE here, at router build time, not
    // per request. Tests build the router via `router_with_route_auth` to pin an
    // explicit mode without touching the process-global env.
    router_with_route_auth(state, case_store, self::route_auth::RouteAuthMode::from_env())
}

pub(crate) fn router_with_route_auth(
    state: AppState,
    case_store: self::cases::SharedCaseStore,
    route_auth_mode: self::route_auth::RouteAuthMode,
) -> Router {
    let console_enabled = state.console_enabled;
    tracing::debug!(
        route_auth_mode = route_auth_mode.as_str(),
        "corecruxd route authorization mode"
    );
    let router = Router::new()
        .route("/healthz", get(self::health::healthz))
        .route("/readyz", get(self::health::readyz))
        .route("/metrics", get(self::health::metrics))
        .route("/v1/gpus", get(self::routing::get_gpus))
        .route("/v1/shards", get(self::routing::get_shards))
        .route("/v1/route", get(self::routing::route_v1))
        .route(
            "/v1/audit/bundle/verify",
            axum::routing::post(self::audit_verify::post_audit_bundle_verify).layer(
                axum::extract::DefaultBodyLimit::max(self::audit_verify::AUDIT_BUNDLE_MAX_UPLOAD_BYTES),
            ),
        )
        .route(
            "/v1/compute/embed",
            axum::routing::post(self::compute::post_compute_embed).layer(
                axum::extract::DefaultBodyLimit::max(self::compute::COMPUTE_EMBED_MAX_REQUEST_BYTES),
            ),
        )
        .route("/v1/legal-holds", axum::routing::post(self::legal_holds::post_legal_hold))
        .route(
            "/v1/legal-holds/{id}",
            axum::routing::delete(self::legal_holds::delete_legal_hold),
        )
        .route(
            "/v1/incidents",
            get(self::incidents::list_incidents).post(self::incidents::post_incident),
        )
        .route("/v1/incidents/{id}", get(self::incidents::get_incident))
        .route(
            "/v1/incidents/{id}/export",
            axum::routing::post(self::incidents::export_incident),
        )
        .route("/v1/receipts/{receiptId}", get(self::receipts::get_receipt_body_v1))
        .route(
            "/v1/receipts/{receiptId}/signature",
            get(self::receipts::get_receipt_signature_v1),
        )
        .route(
            "/v1/receipts/{receiptId}/verification",
            get(self::receipts::get_receipt_verification_v1),
        )
        .route("/v1/witness/smoke", get(self::witness::get_witness_smoke))
        // Unified-login auth rails (ExecPlan crux-unified-login-rails).
        .route("/v1/auth/whoami", get(self::auth_rails::get_whoami))
        .route(
            "/v1/auth/tailscale/token",
            axum::routing::post(self::auth_rails::post_tailscale_token),
        )
        .route(
            "/v1/auth/device/start",
            axum::routing::post(self::auth_device::post_device_start),
        )
        .route(
            "/v1/auth/device/token",
            axum::routing::post(self::auth_device::post_device_token),
        )
        .route(
            "/v1/auth/device/approve",
            axum::routing::post(self::auth_device::post_device_approve),
        )
        .route(
            "/v1/auth/device/refresh",
            axum::routing::post(self::auth_device::post_device_refresh),
        )
        .route(
            "/v1/auth/device/revoke",
            axum::routing::post(self::auth_device::post_device_revoke),
        )
        .route(
            "/v1/replay/exports/receipts/{receiptId}",
            get(self::receipts::get_receipt_export_v1),
        )
        .route(
            "/v1/replay/exports/answers/{answerId}",
            get(self::receipts::get_answer_export_v1),
        )
        .route(
            "/v1/replay/exports/actions/{actionId}",
            get(self::receipts::get_action_export_v1),
        )
        .route(
            "/v1/replay/exports/streams/{streamType}/{streamId}",
            get(self::receipts::get_stream_export_v1),
        )
        .route("/v1/replay/answers/{answerId}", get(self::replay::get_answer_replay))
        .route(
            "/v1/replay/answers/{answerId}/validity",
            get(self::replay::get_answer_replay_validity),
        )
        .route("/v1/shard-map", get(self::admin::get_shard_map))
        .route("/v1/admin/shard-map", axum::routing::post(self::admin::post_shard_map))
        .route("/v1/admin/control", get(self::admin::get_control))
        .route("/v1/admin/restart", axum::routing::post(self::admin::post_restart_daemon))
        .route("/v1/admin/segments/fingerprints", get(self::admin::get_segment_fingerprints))
        .route("/v1/admin/sharing/posture", get(self::admin::get_sharing_posture))
        .route("/v1/admin/sharing/backfill", axum::routing::post(self::admin::post_sharing_backfill))
        .route("/v1/admin/ops-log", get(self::admin::get_ops_log))
        .route("/v1/admin/valves", axum::routing::post(self::admin::post_valves))
        .route("/v1/admin/replication/status", get(self::admin::get_replication_status))
        .route("/v1/admin/version", get(self::health::get_admin_version))
        .route("/v1/admin/actions", axum::routing::post(self::admin::post_admin_action))
        .route("/v1/admin/actions/{actionId}", get(self::admin::get_admin_action))
        .route(
            "/v1/admin/stream-meta",
            axum::routing::post(self::admin::post_stream_meta),
        )
        .route(
            "/v1/internal/replication/segments",
            axum::routing::post(self::admin::post_replication_segment),
        )
        .route(
            "/v1/admin/projections/artifacts/{artifactId}/state",
            get(self::projections::get_proj_artifact_state),
        )
        .route(
            "/v1/admin/projections/artifacts/{artifactId}/relations",
            get(self::projections::get_proj_artifact_relations),
        )
        .route(
            "/v1/admin/projections/artifacts/{artifactId}/dependents",
            get(self::projections::get_proj_artifact_dependents),
        )
        .route(
            "/v1/admin/projections/artifacts/{artifactId}/pressure-events",
            get(self::projections::get_proj_artifact_pressure_events),
        )
        .route("/v1/admin/projections/meta", get(self::projections::get_proj_meta))
        .route(
            "/v1/admin/projections/modules",
            get(self::projections::get_projection_modules),
        )
        // Phase 7: Entity projection query endpoints
        .route("/v1/activity", get(self::activity::get_activity))
        .route("/v1/activity", axum::routing::post(self::activity::post_activity))
        .route("/v1/activity/turn/{turn_id}", get(self::activity::get_activity_turn))
        .route("/v1/activity/turn/{turn_id}/verify", get(self::activity::get_activity_turn_verify))
        .route("/v1/projections/entity/count", get(self::projections::get_entity_count))
        .route("/v1/projections/entity/timeline", get(self::projections::get_entity_timeline))
        .route("/v1/projections/entity/current-state", get(self::projections::get_entity_current_state))
        .route(
            "/v1/admin/projections/rebuild",
            axum::routing::post(self::projections::post_projection_rebuild),
        )
        // stateful-extraction-flywheel M1 — chunk extraction cache lookup.
        // `mode=key` is the only live path in M1; `vector` / `key_or_vector` are
        // reserved for optional M13 (semantic near-hit). Materializer ships next.
        .route(
            "/v1/projections/lookup",
            axum::routing::post(self::projections::post_projection_lookup),
        )
        .route(
            "/v1/projections/batch_lookup",
            axum::routing::post(self::projections::post_projection_batch_lookup),
        )
        .route("/v1/routing/route", get(self::routing::route_debug))
        .route("/v1/routing/status", get(self::routing::routing_status))
        // ── v4.2 query endpoints (graph expand + temporal range) ─────
        .route(
            "/v1/query/graph-expand",
            axum::routing::post(self::query::post_query_graph_expand),
        )
        .route(
            "/v1/query/time-range",
            axum::routing::post(self::query::post_query_time_range),
        )
        // ── v5 append + text retrieval endpoints ─────────────────────
        .route(
            "/v1/append",
            axum::routing::post(self::append::post_admin_append),
        )
        .route(
            "/v1/admin/append",
            axum::routing::post(self::append::post_admin_append),
        )
        .route(
            "/v1/local/ingest",
            axum::routing::post(self::local_ingest::post_local_ingest),
        )
        .route(
            "/v1/query/text-search",
            axum::routing::post(self::query::post_query_text_search),
        )
        .route(
            "/v1/query/text-search/expand",
            axum::routing::post(self::query::post_query_text_search_expand),
        )
        // Memory primitives (Phase 1.5)
        .route("/v1/facts", axum::routing::put(self::facts::put_fact))
        .route("/v1/facts", get(self::facts::query_facts))
        .route("/v1/facts/bulk", axum::routing::put(self::facts::put_facts_bulk))
        .route("/v1/facts/aggregate", axum::routing::post(self::facts::post_aggregate))
        .route("/v1/memory/import", axum::routing::post(self::memory_import::post_memory_import))
        .route(
            "/v1/identity/links",
            axum::routing::post(self::identity_links::post_identity_link),
        )
        .route("/v1/identity/links", get(self::identity_links::get_identity_links))
        .route(
            "/v1/identity/links/{linkId}/revoke",
            axum::routing::post(self::identity_links::post_identity_link_revoke),
        )
        .route(
            "/v1/identity/candidates/{candidateId}/confirm",
            axum::routing::post(self::identity_links::post_identity_candidate_confirm),
        )
        .route(
            "/v1/identity/candidates/{candidateId}/reject",
            axum::routing::post(self::identity_links::post_identity_candidate_reject),
        )
        .route(
            "/v1/identity/candidates",
            get(self::identity_links::get_identity_candidates),
        )
        .route("/v1/facts/{factId}", get(self::facts::get_fact))
        .route("/v1/facts/{factId}", axum::routing::delete(self::facts::delete_fact))
        .route("/v1/facts/entity/{entity}", get(self::facts::get_facts_by_entity))
        .route("/v1/facts/export", get(self::facts::export_facts))
        .route("/v1/facts/list", get(self::facts::list_facts))
        // Substrate (M1: Crux as domain substrate).
        .route("/v1/entities", get(self::entities::list_entities))
        .route("/v1/entities/{kind}/{id}", get(self::entities::get_entity))
        .route("/v1/entities/{kind}/{id}", axum::routing::put(self::entities::put_entity))
        .route(
            "/v1/entities/{kind}/{id}",
            axum::routing::delete(self::entities::delete_entity),
        )
        .route(
            "/v1/entities/{kind}/{id}/history",
            get(self::entities::get_entity_history),
        )
        .route("/v1/edges", get(self::entities::list_edges))
        .route("/v1/edges", axum::routing::put(self::entities::put_edge))
        .route("/v1/edges", axum::routing::delete(self::entities::delete_edge))
        .route("/v1/kinds", get(self::entities::list_kinds))
        .route("/v1/kinds/{kind}", get(self::entities::get_kind))
        // Features lens (M3).
        .route("/v1/features/capabilities", get(self::features::list_capabilities))
        .route("/v1/features/capabilities/{id}", get(self::features::get_capability))
        .route("/v1/features/capabilities/{id}/tree", get(self::features::get_dependency_tree))
        .route("/v1/features/capabilities/analysis/gaps", get(self::features::analysis_gaps))
        .route(
            "/v1/features/capabilities/analysis/promises",
            get(self::features::analysis_promises),
        )
        .route(
            "/v1/features/capabilities/analysis/coverage",
            get(self::features::analysis_coverage),
        )
        .route(
            "/v1/features/capabilities/{id}/audit",
            axum::routing::post(self::features::post_audit),
        )
        .route(
            "/v1/sync/handshake/nonce",
            axum::routing::post(self::sync::post_handshake_nonce),
        )
        .route(
            "/v1/sync/tenants/{tenantId}/manifest",
            get(self::sync::get_tenant_manifest),
        )
        .route(
            "/v1/sync/tenants/{tenantId}/collections/{collection}",
            get(self::sync::get_tenant_collection),
        )
        .route(
            "/v1/sync/tenants/{tenantId}/promotions/preview",
            axum::routing::post(self::sync::post_promotion_preview),
        )
        .route(
            "/v1/sync/tenants/{tenantId}/promotions/confirm",
            axum::routing::post(self::sync::post_promotion_confirm),
        )
        .route(
            "/v1/sync/tenants/{tenantId}/offboard",
            axum::routing::post(self::sync::post_tenant_offboard),
        )
        .route(
            "/v1/result-envelope/import",
            axum::routing::post(self::result_envelope::post_result_envelope_import),
        )
        .route("/v1/sessions/{sessionId}/state", axum::routing::put(self::facts::put_session_state))
        .route("/v1/sessions/{sessionId}/state", get(self::facts::get_session_state))
        // Session archive lifecycle (soft, reversible — preserves state, hides from default listings).
        .route(
            "/v1/sessions/{sessionId}/archive",
            axum::routing::post(self::facts::archive_session),
        )
        .route(
            "/v1/sessions/{sessionId}/unarchive",
            axum::routing::post(self::facts::unarchive_session),
        )
        // Session observations (multi-provider capture, ExecPlan 2026-05-13).
        .route(
            "/v1/sessions/{sessionId}/observations",
            axum::routing::post(self::observations::post_observation),
        )
        .route(
            "/v1/sessions/{sessionId}/observations",
            get(self::observations::get_observations),
        )
        .route(
            "/v1/sessions/{sessionId}/observations/batch",
            axum::routing::post(self::observations::post_observations_batch),
        )
        .route(
            "/v1/observations/aggregate",
            get(self::observations::get_observations_aggregate),
        )
        // Per-passport tool-usage rollup over the action ledger (action-ledger M3).
        .route("/v1/agents/{passport}/usage", get(self::agent_usage::get_agent_usage))
        // Token-burn cost lens — POST a ground-truth report, GET it for the console.
        .route("/v1/cost/report", get(self::cost::get_cost_report))
        .route("/v1/cost/report", axum::routing::post(self::cost::post_cost_report))
        // Real-time event stream (SSE)
        .route("/v1/events/stream", get(self::events::event_stream))
        // Self-observation (crux-observe)
        .route("/v1/ops/facts", get(self::observe::query_ops_facts))
        .route("/v1/ops/errors", get(self::observe::query_ops_errors))
        .route("/v1/ops/health", get(self::observe::get_ops_health))
        .route("/v1/bootstrap/pull", axum::routing::post(self::observe::post_bootstrap_pull))
        .route("/v1/bootstrap/status", get(self::observe::get_bootstrap_status))
        // Session handshake (master-plan §5.1): Crux Daemon uses /session, not /v1/session.
        .route("/session", axum::routing::post(self::session::post_session))
        .route("/v1/sessions/active", get(self::session::get_active_sessions))
        .route("/v1/sessions/{sessionId}/plan", get(self::session::get_session_plan))
        // Invocation verification (master-plan §8).
        .route(
            "/invocation/verify",
            axum::routing::post(self::invocation::post_invocation_verify),
        )
        // Production hardening: version endpoint
        .route("/v1/version", get(self::health::get_version))
        .route("/v1/actions/enrich", axum::routing::post(self::actions::post_action_enrich))
        .route("/v1/workbench/contract", get(self::workbench::get_workbench_contract))
        .route("/v1/workbench/brief", get(self::workbench::get_agent_brief))
        .route(
            "/v1/workbench/context-pack",
            axum::routing::post(self::workbench::post_context_pack),
        )
        .route(
            "/v1/workbench/impact-preflight",
            axum::routing::post(self::workbench::post_impact_preflight),
        )
        .route("/v1/workbench/command-ledger", get(self::workbench::get_command_ledger))
        .route(
            "/v1/workbench/command-ledger",
            axum::routing::post(self::workbench::post_command_ledger),
        )
        .route("/v1/workbench/audit-triage", get(self::workbench::get_audit_triage))
        .route(
            "/v1/workbench/reasoning-timeline",
            get(self::workbench::get_reasoning_timeline),
        )
        .route(
            "/v1/workbench/handoff-v2",
            axum::routing::post(self::workbench::post_handoff_v2),
        )
        .route(
            "/v1/workbench/route-probe",
            axum::routing::post(self::workbench::post_route_probe),
        )
        .route("/v1/workbench/api-drift", get(self::workbench::get_api_drift))
        .route(
            "/v1/workbench/policy-simulation",
            axum::routing::post(self::workbench::post_policy_simulation),
        )
        // OpenAPI spec
        .route("/v1/openapi.json", get(self::openapi::openapi_json))
        // G20 quota state (gated by CORECRUXD_QUOTA, default OFF → 404).
        .route("/v1/quota", get(self::quota::get_quota))
        // Credit-burn Meter M1b. Default OFF and comped-wallet only.
        .route(
            "/v1/credits/spend",
            axum::routing::post(self::credit_meter::post_credit_spend),
        )
        // Provider-agnostic injection-bundle surface (context_bundle/v1).
        // Gated by CORECRUXD_CONTEXT_SURFACE (default OFF → 404).
        .route("/v1/context", get(self::context_surface::get_context))
        .route("/v1/context", axum::routing::post(self::context_surface::post_context))
        // Gated auto-capture (ExecPlan buyer-fit M1). Extract review-only
        // candidates + review them. Gated by CORECRUXD_AUTO_CAPTURE (default
        // OFF → 404). A promoted candidate is the only path to recall.
        .route("/v1/memory/extract", axum::routing::post(self::memory_capture::post_extract))
        .route("/v1/memory/candidates", get(self::memory_capture::get_candidates))
        .route(
            "/v1/memory/candidates/{id}/promote",
            axum::routing::post(self::memory_capture::post_promote),
        )
        .route(
            "/v1/memory/candidates/{id}/reject",
            axum::routing::post(self::memory_capture::post_reject),
        )
        // OpenAI function-calling shim over the MCP tool surface.
        // Gated by CORECRUXD_OPENAI_SHIM (default OFF → 404).
        .route("/v1/openai/tools.json", get(self::openai_shim::get_tools_json))
        .route("/v1/openai/invoke", axum::routing::post(self::openai_shim::post_invoke))
        // Multi-agent coordination plane — presence-joined session board
        // (flag-gated by `CORECRUXD_COORD`; 404 when off).
        .route("/v1/coord/active", get(self::coord::get_coord_active))
        .route(
            "/v1/coord/announce",
            axum::routing::post(self::coord::post_coord_announce),
        )
        // Work coordination — kanban over `__work__::*` facts.
        .route("/v1/work", get(self::work::get_work))
        .route("/v1/work", axum::routing::post(self::work::post_work))
        .route("/v1/work/gate/pending", get(self::work::get_pending_gates))
        .route(
            "/v1/work/gate/{actionId}/approve",
            axum::routing::post(self::work::post_gate_approve),
        )
        .route(
            "/v1/work/gate/{actionId}/reject",
            axum::routing::post(self::work::post_gate_reject),
        )
        .route("/v1/work/{id}", get(self::work::get_work_item))
        .route("/v1/work/{id}", axum::routing::patch(self::work::patch_work))
        .route(
            "/v1/work/{id}/comments",
            axum::routing::post(self::work::post_comment),
        )
        .route("/v1/work/{id}/comments", get(self::work::get_comments))
        .route("/v1/work/{id}/transitions", get(self::work::get_transitions))
        .route("/v1/status-feed", get(self::work::get_status_feed))
        // Project endpoints.
        .route("/v1/projects", get(self::projects::get_projects))
        .route(
            "/v1/projects",
            axum::routing::post(self::projects::post_project),
        )
        .route("/v1/projects/{id}", get(self::projects::get_project))
        .route(
            "/v1/projects/{id}",
            axum::routing::patch(self::projects::patch_project),
        )
        .route(
            "/v1/projects/{id}",
            axum::routing::delete(self::projects::delete_project),
        )
        .route(
            "/v1/projects/{id}/passports",
            axum::routing::post(self::projects::post_project_member),
        )
        .route(
            "/v1/projects/{id}/passports/{passportId}",
            axum::routing::delete(self::projects::delete_project_member),
        )
        .route(
            "/v1/projects/{id}/tenants",
            axum::routing::post(self::projects::post_project_tenant),
        )
        // Tenant-scoped repository registry endpoints.
        .route("/v1/repos", get(self::repos::get_repos))
        .route("/v1/repos", axum::routing::post(self::repos::post_repo))
        .route("/v1/repos/dependents", get(self::repos::get_repo_dependents))
        .route(
            "/v1/repos/scan-jobs/{job_id}",
            get(self::repos::get_repo_scan_job),
        )
        .route("/v1/repos/{repo_id}", get(self::repos::get_repo))
        .route(
            "/v1/repos/{repo_id}",
            axum::routing::delete(self::repos::delete_repo),
        )
        // AST-derived code map for a registered repo — the read side of the
        // registration-time scan (dogfood: register this repo, serve its map).
        .route(
            "/v1/repos/{repo_id}/codemap",
            get(self::repos::get_repo_codemap),
        )
        .route(
            "/v1/projects/{id}/tenants/{tenantId}",
            axum::routing::delete(self::projects::delete_project_tenant),
        )
        // Project layers (Vision, Goals, Manifesto, …) — content cards
        // attached to a project. Backed by `__project_layer__::*` facts.
        .route(
            "/v1/projects/{id}/layers",
            get(self::projects::get_project_layers),
        )
        .route(
            "/v1/projects/{id}/layers/{layer}",
            axum::routing::put(self::projects::put_project_layer),
        )
        .route(
            "/v1/projects/{id}/layers/{layer}",
            axum::routing::delete(self::projects::delete_project_layer),
        )
        // Project ↔ GitHub-repo links — replaces the old "select repos in
        // Integrations panel" UX. Repos are now linked per-project (and
        // optionally per-plane).
        .route(
            "/v1/projects/{id}/repos",
            get(self::projects::get_project_repos),
        )
        .route(
            "/v1/projects/{id}/repos",
            axum::routing::post(self::projects::post_project_repo),
        )
        .route(
            "/v1/projects/{id}/repos/{owner}/{repo}",
            axum::routing::delete(self::projects::delete_project_repo),
        )
        .route(
            "/v1/projects/{id}/planes/{planeId}/repos",
            get(self::projects::get_plane_repos),
        )
        // Context graph — canonical {nodes, edges} for the agent-native view.
        .route(
            "/v1/projects/{id}/context-graph",
            get(self::projects::get_context_graph),
        )
        // RCX Registry publish preview/emit for local projects.
        .route(
            "/v1/rcx/publish/projects/{projectId}/preview",
            axum::routing::post(self::rcx_publish::preview_project),
        )
        .route(
            "/v1/rcx/publish/projects/{projectId}/emit",
            axum::routing::post(self::rcx_publish::emit_project),
        )
        // Workspace scan — Phase 2 of the context graph (modules, deps,
        // stubs, dead code).
        .route(
            "/v1/workspace/scan",
            axum::routing::post(self::workspace::post_scan),
        )
        .route(
            "/v1/workspace/scan",
            get(self::workspace::get_scan),
        )
        // Storyline — agent-friendly per-route call tree derived from the
        // latest scan. Tree-art (default) for LLM consumption; compact JSON
        // for agents that want to traverse the graph themselves.
        .route(
            "/v1/workspace/storyline",
            get(self::workspace::get_storyline),
        )
        // MCP tool catalog proxy — same data the MCP server exposes via
        // tools/list on :14801, but reachable from the in-browser console
        // without crossing CORS to a different port.
        .route(
            "/v1/mcp/tools",
            get(self::workspace::get_mcp_tools),
        )
        // Local MemoryCrux-compatible engram/session-procedure surfaces.
        .route("/v1/engrams", get(self::engrams::list_engrams))
        .route(
            "/v1/memory/session-init",
            axum::routing::post(self::engrams::memory_session_init),
        )
        .route(
            "/v1/memory/engrams/resolve",
            axum::routing::post(self::engrams::resolve_engrams),
        )
        // Community extensions registry (M2 of community-extensions plan).
        // List/install/show/delete + trusted-key management. M3+M4 will add
        // /grants/* (capability-token issuance) + tool dispatch on top.
        .route(
            "/v1/extensions",
            get(self::extensions::list_extensions),
        )
        .route(
            "/v1/extensions/register",
            axum::routing::post(self::extensions::register_extension),
        )
        .route(
            "/v1/extensions/install-from-registry",
            axum::routing::post(self::extensions::install_from_registry),
        )
        .route(
            "/v1/extensions/keys",
            get(self::extensions::list_trusted_keys),
        )
        .route(
            "/v1/extensions/keys",
            axum::routing::post(self::extensions::add_trusted_key),
        )
        .route(
            "/v1/extensions/keys/{passport_fpr}",
            axum::routing::delete(self::extensions::delete_trusted_key),
        )
        .route(
            "/v1/extensions/{id}",
            get(self::extensions::get_extension),
        )
        .route(
            "/v1/extensions/{id}",
            axum::routing::delete(self::extensions::delete_extension),
        )
        // M3: per-passport grants. The dispatcher (M4) consults these when
        // filtering the MCP catalog and validating per-call scope.
        .route(
            "/v1/extensions/{id}/grants",
            get(self::extensions::list_grants),
        )
        .route(
            "/v1/extensions/{id}/grants",
            axum::routing::post(self::extensions::issue_grant),
        )
        .route(
            "/v1/extensions/{id}/grants/{passport_fpr}",
            axum::routing::delete(self::extensions::revoke_grant),
        )
        // M4: direct external-tool invocation (Phase A entry point before
        // the MCP dispatcher integration lands in M5).
        .route(
            "/v1/extensions/{id}/tools/{tool_name}/invoke",
            axum::routing::post(self::extensions::invoke_extension_tool),
        )
        // Storybook readout — Phase 3 of the context graph.
        .route(
            "/v1/projects/{id}/storybook",
            axum::routing::post(self::storybook::post_generate),
        )
        .route(
            "/v1/projects/{id}/storybook",
            get(self::storybook::get_latest),
        )
        .route(
            "/v1/projects/{id}/storybook/versions",
            get(self::storybook::list_versions),
        )
        .route(
            "/v1/projects/{id}/storybook/diff",
            get(self::storybook::get_diff),
        )
        .route(
            "/v1/projects/{id}/storybook/{ts}",
            get(self::storybook::get_version),
        )
        // Phase 4 — agent dossier exchange.
        .route(
            "/v1/projects/{id}/dossiers/auto",
            axum::routing::post(self::dossier::post_auto),
        )
        .route(
            "/v1/projects/{id}/dossiers",
            axum::routing::post(self::dossier::post_publish),
        )
        .route(
            "/v1/projects/{id}/dossiers",
            get(self::dossier::list_dossiers),
        )
        .route(
            "/v1/projects/{id}/dossiers/diff",
            get(self::dossier::get_diff),
        )
        .route(
            "/v1/projects/{id}/dossiers/reconcile",
            get(self::dossier::get_reconciliation),
        )
        .route(
            "/v1/projects/{id}/dossiers/{dossierId}",
            get(self::dossier::get_dossier),
        )
        // Planes — sub-units inside a project. Each plane carries its own
        // members, tenants, and layers (Vision/Goals/etc.).
        .route(
            "/v1/projects/{id}/planes",
            get(self::planes::get_planes),
        )
        .route(
            "/v1/projects/{id}/planes",
            axum::routing::post(self::planes::post_plane),
        )
        .route(
            "/v1/projects/{id}/planes/{planeId}",
            get(self::planes::get_plane),
        )
        .route(
            "/v1/projects/{id}/planes/{planeId}",
            axum::routing::delete(self::planes::delete_plane),
        )
        .route(
            "/v1/projects/{id}/planes/{planeId}/passports",
            axum::routing::post(self::planes::post_plane_member),
        )
        .route(
            "/v1/projects/{id}/planes/{planeId}/passports/{passportId}",
            axum::routing::delete(self::planes::delete_plane_member),
        )
        .route(
            "/v1/projects/{id}/planes/{planeId}/tenants",
            axum::routing::post(self::planes::post_plane_tenant),
        )
        .route(
            "/v1/projects/{id}/planes/{planeId}/tenants/{tenantId}",
            axum::routing::delete(self::planes::delete_plane_tenant),
        )
        .route(
            "/v1/projects/{id}/planes/{planeId}/layers",
            get(self::planes::get_plane_layers),
        )
        .route(
            "/v1/projects/{id}/planes/{planeId}/layers/{layer}",
            axum::routing::put(self::planes::put_plane_layer),
        )
        .route(
            "/v1/projects/{id}/planes/{planeId}/layers/{layer}",
            axum::routing::delete(self::planes::delete_plane_layer),
        )
        // Phase 2B — bulk sync per-plane layers from a mounted source path.
        .route(
            "/v1/projects/{id}/planes/sync-layers",
            axum::routing::post(self::planes::post_sync_layers),
        )
        // Multi-passport CRUD.
        .route(
            "/v1/passport/mint-requests/pending",
            get(self::passports::get_pending_mint_requests),
        )
        .route(
            "/v1/passport/mint-requests/{request_id}/approve",
            axum::routing::post(self::passports::post_mint_request_approve),
        )
        .route(
            "/v1/passport/mint-requests/{request_id}/reject",
            axum::routing::post(self::passports::post_mint_request_reject),
        )
        .route("/v1/passports/presence", get(self::passports::get_presence))
        .route("/v1/passports", get(self::passports::get_passports))
        .route(
            "/v1/passports",
            axum::routing::post(self::passports::post_passport),
        )
        .route("/v1/passports/{passportId}", get(self::passports::get_passport))
        .route(
            "/v1/passports/{passportId}",
            axum::routing::patch(self::passports::patch_passport),
        )
        .route(
            "/v1/passports/{passportId}",
            axum::routing::delete(self::passports::delete_passport),
        )
        // Principal resolution for external mediators (the MCP gateway):
        // session/passport → tier + capabilities + tenant, tenant-scoped.
        .route(
            "/v1/principal/resolve",
            get(self::principal::get_resolve_principal),
        )
        // Mediation receipts: an external mediator (the gateway) ingests a
        // CROWN receipt for a proxied tool call, attributed to a resolvable
        // passport (capability-bound; never a raw write).
        .route(
            "/v1/mediation/receipts",
            axum::routing::post(self::observations::post_mediation_receipt),
        )
        // Canonical tool tier/capability policy — the single source the gateway
        // and daemon authorize against (no ladder drift).
        .route(
            "/v1/policy/capabilities",
            get(self::policy::get_policy_capabilities),
        )
        // RCX Registry publish preview/emit for local passports.
        .route(
            "/v1/rcx/publish/passports/{passportId}/preview",
            axum::routing::post(self::rcx_publish::preview_passport),
        )
        .route(
            "/v1/rcx/publish/passports/{passportId}/emit",
            axum::routing::post(self::rcx_publish::emit_passport),
        )
        // GitHub integration — encrypted PAT + connect/disconnect/status (Plan B G1).
        .route(
            "/v1/integrations/github/status",
            get(self::integrations_github::get_status),
        )
        .route(
            "/v1/integrations/github/connect",
            axum::routing::post(self::integrations_github::post_connect),
        )
        .route(
            "/v1/integrations/github/disconnect",
            axum::routing::post(self::integrations_github::post_disconnect),
        )
        .route(
            "/v1/integrations/github/sync",
            axum::routing::post(self::integrations_github::post_sync),
        )
        .route(
            "/v1/integrations/github/repos",
            get(self::integrations_github::get_selected_repos),
        )
        .route(
            "/v1/integrations/github/repos/accessible",
            get(self::integrations_github::get_accessible_repos),
        )
        .route(
            "/v1/integrations/github/repos/{owner}/{repo}/select",
            axum::routing::post(self::integrations_github::post_select_repo),
        )
        .route(
            "/v1/integrations/github/repos/{owner}/{repo}/select",
            axum::routing::delete(self::integrations_github::delete_selected_repo),
        )
        .route(
            "/v1/integrations/github/repos/{owner}/{repo}/planning",
            axum::routing::put(self::integrations_github::put_planning_flag),
        )
        // OpenAI integration — encrypted API key + connect/disconnect/status.
        .route(
            "/v1/integrations/openai/status",
            get(self::integrations_openai::get_status),
        )
        .route(
            "/v1/integrations/openai/connect",
            axum::routing::post(self::integrations_openai::post_connect),
        )
        .route(
            "/v1/integrations/openai/disconnect",
            axum::routing::post(self::integrations_openai::post_disconnect),
        )
        .route(
            "/v1/integrations/openai/settings",
            axum::routing::patch(self::integrations_openai::patch_settings),
        )
        .route(
            "/v1/integrations/openai/chat",
            axum::routing::post(self::integrations_openai::post_chat),
        )
        // In-process relation graph (open-distribution surface for `corecrux-projections`).
        .route(
            "/v1/relations",
            axum::routing::post(self::relations::post_relation),
        )
        .route("/v1/relations", get(self::relations::get_relations))
        .route(
            "/v1/relations/incoming",
            get(self::relations::get_incoming_relations),
        )
        .route(
            "/v1/relations/expand",
            axum::routing::post(self::relations::post_expand),
        )
        // Console settings (auth posture + embedding config).
        .route("/v1/console/settings", get(self::console::get_console_settings))
        .route(
            "/v1/console/settings",
            axum::routing::put(self::console::put_console_settings),
        )
        .route(
            "/v1/console/embedding/probe",
            axum::routing::post(self::console::post_console_embedding_probe),
        )
        .route(
            "/v1/console/corecrux/lane-weights",
            get(self::console::get_console_corecrux_lane_weights)
                .put(self::console::put_console_corecrux_lane_weights)
                .delete(self::console::delete_console_corecrux_lane_weights),
        )
        .route(
            "/v1/console/review/contradictions",
            get(self::console::get_console_review_contradictions),
        )
        // Read-only review-queue view over surfaced `__consolidation_review__::`
        // receipts (P1 widen); backs the embedded `/console/review` page.
        .route(
            "/v1/console/review/queue",
            get(self::console::get_console_review_queue),
        )
        // Operator applies age-based expiry proposals (wires mark_retention_eligible).
        .route(
            "/v1/console/review/expiries",
            axum::routing::post(self::console::post_console_review_expiries),
        )
        .route(
            "/v1/console/review/consolidations",
            axum::routing::post(self::console::post_console_review_consolidation),
        )
        .route(
            "/v1/console/review/consolidations/undo",
            axum::routing::post(self::console::post_console_review_consolidation_undo),
        )
        // First-run onboarding state for the embedded console.
        .route("/v1/console/onboarding", get(self::console::get_console_onboarding))
        .route(
            "/v1/console/onboarding/complete",
            axum::routing::post(self::console::post_console_onboarding_complete),
        )
        .route(
            "/v1/console/onboarding/restart",
            axum::routing::post(self::console::post_console_onboarding_restart),
        )
        // Read-only console aggregation APIs.
        .route("/v1/console/summary", get(self::console::get_console_summary))
        .route("/v1/console/infra/summary", get(self::infra::get_infra_summary))
        .route(
            "/v1/console/storage-breakdown",
            get(self::console::get_console_storage_breakdown),
        )
        .route(
            "/v1/console/integrations",
            get(self::console::get_console_integrations),
        )
        .route(
            "/v1/console/integrations/{packId}/install",
            axum::routing::post(self::console::post_console_integration_install),
        )
        .route(
            "/v1/console/integrations/{packId}/grant",
            axum::routing::post(self::console::post_console_integration_grant),
        )
        .route(
            "/v1/console/integrations/{packId}/disable",
            axum::routing::post(self::console::post_console_integration_disable),
        )
        .route("/v1/console/passports", get(self::console::get_console_passports))
        .route("/v1/console/sessions", get(self::console::get_console_sessions))
        .route(
            "/v1/console/sessions/detail",
            get(self::console::get_console_session_detail),
        )
        .route("/v1/console/facts", get(self::console::get_console_facts))
        .route(
            "/v1/console/facts/add",
            axum::routing::post(self::console::post_console_fact_add),
        )
        .route("/v1/console/tenants", get(self::console::get_console_tenants))
        .route(
            "/v1/console/tenants/{tenantId}/category",
            get(self::console::get_console_tenant_category)
                .patch(self::console::patch_console_tenant_category),
        )
        .route(
            "/v1/console/tenants/{tenantId}/chunks",
            get(self::console::get_console_tenant_chunks),
        )
        .route("/v1/console/chunks/{chunkDigest}", get(self::console::get_console_chunk))
        .route(
            "/v1/console/chunks/{chunkDigest}/preview",
            get(self::console::get_console_chunk_preview),
        )
        // Engine mediation group (read-only, customer-safe): GET only, so any
        // other method 405s at the routing layer — no mutating Engine route is
        // mounted. Env-gated (CORECRUXD_ENGINE_BASE_URL); see `engine_console`.
        .route(
            "/v1/console/engine/summary",
            get(self::engine_console::get_engine_summary),
        )
        .route("/v1/console/engine/bench", get(self::engine_console::get_engine_bench))
        .route("/v1/console/engine/spend", get(self::engine_console::get_engine_spend))
        // The ONE mediated read POST (M11): proxies CruxEngine POST /v1/retrieve.
        // Mounted post-only, so GET /v1/console/engine/search 405s. Env-gated.
        .route(
            "/v1/console/engine/search",
            axum::routing::post(self::engine_console::post_engine_search),
        )
        // Agent-graph backends (Package S scaffold). Each surface is gated
        // default-OFF and merged here so Wave-2 plans never touch this file.
        .merge(self::observe_audit::routes())
        .merge(self::orchestrators::routes())
        .merge(self::punchcards::routes())
        // Procedural memory (M3): case bank record/retrieve. The store is
        // supplied via an Extension layer (handlers also extract State<AppState>
        // for scope auth), so this adds no field to AppState's ~25 call sites.
        .route("/v1/cases", axum::routing::post(self::cases::record_case))
        .route("/v1/cases/retrieve", axum::routing::post(self::cases::retrieve_cases));

    // W1 Provenance Marking Gateway (BYOK). Mounted only when the flag is
    // captured ON at startup, so flag-off returns 404 for every provenance
    // path *before* any request body (incl. key material) is read — a
    // malformed or oversized flag-off request never reaches an extractor.
    // Kept as a separate runtime-conditional block (like the hosted-surfaces
    // block below) so the `.route(...)` templates still appear verbatim in
    // source for the route-auth matrix + route-spec drift tests.
    let router = if self::provenance::provenance_api_enabled() {
        router
            .route(
                "/v1/provenance/sign",
                axum::routing::post(self::provenance::post_provenance_sign).layer(
                    axum::extract::DefaultBodyLimit::max(self::provenance::PROVENANCE_MAX_UPLOAD_BYTES),
                ),
            )
            .route(
                "/v1/provenance/verify",
                axum::routing::post(self::provenance::post_provenance_verify).layer(
                    axum::extract::DefaultBodyLimit::max(self::provenance::PROVENANCE_MAX_UPLOAD_BYTES),
                ),
            )
            .route(
                "/v1/provenance/verify-record",
                axum::routing::post(self::provenance::post_provenance_verify_record).layer(
                    axum::extract::DefaultBodyLimit::max(self::provenance::PROVENANCE_MAX_UPLOAD_BYTES),
                ),
            )
    } else {
        router
    };

    // Hosted-service HTTP surfaces (ExecPlan crux-external-findings-remediation
    // M4): the Pro GPU-1 compute bridge and Pro cloud access posture are mounted
    // only when built with the `hosted-surfaces` feature, so the default
    // Community Edition binary carries neither the routes nor their handlers.
    // Kept as a separate cfg'd block (rather than inline in the chain above) so
    // the `.route(...)` templates still appear verbatim in this file's source —
    // the route-auth completeness matrix and the route-spec drift test parse
    // source text, not the compiled router, and stay green in both configs.
    #[cfg(feature = "hosted-surfaces")]
    let router = router
        .route("/v1/cloud/access-contract", get(self::cloud::get_cloud_access_contract))
        .route("/v1/gpu1/contract", get(self::gpu1::get_gpu1_contract))
        .route("/v1/gpu1/answer", axum::routing::post(self::gpu1::post_gpu1_answer))
        .route("/v1/gpu1/rerank", axum::routing::post(self::gpu1::post_gpu1_rerank))
        .route("/v1/gpu1/enrich", axum::routing::post(self::gpu1::post_gpu1_enrich))
        .route("/v1/gpu1/coverage", axum::routing::post(self::gpu1::post_gpu1_coverage))
        .route(
            "/v1/gpu1/developer",
            axum::routing::post(self::gpu1::post_gpu1_developer),
        );

    router
        .layer(axum::Extension(case_store))
        .layer(middleware::from_fn_with_state(state.clone(), presence_middleware))
        // G20 per-surface request quota (pass-through unless CORECRUXD_QUOTA=1
        // AND the path matches a configured hosted-surface prefix).
        .layer(middleware::from_fn_with_state(state.clone(), self::quota::quota_middleware))
        // M3 deny-by-default route authorization. Sits OUTSIDE quota/presence so
        // a would-deny short-circuits before any accounting or presence writes;
        // sits over the same route set (main `/v1/*` plane + merged agent-graph
        // surfaces), so it reads the `MatchedPath` template axum populates during
        // routing. Static console assets (merged after `with_state`) are not in
        // the contract and are intentionally out of scope. Handler-level scope
        // checks remain in place as defence in depth.
        .layer(middleware::from_fn_with_state(
            (state.clone(), route_auth_mode),
            self::route_auth::route_auth_middleware,
        ))
        .with_state(state)
        // Built-in web console (stateless, merged after with_state)
        .merge(crate::console::routes(console_enabled))
        .layer(CatchPanicLayer::custom(self::health::handle_panic))
        .layer(TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, Duration::from_secs(30)))
        .layer(middleware::from_fn(traceparent_middleware))
        .layer(middleware::from_fn(request_id_middleware))
}

/// Updates the presence tracker on every request that carries
/// `X-Corecrux-Passport-Id`. Cheap path: when the header is absent we don't
/// touch the lock at all.
async fn presence_middleware(
    State(app_state): State<AppState>,
    req: Request<axum::body::Body>,
    next: Next,
) -> impl IntoResponse {
    let passport_id = req
        .headers()
        .get("x-corecrux-passport-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    if let Some(pid) = passport_id {
        let method = req.method().as_str().to_string();
        let route = req.uri().path().to_string();
        // Touch in the background so the request path doesn't pay for the
        // RwLock acquire; the next snapshot will see this entry.
        let tracker = app_state.presence.clone();
        tokio::spawn(async move {
            tracker.touch(&pid, &method, &route).await;
        });
    }
    next.run(req).await
}

async fn traceparent_middleware(req: Request<axum::body::Body>, next: Next) -> impl IntoResponse {
    #[cfg(feature = "otel")]
    {
        use opentelemetry::global;
        use tracing_opentelemetry::OpenTelemetrySpanExt as _;

        struct HeaderExtractor<'a>(&'a HeaderMap);

        impl opentelemetry::propagation::Extractor for HeaderExtractor<'_> {
            fn get(&self, key: &str) -> Option<&str> {
                self.0.get(key).and_then(|v| v.to_str().ok())
            }

            fn keys(&self) -> Vec<&str> {
                self.0.keys().map(|k| k.as_str()).collect()
            }
        }

        let parent_cx =
            global::get_text_map_propagator(|propagator| propagator.extract(&HeaderExtractor(req.headers())));
        let _ = tracing::Span::current().set_parent(parent_cx);
    }
    next.run(req).await
}

async fn request_id_middleware(req: Request<axum::body::Body>, next: Next) -> impl IntoResponse {
    let started = std::time::Instant::now();
    let corr = CorrelationIds::from_headers(req.headers());
    let request_id = corr.request_id_or_new();
    let traceparent = corr.traceparent.clone();

    let mut response = next.run(req).await;
    let status = response.status();
    if let Ok(hv) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert("x-request-id", hv);
    }
    if let Some(tp) = traceparent.as_deref() {
        if let Ok(hv) = HeaderValue::from_str(tp) {
            response.headers_mut().insert("traceparent", hv);
        }
    }
    #[cfg(feature = "otel")]
    {
        use opentelemetry::trace::TraceContextExt as _;
        use tracing_opentelemetry::OpenTelemetrySpanExt as _;
        let cx = tracing::Span::current().context();
        let trace_id = cx.span().span_context().trace_id();
        if trace_id != opentelemetry::trace::TraceId::INVALID {
            if let Ok(hv) = HeaderValue::from_str(&trace_id.to_string()) {
                response.headers_mut().insert("x-trace-id", hv);
            }
        }
    }
    let outcome = if status.is_success() || status.is_redirection() {
        "ok"
    } else {
        "fail"
    };
    let mut op_log = StructuredOpLog::new(
        if outcome == "ok" { "info" } else { "warn" },
        "http_control",
        outcome,
        started.elapsed().as_millis() as u64,
    );
    op_log.request_id = Some(request_id.clone());
    op_log.traceparent = traceparent;
    if outcome != "ok" {
        op_log.error_code = Some(ErrorCode::Internal.as_str().to_string());
    }
    tracing::info!(
        ts = %op_log.ts,
        level = %op_log.level,
        request_id = %request_id,
        traceparent = ?op_log.traceparent,
        op = %op_log.op,
        outcome = %op_log.outcome,
        took_ms = op_log.took_ms,
        status = status.as_u16(),
        "http request complete"
    );
    response
}

fn map_store_error_http(err: AppendError) -> ProblemResponse {
    let pd = match err {
        AppendError::InvalidArgument(msg) => ProblemDetails::bad_request(msg),
        AppendError::FailedPrecondition(msg) => ProblemDetails::precondition_failed(msg),
        AppendError::ResourceExhausted(msg) => ProblemDetails::rate_limited(msg),
        AppendError::IoBackend(msg) => ProblemDetails::service_unavailable(msg),
        AppendError::Internal(msg) => ProblemDetails::internal(msg),
        AppendError::ShardUnavailable {
            shard_id,
            owner_gpu_id,
            current_shard_map_version,
        } => ProblemDetails::service_unavailable("shard unavailable").with_extensions(serde_json::json!({
            "code": "SHARD_UNAVAILABLE",
            "shardId": shard_id,
            "ownerGpuId": owner_gpu_id,
            "currentShardMapVersion": current_shard_map_version
        })),
        AppendError::WrongShard {
            leader_grpc_addr,
            current_shard_map_version,
        } => ProblemDetails::precondition_failed("wrong shard").with_extensions(serde_json::json!({
            "code": "WRONG_SHARD",
            "leaderGrpcAddr": leader_grpc_addr,
            "currentShardMapVersion": current_shard_map_version
        })),
        AppendError::ShardMapVersionMismatch {
            client_version,
            current_version,
        } => ProblemDetails::precondition_failed("shard map version mismatch").with_extensions(serde_json::json!({
            "code": "SHARDMAP_VERSION_MISMATCH",
            "clientShardMapVersion": client_version,
            "currentShardMapVersion": current_version
        })),
    };
    ProblemResponse(pd)
}

fn map_http_dataplane_error(err: HttpDataplaneError) -> Response {
    match err {
        HttpDataplaneError::Disabled => problem_response(StatusCode::NOT_IMPLEMENTED, "dataplane disabled"),
        HttpDataplaneError::Store(err) => map_store_error_http(err).into_response(),
    }
}

fn problem_for_status(status: StatusCode, detail: impl Into<String>) -> ProblemResponse {
    let detail = detail.into();
    let pd = match status {
        StatusCode::BAD_REQUEST => ProblemDetails::bad_request(detail),
        StatusCode::NOT_FOUND => ProblemDetails::not_found(detail),
        StatusCode::PRECONDITION_FAILED => ProblemDetails::precondition_failed(detail),
        StatusCode::NOT_IMPLEMENTED => ProblemDetails::not_implemented(detail),
        StatusCode::SERVICE_UNAVAILABLE => ProblemDetails::service_unavailable(detail),
        StatusCode::PAYLOAD_TOO_LARGE => ProblemDetails::new(
            StatusCode::PAYLOAD_TOO_LARGE.as_u16(),
            "https://errors.cuecrux.com/payload-too-large",
            "Payload Too Large",
        )
        .with_detail(detail),
        StatusCode::CONFLICT => ProblemDetails::new(
            StatusCode::CONFLICT.as_u16(),
            "https://errors.cuecrux.com/conflict",
            "Conflict",
        )
        .with_detail(detail),
        StatusCode::UNPROCESSABLE_ENTITY => ProblemDetails::new(
            StatusCode::UNPROCESSABLE_ENTITY.as_u16(),
            "https://errors.cuecrux.com/unprocessable-entity",
            "Unprocessable Entity",
        )
        .with_detail(detail),
        StatusCode::BAD_GATEWAY => ProblemDetails::new(
            StatusCode::BAD_GATEWAY.as_u16(),
            "https://errors.cuecrux.com/bad-gateway",
            "Bad Gateway",
        )
        .with_detail(detail),
        StatusCode::FORBIDDEN => ProblemDetails::new(
            StatusCode::FORBIDDEN.as_u16(),
            "https://errors.cuecrux.com/forbidden",
            "Forbidden",
        )
        .with_detail(detail),
        StatusCode::UNAUTHORIZED => ProblemDetails::new(
            StatusCode::UNAUTHORIZED.as_u16(),
            "https://errors.cuecrux.com/unauthorized",
            "Unauthorized",
        )
        .with_detail(detail),
        StatusCode::PAYMENT_REQUIRED => ProblemDetails::new(
            StatusCode::PAYMENT_REQUIRED.as_u16(),
            "https://errors.cuecrux.com/payment-required",
            "Payment Required",
        )
        .with_detail(detail),
        StatusCode::TOO_MANY_REQUESTS => ProblemDetails::new(
            StatusCode::TOO_MANY_REQUESTS.as_u16(),
            "https://errors.cuecrux.com/rate-limited",
            "Too Many Requests",
        )
        .with_detail(detail),
        StatusCode::NO_CONTENT => ProblemDetails::new(
            StatusCode::NO_CONTENT.as_u16(),
            "https://errors.cuecrux.com/no-content",
            "No Content",
        )
        .with_detail(detail),
        _ => ProblemDetails::internal(detail),
    };
    ProblemResponse(pd)
}

fn problem_response(status: StatusCode, detail: impl Into<String>) -> Response {
    problem_for_status(status, detail).into_response()
}

/// Fail closed when a configured daemon-to-daemon embedder cannot provide the
/// vector required by the current operation. The reason code mirrors the live
/// `/v1/version` descriptor without exposing the delegate URL, token, or raw
/// transport error.
fn embedding_delegation_degraded_response(status: &corecrux_memory::embeddings::DelegationStatus) -> Response {
    ProblemResponse(
        ProblemDetails::service_unavailable(
            "Remote embedding delegation is degraded; no local or empty-vector fallback was used.",
        )
        .with_extensions(serde_json::json!({
            "code": "EMBEDDING_DELEGATION_DEGRADED",
            "capability": "embedding_delegation",
            "availability": "degraded",
            "reason_code": status.reason_code,
            "circuit_state": status.circuit_state,
        })),
    )
    .into_response()
}

fn embedding_semantic_profile_mismatch_response(detail: &'static str) -> Response {
    ProblemResponse(
        ProblemDetails::service_unavailable(detail).with_extensions(serde_json::json!({
            "code": "EMBEDDING_SEMANTIC_PROFILE_MISMATCH",
            "capability": "embedding_delegation",
            "availability": "degraded",
            "reason_code": "embedding_semantic_profile_mismatch",
        })),
    )
    .into_response()
}

/// Upgrade-aware `501 Not Implemented` for capabilities that exist on the
/// CueCrux platform but not in the free local daemon build.
///
/// Same status as the bare 501 it replaces — only the problem-details payload
/// changes: structured extensions tell the caller the capability is real,
/// where it lives, and what it requires. Honest signpost, no dark patterns.
fn platform_upgrade_response(capability: &str) -> Response {
    let pd = ProblemDetails::not_implemented(format!(
        "`{capability}` is not available in the local daemon build. It is available via the CueCrux platform (metered)."
    ))
    .with_extensions(serde_json::json!({
        "platform_available": true,
        "capability": capability,
        "docs": format!("https://crux.cuecrux.com/docs/platform/{capability}"),
        "requires": "rcx_capability_token",
    }));
    ProblemResponse(pd).into_response()
}

#[derive(Debug, serde::Deserialize)]
struct TenantQuery {
    tenant_id: String,
}

#[derive(Debug, serde::Deserialize)]
struct RelationsQuery {
    tenant_id: String,
    direction: Option<String>, // "in" | "out"
    relation_type: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
}

#[derive(Debug, serde::Deserialize)]
struct DependentsQuery {
    tenant_id: String,
    dependent_type: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
}

#[derive(Debug, serde::Deserialize)]
struct PressureQuery {
    tenant_id: String,
    open_only: Option<bool>,
    limit: Option<usize>,
    offset: Option<usize>,
}

#[derive(Debug, serde::Deserialize)]
struct ProjMetaQuery {
    shard_id: String,
}

fn is_query_feature_enabled(env_var: &str) -> bool {
    if env_var == "CORECRUXD_QUERY_TEXT_SEARCH" {
        return crate::config::env_default_on(env_var);
    }
    match std::env::var(env_var) {
        Ok(value) => value == "1" || value.eq_ignore_ascii_case("true"),
        Err(_) => false,
    }
}

fn hex16(bytes: &[u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0u8; 32];
    for (i, b) in bytes.iter().enumerate() {
        out[i * 2] = HEX[(b >> 4) as usize];
        out[i * 2 + 1] = HEX[(b & 0x0f) as usize];
    }
    String::from_utf8_lossy(&out).to_string()
}

fn to_valve_info(v: &control::ValveV1) -> ValveInfo {
    ValveInfo {
        enabled: v.enabled,
        actor: v.actor.clone(),
        reason: v.reason.clone(),
        updated_at_unix_ns: v.updated_at_unix_ns,
        retry_after_ms: v.retry_after_ms,
    }
}

fn wants_cbor(headers: &HeaderMap) -> bool {
    let Some(v) = headers.get(header::ACCEPT).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    v.split(',')
        .map(|s| s.trim())
        .any(|s| s.starts_with("application/cbor"))
}

pub(crate) fn hex32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0u8; 64];
    for (i, b) in bytes.iter().enumerate() {
        out[i * 2] = HEX[(b >> 4) as usize];
        out[i * 2 + 1] = HEX[(b & 0x0f) as usize];
    }
    String::from_utf8_lossy(&out).to_string()
}

#[cfg(test)]
#[path = "tests.rs"]
pub(crate) mod tests;
