// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Crux Daemon session-handshake endpoint.
//!
//! `POST /session` — accepts a `SessionHandshakeRequest` in JSON or CBOR,
//! mints a [`crux_session::SessionPlan`], writes it to the registry, and
//! returns the plan in the negotiated content type.
//!
//! This is the local-daemon analogue of VaultCrux's hosted `POST /v1/session`. Both
//! share the same schema and encoder (via the [`crux_session`] crate);
//! the Crux Daemon implementation differs only in:
//! - passport source (synthesised from the install UUID rather than JWT)
//! - signer (NullSigner by default → BLAKE3-only plan)
//! - registry (in-memory rather than Postgres)
//!
//! The endpoint is localhost-only by default. No auth is required in the local-daemon
//! threat model (master-plan §5.3).

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::to_bytes;
use axum::extract::{ConnectInfo, Path, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use corecrux_projections::{SessionPlanSealedV1, CONTENT_TYPE_SESSION_BIN_V1, EVT_SESSION_PLAN_SEALED_V1};
use crux_session::{
    generator::GraphHints, handshake, Budget, Channels, FileSealer, FileSessionRegistry, HandshakeInputs,
    HandshakeRequest, InMemoryRegistry, InMemorySealer, LocalPassportConfig, NullSigner, PlanSealer, PlanSigner,
    RegistryEntry, RegistryError, SealedEvent, SessionError, SessionRegistry, DEFAULT_CATALOG,
};
use uuid::Uuid;

use super::AppState;
use crate::problem::ProblemResponse;
use corecrux_types::ProblemDetails;

pub(super) fn problem(status: StatusCode, title: &str, detail: impl Into<String>) -> Response {
    ProblemResponse(
        ProblemDetails::new(status.as_u16(), "https://errors.cuecrux.com/session", title).with_detail(detail),
    )
    .into_response()
}

const DEFAULT_SESSION_TTL_SECS: u64 = 3_600;
const DEFAULT_SESSION_MAX_REQUEST_BYTES: usize = 64 * 1024;
const DEFAULT_SESSION_MAX_PER_PRINCIPAL: usize = 32;
const DEFAULT_SESSION_MAX_PER_IP: usize = 64;
const DEFAULT_SESSION_MAX_TOTAL: usize = 1_024;
const DEFAULT_SESSION_REGISTRY_MAX_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_SESSION_EVENT_LOG_MAX_BYTES: u64 = 512 * 1024 * 1024;

/// Default-on resource and trust policy for `POST /session`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionPolicy {
    pub ttl_secs: u64,
    pub max_request_bytes: usize,
    pub max_per_principal: usize,
    pub max_per_ip: usize,
    pub max_total: usize,
    pub registry_max_bytes: u64,
    pub event_log_max_bytes: u64,
    pub trusted_proxy_cidrs: Vec<String>,
}

impl Default for SessionPolicy {
    fn default() -> Self {
        Self {
            ttl_secs: DEFAULT_SESSION_TTL_SECS,
            max_request_bytes: DEFAULT_SESSION_MAX_REQUEST_BYTES,
            max_per_principal: DEFAULT_SESSION_MAX_PER_PRINCIPAL,
            max_per_ip: DEFAULT_SESSION_MAX_PER_IP,
            max_total: DEFAULT_SESSION_MAX_TOTAL,
            registry_max_bytes: DEFAULT_SESSION_REGISTRY_MAX_BYTES,
            event_log_max_bytes: DEFAULT_SESSION_EVENT_LOG_MAX_BYTES,
            trusted_proxy_cidrs: Vec::new(),
        }
    }
}

impl SessionPolicy {
    pub fn from_env(trusted_proxy_cidrs: Vec<String>) -> Self {
        Self {
            ttl_secs: positive_env_u64("CORECRUXD_SESSION_TTL_SECS", DEFAULT_SESSION_TTL_SECS).clamp(60, 86_400),
            max_request_bytes: positive_env_usize(
                "CORECRUXD_SESSION_MAX_REQUEST_BYTES",
                DEFAULT_SESSION_MAX_REQUEST_BYTES,
            )
            .clamp(1_024, 1024 * 1024),
            max_per_principal: positive_env_usize(
                "CORECRUXD_SESSION_MAX_PER_PRINCIPAL",
                DEFAULT_SESSION_MAX_PER_PRINCIPAL,
            )
            .clamp(1, 1_000_000),
            max_per_ip: positive_env_usize("CORECRUXD_SESSION_MAX_PER_IP", DEFAULT_SESSION_MAX_PER_IP)
                .clamp(1, 1_000_000),
            max_total: positive_env_usize("CORECRUXD_SESSION_MAX_TOTAL", DEFAULT_SESSION_MAX_TOTAL).clamp(1, 1_000_000),
            registry_max_bytes: positive_env_u64(
                "CORECRUXD_SESSION_REGISTRY_MAX_BYTES",
                DEFAULT_SESSION_REGISTRY_MAX_BYTES,
            )
            .clamp(1024 * 1024, 1024 * 1024 * 1024 * 1024),
            event_log_max_bytes: positive_env_u64(
                "CORECRUXD_SESSION_EVENT_LOG_MAX_BYTES",
                DEFAULT_SESSION_EVENT_LOG_MAX_BYTES,
            )
            .clamp(1024 * 1024, 1024 * 1024 * 1024 * 1024),
            trusted_proxy_cidrs,
        }
    }
}

fn positive_env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn positive_env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

/// Subset of AppState actually used by the session route. Wrapping these
/// into a separate struct keeps the rest of AppState untouched and lets
/// tests inject a fake without constructing a full daemon state.
///
/// The `sealer` enforces the master-plan "always-store" rule: the
/// SessionPlanSealed event lands in the durable log BEFORE the registry
/// sees the row. If the sealer fails, the handshake fails closed and no
/// registry write happens. See [`post_session`].
#[derive(Clone)]
pub struct SessionServices {
    pub signer: Arc<dyn PlanSigner>,
    pub sealer: Arc<dyn PlanSealer>,
    pub registry: Arc<dyn SessionRegistry>,
    pub passport_cfg: Arc<LocalPassportConfig>,
    pub feature_flags: Arc<HashSet<String>>,
    pub mcp_url: String,
    pub bulk_url: Option<String>,
    pub policy: Arc<SessionPolicy>,
    trusted_proxy_cidrs: Arc<Vec<(IpAddr, u8)>>,
    admission_key: Arc<[u8; 32]>,
    admission_lock: Arc<tokio::sync::Mutex<()>>,
    /// Prometheus metric handles (master-plan §11). `None` disables
    /// emission — legacy paths that wire services without a Prometheus
    /// registry still work.
    pub metrics: Option<Arc<super::session_metrics::SessionMetrics>>,
}

impl SessionServices {
    /// Ephemeral local-daemon wiring — `NullSigner` + `InMemorySealer` + `InMemoryRegistry`.
    /// Pre-M6 default; used only when the caller has no durable data
    /// directory (tests, smoke scripts). Sessions do not survive restart.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn local_default(node_id: impl Into<String>) -> Self {
        let install_uuid = node_id.into();
        let admission_key = blake3::derive_key("cuecrux.session.admission.test-fallback.v1", install_uuid.as_bytes());
        Self::local_default_with_policy(install_uuid, SessionPolicy::default(), admission_key)
    }

    pub fn local_default_with_policy(
        install_uuid: impl Into<String>,
        policy: SessionPolicy,
        admission_key: [u8; 32],
    ) -> Self {
        let install_uuid = install_uuid.into();
        let trusted_proxy_cidrs = super::ingress::parse_trusted_proxy_cidrs(&policy.trusted_proxy_cidrs);
        Self {
            signer: Arc::new(NullSigner),
            sealer: Arc::new(InMemorySealer::new_bounded(policy.event_log_max_bytes)),
            registry: Arc::new(InMemoryRegistry::new_with_limits(
                policy.registry_max_bytes,
                policy.max_total,
            )),
            passport_cfg: Arc::new(LocalPassportConfig {
                install_uuid,
                user: std::env::var("USER").unwrap_or_else(|_| "local".into()),
            }),
            feature_flags: Arc::new(HashSet::new()),
            mcp_url: "http://localhost:14800/mcp".into(),
            bulk_url: None,
            policy: Arc::new(policy),
            trusted_proxy_cidrs: Arc::new(trusted_proxy_cidrs),
            admission_key: Arc::new(admission_key),
            admission_lock: Arc::new(tokio::sync::Mutex::new(())),
            metrics: None,
        }
    }

    /// Durable local-daemon wiring — persistent install UUID + file-backed
    /// registry (`data_dir/sessions/*.json`) + file-backed sealer
    /// (`data_dir/session-events.jsonl`). Sessions survive restart;
    /// the segment log is operator-inspectable with `jq`.
    ///
    /// Called from `main.rs` whenever corecruxd has a configured `data_dir`.
    /// Persistent-state errors disable session creation rather than silently
    /// resetting admission state in an ephemeral registry.
    pub fn local_durable(
        data_dir: &std::path::Path,
        node_id: impl Into<String>,
        mcp_url: impl Into<String>,
        policy: SessionPolicy,
        admission_key: [u8; 32],
    ) -> Result<Self, String> {
        let trusted_proxy_cidrs = super::ingress::parse_trusted_proxy_cidrs(&policy.trusted_proxy_cidrs);
        let user = std::env::var("USER").unwrap_or_else(|_| "local".into());
        let passport_cfg =
            LocalPassportConfig::from_data_dir(data_dir, user).map_err(|e| format!("persistent passport: {e}"))?;
        let registry = FileSessionRegistry::open_bounded(data_dir, policy.registry_max_bytes, policy.max_total)
            .map_err(|e| format!("file registry: {e}"))?;
        let sealer =
            FileSealer::open_bounded(data_dir, policy.event_log_max_bytes).map_err(|e| format!("file sealer: {e}"))?;
        let _ = node_id; // retained for future node-scoped wiring
        Ok(Self {
            signer: Arc::new(NullSigner),
            sealer: Arc::new(sealer),
            registry: Arc::new(registry),
            passport_cfg: Arc::new(passport_cfg),
            feature_flags: Arc::new(HashSet::new()),
            mcp_url: mcp_url.into(),
            bulk_url: None,
            policy: Arc::new(policy),
            trusted_proxy_cidrs: Arc::new(trusted_proxy_cidrs),
            admission_key: Arc::new(admission_key),
            admission_lock: Arc::new(tokio::sync::Mutex::new(())),
            metrics: None,
        })
    }

    /// Attach a Prometheus metric sink. Idempotent; overwrites any
    /// previously-configured handle.
    pub fn with_metrics(mut self, metrics: Arc<super::session_metrics::SessionMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    pub async fn prune_expired(&self, now_unix_ms: u64) -> Result<usize, RegistryError> {
        let _guard = self.admission_lock.lock().await;
        let report = self.registry.prune_expired(now_unix_ms)?;
        if let Some(metrics) = self.metrics.as_ref() {
            if let Ok(active) = self.registry.active_count() {
                metrics.active_set(active as i64);
            }
        }
        Ok(report.removed)
    }
}

// Wire fields that are currently parsed-but-unused (reserved for later
// milestones: max_capabilities/want_parent_chain = Phase 7+; client_id /
// client_version feed future structured logs). Suppressing dead_code here
// keeps the wire contract aligned with the TS side without prematurely
// threading them through.
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize, Default)]
pub struct HandshakeHintsWire {
    pub prefer_bulk: Option<bool>,
    pub max_capabilities: Option<u32>,
    pub want_parent_chain: Option<bool>,
    /// §5.7 privacy: suppress the capability-graph `excluded` list entirely.
    /// Absent = false (the generator's tier/affinity guard still applies).
    pub hide_exclusions: Option<bool>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct SessionHandshakeRequestWire {
    pub client_id: String,
    pub client_version: String,
    #[serde(default)]
    pub accepts: Vec<String>,
    pub intent: Option<String>,
    #[serde(default)]
    pub hints: HandshakeHintsWire,
    /// Optional project the agent is acting in. Stored alongside the session
    /// binding; not validated until the project store ships.
    #[serde(default)]
    pub project_id: Option<String>,
    /// Optional tenant. Drives passport defaulting when `passport_id` is absent.
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// Optional explicit passport. If present, must exist in the passport store.
    #[serde(default)]
    pub passport_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: ErrorInner,
}

#[derive(Debug, Serialize)]
struct ErrorInner {
    code: &'static str,
    message: String,
}

fn bad_request(message: impl Into<String>) -> Response {
    let body = ErrorBody {
        error: ErrorInner {
            code: "bad_request",
            message: message.into(),
        },
    };
    (StatusCode::BAD_REQUEST, Json(body)).into_response()
}

#[allow(clippy::result_large_err)]
fn parse_session_id_hex(value: &str) -> Result<[u8; 16], Response> {
    let trimmed = value.trim();
    let bytes = match hex::decode(trimmed) {
        Ok(bytes) => bytes,
        Err(err) => {
            return Err(problem(
                StatusCode::BAD_REQUEST,
                "bad_request",
                format!("invalid session id hex: {err}"),
            ));
        }
    };
    match <[u8; 16]>::try_from(bytes.as_slice()) {
        Ok(session_id) => Ok(session_id),
        Err(_) => Err(problem(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "session id must be 16 bytes / 32 hex characters",
        )),
    }
}

/// `GET /v1/sessions/active` — list session bindings the daemon has minted
/// (most recent first). Returns the resolved `(project_id, tenant_id,
/// passport_id)` triple per session — does NOT include the cryptographically-
/// signed session plan, that's still a `POST /session` round trip.
pub async fn get_active_sessions(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(problem) = crate::auth::require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    let store = state.fact_store.read().await;
    let bindings = crate::session_bindings::list_bindings(&store);
    // Uncapped totals — `bindings`/`count` are truncated at top_k: 200, which
    // historically hid a binding-churn leak; surface the real figures.
    let counts = crate::session_bindings::count_bindings(&store);
    drop(store);
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "count": bindings.len(),
            "total_bindings": counts.total,
            "bindings_by_passport": counts.by_passport,
            "sessions": bindings,
        })),
    )
        .into_response()
}

/// `GET /v1/sessions/{session_id}/plan` — read through to the sealed
/// session-plan registry. This emits the shared SessionPlan v2 JSON shape
/// while continuing to decode older flat-graph plans from the sealed registry.
pub async fn get_session_plan(
    State(state): State<AppState>,
    Path(session_id_hex): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(problem) = crate::auth::require_http_any_scope(&state.auth, &headers, &["sessions:read", "admin:read"]) {
        return problem.into_response();
    }
    let services = match state.session.as_ref() {
        Some(services) => services.clone(),
        None => {
            return problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "feature_disabled",
                "session handshake feature is not enabled",
            );
        }
    };
    let session_id = match parse_session_id_hex(&session_id_hex) {
        Ok(session_id) => session_id,
        Err(response) => return response,
    };
    let entry = match services.registry.get(&session_id) {
        Ok(Some(entry)) => entry,
        Ok(None) => return problem(StatusCode::NOT_FOUND, "not_found", "session plan not found"),
        Err(err) => {
            return problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("registry read failed: {err}"),
            );
        }
    };
    let ctx = match crate::auth::passport_bound_context(&state.auth, &headers) {
        Ok(ctx) => ctx,
        Err(problem) => return problem.into_response(),
    };
    if !ctx.has_scope("admin:read") {
        let store = state.fact_store.read().await;
        let allowed = crate::session_bindings::list_bindings(&store)
            .into_iter()
            .any(|binding| {
                binding.session_id_hex.eq_ignore_ascii_case(&session_id_hex)
                    && ctx.passport_id.as_deref() == Some(binding.passport_id.as_str())
            });
        drop(store);
        if !allowed {
            return problem(
                StatusCode::FORBIDDEN,
                "forbidden",
                "session plan is not bound to the request passport",
            );
        }
    }
    let plan = match crux_session::SessionPlan::from_canonical_cbor(&entry.plan_cbor) {
        Ok(plan) => plan,
        Err(err) => {
            return problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("stored session plan decode failed: {err}"),
            );
        }
    };
    let plan_json = match serde_json::from_str::<serde_json::Value>(&plan.to_canonical_json()) {
        Ok(value) => value,
        Err(err) => {
            return problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("stored session plan JSON mirror failed: {err}"),
            );
        }
    };
    let plan_hash_hex = hex::encode(entry.plan_receipt_hash);
    let capability_graph_hash_hex = hex::encode(entry.capability_graph_hash);
    let body = serde_json::json!({
        "schema": "crux.session_plan.read.v2",
        "session_id": session_id_hex.to_ascii_lowercase(),
        "plan_hash": plan_hash_hex,
        "capability_graph_hash": capability_graph_hash_hex,
        "contract": "cuecrux.shared.session_plan.v2",
        "legacy_contract": format!("crux.session_plan.v{}", plan.plan_version),
        "target_contract": "cuecrux.shared.session_plan.v2",
        "status": "current",
        "minted_at": entry.minted_at,
        "expires_at": entry.expires_at,
        "closed": entry.closed,
        "close_reason": entry.close_reason,
        "origin": entry.origin,
        "principal_id": entry.principal_id,
        "plan": plan_json,
    });
    let mut response = (StatusCode::OK, Json(body)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Ok(value) = HeaderValue::from_str(&session_id_hex.to_ascii_lowercase()) {
        response.headers_mut().insert("x-crux-session-id", value.clone());
        response.headers_mut().insert("x-cuecrux-session-id", value);
    }
    if let Ok(value) = HeaderValue::from_str(&plan_hash_hex) {
        response.headers_mut().insert("x-crux-plan-hash", value.clone());
        response.headers_mut().insert("x-cuecrux-plan-hash", value);
    }
    response
}

/// `POST /session` — mint a session plan.
#[tracing::instrument(level = "info", skip(state, request))]
pub async fn post_session(State(state): State<AppState>, request: Request) -> Response {
    let start = std::time::Instant::now();
    let services = match state.session.as_ref() {
        Some(s) => s.clone(),
        None => {
            return problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "feature_disabled",
                "session handshake feature is not enabled",
            );
        }
    };
    let (parts, body_stream) = request.into_parts();
    let peer_ip = parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(address)| address.ip());
    let headers = parts.headers;
    let (passport, origin_install) = services.passport_cfg.synthesise();
    let admission = match admission_identity(&state, &services, &headers, peer_ip, &passport.principal_id) {
        Ok(admission) => admission,
        Err(response) => {
            if let Some(metrics) = services.metrics.as_ref() {
                metrics.handshake_failed("ce", "authentication_required");
            }
            return response;
        }
    };
    let body = match to_bytes(body_stream, services.policy.max_request_bytes).await {
        Ok(body) => body,
        Err(_) => {
            if let Some(metrics) = services.metrics.as_ref() {
                metrics.handshake_failed("ce", "body_too_large");
            }
            return problem(
                StatusCode::PAYLOAD_TOO_LARGE,
                "payload_too_large",
                format!(
                    "session handshake body exceeds {} bytes",
                    services.policy.max_request_bytes
                ),
            );
        }
    };

    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json");

    let request: SessionHandshakeRequestWire = if content_type.starts_with("application/cbor") {
        match crux_session::canonical::decode(&body)
            .ok()
            .and_then(|v| to_json_value(&v))
            .and_then(|v| serde_json::from_value(v).ok())
        {
            Some(r) => r,
            None => {
                if let Some(m) = services.metrics.as_ref() {
                    m.handshake_failed("ce", "bad_request");
                }
                return bad_request("failed to decode CBOR request body");
            }
        }
    } else {
        match serde_json::from_slice::<SessionHandshakeRequestWire>(&body) {
            Ok(r) => r,
            Err(e) => {
                if let Some(m) = services.metrics.as_ref() {
                    m.handshake_failed("ce", "bad_request");
                }
                return bad_request(format!("failed to decode JSON: {e}"));
            }
        }
    };

    let prefer_cbor = should_prefer_cbor(&headers, &request.accepts);

    // One admission lock makes prune, quota checks, mint, seal, and insert a
    // linearizable transaction with respect to competing session creations.
    let admission_guard = services.admission_lock.lock().await;
    let admitted_at_ms = now_ms();
    if let Err(error) = services.registry.prune_expired(admitted_at_ms) {
        return problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "session_registry_unavailable",
            format!("expired-session cleanup failed: {error}"),
        );
    }
    let usage = match services
        .registry
        .admission_usage(admitted_at_ms, &admission.principal_key, &admission.ip_key)
    {
        Ok(usage) => usage,
        Err(error) => {
            return problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "session_registry_unavailable",
                format!("session admission usage failed: {error}"),
            );
        }
    };
    if usage.retained_for_principal >= services.policy.max_per_principal {
        if let Some(metrics) = services.metrics.as_ref() {
            metrics.handshake_failed("ce", "principal_quota");
        }
        return quota_response(
            "principal",
            retry_after_secs(usage.next_principal_expiry_ms, admitted_at_ms),
        );
    }
    if usage.retained_for_ip >= services.policy.max_per_ip {
        if let Some(metrics) = services.metrics.as_ref() {
            metrics.handshake_failed("ce", "ip_quota");
        }
        return quota_response("ip", retry_after_secs(usage.next_ip_expiry_ms, admitted_at_ms));
    }
    if usage.retained_total >= services.policy.max_total {
        if let Some(metrics) = services.metrics.as_ref() {
            metrics.handshake_failed("ce", "global_capacity");
        }
        return capacity_response(
            "session registry entries",
            u64::try_from(services.policy.max_total).unwrap_or(u64::MAX),
            u64::try_from(usage.retained_total).unwrap_or(u64::MAX),
            1,
        );
    }

    let channels = Channels {
        bulk: services.bulk_url.clone(),
        mcp: services.mcp_url.clone(),
    };
    let budget = Budget {
        tokens_cap: None,
        crux_cap: None,
        ttl_s: services.policy.ttl_secs,
    };

    let handshake_request = HandshakeRequest {
        passport,
        channels,
        hints: GraphHints::from_request(request.hints.prefer_bulk)
            .with_hide_exclusions(request.hints.hide_exclusions.unwrap_or(false)),
        session_ttl_s: services.policy.ttl_secs,
        budget,
        origin: "ce".into(),
        origin_install: Some(origin_install),
        intent_hint: request.intent,
        now_ms: admitted_at_ms,
    };

    let sealed = match handshake::mint(
        handshake_request,
        HandshakeInputs {
            catalog: DEFAULT_CATALOG,
            enabled_feature_flags: services.feature_flags.as_ref(),
            signer: services.signer.as_ref(),
        },
    ) {
        Ok(s) => s,
        Err(e) => {
            return problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("mint failed: {e}"),
            );
        }
    };

    // ALWAYS-STORE: seal the SessionPlanSealed event to the durable log
    // BEFORE writing to the registry. Any failure here is fatal — the
    // registry must never hold a row that has no matching sealed event.
    let event = build_sealed_event_for_plan(&sealed);
    let entry = RegistryEntry::from_plan(&sealed.plan, sealed.canonical_cbor.clone())
        .with_admission_keys(admission.principal_key, admission.ip_key);
    let entry_bytes = match services.registry.entry_storage_bytes(&entry) {
        Ok(bytes) => bytes,
        Err(error) => {
            return problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "session_registry_unavailable",
                format!("session entry sizing failed: {error}"),
            );
        }
    };
    if usage.storage_bytes.checked_add(entry_bytes).unwrap_or(u64::MAX) > services.policy.registry_max_bytes {
        if let Some(metrics) = services.metrics.as_ref() {
            metrics.handshake_failed("ce", "registry_capacity");
        }
        return capacity_response(
            "session registry bytes",
            services.policy.registry_max_bytes,
            usage.storage_bytes,
            entry_bytes,
        );
    }
    let event_bytes = match services.sealer.event_storage_bytes(&event) {
        Ok(bytes) => bytes,
        Err(error) => {
            return problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "session_event_log_unavailable",
                format!("session event sizing failed: {error}"),
            );
        }
    };
    let event_log_bytes = match services.sealer.storage_bytes() {
        Ok(bytes) => bytes,
        Err(error) => {
            return problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "session_event_log_unavailable",
                format!("session event usage failed: {error}"),
            );
        }
    };
    if event_log_bytes.checked_add(event_bytes).unwrap_or(u64::MAX) > services.policy.event_log_max_bytes {
        if let Some(metrics) = services.metrics.as_ref() {
            metrics.handshake_failed("ce", "event_log_capacity");
        }
        return capacity_response(
            "session event log bytes",
            services.policy.event_log_max_bytes,
            event_log_bytes,
            event_bytes,
        );
    }
    if let Err(e) = services.sealer.seal(&event) {
        if let Some(m) = services.metrics.as_ref() {
            m.handshake_seal_failure("ce");
        }
        match e {
            SessionError::Capacity {
                resource,
                limit,
                current,
                attempted,
            } => return capacity_response(resource, limit, current, attempted),
            other => {
                return problem(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "segment_seal_failed",
                    format!("segment log append failed: {other}"),
                );
            }
        }
    }

    if let Err(e) = services.registry.insert(entry) {
        if let Some(m) = services.metrics.as_ref() {
            m.handshake_failed("ce", "registry_insert_failed");
        }
        match e {
            RegistryError::Capacity {
                resource,
                limit,
                current,
                attempted,
            } => return capacity_response(resource, limit, current, attempted),
            other => {
                return problem(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    format!("registry insert failed: {other}"),
                );
            }
        }
    }
    drop(admission_guard);

    if let Some(m) = services.metrics.as_ref() {
        let latency = start.elapsed().as_secs_f64();
        let encoding = if prefer_cbor { "cbor" } else { "json" };
        let plan_bytes = if prefer_cbor {
            sealed.canonical_cbor.len()
        } else {
            sealed.plan.to_canonical_json().len()
        };
        m.handshake_ok(
            "ce",
            latency,
            sealed.plan.capability_graph.len(),
            &sealed.plan.passport.tier,
            plan_bytes,
            encoding,
        );
        if let Ok(count) = services.registry.active_count() {
            m.active_set(count as i64);
        }
    }

    // Multi-passport binding (M2): resolve the (project_id, tenant_id, passport_id)
    // triple against the local passport store, persist as a fact keyed by the
    // session id, surface in response headers so MCP/HTTP clients can read it
    // without parsing the signed plan.
    let session_id_hex = hex::encode(sealed.plan.session_id);
    let binding_result = {
        let store = state.fact_store.read().await;
        crate::session_bindings::resolve(
            &store,
            crate::session_bindings::ResolveInput {
                session_id_hex: &session_id_hex,
                project_id: request.project_id.clone(),
                tenant_id: request.tenant_id.clone(),
                passport_id: request.passport_id.clone(),
                now_unix_ms: now_ms(),
            },
        )
    };
    let binding = match binding_result {
        Ok(b) => Some(b),
        Err(err) => {
            tracing::warn!(
                ?err,
                "session binding resolution failed; session minted without binding"
            );
            None
        }
    };
    if let Some(b) = binding.as_ref() {
        {
            let mut store = state.fact_store.write().await;
            if let Err(err) = crate::session_bindings::write_binding(&mut store, b) {
                tracing::warn!(?err, "failed to persist session binding fact");
            }
        }
        // Binding a session enrolls it on the coordination board; give its
        // passport an immediate presence heartbeat so the session is "live"
        // from the moment it boots, not from its first passport-stamped
        // HTTP write (MCP traffic doesn't pass the presence middleware).
        state.presence.touch(&b.passport_id, "POST", "/session(bind)").await;
    }

    build_plan_response(&sealed, prefer_cbor, binding.as_ref())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AdmissionIdentity {
    principal_key: String,
    ip_key: String,
}

#[allow(clippy::result_large_err)]
fn admission_identity(
    state: &AppState,
    services: &SessionServices,
    headers: &HeaderMap,
    peer_ip: Option<IpAddr>,
    local_principal_id: &str,
) -> Result<AdmissionIdentity, Response> {
    let client = super::ingress::effective_client_ip(headers, peer_ip, &services.trusted_proxy_cidrs);
    let local_loopback = super::ingress::is_direct_loopback_request(headers, peer_ip);

    let principal = if local_loopback {
        format!("local:{local_principal_id}")
    } else {
        let context = crate::auth::passport_bound_context(&state.auth, headers).map_err(IntoResponse::into_response)?;
        if !context.auth_enforced() || context.local_unverified_identity() {
            return Err(ProblemResponse(
                ProblemDetails::unauthorized(
                    "remote session creation requires a cryptographically verified credential",
                )
                .with_extensions(serde_json::json!({
                    "code": "SESSION_VERIFIED_CREDENTIAL_REQUIRED",
                })),
            )
            .into_response());
        }
        if !context.has_scope("sessions:write") && !context.has_scope("admin:write") {
            return Err(ProblemResponse(
                ProblemDetails::forbidden("remote session creation requires sessions:write or admin:write")
                    .with_extensions(serde_json::json!({
                        "code": "SESSION_WRITE_SCOPE_REQUIRED",
                    })),
            )
            .into_response());
        }
        context
            .verified_credential_identity()
            .map(str::trim)
            .filter(|identity| !identity.is_empty())
            .map(str::to_string)
            .ok_or_else(|| {
                ProblemResponse(
                    ProblemDetails::unauthorized("verified credential does not contain a stable principal identity")
                        .with_extensions(serde_json::json!({
                            "code": "SESSION_VERIFIED_IDENTITY_REQUIRED",
                        })),
                )
                .into_response()
            })?
    };
    let ip = client
        .key_ip
        .map_or_else(|| "missing-peer".to_string(), |ip| ip.to_string());

    Ok(AdmissionIdentity {
        principal_key: keyed_admission_key(&services.admission_key, b"principal", principal.as_bytes()),
        ip_key: keyed_admission_key(&services.admission_key, b"ip", ip.as_bytes()),
    })
}

fn keyed_admission_key(key: &[u8; 32], domain: &[u8], value: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(b"cuecrux.session.admission.v1\0");
    hasher.update(domain);
    hasher.update(b"\0");
    hasher.update(value);
    hex::encode(hasher.finalize().as_bytes())
}

fn retry_after_secs(next_expiry_ms: Option<u64>, now_ms: u64) -> u64 {
    next_expiry_ms
        .map_or(1, |expiry| expiry.saturating_sub(now_ms).saturating_add(999) / 1_000)
        .max(1)
}

fn quota_response(quota: &'static str, retry_after: u64) -> Response {
    let mut response = ProblemResponse(
        ProblemDetails::new(
            StatusCode::TOO_MANY_REQUESTS.as_u16(),
            "https://errors.cuecrux.com/session-quota-exceeded",
            "Session quota exceeded",
        )
        .with_detail(format!(
            "the retained per-{quota} session limit is exhausted; retry after {retry_after}s"
        ))
        .with_extensions(serde_json::json!({
            "code": "SESSION_QUOTA_EXCEEDED",
            "quota": quota,
        })),
    )
    .into_response();
    if let Ok(value) = HeaderValue::from_str(&retry_after.to_string()) {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    response
}

fn capacity_response(resource: &str, limit: u64, current: u64, attempted: u64) -> Response {
    ProblemResponse(
        ProblemDetails::new(
            StatusCode::INSUFFICIENT_STORAGE.as_u16(),
            "https://errors.cuecrux.com/session-capacity-exceeded",
            "Session capacity exceeded",
        )
        .with_detail(format!(
            "{resource} capacity is exhausted (limit={limit}, current={current}, attempted={attempted})"
        ))
        .with_extensions(serde_json::json!({
            "code": "SESSION_CAPACITY_EXCEEDED",
            "resource": resource,
            "limit": limit,
            "current": current,
            "attempted": attempted,
        })),
    )
    .into_response()
}

/// Translate a freshly-minted sealed plan into the
/// `corecrux_projections::events::SessionPlanSealedV1` event that lands
/// in the segment log. Payload is the binary encoding produced by that
/// event's `encode_bin()`.
fn build_sealed_event_for_plan(sealed: &handshake::SealedPlan) -> SealedEvent {
    let plan = &sealed.plan;
    let expires_at_ms = plan.minted_at.saturating_add(plan.session_ttl_s * 1000);

    let event = SessionPlanSealedV1 {
        event_id: *Uuid::new_v4().as_bytes(),
        plan_id: plan.plan_id,
        session_id: plan.session_id,
        principal_id: plan.passport.principal_id.clone(),
        origin: plan.origin.clone(),
        origin_install: plan.origin_install,
        minted_at_ms: i64::try_from(plan.minted_at).unwrap_or(i64::MAX),
        expires_at_ms: i64::try_from(expires_at_ms).unwrap_or(i64::MAX),
        plan_receipt_hash: plan.receipt.hash,
        plan_receipt_signature: plan.receipt.signature,
        capability_graph_hash: plan.capability_graph_hash,
        plan_bytes_cbor: sealed.canonical_cbor.clone(),
    };

    SealedEvent {
        event_type: EVT_SESSION_PLAN_SEALED_V1,
        content_type: CONTENT_TYPE_SESSION_BIN_V1,
        tenant_id: plan.origin.clone(),
        stream_type: "session-plans".to_string(),
        stream_id: plan.passport.principal_id.clone(),
        payload: event.encode_bin(),
    }
}

fn build_plan_response(
    sealed: &handshake::SealedPlan,
    prefer_cbor: bool,
    binding: Option<&crate::session_bindings::SessionBinding>,
) -> Response {
    let session_id_hex = hex::encode(sealed.plan.session_id);
    let plan_hash_hex = hex::encode(sealed.plan.receipt.hash);
    let mut response = if prefer_cbor {
        (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "application/cbor"),
                (header::CACHE_CONTROL, "no-store"),
            ],
            sealed.canonical_cbor.clone(),
        )
            .into_response()
    } else {
        (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "application/json"),
                (header::CACHE_CONTROL, "no-store"),
            ],
            sealed.plan.to_canonical_json(),
        )
            .into_response()
    };
    let headers = response.headers_mut();
    // hex::encode output is guaranteed ASCII, so HeaderValue::from_str can
    // only fail on future refactors that change the source to non-ASCII; we
    // fall back to dropping the header rather than panicking in that case.
    if let Ok(hv) = HeaderValue::from_str(&session_id_hex) {
        headers.insert("X-CueCrux-Session-Id", hv);
    }
    if let Ok(hv) = HeaderValue::from_str(&plan_hash_hex) {
        headers.insert("X-CueCrux-Plan-Hash", hv);
    }
    if let Some(b) = binding {
        if let Ok(hv) = HeaderValue::from_str(&b.passport_id) {
            headers.insert("X-CueCrux-Passport-Id", hv);
        }
        if let Ok(hv) = HeaderValue::from_str(&b.tenant_id) {
            headers.insert("X-CueCrux-Tenant-Id", hv);
        }
        if let Some(p) = &b.project_id {
            if let Ok(hv) = HeaderValue::from_str(p) {
                headers.insert("X-CueCrux-Project-Id", hv);
            }
        }
        if let Ok(hv) = HeaderValue::from_str(&b.passport_category) {
            headers.insert("X-CueCrux-Passport-Category", hv);
        }
        let gate = if b.agent_work_gate { "true" } else { "false" };
        if let Ok(hv) = HeaderValue::from_str(gate) {
            headers.insert("X-CueCrux-Agent-Work-Gate", hv);
        }
    }
    response
}

fn should_prefer_cbor(headers: &HeaderMap, accepts: &[String]) -> bool {
    if accepts.iter().any(|s| s == "application/cbor") {
        return true;
    }
    headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|s| s.contains("application/cbor"))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Convert a canonical-CBOR value (from a CBOR request body) into a
/// serde_json::Value so we can reuse serde(Deserialize) on the request
/// struct. We only expect small JSON-compatible structures here
/// (client_id, client_version, accepts[], intent, hints).
fn to_json_value(value: &crux_session::canonical::CborValue) -> Option<serde_json::Value> {
    use crux_session::canonical::CborValue;
    Some(match value {
        CborValue::Uint(n) => serde_json::Value::Number((*n).into()),
        CborValue::Bytes(b) => serde_json::Value::String(hex::encode(b)),
        CborValue::Text(s) => serde_json::Value::String(s.clone()),
        CborValue::Array(items) => {
            serde_json::Value::Array(items.iter().map(to_json_value).collect::<Option<Vec<_>>>()?)
        }
        CborValue::Map(pairs) => {
            let mut map = serde_json::Map::with_capacity(pairs.len());
            for (k, v) in pairs {
                map.insert(k.clone(), to_json_value(v)?);
            }
            serde_json::Value::Object(map)
        }
        CborValue::Bool(b) => serde_json::Value::Bool(*b),
        CborValue::Null => serde_json::Value::Null,
    })
}
