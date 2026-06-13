// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

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
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{body::Bytes, Json};
use serde::{Deserialize, Serialize};

use corecrux_projections::{SessionPlanSealedV1, CONTENT_TYPE_SESSION_BIN_V1, EVT_SESSION_PLAN_SEALED_V1};
use crux_session::{
    generator::GraphHints, handshake, Budget, Channels, FileSealer, FileSessionRegistry, HandshakeInputs,
    HandshakeRequest, InMemoryRegistry, InMemorySealer, LocalPassportConfig, NullSigner, PlanSealer, PlanSigner,
    RegistryEntry, SealedEvent, SessionRegistry, DEFAULT_CATALOG,
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
    pub default_ttl_s: u64,
    /// Prometheus metric handles (master-plan §11). `None` disables
    /// emission — legacy paths that wire services without a Prometheus
    /// registry still work.
    pub metrics: Option<Arc<super::session_metrics::SessionMetrics>>,
}

impl SessionServices {
    /// Ephemeral local-daemon wiring — `NullSigner` + `InMemorySealer` + `InMemoryRegistry`.
    /// Pre-M6 default; used only when the caller has no durable data
    /// directory (tests, smoke scripts). Sessions do not survive restart.
    pub fn local_default(node_id: impl Into<String>) -> Self {
        let install_uuid = node_id.into();
        Self {
            signer: Arc::new(NullSigner),
            sealer: Arc::new(InMemorySealer::new()),
            registry: Arc::new(InMemoryRegistry::new()),
            passport_cfg: Arc::new(LocalPassportConfig {
                install_uuid,
                user: std::env::var("USER").unwrap_or_else(|_| "local".into()),
            }),
            feature_flags: Arc::new(HashSet::new()),
            mcp_url: "http://localhost:14800/mcp".into(),
            bulk_url: None,
            default_ttl_s: 3600,
            metrics: None,
        }
    }

    /// Durable local-daemon wiring — persistent install UUID + file-backed
    /// registry (`data_dir/sessions/*.json`) + file-backed sealer
    /// (`data_dir/session-events.jsonl`). Sessions survive restart;
    /// the segment log is operator-inspectable with `jq`.
    ///
    /// Called from `main.rs` whenever corecruxd has a configured
    /// `data_dir`. Falls back to [`Self::local_default`] only when
    /// opening persistent state fails.
    pub fn local_durable(
        data_dir: &std::path::Path,
        node_id: impl Into<String>,
        mcp_url: impl Into<String>,
    ) -> Result<Self, String> {
        let user = std::env::var("USER").unwrap_or_else(|_| "local".into());
        let passport_cfg =
            LocalPassportConfig::from_data_dir(data_dir, user).map_err(|e| format!("persistent passport: {e}"))?;
        let registry = FileSessionRegistry::open(data_dir).map_err(|e| format!("file registry: {e}"))?;
        let sealer = FileSealer::open(data_dir).map_err(|e| format!("file sealer: {e}"))?;
        let _ = node_id; // retained for future node-scoped wiring
        Ok(Self {
            signer: Arc::new(NullSigner),
            sealer: Arc::new(sealer),
            registry: Arc::new(registry),
            passport_cfg: Arc::new(passport_cfg),
            feature_flags: Arc::new(HashSet::new()),
            mcp_url: mcp_url.into(),
            bulk_url: None,
            default_ttl_s: 3600,
            metrics: None,
        })
    }

    /// Attach a Prometheus metric sink. Idempotent; overwrites any
    /// previously-configured handle.
    pub fn with_metrics(mut self, metrics: Arc<super::session_metrics::SessionMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
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
#[tracing::instrument(level = "info", skip(state, headers, body))]
pub async fn post_session(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
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

    let (passport, origin_install) = services.passport_cfg.synthesise();
    let channels = Channels {
        bulk: services.bulk_url.clone(),
        mcp: services.mcp_url.clone(),
    };
    let budget = Budget {
        tokens_cap: None,
        crux_cap: None,
        ttl_s: services.default_ttl_s,
    };

    let handshake_request = HandshakeRequest {
        passport,
        channels,
        hints: GraphHints::from_request(request.hints.prefer_bulk),
        session_ttl_s: services.default_ttl_s,
        budget,
        origin: "ce".into(),
        origin_install: Some(origin_install),
        intent_hint: request.intent,
        now_ms: now_ms(),
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
    if let Err(e) = services.sealer.seal(&event) {
        if let Some(m) = services.metrics.as_ref() {
            m.handshake_seal_failure("ce");
        }
        return problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "segment_seal_failed",
            format!("segment log append failed: {e}"),
        );
    }

    let entry = RegistryEntry::from_plan(&sealed.plan, sealed.canonical_cbor.clone());
    if let Err(e) = services.registry.insert(entry) {
        if let Some(m) = services.metrics.as_ref() {
            m.handshake_failed("ce", "registry_insert_failed");
        }
        return problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            format!("registry insert failed: {e}"),
        );
    }

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
