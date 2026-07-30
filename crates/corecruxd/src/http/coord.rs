// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! HTTP surface for the multi-agent coordination plane ([`crate::coord`]).
//!
//! - `GET /v1/coord/active` — merged "who is live, what are they doing"
//!   board: presence ⋈ session bindings ⋈ declared intents ⋈ punchcard
//!   leases + kanban work in flight.
//! - `POST /v1/coord/announce` — declare (or clear, with `ttl_seconds: 0`)
//!   this session's focus.
//!
//! All routes are gated by `CORECRUXD_COORD=1`; when the flag is off they
//! return 404 so the surface is invisible rather than half-alive.

use std::net::SocketAddr;

use axum::extract::ConnectInfo;
use serde_json::Value;

use super::{
    problem_response, require_http_any_scope, AppState, HeaderMap, IntoResponse, Json, Query, State, StatusCode,
};
use crate::agentgraph_kinds::PUNCHCARD_KIND;
use crate::coord::{CoordIntent, LeaseSummary};

#[derive(Debug, serde::Deserialize)]
pub(super) struct ActiveQuery {
    pub project_id: Option<String>,
    pub tenant_id: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct AnnounceBody {
    pub session_id: String,
    /// Immutable coordination partition label selected at session mint. It is
    /// not a project ACL grant; tenant authority remains the security boundary.
    pub project_id: String,
    /// Announcing passport. Optional — resolved from the session binding
    /// (authoritative) or the authenticated request passport when omitted.
    #[serde(default, alias = "passport_id", alias = "author_passport")]
    pub by_passport: Option<String>,
    #[serde(default)]
    pub execplan_slug: Option<String>,
    #[serde(default)]
    pub milestone: Option<String>,
    /// Optional deploy-axis focus (e.g. `"deploy:crux"`). When two live peers
    /// announce the same target, the response `overlaps[]` carries a
    /// `deploy_target` warning. Advisory only.
    #[serde(default)]
    pub deploy_target: Option<String>,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub note: Option<String>,
    /// Intent lifetime. Defaults to [`crate::coord::DEFAULT_INTENT_TTL_SECS`];
    /// `0` clears the current intent (expires immediately).
    #[serde(default)]
    pub ttl_seconds: Option<u64>,
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

fn coord_disabled_response() -> axum::response::Response {
    problem_response(
        StatusCode::NOT_FOUND,
        "coordination plane disabled (set CORECRUXD_COORD=1)".to_string(),
    )
}

/// Live `held` punchcards from the substrate entity store, summarised for
/// the active view. Read-only — the punchcard surface's own handlers sweep
/// expired cards on acquire/list; here an expired card is simply filtered.
async fn live_lease_summaries(state: &AppState, now_ms: i64, tenant_id: &str) -> Vec<LeaseSummary> {
    let store = state.entity_store.read().await;
    let query = corecrux_memory::EntityQuery {
        kind: Some(PUNCHCARD_KIND.to_string()),
        limit: None,
        include_deleted: false,
    };
    store
        .list(&query)
        .into_iter()
        .filter_map(|rec| {
            let p: &Value = &rec.payload;
            let lease_tenant = p.get("tenant_id").and_then(Value::as_str).unwrap_or("default");
            if lease_tenant != tenant_id {
                return None;
            }
            if p.get("status").and_then(Value::as_str) != Some("held") {
                return None;
            }
            let expires = p.get("expires_at_unix_ms").and_then(Value::as_i64).unwrap_or(i64::MAX);
            if expires <= now_ms {
                return None;
            }
            Some(LeaseSummary {
                punchcard_id: rec.id.clone(),
                resource: p
                    .get("resource")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                mode: p.get("mode").and_then(Value::as_str).unwrap_or("modify").to_string(),
                holder_passport: p
                    .get("holder_passport")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                tenant_id: lease_tenant.to_string(),
                reason: p.get("reason").and_then(Value::as_str).map(str::to_string),
                expires_at_unix_ms: expires,
            })
        })
        .collect()
}

/// `GET /v1/coord/active?project_id=` — merged "who is live, what are they
/// doing" view.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_coord_active(
    State(state): State<AppState>,
    Query(q): Query<ActiveQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !state.coord_enabled {
        return coord_disabled_response();
    }
    let context = match crate::auth::passport_bound_context(&state.auth, &headers) {
        Ok(context) => context,
        Err(problem) => return problem.into_response(),
    };
    if !context.has_scope("admin:read") && !context.has_scope("sessions:read") {
        return problem_response(
            StatusCode::FORBIDDEN,
            "admin:read or sessions:read scope required for coordination status",
        );
    }
    let tenant_id = match context.resolve_authorized_tenant(q.tenant_id.as_deref()) {
        Ok(tenant_id) => tenant_id,
        Err(problem) => return problem.into_response(),
    };
    let now = now_unix_ms();
    let store = state.fact_store.read().await;
    let bindings = crate::session_bindings::list_bindings_for_tenant(&store, &tenant_id);
    let intents = crate::coord::list_intents_for_tenant(&store, q.project_id.as_deref(), &tenant_id);
    let mut work_in_flight = crate::work::list_work(
        &store,
        q.project_id.as_deref(),
        Some("in_progress"),
        Some(&tenant_id),
        None,
    );
    work_in_flight.extend(crate::work::list_work(
        &store,
        q.project_id.as_deref(),
        Some("blocked"),
        Some(&tenant_id),
        None,
    ));
    drop(store);

    let leases = live_lease_summaries(&state, now as i64, &tenant_id).await;

    let presence_by_passport: std::collections::BTreeMap<String, u64> = state
        .presence
        .snapshot()
        .await
        .into_iter()
        .map(|e| (e.passport_id, e.last_seen_at_unix_ms))
        .collect();

    let view = crate::coord::assemble_active(
        &bindings,
        &presence_by_passport,
        &intents,
        &leases,
        work_in_flight,
        &tenant_id,
        q.project_id.as_deref(),
        state.coord_presence_ttl_secs,
        now,
    );
    (StatusCode::OK, Json(view)).into_response()
}

/// `POST /v1/coord/announce` — declare this session's focus. Re-announcing
/// replaces; `ttl_seconds: 0` clears.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn post_coord_announce(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<AnnounceBody>,
) -> impl IntoResponse {
    if !state.coord_enabled {
        return coord_disabled_response();
    }
    if let Err(problem) = require_http_any_scope(&state.auth, &headers, &["sessions:write", "admin:write"]) {
        return problem.into_response();
    }
    if body.session_id.trim().is_empty() || body.project_id.trim().is_empty() {
        return problem_response(
            StatusCode::BAD_REQUEST,
            "session_id and project_id must not be empty".to_string(),
        );
    }

    let now = now_unix_ms();
    let session_id_hex = body.session_id.trim().to_ascii_lowercase();
    let (authority, _) =
        match super::session::authorize_live_session_admission(&state, &headers, Some(peer.ip()), &session_id_hex, now)
        {
            Ok(authorized) => authorized,
            Err(response) => return response,
        };
    let ttl_secs = body
        .ttl_seconds
        .unwrap_or(crate::coord::DEFAULT_INTENT_TTL_SECS)
        .min(crate::coord::MAX_TTL_SECS);

    let mut store = state.fact_store.write().await;
    let Some(binding) = crate::session_bindings::get_binding(&store, &session_id_hex) else {
        return problem_response(
            StatusCode::FORBIDDEN,
            "session has no authoritative binding; mint a new session".to_string(),
        );
    };
    if authority.verified && authority.actor_id != binding.passport_id {
        return problem_response(
            StatusCode::FORBIDDEN,
            "session binding does not match the verified request authority".to_string(),
        );
    }
    if let Some(claimed) = body
        .by_passport
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if claimed != binding.passport_id {
            return problem_response(
                StatusCode::FORBIDDEN,
                "body passport does not match the session binding".to_string(),
            );
        }
    }
    match binding.project_id.as_deref() {
        Some(project_id) if project_id == body.project_id.trim() => {}
        Some(_) => {
            return problem_response(
                StatusCode::FORBIDDEN,
                "body project does not match the session binding".to_string(),
            );
        }
        None => {
            return problem_response(
                StatusCode::FORBIDDEN,
                "session has no immutable coordination project label; mint a new session with project_id".to_string(),
            );
        }
    }
    let context = match crate::auth::passport_bound_context(&state.auth, &headers) {
        Ok(context) => context,
        Err(problem) => return problem.into_response(),
    };
    if let Err(problem) = context.resolve_authorized_tenant(Some(&binding.tenant_id)) {
        return problem.into_response();
    }
    let include_global_plan_claims = !context.auth_enforced() || context.has_global_tenant_authority();

    let intent = CoordIntent {
        project_id: body.project_id.trim().to_string(),
        session_id_hex,
        passport_id: binding.passport_id,
        tenant_id: binding.tenant_id,
        execplan_slug: body.execplan_slug.filter(|s| !s.trim().is_empty()),
        milestone: body.milestone.filter(|s| !s.trim().is_empty()),
        deploy_target: body.deploy_target.filter(|s| !s.trim().is_empty()),
        paths: body.paths,
        note: body.note.filter(|s| !s.trim().is_empty()),
        announced_at_unix_ms: now,
        expires_at_unix_ms: now.saturating_add(ttl_secs.saturating_mul(1000)),
    };
    if let Err(e) = crate::coord::write_intent(&mut store, &intent) {
        return problem_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
    }
    // Advisory overlap check against the other live intents + held leases,
    // computed in the same call so the announcing session learns who it
    // collides with the moment it declares an execplan. Never blocking.
    let peer_intents = crate::coord::list_intents_for_tenant(&store, Some(&intent.project_id), &intent.tenant_id);
    drop(store);
    // Announcing IS a liveness signal: touch presence for the resolved
    // passport so the session shows on the board even when the caller's
    // transport (MCP loopback, raw curl) doesn't carry the passport header
    // the presence middleware keys on. Without this, deployed smoke showed
    // bound+announced sessions filtered out of /v1/coord/active because the
    // presence map had no row for their passport.
    state
        .presence
        .touch(&intent.passport_id, "POST", "/v1/coord/announce")
        .await;
    let leases = live_lease_summaries(&state, now as i64, &intent.tenant_id).await;
    let mut overlaps = crate::coord::find_overlaps(&intent, &peer_intents, &leases, now);
    // Fourth signal: two OPEN plans naming the same file. Unlike the other
    // three it needs neither an announcement nor a lease, so it is the only one
    // that sees a peer who has not announced and has not edited yet. Weakest
    // and last, and each warning says so via its `signal`.
    if include_global_plan_claims {
        overlaps.extend(crate::coord::find_plan_path_overlaps(
            &intent,
            &open_plan_path_claims(&state).await,
        ));
    }
    let peers = peer_intents
        .iter()
        .filter(|p| p.session_id_hex != intent.session_id_hex && p.is_live(now))
        .count();

    let cleared = ttl_secs == 0;
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "intent": intent,
            "cleared": cleared,
            "live_peer_intents": peers,
            "overlaps": overlaps,
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::tests::test_app_state;
    use axum::body::to_bytes;
    use axum::extract::{Json as JsonExtract, Query as QueryExtract, State as StateExtract};
    use axum::response::Response;
    use crux_session::RegistryEntry;
    use serde_json::json;

    const SESSION_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SESSION_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const SESSION_D: &str = "dddddddddddddddddddddddddddddddd";

    fn loopback_peer() -> ConnectInfo<SocketAddr> {
        ConnectInfo("127.0.0.1:41000".parse().expect("loopback socket"))
    }

    fn coord_state() -> AppState {
        let mut state = test_app_state(1);
        state.session = Some(std::sync::Arc::new(
            super::super::session::SessionServices::local_default("coord-test"),
        ));
        state
    }

    async fn body_json(resp: Response) -> Value {
        let bytes = to_bytes(resp.into_body(), 1 << 20).await.expect("read body");
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    }

    fn announce_body(session: &str, project: &str) -> AnnounceBody {
        AnnounceBody {
            session_id: session.to_string(),
            project_id: project.to_string(),
            by_passport: None,
            execplan_slug: Some("plan-x".to_string()),
            milestone: Some("M2".to_string()),
            deploy_target: None,
            paths: vec!["crates/corecruxd/src/coord.rs".to_string()],
            note: None,
            ttl_seconds: None,
        }
    }

    async fn seed_registry_with(
        state: &AppState,
        session: &str,
        headers: &HeaderMap,
        closed: bool,
        include_owner_key: bool,
    ) {
        let decoded = hex::decode(session).expect("valid session hex");
        let session_id = <[u8; 16]>::try_from(decoded.as_slice()).expect("16-byte session id");
        let services = state.session.as_ref().expect("session services");
        let (local_passport, _) = services.passport_cfg.synthesise();
        let authority = super::super::session::admission_identity(
            state,
            services,
            headers,
            Some(loopback_peer().0.ip()),
            &local_passport.principal_id,
            true,
        )
        .expect("local admission identity");
        services
            .registry
            .insert(RegistryEntry {
                session_id,
                principal_id: local_passport.principal_id,
                capability_graph_hash: [0; 32],
                plan_receipt_hash: [0; 32],
                minted_at: now_unix_ms(),
                expires_at: now_unix_ms().saturating_add(60_000),
                origin: "test".to_string(),
                origin_install: None,
                plan_cbor: Vec::new(),
                closed,
                close_reason: None,
                admission_principal_key: include_owner_key.then_some(authority.principal_key),
                admission_ip_key: Some(authority.ip_key),
            })
            .expect("seed session registry");
    }

    async fn seed_registry_only(state: &AppState, session: &str) {
        seed_registry_with(state, session, &HeaderMap::new(), false, true).await;
    }

    fn dev_headers(passport: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("x-corecrux-scopes", "sessions:write".parse().expect("scope header"));
        headers.insert("x-corecrux-passport-id", passport.parse().expect("passport header"));
        headers
    }

    const JWT_SECRET: &[u8] = b"coord-test-secret-at-least-32-bytes";
    const JWT_ISSUER: &str = "coord-tests";
    const JWT_AUDIENCE: &str = "corecrux";

    fn jwt_headers(scopes: &str, passport: &str, subject: &str, tenant: &str) -> HeaderMap {
        let exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_secs()
            .saturating_add(3_600);
        let claims = serde_json::json!({
            "exp": exp,
            "iss": JWT_ISSUER,
            "aud": JWT_AUDIENCE,
            "scope": scopes,
            "sub": subject,
            "passport_id": passport,
            "tenant_id": tenant,
        });
        let token = jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(JWT_SECRET),
        )
        .expect("test JWT");
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().expect("bearer header"),
        );
        headers
    }

    async fn seed_owned_session(state: &AppState, session: &str, project: &str, passport: &str, headers: &HeaderMap) {
        seed_owned_session_in_tenant(state, session, project, passport, "default", headers).await;
    }

    async fn seed_owned_session_in_tenant(
        state: &AppState,
        session: &str,
        project: &str,
        passport: &str,
        tenant: &str,
        headers: &HeaderMap,
    ) {
        seed_registry_with(state, session, headers, false, true).await;
        let binding = crate::session_bindings::SessionBinding {
            session_id_hex: session.to_string(),
            project_id: Some(project.to_string()),
            tenant_id: tenant.to_string(),
            passport_id: passport.to_string(),
            passport_category: "automation".to_string(),
            agent_work_gate: false,
            bound_at_unix_ms: now_unix_ms(),
        };
        let mut store = state.fact_store.write().await;
        crate::session_bindings::write_binding(&mut store, &binding).expect("write owned binding");
    }

    /// Bind a session + touch presence so the active view has a live row.
    async fn seed_live_session(state: &AppState, session: &str, project: &str) {
        seed_registry_only(state, session).await;
        {
            let mut store = state.fact_store.write().await;
            crate::passports::seed_defaults_if_missing(&state.data_dir, &mut store, 1).expect("seed passports");
            let binding = crate::session_bindings::resolve(
                &store,
                crate::session_bindings::ResolveInput {
                    session_id_hex: session,
                    project_id: Some(project.to_string()),
                    tenant_id: Some("default".to_string()),
                    passport_id: None,
                    now_unix_ms: now_unix_ms(),
                },
            )
            .expect("resolve binding");
            crate::session_bindings::write_binding(&mut store, &binding).expect("write binding");
        }
        state.presence.touch("work-default", "POST", "/v1/coord/announce").await;
    }

    #[tokio::test]
    async fn coord_disabled_returns_404() {
        let mut state = coord_state();
        state.coord_enabled = false;
        let resp = get_coord_active(
            StateExtract(state.clone()),
            QueryExtract(ActiveQuery {
                project_id: None,
                tenant_id: None,
            }),
            HeaderMap::new(),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let resp = post_coord_announce(
            StateExtract(state),
            loopback_peer(),
            HeaderMap::new(),
            JsonExtract(announce_body(SESSION_A, "proj")),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn announce_then_active_roundtrip_with_lease_join() {
        let state = coord_state();
        seed_live_session(&state, SESSION_A, "proj").await;

        // Announce focus for the bound session.
        let resp = post_coord_announce(
            StateExtract(state.clone()),
            loopback_peer(),
            HeaderMap::new(),
            JsonExtract(announce_body(SESSION_A, "proj")),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["intent"]["execplan_slug"], "plan-x");
        assert_eq!(body["cleared"], false);
        // Binding is authoritative for the passport even though by_passport
        // was also supplied.
        assert_eq!(body["intent"]["passport_id"], "work-default");

        // Seed one held punchcard for the same passport (direct entity-store
        // write; the punchcard HTTP surface is env-gated and swept elsewhere).
        {
            let mut reg = state.kind_registry.write().await;
            crate::agentgraph_kinds::bootstrap(&mut reg).expect("bootstrap kinds");
        }
        {
            let reg = state.kind_registry.read().await;
            let mut estore = state.entity_store.write().await;
            let payload = json!({
                "id": "pc_test1",
                "resource": "tree://crates/corecruxd",
                "mode": "modify",
                "holder_passport": "work-default",
                "tenant_id": "default",
                "status": "held",
                "acquired_at_unix_ms": 0,
                "expires_at_unix_ms": i64::MAX,
            });
            estore
                .upsert(PUNCHCARD_KIND, "pc_test1", payload, "work-default", Some(&reg))
                .expect("seed punchcard");
        }

        let resp = get_coord_active(
            StateExtract(state.clone()),
            QueryExtract(ActiveQuery {
                project_id: Some("proj".to_string()),
                tenant_id: None,
            }),
            HeaderMap::new(),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let view = body_json(resp).await;
        let sessions = view["active_sessions"].as_array().expect("sessions array");
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0]["session_id_hex"], SESSION_A);
        assert_eq!(sessions[0]["intent"]["execplan_slug"], "plan-x");
        assert_eq!(sessions[0]["intent"]["milestone"], "M2");
        let leases = sessions[0]["leases"].as_array().expect("leases array");
        assert_eq!(leases.len(), 1);
        assert_eq!(leases[0]["resource"], "tree://crates/corecruxd");

        // Project scoping: another project sees no sessions.
        let resp = get_coord_active(
            StateExtract(state),
            QueryExtract(ActiveQuery {
                project_id: Some("other".to_string()),
                tenant_id: None,
            }),
            HeaderMap::new(),
        )
        .await
        .into_response();
        let view = body_json(resp).await;
        assert_eq!(view["active_sessions"].as_array().map(Vec::len), Some(0));
    }

    #[tokio::test]
    async fn announce_zero_ttl_clears_intent() {
        let state = coord_state();
        seed_live_session(&state, SESSION_B, "proj").await;

        let mut body = announce_body(SESSION_B, "proj");
        body.ttl_seconds = Some(0);
        let resp = post_coord_announce(
            StateExtract(state.clone()),
            loopback_peer(),
            HeaderMap::new(),
            JsonExtract(body),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_json(resp).await["cleared"], true);

        let resp = get_coord_active(
            StateExtract(state),
            QueryExtract(ActiveQuery {
                project_id: Some("proj".to_string()),
                tenant_id: None,
            }),
            HeaderMap::new(),
        )
        .await
        .into_response();
        let view = body_json(resp).await;
        let sessions = view["active_sessions"].as_array().expect("sessions array");
        assert_eq!(sessions.len(), 1, "session still live (presence)");
        assert!(sessions[0].get("intent").is_none(), "cleared intent hidden");
    }

    #[tokio::test]
    async fn announce_alone_marks_session_live() {
        // Regression for the v0.4.3 deploy gap: bound + announced sessions
        // were invisible on the board because nothing had touched presence
        // for their passport (MCP traffic bypasses the presence middleware).
        let state = coord_state();
        {
            let mut store = state.fact_store.write().await;
            crate::passports::seed_defaults_if_missing(&state.data_dir, &mut store, 1).expect("seed passports");
            let binding = crate::session_bindings::resolve(
                &store,
                crate::session_bindings::ResolveInput {
                    session_id_hex: SESSION_D,
                    project_id: Some("proj".to_string()),
                    tenant_id: Some("default".to_string()),
                    passport_id: None,
                    now_unix_ms: now_unix_ms(),
                },
            )
            .expect("resolve binding");
            crate::session_bindings::write_binding(&mut store, &binding).expect("write binding");
        }
        seed_registry_only(&state, SESSION_D).await;
        // Deliberately NO presence.touch here — announce must provide it.
        let resp = post_coord_announce(
            StateExtract(state.clone()),
            loopback_peer(),
            HeaderMap::new(),
            JsonExtract(announce_body(SESSION_D, "proj")),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = get_coord_active(
            StateExtract(state),
            QueryExtract(ActiveQuery {
                project_id: Some("proj".to_string()),
                tenant_id: None,
            }),
            HeaderMap::new(),
        )
        .await
        .into_response();
        let view = body_json(resp).await;
        let sessions = view["active_sessions"].as_array().expect("sessions array");
        assert_eq!(sessions.len(), 1, "announce alone must make the session live: {view}");
        assert_eq!(sessions[0]["session_id_hex"], SESSION_D);
    }

    #[tokio::test]
    async fn announce_returns_peer_overlaps() {
        let state = coord_state();
        seed_live_session(&state, SESSION_A, "proj").await;
        seed_live_session(&state, SESSION_B, "proj").await;

        // Session A declares a directory focus.
        let mut a = announce_body(SESSION_A, "proj");
        a.paths = vec!["crates/corecruxd/src".to_string()];
        let resp = post_coord_announce(
            StateExtract(state.clone()),
            loopback_peer(),
            HeaderMap::new(),
            JsonExtract(a),
        )
        .await
        .into_response();
        assert_eq!(body_json(resp).await["overlaps"].as_array().map(Vec::len), Some(0));

        // A different passport holds a lease inside that directory.
        {
            let mut reg = state.kind_registry.write().await;
            crate::agentgraph_kinds::bootstrap(&mut reg).expect("bootstrap kinds");
        }
        {
            let reg = state.kind_registry.read().await;
            let mut estore = state.entity_store.write().await;
            let payload = json!({
                "id": "pc_other",
                "resource": "tree://crates/corecruxd/src/http",
                "mode": "modify",
                "holder_passport": "other-passport",
                "tenant_id": "default",
                "status": "held",
                "acquired_at_unix_ms": 0,
                "expires_at_unix_ms": i64::MAX,
            });
            estore
                .upsert(PUNCHCARD_KIND, "pc_other", payload, "other-passport", Some(&reg))
                .expect("seed peer punchcard");
        }

        // Session B (unbound; explicit different passport) announces an
        // overlapping file under A's directory + the same execplan slug.
        let mut b = announce_body(SESSION_B, "proj");
        b.paths = vec!["crates/corecruxd/src/coord.rs".to_string()];
        let resp = post_coord_announce(StateExtract(state), loopback_peer(), HeaderMap::new(), JsonExtract(b))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["live_peer_intents"], 1);
        let kinds: Vec<&str> = body["overlaps"]
            .as_array()
            .expect("overlaps array")
            .iter()
            .filter_map(|w| w["kind"].as_str())
            .collect();
        assert!(kinds.contains(&"execplan"), "same slug flagged: {kinds:?}");
        assert!(kinds.contains(&"intent_path"), "path containment flagged: {kinds:?}");
        assert!(
            !kinds.contains(&"lease"),
            "the sibling http subtree does not overlap coord.rs: {kinds:?}"
        );
    }

    #[tokio::test]
    async fn announce_rejects_cross_owner_and_body_spoof_before_writing() {
        let mut state = coord_state();
        state.auth = crate::auth::Authz::from_env(crate::auth::AuthMode::DevScopes).expect("dev auth");
        let owner_headers = dev_headers("owner-a");
        seed_owned_session(&state, SESSION_A, "proj", "owner-a", &owner_headers).await;

        let mut body = announce_body(SESSION_A, "proj");
        body.by_passport = Some("owner-a".to_string());
        let resp = post_coord_announce(
            StateExtract(state.clone()),
            loopback_peer(),
            dev_headers("owner-b"),
            JsonExtract(body),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        let mut spoofed = announce_body(SESSION_A, "proj");
        spoofed.by_passport = Some("owner-b".to_string());
        let resp = post_coord_announce(
            StateExtract(state.clone()),
            loopback_peer(),
            owner_headers.clone(),
            JsonExtract(spoofed),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        let mut wrong_project = announce_body(SESSION_A, "other-project");
        wrong_project.by_passport = Some("owner-a".to_string());
        let resp = post_coord_announce(
            StateExtract(state.clone()),
            loopback_peer(),
            owner_headers.clone(),
            JsonExtract(wrong_project),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        {
            let store = state.fact_store.read().await;
            assert!(
                crate::coord::list_intents(&store, None).is_empty(),
                "denied announcements must not write an intent"
            );
        }

        let mut uppercase = announce_body(&SESSION_A.to_ascii_uppercase(), "proj");
        uppercase.by_passport = Some("owner-a".to_string());
        let resp = post_coord_announce(
            StateExtract(state.clone()),
            loopback_peer(),
            owner_headers,
            JsonExtract(uppercase),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_json(resp).await["intent"]["session_id_hex"], SESSION_A);
    }

    #[tokio::test]
    async fn announce_rejects_closed_and_legacy_unowned_sessions() {
        let state = coord_state();
        seed_live_session(&state, SESSION_A, "proj").await;
        let session_a = <[u8; 16]>::try_from(hex::decode(SESSION_A).expect("hex").as_slice()).expect("session");
        state
            .session
            .as_ref()
            .expect("session services")
            .registry
            .close(&session_a, "test")
            .expect("close session");
        let resp = post_coord_announce(
            StateExtract(state.clone()),
            loopback_peer(),
            HeaderMap::new(),
            JsonExtract(announce_body(SESSION_A, "proj")),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        seed_live_session(&state, SESSION_B, "proj").await;
        seed_registry_with(&state, SESSION_B, &HeaderMap::new(), false, false).await;
        let resp = post_coord_announce(
            StateExtract(state.clone()),
            loopback_peer(),
            HeaderMap::new(),
            JsonExtract(announce_body(SESSION_B, "proj")),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        {
            let store = state.fact_store.read().await;
            assert!(
                crate::coord::list_intents(&store, None).is_empty(),
                "closed and legacy sessions must not write intents"
            );
        }
    }

    #[tokio::test]
    async fn jwt_coord_status_and_announce_do_not_expose_another_tenant() {
        let mut state = coord_state();
        state.auth = crate::auth::Authz::test_hs256(JWT_SECRET, JWT_ISSUER, JWT_AUDIENCE);
        let write_a = jwt_headers("sessions:write", "passport-a", "subject-a", "tenant-a");
        let write_b = jwt_headers("sessions:write", "passport-b", "subject-b", "tenant-b");
        seed_owned_session_in_tenant(&state, SESSION_A, "proj", "passport-a", "tenant-a", &write_a).await;
        seed_owned_session_in_tenant(&state, SESSION_B, "proj", "passport-b", "tenant-b", &write_b).await;

        let mut body_b = announce_body(SESSION_B, "proj");
        body_b.note = Some("TENANT-B-SECRET-NOTE".to_string());
        body_b.paths = vec!["TENANT-B-SECRET-PATH".to_string()];
        let announced_b = post_coord_announce(
            StateExtract(state.clone()),
            loopback_peer(),
            write_b,
            JsonExtract(body_b),
        )
        .await
        .into_response();
        assert_eq!(announced_b.status(), StatusCode::OK);

        {
            let registry = state.kind_registry.read().await;
            let registry_opt = registry.is_registered(PUNCHCARD_KIND).then_some(&*registry);
            state
                .entity_store
                .write()
                .await
                .upsert(
                    PUNCHCARD_KIND,
                    "pc_tenant_b_secret",
                    serde_json::json!({
                        "id": "pc_tenant_b_secret",
                        "resource": "TENANT-B-SECRET-LEASE",
                        "mode": "modify",
                        "holder_passport": "passport-b",
                        "tenant_id": "tenant-b",
                        "status": "held",
                        "expires_at_unix_ms": now_unix_ms().saturating_add(60_000) as i64,
                    }),
                    "passport-b",
                    registry_opt,
                )
                .expect("seed tenant B lease");
        }

        let announced_a = post_coord_announce(
            StateExtract(state.clone()),
            loopback_peer(),
            write_a,
            JsonExtract(announce_body(SESSION_A, "proj")),
        )
        .await
        .into_response();
        assert_eq!(announced_a.status(), StatusCode::OK);
        let announced_a = body_json(announced_a).await;
        assert_eq!(announced_a["live_peer_intents"], 0);
        let announcement_text = announced_a.to_string();
        for secret in [
            SESSION_B,
            "passport-b",
            "TENANT-B-SECRET-NOTE",
            "TENANT-B-SECRET-PATH",
            "TENANT-B-SECRET-LEASE",
        ] {
            assert!(!announcement_text.contains(secret), "announce leaked {secret}");
        }

        let active_a = get_coord_active(
            StateExtract(state),
            QueryExtract(ActiveQuery {
                project_id: Some("proj".to_string()),
                tenant_id: Some("tenant-a".to_string()),
            }),
            jwt_headers("sessions:read", "passport-a", "subject-a", "tenant-a"),
        )
        .await
        .into_response();
        assert_eq!(active_a.status(), StatusCode::OK);
        let active_text = body_json(active_a).await.to_string();
        for secret in [
            SESSION_B,
            "passport-b",
            "tenant-b",
            "TENANT-B-SECRET-NOTE",
            "TENANT-B-SECRET-PATH",
            "TENANT-B-SECRET-LEASE",
            "pc_tenant_b_secret",
        ] {
            assert!(!active_text.contains(secret), "active board leaked {secret}");
        }
    }

    #[tokio::test]
    async fn announce_without_binding_or_passport_is_rejected() {
        let state = coord_state();
        let mut body = announce_body("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "proj");
        body.by_passport = None;
        let resp = post_coord_announce(
            StateExtract(state),
            loopback_peer(),
            HeaderMap::new(),
            JsonExtract(body),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }
}

/// Repo-relative paths declared by each OPEN ExecPlan, for the plan-paths
/// collision signal.
///
/// Reads the plans the projection already walked — no extra scan — and pulls
/// the paths out of each plan's own text. Deliberately cheap and approximate:
/// this signal exists to say "two plans name the same file", and a missed path
/// costs a warning nobody needed rather than a wrong one.
async fn open_plan_path_claims(state: &AppState) -> Vec<crate::coord::PlanPathClaim> {
    let Some(root) = crate::work_execplans::execplans_root_from_env() else {
        return Vec::new();
    };
    let files = match crate::work_execplans::walk_execplans_root(&root) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };
    let store = state.fact_store.read().await;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64);
    let items = crate::work_execplans::list_execplans(&store, &root, now).unwrap_or_default();
    drop(store);
    let open: std::collections::HashSet<&str> = items
        .iter()
        .filter(|i| crate::work_execplans::is_open_state(&i.state))
        .filter_map(|i| i.id.strip_prefix("execplan:"))
        .collect();

    files
        .iter()
        .filter(|f| open.contains(f.slug.as_str()))
        .map(|f| crate::coord::PlanPathClaim {
            execplan_slug: f.slug.clone(),
            paths: extract_declared_paths(&f.content),
        })
        .filter(|c| !c.paths.is_empty())
        .collect()
}

/// Pull `<Repo>/path/to/file.ext` mentions out of a plan's markdown.
///
/// Vendored and generated trees carry no authorship signal — two plans
/// "sharing" a `node_modules` file tells you nothing — so they are dropped.
fn extract_declared_paths(md: &str) -> Vec<String> {
    const NOISE: &[&str] = &["node_modules/", "target/", "dist/", "build/", ".git/", "vendor/"];
    let mut out: Vec<String> = Vec::new();
    for token in md.split(|c: char| c.is_whitespace() || matches!(c, '(' | ')' | '[' | ']' | '`' | '"' | ',' | ';')) {
        let t = token.trim_matches(|c: char| matches!(c, '.' | ':' | '*' | '#' | '<' | '>'));
        if t.len() < 5 || !t.contains('/') || !t.contains('.') {
            continue;
        }
        let ext_ok = [
            ".rs", ".ts", ".tsx", ".js", ".mjs", ".py", ".vue", ".sh", ".toml", ".sql",
        ]
        .iter()
        .any(|e| t.ends_with(e));
        if !ext_ok || NOISE.iter().any(|n| t.contains(n)) {
            continue;
        }
        let s = t.to_string();
        if !out.contains(&s) {
            out.push(s);
        }
    }
    out.truncate(64);
    out
}
