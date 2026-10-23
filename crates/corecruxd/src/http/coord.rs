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
    pub project_id: String,
    /// Announcing passport. Optional and never a trust input: the session
    /// binding is authoritative, otherwise the authenticated request passport
    /// is used, and a value naming any other passport is refused.
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
    /// Absolute path of the git worktree this session is working in. Optional.
    /// Recorded so a worktree can be tied to the plan that created it — a
    /// worktree whose plan has closed is an orphan, and without this the only
    /// way to find one is to walk every repo and test each branch against
    /// `origin/main`.
    #[serde(default)]
    pub worktree: Option<String>,
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
async fn live_lease_summaries(state: &AppState, now_ms: i64) -> Vec<LeaseSummary> {
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
    if !context.has_scope("admin:read") {
        return problem_response(
            StatusCode::FORBIDDEN,
            "admin:read scope required for coordination status",
        );
    }
    let tenant_id = match context.resolve_authorized_tenant(q.tenant_id.as_deref()) {
        Ok(tenant_id) => tenant_id,
        Err(problem) => return problem.into_response(),
    };
    let now = now_unix_ms();
    let store = state.fact_store.read().await;
    let bindings = crate::session_bindings::list_bindings(&store);
    let intents = crate::coord::list_intents(&store, q.project_id.as_deref());
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

    let leases = live_lease_summaries(&state, now as i64).await;

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
    headers: HeaderMap,
    Json(body): Json<AnnounceBody>,
) -> impl IntoResponse {
    if !state.coord_enabled {
        return coord_disabled_response();
    }
    if let Err(problem) = require_http_any_scope(&state.auth, &headers, &["facts:write", "admin:write"]) {
        return problem.into_response();
    }
    if body.session_id.trim().is_empty() || body.project_id.trim().is_empty() {
        return problem_response(
            StatusCode::BAD_REQUEST,
            "session_id and project_id must not be empty".to_string(),
        );
    }

    // The caller's own passport: the verified token claim, an admin's
    // passport-header override, or (auth-off/dev) the asserted header.
    let caller_passport = match crate::auth::http_scope_context(&state.auth, &headers) {
        Ok(ctx) => ctx.passport_id,
        Err(problem) => return problem.into_response(),
    };

    let now = now_unix_ms();
    let ttl_secs = body
        .ttl_seconds
        .unwrap_or(crate::coord::DEFAULT_INTENT_TTL_SECS)
        .min(crate::coord::MAX_TTL_SECS);

    let mut store = state.fact_store.write().await;
    // Passport resolution: session binding (authoritative) → the caller's own
    // passport. `by_passport` is not a trust input (D5): an unbound session
    // naming a passport the caller does not hold is refused, so an intent can
    // never be attributed to someone else. Never anonymous.
    let passport_id = match crate::session_bindings::get_binding(&store, body.session_id.trim()) {
        Some(binding) => binding.passport_id,
        None => {
            let claimed = body.by_passport.as_deref().map(str::trim).filter(|p| !p.is_empty());
            if claimed.is_some_and(|claimed| caller_passport.as_deref() != Some(claimed)) {
                return problem_response(
                    StatusCode::FORBIDDEN,
                    "by_passport does not match the authenticated passport".to_string(),
                );
            }
            let Some(passport_id) = caller_passport else {
                return problem_response(
                    StatusCode::BAD_REQUEST,
                    "no passport: bind the session or authenticate with a passport".to_string(),
                );
            };
            passport_id
        }
    };

    let intent = CoordIntent {
        project_id: body.project_id.trim().to_string(),
        session_id_hex: body.session_id.trim().to_string(),
        passport_id,
        execplan_slug: body.execplan_slug.filter(|s| !s.trim().is_empty()),
        milestone: body.milestone.filter(|s| !s.trim().is_empty()),
        deploy_target: body.deploy_target.filter(|s| !s.trim().is_empty()),
        worktree: body.worktree.filter(|s| !s.trim().is_empty()),
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
    let peer_intents = crate::coord::list_intents(&store, Some(&intent.project_id));
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
    let leases = live_lease_summaries(&state, now as i64).await;
    let mut overlaps = crate::coord::find_overlaps(&intent, &peer_intents, &leases, now);
    // Fourth signal: two OPEN plans naming the same file. Unlike the other
    // three it needs neither an announcement nor a lease, so it is the only one
    // that sees a peer who has not announced and has not edited yet. Weakest
    // and last, and each warning says so via its `signal`.
    overlaps.extend(crate::coord::find_plan_path_overlaps(
        &intent,
        &open_plan_path_claims(&state).await,
    ));
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
    use serde_json::json;

    async fn body_json(resp: Response) -> Value {
        let bytes = to_bytes(resp.into_body(), 1 << 20).await.expect("read body");
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    }

    fn announce_body(session: &str, project: &str) -> AnnounceBody {
        AnnounceBody {
            session_id: session.to_string(),
            project_id: project.to_string(),
            by_passport: Some("personal-default".to_string()),
            execplan_slug: Some("plan-x".to_string()),
            milestone: Some("M2".to_string()),
            deploy_target: None,
            worktree: None,
            paths: vec!["crates/corecruxd/src/coord.rs".to_string()],
            note: None,
            ttl_seconds: None,
        }
    }

    /// Bind a session + touch presence so the active view has a live row.
    async fn seed_live_session(state: &AppState, session: &str, project: &str) {
        seed_live_session_in_tenant(state, session, project, None).await;
    }

    /// As [`seed_live_session`], but stamps an explicit tenant on the binding
    /// and heartbeats whichever passport that tenant's category resolves to
    /// (`None` keeps the `personal` placeholder that `session_bindings::resolve`
    /// defaults to). Returns the bound passport so callers can assert on the
    /// passport-level joins.
    async fn seed_live_session_in_tenant(
        state: &AppState,
        session: &str,
        project: &str,
        tenant: Option<&str>,
    ) -> String {
        let passport_id = {
            let mut store = state.fact_store.write().await;
            crate::passports::seed_defaults_if_missing(&state.data_dir, &mut store, 1).expect("seed passports");
            let binding = crate::session_bindings::resolve(
                &store,
                crate::session_bindings::ResolveInput {
                    session_id_hex: session,
                    project_id: Some(project.to_string()),
                    tenant_id: tenant.map(str::to_string),
                    passport_id: None,
                    now_unix_ms: now_unix_ms(),
                },
            )
            .expect("resolve binding");
            crate::session_bindings::write_binding(&mut store, &binding).expect("write binding");
            binding.passport_id
        };
        state.presence.touch(&passport_id, "POST", "/v1/coord/announce").await;
        passport_id
    }

    #[tokio::test]
    async fn coord_disabled_returns_404() {
        let mut state = test_app_state(1);
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
            HeaderMap::new(),
            JsonExtract(announce_body("aaaa", "proj")),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// A worktree announced on the intent must survive the fact round-trip and
    /// reappear on `/v1/coord/active` — that read is the only way another
    /// session (or the reaper) can learn which checkout belongs to which plan.
    #[tokio::test]
    async fn announce_carries_worktree_through_to_active() {
        let state = test_app_state(1);
        seed_live_session(&state, "aaaa", "proj").await;

        let mut body = announce_body("aaaa", "proj");
        body.worktree = Some("/w/Crux-worktrees/coord-board-honesty".to_string());
        let resp = post_coord_announce(StateExtract(state.clone()), HeaderMap::new(), JsonExtract(body))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let announced = body_json(resp).await;
        assert_eq!(
            announced["intent"]["worktree"], "/w/Crux-worktrees/coord-board-honesty",
            "announce response must echo the worktree"
        );

        let active = get_coord_active(
            StateExtract(state.clone()),
            Query(ActiveQuery {
                project_id: Some("proj".to_string()),
                tenant_id: Some("personal".to_string()),
            }),
            HeaderMap::new(),
        )
        .await
        .into_response();
        let view = body_json(active).await;
        assert_eq!(
            view["active_sessions"][0]["intent"]["worktree"], "/w/Crux-worktrees/coord-board-honesty",
            "worktree must survive the fact round-trip onto the active board: {view}"
        );
    }

    /// Omitting it must leave the wire shape exactly as it was — the field is
    /// `skip_serializing_if`, so an intent that declares no worktree carries no
    /// `worktree` key at all, not a null.
    #[tokio::test]
    async fn announce_without_worktree_is_wire_identical() {
        let state = test_app_state(1);
        seed_live_session(&state, "aaaa", "proj").await;
        let resp = post_coord_announce(
            StateExtract(state.clone()),
            HeaderMap::new(),
            JsonExtract(announce_body("aaaa", "proj")),
        )
        .await
        .into_response();
        let announced = body_json(resp).await;
        assert!(
            announced["intent"].get("worktree").is_none(),
            "an intent with no worktree must omit the key, not emit null: {announced}"
        );
    }

    /// Whitespace is filtered to `None` like `deploy_target`, so a client that
    /// sends `""` does not pin an empty string onto the board.
    #[tokio::test]
    async fn announce_blank_worktree_is_treated_as_absent() {
        let state = test_app_state(1);
        seed_live_session(&state, "aaaa", "proj").await;
        let mut body = announce_body("aaaa", "proj");
        body.worktree = Some("   ".to_string());
        let resp = post_coord_announce(StateExtract(state.clone()), HeaderMap::new(), JsonExtract(body))
            .await
            .into_response();
        let announced = body_json(resp).await;
        assert!(
            announced["intent"].get("worktree").is_none(),
            "blank worktree must be dropped: {announced}"
        );
    }

    #[tokio::test]
    async fn announce_then_active_roundtrip_with_lease_join() {
        let state = test_app_state(1);
        seed_live_session(&state, "aaaa", "proj").await;

        // Announce focus for the bound session.
        let resp = post_coord_announce(
            StateExtract(state.clone()),
            HeaderMap::new(),
            JsonExtract(announce_body("aaaa", "proj")),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["intent"]["execplan_slug"], "plan-x");
        assert_eq!(body["cleared"], false);
        // Binding is authoritative for the passport even though by_passport
        // was also supplied.
        assert_eq!(body["intent"]["passport_id"], "personal-default");

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
                "holder_passport": "personal-default",
                "tenant_id": "default",
                "status": "held",
                "acquired_at_unix_ms": 0,
                "expires_at_unix_ms": i64::MAX,
            });
            estore
                .upsert(PUNCHCARD_KIND, "pc_test1", payload, "personal-default", Some(&reg))
                .expect("seed punchcard");
        }

        let resp = get_coord_active(
            StateExtract(state.clone()),
            QueryExtract(ActiveQuery {
                project_id: Some("proj".to_string()),
                tenant_id: Some("personal".to_string()),
            }),
            HeaderMap::new(),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let view = body_json(resp).await;
        let sessions = view["active_sessions"].as_array().expect("sessions array");
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0]["session_id_hex"], "aaaa");
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
                tenant_id: Some("personal".to_string()),
            }),
            HeaderMap::new(),
        )
        .await
        .into_response();
        let view = body_json(resp).await;
        assert_eq!(view["active_sessions"].as_array().map(Vec::len), Some(0));
    }

    #[tokio::test]
    async fn coord_active_never_returns_another_tenants_sessions() {
        // D4 (play03 M4) end-to-end: before the `assemble_active` tenant
        // filter, a tenant-A caller holding admin:read got every tenant's live
        // sessions and their declared focus. Both sessions here deliberately
        // resolve to the SAME passport (both tenants classify as `work`), so a
        // passport-level filter would still leak — only the binding's tenant
        // separates them.
        let state = test_app_state(1);
        let pa = seed_live_session_in_tenant(&state, "aaaa", "proj", Some("tenant-a")).await;
        let pb = seed_live_session_in_tenant(&state, "bbbb", "proj", Some("tenant-b")).await;
        assert_eq!(pa, pb, "test only bites if both tenants share one passport");

        for (session, slug) in [("aaaa", "plan-a"), ("bbbb", "plan-b-secret")] {
            let mut body = announce_body(session, "proj");
            body.by_passport = None;
            body.execplan_slug = Some(slug.to_string());
            let resp = post_coord_announce(StateExtract(state.clone()), HeaderMap::new(), JsonExtract(body))
                .await
                .into_response();
            assert_eq!(resp.status(), StatusCode::OK, "announce {session}");
        }

        let view_for = |tenant: &str| {
            let state = state.clone();
            let tenant = tenant.to_string();
            async move {
                let resp = get_coord_active(
                    StateExtract(state),
                    QueryExtract(ActiveQuery {
                        project_id: Some("proj".to_string()),
                        tenant_id: Some(tenant),
                    }),
                    HeaderMap::new(),
                )
                .await
                .into_response();
                assert_eq!(resp.status(), StatusCode::OK);
                body_json(resp).await
            }
        };

        let a = view_for("tenant-a").await;
        let sessions = a["active_sessions"].as_array().expect("sessions array");
        assert_eq!(sessions.len(), 1, "tenant-a must see exactly its own session: {a}");
        assert_eq!(sessions[0]["session_id_hex"], "aaaa");
        assert_eq!(sessions[0]["tenant_id"], "tenant-a");
        assert_eq!(sessions[0]["intent"]["execplan_slug"], "plan-a");
        assert!(
            !serde_json::to_string(&a).expect("serialize").contains("plan-b-secret"),
            "tenant-b intent leaked into the tenant-a board: {a}"
        );

        let b = view_for("tenant-b").await;
        let sessions = b["active_sessions"].as_array().expect("sessions array");
        assert_eq!(sessions.len(), 1, "tenant-b must see exactly its own session: {b}");
        assert_eq!(sessions[0]["session_id_hex"], "bbbb");
        assert_eq!(sessions[0]["tenant_id"], "tenant-b");

        // A third tenant is shown nothing rather than everything.
        let c = view_for("tenant-c").await;
        assert_eq!(
            c["active_sessions"].as_array().map(Vec::len),
            Some(0),
            "unknown tenant must fail closed: {c}"
        );
    }

    #[tokio::test]
    async fn announce_zero_ttl_clears_intent() {
        let state = test_app_state(1);
        seed_live_session(&state, "bbbb", "proj").await;

        let mut body = announce_body("bbbb", "proj");
        body.ttl_seconds = Some(0);
        let resp = post_coord_announce(StateExtract(state.clone()), HeaderMap::new(), JsonExtract(body))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_json(resp).await["cleared"], true);

        let resp = get_coord_active(
            StateExtract(state),
            QueryExtract(ActiveQuery {
                project_id: Some("proj".to_string()),
                tenant_id: Some("personal".to_string()),
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
        let state = test_app_state(1);
        {
            let mut store = state.fact_store.write().await;
            crate::passports::seed_defaults_if_missing(&state.data_dir, &mut store, 1).expect("seed passports");
            let binding = crate::session_bindings::resolve(
                &store,
                crate::session_bindings::ResolveInput {
                    session_id_hex: "dddd",
                    project_id: Some("proj".to_string()),
                    tenant_id: None,
                    passport_id: None,
                    now_unix_ms: now_unix_ms(),
                },
            )
            .expect("resolve binding");
            crate::session_bindings::write_binding(&mut store, &binding).expect("write binding");
        }
        // Deliberately NO presence.touch here — announce must provide it.
        let resp = post_coord_announce(
            StateExtract(state.clone()),
            HeaderMap::new(),
            JsonExtract(announce_body("dddd", "proj")),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = get_coord_active(
            StateExtract(state),
            QueryExtract(ActiveQuery {
                project_id: Some("proj".to_string()),
                tenant_id: Some("personal".to_string()),
            }),
            HeaderMap::new(),
        )
        .await
        .into_response();
        let view = body_json(resp).await;
        let sessions = view["active_sessions"].as_array().expect("sessions array");
        assert_eq!(sessions.len(), 1, "announce alone must make the session live: {view}");
        assert_eq!(sessions[0]["session_id_hex"], "dddd");
    }

    #[tokio::test]
    async fn announce_returns_peer_overlaps() {
        let state = test_app_state(1);
        seed_live_session(&state, "aaaa", "proj").await;

        // Session A declares a directory focus.
        let mut a = announce_body("aaaa", "proj");
        a.paths = vec!["crates/corecruxd/src".to_string()];
        let resp = post_coord_announce(StateExtract(state.clone()), HeaderMap::new(), JsonExtract(a))
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

        // Session B (unbound) announces as a different passport: an
        // overlapping file under A's directory + the same execplan slug.
        let b = || {
            let mut b = announce_body("bbbb", "proj");
            b.by_passport = Some("other-passport".to_string());
            b.paths = vec!["crates/corecruxd/src/coord.rs".to_string()];
            b
        };
        // D5: by_passport alone is a claim, not an identity — with no caller
        // passport behind it, the announce is refused and nothing is written.
        let resp = post_coord_announce(StateExtract(state.clone()), HeaderMap::new(), JsonExtract(b()))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        // The caller asserts that passport as its own identity (auth-off
        // mode's passport header), so by_passport now names the caller.
        let mut headers = HeaderMap::new();
        headers.insert("x-corecrux-passport-id", "other-passport".parse().expect("header"));
        let resp = post_coord_announce(StateExtract(state), headers, JsonExtract(b()))
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
        // B's own lease would be excluded, but this lease belongs to B's
        // passport — so from B's announce it's self, not a conflict.
        assert!(!kinds.contains(&"lease"), "own lease not flagged: {kinds:?}");
    }

    const JWT_SECRET: &str = "coord-announce-test-secret-32-bytes-minimum";
    const JWT_ISS: &str = "corecrux-coord-test";
    const JWT_AUD: &str = "corecrux";

    fn jwt_state() -> AppState {
        let mut state = test_app_state(1);
        state.auth = crate::auth::Authz::test_hs256(JWT_SECRET.as_bytes(), JWT_ISS, JWT_AUD);
        state
    }

    /// Bearer headers for a verified HS256 token bound to `passport_id`.
    fn jwt_headers(scopes: &str, passport_id: &str) -> HeaderMap {
        let claims = json!({
            "exp": now_unix_ms() / 1000 + 3_600,
            "iss": JWT_ISS,
            "aud": JWT_AUD,
            "scope": scopes,
            "tenant_id": "default",
            "passport_id": passport_id,
        });
        let token = jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(JWT_SECRET.as_bytes()),
        )
        .expect("mint test JWT");
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().expect("bearer header"),
        );
        headers
    }

    async fn announce_unbound(state: &AppState, headers: HeaderMap, by_passport: Option<&str>) -> (StatusCode, Value) {
        let mut body = announce_body("unbound", "proj");
        body.by_passport = by_passport.map(str::to_string);
        let resp = post_coord_announce(StateExtract(state.clone()), headers, JsonExtract(body))
            .await
            .into_response();
        let status = resp.status();
        (status, body_json(resp).await)
    }

    /// D5: a verified caller cannot attribute an intent to a passport it does
    /// not hold — the live repro announced as `personal-default` from an
    /// unrelated token.
    #[tokio::test]
    async fn announce_rejects_a_by_passport_the_caller_does_not_hold() {
        let state = jwt_state();
        let (status, body) =
            announce_unbound(&state, jwt_headers("facts:write", "agent-a"), Some("personal-default")).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        {
            let store = state.fact_store.read().await;
            assert!(
                crate::coord::list_intents(&store, Some("proj")).is_empty(),
                "a refused announce must not write an intent"
            );
        }

        // Positive control: the caller's own passport, named or implied.
        for by_passport in [Some("agent-a"), None] {
            let (status, body) = announce_unbound(&state, jwt_headers("facts:write", "agent-a"), by_passport).await;
            assert_eq!(status, StatusCode::OK, "{by_passport:?}: {body}");
            assert_eq!(body["intent"]["passport_id"], "agent-a");
        }
    }

    /// The admin exception is the existing passport-header override: an
    /// `admin:write` caller acts as another passport, and by_passport may then
    /// name it.
    #[tokio::test]
    async fn admin_announces_for_another_passport_via_the_header_override() {
        let state = jwt_state();
        let mut headers = jwt_headers("admin:write", "operator");
        headers.insert("x-corecrux-passport-id", "personal-default".parse().expect("header"));
        let (status, body) = announce_unbound(&state, headers, Some("personal-default")).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["intent"]["passport_id"], "personal-default");
    }

    #[tokio::test]
    async fn announce_without_binding_or_passport_is_rejected() {
        let state = test_app_state(1);
        let mut body = announce_body("unbound", "proj");
        body.by_passport = None;
        let resp = post_coord_announce(StateExtract(state), HeaderMap::new(), JsonExtract(body))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
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
pub(crate) fn extract_declared_paths(md: &str) -> Vec<String> {
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
