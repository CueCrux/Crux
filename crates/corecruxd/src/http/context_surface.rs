// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `GET/POST /v1/context` — provider-agnostic injection-bundle surface
//! (`context_bundle/v1`).
//!
//! ExecPlan `provider-integration-surfaces-2026-06-11` M1 (G1a). Returns the
//! same memory bundle the Claude Code boot banner uses today — facts +
//! session state — in a stable, versioned JSON shape that any harness
//! (OpenAI SDK loops, Codex CLI, Cursor rules, LangChain) can inject at
//! session start. The semantics are owned by the normative spec
//! `Context-Bundle-v1-Spec` (planning monorepo, shared plane; child plan E,
//! `context-mediation-injection-2026-06-11`); this module owns the transport.
//!
//! Assembly is delegated to the canonical deterministic assembler,
//! [`corecrux_projections::context_bundle::assemble`] (ExecPlan
//! `context-mediation-injection-2026-06-11` M2) — this module fetches
//! tenant-/passport-scoped inputs, maps them to the assembler's input
//! types, and owns the HTTP wire shape. The interim mirror assembler this
//! module shipped with has been deleted in favour of the canonical one.
//!
//! Gating: `CORECRUXD_CONTEXT_SURFACE=1`, default OFF. When off the routes
//! return 404 so the surface is invisible rather than half-alive (same
//! convention as the coord plane).
//!
//! Determinism: the *stable region* (`bundle_version` + ordered `sections`)
//! is byte-stable for an unchanged fact-chain head and is hashed with blake3
//! (`stable_hash`) so provider-side prompt caches hit on the injected
//! prefix. Volatile material (`assembled_at`, `budget`, `receipt_ref`,
//! identity echo) lives outside the stable region.

use corecrux_projections::assembly_cache::AssemblyKey;
use corecrux_projections::context_bundle::{
    self as cb, render_markdown_stable, AuxItem, AuxSection, ContextBundle, SectionKind, BUNDLE_VERSION,
    DEFAULT_REQUESTED_BUDGET, FREE_TIER_CEILING,
};
use corecrux_projections::decay;
use serde_json::{json, Value};

use super::observations::{append_one, PostObservationBody};
use super::{problem_response, AppState, HeaderMap, IntoResponse, Json, Query, Response, State, StatusCode};

/// Selection cap for the zero-hint default bundle (no `entity`, no `query`):
/// top facts by effective confidence, before budget enforcement.
const DEFAULT_BUNDLE_TOP_K: usize = 20;

/// Selection cap for keyword / addressed recall passes.
const RECALL_TOP_K: usize = 50;

// ── Request shapes ────────────────────────────────────────────────────────

/// Shared request fields for GET (query string) and POST (JSON body).
#[derive(Debug, Default, serde::Deserialize, utoipa::IntoParams, utoipa::ToSchema)]
pub(super) struct ContextRequest {
    /// Consumer session id — when present, the saved session state for it is
    /// included as the `session_state` section (the resume payload).
    pub session_id: Option<String>,
    /// Typed address: exact entity to resolve first (addressed recall —
    /// `execplan:<slug>`, `bench:<id>`, `design:<slug>`, …).
    pub entity: Option<String>,
    /// Keyword recall over fact values/keys/entities, ranked by
    /// time-decayed effective confidence.
    pub query: Option<String>,
    /// `budget.requested`. Defaults to 2000; hard-capped by the tier
    /// ceiling (8000 free/local).
    pub token_budget: Option<usize>,
    /// Renderer: `json` (default), `markdown` (boot-banner shape), or
    /// `openai_messages` (messages-array fragment for OpenAI-SDK harnesses).
    pub render: Option<String>,
}

// ── Fact gathering (tenant/passport-scoped, supersession-aware) ──────────

fn projection_class(class: corecrux_memory::fact_store::HorizonClass) -> decay::HorizonClass {
    decay::HorizonClass::parse(class.as_str()).unwrap_or(decay::HorizonClass::None)
}

/// Map a store fact to the canonical assembler's input row.
///
/// Visibility/tenancy scoping has already been enforced at fetch time by
/// `query_visible_http_facts`; the assembler's private-owner re-check is
/// defense in depth and therefore only engages when an owner is actually
/// recorded (`actor`) — a private fact without a recorded owner relies on
/// the fetch-time scope, exactly as before the canonical-assembler swap.
fn fact_input(fact: corecrux_memory::fact_store::Fact, addressed: bool) -> cb::FactInput {
    let written_ms = fact.reverified_at.unwrap_or(fact.stored_at).timestamp_millis();
    cb::FactInput {
        private: fact.private && fact.actor.is_some(),
        owner: fact.actor,
        fact_id: fact.fact_id,
        entity: fact.entity,
        key: fact.key,
        value: fact.value,
        confidence: f64::from(fact.confidence),
        written_ms,
        horizon_class: projection_class(fact.horizon_class),
        version: fact.version,
        superseded: fact.superseded_by.is_some(),
        est_tokens: Some(fact.tokens.max(1)),
        addressed,
    }
}

/// Gather candidate facts under the caller's scope. Superseded facts are
/// excluded (spec §4 rule 2); stale facts are included with their `stale`
/// annotation, never silently presented as current.
async fn gather_facts(
    state: &AppState,
    ctx: &crate::auth::HttpScopeContext,
    req: &ContextRequest,
) -> Vec<cb::FactInput> {
    let store = state.fact_store.read().await;

    let mut out: Vec<cb::FactInput> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    // 1. Addressed recall first (spec §4 rule 1).
    if let Some(entity) = req.entity.as_deref().map(str::trim).filter(|e| !e.is_empty()) {
        let q = corecrux_memory::fact_store::FactQuery {
            query: None,
            entity: Some(entity.to_string()),
            entity_prefix: None,
            top_k: RECALL_TOP_K,
            token_budget: None,
        };
        for fact in super::facts::query_visible_http_facts(&store, &q, ctx) {
            if fact.superseded_by.is_some() || !seen.insert(fact.fact_id.clone()) {
                continue;
            }
            out.push(fact_input(fact, true));
        }
    }

    // 2. Keyword recall, effective-confidence ranked (spec §4 rule 2) —
    //    or the zero-hint default bundle (top facts overall).
    let keyword = req.query.as_deref().map(str::trim).filter(|q| !q.is_empty());
    if keyword.is_some() || req.entity.is_none() {
        let q = corecrux_memory::fact_store::FactQuery {
            query: keyword.map(str::to_string),
            entity: None,
            entity_prefix: None,
            top_k: if keyword.is_some() {
                RECALL_TOP_K
            } else {
                DEFAULT_BUNDLE_TOP_K
            },
            token_budget: None,
        };
        for fact in super::facts::query_visible_http_facts(&store, &q, ctx) {
            if fact.superseded_by.is_some() || !seen.insert(fact.fact_id.clone()) {
                continue;
            }
            out.push(fact_input(fact, false));
        }
    }
    out
}

/// Saved session state for the requested session, scoped to the caller,
/// as a `session_state` aux section. Stable item carries no timestamps
/// (spec §6) — `updated_at` is excluded; the state rides as canonical JSON
/// text under the deterministic `id` sort key.
async fn gather_session_state(
    state: &AppState,
    ctx: &crate::auth::HttpScopeContext,
    req: &ContextRequest,
) -> Option<AuxSection> {
    let session_id = req.session_id.as_deref().map(str::trim).filter(|s| !s.is_empty())?;
    let scoped = super::facts::scoped_session_id_for_http(ctx, session_id);
    let store = state.session_store.read().await;
    let session = store.get(&scoped)?;
    let text = serde_json::to_string(&session.state).unwrap_or_default();
    let est = session.total_tokens.max(text.len() / 4);
    Some(AuxSection {
        kind: SectionKind::SessionState,
        items: vec![AuxItem {
            id: session_id.to_string(),
            text,
            est_tokens: Some(est),
        }],
    })
}

// ── Assembly cache (G21b wiring, CORECRUXD_ASSEMBLY_CACHE) ───────────────

/// Build the structural cache key for one assembly request
/// (`corecrux_projections::assembly_cache::AssemblyKey`).
///
/// `facts_chain_head` is a digest over every mutation-relevant fact field
/// (id, version, supersession, re-verify anchor, deletion, horizon) — any
/// fact write moves it, which IS the invalidation mechanism (no bus, no
/// staleness window). Folded into the same digest, because they also
/// change the assembled bundle without moving the fact chain:
///
/// - the requested session's state (the `session_state` section),
/// - the request identity (`entity` / `query` / `token_budget` — the
///   merged `AssemblyKey` carries only passport/session, so request shape
///   rides in the head),
/// - the current UTC hour (freshness *classes* may flip at horizon
///   crossings without a write; an entry therefore serves at most one
///   hour of class lag).
async fn assembly_cache_key(
    state: &AppState,
    ctx: &crate::auth::HttpScopeContext,
    req: &ContextRequest,
    principal: &str,
    now_ms: i64,
) -> AssemblyKey {
    let mut per_fact: Vec<[u8; 32]> = {
        let store = state.fact_store.read().await;
        store
            .all_facts()
            .map(|f| {
                let mut h = blake3::Hasher::new();
                h.update(f.fact_id.as_bytes());
                h.update(&f.version.to_le_bytes());
                h.update(&[u8::from(f.deleted), u8::from(f.private)]);
                h.update(f.superseded_by.as_deref().unwrap_or("").as_bytes());
                h.update(
                    &f.reverified_at
                        .map(|t| t.timestamp_millis())
                        .unwrap_or_default()
                        .to_le_bytes(),
                );
                h.update(f.horizon_class.as_str().as_bytes());
                *h.finalize().as_bytes()
            })
            .collect()
    };
    // The store iterates a HashMap — sort for a deterministic head.
    per_fact.sort_unstable();

    let mut head = blake3::Hasher::new();
    for h in &per_fact {
        head.update(h);
    }
    // Session-state slice (rides outside the fact chain).
    if let Some(session_id) = req.session_id.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        let scoped = super::facts::scoped_session_id_for_http(ctx, session_id);
        let store = state.session_store.read().await;
        if let Some(session) = store.get(&scoped) {
            head.update(serde_json::to_string(&session.state).unwrap_or_default().as_bytes());
        }
    }
    // Request identity.
    head.update(req.entity.as_deref().unwrap_or("").as_bytes());
    head.update(&[0]);
    head.update(req.query.as_deref().unwrap_or("").as_bytes());
    head.update(&req.token_budget.unwrap_or(0).to_le_bytes());
    // Freshness epoch (hour bucket).
    head.update(&(now_ms / 3_600_000).to_le_bytes());

    AssemblyKey {
        passport: principal.to_string(),
        session_id: req.session_id.clone(),
        facts_chain_head: format!("blake3:{}", head.finalize().to_hex()),
    }
}

// ── Receipting (spec §4 rule 7) ───────────────────────────────────────────

fn bundle_fact_ids(bundle: &ContextBundle) -> Vec<String> {
    bundle
        .stable
        .sections
        .iter()
        .flat_map(|s| s.facts.iter().map(|f| f.fact_id.clone()))
        .collect()
}

/// Mint a mediation-class receipt for the assembled bundle through the
/// signed-observation path. Best-effort: assembly is a read, and a node
/// without a passport key must still serve bundles (free tier, T.5) — a
/// minting failure is reported in the volatile region, never a 500.
fn mint_bundle_receipt(
    state: &AppState,
    principal: &str,
    session_id: Option<&str>,
    bundle: &ContextBundle,
) -> Result<String, String> {
    let section_counts: Vec<Value> = bundle
        .stable
        .sections
        .iter()
        .map(|s| {
            json!({
                "kind": s.kind.as_str(),
                "count": s.facts.len() + s.items.len(),
                "est_tokens": s.est_tokens,
            })
        })
        .collect();
    let body = PostObservationBody {
        kind: "context.bundle.assembled.v1".to_string(),
        provider: "crux-context-surface".to_string(),
        client_ts: None,
        payload: json!({
            "bundle_version": BUNDLE_VERSION,
            "stable_hash": bundle.stable_hash,
            "budget": bundle.budget,
            "section_counts": section_counts,
            "fact_ids": bundle_fact_ids(bundle),
            "session_id": session_id,
        }),
    };
    let scoped = format!("context::{principal}");
    append_one(state, &scoped, principal, body, None)
        .map(|(resp, _tip)| resp.observation_id)
        .map_err(|(_, msg)| msg)
}

// ── Renderers (spec §7) ───────────────────────────────────────────────────

/// Markdown renderer — boot-banner shape. Canonical stable prefix FIRST
/// (the prompt prefix providers cache on), this surface's volatile trailer
/// (incl. `receipt_ref`) last.
fn render_markdown(bundle_json: &Value, bundle: &ContextBundle) -> String {
    use std::fmt::Write as _;
    let mut out = render_markdown_stable(&bundle.stable);
    out.push_str("\n---\n");
    let _ = writeln!(
        out,
        "assembled_at: {} · stable_hash: {} · receipt: {} · budget: {}/{} (ceiling {})",
        bundle_json.get("assembled_at").and_then(Value::as_str).unwrap_or(""),
        bundle_json.get("stable_hash").and_then(Value::as_str).unwrap_or(""),
        bundle_json.get("receipt_ref").and_then(Value::as_str).unwrap_or("none"),
        bundle_json["budget"]["spent_est"].as_u64().unwrap_or(0),
        bundle_json["budget"]["requested"].as_u64().unwrap_or(0),
        bundle_json["budget"]["ceiling"].as_u64().unwrap_or(0),
    );
    out
}

/// OpenAI messages-array fragment: canonical stable markdown as one system
/// message, volatile metadata in a separate field (so the prefix stays
/// cacheable).
fn render_openai_messages(bundle_json: &Value, bundle: &ContextBundle) -> Value {
    json!({
        "bundle_version": BUNDLE_VERSION,
        "messages": [
            {"role": "system", "content": render_markdown_stable(&bundle.stable)}
        ],
        "metadata": {
            "stable_hash": bundle_json.get("stable_hash"),
            "assembled_at": bundle_json.get("assembled_at"),
            "receipt_ref": bundle_json.get("receipt_ref"),
            "budget": bundle_json.get("budget"),
        }
    })
}

// ── Handlers ──────────────────────────────────────────────────────────────

fn context_disabled_response() -> Response {
    problem_response(
        StatusCode::NOT_FOUND,
        "context surface disabled (set CORECRUXD_CONTEXT_SURFACE=1)".to_string(),
    )
    .into_response()
}

async fn handle_context(state: AppState, headers: HeaderMap, req: ContextRequest) -> Response {
    if !state.context_surface_enabled {
        return context_disabled_response();
    }
    // T.3: existing auth model only — read scopes, 401 unauthenticated
    // (regression class: tenant-isolation-shipped-2026-06-11).
    let ctx = match super::facts::require_fact_read_ctx(&state, &headers) {
        Ok(ctx) => ctx,
        Err(resp) => return resp,
    };

    // Attribution: caller passport when bound, else the operator tag
    // (anonymous writes are operator-tagged, not silently allowed —
    // audit-hygiene profile).
    let principal = ctx.passport_id.clone().unwrap_or_else(|| "operator".to_string());
    let bundle_req = cb::BundleRequest {
        actor: principal.clone(),
        // Local daemon: single-tenant store; tenant identity rides the
        // passport scoping already enforced at fetch time.
        tenant_id: "local".to_string(),
        session_id: req.session_id.clone(),
        requested_budget: req.token_budget.unwrap_or(DEFAULT_REQUESTED_BUDGET),
        ceiling: FREE_TIER_CEILING,
        now_ms: chrono::Utc::now().timestamp_millis(),
        policy: decay::DecayPolicy::from_env(),
    };

    // G21b assembly cache (CORECRUXD_ASSEMBLY_CACHE, default OFF →
    // `assembly_cache` is None and this surface behaves exactly as
    // before). A hit skips gather + assemble entirely; the receipt below
    // is still minted per serve (every serve is receipted).
    let cache_key = if state.assembly_cache.is_some() {
        Some(assembly_cache_key(&state, &ctx, &req, &principal, bundle_req.now_ms).await)
    } else {
        None
    };
    let cached: Option<ContextBundle> = match (&state.assembly_cache, &cache_key) {
        (Some(cache), Some(key)) => {
            let mut cache = cache.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            cache.get(key).cloned()
        }
        _ => None,
    };
    let bundle = if let Some(bundle) = cached {
        bundle
    } else {
        let facts = gather_facts(&state, &ctx, &req).await;
        let aux: Vec<AuxSection> = gather_session_state(&state, &ctx, &req).await.into_iter().collect();
        let bundle = cb::assemble(&bundle_req, facts, aux);
        if let (Some(cache), Some(key)) = (&state.assembly_cache, cache_key) {
            let mut cache = cache.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            cache.insert(key, bundle.clone());
        }
        bundle
    };

    // Receipt the assembly (spec §4 rule 7).
    let (receipt_ref, receipt_error) = match mint_bundle_receipt(&state, &principal, req.session_id.as_deref(), &bundle)
    {
        Ok(id) => (Some(id), None),
        Err(e) => (None, Some(e)),
    };

    let mut bundle_json = json!({
        "bundle_version": bundle.stable.bundle_version,
        "passport": ctx.passport_id,
        "session_id": req.session_id,
        "assembled_at": chrono::Utc::now().to_rfc3339(),
        "budget": bundle.budget,
        "sections": bundle.stable.sections,
        "stable_hash": bundle.stable_hash,
        "receipt_ref": receipt_ref,
    });
    if let Some(err) = receipt_error {
        bundle_json["receipt_error"] = Value::String(err);
    }

    match req.render.as_deref().unwrap_or("json") {
        "markdown" => {
            let md = render_markdown(&bundle_json, &bundle);
            (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "text/markdown; charset=utf-8")],
                md,
            )
                .into_response()
        }
        "openai_messages" => (StatusCode::OK, Json(render_openai_messages(&bundle_json, &bundle))).into_response(),
        "json" => (StatusCode::OK, Json(bundle_json)).into_response(),
        other => problem_response(
            StatusCode::BAD_REQUEST,
            format!("unknown render '{other}' (expected json | markdown | openai_messages)"),
        )
        .into_response(),
    }
}

/// `GET /v1/context` — assemble an injection bundle from query parameters.
#[utoipa::path(
    get,
    path = "/v1/context",
    tag = "Context",
    params(ContextRequest),
    responses(
        (status = 200, description = "context_bundle/v1 injection bundle"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Surface disabled (CORECRUXD_CONTEXT_SURFACE unset)"),
    ),
    security(("bearer_auth" = []))
)]
pub(super) async fn get_context(
    State(state): State<AppState>,
    Query(req): Query<ContextRequest>,
    headers: HeaderMap,
) -> Response {
    handle_context(state, headers, req).await
}

/// `POST /v1/context` — same surface, JSON body (for harnesses that prefer
/// a body over a query string).
#[utoipa::path(
    post,
    path = "/v1/context",
    tag = "Context",
    request_body = ContextRequest,
    responses(
        (status = 200, description = "context_bundle/v1 injection bundle"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Surface disabled (CORECRUXD_CONTEXT_SURFACE unset)"),
    ),
    security(("bearer_auth" = []))
)]
pub(super) async fn post_context(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ContextRequest>,
) -> Response {
    handle_context(state, headers, req).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AuthMode;
    use crate::http::tests::{test_app_state, test_app_state_with_auth};
    use axum::body::to_bytes;
    use axum::extract::{Json as JsonExtract, Query as QueryExtract, State as StateExtract};

    async fn body_json(resp: Response) -> Value {
        let bytes = to_bytes(resp.into_body(), 1 << 22).await.expect("read body");
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    }

    fn new_fact(entity: &str, key: &str, value: &str, private: bool) -> corecrux_memory::fact_store::StoreFact {
        corecrux_memory::fact_store::StoreFact {
            entity: entity.to_string(),
            key: key.to_string(),
            value: value.to_string(),
            source_receipt: None,
            confidence: 1.0,
            private,
            horizon_class: None,
            actor: None,
        }
    }

    async fn store_fact(state: &AppState, entity: &str, key: &str, value: &str) -> corecrux_memory::fact_store::Fact {
        let mut s = state.fact_store.write().await;
        s.try_store(new_fact(entity, key, value, false)).expect("store fact")
    }

    fn req(entity: Option<&str>, query: Option<&str>, budget: Option<usize>) -> ContextRequest {
        ContextRequest {
            session_id: None,
            entity: entity.map(str::to_string),
            query: query.map(str::to_string),
            token_budget: budget,
            render: None,
        }
    }

    async fn get_bundle(state: &AppState, request: ContextRequest) -> Value {
        let resp = get_context(StateExtract(state.clone()), QueryExtract(request), HeaderMap::new())
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        body_json(resp).await
    }

    fn enabled_state() -> AppState {
        let mut state = test_app_state(1);
        state.context_surface_enabled = true;
        state
    }

    fn facts_items(bundle: &Value) -> &Vec<Value> {
        bundle["sections"]
            .as_array()
            .expect("sections")
            .iter()
            .find(|s| s["kind"] == "facts")
            .expect("facts section")["facts"]
            .as_array()
            .expect("facts items")
    }

    #[tokio::test]
    async fn disabled_flag_returns_404() {
        let mut state = test_app_state(1);
        state.context_surface_enabled = false;
        let resp = get_context(
            StateExtract(state.clone()),
            QueryExtract(req(None, None, None)),
            HeaderMap::new(),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let resp = post_context(
            StateExtract(state),
            HeaderMap::new(),
            JsonExtract(req(None, None, None)),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn unauthenticated_returns_401_when_auth_on() {
        // Regression class: tenant-isolation-shipped-2026-06-11 (a new
        // surface must never be an unauthenticated read).
        let mut state = test_app_state_with_auth(1, AuthMode::DevScopes);
        state.context_surface_enabled = true;
        let resp = get_context(
            StateExtract(state),
            QueryExtract(req(None, None, None)),
            HeaderMap::new(),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn bundle_shape_and_addressed_recall() {
        let state = enabled_state();
        store_fact(&state, "execplan:demo", "milestone:M1", "shipped").await;
        store_fact(&state, "other-entity", "note", "unrelated").await;

        let bundle = get_bundle(&state, req(Some("execplan:demo"), None, Some(2000))).await;
        assert_eq!(bundle["bundle_version"], BUNDLE_VERSION);
        assert!(bundle["stable_hash"].as_str().unwrap_or("").starts_with("blake3:"));
        let items = facts_items(&bundle);
        assert!(items
            .iter()
            .any(|i| i["entity"] == "execplan:demo" && i["key"] == "milestone:M1"));
        // Item carries provenance + class-only freshness, no volatile fields.
        let item = &items[0];
        assert!(item.get("fact_id").is_some());
        assert!(item.get("freshness").is_some());
        assert!(item.get("age_hours").is_none(), "continuous values are volatile");
        assert!(
            item.get("effective_confidence").is_none(),
            "continuous values are volatile"
        );
    }

    #[tokio::test]
    async fn stable_region_is_byte_stable_across_calls() {
        let state = enabled_state();
        store_fact(&state, "execplan:demo", "decision:arch", "exposed via /v1/context").await;
        store_fact(&state, "bench:lme-s", "baseline", "91.7%").await;

        let a = get_bundle(&state, req(None, Some("demo baseline"), Some(2000))).await;
        let b = get_bundle(&state, req(None, Some("demo baseline"), Some(2000))).await;
        assert_eq!(
            a["stable_hash"], b["stable_hash"],
            "unchanged store => identical stable hash"
        );
        assert_eq!(
            a["sections"], b["sections"],
            "unchanged store => byte-identical stable region"
        );
        // Volatile region may differ; the receipt ref must not be hashed.
        assert!(a["stable_hash"].as_str().unwrap().starts_with("blake3:"));
    }

    #[tokio::test]
    async fn budget_is_honored_and_truncation_is_explicit() {
        let state = enabled_state();
        for i in 0..40 {
            store_fact(&state, &format!("entity-{i:02}"), "k", &"long value text ".repeat(40)).await;
        }
        let bundle = get_bundle(&state, req(None, Some("long value"), Some(500))).await;
        let spent = bundle["budget"]["spent_est"].as_u64().expect("spent");
        assert!(spent <= 500, "spent_est {spent} must be <= requested 500");
        let dropped = bundle["budget"]["dropped"].as_array().expect("dropped");
        assert!(
            dropped.iter().any(|d| d["kind"] == "facts" && d["reason"] == "budget"),
            "truncation must be explicit: {dropped:?}"
        );
        assert_eq!(bundle["budget"]["ceiling"], FREE_TIER_CEILING as u64);
    }

    #[tokio::test]
    async fn requested_budget_is_capped_by_ceiling() {
        let state = enabled_state();
        store_fact(&state, "e", "k", "v").await;
        let bundle = get_bundle(&state, req(None, None, Some(1_000_000))).await;
        assert_eq!(bundle["budget"]["requested"], 1_000_000u64);
        let spent = bundle["budget"]["spent_est"].as_u64().expect("spent");
        assert!(spent <= FREE_TIER_CEILING as u64);
    }

    #[tokio::test]
    async fn superseded_fact_excluded_successor_present() {
        let state = enabled_state();
        let old = store_fact(&state, "bench:lme-s", "baseline", "86.8%").await;
        let new = store_fact(&state, "bench:lme-s", "baseline-2026", "91.7%").await;
        {
            let mut s = state.fact_store.write().await;
            assert!(s.mark_superseded(&old.fact_id, &new.fact_id), "mark superseded");
        }
        let bundle = get_bundle(&state, req(Some("bench:lme-s"), None, Some(2000))).await;
        let items = facts_items(&bundle);
        assert!(
            !items.iter().any(|i| i["fact_id"] == old.fact_id.as_str()),
            "superseded fact must never appear"
        );
        assert!(
            items.iter().any(|i| i["fact_id"] == new.fact_id.as_str()),
            "successor must appear"
        );
    }

    #[tokio::test]
    async fn private_fact_of_other_agent_is_isolated() {
        let state = enabled_state();
        // A private fact owned by a different agent identity must never
        // enter the caller's bundle (spec §4 rules 5–6).
        {
            // Ownership rides the `__agent::<owner>::` entity prefix (see
            // crux_mcp::scope::visible_entity_for_agent).
            let mut s = state.fact_store.write().await;
            s.try_store(new_fact(
                "__agent::other-agent::secret-project",
                "k",
                "other agent's private note",
                true,
            ))
            .expect("store private fact");
        }
        store_fact(&state, "public-entity", "k", "public note").await;

        // Caller bound to a different passport: private fact invisible.
        let mut headers = HeaderMap::new();
        headers.insert("x-corecrux-passport-id", "caller-agent".parse().unwrap());
        let resp = get_context(
            StateExtract(state.clone()),
            QueryExtract(req(None, Some("note"), Some(2000))),
            headers,
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let bundle = body_json(resp).await;
        let as_text = serde_json::to_string(&bundle["sections"]).expect("serialize");
        assert!(
            !as_text.contains("other agent's private note"),
            "cross-agent private fact leaked into bundle"
        );
        assert!(as_text.contains("public note"), "public fact should be present");
    }

    #[tokio::test]
    async fn private_fact_with_recorded_owner_is_owner_only() {
        // Defense-in-depth re-check inside the canonical assembler: a
        // private fact whose `actor` is recorded only enters its owner's
        // bundle (spec §4.6) — even if fetch-time visibility passes.
        let state = enabled_state();
        {
            let mut s = state.fact_store.write().await;
            let mut fact = new_fact("notes", "k", "owner-only secret", true);
            fact.actor = Some("owner-agent".to_string());
            s.try_store(fact).expect("store");
        }
        store_fact(&state, "public-entity", "k", "public note").await;

        // Operator caller (no passport): the owned private fact is excluded.
        let bundle = get_bundle(&state, req(None, Some("note secret"), Some(2000))).await;
        let as_text = serde_json::to_string(&bundle["sections"]).expect("serialize");
        assert!(!as_text.contains("owner-only secret"));
    }

    #[tokio::test]
    async fn session_state_section_included_when_requested() {
        let state = enabled_state();
        {
            let mut s = state.session_store.write().await;
            s.put("sess-1", json!({"summary": "resumed from M1", "next": "M2"}), None);
        }
        let bundle = get_bundle(
            &state,
            ContextRequest {
                session_id: Some("sess-1".to_string()),
                ..req(None, None, Some(2000))
            },
        )
        .await;
        let sections = bundle["sections"].as_array().expect("sections");
        let ss = sections
            .iter()
            .find(|s| s["kind"] == "session_state")
            .expect("session_state section");
        // Canonical AuxItem shape: deterministic `id` + rendered `text`.
        assert_eq!(ss["items"][0]["id"], "sess-1");
        let text = ss["items"][0]["text"].as_str().expect("text");
        assert!(
            text.contains("\"next\":\"M2\""),
            "state must ride in the item text: {text}"
        );
        assert!(!text.contains("updated_at"), "no timestamps in stable region");
    }

    #[tokio::test]
    async fn markdown_render_places_stable_prefix_first() {
        let state = enabled_state();
        store_fact(&state, "e1", "k1", "v1").await;
        let resp = get_context(
            StateExtract(state.clone()),
            QueryExtract(ContextRequest {
                render: Some("markdown".to_string()),
                ..req(None, None, Some(2000))
            }),
            HeaderMap::new(),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = to_bytes(resp.into_body(), 1 << 22).await.expect("body");
        let md = String::from_utf8(bytes.to_vec()).expect("utf8");
        assert!(md.starts_with("## Crux Context (context_bundle/v1)"));
        let stable_end = md.find("\n---\n").expect("volatile trailer present");
        let trailer = &md[stable_end..];
        assert!(
            trailer.contains("assembled_at:"),
            "volatile material rides after the stable prefix"
        );
        assert!(
            !md[..stable_end].contains("assembled_at"),
            "no timestamps in the stable prefix"
        );
    }

    #[tokio::test]
    async fn openai_messages_render_shape() {
        let state = enabled_state();
        store_fact(&state, "e1", "k1", "v1").await;
        let bundle = {
            let resp = get_context(
                StateExtract(state.clone()),
                QueryExtract(ContextRequest {
                    render: Some("openai_messages".to_string()),
                    ..req(None, None, Some(2000))
                }),
                HeaderMap::new(),
            )
            .await
            .into_response();
            assert_eq!(resp.status(), StatusCode::OK);
            body_json(resp).await
        };
        assert_eq!(bundle["bundle_version"], BUNDLE_VERSION);
        assert_eq!(bundle["messages"][0]["role"], "system");
        assert!(bundle["messages"][0]["content"]
            .as_str()
            .expect("content")
            .starts_with("## Crux Context"));
        assert!(bundle["metadata"]["stable_hash"].as_str().is_some());
    }

    // ── G21b assembly-cache wiring (CORECRUXD_ASSEMBLY_CACHE) ────────────

    fn cached_state() -> AppState {
        let mut state = enabled_state();
        state.assembly_cache = Some(std::sync::Arc::new(std::sync::Mutex::new(
            corecrux_projections::assembly_cache::AssemblyCache::new(8),
        )));
        state
    }

    fn cache_stats(state: &AppState) -> corecrux_projections::assembly_cache::CacheStats {
        state
            .assembly_cache
            .as_ref()
            .expect("cache enabled")
            .lock()
            .expect("lock")
            .stats()
    }

    #[tokio::test]
    async fn assembly_cache_hits_on_identical_request() {
        let state = cached_state();
        store_fact(&state, "execplan:demo", "milestone:M1", "shipped").await;

        let a = get_bundle(&state, req(None, Some("shipped"), Some(2000))).await;
        let b = get_bundle(&state, req(None, Some("shipped"), Some(2000))).await;
        assert_eq!(a["stable_hash"], b["stable_hash"]);
        assert_eq!(a["sections"], b["sections"]);
        let stats = cache_stats(&state);
        assert_eq!(stats.misses, 1, "first request assembles");
        assert_eq!(stats.hits, 1, "second identical request is served from the memo");
        // Every serve is receipted, hit or miss.
        assert!(b["receipt_ref"].as_str().is_some() || b.get("receipt_error").is_some());
    }

    #[tokio::test]
    async fn fact_write_moves_the_chain_head_and_invalidates() {
        let state = cached_state();
        store_fact(&state, "execplan:demo", "milestone:M1", "shipped").await;
        let _ = get_bundle(&state, req(None, None, Some(2000))).await;

        // A fact write between requests → structural miss, fresh assembly
        // that includes the new fact.
        store_fact(&state, "bench:lme-s", "baseline", "91.7%").await;
        let bundle = get_bundle(&state, req(None, None, Some(2000))).await;
        let stats = cache_stats(&state);
        assert_eq!(stats.hits, 0, "chain head moved — the stale entry must not serve");
        assert_eq!(stats.misses, 2);
        assert!(facts_items(&bundle).iter().any(|i| i["entity"] == "bench:lme-s"));
    }

    #[tokio::test]
    async fn request_shape_is_part_of_the_cache_identity() {
        let state = cached_state();
        store_fact(&state, "execplan:demo", "milestone:M1", "shipped").await;
        store_fact(&state, "bench:lme-s", "baseline", "91.7%").await;

        let a = get_bundle(&state, req(Some("execplan:demo"), None, Some(2000))).await;
        let b = get_bundle(&state, req(Some("bench:lme-s"), None, Some(2000))).await;
        assert_ne!(
            a["sections"], b["sections"],
            "different addresses are different bundles"
        );
        assert_eq!(cache_stats(&state).hits, 0, "different request shapes must not collide");
    }

    #[tokio::test]
    async fn session_state_change_invalidates() {
        let state = cached_state();
        {
            let mut s = state.session_store.write().await;
            s.put("sess-1", json!({"next": "M2"}), None);
        }
        let request = || ContextRequest {
            session_id: Some("sess-1".to_string()),
            ..req(None, None, Some(2000))
        };
        let _ = get_bundle(&state, request()).await;
        {
            let mut s = state.session_store.write().await;
            s.put("sess-1", json!({"next": "M3"}), None);
        }
        let bundle = get_bundle(&state, request()).await;
        assert_eq!(cache_stats(&state).hits, 0, "session-state change must invalidate");
        let as_text = serde_json::to_string(&bundle["sections"]).expect("serialize");
        assert!(as_text.contains("M3"), "fresh session state must be served");
    }

    #[tokio::test]
    async fn unknown_render_is_rejected() {
        let state = enabled_state();
        let resp = get_context(
            StateExtract(state),
            QueryExtract(ContextRequest {
                render: Some("xml".to_string()),
                ..req(None, None, None)
            }),
            HeaderMap::new(),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
