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
//! Gating: `CORECRUXD_CONTEXT_SURFACE=1`, default OFF. When off the routes
//! return 404 so the surface is invisible rather than half-alive (same
//! convention as the coord plane).
//!
//! Determinism: the *stable region* (`bundle_version` + ordered `sections`)
//! is byte-stable for an unchanged fact-chain head and is hashed with blake3
//! (`stable_hash`) so provider-side prompt caches hit on the injected prefix.
//! Volatile material (`assembled_at`, `budget`, `receipt_ref`, identity
//! echo) lives outside the stable region.
//!
//! TODO(context-mediation-injection-2026-06-11): replace [`assemble`] with
//! `corecrux_projections::context_bundle::assemble` (commit `0664614` on
//! branch `feat/context-mediation-injection-2026-06-11`, 13 unit tests) once
//! that PR merges. The local types below deliberately mirror that crate's
//! `BundleRequest` / `FactInput` / `StableRegion` API so the swap is a
//! mechanical call-site change — do not grow divergent behaviour here.

use corecrux_projections::decay;
use serde_json::{json, Value};

use super::observations::{append_one, PostObservationBody};
use super::{problem_response, AppState, HeaderMap, IntoResponse, Json, Query, Response, State, StatusCode};

/// Bundle schema version — the only field consumers may dispatch on.
pub(super) const BUNDLE_VERSION: &str = "context_bundle/v1";

/// Default `budget.requested` when the caller omits `token_budget`
/// (free/local tier default per spec §5 — the house "scan" budget).
const DEFAULT_REQUESTED_TOKENS: usize = 2000;

/// Hard per-assembly ceiling for the free/local tier (spec §5). The
/// anti-bloat backstop: the bundle must never become the token problem it
/// solves.
const FREE_TIER_CEILING_TOKENS: usize = 8000;

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

// ── Bundle types (mirror corecrux_projections::context_bundle, see TODO) ──

/// One fact row inside the stable region. Continuous values (`age_hours`,
/// `effective_confidence`) are deliberately ABSENT: only the freshness
/// *class* may appear, the one sanctioned source of stable-region change
/// without a fact write (spec §3).
#[derive(Debug, Clone, serde::Serialize)]
pub(super) struct StableFactItem {
    pub fact_id: String,
    pub entity: String,
    pub key: String,
    pub value: String,
    pub confidence: f32,
    pub horizon_class: String,
    pub freshness: String,
    pub est_tokens: usize,
}

/// One section of the stable region. Order of sections and order of items
/// within a section are normative (spec §2, §6).
#[derive(Debug, Clone, serde::Serialize)]
pub(super) struct StableSection {
    pub kind: String,
    pub items: Vec<Value>,
    pub est_tokens: usize,
}

/// The hashed, byte-stable prefix: `bundle_version` + ordered sections.
/// No timestamps, no receipt ids, no random ids (spec §6).
#[derive(Debug, Clone, serde::Serialize)]
pub(super) struct StableRegion {
    pub bundle_version: String,
    pub sections: Vec<StableSection>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(super) struct DroppedReport {
    pub kind: String,
    pub count: usize,
    pub reason: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(super) struct BudgetReport {
    pub requested: usize,
    pub spent_est: usize,
    pub ceiling: usize,
    pub dropped: Vec<DroppedReport>,
}

/// Assembly inputs (mirrors the mediation assembler's `BundleRequest`).
pub(super) struct BundleRequest {
    pub requested_tokens: usize,
    pub ceiling_tokens: usize,
}

/// A selected fact in *selection* order (addressed first, then effective-
/// confidence rank). Presentation order is recomputed at render time.
pub(super) struct FactInput {
    pub item: StableFactItem,
    /// True when this fact was resolved via a typed address (exact entity).
    pub addressed: bool,
    /// Recall-time effective confidence — used for SELECTION only; never
    /// serialized into the stable region (volatile, spec §3).
    pub effective_confidence: f64,
}

pub(super) struct AssembledBundle {
    pub stable: StableRegion,
    pub stable_hash: String,
    pub budget: BudgetReport,
    pub fact_ids: Vec<String>,
}

/// Deterministic serialization of the stable region. Struct field order is
/// fixed by the type definitions; item order is enforced by [`assemble`].
pub(super) fn stable_region_bytes(stable: &StableRegion) -> Vec<u8> {
    serde_json::to_vec(stable).unwrap_or_default()
}

pub(super) fn hash_stable_region(stable: &StableRegion) -> String {
    format!("blake3:{}", blake3::hash(&stable_region_bytes(stable)).to_hex())
}

/// Pure, deterministic interim assembler.
///
/// Selection: addressed facts first, then effective-confidence rank, walking
/// the budget. Presentation: items re-sorted by `(entity, key, fact_id)` —
/// never by retrieval-score ties (spec §6). Truncation is explicit via
/// `dropped`, never silent.
pub(super) fn assemble(
    req: &BundleRequest,
    mut facts: Vec<FactInput>,
    session_state: Option<(Value, usize)>,
) -> AssembledBundle {
    let ceiling = req.ceiling_tokens;
    let budget_limit = req.requested_tokens.min(ceiling);

    // Selection order: addressed first, then effective confidence desc,
    // tie-broken deterministically by (entity, key, fact_id).
    facts.sort_by(|a, b| {
        b.addressed
            .cmp(&a.addressed)
            .then_with(|| {
                b.effective_confidence
                    .partial_cmp(&a.effective_confidence)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| {
                (&a.item.entity, &a.item.key, &a.item.fact_id).cmp(&(&b.item.entity, &b.item.key, &b.item.fact_id))
            })
    });

    let mut spent = 0usize;
    let mut dropped: Vec<DroppedReport> = Vec::new();
    let mut selected: Vec<StableFactItem> = Vec::new();
    let mut dropped_facts = 0usize;
    for f in facts {
        if spent + f.item.est_tokens > budget_limit && !selected.is_empty() {
            dropped_facts += 1;
            continue;
        }
        if spent + f.item.est_tokens > budget_limit {
            // First fact alone blows the budget: still drop it (explicitly).
            dropped_facts += 1;
            continue;
        }
        spent += f.item.est_tokens;
        selected.push(f.item);
    }
    if dropped_facts > 0 {
        dropped.push(DroppedReport {
            kind: "facts".to_string(),
            count: dropped_facts,
            reason: "budget".to_string(),
        });
    }

    // Presentation order (spec §6): (entity, key, fact_id).
    selected.sort_by(|a, b| (&a.entity, &a.key, &a.fact_id).cmp(&(&b.entity, &b.key, &b.fact_id)));
    let fact_ids: Vec<String> = selected.iter().map(|f| f.fact_id.clone()).collect();

    let mut sections: Vec<StableSection> = Vec::new();
    if !selected.is_empty() {
        let est: usize = selected.iter().map(|f| f.est_tokens).sum();
        sections.push(StableSection {
            kind: "facts".to_string(),
            items: selected
                .into_iter()
                .map(|f| serde_json::to_value(f).unwrap_or(Value::Null))
                .collect(),
            est_tokens: est,
        });
    }

    // session_state rides after facts (spec §4 order: facts → dossier →
    // session_state → work_table → coord; dossier/work_table/coord are
    // TODO(context-mediation-injection-2026-06-11) — they ship with the
    // mediation assembler swap).
    if let Some((state_item, est_tokens)) = session_state {
        if spent + est_tokens <= budget_limit {
            spent += est_tokens;
            sections.push(StableSection {
                kind: "session_state".to_string(),
                items: vec![state_item],
                est_tokens,
            });
        } else {
            dropped.push(DroppedReport {
                kind: "session_state".to_string(),
                count: 1,
                reason: "budget".to_string(),
            });
        }
    }

    let stable = StableRegion {
        bundle_version: BUNDLE_VERSION.to_string(),
        sections,
    };
    let stable_hash = hash_stable_region(&stable);
    AssembledBundle {
        stable,
        stable_hash,
        budget: BudgetReport {
            requested: req.requested_tokens,
            spent_est: spent,
            ceiling,
            dropped,
        },
        fact_ids,
    }
}

// ── Fact gathering (tenant/passport-scoped, supersession-aware) ──────────

fn projection_class(class: corecrux_memory::fact_store::HorizonClass) -> decay::HorizonClass {
    decay::HorizonClass::parse(class.as_str()).unwrap_or(decay::HorizonClass::None)
}

fn fact_input(
    fact: corecrux_memory::fact_store::Fact,
    addressed: bool,
    now: chrono::DateTime<chrono::Utc>,
    policy: decay::DecayPolicy,
) -> FactInput {
    let class = projection_class(fact.horizon_class);
    let fresh = decay::apply_at_chrono(class, fact.stored_at, fact.reverified_at, now, policy);
    let effective = decay::effective_confidence(f64::from(fact.confidence), fresh);
    FactInput {
        item: StableFactItem {
            fact_id: fact.fact_id,
            entity: fact.entity,
            key: fact.key,
            value: fact.value,
            confidence: fact.confidence,
            horizon_class: class.as_str().to_string(),
            // Class only — the one sanctioned stable-region freshness signal.
            freshness: fresh.as_str().to_string(),
            est_tokens: fact.tokens,
        },
        addressed,
        effective_confidence: effective,
    }
}

/// Gather candidate facts under the caller's scope. Superseded facts are
/// excluded (spec §4 rule 2); stale facts are included with their `stale`
/// annotation, never silently presented as current.
async fn gather_facts(state: &AppState, ctx: &crate::auth::HttpScopeContext, req: &ContextRequest) -> Vec<FactInput> {
    let now = chrono::Utc::now();
    let policy = decay::DecayPolicy::from_env();
    let store = state.fact_store.read().await;

    let mut out: Vec<FactInput> = Vec::new();
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
            out.push(fact_input(fact, true, now, policy));
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
            out.push(fact_input(fact, false, now, policy));
        }
    }
    out
}

/// Saved session state for the requested session, scoped to the caller.
/// Stable item carries no timestamps (spec §6) — `updated_at` is excluded.
async fn gather_session_state(
    state: &AppState,
    ctx: &crate::auth::HttpScopeContext,
    req: &ContextRequest,
) -> Option<(Value, usize)> {
    let session_id = req.session_id.as_deref().map(str::trim).filter(|s| !s.is_empty())?;
    let scoped = super::facts::scoped_session_id_for_http(ctx, session_id);
    let store = state.session_store.read().await;
    let session = store.get(&scoped)?;
    let est = session
        .total_tokens
        .max(serde_json::to_string(&session.state).map(|s| s.len() / 4).unwrap_or(0));
    Some((
        json!({
            "session_id": session_id,
            "state": session.state,
            "est_tokens": est,
        }),
        est,
    ))
}

// ── Receipting (spec §4 rule 7) ───────────────────────────────────────────

/// Mint a mediation-class receipt for the assembled bundle through the
/// signed-observation path. Best-effort: assembly is a read, and a node
/// without a passport key must still serve bundles (free tier, T.5) — a
/// minting failure is reported in the volatile region, never a 500.
fn mint_bundle_receipt(
    state: &AppState,
    principal: &str,
    session_id: Option<&str>,
    bundle: &AssembledBundle,
) -> Result<String, String> {
    let section_counts: Vec<Value> = bundle
        .stable
        .sections
        .iter()
        .map(|s| json!({"kind": s.kind, "count": s.items.len(), "est_tokens": s.est_tokens}))
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
            "fact_ids": bundle.fact_ids,
            "session_id": session_id,
        }),
    };
    let scoped = format!("context::{principal}");
    append_one(state, &scoped, principal, body, None)
        .map(|(resp, _tip)| resp.observation_id)
        .map_err(|(_, msg)| msg)
}

// ── Renderers (spec §7) ───────────────────────────────────────────────────

/// Markdown renderer — boot-banner shape. Stable region FIRST (the prompt
/// prefix providers cache on), volatile trailer last.
pub(super) fn render_markdown_stable(stable: &StableRegion) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(out, "# Crux Context Bundle ({})", stable.bundle_version);
    for section in &stable.sections {
        let _ = write!(out, "\n## {}\n\n", section.kind);
        match section.kind.as_str() {
            "facts" => {
                out.push_str("| entity | key | value | confidence | freshness |\n");
                out.push_str("|---|---|---|---|---|\n");
                for item in &section.items {
                    let _ = writeln!(
                        out,
                        "| {} | {} | {} | {:.2} | {} |",
                        item.get("entity").and_then(Value::as_str).unwrap_or(""),
                        item.get("key").and_then(Value::as_str).unwrap_or(""),
                        item.get("value")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .replace('\n', " "),
                        item.get("confidence").and_then(Value::as_f64).unwrap_or(0.0),
                        item.get("freshness").and_then(Value::as_str).unwrap_or("unknown"),
                    );
                }
            }
            _ => {
                for item in &section.items {
                    let _ = writeln!(
                        out,
                        "```json\n{}\n```",
                        serde_json::to_string_pretty(item).unwrap_or_default()
                    );
                }
            }
        }
    }
    out
}

fn render_markdown(bundle_json: &Value, stable: &StableRegion) -> String {
    use std::fmt::Write as _;
    let mut out = render_markdown_stable(stable);
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

/// OpenAI messages-array fragment: stable markdown as one system message,
/// volatile metadata in a separate field (so the prefix stays cacheable).
fn render_openai_messages(bundle_json: &Value, stable: &StableRegion) -> Value {
    json!({
        "bundle_version": BUNDLE_VERSION,
        "messages": [
            {"role": "system", "content": render_markdown_stable(stable)}
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

    let requested = req.token_budget.unwrap_or(DEFAULT_REQUESTED_TOKENS);
    let bundle_req = BundleRequest {
        requested_tokens: requested,
        ceiling_tokens: FREE_TIER_CEILING_TOKENS,
    };

    let facts = gather_facts(&state, &ctx, &req).await;
    let session_state = gather_session_state(&state, &ctx, &req).await;
    let bundle = assemble(&bundle_req, facts, session_state);

    // Receipt the assembly (spec §4 rule 7). Attribution: caller passport
    // when bound, else the operator tag (anonymous writes are operator-
    // tagged, not silently allowed — audit-hygiene profile).
    let principal = ctx.passport_id.clone().unwrap_or_else(|| "operator".to_string());
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
            let md = render_markdown(&bundle_json, &bundle.stable);
            (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "text/markdown; charset=utf-8")],
                md,
            )
                .into_response()
        }
        "openai_messages" => (
            StatusCode::OK,
            Json(render_openai_messages(&bundle_json, &bundle.stable)),
        )
            .into_response(),
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
        let sections = bundle["sections"].as_array().expect("sections");
        let facts = sections.iter().find(|s| s["kind"] == "facts").expect("facts section");
        let items = facts["items"].as_array().expect("items");
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
        assert_eq!(bundle["budget"]["ceiling"], FREE_TIER_CEILING_TOKENS as u64);
    }

    #[tokio::test]
    async fn requested_budget_is_capped_by_ceiling() {
        let state = enabled_state();
        store_fact(&state, "e", "k", "v").await;
        let bundle = get_bundle(&state, req(None, None, Some(1_000_000))).await;
        assert_eq!(bundle["budget"]["requested"], 1_000_000u64);
        let spent = bundle["budget"]["spent_est"].as_u64().expect("spent");
        assert!(spent <= FREE_TIER_CEILING_TOKENS as u64);
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
        let items = bundle["sections"][0]["items"].as_array().expect("items");
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
        assert_eq!(ss["items"][0]["session_id"], "sess-1");
        assert_eq!(ss["items"][0]["state"]["next"], "M2");
        assert!(
            ss["items"][0].get("updated_at").is_none(),
            "no timestamps in stable region"
        );
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
        assert!(md.starts_with("# Crux Context Bundle (context_bundle/v1)"));
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
            .starts_with("# Crux Context Bundle"));
        assert!(bundle["metadata"]["stable_hash"].as_str().is_some());
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

    #[test]
    fn assemble_presentation_order_is_deterministic() {
        let mk = |entity: &str, key: &str, id: &str, eff: f64| FactInput {
            item: StableFactItem {
                fact_id: id.to_string(),
                entity: entity.to_string(),
                key: key.to_string(),
                value: "v".to_string(),
                confidence: 1.0,
                horizon_class: "none".to_string(),
                freshness: "unknown".to_string(),
                est_tokens: 1,
            },
            addressed: false,
            effective_confidence: eff,
        };
        let req = BundleRequest {
            requested_tokens: 100,
            ceiling_tokens: 100,
        };
        // Same set, different input order + different scores: presentation
        // must come out (entity, key, fact_id)-sorted both times.
        let a = assemble(&req, vec![mk("b", "k", "f2", 0.9), mk("a", "k", "f1", 0.1)], None);
        let b = assemble(&req, vec![mk("a", "k", "f1", 0.9), mk("b", "k", "f2", 0.1)], None);
        assert_eq!(a.stable_hash, b.stable_hash);
        assert_eq!(
            a.stable.sections[0].items[0]["entity"], "a",
            "items presented in (entity,key,fact_id) order"
        );
    }
}
