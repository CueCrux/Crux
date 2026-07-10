// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! OpenAPI document — `GET /v1/openapi.json`.
//!
//! The document is produced in two layers:
//!   1. A rich utoipa-derived base ([`ApiDoc`]) carrying hand-written
//!      request/response schemas + component definitions for the originally
//!      annotated operations, plus the bearer security scheme.
//!   2. A declarative [`ROUTES`] manifest covering **every** `/v1/*` (and
//!      health) route the daemon router mounts. [`openapi_json`] overlays the
//!      manifest onto the base: the manifest is the *path authority* (it adds
//!      every mounted path), while any operation object already emitted by
//!      layer 1 is left untouched so its rich metadata survives.
//!
//! The manifest is the single source of truth the route↔spec drift gate
//! (`tests/route_spec_drift.rs`) checks against the router's `.route(...)`
//! calls, and the input the generated fetch layer (`console/v2/api.js`) is
//! emitted from.

use axum::Json;
use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Crux Daemon API",
        version = env!("CARGO_PKG_VERSION"),
        description = "Append-only event store with BM25 retrieval, CROWN receipts, and fact memory.",
        license(name = "CCL v1.0", url = "https://github.com/CueCrux/Crux/blob/main/LICENCE.md")
    ),
    paths(
        // Health
        super::health::healthz,
        super::health::readyz,
        super::health::metrics,
        super::health::get_version,
        // Facts
        super::facts::put_fact,
        super::facts::put_facts_bulk,
        super::facts::get_fact,
        super::facts::delete_fact,
        super::facts::get_facts_by_entity,
        super::facts::query_facts,
        super::facts::export_facts,
        // Sessions
        super::facts::put_session_state,
        super::facts::get_session_state,
        super::facts::archive_session,
        super::facts::unarchive_session,
        // Events
        super::events::event_stream,
        // Query
        super::query::post_query_text_search,
        super::query::post_query_text_search_expand,
        super::query::post_query_graph_expand,
        super::query::post_query_time_range,
        // Receipts
        super::receipts::get_receipt_body_v1,
        super::receipts::get_receipt_signature_v1,
        super::receipts::get_receipt_verification_v1,
        super::witness::get_witness_smoke,
    ),
    components(schemas(
        corecrux_memory::fact_store::Fact,
        corecrux_memory::fact_store::StoreFact,
        corecrux_memory::fact_store::FactQuery,
        corecrux_memory::fact_store::FactQueryResult,
        corecrux_memory::fact_store::FactExportResult,
        corecrux_memory::session_store::SessionState,
        super::query::GraphExpandBody,
        super::query::TimeRangeBody,
        super::query::TextSearchBody,
        super::query::TextSearchExpandBody,
        super::query::ExpandResultId,
    )),
    security(
        ("bearer_auth" = [])
    ),
    modifiers(&SecurityAddon)
)]
pub(super) struct ApiDoc;

struct SecurityAddon;
impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "bearer_auth",
            utoipa::openapi::security::SecurityScheme::Http(
                utoipa::openapi::security::HttpBuilder::new()
                    .scheme(utoipa::openapi::security::HttpAuthScheme::Bearer)
                    .bearer_format("JWT")
                    .build(),
            ),
        );
    }
}

/// One row of the route manifest: a mounted HTTP path, the methods it answers,
/// its OpenAPI `tag`, a coarse `auth` posture label, and a short summary.
///
/// `auth` is derived from the same prefix rules as
/// `crate::http::route_auth::classify_route` (which is `#[cfg(test)]`-only and
/// therefore cannot be called from this always-compiled module). Reduced over
/// each path's methods, the labels are:
///   * `public` — health / version / witness / openapi / `/v1/auth/*`.
///   * `read` / `write` / `read-write` — standard bearer read/mutate groups.
///   * `admin-read` / `admin-write` / `admin` — `/v1/admin/*`, routing, console, identity-candidates, non-entity projections.
///   * `internal` — `/v1/internal/replication/*`.
///   * `feature-gated` — behind a runtime flag (gpu1, context, openai, quota, coord, observe, orchestrators, punchcards, activity).
///
/// A `read-write` / `admin` label means the path exposes both a GET (read) and a
/// mutating method under the same protection domain.
struct RouteEntry {
    path: &'static str,
    methods: &'static [&'static str],
    tag: &'static str,
    auth: &'static str,
    summary: &'static str,
}

/// Every `/v1/*` route plus `/healthz`, `/readyz`, `/metrics` the daemon router
/// mounts, grounded 1:1 against the `.route(...)` calls in
/// `src/http/{mod,observe_audit,orchestrators,punchcards}.rs`.
///
/// Intentionally excluded (mounted, but out of the versioned-API spec scope):
///   * `/session`, `/invocation/verify` — legacy non-`/v1` invocation-verify
///     rails; still auth-classified by `route_auth`, candidates for a future
///     `/v1` migration.
///   * HTML console asset routes (`/console*`, `/activate`, `/`) served by
///     `crate::console::routes` — not API surface.
///
/// Keep this in sync with the router: adding a `.route(...)` without a matching
/// row here (or vice-versa) fails `tests/route_spec_drift.rs`. `#[rustfmt::skip]`
/// keeps one row per line so that test parses it line-by-line.
#[rustfmt::skip]
const ROUTES: &[RouteEntry] = &[
    RouteEntry { path: "/healthz", methods: &["GET"], tag: "Health", auth: "public", summary: "Healthz" },
    RouteEntry { path: "/metrics", methods: &["GET"], tag: "Health", auth: "public", summary: "Metrics" },
    RouteEntry { path: "/readyz", methods: &["GET"], tag: "Health", auth: "public", summary: "Readyz" },
    RouteEntry { path: "/v1/actions/enrich", methods: &["POST"], tag: "Actions", auth: "write", summary: "Actions enrich" },
    RouteEntry { path: "/v1/activity", methods: &["GET", "POST"], tag: "Activity", auth: "feature-gated", summary: "Activity" },
    RouteEntry { path: "/v1/activity/turn/{turn_id}", methods: &["GET"], tag: "Activity", auth: "feature-gated", summary: "Activity turn {turn id}" },
    RouteEntry { path: "/v1/activity/turn/{turn_id}/verify", methods: &["GET"], tag: "Activity", auth: "feature-gated", summary: "Activity turn {turn id} verify" },
    RouteEntry { path: "/v1/admin/actions", methods: &["POST"], tag: "Admin", auth: "admin-write", summary: "Admin actions" },
    RouteEntry { path: "/v1/admin/actions/{actionId}", methods: &["GET"], tag: "Admin", auth: "admin-read", summary: "Admin actions {actionId}" },
    RouteEntry { path: "/v1/admin/append", methods: &["POST"], tag: "Admin", auth: "admin-write", summary: "Admin append" },
    RouteEntry { path: "/v1/admin/control", methods: &["GET"], tag: "Admin", auth: "admin-read", summary: "Admin control" },
    RouteEntry { path: "/v1/admin/ops-log", methods: &["GET"], tag: "Admin", auth: "admin-read", summary: "Admin ops log" },
    RouteEntry { path: "/v1/admin/projections/artifacts/{artifactId}/dependents", methods: &["GET"], tag: "Admin", auth: "admin-read", summary: "Admin projections artifacts {artifactId} dependents" },
    RouteEntry { path: "/v1/admin/projections/artifacts/{artifactId}/pressure-events", methods: &["GET"], tag: "Admin", auth: "admin-read", summary: "Admin projections artifacts {artifactId} pressure events" },
    RouteEntry { path: "/v1/admin/projections/artifacts/{artifactId}/relations", methods: &["GET"], tag: "Admin", auth: "admin-read", summary: "Admin projections artifacts {artifactId} relations" },
    RouteEntry { path: "/v1/admin/projections/artifacts/{artifactId}/state", methods: &["GET"], tag: "Admin", auth: "admin-read", summary: "Admin projections artifacts {artifactId} state" },
    RouteEntry { path: "/v1/admin/projections/meta", methods: &["GET"], tag: "Admin", auth: "admin-read", summary: "Admin projections meta" },
    RouteEntry { path: "/v1/admin/projections/modules", methods: &["GET"], tag: "Admin", auth: "admin-read", summary: "Admin projections modules" },
    RouteEntry { path: "/v1/admin/projections/rebuild", methods: &["POST"], tag: "Admin", auth: "admin-write", summary: "Admin projections rebuild" },
    RouteEntry { path: "/v1/admin/replication/status", methods: &["GET"], tag: "Admin", auth: "admin-read", summary: "Admin replication status" },
    RouteEntry { path: "/v1/admin/restart", methods: &["POST"], tag: "Admin", auth: "admin-write", summary: "Admin restart" },
    RouteEntry { path: "/v1/admin/segments/fingerprints", methods: &["GET"], tag: "Admin", auth: "admin-read", summary: "Admin segments fingerprints" },
    RouteEntry { path: "/v1/admin/shard-map", methods: &["POST"], tag: "Admin", auth: "admin-write", summary: "Admin shard map" },
    RouteEntry { path: "/v1/admin/sharing/backfill", methods: &["POST"], tag: "Admin", auth: "admin-write", summary: "Admin sharing backfill" },
    RouteEntry { path: "/v1/admin/sharing/posture", methods: &["GET"], tag: "Admin", auth: "admin-read", summary: "Admin sharing posture" },
    RouteEntry { path: "/v1/admin/stream-meta", methods: &["POST"], tag: "Admin", auth: "admin-write", summary: "Admin stream meta" },
    RouteEntry { path: "/v1/admin/valves", methods: &["POST"], tag: "Admin", auth: "admin-write", summary: "Admin valves" },
    RouteEntry { path: "/v1/admin/version", methods: &["GET"], tag: "Admin", auth: "admin-read", summary: "Admin version" },
    RouteEntry { path: "/v1/agents/{passport}/usage", methods: &["GET"], tag: "Agents", auth: "read", summary: "Agents {passport} usage" },
    RouteEntry { path: "/v1/append", methods: &["POST"], tag: "Append", auth: "write", summary: "Append" },
    RouteEntry { path: "/v1/auth/device/approve", methods: &["POST"], tag: "Auth", auth: "public", summary: "Auth device approve" },
    RouteEntry { path: "/v1/auth/device/refresh", methods: &["POST"], tag: "Auth", auth: "public", summary: "Auth device refresh" },
    RouteEntry { path: "/v1/auth/device/revoke", methods: &["POST"], tag: "Auth", auth: "public", summary: "Auth device revoke" },
    RouteEntry { path: "/v1/auth/device/start", methods: &["POST"], tag: "Auth", auth: "public", summary: "Auth device start" },
    RouteEntry { path: "/v1/auth/device/token", methods: &["POST"], tag: "Auth", auth: "public", summary: "Auth device token" },
    RouteEntry { path: "/v1/auth/tailscale/token", methods: &["POST"], tag: "Auth", auth: "public", summary: "Auth tailscale token" },
    RouteEntry { path: "/v1/auth/whoami", methods: &["GET"], tag: "Auth", auth: "public", summary: "Auth whoami" },
    RouteEntry { path: "/v1/bootstrap/pull", methods: &["POST"], tag: "Bootstrap", auth: "read", summary: "Bootstrap pull" },
    RouteEntry { path: "/v1/bootstrap/status", methods: &["GET"], tag: "Bootstrap", auth: "read", summary: "Bootstrap status" },
    RouteEntry { path: "/v1/cases", methods: &["POST"], tag: "Cases", auth: "write", summary: "Cases" },
    RouteEntry { path: "/v1/cases/retrieve", methods: &["POST"], tag: "Cases", auth: "read", summary: "Cases retrieve" },
    RouteEntry { path: "/v1/cloud/access-contract", methods: &["GET"], tag: "Cloud", auth: "read", summary: "Cloud access contract" },
    RouteEntry { path: "/v1/console/chunks/{chunkDigest}", methods: &["GET"], tag: "Console", auth: "admin-read", summary: "Console chunks {chunkDigest}" },
    RouteEntry { path: "/v1/console/chunks/{chunkDigest}/preview", methods: &["GET"], tag: "Console", auth: "admin-read", summary: "Console chunks {chunkDigest} preview" },
    RouteEntry { path: "/v1/console/corecrux/lane-weights", methods: &["GET", "PUT", "DELETE"], tag: "Console", auth: "admin", summary: "Console corecrux lane weights" },
    RouteEntry { path: "/v1/console/embedding/probe", methods: &["POST"], tag: "Console", auth: "admin-write", summary: "Console embedding probe" },
    RouteEntry { path: "/v1/console/engine/bench", methods: &["GET"], tag: "console-engine", auth: "admin-read", summary: "Console engine bench (read-only Engine mediation)" },
    RouteEntry { path: "/v1/console/engine/search", methods: &["POST"], tag: "console-engine", auth: "admin-read", summary: "Console engine search (mediated WikiCrux retrieval; curated read POST)" },
    RouteEntry { path: "/v1/console/engine/spend", methods: &["GET"], tag: "console-engine", auth: "admin-read", summary: "Console engine spend (read-only Engine mediation)" },
    RouteEntry { path: "/v1/console/engine/summary", methods: &["GET"], tag: "console-engine", auth: "admin-read", summary: "Console engine summary (read-only Engine mediation)" },
    RouteEntry { path: "/v1/console/facts", methods: &["GET"], tag: "Console", auth: "admin-read", summary: "Console facts" },
    RouteEntry { path: "/v1/console/facts/add", methods: &["POST"], tag: "Console", auth: "admin-write", summary: "Console facts add" },
    RouteEntry { path: "/v1/console/infra/summary", methods: &["GET"], tag: "Console", auth: "admin-read", summary: "Console infra summary" },
    RouteEntry { path: "/v1/console/integrations", methods: &["GET"], tag: "Console", auth: "admin-read", summary: "Console integrations" },
    RouteEntry { path: "/v1/console/integrations/{packId}/disable", methods: &["POST"], tag: "Console", auth: "admin-write", summary: "Console integrations {packId} disable" },
    RouteEntry { path: "/v1/console/integrations/{packId}/grant", methods: &["POST"], tag: "Console", auth: "admin-write", summary: "Console integrations {packId} grant" },
    RouteEntry { path: "/v1/console/integrations/{packId}/install", methods: &["POST"], tag: "Console", auth: "admin-write", summary: "Console integrations {packId} install" },
    RouteEntry { path: "/v1/console/onboarding", methods: &["GET"], tag: "Console", auth: "admin-read", summary: "Console onboarding" },
    RouteEntry { path: "/v1/console/onboarding/complete", methods: &["POST"], tag: "Console", auth: "admin-write", summary: "Console onboarding complete" },
    RouteEntry { path: "/v1/console/onboarding/restart", methods: &["POST"], tag: "Console", auth: "admin-write", summary: "Console onboarding restart" },
    RouteEntry { path: "/v1/console/passports", methods: &["GET"], tag: "Console", auth: "admin-read", summary: "Console passports" },
    RouteEntry { path: "/v1/console/review/consolidations", methods: &["POST"], tag: "Console", auth: "admin-write", summary: "Console review consolidations" },
    RouteEntry { path: "/v1/console/review/contradictions", methods: &["GET"], tag: "Console", auth: "admin-read", summary: "Console review contradictions" },
    RouteEntry { path: "/v1/console/sessions", methods: &["GET"], tag: "Console", auth: "admin-read", summary: "Console sessions" },
    RouteEntry { path: "/v1/console/settings", methods: &["GET", "PUT"], tag: "Console", auth: "admin", summary: "Console settings" },
    RouteEntry { path: "/v1/console/storage-breakdown", methods: &["GET"], tag: "Console", auth: "admin-read", summary: "Console storage breakdown" },
    RouteEntry { path: "/v1/console/summary", methods: &["GET"], tag: "Console", auth: "admin-read", summary: "Console summary" },
    RouteEntry { path: "/v1/console/tenants", methods: &["GET"], tag: "Console", auth: "admin-read", summary: "Console tenants" },
    RouteEntry { path: "/v1/console/tenants/{tenantId}/category", methods: &["GET", "PATCH"], tag: "Console", auth: "admin", summary: "Console tenants {tenantId} category" },
    RouteEntry { path: "/v1/console/tenants/{tenantId}/chunks", methods: &["GET"], tag: "Console", auth: "admin-read", summary: "Console tenants {tenantId} chunks" },
    RouteEntry { path: "/v1/context", methods: &["GET", "POST"], tag: "Context", auth: "feature-gated", summary: "Context" },
    RouteEntry { path: "/v1/coord/active", methods: &["GET"], tag: "Coord", auth: "feature-gated", summary: "Coord active" },
    RouteEntry { path: "/v1/coord/announce", methods: &["POST"], tag: "Coord", auth: "feature-gated", summary: "Coord announce" },
    RouteEntry { path: "/v1/cost/report", methods: &["GET", "POST"], tag: "Cost", auth: "read-write", summary: "Cost report" },
    RouteEntry { path: "/v1/credits/spend", methods: &["POST"], tag: "Credits", auth: "feature-gated", summary: "Credits spend" },
    RouteEntry { path: "/v1/edges", methods: &["GET", "PUT", "DELETE"], tag: "Edges", auth: "read-write", summary: "Edges" },
    RouteEntry { path: "/v1/engrams", methods: &["GET"], tag: "Engrams", auth: "read", summary: "Engrams" },
    RouteEntry { path: "/v1/entities", methods: &["GET"], tag: "Entities", auth: "read", summary: "Entities" },
    RouteEntry { path: "/v1/entities/{kind}/{id}", methods: &["GET", "PUT", "DELETE"], tag: "Entities", auth: "read-write", summary: "Entities {kind} {id}" },
    RouteEntry { path: "/v1/entities/{kind}/{id}/history", methods: &["GET"], tag: "Entities", auth: "read", summary: "Entities {kind} {id} history" },
    RouteEntry { path: "/v1/events/stream", methods: &["GET"], tag: "Events", auth: "read", summary: "Events stream" },
    RouteEntry { path: "/v1/extensions", methods: &["GET"], tag: "Extensions", auth: "read", summary: "Extensions" },
    RouteEntry { path: "/v1/extensions/install-from-registry", methods: &["POST"], tag: "Extensions", auth: "write", summary: "Extensions install from registry" },
    RouteEntry { path: "/v1/extensions/keys", methods: &["GET", "POST"], tag: "Extensions", auth: "read-write", summary: "Extensions keys" },
    RouteEntry { path: "/v1/extensions/keys/{passport_fpr}", methods: &["DELETE"], tag: "Extensions", auth: "write", summary: "Extensions keys {passport fpr}" },
    RouteEntry { path: "/v1/extensions/register", methods: &["POST"], tag: "Extensions", auth: "write", summary: "Extensions register" },
    RouteEntry { path: "/v1/extensions/{id}", methods: &["GET", "DELETE"], tag: "Extensions", auth: "read-write", summary: "Extensions {id}" },
    RouteEntry { path: "/v1/extensions/{id}/grants", methods: &["GET", "POST"], tag: "Extensions", auth: "read-write", summary: "Extensions {id} grants" },
    RouteEntry { path: "/v1/extensions/{id}/grants/{passport_fpr}", methods: &["DELETE"], tag: "Extensions", auth: "write", summary: "Extensions {id} grants {passport fpr}" },
    RouteEntry { path: "/v1/extensions/{id}/tools/{tool_name}/invoke", methods: &["POST"], tag: "Extensions", auth: "write", summary: "Extensions {id} tools {tool name} invoke" },
    RouteEntry { path: "/v1/facts", methods: &["GET", "PUT"], tag: "Facts", auth: "read-write", summary: "Facts" },
    RouteEntry { path: "/v1/facts/bulk", methods: &["PUT"], tag: "Facts", auth: "write", summary: "Facts bulk" },
    RouteEntry { path: "/v1/facts/entity/{entity}", methods: &["GET"], tag: "Facts", auth: "read", summary: "Facts entity {entity}" },
    RouteEntry { path: "/v1/facts/export", methods: &["GET"], tag: "Facts", auth: "read", summary: "Facts export" },
    RouteEntry { path: "/v1/facts/{factId}", methods: &["GET", "DELETE"], tag: "Facts", auth: "read-write", summary: "Facts {factId}" },
    RouteEntry { path: "/v1/features/capabilities", methods: &["GET"], tag: "Features", auth: "read", summary: "Features capabilities" },
    RouteEntry { path: "/v1/features/capabilities/analysis/coverage", methods: &["GET"], tag: "Features", auth: "read", summary: "Features capabilities analysis coverage" },
    RouteEntry { path: "/v1/features/capabilities/analysis/gaps", methods: &["GET"], tag: "Features", auth: "read", summary: "Features capabilities analysis gaps" },
    RouteEntry { path: "/v1/features/capabilities/analysis/promises", methods: &["GET"], tag: "Features", auth: "read", summary: "Features capabilities analysis promises" },
    RouteEntry { path: "/v1/features/capabilities/{id}", methods: &["GET"], tag: "Features", auth: "read", summary: "Features capabilities {id}" },
    RouteEntry { path: "/v1/features/capabilities/{id}/audit", methods: &["POST"], tag: "Features", auth: "write", summary: "Features capabilities {id} audit" },
    RouteEntry { path: "/v1/features/capabilities/{id}/tree", methods: &["GET"], tag: "Features", auth: "read", summary: "Features capabilities {id} tree" },
    RouteEntry { path: "/v1/gpu1/answer", methods: &["POST"], tag: "GPU1", auth: "feature-gated", summary: "Gpu1 answer" },
    RouteEntry { path: "/v1/gpu1/contract", methods: &["GET"], tag: "GPU1", auth: "feature-gated", summary: "Gpu1 contract" },
    RouteEntry { path: "/v1/gpu1/coverage", methods: &["POST"], tag: "GPU1", auth: "feature-gated", summary: "Gpu1 coverage" },
    RouteEntry { path: "/v1/gpu1/developer", methods: &["POST"], tag: "GPU1", auth: "feature-gated", summary: "Gpu1 developer" },
    RouteEntry { path: "/v1/gpu1/enrich", methods: &["POST"], tag: "GPU1", auth: "feature-gated", summary: "Gpu1 enrich" },
    RouteEntry { path: "/v1/gpu1/rerank", methods: &["POST"], tag: "GPU1", auth: "feature-gated", summary: "Gpu1 rerank" },
    RouteEntry { path: "/v1/gpus", methods: &["GET"], tag: "Routing", auth: "admin-read", summary: "Gpus" },
    RouteEntry { path: "/v1/identity/candidates", methods: &["GET"], tag: "Identity", auth: "admin-read", summary: "Identity candidates" },
    RouteEntry { path: "/v1/identity/candidates/{candidateId}/confirm", methods: &["POST"], tag: "Identity", auth: "admin-write", summary: "Identity candidates {candidateId} confirm" },
    RouteEntry { path: "/v1/identity/candidates/{candidateId}/reject", methods: &["POST"], tag: "Identity", auth: "admin-write", summary: "Identity candidates {candidateId} reject" },
    RouteEntry { path: "/v1/identity/links", methods: &["GET", "POST"], tag: "Identity", auth: "read-write", summary: "Identity links" },
    RouteEntry { path: "/v1/identity/links/{linkId}/revoke", methods: &["POST"], tag: "Identity", auth: "write", summary: "Identity links {linkId} revoke" },
    RouteEntry { path: "/v1/integrations/github/connect", methods: &["POST"], tag: "Integrations", auth: "write", summary: "Integrations github connect" },
    RouteEntry { path: "/v1/integrations/github/disconnect", methods: &["POST"], tag: "Integrations", auth: "write", summary: "Integrations github disconnect" },
    RouteEntry { path: "/v1/integrations/github/repos", methods: &["GET"], tag: "Integrations", auth: "admin-read", summary: "Integrations github repos" },
    RouteEntry { path: "/v1/integrations/github/repos/accessible", methods: &["GET"], tag: "Integrations", auth: "admin-read", summary: "Integrations github repos accessible" },
    RouteEntry { path: "/v1/integrations/github/repos/{owner}/{repo}/planning", methods: &["PUT"], tag: "Integrations", auth: "write", summary: "Integrations github repos {owner} {repo} planning" },
    RouteEntry { path: "/v1/integrations/github/repos/{owner}/{repo}/select", methods: &["POST", "DELETE"], tag: "Integrations", auth: "write", summary: "Integrations github repos {owner} {repo} select" },
    RouteEntry { path: "/v1/integrations/github/status", methods: &["GET"], tag: "Integrations", auth: "admin-read", summary: "Integrations github status" },
    RouteEntry { path: "/v1/integrations/github/sync", methods: &["POST"], tag: "Integrations", auth: "write", summary: "Integrations github sync" },
    RouteEntry { path: "/v1/integrations/openai/chat", methods: &["POST"], tag: "Integrations", auth: "write", summary: "Integrations openai chat" },
    RouteEntry { path: "/v1/integrations/openai/connect", methods: &["POST"], tag: "Integrations", auth: "write", summary: "Integrations openai connect" },
    RouteEntry { path: "/v1/integrations/openai/disconnect", methods: &["POST"], tag: "Integrations", auth: "write", summary: "Integrations openai disconnect" },
    RouteEntry { path: "/v1/integrations/openai/settings", methods: &["PATCH"], tag: "Integrations", auth: "write", summary: "Integrations openai settings" },
    RouteEntry { path: "/v1/integrations/openai/status", methods: &["GET"], tag: "Integrations", auth: "admin-read", summary: "Integrations openai status" },
    RouteEntry { path: "/v1/internal/replication/segments", methods: &["POST"], tag: "Internal", auth: "internal", summary: "Internal replication segments" },
    RouteEntry { path: "/v1/kinds", methods: &["GET"], tag: "Kinds", auth: "read", summary: "Kinds" },
    RouteEntry { path: "/v1/kinds/{kind}", methods: &["GET"], tag: "Kinds", auth: "read", summary: "Kinds {kind}" },
    RouteEntry { path: "/v1/local/ingest", methods: &["POST"], tag: "Local", auth: "admin-write", summary: "Local ingest" },
    RouteEntry { path: "/v1/mcp/tools", methods: &["GET"], tag: "MCP", auth: "read", summary: "Mcp tools" },
    RouteEntry { path: "/v1/mediation/receipts", methods: &["POST"], tag: "Mediation", auth: "write", summary: "Mediation receipts" },
    RouteEntry { path: "/v1/memory/engrams/resolve", methods: &["POST"], tag: "Memory", auth: "write", summary: "Memory engrams resolve" },
    RouteEntry { path: "/v1/memory/import", methods: &["POST"], tag: "Memory", auth: "write", summary: "Memory import" },
    RouteEntry { path: "/v1/memory/session-init", methods: &["POST"], tag: "Memory", auth: "write", summary: "Memory session init" },
    RouteEntry { path: "/v1/observations/aggregate", methods: &["GET"], tag: "Observations", auth: "read", summary: "Observations aggregate" },
    RouteEntry { path: "/v1/observe/sessions/{id}/audit", methods: &["GET"], tag: "Observe", auth: "feature-gated", summary: "Observe sessions {id} audit" },
    RouteEntry { path: "/v1/observe/sessions/{id}/audit/conformance", methods: &["GET"], tag: "Observe", auth: "feature-gated", summary: "Observe sessions {id} audit conformance" },
    RouteEntry { path: "/v1/observe/sessions/{id}/audit/export", methods: &["GET"], tag: "Observe", auth: "feature-gated", summary: "Observe sessions {id} audit export" },
    RouteEntry { path: "/v1/observe/sessions/{id}/steps", methods: &["POST"], tag: "Observe", auth: "feature-gated", summary: "Observe sessions {id} steps" },
    RouteEntry { path: "/v1/observe/sessions/{id}/steps/{node_id}", methods: &["PATCH"], tag: "Observe", auth: "feature-gated", summary: "Observe sessions {id} steps {node id}" },
    RouteEntry { path: "/v1/openai/invoke", methods: &["POST"], tag: "OpenAI", auth: "feature-gated", summary: "Openai invoke" },
    RouteEntry { path: "/v1/openai/tools.json", methods: &["GET"], tag: "OpenAI", auth: "feature-gated", summary: "Openai tools.json" },
    RouteEntry { path: "/v1/openapi.json", methods: &["GET"], tag: "OpenAPI", auth: "public", summary: "Openapi.json" },
    RouteEntry { path: "/v1/ops/errors", methods: &["GET"], tag: "Ops", auth: "read", summary: "Ops errors" },
    RouteEntry { path: "/v1/ops/facts", methods: &["GET"], tag: "Ops", auth: "read", summary: "Ops facts" },
    RouteEntry { path: "/v1/ops/health", methods: &["GET"], tag: "Ops", auth: "read", summary: "Ops health" },
    RouteEntry { path: "/v1/orchestrators", methods: &["GET", "POST"], tag: "Orchestrators", auth: "feature-gated", summary: "Orchestrators" },
    RouteEntry { path: "/v1/orchestrators/{id}", methods: &["GET", "PATCH"], tag: "Orchestrators", auth: "feature-gated", summary: "Orchestrators {id}" },
    RouteEntry { path: "/v1/orchestrators/{id}/members", methods: &["POST"], tag: "Orchestrators", auth: "feature-gated", summary: "Orchestrators {id} members" },
    RouteEntry { path: "/v1/orchestrators/{id}/members/{ref}", methods: &["DELETE"], tag: "Orchestrators", auth: "feature-gated", summary: "Orchestrators {id} members {ref}" },
    RouteEntry { path: "/v1/orchestrators/{id}/work", methods: &["GET"], tag: "Orchestrators", auth: "feature-gated", summary: "Orchestrators {id} work" },
    RouteEntry { path: "/v1/passports", methods: &["GET", "POST"], tag: "Passports", auth: "read-write", summary: "Passports" },
    RouteEntry { path: "/v1/passports/presence", methods: &["GET"], tag: "Passports", auth: "read", summary: "Passports presence" },
    RouteEntry { path: "/v1/passports/{passportId}", methods: &["GET", "PATCH", "DELETE"], tag: "Passports", auth: "read-write", summary: "Passports {passportId}" },
    RouteEntry { path: "/v1/policy/capabilities", methods: &["GET"], tag: "Policy", auth: "read", summary: "Policy capabilities" },
    RouteEntry { path: "/v1/principal/resolve", methods: &["GET"], tag: "Principal", auth: "read", summary: "Principal resolve" },
    RouteEntry { path: "/v1/projections/batch_lookup", methods: &["POST"], tag: "Projections", auth: "admin-write", summary: "Projections batch lookup" },
    RouteEntry { path: "/v1/projections/entity/count", methods: &["GET"], tag: "Projections", auth: "read", summary: "Projections entity count" },
    RouteEntry { path: "/v1/projections/entity/current-state", methods: &["GET"], tag: "Projections", auth: "read", summary: "Projections entity current state" },
    RouteEntry { path: "/v1/projections/entity/timeline", methods: &["GET"], tag: "Projections", auth: "read", summary: "Projections entity timeline" },
    RouteEntry { path: "/v1/projections/lookup", methods: &["POST"], tag: "Projections", auth: "admin-write", summary: "Projections lookup" },
    RouteEntry { path: "/v1/projects", methods: &["GET", "POST"], tag: "Projects", auth: "read-write", summary: "Projects" },
    RouteEntry { path: "/v1/projects/{id}", methods: &["GET", "PATCH", "DELETE"], tag: "Projects", auth: "read-write", summary: "Projects {id}" },
    RouteEntry { path: "/v1/projects/{id}/context-graph", methods: &["GET"], tag: "Projects", auth: "read", summary: "Projects {id} context graph" },
    RouteEntry { path: "/v1/projects/{id}/dossiers", methods: &["GET", "POST"], tag: "Projects", auth: "read-write", summary: "Projects {id} dossiers" },
    RouteEntry { path: "/v1/projects/{id}/dossiers/auto", methods: &["POST"], tag: "Projects", auth: "write", summary: "Projects {id} dossiers auto" },
    RouteEntry { path: "/v1/projects/{id}/dossiers/diff", methods: &["GET"], tag: "Projects", auth: "read", summary: "Projects {id} dossiers diff" },
    RouteEntry { path: "/v1/projects/{id}/dossiers/reconcile", methods: &["GET"], tag: "Projects", auth: "read", summary: "Projects {id} dossiers reconcile" },
    RouteEntry { path: "/v1/projects/{id}/dossiers/{dossierId}", methods: &["GET"], tag: "Projects", auth: "read", summary: "Projects {id} dossiers {dossierId}" },
    RouteEntry { path: "/v1/projects/{id}/layers", methods: &["GET"], tag: "Projects", auth: "read", summary: "Projects {id} layers" },
    RouteEntry { path: "/v1/projects/{id}/layers/{layer}", methods: &["PUT", "DELETE"], tag: "Projects", auth: "write", summary: "Projects {id} layers {layer}" },
    RouteEntry { path: "/v1/projects/{id}/passports", methods: &["POST"], tag: "Projects", auth: "write", summary: "Projects {id} passports" },
    RouteEntry { path: "/v1/projects/{id}/passports/{passportId}", methods: &["DELETE"], tag: "Projects", auth: "write", summary: "Projects {id} passports {passportId}" },
    RouteEntry { path: "/v1/projects/{id}/planes", methods: &["GET", "POST"], tag: "Projects", auth: "read-write", summary: "Projects {id} planes" },
    RouteEntry { path: "/v1/projects/{id}/planes/sync-layers", methods: &["POST"], tag: "Projects", auth: "write", summary: "Projects {id} planes sync layers" },
    RouteEntry { path: "/v1/projects/{id}/planes/{planeId}", methods: &["GET", "DELETE"], tag: "Projects", auth: "read-write", summary: "Projects {id} planes {planeId}" },
    RouteEntry { path: "/v1/projects/{id}/planes/{planeId}/layers", methods: &["GET"], tag: "Projects", auth: "read", summary: "Projects {id} planes {planeId} layers" },
    RouteEntry { path: "/v1/projects/{id}/planes/{planeId}/layers/{layer}", methods: &["PUT", "DELETE"], tag: "Projects", auth: "write", summary: "Projects {id} planes {planeId} layers {layer}" },
    RouteEntry { path: "/v1/projects/{id}/planes/{planeId}/passports", methods: &["POST"], tag: "Projects", auth: "write", summary: "Projects {id} planes {planeId} passports" },
    RouteEntry { path: "/v1/projects/{id}/planes/{planeId}/passports/{passportId}", methods: &["DELETE"], tag: "Projects", auth: "write", summary: "Projects {id} planes {planeId} passports {passportId}" },
    RouteEntry { path: "/v1/projects/{id}/planes/{planeId}/repos", methods: &["GET"], tag: "Projects", auth: "read", summary: "Projects {id} planes {planeId} repos" },
    RouteEntry { path: "/v1/projects/{id}/planes/{planeId}/tenants", methods: &["POST"], tag: "Projects", auth: "write", summary: "Projects {id} planes {planeId} tenants" },
    RouteEntry { path: "/v1/projects/{id}/planes/{planeId}/tenants/{tenantId}", methods: &["DELETE"], tag: "Projects", auth: "write", summary: "Projects {id} planes {planeId} tenants {tenantId}" },
    RouteEntry { path: "/v1/projects/{id}/repos", methods: &["GET", "POST"], tag: "Projects", auth: "read-write", summary: "Projects {id} repos" },
    RouteEntry { path: "/v1/projects/{id}/repos/{owner}/{repo}", methods: &["DELETE"], tag: "Projects", auth: "write", summary: "Projects {id} repos {owner} {repo}" },
    RouteEntry { path: "/v1/projects/{id}/storybook", methods: &["GET", "POST"], tag: "Projects", auth: "read-write", summary: "Projects {id} storybook" },
    RouteEntry { path: "/v1/projects/{id}/storybook/diff", methods: &["GET"], tag: "Projects", auth: "read", summary: "Projects {id} storybook diff" },
    RouteEntry { path: "/v1/projects/{id}/storybook/versions", methods: &["GET"], tag: "Projects", auth: "read", summary: "Projects {id} storybook versions" },
    RouteEntry { path: "/v1/projects/{id}/storybook/{ts}", methods: &["GET"], tag: "Projects", auth: "read", summary: "Projects {id} storybook {ts}" },
    RouteEntry { path: "/v1/projects/{id}/tenants", methods: &["POST"], tag: "Projects", auth: "write", summary: "Projects {id} tenants" },
    RouteEntry { path: "/v1/projects/{id}/tenants/{tenantId}", methods: &["DELETE"], tag: "Projects", auth: "write", summary: "Projects {id} tenants {tenantId}" },
    RouteEntry { path: "/v1/punchcards", methods: &["GET"], tag: "Punchcards", auth: "feature-gated", summary: "Punchcards" },
    RouteEntry { path: "/v1/punchcards/acquire", methods: &["POST"], tag: "Punchcards", auth: "feature-gated", summary: "Punchcards acquire" },
    RouteEntry { path: "/v1/punchcards/check", methods: &["POST"], tag: "Punchcards", auth: "feature-gated", summary: "Punchcards check" },
    RouteEntry { path: "/v1/punchcards/release", methods: &["POST"], tag: "Punchcards", auth: "feature-gated", summary: "Punchcards release" },
    RouteEntry { path: "/v1/punchcards/{id}/force-release", methods: &["POST"], tag: "Punchcards", auth: "feature-gated", summary: "Punchcards {id} force release" },
    RouteEntry { path: "/v1/query/graph-expand", methods: &["POST"], tag: "Query", auth: "read", summary: "Query graph expand" },
    RouteEntry { path: "/v1/query/text-search", methods: &["POST"], tag: "Query", auth: "read", summary: "Query text search" },
    RouteEntry { path: "/v1/query/text-search/expand", methods: &["POST"], tag: "Query", auth: "read", summary: "Query text search expand" },
    RouteEntry { path: "/v1/query/time-range", methods: &["POST"], tag: "Query", auth: "read", summary: "Query time range" },
    RouteEntry { path: "/v1/quota", methods: &["GET"], tag: "Quota", auth: "feature-gated", summary: "Quota" },
    RouteEntry { path: "/v1/rcx/publish/passports/{passportId}/emit", methods: &["POST"], tag: "RCX", auth: "write", summary: "Rcx publish passports {passportId} emit" },
    RouteEntry { path: "/v1/rcx/publish/passports/{passportId}/preview", methods: &["POST"], tag: "RCX", auth: "write", summary: "Rcx publish passports {passportId} preview" },
    RouteEntry { path: "/v1/rcx/publish/projects/{projectId}/emit", methods: &["POST"], tag: "RCX", auth: "write", summary: "Rcx publish projects {projectId} emit" },
    RouteEntry { path: "/v1/rcx/publish/projects/{projectId}/preview", methods: &["POST"], tag: "RCX", auth: "write", summary: "Rcx publish projects {projectId} preview" },
    RouteEntry { path: "/v1/receipts/{receiptId}", methods: &["GET"], tag: "Receipts", auth: "read", summary: "Receipts {receiptId}" },
    RouteEntry { path: "/v1/receipts/{receiptId}/signature", methods: &["GET"], tag: "Receipts", auth: "read", summary: "Receipts {receiptId} signature" },
    RouteEntry { path: "/v1/receipts/{receiptId}/verification", methods: &["GET"], tag: "Receipts", auth: "read", summary: "Receipts {receiptId} verification" },
    RouteEntry { path: "/v1/relations", methods: &["GET", "POST"], tag: "Relations", auth: "read-write", summary: "Relations" },
    RouteEntry { path: "/v1/relations/incoming", methods: &["GET"], tag: "Relations", auth: "admin-read", summary: "Relations incoming" },
    RouteEntry { path: "/v1/relations/expand", methods: &["POST"], tag: "Relations", auth: "write", summary: "Relations expand" },
    RouteEntry { path: "/v1/replay/answers/{answerId}", methods: &["GET"], tag: "Replay", auth: "read", summary: "Replay answers {answerId}" },
    RouteEntry { path: "/v1/replay/answers/{answerId}/validity", methods: &["GET"], tag: "Replay", auth: "read", summary: "Replay answers {answerId} validity" },
    RouteEntry { path: "/v1/replay/exports/actions/{actionId}", methods: &["GET"], tag: "Replay", auth: "read", summary: "Replay exports actions {actionId}" },
    RouteEntry { path: "/v1/replay/exports/answers/{answerId}", methods: &["GET"], tag: "Replay", auth: "read", summary: "Replay exports answers {answerId}" },
    RouteEntry { path: "/v1/replay/exports/receipts/{receiptId}", methods: &["GET"], tag: "Replay", auth: "read", summary: "Replay exports receipts {receiptId}" },
    RouteEntry { path: "/v1/replay/exports/streams/{streamType}/{streamId}", methods: &["GET"], tag: "Replay", auth: "read", summary: "Replay exports streams {streamType} {streamId}" },
    RouteEntry { path: "/v1/repos", methods: &["GET", "POST"], tag: "Repos", auth: "admin", summary: "Repos" },
    RouteEntry { path: "/v1/repos/dependents", methods: &["GET"], tag: "Repos", auth: "admin-read", summary: "Repos dependents" },
    RouteEntry { path: "/v1/repos/{repo_id}", methods: &["GET", "DELETE"], tag: "Repos", auth: "admin", summary: "Repos {repo_id}" },
    RouteEntry { path: "/v1/repos/{repo_id}/codemap", methods: &["GET"], tag: "Repos", auth: "admin-read", summary: "Repos {repo_id} codemap" },
    RouteEntry { path: "/v1/result-envelope/import", methods: &["POST"], tag: "ResultEnvelope", auth: "write", summary: "Result envelope import" },
    RouteEntry { path: "/v1/route", methods: &["GET"], tag: "Routing", auth: "admin-read", summary: "Route" },
    RouteEntry { path: "/v1/routing/route", methods: &["GET"], tag: "Routing", auth: "admin-read", summary: "Routing route" },
    RouteEntry { path: "/v1/routing/status", methods: &["GET"], tag: "Routing", auth: "admin-read", summary: "Routing status" },
    RouteEntry { path: "/v1/sessions/active", methods: &["GET"], tag: "Sessions", auth: "read", summary: "Sessions active" },
    RouteEntry { path: "/v1/sessions/{sessionId}/archive", methods: &["POST"], tag: "Sessions", auth: "write", summary: "Sessions {sessionId} archive" },
    RouteEntry { path: "/v1/sessions/{sessionId}/observations", methods: &["GET", "POST"], tag: "Sessions", auth: "read-write", summary: "Sessions {sessionId} observations" },
    RouteEntry { path: "/v1/sessions/{sessionId}/observations/batch", methods: &["POST"], tag: "Sessions", auth: "write", summary: "Sessions {sessionId} observations batch" },
    RouteEntry { path: "/v1/sessions/{sessionId}/plan", methods: &["GET"], tag: "Sessions", auth: "read", summary: "Sessions {sessionId} plan" },
    RouteEntry { path: "/v1/sessions/{sessionId}/state", methods: &["GET", "PUT"], tag: "Sessions", auth: "read-write", summary: "Sessions {sessionId} state" },
    RouteEntry { path: "/v1/sessions/{sessionId}/unarchive", methods: &["POST"], tag: "Sessions", auth: "write", summary: "Sessions {sessionId} unarchive" },
    RouteEntry { path: "/v1/shard-map", methods: &["GET"], tag: "Routing", auth: "admin-read", summary: "Shard map" },
    RouteEntry { path: "/v1/shards", methods: &["GET"], tag: "Routing", auth: "admin-read", summary: "Shards" },
    RouteEntry { path: "/v1/status-feed", methods: &["GET"], tag: "StatusFeed", auth: "read", summary: "Status feed" },
    RouteEntry { path: "/v1/sync/tenants/{tenantId}/collections/{collection}", methods: &["GET"], tag: "Sync", auth: "read", summary: "Sync tenants {tenantId} collections {collection}" },
    RouteEntry { path: "/v1/sync/tenants/{tenantId}/manifest", methods: &["GET"], tag: "Sync", auth: "read", summary: "Sync tenants {tenantId} manifest" },
    RouteEntry { path: "/v1/sync/tenants/{tenantId}/offboard", methods: &["POST"], tag: "Sync", auth: "write", summary: "Sync tenants {tenantId} offboard" },
    RouteEntry { path: "/v1/sync/tenants/{tenantId}/promotions/confirm", methods: &["POST"], tag: "Sync", auth: "write", summary: "Sync tenants {tenantId} promotions confirm" },
    RouteEntry { path: "/v1/sync/tenants/{tenantId}/promotions/preview", methods: &["POST"], tag: "Sync", auth: "write", summary: "Sync tenants {tenantId} promotions preview" },
    RouteEntry { path: "/v1/version", methods: &["GET"], tag: "Version", auth: "public", summary: "Version" },
    RouteEntry { path: "/v1/witness/smoke", methods: &["GET"], tag: "Witness", auth: "public", summary: "Witness smoke" },
    RouteEntry { path: "/v1/work", methods: &["GET", "POST"], tag: "Work", auth: "read-write", summary: "Work" },
    RouteEntry { path: "/v1/work/gate/pending", methods: &["GET"], tag: "Work", auth: "read", summary: "Work gate pending" },
    RouteEntry { path: "/v1/work/gate/{actionId}/approve", methods: &["POST"], tag: "Work", auth: "write", summary: "Work gate {actionId} approve" },
    RouteEntry { path: "/v1/work/gate/{actionId}/reject", methods: &["POST"], tag: "Work", auth: "write", summary: "Work gate {actionId} reject" },
    RouteEntry { path: "/v1/work/{id}", methods: &["GET", "PATCH"], tag: "Work", auth: "read-write", summary: "Work {id}" },
    RouteEntry { path: "/v1/work/{id}/comments", methods: &["GET", "POST"], tag: "Work", auth: "read-write", summary: "Work {id} comments" },
    RouteEntry { path: "/v1/work/{id}/transitions", methods: &["GET"], tag: "Work", auth: "read", summary: "Work {id} transitions" },
    RouteEntry { path: "/v1/workbench/api-drift", methods: &["GET"], tag: "Workbench", auth: "read", summary: "Workbench api drift" },
    RouteEntry { path: "/v1/workbench/audit-triage", methods: &["GET"], tag: "Workbench", auth: "read", summary: "Workbench audit triage" },
    RouteEntry { path: "/v1/workbench/brief", methods: &["GET"], tag: "Workbench", auth: "read", summary: "Workbench brief" },
    RouteEntry { path: "/v1/workbench/command-ledger", methods: &["GET", "POST"], tag: "Workbench", auth: "read-write", summary: "Workbench command ledger" },
    RouteEntry { path: "/v1/workbench/context-pack", methods: &["POST"], tag: "Workbench", auth: "write", summary: "Workbench context pack" },
    RouteEntry { path: "/v1/workbench/contract", methods: &["GET"], tag: "Workbench", auth: "read", summary: "Workbench contract" },
    RouteEntry { path: "/v1/workbench/handoff-v2", methods: &["POST"], tag: "Workbench", auth: "write", summary: "Workbench handoff v2" },
    RouteEntry { path: "/v1/workbench/impact-preflight", methods: &["POST"], tag: "Workbench", auth: "write", summary: "Workbench impact preflight" },
    RouteEntry { path: "/v1/workbench/policy-simulation", methods: &["POST"], tag: "Workbench", auth: "write", summary: "Workbench policy simulation" },
    RouteEntry { path: "/v1/workbench/reasoning-timeline", methods: &["GET"], tag: "Workbench", auth: "read", summary: "Workbench reasoning timeline" },
    RouteEntry { path: "/v1/workbench/route-probe", methods: &["POST"], tag: "Workbench", auth: "write", summary: "Workbench route probe" },
    RouteEntry { path: "/v1/workspace/scan", methods: &["GET", "POST"], tag: "Workspace", auth: "read-write", summary: "Workspace scan" },
    RouteEntry { path: "/v1/workspace/storyline", methods: &["GET"], tag: "Workspace", auth: "read", summary: "Workspace storyline" },
];

/// Overlays [`ROUTES`] onto a serialized OpenAPI document: ensures every
/// manifest path is present, tags each newly added operation, and records the
/// coarse auth posture as an `x-crux-auth` path-item extension. Operation
/// objects already emitted by the utoipa base are left intact.
fn apply_route_manifest(spec: &mut serde_json::Value) {
    use serde_json::json;
    let Some(root) = spec.as_object_mut() else {
        return;
    };
    let paths = root.entry("paths").or_insert_with(|| json!({}));
    let Some(paths) = paths.as_object_mut() else {
        return;
    };
    for entry in ROUTES {
        let item = paths.entry(entry.path).or_insert_with(|| json!({}));
        let Some(item) = item.as_object_mut() else {
            continue;
        };
        // Coarse protection domain, one label per path (see `RouteEntry`).
        item.insert("x-crux-auth".to_string(), json!(entry.auth));
        for method in entry.methods {
            let m = method.to_ascii_lowercase();
            if item.contains_key(&m) {
                // Preserve the utoipa-derived operation (rich schemas).
                continue;
            }
            let security = if entry.auth == "public" {
                json!([])
            } else {
                json!([{ "bearer_auth": [] }])
            };
            item.insert(
                m,
                json!({
                    "summary": entry.summary,
                    "tags": [entry.tag],
                    "responses": { "200": { "description": "OK" } },
                    "security": security,
                }),
            );
        }
    }
}

pub(super) async fn openapi_json() -> Json<serde_json::Value> {
    let mut spec =
        serde_json::to_value(ApiDoc::openapi()).unwrap_or_else(|_| serde_json::json!({ "openapi": "3.1.0" }));
    apply_route_manifest(&mut spec);
    Json(spec)
}
