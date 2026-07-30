// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Route authorization contract for the daemon HTTP surface, plus the
//! deny-by-default enforcement middleware that promotes it from a test-only
//! matrix into a runtime gate.
//!
//! The contract ([`classify_route`]) maps `(method, route-template)` to a
//! [`RouteAuthContract`] — the accepted (any-of) scope set for that route and
//! its [`RouteAuthClass`]. [`route_auth_middleware`] evaluates that contract
//! before handler dispatch:
//!
//! * `off` — pass-through.
//! * `shadow` — evaluate the contract; on a would-deny, emit a structured
//!   `route_auth_shadow_mismatch` warning and continue. This is the derived
//!   default only for an auth-off, loopback-only daemon.
//! * `enforce` — Public routes pass with no auth; classified routes require the
//!   contract's scopes via the same `auth.rs` primitive handlers use; an
//!   unclassified route (or a request with no matched path) fails closed with
//!   `403`. This is the derived default whenever authentication is enabled or
//!   the listener is non-loopback.
//!
//! Handler-level scope checks stay in place as defence in depth — this layer is
//! a coarse deny-by-default gate in front of them, never a replacement.

use axum::extract::{MatchedPath, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use super::{problem_response, AppState};
use crate::auth::{require_http_any_scope, AuthMode};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RouteAuthClass {
    Public,
    Read,
    Write,
    AdminRead,
    AdminWrite,
    InternalReplication,
    FeatureGated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RouteAuthContract {
    class: RouteAuthClass,
    scopes: &'static [&'static str],
    // The feature flag whose handler gates a `FeatureGated` route. Recorded for
    // documentation/audit; the middleware never reads it — flag gating stays in
    // the handler (M3 contract: the route-auth layer authorizes scopes only, it
    // does not replicate feature-flag logic).
    #[allow(dead_code)]
    feature_gate: Option<&'static str>,
}

impl RouteAuthContract {
    const fn new(class: RouteAuthClass, scopes: &'static [&'static str]) -> Self {
        Self {
            class,
            scopes,
            feature_gate: None,
        }
    }

    const fn gated(class: RouteAuthClass, scopes: &'static [&'static str], feature_gate: &'static str) -> Self {
        Self {
            class,
            scopes,
            feature_gate: Some(feature_gate),
        }
    }
}

pub(crate) fn classify_route(method: &str, path: &str) -> Option<RouteAuthContract> {
    let method = method.to_ascii_uppercase();
    let method = method.as_str();

    if matches!(
        path,
        "/healthz"
            | "/readyz"
            | "/metrics"
            | "/session"
            | "/invocation/verify"
            | "/v1/openapi.json"
            | "/v1/version"
            | "/v1/witness/smoke"
            | "/v1/sync/handshake/nonce"
    ) {
        return Some(RouteAuthContract::new(RouteAuthClass::Public, &[]));
    }

    if path.starts_with("/v1/auth/") {
        // Unified-login auth rails (whoami, tailscale token, device grant) perform
        // their own identity gating (verified tailnet identity, device-grant
        // codes) and are reachable without a prior bearer by design — that is the
        // bootstrap they exist to provide. The device *approve* step is gated to
        // an authenticated console admin inside the handler, not by route scope.
        return Some(RouteAuthContract::new(RouteAuthClass::Public, &[]));
    }

    if path.starts_with("/v1/internal/replication/") {
        return Some(RouteAuthContract::new(
            RouteAuthClass::InternalReplication,
            &["replication:write"],
        ));
    }

    if path.starts_with("/v1/admin/") || matches!(path, "/v1/shard-map" | "/v1/gpus" | "/v1/shards" | "/v1/route") {
        // `sharing/backfill` and `restart` are POST-triggered admin mutations
        // even though a plain-GET admin route would read; every other non-GET
        // admin method is a write. (Behaviour-preserving: same class decision as
        // before, flattened to satisfy `clippy::if_same_then_else`.)
        let special_write = matches!(path, "/v1/admin/sharing/backfill" | "/v1/admin/restart");
        let class = if (method != "GET" && !special_write) || (method == "POST" && special_write) {
            RouteAuthClass::AdminWrite
        } else {
            RouteAuthClass::AdminRead
        };
        let scopes = match class {
            RouteAuthClass::AdminWrite => &["admin:write"][..],
            _ => &["admin:read"][..],
        };
        return Some(RouteAuthContract::new(class, scopes));
    }

    if path.starts_with("/v1/routing/") {
        return Some(RouteAuthContract::new(RouteAuthClass::AdminRead, &["admin:read"]));
    }

    if path.starts_with("/v1/projections/entity/") || path.starts_with("/v1/query/") {
        return Some(RouteAuthContract::new(
            RouteAuthClass::Read,
            &["query:read", "admin:read"],
        ));
    }

    // Semantic-read POSTs. These routes transform or retrieve caller-selected
    // data and their handlers require read authority; classifying by HTTP
    // method alone would make them unreachable once route auth defaults to
    // enforce.
    if method == "POST" && matches!(path, "/v1/projections/lookup" | "/v1/projections/batch_lookup") {
        return Some(RouteAuthContract::new(RouteAuthClass::AdminRead, &["admin:read"]));
    }
    if method == "POST" && path == "/v1/relations/expand" {
        return Some(RouteAuthContract::new(RouteAuthClass::AdminRead, &["admin:read"]));
    }
    if method == "POST"
        && matches!(
            path,
            "/v1/rcx/publish/projects/{projectId}/preview" | "/v1/rcx/publish/passports/{passportId}/preview"
        )
    {
        return Some(RouteAuthContract::new(RouteAuthClass::AdminRead, &["admin:read"]));
    }
    if method == "POST" && path == "/v1/console/engine/search" {
        return Some(RouteAuthContract::new(RouteAuthClass::AdminRead, &["admin:read"]));
    }
    if method == "POST" && path == "/v1/actions/enrich" {
        return Some(RouteAuthContract::new(
            RouteAuthClass::Read,
            &["query:read", "admin:read", "enrichers:first_party"],
        ));
    }

    // Studio template library install (crux-integrations-and-template-library
    // L2). This is the ONE /v1/studio/ route that mutates: it writes the
    // installed pack's board / designs / workspaces / pages as console facts,
    // so it must be write-class and must NOT be swept into the read-class
    // prefix rule below (a read token must never authorize an install).
    if method == "POST" && path.starts_with("/v1/studio/library/") {
        return Some(RouteAuthContract::new(
            RouteAuthClass::Write,
            &["facts:write", "admin:write"],
        ));
    }

    // Studio board packs (console-surfaces-remediation M15) + the read-only
    // library browse. Read class: the pack routes are pure transforms /
    // validators over a client-supplied payload (build = hash + optional sign;
    // verify = schema/hash/signature verdict) and `GET /v1/studio/library`
    // reads the verified cached index. None of them mutates the fact store;
    // the console apply step reuses the gated /v1/console/facts/add write route.
    if path.starts_with("/v1/studio/") {
        return Some(RouteAuthContract::new(
            RouteAuthClass::Read,
            &["query:read", "admin:read"],
        ));
    }

    if path.starts_with("/v1/projections/") {
        let class = if method == "GET" {
            RouteAuthClass::AdminRead
        } else {
            RouteAuthClass::AdminWrite
        };
        let scopes = if method == "GET" {
            &["admin:read"][..]
        } else {
            // Write-class: only a write scope authorizes (handler requires
            // admin:write). Read scopes must never be sufficient for a mutation.
            &["admin:write"][..]
        };
        return Some(RouteAuthContract::new(class, scopes));
    }

    if path.starts_with("/v1/receipts/")
        || path.starts_with("/v1/replay/")
        || path.starts_with("/v1/events/")
        || path.starts_with("/v1/observations/")
        || path.starts_with("/v1/ops/")
        || path.starts_with("/v1/bootstrap/")
        // Offline audit-bundle verification over caller-supplied bytes. Read
        // class: it mutates no daemon state and only reports a verdict, but it
        // is not an open surface — a read scope is required, and the upload is
        // size-capped at the route (compressed) and in the verifier (decompressed).
        || path.starts_with("/v1/audit/")
    {
        return Some(RouteAuthContract::new(
            RouteAuthClass::Read,
            &["query:read", "receipts:read", "exports:read", "admin:read"],
        ));
    }

    // Case store (M3). `/v1/cases/retrieve` is a POST but semantically a read
    // (similar-case lookup), so it is read-scoped; recording a case is a write.
    if path == "/v1/cases/retrieve" {
        return Some(RouteAuthContract::new(
            RouteAuthClass::Read,
            &["query:read", "admin:read"],
        ));
    }
    if path.starts_with("/v1/cases") {
        return Some(RouteAuthContract::new(
            RouteAuthClass::Write,
            &["facts:write", "admin:write"],
        ));
    }

    if path.starts_with("/v1/facts")
        || path.starts_with("/v1/sessions/")
        || path.starts_with("/v1/entities")
        || path.starts_with("/v1/edges")
        || path.starts_with("/v1/kinds")
    {
        let class = if method == "GET" {
            RouteAuthClass::Read
        } else {
            RouteAuthClass::Write
        };
        let scopes = if method == "GET" {
            &["query:read", "admin:read"][..]
        } else {
            &["facts:write", "sessions:write", "admin:write"][..]
        };
        return Some(RouteAuthContract::new(class, scopes));
    }

    if path.starts_with("/v1/features/capabilities") {
        let class = if method == "GET" {
            RouteAuthClass::Read
        } else {
            RouteAuthClass::Write
        };
        let scopes = if method == "GET" {
            &["facts:read", "admin:read"][..]
        } else {
            &["facts:write", "admin:write"][..]
        };
        return Some(RouteAuthContract::new(class, scopes));
    }

    if path.starts_with("/v1/sync/tenants/") {
        let class = if method == "GET" {
            RouteAuthClass::Read
        } else {
            RouteAuthClass::Write
        };
        let scopes = if method == "GET" {
            &["facts:read"][..]
        } else {
            &["facts:write"][..]
        };
        return Some(RouteAuthContract::new(class, scopes));
    }

    if path == "/v1/identity/candidates" || path.starts_with("/v1/identity/candidates/") {
        let class = if method == "GET" {
            RouteAuthClass::AdminRead
        } else {
            RouteAuthClass::AdminWrite
        };
        let scopes = if method == "GET" {
            &["admin:read", "admin:write"][..]
        } else {
            &["admin:write"][..]
        };
        return Some(RouteAuthContract::new(class, scopes));
    }

    if path.starts_with("/v1/memory/import")
        || path.starts_with("/v1/result-envelope/import")
        || path.starts_with("/v1/identity/links")
        || path.starts_with("/v1/append")
    {
        let class = if method == "GET" {
            RouteAuthClass::Read
        } else {
            RouteAuthClass::Write
        };
        // Write-class (POST/…) must not accept a read-only scope; the GET
        // read-class branch may keep the broader union.
        let scopes = if method == "GET" {
            &["facts:write", "admin:write", "admin:read"][..]
        } else {
            &["facts:write", "admin:write"][..]
        };
        return Some(RouteAuthContract::new(class, scopes));
    }

    if path.starts_with("/v1/local/ingest") {
        // Local prose-ingest door: mutation, gated to admin:write and checked
        // against the payload tenant in the handler (ExecPlan
        // cpu-prose-ingest-door-2026-07-01).
        return Some(RouteAuthContract::new(RouteAuthClass::AdminWrite, &["admin:write"]));
    }

    if path.starts_with("/v1/console/") {
        let mutating = !matches!(method, "GET")
            || path.ends_with("/install")
            || path.ends_with("/grant")
            || path.ends_with("/disable")
            || path.ends_with("/add");
        let class = if mutating {
            RouteAuthClass::AdminWrite
        } else {
            RouteAuthClass::AdminRead
        };
        let scopes = if mutating {
            &[
                "admin:write",
                "facts:write",
                "integrations:install",
                "integrations:grant",
                "integrations:disable",
            ][..]
        } else {
            &["admin:read", "tenant:chunks:read", "tenant:content:preview"][..]
        };
        return Some(RouteAuthContract::new(class, scopes));
    }

    if path.starts_with("/v1/integrations/") {
        let class = if method == "GET" {
            RouteAuthClass::AdminRead
        } else {
            RouteAuthClass::Write
        };
        let scopes = if method == "GET" {
            &["admin:read"][..]
        } else {
            &["integrations:install", "integrations:disable"][..]
        };
        return Some(RouteAuthContract::new(class, scopes));
    }

    if path.starts_with("/v1/repos") {
        let class = if method == "GET" {
            RouteAuthClass::AdminRead
        } else {
            RouteAuthClass::AdminWrite
        };
        let scopes = if method == "GET" {
            &["admin:read"][..]
        } else {
            &["admin:write"][..]
        };
        return Some(RouteAuthContract::new(class, scopes));
    }

    // Runtime span capture (ExecPlan crux-runtime-codemap M2). Read-only, and
    // admin-scoped: captured spans expose internal file paths and call
    // structure, which is operator information rather than tenant data.
    // M5 agent query API: same posture as /v1/traces — it exposes internal
    // call structure and file paths, which is operator information.
    if path.starts_with("/v1/code-intel") {
        return Some(RouteAuthContract::new(RouteAuthClass::AdminRead, &["admin:read"]));
    }

    if path.starts_with("/v1/traces") {
        return Some(RouteAuthContract::new(RouteAuthClass::AdminRead, &["admin:read"]));
    }

    if method == "GET" && path == "/v1/passport/mint-requests/pending" {
        return Some(RouteAuthContract::gated(
            RouteAuthClass::FeatureGated,
            &["admin:read"],
            "CORECRUXD_FEATURE_PASSPORT_MINT_REQUESTS",
        ));
    }

    if method == "POST"
        && matches!(
            path,
            "/v1/passport/mint-requests/{request_id}/approve" | "/v1/passport/mint-requests/{request_id}/reject"
        )
    {
        return Some(RouteAuthContract::gated(
            RouteAuthClass::FeatureGated,
            &["admin:write"],
            "CORECRUXD_FEATURE_PASSPORT_MINT_REQUESTS",
        ));
    }

    if method == "POST" && path == "/v1/passports" {
        return Some(RouteAuthContract::new(RouteAuthClass::AdminWrite, &["admin:write"]));
    }

    // Structural governance mutations are admin-only. Keep this exact table
    // ahead of the broader project/workspace/passport prefix contract so
    // facts:write or integration scopes cannot satisfy the middleware while
    // the handler requires admin:write.
    if matches!(
        (method, path),
        ("PATCH", "/v1/passports/{passportId}")
            | ("DELETE", "/v1/passports/{passportId}")
            | ("POST", "/v1/projects")
            | ("PATCH", "/v1/projects/{id}")
            | ("DELETE", "/v1/projects/{id}")
            | ("POST", "/v1/projects/{id}/passports")
            | ("DELETE", "/v1/projects/{id}/passports/{passportId}")
            | ("POST", "/v1/projects/{id}/tenants")
            | ("DELETE", "/v1/projects/{id}/tenants/{tenantId}")
            | ("POST", "/v1/projects/{id}/planes")
            | ("DELETE", "/v1/projects/{id}/planes/{planeId}")
            | ("POST", "/v1/projects/{id}/planes/{planeId}/passports")
            | ("DELETE", "/v1/projects/{id}/planes/{planeId}/passports/{passportId}")
            | ("POST", "/v1/projects/{id}/planes/{planeId}/tenants")
            | ("DELETE", "/v1/projects/{id}/planes/{planeId}/tenants/{tenantId}")
            | ("POST", "/v1/workspace/scan")
    ) {
        return Some(RouteAuthContract::new(RouteAuthClass::AdminWrite, &["admin:write"]));
    }

    // Pulling the git-backed ExecPlan replica rewrites the projection root. It
    // mutates nothing the daemon owns, but it changes what every reader sees,
    // so it is classified as an admin write rather than a read.
    if method == "POST" && (path == "/v1/execplans/refresh" || path == "/v1/execplans") {
        return Some(RouteAuthContract::new(RouteAuthClass::AdminWrite, &["admin:write"]));
    }

    if path.starts_with("/v1/workbench/") {
        let scopes = if method == "GET" {
            &[
                "admin:read",
                "query:read",
                "agent_brief:pro",
                "context_pack:budgeted",
                "impact:preflight",
                "ledger:history",
                "audit:triage",
                "reasoning:timeline",
                "handoff:v2",
                "route_probe:lab",
                "api_drift:check",
                "policy:simulate",
            ][..]
        } else {
            &[
                "admin:write",
                "agent_brief:pro",
                "context_pack:budgeted",
                "impact:preflight",
                "ledger:history",
                "audit:triage",
                "reasoning:timeline",
                "handoff:v2",
                "route_probe:lab",
                "api_drift:check",
                "policy:simulate",
            ][..]
        };
        return Some(RouteAuthContract::gated(
            RouteAuthClass::FeatureGated,
            scopes,
            "workbench product capability",
        ));
    }

    if path.starts_with("/v1/work")
        // Counts-only roll-up over the work / gate / coord feeds. It reads the
        // same surfaces as `/v1/work`, so it takes the same contract —
        // aggregating into integers is not a reason to authorize it any lower.
        || path.starts_with("/v1/attention/")
        || path.starts_with("/v1/status-feed")
        || path.starts_with("/v1/projects")
        || path.starts_with("/v1/rcx/publish/")
        || path.starts_with("/v1/workspace/")
        || path.starts_with("/v1/mcp/tools")
        || path.starts_with("/v1/engrams")
        || path.starts_with("/v1/extensions")
        || path.starts_with("/v1/passports")
        || path.starts_with("/v1/principal/")
        || path.starts_with("/v1/policy/")
        || path.starts_with("/v1/relations")
        || path.starts_with("/v1/agents/")
        || path.starts_with("/v1/cost/")
        || path.starts_with("/v1/cloud/")
        || path.starts_with("/v1/actions/")
        || path.starts_with("/v1/mediation/")
        || path.starts_with("/v1/memory/")
    {
        let class = if method == "GET" {
            RouteAuthClass::Read
        } else {
            RouteAuthClass::Write
        };
        let scopes = if method == "GET" {
            &["admin:read", "facts:read", "query:read", "sessions:read"][..]
        } else {
            // Write-class: drop the read-only query:read — a read token must not
            // authorize a mutation here.
            &["admin:write", "facts:write", "integrations:install"][..]
        };
        return Some(RouteAuthContract::new(class, scopes));
    }

    if path.starts_with("/v1/gpu1/") {
        let scopes = if method == "GET" {
            &["query:read", "admin:read"][..]
        } else {
            &[
                "gpu1:answer",
                "gpu1:rerank",
                "gpu1:enrich",
                "gpu1:coverage",
                "gpu1:developer",
                "admin:write",
            ][..]
        };
        return Some(RouteAuthContract::gated(
            RouteAuthClass::FeatureGated,
            scopes,
            "gpu1_compute",
        ));
    }

    if path == "/v1/compute/embed" {
        return Some(RouteAuthContract::gated(
            RouteAuthClass::FeatureGated,
            &["compute:embed"],
            "CORECRUXD_COMPUTE_PROVIDER",
        ));
    }

    if path.starts_with("/v1/context") {
        return Some(RouteAuthContract::gated(
            RouteAuthClass::FeatureGated,
            &["query:read", "admin:read"],
            "CORECRUXD_CONTEXT_SURFACE",
        ));
    }

    if path.starts_with("/v1/provenance/") {
        // W1 Provenance Marking Gateway (BYOK). Kept in sync with
        // `http::provenance::PROVENANCE_SCOPES`.
        return Some(RouteAuthContract::gated(
            RouteAuthClass::FeatureGated,
            &["provenance:write", "admin:write"],
            "CORECRUXD_FEATURE_PROVENANCE_API",
        ));
    }

    if path.starts_with("/v1/openai/") {
        return Some(RouteAuthContract::gated(
            RouteAuthClass::FeatureGated,
            &[
                "query:read",
                "facts:write",
                "sessions:write",
                "admin:read",
                "admin:write",
            ],
            "CORECRUXD_OPENAI_SHIM",
        ));
    }

    if path.starts_with("/v1/quota") {
        return Some(RouteAuthContract::gated(
            RouteAuthClass::FeatureGated,
            &["query:read", "admin:read"],
            "CORECRUXD_QUOTA",
        ));
    }

    if path.starts_with("/v1/credits/") {
        return Some(RouteAuthContract::gated(
            RouteAuthClass::FeatureGated,
            &["admin:write"],
            "CORECRUXD_CREDIT_METER",
        ));
    }

    if path.starts_with("/v1/incidents") {
        let scopes = if method == "GET" || path.ends_with("/export") {
            &["query:read", "exports:read", "admin:read"][..]
        } else {
            &["facts:write", "admin:write"][..]
        };
        return Some(RouteAuthContract::gated(
            RouteAuthClass::FeatureGated,
            scopes,
            "CORECRUXD_FEATURE_INCIDENTS",
        ));
    }

    // Escrow holds customer key ciphertext and the custodian-share release
    // lane; reads and writes are both admin-scoped, never public or query-read.
    if path.starts_with("/v1/escrow/") {
        return Some(if method == "GET" {
            RouteAuthContract::new(RouteAuthClass::AdminRead, &["admin:read"])
        } else {
            RouteAuthContract::new(RouteAuthClass::AdminWrite, &["admin:write"])
        });
    }
    if path.starts_with("/v1/legal-holds") {
        return Some(RouteAuthContract::gated(
            RouteAuthClass::FeatureGated,
            &["admin:write"],
            "CORECRUXD_FEATURE_LEGAL_HOLD",
        ));
    }

    if path.starts_with("/v1/coord/") {
        let scopes = if method == "GET" {
            &["admin:read", "sessions:read"][..]
        } else {
            &["admin:write", "sessions:write"][..]
        };
        return Some(RouteAuthContract::gated(
            RouteAuthClass::FeatureGated,
            scopes,
            "CORECRUXD_COORD",
        ));
    }

    if path.starts_with("/v1/observe/sessions/") {
        let scopes = if method == "GET" {
            &["query:read", "admin:read"][..]
        } else {
            &["facts:write", "admin:write"][..]
        };
        return Some(RouteAuthContract::gated(
            RouteAuthClass::FeatureGated,
            scopes,
            "CORECRUXD_OBSERVE",
        ));
    }

    if path.starts_with("/v1/orchestrators") || path.starts_with("/v1/punchcards") {
        let scopes = if method == "GET" {
            &["facts:read", "admin:read"][..]
        } else {
            &["facts:write", "admin:write"][..]
        };
        return Some(RouteAuthContract::gated(
            RouteAuthClass::FeatureGated,
            scopes,
            "CORECRUXD_AGENTGRAPH",
        ));
    }

    if path.starts_with("/v1/activity") {
        // Dual-surface activity log (CORECRUXD_FEATURE_ACTIVITY_LOG, default OFF).
        // GET reads the journal (tenant + privacy scoped, token_budget required);
        // POST ingests a journal append.
        let scopes = if method == "GET" {
            &["facts:read", "admin:read"][..]
        } else {
            &["facts:write", "admin:write"][..]
        };
        return Some(RouteAuthContract::gated(
            RouteAuthClass::FeatureGated,
            scopes,
            "CORECRUXD_FEATURE_ACTIVITY_LOG",
        ));
    }

    None
}

fn uses_sync_peer_handshake(path: &str) -> bool {
    matches!(
        path,
        "/v1/sync/tenants/{tenantId}/manifest"
            | "/v1/sync/tenants/{tenantId}/collections/{collection}"
            | "/v1/sync/tenants/{tenantId}/promotions/preview"
            | "/v1/sync/tenants/{tenantId}/promotions/confirm"
            | "/v1/sync/tenants/{tenantId}/offboard"
    )
}

/// Enforcement posture for the route-authorization middleware. Parsed once from
/// `CORECRUXD_ROUTE_AUTH` at router build time (never per request).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RouteAuthMode {
    /// Pass-through: the middleware does nothing.
    Off,
    /// Evaluate the contract and log would-denies, but never block.
    Shadow,
    /// Deny by default: classified routes require their scopes; unclassified
    /// routes and requests with no matched route template fail closed.
    Enforce,
}

impl RouteAuthMode {
    /// Resolve an explicit value or derive the secure default from daemon
    /// exposure. Unknown and empty explicit values fail safe to `enforce`.
    fn resolve(raw: Option<&str>, auth_mode: AuthMode, bind_loopback: bool) -> Self {
        match raw.map(|value| value.trim().to_ascii_lowercase()).as_deref() {
            Some("off") => Self::Off,
            Some("shadow") => Self::Shadow,
            Some("enforce") => Self::Enforce,
            Some(_) => Self::Enforce,
            None if auth_mode == AuthMode::Off && bind_loopback => Self::Shadow,
            None => Self::Enforce,
        }
    }

    /// Read `CORECRUXD_ROUTE_AUTH` once. Unset derives from auth/listener
    /// posture; an invalid explicit value is logged and fails safe to enforce.
    pub(crate) fn from_env(auth_mode: AuthMode, bind_loopback: bool) -> Self {
        match std::env::var("CORECRUXD_ROUTE_AUTH") {
            Ok(raw) => {
                let mode = Self::resolve(Some(&raw), auth_mode, bind_loopback);
                if !matches!(raw.trim().to_ascii_lowercase().as_str(), "off" | "shadow" | "enforce") {
                    tracing::warn!(
                        configured = %raw,
                        fallback = "enforce",
                        "invalid CORECRUXD_ROUTE_AUTH; failing safe"
                    );
                }
                mode
            }
            Err(std::env::VarError::NotPresent) => Self::resolve(None, auth_mode, bind_loopback),
            Err(std::env::VarError::NotUnicode(_)) => {
                tracing::warn!(fallback = "enforce", "non-Unicode CORECRUXD_ROUTE_AUTH; failing safe");
                Self::Enforce
            }
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Shadow => "shadow",
            Self::Enforce => "enforce",
        }
    }
}

/// Deny-by-default route-authorization middleware.
///
/// Runs before handler dispatch on every classified plane. Uses the axum
/// [`MatchedPath`] extension (the route *template*, e.g.
/// `/v1/identity/candidates/{candidateId}/confirm`) so the path matches the
/// [`classify_route`] contract-table keys, plus the request method. The
/// enforcement mode is captured in the layer state at build time.
pub(crate) async fn route_auth_middleware(
    State((state, mode)): State<(AppState, RouteAuthMode)>,
    req: Request,
    next: Next,
) -> Response {
    if mode == RouteAuthMode::Off {
        return next.run(req).await;
    }

    let method = req.method().as_str().to_ascii_uppercase();
    let matched = req.extensions().get::<MatchedPath>().map(|m| m.as_str().to_string());

    // No matched route template. For a routed request axum always populates
    // `MatchedPath`, so this is the pathological case — fail closed in enforce.
    let Some(path) = matched else {
        return match mode {
            RouteAuthMode::Enforce => problem_response(
                StatusCode::FORBIDDEN,
                format!("route has no authorization contract: {method} request has no matched path"),
            ),
            _ => {
                tracing::warn!(
                    marker = "route_auth_shadow_mismatch",
                    method = %method,
                    reason = "missing_matched_path",
                    "route authorization: request has no matched route template (shadow mode)"
                );
                next.run(req).await
            }
        };
    };

    let Some(contract) = classify_route(&method, &path) else {
        // Unclassified route: FAIL CLOSED in enforce; observe in shadow.
        return match mode {
            RouteAuthMode::Enforce => problem_response(
                StatusCode::FORBIDDEN,
                format!("route has no authorization contract: {method} {path}"),
            ),
            _ => {
                tracing::warn!(
                    marker = "route_auth_shadow_mismatch",
                    method = %method,
                    route = %path,
                    reason = "no_contract",
                    "route has no authorization contract (shadow mode)"
                );
                next.run(req).await
            }
        };
    };

    // In mutual-auth mode these exact routes are authorized cryptographically
    // by require_sync_read/write in the handlers. Requiring an ordinary scope
    // here would reject a handshake-only peer before verification; accepting
    // an admin scope here would also risk being mistaken for an auth bypass.
    // Keep this list exact so future sync routes do not inherit the deferral.
    if state.sync_mutual_auth && uses_sync_peer_handshake(&path) {
        return next.run(req).await;
    }

    // Public routes pass with no auth headers in every mode — monitors and the
    // unauthenticated bootstrap rails depend on this.
    if contract.class == RouteAuthClass::Public {
        return next.run(req).await;
    }

    // Classified route: require any-of the contract's accepted scope set via the
    // SAME primitive the handlers use. The contract lists scopes as an any-of
    // accepted set (read classes union read+admin scopes; write classes union
    // the write scopes that authorize the mutation), so `require_http_any_scope`
    // is the faithful check. `require_http_any_scope` returns `Ok` when the
    // daemon's own auth mode is `off`, and a `401` (no/invalid token) or `403`
    // (insufficient scope) problem otherwise — exactly the handler semantics.
    match require_http_any_scope(&state.auth, req.headers(), contract.scopes) {
        Ok(()) => next.run(req).await,
        Err(problem) => match mode {
            RouteAuthMode::Enforce => problem.into_response(),
            _ => {
                tracing::warn!(
                    marker = "route_auth_shadow_mismatch",
                    method = %method,
                    route = %path,
                    class = ?contract.class,
                    scopes = ?contract.scopes,
                    reason = "insufficient_scope",
                    "route authorization contract would deny (shadow mode)"
                );
                next.run(req).await
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scope that only grants read access. Such a scope must never appear in a
    /// write-class route's accepted (sufficient) set.
    fn is_read_only_scope(scope: &str) -> bool {
        scope.ends_with(":read") || scope == "tenant:content:preview"
    }

    /// A scope that grants a mutation. Every write-class route must accept at
    /// least one of these.
    fn is_write_scope(scope: &str) -> bool {
        scope.ends_with(":write")
            || matches!(
                scope,
                "integrations:install" | "integrations:grant" | "integrations:disable"
            )
    }

    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
    struct ParsedRoute {
        method: String,
        path: String,
    }

    fn parse_routes_in_source(src: &str) -> Vec<ParsedRoute> {
        let mut out = Vec::new();
        let bytes = src.as_bytes();
        let needle = b".route(";
        let mut i = 0usize;
        while i + needle.len() <= bytes.len() {
            if &bytes[i..i + needle.len()] != needle {
                i += 1;
                continue;
            }

            let chunk_start = i + needle.len();
            let mut depth = 1i32;
            let mut j = chunk_start;
            let mut in_str = false;
            let mut prev = 0u8;
            while j < bytes.len() && depth > 0 {
                let c = bytes[j];
                if in_str {
                    if c == b'"' && prev != b'\\' {
                        in_str = false;
                    }
                } else {
                    match c {
                        b'"' => in_str = true,
                        b'(' => depth += 1,
                        b')' => depth -= 1,
                        _ => {}
                    }
                }
                prev = c;
                if depth == 0 {
                    break;
                }
                j += 1;
            }
            if depth == 0 {
                let chunk = std::str::from_utf8(&bytes[chunk_start..j]).unwrap_or("");
                out.extend(parse_route_chunk(chunk));
                i = j + 1;
            } else {
                i += needle.len();
            }
        }
        out
    }

    fn parse_route_chunk(chunk: &str) -> Vec<ParsedRoute> {
        let Some(after_quote) = chunk.trim_start().strip_prefix('"') else {
            return Vec::new();
        };
        let Some((path, rest)) = after_quote.split_once('"') else {
            return Vec::new();
        };

        let mut routes = Vec::new();
        let mut rest = rest;
        for method in ["get", "post", "put", "patch", "delete"] {
            let first = format!("{method}(");
            let chained = format!(".{method}(");
            if rest.contains(&first) || rest.contains(&chained) {
                routes.push(ParsedRoute {
                    method: method.to_ascii_uppercase(),
                    path: path.to_string(),
                });
                rest = rest.trim_start_matches(',');
            }
        }
        routes
    }

    fn router_routes() -> Vec<ParsedRoute> {
        let mut routes = Vec::new();
        for source in [
            include_str!("mod.rs"),
            include_str!("observe_audit.rs"),
            include_str!("orchestrators.rs"),
            include_str!("punchcards.rs"),
        ] {
            routes.extend(parse_routes_in_source(source));
        }
        routes.sort();
        routes.dedup();
        routes
    }

    #[test]
    fn route_auth_unset_derives_from_auth_and_listener_posture() {
        let cases = [
            (AuthMode::Off, true, RouteAuthMode::Shadow),
            (AuthMode::Off, false, RouteAuthMode::Enforce),
            (AuthMode::DevScopes, true, RouteAuthMode::Enforce),
            (AuthMode::DevScopes, false, RouteAuthMode::Enforce),
            (AuthMode::JwtHs256, true, RouteAuthMode::Enforce),
            (AuthMode::JwtJwks, true, RouteAuthMode::Enforce),
        ];
        for (auth_mode, bind_loopback, expected) in cases {
            assert_eq!(
                RouteAuthMode::resolve(None, auth_mode, bind_loopback),
                expected,
                "auth={} loopback={bind_loopback}",
                auth_mode.as_str()
            );
        }
    }

    #[test]
    fn route_auth_explicit_modes_and_typos_are_deterministic() {
        for auth_mode in [
            AuthMode::Off,
            AuthMode::DevScopes,
            AuthMode::JwtHs256,
            AuthMode::JwtJwks,
        ] {
            for bind_loopback in [true, false] {
                assert_eq!(
                    RouteAuthMode::resolve(Some("off"), auth_mode, bind_loopback),
                    RouteAuthMode::Off
                );
                assert_eq!(
                    RouteAuthMode::resolve(Some(" SHADOW "), auth_mode, bind_loopback),
                    RouteAuthMode::Shadow
                );
                assert_eq!(
                    RouteAuthMode::resolve(Some("Enforce"), auth_mode, bind_loopback),
                    RouteAuthMode::Enforce
                );
                assert_eq!(
                    RouteAuthMode::resolve(Some(""), auth_mode, bind_loopback),
                    RouteAuthMode::Enforce
                );
                assert_eq!(
                    RouteAuthMode::resolve(Some("enfore"), auth_mode, bind_loopback),
                    RouteAuthMode::Enforce
                );
            }
        }
    }

    #[test]
    fn route_auth_matrix_is_complete() {
        let missing: Vec<String> = router_routes()
            .into_iter()
            .filter(|route| classify_route(&route.method, &route.path).is_none())
            .map(|route| format!("{} {}", route.method, route.path))
            .collect();
        assert!(missing.is_empty(), "routes missing auth classification: {missing:?}");
    }

    #[test]
    fn route_auth_scope_contracts() {
        let cases = [
            ("POST", "/v1/sync/handshake/nonce", RouteAuthClass::Public, &[][..]),
            (
                "GET",
                "/v1/admin/version",
                RouteAuthClass::AdminRead,
                &["admin:read"][..],
            ),
            (
                "POST",
                "/v1/admin/restart",
                RouteAuthClass::AdminWrite,
                &["admin:write"][..],
            ),
            (
                "POST",
                "/v1/internal/replication/segments",
                RouteAuthClass::InternalReplication,
                &["replication:write"][..],
            ),
            (
                "POST",
                "/v1/console/embedding/probe",
                RouteAuthClass::AdminWrite,
                &["admin:write"][..],
            ),
            (
                "GET",
                "/v1/projections/entity/count",
                RouteAuthClass::Read,
                &["query:read", "admin:read"][..],
            ),
            (
                "POST",
                "/v1/gpu1/answer",
                RouteAuthClass::FeatureGated,
                &["gpu1:answer", "admin:write"][..],
            ),
            (
                "POST",
                "/v1/compute/embed",
                RouteAuthClass::FeatureGated,
                &["compute:embed"][..],
            ),
            (
                "POST",
                "/v1/credits/spend",
                RouteAuthClass::FeatureGated,
                &["admin:write"][..],
            ),
            (
                "GET",
                "/v1/identity/candidates",
                RouteAuthClass::AdminRead,
                &["admin:read"][..],
            ),
            (
                "GET",
                "/v1/passport/mint-requests/pending",
                RouteAuthClass::FeatureGated,
                &["admin:read"][..],
            ),
            (
                "POST",
                "/v1/passport/mint-requests/{request_id}/approve",
                RouteAuthClass::FeatureGated,
                &["admin:write"][..],
            ),
            (
                "POST",
                "/v1/passport/mint-requests/{request_id}/reject",
                RouteAuthClass::FeatureGated,
                &["admin:write"][..],
            ),
            (
                "POST",
                "/v1/passports",
                RouteAuthClass::AdminWrite,
                &["admin:write"][..],
            ),
            (
                "POST",
                "/v1/identity/candidates/{candidateId}/confirm",
                RouteAuthClass::AdminWrite,
                &["admin:write"][..],
            ),
            (
                "POST",
                "/v1/identity/candidates/{candidateId}/reject",
                RouteAuthClass::AdminWrite,
                &["admin:write"][..],
            ),
        ];

        for (method, path, class, scopes) in cases {
            let contract = classify_route(method, path).expect("route contract");
            assert_eq!(contract.class, class, "{method} {path}");
            for scope in scopes {
                assert!(
                    contract.scopes.contains(scope),
                    "{method} {path} missing expected scope {scope}; got {:?}",
                    contract.scopes
                );
            }
        }
    }

    #[test]
    fn structural_mutation_contracts_require_exact_admin_write() {
        let mutations = [
            ("PATCH", "/v1/passports/{passportId}"),
            ("DELETE", "/v1/passports/{passportId}"),
            ("POST", "/v1/projects"),
            ("PATCH", "/v1/projects/{id}"),
            ("DELETE", "/v1/projects/{id}"),
            ("POST", "/v1/projects/{id}/passports"),
            ("DELETE", "/v1/projects/{id}/passports/{passportId}"),
            ("POST", "/v1/projects/{id}/tenants"),
            ("DELETE", "/v1/projects/{id}/tenants/{tenantId}"),
            ("POST", "/v1/projects/{id}/planes"),
            ("DELETE", "/v1/projects/{id}/planes/{planeId}"),
            ("POST", "/v1/projects/{id}/planes/{planeId}/passports"),
            ("DELETE", "/v1/projects/{id}/planes/{planeId}/passports/{passportId}"),
            ("POST", "/v1/projects/{id}/planes/{planeId}/tenants"),
            ("DELETE", "/v1/projects/{id}/planes/{planeId}/tenants/{tenantId}"),
            ("POST", "/v1/workspace/scan"),
        ];
        for (method, path) in mutations {
            let contract = classify_route(method, path).expect("structural mutation contract");
            assert_eq!(contract.class, RouteAuthClass::AdminWrite, "{method} {path}");
            assert_eq!(contract.scopes, &["admin:write"], "{method} {path}");
        }
    }

    #[test]
    fn semantic_post_and_capability_contracts_remain_reachable_in_enforce() {
        let cases: &[(&str, &str, &[&str])] = &[
            ("POST", "/v1/projections/lookup", &["admin:read"]),
            ("POST", "/v1/projections/batch_lookup", &["admin:read"]),
            ("POST", "/v1/relations/expand", &["admin:read"]),
            ("POST", "/v1/rcx/publish/projects/{projectId}/preview", &["admin:read"]),
            (
                "POST",
                "/v1/rcx/publish/passports/{passportId}/preview",
                &["admin:read"],
            ),
            ("POST", "/v1/console/engine/search", &["admin:read"]),
            ("POST", "/v1/actions/enrich", &["query:read", "enrichers:first_party"]),
            (
                "POST",
                "/v1/openai/invoke",
                &["query:read", "facts:write", "sessions:write"],
            ),
            ("POST", "/v1/gpu1/rerank", &["gpu1:rerank", "admin:write"]),
            (
                "POST",
                "/v1/workbench/context-pack",
                &["context_pack:budgeted", "admin:write"],
            ),
            ("GET", "/v1/workbench/contract", &["query:read", "admin:read"]),
            ("GET", "/v1/workbench/brief", &["agent_brief:pro", "admin:read"]),
        ];
        for (method, path, expected_scopes) in cases {
            let contract = classify_route(method, path).expect("route contract");
            for scope in *expected_scopes {
                assert!(
                    contract.scopes.contains(scope),
                    "{method} {path} missing handler scope {scope}; got {:?}",
                    contract.scopes
                );
            }
        }
    }

    #[test]
    fn passport_mint_routes_record_the_feature_gate() {
        for (method, path, scopes) in [
            ("GET", "/v1/passport/mint-requests/pending", &["admin:read"][..]),
            (
                "POST",
                "/v1/passport/mint-requests/{request_id}/approve",
                &["admin:write"][..],
            ),
            (
                "POST",
                "/v1/passport/mint-requests/{request_id}/reject",
                &["admin:write"][..],
            ),
        ] {
            let Some(contract) = classify_route(method, path) else {
                panic!("missing passport mint route contract for {method} {path}");
            };
            assert_eq!(contract.class, RouteAuthClass::FeatureGated, "{path}");
            assert_eq!(contract.scopes, scopes, "{path}");
            assert_eq!(
                contract.feature_gate,
                Some("CORECRUXD_FEATURE_PASSPORT_MINT_REQUESTS"),
                "{path}"
            );
        }
    }

    #[test]
    fn write_class_routes_do_not_accept_read_only_scopes() {
        // Sweep every live route: any classified Write/AdminWrite contract must
        // require a write scope and must not list a read-only scope as
        // sufficient (else a read token could authorize a mutation).
        for route in router_routes() {
            let Some(contract) = classify_route(&route.method, &route.path) else {
                continue;
            };
            if !matches!(contract.class, RouteAuthClass::Write | RouteAuthClass::AdminWrite) {
                continue;
            }
            for scope in contract.scopes {
                assert!(
                    !is_read_only_scope(scope),
                    "{} {} is write-class but accepts read-only scope {scope}; got {:?}",
                    route.method,
                    route.path,
                    contract.scopes
                );
            }
            assert!(
                contract.scopes.iter().any(|s| is_write_scope(s)),
                "{} {} is write-class but accepts no write scope; got {:?}",
                route.method,
                route.path,
                contract.scopes
            );
        }
    }

    #[test]
    fn write_class_contracts_for_known_mutations_are_write_only() {
        // Direct check on representative mutations (independent of the router
        // parser) so a regression is caught even if a path drops out of the
        // parsed sources.
        let mutations = [
            ("POST", "/v1/projections/rebuild"),
            ("POST", "/v1/append"),
            ("POST", "/v1/work/items"),
            ("POST", "/v1/facts"),
            ("PUT", "/v1/sync/tenants/abc"),
            ("POST", "/v1/features/capabilities/x/audit"),
            ("POST", "/v1/identity/candidates/x/confirm"),
            ("POST", "/v1/admin/restart"),
        ];
        for (method, path) in mutations {
            let contract = classify_route(method, path).expect("contract");
            assert!(
                matches!(contract.class, RouteAuthClass::Write | RouteAuthClass::AdminWrite),
                "{method} {path} should classify write-class, got {:?}",
                contract.class
            );
            for scope in contract.scopes {
                assert!(
                    !is_read_only_scope(scope),
                    "{method} {path} accepts read-only scope {scope}; got {:?}",
                    contract.scopes
                );
            }
            assert!(
                contract.scopes.iter().any(|s| is_write_scope(s)),
                "{method} {path} has no write scope; got {:?}",
                contract.scopes
            );
        }
    }

    #[test]
    fn admin_write_routes_do_not_accept_admin_read_only() {
        for route in router_routes() {
            let Some(contract) = classify_route(&route.method, &route.path) else {
                continue;
            };
            if contract.class == RouteAuthClass::AdminWrite {
                assert!(
                    !contract.scopes.contains(&"admin:read"),
                    "{} {} is AdminWrite but accepts admin:read; got {:?}",
                    route.method,
                    route.path,
                    contract.scopes
                );
            }
        }
    }

    #[test]
    fn feature_gated_write_routes_have_write_scope() {
        // Feature-gated routes invoked with a mutating method must require a
        // write scope and reject read-only scopes on the write branch.
        let gated_mutations = [
            ("POST", "/v1/coord/lease"),
            ("POST", "/v1/incidents"),
            ("POST", "/v1/legal-holds"),
            ("DELETE", "/v1/legal-holds/lh_123"),
            ("POST", "/v1/observe/sessions/abc/event"),
            ("POST", "/v1/orchestrators/run"),
            ("POST", "/v1/punchcards/x"),
            ("POST", "/v1/activity"),
        ];
        for (method, path) in gated_mutations {
            let contract = classify_route(method, path).expect("contract");
            assert_eq!(contract.class, RouteAuthClass::FeatureGated, "{method} {path}");
            assert!(
                contract.scopes.iter().any(|s| is_write_scope(s)),
                "{method} {path} gated write must include a write scope; got {:?}",
                contract.scopes
            );
            for scope in contract.scopes {
                assert!(
                    !is_read_only_scope(scope),
                    "{method} {path} gated write accepts read-only scope {scope}; got {:?}",
                    contract.scopes
                );
            }
        }
    }

    #[test]
    fn http_boundary_contracts() {
        let routes = router_routes();
        assert!(
            routes
                .iter()
                .any(|r| r.method == "POST" && r.path == "/v1/admin/restart"),
            "admin restart route must stay covered by the auth matrix"
        );
        assert!(
            routes
                .iter()
                .any(|r| r.method == "GET" && r.path == "/v1/projections/entity/count"),
            "entity projection routes must stay covered by the auth matrix"
        );
        assert!(
            routes
                .iter()
                .any(|r| r.method == "POST" && r.path == "/v1/console/embedding/probe"),
            "embedding probe route must stay covered by the auth matrix"
        );
    }
}
