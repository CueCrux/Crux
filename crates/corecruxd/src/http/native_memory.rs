// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Read-only HTTP surface over the harness-native memory store.
//!
//! ExecPlan `crux-memory-parity-and-codex-bridge-2026-09-17` **M4**. The
//! projection itself is [`corecrux_projections::native_memory`]; this module is
//! the axum-facing shim, in the same shape as [`super::engrams`].
//!
//! ## Why it exists
//!
//! Claude Code's curated memory lives on disk and the daemon has never been able
//! to see it. Codex has no memory store of its own at all. These three routes
//! are the narrow bridge: a Codex session (or any client with a read scope) can
//! list the operator's memories, pull one body by slug, and search their
//! descriptions — memory that until now only one harness could reach.
//!
//! ```text
//! GET /v1/memory/native            list projected memories (no bodies)
//! GET /v1/memory/native/search?q=  description-text search, honest about misses
//! GET /v1/memory/native/{slug}     one memory, with its body read on demand
//! ```
//!
//! ## Posture
//!
//! * **Read-only.** Nothing here mutates the memory directory, and nothing here
//!   writes facts. The projection is computed per request from disk, so the
//!   daemon holds no stale copy of the operator's memory.
//! * **Default off.** Unset [`NATIVE_MEMORY_ROOT_ENV`] means every route
//!   answers `404`, with no filesystem access at all.
//! * **Never logs bodies.** A memory body can quote a credential. Traces carry
//!   slugs and counts; secret-shaped tokens are redacted out of descriptions,
//!   hooks and bodies before they leave the projection.

use serde::Deserialize;
use serde_json::json;

use corecrux_projections::native_memory::{
    ingest_native_memory, read_memory_body, resolve_roots, search_memories, NativeMemoryEntryV1, NativeMemoryError,
    NativeMemoryIngestOptions, NativeMemoryIngestV1, NATIVE_MEMORY_FACT_KEY, NATIVE_MEMORY_PROJECTION_ID,
    NATIVE_MEMORY_ROOT_ENV,
};

use super::{
    problem_response, require_http_any_scope, AppState, HeaderMap, IntoResponse, Json, Path, Query, State, StatusCode,
};

/// Read scopes accepted on every route here. Matches the `/v1/memory/` row in
/// `route_auth::classify_route`, which is the coarse gate in front of these
/// handler-level checks.
const READ_SCOPES: &[&str] = &["admin:read", "facts:read", "query:read", "sessions:read"];

/// Default page size for the list route.
const DEFAULT_LIST_LIMIT: usize = 200;
/// Hard ceiling on rows returned by list or search.
const MAX_LIMIT: usize = 1_000;
/// Default match floor for the search route: at least a third of the query's
/// terms must appear. Below the floor we return nothing rather than falling back
/// to recency — the honesty rule this plan's M1 sets for retrieval generally.
const DEFAULT_MATCH_FLOOR: f32 = 0.34;

#[derive(Debug, Deserialize)]
pub(super) struct ListNativeMemoryQuery {
    /// Restrict to one `MEMORY.md` heading.
    #[serde(default)]
    pub group: Option<String>,
    /// Restrict to one `metadata.type`.
    #[serde(default, rename = "type")]
    pub memory_type: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
    /// Include the parsed `MEMORY.md` sections and the full edge list.
    #[serde(default)]
    pub include_index: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub(super) struct SearchNativeMemoryQuery {
    /// Query text, matched against slug, description, index title/hook and group.
    #[serde(default)]
    pub q: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
    /// Override the match floor (0.0–1.0).
    #[serde(default)]
    pub floor: Option<f32>,
}

#[derive(Debug, Deserialize)]
pub(super) struct GetNativeMemoryQuery {
    /// Set `body=false` for the pointer record without reading the file.
    #[serde(default)]
    pub body: Option<bool>,
}

/// Resolve the configured roots, or `None` when the feature is off.
///
/// `CORECRUXD_NATIVE_MEMORY_ROOT` is a `:`-separated list; `~/` expands against
/// `$HOME` and one `*` segment expands over its children, so the documented
/// `~/.claude/projects/*/memory` covers every project directory on the host.
fn configured_roots() -> Option<Vec<std::path::PathBuf>> {
    let spec = std::env::var(NATIVE_MEMORY_ROOT_ENV).ok()?;
    if spec.trim().is_empty() {
        return None;
    }
    let home = std::env::var("HOME").ok().map(std::path::PathBuf::from);
    let roots = resolve_roots(&spec, home.as_deref());
    if roots.is_empty() {
        return None;
    }
    Some(roots)
}

/// Authorize, then run one read-only ingest pass. `Err` is a ready response,
/// boxed because an axum `Response` is a large `Err` variant to carry inline.
fn authorized_ingest(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<NativeMemoryIngestV1, Box<axum::response::Response>> {
    if let Err(problem) = require_http_any_scope(&state.auth, headers, READ_SCOPES) {
        return Err(Box::new(problem.into_response()));
    }
    let Some(roots) = configured_roots() else {
        return Err(Box::new(problem_response(
            StatusCode::NOT_FOUND,
            format!("native memory projection is disabled; set {NATIVE_MEMORY_ROOT_ENV}"),
        )));
    };
    let ingest = ingest_native_memory(&roots, NativeMemoryIngestOptions::default());
    // Counts only. A body — or a description — can quote a credential, so
    // nothing from the store itself reaches the log.
    tracing::debug!(
        target: "corecruxd::native_memory",
        roots = roots.len(),
        files_scanned = ingest.files_scanned,
        memories = ingest.memories,
        dangling = ingest.dangling.len(),
        warnings = ingest.warnings.len(),
        "native memory ingest"
    );
    Ok(ingest)
}

/// The pointer record for one memory: the `memory_md_ref` fact value plus its
/// addressing. Never the body — that is fetched per slug.
fn row(entry: &NativeMemoryEntryV1) -> serde_json::Value {
    json!({
        "slug": entry.slug,
        "entity": entry.entity(),
        "key": NATIVE_MEMORY_FACT_KEY,
        "value": entry.fact_value(),
    })
}

fn clamp_limit(requested: Option<usize>, default: usize) -> usize {
    requested.unwrap_or(default).clamp(1, MAX_LIMIT)
}

fn warning_rows(ingest: &NativeMemoryIngestV1) -> Vec<serde_json::Value> {
    ingest
        .warnings
        .iter()
        .map(|w| json!({ "kind": w.kind, "file": w.file, "detail": w.detail }))
        .collect()
}

/// `GET /v1/memory/native` — list every projected memory, bodies excluded.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn list_native_memory(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ListNativeMemoryQuery>,
) -> impl IntoResponse {
    let ingest = match authorized_ingest(&state, &headers) {
        Ok(ingest) => ingest,
        Err(response) => return *response,
    };
    let limit = clamp_limit(query.limit, DEFAULT_LIST_LIMIT);
    let group = query.group.as_deref().filter(|s| !s.trim().is_empty());
    let memory_type = query.memory_type.as_deref().filter(|s| !s.trim().is_empty());
    let matched: Vec<&NativeMemoryEntryV1> = ingest
        .entries
        .values()
        .filter(|e| group.is_none_or(|g| e.group.as_deref() == Some(g)))
        .filter(|e| memory_type.is_none_or(|t| e.memory_type.as_deref() == Some(t)))
        .collect();
    let total = matched.len();
    let rows: Vec<serde_json::Value> = matched.into_iter().take(limit).map(row).collect();

    let mut body = json!({
        "schema": "crux.memory.native.list.v1",
        "projection": NATIVE_MEMORY_PROJECTION_ID,
        "roots": ingest.roots,
        "read_only": true,
        "files_scanned": ingest.files_scanned,
        "memories": ingest.memories,
        "set_hash": ingest.set_hash,
        "returned": rows.len(),
        "total": total,
        "memories_page": rows,
        "groups": ingest.groups,
        "dangling": ingest.dangling,
        "warnings": warning_rows(&ingest),
    });
    if query.include_index.unwrap_or(false) {
        body["indexes"] = json!(ingest.indexes);
        body["edges"] = json!(ingest.edges);
    }
    (StatusCode::OK, Json(body)).into_response()
}

/// `GET /v1/memory/native/search?q=` — description-text search.
///
/// Returns `match: "none"` and an empty `hits` array when nothing clears the
/// floor. There is no recency fallback: a miss reads as a miss.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn search_native_memory(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<SearchNativeMemoryQuery>,
) -> impl IntoResponse {
    let ingest = match authorized_ingest(&state, &headers) {
        Ok(ingest) => ingest,
        Err(response) => return *response,
    };
    let q = query.q.unwrap_or_default();
    if q.trim().is_empty() {
        return problem_response(StatusCode::BAD_REQUEST, "query parameter `q` is required").into_response();
    }
    let floor = query.floor.unwrap_or(DEFAULT_MATCH_FLOOR).clamp(0.0, 1.0);
    let limit = clamp_limit(query.limit, 20);
    let hits = search_memories(&ingest, &q, floor, limit);
    let matched = if hits.is_empty() { "none" } else { "scored" };
    (
        StatusCode::OK,
        Json(json!({
            "schema": "crux.memory.native.search.v1",
            "projection": NATIVE_MEMORY_PROJECTION_ID,
            "query": q,
            "floor": floor,
            "match": matched,
            "fallback": false,
            "searched": ingest.memories,
            "hits": hits,
        })),
    )
        .into_response()
}

/// `GET /v1/memory/native/{slug}` — one memory, with its body read on demand.
#[tracing::instrument(level = "info", skip_all, fields(slug = %slug))]
pub(super) async fn get_native_memory(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(slug): Path<String>,
    Query(query): Query<GetNativeMemoryQuery>,
) -> impl IntoResponse {
    let ingest = match authorized_ingest(&state, &headers) {
        Ok(ingest) => ingest,
        Err(response) => return *response,
    };
    let Some(entry) = ingest.get(&slug) else {
        return problem_response(StatusCode::NOT_FOUND, format!("no native memory with slug {slug:?}")).into_response();
    };
    let mut body = row(entry);
    body["schema"] = json!("crux.memory.native.get.v1");
    body["projection"] = json!(NATIVE_MEMORY_PROJECTION_ID);
    body["read_only"] = json!(true);
    body["description"] = json!(entry.description);
    body["group"] = json!(entry.group);
    body["links"] = json!(entry.links);
    body["dangling_links"] = json!(entry.dangling_links);
    body["backlinks"] = json!(entry.backlinks);

    if query.body.unwrap_or(true) {
        match read_memory_body(&ingest, &slug, NativeMemoryIngestOptions::default()) {
            Ok(read) => {
                body["body"] = json!(read.body);
                body["body_bytes"] = json!(read.body_bytes);
                body["content_hash"] = json!(read.content_hash);
                body["changed_since_ingest"] = json!(read.changed_since_ingest);
                body["redacted"] = json!(read.redacted);
                body["lossy"] = json!(read.lossy);
            }
            Err(NativeMemoryError::InvalidSlug) => {
                return problem_response(StatusCode::BAD_REQUEST, "invalid memory slug").into_response()
            }
            Err(NativeMemoryError::UnknownSlug { .. }) => {
                return problem_response(StatusCode::NOT_FOUND, "memory file disappeared between ingest and read")
                    .into_response()
            }
            Err(NativeMemoryError::Io(err)) => {
                // The error kind, never the path or the contents.
                return problem_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("memory body unreadable: {}", err.kind()),
                )
                .into_response();
            }
        }
    }
    (StatusCode::OK, Json(body)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_are_clamped_into_range() {
        assert_eq!(clamp_limit(None, DEFAULT_LIST_LIMIT), DEFAULT_LIST_LIMIT);
        assert_eq!(clamp_limit(Some(0), DEFAULT_LIST_LIMIT), 1);
        assert_eq!(clamp_limit(Some(usize::MAX), DEFAULT_LIST_LIMIT), MAX_LIMIT);
        assert_eq!(clamp_limit(Some(7), DEFAULT_LIST_LIMIT), 7);
    }

    #[test]
    fn row_carries_the_pointer_and_not_the_body() {
        let entry = NativeMemoryEntryV1 {
            slug: "example-memory".to_string(),
            file_name: "example-memory.md".to_string(),
            root: "/tmp/memory".to_string(),
            name: Some("example-memory".to_string()),
            description: "A one-line recall hook".to_string(),
            memory_type: Some("project".to_string()),
            node_type: Some("memory".to_string()),
            modified: Some("2026-09-17T00:00:00.000Z".to_string()),
            group: Some("Environment traps".to_string()),
            index_title: Some("Example".to_string()),
            index_hook: Some("hook".to_string()),
            links: vec!["other".to_string()],
            dangling_links: vec![],
            backlinks: vec![],
            bytes: 128,
            body_bytes: 64,
            content_hash: "deadbeef".to_string(),
            redacted: false,
            lossy: false,
        };
        let row = row(&entry);
        assert_eq!(row["entity"], "memory:example-memory");
        assert_eq!(row["key"], NATIVE_MEMORY_FACT_KEY);
        assert_eq!(row["value"]["memory_md_ref"], "example-memory.md");
        assert!(row.get("body").is_none());
    }

    #[test]
    fn unset_env_disables_the_feature() {
        // Not a `set_var` test: the guard is simply that an unset or blank spec
        // resolves to no roots, which the handlers turn into a 404.
        let resolved = resolve_roots("   ", None);
        assert!(resolved.is_empty());
    }
}
