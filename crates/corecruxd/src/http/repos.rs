// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! HTTP CRUD for tenant-scoped repository registrations.

use std::collections::BTreeMap;
use std::path::PathBuf;

use super::{
    problem_response, require_http_scopes_for_tenant, AppState, HeaderMap, IntoResponse, Json, Path, Query, State,
    StatusCode,
};

#[derive(Debug, serde::Deserialize)]
pub(super) struct CreateRepoBody {
    #[serde(default)]
    pub repo_id: Option<String>,
    pub tenant_id: String,
    #[serde(default)]
    pub root_path: Option<String>,
    #[serde(default)]
    pub clone_url: Option<String>,
    #[serde(default)]
    pub languages: Vec<String>,
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct RepoTenantQuery {
    pub tenant_id: String,
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct RepoDependentsQuery {
    pub tenant_id: String,
    pub ecosystem: String,
    pub name: String,
    #[serde(default)]
    pub cursor: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

fn clean_opt(value: Option<String>) -> Option<String> {
    value.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

fn body_repo_id(body: &CreateRepoBody, root_path: Option<&str>, clone_url: Option<&str>) -> String {
    clean_opt(body.repo_id.clone()).unwrap_or_else(|| {
        root_path
            .or(clone_url)
            .map_or_else(|| "repo".to_string(), crate::repo_registry::slug)
    })
}

fn map_registry_error(err: crate::repo_registry::RepoRegistryError) -> axum::response::Response {
    use crate::repo_registry::RepoRegistryError;
    match err {
        RepoRegistryError::Duplicate { .. } => problem_response(StatusCode::CONFLICT, err.to_string()),
        RepoRegistryError::NotFound { .. } => problem_response(StatusCode::NOT_FOUND, err.to_string()),
        RepoRegistryError::InvalidTenantId(_) | RepoRegistryError::InvalidRepoId(_) | RepoRegistryError::Json(_) => {
            problem_response(StatusCode::BAD_REQUEST, err.to_string())
        }
    }
}

pub(super) async fn post_repo(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CreateRepoBody>,
) -> impl IntoResponse {
    let tenant_id = body.tenant_id.trim().to_string();
    if let Err(err) = crate::repo_registry::validate_tenant_id(&tenant_id) {
        return map_registry_error(err);
    }
    if let Err(problem) = require_http_scopes_for_tenant(&state.auth, &headers, &["admin:write"], &tenant_id) {
        return problem.into_response();
    }

    let root_path = clean_opt(body.root_path.clone());
    let clone_url = clean_opt(body.clone_url.clone());
    if root_path.is_some() == clone_url.is_some() {
        return problem_response(
            StatusCode::BAD_REQUEST,
            "exactly one of root_path or clone_url is required",
        );
    }

    let repo_id = body_repo_id(&body, root_path.as_deref(), clone_url.as_deref());
    if let Err(err) = crate::repo_registry::validate_repo_id(&repo_id) {
        return map_registry_error(err);
    }

    let mut note = None;
    let mut scan_json = None;
    let mut scan_for_codegraph = None;
    let mut last_scan_id = None;
    if let Some(path) = root_path.as_deref() {
        let path_buf = PathBuf::from(path);
        if !path_buf.is_absolute() {
            return problem_response(StatusCode::BAD_REQUEST, "root_path must be an absolute path");
        }
        if !path_buf.exists() {
            return problem_response(StatusCode::NOT_FOUND, format!("root_path '{path}' not found"));
        }
        let scan_result =
            tokio::task::spawn_blocking(move || crate::workspace_scan_polyglot::run_repo_scan_at(&path_buf))
                .await
                .map_err(|err| problem_response(StatusCode::INTERNAL_SERVER_ERROR, format!("scan task failed: {err}")));
        let scan = match scan_result {
            Ok(Ok(scan)) => scan,
            Ok(Err(err)) => return problem_response(StatusCode::BAD_REQUEST, format!("repo scan failed: {err}")),
            Err(resp) => return resp,
        };
        last_scan_id = Some(scan.scan_id.clone());
        match serde_json::to_string(&scan) {
            Ok(json) => scan_json = Some(json),
            Err(err) => {
                return problem_response(StatusCode::INTERNAL_SERVER_ERROR, format!("scan encode failed: {err}"))
            }
        }
        scan_for_codegraph = Some(scan);
    } else {
        note = Some("clone_url registered; cloning and scan are deferred".to_string());
    }

    let registration = crate::repo_registry::RepoRegistration {
        repo_id: repo_id.clone(),
        tenant_id: tenant_id.clone(),
        root_path,
        clone_url,
        languages: body.languages,
        enabled: true,
        added_at_unix_ms: now_unix_ms(),
        last_scan_id,
    };

    let mut store = state.fact_store.write().await;
    if let Err(err) = crate::repo_registry::create_repo(&mut store, &registration) {
        return map_registry_error(err);
    }
    if let Some(json) = scan_json {
        crate::repo_registry::store_scan_json(&mut store, &tenant_id, &repo_id, json);
    }
    drop(store);
    if let Some(scan) = scan_for_codegraph.as_ref() {
        if let Err(err) = crate::repo_codegraph::maybe_emit_codegraph_edges(
            &state.fact_store,
            &state.projection_state,
            &state.data_dir,
            &tenant_id,
            &repo_id,
            scan,
        )
        .await
        {
            tracing::warn!(?err, tenant_id, repo_id, "repo-codegraph-edge-emission-failed");
        }
    }
    if let Some(watcher) = &state.repo_watch {
        watcher.start_repo(registration.clone()).await;
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({ "repo": registration, "note": note })),
    )
        .into_response()
}

pub(super) async fn get_repos(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<RepoTenantQuery>,
) -> impl IntoResponse {
    let tenant_id = query.tenant_id.trim().to_string();
    if let Err(problem) = require_http_scopes_for_tenant(&state.auth, &headers, &["admin:read"], &tenant_id) {
        return problem.into_response();
    }
    let store = state.fact_store.read().await;
    let repos = crate::repo_registry::list_repos(&store, &tenant_id);
    drop(store);
    (StatusCode::OK, Json(serde_json::json!({ "repos": repos }))).into_response()
}

/// `GET /v1/repos/dependents` — daemon-owned package reverse-dependency
/// lookup. Version requirements are returned as raw manifest strings only;
/// version range semantics and filtering live in upstream clients/proxies.
pub(super) async fn get_repo_dependents(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<RepoDependentsQuery>,
) -> impl IntoResponse {
    let tenant_id = query.tenant_id.trim().to_string();
    if let Err(problem) = require_http_scopes_for_tenant(&state.auth, &headers, &["admin:read"], &tenant_id) {
        return problem.into_response();
    }
    if tenant_id.is_empty() {
        return problem_response(StatusCode::BAD_REQUEST, "tenant_id must not be empty");
    }

    let ecosystem = normalize_package_query_part(&query.ecosystem);
    if !matches!(ecosystem.as_str(), "cargo" | "npm" | "pypi" | "go") {
        return problem_response(StatusCode::BAD_REQUEST, "ecosystem must be one of cargo, npm, pypi, go");
    }
    let name = normalize_package_query_part(&query.name);
    if name.is_empty() {
        return problem_response(StatusCode::BAD_REQUEST, "name must not be empty");
    }
    let cursor = match crate::relations::parse_incoming_cursor(query.cursor.as_deref()) {
        Ok(cursor) => cursor,
        Err(message) => return problem_response(StatusCode::BAD_REQUEST, message),
    };
    let limit = query.limit.unwrap_or(100).clamp(1, 500);
    let package_map_key = crate::repo_codegraph::external_dep_map_key(&ecosystem, &name);
    let package_node_key = crate::repo_codegraph::pkg_key(&ecosystem, &name);

    let store = state.fact_store.read().await;
    let shared_ids = match crate::repo_codegraph::load_shared_id_store(&store, &tenant_id) {
        Ok(ids) => ids,
        Err(err) => {
            drop(store);
            return problem_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("shared codegraph id store failed to decode: {err}"),
            );
        }
    };
    let Some(package_node_id) = shared_ids.map.get(&package_node_key).copied() else {
        drop(store);
        return (
            StatusCode::OK,
            Json(serde_json::json!({
                "tenant_id": tenant_id,
                "ecosystem": ecosystem,
                "name": name,
                "package_known": false,
                "dependents": [],
                "next_cursor": null,
            })),
        )
            .into_response();
    };
    let repo_by_node_id = repo_reverse_map(&shared_ids);
    drop(store);

    let tenant_hash = corecrux_projections::tenant_hash_xxhash64(&tenant_id);
    let ps = state.projection_state.read().await;
    let page = crate::relations::list_incoming_page(
        &ps,
        tenant_hash,
        package_node_id,
        Some(corecrux_projections::RelationTypeV1::DependsOn),
        cursor,
        limit,
    );
    let next_cursor = page.next_cursor.map(crate::relations::IncomingCursor::encode);
    let from_ids: Vec<u32> = page.rows.into_iter().map(|((_, from_id, _, _), _)| from_id).collect();
    drop(ps);

    let store = state.fact_store.read().await;
    let mut dependents = Vec::new();
    for from_id in from_ids {
        let Some(repo_id) = repo_by_node_id.get(&from_id) else {
            continue;
        };
        let version_map = match crate::repo_codegraph::load_extdeps(&store, &tenant_id, repo_id) {
            Ok(version_map) => version_map,
            Err(err) => {
                tracing::warn!(?err, tenant_id, repo_id, "repo-extdeps-version-join-failed");
                BTreeMap::new()
            }
        };
        let version = version_map.get(&package_map_key);
        dependents.push(serde_json::json!({
            "repo_id": repo_id,
            "version_req": version.and_then(|row| row.version_req.as_deref()),
            "version_locked": version.and_then(|row| row.version_locked.as_deref()),
            "kind": version.map(|row| row.kind.as_str()),
            "source_manifest": version.map(|row| row.source_manifest.as_str()),
        }));
    }
    drop(store);

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "tenant_id": tenant_id,
            "ecosystem": ecosystem,
            "name": name,
            "package_known": true,
            "dependents": dependents,
            "next_cursor": next_cursor,
        })),
    )
        .into_response()
}

fn normalize_package_query_part(value: &str) -> String {
    value.trim().replace('\\', "/").to_ascii_lowercase()
}

fn repo_reverse_map(id_store: &crate::repo_codegraph::CodeGraphIdStore) -> BTreeMap<u32, String> {
    id_store
        .map
        .iter()
        .filter_map(|(key, id)| key.strip_prefix("repo:").map(|repo_id| (*id, repo_id.to_string())))
        .collect()
}

pub(super) async fn get_repo(
    State(state): State<AppState>,
    Path(repo_id): Path<String>,
    headers: HeaderMap,
    Query(query): Query<RepoTenantQuery>,
) -> impl IntoResponse {
    let tenant_id = query.tenant_id.trim().to_string();
    if let Err(problem) = require_http_scopes_for_tenant(&state.auth, &headers, &["admin:read"], &tenant_id) {
        return problem.into_response();
    }
    let store = state.fact_store.read().await;
    let repo = crate::repo_registry::get_repo(&store, &tenant_id, &repo_id);
    drop(store);
    match repo {
        Some(repo) => (StatusCode::OK, Json(serde_json::json!({ "repo": repo }))).into_response(),
        None => problem_response(StatusCode::NOT_FOUND, "repo not found"),
    }
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct CodemapQuery {
    pub tenant_id: String,
    /// `summary` (default) → scan stats + per-crate rollup.
    /// `full` → the entire persisted `WorkspaceScan` (files, symbols, deps, routes).
    #[serde(default)]
    pub format: Option<String>,
}

/// `GET /v1/repos/{repo_id}/codemap` — serve the AST-derived code map the
/// daemon persisted when the repo was registered (or last re-indexed by the
/// watch loop). This is the read side of the `POST /v1/repos` scan: same
/// tenant scoping, same auth as the sibling repo reads.
pub(super) async fn get_repo_codemap(
    State(state): State<AppState>,
    Path(repo_id): Path<String>,
    headers: HeaderMap,
    Query(query): Query<CodemapQuery>,
) -> impl IntoResponse {
    let tenant_id = query.tenant_id.trim().to_string();
    if let Err(problem) = require_http_scopes_for_tenant(&state.auth, &headers, &["admin:read"], &tenant_id) {
        return problem.into_response();
    }
    let format = query.format.as_deref().unwrap_or("summary");
    if !matches!(format, "summary" | "full") {
        return problem_response(
            StatusCode::BAD_REQUEST,
            format!("unknown format '{format}'; expected 'summary' or 'full'"),
        );
    }

    let store = state.fact_store.read().await;
    let Some(repo) = crate::repo_registry::get_repo(&store, &tenant_id, &repo_id) else {
        drop(store);
        return problem_response(StatusCode::NOT_FOUND, "repo not found");
    };
    let scan_json = crate::repo_registry::load_scan_json(&store, &tenant_id, &repo_id);
    drop(store);

    let Some(scan_json) = scan_json else {
        return problem_response(
            StatusCode::NOT_FOUND,
            "no scan persisted for this repo. Register with root_path (POST /v1/repos) to run a scan; clone_url-only registrations defer scanning.",
        );
    };
    let scan: crate::workspace_scan::WorkspaceScan = match serde_json::from_str(&scan_json) {
        Ok(scan) => scan,
        Err(err) => {
            return problem_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("persisted scan failed to decode: {err}"),
            )
        }
    };

    if format == "full" {
        return (
            StatusCode::OK,
            Json(serde_json::json!({
                "repo_id": repo.repo_id,
                "tenant_id": repo.tenant_id,
                "languages": repo.languages,
                "scan": scan,
            })),
        )
            .into_response();
    }

    let crates: Vec<serde_json::Value> = scan
        .crates
        .iter()
        .map(|c| {
            serde_json::json!({
                "name": c.name,
                "rel_path": c.rel_path,
                "file_count": c.file_count,
                "total_loc": c.total_loc,
                "internal_deps": c.internal_deps,
            })
        })
        .collect();
    let mut body = serde_json::json!({
        "repo_id": repo.repo_id,
        "tenant_id": repo.tenant_id,
        "languages": repo.languages,
        "scan_id": scan.scan_id,
        "root_path": scan.root_path,
        "started_at_unix_ms": scan.started_at_unix_ms,
        "duration_ms": scan.duration_ms,
        "stats": scan.stats,
        "crates": crates,
        "hint": "pass format=full for files, symbols, deps and routes",
    });
    if !scan.external_deps.is_empty() {
        let mut by_ecosystem = std::collections::BTreeMap::new();
        for dep in &scan.external_deps {
            *by_ecosystem.entry(dep.ecosystem.clone()).or_insert(0usize) += 1;
        }
        if let Some(obj) = body.as_object_mut() {
            obj.insert(
                "external_deps_by_ecosystem".to_string(),
                serde_json::json!(by_ecosystem),
            );
        }
    }
    (StatusCode::OK, Json(body)).into_response()
}

pub(super) async fn delete_repo(
    State(state): State<AppState>,
    Path(repo_id): Path<String>,
    headers: HeaderMap,
    Query(query): Query<RepoTenantQuery>,
) -> impl IntoResponse {
    let tenant_id = query.tenant_id.trim().to_string();
    if let Err(problem) = require_http_scopes_for_tenant(&state.auth, &headers, &["admin:write"], &tenant_id) {
        return problem.into_response();
    }
    let mut store = state.fact_store.write().await;
    let result = crate::repo_registry::delete_repo(&mut store, &tenant_id, &repo_id);
    drop(store);
    match result {
        Ok(()) => {
            if let Some(watcher) = &state.repo_watch {
                watcher.stop_repo(&tenant_id, &repo_id).await;
            }
            (StatusCode::NO_CONTENT, ()).into_response()
        }
        Err(err) => map_registry_error(err),
    }
}
