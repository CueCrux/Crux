// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! HTTP CRUD for tenant-scoped repository registrations.

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
