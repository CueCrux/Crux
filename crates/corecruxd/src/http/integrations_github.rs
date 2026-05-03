// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! HTTP CRUD for GitHub integration: connect (POST PAT), disconnect, status.

use super::{problem_response, require_http_scopes, AppState, HeaderMap, IntoResponse, Json, Path, State, StatusCode};

#[derive(Debug, serde::Deserialize)]
pub(super) struct ConnectGithubBody {
    pub pat: String,
    /// When `true`, persist without contacting api.github.com. Allows scripted
    /// setup (e.g. test harnesses) and avoids a hard fail on intermittent
    /// outbound connectivity. Production setups should leave this `false`.
    #[serde(default)]
    pub skip_verify: bool,
    /// Optional override for the username when `skip_verify` is true (e.g.
    /// `"local-bot"`). Ignored when `skip_verify` is false — the verified
    /// `/user` response wins.
    #[serde(default)]
    pub username_override: Option<String>,
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

pub(super) async fn get_status(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    let status = crate::integrations_github::read_status(&state.data_dir);
    (StatusCode::OK, Json(status)).into_response()
}

pub(super) async fn post_connect(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ConnectGithubBody>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["integrations:install"]) {
        return problem.into_response();
    }
    let pat = body.pat.trim().to_string();
    if pat.is_empty() {
        return problem_response(StatusCode::BAD_REQUEST, "pat must not be empty");
    }

    let (username, scopes, last_verified_at_unix_ms) = if body.skip_verify {
        (
            body.username_override.unwrap_or_else(|| "unverified".to_string()),
            Vec::<String>::new(),
            None,
        )
    } else {
        let pat_for_verify = pat.clone();
        let result = tokio::task::spawn_blocking(move || crate::integrations_github::verify_pat(&pat_for_verify))
            .await
            .map_err(|e| e.to_string());
        match result {
            Ok(Ok(user)) => (user.username, user.scopes, Some(now_unix_ms())),
            Ok(Err(err)) => return problem_response(StatusCode::BAD_REQUEST, err.to_string()),
            Err(err) => {
                return problem_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("verification join failed: {err}"),
                )
            }
        }
    };

    let envelope = crate::encrypted_secrets::seal(pat.as_bytes(), state.integration_encryption_key.as_ref());
    let creds = crate::integrations_github::GithubCredentials {
        encrypted_pat: envelope,
        username,
        scopes,
        connected_at_unix_ms: now_unix_ms(),
        last_verified_at_unix_ms,
    };
    if let Err(err) = crate::integrations_github::write_credentials(&state.data_dir, &creds) {
        return problem_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string());
    }

    let status = crate::integrations_github::read_status(&state.data_dir);
    (StatusCode::OK, Json(status)).into_response()
}

pub(super) async fn post_disconnect(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["integrations:disable"]) {
        return problem.into_response();
    }
    if let Err(err) = crate::integrations_github::delete_credentials(&state.data_dir) {
        return problem_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string());
    }
    if let Err(err) = std::fs::remove_file(state.data_dir.join("integrations").join("github").join("selected_repos.json")) {
        if err.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!(?err, "failed to remove selected_repos.json on disconnect");
        }
    }
    (StatusCode::NO_CONTENT, ()).into_response()
}

pub(super) async fn get_accessible_repos(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    let creds = match crate::integrations_github::read_credentials(&state.data_dir) {
        Ok(c) => c,
        Err(_) => return problem_response(StatusCode::PRECONDITION_FAILED, "GitHub not connected; POST /v1/integrations/github/connect first"),
    };
    let pat = match crate::integrations_github::decrypt_pat(&creds, state.integration_encryption_key.as_ref()) {
        Ok(p) => p,
        Err(err) => return problem_response(StatusCode::INTERNAL_SERVER_ERROR, format!("decrypt failed: {err}")),
    };
    let result = tokio::task::spawn_blocking(move || crate::integrations_github::fetch_accessible_repos(&pat, 5))
        .await;
    match result {
        Ok(Ok(repos)) => {
            let selected = crate::integrations_github::list_selected_repos(&state.data_dir);
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "count": repos.len(),
                    "accessible": repos,
                    "selected": selected,
                })),
            )
                .into_response()
        }
        Ok(Err(err)) => problem_response(StatusCode::BAD_GATEWAY, err.to_string()),
        Err(err) => problem_response(StatusCode::INTERNAL_SERVER_ERROR, format!("join: {err}")),
    }
}

pub(super) async fn post_select_repo(
    State(state): State<AppState>,
    Path((owner, repo)): Path<(String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["integrations:install"]) {
        return problem.into_response();
    }
    let creds = match crate::integrations_github::read_credentials(&state.data_dir) {
        Ok(c) => c,
        Err(_) => return problem_response(StatusCode::PRECONDITION_FAILED, "GitHub not connected"),
    };
    // Look up the repo's actual privacy from the cached accessible-repos
    // listing so we record private=true for private repos. Failure modes
    // (network, scope) are not fatal — we default to private=true on
    // unknown, since the safer assumption is "treat as private until proven
    // otherwise".
    let private = match crate::integrations_github::decrypt_pat(&creds, state.integration_encryption_key.as_ref()) {
        Ok(pat) => {
            let owner_clone = owner.clone();
            let repo_clone = repo.clone();
            tokio::task::spawn_blocking(move || crate::integrations_github::fetch_accessible_repos(&pat, 5))
                .await
                .ok()
                .and_then(|res| res.ok())
                .and_then(|repos| repos.into_iter().find(|r| r.owner == owner_clone && r.repo == repo_clone))
                .map(|r| r.private)
                .unwrap_or(true) // unknown → treat as private
        }
        Err(_) => true,
    };
    match crate::integrations_github::select_repo(&state.data_dir, &owner, &repo, private, now_unix_ms()) {
        Ok(r) => (StatusCode::CREATED, Json(r)).into_response(),
        Err(err) => problem_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    }
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct PlanningFlagBody {
    pub planning: bool,
}

pub(super) async fn put_planning_flag(
    State(state): State<AppState>,
    Path((owner, repo)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<PlanningFlagBody>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["integrations:install"]) {
        return problem.into_response();
    }
    match crate::integrations_github::set_planning_repo(&state.data_dir, &owner, &repo, body.planning) {
        Ok(r) => (StatusCode::OK, Json(r)).into_response(),
        Err(err) => problem_response(StatusCode::BAD_REQUEST, err.to_string()),
    }
}

pub(super) async fn delete_selected_repo(
    State(state): State<AppState>,
    Path((owner, repo)): Path<(String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["integrations:disable"]) {
        return problem.into_response();
    }
    match crate::integrations_github::unselect_repo(&state.data_dir, &owner, &repo) {
        Ok(()) => (StatusCode::NO_CONTENT, ()).into_response(),
        Err(err) => problem_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    }
}

pub(super) async fn post_sync(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["integrations:install"]) {
        return problem.into_response();
    }
    let data_dir = state.data_dir.clone();
    let key = state.integration_encryption_key.clone();
    let fact_store = state.fact_store.clone();
    let result = tokio::task::spawn_blocking(move || {
        let mut store = match fact_store.try_write() {
            Ok(g) => g,
            Err(_) => return Err(crate::integrations_github::GithubIntegrationError::Network(
                "fact store busy; retry shortly".to_string(),
            )),
        };
        crate::integrations_github_sync::run_sync_with_key(&data_dir, &mut store, key.as_ref(), now_unix_ms())
    })
    .await;
    match result {
        Ok(Ok(run)) => (StatusCode::OK, Json(run)).into_response(),
        Ok(Err(crate::integrations_github::GithubIntegrationError::NotConnected)) => {
            problem_response(StatusCode::PRECONDITION_FAILED, "GitHub not connected")
        }
        Ok(Err(err)) => problem_response(StatusCode::BAD_GATEWAY, err.to_string()),
        Err(err) => problem_response(StatusCode::INTERNAL_SERVER_ERROR, format!("join: {err}")),
    }
}

pub(super) async fn get_selected_repos(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    let repos = crate::integrations_github::list_selected_repos(&state.data_dir);
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "count": repos.len(),
            "repos": repos,
        })),
    )
        .into_response()
}
