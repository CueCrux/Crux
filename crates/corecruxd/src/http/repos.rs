// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

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
    #[serde(default)]
    pub scan_mode: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScanMode {
    Inline,
    Async,
}

#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RepoScanJobStatus {
    Submitted,
    Running,
    Succeeded,
    Failed,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct RepoScanJob {
    pub(crate) job_id: String,
    pub(crate) tenant_id: String,
    pub(crate) repo_id: String,
    pub(crate) status: RepoScanJobStatus,
    pub(crate) submitted_at_unix_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) started_at_unix_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) finished_at_unix_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<String>,
    #[serde(skip)]
    pub(crate) root_path: String,
}

#[derive(Debug, serde::Deserialize)]
pub(crate) struct RepoTenantQuery {
    pub tenant_id: String,
}

/// Query for the read-only allowance report.
///
/// `seats` and `packs` are supplied by the caller because neither is sourced from
/// a subscription yet — that arrives with the entitlement work. Defaulting seats
/// to one is the honest reading of "not known", not a claim about the account.
#[derive(Debug, serde::Deserialize)]
pub(super) struct RepoAllowanceQuery {
    pub tenant_id: String,
    #[serde(default)]
    pub seats: Option<u32>,
    #[serde(default)]
    pub packs: Option<u32>,
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

fn parse_scan_mode(value: Option<&str>) -> Result<ScanMode, String> {
    match value.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(ScanMode::Inline),
        Some("inline") => Ok(ScanMode::Inline),
        Some("async") => Ok(ScanMode::Async),
        Some(other) => Err(format!("unknown scan_mode '{other}'; expected 'inline' or 'async'")),
    }
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

#[tracing::instrument(level = "info", skip_all)]
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
    let scan_mode = match parse_scan_mode(body.scan_mode.as_deref()) {
        Ok(mode) => mode,
        Err(err) => return problem_response(StatusCode::BAD_REQUEST, err),
    };
    if scan_mode == ScanMode::Async && clone_url.is_some() {
        return problem_response(StatusCode::BAD_REQUEST, "scan_mode async requires root_path");
    }

    let repo_id = body_repo_id(&body, root_path.as_deref(), clone_url.as_deref());
    if let Err(err) = crate::repo_registry::validate_repo_id(&repo_id) {
        return map_registry_error(err);
    }

    let root_path_buf = if let Some(path) = root_path.as_deref() {
        let path_buf = PathBuf::from(path);
        if !path_buf.is_absolute() {
            return problem_response(StatusCode::BAD_REQUEST, "root_path must be an absolute path");
        }
        if !path_buf.exists() {
            return problem_response(StatusCode::NOT_FOUND, format!("root_path '{path}' not found"));
        }
        Some(path_buf)
    } else {
        None
    };

    if scan_mode == ScanMode::Async {
        let Some(path_buf) = root_path_buf else {
            return problem_response(StatusCode::BAD_REQUEST, "scan_mode async requires root_path");
        };
        return enqueue_repo_scan(state, tenant_id, repo_id, root_path, body.languages, path_buf).await;
    }

    let mut note = None;
    let mut scan_json = None;
    let mut scan_for_codegraph = None;
    let mut last_scan_id = None;
    if let Some(path_buf) = root_path_buf {
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
        scan_status: None,
        scan_error: None,
        scan_queued_at_unix_ms: None,
        scan_finished_at_unix_ms: None,
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

    // M4 soft cap. Registration is NEVER refused for being over allowance: the
    // allowance is a commercial limit, and turning it into a technical one would
    // break a paying customer mid-sprint over a billing question. The overage is
    // reported on the response that created it, so the signal arrives at the
    // moment it becomes true rather than waiting to be polled.
    //
    // Computed at default seats/packs because neither is sourced from a
    // subscription yet (see repo_allowance docs); `basis` says so on the wire
    // rather than letting a caller mistake the default for the account's real
    // entitlement.
    let allowance = {
        let store = state.fact_store.read().await;
        crate::repo_allowance::allowance_for_tenant(&store, &tenant_id, 1, 0)
    };

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "repo": registration,
            "note": note,
            "allowance": allowance,
            "allowance_basis": "default seats=1 packs=0; not yet sourced from a subscription",
        })),
    )
        .into_response()
}

async fn enqueue_repo_scan(
    state: AppState,
    tenant_id: String,
    repo_id: String,
    root_path: Option<String>,
    languages: Vec<String>,
    path_buf: PathBuf,
) -> axum::response::Response {
    // Async scans intentionally register first. If the background scan fails,
    // the repo remains registered with scan_status="failed"; the default inline
    // path keeps its historical all-or-nothing behavior.
    let queued_at = now_unix_ms();
    let registration = crate::repo_registry::RepoRegistration {
        repo_id: repo_id.clone(),
        tenant_id: tenant_id.clone(),
        root_path,
        clone_url: None,
        languages,
        enabled: true,
        added_at_unix_ms: queued_at,
        last_scan_id: None,
        scan_status: Some("pending".to_string()),
        scan_error: None,
        scan_queued_at_unix_ms: Some(queued_at),
        scan_finished_at_unix_ms: None,
    };
    let job_id = format!("repo_scan_{}", uuid::Uuid::new_v4());
    let job = RepoScanJob {
        job_id: job_id.clone(),
        tenant_id: tenant_id.clone(),
        repo_id: repo_id.clone(),
        status: RepoScanJobStatus::Submitted,
        submitted_at_unix_ms: queued_at,
        started_at_unix_ms: None,
        finished_at_unix_ms: None,
        error: None,
        root_path: path_buf.display().to_string(),
    };

    let mut jobs = state.repo_scan_jobs.write().await;
    let pending_count = jobs
        .values()
        .filter(|r| matches!(r.status, RepoScanJobStatus::Submitted | RepoScanJobStatus::Running))
        .count();
    if pending_count >= state.repo_scan_max_pending {
        return problem_response(
            StatusCode::SERVICE_UNAVAILABLE,
            format!(
                "repo scan queue is full (pending={pending_count}, limit={})",
                state.repo_scan_max_pending
            ),
        );
    }

    {
        let mut store = state.fact_store.write().await;
        if let Err(err) = crate::repo_registry::create_repo(&mut store, &registration) {
            return map_registry_error(err);
        }
    }

    jobs.insert(job_id.clone(), job.clone());
    gc_finished_repo_scan_jobs(&mut jobs, state.repo_scan_max_pending);
    drop(jobs);

    let task_state = state.clone();
    let task_job_id = job_id.clone();
    tokio::spawn(async move {
        run_repo_scan_job(task_state, task_job_id).await;
    });

    (
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "repo": registration,
            "job_id": job_id,
            "note": "scan queued",
        })),
    )
        .into_response()
}

fn gc_finished_repo_scan_jobs(jobs: &mut BTreeMap<String, RepoScanJob>, max_pending: usize) {
    let retain_limit = max_pending.saturating_mul(8).max(256);
    if jobs.len() <= retain_limit {
        return;
    }
    let mut finished: Vec<(String, u64)> = jobs
        .iter()
        .filter_map(|(id, rec)| {
            if matches!(rec.status, RepoScanJobStatus::Succeeded | RepoScanJobStatus::Failed) {
                Some((id.clone(), rec.finished_at_unix_ms.unwrap_or(0)))
            } else {
                None
            }
        })
        .collect();
    finished.sort_by_key(|(_, ts)| *ts);
    let to_remove = jobs.len().saturating_sub(retain_limit);
    for (id, _) in finished.into_iter().take(to_remove) {
        jobs.remove(&id);
    }
}

async fn run_repo_scan_job(state: AppState, job_id: String) {
    let permit = match state.repo_scan_semaphore.clone().acquire_owned().await {
        Ok(permit) => permit,
        Err(_) => {
            finish_repo_scan_job(
                &state,
                &job_id,
                RepoScanJobStatus::Failed,
                Some("repo scan queue shut down".to_string()),
            )
            .await;
            return;
        }
    };
    let started_at = now_unix_ms();
    let (tenant_id, repo_id, root_path) = {
        let mut jobs = state.repo_scan_jobs.write().await;
        let Some(rec) = jobs.get_mut(&job_id) else {
            drop(permit);
            return;
        };
        if rec.status != RepoScanJobStatus::Submitted {
            drop(permit);
            return;
        }
        rec.status = RepoScanJobStatus::Running;
        rec.started_at_unix_ms = Some(started_at);
        (rec.tenant_id.clone(), rec.repo_id.clone(), rec.root_path.clone())
    };

    if let Err(err) = update_repo_scan_registration(&state, &tenant_id, &repo_id, |registration| {
        registration.scan_status = Some("running".to_string());
        registration.scan_error = None;
    })
    .await
    {
        tracing::warn!(
            ?err,
            tenant_id,
            repo_id,
            job_id,
            "repo-scan-running-status-update-failed"
        );
    }

    #[cfg(test)]
    if let Some(hook) = repo_scan_test_hook(&repo_id) {
        if let Some(delay_ms) = hook.delay_ms {
            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
        }
        if let Some(error) = hook.error {
            finish_failed_repo_scan(&state, &job_id, &tenant_id, &repo_id, error).await;
            drop(permit);
            return;
        }
    }

    let scan_result = run_repo_scan_for_job(&root_path).await;
    match scan_result {
        Ok(scan) => {
            let scan_id = scan.scan_id.clone();
            let finished_at = now_unix_ms();
            match persist_successful_repo_scan(&state, &tenant_id, &repo_id, scan, finished_at).await {
                Ok(()) => {
                    tracing::info!(tenant_id, repo_id, job_id, scan_id, "repo-scan-job-succeeded");
                    finish_repo_scan_job(&state, &job_id, RepoScanJobStatus::Succeeded, None).await;
                }
                Err(err) => {
                    finish_failed_repo_scan(&state, &job_id, &tenant_id, &repo_id, err).await;
                }
            }
        }
        Err(err) => {
            finish_failed_repo_scan(&state, &job_id, &tenant_id, &repo_id, err).await;
        }
    }
    drop(permit);
}

async fn run_repo_scan_for_job(root_path: &str) -> Result<crate::workspace_scan::WorkspaceScan, String> {
    let path_buf = PathBuf::from(root_path);
    let scan_result = tokio::task::spawn_blocking(move || crate::workspace_scan_polyglot::run_repo_scan_at(&path_buf))
        .await
        .map_err(|err| format!("scan task failed: {err}"))?;
    scan_result.map_err(|err| format!("repo scan failed: {err}"))
}

async fn persist_successful_repo_scan(
    state: &AppState,
    tenant_id: &str,
    repo_id: &str,
    scan: crate::workspace_scan::WorkspaceScan,
    finished_at_unix_ms: u64,
) -> Result<(), String> {
    let scan_id = scan.scan_id.clone();
    let scan_json = serde_json::to_string(&scan).map_err(|err| format!("scan encode failed: {err}"))?;
    let registration = {
        let mut store = state.fact_store.write().await;
        crate::repo_registry::store_scan_json(&mut store, tenant_id, repo_id, scan_json);
        let Some(mut registration) = crate::repo_registry::get_repo(&store, tenant_id, repo_id) else {
            return Err("repo disappeared before scan completed".to_string());
        };
        registration.last_scan_id = Some(scan_id);
        registration.scan_status = Some("done".to_string());
        registration.scan_error = None;
        registration.scan_finished_at_unix_ms = Some(finished_at_unix_ms);
        crate::repo_registry::store_repo(&mut store, &registration).map_err(|err| err.to_string())?;
        registration
    };
    if let Err(err) = crate::repo_codegraph::maybe_emit_codegraph_edges(
        &state.fact_store,
        &state.projection_state,
        &state.data_dir,
        tenant_id,
        repo_id,
        &scan,
    )
    .await
    {
        tracing::warn!(?err, tenant_id, repo_id, "repo-scan-codegraph-edge-emission-failed");
    }
    if let Some(watcher) = &state.repo_watch {
        watcher.start_repo(registration).await;
    }
    Ok(())
}

async fn finish_failed_repo_scan(state: &AppState, job_id: &str, tenant_id: &str, repo_id: &str, error: String) {
    let finished_at = now_unix_ms();
    if let Err(err) = update_repo_scan_registration(state, tenant_id, repo_id, |registration| {
        registration.scan_status = Some("failed".to_string());
        registration.scan_error = Some(error.clone());
        registration.scan_finished_at_unix_ms = Some(finished_at);
    })
    .await
    {
        tracing::warn!(
            ?err,
            tenant_id,
            repo_id,
            job_id,
            "repo-scan-failed-status-update-failed"
        );
    }
    finish_repo_scan_job(state, job_id, RepoScanJobStatus::Failed, Some(error)).await;
}

async fn finish_repo_scan_job(state: &AppState, job_id: &str, status: RepoScanJobStatus, error: Option<String>) {
    let finished_at = now_unix_ms();
    let mut jobs = state.repo_scan_jobs.write().await;
    if let Some(rec) = jobs.get_mut(job_id) {
        rec.status = status;
        rec.finished_at_unix_ms = Some(finished_at);
        rec.error = error;
    }
}

async fn update_repo_scan_registration<F>(
    state: &AppState,
    tenant_id: &str,
    repo_id: &str,
    update: F,
) -> Result<(), String>
where
    F: FnOnce(&mut crate::repo_registry::RepoRegistration),
{
    let mut store = state.fact_store.write().await;
    let Some(mut registration) = crate::repo_registry::get_repo(&store, tenant_id, repo_id) else {
        return Err("repo not found".to_string());
    };
    update(&mut registration);
    crate::repo_registry::store_repo(&mut store, &registration).map_err(|err| err.to_string())
}

#[cfg(test)]
#[derive(Debug, Clone, Default)]
pub(super) struct RepoScanTestHook {
    pub(super) delay_ms_by_repo: BTreeMap<String, u64>,
    pub(super) errors_by_repo: BTreeMap<String, String>,
}

#[cfg(test)]
#[derive(Debug, Clone)]
struct RepoScanTestOutcome {
    delay_ms: Option<u64>,
    error: Option<String>,
}

#[cfg(test)]
static REPO_SCAN_TEST_HOOK: std::sync::Mutex<Option<RepoScanTestHook>> = std::sync::Mutex::new(None);

#[cfg(test)]
pub(super) struct RepoScanTestHookGuard;

#[cfg(test)]
impl RepoScanTestHookGuard {
    pub(super) fn install(hook: RepoScanTestHook) -> Self {
        if let Ok(mut slot) = REPO_SCAN_TEST_HOOK.lock() {
            *slot = Some(hook);
        }
        Self
    }
}

#[cfg(test)]
impl Drop for RepoScanTestHookGuard {
    fn drop(&mut self) {
        if let Ok(mut slot) = REPO_SCAN_TEST_HOOK.lock() {
            *slot = None;
        }
    }
}

#[cfg(test)]
fn repo_scan_test_hook(repo_id: &str) -> Option<RepoScanTestOutcome> {
    let hook = REPO_SCAN_TEST_HOOK.lock().ok().and_then(|slot| slot.clone())?;
    Some(RepoScanTestOutcome {
        delay_ms: hook.delay_ms_by_repo.get(repo_id).copied(),
        error: hook.errors_by_repo.get(repo_id).cloned(),
    })
}

#[tracing::instrument(level = "info", skip_all)]
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

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_repo_allowance(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<RepoAllowanceQuery>,
) -> impl IntoResponse {
    let tenant_id = query.tenant_id.trim().to_string();
    if let Err(problem) = require_http_scopes_for_tenant(&state.auth, &headers, &["admin:read"], &tenant_id) {
        return problem.into_response();
    }
    let store = state.fact_store.read().await;
    let allowance = crate::repo_allowance::allowance_for_tenant(
        &store,
        &tenant_id,
        query.seats.unwrap_or(1),
        query.packs.unwrap_or(0),
    );
    drop(store);
    (StatusCode::OK, Json(serde_json::json!(allowance))).into_response()
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_repo_scan_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(job_id): Path<String>,
    Query(query): Query<RepoTenantQuery>,
) -> impl IntoResponse {
    let tenant_id = query.tenant_id.trim().to_string();
    if let Err(problem) = require_http_scopes_for_tenant(&state.auth, &headers, &["admin:read"], &tenant_id) {
        return problem.into_response();
    }
    let jobs = state.repo_scan_jobs.read().await;
    match jobs.get(&job_id).filter(|job| job.tenant_id == tenant_id) {
        Some(job) => (StatusCode::OK, Json(job.clone())).into_response(),
        None => problem_response(StatusCode::NOT_FOUND, format!("repo scan job '{job_id}' not found")),
    }
}

/// `GET /v1/repos/dependents` — daemon-owned package reverse-dependency
/// lookup. Version requirements are returned as raw manifest strings only;
/// version range semantics and filtering live in upstream clients/proxies.
#[tracing::instrument(level = "info", skip_all)]
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

#[tracing::instrument(level = "info", skip_all)]
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

#[derive(Debug, serde::Deserialize)]
pub(super) struct SymbolResolveQuery {
    pub tenant_id: String,
    /// Repo-relative path, exactly as `tracing::Metadata::file()` reports it.
    pub file: String,
    /// Symbol name. For `#[tracing::instrument]` spans this is the span name,
    /// which defaults to the function name.
    pub name: String,
    /// Callsite line, when known. Optional because it is only needed to break
    /// `(file, name)` collisions — 2.02% of symbols in the Crux workspace.
    #[serde(default)]
    pub line: Option<usize>,
    /// Optional `fn` / `struct` / `enum` / … pre-filter.
    #[serde(default)]
    pub kind: Option<String>,
}

/// `GET /v1/repos/{repo_id}/symbols/resolve` — map a `(file, name[, line])`
/// callsite onto a stable `symbol_id`.
///
/// This is the runtime→static join the span layer (M2) depends on. It answers
/// with an explicit confidence and **never guesses**: an unresolvable collision
/// returns `confidence: "ambiguous"` with the candidate list, because
/// mis-attributing a trace to the wrong symbol corrupts silently.
///
/// `404` means no symbol of that name exists in that file — a genuine miss,
/// distinct from an ambiguous match, which is `200`.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_symbol_resolve(
    State(state): State<AppState>,
    Path(repo_id): Path<String>,
    headers: HeaderMap,
    Query(query): Query<SymbolResolveQuery>,
) -> impl IntoResponse {
    let tenant_id = query.tenant_id.trim().to_string();
    if let Err(problem) = require_http_scopes_for_tenant(&state.auth, &headers, &["admin:read"], &tenant_id) {
        return problem.into_response();
    }

    let store = state.fact_store.read().await;
    if crate::repo_registry::get_repo(&store, &tenant_id, &repo_id).is_none() {
        drop(store);
        return problem_response(StatusCode::NOT_FOUND, "repo not found");
    }
    let scan_json = crate::repo_registry::load_scan_json(&store, &tenant_id, &repo_id);
    drop(store);

    let Some(scan_json) = scan_json else {
        return problem_response(
            StatusCode::NOT_FOUND,
            "no scan persisted for this repo. Register with root_path (POST /v1/repos) to run a scan.",
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

    let resolver = crate::symbol_resolve::SymbolResolver::from_scan(&scan);
    if resolver.is_empty() {
        // Distinguish "this scan indexed nothing" from "that symbol isn't here";
        // otherwise an empty scan looks like a repo full of missing symbols.
        return problem_response(
            StatusCode::CONFLICT,
            "the persisted scan contains no symbols; re-scan the repo before resolving callsites",
        );
    }
    let Some(resolution) = resolver.resolve(&query.file, &query.name, query.line, query.kind.as_deref()) else {
        return problem_response(
            StatusCode::NOT_FOUND,
            format!("no symbol named '{}' in '{}'", query.name, query.file),
        );
    };

    let symbol = resolution.symbol_id().and_then(|id| resolver.get(id));
    let clusters = resolver.collision_clusters().len();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "repo_id": repo_id,
            "tenant_id": tenant_id,
            "query": {
                "file": query.file,
                "name": query.name,
                "line": query.line,
                "kind": query.kind,
            },
            "resolution": resolution,
            "symbol": symbol,
            // How ambiguous this repo is overall — lets a caller judge how much
            // to trust joins here without a second round trip.
            "index": {
                "symbols": resolver.len(),
                "collision_clusters": clusters,
            },
        })),
    )
        .into_response()
}

/// `GET /v1/repos/{repo_id}/codemap` — serve the AST-derived code map the
/// daemon persisted when the repo was registered (or last re-indexed by the
/// watch loop). This is the read side of the `POST /v1/repos` scan: same
/// tenant scoping, same auth as the sibling repo reads.
#[tracing::instrument(level = "info", skip_all)]
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

#[tracing::instrument(level = "info", skip_all)]
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
