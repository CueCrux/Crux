// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! HTTP CRUD for tenant-scoped repository registrations.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::http::header;
use axum::response::Response;
use tokio_stream::wrappers::ReceiverStream;

use super::{
    problem_response, require_http_scopes_for_tenant, AppState, HeaderMap, IntoResponse, Json, Path, Query, State,
    StatusCode,
};

const MAX_PENDING_REPO_SCANS_PER_TENANT: usize = 8;

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
    #[serde(skip)]
    pub(crate) registration_generation: String,
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

fn parse_scan_mode(value: Option<&str>, local_root: bool) -> Result<ScanMode, String> {
    match value.map(str::trim).filter(|s| !s.is_empty()) {
        None if local_root => Ok(ScanMode::Async),
        None => Ok(ScanMode::Inline),
        Some("inline") if local_root => {
            Err("local root scans require scan_mode 'async'; inline scans exceed the HTTP request budget".to_string())
        }
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
        RepoRegistryError::LegalHold { .. } => problem_response(StatusCode::LOCKED, err.to_string()),
        RepoRegistryError::SnapshotTooLarge => problem_response(StatusCode::PAYLOAD_TOO_LARGE, err.to_string()),
        RepoRegistryError::InvalidTenantId(_) | RepoRegistryError::InvalidRepoId(_) | RepoRegistryError::Json(_) => {
            problem_response(StatusCode::BAD_REQUEST, err.to_string())
        }
        RepoRegistryError::Io(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => {
            problem_response(StatusCode::SERVICE_UNAVAILABLE, err.to_string())
        }
        RepoRegistryError::Io(_) => problem_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    }
}

fn map_scan_root_error(err: crate::workspace_scan::ScanError) -> axum::response::Response {
    match &err {
        crate::workspace_scan::ScanError::Policy(message)
            if message.contains("outside CORECRUXD_REPO_SCAN_ALLOWED_ROOTS")
                || message.contains("scanning is disabled") =>
        {
            problem_response(StatusCode::FORBIDDEN, err.to_string())
        }
        crate::workspace_scan::ScanError::Io(io_error) if io_error.kind() == std::io::ErrorKind::NotFound => {
            problem_response(StatusCode::NOT_FOUND, err.to_string())
        }
        _ => problem_response(StatusCode::BAD_REQUEST, err.to_string()),
    }
}

fn map_scan_load_error(err: crate::repo_registry::RepoRegistryError) -> axum::response::Response {
    if matches!(
        &err,
        crate::repo_registry::RepoRegistryError::Io(error)
            if error.kind() == std::io::ErrorKind::WouldBlock
    ) {
        let mut response = problem_response(StatusCode::SERVICE_UNAVAILABLE, err.to_string());
        response.headers_mut().insert(
            axum::http::header::RETRY_AFTER,
            axum::http::HeaderValue::from_static("1"),
        );
        response
    } else {
        problem_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("persisted scan failed to load: {err}"),
        )
    }
}

fn require_durable_local_repo_scan(
    local_root_requested: bool,
    persistence_enabled: bool,
    durability_poisoned: bool,
) -> Result<(), &'static str> {
    if local_root_requested && !persistence_enabled {
        Err("local repository scans require durable fact persistence")
    } else if local_root_requested && durability_poisoned {
        Err("fact journal durable mutation plane is poisoned; restart required before local repository scans")
    } else {
        Ok(())
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
    let (fact_persistence_enabled, fact_durability_poisoned) = {
        let store = state.fact_store.read().await;
        (store.persistence_enabled(), store.journal_durability_poisoned())
    };
    if let Err(error) =
        require_durable_local_repo_scan(root_path.is_some(), fact_persistence_enabled, fact_durability_poisoned)
    {
        return problem_response(StatusCode::SERVICE_UNAVAILABLE, error);
    }
    if root_path.is_some() {
        let context = match crate::auth::passport_bound_context(&state.auth, &headers) {
            Ok(context) => context,
            Err(problem) => return problem.into_response(),
        };
        if context.auth_enforced() && !context.has_global_tenant_authority() {
            return problem_response(
                StatusCode::FORBIDDEN,
                "local repository paths require cross-tenant operator authority",
            );
        }
    }
    let scan_mode = match parse_scan_mode(body.scan_mode.as_deref(), root_path.is_some()) {
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
        Some(path_buf)
    } else {
        None
    };

    if scan_mode == ScanMode::Async {
        let Some(path_buf) = root_path_buf else {
            return problem_response(StatusCode::BAD_REQUEST, "scan_mode async requires root_path");
        };
        let path_buf = match resolve_repo_root_for_admission(&state, path_buf).await {
            Ok(canonical) => canonical,
            Err(response) => return response,
        };
        let root_path = Some(path_buf.display().to_string());
        return enqueue_repo_scan(state, tenant_id, repo_id, root_path, body.languages, path_buf).await;
    }

    let mut note = None;
    let mut resolved_root_path = None;
    let mut scan_for_codegraph = None;
    let mut last_scan_id = None;
    let mut _scan_permit = None;
    let mut pending_snapshot = None;
    if let Some(path_buf) = root_path_buf {
        let permit = match state.repo_scan_semaphore.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => return problem_response(StatusCode::SERVICE_UNAVAILABLE, "repository scan admission is busy"),
        };
        if crate::repo_registry::get_repo(&*state.fact_store.read().await, &tenant_id, &repo_id).is_some() {
            drop(permit);
            return map_registry_error(crate::repo_registry::RepoRegistryError::Duplicate { tenant_id, repo_id });
        }
        let scan_policy = state.repo_scan_policy.clone();
        let scan_result = tokio::task::spawn_blocking(move || {
            crate::workspace_scan_polyglot::run_repo_scan_at_with_policy(&path_buf, &scan_policy)
                .map(|scan| (scan, permit))
        })
        .await
        .map_err(|err| problem_response(StatusCode::INTERNAL_SERVER_ERROR, format!("scan task failed: {err}")));
        let (scan, scan_permit) = match scan_result {
            Ok(Ok(result)) => result,
            Ok(Err(err)) => return map_scan_root_error(err),
            Err(resp) => return resp,
        };
        // Keep process-wide admission through encoding, persistence and
        // optional codegraph emission, not only through parsing.
        resolved_root_path = Some(scan.root_path.clone());
        last_scan_id = Some(scan.scan_id.clone());
        let snapshot_data_dir = state.data_dir.clone();
        let snapshot_tenant = tenant_id.clone();
        let snapshot_repo = repo_id.clone();
        let snapshot_result = tokio::task::spawn_blocking(move || {
            crate::repo_registry::write_scan_snapshot(&snapshot_data_dir, &snapshot_tenant, &snapshot_repo, &scan)
                .map(|pending| (scan, pending, scan_permit))
        })
        .await;
        scan_for_codegraph = match snapshot_result {
            Ok(Ok((scan, pending, scan_permit))) => {
                pending_snapshot = Some(pending);
                _scan_permit = Some(scan_permit);
                Some(scan)
            }
            Ok(Err(error)) => {
                return problem_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("scan snapshot write failed: {error}"),
                )
            }
            Err(error) => {
                return problem_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("scan snapshot task failed: {error}"),
                )
            }
        };
    } else {
        note = Some("clone_url registered; cloning and scan are deferred".to_string());
    }

    let registration = crate::repo_registry::RepoRegistration {
        repo_id: repo_id.clone(),
        tenant_id: tenant_id.clone(),
        root_path: resolved_root_path,
        clone_url,
        languages: body.languages,
        enabled: true,
        added_at_unix_ms: now_unix_ms(),
        generation_id: uuid::Uuid::new_v4().to_string(),
        last_scan_id,
        scan_status: None,
        scan_error: None,
        scan_queued_at_unix_ms: None,
        scan_finished_at_unix_ms: None,
    };

    let mut store = state.fact_store.write().await;
    let create_result = if registration.last_scan_id.is_some() {
        crate::repo_registry::ensure_scan_writable(&store, &tenant_id, &repo_id)
            .and_then(|()| crate::repo_registry::create_repo(&mut store, &registration))
    } else {
        crate::repo_registry::create_repo(&mut store, &registration)
    };
    if let Err(err) = create_result {
        if let Some(pending) = pending_snapshot.take() {
            pending.settle_failed_commit(&store, Some(&err));
        }
        drop(store);
        return map_registry_error(err);
    }
    drop(store);
    if let Some(pending) = pending_snapshot.take() {
        pending.commit();
    }
    if let Some(scan) = scan_for_codegraph.as_ref() {
        if let Err(err) = crate::repo_codegraph::maybe_emit_codegraph_edges_for_registration(
            &state.fact_store,
            &state.projection_state,
            &state.data_dir,
            &tenant_id,
            &repo_id,
            &registration.generation_id,
            scan,
        ) {
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

async fn resolve_repo_root_for_admission(state: &AppState, path: PathBuf) -> Result<PathBuf, axum::response::Response> {
    let scan_policy = state.repo_scan_policy.clone();
    // Admission only canonicalises and authorises the root; the queued job
    // holds the process-wide scan permit for traversal through persistence.
    // Do not consume that permit here or a running scan would prevent bounded
    // async work from entering the queue at all.
    let result = tokio::task::spawn_blocking(move || scan_policy.resolve_root(&path))
        .await
        .map_err(|error| {
            problem_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("repository root validation task failed: {error}"),
            )
        })?;
    result.map_err(map_scan_root_error)
}

async fn enqueue_repo_scan(
    state: AppState,
    tenant_id: String,
    repo_id: String,
    root_path: Option<String>,
    languages: Vec<String>,
    path_buf: PathBuf,
) -> axum::response::Response {
    // Local scans intentionally register first. If the background scan fails,
    // the repo remains registered with scan_status="failed"; local inline scans
    // are rejected because the router's request budget is shorter than a scan.
    let queued_at = now_unix_ms();
    let registration_generation = uuid::Uuid::new_v4().to_string();
    let registration = crate::repo_registry::RepoRegistration {
        repo_id: repo_id.clone(),
        tenant_id: tenant_id.clone(),
        root_path,
        clone_url: None,
        languages,
        enabled: true,
        added_at_unix_ms: queued_at,
        generation_id: registration_generation.clone(),
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
        registration_generation,
        status: RepoScanJobStatus::Submitted,
        submitted_at_unix_ms: queued_at,
        started_at_unix_ms: None,
        finished_at_unix_ms: None,
        error: None,
        root_path: path_buf.display().to_string(),
    };

    let mut jobs = state.repo_scan_jobs.write().await;
    let (pending_count, tenant_pending_count) = pending_repo_scan_counts(&jobs, &tenant_id);
    if pending_count >= state.repo_scan_max_pending {
        return problem_response(
            StatusCode::SERVICE_UNAVAILABLE,
            format!(
                "repo scan queue is full (pending={pending_count}, limit={})",
                state.repo_scan_max_pending
            ),
        );
    }
    let tenant_pending_limit = tenant_pending_repo_scan_limit(state.repo_scan_max_pending);
    if tenant_pending_count >= tenant_pending_limit {
        return problem_response(
            StatusCode::SERVICE_UNAVAILABLE,
            format!("tenant repo scan queue is full (pending={tenant_pending_count}, limit={tenant_pending_limit})"),
        );
    }

    {
        let mut store = state.fact_store.write().await;
        if let Err(err) = crate::repo_registry::ensure_scan_writable(&store, &tenant_id, &repo_id) {
            return map_registry_error(err);
        }
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

fn pending_repo_scan_counts(jobs: &BTreeMap<String, RepoScanJob>, tenant_id: &str) -> (usize, usize) {
    let mut total = 0usize;
    let mut tenant = 0usize;
    for record in jobs.values() {
        if matches!(record.status, RepoScanJobStatus::Submitted | RepoScanJobStatus::Running) {
            total = total.saturating_add(1);
            if record.tenant_id == tenant_id {
                tenant = tenant.saturating_add(1);
            }
        }
    }
    (total, tenant)
}

fn tenant_pending_repo_scan_limit(max_pending: usize) -> usize {
    max_pending.clamp(1, MAX_PENDING_REPO_SCANS_PER_TENANT)
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
    let (tenant_id, repo_id, registration_generation, root_path) = {
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
        (
            rec.tenant_id.clone(),
            rec.repo_id.clone(),
            rec.registration_generation.clone(),
            rec.root_path.clone(),
        )
    };

    if let Err(err) =
        update_repo_scan_registration(&state, &tenant_id, &repo_id, &registration_generation, |registration| {
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
        finish_repo_scan_job(
            &state,
            &job_id,
            RepoScanJobStatus::Failed,
            Some(format!("stale repository scan discarded before execution: {err}")),
        )
        .await;
        drop(permit);
        return;
    }

    #[cfg(test)]
    if let Some(hook) = repo_scan_test_hook(&repo_id) {
        if let Some(delay_ms) = hook.delay_ms {
            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
        }
        if let Some(error) = hook.error {
            finish_failed_repo_scan(&state, &job_id, &tenant_id, &repo_id, &registration_generation, error).await;
            drop(permit);
            return;
        }
    }

    if state.fact_store.read().await.journal_durability_poisoned() {
        finish_failed_repo_scan(
            &state,
            &job_id,
            &tenant_id,
            &repo_id,
            &registration_generation,
            "fact journal durable mutation plane is poisoned; restart required before repository scanning".to_string(),
        )
        .await;
        drop(permit);
        return;
    }

    let scan_result = run_repo_scan_for_job(&root_path, state.repo_scan_policy.clone(), permit).await;
    match scan_result {
        Ok((scan, scan_permit)) => {
            let scan_id = scan.scan_id.clone();
            let finished_at = now_unix_ms();
            let completion = SuccessfulRepoScan {
                tenant_id: &tenant_id,
                repo_id: &repo_id,
                expected_generation: &registration_generation,
                expected_root: &root_path,
                finished_at_unix_ms: finished_at,
            };
            match persist_successful_repo_scan(&state, completion, scan, scan_permit).await {
                Ok(()) => {
                    tracing::info!(tenant_id, repo_id, job_id, scan_id, "repo-scan-job-succeeded");
                    finish_repo_scan_job(&state, &job_id, RepoScanJobStatus::Succeeded, None).await;
                }
                Err(err) => {
                    finish_failed_repo_scan(&state, &job_id, &tenant_id, &repo_id, &registration_generation, err).await;
                }
            }
        }
        Err(err) => {
            finish_failed_repo_scan(&state, &job_id, &tenant_id, &repo_id, &registration_generation, err).await;
        }
    }
}

async fn run_repo_scan_for_job(
    root_path: &str,
    scan_policy: Arc<crate::repo_scan_policy::RepoScanPolicy>,
    permit: tokio::sync::OwnedSemaphorePermit,
) -> Result<(crate::workspace_scan::WorkspaceScan, tokio::sync::OwnedSemaphorePermit), String> {
    let path_buf = PathBuf::from(root_path);
    let scan_result = tokio::task::spawn_blocking(move || {
        crate::workspace_scan_polyglot::run_repo_scan_at_with_policy(&path_buf, &scan_policy).map(|scan| (scan, permit))
    })
    .await
    .map_err(|err| format!("scan task failed: {err}"))?;
    scan_result.map_err(|err| format!("repo scan failed: {err}"))
}

struct SuccessfulRepoScan<'a> {
    tenant_id: &'a str,
    repo_id: &'a str,
    expected_generation: &'a str,
    expected_root: &'a str,
    finished_at_unix_ms: u64,
}

async fn persist_successful_repo_scan(
    state: &AppState,
    completion: SuccessfulRepoScan<'_>,
    scan: crate::workspace_scan::WorkspaceScan,
    scan_permit: tokio::sync::OwnedSemaphorePermit,
) -> Result<(), String> {
    let SuccessfulRepoScan {
        tenant_id,
        repo_id,
        expected_generation,
        expected_root,
        finished_at_unix_ms,
    } = completion;
    let scan_id = scan.scan_id.clone();
    {
        let store = state.fact_store.read().await;
        if store.journal_durability_poisoned() {
            return Err(
                "fact journal durable mutation plane is poisoned; restart required before scan publication".to_string(),
            );
        }
        let Some(registration) = crate::repo_registry::get_repo(&store, tenant_id, repo_id) else {
            return Err("repo disappeared before scan completed".to_string());
        };
        if !registration.enabled
            || registration.generation_id != expected_generation
            || registration.root_path.as_deref() != Some(expected_root)
        {
            return Err("repo changed before scan completed; stale result discarded".to_string());
        }
    }
    let snapshot_data_dir = state.data_dir.clone();
    let snapshot_tenant = tenant_id.to_string();
    let snapshot_repo = repo_id.to_string();
    let (scan, pending_snapshot, _scan_permit) = tokio::task::spawn_blocking(move || {
        crate::repo_registry::write_scan_snapshot(&snapshot_data_dir, &snapshot_tenant, &snapshot_repo, &scan)
            .map(|pending| (scan, pending, scan_permit))
    })
    .await
    .map_err(|error| format!("scan snapshot task failed: {error}"))?
    .map_err(|error| format!("scan snapshot write failed: {error}"))?;
    let mut store = state.fact_store.write().await;
    let Some(mut registration) = crate::repo_registry::get_repo(&store, tenant_id, repo_id) else {
        pending_snapshot.settle_failed_commit(&store, None);
        drop(store);
        return Err("repo disappeared before scan completed".to_string());
    };
    if !registration.enabled
        || registration.generation_id != expected_generation
        || registration.root_path.as_deref() != Some(expected_root)
    {
        pending_snapshot.settle_failed_commit(&store, None);
        drop(store);
        return Err("repo changed before scan completed; stale result discarded".to_string());
    }
    if let Err(error) = crate::repo_registry::ensure_scan_writable(&store, tenant_id, repo_id) {
        pending_snapshot.settle_failed_commit(&store, Some(&error));
        drop(store);
        return Err(error.to_string());
    }
    let previous_scan_id = registration.last_scan_id.clone();
    registration.last_scan_id = Some(scan_id.clone());
    registration.scan_status = Some("done".to_string());
    registration.scan_error = None;
    registration.scan_finished_at_unix_ms = Some(finished_at_unix_ms);
    if let Err(error) = crate::repo_registry::store_repo(&mut store, &registration) {
        pending_snapshot.settle_failed_commit(&store, Some(&error));
        drop(store);
        return Err(error.to_string());
    }
    drop(store);
    pending_snapshot.commit();
    if let Some(previous_scan_id) = previous_scan_id.filter(|previous| previous != &scan_id) {
        if let Err(error) = crate::repo_registry::remove_scan_snapshot_if_unheld_async(
            state.fact_store.clone(),
            state.data_dir.clone(),
            tenant_id.to_string(),
            repo_id.to_string(),
            previous_scan_id,
        )
        .await
        {
            tracing::warn!(
                ?error,
                tenant_id,
                repo_id,
                "old-repo-scan-snapshot-cleanup-deferred-to-startup-gc"
            );
        }
    }
    if let Err(err) = crate::repo_codegraph::maybe_emit_codegraph_edges_for_registration(
        &state.fact_store,
        &state.projection_state,
        &state.data_dir,
        tenant_id,
        repo_id,
        expected_generation,
        &scan,
    ) {
        tracing::warn!(?err, tenant_id, repo_id, "repo-scan-codegraph-edge-emission-failed");
    }
    if let Some(watcher) = &state.repo_watch {
        watcher.start_repo(registration).await;
    }
    Ok(())
}

async fn finish_failed_repo_scan(
    state: &AppState,
    job_id: &str,
    tenant_id: &str,
    repo_id: &str,
    expected_generation: &str,
    error: String,
) {
    let finished_at = now_unix_ms();
    if let Err(err) = update_repo_scan_registration(state, tenant_id, repo_id, expected_generation, |registration| {
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
    expected_generation: &str,
    update: F,
) -> Result<(), String>
where
    F: FnOnce(&mut crate::repo_registry::RepoRegistration),
{
    let mut store = state.fact_store.write().await;
    let Some(mut registration) = crate::repo_registry::get_repo(&store, tenant_id, repo_id) else {
        return Err("repo not found".to_string());
    };
    if registration.generation_id != expected_generation {
        return Err("repo registration changed; stale job update discarded".to_string());
    }
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

#[cfg(test)]
mod admission_tests {
    use super::*;

    fn job(id: &str, tenant_id: &str, status: RepoScanJobStatus) -> RepoScanJob {
        RepoScanJob {
            job_id: id.to_string(),
            tenant_id: tenant_id.to_string(),
            repo_id: id.to_string(),
            registration_generation: format!("generation-{id}"),
            status,
            submitted_at_unix_ms: 1,
            started_at_unix_ms: None,
            finished_at_unix_ms: None,
            error: None,
            root_path: "/srv/repos/fixture".to_string(),
        }
    }

    #[test]
    fn pending_queue_counts_enforce_a_per_tenant_share() {
        let mut jobs = BTreeMap::new();
        for index in 0..MAX_PENDING_REPO_SCANS_PER_TENANT {
            let id = format!("tenant-a-{index}");
            jobs.insert(id.clone(), job(&id, "tenant-a", RepoScanJobStatus::Submitted));
        }
        jobs.insert(
            "tenant-b".to_string(),
            job("tenant-b", "tenant-b", RepoScanJobStatus::Running),
        );
        jobs.insert(
            "finished".to_string(),
            job("finished", "tenant-a", RepoScanJobStatus::Succeeded),
        );

        assert_eq!(
            pending_repo_scan_counts(&jobs, "tenant-a"),
            (MAX_PENDING_REPO_SCANS_PER_TENANT + 1, MAX_PENDING_REPO_SCANS_PER_TENANT)
        );
        assert_eq!(tenant_pending_repo_scan_limit(32), MAX_PENDING_REPO_SCANS_PER_TENANT);
        assert_eq!(tenant_pending_repo_scan_limit(0), 1);
    }
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

#[derive(serde::Serialize)]
struct CodemapFullResponse {
    repo_id: String,
    tenant_id: String,
    languages: Vec<String>,
    scan: crate::workspace_scan::WorkspaceScan,
}

struct CodemapStreamWriter {
    sender: tokio::sync::mpsc::Sender<Result<Bytes, std::io::Error>>,
    buffer: Vec<u8>,
    runtime: tokio::runtime::Handle,
    deadline: std::time::Instant,
}

impl CodemapStreamWriter {
    const CHUNK_BYTES: usize = 64 * 1024;

    fn send_buffer(&mut self) -> std::io::Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        let chunk = Bytes::from(std::mem::replace(
            &mut self.buffer,
            Vec::with_capacity(Self::CHUNK_BYTES),
        ));
        let remaining = self.deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "codemap response stream exceeded its total send deadline",
            ));
        }
        match self
            .runtime
            .block_on(tokio::time::timeout(remaining, self.sender.send(Ok(chunk))))
        {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "codemap client disconnected",
            )),
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "codemap response stream stalled",
            )),
        }
    }
}

impl std::io::Write for CodemapStreamWriter {
    fn write(&mut self, mut bytes: &[u8]) -> std::io::Result<usize> {
        let original_len = bytes.len();
        while !bytes.is_empty() {
            let remaining = Self::CHUNK_BYTES.saturating_sub(self.buffer.len());
            let take = remaining.min(bytes.len());
            self.buffer.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
            if self.buffer.len() == Self::CHUNK_BYTES {
                self.send_buffer()?;
            }
        }
        Ok(original_len)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.send_buffer()
    }
}

fn streamed_full_codemap(response: CodemapFullResponse, admission: tokio::sync::OwnedSemaphorePermit) -> Response {
    streamed_full_codemap_with_timeout(response, admission, std::time::Duration::from_secs(30))
}

fn streamed_full_codemap_with_timeout(
    response: CodemapFullResponse,
    admission: tokio::sync::OwnedSemaphorePermit,
    stream_timeout: std::time::Duration,
) -> Response {
    let started_at = std::time::Instant::now();
    let deadline = started_at.checked_add(stream_timeout).unwrap_or(started_at);
    streamed_full_codemap_with_deadline(response, admission, deadline)
}

fn streamed_full_codemap_with_deadline(
    response: CodemapFullResponse,
    admission: tokio::sync::OwnedSemaphorePermit,
    deadline: std::time::Instant,
) -> Response {
    let (sender, receiver) = tokio::sync::mpsc::channel(2);
    let runtime = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        // The producer owns admission until serialization completes or the
        // client drops. A bounded channel prevents slow clients from turning
        // many accepted scans into queued 64 MiB response bodies. The total
        // deadline starts before blocking-pool admission, so a saturated pool
        // cannot extend how long this response retains the global scan permit.
        let _admission = admission;
        let error_sender = sender.clone();
        let mut writer = CodemapStreamWriter {
            sender,
            buffer: Vec::with_capacity(CodemapStreamWriter::CHUNK_BYTES),
            runtime,
            deadline,
        };
        let serialized = serde_json::to_writer(&mut writer, &response)
            .map_err(std::io::Error::other)
            .and_then(|()| writer.flush());
        if let Err(error) = serialized {
            let _ = error_sender.try_send(Err(std::io::Error::other(format!(
                "codemap serialization failed: {error}"
            ))));
        }
    });
    let mut response = Response::new(Body::from_stream(ReceiverStream::new(receiver)));
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/json"),
    );
    response
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

pub(super) async fn load_repo_scan(
    state: &AppState,
    tenant_id: &str,
    repo_id: &str,
) -> Result<Option<crate::repo_registry::LoadedRepoScan>, crate::repo_registry::RepoRegistryError> {
    crate::repo_registry::load_registered_workspace_scan_async(
        &state.fact_store,
        state.repo_scan_semaphore.clone(),
        &state.data_dir,
        tenant_id,
        repo_id,
    )
    .await
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

    let loaded = match load_repo_scan(&state, &tenant_id, &repo_id).await {
        Ok(Some(loaded)) => loaded,
        Ok(None) => return problem_response(StatusCode::NOT_FOUND, "repo not found"),
        Err(err) => return map_scan_load_error(err),
    };
    let crate::repo_registry::LoadedRepoScan {
        scan,
        admission: _scan_admission,
        ..
    } = loaded;
    let Some(scan) = scan else {
        return problem_response(
            StatusCode::NOT_FOUND,
            "no scan persisted for this repo. Register with root_path (POST /v1/repos) to run a scan.",
        );
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

    let loaded = match load_repo_scan(&state, &tenant_id, &repo_id).await {
        Ok(Some(loaded)) => loaded,
        Ok(None) => return problem_response(StatusCode::NOT_FOUND, "repo not found"),
        Err(err) => return map_scan_load_error(err),
    };
    let crate::repo_registry::LoadedRepoScan {
        registration: repo,
        scan,
        admission: scan_admission,
    } = loaded;
    let Some(scan) = scan else {
        return problem_response(
            StatusCode::NOT_FOUND,
            "no scan persisted for this repo. Register with root_path (POST /v1/repos) to run a scan; clone_url-only registrations defer scanning.",
        );
    };

    if format == "full" {
        return streamed_full_codemap(
            CodemapFullResponse {
                repo_id: repo.repo_id,
                tenant_id: repo.tenant_id,
                languages: repo.languages,
                scan,
            },
            scan_admission,
        );
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
    let deleted_registration = crate::repo_registry::get_repo(&store, &tenant_id, &repo_id)
        .map(|registration| (registration.generation_id, registration.last_scan_id));
    let result = crate::repo_registry::delete_repo(&mut store, &tenant_id, &repo_id);
    drop(store);
    match result {
        Ok(()) => {
            if let (Some(watcher), Some((generation, _))) = (&state.repo_watch, deleted_registration.as_ref()) {
                watcher.stop_repo(&tenant_id, &repo_id, generation).await;
            }
            if let Some((_, Some(scan_id))) = deleted_registration {
                if let Err(error) = crate::repo_registry::remove_scan_snapshot_if_unheld_async(
                    state.fact_store.clone(),
                    state.data_dir.clone(),
                    tenant_id.clone(),
                    repo_id.clone(),
                    scan_id,
                )
                .await
                {
                    tracing::warn!(?error, tenant_id, repo_id, "repo-delete-scan-snapshot-cleanup-failed");
                }
            }
            (StatusCode::NO_CONTENT, ()).into_response()
        }
        Err(err) => map_registry_error(err),
    }
}

#[cfg(test)]
mod stream_tests {
    use super::*;

    #[test]
    fn local_root_rejects_inline_scan_mode() {
        assert_eq!(parse_scan_mode(None, true), Ok(ScanMode::Async));
        let error = parse_scan_mode(Some("inline"), true).expect_err("local inline scan must be rejected");
        assert!(error.contains("HTTP request budget"));
    }

    #[test]
    fn ephemeral_mode_rejects_sidecar_producing_local_repo_scans() {
        assert_eq!(
            require_durable_local_repo_scan(true, false, false),
            Err("local repository scans require durable fact persistence")
        );
        assert_eq!(require_durable_local_repo_scan(false, false, false), Ok(()));
        assert_eq!(require_durable_local_repo_scan(true, true, false), Ok(()));
        assert_eq!(
            require_durable_local_repo_scan(true, true, true),
            Err("fact journal durable mutation plane is poisoned; restart required before local repository scans")
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stalled_full_codemap_consumer_releases_scan_admission() {
        let admission = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
        let permit = admission.clone().acquire_owned().await.expect("initial permit");
        let scan = crate::workspace_scan::WorkspaceScan {
            root_path: "x".repeat(CodemapStreamWriter::CHUNK_BYTES * 4),
            ..Default::default()
        };
        let _unpolled_response = streamed_full_codemap_with_timeout(
            CodemapFullResponse {
                repo_id: "repo".to_string(),
                tenant_id: "tenant".to_string(),
                languages: vec!["rust".to_string()],
                scan,
            },
            permit,
            std::time::Duration::from_millis(50),
        );

        let _recovered_permit =
            tokio::time::timeout(std::time::Duration::from_secs(1), admission.clone().acquire_owned())
                .await
                .expect("stalled stream must release admission by its deadline")
                .expect("semaphore remains open");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn producer_start_does_not_reset_expired_codemap_deadline() {
        let admission = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
        let permit = admission.clone().acquire_owned().await.expect("initial permit");
        let _unpolled_response = streamed_full_codemap_with_deadline(
            CodemapFullResponse {
                repo_id: "repo".to_string(),
                tenant_id: "tenant".to_string(),
                languages: vec!["rust".to_string()],
                scan: crate::workspace_scan::WorkspaceScan {
                    root_path: "expired".to_string(),
                    ..Default::default()
                },
            },
            permit,
            std::time::Instant::now()
                .checked_sub(std::time::Duration::from_millis(1))
                .expect("past instant"),
        );

        let _recovered_permit =
            tokio::time::timeout(std::time::Duration::from_secs(1), admission.clone().acquire_owned())
                .await
                .expect("an already-expired producer deadline must release admission")
                .expect("semaphore remains open");
    }
}
