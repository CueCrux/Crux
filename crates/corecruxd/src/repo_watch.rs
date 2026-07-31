// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Feature-gated active watch loop for registered local repositories.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Mutex, RwLock};

use crate::repo_registry::RepoRegistration;
use crate::repo_scan_policy::RepoScanPolicy;

const WATCH_ENV: &str = "CORECRUXD_REPO_WATCH";
const POLL_INTERVAL_MS: u64 = 30_000;
const MAX_ACTIVE_WATCHERS: usize = 16;
const MAX_ACTIVE_WATCHERS_PER_TENANT: usize = 4;

pub(crate) fn enabled_from_env() -> bool {
    std::env::var(WATCH_ENV).ok().is_some_and(|v| {
        let v = v.trim().to_ascii_lowercase();
        !(v.is_empty() || v == "0" || v == "false" || v == "off" || v == "no")
    })
}

#[derive(Clone)]
pub(crate) struct RepoWatchService {
    inner: Arc<RepoWatchInner>,
}

struct RepoWatchInner {
    fact_store: Arc<RwLock<corecrux_memory::FactStore>>,
    projection_state: Arc<RwLock<corecrux_projections::ProjectionState>>,
    data_dir: PathBuf,
    scan_policy: Arc<RepoScanPolicy>,
    scan_semaphore: Arc<tokio::sync::Semaphore>,
    tasks: Mutex<HashMap<String, WatchTask>>,
}

struct WatchTask {
    tenant_id: String,
    generation_id: String,
    handle: tokio::task::JoinHandle<()>,
}

#[derive(Clone)]
struct WatchScanContext {
    fact_store: Arc<RwLock<corecrux_memory::FactStore>>,
    projection_state: Arc<RwLock<corecrux_projections::ProjectionState>>,
    data_dir: PathBuf,
    scan_policy: Arc<RepoScanPolicy>,
    scan_semaphore: Arc<tokio::sync::Semaphore>,
}

impl Drop for WatchTask {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

impl RepoWatchService {
    pub(crate) fn maybe_new(
        fact_store: Arc<RwLock<corecrux_memory::FactStore>>,
        projection_state: Arc<RwLock<corecrux_projections::ProjectionState>>,
        data_dir: PathBuf,
        scan_policy: Arc<RepoScanPolicy>,
        scan_semaphore: Arc<tokio::sync::Semaphore>,
    ) -> Option<Self> {
        enabled_from_env().then(|| Self {
            inner: Arc::new(RepoWatchInner {
                fact_store,
                projection_state,
                data_dir,
                scan_policy,
                scan_semaphore,
                tasks: Mutex::new(HashMap::new()),
            }),
        })
    }

    pub(crate) async fn start_repo(&self, registration: RepoRegistration) {
        let key = repo_key(&registration.tenant_id, &registration.repo_id);
        let root = if registration.enabled {
            if let Some(root_path) = registration.root_path.as_deref() {
                let policy = self.inner.scan_policy.clone();
                let requested_root = PathBuf::from(root_path);
                let resolved = tokio::task::spawn_blocking(move || policy.resolve_root(&requested_root)).await;
                match resolved {
                    Ok(Ok(root)) => Some(root),
                    Ok(Err(err)) => {
                        tracing::warn!(
                            repo_id=%registration.repo_id,
                            tenant_id=%registration.tenant_id,
                            root_path,
                            ?err,
                            "repo-watch-root-rejected"
                        );
                        None
                    }
                    Err(err) => {
                        tracing::warn!(
                            repo_id=%registration.repo_id,
                            tenant_id=%registration.tenant_id,
                            root_path,
                            ?err,
                            "repo-watch-root-resolution-task-failed"
                        );
                        None
                    }
                }
            } else {
                None
            }
        } else {
            None
        };
        let context = WatchScanContext {
            fact_store: self.inner.fact_store.clone(),
            projection_state: self.inner.projection_state.clone(),
            data_dir: self.inner.data_dir.clone(),
            scan_policy: self.inner.scan_policy.clone(),
            scan_semaphore: self.inner.scan_semaphore.clone(),
        };
        // Lock order is registry -> task map everywhere this operation needs
        // both. Holding the registry read lock through task installation makes
        // the generation check atomic with delete/recreate.
        let store = self.inner.fact_store.read().await;
        let is_current = crate::repo_registry::get_repo(&store, &registration.tenant_id, &registration.repo_id)
            .is_some_and(|current| {
                current.enabled == registration.enabled
                    && current.generation_id == registration.generation_id
                    && current.root_path == registration.root_path
            });
        if !is_current {
            return;
        }
        let mut tasks = self.inner.tasks.lock().await;
        // Finished watcher futures no longer consume global or tenant
        // admission slots. Prune only while installing a replacement so an
        // active generation cannot be removed by a detached cleanup task.
        tasks.retain(|_, task| !task.handle.is_finished());
        tasks.remove(&key);
        let Some(root) = root else {
            return;
        };
        if tasks.len() >= MAX_ACTIVE_WATCHERS {
            tracing::warn!(
                repo_id=%registration.repo_id,
                tenant_id=%registration.tenant_id,
                limit=MAX_ACTIVE_WATCHERS,
                "repo-watch-cap-reached"
            );
            return;
        }
        if tasks
            .values()
            .filter(|task| task.tenant_id == registration.tenant_id)
            .count()
            >= MAX_ACTIVE_WATCHERS_PER_TENANT
        {
            tracing::warn!(
                repo_id=%registration.repo_id,
                tenant_id=%registration.tenant_id,
                limit=MAX_ACTIVE_WATCHERS_PER_TENANT,
                "repo-watch-tenant-cap-reached"
            );
            return;
        }
        let task_tenant = registration.tenant_id.clone();
        let task_generation = registration.generation_id.clone();
        let handle = tokio::spawn(async move {
            if let Err(err) = watch_repo_task(registration, root, context).await {
                tracing::warn!(?err, "repo-watch-task-exited");
            }
        });
        tasks.insert(
            key,
            WatchTask {
                tenant_id: task_tenant,
                generation_id: task_generation,
                handle,
            },
        );
    }

    pub(crate) async fn stop_repo(&self, tenant_id: &str, repo_id: &str, expected_generation: &str) {
        let key = repo_key(tenant_id, repo_id);
        let mut tasks = self.inner.tasks.lock().await;
        if tasks
            .get(&key)
            .is_some_and(|task| task.generation_id == expected_generation)
        {
            tasks.remove(&key);
        }
    }

    pub(crate) async fn start_existing_repos(&self) {
        let repos = {
            let store = self.inner.fact_store.read().await;
            crate::repo_registry::list_all_repos(&store)
        };
        for repo in repos {
            self.start_repo(repo).await;
        }
    }
}

fn repo_key(tenant_id: &str, repo_id: &str) -> String {
    format!("{tenant_id}::{repo_id}")
}

async fn watch_repo_task(
    registration: RepoRegistration,
    root: PathBuf,
    context: WatchScanContext,
) -> Result<(), String> {
    tracing::info!(repo_id=%registration.repo_id, tenant_id=%registration.tenant_id, root=?root, "repo-watch-starting");
    // A recursive notify watcher performs its own unbounded directory walk
    // before scanner policy can apply depth/entry/time limits. Poll the bounded
    // policy snapshot instead; this also avoids access/open events emitted by
    // scanner reads recursively triggering more scans.
    tracing::info!(repo_id=%registration.repo_id, tenant_id=%registration.tenant_id, root=?root, "repo-watch-bounded-polling-backend");
    poll_watch_loop(registration, root, context, WatchMode::NeedsFullRescan).await
}

#[derive(Debug)]
enum WatchMode {
    Snapshot { snapshot: WatchSnapshot },
    NeedsFullRescan,
    Unavailable,
}

type WatchScanPayload = (crate::workspace_scan::WorkspaceScan, usize, usize, usize);

#[derive(Debug)]
struct WatchScanOutput {
    mode: WatchMode,
    payload: Option<WatchScanPayload>,
}

enum WatchAttemptError {
    Busy,
    Held,
    Stopped,
    Failed(String),
    Permanent(String),
}

#[derive(Debug)]
struct WatchScanFailure {
    mode: WatchMode,
    error: String,
}

async fn poll_watch_loop(
    registration: RepoRegistration,
    root: PathBuf,
    context: WatchScanContext,
    mut mode: WatchMode,
) -> Result<(), String> {
    loop {
        tokio::time::sleep(Duration::from_millis(POLL_INTERVAL_MS)).await;
        match run_scan_and_store(
            &registration,
            &root,
            &context.fact_store,
            &context.projection_state,
            &context.data_dir,
            &context.scan_policy,
            &context.scan_semaphore,
            &mut mode,
        )
        .await
        {
            Ok(()) | Err(WatchAttemptError::Busy | WatchAttemptError::Held) => {}
            Err(WatchAttemptError::Stopped) => return Ok(()),
            Err(WatchAttemptError::Failed(error)) => {
                record_watch_error(&registration, &context.fact_store, &error).await;
                tracing::warn!(
                    repo_id=%registration.repo_id,
                    tenant_id=%registration.tenant_id,
                    ?error,
                    "repo-watch-scan-failed-retrying"
                );
            }
            Err(WatchAttemptError::Permanent(error)) => {
                record_watch_error(&registration, &context.fact_store, &error).await;
                tracing::error!(
                    repo_id=%registration.repo_id,
                    tenant_id=%registration.tenant_id,
                    ?error,
                    "repo-watch-scan-failed-permanently"
                );
                return Err(error);
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_scan_and_store(
    registration: &RepoRegistration,
    root: &Path,
    fact_store: &Arc<RwLock<corecrux_memory::FactStore>>,
    projection_state: &Arc<RwLock<corecrux_projections::ProjectionState>>,
    data_dir: &Path,
    scan_policy: &RepoScanPolicy,
    scan_semaphore: &Arc<tokio::sync::Semaphore>,
    mode: &mut WatchMode,
) -> Result<(), WatchAttemptError> {
    {
        let store = fact_store.read().await;
        if store.journal_durability_poisoned() {
            return Err(WatchAttemptError::Permanent(
                "fact journal durable mutation plane is poisoned; restart required before repository watching"
                    .to_string(),
            ));
        }
        let is_current = crate::repo_registry::get_repo(&store, &registration.tenant_id, &registration.repo_id)
            .is_some_and(|current| {
                current.enabled
                    && current.generation_id == registration.generation_id
                    && current.root_path == registration.root_path
            });
        if !is_current {
            return Err(WatchAttemptError::Stopped);
        }
        if crate::repo_registry::scan_storage_held(&store, &registration.tenant_id, &registration.repo_id) {
            // A held watcher is paused, not failed. Keep its current snapshot
            // mode and avoid generating sidecars that cannot be selected or
            // garbage-collected until the hold is released.
            return Err(WatchAttemptError::Held);
        }
    }
    let permit = match scan_semaphore.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(tokio::sync::TryAcquireError::NoPermits) => return Err(WatchAttemptError::Busy),
        Err(tokio::sync::TryAcquireError::Closed) => {
            return Err(WatchAttemptError::Failed(
                "repository scan admission closed".to_string(),
            ));
        }
    };
    let owned_mode = std::mem::replace(mode, WatchMode::Unavailable);
    let root = root.to_path_buf();
    let scan_policy = scan_policy.clone();
    let output = tokio::task::spawn_blocking(move || {
        run_watch_scan(&root, &scan_policy, owned_mode).map(|output| (output, permit))
    })
    .await;
    let (output, scan_permit) = match output {
        Ok(Ok(result)) => result,
        Ok(Err(failure)) => {
            // Any failed incremental snapshot must be followed by a full
            // replacement scan. Retaining the old snapshot here can make a
            // byte-identical restoration look unchanged and leave the durable
            // repo status stuck at `failed`.
            let _ = failure.mode;
            *mode = WatchMode::NeedsFullRescan;
            return Err(WatchAttemptError::Failed(failure.error));
        }
        Err(error) => {
            *mode = WatchMode::NeedsFullRescan;
            return Err(WatchAttemptError::Failed(format!(
                "repository watcher scan task failed: {error}"
            )));
        }
    };
    *mode = output.mode;
    let Some((scan, files_reparsed, cache_hits, files_dropped)) = output.payload else {
        return Ok(());
    };
    if let Err(error) = store_scan(
        registration,
        fact_store,
        projection_state,
        data_dir,
        scan,
        scan_permit,
        files_reparsed,
        cache_hits,
        files_dropped,
    )
    .await
    {
        *mode = WatchMode::NeedsFullRescan;
        return Err(error);
    }
    Ok(())
}

fn run_watch_scan(
    root: &Path,
    scan_policy: &RepoScanPolicy,
    mode: WatchMode,
) -> Result<WatchScanOutput, WatchScanFailure> {
    match mode {
        WatchMode::Snapshot { snapshot } => {
            let result = scan_policy.execute(root, |canonical| {
                let next = polyglot_snapshot_in_context(canonical)?;
                let payload = if snapshot == next {
                    None
                } else {
                    // Snapshot detection and the full replacement scan share
                    // one root revalidation, deadline and work budget.
                    let scan = crate::workspace_scan_polyglot::run_repo_scan_in_context(canonical)?;
                    let files_reparsed = scan.files.len();
                    Some((scan, files_reparsed, 0, 0))
                };
                Ok(WatchScanOutput {
                    mode: WatchMode::Snapshot { snapshot: next },
                    payload,
                })
            });
            result.map_err(|error| WatchScanFailure {
                mode: WatchMode::Snapshot { snapshot },
                error: error.to_string(),
            })
        }
        WatchMode::NeedsFullRescan | WatchMode::Unavailable => scan_policy
            .execute(root, |canonical| {
                let snapshot = polyglot_snapshot_in_context(canonical)?;
                let scan = crate::workspace_scan_polyglot::run_repo_scan_in_context(canonical)?;
                let files_reparsed = scan.files.len();
                Ok(WatchScanOutput {
                    mode: WatchMode::Snapshot { snapshot },
                    payload: Some((scan, files_reparsed, 0, 0)),
                })
            })
            .map_err(|error| WatchScanFailure {
                mode: WatchMode::NeedsFullRescan,
                error: error.to_string(),
            }),
    }
}

#[allow(clippy::too_many_arguments)]
async fn store_scan(
    registration: &RepoRegistration,
    fact_store: &Arc<RwLock<corecrux_memory::FactStore>>,
    projection_state: &Arc<RwLock<corecrux_projections::ProjectionState>>,
    data_dir: &Path,
    scan: crate::workspace_scan::WorkspaceScan,
    scan_permit: tokio::sync::OwnedSemaphorePermit,
    files_reparsed: usize,
    cache_hits: usize,
    files_dropped: usize,
) -> Result<(), WatchAttemptError> {
    let scan_id = scan.scan_id.clone();
    {
        let store = fact_store.read().await;
        let Some(current) = crate::repo_registry::get_repo(&store, &registration.tenant_id, &registration.repo_id)
        else {
            return Ok(());
        };
        if !current.enabled
            || current.generation_id != registration.generation_id
            || current.root_path != registration.root_path
        {
            return Ok(());
        }
    }
    let snapshot_data_dir = data_dir.to_path_buf();
    let snapshot_tenant = registration.tenant_id.clone();
    let snapshot_repo = registration.repo_id.clone();
    let snapshot_result = tokio::task::spawn_blocking(move || {
        crate::repo_registry::write_scan_snapshot(&snapshot_data_dir, &snapshot_tenant, &snapshot_repo, &scan)
            .map(|pending| (scan, pending, scan_permit))
    })
    .await
    .map_err(|error| WatchAttemptError::Permanent(format!("watch scan snapshot task failed: {error}")))?;
    let (scan, pending_snapshot, _scan_permit) = snapshot_result.map_err(classify_snapshot_write_error)?;
    let mut store = fact_store.write().await;
    let Some(mut current) = crate::repo_registry::get_repo(&store, &registration.tenant_id, &registration.repo_id)
    else {
        pending_snapshot.settle_failed_commit(&store, None);
        drop(store);
        return Ok(());
    };
    if !current.enabled
        || current.generation_id != registration.generation_id
        || current.root_path != registration.root_path
    {
        pending_snapshot.settle_failed_commit(&store, None);
        drop(store);
        return Ok(());
    }
    if let Err(error) =
        crate::repo_registry::ensure_scan_writable(&store, &registration.tenant_id, &registration.repo_id)
    {
        pending_snapshot.settle_failed_commit(&store, Some(&error));
        drop(store);
        if matches!(error, crate::repo_registry::RepoRegistryError::LegalHold { .. }) {
            return Err(WatchAttemptError::Held);
        }
        return Err(classify_registry_commit_error(&error));
    }
    let previous_scan_id = current.last_scan_id.clone();
    current.last_scan_id = Some(scan_id.clone());
    current.scan_status = Some("done".to_string());
    current.scan_error = None;
    current.scan_finished_at_unix_ms = Some(now_unix_ms());
    if let Err(error) = crate::repo_registry::store_repo(&mut store, &current) {
        pending_snapshot.settle_failed_commit(&store, Some(&error));
        drop(store);
        return Err(classify_registry_commit_error(&error));
    }
    drop(store);
    pending_snapshot.commit();
    if let Some(previous_scan_id) = previous_scan_id.filter(|previous| previous != &scan_id) {
        if let Err(error) = crate::repo_registry::remove_scan_snapshot_if_unheld_async(
            fact_store.clone(),
            data_dir.to_path_buf(),
            registration.tenant_id.clone(),
            registration.repo_id.clone(),
            previous_scan_id,
        )
        .await
        {
            tracing::warn!(
                ?error,
                repo_id=%registration.repo_id,
                tenant_id=%registration.tenant_id,
                "old-repo-watch-snapshot-cleanup-deferred-to-startup-gc"
            );
        }
    }
    if let Err(err) = crate::repo_codegraph::maybe_emit_codegraph_edges_for_registration(
        fact_store,
        projection_state,
        data_dir,
        &registration.tenant_id,
        &registration.repo_id,
        &registration.generation_id,
        &scan,
    ) {
        tracing::warn!(
            ?err,
            repo_id=%registration.repo_id,
            tenant_id=%registration.tenant_id,
            "repo-watch-codegraph-edge-emission-failed"
        );
    }
    tracing::info!(
        repo_id=%registration.repo_id,
        tenant_id=%registration.tenant_id,
        scan_id,
        files_reparsed,
        cache_hits,
        files_dropped,
        "repo-watch-incremental-scan-stored"
    );
    Ok(())
}

fn classify_snapshot_write_error(error: crate::repo_registry::RepoRegistryError) -> WatchAttemptError {
    let message = format!("watch scan snapshot write failed: {error}");
    // Publication failures can occur after rename with indeterminate parent
    // durability. Retrying automatically could create one preserved orphan per
    // poll, so watcher-side snapshot persistence is fail-stop.
    WatchAttemptError::Permanent(message)
}

fn classify_registry_commit_error(error: &crate::repo_registry::RepoRegistryError) -> WatchAttemptError {
    let message = error.to_string();
    // Any selector-store failure is a storage-plane failure. Retrying a full
    // scan cannot repair it and may monopolize admission while a poisoned or
    // unavailable journal awaits operator recovery.
    WatchAttemptError::Permanent(message)
}

async fn record_watch_error(
    registration: &RepoRegistration,
    fact_store: &Arc<RwLock<corecrux_memory::FactStore>>,
    error: &str,
) {
    let mut store = fact_store.write().await;
    let Some(mut current) = crate::repo_registry::get_repo(&store, &registration.tenant_id, &registration.repo_id)
    else {
        return;
    };
    if !current.enabled
        || current.generation_id != registration.generation_id
        || current.root_path != registration.root_path
    {
        return;
    }
    if current.scan_status.as_deref() == Some("failed") && current.scan_error.as_deref() == Some(error) {
        return;
    }
    current.scan_status = Some("failed".to_string());
    current.scan_error = Some(error.to_string());
    current.scan_finished_at_unix_ms = Some(now_unix_ms());
    if let Err(store_error) = crate::repo_registry::store_repo(&mut store, &current) {
        tracing::warn!(?store_error, "repo-watch-error-status-update-failed");
    }
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis() as u64)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WatchSnapshot {
    relevant_file_count: u64,
    digest: [u8; 32],
}

fn polyglot_snapshot_in_context(root: &Path) -> Result<WatchSnapshot, crate::workspace_scan::ScanError> {
    #[cfg(not(unix))]
    {
        let _ = root;
        return Err(crate::workspace_scan::ScanError::Policy(
            "repository watcher snapshots require Unix secure metadata".to_string(),
        ));
    }

    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;

        let mut hasher = blake3::Hasher::new();
        let mut relevant_file_count = 0_u64;
        let mut read_error = None;
        crate::workspace_scan::walk_dir(root, root, &mut |rel, abs| {
            if read_error.is_some() || !is_watch_relevant_path(abs) {
                return;
            }
            match crate::workspace_scan::read_scan_bytes(abs) {
                Ok(bytes) => {
                    let rel = rel.as_os_str().as_bytes();
                    hasher.update(b"repo-watch-file-v3\0");
                    hasher.update(&(rel.len() as u64).to_le_bytes());
                    hasher.update(rel);
                    hasher.update(&(bytes.len() as u64).to_le_bytes());
                    hasher.update(&bytes);
                    relevant_file_count = relevant_file_count.saturating_add(1);
                }
                Err(error) => read_error = Some(error),
            }
        })?;
        if let Some(error) = read_error {
            return Err(error);
        }
        hasher.update(b"repo-watch-count-v1\0");
        hasher.update(&relevant_file_count.to_le_bytes());
        Ok(WatchSnapshot {
            relevant_file_count,
            digest: *hasher.finalize().as_bytes(),
        })
    }
}

fn is_watch_relevant_path(path: &Path) -> bool {
    let extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default();
    matches!(
        extension,
        "rs" | "ts"
            | "tsx"
            | "js"
            | "jsx"
            | "mjs"
            | "cjs"
            | "py"
            | "vue"
            | "svelte"
            | "go"
            | "java"
            | "c"
            | "h"
            | "cpp"
            | "cc"
            | "cxx"
            | "hpp"
            | "hh"
            | "hxx"
            | "cs"
            | "rb"
            | "swift"
            | "php"
    ) || crate::workspace_scan_manifests::is_dependency_input_path(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(root: &Path) -> RepoScanPolicy {
        RepoScanPolicy::for_test_roots(
            vec![root.canonicalize().expect("canonical root")],
            crate::repo_scan_policy::RepoScanLimits::default(),
        )
    }

    #[cfg(unix)]
    #[test]
    fn polling_snapshot_detects_same_length_edit_and_dependency_locks() {
        let root = tempfile::tempdir().expect("root");
        let policy = policy(root.path());
        let source = root.path().join("source.ts");
        let lock = root.path().join("package-lock.json");
        std::fs::write(&source, "aaaa").expect("source");
        std::fs::write(&lock, "{}").expect("lock");
        let first = policy
            .execute(root.path(), polyglot_snapshot_in_context)
            .expect("first snapshot");
        assert_eq!(first.relevant_file_count, 2);

        std::fs::write(&source, "bbbb").expect("same-length edit");
        let second = policy
            .execute(root.path(), polyglot_snapshot_in_context)
            .expect("second snapshot");
        assert_ne!(first, second);
    }

    #[test]
    fn polling_full_scan_transitions_rust_repo_to_polyglot() {
        let root = tempfile::tempdir().expect("root");
        std::fs::create_dir_all(root.path().join("mini/src")).expect("source dir");
        std::fs::write(root.path().join("Cargo.toml"), "[workspace]\nmembers = [\"mini\"]\n").expect("workspace");
        std::fs::write(
            root.path().join("mini/Cargo.toml"),
            "[package]\nname = \"mini\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .expect("manifest");
        std::fs::write(root.path().join("mini/src/lib.rs"), "pub fn rust_only() {}\n").expect("rust");
        let policy = policy(root.path());
        let initial = run_watch_scan(root.path(), &policy, WatchMode::NeedsFullRescan).expect("initial full scan");
        assert!(initial.payload.is_some());

        std::fs::write(root.path().join("web.ts"), "export function webRoute() {}\n").expect("typescript");
        let changed = run_watch_scan(root.path(), &policy, initial.mode).expect("changed full scan");
        let scan = changed.payload.expect("changed payload").0;
        assert!(scan.files.iter().any(|file| file.rel_path == "web.ts"));
    }

    #[tokio::test]
    async fn persisted_out_of_policy_repo_never_starts_a_watch_task() {
        let allowed = tempfile::tempdir().expect("allowed");
        let outside = tempfile::tempdir().expect("outside");
        let service = RepoWatchService {
            inner: Arc::new(RepoWatchInner {
                fact_store: Arc::new(RwLock::new(corecrux_memory::FactStore::new())),
                projection_state: Arc::new(RwLock::new(corecrux_projections::ProjectionState::default())),
                data_dir: allowed.path().to_path_buf(),
                scan_policy: Arc::new(policy(allowed.path())),
                scan_semaphore: Arc::new(tokio::sync::Semaphore::new(1)),
                tasks: Mutex::new(HashMap::new()),
            }),
        };
        let registration = RepoRegistration {
            repo_id: "outside".to_string(),
            tenant_id: "tenant-a".to_string(),
            root_path: Some(outside.path().display().to_string()),
            clone_url: None,
            languages: vec!["rust".to_string()],
            enabled: true,
            added_at_unix_ms: 0,
            generation_id: "fixture-generation".to_string(),
            last_scan_id: None,
            scan_status: None,
            scan_error: None,
            scan_queued_at_unix_ms: None,
            scan_finished_at_unix_ms: None,
        };
        {
            let mut store = service.inner.fact_store.write().await;
            crate::repo_registry::store_repo(&mut store, &registration).expect("persist registration");
        }
        service.start_repo(registration).await;
        assert!(service.inner.tasks.lock().await.is_empty());
    }

    #[tokio::test]
    async fn finished_watcher_releases_tenant_admission_slot_on_next_start() {
        let root = tempfile::tempdir().expect("root");
        let completed_handle = tokio::spawn(async {});
        tokio::time::timeout(Duration::from_secs(1), async {
            while !completed_handle.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("completed watcher must finish");
        let mut seeded_tasks = HashMap::new();
        seeded_tasks.insert(
            "tenant-a::finished".to_string(),
            WatchTask {
                tenant_id: "tenant-a".to_string(),
                generation_id: "finished-generation".to_string(),
                handle: completed_handle,
            },
        );
        for index in 0..(MAX_ACTIVE_WATCHERS_PER_TENANT - 1) {
            seeded_tasks.insert(
                format!("tenant-a::active-{index}"),
                WatchTask {
                    tenant_id: "tenant-a".to_string(),
                    generation_id: format!("active-generation-{index}"),
                    handle: tokio::spawn(std::future::pending()),
                },
            );
        }
        let fact_store = Arc::new(RwLock::new(corecrux_memory::FactStore::new()));
        let service = RepoWatchService {
            inner: Arc::new(RepoWatchInner {
                fact_store: fact_store.clone(),
                projection_state: Arc::new(RwLock::new(corecrux_projections::ProjectionState::default())),
                data_dir: root.path().to_path_buf(),
                scan_policy: Arc::new(policy(root.path())),
                scan_semaphore: Arc::new(tokio::sync::Semaphore::new(1)),
                tasks: Mutex::new(seeded_tasks),
            }),
        };
        let registration = RepoRegistration {
            repo_id: "replacement".to_string(),
            tenant_id: "tenant-a".to_string(),
            root_path: Some(root.path().display().to_string()),
            clone_url: None,
            languages: vec!["rust".to_string()],
            enabled: true,
            added_at_unix_ms: 1,
            generation_id: "replacement-generation".to_string(),
            last_scan_id: None,
            scan_status: None,
            scan_error: None,
            scan_queued_at_unix_ms: None,
            scan_finished_at_unix_ms: None,
        };
        {
            let mut store = fact_store.write().await;
            crate::repo_registry::store_repo(&mut store, &registration).expect("persist replacement");
        }

        service.start_repo(registration).await;

        let tasks = service.inner.tasks.lock().await;
        assert!(!tasks.contains_key("tenant-a::finished"));
        assert!(tasks.contains_key("tenant-a::replacement"));
        assert_eq!(tasks.len(), MAX_ACTIVE_WATCHERS_PER_TENANT);
    }

    #[tokio::test]
    async fn stale_watcher_generation_cannot_overwrite_replacement_status() {
        let root = tempfile::tempdir().expect("root");
        let fact_store = Arc::new(RwLock::new(corecrux_memory::FactStore::new()));
        let current = RepoRegistration {
            repo_id: "generation-race".to_string(),
            tenant_id: "tenant-a".to_string(),
            root_path: Some(root.path().display().to_string()),
            clone_url: None,
            languages: vec!["rust".to_string()],
            enabled: true,
            added_at_unix_ms: 2,
            generation_id: "replacement-generation".to_string(),
            last_scan_id: None,
            scan_status: None,
            scan_error: None,
            scan_queued_at_unix_ms: None,
            scan_finished_at_unix_ms: None,
        };
        {
            let mut store = fact_store.write().await;
            crate::repo_registry::store_repo(&mut store, &current).expect("store replacement");
        }
        let stale = RepoRegistration {
            generation_id: "stale-generation".to_string(),
            ..current
        };

        record_watch_error(&stale, &fact_store, "stale watcher error").await;

        let store = fact_store.read().await;
        let persisted =
            crate::repo_registry::get_repo(&store, "tenant-a", "generation-race").expect("replacement persisted");
        assert_eq!(persisted.generation_id, "replacement-generation");
        assert!(persisted.scan_status.is_none());
        assert!(persisted.scan_error.is_none());
    }

    #[tokio::test]
    async fn stale_watcher_self_stops_before_scan_admission() {
        let root = tempfile::tempdir().expect("root");
        let fact_store = Arc::new(RwLock::new(corecrux_memory::FactStore::new()));
        let current = RepoRegistration {
            repo_id: "self-stop".to_string(),
            tenant_id: "tenant-a".to_string(),
            root_path: Some(root.path().display().to_string()),
            clone_url: None,
            languages: vec!["rust".to_string()],
            enabled: true,
            added_at_unix_ms: 2,
            generation_id: "replacement-generation".to_string(),
            last_scan_id: None,
            scan_status: None,
            scan_error: None,
            scan_queued_at_unix_ms: None,
            scan_finished_at_unix_ms: None,
        };
        {
            let mut store = fact_store.write().await;
            crate::repo_registry::store_repo(&mut store, &current).expect("store replacement");
        }
        let stale = RepoRegistration {
            generation_id: "stale-generation".to_string(),
            ..current
        };
        let mut mode = WatchMode::NeedsFullRescan;

        let result = run_scan_and_store(
            &stale,
            root.path(),
            &fact_store,
            &Arc::new(RwLock::new(corecrux_projections::ProjectionState::default())),
            root.path(),
            &policy(root.path()),
            &Arc::new(tokio::sync::Semaphore::new(0)),
            &mut mode,
        )
        .await;

        assert!(matches!(result, Err(WatchAttemptError::Stopped)));
        assert!(matches!(mode, WatchMode::NeedsFullRescan));
    }

    #[tokio::test]
    async fn delayed_stale_start_cannot_replace_current_watcher() {
        let root = tempfile::tempdir().expect("root");
        let fact_store = Arc::new(RwLock::new(corecrux_memory::FactStore::new()));
        let current = RepoRegistration {
            repo_id: "generation-start-race".to_string(),
            tenant_id: "tenant-a".to_string(),
            root_path: Some(root.path().display().to_string()),
            clone_url: None,
            languages: vec!["rust".to_string()],
            enabled: true,
            added_at_unix_ms: 2,
            generation_id: "current-generation".to_string(),
            last_scan_id: None,
            scan_status: None,
            scan_error: None,
            scan_queued_at_unix_ms: None,
            scan_finished_at_unix_ms: None,
        };
        {
            let mut store = fact_store.write().await;
            crate::repo_registry::store_repo(&mut store, &current).expect("store current");
        }
        let service = RepoWatchService {
            inner: Arc::new(RepoWatchInner {
                fact_store,
                projection_state: Arc::new(RwLock::new(corecrux_projections::ProjectionState::default())),
                data_dir: root.path().to_path_buf(),
                scan_policy: Arc::new(policy(root.path())),
                scan_semaphore: Arc::new(tokio::sync::Semaphore::new(1)),
                tasks: Mutex::new(HashMap::new()),
            }),
        };
        service.start_repo(current.clone()).await;
        let key = repo_key(&current.tenant_id, &current.repo_id);
        let current_task_id = service
            .inner
            .tasks
            .lock()
            .await
            .get(&key)
            .expect("current watcher")
            .handle
            .id();

        service
            .start_repo(RepoRegistration {
                generation_id: "stale-generation".to_string(),
                ..current
            })
            .await;

        let tasks = service.inner.tasks.lock().await;
        assert_eq!(tasks.len(), 1);
        assert_eq!(
            tasks.get(&key).expect("current watcher retained").handle.id(),
            current_task_id
        );
    }

    #[tokio::test]
    async fn stale_stop_cannot_abort_current_watcher_generation() {
        let root = tempfile::tempdir().expect("root");
        let fact_store = Arc::new(RwLock::new(corecrux_memory::FactStore::new()));
        let current = RepoRegistration {
            repo_id: "generation-stop-race".to_string(),
            tenant_id: "tenant-a".to_string(),
            root_path: Some(root.path().display().to_string()),
            clone_url: None,
            languages: vec!["rust".to_string()],
            enabled: true,
            added_at_unix_ms: 2,
            generation_id: "current-generation".to_string(),
            last_scan_id: None,
            scan_status: None,
            scan_error: None,
            scan_queued_at_unix_ms: None,
            scan_finished_at_unix_ms: None,
        };
        {
            let mut store = fact_store.write().await;
            crate::repo_registry::store_repo(&mut store, &current).expect("store current");
        }
        let service = RepoWatchService {
            inner: Arc::new(RepoWatchInner {
                fact_store,
                projection_state: Arc::new(RwLock::new(corecrux_projections::ProjectionState::default())),
                data_dir: root.path().to_path_buf(),
                scan_policy: Arc::new(policy(root.path())),
                scan_semaphore: Arc::new(tokio::sync::Semaphore::new(1)),
                tasks: Mutex::new(HashMap::new()),
            }),
        };
        service.start_repo(current.clone()).await;
        let key = repo_key(&current.tenant_id, &current.repo_id);
        let task_id = service.inner.tasks.lock().await.get(&key).expect("watcher").handle.id();

        service
            .stop_repo(&current.tenant_id, &current.repo_id, "stale-generation")
            .await;
        assert_eq!(
            service
                .inner
                .tasks
                .lock()
                .await
                .get(&key)
                .expect("current watcher retained")
                .handle
                .id(),
            task_id
        );

        service
            .stop_repo(&current.tenant_id, &current.repo_id, &current.generation_id)
            .await;
        assert!(service.inner.tasks.lock().await.is_empty());
    }

    #[tokio::test]
    async fn busy_watcher_preserves_pending_full_rescan_state() {
        let root = tempfile::tempdir().expect("root");
        let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
        let _permit = semaphore.clone().acquire_owned().await.expect("hold admission");
        let registration = RepoRegistration {
            repo_id: "busy".to_string(),
            tenant_id: "tenant-a".to_string(),
            root_path: Some(root.path().display().to_string()),
            clone_url: None,
            languages: vec!["rust".to_string()],
            enabled: true,
            added_at_unix_ms: 1,
            generation_id: "busy-generation".to_string(),
            last_scan_id: None,
            scan_status: None,
            scan_error: None,
            scan_queued_at_unix_ms: None,
            scan_finished_at_unix_ms: None,
        };
        let mut mode = WatchMode::NeedsFullRescan;
        let mut store = corecrux_memory::FactStore::new();
        crate::repo_registry::store_repo(&mut store, &registration).expect("store current registration");
        let result = run_scan_and_store(
            &registration,
            root.path(),
            &Arc::new(RwLock::new(store)),
            &Arc::new(RwLock::new(corecrux_projections::ProjectionState::default())),
            root.path(),
            &policy(root.path()),
            &semaphore,
            &mut mode,
        )
        .await;

        assert!(matches!(result, Err(WatchAttemptError::Busy)));
        assert!(matches!(mode, WatchMode::NeedsFullRescan));
    }

    #[tokio::test]
    async fn poisoned_fact_journal_stops_watcher_before_scan_or_sidecar_publication() {
        let root = tempfile::tempdir().expect("root");
        std::fs::write(root.path().join("lib.rs"), "pub fn fixture() {}\n").expect("fixture source");
        let data_dir = tempfile::tempdir().expect("data dir");
        let registration = RepoRegistration {
            repo_id: "poisoned".to_string(),
            tenant_id: "tenant-a".to_string(),
            root_path: Some(root.path().display().to_string()),
            clone_url: None,
            languages: vec!["rust".to_string()],
            enabled: true,
            added_at_unix_ms: 1,
            generation_id: "poisoned-generation".to_string(),
            last_scan_id: None,
            scan_status: None,
            scan_error: None,
            scan_queued_at_unix_ms: None,
            scan_finished_at_unix_ms: None,
        };
        let mut store = corecrux_memory::FactStore::with_persistence(data_dir.path()).expect("durable store");
        crate::repo_registry::store_repo(&mut store, &registration).expect("store registration");
        store.fail_next_durable_append_after_write_for_test();
        store
            .place_legal_hold(corecrux_memory::legal_hold::PlaceLegalHold {
                tenant_id: "tenant-a".to_string(),
                entity_prefixes: vec![crate::repo_registry::scan_entity("tenant-a", "poisoned")],
                reason: "indeterminate watcher hold".to_string(),
                actor: Some("fixture".to_string()),
            })
            .expect_err("inject indeterminate hold append");
        assert!(store.journal_durability_poisoned());

        let mut mode = WatchMode::NeedsFullRescan;
        let result = run_scan_and_store(
            &registration,
            root.path(),
            &Arc::new(RwLock::new(store)),
            &Arc::new(RwLock::new(corecrux_projections::ProjectionState::default())),
            data_dir.path(),
            &policy(root.path()),
            &Arc::new(tokio::sync::Semaphore::new(1)),
            &mut mode,
        )
        .await;

        assert!(matches!(result, Err(WatchAttemptError::Permanent(_))));
        assert!(matches!(mode, WatchMode::NeedsFullRescan));
        assert!(
            !data_dir.path().join("repo-scans-v1").exists(),
            "poisoned watcher must stop before publishing a sidecar"
        );
    }

    #[tokio::test]
    async fn held_watcher_pauses_without_scanning_or_accumulating_sidecars() {
        let root = tempfile::tempdir().expect("root");
        let data_dir = tempfile::tempdir().expect("data dir");
        let fact_store = Arc::new(RwLock::new(corecrux_memory::FactStore::new()));
        let registration = RepoRegistration {
            repo_id: "held".to_string(),
            tenant_id: "tenant-a".to_string(),
            root_path: Some(root.path().display().to_string()),
            clone_url: None,
            languages: vec!["rust".to_string()],
            enabled: true,
            added_at_unix_ms: 1,
            generation_id: "held-generation".to_string(),
            last_scan_id: None,
            scan_status: None,
            scan_error: None,
            scan_queued_at_unix_ms: None,
            scan_finished_at_unix_ms: None,
        };
        {
            let mut store = fact_store.write().await;
            crate::repo_registry::store_repo(&mut store, &registration).expect("store registration");
            store
                .place_legal_hold(corecrux_memory::legal_hold::PlaceLegalHold {
                    tenant_id: "tenant-a".to_string(),
                    entity_prefixes: vec![crate::repo_registry::scan_entity("tenant-a", "held")],
                    reason: "pause watched repo".to_string(),
                    actor: Some("fixture".to_string()),
                })
                .expect("place hold");
        }
        let mut mode = WatchMode::NeedsFullRescan;
        for _ in 0..2 {
            let result = run_scan_and_store(
                &registration,
                root.path(),
                &fact_store,
                &Arc::new(RwLock::new(corecrux_projections::ProjectionState::default())),
                data_dir.path(),
                &policy(root.path()),
                &Arc::new(tokio::sync::Semaphore::new(1)),
                &mut mode,
            )
            .await;
            assert!(matches!(result, Err(WatchAttemptError::Held)));
            assert!(matches!(mode, WatchMode::NeedsFullRescan));
        }
        assert!(
            !data_dir.path().join("repo-scans-v1").exists(),
            "held polls must not publish retry orphans"
        );
    }

    #[test]
    fn oversized_snapshot_output_disables_retry_loop() {
        let classified = classify_snapshot_write_error(crate::repo_registry::RepoRegistryError::SnapshotTooLarge);
        assert!(
            matches!(classified, WatchAttemptError::Permanent(message) if message.contains("64 MiB")),
            "a deterministic sidecar overflow must not trigger another full scan every poll"
        );
    }

    #[test]
    fn indeterminate_snapshot_publication_disables_retry_loop() {
        let classified = classify_snapshot_write_error(crate::repo_registry::RepoRegistryError::Io(
            std::io::Error::other("parent directory fsync failed after rename"),
        ));
        assert!(
            matches!(classified, WatchAttemptError::Permanent(message) if message.contains("fsync failed")),
            "watchers must not create another orphan after an indeterminate publication"
        );
    }

    #[test]
    fn failed_watcher_scan_preserves_snapshot_and_full_retry_modes() {
        let root = tempfile::tempdir().expect("root");
        let source = root.path().join("source.ts");
        std::fs::write(&source, "export const value = 1;\n").expect("source");
        let initial_policy = policy(root.path());
        let snapshot = initial_policy
            .execute(root.path(), polyglot_snapshot_in_context)
            .expect("initial snapshot");
        let tight_policy = RepoScanPolicy::for_test_roots(
            vec![root.path().canonicalize().expect("canonical root")],
            crate::repo_scan_policy::RepoScanLimits {
                max_file_bytes: 1,
                ..crate::repo_scan_policy::RepoScanLimits::default()
            },
        );

        let incremental = run_watch_scan(
            root.path(),
            &tight_policy,
            WatchMode::Snapshot {
                snapshot: snapshot.clone(),
            },
        )
        .expect_err("tight policy must fail");
        assert!(matches!(&incremental.mode, WatchMode::Snapshot { .. }));
        if let WatchMode::Snapshot { snapshot: retained } = incremental.mode {
            assert_eq!(retained, snapshot);
        }

        let full = run_watch_scan(root.path(), &tight_policy, WatchMode::NeedsFullRescan)
            .expect_err("tight full scan must fail");
        assert!(matches!(full.mode, WatchMode::NeedsFullRescan));
    }
}
