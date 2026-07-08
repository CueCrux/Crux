// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Feature-gated active watch loop for registered local repositories.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::{mpsc, Mutex, RwLock};

use crate::repo_registry::RepoRegistration;

const WATCH_ENV: &str = "CORECRUXD_REPO_WATCH";
const WATCH_POLL_ENV: &str = "CORECRUXD_REPO_WATCH_POLL";
const DEBOUNCE_MS: u64 = 750;
const POLL_INTERVAL_MS: u64 = 1_000;

pub(crate) fn enabled_from_env() -> bool {
    std::env::var(WATCH_ENV).ok().is_some_and(|v| {
        let v = v.trim().to_ascii_lowercase();
        !(v.is_empty() || v == "0" || v == "false" || v == "off" || v == "no")
    })
}

fn poll_enabled_from_env() -> bool {
    std::env::var(WATCH_POLL_ENV).ok().is_some_and(|v| {
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
    tasks: Mutex<HashMap<String, WatchTask>>,
}

struct WatchTask {
    handle: tokio::task::JoinHandle<()>,
}

impl Drop for WatchTask {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

impl RepoWatchService {
    pub(crate) fn maybe_new(fact_store: Arc<RwLock<corecrux_memory::FactStore>>) -> Option<Self> {
        enabled_from_env().then(|| Self {
            inner: Arc::new(RepoWatchInner {
                fact_store,
                tasks: Mutex::new(HashMap::new()),
            }),
        })
    }

    pub(crate) async fn start_repo(&self, registration: RepoRegistration) {
        if !registration.enabled {
            return;
        }
        let Some(root_path) = registration.root_path.clone() else {
            return;
        };
        let root = PathBuf::from(&root_path);
        if !root.exists() {
            tracing::warn!(repo_id=%registration.repo_id, tenant_id=%registration.tenant_id, root_path, "repo-watch-root-missing");
            return;
        }
        let key = repo_key(&registration.tenant_id, &registration.repo_id);
        self.stop_repo(&registration.tenant_id, &registration.repo_id).await;
        let fact_store = self.inner.fact_store.clone();
        let handle = tokio::spawn(async move {
            if let Err(err) = watch_repo_task(registration, root, fact_store).await {
                tracing::warn!(?err, "repo-watch-task-exited");
            }
        });
        self.inner.tasks.lock().await.insert(key, WatchTask { handle });
    }

    pub(crate) async fn stop_repo(&self, tenant_id: &str, repo_id: &str) {
        self.inner.tasks.lock().await.remove(&repo_key(tenant_id, repo_id));
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
    fact_store: Arc<RwLock<corecrux_memory::FactStore>>,
) -> Result<(), String> {
    let mut cache = crate::workspace_scan_ast::AstScanCache::from_root(&root).map_err(|err| err.to_string())?;
    tracing::info!(repo_id=%registration.repo_id, tenant_id=%registration.tenant_id, root=?root, "repo-watch-starting");

    if should_use_polling(&root) {
        tracing::info!(repo_id=%registration.repo_id, tenant_id=%registration.tenant_id, root=?root, "repo-watch-polling-backend");
        return poll_watch_loop(registration, root, fact_store, cache).await;
    }

    match notify_watch_loop(registration.clone(), root.clone(), fact_store.clone(), cache).await {
        Ok(()) => Ok(()),
        Err(err) => {
            tracing::warn!(?err, repo_id=%registration.repo_id, tenant_id=%registration.tenant_id, root=?root, "repo-watch-notify-start-failed-falling-back-to-poll");
            cache = crate::workspace_scan_ast::AstScanCache::from_root(&root).map_err(|err| err.to_string())?;
            poll_watch_loop(registration, root, fact_store, cache).await
        }
    }
}

async fn notify_watch_loop(
    registration: RepoRegistration,
    root: PathBuf,
    fact_store: Arc<RwLock<corecrux_memory::FactStore>>,
    mut cache: crate::workspace_scan_ast::AstScanCache,
) -> Result<(), String> {
    let (tx, mut rx) = mpsc::unbounded_channel::<PathBuf>();
    let tx_events = tx.clone();
    let mut watcher: RecommendedWatcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        if let Ok(event) = res {
            for path in event.paths {
                let _ = tx_events.send(path);
            }
        }
    })
    .map_err(|err| err.to_string())?;
    watcher
        .watch(&root, RecursiveMode::Recursive)
        .map_err(|err| err.to_string())?;

    tracing::info!(repo_id=%registration.repo_id, tenant_id=%registration.tenant_id, root=?root, "repo-watch-notify-backend");
    while let Some(first) = rx.recv().await {
        let mut paths = vec![first];
        tokio::time::sleep(Duration::from_millis(DEBOUNCE_MS)).await;
        while let Ok(path) = rx.try_recv() {
            paths.push(path);
        }
        let paths = filter_event_paths(&root, paths);
        if paths.is_empty() {
            continue;
        }
        run_incremental_and_store(&registration, &root, &fact_store, &mut cache, &paths).await?;
    }
    drop(watcher);
    Ok(())
}

async fn poll_watch_loop(
    registration: RepoRegistration,
    root: PathBuf,
    fact_store: Arc<RwLock<corecrux_memory::FactStore>>,
    mut cache: crate::workspace_scan_ast::AstScanCache,
) -> Result<(), String> {
    // Fallback for WSL `/mnt/*` paths and explicit `CORECRUXD_REPO_WATCH_POLL=1`.
    // Native inotify often misses or coalesces Windows-host filesystem events
    // surfaced through `/mnt`, while the daemon's Linux worktree paths work
    // correctly with notify's recommended watcher.
    loop {
        tokio::time::sleep(Duration::from_millis(POLL_INTERVAL_MS)).await;
        run_incremental_and_store(&registration, &root, &fact_store, &mut cache, &[]).await?;
    }
}

#[cfg(test)]
pub(crate) fn construct_notify_watcher_for_smoke(root: &std::path::Path) -> Result<(), notify::Error> {
    let mut watcher = notify::recommended_watcher(|_res: notify::Result<notify::Event>| {})?;
    watcher.watch(root, RecursiveMode::Recursive)?;
    Ok(())
}

async fn run_incremental_and_store(
    registration: &RepoRegistration,
    root: &Path,
    fact_store: &Arc<RwLock<corecrux_memory::FactStore>>,
    cache: &mut crate::workspace_scan_ast::AstScanCache,
    paths: &[PathBuf],
) -> Result<(), String> {
    let result =
        crate::workspace_scan_ast::update_cache_incremental(root, cache, paths).map_err(|err| err.to_string())?;
    if result.stats.files_reparsed == 0 && result.stats.files_dropped == 0 {
        return Ok(());
    }
    let scan_id = result.scan.scan_id.clone();
    let scan_json = serde_json::to_string(&result.scan).map_err(|err| err.to_string())?;
    {
        let mut store = fact_store.write().await;
        crate::repo_registry::store_scan_json(&mut store, &registration.tenant_id, &registration.repo_id, scan_json);
    }
    tracing::info!(
        repo_id=%registration.repo_id,
        tenant_id=%registration.tenant_id,
        scan_id,
        files_reparsed=result.stats.files_reparsed,
        cache_hits=result.stats.cache_hits,
        files_dropped=result.stats.files_dropped,
        "repo-watch-incremental-scan-stored"
    );
    Ok(())
}

fn should_use_polling(root: &Path) -> bool {
    poll_enabled_from_env() || root.starts_with("/mnt")
}

fn filter_event_paths(root: &Path, paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut out = BTreeSet::new();
    for path in paths {
        let rel = path.strip_prefix(root).unwrap_or(&path);
        if crate::workspace_scan_ast::should_ignore_path(rel) {
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) == Some("rs") || !path.exists() {
            out.insert(path);
        }
    }
    out.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notify_watcher_constructs_for_temp_dir() {
        let tmp = tempfile::tempdir().expect("tempdir");
        construct_notify_watcher_for_smoke(tmp.path()).expect("notify watcher smoke");
    }

    #[test]
    fn mnt_paths_use_polling_backend() {
        assert!(should_use_polling(std::path::Path::new("/mnt/c/project")));
    }
}
