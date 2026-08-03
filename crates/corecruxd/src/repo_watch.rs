// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Feature-gated active watch loop for registered local repositories.

use std::collections::{BTreeMap, BTreeSet, HashMap};
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
    projection_state: Arc<RwLock<corecrux_projections::ProjectionState>>,
    data_dir: PathBuf,
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
    pub(crate) fn maybe_new(
        fact_store: Arc<RwLock<corecrux_memory::FactStore>>,
        projection_state: Arc<RwLock<corecrux_projections::ProjectionState>>,
        data_dir: PathBuf,
    ) -> Option<Self> {
        enabled_from_env().then(|| Self {
            inner: Arc::new(RepoWatchInner {
                fact_store,
                projection_state,
                data_dir,
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
        let projection_state = self.inner.projection_state.clone();
        let data_dir = self.inner.data_dir.clone();
        let handle = tokio::spawn(async move {
            if let Err(err) = watch_repo_task(registration, root, fact_store, projection_state, data_dir).await {
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
    projection_state: Arc<RwLock<corecrux_projections::ProjectionState>>,
    data_dir: PathBuf,
) -> Result<(), String> {
    tracing::info!(repo_id=%registration.repo_id, tenant_id=%registration.tenant_id, root=?root, "repo-watch-starting");
    let mode = if crate::workspace_scan_polyglot::should_use_rust_workspace_scan(&root) {
        WatchMode::Rust {
            cache: crate::workspace_scan_ast::AstScanCache::from_root(&root).map_err(|err| err.to_string())?,
        }
    } else {
        WatchMode::Polyglot {
            snapshot: polyglot_snapshot(&root),
        }
    };

    if should_use_polling(&root) {
        tracing::info!(repo_id=%registration.repo_id, tenant_id=%registration.tenant_id, root=?root, "repo-watch-polling-backend");
        return poll_watch_loop(registration, root, fact_store, projection_state, data_dir, mode).await;
    }

    match notify_watch_loop(
        registration.clone(),
        root.clone(),
        fact_store.clone(),
        projection_state.clone(),
        data_dir.clone(),
        mode,
    )
    .await
    {
        Ok(()) => Ok(()),
        Err(err) => {
            tracing::warn!(?err, repo_id=%registration.repo_id, tenant_id=%registration.tenant_id, root=?root, "repo-watch-notify-start-failed-falling-back-to-poll");
            let mode = if crate::workspace_scan_polyglot::should_use_rust_workspace_scan(&root) {
                WatchMode::Rust {
                    cache: crate::workspace_scan_ast::AstScanCache::from_root(&root).map_err(|err| err.to_string())?,
                }
            } else {
                WatchMode::Polyglot {
                    snapshot: polyglot_snapshot(&root),
                }
            };
            poll_watch_loop(registration, root, fact_store, projection_state, data_dir, mode).await
        }
    }
}

enum WatchMode {
    Rust {
        cache: crate::workspace_scan_ast::AstScanCache,
    },
    Polyglot {
        snapshot: BTreeMap<String, (u64, u64)>,
    },
}

async fn notify_watch_loop(
    registration: RepoRegistration,
    root: PathBuf,
    fact_store: Arc<RwLock<corecrux_memory::FactStore>>,
    projection_state: Arc<RwLock<corecrux_projections::ProjectionState>>,
    data_dir: PathBuf,
    mut mode: WatchMode,
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
        run_scan_and_store(
            &registration,
            &root,
            &fact_store,
            &projection_state,
            &data_dir,
            &mut mode,
            &paths,
        )
        .await?;
    }
    drop(watcher);
    Ok(())
}

async fn poll_watch_loop(
    registration: RepoRegistration,
    root: PathBuf,
    fact_store: Arc<RwLock<corecrux_memory::FactStore>>,
    projection_state: Arc<RwLock<corecrux_projections::ProjectionState>>,
    data_dir: PathBuf,
    mut mode: WatchMode,
) -> Result<(), String> {
    // Fallback for WSL `/mnt/*` paths and explicit `CORECRUXD_REPO_WATCH_POLL=1`.
    // Native inotify often misses or coalesces Windows-host filesystem events
    // surfaced through `/mnt`, while the daemon's Linux worktree paths work
    // correctly with notify's recommended watcher.
    loop {
        tokio::time::sleep(Duration::from_millis(POLL_INTERVAL_MS)).await;
        run_scan_and_store(
            &registration,
            &root,
            &fact_store,
            &projection_state,
            &data_dir,
            &mut mode,
            &[],
        )
        .await?;
    }
}

#[cfg(test)]
pub(crate) fn construct_notify_watcher_for_smoke(root: &std::path::Path) -> Result<(), notify::Error> {
    let mut watcher = notify::recommended_watcher(|_res: notify::Result<notify::Event>| {})?;
    watcher.watch(root, RecursiveMode::Recursive)?;
    Ok(())
}

async fn run_scan_and_store(
    registration: &RepoRegistration,
    root: &Path,
    fact_store: &Arc<RwLock<corecrux_memory::FactStore>>,
    projection_state: &Arc<RwLock<corecrux_projections::ProjectionState>>,
    data_dir: &Path,
    mode: &mut WatchMode,
    paths: &[PathBuf],
) -> Result<(), String> {
    // A vanished repo root must not overwrite the last good scan with an empty
    // one. When every file disappears, `files_dropped` is non-zero, so the
    // early-returns below do NOT fire and the empty scan is stored — the
    // operator loses the whole index with no signal. A scan that could not run
    // is not a scan that ran and found nothing: leave the stored scan alone
    // and say so.
    if !root.is_dir() {
        tracing::warn!(
            repo_id=%registration.repo_id,
            tenant_id=%registration.tenant_id,
            root=?root,
            "repo-watch-root-missing-scan-skipped"
        );
        return Ok(());
    }
    let (scan, files_reparsed, cache_hits, files_dropped) = match mode {
        WatchMode::Rust { cache } => {
            let result = crate::workspace_scan_ast::update_cache_incremental(root, cache, paths)
                .map_err(|err| err.to_string())?;
            if result.stats.files_reparsed == 0 && result.stats.files_dropped == 0 {
                return Ok(());
            }
            (
                result.scan,
                result.stats.files_reparsed,
                result.stats.cache_hits,
                result.stats.files_dropped,
            )
        }
        WatchMode::Polyglot { snapshot } => {
            let changed_count = if paths.is_empty() {
                let next = polyglot_snapshot(root);
                let changed = count_snapshot_changes(snapshot, &next);
                if changed == 0 {
                    return Ok(());
                }
                *snapshot = next;
                changed
            } else {
                *snapshot = polyglot_snapshot(root);
                paths.len()
            };
            // run_repo_scan_at, not run_polyglot_scan_at: a cargo-workspace repo
            // with polyglot files re-indexes as a merged scan (crates + routes
            // preserved), identical to what registration produced.
            let scan = crate::workspace_scan_polyglot::run_repo_scan_at(root).map_err(|err| err.to_string())?;
            (scan, changed_count, 0, 0)
        }
    };
    let scan_id = scan.scan_id.clone();
    let scan_json = serde_json::to_string(&scan).map_err(|err| err.to_string())?;
    {
        let mut store = fact_store.write().await;
        crate::repo_registry::store_scan_json(&mut store, &registration.tenant_id, &registration.repo_id, scan_json);
    }
    if let Err(err) = crate::repo_codegraph::maybe_emit_codegraph_edges(
        fact_store,
        projection_state,
        data_dir,
        &registration.tenant_id,
        &registration.repo_id,
        &scan,
    )
    .await
    {
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
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or_default();
        if matches!(ext, "rs" | "ts" | "tsx" | "py" | "vue") || !path.exists() {
            out.insert(path);
        }
    }
    out.into_iter().collect()
}

fn polyglot_snapshot(root: &Path) -> BTreeMap<String, (u64, u64)> {
    let mut out = BTreeMap::new();
    let _ = crate::workspace_scan::walk_dir(root, root, &mut |_rel, abs| {
        let ext = abs.extension().and_then(|e| e.to_str()).unwrap_or_default();
        if !matches!(ext, "rs" | "ts" | "tsx" | "py" | "vue") {
            return;
        }
        if let Ok(meta) = std::fs::metadata(abs) {
            let mtime_ms = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |d| d.as_millis() as u64);
            out.insert(abs.display().to_string(), (mtime_ms, meta.len()));
        }
    });
    out
}

fn count_snapshot_changes(old: &BTreeMap<String, (u64, u64)>, new: &BTreeMap<String, (u64, u64)>) -> usize {
    let added_or_changed = new.iter().filter(|(path, sig)| old.get(*path) != Some(*sig)).count();
    let removed = old.keys().filter(|path| !new.contains_key(*path)).count();
    added_or_changed + removed
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::test_support::EnvVarGuard;

    // ────────────────────────── Fixtures ──────────────────────────

    fn stores() -> (
        Arc<RwLock<corecrux_memory::FactStore>>,
        Arc<RwLock<corecrux_projections::ProjectionState>>,
    ) {
        (
            Arc::new(RwLock::new(corecrux_memory::FactStore::new())),
            Arc::new(RwLock::new(corecrux_projections::ProjectionState::default())),
        )
    }

    /// Build the service directly rather than through `maybe_new`, so the
    /// task-bookkeeping tests do not have to mutate process-global env.
    fn service(
        fact_store: Arc<RwLock<corecrux_memory::FactStore>>,
        projection_state: Arc<RwLock<corecrux_projections::ProjectionState>>,
        data_dir: PathBuf,
    ) -> RepoWatchService {
        RepoWatchService {
            inner: Arc::new(RepoWatchInner {
                fact_store,
                projection_state,
                data_dir,
                tasks: Mutex::new(HashMap::new()),
            }),
        }
    }

    fn registration(tenant: &str, repo: &str, root: Option<&Path>, enabled: bool) -> RepoRegistration {
        RepoRegistration {
            repo_id: repo.to_string(),
            tenant_id: tenant.to_string(),
            root_path: root.map(|p| p.display().to_string()),
            clone_url: None,
            languages: Vec::new(),
            enabled,
            added_at_unix_ms: 1,
            last_scan_id: None,
            scan_status: None,
            scan_error: None,
            scan_queued_at_unix_ms: None,
            scan_finished_at_unix_ms: None,
        }
    }

    /// A non-cargo repo the polyglot scanner can see: one TypeScript file.
    fn polyglot_repo(root: &Path) {
        std::fs::create_dir_all(root.join("src")).expect("mkdir src");
        std::fs::write(root.join("src/app.ts"), "export function hello() { return 1; }\n").expect("write ts");
    }

    /// A minimal cargo workspace, so the Rust (AST-cache) lane has a root it
    /// can discover crates in.
    fn cargo_workspace(root: &Path) {
        std::fs::create_dir_all(root.join("crates/alpha/src")).expect("mkdir crate");
        std::fs::write(root.join("Cargo.toml"), "[workspace]\nmembers = [\"crates/alpha\"]\n").expect("workspace toml");
        std::fs::write(
            root.join("crates/alpha/Cargo.toml"),
            "[package]\nname = \"alpha\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .expect("crate toml");
        std::fs::write(root.join("crates/alpha/src/lib.rs"), "pub fn alpha() {}\n").expect("lib.rs");
    }

    async fn stored_scan(
        fact_store: &Arc<RwLock<corecrux_memory::FactStore>>,
        tenant: &str,
        repo: &str,
    ) -> Option<crate::workspace_scan::WorkspaceScan> {
        let store = fact_store.read().await;
        // Background: the watcher reacts to filesystem events, not requests.
        let scope = crate::auth::TenantScope::background(tenant, "repo watch: reload scan after change");
        let json = crate::repo_registry::load_scan_json(&store, &scope, repo)?;
        Some(serde_json::from_str(&json).expect("stored scan must decode"))
    }

    /// Poll for a stored scan fact rather than sleeping a fixed interval: the
    /// watch loops tick on wall-clock timers we do not want to hard-code.
    async fn await_stored_scan(
        fact_store: &Arc<RwLock<corecrux_memory::FactStore>>,
        tenant: &str,
        repo: &str,
    ) -> Option<crate::workspace_scan::WorkspaceScan> {
        for _ in 0..120 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if let Some(scan) = stored_scan(fact_store, tenant, repo).await {
                return Some(scan);
            }
        }
        None
    }

    // ────────────────────────── Env gates ──────────────────────────

    /// The watch loop is opt-in and every conventional "off" spelling must stay
    /// off. A truthy read of `CORECRUXD_REPO_WATCH=false` would start a watcher
    /// on every registered repo of a daemon that explicitly asked for none.
    #[test]
    #[serial_test::serial]
    fn watch_flag_is_off_unless_explicitly_truthy() {
        {
            let _guard = EnvVarGuard::unset(WATCH_ENV);
            assert!(!enabled_from_env(), "an absent env var must read as off");
        }
        for off in ["", "   ", "0", "false", "FALSE", " Off ", "no", "NO"] {
            let _guard = EnvVarGuard::set(WATCH_ENV, off);
            assert!(!enabled_from_env(), "{off:?} must read as off");
        }
        for on in ["1", "true", "TRUE", "yes", "on", "enabled"] {
            let _guard = EnvVarGuard::set(WATCH_ENV, on);
            assert!(enabled_from_env(), "{on:?} must read as on");
        }
    }

    /// `CORECRUXD_REPO_WATCH_POLL` selects the polling backend for roots that
    /// would otherwise get inotify, and must respect the same off spellings.
    #[test]
    #[serial_test::serial]
    fn poll_flag_selects_the_polling_backend() {
        let tmp = tempfile::tempdir().expect("tempdir");
        {
            let _guard = EnvVarGuard::unset(WATCH_POLL_ENV);
            assert!(!poll_enabled_from_env());
            assert!(!should_use_polling(tmp.path()), "a normal root defaults to notify");
        }
        {
            let _guard = EnvVarGuard::set(WATCH_POLL_ENV, "0");
            assert!(!poll_enabled_from_env(), "0 must not force polling");
            assert!(!should_use_polling(tmp.path()));
        }
        {
            let _guard = EnvVarGuard::set(WATCH_POLL_ENV, "1");
            assert!(poll_enabled_from_env());
            assert!(should_use_polling(tmp.path()));
        }
    }

    #[test]
    fn notify_watcher_constructs_for_temp_dir() {
        let tmp = tempfile::tempdir().expect("tempdir");
        construct_notify_watcher_for_smoke(tmp.path()).expect("notify watcher smoke");
    }

    #[test]
    fn mnt_paths_use_polling_backend() {
        assert!(should_use_polling(std::path::Path::new("/mnt/c/project")));
    }

    #[test]
    #[serial_test::serial]
    fn maybe_new_builds_a_service_only_when_the_watch_flag_is_on() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (fact_store, projection_state) = stores();
        {
            let _guard = EnvVarGuard::unset(WATCH_ENV);
            assert!(
                RepoWatchService::maybe_new(fact_store.clone(), projection_state.clone(), tmp.path().to_path_buf())
                    .is_none(),
                "watching must not start without the flag"
            );
        }
        let _guard = EnvVarGuard::set(WATCH_ENV, "1");
        assert!(RepoWatchService::maybe_new(fact_store, projection_state, tmp.path().to_path_buf()).is_some());
    }

    // ────────────────────────── Task bookkeeping ──────────────────────────

    /// The task key must be tenant-qualified: two tenants may register the same
    /// repo id, and a collision would have one tenant's `start_repo` silently
    /// abort the other tenant's live watcher.
    #[test]
    fn repo_key_is_tenant_qualified() {
        assert_eq!(repo_key("tenant-a", "api"), "tenant-a::api");
        assert_ne!(repo_key("tenant-a", "api"), repo_key("tenant-b", "api"));
    }

    /// Three ways a registration is not watchable, none of which may spawn a
    /// task: disabled, no `root_path` at all, and a `root_path` that is gone.
    #[tokio::test]
    async fn start_repo_skips_disabled_pathless_and_missing_roots() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path().join("live");
        std::fs::create_dir_all(&root).expect("mkdir");
        let (fact_store, projection_state) = stores();
        let svc = service(fact_store, projection_state, tmp.path().to_path_buf());

        svc.start_repo(registration("t", "disabled", Some(&root), false)).await;
        svc.start_repo(registration("t", "pathless", None, true)).await;
        svc.start_repo(registration("t", "gone", Some(&tmp.path().join("nope")), true))
            .await;

        assert!(
            svc.inner.tasks.lock().await.is_empty(),
            "no unwatchable registration may spawn a task"
        );
    }

    #[tokio::test]
    async fn start_repo_registers_one_task_per_repo_and_stop_removes_it() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path().join("repo");
        polyglot_repo(&root);
        let (fact_store, projection_state) = stores();
        let svc = service(fact_store, projection_state, tmp.path().to_path_buf());

        svc.start_repo(registration("t", "r", Some(&root), true)).await;
        assert_eq!(svc.inner.tasks.lock().await.len(), 1);

        // Restarting the same repo replaces rather than duplicates.
        svc.start_repo(registration("t", "r", Some(&root), true)).await;
        assert_eq!(svc.inner.tasks.lock().await.len(), 1);

        // The same repo id under another tenant is a separate task.
        svc.start_repo(registration("t2", "r", Some(&root), true)).await;
        assert_eq!(svc.inner.tasks.lock().await.len(), 2);

        svc.stop_repo("t", "r").await;
        // Stopping something that was never started is a no-op, not a panic.
        svc.stop_repo("t", "never-started").await;
        let tasks = svc.inner.tasks.lock().await;
        assert_eq!(tasks.len(), 1);
        assert!(tasks.contains_key(&repo_key("t2", "r")));
    }

    /// Dropping a `WatchTask` must abort the spawned future. Without the `Drop`
    /// impl, `stop_repo` would only forget the watcher while it kept scanning
    /// and overwriting the repo's scan fact.
    #[tokio::test]
    async fn dropping_a_watch_task_aborts_the_spawned_future() {
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let task = WatchTask {
            handle: tokio::spawn(async move {
                let _tx = tx;
                std::future::pending::<()>().await;
            }),
        };
        tokio::task::yield_now().await;
        drop(task);
        // Aborting drops the future, which drops the sender the receiver waits on.
        assert!(rx.await.is_err(), "the aborted task must have been dropped");
    }

    #[tokio::test]
    async fn start_existing_repos_starts_only_enabled_repos_with_live_roots() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path().join("repo");
        polyglot_repo(&root);
        let (fact_store, projection_state) = stores();
        {
            let mut store = fact_store.write().await;
            for reg in [
                registration("t", "live", Some(&root), true),
                registration("t", "disabled", Some(&root), false),
                registration("t", "missing-root", Some(&tmp.path().join("nope")), true),
                registration("t", "pathless", None, true),
            ] {
                crate::repo_registry::store_repo(&mut store, &reg).expect("store repo");
            }
        }
        let svc = service(fact_store, projection_state, tmp.path().to_path_buf());

        svc.start_existing_repos().await;

        let tasks = svc.inner.tasks.lock().await;
        assert_eq!(
            tasks.len(),
            1,
            "only the live enabled repo is watched: {:?}",
            tasks.keys()
        );
        assert!(tasks.contains_key(&repo_key("t", "live")));
    }

    #[tokio::test]
    async fn start_existing_repos_on_an_empty_registry_is_a_no_op() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (fact_store, projection_state) = stores();
        let svc = service(fact_store, projection_state, tmp.path().to_path_buf());
        svc.start_existing_repos().await;
        assert!(svc.inner.tasks.lock().await.is_empty());
    }

    // ────────────────────────── Event filtering ──────────────────────────

    /// `filter_event_paths` is the gate between the raw inotify firehose and a
    /// rescan. Regressions it catches: build artefacts under `target/`,
    /// `node_modules/` or a dot-dir triggering a rescan; a non-source file that
    /// exists slipping through; and — the subtle one — a path that no longer
    /// exists being dropped, when a deletion is exactly the event a rescan
    /// needs to see whatever the extension was.
    #[test]
    fn filter_event_paths_keeps_source_edits_and_every_deletion() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path();
        for dir in ["src", "target/debug", "node_modules/pkg", ".git"] {
            std::fs::create_dir_all(root.join(dir)).expect("mkdir");
        }
        for rel in [
            "src/a.rs",
            "src/b.ts",
            "src/c.vue",
            "README.md",
            "target/debug/d.rs",
            "node_modules/pkg/e.ts",
            ".git/f.rs",
        ] {
            std::fs::write(root.join(rel), "x").expect("write");
        }
        let deleted = root.join("src/gone.md"); // never created

        let filtered = filter_event_paths(
            root,
            vec![
                root.join("src/a.rs"),
                root.join("src/a.rs"), // duplicate — must collapse
                root.join("src/b.ts"),
                root.join("src/c.vue"),
                root.join("README.md"),
                root.join("target/debug/d.rs"),
                root.join("node_modules/pkg/e.ts"),
                root.join(".git/f.rs"),
                deleted.clone(),
            ],
        );

        assert_eq!(
            filtered,
            vec![
                root.join("src/a.rs"),
                root.join("src/b.ts"),
                root.join("src/c.vue"),
                deleted,
            ]
        );
        assert!(filter_event_paths(root, Vec::new()).is_empty());
    }

    // ────────────────────────── Snapshot diffing ──────────────────────────

    #[test]
    fn polyglot_snapshot_records_only_source_files_and_skips_build_dirs() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path();
        for dir in ["src", "target", "node_modules", ".hidden"] {
            std::fs::create_dir_all(root.join(dir)).expect("mkdir");
        }
        for rel in ["src/a.rs", "src/b.ts", "src/c.tsx", "src/d.py", "src/e.vue"] {
            std::fs::write(root.join(rel), "abc").expect("write source");
        }
        for rel in [
            "src/notes.md",
            "Makefile",
            "target/gen.rs",
            "node_modules/dep.ts",
            ".hidden/secret.py",
        ] {
            std::fs::write(root.join(rel), "abc").expect("write noise");
        }

        let snapshot = polyglot_snapshot(root);
        assert_eq!(snapshot.len(), 5, "only the five source files: {snapshot:?}");
        assert!(snapshot.contains_key(&root.join("src/a.rs").display().to_string()));
        assert!(!snapshot.contains_key(&root.join("src/notes.md").display().to_string()));
        assert!(snapshot.values().all(|(_, len)| *len == 3), "file length is recorded");

        // A root that does not exist yields an empty snapshot rather than an error.
        assert!(polyglot_snapshot(&root.join("does-not-exist")).is_empty());
    }

    #[test]
    fn count_snapshot_changes_counts_adds_edits_and_deletes() {
        let mut old: BTreeMap<String, (u64, u64)> = BTreeMap::new();
        old.insert("a".into(), (1, 10));
        old.insert("b".into(), (1, 10));
        old.insert("c".into(), (1, 10));

        assert_eq!(count_snapshot_changes(&old, &old), 0);
        assert_eq!(count_snapshot_changes(&BTreeMap::new(), &BTreeMap::new()), 0);

        let mut new = old.clone();
        new.insert("b".into(), (2, 10)); // mtime moved
        new.insert("d".into(), (1, 10)); // added
        new.remove("c"); // deleted
        assert_eq!(count_snapshot_changes(&old, &new), 3);

        // A same-mtime size change still counts — a fast rewrite can land inside
        // one millisecond and must not read as "nothing happened".
        let mut resized = old.clone();
        resized.insert("a".into(), (1, 11));
        assert_eq!(count_snapshot_changes(&old, &resized), 1);
    }

    // ────────────────────────── Scan + store ──────────────────────────

    #[tokio::test]
    async fn a_polyglot_rescan_stores_the_scan_under_the_repo_scan_entity() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path().join("repo");
        polyglot_repo(&root);
        let (fact_store, projection_state) = stores();
        let reg = registration("t", "r", Some(&root), true);
        let mut mode = WatchMode::Polyglot {
            snapshot: BTreeMap::new(),
        };

        run_scan_and_store(&reg, &root, &fact_store, &projection_state, tmp.path(), &mut mode, &[])
            .await
            .expect("first scan");

        let scan = stored_scan(&fact_store, "t", "r").await.expect("scan stored");
        assert!(!scan.scan_id.is_empty());
        assert!(
            scan.files.iter().any(|f| f.rel_path.ends_with("app.ts")),
            "the TypeScript file is in the scan: {:?}",
            scan.files.iter().map(|f| &f.rel_path).collect::<Vec<_>>()
        );

        // The snapshot was adopted, so the mode now sees the tree as current.
        match &mode {
            WatchMode::Polyglot { snapshot } => assert_eq!(snapshot.len(), 1),
            WatchMode::Rust { .. } => panic!("mode must not change kind"),
        }
    }

    /// A poll that finds nothing changed must not write a scan fact. Otherwise
    /// every idle tick rewrites the repo's scan and the fact's version history
    /// stops meaning "the code changed".
    #[tokio::test]
    async fn an_unchanged_polyglot_poll_stores_nothing() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path().join("repo");
        polyglot_repo(&root);
        let (fact_store, projection_state) = stores();
        let reg = registration("t", "r", Some(&root), true);
        let mut mode = WatchMode::Polyglot {
            snapshot: polyglot_snapshot(&root),
        };

        run_scan_and_store(&reg, &root, &fact_store, &projection_state, tmp.path(), &mut mode, &[])
            .await
            .expect("idle poll is not an error");

        assert!(
            stored_scan(&fact_store, "t", "r").await.is_none(),
            "an idle poll must not write a scan fact"
        );
    }

    /// With explicit event paths the snapshot comparison is skipped entirely:
    /// notify already reported movement, and a snapshot check can miss an edit
    /// that keeps both mtime and length.
    #[tokio::test]
    async fn explicit_event_paths_force_a_rescan_even_when_the_snapshot_matches() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path().join("repo");
        polyglot_repo(&root);
        let (fact_store, projection_state) = stores();
        let reg = registration("t", "r", Some(&root), true);
        let mut mode = WatchMode::Polyglot {
            snapshot: polyglot_snapshot(&root),
        };

        run_scan_and_store(
            &reg,
            &root,
            &fact_store,
            &projection_state,
            tmp.path(),
            &mut mode,
            &[root.join("src/app.ts")],
        )
        .await
        .expect("explicit path scan");

        assert!(
            stored_scan(&fact_store, "t", "r").await.is_some(),
            "an explicit event path must always produce a scan"
        );
    }

    /// The Rust (AST-cache) lane must return early when nothing was reparsed
    /// and nothing dropped, then store once the cache actually moves.
    #[tokio::test]
    async fn rust_mode_stores_only_when_the_ast_cache_actually_moves() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path().join("repo");
        cargo_workspace(&root);
        let (fact_store, projection_state) = stores();
        let reg = registration("t", "r", Some(&root), true);
        let mut mode = WatchMode::Rust {
            cache: crate::workspace_scan_ast::AstScanCache::from_root(&root).expect("ast cache"),
        };

        run_scan_and_store(&reg, &root, &fact_store, &projection_state, tmp.path(), &mut mode, &[])
            .await
            .expect("idle rust poll is not an error");
        assert!(
            stored_scan(&fact_store, "t", "r").await.is_none(),
            "an all-cache-hits pass must not write a scan fact"
        );

        std::fs::write(
            root.join("crates/alpha/src/lib.rs"),
            "pub fn alpha() {}\npub fn beta() {}\n",
        )
        .expect("edit lib.rs");
        run_scan_and_store(
            &reg,
            &root,
            &fact_store,
            &projection_state,
            tmp.path(),
            &mut mode,
            &[root.join("crates/alpha/src/lib.rs")],
        )
        .await
        .expect("rust rescan");

        let scan = stored_scan(&fact_store, "t", "r").await.expect("scan stored");
        assert!(
            scan.symbols.iter().any(|s| s.name == "beta"),
            "the edit is reflected in the stored scan"
        );
        assert!(scan.crates.iter().any(|c| c.name == "alpha"));
    }

    /// D-7 (inverted pin): if the watched tree disappears under the Rust lane,
    /// `files_dropped` is non-zero so the "nothing changed" early return does
    /// not fire, and an *empty* scan used to be written over the last good
    /// one — nothing distinguished "the repo was deleted" from "the repo has
    /// no code". A scan that could not run must now leave the stored scan
    /// untouched.
    #[tokio::test]
    async fn a_vanished_rust_root_leaves_the_last_good_scan_intact() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path().join("repo");
        cargo_workspace(&root);
        let (fact_store, projection_state) = stores();
        let reg = registration("t", "r", Some(&root), true);
        let mut mode = WatchMode::Rust {
            cache: crate::workspace_scan_ast::AstScanCache::from_root(&root).expect("ast cache"),
        };

        // Land a good scan first: an edit is what moves the AST cache.
        std::fs::write(
            root.join("crates/alpha/src/lib.rs"),
            "pub fn alpha() {}\npub fn beta() {}\n",
        )
        .expect("edit lib.rs");
        run_scan_and_store(
            &reg,
            &root,
            &fact_store,
            &projection_state,
            tmp.path(),
            &mut mode,
            &[root.join("crates/alpha/src/lib.rs")],
        )
        .await
        .expect("first scan");
        let good = stored_scan(&fact_store, "t", "r").await.expect("scan stored");
        assert!(good.crates.iter().any(|c| c.name == "alpha"));

        std::fs::remove_dir_all(&root).expect("delete the repo out from under the watcher");
        run_scan_and_store(&reg, &root, &fact_store, &projection_state, tmp.path(), &mut mode, &[])
            .await
            .expect("a vanished root is not reported as an error");

        let after = stored_scan(&fact_store, "t", "r").await.expect("scan still stored");
        assert_eq!(
            after.scan_id, good.scan_id,
            "the last good scan survives a vanished root"
        );
        assert!(
            after.crates.iter().any(|c| c.name == "alpha"),
            "it was not replaced by an empty scan"
        );
    }

    // ────────────────────────── Watch loops ──────────────────────────

    /// A root that cannot be watched must surface as an error, not as a loop
    /// parked forever on a channel nothing will ever send to.
    #[tokio::test]
    async fn notify_watch_loop_errors_when_the_root_cannot_be_watched() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let missing = tmp.path().join("not-there");
        let (fact_store, projection_state) = stores();

        let err = notify_watch_loop(
            registration("t", "r", Some(&missing), true),
            missing,
            fact_store,
            projection_state,
            tmp.path().to_path_buf(),
            WatchMode::Polyglot {
                snapshot: BTreeMap::new(),
            },
        )
        .await
        .expect_err("watching a missing root must fail");
        assert!(!err.is_empty(), "the notify error must be reported, not swallowed");
    }

    /// The polling backend must actually scan. The loop sleeps before its first
    /// scan, so a regression that dropped the scan call would be
    /// indistinguishable from a healthy idle watcher.
    #[tokio::test]
    async fn poll_watch_loop_scans_on_its_first_tick() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path().join("repo");
        polyglot_repo(&root);
        let (fact_store, projection_state) = stores();

        let task = tokio::spawn(poll_watch_loop(
            registration("t", "r", Some(&root), true),
            root,
            fact_store.clone(),
            projection_state,
            tmp.path().to_path_buf(),
            WatchMode::Polyglot {
                snapshot: BTreeMap::new(),
            },
        ));
        let scan = await_stored_scan(&fact_store, "t", "r").await;
        task.abort();
        assert!(scan.is_some(), "the polling loop must run a scan");
    }

    /// End-to-end through `watch_repo_task`: with the poll flag set it must
    /// select the Rust lane for a cargo workspace, poll, and land the scan.
    #[tokio::test]
    #[serial_test::serial]
    async fn watch_repo_task_polls_a_cargo_workspace_and_stores_the_scan() {
        let _guard = EnvVarGuard::set(WATCH_POLL_ENV, "1");
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path().join("repo");
        cargo_workspace(&root);
        assert!(
            crate::workspace_scan_polyglot::should_use_rust_workspace_scan(&root),
            "the fixture must take the Rust lane"
        );
        let (fact_store, projection_state) = stores();

        let task = tokio::spawn(watch_repo_task(
            registration("t", "r", Some(&root), true),
            root.clone(),
            fact_store.clone(),
            projection_state,
            tmp.path().to_path_buf(),
        ));
        // Nothing has changed since the cache was built, so force a real edit.
        tokio::time::sleep(Duration::from_millis(200)).await;
        std::fs::write(
            root.join("crates/alpha/src/lib.rs"),
            "pub fn alpha() {}\npub fn gamma() {}\n",
        )
        .expect("edit lib.rs");

        let scan = await_stored_scan(&fact_store, "t", "r").await;
        task.abort();
        let scan = scan.expect("the polling watch task must store a scan");
        assert!(scan.symbols.iter().any(|s| s.name == "gamma"));
    }

    /// Current behaviour, pinned deliberately: `watch_repo_task` does not check
    /// that its root exists. `notify` fails, the task falls back to the polling
    /// loop, and that loop then polls a directory that is not there forever —
    /// no error, no fact, no log after the one fallback warning. `start_repo`
    /// screens missing roots up front, so this only bites a root that vanishes
    /// after the watcher started.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_missing_root_degrades_into_a_silent_forever_poll() {
        let _guard = EnvVarGuard::unset(WATCH_POLL_ENV);
        let tmp = tempfile::tempdir().expect("tempdir");
        let missing = tmp.path().join("not-there");
        let (fact_store, projection_state) = stores();

        let task = tokio::spawn(watch_repo_task(
            registration("t", "r", Some(&missing), true),
            missing,
            fact_store.clone(),
            projection_state,
            tmp.path().to_path_buf(),
        ));
        tokio::time::sleep(Duration::from_millis(1_500)).await;
        let finished = task.is_finished();
        task.abort();

        assert!(!finished, "the fallback poll loop keeps running instead of erroring");
        assert!(
            stored_scan(&fact_store, "t", "r").await.is_none(),
            "and it never stores anything"
        );
    }
}
