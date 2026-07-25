// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Generic periodic-job scheduler for daemon-side integration syncs.
//!
//! ExecPlan `crux-integrations-and-template-library-2026-07-25` (I4, package D0).
//!
//! Before this module every recurring integration job open-coded its own
//! `tokio::time::interval` loop in `main.rs`, with no shared notion of "when did
//! this last run", "did it fail", or "how many times in a row". The GitHub
//! indexer poll was the only such job; the markdown vault watcher is the second.
//! Rather than copy the loop, both register here.
//!
//! ## What the scheduler owns
//!
//! - One driver task for all jobs (sleeps to the earliest deadline, not a
//!   busy 1-second tick).
//! - Per-job bookkeeping: `last_run_unix_ms`, `last_status`,
//!   `consecutive_failures`, and the derived `next_run_unix_ms`.
//! - Failure backoff: the effective interval doubles per consecutive failure,
//!   capped at 4× the configured interval, and resets on the first success.
//! - Persistence of that bookkeeping as ONE fact per job under
//!   `__sync__::<job_id>` key `status`, so the existing `GET /v1/facts` routes
//!   surface scheduler health with no new HTTP surface. `__sync__::` is a
//!   born-private prefix (see `corecrux_memory::fact_privacy`) — node-local
//!   operational state is never push-eligible to a remote.
//!
//! ## What the scheduler does NOT own
//!
//! Job semantics. A job is an async closure returning [`JobResult`]; it decides
//! what "did work" means and what to report. A job that is inert this cycle
//! (integration not connected, feature not configured) returns
//! [`JobOutcome::Skipped`], which writes NO fact and does NOT touch backoff
//! state — an unconfigured daemon stays exactly as quiet as it was before this
//! module existed.
//!
//! ## Status fact schema (`__sync__::<job_id>` / key `status`)
//!
//! ```json
//! {
//!   "schema": "crux.sync_job_status.v1",
//!   "job_id": "github-sync",
//!   "last_run_unix_ms": 1753440000000,
//!   "last_status": "ok",
//!   "last_error": null,
//!   "consecutive_failures": 0,
//!   "interval_secs": 900,
//!   "effective_interval_secs": 900,
//!   "next_run_unix_ms": 1753440900000,
//!   "detail": { "repos": 3, "commits_added": 12 }
//! }
//! ```
//!
//! `last_status` is `"ok"` or `"error"`; `last_error` carries the message on
//! `"error"` and is `null` otherwise. `detail` is job-supplied and may be any
//! JSON value or `null`.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use corecrux_memory::fact_store::StoreFact;
use corecrux_memory::{FactStore, HorizonClass};
use tokio::sync::{broadcast, RwLock};

/// Entity prefix every scheduler-owned bookkeeping fact is written under.
pub const SYNC_ENTITY_PREFIX: &str = "__sync__::";
/// Fact key holding the per-job [`JobStatus`] JSON.
pub const STATUS_KEY: &str = "status";
/// Schema tag stamped on the status value.
pub const STATUS_SCHEMA_V1: &str = "crux.sync_job_status.v1";
/// Backoff ceiling: the effective interval never exceeds 4× the configured one.
pub const MAX_BACKOFF_MULTIPLIER: u32 = 4;

/// What a job reports when it did not fail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JobOutcome {
    /// The job ran. The payload is an optional structured summary persisted as
    /// the status fact's `detail` field.
    Ran(Option<serde_json::Value>),
    /// The job was inert this cycle — not connected, not configured, nothing to
    /// do that is worth a record. No status fact is written and the backoff
    /// state is left untouched. The reason is logged at trace level only.
    Skipped(String),
}

impl JobOutcome {
    /// Convenience for a job that ran and has nothing structured to report.
    /// Both jobs registered today report a summary; kept as part of the public
    /// job contract so a future job need not hand-roll `Ran(None)`.
    #[allow(dead_code)]
    pub fn ran() -> Self {
        JobOutcome::Ran(None)
    }
}

/// `Ok` = the job completed (see [`JobOutcome`]); `Err` = a failure message
/// that drives backoff and lands in the status fact's `last_error`.
pub type JobResult = Result<JobOutcome, String>;

type BoxedFuture = Pin<Box<dyn Future<Output = JobResult> + Send>>;
type JobRunner = Arc<dyn Fn() -> BoxedFuture + Send + Sync>;

/// Terminal state of the most recent non-skipped run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LastStatus {
    Ok,
    Error,
}

impl LastStatus {
    fn as_str(self) -> &'static str {
        match self {
            LastStatus::Ok => "ok",
            LastStatus::Error => "error",
        }
    }
}

/// Per-job bookkeeping. Pure state + transitions, so backoff and the persisted
/// shape are unit-testable without a running task.
#[derive(Debug, Clone)]
pub struct JobStatus {
    pub job_id: String,
    /// The configured cadence. Backoff multiplies this; it is never mutated.
    pub interval: Duration,
    pub last_run_unix_ms: Option<u64>,
    pub last_status: Option<LastStatus>,
    pub last_error: Option<String>,
    pub consecutive_failures: u32,
    /// Structured summary from the most recent successful run.
    pub detail: Option<serde_json::Value>,
}

impl JobStatus {
    pub fn new(job_id: impl Into<String>, interval: Duration) -> Self {
        Self {
            job_id: job_id.into(),
            interval,
            last_run_unix_ms: None,
            last_status: None,
            last_error: None,
            consecutive_failures: 0,
            detail: None,
        }
    }

    /// Interval to wait before the next attempt: the configured interval
    /// doubled once per consecutive failure, capped at [`MAX_BACKOFF_MULTIPLIER`]×.
    /// Zero failures → exactly the configured interval.
    pub fn effective_interval(&self) -> Duration {
        let multiplier = if self.consecutive_failures == 0 {
            1
        } else {
            // 1 failure → 2×, 2 → 4×, 3+ → 4× (capped).
            let shift = self.consecutive_failures.min(u32::BITS - 1);
            1u32.checked_shl(shift).unwrap_or(MAX_BACKOFF_MULTIPLIER)
        };
        self.interval * multiplier.min(MAX_BACKOFF_MULTIPLIER)
    }

    /// Fold a completed run into the status. `Skipped` outcomes never reach
    /// here — the scheduler filters them out before recording.
    pub fn record(&mut self, now_unix_ms: u64, result: &JobResult) {
        self.last_run_unix_ms = Some(now_unix_ms);
        match result {
            Ok(JobOutcome::Ran(detail)) => {
                self.last_status = Some(LastStatus::Ok);
                self.last_error = None;
                self.consecutive_failures = 0;
                self.detail.clone_from(detail);
            }
            Ok(JobOutcome::Skipped(_)) => {}
            Err(message) => {
                self.last_status = Some(LastStatus::Error);
                self.last_error = Some(message.clone());
                self.consecutive_failures = self.consecutive_failures.saturating_add(1);
            }
        }
    }

    /// The `__sync__::<job_id>` entity this status persists under.
    pub fn entity(&self) -> String {
        format!("{SYNC_ENTITY_PREFIX}{}", self.job_id)
    }

    /// Serialize to the persisted status shape (see the module docs).
    pub fn to_value(&self, now_unix_ms: u64) -> serde_json::Value {
        let effective = self.effective_interval();
        serde_json::json!({
            "schema": STATUS_SCHEMA_V1,
            "job_id": self.job_id,
            "last_run_unix_ms": self.last_run_unix_ms,
            "last_status": self.last_status.map(LastStatus::as_str),
            "last_error": self.last_error,
            "consecutive_failures": self.consecutive_failures,
            "interval_secs": self.interval.as_secs(),
            "effective_interval_secs": effective.as_secs(),
            "next_run_unix_ms": now_unix_ms.saturating_add(effective.as_millis() as u64),
            "detail": self.detail,
        })
    }
}

/// Persist one job's status fact. Best-effort: a store failure is logged and
/// never propagated — bookkeeping must not take down the job.
pub async fn persist_status(store: &Arc<RwLock<FactStore>>, status: &JobStatus, now_unix_ms: u64) {
    let req = StoreFact {
        tenant_hash: "default".to_string(),
        entity: status.entity(),
        key: STATUS_KEY.to_string(),
        value: status.to_value(now_unix_ms).to_string(),
        source_receipt: None,
        confidence: 1.0,
        // Born private via the `__sync__::` prefix; set explicitly so the
        // intent survives a privacy-policy override.
        private: true,
        horizon_class: Some(HorizonClass::Volatile),
        actor: Some("sync-scheduler".to_string()),
    };
    let mut guard = store.write().await;
    if let Err(err) = guard.try_store(req) {
        tracing::warn!(?err, job_id = %status.job_id, "sync-scheduler-status-append-failed");
    }
}

struct RegisteredJob {
    status: JobStatus,
    run: JobRunner,
    /// Monotonic deadline for the next attempt.
    next_run: tokio::time::Instant,
}

/// Registry + driver for periodic daemon jobs. Build it, [`register`] jobs,
/// then hand it to [`spawn`].
///
/// [`register`]: SyncScheduler::register
/// [`spawn`]: SyncScheduler::spawn
pub struct SyncScheduler {
    store: Arc<RwLock<FactStore>>,
    jobs: Vec<RegisteredJob>,
}

impl SyncScheduler {
    pub fn new(store: Arc<RwLock<FactStore>>) -> Self {
        Self {
            store,
            jobs: Vec::new(),
        }
    }

    /// Register a periodic job.
    ///
    /// `run` is invoked once per cycle and must be re-callable. The first
    /// attempt happens one full `interval` after [`SyncScheduler::spawn`] — never
    /// at boot, matching the pre-existing GitHub poll ("burn the immediate
    /// tick") so a restart storm cannot stampede an upstream.
    ///
    /// A zero interval is clamped to one second; a job that wants to be off
    /// should simply not be registered.
    pub fn register<F, Fut>(&mut self, job_id: impl Into<String>, interval: Duration, run: F)
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = JobResult> + Send + 'static,
    {
        let interval = if interval.is_zero() {
            Duration::from_secs(1)
        } else {
            interval
        };
        let status = JobStatus::new(job_id, interval);
        self.jobs.push(RegisteredJob {
            status,
            run: Arc::new(move || Box::pin(run()) as BoxedFuture),
            next_run: tokio::time::Instant::now() + interval,
        });
    }

    /// Registry introspection. Used by tests and available to future callers
    /// (e.g. a scheduler panel); the driver checks `self.jobs` directly.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.jobs.is_empty()
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.jobs.len()
    }

    /// Registered job ids, in registration order.
    pub fn job_ids(&self) -> Vec<&str> {
        self.jobs.iter().map(|job| job.status.job_id.as_str()).collect()
    }

    /// Read-only view of a job's bookkeeping (tests + diagnostics).
    #[allow(dead_code)]
    pub fn status(&self, job_id: &str) -> Option<&JobStatus> {
        self.jobs
            .iter()
            .find(|job| job.status.job_id == job_id)
            .map(|job| &job.status)
    }

    /// Run job `index` once: invoke it, fold the result into its status,
    /// persist the status fact (unless skipped), and re-arm its deadline.
    ///
    /// This is the whole per-cycle body — the driver loop calls nothing else,
    /// so tests exercising this exercise the production path.
    pub async fn run_job(&mut self, index: usize) -> Option<JobResult> {
        let (runner, job_id) = {
            let job = self.jobs.get(index)?;
            (job.run.clone(), job.status.job_id.clone())
        };
        let result = runner().await;
        let now_ms = crate::ops_events::now_unix_ms();

        if let Ok(JobOutcome::Skipped(reason)) = &result {
            tracing::trace!(job_id = %job_id, reason = %reason, "sync-job-skipped");
            // Re-arm on the configured interval; a skip is not a failure.
            let interval = self.jobs[index].status.effective_interval();
            self.jobs[index].next_run = tokio::time::Instant::now() + interval;
            return Some(result);
        }

        let job = &mut self.jobs[index];
        job.status.record(now_ms, &result);
        match &result {
            Ok(_) => tracing::debug!(job_id = %job_id, "sync-job-ok"),
            Err(message) => tracing::warn!(
                job_id = %job_id,
                consecutive_failures = job.status.consecutive_failures,
                error = %message,
                "sync-job-failed"
            ),
        }
        let interval = job.status.effective_interval();
        job.next_run = tokio::time::Instant::now() + interval;
        let status = job.status.clone();
        persist_status(&self.store, &status, now_ms).await;
        Some(result)
    }

    /// Spawn the single driver task. Returns immediately; a scheduler with no
    /// registered jobs spawns nothing.
    pub fn spawn(mut self, mut shutdown: broadcast::Receiver<()>) {
        if self.jobs.is_empty() {
            return;
        }
        tracing::info!(jobs = self.jobs.len(), ids = ?self.job_ids(), "sync-scheduler-started");
        tokio::spawn(async move {
            loop {
                // Earliest deadline across all jobs; jobs are few (2 today) so a
                // linear scan is cheaper than a heap and keeps ordering obvious.
                let Some((index, deadline)) = self
                    .jobs
                    .iter()
                    .enumerate()
                    .map(|(index, job)| (index, job.next_run))
                    .min_by_key(|(_, deadline)| *deadline)
                else {
                    break;
                };
                tokio::select! {
                    _ = shutdown.recv() => break,
                    () = tokio::time::sleep_until(deadline) => {
                        self.run_job(index).await;
                    }
                }
            }
            tracing::info!("sync-scheduler-stopped");
        });
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use corecrux_memory::fact_store::FactQuery;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn store() -> Arc<RwLock<FactStore>> {
        Arc::new(RwLock::new(FactStore::new()))
    }

    async fn status_fact(store: &Arc<RwLock<FactStore>>, job_id: &str) -> Option<serde_json::Value> {
        let guard = store.read().await;
        let result = guard.query(&FactQuery {
            entity: Some(format!("{SYNC_ENTITY_PREFIX}{job_id}")),
            top_k: 10,
            ..Default::default()
        });
        result
            .facts
            .iter()
            .find(|fact| fact.key == STATUS_KEY)
            .and_then(|fact| serde_json::from_str(&fact.value).ok())
    }

    #[test]
    fn backoff_doubles_then_caps_at_four_x() {
        let mut status = JobStatus::new("job", Duration::from_secs(100));
        assert_eq!(status.effective_interval(), Duration::from_secs(100));

        status.record(1, &Err("boom".to_string()));
        assert_eq!(status.consecutive_failures, 1);
        assert_eq!(status.effective_interval(), Duration::from_secs(200));

        status.record(2, &Err("boom".to_string()));
        assert_eq!(status.effective_interval(), Duration::from_secs(400));

        // Capped at 4×, not 8×.
        status.record(3, &Err("boom".to_string()));
        status.record(4, &Err("boom".to_string()));
        assert_eq!(status.consecutive_failures, 4);
        assert_eq!(status.effective_interval(), Duration::from_secs(400));
    }

    #[test]
    fn success_resets_backoff_and_clears_error() {
        let mut status = JobStatus::new("job", Duration::from_secs(60));
        status.record(1, &Err("boom".to_string()));
        status.record(2, &Err("boom".to_string()));
        assert_eq!(status.last_status, Some(LastStatus::Error));

        status.record(3, &Ok(JobOutcome::Ran(Some(serde_json::json!({ "n": 1 })))));
        assert_eq!(status.consecutive_failures, 0);
        assert_eq!(status.last_status, Some(LastStatus::Ok));
        assert!(status.last_error.is_none());
        assert_eq!(status.effective_interval(), Duration::from_secs(60));
        assert_eq!(status.detail, Some(serde_json::json!({ "n": 1 })));
    }

    #[test]
    fn status_value_shape_is_stable() {
        let mut status = JobStatus::new("github-sync", Duration::from_secs(900));
        status.record(1_000, &Ok(JobOutcome::Ran(Some(serde_json::json!({ "repos": 2 })))));
        let value = status.to_value(1_000);

        assert_eq!(value["schema"], STATUS_SCHEMA_V1);
        assert_eq!(value["job_id"], "github-sync");
        assert_eq!(value["last_run_unix_ms"], 1_000);
        assert_eq!(value["last_status"], "ok");
        assert!(value["last_error"].is_null());
        assert_eq!(value["consecutive_failures"], 0);
        assert_eq!(value["interval_secs"], 900);
        assert_eq!(value["effective_interval_secs"], 900);
        assert_eq!(value["next_run_unix_ms"], 1_000 + 900_000);
        assert_eq!(value["detail"], serde_json::json!({ "repos": 2 }));

        status.record(2_000, &Err("upstream 500".to_string()));
        let value = status.to_value(2_000);
        assert_eq!(value["last_status"], "error");
        assert_eq!(value["last_error"], "upstream 500");
        assert_eq!(value["consecutive_failures"], 1);
        assert_eq!(value["effective_interval_secs"], 1_800);
        assert_eq!(value["next_run_unix_ms"], 2_000 + 1_800_000);
    }

    #[tokio::test]
    async fn run_job_invokes_runner_and_persists_status() {
        let store = store();
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = calls.clone();
        let mut scheduler = SyncScheduler::new(store.clone());
        scheduler.register("unit-job", Duration::from_secs(300), move || {
            let seen = seen.clone();
            async move {
                seen.fetch_add(1, Ordering::SeqCst);
                Ok(JobOutcome::Ran(Some(serde_json::json!({ "items": 3 }))))
            }
        });
        assert_eq!(scheduler.len(), 1);
        assert_eq!(scheduler.job_ids(), vec!["unit-job"]);

        let result = scheduler.run_job(0).await.expect("job exists");
        assert!(result.is_ok());
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let fact = status_fact(&store, "unit-job").await.expect("status fact written");
        assert_eq!(fact["last_status"], "ok");
        assert_eq!(fact["detail"], serde_json::json!({ "items": 3 }));
        assert_eq!(fact["interval_secs"], 300);
        assert!(fact["last_run_unix_ms"].as_u64().unwrap_or(0) > 0);
    }

    #[tokio::test]
    async fn failing_job_records_error_and_backs_off() {
        let store = store();
        let mut scheduler = SyncScheduler::new(store.clone());
        scheduler.register("flaky", Duration::from_secs(100), || async {
            Err("network unreachable".to_string())
        });

        let _ = scheduler.run_job(0).await;
        let _ = scheduler.run_job(0).await;

        let status = scheduler.status("flaky").expect("registered");
        assert_eq!(status.consecutive_failures, 2);
        assert_eq!(status.effective_interval(), Duration::from_secs(400));

        let fact = status_fact(&store, "flaky").await.expect("status fact written");
        assert_eq!(fact["last_status"], "error");
        assert_eq!(fact["last_error"], "network unreachable");
        assert_eq!(fact["consecutive_failures"], 2);
    }

    #[tokio::test]
    async fn skipped_job_writes_no_fact_and_leaves_backoff_untouched() {
        let store = store();
        let mut scheduler = SyncScheduler::new(store.clone());
        scheduler.register("inert", Duration::from_secs(100), || async {
            Ok(JobOutcome::Skipped("not connected".to_string()))
        });

        let _ = scheduler.run_job(0).await;

        assert!(status_fact(&store, "inert").await.is_none());
        let status = scheduler.status("inert").expect("registered");
        assert!(status.last_run_unix_ms.is_none());
        assert_eq!(status.consecutive_failures, 0);
    }

    /// Wall-clock driver test (the `tokio` dep here has no `test-util`
    /// feature, so paused time is unavailable). Intervals are milliseconds and
    /// the assertions are one-sided — "at least"/"not yet" — so the test cannot
    /// flake on a slow runner.
    #[tokio::test]
    async fn driver_runs_each_job_on_its_own_cadence() {
        let store = store();
        let fast = Arc::new(AtomicUsize::new(0));
        let slow = Arc::new(AtomicUsize::new(0));
        let mut scheduler = SyncScheduler::new(store.clone());
        {
            let fast = fast.clone();
            scheduler.register("fast", Duration::from_millis(20), move || {
                let fast = fast.clone();
                async move {
                    fast.fetch_add(1, Ordering::SeqCst);
                    Ok(JobOutcome::ran())
                }
            });
        }
        {
            let slow = slow.clone();
            scheduler.register("slow", Duration::from_secs(3_600), move || {
                let slow = slow.clone();
                async move {
                    slow.fetch_add(1, Ordering::SeqCst);
                    Ok(JobOutcome::ran())
                }
            });
        }

        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
        scheduler.spawn(shutdown_rx);

        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(fast.load(Ordering::SeqCst) >= 2, "fast job should have run repeatedly");
        // The hourly job's first deadline is one full interval out: nothing at boot.
        assert_eq!(slow.load(Ordering::SeqCst), 0, "no job fires at boot");

        assert!(status_fact(&store, "fast").await.is_some());
        assert!(status_fact(&store, "slow").await.is_none());

        let _ = shutdown_tx.send(());
        let observed = fast.load(Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            fast.load(Ordering::SeqCst) <= observed + 1,
            "shutdown should stop the driver"
        );
    }

    #[tokio::test]
    async fn empty_scheduler_spawns_nothing() {
        let scheduler = SyncScheduler::new(store());
        assert!(scheduler.is_empty());
        let (_tx, rx) = broadcast::channel(1);
        scheduler.spawn(rx);
    }
}
