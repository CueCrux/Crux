// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Cached git-update-posture probe — checks ahead/behind/diverged status, feeds `/v1/version` and the wizard hook.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::Utc;
use tokio::process::Command;
use tokio::sync::{broadcast, RwLock};
use tracing::warn;

use corecrux_types::{UpdateCheckState, UpdateStatus};

use crate::config::Config;

const GIT_TIMEOUT: Duration = Duration::from_secs(3);

pub fn initial_status(config: &Config) -> UpdateStatus {
    let tracking_ref = tracking_ref(config);
    if !config.update_check_enabled {
        return UpdateStatus {
            enabled: false,
            state: UpdateCheckState::Disabled,
            remote: config.update_check_remote.clone(),
            ref_name: config.update_check_ref.clone(),
            tracking_ref,
            repo_dir: config
                .update_check_repo_dir
                .as_ref()
                .map(|path| path.display().to_string()),
            current_commit: None,
            latest_commit: None,
            ahead_by: 0,
            behind_by: 0,
            checked_at: None,
            error: None,
            comparison_stale: false,
            basis: "checkout".to_string(),
            binary_commit: None,
            checkout_commit: None,
            checkout_ahead_by: 0,
            checkout_behind_by: 0,
            upgrade_hint: "Update checks are disabled. Set CORECRUXD_UPDATE_CHECK_ENABLED=1 to compare this checkout against the tracked branch.".to_string(),
        };
    }

    UpdateStatus {
        enabled: true,
        state: UpdateCheckState::Unavailable,
        remote: config.update_check_remote.clone(),
        ref_name: config.update_check_ref.clone(),
        tracking_ref,
        repo_dir: config
            .update_check_repo_dir
            .as_ref()
            .map(|path| path.display().to_string()),
        current_commit: None,
        latest_commit: None,
        ahead_by: 0,
        behind_by: 0,
        checked_at: None,
        error: Some("update check pending".to_string()),
        comparison_stale: false,
        basis: "checkout".to_string(),
        binary_commit: None,
        checkout_commit: None,
        checkout_ahead_by: 0,
        checkout_behind_by: 0,
        upgrade_hint: "Update check is starting. If this node runs from a git checkout, the current tracked-branch status will appear shortly.".to_string(),
    }
}

pub fn spawn_update_checker(
    config: Config,
    status: std::sync::Arc<RwLock<UpdateStatus>>,
    mut shutdown: broadcast::Receiver<()>,
) {
    if !config.update_check_enabled {
        return;
    }

    tokio::spawn(async move {
        write_status(&status, refresh_status(&config).await).await;

        let mut interval = tokio::time::interval(Duration::from_secs(config.update_check_interval_secs));
        interval.tick().await;

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    write_status(&status, refresh_status(&config).await).await;
                }
                _ = shutdown.recv() => break,
            }
        }
    });
}

async fn write_status(status: &std::sync::Arc<RwLock<UpdateStatus>>, next: UpdateStatus) {
    *status.write().await = next;
}

pub async fn refresh_status(config: &Config) -> UpdateStatus {
    refresh_status_with_binary_sha(config, binary_sha_from_env()).await
}

/// The running binary's embedded commit (`CORECRUX_GIT_SHA`, the same source
/// `/v1/version`'s `commit` uses). `"unknown"`/empty are treated as absent so a
/// container build without a resolvable sha falls back to checkout basis.
fn binary_sha_from_env() -> Option<String> {
    option_env!("CORECRUX_GIT_SHA")
        .map(str::trim)
        .filter(|sha| !sha.is_empty() && *sha != "unknown")
        .map(str::to_string)
}

/// Core of [`refresh_status`], parameterised on the binary sha so tests can pin
/// a known commit rather than the compile-time-baked `CORECRUX_GIT_SHA`.
///
/// Basis selection: when the binary's embedded commit resolves in the checkout,
/// the primary `state/ahead_by/behind_by/current_commit` describe the *running
/// binary* vs the tracking ref (basis = "binary"). Otherwise they describe the
/// checkout HEAD (basis = "checkout") — the legacy behaviour. Either way the
/// `checkout_*` fields carry the HEAD-vs-tracking-ref comparison so a stale
/// source clone is always visible.
async fn refresh_status_with_binary_sha(config: &Config, binary_sha: Option<String>) -> UpdateStatus {
    let tracking_ref = tracking_ref(config);
    let checked_at = Some(Utc::now().to_rfc3339());

    if !config.update_check_enabled {
        let mut status = initial_status(config);
        status.checked_at = checked_at;
        return status;
    }

    if config.update_check_remote.trim().is_empty() || config.update_check_ref.trim().is_empty() {
        return unavailable_status(
            config,
            None,
            None,
            checked_at,
            "CORECRUXD_UPDATE_CHECK_REMOTE and CORECRUXD_UPDATE_CHECK_REF must be non-empty".to_string(),
        );
    }

    let repo_dir = match discover_repo_dir(config).await {
        Ok(repo_dir) => repo_dir,
        Err(err) => return unavailable_status(config, None, None, checked_at, err),
    };
    let repo_dir_display = Some(repo_dir.display().to_string());

    // The source checkout's HEAD — the legacy "current" and the checkout-basis
    // fallback. The primary `current_commit` now follows the chosen basis (the
    // binary sha when it resolves), so it gets its own name here.
    let checkout_commit = match run_git(&repo_dir, &["rev-parse", "--short", "HEAD"]).await {
        Ok(commit) => Some(commit),
        Err(err) => return error_status(config, repo_dir_display, None, checked_at, err),
    };

    let mut fetch_warning = None;
    if let Err(err) = run_git(
        &repo_dir,
        &[
            "fetch",
            "--quiet",
            config.update_check_remote.as_str(),
            config.update_check_ref.as_str(),
        ],
    )
    .await
    {
        fetch_warning = Some(format!(
            "git fetch {} failed: {err}; using the locally cached tracking ref if available",
            tracking_ref
        ));
    }

    let latest_commit = match run_git(&repo_dir, &["rev-parse", "--short", tracking_ref.as_str()]).await {
        Ok(commit) => Some(commit),
        Err(err) => {
            let message = if let Some(fetch_warning) = fetch_warning {
                format!("{fetch_warning}; tracking ref {tracking_ref} is unavailable locally: {err}")
            } else {
                format!("tracking ref {tracking_ref} is unavailable locally: {err}")
            };
            return unavailable_status(config, repo_dir_display, checkout_commit, checked_at, message);
        }
    };

    // Always compute the checkout (HEAD vs tracking ref) comparison — operators
    // still want to see a stale source clone even when the binary is the basis.
    let (checkout_ahead_by, checkout_behind_by) = match left_right_counts(&repo_dir, "HEAD", &tracking_ref).await {
        Ok(counts) => counts,
        Err(err) => {
            let message = match fetch_warning {
                Some(fetch_warning) => format!("{fetch_warning}; {err}"),
                None => err,
            };
            return error_status(config, repo_dir_display, checkout_commit, checked_at, message);
        }
    };

    // Prefer the running binary's embedded commit when it resolves in this
    // checkout, so the primary count reflects what is actually running rather
    // than the source tree's HEAD (prod: a bind-mounted clone can be far staler
    // than the binary built from it). `binary_note` records the fallback reason
    // when a sha existed but could not be used; it is surfaced via the hint.
    let mut binary_note = None;
    let (basis, current_commit, ahead_by, behind_by, binary_commit) = match binary_sha.as_deref() {
        Some(sha) => match run_git(
            &repo_dir,
            &[
                "rev-parse",
                "--short",
                "--verify",
                "--quiet",
                &format!("{sha}^{{commit}}"),
            ],
        )
        .await
        {
            Ok(short_sha) => match left_right_counts(&repo_dir, &short_sha, &tracking_ref).await {
                Ok((ahead, behind)) => (
                    "binary".to_string(),
                    Some(short_sha.clone()),
                    ahead,
                    behind,
                    Some(short_sha),
                ),
                Err(_) => {
                    // Keep the sha and git error (which can embed paths) out of
                    // the hint — /v1/version serves it unauthenticated. The
                    // structured admin-only `binary_commit` carries the sha.
                    binary_note = Some(format!(
                        "binary-commit comparison against {tracking_ref} failed; reporting source-checkout drift instead."
                    ));
                    (
                        "checkout".to_string(),
                        checkout_commit.clone(),
                        checkout_ahead_by,
                        checkout_behind_by,
                        Some(short_sha),
                    )
                }
            },
            Err(_) => {
                // No sha in the text (public hint); `binary_commit` carries it.
                binary_note = Some(
                    "the running binary's commit does not resolve in the source checkout; reporting source-checkout drift instead."
                        .to_string(),
                );
                (
                    "checkout".to_string(),
                    checkout_commit.clone(),
                    checkout_ahead_by,
                    checkout_behind_by,
                    Some(sha.to_string()),
                )
            }
        },
        None => (
            "checkout".to_string(),
            checkout_commit.clone(),
            checkout_ahead_by,
            checkout_behind_by,
            None,
        ),
    };

    let state = derive_state(ahead_by, behind_by);
    // Fetch failed → the counts came from a stale cached tracking ref. Flag it
    // so the banner / /v1/version present "drift unverified" rather than a
    // confident (and possibly wrong) number. Independent of `binary_note`.
    let comparison_stale = fetch_warning.is_some();

    // On binary basis, if the source checkout is at a different distance than
    // the binary, tell the operator to refresh the src clone on deploy (the
    // prod scenario: binary 90 behind, src clone 663 behind).
    // No repo path in the text — /v1/version serves the hint unauthenticated
    // and the path stays admin-only (`repo_dir` on /v1/admin/version).
    let checkout_note = (basis == "binary" && (checkout_behind_by != behind_by || checkout_ahead_by != ahead_by))
        .then(|| format!("note: the source checkout is {checkout_behind_by} behind — refresh it on deploy."));

    // Both notes are operator-facing → append to the hint. The error channel is
    // reserved for the fetch-staleness warning (drives `comparison_stale`).
    let mut notes: Vec<String> = Vec::new();
    notes.extend(checkout_note);
    notes.extend(binary_note);
    let extra_note = (!notes.is_empty()).then(|| notes.join(" "));
    let hint = upgrade_hint(state, &basis, comparison_stale, extra_note.as_deref());

    UpdateStatus {
        enabled: true,
        state,
        remote: config.update_check_remote.clone(),
        ref_name: config.update_check_ref.clone(),
        tracking_ref,
        repo_dir: repo_dir_display,
        current_commit,
        latest_commit,
        ahead_by,
        behind_by,
        checked_at,
        error: fetch_warning,
        comparison_stale,
        basis,
        binary_commit,
        checkout_commit,
        checkout_ahead_by,
        checkout_behind_by,
        upgrade_hint: hint,
    }
}

/// Run `git rev-list --left-right --count <left>...<right>` in `repo_dir` and
/// parse it into `(ahead, behind)`. Shared by the checkout and binary bases.
async fn left_right_counts(repo_dir: &Path, left: &str, right: &str) -> Result<(u64, u64), String> {
    let raw = run_git(
        repo_dir,
        &["rev-list", "--left-right", "--count", &format!("{left}...{right}")],
    )
    .await?;
    parse_left_right_counts(&raw)
}

fn tracking_ref(config: &Config) -> String {
    format!(
        "{}/{}",
        config.update_check_remote.trim(),
        config.update_check_ref.trim()
    )
}

fn unavailable_status(
    config: &Config,
    repo_dir: Option<String>,
    current_commit: Option<String>,
    checked_at: Option<String>,
    error: String,
) -> UpdateStatus {
    UpdateStatus {
        enabled: true,
        state: UpdateCheckState::Unavailable,
        remote: config.update_check_remote.clone(),
        ref_name: config.update_check_ref.clone(),
        tracking_ref: tracking_ref(config),
        repo_dir,
        current_commit: current_commit.clone(),
        latest_commit: None,
        ahead_by: 0,
        behind_by: 0,
        checked_at,
        error: Some(error),
        comparison_stale: false,
        basis: "checkout".to_string(),
        binary_commit: None,
        checkout_commit: current_commit,
        checkout_ahead_by: 0,
        checkout_behind_by: 0,
        upgrade_hint: "Update checks require a readable git checkout and a tracked branch. Continue serving traffic locally and configure CORECRUXD_UPDATE_CHECK_REPO_DIR if the service starts outside the repo.".to_string(),
    }
}

fn error_status(
    config: &Config,
    repo_dir: Option<String>,
    current_commit: Option<String>,
    checked_at: Option<String>,
    error: String,
) -> UpdateStatus {
    UpdateStatus {
        enabled: true,
        state: UpdateCheckState::Error,
        remote: config.update_check_remote.clone(),
        ref_name: config.update_check_ref.clone(),
        tracking_ref: tracking_ref(config),
        repo_dir,
        current_commit: current_commit.clone(),
        latest_commit: None,
        ahead_by: 0,
        behind_by: 0,
        checked_at,
        error: Some(error),
        comparison_stale: false,
        basis: "checkout".to_string(),
        binary_commit: None,
        checkout_commit: current_commit,
        checkout_ahead_by: 0,
        checkout_behind_by: 0,
        upgrade_hint: "Update comparison failed. Keep the node running locally, inspect git connectivity, and use the upgrade playbooks before attempting maintenance.".to_string(),
    }
}

fn derive_state(ahead_by: u64, behind_by: u64) -> UpdateCheckState {
    match (ahead_by, behind_by) {
        (0, 0) => UpdateCheckState::Current,
        (0, _) => UpdateCheckState::Behind,
        (_, 0) => UpdateCheckState::Ahead,
        _ => UpdateCheckState::Diverged,
    }
}

fn upgrade_hint(
    state: UpdateCheckState,
    basis: &str,
    using_cached_tracking_ref: bool,
    extra_note: Option<&str>,
) -> String {
    let suffix = if using_cached_tracking_ref {
        " The comparison used the last locally cached tracking ref because fetch failed."
    } else {
        ""
    };
    let base = match state {
        UpdateCheckState::Disabled => {
            "Update checks are disabled. Enable them before asking an agent to decide whether an upgrade is needed."
                .to_string()
        }
        UpdateCheckState::Current => format!(
            "This checkout matches the tracked branch. No upgrade is needed right now.{suffix}"
        ),
        UpdateCheckState::Behind => {
            if basis == "binary" {
                format!(
                    "A newer tracked commit is available than the running binary. Take a filesystem snapshot of CORECRUXD_DATA_DIR or export receipts first, then rebuild/redeploy.{suffix}"
                )
            } else {
                format!(
                    "A newer tracked commit is available. Take a filesystem snapshot of CORECRUXD_DATA_DIR or export receipts first, then pull, rebuild, and restart.{suffix}"
                )
            }
        }
        UpdateCheckState::Ahead => format!(
            "This checkout is ahead of the tracked branch. Avoid automated downgrades; review local commits before changing versions.{suffix}"
        ),
        UpdateCheckState::Diverged => format!(
            "This checkout has local commits and is also behind the tracked branch. Merge or rebase intentionally instead of blind-pulling.{suffix}"
        ),
        UpdateCheckState::Unavailable => {
            "Update status is unavailable because the service cannot resolve a usable git checkout or tracking ref."
                .to_string()
        }
        UpdateCheckState::Error => {
            "Update status could not be refreshed because git comparison failed. Keep the node online locally and investigate before attempting an upgrade."
                .to_string()
        }
    };
    match extra_note {
        Some(note) if !note.is_empty() => format!("{base} {note}"),
        _ => base,
    }
}

fn parse_left_right_counts(raw: &str) -> Result<(u64, u64), String> {
    let mut parts = raw.split_whitespace();
    let ahead_by = parts
        .next()
        .ok_or_else(|| format!("invalid git rev-list output: {raw}"))?
        .parse::<u64>()
        .map_err(|err| format!("invalid ahead count in git rev-list output '{raw}': {err}"))?;
    let behind_by = parts
        .next()
        .ok_or_else(|| format!("invalid git rev-list output: {raw}"))?
        .parse::<u64>()
        .map_err(|err| format!("invalid behind count in git rev-list output '{raw}': {err}"))?;
    if parts.next().is_some() {
        return Err(format!("invalid git rev-list output: {raw}"));
    }
    Ok((ahead_by, behind_by))
}

async fn discover_repo_dir(config: &Config) -> Result<PathBuf, String> {
    for candidate in repo_dir_candidates(config) {
        if !candidate.exists() {
            continue;
        }
        match run_git(&candidate, &["rev-parse", "--show-toplevel"]).await {
            Ok(repo_root) => return Ok(PathBuf::from(repo_root)),
            Err(err) => {
                if config
                    .update_check_repo_dir
                    .as_ref()
                    .is_some_and(|configured| configured == &candidate)
                {
                    warn!(path = %candidate.display(), error = %err, "configured update-check repo dir is not a git checkout");
                }
            }
        }
    }

    Err(
        "no git checkout detected for update checks; set CORECRUXD_UPDATE_CHECK_REPO_DIR if the daemon starts outside the repo"
            .to_string(),
    )
}

fn repo_dir_candidates(config: &Config) -> Vec<PathBuf> {
    let mut seen = BTreeSet::new();
    let mut candidates = Vec::new();

    let mut push_candidate = |path: PathBuf| {
        let key = path.display().to_string();
        if seen.insert(key) {
            candidates.push(path);
        }
    };

    if let Some(repo_dir) = config.update_check_repo_dir.clone() {
        push_candidate(repo_dir);
    }
    if let Ok(current_dir) = std::env::current_dir() {
        push_candidate(current_dir);
    }
    if let Ok(current_exe) = std::env::current_exe() {
        for ancestor in current_exe.ancestors() {
            push_candidate(ancestor.to_path_buf());
        }
    }

    candidates
}

async fn run_git(repo_dir: &Path, args: &[&str]) -> Result<String, String> {
    let mut command = Command::new("git");
    // Harden every invocation against ownership/bareness refusals.
    //
    // Production case: /repo is a host-owned bind mount but the daemon runs as a
    // different in-container uid, so modern git refuses with "detected dubious
    // ownership in repository" unless safe.directory covers the path. We scope
    // safe.directory to the exact repo_dir so we never globally trust arbitrary
    // checkouts. safe.bareRepository=all additionally lets `git -C <bare>` work
    // under a host/CI global of safe.bareRepository=explicit (the same refusal
    // that otherwise breaks the test harness's bare seed repos).
    command.arg("-c").arg(format!("safe.directory={}", repo_dir.display()));
    command.arg("-c").arg("safe.bareRepository=all");
    command.arg("-C").arg(repo_dir);
    command.args(args);
    command.kill_on_drop(true);

    let output = tokio::time::timeout(GIT_TIMEOUT, command.output())
        .await
        .map_err(|_| format!("git {} timed out after {}s", args.join(" "), GIT_TIMEOUT.as_secs()))?
        .map_err(|err| match err.kind() {
            std::io::ErrorKind::NotFound => "git executable not found in PATH".to_string(),
            _ => format!("failed to start git {}: {err}", args.join(" ")),
        })?;

    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).trim().to_string());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let detail = if !stderr.is_empty() { stderr } else { stdout };
    Err(format!("git {} failed: {}", args.join(" "), detail))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;
    use std::process::Command as StdCommand;

    struct GitFixture {
        _tmp: tempfile::TempDir,
        seed: PathBuf,
        local: PathBuf,
    }

    fn test_config(repo_dir: Option<PathBuf>) -> Config {
        let mut config = crate::config::load_config();
        config.update_check_enabled = true;
        config.update_check_remote = "origin".to_string();
        config.update_check_ref = "main".to_string();
        config.update_check_interval_secs = 60;
        config.update_check_repo_dir = repo_dir;
        config
    }

    fn git(dir: &Path, args: &[&str]) -> String {
        // Mirror run_git's ownership/bareness hardening so the fixtures behave
        // the same under a sandbox global of safe.bareRepository=explicit.
        let output = StdCommand::new("git")
            .arg("-c")
            .arg(format!("safe.directory={}", dir.display()))
            .arg("-c")
            .arg("safe.bareRepository=all")
            .arg("-C")
            .arg(dir)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    }

    fn configure_git_user(repo: &Path) {
        git(repo, &["config", "user.name", "Crux Update Tests"]);
        git(repo, &["config", "user.email", "crux-update-tests@example.com"]);
    }

    fn write_commit(repo: &Path, file_name: &str, content: &str, message: &str) {
        fs::write(repo.join(file_name), content).unwrap();
        git(repo, &["add", "."]);
        git(repo, &["commit", "-m", message]);
    }

    fn setup_tracked_repo() -> GitFixture {
        let tmp = tempfile::tempdir().unwrap();
        let remote = tmp.path().join("remote.git");
        let seed = tmp.path().join("seed");
        let local = tmp.path().join("local");
        let remote_str = remote.display().to_string();
        let seed_str = seed.display().to_string();
        let local_str = local.display().to_string();

        git(tmp.path(), &["init", "--bare", remote_str.as_str()]);
        git(tmp.path(), &["clone", remote_str.as_str(), seed_str.as_str()]);
        configure_git_user(&seed);
        write_commit(&seed, "README.md", "seed\n", "initial");
        git(&seed, &["branch", "-M", "main"]);
        git(&seed, &["push", "-u", "origin", "main"]);
        git(&remote, &["symbolic-ref", "HEAD", "refs/heads/main"]);
        git(tmp.path(), &["clone", remote_str.as_str(), local_str.as_str()]);
        configure_git_user(&local);

        GitFixture { _tmp: tmp, seed, local }
    }

    #[test]
    fn derive_state_distinguishes_direction() {
        assert_eq!(derive_state(0, 0), UpdateCheckState::Current);
        assert_eq!(derive_state(0, 2), UpdateCheckState::Behind);
        assert_eq!(derive_state(3, 0), UpdateCheckState::Ahead);
        assert_eq!(derive_state(1, 4), UpdateCheckState::Diverged);
    }

    #[test]
    fn parse_left_right_counts_accepts_git_output() {
        assert_eq!(parse_left_right_counts("0\t3").unwrap(), (0, 3));
        assert_eq!(parse_left_right_counts("2 0").unwrap(), (2, 0));
    }

    #[test]
    fn parse_left_right_counts_rejects_invalid_output() {
        assert!(parse_left_right_counts("2").is_err());
        assert!(parse_left_right_counts("a b").is_err());
        assert!(parse_left_right_counts("1 2 3").is_err());
    }

    #[test]
    fn initial_status_public_view_redacts_sensitive_fields() {
        let status = UpdateStatus {
            enabled: true,
            state: UpdateCheckState::Error,
            remote: "origin".to_string(),
            ref_name: "main".to_string(),
            tracking_ref: "origin/main".to_string(),
            repo_dir: Some("/srv/crux".to_string()),
            current_commit: Some("abc123".to_string()),
            latest_commit: None,
            ahead_by: 0,
            behind_by: 0,
            checked_at: Some("2026-04-10T00:00:00Z".to_string()),
            error: Some("git fetch failed".to_string()),
            comparison_stale: true,
            basis: "checkout".to_string(),
            binary_commit: None,
            checkout_commit: Some("abc123".to_string()),
            checkout_ahead_by: 0,
            checkout_behind_by: 0,
            upgrade_hint: "investigate".to_string(),
        };

        let public = status.public_view();
        assert_eq!(public.state, UpdateCheckState::Error);
        assert_eq!(public.current_commit.as_deref(), Some("abc123"));
        assert!(public.repo_dir.is_none());
        assert!(public.error.is_none());
        // comparison_stale survives redaction so the public banner can still
        // flag "drift unverified" even with error stripped.
        assert!(public.comparison_stale);
    }

    #[tokio::test]
    async fn refresh_status_disabled_keeps_disabled_state() {
        let mut config = test_config(None);
        config.update_check_enabled = false;

        let status = refresh_status(&config).await;

        assert_eq!(status.state, UpdateCheckState::Disabled);
        assert!(!status.enabled);
        assert!(status.checked_at.is_some());
    }

    #[tokio::test]
    async fn refresh_status_requires_non_empty_tracking_config() {
        let mut config = test_config(None);
        config.update_check_remote = " ".to_string();

        let status = refresh_status(&config).await;

        assert_eq!(status.state, UpdateCheckState::Unavailable);
        assert!(status.error.unwrap().contains("must be non-empty"));
    }

    #[tokio::test]
    async fn refresh_status_reports_unavailable_when_tracking_ref_is_missing() {
        let fixture = setup_tracked_repo();
        let mut config = test_config(Some(fixture.local.clone()));
        config.update_check_ref = "missing-branch".to_string();

        let status = refresh_status(&config).await;

        assert_eq!(status.state, UpdateCheckState::Unavailable);
        assert!(status.error.unwrap().contains("tracking ref"));
    }

    #[tokio::test]
    async fn refresh_status_reports_current_for_synced_repo() {
        let fixture = setup_tracked_repo();
        let config = test_config(Some(fixture.local.clone()));

        let status = refresh_status(&config).await;

        assert_eq!(status.state, UpdateCheckState::Current);
        assert_eq!(status.ahead_by, 0);
        assert_eq!(status.behind_by, 0);
        assert!(status.error.is_none());
        assert_eq!(status.current_commit, status.latest_commit);
        assert!(status.checked_at.is_some());
    }

    #[tokio::test]
    async fn refresh_status_reports_behind_when_remote_advances() {
        let fixture = setup_tracked_repo();
        write_commit(&fixture.seed, "remote.txt", "remote\n", "remote");
        git(&fixture.seed, &["push"]);
        let config = test_config(Some(fixture.local.clone()));

        let status = refresh_status(&config).await;

        assert_eq!(status.state, UpdateCheckState::Behind);
        assert_eq!(status.ahead_by, 0);
        assert_eq!(status.behind_by, 1);
        assert_ne!(status.current_commit, status.latest_commit);
    }

    #[tokio::test]
    async fn refresh_status_reports_ahead_when_local_has_unpushed_commit() {
        let fixture = setup_tracked_repo();
        write_commit(&fixture.local, "local.txt", "local\n", "local");
        let config = test_config(Some(fixture.local.clone()));

        let status = refresh_status(&config).await;

        assert_eq!(status.state, UpdateCheckState::Ahead);
        assert_eq!(status.ahead_by, 1);
        assert_eq!(status.behind_by, 0);
    }

    #[tokio::test]
    async fn refresh_status_reports_diverged_when_both_sides_advance() {
        let fixture = setup_tracked_repo();
        write_commit(&fixture.local, "local.txt", "local\n", "local");
        write_commit(&fixture.seed, "remote.txt", "remote\n", "remote");
        git(&fixture.seed, &["push"]);
        let config = test_config(Some(fixture.local.clone()));

        let status = refresh_status(&config).await;

        assert_eq!(status.state, UpdateCheckState::Diverged);
        assert_eq!(status.ahead_by, 1);
        assert_eq!(status.behind_by, 1);
    }

    #[tokio::test]
    async fn refresh_status_uses_cached_tracking_ref_when_fetch_fails() {
        let fixture = setup_tracked_repo();
        let broken_remote = fixture.local.join("missing-remote.git");
        let broken_remote = broken_remote.display().to_string();
        git(&fixture.local, &["remote", "set-url", "origin", broken_remote.as_str()]);
        let config = test_config(Some(fixture.local.clone()));

        let status = refresh_status(&config).await;

        assert_eq!(status.state, UpdateCheckState::Current);
        assert_eq!(status.ahead_by, 0);
        assert_eq!(status.behind_by, 0);
        assert!(status
            .error
            .as_deref()
            .is_some_and(|error| error.contains("using the locally cached tracking ref")));
        assert!(status.upgrade_hint.contains("cached tracking ref"));
        // Honest staleness: the count came from a stale cached ref, so the
        // comparison is flagged unverified rather than presented confidently.
        assert!(status.comparison_stale);
    }

    #[tokio::test]
    async fn refresh_status_behind_count_reflects_fetched_remote_not_stale_cache() {
        // Advance the remote by N commits *after* the local checkout was cloned,
        // so the local repo's cached origin/main is still at the seed commit.
        // A working `git fetch` must refresh the tracking ref; if it silently
        // failed we'd see behind_by == 0 from the stale cache.
        let fixture = setup_tracked_repo();
        let n = 3;
        for i in 0..n {
            write_commit(
                &fixture.seed,
                "remote.txt",
                &format!("remote {i}\n"),
                &format!("remote {i}"),
            );
        }
        git(&fixture.seed, &["push"]);
        let config = test_config(Some(fixture.local.clone()));

        let status = refresh_status(&config).await;

        assert_eq!(status.state, UpdateCheckState::Behind);
        assert_eq!(status.ahead_by, 0);
        assert_eq!(status.behind_by, n as u64);
        // Fetch genuinely succeeded → no staleness flag, count is trustworthy.
        assert!(!status.comparison_stale);
        assert!(status.error.is_none());
        assert_ne!(status.current_commit, status.latest_commit);
    }

    #[tokio::test]
    async fn refresh_status_fetch_failure_does_not_present_unqualified_count() {
        // Remote advances, but the local origin URL is broken so fetch cannot
        // reach it. The status must NOT confidently report the real drift; it
        // must flag comparison_stale and carry the fetch-failure error.
        let fixture = setup_tracked_repo();
        write_commit(&fixture.seed, "remote.txt", "remote\n", "remote");
        git(&fixture.seed, &["push"]);
        let broken_remote = fixture.local.join("missing-remote.git");
        let broken_remote = broken_remote.display().to_string();
        git(&fixture.local, &["remote", "set-url", "origin", broken_remote.as_str()]);
        let config = test_config(Some(fixture.local.clone()));

        let status = refresh_status(&config).await;

        // Fetch failed → comparison is unverified. The cached ref still matches
        // local HEAD (Current), but the staleness signal is what callers gate on.
        assert!(status.comparison_stale);
        assert!(status
            .error
            .as_deref()
            .is_some_and(|error| error.contains("git fetch") && error.contains("failed")));
        assert!(status.upgrade_hint.contains("cached tracking ref"));
    }

    #[tokio::test]
    async fn left_right_counts_reports_ahead_and_behind() {
        // Exercises the shared parse-reuse helper directly: one local-only
        // commit (ahead) against two remote-only commits (behind).
        let fixture = setup_tracked_repo();
        write_commit(&fixture.local, "local.txt", "local\n", "local");
        for i in 0..2 {
            write_commit(&fixture.seed, "r.txt", &format!("r{i}\n"), &format!("r{i}"));
        }
        git(&fixture.seed, &["push"]);
        git(&fixture.local, &["fetch", "origin", "main"]);

        let counts = left_right_counts(&fixture.local, "HEAD", "origin/main").await.unwrap();
        assert_eq!(counts, (1, 2));
    }

    #[tokio::test]
    async fn refresh_status_binary_basis_reports_binary_drift_not_checkout() {
        // Remote advances 3 commits past the local clone; the checkout HEAD stays
        // at the seed commit (3 behind). The "binary" is the second-to-last
        // remote commit — 1 behind the tracking ref. Primary counts must follow
        // the binary; the checkout_* fields must carry the staler HEAD drift.
        let fixture = setup_tracked_repo();
        for i in 0..3 {
            write_commit(
                &fixture.seed,
                "remote.txt",
                &format!("remote {i}\n"),
                &format!("remote {i}"),
            );
        }
        git(&fixture.seed, &["push"]);
        let binary_sha = git(&fixture.seed, &["rev-parse", "HEAD~1"]);
        let config = test_config(Some(fixture.local.clone()));

        let status = refresh_status_with_binary_sha(&config, Some(binary_sha.clone())).await;

        // Primary comparison follows the running binary.
        assert_eq!(status.basis, "binary");
        assert_eq!(status.state, UpdateCheckState::Behind);
        assert_eq!(status.ahead_by, 0);
        assert_eq!(status.behind_by, 1);
        let short = status.current_commit.as_deref().expect("current_commit set");
        assert!(binary_sha.starts_with(short), "current_commit is the binary sha prefix");
        assert_eq!(status.binary_commit.as_deref(), Some(short));
        // The staler source checkout is still visible in the secondary fields.
        assert_eq!(status.checkout_ahead_by, 0);
        assert_eq!(status.checkout_behind_by, 3);
        assert!(status.checkout_commit.is_some());
        assert_ne!(status.current_commit, status.checkout_commit);
        // Binary basis + materially staler checkout → hint nudges a src refresh.
        assert!(status.upgrade_hint.contains("running binary"));
        assert!(status.upgrade_hint.contains("source checkout"));
        // The hint is served unauthenticated via /v1/version — it must not leak
        // the repo path (which stays admin-only in `repo_dir`).
        assert!(!status.upgrade_hint.contains(fixture.local.to_str().unwrap()));
        // Binary note is operator-facing (hint), not an error/staleness signal.
        assert!(status.error.is_none());
        assert!(!status.comparison_stale);
    }

    #[tokio::test]
    async fn refresh_status_checkout_basis_when_binary_sha_absent() {
        let fixture = setup_tracked_repo();
        write_commit(&fixture.seed, "remote.txt", "remote\n", "remote");
        git(&fixture.seed, &["push"]);
        let config = test_config(Some(fixture.local.clone()));

        let status = refresh_status_with_binary_sha(&config, None).await;

        assert_eq!(status.basis, "checkout");
        assert_eq!(status.state, UpdateCheckState::Behind);
        assert_eq!(status.behind_by, 1);
        assert_eq!(status.checkout_behind_by, 1);
        assert!(status.binary_commit.is_none());
        // Under checkout basis the primary commit is the checkout HEAD.
        assert_eq!(status.current_commit, status.checkout_commit);
        assert!(status.error.is_none());
    }

    #[tokio::test]
    async fn refresh_status_checkout_basis_with_note_when_binary_sha_unresolvable() {
        let fixture = setup_tracked_repo();
        let config = test_config(Some(fixture.local.clone()));
        // Syntactically valid but absent from the checkout.
        let bogus = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string();

        let status = refresh_status_with_binary_sha(&config, Some(bogus.clone())).await;

        assert_eq!(status.basis, "checkout");
        // The unresolved binary sha is still surfaced so operators can see it.
        assert_eq!(status.binary_commit.as_deref(), Some(bogus.as_str()));
        // The fallback reason lands in the hint, not the error/staleness channel.
        assert!(status.upgrade_hint.contains("does not resolve"));
        // The unauthenticated /v1/version hint must not leak the binary sha.
        assert!(!status.upgrade_hint.contains(&bogus));
        assert!(status.error.is_none());
        assert!(!status.comparison_stale);
        // Synced checkout → Current under the checkout basis.
        assert_eq!(status.state, UpdateCheckState::Current);
    }
}
