// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

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

    let current_commit = match run_git(&repo_dir, &["rev-parse", "--short", "HEAD"]).await {
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
            return unavailable_status(config, repo_dir_display, current_commit, checked_at, message);
        }
    };

    let counts = match run_git(
        &repo_dir,
        &["rev-list", "--left-right", "--count", &format!("HEAD...{tracking_ref}")],
    )
    .await
    {
        Ok(counts) => counts,
        Err(err) => {
            let message = if let Some(fetch_warning) = fetch_warning {
                format!("{fetch_warning}; git rev-list comparison failed: {err}")
            } else {
                format!("git rev-list comparison failed: {err}")
            };
            return error_status(config, repo_dir_display, current_commit, checked_at, message);
        }
    };

    let (ahead_by, behind_by) = match parse_left_right_counts(&counts) {
        Ok(counts) => counts,
        Err(err) => return error_status(config, repo_dir_display, current_commit, checked_at, err),
    };
    let state = derive_state(ahead_by, behind_by);
    let error = fetch_warning;

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
        error: error.clone(),
        upgrade_hint: upgrade_hint(state, error.is_some()),
    }
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
        current_commit,
        latest_commit: None,
        ahead_by: 0,
        behind_by: 0,
        checked_at,
        error: Some(error),
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
        current_commit,
        latest_commit: None,
        ahead_by: 0,
        behind_by: 0,
        checked_at,
        error: Some(error),
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

fn upgrade_hint(state: UpdateCheckState, using_cached_tracking_ref: bool) -> String {
    let suffix = if using_cached_tracking_ref {
        " The comparison used the last locally cached tracking ref because fetch failed."
    } else {
        ""
    };
    match state {
        UpdateCheckState::Disabled => {
            "Update checks are disabled. Enable them before asking an agent to decide whether an upgrade is needed."
                .to_string()
        }
        UpdateCheckState::Current => format!(
            "This checkout matches the tracked branch. No upgrade is needed right now.{suffix}"
        ),
        UpdateCheckState::Behind => format!(
            "A newer tracked commit is available. Take a filesystem snapshot of CORECRUXD_DATA_DIR or export receipts first, then pull, rebuild, and restart.{suffix}"
        ),
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
        let output = StdCommand::new("git").arg("-C").arg(dir).args(args).output().unwrap();
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
            upgrade_hint: "investigate".to_string(),
        };

        let public = status.public_view();
        assert_eq!(public.state, UpdateCheckState::Error);
        assert_eq!(public.current_commit.as_deref(), Some("abc123"));
        assert!(public.repo_dir.is_none());
        assert!(public.error.is_none());
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
    }
}
