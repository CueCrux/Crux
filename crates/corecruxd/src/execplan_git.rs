// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Git-backed ExecPlan projection root.
//!
//! The projection ([`crate::work_execplans`]) reads plan markdown from a
//! directory. How that directory gets its content was, until this module,
//! nobody's job — in practice a human ran `rsync`. That made the directory a
//! *second writer*: plans were authored straight into it and existed in no git
//! repository at all, while plans committed elsewhere never arrived.
//!
//! This module makes the root a **pull-only replica**. It clones once and
//! fast-forwards thereafter. It never commits, never pushes, never resets, and
//! never merges — so it cannot hold state that git does not already have, which
//! is what makes bidirectional drift structurally impossible rather than
//! something an operator notices and repairs.
//!
//! Shelling out to `git` is deliberate: clone + `pull --ff-only` is two
//! commands, and a linked libgit2 would be a large dependency for that.
//!
//! Configuration (all optional — unset means "plain directory", today's
//! behaviour, byte-identical):
//!
//! - `CRUX_EXECPLANS_GIT_REMOTE` — clone URL. Absent ⇒ this module does nothing.
//! - `CRUX_EXECPLANS_GIT_BRANCH` — defaults to `main`.
//! - `CRUX_EXECPLANS_GIT_INTERVAL_SECS` — background refresh cadence;
//!   `0`/unset ⇒ no timer (refresh on demand only).
//! - `CRUX_EXECPLANS_GIT_CHECKOUT` — where the clone lives. **The checkout is
//!   the repository; the projection root is usually a subdirectory of it**
//!   (`<checkout>/.agent/execplans`). Defaults to `CRUX_EXECPLANS_ROOT`, which
//!   is correct only for a repository whose top level *is* the plans directory.
//!   Getting this wrong is silent — git clones happily into the wrong place and
//!   the board simply stays empty — so a mismatch is validated and reported.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Serialize;

pub const GIT_REMOTE_ENV: &str = "CRUX_EXECPLANS_GIT_REMOTE";
pub const GIT_BRANCH_ENV: &str = "CRUX_EXECPLANS_GIT_BRANCH";
pub const GIT_INTERVAL_ENV: &str = "CRUX_EXECPLANS_GIT_INTERVAL_SECS";
pub const GIT_CHECKOUT_ENV: &str = "CRUX_EXECPLANS_GIT_CHECKOUT";

const DEFAULT_BRANCH: &str = "main";
/// A hung `git` on an unreachable remote must not wedge the refresh task.
const GIT_TIMEOUT_SECS: u64 = 120;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitConfig {
    pub remote: String,
    pub branch: String,
    pub interval_secs: u64,
}

/// Read the git-backing config from the environment. `None` = not configured;
/// the root is then treated as a plain directory exactly as before.
pub fn git_config_from_env() -> Option<GitConfig> {
    let remote = std::env::var(GIT_REMOTE_ENV).ok()?;
    let remote = remote.trim().to_string();
    if remote.is_empty() {
        return None;
    }
    let branch = std::env::var(GIT_BRANCH_ENV)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_BRANCH.to_string());
    let interval_secs = std::env::var(GIT_INTERVAL_ENV)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0);
    Some(GitConfig {
        remote,
        branch,
        interval_secs,
    })
}

/// What a refresh did. `changed` is the honest signal for "re-read the board":
/// false means the replica was already at the remote's tip.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SyncOutcome {
    /// `cloned` | `fast_forwarded` | `already_current` | `skipped`
    pub action: String,
    pub head_sha: Option<String>,
    pub previous_sha: Option<String>,
    pub changed: bool,
    pub branch: String,
    /// Present when the refresh could not complete. The replica is left
    /// untouched — a failed pull never degrades what is already projected.
    pub error: Option<String>,
}

impl SyncOutcome {
    fn failed(branch: &str, error: impl Into<String>) -> Self {
        Self {
            action: "skipped".into(),
            head_sha: None,
            previous_sha: None,
            changed: false,
            branch: branch.to_string(),
            error: Some(error.into()),
        }
    }
}

fn run_git(dir: Option<&Path>, args: &[&str]) -> Result<String, String> {
    let mut cmd = Command::new("git");
    if let Some(d) = dir {
        cmd.current_dir(d);
    }
    // Never let git prompt for credentials — a blocked prompt on a headless
    // daemon is an unrecoverable hang, and a private-remote misconfiguration
    // should surface as an error the operator can read.
    cmd.env("GIT_TERMINAL_PROMPT", "0");
    cmd.env("GIT_HTTP_LOW_SPEED_LIMIT", "1000");
    cmd.env("GIT_HTTP_LOW_SPEED_TIME", GIT_TIMEOUT_SECS.to_string());
    cmd.args(args);
    let out = cmd.output().map_err(|e| format!("git {}: {e}", args.join(" ")))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        return Err(format!("git {} failed: {stderr}", args.join(" ")));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn is_git_repo(root: &Path) -> bool {
    root.join(".git").exists()
}

fn head_sha(root: &Path) -> Option<String> {
    run_git(Some(root), &["rev-parse", "HEAD"]).ok()
}

/// `true` when the replica has local modifications. A dirty replica means
/// something wrote to it directly — the exact failure this module exists to
/// prevent — so we refuse to pull rather than clobber or merge it.
fn is_dirty(root: &Path) -> bool {
    run_git(Some(root), &["status", "--porcelain"]).is_ok_and(|s| !s.trim().is_empty())
}

/// Bring the replica to the remote branch tip. Clones if absent; otherwise
/// fetches and fast-forwards. Never resets, merges, commits or pushes.
pub fn refresh(cfg: &GitConfig, root: &Path) -> SyncOutcome {
    if !root.exists() || !is_git_repo(root) {
        // A non-empty non-repo directory is almost certainly the legacy rsync
        // root. Refuse rather than clone over it — the operator should move it
        // aside deliberately so nothing that was only ever there is lost.
        if root.exists() && std::fs::read_dir(root).map(|mut d| d.next().is_some()).unwrap_or(false) {
            return SyncOutcome::failed(
                &cfg.branch,
                format!(
                    "{} exists, is not a git repository, and is not empty — move the legacy \
                     directory aside before enabling git backing (it may hold plans that were \
                     never committed)",
                    root.display()
                ),
            );
        }
        if let Some(parent) = root.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                return SyncOutcome::failed(&cfg.branch, format!("create {}: {e}", parent.display()));
            }
        }
        let root_s = root.display().to_string();
        return match run_git(
            None,
            &[
                "clone",
                "--branch",
                &cfg.branch,
                "--single-branch",
                &cfg.remote,
                &root_s,
            ],
        ) {
            Ok(_) => SyncOutcome {
                action: "cloned".into(),
                head_sha: head_sha(root),
                previous_sha: None,
                changed: true,
                branch: cfg.branch.clone(),
                error: None,
            },
            Err(e) => SyncOutcome::failed(&cfg.branch, e),
        };
    }

    if is_dirty(root) {
        return SyncOutcome::failed(
            &cfg.branch,
            format!(
                "{} has local modifications — the projection root is pull-only; something wrote \
                 to it directly. Inspect and clear it before refreshing.",
                root.display()
            ),
        );
    }

    let before = head_sha(root);
    if let Err(e) = run_git(Some(root), &["fetch", "--quiet", "origin", &cfg.branch]) {
        return SyncOutcome::failed(&cfg.branch, e);
    }
    // --ff-only: a replica that has diverged is a bug to report, never
    // something to resolve by merging.
    match run_git(Some(root), &["merge", "--ff-only", &format!("origin/{}", cfg.branch)]) {
        Ok(_) => {
            let after = head_sha(root);
            let changed = before != after;
            SyncOutcome {
                action: if changed {
                    "fast_forwarded".into()
                } else {
                    "already_current".into()
                },
                head_sha: after,
                previous_sha: before,
                changed,
                branch: cfg.branch.clone(),
                error: None,
            }
        }
        Err(e) => SyncOutcome::failed(
            &cfg.branch,
            format!("{e} (replica has diverged from origin/{})", cfg.branch),
        ),
    }
}

/// Where the clone lives. This is the REPOSITORY, which is normally an ancestor
/// of the projection root (`<checkout>/.agent/execplans`). Explicit
/// `CRUX_EXECPLANS_GIT_CHECKOUT` wins; otherwise the projection root doubles as
/// the checkout, which is only correct when the repo's top level is the plans
/// directory itself.
pub fn checkout_path_from_env() -> Option<PathBuf> {
    if let Ok(p) = std::env::var(GIT_CHECKOUT_ENV) {
        let p = p.trim().to_string();
        if !p.is_empty() {
            return Some(PathBuf::from(p));
        }
    }
    crate::work_execplans::execplans_root_from_env()
}

/// Refresh using the env config + the resolved checkout. `None` when git
/// backing is not configured, so callers can stay silent in that case.
///
/// After a successful refresh the projection root is checked for existence.
/// A checkout that succeeded while the root stayed missing is the classic
/// misconfiguration — clone target set to the plans subdirectory rather than
/// the repository — and it is otherwise completely silent: git reports success
/// and the board just stays empty.
pub fn refresh_from_env() -> Option<(PathBuf, SyncOutcome)> {
    let cfg = git_config_from_env()?;
    let checkout = checkout_path_from_env()?;
    let mut outcome = refresh(&cfg, &checkout);
    if outcome.error.is_none() {
        if let Some(root) = crate::work_execplans::execplans_root_from_env() {
            if !root.exists() {
                outcome.error = Some(format!(
                    "clone succeeded at {} but the projection root {} does not exist — {} should \
                     name the REPOSITORY (the root is usually <checkout>/.agent/execplans)",
                    checkout.display(),
                    root.display(),
                    GIT_CHECKOUT_ENV
                ));
            }
        }
    }
    Some((checkout, outcome))
}

/// Background refresh loop. No-op unless both a remote and a non-zero interval
/// are configured.
pub fn spawn_refresh_task() {
    let Some(cfg) = git_config_from_env() else { return };
    if cfg.interval_secs == 0 {
        tracing::info!(remote = %cfg.remote, branch = %cfg.branch, "execplan-git-backing-on-demand-only");
        return;
    }
    let Some(root) = checkout_path_from_env() else {
        tracing::warn!("execplan-git-remote-set-but-no-root: set CRUX_EXECPLANS_ROOT or CRUX_EXECPLANS_GIT_CHECKOUT");
        return;
    };
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(cfg.interval_secs));
        loop {
            tick.tick().await;
            let cfg2 = cfg.clone();
            let root2 = root.clone();
            // Blocking `git` off the async runtime.
            let outcome = tokio::task::spawn_blocking(move || refresh(&cfg2, &root2)).await;
            match outcome {
                Ok(o) if o.error.is_some() => {
                    tracing::warn!(error = %o.error.unwrap_or_default(), "execplan-git-refresh-failed");
                }
                Ok(o) if o.changed => {
                    tracing::info!(action = %o.action, head = ?o.head_sha, "execplan-git-refreshed");
                }
                Ok(_) => {}
                Err(e) => tracing::warn!(error = %e, "execplan-git-refresh-join-failed"),
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("crux-execplan-git-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    /// Build a throwaway origin with one plan committed, and return its path.
    fn seed_origin(dir: &Path) {
        std::fs::create_dir_all(dir).expect("mkdir origin");
        run_git(Some(dir), &["init", "--initial-branch=main"]).expect("init");
        run_git(Some(dir), &["config", "user.email", "t@example.com"]).expect("cfg email");
        run_git(Some(dir), &["config", "user.name", "t"]).expect("cfg name");
        std::fs::create_dir_all(dir.join(".agent/execplans")).expect("mkdir plans");
        std::fs::write(
            dir.join(".agent/execplans/seed-plan-2026-01-01.md"),
            "# Seed\n\nStatus: Planned\n",
        )
        .expect("write plan");
        run_git(Some(dir), &["add", "-A"]).expect("add");
        run_git(Some(dir), &["commit", "-m", "seed"]).expect("commit");
    }

    fn cfg_for(remote: &Path) -> GitConfig {
        GitConfig {
            remote: remote.display().to_string(),
            branch: "main".into(),
            interval_secs: 0,
        }
    }

    #[test]
    fn clone_then_fast_forward_then_idempotent() {
        let origin = tmp("origin-a");
        let replica = tmp("replica-a");
        seed_origin(&origin);
        let cfg = cfg_for(&origin);

        // 1. First refresh clones.
        let o1 = refresh(&cfg, &replica);
        assert_eq!(o1.action, "cloned", "{o1:?}");
        assert!(o1.changed);
        assert!(replica.join(".agent/execplans/seed-plan-2026-01-01.md").exists());

        // 2. Nothing new upstream → already_current, changed=false.
        let o2 = refresh(&cfg, &replica);
        assert_eq!(o2.action, "already_current", "{o2:?}");
        assert!(!o2.changed, "an unchanged remote must not report a change");
        assert_eq!(o2.head_sha, o1.head_sha);

        // 3. A new commit upstream fast-forwards.
        std::fs::write(origin.join(".agent/execplans/second-plan-2026-01-02.md"), "# Second\n").expect("write");
        run_git(Some(&origin), &["add", "-A"]).expect("add");
        run_git(Some(&origin), &["commit", "-m", "second"]).expect("commit");
        let o3 = refresh(&cfg, &replica);
        assert_eq!(o3.action, "fast_forwarded", "{o3:?}");
        assert!(o3.changed);
        assert_ne!(o3.head_sha, o3.previous_sha);
        assert!(replica.join(".agent/execplans/second-plan-2026-01-02.md").exists());

        let _ = std::fs::remove_dir_all(&origin);
        let _ = std::fs::remove_dir_all(&replica);
    }

    #[test]
    fn dirty_replica_refuses_rather_than_clobbering() {
        let origin = tmp("origin-b");
        let replica = tmp("replica-b");
        seed_origin(&origin);
        let cfg = cfg_for(&origin);
        assert_eq!(refresh(&cfg, &replica).action, "cloned");

        // Simulate the exact failure this module prevents: someone wrote a plan
        // straight into the replica.
        std::fs::write(replica.join(".agent/execplans/orphan-2026-01-03.md"), "# Orphan\n").expect("write");
        let o = refresh(&cfg, &replica);
        assert_eq!(o.action, "skipped");
        assert!(
            o.error.as_deref().unwrap_or_default().contains("local modifications"),
            "{o:?}"
        );
        // The orphan is still there — refusing must never destroy the evidence.
        assert!(replica.join(".agent/execplans/orphan-2026-01-03.md").exists());

        let _ = std::fs::remove_dir_all(&origin);
        let _ = std::fs::remove_dir_all(&replica);
    }

    #[test]
    fn unreachable_remote_reports_and_leaves_replica_intact() {
        let origin = tmp("origin-c");
        let replica = tmp("replica-c");
        seed_origin(&origin);
        let cfg = cfg_for(&origin);
        assert_eq!(refresh(&cfg, &replica).action, "cloned");
        let good_head = head_sha(&replica);

        // Point at a remote that does not exist.
        let bad = GitConfig {
            remote: tmp("no-such-origin").display().to_string(),
            branch: "main".into(),
            interval_secs: 0,
        };
        // `git fetch origin` uses the cloned remote, so break the origin instead.
        std::fs::remove_dir_all(&origin).expect("rm origin");
        let o = refresh(&bad, &replica);
        assert_eq!(o.action, "skipped", "{o:?}");
        assert!(o.error.is_some());
        // A failed refresh must not degrade what is already projected.
        assert_eq!(head_sha(&replica), good_head);
        assert!(replica.join(".agent/execplans/seed-plan-2026-01-01.md").exists());

        let _ = std::fs::remove_dir_all(&replica);
    }

    #[test]
    fn non_empty_non_repo_root_is_refused_not_cloned_over() {
        let origin = tmp("origin-d");
        let legacy = tmp("legacy-rsync-root");
        seed_origin(&origin);
        std::fs::create_dir_all(&legacy).expect("mkdir");
        // A plan that exists ONLY here — precisely what was found on the live
        // host. Cloning over it would destroy it silently.
        std::fs::write(legacy.join("only-here-2026-01-04.md"), "# Only here\n").expect("write");

        let o = refresh(&cfg_for(&origin), &legacy);
        assert_eq!(o.action, "skipped", "{o:?}");
        assert!(o.error.as_deref().unwrap_or_default().contains("not empty"), "{o:?}");
        assert!(
            legacy.join("only-here-2026-01-04.md").exists(),
            "must not destroy uncommitted plans"
        );

        let _ = std::fs::remove_dir_all(&origin);
        let _ = std::fs::remove_dir_all(&legacy);
    }

    // ── write path ──

    const GOOD: &str = "# Title\n\nStatus: Planned\n\n## Purpose\n\nWhy.\n\n## Milestones\n\n- [ ] M0 — thing.\n";

    fn plans_subdir() -> PathBuf {
        PathBuf::from(".agent/execplans")
    }

    #[test]
    fn write_creates_commits_exactly_one_file_and_updates_with_hash() {
        let repo = tmp("w-a");
        seed_origin(&repo);
        // An unrelated dirty file: the write path must not sweep it into the commit.
        std::fs::write(repo.join("unrelated.txt"), "someone else's work in progress").expect("write");
        run_git(Some(&repo), &["add", "unrelated.txt"]).expect("stage unrelated");

        let out = write_plan(&repo, &plans_subdir(), "new-plan-2026-07-29", GOOD, None, false, None).expect("create");
        assert_eq!(out.action, "created");
        assert!(out.commit_sha.is_some());

        // The commit contains ONLY the plan.
        let files = run_git(Some(&repo), &["show", "--name-only", "--format=", "HEAD"]).expect("show");
        let listed: Vec<&str> = files.lines().filter(|l| !l.trim().is_empty()).collect();
        assert_eq!(
            listed,
            vec![".agent/execplans/new-plan-2026-07-29.md"],
            "commit must hold one file: {listed:?}"
        );
        // And the unrelated staged file is still staged, uncommitted.
        assert!(
            run_git(Some(&repo), &["status", "--porcelain"])
                .expect("status")
                .contains("unrelated.txt"),
            "unrelated staged work must survive uncommitted"
        );

        // Update requires the current hash.
        let updated = GOOD.replace("Why.", "Why, revised.");
        let conflict = write_plan(
            &repo,
            &plans_subdir(),
            "new-plan-2026-07-29",
            &updated,
            None,
            false,
            None,
        );
        assert!(
            matches!(conflict, Err(WriteError::Conflict { .. })),
            "no-hash update must conflict"
        );

        let out2 = write_plan(
            &repo,
            &plans_subdir(),
            "new-plan-2026-07-29",
            &updated,
            Some(&out.content_hash),
            false,
            None,
        )
        .expect("update");
        assert_eq!(out2.action, "updated");
        assert_ne!(out2.commit_sha, out.commit_sha);

        let _ = std::fs::remove_dir_all(&repo);
    }

    #[test]
    fn write_refuses_stale_hash_and_hands_back_the_current_one() {
        let repo = tmp("w-b");
        seed_origin(&repo);
        let first =
            write_plan(&repo, &plans_subdir(), "race-plan-2026-07-29", GOOD, None, false, None).expect("create");
        // Peer writes.
        let peer = GOOD.replace("Why.", "Peer got here first.");
        write_plan(
            &repo,
            &plans_subdir(),
            "race-plan-2026-07-29",
            &peer,
            Some(&first.content_hash),
            false,
            None,
        )
        .expect("peer update");
        // We retry against the base we read — must be refused, with the new hash.
        let mine = GOOD.replace("Why.", "My edit, based on a stale read.");
        match write_plan(
            &repo,
            &plans_subdir(),
            "race-plan-2026-07-29",
            &mine,
            Some(&first.content_hash),
            false,
            None,
        ) {
            Err(WriteError::Conflict { current_hash, .. }) => {
                let cur = current_hash.expect("conflict must carry the current hash");
                assert_ne!(cur, first.content_hash);
                assert_eq!(cur, content_hash(peer.as_bytes()), "must hand back the PEER's hash");
            }
            other => panic!("expected a conflict, got {other:?}"),
        }
        // The peer's content is intact — a refused write must change nothing.
        let on_disk = std::fs::read_to_string(repo.join(".agent/execplans/race-plan-2026-07-29.md")).expect("read");
        assert_eq!(on_disk, peer);
        let _ = std::fs::remove_dir_all(&repo);
    }

    #[test]
    fn write_rejects_path_traversal_and_bad_slugs() {
        let repo = tmp("w-c");
        seed_origin(&repo);
        for bad in [
            "../escape",
            "a/b",
            "UPPER",
            "with space",
            "..",
            ".hidden",
            "_fragment",
            "",
        ] {
            let r = write_plan(&repo, &plans_subdir(), bad, GOOD, None, false, None);
            assert!(
                matches!(r, Err(WriteError::Invalid(_))),
                "slug {bad:?} must be rejected, got {r:?}"
            );
        }
        assert!(
            !repo.parent().map(|p| p.join("escape.md").exists()).unwrap_or(false),
            "nothing escaped"
        );
        let _ = std::fs::remove_dir_all(&repo);
    }

    #[test]
    fn write_rejects_content_missing_required_sections() {
        let repo = tmp("w-d");
        seed_origin(&repo);
        for (body, why) in [
            ("no heading at all\n\n## Purpose\n\n## Milestones\n", "missing # title"),
            ("# T\n\n## Milestones\n\n- [ ] M0\n", "missing Purpose"),
            ("# T\n\n## Purpose\n\nWhy.\n", "missing Milestones"),
            ("   \n", "empty"),
        ] {
            let r = write_plan(&repo, &plans_subdir(), "check-plan-2026-07-29", body, None, false, None);
            assert!(
                matches!(r, Err(WriteError::Invalid(_))),
                "{why} must be rejected, got {r:?}"
            );
        }
        let _ = std::fs::remove_dir_all(&repo);
    }

    #[test]
    fn write_then_projection_sees_it() {
        // The whole point: a plan written through this path is projectable.
        let repo = tmp("w-e");
        seed_origin(&repo);
        write_plan(
            &repo,
            &plans_subdir(),
            "projectable-2026-07-29",
            GOOD,
            None,
            false,
            None,
        )
        .expect("write");
        let files = crate::work_execplans::walk_execplans_root(&repo.join(".agent/execplans")).expect("walk");
        assert!(
            files.iter().any(|f| f.slug == "projectable-2026-07-29"),
            "written plan must be visible to the projection"
        );
        let _ = std::fs::remove_dir_all(&repo);
    }

    /// The checkout is the REPOSITORY; the projection root is normally
    /// `<checkout>/.agent/execplans`. Conflating them clones into the wrong
    /// place and the board silently stays empty — caught live on 2026-07-29.
    // Mutates process env, shared across the test binary's threads.
    #[serial_test::serial]
    #[test]
    fn checkout_defaults_to_root_but_explicit_checkout_wins() {
        std::env::remove_var(GIT_CHECKOUT_ENV);
        std::env::set_var(crate::work_execplans::EXECPLANS_ROOT_ENV, "/repo/.agent/execplans");
        assert_eq!(
            checkout_path_from_env(),
            Some(PathBuf::from("/repo/.agent/execplans")),
            "no explicit checkout ⇒ the root doubles as the repo"
        );
        std::env::set_var(GIT_CHECKOUT_ENV, "/repo");
        assert_eq!(
            checkout_path_from_env(),
            Some(PathBuf::from("/repo")),
            "explicit checkout names the repository"
        );
        std::env::set_var(GIT_CHECKOUT_ENV, "   ");
        assert_eq!(
            checkout_path_from_env(),
            Some(PathBuf::from("/repo/.agent/execplans")),
            "blank checkout falls back to the root"
        );
        for k in [GIT_CHECKOUT_ENV, crate::work_execplans::EXECPLANS_ROOT_ENV] {
            std::env::remove_var(k);
        }
    }

    /// A clone that succeeds while the projection root stays missing is the
    /// silent misconfiguration: git is happy, the board is empty, nothing says
    /// why. `refresh_from_env` must turn that into a stated error.
    // Mutates process env, shared across the test binary's threads.
    #[serial_test::serial]
    #[test]
    fn checkout_ok_but_missing_projection_root_is_reported() {
        let origin = tmp("origin-e");
        let checkout = tmp("checkout-e");
        seed_origin(&origin);

        std::env::set_var(GIT_REMOTE_ENV, origin.display().to_string());
        std::env::set_var(GIT_BRANCH_ENV, "main");
        std::env::remove_var(GIT_INTERVAL_ENV);
        std::env::set_var(GIT_CHECKOUT_ENV, checkout.display().to_string());
        // Point the projection root at a path the clone will NOT create.
        std::env::set_var(
            crate::work_execplans::EXECPLANS_ROOT_ENV,
            checkout.join("wrong/subdir").display().to_string(),
        );

        let (_, outcome) = refresh_from_env().expect("configured");
        assert_eq!(outcome.action, "cloned", "the clone itself succeeds: {outcome:?}");
        let err = outcome.error.as_deref().unwrap_or_default();
        assert!(err.contains("projection root"), "must name the real problem: {err}");
        assert!(err.contains(GIT_CHECKOUT_ENV), "must name the var to fix: {err}");

        // And the correctly-configured root reports no error.
        std::env::set_var(
            crate::work_execplans::EXECPLANS_ROOT_ENV,
            checkout.join(".agent/execplans").display().to_string(),
        );
        let (_, ok) = refresh_from_env().expect("configured");
        assert!(ok.error.is_none(), "correct config must be clean: {ok:?}");

        for k in [
            GIT_REMOTE_ENV,
            GIT_BRANCH_ENV,
            GIT_CHECKOUT_ENV,
            crate::work_execplans::EXECPLANS_ROOT_ENV,
        ] {
            std::env::remove_var(k);
        }
        let _ = std::fs::remove_dir_all(&origin);
        let _ = std::fs::remove_dir_all(&checkout);
    }

    // Mutates process env, shared across the test binary's threads.
    #[serial_test::serial]
    #[test]
    fn config_absent_means_not_configured() {
        std::env::remove_var(GIT_REMOTE_ENV);
        assert_eq!(git_config_from_env(), None, "no remote ⇒ plain-directory mode");
        std::env::set_var(GIT_REMOTE_ENV, "   ");
        assert_eq!(git_config_from_env(), None, "blank remote ⇒ plain-directory mode");
        std::env::remove_var(GIT_REMOTE_ENV);
    }

    // Mutates process env, shared across the test binary's threads.
    #[serial_test::serial]
    #[test]
    fn config_defaults_branch_to_main_and_interval_to_zero() {
        std::env::set_var(GIT_REMOTE_ENV, "https://example.invalid/r.git");
        std::env::remove_var(GIT_BRANCH_ENV);
        std::env::remove_var(GIT_INTERVAL_ENV);
        let c = git_config_from_env().expect("configured");
        assert_eq!(c.branch, "main");
        assert_eq!(c.interval_secs, 0, "no timer unless asked for");
        std::env::set_var(GIT_BRANCH_ENV, "release");
        std::env::set_var(GIT_INTERVAL_ENV, "900");
        let c2 = git_config_from_env().expect("configured");
        assert_eq!(c2.branch, "release");
        assert_eq!(c2.interval_secs, 900);
        for k in [GIT_REMOTE_ENV, GIT_BRANCH_ENV, GIT_INTERVAL_ENV] {
            std::env::remove_var(k);
        }
    }
}

// ── Write path ───────────────────────────────────────────────────────────────
//
// The projection is read-only, which meant an agent without a checkout had no
// legal way to author a plan. On the live host that produced three plans
// existing in no git repository at all. This is the one legal write path:
// validate, write, stage exactly one file, commit.
//
// It deliberately does NOT `git add -A`. A planning-document tool that sweeps
// the working tree would eventually commit somebody's unrelated work in progress.

/// Sections a plan must carry to be projectable. `# ` gives the title,
/// `## Milestones` drives state derivation. Everything else in `PLANS.md` is
/// convention this layer does not enforce — rejecting a plan for a missing
/// `## Non-goals` would push authors back to writing files by hand, which is
/// the behaviour this path exists to replace.
const REQUIRED_HEADINGS: &[&str] = &["## Purpose", "## Milestones"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WriteOutcome {
    /// `created` | `updated`
    pub action: String,
    pub slug: String,
    pub rel_path: String,
    pub commit_sha: Option<String>,
    pub content_hash: String,
    pub pushed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteError {
    /// Caller error — 400.
    Invalid(String),
    /// Lost-update / precondition — 409. Carries the current hash so the caller
    /// can re-read, merge, and retry against a known base.
    Conflict {
        message: String,
        current_hash: Option<String>,
    },
    /// Environment or git failure — 500.
    Failed(String),
}

/// BLAKE3 of the plan bytes — the same digest `list_execplans` publishes as
/// `plan_content_hash`, so a caller can round-trip board → edit → write without
/// a second hashing convention.
pub fn content_hash(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

/// A slug must be a bare filename. Rejecting separators is what stops
/// `../../etc/whatever` from being written through this path.
fn validate_slug(slug: &str) -> Result<(), WriteError> {
    if slug.is_empty() || slug.len() > 160 {
        return Err(WriteError::Invalid("slug must be 1..=160 characters".into()));
    }
    if !slug
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_' || c == '.')
    {
        return Err(WriteError::Invalid(
            "slug must be lowercase alphanumeric with - _ . only".into(),
        ));
    }
    if slug.contains("..") || slug.starts_with('.') || slug.starts_with('_') {
        return Err(WriteError::Invalid(
            "slug must not traverse, and must not start with '.' or '_' (underscore-prefixed files \
             are excluded from the projection)"
                .into(),
        ));
    }
    Ok(())
}

fn validate_content(content: &str) -> Result<(), WriteError> {
    if content.trim().is_empty() {
        return Err(WriteError::Invalid("content must not be empty".into()));
    }
    if !content.lines().any(|l| l.starts_with("# ")) {
        return Err(WriteError::Invalid("plan must open with a `# <Title>` heading".into()));
    }
    let missing: Vec<&str> = REQUIRED_HEADINGS
        .iter()
        .filter(|h| !content.lines().any(|l| l.trim_start().starts_with(*h)))
        .copied()
        .collect();
    if !missing.is_empty() {
        return Err(WriteError::Invalid(format!(
            "plan is missing required section(s): {} (see PLANS.md)",
            missing.join(", ")
        )));
    }
    Ok(())
}

/// Write a plan into the checkout and commit exactly that file.
///
/// `expected_hash` is the lost-update guard: `None` means "must not exist",
/// `Some(h)` means "must currently hash to `h`". Two sessions editing the same
/// plan therefore cannot silently overwrite each other — the loser is handed the
/// current hash rather than discovering the loss later.
pub fn write_plan(
    checkout: &Path,
    plans_subdir: &Path,
    slug: &str,
    content: &str,
    expected_hash: Option<&str>,
    push: bool,
    author: Option<&str>,
) -> Result<WriteOutcome, WriteError> {
    validate_slug(slug)?;
    validate_content(content)?;

    if !is_git_repo(checkout) {
        return Err(WriteError::Failed(format!(
            "{} is not a git repository — the write path commits, so it needs one",
            checkout.display()
        )));
    }

    let abs_dir = checkout.join(plans_subdir);
    let abs_path = abs_dir.join(format!("{slug}.md"));
    let rel_path = plans_subdir.join(format!("{slug}.md")).display().to_string();

    let existing = std::fs::read(&abs_path).ok();
    let existing_hash = existing.as_deref().map(content_hash);
    match (expected_hash, &existing_hash) {
        (None, Some(h)) => {
            return Err(WriteError::Conflict {
                message: format!("{slug} already exists; pass expected_content_hash to update it"),
                current_hash: Some(h.clone()),
            });
        }
        (Some(want), Some(have)) if want != have => {
            return Err(WriteError::Conflict {
                message: format!("{slug} changed since you read it — re-read, merge, and retry"),
                current_hash: Some(have.clone()),
            });
        }
        (Some(_), None) => {
            return Err(WriteError::Conflict {
                message: format!("{slug} does not exist, but expected_content_hash was supplied"),
                current_hash: None,
            });
        }
        _ => {}
    }

    if let Err(e) = std::fs::create_dir_all(&abs_dir) {
        return Err(WriteError::Failed(format!("create {}: {e}", abs_dir.display())));
    }
    if let Err(e) = std::fs::write(&abs_path, content) {
        return Err(WriteError::Failed(format!("write {}: {e}", abs_path.display())));
    }

    // Exactly one path. Never `-A`.
    run_git(Some(checkout), &["add", "--", &rel_path]).map_err(WriteError::Failed)?;

    let action = if existing_hash.is_some() { "updated" } else { "created" };
    let trailer = author.map(|a| format!("\nCo-Authored-By: {a}\n")).unwrap_or_default();
    let message = format!("plan({slug}): {action} via execplan_write\n\nExecPlan: {slug}\n{trailer}");
    // `--only <path>` commits that path alone even when the index holds other
    // staged changes — a session's unrelated staged work must not ride along.
    match run_git(
        Some(checkout),
        &["commit", "--only", "--message", &message, "--", &rel_path],
    ) {
        Ok(_) => {}
        Err(e) if e.contains("nothing to commit") || e.contains("no changes added") => {
            // Byte-identical rewrite. Not an error; report it honestly.
            return Ok(WriteOutcome {
                action: "updated".into(),
                slug: slug.to_string(),
                rel_path,
                commit_sha: head_sha(checkout),
                content_hash: content_hash(content.as_bytes()),
                pushed: false,
            });
        }
        Err(e) => return Err(WriteError::Failed(e)),
    }

    let mut pushed = false;
    if push {
        let branch = run_git(Some(checkout), &["rev-parse", "--abbrev-ref", "HEAD"]).map_err(WriteError::Failed)?;
        run_git(Some(checkout), &["push", "origin", &branch]).map_err(WriteError::Failed)?;
        pushed = true;
    }

    Ok(WriteOutcome {
        action: action.to_string(),
        slug: slug.to_string(),
        rel_path,
        commit_sha: head_sha(checkout),
        content_hash: content_hash(content.as_bytes()),
        pushed,
    })
}
