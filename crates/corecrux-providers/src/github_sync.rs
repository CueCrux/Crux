// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! GitHub commit sync — pull commits from selected repos via api.github.com,
//! write each as a fact under `github::owner/repo::commit/{sha}`. Polled by
//! a tokio task on a fixed cadence and triggerable by hand via
//! `POST /v1/integrations/github/sync`.

#![allow(dead_code)] // sync constants + helpers used conditionally
#![allow(clippy::format_push_string)] // builder pattern

use std::path::Path;

use corecrux_memory::fact_store::{FactStore, StoreFact};
use serde::{Deserialize, Serialize};

use crate::github::{decrypt_pat, list_selected_repos, read_credentials, GithubIntegrationError, SelectedRepo};

#[allow(dead_code)] // documentation marker — used by the MCP tool descriptions in G5.
pub const COMMIT_ENTITY_TEMPLATE: &str = "github::{owner}/{repo}::commit/{sha}";
const PER_REPO_PAGE_SIZE: usize = 100;
const PER_REPO_MAX_PAGES: usize = 10; // up to 1000 commits per repo per sync

/// Result of a sync run for a single repo.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct RepoSyncOutcome {
    pub owner: String,
    pub repo: String,
    pub commits_added: usize,
    pub commits_skipped: usize,
    #[serde(default)]
    pub prs_added: usize,
    #[serde(default)]
    pub issues_added: usize,
    #[serde(default)]
    pub comments_added: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Aggregate result across all selected repos.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SyncRunResult {
    pub started_at_unix_ms: u64,
    pub finished_at_unix_ms: u64,
    pub repos: Vec<RepoSyncOutcome>,
}

/// Sync entry point — the caller supplies the integration encryption key
/// (the daemon holds it in its application state; this crate never sources it).
/// Blocking — caller dispatches via `tokio::task::spawn_blocking`. The first
/// call after `select_repo` does a full first-sync (capped at
/// `PER_REPO_MAX_PAGES * PER_REPO_PAGE_SIZE`); subsequent calls use the
/// `last_synced_at` cursor as `since=`.
pub fn run_sync_with_key(
    data_dir: &Path,
    store: &mut FactStore,
    encryption_key: &[u8; 32],
    now_unix_ms: u64,
) -> Result<SyncRunResult, GithubIntegrationError> {
    let creds = read_credentials(data_dir)?;
    let pat = decrypt_pat(&creds, encryption_key)?;
    let selected = list_selected_repos(data_dir);

    let mut outcomes = Vec::new();
    for repo in &selected {
        let outcome = sync_one_repo(data_dir, store, &pat, repo, now_unix_ms);
        outcomes.push(outcome);
    }

    Ok(SyncRunResult {
        started_at_unix_ms: now_unix_ms,
        finished_at_unix_ms: current_unix_ms(),
        repos: outcomes,
    })
}

fn sync_one_repo(
    data_dir: &Path,
    store: &mut FactStore,
    pat: &str,
    repo: &SelectedRepo,
    now_unix_ms: u64,
) -> RepoSyncOutcome {
    let since_iso = repo
        .last_synced_at_unix_ms
        .map(|ms| chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ms as i64))
        .and_then(|d| d.map(|d| d.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)));
    let entity_prefix = format!("github::{}/{}", repo.owner, repo.repo);
    let mut outcome = RepoSyncOutcome {
        owner: repo.owner.clone(),
        repo: repo.repo.clone(),
        commits_added: 0,
        commits_skipped: 0,
        prs_added: 0,
        issues_added: 0,
        comments_added: 0,
        error: None,
    };

    // Commits.
    match fetch_commits_paginated(pat, &repo.owner, &repo.repo, since_iso.as_deref()) {
        Ok(commits) => {
            for commit in &commits {
                let entity = format!("{entity_prefix}::commit/{}", commit.sha);
                if record_exists(store, &entity) {
                    outcome.commits_skipped += 1;
                    continue;
                }
                let value = serde_json::to_string(&commit).unwrap_or_default();
                store.store(StoreFact {
                    tenant_hash: "default".to_string(),
                    entity,
                    key: "record".to_string(),
                    value,
                    source_receipt: None,
                    confidence: 1.0,
                    private: repo.private,
                    horizon_class: None,
                    actor: None,
                });
                outcome.commits_added += 1;
            }
        }
        Err(err) => {
            outcome.error = Some(err.to_string());
            persist_repo_error(data_dir, repo, err.to_string());
            return outcome;
        }
    }

    // PRs.
    match fetch_prs_paginated(pat, &repo.owner, &repo.repo, since_iso.as_deref()) {
        Ok(prs) => {
            for pr in &prs {
                let entity = format!("{entity_prefix}::pr/{}", pr.number);
                let value = serde_json::to_string(&pr).unwrap_or_default();
                store.store(StoreFact {
                    tenant_hash: "default".to_string(),
                    entity,
                    key: "record".to_string(),
                    value,
                    source_receipt: None,
                    confidence: 1.0,
                    private: repo.private,
                    horizon_class: None,
                    actor: None,
                });
                outcome.prs_added += 1;
            }
        }
        Err(err) => {
            outcome.error = Some(format!("prs: {err}"));
            persist_repo_error(data_dir, repo, format!("prs: {err}"));
            return outcome;
        }
    }

    // Issues.
    match fetch_issues_paginated(pat, &repo.owner, &repo.repo, since_iso.as_deref()) {
        Ok(issues) => {
            for issue in &issues {
                let entity = format!("{entity_prefix}::issue/{}", issue.number);
                let value = serde_json::to_string(&issue).unwrap_or_default();
                store.store(StoreFact {
                    tenant_hash: "default".to_string(),
                    entity,
                    key: "record".to_string(),
                    value,
                    source_receipt: None,
                    confidence: 1.0,
                    private: repo.private,
                    horizon_class: None,
                    actor: None,
                });
                outcome.issues_added += 1;
            }
        }
        Err(err) => {
            outcome.error = Some(format!("issues: {err}"));
            persist_repo_error(data_dir, repo, format!("issues: {err}"));
            return outcome;
        }
    }

    // Comments — issue + PR review comments share the /issues/comments shape.
    match fetch_issue_comments_paginated(pat, &repo.owner, &repo.repo, since_iso.as_deref()) {
        Ok(comments) => {
            for c in &comments {
                let entity = format!("{entity_prefix}::comment/{}", c.id);
                if record_exists(store, &entity) {
                    continue;
                }
                let value = serde_json::to_string(&c).unwrap_or_default();
                store.store(StoreFact {
                    tenant_hash: "default".to_string(),
                    entity,
                    key: "record".to_string(),
                    value,
                    source_receipt: None,
                    confidence: 1.0,
                    private: repo.private,
                    horizon_class: None,
                    actor: None,
                });
                outcome.comments_added += 1;
            }
        }
        Err(err) => {
            outcome.error = Some(format!("comments: {err}"));
            persist_repo_error(data_dir, repo, format!("comments: {err}"));
            return outcome;
        }
    }

    persist_repo_synced(data_dir, repo, now_unix_ms);
    outcome
}

fn record_exists(store: &FactStore, entity: &str) -> bool {
    let result = store.query(&corecrux_memory::fact_store::FactQuery {
        min_effective_confidence: None,
        tenant_hash: None,
        query: None,
        entity: Some(entity.to_string()),
        entity_prefix: None,
        top_k: 5,
        token_budget: None,
    });
    result.facts.iter().any(|f| f.key == "record")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitRecord {
    pub sha: String,
    pub message: String,
    pub author_name: String,
    pub author_login: Option<String>,
    pub committed_at: String,
    pub parents: Vec<String>,
    pub html_url: String,
}

fn fetch_commits_paginated(
    pat: &str,
    owner: &str,
    repo: &str,
    since_iso: Option<&str>,
) -> Result<Vec<CommitRecord>, GithubIntegrationError> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(20)))
        .build()
        .into();
    let mut out = Vec::new();
    for page in 1..=PER_REPO_MAX_PAGES {
        let mut url =
            format!("https://api.github.com/repos/{owner}/{repo}/commits?per_page={PER_REPO_PAGE_SIZE}&page={page}");
        if let Some(since) = since_iso {
            url.push_str(&format!("&since={}", urlencoding(since)));
        }
        let mut response = agent
            .get(&url)
            .header("Authorization", &format!("Bearer {}", pat.trim()))
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("User-Agent", "crux-daemon")
            .call()
            .map_err(|e| GithubIntegrationError::Network(e.to_string()))?;
        let status = response.status().as_u16();
        let body = response
            .body_mut()
            .read_to_string()
            .map_err(|e| GithubIntegrationError::Network(e.to_string()))?;
        if status == 409 {
            // Empty repository — return what we have (probably nothing).
            break;
        }
        if status != 200 {
            return Err(GithubIntegrationError::VerifyFailed(format!(
                "github returned {status} on commits/{owner}/{repo}: {}",
                truncate(&body, 256)
            )));
        }
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&body)?;
        if parsed.is_empty() {
            break;
        }
        let count = parsed.len();
        for item in parsed {
            if let Some(rec) = parse_commit(&item) {
                out.push(rec);
            }
        }
        if count < PER_REPO_PAGE_SIZE {
            break;
        }
    }
    Ok(out)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrRecord {
    pub number: u64,
    pub title: String,
    pub state: String,
    pub author_login: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merged_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closed_at: Option<String>,
    pub head_sha: String,
    pub base_branch: String,
    pub body: String,
    pub html_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueRecord {
    pub number: u64,
    pub title: String,
    pub state: String,
    pub author_login: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closed_at: Option<String>,
    pub body: String,
    pub labels: Vec<String>,
    pub html_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommentRecord {
    pub id: u64,
    pub author_login: Option<String>,
    pub body: String,
    pub posted_at: String,
    pub html_url: String,
    /// Issue or PR number derived from `issue_url` (for `/issues/comments`).
    pub parent_number: Option<u64>,
}

fn fetch_prs_paginated(
    pat: &str,
    owner: &str,
    repo: &str,
    _since_iso: Option<&str>,
) -> Result<Vec<PrRecord>, GithubIntegrationError> {
    // /pulls doesn't support `since=`; we fetch state=all and let the dedup-by-entity
    // path keep facts current. Bound at 5 pages (500 PRs).
    fetch_paginated_json("pulls", pat, owner, repo, 5, "state=all&sort=updated&direction=desc")
        .map(|items| items.iter().filter_map(parse_pr).collect())
}

fn fetch_issues_paginated(
    pat: &str,
    owner: &str,
    repo: &str,
    since_iso: Option<&str>,
) -> Result<Vec<IssueRecord>, GithubIntegrationError> {
    let mut qs = "state=all&sort=updated&direction=desc".to_string();
    if let Some(s) = since_iso {
        qs.push_str(&format!("&since={}", urlencoding(s)));
    }
    fetch_paginated_json("issues", pat, owner, repo, 5, &qs)
        // /issues returns BOTH issues AND pull requests; filter PRs out (they have a
        // `pull_request` field).
        .map(|items| {
            items
                .iter()
                .filter(|v| v.get("pull_request").is_none())
                .filter_map(parse_issue)
                .collect()
        })
}

fn fetch_issue_comments_paginated(
    pat: &str,
    owner: &str,
    repo: &str,
    since_iso: Option<&str>,
) -> Result<Vec<CommentRecord>, GithubIntegrationError> {
    let mut qs = "sort=updated&direction=desc".to_string();
    if let Some(s) = since_iso {
        qs.push_str(&format!("&since={}", urlencoding(s)));
    }
    fetch_paginated_json("issues/comments", pat, owner, repo, 5, &qs)
        .map(|items| items.iter().filter_map(parse_comment).collect())
}

fn fetch_paginated_json(
    path: &str,
    pat: &str,
    owner: &str,
    repo: &str,
    max_pages: usize,
    extra_qs: &str,
) -> Result<Vec<serde_json::Value>, GithubIntegrationError> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(20)))
        .build()
        .into();
    let mut out = Vec::new();
    for page in 1..=max_pages.max(1) {
        let url = format!("https://api.github.com/repos/{owner}/{repo}/{path}?per_page=100&page={page}&{extra_qs}");
        let mut response = agent
            .get(&url)
            .header("Authorization", &format!("Bearer {}", pat.trim()))
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("User-Agent", "crux-daemon")
            .call()
            .map_err(|e| GithubIntegrationError::Network(e.to_string()))?;
        let status = response.status().as_u16();
        let body = response
            .body_mut()
            .read_to_string()
            .map_err(|e| GithubIntegrationError::Network(e.to_string()))?;
        if status != 200 {
            return Err(GithubIntegrationError::VerifyFailed(format!(
                "github returned {status} on {path} for {owner}/{repo}: {}",
                truncate(&body, 256)
            )));
        }
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&body)?;
        let count = parsed.len();
        if count == 0 {
            break;
        }
        out.extend(parsed);
        if count < 100 {
            break;
        }
    }
    Ok(out)
}

fn parse_pr(v: &serde_json::Value) -> Option<PrRecord> {
    let number = v.get("number").and_then(|x| x.as_u64())?;
    Some(PrRecord {
        number,
        title: v.get("title").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        state: v.get("state").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        author_login: v
            .get("user")
            .and_then(|u| u.get("login"))
            .and_then(|x| x.as_str())
            .map(str::to_string),
        created_at: v.get("created_at").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        updated_at: v.get("updated_at").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        merged_at: v.get("merged_at").and_then(|x| x.as_str()).map(str::to_string),
        closed_at: v.get("closed_at").and_then(|x| x.as_str()).map(str::to_string),
        head_sha: v
            .get("head")
            .and_then(|h| h.get("sha"))
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string(),
        base_branch: v
            .get("base")
            .and_then(|b| b.get("ref"))
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string(),
        body: v.get("body").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        html_url: v.get("html_url").and_then(|x| x.as_str()).unwrap_or("").to_string(),
    })
}

fn parse_issue(v: &serde_json::Value) -> Option<IssueRecord> {
    let number = v.get("number").and_then(|x| x.as_u64())?;
    let labels = v
        .get("labels")
        .and_then(|l| l.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|lbl| lbl.get("name").and_then(|n| n.as_str()).map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    Some(IssueRecord {
        number,
        title: v.get("title").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        state: v.get("state").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        author_login: v
            .get("user")
            .and_then(|u| u.get("login"))
            .and_then(|x| x.as_str())
            .map(str::to_string),
        created_at: v.get("created_at").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        updated_at: v.get("updated_at").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        closed_at: v.get("closed_at").and_then(|x| x.as_str()).map(str::to_string),
        body: v.get("body").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        labels,
        html_url: v.get("html_url").and_then(|x| x.as_str()).unwrap_or("").to_string(),
    })
}

fn parse_comment(v: &serde_json::Value) -> Option<CommentRecord> {
    let id = v.get("id").and_then(|x| x.as_u64())?;
    let issue_url = v.get("issue_url").and_then(|x| x.as_str()).unwrap_or("");
    let parent_number = issue_url.rsplit('/').next().and_then(|s| s.parse::<u64>().ok());
    Some(CommentRecord {
        id,
        author_login: v
            .get("user")
            .and_then(|u| u.get("login"))
            .and_then(|x| x.as_str())
            .map(str::to_string),
        body: v.get("body").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        posted_at: v.get("created_at").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        html_url: v.get("html_url").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        parent_number,
    })
}

/// Parse `[work:<id>]` markers out of free text. Returns the matched ids in
/// document order. Strict regex-free matcher — keeps the dep surface small.
pub fn parse_work_mentions(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while i + 6 <= bytes.len() {
        if &bytes[i..i + 6] == b"[work:" {
            let rest = &text[i + 6..];
            if let Some(close) = rest.find(']') {
                let candidate = &rest[..close];
                if !candidate.is_empty()
                    && candidate
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                {
                    out.push(candidate.to_string());
                    i += 6 + close + 1;
                    continue;
                }
                // Malformed — don't skip past the close; advance by 1 so a later
                // `[work:` inside the same span can still be picked up.
            }
        }
        i += 1;
    }
    out
}

fn parse_commit(v: &serde_json::Value) -> Option<CommitRecord> {
    let sha = v.get("sha").and_then(|x| x.as_str())?.to_string();
    let commit = v.get("commit")?;
    let message = commit.get("message").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let author_name = commit
        .get("author")
        .and_then(|a| a.get("name"))
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let committed_at = commit
        .get("author")
        .and_then(|a| a.get("date"))
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let author_login = v
        .get("author")
        .and_then(|a| a.get("login"))
        .and_then(|x| x.as_str())
        .map(str::to_string);
    let parents = v
        .get("parents")
        .and_then(|p| p.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|p| p.get("sha").and_then(|s| s.as_str()).map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let html_url = v.get("html_url").and_then(|x| x.as_str()).unwrap_or("").to_string();
    Some(CommitRecord {
        sha,
        message,
        author_name,
        author_login,
        committed_at,
        parents,
        html_url,
    })
}

fn persist_repo_synced(data_dir: &Path, repo: &SelectedRepo, now_unix_ms: u64) {
    let mut all = list_selected_repos(data_dir);
    if let Some(found) = all.iter_mut().find(|r| r.owner == repo.owner && r.repo == repo.repo) {
        found.last_synced_at_unix_ms = Some(now_unix_ms);
        found.last_sync_error = None;
        let _ = write_selected_for_sync(data_dir, &all);
    }
}

fn persist_repo_error(data_dir: &Path, repo: &SelectedRepo, err: String) {
    let mut all = list_selected_repos(data_dir);
    if let Some(found) = all.iter_mut().find(|r| r.owner == repo.owner && r.repo == repo.repo) {
        found.last_sync_error = Some(err);
        let _ = write_selected_for_sync(data_dir, &all);
    }
}

fn write_selected_for_sync(data_dir: &Path, repos: &[SelectedRepo]) -> Result<(), GithubIntegrationError> {
    // Mirrors integrations_github::write_selected_repos but reachable from this
    // module without a circular dep. Rewrites the whole file.
    let path = data_dir.join("integrations").join("github").join("selected_repos.json");
    // Same guard as the sibling writer: never clobber a selection we could not
    // read (D-8).
    crate::integrations_github::ensure_selection_writable(&path)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let body = serde_json::json!({ "repos": repos });
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(&body)?)?;
    std::fs::rename(tmp, &path)?;
    Ok(())
}

fn current_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        let mut out = s[..n].to_string();
        out.push_str("...");
        out
    }
}

fn urlencoding(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
            _ => format!("%{:02X}", c as u8),
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_dir(name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        // nanos alone collides on VMs with coarse clocks (parallel tests
        // land in the same quantum and share a dir) — salt with pid + a counter.
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("corecruxd-gh-sync-{name}-{nanos}-{}-{seq}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        dir
    }

    #[test]
    fn parse_commit_extracts_sha_and_message() {
        let raw = serde_json::json!({
            "sha": "abc123",
            "html_url": "https://github.com/o/r/commit/abc123",
            "commit": {
                "message": "fix the thing",
                "author": { "name": "Alice", "date": "2026-05-01T12:00:00Z" }
            },
            "author": { "login": "alice" },
            "parents": [{ "sha": "parent1" }, { "sha": "parent2" }]
        });
        let rec = parse_commit(&raw).expect("parsed");
        assert_eq!(rec.sha, "abc123");
        assert_eq!(rec.message, "fix the thing");
        assert_eq!(rec.author_name, "Alice");
        assert_eq!(rec.author_login.as_deref(), Some("alice"));
        assert_eq!(rec.parents, vec!["parent1".to_string(), "parent2".to_string()]);
    }

    #[test]
    fn parse_commit_missing_sha_returns_none() {
        let raw = serde_json::json!({ "commit": { "message": "no sha" } });
        assert!(parse_commit(&raw).is_none());
    }

    #[test]
    fn parse_pr_extracts_number_and_state() {
        let raw = serde_json::json!({
            "number": 42,
            "title": "fix bug",
            "state": "open",
            "user": { "login": "alice" },
            "created_at": "2026-05-01T10:00:00Z",
            "updated_at": "2026-05-01T11:00:00Z",
            "head": { "sha": "deadbeef" },
            "base": { "ref": "main" },
            "body": "see [work:abc-123] for context",
            "html_url": "https://github.com/o/r/pull/42"
        });
        let pr = parse_pr(&raw).expect("parsed");
        assert_eq!(pr.number, 42);
        assert_eq!(pr.state, "open");
        assert_eq!(pr.head_sha, "deadbeef");
        assert_eq!(pr.base_branch, "main");
    }

    #[test]
    fn parse_issue_filters_labels() {
        let raw = serde_json::json!({
            "number": 7,
            "title": "thing",
            "state": "open",
            "user": { "login": "bob" },
            "created_at": "2026-05-01T00:00:00Z",
            "updated_at": "2026-05-01T01:00:00Z",
            "body": "broken",
            "labels": [ { "name": "bug" }, { "name": "good first issue" } ],
            "html_url": "https://github.com/o/r/issues/7"
        });
        let issue = parse_issue(&raw).expect("parsed");
        assert_eq!(issue.labels, vec!["bug".to_string(), "good first issue".to_string()]);
    }

    #[test]
    fn parse_comment_extracts_parent_number_from_url() {
        let raw = serde_json::json!({
            "id": 999,
            "user": { "login": "x" },
            "body": "lgtm",
            "created_at": "2026-05-01T12:00:00Z",
            "html_url": "https://github.com/o/r/issues/42#issuecomment-999",
            "issue_url": "https://api.github.com/repos/o/r/issues/42"
        });
        let c = parse_comment(&raw).expect("parsed");
        assert_eq!(c.id, 999);
        assert_eq!(c.parent_number, Some(42));
    }

    #[test]
    fn parse_work_mentions_extracts_ids() {
        let text = "fixes [work:auth-rotate-2026] and tracks [work:logs-cleanup]";
        let ids = parse_work_mentions(text);
        assert_eq!(ids, vec!["auth-rotate-2026".to_string(), "logs-cleanup".to_string()]);
    }

    #[test]
    fn parse_work_mentions_rejects_invalid_chars() {
        let text = "ignore [work:has spaces] and [work:has/slash] but accept [work:valid_id]";
        let ids = parse_work_mentions(text);
        assert_eq!(ids, vec!["valid_id".to_string()]);
    }

    #[test]
    fn parse_work_mentions_handles_unclosed_brackets() {
        let text = "open bracket [work:unclosed and another [work:closed]";
        let ids = parse_work_mentions(text);
        assert_eq!(ids, vec!["closed".to_string()]);
    }

    #[test]
    fn run_sync_with_key_no_credentials_returns_error() {
        let dir = temp_dir("no-creds");
        let mut store = FactStore::new();
        let result = run_sync_with_key(&dir, &mut store, &[0u8; 32], 1_000);
        assert!(matches!(result, Err(GithubIntegrationError::NotConnected)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── Fixtures ──────────────────────────────────────────────────────────

    /// Write a credentials file whose PAT envelope is sealed with `key`. The
    /// token is an obvious fake; nothing here reaches api.github.com because
    /// every test that uses it keeps the selected-repo set empty.
    fn write_fake_credentials(dir: &Path, key: &[u8; 32]) {
        let creds = crate::github::GithubCredentials {
            encrypted_pat: corecrux_secrets::seal(b"github_pat_FAKE_not_a_real_token", key),
            username: "octocat".to_string(),
            scopes: vec!["repo".to_string()],
            connected_at_unix_ms: 1_700_000_000_000,
            last_verified_at_unix_ms: None,
        };
        crate::github::write_credentials(dir, &creds).expect("write credentials");
    }

    fn store_record(store: &mut FactStore, entity: &str, private: bool) {
        store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: entity.to_string(),
            key: "record".to_string(),
            value: "{}".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private,
            horizon_class: None,
            actor: None,
        });
    }

    // ── run_sync_with_key gating (no network reached) ─────────────────────

    /// Credentials present but nothing selected: the sync must complete
    /// successfully with zero repo outcomes and — critically — must not
    /// attempt any outbound call.
    #[test]
    fn run_sync_with_no_selected_repos_is_a_successful_no_op() {
        let dir = temp_dir("no-repos");
        let key = [3u8; 32];
        write_fake_credentials(&dir, &key);
        let mut store = FactStore::new();
        let result = run_sync_with_key(&dir, &mut store, &key, 1_234).expect("sync");
        assert!(result.repos.is_empty());
        assert_eq!(result.started_at_unix_ms, 1_234);
        assert!(
            result.finished_at_unix_ms > 0,
            "finished_at is stamped from the wall clock"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A rotated passport (wrong integration key) must fail loudly at decrypt
    /// time rather than falling through to an unauthenticated sync.
    #[test]
    fn run_sync_with_wrong_key_fails_before_any_fetch() {
        let dir = temp_dir("wrong-key");
        write_fake_credentials(&dir, &[3u8; 32]);
        // A repo IS selected — so if decrypt did not hard-fail first, this
        // test would try to reach the network.
        crate::github::select_repo(&dir, "cuecrux", "Crux", false, 1).expect("select");
        let mut store = FactStore::new();
        let err = run_sync_with_key(&dir, &mut store, &[9u8; 32], 1).expect_err("must fail");
        assert!(
            matches!(
                err,
                GithubIntegrationError::Encryption(corecrux_secrets::EncryptedSecretError::DecryptionFailed)
            ),
            "got {err:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── record_exists (idempotency guard) ─────────────────────────────────

    /// `record_exists` is the only thing stopping a re-sync from duplicating
    /// every commit fact. It must match on the exact entity + the `record` key.
    #[test]
    fn record_exists_matches_only_exact_entity_and_record_key() {
        let mut store = FactStore::new();
        let entity = "github::cuecrux/Crux::commit/abc123";
        assert!(!record_exists(&store, entity), "empty store has no record");
        store_record(&mut store, entity, false);
        assert!(record_exists(&store, entity));
        assert!(
            !record_exists(&store, "github::cuecrux/Crux::commit/other"),
            "a different sha must not be treated as already-synced"
        );
    }

    /// A fact stored under the same entity but a different key must not be
    /// mistaken for a synced record.
    #[test]
    fn record_exists_ignores_other_keys_on_the_same_entity() {
        let mut store = FactStore::new();
        let entity = "github::o/r::comment/1";
        store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: entity.to_string(),
            key: "note".to_string(),
            value: "{}".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        });
        assert!(!record_exists(&store, entity));
    }

    // ── Cursor persistence ────────────────────────────────────────────────

    /// A successful repo sync must stamp the cursor and clear any previous
    /// error, so the next run uses `since=` instead of doing a full re-pull.
    #[test]
    fn persist_repo_synced_sets_cursor_and_clears_previous_error() {
        let dir = temp_dir("persist-ok");
        let repo = crate::github::select_repo(&dir, "a", "b", false, 1).expect("select");
        persist_repo_error(&dir, &repo, "earlier failure".to_string());
        assert_eq!(
            crate::github::list_selected_repos(&dir)[0].last_sync_error.as_deref(),
            Some("earlier failure")
        );
        persist_repo_synced(&dir, &repo, 9_999);
        let after = crate::github::list_selected_repos(&dir);
        assert_eq!(after[0].last_synced_at_unix_ms, Some(9_999));
        assert!(after[0].last_sync_error.is_none(), "success must clear the error");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An error must be persisted so the console can surface it, and it must
    /// NOT advance the cursor (otherwise the failed window would be skipped).
    #[test]
    fn persist_repo_error_records_error_without_advancing_cursor() {
        let dir = temp_dir("persist-err");
        let repo = crate::github::select_repo(&dir, "a", "b", false, 1).expect("select");
        persist_repo_synced(&dir, &repo, 500);
        persist_repo_error(&dir, &repo, "github returned 403".to_string());
        let after = crate::github::list_selected_repos(&dir);
        assert_eq!(after[0].last_sync_error.as_deref(), Some("github returned 403"));
        assert_eq!(after[0].last_synced_at_unix_ms, Some(500), "cursor unchanged");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Persisting for a repo that is no longer in the selected set (operator
    /// unselected it mid-sync) must be a silent no-op, not a panic or a
    /// resurrected entry.
    #[test]
    fn persist_for_unselected_repo_is_a_no_op() {
        let dir = temp_dir("persist-gone");
        let repo = SelectedRepo {
            owner: "ghost".to_string(),
            repo: "gone".to_string(),
            private: false,
            selected_at_unix_ms: 1,
            last_synced_at_unix_ms: None,
            last_sync_error: None,
            planning: false,
        };
        persist_repo_synced(&dir, &repo, 5);
        persist_repo_error(&dir, &repo, "boom".to_string());
        assert!(crate::github::list_selected_repos(&dir).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The sync module writes `selected_repos.json` through its own helper to
    /// avoid a circular dep — that file must stay readable by the owning
    /// module, including the `planning` flag it does not itself use.
    #[test]
    fn write_selected_for_sync_is_readable_by_the_owning_module() {
        let dir = temp_dir("write-compat");
        crate::github::select_repo(&dir, "a", "b", true, 7).expect("select");
        crate::github::set_planning_repo(&dir, "a", "b", true).expect("planning");
        let mut repos = crate::github::list_selected_repos(&dir);
        repos[0].last_synced_at_unix_ms = Some(4_242);
        write_selected_for_sync(&dir, &repos).expect("write");
        let reloaded = crate::github::list_selected_repos(&dir);
        assert_eq!(reloaded.len(), 1);
        assert!(reloaded[0].private);
        assert!(reloaded[0].planning, "planning flag survives the sync-side write");
        assert_eq!(reloaded[0].last_synced_at_unix_ms, Some(4_242));
        assert_eq!(reloaded[0].selected_at_unix_ms, 7);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_selected_for_sync_creates_missing_directories() {
        let dir = temp_dir("write-mkdir");
        write_selected_for_sync(&dir, &[]).expect("write into a fresh data dir");
        assert!(dir
            .join("integrations")
            .join("github")
            .join("selected_repos.json")
            .exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── Payload parsing: defaults and rejection ───────────────────────────

    /// GitHub omits `commit.author` on some rewritten history; the record must
    /// still parse with empty strings rather than being dropped.
    #[test]
    fn parse_commit_tolerates_missing_author_and_parents() {
        let raw = serde_json::json!({ "sha": "deadbeef", "commit": {} });
        let rec = parse_commit(&raw).expect("parsed");
        assert_eq!(rec.sha, "deadbeef");
        assert_eq!(rec.message, "");
        assert_eq!(rec.author_name, "");
        assert_eq!(rec.committed_at, "");
        assert!(rec.author_login.is_none());
        assert!(rec.parents.is_empty());
        assert_eq!(rec.html_url, "");
    }

    /// A payload with no `commit` object at all is not a commit — it must be
    /// rejected, not stored as a fact with an empty message.
    #[test]
    fn parse_commit_without_commit_object_returns_none() {
        assert!(parse_commit(&serde_json::json!({ "sha": "abc" })).is_none());
    }

    #[test]
    fn parse_commit_with_non_string_sha_returns_none() {
        assert!(parse_commit(&serde_json::json!({ "sha": 42, "commit": {} })).is_none());
    }

    /// The entity id is keyed off the PR number, so a payload without a
    /// numeric `number` must be dropped rather than collapsing onto one entity.
    #[test]
    fn parse_pr_without_number_returns_none() {
        assert!(parse_pr(&serde_json::json!({ "title": "x" })).is_none());
        assert!(parse_pr(&serde_json::json!({ "number": "42" })).is_none());
    }

    #[test]
    fn parse_pr_defaults_missing_fields_and_keeps_null_timestamps_absent() {
        let raw = serde_json::json!({ "number": 1 });
        let pr = parse_pr(&raw).expect("parsed");
        assert_eq!(pr.title, "");
        assert_eq!(pr.state, "");
        assert!(pr.author_login.is_none());
        assert!(pr.merged_at.is_none());
        assert!(pr.closed_at.is_none());
        assert_eq!(pr.head_sha, "");
        assert_eq!(pr.base_branch, "");
        assert_eq!(pr.body, "");
    }

    /// A merged PR carries both timestamps; an open one carries neither. The
    /// `null` JSON value must map to `None`, not to the string "null".
    #[test]
    fn parse_pr_maps_json_null_timestamps_to_none() {
        let raw = serde_json::json!({
            "number": 9,
            "merged_at": serde_json::Value::Null,
            "closed_at": "2026-05-02T00:00:00Z",
            "body": serde_json::Value::Null,
        });
        let pr = parse_pr(&raw).expect("parsed");
        assert!(pr.merged_at.is_none());
        assert_eq!(pr.closed_at.as_deref(), Some("2026-05-02T00:00:00Z"));
        assert_eq!(pr.body, "", "a null body becomes an empty string");
    }

    /// `merged_at` is what distinguishes a merged PR from a closed one; it must
    /// survive the round trip through the stored JSON value.
    #[test]
    fn pr_record_round_trips_through_json() {
        let raw = serde_json::json!({
            "number": 42,
            "title": "fix",
            "state": "closed",
            "user": { "login": "alice" },
            "created_at": "2026-05-01T10:00:00Z",
            "updated_at": "2026-05-01T11:00:00Z",
            "merged_at": "2026-05-01T11:30:00Z",
            "head": { "sha": "abc" },
            "base": { "ref": "main" },
            "body": "b",
            "html_url": "u"
        });
        let pr = parse_pr(&raw).expect("parsed");
        let encoded = serde_json::to_string(&pr).expect("encode");
        let decoded: PrRecord = serde_json::from_str(&encoded).expect("decode");
        assert_eq!(decoded.merged_at.as_deref(), Some("2026-05-01T11:30:00Z"));
        assert!(decoded.closed_at.is_none());
        assert_eq!(decoded.number, 42);
    }

    #[test]
    fn parse_issue_without_number_returns_none() {
        assert!(parse_issue(&serde_json::json!({ "title": "x" })).is_none());
    }

    /// Labels come back as objects; entries without a `name` (and a non-array
    /// `labels`) must degrade to an empty list rather than dropping the issue.
    #[test]
    fn parse_issue_tolerates_malformed_labels() {
        let unnamed = serde_json::json!({ "number": 1, "labels": [ { "colour": "red" }, { "name": "bug" } ] });
        assert_eq!(parse_issue(&unnamed).expect("parsed").labels, vec!["bug".to_string()]);

        let not_an_array = serde_json::json!({ "number": 2, "labels": "bug" });
        assert!(parse_issue(&not_an_array).expect("parsed").labels.is_empty());

        let missing = serde_json::json!({ "number": 3 });
        assert!(parse_issue(&missing).expect("parsed").labels.is_empty());
    }

    #[test]
    fn parse_comment_without_id_returns_none() {
        assert!(parse_comment(&serde_json::json!({ "body": "hi" })).is_none());
    }

    /// `parent_number` is derived by string-splitting `issue_url`. A missing or
    /// non-numeric tail must yield `None` rather than a bogus parent link.
    #[test]
    fn parse_comment_parent_number_is_none_for_unusable_issue_url() {
        let no_url = parse_comment(&serde_json::json!({ "id": 1 })).expect("parsed");
        assert!(no_url.parent_number.is_none());

        let non_numeric =
            parse_comment(&serde_json::json!({ "id": 2, "issue_url": "https://api.github.com/repos/o/r/issues/abc" }))
                .expect("parsed");
        assert!(non_numeric.parent_number.is_none());

        let trailing_slash =
            parse_comment(&serde_json::json!({ "id": 3, "issue_url": "https://api.github.com/repos/o/r/issues/7/" }))
                .expect("parsed");
        assert!(
            trailing_slash.parent_number.is_none(),
            "a trailing slash makes the last segment empty"
        );
    }

    // ── parse_work_mentions ───────────────────────────────────────────────

    #[test]
    fn parse_work_mentions_on_text_without_markers_is_empty() {
        assert!(parse_work_mentions("").is_empty());
        assert!(parse_work_mentions("no markers here at all").is_empty());
        assert!(parse_work_mentions("[work").is_empty(), "truncated prefix");
    }

    /// An empty marker (`[work:]`) is not an id and must be dropped.
    #[test]
    fn parse_work_mentions_rejects_empty_id() {
        assert!(parse_work_mentions("[work:]").is_empty());
    }

    /// Repeated mentions of the same id are returned once per occurrence, in
    /// document order — the caller dedups, the parser does not.
    #[test]
    fn parse_work_mentions_preserves_duplicates_in_document_order() {
        let ids = parse_work_mentions("[work:b] then [work:a] then [work:b]");
        assert_eq!(ids, vec!["b".to_string(), "a".to_string(), "b".to_string()]);
    }

    /// Regression for the malformed-span rewind: after rejecting
    /// `[work:bad id]` the scanner must not skip past a valid marker that
    /// starts inside the rejected span.
    #[test]
    fn parse_work_mentions_recovers_from_a_nested_marker() {
        let ids = parse_work_mentions("[work:bad [work:good]");
        assert_eq!(ids, vec!["good".to_string()]);
    }

    #[test]
    fn parse_work_mentions_accepts_hyphens_underscores_and_digits() {
        let ids = parse_work_mentions("[work:a-b_c9]");
        assert_eq!(ids, vec!["a-b_c9".to_string()]);
    }

    /// Multi-byte text must not panic the byte-wise scanner.
    #[test]
    fn parse_work_mentions_handles_multibyte_text() {
        let ids = parse_work_mentions("héllo — [work:unicode-ok] — 日本語");
        assert_eq!(ids, vec!["unicode-ok".to_string()]);
    }

    // ── Small helpers ─────────────────────────────────────────────────────

    /// `since=` goes into a query string; RFC3339 colons and the `+` in an
    /// offset must be percent-encoded or GitHub reads a different instant.
    #[test]
    fn urlencoding_escapes_rfc3339_timestamps() {
        assert_eq!(urlencoding("2026-05-01T12:00:00Z"), "2026-05-01T12%3A00%3A00Z");
        assert_eq!(urlencoding("a+b"), "a%2Bb");
        assert_eq!(urlencoding("a&b=c"), "a%26b%3Dc");
        assert_eq!(urlencoding("-_.~"), "-_.~", "unreserved characters pass through");
    }

    #[test]
    fn truncate_appends_ellipsis_only_when_over_limit() {
        assert_eq!(truncate("short", 32), "short");
        assert_eq!(truncate("abcdef", 6), "abcdef");
        assert_eq!(truncate("abcdef", 2), "ab...");
    }

    #[test]
    fn current_unix_ms_is_after_2020() {
        assert!(current_unix_ms() > 1_577_836_800_000, "clock reads before 2020");
    }

    // ── Outcome shapes ────────────────────────────────────────────────────

    /// The additive counters are `#[serde(default)]`, so an outcome recorded by
    /// an older build (commits only) must still deserialise.
    #[test]
    fn repo_sync_outcome_deserialises_legacy_commit_only_shape() {
        let legacy = serde_json::json!({
            "owner": "a", "repo": "b", "commits_added": 3, "commits_skipped": 1
        });
        let outcome: RepoSyncOutcome = serde_json::from_value(legacy).expect("decode");
        assert_eq!(outcome.commits_added, 3);
        assert_eq!(outcome.prs_added, 0);
        assert_eq!(outcome.issues_added, 0);
        assert_eq!(outcome.comments_added, 0);
        assert!(outcome.error.is_none());
    }

    /// A clean outcome must not emit `"error": null` — the console treats the
    /// presence of the key as "this repo failed".
    #[test]
    fn repo_sync_outcome_omits_error_when_absent() {
        let json = serde_json::to_value(RepoSyncOutcome::default()).expect("encode");
        assert!(json.get("error").is_none());
        let failed = RepoSyncOutcome {
            error: Some("boom".to_string()),
            ..RepoSyncOutcome::default()
        };
        assert_eq!(
            serde_json::to_value(failed).expect("encode")["error"],
            serde_json::json!("boom")
        );
    }

    #[test]
    fn sync_run_result_round_trips() {
        let result = SyncRunResult {
            started_at_unix_ms: 1,
            finished_at_unix_ms: 2,
            repos: vec![RepoSyncOutcome {
                owner: "a".to_string(),
                repo: "b".to_string(),
                commits_added: 1,
                ..RepoSyncOutcome::default()
            }],
        };
        let encoded = serde_json::to_string(&result).expect("encode");
        let decoded: SyncRunResult = serde_json::from_str(&encoded).expect("decode");
        assert_eq!(decoded.repos.len(), 1);
        assert_eq!(decoded.repos[0].owner, "a");
        assert_eq!(decoded.finished_at_unix_ms, 2);
    }

    /// The entity template documents the layout the MCP tool descriptions
    /// promise; the sync writer must keep producing exactly that shape.
    #[test]
    fn commit_entity_template_matches_the_written_entity() {
        assert_eq!(COMMIT_ENTITY_TEMPLATE, "github::{owner}/{repo}::commit/{sha}");
        let built = format!("github::{}/{}::commit/{}", "cuecrux", "Crux", "abc123");
        let rendered = COMMIT_ENTITY_TEMPLATE
            .replace("{owner}", "cuecrux")
            .replace("{repo}", "Crux")
            .replace("{sha}", "abc123");
        assert_eq!(built, rendered);
    }
}
