// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! GitHub commit sync — pull commits from selected repos via api.github.com,
//! write each as a fact under `github::owner/repo::commit/{sha}`. Polled by
//! a tokio task on a fixed cadence and triggerable by hand via
//! `POST /v1/integrations/github/sync`.

#![allow(dead_code)] // sync constants + helpers used conditionally
#![allow(clippy::format_push_string)] // builder pattern

use std::path::Path;

use corecrux_memory::fact_store::{FactStore, StoreFact};
use serde::{Deserialize, Serialize};

use crate::integrations_github::{
    decrypt_pat, list_selected_repos, read_credentials, GithubIntegrationError, SelectedRepo,
};

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

/// Sync entry point — needs the integration encryption key (held in AppState).
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
}
