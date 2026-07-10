// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! GitHub integration — encrypted PAT storage + verification + status.
//!
//! On-disk layout (under `data_dir/integrations/github/`):
//!
//! - `credentials.json` — `GithubCredentials { encrypted_pat, username, scopes,
//!   connected_at_unix_ms, last_verified_at_unix_ms? }`. The PAT itself never
//!   appears in plaintext; the envelope is sealed with the daemon-root
//!   passport-derived key (see `crate::encrypted_secrets`).
//!
//! Future (G2): `selected_repos.json` for the operator-selected repo set.

#![allow(dead_code)] // integration scaffolding kept for upcoming PAT-rotation flow

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::encrypted_secrets::{EncryptedEnvelope, EncryptedSecretError};

#[derive(Debug, thiserror::Error)]
pub enum GithubIntegrationError {
    #[error("not connected: no credentials on disk")]
    NotConnected,
    #[error("PAT verification failed: {0}")]
    VerifyFailed(String),
    #[error("network: {0}")]
    Network(String),
    #[error(transparent)]
    Encryption(#[from] EncryptedSecretError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GithubCredentials {
    pub encrypted_pat: EncryptedEnvelope,
    pub username: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    pub connected_at_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_verified_at_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GithubStatus {
    pub connected: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connected_at_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_verified_at_unix_ms: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct VerifiedUser {
    pub username: String,
    pub scopes: Vec<String>,
}

pub fn read_status(data_dir: &Path) -> GithubStatus {
    match read_credentials(data_dir) {
        Ok(creds) => GithubStatus {
            connected: true,
            username: Some(creds.username),
            scopes: creds.scopes,
            connected_at_unix_ms: Some(creds.connected_at_unix_ms),
            last_verified_at_unix_ms: creds.last_verified_at_unix_ms,
        },
        Err(_) => GithubStatus {
            connected: false,
            username: None,
            scopes: Vec::new(),
            connected_at_unix_ms: None,
            last_verified_at_unix_ms: None,
        },
    }
}

pub fn read_credentials(data_dir: &Path) -> Result<GithubCredentials, GithubIntegrationError> {
    let path = credentials_path(data_dir);
    if !path.exists() {
        return Err(GithubIntegrationError::NotConnected);
    }
    let bytes = fs::read(&path)?;
    let creds: GithubCredentials = serde_json::from_slice(&bytes)?;
    Ok(creds)
}

pub fn write_credentials(data_dir: &Path, creds: &GithubCredentials) -> Result<(), GithubIntegrationError> {
    let path = credentials_path(data_dir);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, serde_json::to_vec_pretty(creds)?)?;
    fs::rename(tmp, &path)?;
    set_owner_only_perms(&path)?;
    Ok(())
}

pub fn delete_credentials(data_dir: &Path) -> Result<(), GithubIntegrationError> {
    let path = credentials_path(data_dir);
    if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(())
}

#[allow(dead_code)] // Used by G3 sync worker — reads PAT for outbound api.github.com calls.
pub fn decrypt_pat(creds: &GithubCredentials, key: &[u8; 32]) -> Result<String, GithubIntegrationError> {
    let bytes = crate::encrypted_secrets::open(&creds.encrypted_pat, key)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Verify a PAT by hitting `GET https://api.github.com/user`. Used at /connect
/// time so we can return the resolved username + scopes immediately. Blocking
/// call — caller must dispatch via `tokio::task::spawn_blocking`.
pub fn verify_pat(pat: &str) -> Result<VerifiedUser, GithubIntegrationError> {
    if pat.trim().is_empty() {
        return Err(GithubIntegrationError::VerifyFailed("PAT is empty".to_string()));
    }
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(10)))
        .build()
        .into();
    let req = agent
        .get("https://api.github.com/user")
        .header("Authorization", &format!("Bearer {}", pat.trim()))
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .header("User-Agent", "crux-daemon");
    let mut response = req.call().map_err(|e| GithubIntegrationError::Network(e.to_string()))?;
    let status = response.status().as_u16();
    let scopes = response
        .headers()
        .get("x-oauth-scopes")
        .and_then(|v| v.to_str().ok())
        .map(|s| {
            s.split(',')
                .map(|p| p.trim().to_string())
                .filter(|p| !p.is_empty())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let body = response
        .body_mut()
        .read_to_string()
        .map_err(|e| GithubIntegrationError::Network(e.to_string()))?;
    if status != 200 {
        return Err(GithubIntegrationError::VerifyFailed(format!(
            "github returned {status}: {}",
            truncate(&body, 256)
        )));
    }
    let parsed: serde_json::Value = serde_json::from_str(&body)?;
    let username = parsed
        .get("login")
        .and_then(|v| v.as_str())
        .ok_or_else(|| GithubIntegrationError::VerifyFailed("no 'login' field in /user response".to_string()))?
        .to_string();
    Ok(VerifiedUser { username, scopes })
}

fn credentials_path(data_dir: &Path) -> PathBuf {
    data_dir.join("integrations").join("github").join("credentials.json")
}

fn selected_repos_path(data_dir: &Path) -> PathBuf {
    data_dir.join("integrations").join("github").join("selected_repos.json")
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SelectedRepo {
    pub owner: String,
    pub repo: String,
    pub private: bool,
    pub selected_at_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_synced_at_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_sync_error: Option<String>,
    /// Operator-flagged: this repo is the canonical planning surface (e.g.
    /// open issues = roadmap). Surfaced on the Project detail page so the
    /// planning-target picker can suggest it.
    #[serde(default)]
    pub planning: bool,
}

impl SelectedRepo {
    pub fn full_name(&self) -> String {
        format!("{}/{}", self.owner, self.repo)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
struct SelectedReposFile {
    #[serde(default)]
    repos: Vec<SelectedRepo>,
}

pub fn list_selected_repos(data_dir: &Path) -> Vec<SelectedRepo> {
    let path = selected_repos_path(data_dir);
    if !path.exists() {
        return Vec::new();
    }
    match fs::read(&path)
        .ok()
        .and_then(|b| serde_json::from_slice::<SelectedReposFile>(&b).ok())
    {
        Some(file) => file.repos,
        None => Vec::new(),
    }
}

pub fn select_repo(
    data_dir: &Path,
    owner: &str,
    repo: &str,
    private: bool,
    now_unix_ms: u64,
) -> Result<SelectedRepo, GithubIntegrationError> {
    let mut repos = list_selected_repos(data_dir);
    if let Some(existing) = repos.iter().find(|r| r.owner == owner && r.repo == repo) {
        // Always upgrade an existing selection's `private` flag if the new
        // call says it's private — never downgrade. This is the safe direction:
        // if a repo became private after first select, treat it as private.
        if private && !existing.private {
            let mut upgraded = existing.clone();
            upgraded.private = true;
            for r in &mut repos {
                if r.owner == owner && r.repo == repo {
                    *r = upgraded.clone();
                }
            }
            write_selected_repos(data_dir, &repos)?;
            return Ok(upgraded);
        }
        return Ok(existing.clone());
    }
    let new = SelectedRepo {
        owner: owner.to_string(),
        repo: repo.to_string(),
        private,
        selected_at_unix_ms: now_unix_ms,
        last_synced_at_unix_ms: None,
        last_sync_error: None,
        planning: false,
    };
    repos.push(new.clone());
    write_selected_repos(data_dir, &repos)?;
    Ok(new)
}

pub fn set_planning_repo(
    data_dir: &Path,
    owner: &str,
    repo: &str,
    planning: bool,
) -> Result<SelectedRepo, GithubIntegrationError> {
    let mut repos = list_selected_repos(data_dir);
    let target = repos
        .iter_mut()
        .find(|r| r.owner == owner && r.repo == repo)
        .ok_or_else(|| {
            GithubIntegrationError::VerifyFailed(format!(
                "repo {owner}/{repo} is not in the selected set; select it first"
            ))
        })?;
    target.planning = planning;
    let updated = target.clone();
    write_selected_repos(data_dir, &repos)?;
    Ok(updated)
}

pub fn unselect_repo(data_dir: &Path, owner: &str, repo: &str) -> Result<(), GithubIntegrationError> {
    let mut repos = list_selected_repos(data_dir);
    repos.retain(|r| !(r.owner == owner && r.repo == repo));
    write_selected_repos(data_dir, &repos)?;
    Ok(())
}

fn write_selected_repos(data_dir: &Path, repos: &[SelectedRepo]) -> Result<(), GithubIntegrationError> {
    let path = selected_repos_path(data_dir);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let file = SelectedReposFile { repos: repos.to_vec() };
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, serde_json::to_vec_pretty(&file)?)?;
    fs::rename(tmp, &path)?;
    set_owner_only_perms(&path)?;
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
pub struct AccessibleRepo {
    pub owner: String,
    pub repo: String,
    pub private: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub default_branch: String,
    pub stargazers_count: u64,
    pub html_url: String,
}

/// Fetch up to `max_pages` of repos accessible to the PAT. Page size 100.
/// Blocking call — caller dispatches via `tokio::task::spawn_blocking`.
pub fn fetch_accessible_repos(pat: &str, max_pages: usize) -> Result<Vec<AccessibleRepo>, GithubIntegrationError> {
    if pat.trim().is_empty() {
        return Err(GithubIntegrationError::VerifyFailed("PAT is empty".to_string()));
    }
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(20)))
        .build()
        .into();
    let mut out = Vec::new();
    for page in 1..=max_pages.max(1) {
        let url = format!(
            "https://api.github.com/user/repos?per_page=100&page={page}&affiliation=owner,collaborator,organization_member&sort=updated"
        );
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
                "github returned {status}: {}",
                truncate(&body, 256)
            )));
        }
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&body)?;
        if parsed.is_empty() {
            break;
        }
        let page_count = parsed.len();
        for repo in parsed {
            let owner = repo
                .get("owner")
                .and_then(|o| o.get("login"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let name = repo.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            if owner.is_empty() || name.is_empty() {
                continue;
            }
            out.push(AccessibleRepo {
                owner,
                repo: name,
                private: repo.get("private").and_then(|v| v.as_bool()).unwrap_or(false),
                description: repo.get("description").and_then(|v| v.as_str()).map(str::to_string),
                default_branch: repo
                    .get("default_branch")
                    .and_then(|v| v.as_str())
                    .unwrap_or("main")
                    .to_string(),
                stargazers_count: repo.get("stargazers_count").and_then(|v| v.as_u64()).unwrap_or(0),
                html_url: repo.get("html_url").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            });
        }
        if page_count < 100 {
            break;
        }
    }
    Ok(out)
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

#[cfg(unix)]
fn set_owner_only_perms(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(path, perms)
}

#[cfg(not(unix))]
fn set_owner_only_perms(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        // nanos alone collides on VMs with coarse clocks (parallel tests
        // land in the same quantum and share a dir) — salt with pid + a counter.
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("corecruxd-github-{name}-{nanos}-{}-{seq}", std::process::id()));
        fs::create_dir_all(&dir).expect("mkdir");
        dir
    }

    fn sample_creds() -> (GithubCredentials, [u8; 32]) {
        let key = [7u8; 32];
        let env = crate::encrypted_secrets::seal(b"github_pat_test_token_12345", &key);
        (
            GithubCredentials {
                encrypted_pat: env,
                username: "octocat".to_string(),
                scopes: vec!["repo".to_string(), "read:org".to_string()],
                connected_at_unix_ms: 1_700_000_000_000,
                last_verified_at_unix_ms: None,
            },
            key,
        )
    }

    #[test]
    fn status_reports_disconnected_when_no_file() {
        let dir = temp_dir("disconn");
        let s = read_status(&dir);
        assert!(!s.connected);
        assert!(s.username.is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_then_read_round_trip_preserves_envelope() {
        let dir = temp_dir("rt");
        let (creds, _) = sample_creds();
        write_credentials(&dir, &creds).expect("write");
        let loaded = read_credentials(&dir).expect("read");
        assert_eq!(loaded, creds);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn status_reports_connected_after_write() {
        let dir = temp_dir("conn");
        let (creds, _) = sample_creds();
        write_credentials(&dir, &creds).expect("write");
        let s = read_status(&dir);
        assert!(s.connected);
        assert_eq!(s.username.as_deref(), Some("octocat"));
        assert_eq!(s.scopes, vec!["repo".to_string(), "read:org".to_string()]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn delete_removes_credentials() {
        let dir = temp_dir("del");
        let (creds, _) = sample_creds();
        write_credentials(&dir, &creds).expect("write");
        delete_credentials(&dir).expect("delete");
        assert!(!read_status(&dir).connected);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn decrypt_pat_round_trip() {
        let (creds, key) = sample_creds();
        let pat = decrypt_pat(&creds, &key).expect("decrypt");
        assert_eq!(pat, "github_pat_test_token_12345");
    }

    #[test]
    fn decrypt_pat_with_wrong_key_fails() {
        let (creds, _) = sample_creds();
        let wrong = [0u8; 32];
        let err = decrypt_pat(&creds, &wrong).expect_err("must fail");
        assert!(matches!(
            err,
            GithubIntegrationError::Encryption(EncryptedSecretError::DecryptionFailed)
        ));
    }

    #[test]
    fn verify_pat_rejects_empty() {
        let err = verify_pat("").expect_err("empty rejected");
        assert!(matches!(err, GithubIntegrationError::VerifyFailed(_)));
    }

    #[test]
    fn select_then_list_round_trip() {
        let dir = temp_dir("select");
        let r = select_repo(&dir, "cuecrux", "Crux", false, 1_000).expect("select");
        assert_eq!(r.full_name(), "cuecrux/Crux");
        let listed = list_selected_repos(&dir);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].full_name(), "cuecrux/Crux");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn select_is_idempotent() {
        let dir = temp_dir("idem");
        select_repo(&dir, "a", "b", false, 1).expect("first");
        select_repo(&dir, "a", "b", false, 2).expect("second");
        assert_eq!(list_selected_repos(&dir).len(), 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn unselect_removes_only_target() {
        let dir = temp_dir("unsel");
        select_repo(&dir, "a", "x", false, 1).expect("a/x");
        select_repo(&dir, "a", "y", false, 1).expect("a/y");
        unselect_repo(&dir, "a", "x").expect("unsel");
        let remaining = list_selected_repos(&dir);
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].full_name(), "a/y");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn fetch_accessible_rejects_empty_pat() {
        let err = fetch_accessible_repos("", 1).expect_err("empty rejected");
        assert!(matches!(err, GithubIntegrationError::VerifyFailed(_)));
    }
}
