// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `corecruxctl repo` — tenant-scoped daemon repository registry commands.

use std::path::Path;

use serde::{Deserialize, Serialize};

type DynErr = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug, Clone, Serialize)]
pub struct AddRepoRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo_id: Option<String>,
    pub tenant_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clone_url: Option<String>,
    #[serde(default)]
    pub languages: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoRegistration {
    pub repo_id: String,
    pub tenant_id: String,
    #[serde(default)]
    pub root_path: Option<String>,
    #[serde(default)]
    pub clone_url: Option<String>,
    #[serde(default)]
    pub languages: Vec<String>,
    pub enabled: bool,
    pub added_at_unix_ms: u64,
    #[serde(default)]
    pub last_scan_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AddRepoResponse {
    pub repo: RepoRegistration,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ListReposResponse {
    pub repos: Vec<RepoRegistration>,
}

fn http_agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(120)))
        .build()
        .into()
}

fn with_bearer(
    mut req: ureq::RequestBuilder<ureq::typestate::WithoutBody>,
    token: Option<&str>,
) -> ureq::RequestBuilder<ureq::typestate::WithoutBody> {
    if let Some(t) = token {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    req
}

fn with_bearer_body(
    mut req: ureq::RequestBuilder<ureq::typestate::WithBody>,
    token: Option<&str>,
) -> ureq::RequestBuilder<ureq::typestate::WithBody> {
    if let Some(t) = token {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    req
}

fn read_json<T: for<'de> Deserialize<'de>>(resp: ureq::http::Response<ureq::Body>) -> Result<T, DynErr> {
    let status = resp.status().as_u16();
    let body = resp.into_body().read_to_string()?;
    if status >= 400 {
        return Err(format!("daemon request failed ({status}): {body}").into());
    }
    Ok(serde_json::from_str(&body)?)
}

pub fn add(base: &str, token: Option<&str>, request: AddRepoRequest) -> Result<AddRepoResponse, DynErr> {
    let agent = http_agent();
    let url = add_url(base);
    let resp = with_bearer_body(agent.post(&url), token).send_json(serde_json::to_value(request)?)?;
    read_json(resp)
}

pub fn list(base: &str, token: Option<&str>, tenant_id: &str) -> Result<ListReposResponse, DynErr> {
    let agent = http_agent();
    let url = list_url(base, tenant_id);
    let resp = with_bearer(agent.get(&url), token).call()?;
    read_json(resp)
}

pub fn remove(base: &str, token: Option<&str>, tenant_id: &str, repo_id: &str) -> Result<(), DynErr> {
    let agent = http_agent();
    let url = remove_url(base, tenant_id, repo_id);
    let resp = with_bearer(agent.delete(&url), token).call()?;
    let status = resp.status().as_u16();
    if status >= 400 {
        let body = resp.into_body().read_to_string().unwrap_or_default();
        return Err(format!("daemon request failed ({status}): {body}").into());
    }
    Ok(())
}

fn add_url(base: &str) -> String {
    format!("{}/v1/repos", base.trim_end_matches('/'))
}

fn list_url(base: &str, tenant_id: &str) -> String {
    format!(
        "{}/v1/repos?tenant_id={}",
        base.trim_end_matches('/'),
        urlencoding::encode(tenant_id)
    )
}

fn remove_url(base: &str, tenant_id: &str, repo_id: &str) -> String {
    format!(
        "{}/v1/repos/{}?tenant_id={}",
        base.trim_end_matches('/'),
        urlencoding::encode(repo_id),
        urlencoding::encode(tenant_id)
    )
}

pub fn run_add(
    base: &str,
    token_file: Option<&Path>,
    tenant_id: String,
    repo_id: Option<String>,
    path: Option<String>,
    clone_url: Option<String>,
    languages: Vec<String>,
) -> Result<(), DynErr> {
    let token = crate::code_health::resolve_token(token_file);
    let response = add(
        base,
        token.as_deref(),
        AddRepoRequest {
            repo_id,
            tenant_id,
            root_path: path,
            clone_url,
            languages,
        },
    )?;
    println!(
        "registered repo {} for tenant {}{}",
        response.repo.repo_id,
        response.repo.tenant_id,
        response
            .repo
            .last_scan_id
            .as_deref()
            .map(|id| format!("; scan {id}"))
            .unwrap_or_default()
    );
    if let Some(note) = response.note {
        println!("{note}");
    }
    Ok(())
}

pub fn run_list(base: &str, token_file: Option<&Path>, tenant_id: &str) -> Result<(), DynErr> {
    let token = crate::code_health::resolve_token(token_file);
    let response = list(base, token.as_deref(), tenant_id)?;
    println!("{}", serde_json::to_string_pretty(&response.repos)?);
    Ok(())
}

pub fn run_remove(base: &str, token_file: Option<&Path>, tenant_id: &str, repo_id: &str) -> Result<(), DynErr> {
    let token = crate::code_health::resolve_token(token_file);
    remove(base, token.as_deref(), tenant_id, repo_id)?;
    println!("removed repo {repo_id} for tenant {tenant_id}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repo_urls_match_daemon_contract() {
        assert_eq!(add_url("http://127.0.0.1:14800/"), "http://127.0.0.1:14800/v1/repos");
        assert_eq!(
            list_url("http://127.0.0.1:14800", "tenant a"),
            "http://127.0.0.1:14800/v1/repos?tenant_id=tenant%20a"
        );
        assert_eq!(
            remove_url("http://127.0.0.1:14800", "tenant/a", "repo one"),
            "http://127.0.0.1:14800/v1/repos/repo%20one?tenant_id=tenant%2Fa"
        );
    }

    #[test]
    fn add_request_serializes_expected_shape() {
        let request = AddRepoRequest {
            repo_id: Some("sample".to_string()),
            tenant_id: "test".to_string(),
            root_path: Some("/tmp/sample".to_string()),
            clone_url: None,
            languages: vec!["rust".to_string()],
        };
        let value = serde_json::to_value(request).expect("serialize request");
        assert_eq!(value["repo_id"], "sample");
        assert_eq!(value["tenant_id"], "test");
        assert_eq!(value["root_path"], "/tmp/sample");
        assert!(value.get("clone_url").is_none());
        assert_eq!(value["languages"][0], "rust");
    }
}
