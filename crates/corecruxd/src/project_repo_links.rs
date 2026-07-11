// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Project ↔ GitHub-repo links.
//!
//! Stored as facts under `__project_repo_link__::{project_id}::{owner}/{repo}`
//! key=`record`. Each link records:
//! - `plane_id` (optional) — when set, the link is scoped to a specific plane
//!   inside the project; otherwise the link is project-level.
//! - `role` — one of `planning` (single canonical planning repo) /
//!   `work` (active development) / `reference` (read-only context).
//! - `linked_at_unix_ms` and `linked_by_passport` for provenance.
//!
//! The actual GitHub credentials + the indexed-repo set still live under the
//! GitHub integration module (`integrations_github`) — this module only
//! records the *project-scoped semantics* of "which linked repos belong to
//! which project, and which plane within that project."

#![allow(dead_code)] // API helper kept for symmetry; may be wired by future endpoint

use corecrux_memory::fact_store::{FactQuery, FactStore, StoreFact};
use serde::{Deserialize, Serialize};

pub const REPO_LINK_PREFIX: &str = "__project_repo_link__";
const REPO_LINK_KEY: &str = "record";

#[derive(Debug, thiserror::Error)]
pub enum RepoLinkError {
    #[error("invalid owner/repo '{0}' (must look like 'owner/repo')")]
    InvalidRepo(String),
    #[error("invalid role '{0}' — must be planning|work|reference")]
    InvalidRole(String),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RepoLink {
    pub project_id: String,
    pub owner: String,
    pub repo: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plane_id: Option<String>,
    pub role: String,
    pub linked_at_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linked_by_passport: Option<String>,
}

impl RepoLink {
    pub fn slug(&self) -> String {
        format!("{}/{}", self.owner, self.repo)
    }
}

pub fn validate_repo_slug(slug: &str) -> Result<(String, String), RepoLinkError> {
    let parts: Vec<&str> = slug.split('/').collect();
    if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
        return Err(RepoLinkError::InvalidRepo(slug.to_string()));
    }
    Ok((parts[0].to_string(), parts[1].to_string()))
}

pub fn validate_role(role: &str) -> Result<String, RepoLinkError> {
    match role {
        "planning" | "work" | "reference" => Ok(role.to_string()),
        _ => Err(RepoLinkError::InvalidRole(role.to_string())),
    }
}

fn entity(project_id: &str, owner: &str, repo: &str) -> String {
    format!("{REPO_LINK_PREFIX}::{project_id}::{owner}/{repo}")
}

pub fn link_repo(
    store: &mut FactStore,
    project_id: &str,
    repo_slug: &str,
    plane_id: Option<String>,
    role: &str,
    linked_by_passport: Option<String>,
    now_unix_ms: u64,
) -> Result<RepoLink, RepoLinkError> {
    let (owner, repo) = validate_repo_slug(repo_slug)?;
    let role = validate_role(role)?;
    let link = RepoLink {
        project_id: project_id.to_string(),
        owner: owner.clone(),
        repo: repo.clone(),
        plane_id: plane_id.filter(|s| !s.trim().is_empty()),
        role,
        linked_at_unix_ms: now_unix_ms,
        linked_by_passport: linked_by_passport.filter(|s| !s.trim().is_empty()),
    };
    let value = serde_json::to_string(&link)?;
    let mut sf = StoreFact {
        tenant_hash: "default".to_string(),
        entity: entity(project_id, &owner, &repo),
        key: REPO_LINK_KEY.to_string(),
        value,
        source_receipt: None,
        confidence: 1.0,
        private: false,
        horizon_class: None,
        actor: None,
    };
    crate::fact_privacy::enforce_global(&mut sf);
    store.store(sf);
    Ok(link)
}

pub fn unlink_repo(store: &mut FactStore, project_id: &str, repo_slug: &str) -> Result<(), RepoLinkError> {
    let (owner, repo) = validate_repo_slug(repo_slug)?;
    let mut sf = StoreFact {
        tenant_hash: "default".to_string(),
        entity: entity(project_id, &owner, &repo),
        key: REPO_LINK_KEY.to_string(),
        value: String::new(),
        source_receipt: None,
        confidence: 0.0,
        private: false,
        horizon_class: None,
        actor: None,
    };
    crate::fact_privacy::enforce_global(&mut sf);
    store.store(sf);
    Ok(())
}

pub fn list_links(store: &FactStore, project_id: &str) -> Vec<RepoLink> {
    let prefix = format!("{REPO_LINK_PREFIX}::{project_id}::");
    let result = store.query(&FactQuery {
        tenant_hash: None,
        query: Some(prefix.clone()),
        entity: None,
        entity_prefix: None,
        top_k: 500,
        token_budget: None,
    });
    let latest = crate::fact_helpers::dedup_latest(result.facts);
    latest
        .into_iter()
        .filter(|f| f.entity.starts_with(&prefix) && f.key == REPO_LINK_KEY && !f.value.is_empty())
        .filter_map(|f| serde_json::from_str::<RepoLink>(&f.value).ok())
        .collect()
}

pub fn list_links_for_plane(store: &FactStore, project_id: &str, plane_id: &str) -> Vec<RepoLink> {
    list_links(store, project_id)
        .into_iter()
        .filter(|l| l.plane_id.as_deref() == Some(plane_id))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> FactStore {
        FactStore::new()
    }

    #[test]
    fn validate_repo_slug_accepts_owner_slash_repo() {
        assert_eq!(
            validate_repo_slug("CueCrux/PlanCrux").unwrap(),
            ("CueCrux".into(), "PlanCrux".into())
        );
        assert!(validate_repo_slug("nope").is_err());
        assert!(validate_repo_slug("a/").is_err());
        assert!(validate_repo_slug("/b").is_err());
    }

    #[test]
    fn link_then_list_round_trips_with_plane_scope() {
        let mut s = store();
        link_repo(
            &mut s,
            "p",
            "CueCrux/PlanCrux",
            Some("daemon".into()),
            "planning",
            Some("agent-claude".into()),
            1_000,
        )
        .unwrap();
        link_repo(
            &mut s,
            "p",
            "CueCrux/Crux",
            None,
            "work",
            Some("agent-claude".into()),
            1_001,
        )
        .unwrap();
        let all = list_links(&s, "p");
        assert_eq!(all.len(), 2);
        let plane_only = list_links_for_plane(&s, "p", "daemon");
        assert_eq!(plane_only.len(), 1);
        assert_eq!(plane_only[0].repo, "PlanCrux");
    }

    #[test]
    fn invalid_role_rejected() {
        let mut s = store();
        assert!(link_repo(&mut s, "p", "a/b", None, "junk", None, 1).is_err());
    }
}
