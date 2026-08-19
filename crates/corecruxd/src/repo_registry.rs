// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Tenant-scoped repository registry stored as reserved daemon facts.

use corecrux_memory::fact_store::{FactQuery, FactStore, StoreFact};
use serde::{Deserialize, Serialize};

pub const REPO_REGISTRY_PREFIX: &str = "__repo_registry__";
pub const REPO_SCAN_PREFIX: &str = "__repo_scan__";
pub const REPO_FACT_KEY: &str = "content";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RepoRegistration {
    pub repo_id: String,
    pub tenant_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clone_url: Option<String>,
    #[serde(default)]
    pub languages: Vec<String>,
    pub enabled: bool,
    pub added_at_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_scan_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scan_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scan_error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scan_queued_at_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scan_finished_at_unix_ms: Option<u64>,
}

#[derive(Debug, thiserror::Error)]
pub enum RepoRegistryError {
    #[error("invalid tenant id '{0}'")]
    InvalidTenantId(String),
    #[error("invalid repo id '{0}': must be lowercase alphanumeric with - or _, length 1..=96")]
    InvalidRepoId(String),
    #[error("repo '{repo_id}' already exists for tenant '{tenant_id}'")]
    Duplicate { tenant_id: String, repo_id: String },
    #[error("repo '{repo_id}' not found for tenant '{tenant_id}'")]
    NotFound { tenant_id: String, repo_id: String },
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

pub fn registry_entity(tenant_id: &str, repo_id: &str) -> String {
    format!("{REPO_REGISTRY_PREFIX}::{tenant_id}::{repo_id}")
}

pub fn scan_entity(tenant_id: &str, repo_id: &str) -> String {
    format!("{REPO_SCAN_PREFIX}::{tenant_id}::{repo_id}::latest")
}

pub fn slug(input: &str) -> String {
    let trimmed = input.trim().trim_end_matches('/');
    let leaf = trimmed.rsplit(['/', '\\', ':']).next().unwrap_or(trimmed);
    let leaf = leaf.strip_suffix(".git").unwrap_or(leaf);
    let mut out = String::new();
    let mut last_dash = false;
    for ch in leaf.chars().flat_map(char::to_lowercase) {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            out.push(ch);
            last_dash = false;
        } else if !last_dash {
            out.push('-');
            last_dash = true;
        }
    }
    let slug = out.trim_matches('-').to_string();
    if slug.is_empty() {
        "repo".to_string()
    } else {
        slug
    }
}

pub fn validate_tenant_id(id: &str) -> Result<(), RepoRegistryError> {
    if id.is_empty() || id.len() > 128 || id.contains("::") {
        return Err(RepoRegistryError::InvalidTenantId(id.to_string()));
    }
    let ok = id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@'));
    if ok {
        Ok(())
    } else {
        Err(RepoRegistryError::InvalidTenantId(id.to_string()))
    }
}

pub fn validate_repo_id(id: &str) -> Result<(), RepoRegistryError> {
    if id.is_empty() || id.len() > 96 {
        return Err(RepoRegistryError::InvalidRepoId(id.to_string()));
    }
    let ok = id
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_');
    if ok {
        Ok(())
    } else {
        Err(RepoRegistryError::InvalidRepoId(id.to_string()))
    }
}

/// List every registration under `prefix`, latest version per repo.
///
/// Uses [`FactStore::latest_by_entity_prefix`] — NOT `query { top_k }` +
/// `dedup_latest`. The query path truncates to `top_k` before dedup collapses
/// versions, and every in-place rescan appends registration versions
/// (pending/running/done — see `http/repos.rs`), so a fixed page silently
/// dropped repos once `repos × versions` crossed it: 954 registered repos
/// listed as 666 after one full rescan (issue #720).
fn list_registrations(store: &FactStore, prefix: &str) -> Vec<RepoRegistration> {
    let mut repos = Vec::new();
    for fact in store.latest_by_entity_prefix(prefix) {
        if fact.key != REPO_FACT_KEY {
            continue;
        }
        if let Ok(registration) = serde_json::from_str::<RepoRegistration>(&fact.value) {
            repos.push(registration);
        }
    }
    repos
}

pub fn list_repos(store: &FactStore, tenant_id: &str) -> Vec<RepoRegistration> {
    let prefix = format!("{REPO_REGISTRY_PREFIX}::{tenant_id}::");
    let mut repos = list_registrations(store, &prefix);
    repos.sort_by(|a, b| a.repo_id.cmp(&b.repo_id));
    repos
}

pub fn list_all_repos(store: &FactStore) -> Vec<RepoRegistration> {
    let mut repos = list_registrations(store, &format!("{REPO_REGISTRY_PREFIX}::"));
    repos.sort_by(|a, b| a.tenant_id.cmp(&b.tenant_id).then_with(|| a.repo_id.cmp(&b.repo_id)));
    repos
}

pub fn get_repo(store: &FactStore, tenant_id: &str, repo_id: &str) -> Option<RepoRegistration> {
    let entity = registry_entity(tenant_id, repo_id);
    let result = store.query(&FactQuery {
        min_effective_confidence: None,
        tenant_hash: None,
        query: None,
        entity: Some(entity),
        entity_prefix: None,
        top_k: 10,
        token_budget: None,
    });
    crate::fact_helpers::dedup_latest(result.facts)
        .into_iter()
        .filter(|fact| fact.key == REPO_FACT_KEY)
        .find_map(|fact| serde_json::from_str::<RepoRegistration>(&fact.value).ok())
}

pub fn store_repo(store: &mut FactStore, registration: &RepoRegistration) -> Result<(), RepoRegistryError> {
    validate_tenant_id(&registration.tenant_id)?;
    validate_repo_id(&registration.repo_id)?;
    let value = serde_json::to_string(registration)?;
    store.store(StoreFact {
        tenant_hash: "default".to_string(),
        entity: registry_entity(&registration.tenant_id, &registration.repo_id),
        key: REPO_FACT_KEY.to_string(),
        value,
        source_receipt: None,
        confidence: 1.0,
        private: true,
        horizon_class: None,
        actor: None,
    });
    Ok(())
}

pub fn create_repo(store: &mut FactStore, registration: &RepoRegistration) -> Result<(), RepoRegistryError> {
    if get_repo(store, &registration.tenant_id, &registration.repo_id).is_some() {
        return Err(RepoRegistryError::Duplicate {
            tenant_id: registration.tenant_id.clone(),
            repo_id: registration.repo_id.clone(),
        });
    }
    store_repo(store, registration)
}

pub fn fail_incomplete_scans(
    store: &mut FactStore,
    error: &str,
    finished_at_unix_ms: u64,
) -> Result<usize, RepoRegistryError> {
    let mut updated = 0usize;
    for mut registration in list_all_repos(store) {
        let Some(status) = registration.scan_status.as_deref() else {
            continue;
        };
        if !matches!(status, "pending" | "running") {
            continue;
        }
        registration.scan_status = Some("failed".to_string());
        registration.scan_error = Some(error.to_string());
        registration.scan_finished_at_unix_ms = Some(finished_at_unix_ms);
        store_repo(store, &registration)?;
        updated = updated.saturating_add(1);
    }
    Ok(updated)
}

/// Read back the latest persisted scan JSON for a registered repo — the
/// mirror of [`store_scan_json`]. `None` when the repo was registered by
/// `clone_url` only (scan deferred) or has never been scanned.
/// Takes a [`TenantScope`](crate::auth::TenantScope) rather than a tenant
/// string: the caller must have *obtained* the right to read this tenant, not
/// merely be able to spell it. Background callers with no request behind them
/// mint one through `TenantScope::background`, which records why.
pub fn load_scan_json(store: &FactStore, scope: &crate::auth::TenantScope, repo_id: &str) -> Option<String> {
    let tenant_id = scope.as_str();
    let entity = scan_entity(tenant_id, repo_id);
    let result = store.query(&FactQuery {
        min_effective_confidence: None,
        tenant_hash: None,
        query: None,
        entity: Some(entity),
        entity_prefix: None,
        top_k: 10,
        token_budget: None,
    });
    crate::fact_helpers::dedup_latest(result.facts)
        .into_iter()
        .find(|fact| fact.key == REPO_FACT_KEY)
        .map(|fact| fact.value)
}

pub fn store_scan_json(store: &mut FactStore, tenant_id: &str, repo_id: &str, scan_json: String) {
    store.store(StoreFact {
        tenant_hash: "default".to_string(),
        entity: scan_entity(tenant_id, repo_id),
        key: REPO_FACT_KEY.to_string(),
        value: scan_json,
        source_receipt: None,
        confidence: 1.0,
        private: true,
        horizon_class: None,
        actor: None,
    });
}

pub fn delete_repo(store: &mut FactStore, tenant_id: &str, repo_id: &str) -> Result<(), RepoRegistryError> {
    if get_repo(store, tenant_id, repo_id).is_none() {
        return Err(RepoRegistryError::NotFound {
            tenant_id: tenant_id.to_string(),
            repo_id: repo_id.to_string(),
        });
    }
    for entity in [
        registry_entity(tenant_id, repo_id),
        scan_entity(tenant_id, repo_id),
        crate::repo_codegraph::ids_entity(tenant_id, repo_id),
        crate::repo_codegraph::extdeps_entity(tenant_id, repo_id),
    ] {
        let facts = store.get_by_entity(&entity);
        let ids: Vec<(String, String)> = facts
            .into_iter()
            .map(|fact| (fact.tenant_hash.clone(), fact.fact_id.clone()))
            .collect();
        for (tenant_hash, fact_id) in ids {
            store.delete(&tenant_hash, &fact_id);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registration(repo_id: &str, status: Option<&str>) -> RepoRegistration {
        RepoRegistration {
            repo_id: repo_id.to_string(),
            tenant_id: "tenant-a".to_string(),
            root_path: Some("/tmp/repo".to_string()),
            clone_url: None,
            languages: vec!["rust".to_string()],
            enabled: true,
            added_at_unix_ms: 1,
            last_scan_id: None,
            scan_status: status.map(str::to_string),
            scan_error: None,
            scan_queued_at_unix_ms: Some(2),
            scan_finished_at_unix_ms: None,
        }
    }

    #[test]
    fn old_registration_json_decodes_without_scan_fields() {
        let json = r#"{
            "repo_id":"fixture",
            "tenant_id":"tenant-a",
            "root_path":"/tmp/fixture",
            "languages":["rust"],
            "enabled":true,
            "added_at_unix_ms":1,
            "last_scan_id":"ws_1"
        }"#;
        let decoded: RepoRegistration = serde_json::from_str(json).expect("decode old registration");
        assert_eq!(decoded.repo_id, "fixture");
        assert_eq!(decoded.last_scan_id.as_deref(), Some("ws_1"));
        assert!(decoded.scan_status.is_none());
        assert!(decoded.scan_error.is_none());
        assert!(decoded.scan_queued_at_unix_ms.is_none());
        assert!(decoded.scan_finished_at_unix_ms.is_none());
    }

    #[test]
    fn fail_incomplete_scans_marks_pending_and_running_failed() {
        let mut store = FactStore::new();
        for reg in [
            registration("pending", Some("pending")),
            registration("running", Some("running")),
            registration("done", Some("done")),
            registration("legacy", None),
        ] {
            store_repo(&mut store, &reg).expect("store repo");
        }

        let count = fail_incomplete_scans(&mut store, "daemon restarted before scan completed", 99)
            .expect("recover incomplete scans");
        assert_eq!(count, 2);

        let pending = get_repo(&store, "tenant-a", "pending").expect("pending repo");
        assert_eq!(pending.scan_status.as_deref(), Some("failed"));
        assert_eq!(
            pending.scan_error.as_deref(),
            Some("daemon restarted before scan completed")
        );
        assert_eq!(pending.scan_finished_at_unix_ms, Some(99));

        let running = get_repo(&store, "tenant-a", "running").expect("running repo");
        assert_eq!(running.scan_status.as_deref(), Some("failed"));

        let done = get_repo(&store, "tenant-a", "done").expect("done repo");
        assert_eq!(done.scan_status.as_deref(), Some("done"));

        let legacy = get_repo(&store, "tenant-a", "legacy").expect("legacy repo");
        assert!(legacy.scan_status.is_none());
    }

    /// Regression for issue #720: every in-place rescan (`POST .../rescan`)
    /// appends registration versions (pending → running → done, see
    /// `http/repos.rs`), and the old list path fetched at most `top_k = 2_000`
    /// fact versions BEFORE `dedup_latest` collapsed them — so after one full
    /// rescan of 954 repos (× 4 versions = 3_816 rows) `GET /v1/repos` listed
    /// only 666 repos. The listing must return every repo exactly once, at its
    /// latest version, however many versions accumulate.
    #[test]
    fn list_repos_lists_every_repo_once_when_versions_exceed_any_page() {
        let mut store = FactStore::new();
        let repo_count = 954usize;
        for i in 0..repo_count {
            let mut reg = registration(&format!("repo-{i:04}"), None);
            store_repo(&mut store, &reg).expect("register repo");
            // One full in-place rescan cycle: three more registration versions.
            for status in ["pending", "running", "done"] {
                reg.scan_status = Some(status.to_string());
                store_repo(&mut store, &reg).expect("rescan status write");
            }
        }

        let listed = list_repos(&store, "tenant-a");
        assert_eq!(
            listed.len(),
            repo_count,
            "all repos listed exactly once (954 -> 666 was the bug)"
        );
        let mut seen = std::collections::HashSet::new();
        for reg in &listed {
            assert!(
                seen.insert(reg.repo_id.clone()),
                "duplicate listing for {}",
                reg.repo_id
            );
            assert_eq!(
                reg.scan_status.as_deref(),
                Some("done"),
                "{}: latest registration version wins",
                reg.repo_id
            );
        }
    }

    /// Cross-tenant sibling of the #720 regression: `list_all_repos` (used by
    /// scan recovery and admin surfaces) must also count repos, not versions,
    /// and keep each latest registration per tenant.
    #[test]
    fn list_all_repos_lists_every_tenant_repo_once_despite_versions() {
        let mut store = FactStore::new();
        for tenant in ["tenant-a", "tenant-b"] {
            for i in 0..3 {
                let mut reg = registration(&format!("repo-{i}"), Some("pending"));
                reg.tenant_id = tenant.to_string();
                store_repo(&mut store, &reg).expect("register repo");
                reg.scan_status = Some("done".to_string());
                store_repo(&mut store, &reg).expect("update repo");
            }
        }

        let listed = list_all_repos(&store);
        assert_eq!(listed.len(), 6, "one row per (tenant, repo)");
        assert!(listed.iter().all(|r| r.scan_status.as_deref() == Some("done")));
        assert_eq!(listed.iter().filter(|r| r.tenant_id == "tenant-a").count(), 3);
        assert_eq!(listed.iter().filter(|r| r.tenant_id == "tenant-b").count(), 3);
    }
}
