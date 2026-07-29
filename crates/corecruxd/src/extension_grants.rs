// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Per-passport grants for community extensions (M3 of the
//! community-extensions ExecPlan).
//!
//! Each grant is one fact under
//! `__extension_grant__::{extension_id}::{passport_fpr}` key=`record`,
//! value = a JSON-encoded [`ExtensionGrant`]. The privacy gate covers
//! `__extension_grant__::*` so grants are never push-eligible to a remote.
//!
//! ## Why facts, not tokens
//!
//! The original ExecPlan called for adding an `ExtensionTool` variant to
//! `rcx_capability_token::DataEgressClass`. We chose facts instead:
//!
//! 1. `DataEgressClass` is a flat enum (`None`, `Vectors`, `Text`, ...) —
//!    consumed in many match arms across the workspace. Adding a struct
//!    variant would require touching every consumer.
//! 2. Tokens flow between agents; grants are operator-managed central
//!    state. Having grants travel inside a bearer token would let any
//!    agent re-issue the same token with different scope. Operator
//!    issuance/revocation is the correct authority model.
//! 3. The dispatcher (M4) queries the fact store at call time anyway to
//!    look up which extension a tool name belongs to; checking the grant
//!    in the same query is essentially free.

use corecrux_memory::fact_store::{FactQuery, FactStore, StoreFact};
use crux_integrations::{
    append_audit_event, IntegrationAuditEvent, AUDIT_EXTENSION_GRANT_ADDED, AUDIT_EXTENSION_GRANT_REMOVED,
};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const GRANT_ENTITY_PREFIX: &str = "__extension_grant__";
pub const GRANT_RECORD_KEY: &str = "record";

#[derive(Debug, thiserror::Error)]
pub enum GrantError {
    #[error("extension '{0}' is not installed; install it first via POST /v1/extensions/register")]
    ExtensionNotInstalled(String),
    #[error("grant for extension '{0}' + passport '{1}' already exists; revoke first to replace")]
    AlreadyGranted(String, String),
    #[error("grant for extension '{0}' + passport '{1}' not found")]
    NotFound(String, String),
    #[error("invalid prefix '{0}': community extensions cannot grant access to a privacy-gated prefix")]
    PrefixForbidden(String),
    #[error("invalid extension_id '{0}'")]
    InvalidExtensionId(String),
    #[error("invalid passport_fpr '{0}': cannot be empty")]
    InvalidPassportFpr(String),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

/// A capability grant. Operator issues one per (extension_id, passport_fpr)
/// pair. The dispatcher (M4) consults this when filtering the MCP catalog
/// for the calling passport and when validating the per-call scope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExtensionGrant {
    pub extension_id: String,
    pub passport_fpr: String,
    /// Subset of the extension's manifest tool names this grant authorises.
    /// Empty = grant covers every tool the manifest declares.
    #[serde(default)]
    pub allowed_tool_names: Vec<String>,
    /// Fact-prefix scopes this grant unlocks for the extension's
    /// `read_fact` / `query_facts` calls (M4 host ABI).
    #[serde(default)]
    pub allowed_prefixes_read: Vec<String>,
    /// Fact-prefix scopes this grant unlocks for the extension's
    /// `store_fact` calls. Privacy-gated prefixes (the
    /// `fact_privacy::DEFAULT_PRIVATE_PREFIXES` list) are forbidden
    /// regardless of grant — see [`is_prefix_grantable`].
    #[serde(default)]
    pub allowed_prefixes_write: Vec<String>,
    /// Per-passport rate cap on `tools/call` invocations for this
    /// extension. None = use the daemon-wide default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit_per_min: Option<u32>,
    pub granted_at_unix_ms: u64,
    /// Passport that issued the grant (operator).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub granted_by_passport: Option<String>,
}

/// Reject grants targeting privacy-gated prefixes. The privacy gate is
/// authoritative regardless of grant; checking here means we surface the
/// rejection at issue time instead of silently dropping writes at dispatch.
fn is_prefix_grantable(prefix: &str) -> bool {
    // Identical to the daemon's default-private list. Kept inline rather
    // than imported from `fact_privacy` because that module is private.
    const RESERVED: &[&str] = &[
        "__ax__::",
        "__ax_session::",
        "__constraints__::",
        "__project_layer__::",
        "__plane__::",
        "__plane_layer__::",
        "__workspace__::",
        "__workspace_scan__::",
        "__repo_registry__::",
        "__repo_scan__::",
        "__repo_codegraph_ids__::",
        "__repo_extdeps__::",
        "__storybook__::",
        "__dossier__::",
        "__project_repo_link__::",
        "__extension__::",
        "__extension_grant__::",
        "__work__::",
        "__work_transition__::",
        "__passport__::",
        "__mint_request__::",
        "__bootstrap__::",
        "__project__::",
        "decisions::",
        "github::",
    ];
    !RESERVED.iter().any(|reserved| prefix.starts_with(reserved))
}

fn validate_extension_id(id: &str) -> Result<(), GrantError> {
    if id.is_empty() || id.len() > 128 {
        return Err(GrantError::InvalidExtensionId(id.to_string()));
    }
    let ok = id
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '-' | '_'));
    if !ok {
        return Err(GrantError::InvalidExtensionId(id.to_string()));
    }
    Ok(())
}

fn entity_for(extension_id: &str, passport_fpr: &str) -> String {
    format!("{GRANT_ENTITY_PREFIX}::{extension_id}::{passport_fpr}")
}

pub struct IssueGrantInput {
    pub extension_id: String,
    pub passport_fpr: String,
    pub allowed_tool_names: Vec<String>,
    pub allowed_prefixes_read: Vec<String>,
    pub allowed_prefixes_write: Vec<String>,
    pub rate_limit_per_min: Option<u32>,
    pub granted_by_passport: Option<String>,
}

/// Issue a grant. Caller is responsible for confirming the extension
/// itself is installed (the HTTP layer does this) — passing
/// `extension_installed=false` flips the call into a clean error.
pub fn issue_grant(
    store: &mut FactStore,
    data_dir: impl AsRef<Path>,
    extension_installed: bool,
    extension_version: Option<&str>,
    input: IssueGrantInput,
    now_unix_ms: u64,
) -> Result<ExtensionGrant, GrantError> {
    validate_extension_id(&input.extension_id)?;
    if input.passport_fpr.trim().is_empty() {
        return Err(GrantError::InvalidPassportFpr(input.passport_fpr));
    }
    if !extension_installed {
        return Err(GrantError::ExtensionNotInstalled(input.extension_id));
    }
    for prefix in input
        .allowed_prefixes_read
        .iter()
        .chain(input.allowed_prefixes_write.iter())
    {
        if !is_prefix_grantable(prefix) {
            return Err(GrantError::PrefixForbidden(prefix.clone()));
        }
    }
    if get_grant(store, &input.extension_id, &input.passport_fpr).is_some() {
        return Err(GrantError::AlreadyGranted(input.extension_id, input.passport_fpr));
    }

    let grant = ExtensionGrant {
        extension_id: input.extension_id.clone(),
        passport_fpr: input.passport_fpr.clone(),
        allowed_tool_names: input.allowed_tool_names,
        allowed_prefixes_read: input.allowed_prefixes_read,
        allowed_prefixes_write: input.allowed_prefixes_write,
        rate_limit_per_min: input.rate_limit_per_min,
        granted_at_unix_ms: now_unix_ms,
        granted_by_passport: input.granted_by_passport.filter(|s| !s.trim().is_empty()),
    };
    let value = serde_json::to_string(&grant)?;
    let mut sf = StoreFact {
        tenant_hash: "default".to_string(),
        entity: entity_for(&input.extension_id, &input.passport_fpr),
        key: GRANT_RECORD_KEY.to_string(),
        value,
        source_receipt: None,
        confidence: 1.0,
        private: false,
        horizon_class: None,
        actor: None,
    };
    crate::fact_privacy::enforce_global(&mut sf);
    store.store(sf);
    append_audit_event(
        data_dir,
        &IntegrationAuditEvent::extension(
            now_unix_ms,
            AUDIT_EXTENSION_GRANT_ADDED,
            grant.granted_by_passport.as_deref(),
            &grant.extension_id,
            extension_version,
            "added",
            serde_json::json!({
                "passport_fpr": grant.passport_fpr,
                "allowed_tool_names": grant.allowed_tool_names,
                "allowed_prefixes_read": grant.allowed_prefixes_read,
                "allowed_prefixes_write": grant.allowed_prefixes_write,
                "rate_limit_per_min": grant.rate_limit_per_min,
            }),
        ),
    );
    Ok(grant)
}

pub fn revoke_grant(
    store: &mut FactStore,
    data_dir: impl AsRef<Path>,
    extension_id: &str,
    extension_version: Option<&str>,
    passport_fpr: &str,
    revoked_by_passport: Option<&str>,
    now_unix_ms: u64,
) -> Result<(), GrantError> {
    let grant = get_grant(store, extension_id, passport_fpr)
        .ok_or_else(|| GrantError::NotFound(extension_id.to_string(), passport_fpr.to_string()))?;
    let mut sf = StoreFact {
        tenant_hash: "default".to_string(),
        entity: entity_for(extension_id, passport_fpr),
        key: GRANT_RECORD_KEY.to_string(),
        value: String::new(),
        source_receipt: None,
        confidence: 0.0,
        private: false,
        horizon_class: None,
        actor: None,
    };
    crate::fact_privacy::enforce_global(&mut sf);
    store.store(sf);
    append_audit_event(
        data_dir,
        &IntegrationAuditEvent::extension(
            now_unix_ms,
            AUDIT_EXTENSION_GRANT_REMOVED,
            revoked_by_passport,
            extension_id,
            extension_version,
            "removed",
            serde_json::json!({
                "passport_fpr": grant.passport_fpr,
                "allowed_tool_names": grant.allowed_tool_names,
                "allowed_prefixes_read": grant.allowed_prefixes_read,
                "allowed_prefixes_write": grant.allowed_prefixes_write,
                "rate_limit_per_min": grant.rate_limit_per_min,
            }),
        ),
    );
    Ok(())
}

pub fn get_grant(store: &FactStore, extension_id: &str, passport_fpr: &str) -> Option<ExtensionGrant> {
    list_grants_for_extension(store, extension_id)
        .into_iter()
        .find(|g| g.passport_fpr == passport_fpr)
}

pub fn list_grants_for_extension(store: &FactStore, extension_id: &str) -> Vec<ExtensionGrant> {
    let prefix = format!("{GRANT_ENTITY_PREFIX}::{extension_id}::");
    let result = store.query(&FactQuery {
        min_effective_confidence: None,
        tenant_hash: None,
        query: None,
        entity: None,
        entity_prefix: Some(prefix.clone()),
        top_k: 500,
        token_budget: None,
    });
    let latest = crate::fact_helpers::dedup_latest(result.facts);
    let mut out: Vec<ExtensionGrant> = latest
        .into_iter()
        .filter(|f| f.entity.starts_with(&prefix) && f.key == GRANT_RECORD_KEY && !f.value.is_empty())
        .filter_map(|f| serde_json::from_str::<ExtensionGrant>(&f.value).ok())
        .collect();
    out.sort_by(|a, b| a.passport_fpr.cmp(&b.passport_fpr));
    out
}

/// List every grant a given passport holds (across all extensions). Used
/// by the dispatcher (M4) to filter the MCP catalog per-caller — only
/// surfacing tools the calling passport has been granted.
#[allow(dead_code)]
pub fn list_grants_for_passport(store: &FactStore, passport_fpr: &str) -> Vec<ExtensionGrant> {
    // Walk the entire `__extension_grant__::` prefix and filter by passport.
    // Cheap: per-daemon grant counts are expected to be ≤ low hundreds.
    let prefix = format!("{GRANT_ENTITY_PREFIX}::");
    let result = store.query(&FactQuery {
        min_effective_confidence: None,
        tenant_hash: None,
        query: None,
        entity: None,
        entity_prefix: Some(prefix.clone()),
        top_k: 5_000,
        token_budget: None,
    });
    let latest = crate::fact_helpers::dedup_latest(result.facts);
    let mut out: Vec<ExtensionGrant> = latest
        .into_iter()
        .filter(|f| f.entity.starts_with(&prefix) && f.key == GRANT_RECORD_KEY && !f.value.is_empty())
        .filter_map(|f| serde_json::from_str::<ExtensionGrant>(&f.value).ok())
        .filter(|g| g.passport_fpr == passport_fpr)
        .collect();
    out.sort_by(|a, b| a.extension_id.cmp(&b.extension_id));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> FactStore {
        FactStore::new()
    }

    fn input(ext: &str, fpr: &str) -> IssueGrantInput {
        IssueGrantInput {
            extension_id: ext.to_string(),
            passport_fpr: fpr.to_string(),
            allowed_tool_names: vec!["quote.daily".to_string()],
            allowed_prefixes_read: vec!["personal::quotes::".to_string()],
            allowed_prefixes_write: vec!["personal::quotes::".to_string()],
            rate_limit_per_min: Some(30),
            granted_by_passport: Some("agent-claude".to_string()),
        }
    }

    #[test]
    fn issue_then_get_then_revoke() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut s = store();
        let g = issue_grant(
            &mut s,
            dir.path(),
            true,
            Some("0.1.0"),
            input("ext.example.quote", "p_alice"),
            1,
        )
        .expect("issue");
        assert_eq!(g.extension_id, "ext.example.quote");
        assert_eq!(g.rate_limit_per_min, Some(30));

        let got = get_grant(&s, "ext.example.quote", "p_alice").expect("get");
        assert_eq!(got.granted_by_passport.as_deref(), Some("agent-claude"));

        revoke_grant(
            &mut s,
            dir.path(),
            "ext.example.quote",
            Some("0.1.0"),
            "p_alice",
            Some("operator-passport"),
            2,
        )
        .expect("revoke");
        assert!(get_grant(&s, "ext.example.quote", "p_alice").is_none());

        let audit = crux_integrations::read_audit_tail(dir.path(), 50).expect("audit");
        assert_eq!(audit.len(), 2);
        assert_eq!(audit[0].action, AUDIT_EXTENSION_GRANT_ADDED);
        assert_eq!(audit[0].actor, "agent-claude");
        assert_eq!(audit[1].action, AUDIT_EXTENSION_GRANT_REMOVED);
        assert_eq!(audit[1].actor, "operator-passport");
    }

    #[test]
    fn rejects_extension_not_installed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut s = store();
        let err = issue_grant(
            &mut s,
            dir.path(),
            false,
            None,
            input("ext.example.quote", "p_alice"),
            1,
        )
        .expect_err("not installed");
        assert!(matches!(err, GrantError::ExtensionNotInstalled(_)));
    }

    #[test]
    fn rejects_duplicate_grant() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut s = store();
        issue_grant(&mut s, dir.path(), true, None, input("ext.example.quote", "p_alice"), 1).expect("first");
        let err =
            issue_grant(&mut s, dir.path(), true, None, input("ext.example.quote", "p_alice"), 2).expect_err("dup");
        assert!(matches!(err, GrantError::AlreadyGranted(_, _)));
    }

    #[test]
    fn rejects_privacy_gated_prefix_in_grant() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut s = store();
        let mut bad = input("ext.example.quote", "p_alice");
        bad.allowed_prefixes_write.push("__ax__::".to_string());
        let err = issue_grant(&mut s, dir.path(), true, None, bad, 1).expect_err("forbidden");
        match err {
            GrantError::PrefixForbidden(p) => assert!(p.starts_with("__ax__::")),
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn list_for_extension_orders_by_passport() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut s = store();
        issue_grant(&mut s, dir.path(), true, None, input("ext.example.quote", "p_bob"), 1).expect("bob");
        issue_grant(&mut s, dir.path(), true, None, input("ext.example.quote", "p_alice"), 2).expect("alice");
        let listed = list_grants_for_extension(&s, "ext.example.quote");
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].passport_fpr, "p_alice");
        assert_eq!(listed[1].passport_fpr, "p_bob");
    }

    #[test]
    fn list_for_passport_filters_correctly() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut s = store();
        issue_grant(&mut s, dir.path(), true, None, input("ext.one", "p_alice"), 1).expect("ext.one alice");
        issue_grant(&mut s, dir.path(), true, None, input("ext.two", "p_alice"), 2).expect("ext.two alice");
        issue_grant(&mut s, dir.path(), true, None, input("ext.one", "p_bob"), 3).expect("ext.one bob");
        let alice = list_grants_for_passport(&s, "p_alice");
        assert_eq!(alice.len(), 2);
        assert_eq!(alice[0].extension_id, "ext.one");
        assert_eq!(alice[1].extension_id, "ext.two");
        let bob = list_grants_for_passport(&s, "p_bob");
        assert_eq!(bob.len(), 1);
    }

    #[test]
    fn revoke_unknown_returns_not_found() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut s = store();
        let err =
            revoke_grant(&mut s, dir.path(), "ext.example.quote", None, "p_alice", None, 1).expect_err("not found");
        assert!(matches!(err, GrantError::NotFound(_, _)));
    }

    #[test]
    fn rejects_empty_passport_fpr() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut s = store();
        let err =
            issue_grant(&mut s, dir.path(), true, None, input("ext.example.quote", ""), 1).expect_err("empty fpr");
        assert!(matches!(err, GrantError::InvalidPassportFpr(_)));
    }
}
