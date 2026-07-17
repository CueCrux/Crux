// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Session bindings — `(session_id, project_id, tenant_id, passport_id)`
//! triples that record which agent identity is acting in which scope for
//! each minted session plan.
//!
//! Stored as a fact under `__session_binding__::{session_id_hex}` so the
//! `cuecrux_session` MCP tool, the coordination view, and audit trails can
//! look up "who is on the other end of this session" without re-decoding the
//! session plan.

use corecrux_memory::fact_store::{FactQuery, FactStore, StoreFact};
use serde::{Deserialize, Serialize};

pub const SESSION_BINDING_ENTITY_PREFIX: &str = "__session_binding__";
pub const SESSION_BINDING_RECORD_KEY: &str = "record";

#[derive(Debug, thiserror::Error)]
pub enum SessionBindingsError {
    #[error("requested passport '{0}' not found in store")]
    PassportNotFound(String),
    #[error("invalid tenant id '{0}'")]
    InvalidTenant(String),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionBinding {
    pub session_id_hex: String,
    pub project_id: Option<String>,
    pub tenant_id: String,
    pub passport_id: String,
    pub passport_category: String,
    pub agent_work_gate: bool,
    pub bound_at_unix_ms: u64,
}

pub struct ResolveInput<'a> {
    pub session_id_hex: &'a str,
    pub project_id: Option<String>,
    pub tenant_id: Option<String>,
    pub passport_id: Option<String>,
    pub now_unix_ms: u64,
}

pub fn resolve(store: &FactStore, input: ResolveInput<'_>) -> Result<SessionBinding, SessionBindingsError> {
    let tenant_id = input.tenant_id.unwrap_or_else(|| "personal".to_string());
    if tenant_id.is_empty() {
        return Err(SessionBindingsError::InvalidTenant(tenant_id));
    }
    let category = crux_mcp::tenant_category::classify_tenant(&tenant_id, None).as_str();

    let passport = if let Some(id) = input.passport_id {
        crate::passports::get_passport(store, &id).ok_or(SessionBindingsError::PassportNotFound(id))?
    } else {
        crate::passports::default_for_category(store, category)
            .or_else(|| crate::passports::default_for_category(store, "personal"))
            .ok_or_else(|| SessionBindingsError::PassportNotFound("personal-default".to_string()))?
    };

    Ok(SessionBinding {
        session_id_hex: input.session_id_hex.to_string(),
        project_id: input.project_id,
        tenant_id,
        passport_id: passport.id,
        passport_category: passport.category,
        agent_work_gate: passport.agent_work_gate,
        bound_at_unix_ms: input.now_unix_ms,
    })
}

pub fn write_binding(store: &mut FactStore, binding: &SessionBinding) -> Result<(), SessionBindingsError> {
    let value = serde_json::to_string(binding)?;
    let mut sf = StoreFact {
        tenant_hash: "default".to_string(),
        entity: format!("{SESSION_BINDING_ENTITY_PREFIX}::{}", binding.session_id_hex),
        key: SESSION_BINDING_RECORD_KEY.to_string(),
        value,
        source_receipt: None,
        confidence: 1.0,
        private: false,
        horizon_class: None,
        actor: None,
    };
    crate::fact_privacy::enforce_global(&mut sf);
    store.store(sf);
    Ok(())
}

pub fn list_bindings(store: &FactStore) -> Vec<SessionBinding> {
    let result = store.query(&FactQuery {
        min_effective_confidence: None,
        tenant_hash: None,
        query: None,
        entity: None,
        entity_prefix: Some(format!("{SESSION_BINDING_ENTITY_PREFIX}::")),
        top_k: 200,
        token_budget: None,
    });
    let mut out = Vec::new();
    for fact in crate::fact_helpers::dedup_latest(result.facts) {
        if fact.key != SESSION_BINDING_RECORD_KEY {
            continue;
        }
        if let Ok(b) = serde_json::from_str::<SessionBinding>(&fact.value) {
            out.push(b);
        }
    }
    out.sort_by(|a, b| b.bound_at_unix_ms.cmp(&a.bound_at_unix_ms));
    out
}

/// Uncapped total of live session bindings with a per-passport breakdown.
///
/// Unlike [`list_bindings`] (which caps at `top_k: 200`) this is O(n) over the
/// whole fact store and does not truncate — use it for leak / observability
/// (e.g. spotting a churning client minting one binding per MCP `initialize`),
/// not for listing. Deduplicates by entity (session id) and skips tombstones.
pub fn count_bindings(store: &FactStore) -> BindingCounts {
    let prefix = format!("{SESSION_BINDING_ENTITY_PREFIX}::");
    let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
    let mut by_passport: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
    let mut total = 0u64;
    for fact in store.all_facts() {
        if fact.deleted || fact.key != SESSION_BINDING_RECORD_KEY || !fact.entity.starts_with(&prefix) {
            continue;
        }
        if !seen.insert(fact.entity.as_str()) {
            continue;
        }
        total += 1;
        if let Ok(b) = serde_json::from_str::<SessionBinding>(&fact.value) {
            *by_passport.entry(b.passport_id).or_default() += 1;
        }
    }
    BindingCounts { total, by_passport }
}

/// Result of [`count_bindings`].
#[derive(Debug, Clone, Serialize)]
pub struct BindingCounts {
    pub total: u64,
    pub by_passport: std::collections::BTreeMap<String, u64>,
}

/// Point lookup of the binding for a single session id (hex). Returns the
/// latest `record` fact under `__session_binding__::{session_id_hex}`, or
/// `None` if no binding exists. Cheaper than [`list_bindings`] when the caller
/// already knows the session id (the `resolve_principal` path).
pub fn get_binding(store: &FactStore, session_id_hex: &str) -> Option<SessionBinding> {
    let result = store.query(&FactQuery {
        min_effective_confidence: None,
        tenant_hash: None,
        query: None,
        entity: Some(format!("{SESSION_BINDING_ENTITY_PREFIX}::{session_id_hex}")),
        entity_prefix: None,
        top_k: 8,
        token_budget: None,
    });
    crate::fact_helpers::dedup_latest(result.facts)
        .into_iter()
        .find(|f| f.key == SESSION_BINDING_RECORD_KEY)
        .and_then(|f| serde_json::from_str::<SessionBinding>(&f.value).ok())
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
        let dir = std::env::temp_dir().join(format!(
            "corecruxd-bindings-{name}-{nanos}-{}-{seq}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        dir
    }

    #[test]
    fn resolve_uses_explicit_passport_when_present() {
        let dir = temp_dir("explicit");
        let mut store = FactStore::new();
        crate::passports::seed_defaults_if_missing(&dir, &mut store, 1).expect("seed");
        let b = resolve(
            &store,
            ResolveInput {
                session_id_hex: "deadbeef",
                project_id: None,
                tenant_id: Some("work::team".to_string()),
                passport_id: Some("personal-default".to_string()),
                now_unix_ms: 1000,
            },
        )
        .expect("resolve");
        assert_eq!(b.passport_id, "personal-default");
        assert_eq!(b.tenant_id, "work::team");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_falls_back_to_category_default_when_passport_omitted() {
        let dir = temp_dir("category");
        let mut store = FactStore::new();
        crate::passports::seed_defaults_if_missing(&dir, &mut store, 1).expect("seed");
        let b = resolve(
            &store,
            ResolveInput {
                session_id_hex: "abcd",
                project_id: None,
                tenant_id: Some("work::ops".to_string()),
                passport_id: None,
                now_unix_ms: 1000,
            },
        )
        .expect("resolve");
        assert_eq!(b.passport_id, "work-default");
        assert_eq!(b.passport_category, "work");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_falls_back_to_personal_default_when_nothing_supplied() {
        let dir = temp_dir("none");
        let mut store = FactStore::new();
        crate::passports::seed_defaults_if_missing(&dir, &mut store, 1).expect("seed");
        let b = resolve(
            &store,
            ResolveInput {
                session_id_hex: "1234",
                project_id: None,
                tenant_id: None,
                passport_id: None,
                now_unix_ms: 1000,
            },
        )
        .expect("resolve");
        assert_eq!(b.passport_id, "personal-default");
        assert_eq!(b.passport_category, "personal");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_rejects_unknown_passport_id() {
        let dir = temp_dir("unknown");
        let mut store = FactStore::new();
        crate::passports::seed_defaults_if_missing(&dir, &mut store, 1).expect("seed");
        let err = resolve(
            &store,
            ResolveInput {
                session_id_hex: "x",
                project_id: None,
                tenant_id: None,
                passport_id: Some("does-not-exist".to_string()),
                now_unix_ms: 1000,
            },
        )
        .expect_err("should reject");
        assert!(matches!(err, SessionBindingsError::PassportNotFound(_)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_then_list_roundtrip() {
        let dir = temp_dir("listing");
        let mut store = FactStore::new();
        crate::passports::seed_defaults_if_missing(&dir, &mut store, 1).expect("seed");
        let b1 = resolve(
            &store,
            ResolveInput {
                session_id_hex: "aaaa",
                project_id: Some("proj-x".to_string()),
                tenant_id: Some("work::team".to_string()),
                passport_id: None,
                now_unix_ms: 100,
            },
        )
        .expect("r1");
        let b2 = resolve(
            &store,
            ResolveInput {
                session_id_hex: "bbbb",
                project_id: None,
                tenant_id: None,
                passport_id: None,
                now_unix_ms: 200,
            },
        )
        .expect("r2");
        write_binding(&mut store, &b1).expect("w1");
        write_binding(&mut store, &b2).expect("w2");
        let listed = list_bindings(&store);
        assert_eq!(listed.len(), 2);
        // Sorted by bound_at_unix_ms descending → b2 first.
        assert_eq!(listed[0].session_id_hex, "bbbb");
        assert_eq!(listed[1].session_id_hex, "aaaa");

        // Point lookup returns the right binding, and None for an unknown id.
        let got = get_binding(&store, "aaaa").expect("aaaa present");
        assert_eq!(got.session_id_hex, "aaaa");
        assert_eq!(got.project_id.as_deref(), Some("proj-x"));
        assert!(get_binding(&store, "zzzz").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
