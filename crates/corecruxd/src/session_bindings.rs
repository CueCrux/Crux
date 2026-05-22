// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
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
    let category = crate::tenant_category::classify_tenant(&tenant_id, None).as_str();

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
        entity: format!("{SESSION_BINDING_ENTITY_PREFIX}::{}", binding.session_id_hex),
        key: SESSION_BINDING_RECORD_KEY.to_string(),
        value,
        source_receipt: None,
        confidence: 1.0,
        private: false,
    };
    crate::fact_privacy::enforce_global(&mut sf);
    store.store(sf);
    Ok(())
}

pub fn list_bindings(store: &FactStore) -> Vec<SessionBinding> {
    let result = store.query(&FactQuery {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_dir(name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let dir = std::env::temp_dir().join(format!("corecruxd-bindings-{name}-{nanos}"));
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
        let _ = std::fs::remove_dir_all(&dir);
    }
}
