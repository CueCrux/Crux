// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `resolve_principal` — the read-only resolver an external mediator (the MCP
//! gateway) calls to learn the real passport / tier / capabilities / tenant
//! behind a session, so it can authorize and attribute proxied tool calls
//! against the *real* identity instead of an env-supplied tier.
//!
//! It composes the existing stores — it adds no new persistence:
//!
//! ```text
//! __session_binding__::{hex}  ⋈  __passport__::{id} (daemon record)
//!   → tier         via crate::passports::resolve_tier(receipt_count)
//!   → tier_rank    via crate::policy::tier_rank
//!   → capabilities via crate::policy::capabilities_for_tier
//! ```
//!
//! Tenant scoping (T.1) is enforced at the HTTP layer (`http::principal`): the
//! caller's allowed tenants are checked against the *resolved* `tenant_id`, so a
//! mediator authenticated for tenant A cannot resolve tenant B's passport.

use corecrux_memory::fact_store::FactStore;
use serde::{Deserialize, Serialize};

use crate::passports::{self, PassportRecord};
use crate::session_bindings::{self, SessionBinding};

/// The resolved principal surface returned to a mediator. Read-only — it is a
/// projection over the binding + passport stores, never persisted.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResolvedPrincipal {
    pub passport_id: String,
    pub category: String,
    /// Canonical reputation tier (recomputed from `receipt_count`).
    pub tier: String,
    /// Comparable numeric rank for `tier` (see [`crate::policy::tier_rank`]).
    pub tier_rank: u8,
    /// Capability tokens the mediator authorizes tool calls against.
    pub capabilities: Vec<String>,
    pub tenant_id: String,
    pub agent_work_gate: bool,
    /// `"session"` (joined via a session binding) or `"passport"` (direct).
    pub resolved_via: String,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ResolveError {
    #[error("no session binding for '{0}'")]
    BindingNotFound(String),
    #[error("passport '{0}' not found")]
    PassportNotFound(String),
}

fn build(
    passport: PassportRecord,
    tenant_id: String,
    category: String,
    agent_work_gate: bool,
    resolved_via: &str,
) -> ResolvedPrincipal {
    // The canonical tier is recomputed from `receipt_count` — the stored
    // `reputation_tier` can be stale. Capabilities flow from the tier ladder.
    let tier = passports::resolve_tier(passport.receipt_count).to_string();
    let tier_rank = crate::policy::tier_rank(&tier);
    let capabilities = crate::policy::capabilities_for_tier(&tier);
    ResolvedPrincipal {
        passport_id: passport.id,
        category,
        tier,
        tier_rank,
        capabilities,
        tenant_id,
        agent_work_gate,
        resolved_via: resolved_via.to_string(),
    }
}

/// Resolve the principal bound to a session id (hex), joining the session
/// binding to the daemon passport record. The binding carries the
/// authoritative `tenant_id` + `category` + `agent_work_gate`.
pub fn resolve_by_session(store: &FactStore, session_id_hex: &str) -> Result<ResolvedPrincipal, ResolveError> {
    let binding: SessionBinding = session_bindings::get_binding(store, session_id_hex)
        .ok_or_else(|| ResolveError::BindingNotFound(session_id_hex.to_string()))?;
    let passport = passports::get_passport(store, &binding.passport_id)
        .ok_or_else(|| ResolveError::PassportNotFound(binding.passport_id.clone()))?;
    Ok(build(
        passport,
        binding.tenant_id,
        binding.passport_category,
        binding.agent_work_gate,
        "session",
    ))
}

/// Resolve a principal directly by passport id (no session binding). The
/// passport record carries no tenant, so the caller supplies a `tenant_hint`
/// (e.g. its own tenant when resolving itself); absent a hint we fall back to
/// the passport category. The HTTP layer still tenant-scopes the result.
pub fn resolve_by_passport(
    store: &FactStore,
    passport_id: &str,
    tenant_hint: Option<String>,
) -> Result<ResolvedPrincipal, ResolveError> {
    let passport = passports::get_passport(store, passport_id)
        .ok_or_else(|| ResolveError::PassportNotFound(passport_id.to_string()))?;
    let category = passport.category.clone();
    let agent_work_gate = passport.agent_work_gate;
    let tenant_id = tenant_hint.unwrap_or_else(|| category.clone());
    Ok(build(passport, tenant_id, category, agent_work_gate, "passport"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session_bindings::{resolve, write_binding, ResolveInput};
    use std::path::PathBuf;

    fn temp_dir(name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let dir = std::env::temp_dir().join(format!("corecruxd-principal-{name}-{nanos}"));
        std::fs::create_dir_all(&dir).expect("mkdir");
        dir
    }

    /// Seed the three default passports and bind a session to the work default
    /// under tenant `work::team`.
    fn seed_and_bind(dir: &PathBuf, store: &mut FactStore, session_hex: &str) {
        passports::seed_defaults_if_missing(dir, store, 1).expect("seed");
        let binding = resolve(
            store,
            ResolveInput {
                session_id_hex: session_hex,
                project_id: None,
                tenant_id: Some("work::team".to_string()),
                passport_id: None, // → work-default for the work category
                now_unix_ms: 1000,
            },
        )
        .expect("resolve binding");
        write_binding(store, &binding).expect("write binding");
    }

    #[test]
    fn resolve_by_session_joins_binding_and_passport() {
        let dir = temp_dir("by-session");
        let mut store = FactStore::new();
        seed_and_bind(&dir, &mut store, "deadbeef");

        let p = resolve_by_session(&store, "deadbeef").expect("resolve");
        assert_eq!(p.passport_id, "work-default");
        assert_eq!(p.category, "work");
        assert_eq!(p.tenant_id, "work::team");
        assert_eq!(p.tier, "unverified"); // seeded defaults have 0 receipts
        assert_eq!(p.tier_rank, 0);
        assert_eq!(p.capabilities, vec!["tool:list".to_string()]);
        assert_eq!(p.resolved_via, "session");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_by_session_missing_binding_errors() {
        let dir = temp_dir("missing");
        let mut store = FactStore::new();
        passports::seed_defaults_if_missing(&dir, &mut store, 1).expect("seed");
        let err = resolve_by_session(&store, "nope").expect_err("should error");
        assert_eq!(err, ResolveError::BindingNotFound("nope".to_string()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_by_passport_falls_back_to_category_tenant() {
        let dir = temp_dir("by-passport");
        let mut store = FactStore::new();
        passports::seed_defaults_if_missing(&dir, &mut store, 1).expect("seed");
        let p = resolve_by_passport(&store, "personal-default", None).expect("resolve");
        assert_eq!(p.passport_id, "personal-default");
        assert_eq!(p.tenant_id, "personal"); // category fallback
        assert_eq!(p.resolved_via, "passport");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_by_passport_unknown_errors() {
        let dir = temp_dir("unknown");
        let mut store = FactStore::new();
        passports::seed_defaults_if_missing(&dir, &mut store, 1).expect("seed");
        let err = resolve_by_passport(&store, "ghost", None).expect_err("should error");
        assert_eq!(err, ResolveError::PassportNotFound("ghost".to_string()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tier_and_capabilities_track_receipt_count() {
        let dir = temp_dir("tier");
        let mut store = FactStore::new();
        passports::create_passport(
            &dir,
            &mut store,
            passports::CreatePassportInput {
                id: "veteran".to_string(),
                category: "work".to_string(),
                sponsor_id: None,
                agent_work_gate: true,
                is_default_for_category: false,
            },
            1,
        )
        .expect("create");
        // Promote to the `trusted` tier (≥500 receipts).
        passports::update_passport(
            &mut store,
            "veteran",
            passports::UpdatePassportInput {
                agent_work_gate: None,
                is_default_for_category: None,
                sponsor_id: None,
                reputation_tier: None,
                receipt_count: Some(600),
            },
        )
        .expect("promote");

        let p = resolve_by_passport(&store, "veteran", Some("work::ops".to_string())).expect("resolve");
        assert_eq!(p.tier, "trusted");
        assert_eq!(p.tier_rank, 3);
        assert!(p.capabilities.contains(&"tool:invoke:metered".to_string()));
        assert!(!p.capabilities.contains(&"tool:invoke:destructive".to_string()));
        assert!(p.agent_work_gate);
        assert_eq!(p.tenant_id, "work::ops");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
