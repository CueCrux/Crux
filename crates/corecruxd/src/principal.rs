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
    /// Present only for identity-federation fallback resolution. The grant is
    /// explicit so mediators can distinguish a tier-derived read capability
    /// from a confirmed cross-passport memory-read edge.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub federation_grant: Option<crate::policy::FederationReadGrant>,
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
        federation_grant: None,
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

/// Identity-federation fallback (G4b, behind `CORECRUXD_IDENTITY_LINKS`):
/// resolve a passport fingerprint that is NOT local by following a live
/// `identity_link` edge. The result is the *linked local* passport's
/// identity, with capabilities stamped from the policy-owned
/// `federation.read` grant and `resolved_via = "identity_link:<id>"` so
/// receipts attribute the hop.
///
/// Unlinked → `PassportNotFound` (same denial as before the feature).
/// Revoked links are invisible to `find_live_link_for_remote`, so a revoked
/// remote is denied identically — checked at read time, no cache.
pub fn resolve_by_linked_passport(
    store: &FactStore,
    entities: &corecrux_memory::EntityStore,
    remote_fpr: &str,
) -> Result<ResolvedPrincipal, ResolveError> {
    let candidates = crate::identity_links::list_links(entities)
        .into_iter()
        .filter(|(_, p)| p.revoked_at.is_none() && p.remote_fpr == remote_fpr)
        .count();
    if candidates > 1 {
        tracing::warn!(
            remote_fpr,
            candidates,
            "multiple live identity links for one remote fpr — resolving via the oldest"
        );
    }
    let (link_id, payload) = crate::identity_links::find_live_link_for_remote(entities, remote_fpr)
        .ok_or_else(|| ResolveError::PassportNotFound(remote_fpr.to_string()))?;
    let mut principal = resolve_by_passport(store, &payload.local_passport_id, None)?;
    let grant = crate::policy::federation_read_grant();
    principal.capabilities.clone_from(&grant.allowed_capabilities);
    principal.federation_grant = Some(grant);
    principal.resolved_via = format!("identity_link:{link_id}");
    Ok(principal)
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
        // nanos alone collides on VMs with coarse clocks (parallel tests
        // land in the same quantum and share a dir) — salt with pid + a counter.
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "corecruxd-principal-{name}-{nanos}-{}-{seq}",
            std::process::id()
        ));
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
                name: None,
                owner: None,
                position: None,
                company: None,
                notes: None,
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
                name: None,
                owner: None,
                position: None,
                company: None,
                notes: None,
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

    // ── G4b: identity-link resolution (identity-memory-portability M5) ────

    /// Seed defaults, promote `personal-default` to a high tier (so the
    /// capability cap is observable), and create a live link to a synthetic
    /// remote passport. Returns the remote fpr + link id.
    fn seed_link(
        dir: &std::path::Path,
        store: &mut FactStore,
        entities: &mut corecrux_memory::EntityStore,
    ) -> (String, String) {
        use ed25519_dalek::{Signer, SigningKey};
        passports::seed_defaults_if_missing(dir, store, 1).expect("seed");
        passports::update_passport(
            store,
            "personal-default",
            passports::UpdatePassportInput {
                agent_work_gate: None,
                is_default_for_category: None,
                sponsor_id: None,
                reputation_tier: None,
                receipt_count: Some(600), // trusted tier
                name: None,
                owner: None,
                position: None,
                company: None,
                notes: None,
            },
        )
        .expect("promote");

        let local = passports::get_passport(store, "personal-default").expect("local");
        let local_key = crux_session::LocalPassportKey::from_path(&dir.join("passports").join("personal-default.key"))
            .expect("local key");
        let remote_key = SigningKey::from_bytes(&[42_u8; 32]);
        let remote_pub = remote_key.verifying_key().to_bytes();
        let remote_fpr = corecrux_memory::cruxpack::passport_fpr_from_public_key(&remote_pub);

        let created_at = "2026-06-12T00:00:00Z";
        let statement =
            corecrux_memory::identity_link::LinkStatement::memory_read(&local.principal_id, &remote_fpr, created_at);
        let hash = corecrux_memory::identity_link::statement_hash(&statement);
        let (link_id, _) = crate::identity_links::create_link(
            entities,
            store,
            &crate::identity_links::CreateLinkRequest {
                local_passport_id: "personal-default".to_string(),
                remote_fpr: remote_fpr.clone(),
                remote_public_key_hex: hex::encode(remote_pub),
                created_at: created_at.to_string(),
                sig_local: hex::encode(local_key.sign_hash(&hash)),
                sig_remote: hex::encode(remote_key.sign(&hash).to_bytes()),
            },
            "operator",
        )
        .expect("create link");
        (remote_fpr, link_id)
    }

    #[test]
    fn linked_passport_resolves_with_memory_read_caps_only() {
        let dir = temp_dir("linked");
        let mut store = FactStore::new();
        let mut entities = corecrux_memory::EntityStore::new();
        let (remote_fpr, link_id) = seed_link(&dir, &mut store, &mut entities);

        let p = resolve_by_linked_passport(&store, &entities, &remote_fpr).expect("resolve via link");
        assert_eq!(p.passport_id, "personal-default");
        // Trusted tier would normally carry metered/side_effect — the link
        // caps it to the memory.read allowlist, never key custody.
        assert_eq!(p.capabilities, crate::policy::federation_read_allowed_capabilities());
        let grant = p.federation_grant.expect("federation grant stamped");
        assert_eq!(grant.capability, crate::policy::FEDERATION_READ_CAPABILITY);
        assert_eq!(grant.scope, crate::policy::FEDERATION_READ_SCOPE);
        assert_eq!(p.resolved_via, format!("identity_link:{link_id}"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unlinked_passport_denied() {
        let dir = temp_dir("unlinked");
        let mut store = FactStore::new();
        let mut entities = corecrux_memory::EntityStore::new();
        let _ = seed_link(&dir, &mut store, &mut entities);

        let err = resolve_by_linked_passport(&store, &entities, "p_00000000000000000000000000000bad")
            .expect_err("unlinked must be denied");
        assert!(matches!(err, ResolveError::PassportNotFound(_)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn candidate_link_is_not_a_resolving_edge() {
        let dir = temp_dir("candidate-is-not-link");
        let mut store = FactStore::new();
        let mut entities = corecrux_memory::EntityStore::new();
        passports::seed_defaults_if_missing(&dir, &mut store, 1).expect("seed");
        let local = passports::get_passport(&store, "personal-default").expect("local");
        let observed_subject = "p_candidate000000000000000000000000".to_string();
        let (candidate_id, _) = crate::candidate_links::create_candidate(
            &mut entities,
            &store,
            crate::candidate_links::CreateCandidateInput {
                local_passport_fpr: local.principal_id,
                observed_subject: observed_subject.clone(),
                signals: vec![corecrux_memory::candidate_link::CandidateLinkSignal {
                    kind: "temporal_adjacency".to_string(),
                    confidence: 0.7,
                    evidence_ref: Some("evidence:test".to_string()),
                }],
                confidence: 0.7,
                evidence_refs: vec!["evidence:test".to_string()],
                proposed_at: Some("2026-06-15T00:00:00Z".to_string()),
            },
            "operator",
        )
        .expect("candidate");

        assert!(crate::candidate_links::get_candidate(&entities, &candidate_id).is_some());
        let err =
            resolve_by_linked_passport(&store, &entities, &observed_subject).expect_err("candidate must not resolve");
        assert!(matches!(err, ResolveError::PassportNotFound(_)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn revoked_link_denied() {
        let dir = temp_dir("revoked-link");
        let mut store = FactStore::new();
        let mut entities = corecrux_memory::EntityStore::new();
        let (remote_fpr, link_id) = seed_link(&dir, &mut store, &mut entities);

        resolve_by_linked_passport(&store, &entities, &remote_fpr).expect("live link resolves");
        crate::identity_links::revoke_link(&mut entities, &link_id, "operator").expect("revoke");
        let err = resolve_by_linked_passport(&store, &entities, &remote_fpr).expect_err("revoked must be denied");
        assert!(matches!(err, ResolveError::PassportNotFound(_)));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
