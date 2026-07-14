// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Fact-store privacy policy — belt-and-braces gating for "what's pushable
//! to a remote, what stays strictly local".
//!
//! ## Why this exists
//!
//! The MCP `sync_push` tool already filters facts where `private=true`.
//! This module ensures that **everything sensitive is born private** — no
//! human or agent has to remember to set the flag.
//!
//! Default policy: a fact is private if its entity starts with any of the
//! reserved prefixes below. Operators can extend this via the
//! `CORECRUXD_ALWAYS_PRIVATE_PREFIXES` env var (comma-separated). They can
//! also opt-in to share a specific prefix via
//! `CORECRUXD_SHARE_PREFIXES_OVERRIDE` (comma-separated; subtracts from the
//! private set).
//!
//! ## Defaults
//!
//! - `__ax__::`              — agent cockpit (decisions, skills, snapshots, jobs)
//! - `__constraints__::`     — operator/agent constraints
//! - `__project_layer__::`   — Vision / Goals / planes / etc.
//! - `__work__::`            — work items
//! - `__work_transition__::` — work state transitions
//! - `__workbench__::`       — Pro workbench context packs, ledgers, handoffs
//! - `__incident__::`        — private governance incident reconstructions
//! - `__legal_hold__::`      — daemon-owned legal-hold state
//! - `__legal_hold_receipt__::` — daemon-owned legal-hold audit records
//! - `__answer_replay_capsule__::` — deterministic answer replay capsules
//! - `__passport__::`        — passport metadata (already shouldn't sync)
//! - `__bootstrap__::`       — first-run setup state
//! - `__project__::`         — project metadata
//! - `__ax_session::`        — AX session-scoped state
//! - `decisions::`           — legacy decision log entries (if any)
//! - `github::`              — GitHub-ingested commits/PRs/issues (most are
//!   from private repos; keep local until operator explicitly shares a specific
//!   repo)
//!
//! Anything else (manually-added facts, bootstrapped public data) is push-
//! eligible by default — but `sync_push` is already tier-gated and requires
//! `confirm=true` and a configured remote URL, so the actual push surface
//! has multiple defences.

#![allow(dead_code)] // privacy-policy helpers held for richer scope rules; not all wired yet

use std::collections::BTreeSet;
use std::sync::OnceLock;

use crate::fact_store::{Fact, StoreFact};

/// Process-global policy. Set once at startup via `install_global()` so every
/// write path can call `enforce_global(&mut fact)` without threading an
/// explicit policy through their signatures. Tests that need a custom policy
/// can call `install_global_for_test()` (idempotent — last writer wins).
static GLOBAL_POLICY: OnceLock<PrivacyPolicy> = OnceLock::new();

pub fn install_global(policy: PrivacyPolicy) {
    // OnceLock::set returns Err if already initialised. We tolerate that —
    // production sets it from main(), tests may set it after that's already
    // happened. The first-set wins; we don't try to overwrite at runtime.
    let _ = GLOBAL_POLICY.set(policy);
}

/// Like `enforce(&policy, &mut fact)` but reads the global policy. Falls
/// back to the env-derived default if `install_global` was never called.
pub fn enforce_global(fact: &mut StoreFact) {
    let policy = GLOBAL_POLICY.get_or_init(PrivacyPolicy::from_env);
    enforce(policy, fact);
}

/// Enforce the process-global privacy policy on a fully built fact, such as
/// one received from a sync peer.
pub fn enforce_global_fact(fact: &mut Fact) {
    let policy = GLOBAL_POLICY.get_or_init(PrivacyPolicy::from_env);
    if policy.is_always_private(&fact.entity) {
        fact.private = true;
    }
}

/// Read the live global policy (initialises from env on first read if
/// `install_global` hasn't been called).
pub fn global_policy() -> &'static PrivacyPolicy {
    GLOBAL_POLICY.get_or_init(PrivacyPolicy::from_env)
}

pub const DEFAULT_PRIVATE_PREFIXES: &[&str] = &[
    "__agent::",
    "__ops::",
    "__ops__::",
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
    "__workbench__::",
    "__answer_replay_capsule__::",
    "__passport__::",
    "__session_binding__::",
    "__coord__::",
    "__incident__::",
    "__legal_hold__::",
    "__legal_hold_receipt__::",
    "__bootstrap__::",
    "__project__::",
    "__tenant_metadata__::",
    "decisions::",
    "github::",
];

/// Reserved entity namespaces owned exclusively by daemon governance flows.
///
/// Client-facing fact-write handlers must reject these prefixes before they
/// reach [`crate::fact_store::FactStore`]. The core store deliberately does
/// not enforce this policy because legal-hold and incident implementations
/// persist their own state through direct store calls.
pub const DAEMON_OWNED_ENTITY_PREFIXES: &[&str] = &["__legal_hold__::", "__legal_hold_receipt__::", "__incident__::"];

/// Return the daemon-owned prefix covering `entity`, if any.
///
/// This is the canonical client-boundary write guard shared by MCP and HTTP.
pub fn daemon_owned_entity_prefix(entity: &str) -> Option<&'static str> {
    DAEMON_OWNED_ENTITY_PREFIXES
        .iter()
        .copied()
        .find(|prefix| entity.starts_with(prefix))
}

/// Privacy policy resolved at process start. Cheap to clone (it's just two
/// `BTreeSet<String>` of small string keys).
#[derive(Debug, Clone)]
pub struct PrivacyPolicy {
    /// Entity prefixes that force `private=true` on every store_fact write.
    private_prefixes: BTreeSet<String>,
    /// Operator overrides that subtract from the private set
    /// (i.e. "I want to share __ax__::skills::" — drops that single prefix).
    share_overrides: BTreeSet<String>,
}

impl PrivacyPolicy {
    /// Build the default policy + apply operator env overrides.
    pub fn from_env() -> Self {
        let mut private = BTreeSet::new();
        for p in DEFAULT_PRIVATE_PREFIXES {
            private.insert((*p).to_string());
        }
        if let Ok(extra) = std::env::var("CORECRUXD_ALWAYS_PRIVATE_PREFIXES") {
            for p in extra.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                private.insert(p.to_string());
            }
        }
        let mut share = BTreeSet::new();
        if let Ok(overrides) = std::env::var("CORECRUXD_SHARE_PREFIXES_OVERRIDE") {
            for p in overrides.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                share.insert(p.to_string());
            }
        }
        Self {
            private_prefixes: private,
            share_overrides: share,
        }
    }

    /// Construct a policy directly from prefix lists (test + admin use).
    pub fn from_prefixes(private: Vec<String>, share_overrides: Vec<String>) -> Self {
        Self {
            private_prefixes: private.into_iter().collect(),
            share_overrides: share_overrides.into_iter().collect(),
        }
    }

    /// `true` if the entity is covered by an always-private prefix that
    /// hasn't been explicitly overridden to share.
    pub fn is_always_private(&self, entity: &str) -> bool {
        let private_match = self.private_prefixes.iter().any(|p| entity.starts_with(p));
        if !private_match {
            return false;
        }
        let share_match = self.share_overrides.iter().any(|p| entity.starts_with(p));
        !share_match
    }

    /// Snapshot for the sharing-posture endpoint.
    pub fn snapshot(&self) -> PolicySnapshot {
        PolicySnapshot {
            private_prefixes: self.private_prefixes.iter().cloned().collect(),
            share_overrides: self.share_overrides.iter().cloned().collect(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PolicySnapshot {
    pub private_prefixes: Vec<String>,
    pub share_overrides: Vec<String>,
}

/// In-place enforcer used by `FactStore` before persistence. Callers may also
/// apply it earlier as defence in depth. If the entity is covered by the
/// policy, sets `private=true`.
pub fn enforce(policy: &PrivacyPolicy, fact: &mut StoreFact) {
    if policy.is_always_private(&fact.entity) {
        fact.private = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make(entity: &str) -> StoreFact {
        StoreFact {
            tenant_hash: "default".to_string(),
            entity: entity.to_string(),
            key: "content".into(),
            value: "x".into(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        }
    }

    #[test]
    fn defaults_cover_known_internal_prefixes() {
        let p = PrivacyPolicy::from_prefixes(
            DEFAULT_PRIVATE_PREFIXES.iter().map(|s| (*s).to_string()).collect(),
            vec![],
        );
        assert!(p.is_always_private("__ax__::decision::42"));
        assert!(p.is_always_private("__project_layer__::plancrux::vision"));
        assert!(p.is_always_private("__work__::abc123"));
        assert!(p.is_always_private("__constraints__::no-mocks"));
        assert!(p.is_always_private("github::CueCrux/PlanCrux::commit/abc"));
        // B4 (T.1): session bindings carry passport_id/tenant_id and must never
        // sync — born private at ingest like __passport__::.
        assert!(p.is_always_private("__session_binding__::deadbeefcafef00d"));
        // Coord intents/claims name sessions, passports, and repo paths —
        // strictly local, born private (coordination-plane ExecPlan T.1).
        assert!(p.is_always_private("__coord__::proj::deadbeef"));
        assert!(p.is_always_private("__incident__::inc_deadbeef"));
    }

    #[test]
    fn daemon_owned_prefixes_are_write_protected_at_client_boundaries() {
        for prefix in DAEMON_OWNED_ENTITY_PREFIXES {
            let entity = format!("{prefix}owned");
            assert_eq!(daemon_owned_entity_prefix(&entity), Some(*prefix));
            assert!(DEFAULT_PRIVATE_PREFIXES.contains(prefix));
        }
        assert_eq!(
            daemon_owned_entity_prefix("__legal_hold__lookalike::x"),
            None,
            "only the exact reserved namespace must match"
        );
        assert_eq!(daemon_owned_entity_prefix("project::incident"), None);
    }

    #[test]
    fn legal_hold_prefix_constants_match_the_client_write_guard() {
        assert!(DAEMON_OWNED_ENTITY_PREFIXES.contains(&crate::legal_hold::LEGAL_HOLD_ENTITY_PREFIX));
        assert!(DAEMON_OWNED_ENTITY_PREFIXES.contains(&crate::legal_hold::LEGAL_HOLD_RECEIPT_ENTITY_PREFIX));
    }

    #[test]
    fn daemon_internal_legal_hold_placement_remains_available() {
        let mut store = crate::FactStore::new();
        let placed = store
            .place_legal_hold(crate::legal_hold::PlaceLegalHold {
                tenant_id: "tenant-a".to_string(),
                entity_prefixes: vec!["customer::42::".to_string()],
                reason: "litigation".to_string(),
                actor: Some("p_operator".to_string()),
            })
            .unwrap();

        let entity = format!("{}{}", crate::legal_hold::LEGAL_HOLD_ENTITY_PREFIX, placed.hold.hold_id);
        assert_eq!(
            daemon_owned_entity_prefix(&entity),
            Some(crate::legal_hold::LEGAL_HOLD_ENTITY_PREFIX)
        );
        assert!(store.legal_hold(&placed.hold.hold_id).is_some());
    }

    #[test]
    fn unrelated_entity_is_not_forced_private() {
        let p = PrivacyPolicy::from_prefixes(
            DEFAULT_PRIVATE_PREFIXES.iter().map(|s| (*s).to_string()).collect(),
            vec![],
        );
        assert!(!p.is_always_private("personal::scratch::note"));
        assert!(!p.is_always_private("public::announcement"));
    }

    #[test]
    fn share_override_subtracts_from_private_set() {
        let p = PrivacyPolicy::from_prefixes(
            vec!["__ax__::".into(), "github::".into()],
            vec!["__ax__::skills::".into()],
        );
        assert!(p.is_always_private("__ax__::decision::1"));
        // override hits — this prefix is now share-eligible.
        assert!(!p.is_always_private("__ax__::skills::retrieve-ms"));
        assert!(p.is_always_private("github::CueCrux/PlanCrux::commit/abc"));
    }

    #[test]
    fn enforce_sets_private_when_matched() {
        let p = PrivacyPolicy::from_prefixes(vec!["__ax__::".into()], vec![]);
        let mut f = make("__ax__::decision::42");
        enforce(&p, &mut f);
        assert!(f.private);
    }

    #[test]
    fn enforce_leaves_private_alone_when_not_matched() {
        let p = PrivacyPolicy::from_prefixes(vec!["__ax__::".into()], vec![]);
        let mut f = make("personal::scratch");
        enforce(&p, &mut f);
        assert!(!f.private);
    }

    #[test]
    fn enforce_never_unsets_private_already_true() {
        let p = PrivacyPolicy::from_prefixes(vec![], vec![]);
        let mut f = make("personal::scratch");
        f.private = true;
        enforce(&p, &mut f);
        assert!(f.private);
    }

    /// Drift guard for the `.cruxpack` exporter (Memory-Portability-v1 §3):
    /// every born-private prefix the daemon enforces MUST also be on the
    /// exporter's reserved list, so adding a prefix here can never silently
    /// make those facts exportable. (The exporter list is allowed to be a
    /// superset — CLI-side reserved prefixes ride along.)
    #[test]
    fn cruxpack_reserved_prefixes_cover_daemon_private_prefixes() {
        for prefix in DEFAULT_PRIVATE_PREFIXES {
            assert!(
                crate::cruxpack::CRUXPACK_RESERVED_PREFIXES.contains(prefix),
                "born-private prefix '{prefix}' is missing from CRUXPACK_RESERVED_PREFIXES — \
                 facts under it could leak into a .cruxpack export"
            );
        }
    }
}
