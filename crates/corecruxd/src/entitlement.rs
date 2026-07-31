// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Entitlement store and verifier — the replacement for the licence-key gate.
//!
//! ExecPlan `crux-pro-capabilities-rcx-entitled-2026-07-27` M2. **Ships dark:**
//! nothing in this module is wired into an enforcement path yet. `OperatingMode`
//! still comes from `CORECRUXD_OPERATING_MODE`; M7 performs the cutover.
//!
//! The thing being replaced is an environment variable. `require_surface_enabled`
//! reads `enabled_pro_services`, sourced from `env_csv("CORECRUXD_ENABLED_PRO_SERVICES")`
//! — a licence key on a local binary, which the published vow forbids in its own
//! words: *"a hosted-only capability is simply absent from the local build. It is
//! never a licence key."* Here, tier is a property of the account, carried in a
//! signed capability token and verified by the daemon.
//!
//! # Resolution order
//!
//! ```text
//! 1. CORECRUXD_ENTITLEMENT_SOURCE = rcx (default) | env (Max / air-gapped / dev)
//! 2. rcx: load the persisted RcxCapabilityToken from the entitlement store
//! 3. verify: issuer signature -> expires_at -> revocation -> tenant_scope
//! 4. map:  Free -> FreeLocal | Pro -> ProLocalFirst | Governance -> GovernanceHosted
//!          Max is NOT a tier: Governance + source==env + airgap -> MaxPrivate
//! 5. on failure: FallbackPolicy for that failure kind; forgery/revocation
//!    ALWAYS -> FreeLocal, regardless of what the token's own policy asks for
//! ```
//!
//! # Two properties worth stating plainly
//!
//! **Fail-closed on forgery, fail-per-policy on unreachability.** A tampered or
//! revoked token drops to `FreeLocal` unconditionally — the token's own
//! `FallbackPolicy` is not consulted, because a forged token's policy is
//! attacker-controlled. An *expired* token follows its policy, so a paying user
//! who is merely offline keeps working.
//!
//! **Revocation is sticky, and the fact store is versioned.** Re-storing an
//! `(entity, key)` pair appends a new version rather than replacing the old one,
//! so a naive "find the record" hydration can load a pre-revocation token
//! alongside the revoked one and **resurrect a revoked entitlement on restart** —
//! strictly worse than not persisting at all. Reads therefore take the highest
//! version, and any revocation record at any version wins permanently. No
//! ordering quirk, clock skew, or replayed record can un-revoke a device.

// M2 ships this module dark: it is fully implemented and fully tested, but no
// enforcement path calls it yet — `OperatingMode` still comes from the env var
// until M7 performs the cutover. Every item below is exercised by the state-matrix
// tests at the foot of this file. Remove this allow when M7 wires resolution in.
#![allow(dead_code)]

use corecrux_memory::fact_store::{FactStore, HorizonClass, StoreFact};
use rcx_capability_token::{RcxCapabilityToken, RcxTier, VerifyOutcome};

use crate::product::OperatingMode;

/// Reserved entity for this daemon's own entitlement state. Reserved `__x__::`
/// prefixes are filtered out of consumer-facing memory views.
pub const ENTITLEMENT_ENTITY: &str = "__entitlement__::rcx";
/// Key holding the serialised `RcxCapabilityToken`.
pub const ENTITLEMENT_TOKEN_KEY: &str = "capability_token";
/// Key holding a revocation tombstone. Presence at ANY version is terminal.
pub const ENTITLEMENT_REVOKED_KEY: &str = "revoked";

/// Where entitlement is resolved from. `Env` exists for Max, air-gapped and dev
/// deployments that cannot reach an issuer; it is an explicit, logged override.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntitlementSource {
    Rcx,
    Env,
}

impl EntitlementSource {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "rcx" | "token" | "account" => Some(Self::Rcx),
            "env" | "environment" | "local" => Some(Self::Env),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rcx => "rcx",
            Self::Env => "env",
        }
    }
}

impl Default for EntitlementSource {
    fn default() -> Self {
        Self::Rcx
    }
}

/// Why entitlement resolution did not yield the token's nominal tier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntitlementFailure {
    /// No token persisted. The unpaired-daemon default, not an error.
    Absent,
    /// A token exists but does not parse. Fails closed.
    Malformed,
    /// Signature or trust root did not verify. Forgery — always `FreeLocal`.
    BadSignature,
    /// Structurally invalid against the issuer contract.
    Structural(Vec<String>),
    /// Revoked locally or by the issuer. Terminal and sticky.
    Revoked,
    /// Past `expires_at`. Follows the token's own `FallbackPolicy`.
    Expired,
    /// `tenant_scope` does not match the daemon's tenant. Cross-tenant (T.1).
    WrongTenantScope,
}

impl EntitlementFailure {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Malformed => "malformed",
            Self::BadSignature => "bad_signature",
            Self::Structural(_) => "structural_failure",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::WrongTenantScope => "wrong_tenant_scope",
        }
    }

    /// Whether this failure is an integrity failure. Integrity failures ignore
    /// the token's `FallbackPolicy` entirely — that policy is attacker-controlled
    /// on exactly the tokens that fail this way.
    pub fn is_integrity_failure(&self) -> bool {
        matches!(
            self,
            Self::Malformed | Self::BadSignature | Self::Structural(_) | Self::Revoked | Self::WrongTenantScope
        )
    }
}

/// The outcome of entitlement resolution. `mode` is what the daemon would run as;
/// everything else exists so a startup log can explain *why* without guessing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedEntitlement {
    pub mode: OperatingMode,
    pub source: EntitlementSource,
    /// The tier actually carried by a verified token. `None` when no token
    /// verified — deliberately not defaulted, so "Free because Free" and "Free
    /// because the token was forged" stay distinguishable in logs.
    pub tier: Option<RcxTier>,
    pub failure: Option<EntitlementFailure>,
    /// Which `FallbackPolicy` branch fired, when one did.
    pub fallback_branch: Option<&'static str>,
}

impl ResolvedEntitlement {
    fn free(source: EntitlementSource, failure: Option<EntitlementFailure>) -> Self {
        Self {
            mode: OperatingMode::FreeLocal,
            source,
            tier: None,
            failure,
            fallback_branch: None,
        }
    }

    /// One line for the startup log. The plan calls for the resolved tier *and*
    /// its source to be visible, because the documented `overlay-reverts-on-restart`
    /// failure class silently disabled a capability fleet-wide after a host restart.
    pub fn log_line(&self) -> String {
        use std::fmt::Write as _;
        let mut line = format!(
            "entitlement: mode={} source={}",
            self.mode.as_str(),
            self.source.as_str()
        );
        // Writing into a String is infallible; the Result exists only to satisfy
        // the fmt::Write contract.
        if let Some(tier) = &self.tier {
            let _ = write!(line, " tier={}", tier.as_str());
        }
        if let Some(failure) = &self.failure {
            let _ = write!(line, " failure={}", failure.code());
        }
        if let Some(branch) = self.fallback_branch {
            let _ = write!(line, " fallback={branch}");
        }
        line
    }
}

/// `RcxTier` -> `OperatingMode`.
///
/// Max is **not** a tier. It is a Governance entitlement in a private deployment
/// shape, so it is a composite of tier, source and airgap rather than a value the
/// issuer can hand out. `ProCloudOnly` and `ProHybrid` are unreachable here by
/// design — they are explicit hosted-deployment configuration, not entitlements.
pub fn mode_for_tier(tier: &RcxTier, source: EntitlementSource, airgap: bool) -> OperatingMode {
    match tier {
        RcxTier::Free => OperatingMode::FreeLocal,
        RcxTier::Pro => OperatingMode::ProLocalFirst,
        RcxTier::Governance => {
            if source == EntitlementSource::Env && airgap {
                OperatingMode::MaxPrivate
            } else {
                OperatingMode::GovernanceHosted
            }
        }
    }
}

// ---- store -----------------------------------------------------------------

/// Persist a capability token. Serialised as canonical JSON so the record is
/// inspectable; the signature is over the CBOR signing bytes either way.
pub fn persist_token(store: &mut FactStore, token: &RcxCapabilityToken) {
    store.store(StoreFact {
        tenant_hash: "default".to_string(),
        entity: ENTITLEMENT_ENTITY.to_string(),
        key: ENTITLEMENT_TOKEN_KEY.to_string(),
        value: token.to_canonical_json(),
        source_receipt: None,
        confidence: 1.0,
        private: true,
        horizon_class: Some(HorizonClass::None),
        actor: None,
    });
}

/// Record a terminal revocation. Sticky: presence at any version is permanent,
/// so this cannot be undone by storing a newer token.
pub fn revoke(store: &mut FactStore, reason: &str) {
    store.store(StoreFact {
        tenant_hash: "default".to_string(),
        entity: ENTITLEMENT_ENTITY.to_string(),
        key: ENTITLEMENT_REVOKED_KEY.to_string(),
        value: reason.to_string(),
        source_receipt: None,
        confidence: 1.0,
        private: true,
        horizon_class: Some(HorizonClass::None),
        actor: None,
    });
}

/// Whether this daemon's entitlement has been revoked. Any version wins.
pub fn is_revoked(store: &FactStore) -> bool {
    store
        .all_facts()
        .any(|f| f.entity == ENTITLEMENT_ENTITY && f.key == ENTITLEMENT_REVOKED_KEY && !f.deleted)
}

/// Load the persisted token record, **highest version wins**.
///
/// `all_facts` yields every version of an `(entity, key)` pair. Taking the first
/// match would load whichever version the store happened to return first, which
/// after a re-store is not necessarily the current one.
pub fn load_token_record(store: &FactStore) -> Option<String> {
    store
        .all_facts()
        .filter(|f| f.entity == ENTITLEMENT_ENTITY && f.key == ENTITLEMENT_TOKEN_KEY && !f.deleted)
        .max_by_key(|f| f.version)
        .map(|f| f.value.clone())
}

// ---- verify + resolve ------------------------------------------------------

/// Verify a candidate token without touching the store.
///
/// Pairing uses this to check a freshly-minted token **before** persisting it.
/// Persisting first would be a downgrade vector: writes are versioned and reads
/// take the highest version, so a rejected token written over a good one would
/// silently drop a working Pro daemon to Free on the next resolve.
pub fn verify_candidate(
    token: &RcxCapabilityToken,
    trust_root_pubkey: &[u8],
    now_unix_seconds: u64,
    daemon_tenant_id: &str,
) -> Option<EntitlementFailure> {
    if token.tenant_scope.tenant_id != daemon_tenant_id {
        return Some(EntitlementFailure::WrongTenantScope);
    }
    match rcx_capability_token::verify_token(token, trust_root_pubkey, now_unix_seconds) {
        VerifyOutcome::Verified => None,
        VerifyOutcome::BadSignature | VerifyOutcome::BadTrustRoot => Some(EntitlementFailure::BadSignature),
        VerifyOutcome::StructuralFailure(issues) => {
            if !issues.iter().any(|issue| issue == "token_expired") {
                return Some(EntitlementFailure::Structural(issues));
            }
            let when_fresh = token.issued_at.saturating_add(1);
            if rcx_capability_token::verify_token(token, trust_root_pubkey, when_fresh) != VerifyOutcome::Verified {
                return Some(EntitlementFailure::BadSignature);
            }
            Some(EntitlementFailure::Expired)
        }
    }
}

/// Resolve the daemon's operating mode from persisted entitlement state.
///
/// **Dark in M2** — no caller enforces on this yet.
pub fn resolve_entitlement(
    store: &FactStore,
    trust_root_pubkey: &[u8],
    now_unix_seconds: u64,
    daemon_tenant_id: &str,
    source: EntitlementSource,
    airgap: bool,
    env_mode: OperatingMode,
) -> ResolvedEntitlement {
    // The explicit override. Logged, never silent.
    if source == EntitlementSource::Env {
        return ResolvedEntitlement {
            mode: env_mode,
            source,
            tier: None,
            failure: None,
            fallback_branch: None,
        };
    }

    // Revocation is checked before anything else and is terminal. A revoked
    // daemon must not be rescued by a newer token arriving underneath it.
    if is_revoked(store) {
        return ResolvedEntitlement::free(source, Some(EntitlementFailure::Revoked));
    }

    let Some(raw) = load_token_record(store) else {
        return ResolvedEntitlement::free(source, Some(EntitlementFailure::Absent));
    };

    let Ok(token) = serde_json::from_str::<RcxCapabilityToken>(&raw) else {
        return ResolvedEntitlement::free(source, Some(EntitlementFailure::Malformed));
    };

    // Tenant scope before signature is deliberate only in that both fail closed;
    // a token for another tenant is never this daemon's entitlement even if it
    // is perfectly valid for its own.
    if token.tenant_scope.tenant_id != daemon_tenant_id {
        return ResolvedEntitlement::free(source, Some(EntitlementFailure::WrongTenantScope));
    }

    match rcx_capability_token::verify_token(&token, trust_root_pubkey, now_unix_seconds) {
        VerifyOutcome::Verified => {}
        VerifyOutcome::BadSignature | VerifyOutcome::BadTrustRoot => {
            return ResolvedEntitlement::free(source, Some(EntitlementFailure::BadSignature));
        }
        VerifyOutcome::StructuralFailure(issues) => {
            // Expiry arrives here, as a `token_expired` issue, and is the one
            // structural outcome that is not an integrity failure: a paying user
            // merely offline past `expires_at` follows the token's own policy
            // rather than being treated as a forger. Note the crate applies a
            // 30s clock-skew leeway (`DEFAULT_CLOCK_SKEW_LEEWAY_SECS`), which is
            // deliberate tolerance and is honoured rather than second-guessed.
            if !issues.iter().any(|issue| issue == "token_expired") {
                return ResolvedEntitlement::free(source, Some(EntitlementFailure::Structural(issues)));
            }

            // `verify_issuer_signed_token` validates STRUCTURE BEFORE SIGNATURE,
            // so an expired *forgery* also lands here — and would otherwise have
            // its attacker-chosen `FallbackPolicy` honoured. Establish that the
            // token was ever genuine by verifying it at an instant inside its own
            // validity window; only then is its policy worth reading.
            let when_fresh = token.issued_at.saturating_add(1);
            if rcx_capability_token::verify_token(&token, trust_root_pubkey, when_fresh) != VerifyOutcome::Verified {
                return ResolvedEntitlement::free(source, Some(EntitlementFailure::BadSignature));
            }

            let branch = match token.fallback.on_expiry {
                rcx_capability_token::FallbackAction::DegradeToLocal => "on_expiry=degrade_to_local",
                rcx_capability_token::FallbackAction::Refuse => "on_expiry=refuse",
                rcx_capability_token::FallbackAction::Queue => "on_expiry=queue",
            };
            return ResolvedEntitlement {
                mode: OperatingMode::FreeLocal,
                source,
                tier: None,
                failure: Some(EntitlementFailure::Expired),
                fallback_branch: Some(branch),
            };
        }
    }

    ResolvedEntitlement {
        mode: mode_for_tier(&token.tier, source, airgap),
        source,
        tier: Some(token.tier.clone()),
        failure: None,
        fallback_branch: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rcx_capability_token::free_local_verified_fixture;

    const NOW: u64 = 1_776_989_601;

    pub(super) fn issuer() -> SigningKey {
        SigningKey::from_bytes(&[9u8; 32])
    }

    pub(super) fn trust_root(key: &SigningKey) -> Vec<u8> {
        key.verifying_key().to_bytes().to_vec()
    }

    /// A signed, currently-valid token for `tier`, scoped to tenant `default`.
    pub(super) fn signed_token(key: &SigningKey, tier: RcxTier) -> RcxCapabilityToken {
        let mut token = free_local_verified_fixture();
        token.tier = tier;
        token.issued_at = NOW - 60;
        token.expires_at = NOW + 3_600;
        token.refresh_hint_at = NOW + 1_800;
        // Governance requires enterprise_scope (M1 invariant); the fixture is Free,
        // so borrow the fixture's own scope shape rather than invent one.
        if token.tier == RcxTier::Governance {
            token.enterprise_scope = Some(rcx_capability_token::EnterpriseScope {
                customer_id: "customer-a".to_string(),
                contract_id: None,
                backend_id: "customer:cluster-a".to_string(),
                endpoint_url: "https://cluster-a.customer.example/rcx".to_string(),
                trust_root_kid: "customer-root-a".to_string(),
                airgap: true,
                cross_signed_by_vaultcrux: true,
            });
            token.backends[0].backend_id = "customer:cluster-a".to_string();
            token.backends[0].trust_root_kid = "customer-root-a".to_string();
            token.backends[0].endpoint_url = Some("https://cluster-a.customer.example/rcx".to_string());
        }
        token.signature.sig = key.sign(&token.token_hash()).to_bytes();
        token
    }

    fn resolve(store: &FactStore, key: &SigningKey, now: u64) -> ResolvedEntitlement {
        resolve_entitlement(
            store,
            &trust_root(key),
            now,
            "default",
            EntitlementSource::Rcx,
            false,
            OperatingMode::FreeLocal,
        )
    }

    // ---- the blocking state matrix -------------------------------------------
    // {absent, valid Free, valid Pro, valid Governance, expired, revoked,
    //  tampered signature, wrong tenant_scope, malformed} -> resolved mode.

    #[test]
    fn absent_token_resolves_free_local() {
        let key = issuer();
        let store = FactStore::new();
        let r = resolve(&store, &key, NOW);
        assert_eq!(r.mode, OperatingMode::FreeLocal);
        assert_eq!(r.failure, Some(EntitlementFailure::Absent));
        assert_eq!(r.tier, None, "no token means no tier, not a defaulted one");
    }

    #[test]
    fn valid_tokens_map_each_tier_to_its_mode() {
        for (tier, expected) in [
            (RcxTier::Free, OperatingMode::FreeLocal),
            (RcxTier::Pro, OperatingMode::ProLocalFirst),
            (RcxTier::Governance, OperatingMode::GovernanceHosted),
        ] {
            let key = issuer();
            let mut store = FactStore::new();
            persist_token(&mut store, &signed_token(&key, tier.clone()));
            let r = resolve(&store, &key, NOW);
            assert_eq!(r.mode, expected, "tier {:?}", tier);
            assert_eq!(r.failure, None, "tier {:?} should verify cleanly", tier);
            assert_eq!(r.tier, Some(tier));
        }
    }

    #[test]
    fn tampered_signature_resolves_free_local_and_ignores_token_policy() {
        let key = issuer();
        let mut store = FactStore::new();
        let mut token = signed_token(&key, RcxTier::Pro);
        // A forger would of course also set the most generous fallback policy.
        token.fallback.on_expiry = rcx_capability_token::FallbackAction::DegradeToLocal;
        token.signature.sig = [0xAA; 64];
        persist_token(&mut store, &token);

        let r = resolve(&store, &key, NOW);
        assert_eq!(r.mode, OperatingMode::FreeLocal);
        assert_eq!(r.failure, Some(EntitlementFailure::BadSignature));
        assert!(r.failure.as_ref().unwrap().is_integrity_failure());
        assert_eq!(
            r.fallback_branch, None,
            "a forged token's own FallbackPolicy must never be consulted"
        );
    }

    #[test]
    fn wrong_trust_root_resolves_free_local() {
        let key = issuer();
        let other = SigningKey::from_bytes(&[3u8; 32]);
        let mut store = FactStore::new();
        persist_token(&mut store, &signed_token(&key, RcxTier::Pro));

        let r = resolve(&store, &other, NOW);
        assert_eq!(r.mode, OperatingMode::FreeLocal);
        assert_eq!(r.failure, Some(EntitlementFailure::BadSignature));
    }

    #[test]
    fn cross_tenant_token_does_not_entitle_this_daemon() {
        // Test-plan item T.1: tenant A's token must not entitle tenant B.
        let key = issuer();
        let mut store = FactStore::new();
        persist_token(&mut store, &signed_token(&key, RcxTier::Pro));

        let r = resolve_entitlement(
            &store,
            &trust_root(&key),
            NOW,
            "some-other-tenant",
            EntitlementSource::Rcx,
            false,
            OperatingMode::FreeLocal,
        );
        assert_eq!(r.mode, OperatingMode::FreeLocal);
        assert_eq!(r.failure, Some(EntitlementFailure::WrongTenantScope));
    }

    #[test]
    fn malformed_record_fails_closed() {
        let key = issuer();
        let mut store = FactStore::new();
        store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: ENTITLEMENT_ENTITY.to_string(),
            key: ENTITLEMENT_TOKEN_KEY.to_string(),
            value: "{ not a token".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: true,
            horizon_class: Some(HorizonClass::None),
            actor: None,
        });
        let r = resolve(&store, &key, NOW);
        assert_eq!(r.mode, OperatingMode::FreeLocal);
        assert_eq!(r.failure, Some(EntitlementFailure::Malformed));
    }

    #[test]
    fn expired_token_follows_its_own_fallback_policy() {
        let key = issuer();
        let mut store = FactStore::new();
        persist_token(&mut store, &signed_token(&key, RcxTier::Pro));

        // Beyond expiry AND beyond the 30s clock-skew leeway.
        let r = resolve(&store, &key, NOW + 3_600 + 31);
        assert_eq!(r.mode, OperatingMode::FreeLocal);
        assert_eq!(r.failure, Some(EntitlementFailure::Expired));
        assert!(
            !r.failure.as_ref().unwrap().is_integrity_failure(),
            "expiry is not forgery — a paying user merely offline must follow policy"
        );
        assert!(
            r.fallback_branch.is_some_and(|b| b.starts_with("on_expiry=")),
            "the fired FallbackPolicy branch must be reported, got {:?}",
            r.fallback_branch
        );
    }

    // ---- revocation: the resurrection class of bug ---------------------------

    #[test]
    fn revocation_resolves_free_local() {
        let key = issuer();
        let mut store = FactStore::new();
        persist_token(&mut store, &signed_token(&key, RcxTier::Pro));
        revoke(&mut store, "issuer CRL");

        let r = resolve(&store, &key, NOW);
        assert_eq!(r.mode, OperatingMode::FreeLocal);
        assert_eq!(r.failure, Some(EntitlementFailure::Revoked));
    }

    #[test]
    fn revocation_is_sticky_against_a_newer_valid_token() {
        // THE regression this module exists to prevent. The fact store is
        // versioned: re-storing (entity, key) appends rather than replaces. A
        // naive hydration can load a pre-revocation record and resurrect a
        // revoked entitlement on restart — strictly worse than not persisting.
        let key = issuer();
        let mut store = FactStore::new();
        persist_token(&mut store, &signed_token(&key, RcxTier::Pro));
        revoke(&mut store, "issuer CRL");
        // A replayed or newly-minted token arrives after revocation.
        persist_token(&mut store, &signed_token(&key, RcxTier::Governance));

        let r = resolve(&store, &key, NOW);
        assert_eq!(
            r.mode,
            OperatingMode::FreeLocal,
            "a revoked daemon must not be rescued by a later token"
        );
        assert_eq!(r.failure, Some(EntitlementFailure::Revoked));
    }

    #[test]
    fn load_takes_the_highest_version_not_the_first_match() {
        let key = issuer();
        let mut store = FactStore::new();
        persist_token(&mut store, &signed_token(&key, RcxTier::Free));
        persist_token(&mut store, &signed_token(&key, RcxTier::Pro));

        let versions = store
            .all_facts()
            .filter(|f| f.entity == ENTITLEMENT_ENTITY && f.key == ENTITLEMENT_TOKEN_KEY)
            .count();
        assert!(
            versions > 1,
            "precondition: the store must actually append versions, saw {versions}"
        );

        let r = resolve(&store, &key, NOW);
        assert_eq!(r.tier, Some(RcxTier::Pro), "the newest record must win");
        assert_eq!(r.mode, OperatingMode::ProLocalFirst);
    }

    // ---- the Max composite ---------------------------------------------------

    #[test]
    fn max_is_a_composite_not_a_tier() {
        // Max = Governance entitlement + private deployment shape. No issuer can
        // hand out MaxPrivate, and Governance alone never reaches it.
        assert_eq!(
            mode_for_tier(&RcxTier::Governance, EntitlementSource::Env, true),
            OperatingMode::MaxPrivate
        );
        assert_eq!(
            mode_for_tier(&RcxTier::Governance, EntitlementSource::Env, false),
            OperatingMode::GovernanceHosted,
            "env source without airgap is not Max"
        );
        assert_eq!(
            mode_for_tier(&RcxTier::Governance, EntitlementSource::Rcx, true),
            OperatingMode::GovernanceHosted,
            "airgap without the env override is not Max"
        );
        for tier in [RcxTier::Free, RcxTier::Pro] {
            assert_ne!(
                mode_for_tier(&tier, EntitlementSource::Env, true),
                OperatingMode::MaxPrivate,
                "{tier:?} must never reach MaxPrivate"
            );
        }
    }

    #[test]
    fn env_source_is_an_explicit_logged_override() {
        let key = issuer();
        let mut store = FactStore::new();
        persist_token(&mut store, &signed_token(&key, RcxTier::Pro));

        let r = resolve_entitlement(
            &store,
            &trust_root(&key),
            NOW,
            "default",
            EntitlementSource::Env,
            true,
            OperatingMode::MaxPrivate,
        );
        assert_eq!(r.mode, OperatingMode::MaxPrivate);
        assert_eq!(r.source, EntitlementSource::Env);
        assert!(
            r.log_line().contains("source=env"),
            "the override must be visible: {}",
            r.log_line()
        );
    }

    // ---- plumbing ------------------------------------------------------------

    #[test]
    fn entitlement_source_parses_and_defaults_to_rcx() {
        assert_eq!(EntitlementSource::default(), EntitlementSource::Rcx);
        assert_eq!(EntitlementSource::parse("rcx"), Some(EntitlementSource::Rcx));
        assert_eq!(EntitlementSource::parse(" ENV "), Some(EntitlementSource::Env));
        assert_eq!(EntitlementSource::parse("licence-key"), None);
    }

    #[test]
    fn entitlement_state_is_born_private_and_never_expires() {
        // Entitlement is this daemon's own state: it must not sync outward, and
        // must not be aged out by a freshness horizon.
        let key = issuer();
        let mut store = FactStore::new();
        persist_token(&mut store, &signed_token(&key, RcxTier::Pro));
        revoke(&mut store, "test");

        let records: Vec<_> = store.all_facts().filter(|f| f.entity == ENTITLEMENT_ENTITY).collect();
        assert!(!records.is_empty());
        for f in records {
            assert!(f.private, "{} must be private", f.key);
            assert_eq!(f.horizon_class, HorizonClass::None, "{} must not decay", f.key);
        }
    }

    #[test]
    fn log_line_distinguishes_free_by_entitlement_from_free_by_failure() {
        let key = issuer();
        let mut clean = FactStore::new();
        persist_token(&mut clean, &signed_token(&key, RcxTier::Free));
        let entitled_free = resolve(&clean, &key, NOW).log_line();

        let mut forged = FactStore::new();
        let mut token = signed_token(&key, RcxTier::Pro);
        token.signature.sig = [0xAA; 64];
        persist_token(&mut forged, &token);
        let failed_free = resolve(&forged, &key, NOW).log_line();

        assert!(entitled_free.contains("tier=free"), "{entitled_free}");
        assert!(!entitled_free.contains("failure="), "{entitled_free}");
        assert!(failed_free.contains("failure=bad_signature"), "{failed_free}");
        assert_ne!(entitled_free, failed_free, "the two Frees must be distinguishable");
    }
}

#[cfg(test)]
mod expiry_regression {
    //! Expiry semantics are subtle enough to pin explicitly. `verify_token` DOES
    //! enforce `expires_at`, but with a 30s clock-skew leeway, and it validates
    //! structure BEFORE signature — so an expired forgery reaches the same branch
    //! as an honestly expired token.
    use super::tests::{issuer, signed_token, trust_root};
    use super::*;

    const LEEWAY: u64 = 30;

    #[test]
    fn clock_skew_leeway_is_honoured_not_second_guessed() {
        // A token one second past expiry still verifies: that tolerance is the
        // point of the leeway. Re-deriving expiry locally with a bare
        // `now > expires_at` would defeat it and drop paying users on clock skew.
        let key = issuer();
        let mut store = FactStore::new();
        let token = signed_token(&key, RcxTier::Pro);
        let expires_at = token.expires_at;
        persist_token(&mut store, &token);

        let inside = resolve_entitlement(
            &store,
            &trust_root(&key),
            expires_at + 1,
            "default",
            EntitlementSource::Rcx,
            false,
            OperatingMode::FreeLocal,
        );
        assert_eq!(
            inside.mode,
            OperatingMode::ProLocalFirst,
            "within leeway must still be entitled"
        );
        assert_eq!(inside.failure, None);

        let outside = resolve_entitlement(
            &store,
            &trust_root(&key),
            expires_at + LEEWAY + 1,
            "default",
            EntitlementSource::Rcx,
            false,
            OperatingMode::FreeLocal,
        );
        assert_eq!(outside.mode, OperatingMode::FreeLocal, "past the leeway must expire");
        assert_eq!(outside.failure, Some(EntitlementFailure::Expired));
    }

    #[test]
    fn an_expired_forgery_reports_forgery_not_expiry() {
        // The crate validates structure before signature, so a forged AND expired
        // token surfaces as `token_expired`. Without the re-verification at a
        // fresh instant, its attacker-chosen FallbackPolicy would be read as if
        // it came from a genuine token.
        let key = issuer();
        let mut store = FactStore::new();
        let mut token = signed_token(&key, RcxTier::Pro);
        token.fallback.on_expiry = rcx_capability_token::FallbackAction::DegradeToLocal;
        token.signature.sig = [0xAA; 64];
        let expires_at = token.expires_at;
        persist_token(&mut store, &token);

        let r = resolve_entitlement(
            &store,
            &trust_root(&key),
            expires_at + LEEWAY + 1,
            "default",
            EntitlementSource::Rcx,
            false,
            OperatingMode::FreeLocal,
        );
        assert_eq!(r.mode, OperatingMode::FreeLocal);
        assert_eq!(
            r.failure,
            Some(EntitlementFailure::BadSignature),
            "an expired forgery must be reported as forgery"
        );
        assert_eq!(r.fallback_branch, None, "a forged token's policy must never be read");
    }
}
