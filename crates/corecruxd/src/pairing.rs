// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Account pairing — how a daemon acquires its entitlement without a typed secret.
//!
//! ExecPlan `crux-pro-capabilities-rcx-entitled-2026-07-27` M3. **Ships dark:**
//! nothing calls this yet. It is the bridge between the shipped device-authorisation
//! grant and the M2 entitlement store.
//!
//! # Why there is no typed secret
//!
//! The published vow forbids a licence key, and a licence key is not only a
//! `CORECRUXD_ENABLED_PRO_SERVICES` env var — it is *any* long-lived bearer value
//! the operator copies into a config file. So pairing reuses the RFC 8628 device
//! grant already shipped at `/v1/auth/device/*` ([`http/auth_device.rs`]):
//!
//! ```text
//! 1. daemon  -> POST /v1/auth/device/start
//!               <- {device_code, user_code, verification_uri, interval, expires_in}
//! 2. operator -> opens verification_uri in a browser they are ALREADY logged into,
//!                enters the short user_code, approves, picks the tenant
//! 3. daemon  -> POST /v1/auth/device/token (polls at `interval`)
//!               <- an approved grant
//! 4. daemon  -> exchanges the grant for a tenant-scoped RcxCapabilityToken whose
//!               `tier` comes from the live subscription, then persists it
//! 5. daemon  -> re-pairs silently at `refresh_hint_at`, before `expires_at`
//! ```
//!
//! The `user_code` is **not** a secret: it is a short-lived, single-use public
//! correlator, useless without an authenticated browser session on the other side.
//! Nothing durable is ever copied into a config file. `pairing_inputs_are_not_secrets`
//! pins that distinction, because "we replaced the licence key with a shorter string
//! the user types" is the obvious wrong turn here.
//!
//! # What this module does NOT do
//!
//! It does not mint. Minting is CueCrux Account's job (CruxEngine), and step 4's
//! exchange endpoint does not exist yet — see the M3 human-gate packet. The token
//! source is therefore injected, so the daemon-side state machine is complete and
//! testable ahead of the platform half.

#![allow(dead_code)]

use rcx_capability_token::RcxCapabilityToken;

use crate::entitlement;
use corecrux_memory::fact_store::FactStore;

/// Where the daemon is in the pairing handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairingState {
    /// No pairing attempted. An unpaired daemon is Free and fully functional.
    Unpaired,
    /// A device grant is open. The operator has not approved yet.
    AwaitingApproval {
        user_code: String,
        verification_uri: String,
        /// Poll no faster than this, per RFC 8628.
        interval_seconds: u64,
        expires_at_unix_seconds: u64,
    },
    /// A token was obtained and persisted.
    Paired {
        token_id: String,
        tier: String,
        refresh_at_unix_seconds: u64,
        expires_at_unix_seconds: u64,
    },
    /// The grant expired, was denied, or the exchange failed.
    Failed { reason: PairingFailure },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairingFailure {
    /// The operator did not approve before the grant expired.
    GrantExpired,
    /// The operator explicitly declined.
    Denied,
    /// The minted token did not verify, or was for the wrong tenant.
    TokenRejected(String),
}

impl PairingFailure {
    pub fn code(&self) -> &'static str {
        match self {
            Self::GrantExpired => "grant_expired",
            Self::Denied => "denied",
            Self::TokenRejected(_) => "token_rejected",
        }
    }
}

/// The open device grant, as returned by `POST /v1/auth/device/start`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceGrant {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub interval_seconds: u64,
    pub expires_at_unix_seconds: u64,
}

impl DeviceGrant {
    pub fn state(&self) -> PairingState {
        PairingState::AwaitingApproval {
            user_code: self.user_code.clone(),
            verification_uri: self.verification_uri.clone(),
            interval_seconds: self.interval_seconds,
            expires_at_unix_seconds: self.expires_at_unix_seconds,
        }
    }

    pub fn is_expired(&self, now_unix_seconds: u64) -> bool {
        now_unix_seconds >= self.expires_at_unix_seconds
    }
}

/// The result of polling an open grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PollOutcome {
    /// Not approved yet. Poll again no sooner than `interval_seconds`.
    Pending,
    /// Approved; the exchange yielded a token.
    Approved(Box<RcxCapabilityToken>),
    Denied,
}

/// Exchanges an approved device grant for a capability token.
///
/// Injected so the daemon-side flow is testable before CueCrux Account ships the
/// exchange endpoint. The real implementation performs an HTTP round trip; it is
/// deliberately not written here, because guessing a contract the platform has not
/// defined would be a claim this module cannot support.
pub trait TokenSource {
    fn poll(&mut self, grant: &DeviceGrant, now_unix_seconds: u64) -> PollOutcome;
}

/// Advance the handshake by one poll, persisting **only** on successful verification.
///
/// Verification is not skipped just because the token arrived over an approved
/// grant: an approved grant proves the operator consented, not that the bytes are
/// authentic. It runs the same checks `resolve_entitlement` applies at boot, but
/// against the candidate rather than the store — so a rejected token is never
/// written, and cannot displace a good one through version precedence.
pub fn advance<S: TokenSource>(
    store: &mut FactStore,
    source: &mut S,
    grant: &DeviceGrant,
    trust_root_pubkey: &[u8],
    now_unix_seconds: u64,
    daemon_tenant_id: &str,
) -> PairingState {
    if grant.is_expired(now_unix_seconds) {
        return PairingState::Failed {
            reason: PairingFailure::GrantExpired,
        };
    }

    match source.poll(grant, now_unix_seconds) {
        PollOutcome::Pending => grant.state(),
        PollOutcome::Denied => PairingState::Failed {
            reason: PairingFailure::Denied,
        },
        PollOutcome::Approved(token) => {
            // Verify BEFORE persisting. Writes are versioned and reads take the
            // highest version, so persisting a rejected token over a good one would
            // silently downgrade a working Pro daemon to Free on the next resolve —
            // a downgrade vector reachable from a buggy or hostile mint.
            match entitlement::verify_candidate(&token, trust_root_pubkey, now_unix_seconds, daemon_tenant_id) {
                None => {
                    entitlement::persist_token(store, &token);
                    PairingState::Paired {
                        token_id: token.token_id.clone(),
                        tier: token.tier.as_str().to_string(),
                        refresh_at_unix_seconds: token.refresh_hint_at,
                        expires_at_unix_seconds: token.expires_at,
                    }
                }
                Some(failure) => PairingState::Failed {
                    reason: PairingFailure::TokenRejected(failure.code().to_string()),
                },
            }
        }
    }
}

/// Whether it is time to re-pair silently.
///
/// Refresh is driven by `refresh_hint_at`, deliberately **before** `expires_at`, so
/// a paying user never reaches expiry during normal operation and never sees a
/// pairing prompt again. A daemon that is offline across its refresh window keeps
/// working until `expires_at` and then follows the token's own `FallbackPolicy`.
pub fn needs_refresh(token: &RcxCapabilityToken, now_unix_seconds: u64) -> bool {
    now_unix_seconds >= token.refresh_hint_at
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rcx_capability_token::{free_local_verified_fixture, RcxTier};

    const NOW: u64 = 1_776_989_601;

    fn issuer() -> SigningKey {
        SigningKey::from_bytes(&[9u8; 32])
    }

    fn trust_root(k: &SigningKey) -> Vec<u8> {
        k.verifying_key().to_bytes().to_vec()
    }

    fn pro_token(key: &SigningKey) -> RcxCapabilityToken {
        let mut t = free_local_verified_fixture();
        t.tier = RcxTier::Pro;
        t.issued_at = NOW - 60;
        t.refresh_hint_at = NOW + 1_800;
        t.expires_at = NOW + 3_600;
        t.signature.sig = key.sign(&t.token_hash()).to_bytes();
        t
    }

    fn grant() -> DeviceGrant {
        DeviceGrant {
            device_code: "dc_0123456789abcdef".to_string(),
            user_code: "BDXR-KQTZ".to_string(),
            verification_uri: "https://cuecrux.com/activate".to_string(),
            interval_seconds: 5,
            expires_at_unix_seconds: NOW + 600,
        }
    }

    struct Scripted(Vec<PollOutcome>);
    impl TokenSource for Scripted {
        fn poll(&mut self, _g: &DeviceGrant, _now: u64) -> PollOutcome {
            if self.0.is_empty() {
                PollOutcome::Pending
            } else {
                self.0.remove(0)
            }
        }
    }

    #[test]
    fn a_clean_daemon_reaches_pro_without_a_typed_secret() {
        let key = issuer();
        let mut store = FactStore::new();
        let mut src = Scripted(vec![
            PollOutcome::Pending,
            PollOutcome::Approved(Box::new(pro_token(&key))),
        ]);
        let g = grant();

        // First poll: still waiting on the browser.
        let s = advance(&mut store, &mut src, &g, &trust_root(&key), NOW, "default");
        assert!(matches!(s, PairingState::AwaitingApproval { .. }));

        // Second poll: approved, token persisted, daemon is Pro.
        let s = advance(&mut store, &mut src, &g, &trust_root(&key), NOW, "default");
        match s {
            PairingState::Paired {
                tier,
                refresh_at_unix_seconds,
                expires_at_unix_seconds,
                ..
            } => {
                assert_eq!(tier, "pro");
                assert!(
                    refresh_at_unix_seconds < expires_at_unix_seconds,
                    "refresh must precede expiry or a paying user hits a prompt"
                );
            }
            other => panic!("expected Paired, got {other:?}"),
        }

        // And it resolves Pro from disk on the next boot, with no further input.
        let resolved = entitlement::resolve_entitlement(
            &store,
            &trust_root(&key),
            NOW,
            "default",
            entitlement::EntitlementSource::Rcx,
            false,
            crate::product::OperatingMode::FreeLocal,
        );
        assert_eq!(resolved.mode, crate::product::OperatingMode::ProLocalFirst);
    }

    #[test]
    fn pairing_inputs_are_not_secrets() {
        // The wrong turn here is replacing the licence key with a shorter string
        // the operator types. The user_code is a single-use, short-lived, PUBLIC
        // correlator: useless without an authenticated browser session, and never
        // written to configuration. Nothing durable is typed anywhere.
        let g = grant();
        assert!(g.expires_at_unix_seconds - NOW <= 900, "user_code must be short-lived");
        assert!(
            !g.verification_uri.contains(&g.user_code),
            "the code must be entered in an authenticated session, not carried in a link the daemon holds"
        );

        // The durable credential is the token, and it arrives over the wire — it is
        // never an operator input. No pairing type carries a config-shaped secret.
        let key = issuer();
        let mut store = FactStore::new();
        let mut src = Scripted(vec![PollOutcome::Approved(Box::new(pro_token(&key)))]);
        advance(&mut store, &mut src, &g, &trust_root(&key), NOW, "default");
        let persisted = entitlement::load_token_record(&store).expect("token persisted");
        assert!(
            !persisted.contains(&g.user_code) && !persisted.contains(&g.device_code),
            "no pairing-time code may survive into durable entitlement state"
        );
    }

    #[test]
    fn an_approved_grant_does_not_bypass_verification() {
        // Operator consent proves intent, not authenticity. A forged token that
        // arrives over a genuinely approved grant must still fail closed.
        let key = issuer();
        let mut forged = pro_token(&key);
        forged.signature.sig = [0xAA; 64];
        let mut store = FactStore::new();
        let mut src = Scripted(vec![PollOutcome::Approved(Box::new(forged))]);

        let s = advance(&mut store, &mut src, &grant(), &trust_root(&key), NOW, "default");
        assert_eq!(
            s,
            PairingState::Failed {
                reason: PairingFailure::TokenRejected("bad_signature".to_string())
            }
        );
    }

    #[test]
    fn a_token_for_another_tenant_does_not_pair_this_daemon() {
        let key = issuer();
        let mut store = FactStore::new();
        let mut src = Scripted(vec![PollOutcome::Approved(Box::new(pro_token(&key)))]);
        let s = advance(&mut store, &mut src, &grant(), &trust_root(&key), NOW, "another-tenant");
        assert_eq!(
            s,
            PairingState::Failed {
                reason: PairingFailure::TokenRejected("wrong_tenant_scope".to_string())
            }
        );
    }

    #[test]
    fn an_expired_grant_fails_without_polling() {
        let key = issuer();
        let mut store = FactStore::new();
        // Would approve if asked — it must not be asked.
        let mut src = Scripted(vec![PollOutcome::Approved(Box::new(pro_token(&key)))]);
        let g = grant();
        let s = advance(
            &mut store,
            &mut src,
            &g,
            &trust_root(&key),
            g.expires_at_unix_seconds,
            "default",
        );
        assert_eq!(
            s,
            PairingState::Failed {
                reason: PairingFailure::GrantExpired
            }
        );
        assert!(
            entitlement::load_token_record(&store).is_none(),
            "an expired grant must persist nothing"
        );
    }

    #[test]
    fn denial_is_terminal_and_persists_nothing() {
        let key = issuer();
        let mut store = FactStore::new();
        let mut src = Scripted(vec![PollOutcome::Denied]);
        let s = advance(&mut store, &mut src, &grant(), &trust_root(&key), NOW, "default");
        assert_eq!(
            s,
            PairingState::Failed {
                reason: PairingFailure::Denied
            }
        );
        assert!(entitlement::load_token_record(&store).is_none());
    }

    #[test]
    fn a_rejected_token_cannot_downgrade_an_already_paired_daemon() {
        // Writes are versioned and reads take the highest version, so persisting a
        // rejected token would silently drop a working Pro daemon to Free on the
        // next resolve. Verification therefore happens before the write.
        let key = issuer();
        let mut store = FactStore::new();

        let mut src = Scripted(vec![PollOutcome::Approved(Box::new(pro_token(&key)))]);
        assert!(matches!(
            advance(&mut store, &mut src, &grant(), &trust_root(&key), NOW, "default"),
            PairingState::Paired { .. }
        ));

        // A later forged token arrives over an approved grant.
        let mut forged = pro_token(&key);
        forged.token_id = "rcxct_forged".to_string();
        forged.signature.sig = [0xAA; 64];
        let mut bad = Scripted(vec![PollOutcome::Approved(Box::new(forged))]);
        let s = advance(&mut store, &mut bad, &grant(), &trust_root(&key), NOW, "default");
        assert!(matches!(s, PairingState::Failed { .. }));

        // The daemon is still Pro, and the forged token was never written.
        let resolved = entitlement::resolve_entitlement(
            &store,
            &trust_root(&key),
            NOW,
            "default",
            entitlement::EntitlementSource::Rcx,
            false,
            crate::product::OperatingMode::FreeLocal,
        );
        assert_eq!(
            resolved.mode,
            crate::product::OperatingMode::ProLocalFirst,
            "a rejected token must not displace a good one"
        );
        assert!(!entitlement::load_token_record(&store).unwrap().contains("rcxct_forged"));
    }

    #[test]
    fn refresh_fires_at_the_hint_and_before_expiry() {
        let key = issuer();
        let token = pro_token(&key);
        assert!(!needs_refresh(&token, token.refresh_hint_at - 1));
        assert!(needs_refresh(&token, token.refresh_hint_at));
        assert!(
            token.refresh_hint_at < token.expires_at,
            "refreshing at or after expiry would strand a paying user"
        );
    }

    #[test]
    fn an_unpaired_daemon_is_free_not_broken() {
        // The vow: Free is not degraded. An unpaired daemon resolves Free with an
        // `absent` reason, never an error state.
        let key = issuer();
        let store = FactStore::new();
        let resolved = entitlement::resolve_entitlement(
            &store,
            &trust_root(&key),
            NOW,
            "default",
            entitlement::EntitlementSource::Rcx,
            false,
            crate::product::OperatingMode::FreeLocal,
        );
        assert_eq!(resolved.mode, crate::product::OperatingMode::FreeLocal);
        assert_eq!(resolved.failure, Some(entitlement::EntitlementFailure::Absent));
        assert_eq!(PairingState::Unpaired, PairingState::Unpaired);
    }
}
