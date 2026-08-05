// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Relay device identity and the delegation envelope the daemon presents.
//!
//! M1 of ExecPlan `crux-hosted-relay-gateway-2026-07-30`, resolved by **OD-44:
//! the daemon self-attenuates.**
//!
//! The relay contract requires the daemon to `attach` with an **already
//! attenuated** token (§4 F2) whose `envelope.delegate_public_key` equals the
//! key it proves possession of (§5). [`RcxCapabilityToken::attenuate_for`] is
//! the only producer of such an envelope, and it requires the **subject's**
//! signing key while rejecting `delegate_fpr == delegator_fpr`.
//!
//! An earlier reading concluded the daemon therefore could not mint its own
//! envelope. That assumed subject and delegate are the same key. They are not:
//! the subject is the daemon's **passport**, the delegate is a **separate
//! per-device key**, and `attenuate_for` compares *fingerprints*. The daemon
//! holds both, so the edge is legal and needs no new custody.
//!
//! ## Why this is not a self-signed capability
//!
//! The envelope is not what authenticates the daemon. The **base token** is
//! issuer-signed, carries `tenant_scope`, and is revocable through the M2 CRL.
//! Caveats must be non-empty and *strictly narrow*, so a self-attenuating
//! daemon can only ever reduce what it already holds, and cannot borrow another
//! tenant's authority because tenant scope lives in the issuer-signed half.
//! The envelope buys least-privilege scoping at the relay boundary; the human
//! authorisation it might otherwise represent is already delivered by the
//! pairing flow.
//!
//! This module contains `attenuate_for`'s **first production caller** anywhere
//! in the tree — every other call site is a test.

use crux_session::passport::{passport_fpr_from_public_key, LocalPassportKey};
use ed25519_dalek::{Signer, SigningKey};
use rcx_capability_token::{AttenuateError, Caveat, RcxCapabilityToken, RCX_RELAY_SESSION_CAPABILITY};
use zeroize::Zeroizing;

use crate::hosted_token::HostedToken;

/// Domain-separation context for the device key.
///
/// Versioned, per the convention already used for
/// `integration-token-encryption-v1` and the snapshot key. Changing this string
/// mints a **different device identity**, which the registry would not
/// recognise — so it is a breaking change, not a tweak.
pub const DEVICE_KEY_CONTEXT: &str = "crux-relay-device-key-v1";

/// Default envelope lifetime. Short by design: the envelope is re-mintable
/// locally at zero cost (no network, no human), so a short life costs nothing
/// and bounds the damage from a leaked envelope to minutes. It is clamped below
/// the base token's own expiry regardless.
pub const DEFAULT_ENVELOPE_TTL_SECONDS: u64 = 900;

/// The daemon's per-device relay identity.
///
/// Derived from the passport seed rather than stored as a second key file. That
/// is deliberate:
///
/// * it loads at boot with the passport, satisfying M7a's requirement that the
///   device key be available **without interactive unlock** for an unattended
///   daemon;
/// * there is no second file to go missing, diverge, or be restored from a
///   stale backup while the passport moves on;
/// * it exposes nothing extra — under OD-44 the daemon already holds the
///   passport key, so a compromise that yields one yields the other either way.
///
/// It is a genuinely distinct keypair with a distinct fingerprint, which is
/// what `attenuate_for` requires.
pub struct DeviceIdentity {
    signing_key: SigningKey,
    public_key: [u8; 32],
    fpr: String,
}

impl std::fmt::Debug for DeviceIdentity {
    /// Never renders the signing key. A `#[derive(Debug)]` here would put
    /// private key material into any log line that formats a struct holding
    /// one.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceIdentity")
            .field("fpr", &self.fpr)
            .finish_non_exhaustive()
    }
}

impl DeviceIdentity {
    /// Derive this daemon's device identity from its passport.
    ///
    /// `derive_subkey` is `blake3::derive_key` (HKDF-style) and the passport
    /// seed never leaves the `LocalPassportKey`. The derived seed is wrapped in
    /// `Zeroizing` so it is wiped once the signing key owns the material.
    pub fn derive(passport: &LocalPassportKey) -> Self {
        let seed = Zeroizing::new(passport.derive_subkey(DEVICE_KEY_CONTEXT));
        let signing_key = SigningKey::from_bytes(&seed);
        let public_key = signing_key.verifying_key().to_bytes();
        let fpr = passport_fpr_from_public_key(&public_key);
        Self {
            signing_key,
            public_key,
            fpr,
        }
    }

    /// `p_<hex blake3(pubkey)[..16]>` — what the registry stores and what the
    /// base token's `allowed_delegate_fprs` must contain.
    pub fn fpr(&self) -> &str {
        &self.fpr
    }

    /// Raw 32-byte public key, as the `attach` frame carries it.
    pub fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    /// Sign the relay's proof-of-possession challenge.
    ///
    /// `#[allow(dead_code)]` because M4b's relay client is the production
    /// consumer and does not exist yet. Kept here rather than deferred because
    /// the signing half is what makes the derived key *usable*, and its test
    /// proves a real property — that signatures verify under the public key
    /// this type advertises. Deriving a key nothing can be shown to sign with
    /// would be the weaker deliverable.
    #[allow(dead_code)]
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing_key.sign(message).to_bytes()
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RelayEnvelopeError {
    #[error("this grant carries no relay backend; the account is not entitled to a relay session")]
    NoRelayGrant,
    #[error("the relay capability is absent from the base token's backends, so it cannot be scoped to")]
    RelayCapabilityAbsent,
    #[error("base token expires at {expires_at}, which is not in the future at {now}")]
    BaseExpired { expires_at: u64, now: u64 },
    #[error("attenuation refused: {0:?}")]
    Attenuate(AttenuateError),
}

impl From<AttenuateError> for RelayEnvelopeError {
    fn from(value: AttenuateError) -> Self {
        Self::Attenuate(value)
    }
}

/// Mint the relay delegation envelope: subject = passport, delegate = device.
///
/// `delegation_id` must be supplied by the caller so the value is traceable to
/// whatever produced it (a session id, a run id) rather than invented here.
pub fn attenuate_for_relay(
    hosted: &HostedToken,
    passport: &LocalPassportKey,
    device: &DeviceIdentity,
    delegation_id: &str,
    now_unix_seconds: u64,
    ttl_seconds: u64,
) -> Result<RcxCapabilityToken, RelayEnvelopeError> {
    if hosted.relay.is_none() {
        return Err(RelayEnvelopeError::NoRelayGrant);
    }
    let base = &hosted.token;

    if base.expires_at <= now_unix_seconds {
        return Err(RelayEnvelopeError::BaseExpired {
            expires_at: base.expires_at,
            now: now_unix_seconds,
        });
    }

    // The relay capability must actually be in the base grant. `ScopeSubset`
    // would be rejected as outside the base grant otherwise, but failing here
    // says *why* instead of surfacing a generic caveat error.
    let has_relay_capability = base.backends.iter().any(|backend| {
        backend
            .permitted_capabilities
            .iter()
            .any(|permitted| permitted.capability == RCX_RELAY_SESSION_CAPABILITY)
    });
    if !has_relay_capability {
        return Err(RelayEnvelopeError::RelayCapabilityAbsent);
    }

    // Clamp below the base expiry. `ExpiresAtLe` only satisfies the
    // strictly-narrows rule when it is < base.expires_at, so a TTL that would
    // reach or exceed the base has to be pulled in rather than passed through —
    // otherwise the caveat set is rejected as non-narrowing and the failure
    // looks like a bug in the caveats rather than an over-long TTL.
    let requested = now_unix_seconds.saturating_add(ttl_seconds);
    let expires_at = requested.min(base.expires_at.saturating_sub(1));

    let caveats = vec![
        Caveat::ExpiresAtLe { expires_at },
        Caveat::TenantIdEq {
            tenant_id: base.tenant_scope.tenant_id.clone(),
        },
        // Least privilege: the envelope may be used for the relay session and
        // nothing else, even though the base token carries more. This is the
        // property the envelope exists to provide.
        Caveat::ScopeSubset {
            scopes: vec![RCX_RELAY_SESSION_CAPABILITY.to_string()],
        },
    ];

    // `attenuate_for` normalises and canonically orders the caveats itself, so
    // they are passed in declaration order rather than pre-sorted here.
    let attenuated = base.attenuate_for(
        caveats,
        device.public_key(),
        delegation_id,
        passport.delegation_signing_key(),
    )?;
    Ok(attenuated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcx_capability_token::{
        Backend, DataEgressClass, DelegationAudience, DelegationPolicy, DelegationPresentation, PermittedCapability,
        RCX_CT_DELEGATION_SPEC_VERSION, RCX_RELAY_BACKEND_ID,
    };

    fn issuer() -> SigningKey {
        SigningKey::from_bytes(&[9u8; 32])
    }

    /// A hosted grant shaped the way CruxEngine mints one for a paid tenant:
    /// delegation-enabled, subject = this daemon's passport, the device named as
    /// an allowed delegate, and a relay backend carrying the session capability.
    fn hosted(
        passport: &LocalPassportKey,
        delegate_fprs: Vec<String>,
        with_relay_capability: bool,
        expires_at: u64,
    ) -> HostedToken {
        let key = issuer();
        let mut token = crux_router::mint_signed_free_local_token(
            passport.passport_fpr(),
            "daemon_01HV0000000000000000000000",
            "acme",
            vec!["corecrux.query.local".to_string()],
            1_700_000_000,
            expires_at,
            |hash| key.sign(hash).to_bytes(),
        );
        token.spec_version = RCX_CT_DELEGATION_SPEC_VERSION.to_string();
        token.delegation_policy = Some(DelegationPolicy {
            presentation: DelegationPresentation::ProofOfPossession,
            max_depth: 1,
            audience: DelegationAudience::CruxRelay,
            allowed_delegate_fprs: delegate_fprs,
        });
        let mut capabilities = vec![PermittedCapability {
            capability: "corecrux.query.local".to_string(),
            data_egress_classes: vec![DataEgressClass::None],
            required_attestations: vec!["passport_bound".to_string()],
            credit_cost: None,
        }];
        if with_relay_capability {
            capabilities.push(PermittedCapability {
                capability: RCX_RELAY_SESSION_CAPABILITY.to_string(),
                data_egress_classes: vec![DataEgressClass::Text],
                required_attestations: vec!["passport_bound".to_string()],
                credit_cost: None,
            });
        }
        token.backends.push(Backend {
            backend_id: RCX_RELAY_BACKEND_ID.to_string(),
            trust_root_kid: "p_0123456789abcdef0123456789abcdef".to_string(),
            endpoint_url: Some("wss://relay.cuecrux.com".to_string()),
            permitted_capabilities: capabilities,
        });
        token.signature.sig = key.sign(&token.token_hash()).to_bytes();

        crate::hosted_token::verify_loaded(token, &issuer().verifying_key().to_bytes(), 1_800_000_000)
            .expect("fixture must verify")
    }

    fn passport() -> LocalPassportKey {
        LocalPassportKey::from_seed([7u8; 32]).expect("seed must load")
    }

    const NOW: u64 = 1_800_000_000;
    const BASE_EXPIRY: u64 = 1_900_000_000;

    #[test]
    fn mints_an_envelope_naming_the_device_as_delegate() {
        let p = passport();
        let d = DeviceIdentity::derive(&p);
        let h = hosted(&p, vec![d.fpr().to_string()], true, BASE_EXPIRY);

        let envelope = attenuate_for_relay(&h, &p, &d, "sess-1", NOW, DEFAULT_ENVELOPE_TTL_SECONDS)
            .expect("the daemon must be able to mint its own relay envelope");

        let e = envelope.delegation_envelope.as_ref().expect("envelope must be present");
        // Contract §5: proof must equal envelope.delegate_public_key, so this is
        // the field the relay checks the daemon's signature against.
        assert_eq!(e.delegate_public_key, d.public_key());
        assert_eq!(envelope.subject.passport_fpr, p.passport_fpr());
    }

    #[test]
    fn the_envelope_is_scoped_to_the_relay_capability_alone() {
        let p = passport();
        let d = DeviceIdentity::derive(&p);
        let h = hosted(&p, vec![d.fpr().to_string()], true, BASE_EXPIRY);

        let envelope = attenuate_for_relay(&h, &p, &d, "sess-1", NOW, DEFAULT_ENVELOPE_TTL_SECONDS).expect("mints");

        // Least privilege is the point of the envelope: the base token carries
        // corecrux.query.local too, and the envelope must not.
        let scoped = envelope
            .delegation_envelope
            .as_ref()
            .expect("envelope")
            .caveats
            .iter()
            .any(|c| {
                matches!(c, Caveat::ScopeSubset { scopes }
                if scopes == &vec![RCX_RELAY_SESSION_CAPABILITY.to_string()])
            });
        assert!(scoped, "envelope must scope down to the relay session capability");
    }

    #[test]
    fn a_ttl_reaching_past_the_base_is_clamped_below_it() {
        let p = passport();
        let d = DeviceIdentity::derive(&p);
        let h = hosted(&p, vec![d.fpr().to_string()], true, BASE_EXPIRY);

        // Ask for far longer than the base token has left. ExpiresAtLe only
        // narrows when strictly less than the base, so an unclamped value would
        // be rejected as non-narrowing rather than silently honoured.
        let envelope = attenuate_for_relay(&h, &p, &d, "sess-1", NOW, 10_000_000_000)
            .expect("an over-long TTL must clamp, not fail");

        let expires = envelope
            .delegation_envelope
            .as_ref()
            .expect("envelope")
            .caveats
            .iter()
            .find_map(|c| match c {
                Caveat::ExpiresAtLe { expires_at } => Some(*expires_at),
                _ => None,
            })
            .expect("an expiry caveat is mandatory");
        assert!(expires < BASE_EXPIRY, "must be strictly inside the base grant");
    }

    #[test]
    fn refuses_when_the_account_has_no_relay_grant() {
        let p = passport();
        let d = DeviceIdentity::derive(&p);
        let key = issuer();
        let token = crux_router::mint_signed_free_local_token(
            p.passport_fpr(),
            "daemon_01HV0000000000000000000000",
            "acme",
            vec!["corecrux.query.local".to_string()],
            1_700_000_000,
            BASE_EXPIRY,
            |hash| key.sign(hash).to_bytes(),
        );
        let h = crate::hosted_token::verify_loaded(token, &key.verifying_key().to_bytes(), NOW)
            .expect("free-tier token verifies");

        // The ordinary Free-tier shape: not an error at load, but nothing to
        // attenuate for.
        assert_eq!(
            attenuate_for_relay(&h, &p, &d, "sess-1", NOW, DEFAULT_ENVELOPE_TTL_SECONDS),
            Err(RelayEnvelopeError::NoRelayGrant)
        );
    }

    #[test]
    fn refuses_a_device_the_grant_does_not_name_as_a_delegate() {
        let p = passport();
        let d = DeviceIdentity::derive(&p);
        // A grant naming somebody else's device. The registry is the source of
        // allowed_delegate_fprs, so this is what an unregistered daemon sees.
        let h = hosted(&p, vec!["p_".to_string() + &"c".repeat(32)], true, BASE_EXPIRY);

        assert_eq!(
            attenuate_for_relay(&h, &p, &d, "sess-1", NOW, DEFAULT_ENVELOPE_TTL_SECONDS),
            Err(RelayEnvelopeError::Attenuate(AttenuateError::DelegateNotPermitted))
        );
    }

    #[test]
    fn refuses_when_the_base_token_has_already_expired() {
        let p = passport();
        let d = DeviceIdentity::derive(&p);
        let h = hosted(&p, vec![d.fpr().to_string()], true, BASE_EXPIRY);

        let err = attenuate_for_relay(&h, &p, &d, "sess-1", BASE_EXPIRY + 1, 900)
            .expect_err("an expired base must not yield an envelope");
        assert!(matches!(err, RelayEnvelopeError::BaseExpired { .. }));
    }

    #[test]
    fn refuses_when_the_relay_capability_is_absent_from_the_grant() {
        let p = passport();
        let d = DeviceIdentity::derive(&p);
        // A relay backend with no session capability on it — says *why* rather
        // than surfacing a generic caveat error from attenuate_for.
        let h = hosted(&p, vec![d.fpr().to_string()], false, BASE_EXPIRY);

        assert_eq!(
            attenuate_for_relay(&h, &p, &d, "sess-1", NOW, DEFAULT_ENVELOPE_TTL_SECONDS),
            Err(RelayEnvelopeError::RelayCapabilityAbsent)
        );
    }

    #[test]
    fn device_identity_is_a_distinct_keypair_from_the_passport() {
        let passport = LocalPassportKey::from_seed([7u8; 32]).expect("seed must load");
        let device = DeviceIdentity::derive(&passport);
        // The whole OD-44 argument rests on these differing: attenuate_for
        // rejects delegate_fpr == delegator_fpr.
        assert_ne!(device.fpr(), passport.passport_fpr());
        assert_ne!(device.public_key(), passport.verifying_key_bytes());
    }

    #[test]
    fn device_identity_is_deterministic_across_boots() {
        // There is no key file; the identity must survive a restart purely by
        // being derived the same way.
        let a = DeviceIdentity::derive(&LocalPassportKey::from_seed([9u8; 32]).expect("seed"));
        let b = DeviceIdentity::derive(&LocalPassportKey::from_seed([9u8; 32]).expect("seed"));
        assert_eq!(a.fpr(), b.fpr());
        assert_eq!(a.public_key(), b.public_key());
    }

    #[test]
    fn different_passports_yield_different_devices() {
        let a = DeviceIdentity::derive(&LocalPassportKey::from_seed([1u8; 32]).expect("seed"));
        let b = DeviceIdentity::derive(&LocalPassportKey::from_seed([2u8; 32]).expect("seed"));
        assert_ne!(a.fpr(), b.fpr());
    }

    #[test]
    fn debug_never_renders_key_material() {
        let device = DeviceIdentity::derive(&LocalPassportKey::from_seed([3u8; 32]).expect("seed"));
        let rendered = format!("{device:?}");
        assert!(rendered.contains(device.fpr()));
        // A leaked signing key in a log line is the failure this guards.
        let seed_hex = hex::encode(device.signing_key.to_bytes());
        assert!(!rendered.contains(&seed_hex));
    }

    #[test]
    fn signatures_verify_under_the_advertised_public_key() {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let device = DeviceIdentity::derive(&LocalPassportKey::from_seed([5u8; 32]).expect("seed"));
        let sig = device.sign(b"relay challenge");
        let vk = VerifyingKey::from_bytes(&device.public_key()).expect("advertised key must parse");
        assert!(vk.verify(b"relay challenge", &Signature::from_bytes(&sig)).is_ok());
    }
}
