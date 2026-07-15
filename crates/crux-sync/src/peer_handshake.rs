// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Pure verification for the signed federation peer-identity handshake.

use std::collections::HashMap;

use base64::Engine as _;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use rcx_capability_token::{verify_token, RcxCapabilityToken, VerifyOutcome};

/// Domain separator for peer-handshake possession signatures.
///
/// The complete signed message is exactly
/// `PEER_HANDSHAKE_SIGNING_DOMAIN || token_id.as_bytes() || b"\0" || nonce`.
pub const PEER_HANDSHAKE_SIGNING_DOMAIN: &[u8] = b"crux-sync/peer-handshake/v1\0";

/// Identity established by a successfully verified peer handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedPeer {
    pub passport_fpr: String,
    pub tenant_id: String,
}

/// Fail-closed reasons a peer handshake can be rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerAuthError {
    TokenInvalid(VerifyOutcome),
    FprMismatch,
    BadPossessionSig,
    NonceUnknownOrUsed,
    NonceExpired,
    Revoked,
}

/// Capability token and proof-of-possession material presented by a peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerHandshake {
    pub capability_token: RcxCapabilityToken,
    pub peer_public_key: [u8; 32],
    pub nonce: Vec<u8>,
    pub nonce_signature: [u8; 64],
}

#[derive(Debug, Clone, Copy)]
struct NonceEntry {
    expires_at: u64,
    consumed: bool,
}

/// In-memory cache of server-issued, single-use peer-handshake nonces.
pub struct NonceCache {
    ttl_seconds: u64,
    entries: HashMap<Vec<u8>, NonceEntry>,
}

impl NonceCache {
    /// Construct an empty nonce cache with the supplied nonce lifetime.
    pub fn new(ttl_seconds: u64) -> Self {
        Self {
            ttl_seconds,
            entries: HashMap::new(),
        }
    }

    /// Record caller-supplied entropy as a newly issued nonce and return it.
    ///
    /// Reissuing a nonce still present in the cache does not reset its expiry or
    /// consumed state. This fails closed if a caller supplies duplicate entropy.
    pub fn issue(&mut self, now_unix_seconds: u64, random_nonce: [u8; 32]) -> Vec<u8> {
        let nonce = random_nonce.to_vec();
        self.entries.entry(nonce.clone()).or_insert(NonceEntry {
            expires_at: now_unix_seconds.saturating_add(self.ttl_seconds),
            consumed: false,
        });
        nonce
    }

    /// Remove nonce entries whose TTL has elapsed.
    pub fn sweep_expired(&mut self, now_unix_seconds: u64) {
        self.entries.retain(|_, entry| now_unix_seconds <= entry.expires_at);
    }
}

fn passport_fpr_from_public_key(public_key: &[u8; 32]) -> String {
    let digest = blake3::hash(public_key);
    format!("p_{}", hex::encode(&digest.as_bytes()[..16]))
}

fn signing_message(token: &RcxCapabilityToken, nonce: &[u8]) -> Vec<u8> {
    let mut message = PEER_HANDSHAKE_SIGNING_DOMAIN.to_vec();
    message.extend_from_slice(token.token_id.as_bytes());
    message.push(0);
    message.extend_from_slice(nonce);
    message
}

/// Canonical `x-crux-peer-*` header names for the M2a peer handshake. The server
/// (`corecruxd::http::sync`) parses exactly these; the client presents them.
pub const PEER_TOKEN_HEADER: &str = "x-crux-peer-token";
pub const PEER_PUBLIC_KEY_HEADER: &str = "x-crux-peer-pubkey";
pub const PEER_NONCE_HEADER: &str = "x-crux-peer-nonce";
pub const PEER_SIGNATURE_HEADER: &str = "x-crux-peer-sig";

/// The four header values a client presents for the M2a peer handshake, ready to
/// attach to a sync request. Pair each with the matching `PEER_*_HEADER` name.
#[derive(Debug, Clone)]
pub struct PeerHandshakeHeaders {
    /// `x-crux-peer-token`: STANDARD-base64 of the canonical token JSON.
    pub token_b64: String,
    /// `x-crux-peer-pubkey`: hex of the subject signing key's 32-byte public key.
    pub public_key_hex: String,
    /// `x-crux-peer-nonce`: hex of the server-issued nonce.
    pub nonce_hex: String,
    /// `x-crux-peer-sig`: hex of the Ed25519 signature over the handshake message.
    pub signature_hex: String,
}

impl PeerHandshakeHeaders {
    /// `(name, value)` pairs to set on the outgoing request.
    pub fn as_pairs(&self) -> [(&'static str, &str); 4] {
        [
            (PEER_TOKEN_HEADER, self.token_b64.as_str()),
            (PEER_PUBLIC_KEY_HEADER, self.public_key_hex.as_str()),
            (PEER_NONCE_HEADER, self.nonce_hex.as_str()),
            (PEER_SIGNATURE_HEADER, self.signature_hex.as_str()),
        ]
    }
}

/// Build the client side of the M2a peer handshake (audit-v2 M2b client
/// presentation): base64 token, hex public key, hex nonce, and the Ed25519
/// signature over `signing_message(token, nonce)` — exactly what
/// [`verify_peer_handshake`] checks. `nonce` is the raw bytes returned (hex) by
/// `POST /v1/sync/handshake/nonce`. The caller must ensure `signing_key`'s public
/// key matches `token.subject.passport_fpr`, or the server rejects with `FprMismatch`.
pub fn build_peer_handshake_headers(
    token: &RcxCapabilityToken,
    signing_key: &SigningKey,
    nonce: &[u8],
) -> Result<PeerHandshakeHeaders, String> {
    let signature = signing_key.sign(&signing_message(token, nonce));
    Ok(PeerHandshakeHeaders {
        token_b64: base64::engine::general_purpose::STANDARD.encode(token.to_canonical_json().as_bytes()),
        public_key_hex: hex::encode(signing_key.verifying_key().to_bytes()),
        nonce_hex: hex::encode(nonce),
        signature_hex: hex::encode(signature.to_bytes()),
    })
}

/// Verify issuer authority, subject binding, key possession, revocation, and
/// nonce freshness in that order. The nonce is consumed only after every
/// preceding check succeeds.
pub fn verify_peer_handshake(
    hs: &PeerHandshake,
    trust_root_pubkey: &[u8],
    now_unix_seconds: u64,
    nonce_cache: &mut NonceCache,
    is_revoked: impl Fn(&RcxCapabilityToken) -> bool,
) -> Result<AuthenticatedPeer, PeerAuthError> {
    match verify_token(&hs.capability_token, trust_root_pubkey, now_unix_seconds) {
        VerifyOutcome::Verified => {}
        outcome => return Err(PeerAuthError::TokenInvalid(outcome)),
    }

    let presented_fpr = passport_fpr_from_public_key(&hs.peer_public_key);
    if presented_fpr != hs.capability_token.subject.passport_fpr {
        return Err(PeerAuthError::FprMismatch);
    }

    let verifying_key = VerifyingKey::from_bytes(&hs.peer_public_key).map_err(|_| PeerAuthError::BadPossessionSig)?;
    let signature = Signature::from_bytes(&hs.nonce_signature);
    let message = signing_message(&hs.capability_token, &hs.nonce);
    verifying_key
        .verify_strict(&message, &signature)
        .map_err(|_| PeerAuthError::BadPossessionSig)?;

    if is_revoked(&hs.capability_token) {
        return Err(PeerAuthError::Revoked);
    }

    let entry = nonce_cache
        .entries
        .get_mut(hs.nonce.as_slice())
        .ok_or(PeerAuthError::NonceUnknownOrUsed)?;
    if entry.consumed {
        return Err(PeerAuthError::NonceUnknownOrUsed);
    }
    if now_unix_seconds > entry.expires_at {
        return Err(PeerAuthError::NonceExpired);
    }

    let authenticated_peer = AuthenticatedPeer {
        passport_fpr: hs.capability_token.subject.passport_fpr.clone(),
        tenant_id: hs.capability_token.tenant_scope.tenant_id.clone(),
    };
    entry.consumed = true;

    Ok(authenticated_peer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const NOW: u64 = 1_776_989_601;
    const NONCE_TTL: u64 = 60;
    const TENANT_ID: &str = "tenant-federation-test";

    fn signing_key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn valid_token(subject_key: &SigningKey, trust_root: &SigningKey) -> RcxCapabilityToken {
        let mut token = rcx_capability_token::free_local_verified_fixture();
        let issuer_fpr = passport_fpr_from_public_key(&trust_root.verifying_key().to_bytes());
        token.token_id = "rcxct_peer_handshake_test".to_string();
        token.subject.passport_fpr = passport_fpr_from_public_key(&subject_key.verifying_key().to_bytes());
        token.tenant_scope.tenant_id = TENANT_ID.to_string();
        token.issuer.passport_kid.clone_from(&issuer_fpr);
        token.signature.kid.clone_from(&issuer_fpr);
        token.backends[0].trust_root_kid = issuer_fpr;
        token.signature.sig = trust_root.sign(&token.token_hash()).to_bytes();
        token
    }

    fn signed_handshake(
        token: RcxCapabilityToken,
        peer_public_key: [u8; 32],
        possession_key: &SigningKey,
        nonce: Vec<u8>,
    ) -> PeerHandshake {
        let message = signing_message(&token, &nonce);
        PeerHandshake {
            capability_token: token,
            peer_public_key,
            nonce,
            nonce_signature: possession_key.sign(&message).to_bytes(),
        }
    }

    #[test]
    fn valid_handshake_authenticates_peer() {
        let trust_root = signing_key(1);
        let subject = signing_key(2);
        let token = valid_token(&subject, &trust_root);
        let expected_fpr = token.subject.passport_fpr.clone();
        let mut cache = NonceCache::new(NONCE_TTL);
        let nonce = cache.issue(NOW, [3; 32]);
        let mut expected_message = b"crux-sync/peer-handshake/v1\0rcxct_peer_handshake_test\0".to_vec();
        expected_message.extend_from_slice(&nonce);
        let hs = PeerHandshake {
            capability_token: token,
            peer_public_key: subject.verifying_key().to_bytes(),
            nonce,
            nonce_signature: subject.sign(&expected_message).to_bytes(),
        };

        assert_eq!(
            verify_peer_handshake(&hs, &trust_root.verifying_key().to_bytes(), NOW, &mut cache, |_| false,),
            Ok(AuthenticatedPeer {
                passport_fpr: expected_fpr,
                tenant_id: TENANT_ID.to_string(),
            })
        );
    }

    #[test]
    fn stolen_token_with_attackers_key_fails_fingerprint_binding() {
        let trust_root = signing_key(4);
        let subject = signing_key(5);
        let attacker = signing_key(6);
        let token = valid_token(&subject, &trust_root);
        let mut cache = NonceCache::new(NONCE_TTL);
        let nonce = cache.issue(NOW, [7; 32]);
        let hs = signed_handshake(token, attacker.verifying_key().to_bytes(), &attacker, nonce);

        assert_eq!(
            verify_peer_handshake(&hs, &trust_root.verifying_key().to_bytes(), NOW, &mut cache, |_| false,),
            Err(PeerAuthError::FprMismatch)
        );
    }

    #[test]
    fn subject_public_key_without_private_key_fails_possession() {
        let trust_root = signing_key(8);
        let subject = signing_key(9);
        let attacker = signing_key(10);
        let token = valid_token(&subject, &trust_root);
        let mut cache = NonceCache::new(NONCE_TTL);
        let nonce = cache.issue(NOW, [11; 32]);
        let hs = signed_handshake(token, subject.verifying_key().to_bytes(), &attacker, nonce);

        assert_eq!(
            verify_peer_handshake(&hs, &trust_root.verifying_key().to_bytes(), NOW, &mut cache, |_| false,),
            Err(PeerAuthError::BadPossessionSig)
        );
    }

    #[test]
    fn successful_handshake_cannot_be_replayed() {
        let trust_root = signing_key(12);
        let subject = signing_key(13);
        let token = valid_token(&subject, &trust_root);
        let mut cache = NonceCache::new(NONCE_TTL);
        let nonce = cache.issue(NOW, [14; 32]);
        let hs = signed_handshake(token, subject.verifying_key().to_bytes(), &subject, nonce);
        let trust_root_pubkey = trust_root.verifying_key().to_bytes();

        assert!(verify_peer_handshake(&hs, &trust_root_pubkey, NOW, &mut cache, |_| false).is_ok());
        assert_eq!(
            verify_peer_handshake(&hs, &trust_root_pubkey, NOW, &mut cache, |_| false),
            Err(PeerAuthError::NonceUnknownOrUsed)
        );
    }

    #[test]
    fn expired_nonce_is_rejected() {
        let trust_root = signing_key(15);
        let subject = signing_key(16);
        let token = valid_token(&subject, &trust_root);
        let mut cache = NonceCache::new(NONCE_TTL);
        let boundary_nonce = cache.issue(NOW, [17; 32]);
        let expired_nonce = cache.issue(NOW, [18; 32]);
        let boundary_hs = signed_handshake(
            token.clone(),
            subject.verifying_key().to_bytes(),
            &subject,
            boundary_nonce,
        );
        let expired_hs = signed_handshake(token, subject.verifying_key().to_bytes(), &subject, expired_nonce);

        cache.sweep_expired(NOW + NONCE_TTL);
        assert!(verify_peer_handshake(
            &boundary_hs,
            &trust_root.verifying_key().to_bytes(),
            NOW + NONCE_TTL,
            &mut cache,
            |_| false,
        )
        .is_ok());

        assert_eq!(
            verify_peer_handshake(
                &expired_hs,
                &trust_root.verifying_key().to_bytes(),
                NOW + NONCE_TTL + 1,
                &mut cache,
                |_| false,
            ),
            Err(PeerAuthError::NonceExpired)
        );
        cache.sweep_expired(NOW + NONCE_TTL + 1);
        assert_eq!(
            verify_peer_handshake(
                &expired_hs,
                &trust_root.verifying_key().to_bytes(),
                NOW + NONCE_TTL + 1,
                &mut cache,
                |_| false,
            ),
            Err(PeerAuthError::NonceUnknownOrUsed)
        );
    }

    #[test]
    fn tampered_token_signature_is_rejected_before_peer_checks() {
        let trust_root = signing_key(18);
        let subject = signing_key(19);
        let mut token = valid_token(&subject, &trust_root);
        token.signature.sig[0] ^= 1;
        let mut cache = NonceCache::new(NONCE_TTL);
        let nonce = cache.issue(NOW, [20; 32]);
        let hs = signed_handshake(token, subject.verifying_key().to_bytes(), &subject, nonce);

        assert_eq!(
            verify_peer_handshake(&hs, &trust_root.verifying_key().to_bytes(), NOW, &mut cache, |_| false,),
            Err(PeerAuthError::TokenInvalid(VerifyOutcome::BadSignature))
        );
    }

    #[test]
    fn wrong_trust_root_is_rejected() {
        let trust_root = signing_key(21);
        let wrong_trust_root = signing_key(22);
        let subject = signing_key(23);
        let token = valid_token(&subject, &trust_root);
        let mut cache = NonceCache::new(NONCE_TTL);
        let nonce = cache.issue(NOW, [24; 32]);
        let hs = signed_handshake(token, subject.verifying_key().to_bytes(), &subject, nonce);

        assert!(matches!(
            verify_peer_handshake(
                &hs,
                &wrong_trust_root.verifying_key().to_bytes(),
                NOW,
                &mut cache,
                |_| false,
            ),
            Err(PeerAuthError::TokenInvalid(
                VerifyOutcome::BadTrustRoot | VerifyOutcome::BadSignature
            ))
        ));
    }

    #[test]
    fn signature_for_different_nonce_or_domain_is_rejected() {
        let trust_root = signing_key(25);
        let subject = signing_key(26);
        let token = valid_token(&subject, &trust_root);
        let mut cache = NonceCache::new(NONCE_TTL);
        let issued_nonce = cache.issue(NOW, [27; 32]);

        let mut different_nonce_hs = signed_handshake(
            token.clone(),
            subject.verifying_key().to_bytes(),
            &subject,
            vec![28; 32],
        );
        different_nonce_hs.nonce.clone_from(&issued_nonce);
        assert_eq!(
            verify_peer_handshake(
                &different_nonce_hs,
                &trust_root.verifying_key().to_bytes(),
                NOW,
                &mut cache,
                |_| false,
            ),
            Err(PeerAuthError::BadPossessionSig)
        );

        let mut wrong_domain_message = b"crux-sync/peer-handshake/v0\0".to_vec();
        wrong_domain_message.extend_from_slice(token.token_id.as_bytes());
        wrong_domain_message.push(0);
        wrong_domain_message.extend_from_slice(&issued_nonce);
        let wrong_domain_hs = PeerHandshake {
            capability_token: token.clone(),
            peer_public_key: subject.verifying_key().to_bytes(),
            nonce: issued_nonce.clone(),
            nonce_signature: subject.sign(&wrong_domain_message).to_bytes(),
        };
        assert_eq!(
            verify_peer_handshake(
                &wrong_domain_hs,
                &trust_root.verifying_key().to_bytes(),
                NOW,
                &mut cache,
                |_| false,
            ),
            Err(PeerAuthError::BadPossessionSig)
        );

        let mut other_token = token.clone();
        other_token.token_id = "rcxct_peer_handshake_other".to_string();
        other_token.signature.sig = trust_root.sign(&other_token.token_hash()).to_bytes();
        let token_bound_hs = PeerHandshake {
            capability_token: other_token,
            peer_public_key: subject.verifying_key().to_bytes(),
            nonce: issued_nonce.clone(),
            nonce_signature: subject.sign(&signing_message(&token, &issued_nonce)).to_bytes(),
        };
        assert_eq!(
            verify_peer_handshake(
                &token_bound_hs,
                &trust_root.verifying_key().to_bytes(),
                NOW,
                &mut cache,
                |_| false,
            ),
            Err(PeerAuthError::BadPossessionSig)
        );
    }

    #[test]
    fn client_built_handshake_is_accepted_by_verifier() {
        // M2b client presentation: headers built by the client round-trip through
        // the server verifier — the two-node accept, proven at the crypto boundary.
        let trust_root = signing_key(40);
        let subject = signing_key(41);
        let token = valid_token(&subject, &trust_root);
        let mut cache = NonceCache::new(NONCE_TTL);
        let nonce = cache.issue(NOW, [42; 32]);

        let headers = build_peer_handshake_headers(&token, &subject, &nonce).expect("build headers");
        // Header names are the canonical ones the server parses.
        assert_eq!(headers.as_pairs()[0].0, PEER_TOKEN_HEADER);
        assert_eq!(headers.as_pairs()[3].0, PEER_SIGNATURE_HEADER);

        // Reconstruct the wire handshake exactly as the server would from the headers.
        let token_json = base64::engine::general_purpose::STANDARD
            .decode(headers.token_b64.as_bytes())
            .expect("b64");
        let wire_token: RcxCapabilityToken = serde_json::from_slice(&token_json).expect("token json");
        let mut peer_public_key = [0u8; 32];
        peer_public_key.copy_from_slice(&hex::decode(&headers.public_key_hex).expect("pubkey hex"));
        let mut nonce_signature = [0u8; 64];
        nonce_signature.copy_from_slice(&hex::decode(&headers.signature_hex).expect("sig hex"));
        let hs = PeerHandshake {
            capability_token: wire_token,
            peer_public_key,
            nonce: hex::decode(&headers.nonce_hex).expect("nonce hex"),
            nonce_signature,
        };

        let authenticated =
            verify_peer_handshake(&hs, &trust_root.verifying_key().to_bytes(), NOW, &mut cache, |_| false)
                .expect("verifier must accept the client-built handshake");
        assert_eq!(authenticated.tenant_id, TENANT_ID);
    }

    #[test]
    fn client_built_handshake_with_wrong_key_is_rejected() {
        // A signing key that doesn't match the token's passport_fpr → FprMismatch.
        let trust_root = signing_key(43);
        let subject = signing_key(44);
        let attacker = signing_key(45);
        let token = valid_token(&subject, &trust_root);
        let mut cache = NonceCache::new(NONCE_TTL);
        let nonce = cache.issue(NOW, [46; 32]);

        let headers = build_peer_handshake_headers(&token, &attacker, &nonce).expect("build headers");
        let token_json = base64::engine::general_purpose::STANDARD
            .decode(headers.token_b64.as_bytes())
            .expect("b64");
        let wire_token: RcxCapabilityToken = serde_json::from_slice(&token_json).expect("token json");
        let mut peer_public_key = [0u8; 32];
        peer_public_key.copy_from_slice(&hex::decode(&headers.public_key_hex).expect("pubkey hex"));
        let mut nonce_signature = [0u8; 64];
        nonce_signature.copy_from_slice(&hex::decode(&headers.signature_hex).expect("sig hex"));
        let hs = PeerHandshake {
            capability_token: wire_token,
            peer_public_key,
            nonce: hex::decode(&headers.nonce_hex).expect("nonce hex"),
            nonce_signature,
        };
        assert_eq!(
            verify_peer_handshake(&hs, &trust_root.verifying_key().to_bytes(), NOW, &mut cache, |_| false),
            Err(PeerAuthError::FprMismatch)
        );
    }

    #[test]
    fn revoked_token_is_rejected() {
        let trust_root = signing_key(29);
        let subject = signing_key(30);
        let token = valid_token(&subject, &trust_root);
        let mut cache = NonceCache::new(NONCE_TTL);
        let nonce = cache.issue(NOW, [31; 32]);
        let hs = signed_handshake(token, subject.verifying_key().to_bytes(), &subject, nonce);

        assert_eq!(
            verify_peer_handshake(&hs, &trust_root.verifying_key().to_bytes(), NOW, &mut cache, |_| true,),
            Err(PeerAuthError::Revoked)
        );
        assert!(
            verify_peer_handshake(&hs, &trust_root.verifying_key().to_bytes(), NOW, &mut cache, |_| false,).is_ok()
        );
    }

    #[test]
    fn failed_possession_attempt_does_not_consume_nonce() {
        let trust_root = signing_key(32);
        let subject = signing_key(33);
        let attacker = signing_key(34);
        let token = valid_token(&subject, &trust_root);
        let mut cache = NonceCache::new(NONCE_TTL);
        let nonce = cache.issue(NOW, [35; 32]);
        let bad_hs = signed_handshake(
            token.clone(),
            subject.verifying_key().to_bytes(),
            &attacker,
            nonce.clone(),
        );
        let good_hs = signed_handshake(token, subject.verifying_key().to_bytes(), &subject, nonce);
        let trust_root_pubkey = trust_root.verifying_key().to_bytes();

        assert_eq!(
            verify_peer_handshake(&bad_hs, &trust_root_pubkey, NOW, &mut cache, |_| false),
            Err(PeerAuthError::BadPossessionSig)
        );
        assert!(verify_peer_handshake(&good_hs, &trust_root_pubkey, NOW, &mut cache, |_| false).is_ok());
    }

    #[test]
    fn fpr_derivation_matches_crux_session() {
        let seed = [36; 32];
        let public_key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        let canonical = crux_session::LocalPassportKey::from_seed(seed).unwrap();

        assert_eq!(passport_fpr_from_public_key(&public_key), canonical.passport_fpr());
    }
}
