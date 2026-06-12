// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Identity-federation link primitives (G4) — the canonical link statement,
//! its hash, and signature verification. Spec:
//! `PlanCrux docs/master-plan/shared/Identity-Federation-v1.md`.
//!
//! Storage (EntityStore, kind `identity_link`) and resolution live in
//! `corecruxd::identity_links` / `corecruxd::principal`; this module holds
//! only the pure crypto + schema so `corecruxctl identity sign-link` (the
//! other machine's half of the ceremony) shares one canonical byte layout
//! with the daemon. Same hash-then-sign idiom as `.cruxpack` and CROWN wipe
//! receipts: blake3 over canonical JSON, ed25519 over the 32-byte hash.

use serde::{Deserialize, Serialize};

/// Entity-store kind for link records.
pub const IDENTITY_LINK_KIND: &str = "identity_link";

/// Statement schema id (v1).
pub const IDENTITY_LINK_STATEMENT_SCHEMA_V1: &str = "crux.identity_link_statement.v1";

/// Link record schema id (v1).
pub const IDENTITY_LINK_SCHEMA_V1: &str = "crux.identity_link.v1";

/// The only grantable scope in v1: read-only memory access. A linked
/// passport never gains write, admin, or key custody.
pub const IDENTITY_LINK_SCOPE_MEMORY_READ: &str = "memory.read";

/// The canonical link statement both passports sign. Field order is the
/// serialization order — do not reorder (the hash depends on it).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LinkStatement {
    pub schema: String,
    /// Passport fingerprint known to the granting daemon.
    pub local_fpr: String,
    /// Passport fingerprint being granted equivalence.
    pub remote_fpr: String,
    /// Always [`IDENTITY_LINK_SCOPE_MEMORY_READ`] in v1.
    pub scope: String,
    pub created_at: String,
}

impl LinkStatement {
    pub fn memory_read(local_fpr: &str, remote_fpr: &str, created_at: &str) -> Self {
        Self {
            schema: IDENTITY_LINK_STATEMENT_SCHEMA_V1.to_string(),
            local_fpr: local_fpr.to_string(),
            remote_fpr: remote_fpr.to_string(),
            scope: IDENTITY_LINK_SCOPE_MEMORY_READ.to_string(),
            created_at: created_at.to_string(),
        }
    }
}

/// blake3 over the canonical JSON serialization of the statement.
pub fn statement_hash(statement: &LinkStatement) -> [u8; 32] {
    let bytes = serde_json::to_vec(statement).unwrap_or_default();
    *blake3::hash(&bytes).as_bytes()
}

/// `il_<first-16-hex-of-statement-hash>` — the link record id.
pub fn link_id_for_hash(hash: &[u8; 32]) -> String {
    format!("il_{}", hex::encode(&hash[..8]))
}

/// The entity-store payload of an `identity_link` record. Born-local: the
/// entity store never syncs and the `.cruxpack` exporter ships no entities
/// in v1 — a link is a local trust decision.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityLinkPayload {
    pub schema_version: String,
    /// Daemon-local passport record id (e.g. `personal-default`) the link
    /// resolves to.
    pub local_passport_id: String,
    pub local_fpr: String,
    pub remote_fpr: String,
    /// 64-hex ed25519 verifying key of the remote passport.
    pub remote_public_key_hex: String,
    /// v1: always `passport` (`github` / `email_hash` reserved).
    pub subject_kind: String,
    pub scope: String,
    /// `blake3:<64-hex>` of the canonical statement.
    pub statement_hash: String,
    pub created_at: String,
    /// 128-hex ed25519 signatures over the 32-byte statement hash.
    pub sig_local: String,
    pub sig_remote: String,
    /// Set on revocation — the record is never deleted (audit trail).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LinkVerifyError {
    #[error("malformed public key: {0}")]
    MalformedPubkey(String),
    #[error("malformed signature: {0}")]
    MalformedSignature(String),
    #[error("signature verification failed for {0}")]
    BadSignature(String),
    #[error("fingerprint {stated} does not match key-derived fingerprint {derived}")]
    FingerprintMismatch { stated: String, derived: String },
    #[error("self-link rejected: local and remote fingerprints are identical")]
    SelfLink,
    #[error("unsupported scope: {0} (v1 grants only memory.read)")]
    UnsupportedScope(String),
}

/// Verify one ed25519 signature (128 hex) over the 32-byte statement hash
/// against a 64-hex public key. `who` labels the failing side in errors.
pub fn verify_link_signature(
    public_key_hex: &str,
    hash: &[u8; 32],
    signature_hex: &str,
    who: &str,
) -> Result<(), LinkVerifyError> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let pubkey_bytes = hex::decode(public_key_hex).map_err(|e| LinkVerifyError::MalformedPubkey(e.to_string()))?;
    let pubkey_arr: [u8; 32] = pubkey_bytes.as_slice().try_into().map_err(|_| {
        LinkVerifyError::MalformedPubkey(format!("public key is {} bytes, expected 32", pubkey_bytes.len()))
    })?;
    let verifying_key =
        VerifyingKey::from_bytes(&pubkey_arr).map_err(|e| LinkVerifyError::MalformedPubkey(e.to_string()))?;
    let sig_bytes = hex::decode(signature_hex).map_err(|e| LinkVerifyError::MalformedSignature(e.to_string()))?;
    let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| {
        LinkVerifyError::MalformedSignature(format!("signature is {} bytes, expected 64", sig_bytes.len()))
    })?;
    verifying_key
        .verify(hash, &Signature::from_bytes(&sig_arr))
        .map_err(|_| LinkVerifyError::BadSignature(who.to_string()))
}

/// Validate that `fpr` is the fingerprint of `public_key_hex`
/// (`p_<blake3(pubkey)[..16] hex>` — the same self-certification rule as
/// `.cruxpack`).
pub fn check_fingerprint(fpr: &str, public_key_hex: &str) -> Result<(), LinkVerifyError> {
    let pubkey_bytes = hex::decode(public_key_hex).map_err(|e| LinkVerifyError::MalformedPubkey(e.to_string()))?;
    let pubkey_arr: [u8; 32] = pubkey_bytes.as_slice().try_into().map_err(|_| {
        LinkVerifyError::MalformedPubkey(format!("public key is {} bytes, expected 32", pubkey_bytes.len()))
    })?;
    let derived = crate::cruxpack::passport_fpr_from_public_key(&pubkey_arr);
    if derived != fpr {
        return Err(LinkVerifyError::FingerprintMismatch {
            stated: fpr.to_string(),
            derived,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn keypair(seed: u8) -> (SigningKey, String, String) {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let public = key.verifying_key().to_bytes();
        let fpr = crate::cruxpack::passport_fpr_from_public_key(&public);
        (key, fpr, hex::encode(public))
    }

    #[test]
    fn statement_hash_is_stable_and_field_order_sensitive() {
        let s1 = LinkStatement::memory_read("p_a", "p_b", "2026-06-12T00:00:00Z");
        let s2 = LinkStatement::memory_read("p_a", "p_b", "2026-06-12T00:00:00Z");
        assert_eq!(statement_hash(&s1), statement_hash(&s2));
        let s3 = LinkStatement::memory_read("p_b", "p_a", "2026-06-12T00:00:00Z");
        assert_ne!(statement_hash(&s1), statement_hash(&s3), "direction matters");
    }

    #[test]
    fn cross_signature_verifies_and_tamper_fails() {
        let (local_key, local_fpr, local_pub) = keypair(1);
        let (remote_key, remote_fpr, remote_pub) = keypair(2);
        let stmt = LinkStatement::memory_read(&local_fpr, &remote_fpr, "2026-06-12T00:00:00Z");
        let hash = statement_hash(&stmt);
        let sig_local = hex::encode(local_key.sign(&hash).to_bytes());
        let sig_remote = hex::encode(remote_key.sign(&hash).to_bytes());

        verify_link_signature(&local_pub, &hash, &sig_local, "local").expect("local ok");
        verify_link_signature(&remote_pub, &hash, &sig_remote, "remote").expect("remote ok");

        // Swapped signatures fail — both keys MUST sign.
        assert!(matches!(
            verify_link_signature(&local_pub, &hash, &sig_remote, "local"),
            Err(LinkVerifyError::BadSignature(_))
        ));

        // A different statement's hash fails.
        let other = statement_hash(&LinkStatement::memory_read(
            &local_fpr,
            &remote_fpr,
            "2027-01-01T00:00:00Z",
        ));
        assert!(verify_link_signature(&local_pub, &other, &sig_local, "local").is_err());
    }

    #[test]
    fn fingerprint_check_catches_substitution() {
        let (_, fpr, pub_hex) = keypair(3);
        check_fingerprint(&fpr, &pub_hex).expect("honest fpr");
        let (_, _, other_pub) = keypair(4);
        assert!(matches!(
            check_fingerprint(&fpr, &other_pub),
            Err(LinkVerifyError::FingerprintMismatch { .. })
        ));
    }

    #[test]
    fn link_id_is_derived_from_statement_hash() {
        let stmt = LinkStatement::memory_read("p_a", "p_b", "2026-06-12T00:00:00Z");
        let id = link_id_for_hash(&statement_hash(&stmt));
        assert!(id.starts_with("il_"));
        assert_eq!(id.len(), 3 + 16);
    }
}
