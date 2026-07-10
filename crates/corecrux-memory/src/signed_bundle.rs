// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Shared signed-bundle verification idiom.
//!
//! Two signed-bundle formats live in this crate and deliberately share one
//! verification idiom (blake3 content hash over canonical JSON, ed25519
//! signature over the decoded 32-byte hash, typed hard-reject errors
//! before any write):
//!
//! - the **Result Envelope** ([`crate::result_envelope`], Crux #188) —
//!   signed by a *pinned platform key*;
//! - the **`.cruxpack`** ([`crate::cruxpack`], Crux #191) — signed by the
//!   exporting daemon's *own passport key*, self-certifying to a
//!   fingerprint.
//!
//! This module is the one implementation of that idiom (the unification
//! follow-up recorded in `cruxpack.rs` and ExecPlan
//! `identity-memory-portability-2026-06-11` when #188 merged first). The
//! callers keep their own typed error enums, check *ordering*, and
//! format-specific gates (key pinning vs self-certification, counts,
//! erasure, privacy); the hash/decode/verify primitives live here. Pure
//! refactor: error detail strings are emitted verbatim from here so both
//! callers' rejection messages are byte-identical to before.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// `blake3:<64-hex>` over the stable serde JSON serialization of a
/// canonical document (the caller fixes field order by constructing the
/// `serde_json::Value` itself — `json!` object order is preserved).
pub fn content_hash_json(canonical: &serde_json::Value) -> String {
    let bytes = serde_json::to_vec(canonical).unwrap_or_default();
    format!("blake3:{}", blake3::hash(&bytes).to_hex())
}

/// Decode a stated `blake3:<hex>` content hash (prefix optional) into the
/// signed 32-byte hash. Error string is the shared `MalformedHash` detail.
pub fn decode_content_hash(stated: &str) -> Result<[u8; 32], String> {
    let hex_hash = stated.strip_prefix("blake3:").unwrap_or(stated);
    let decoded = hex::decode(hex_hash).map_err(|err| err.to_string())?;
    if decoded.len() != 32 {
        return Err(format!("content hash is {} bytes, expected 32", decoded.len()));
    }
    let mut hash = [0_u8; 32];
    hash.copy_from_slice(&decoded);
    Ok(hash)
}

/// Decode a 64-hex ed25519 public key into its raw 32 bytes. Error string
/// is the shared `MalformedPubkey` detail.
pub fn decode_public_key(hex_str: &str) -> Result<[u8; 32], String> {
    let decoded = hex::decode(hex_str).map_err(|err| err.to_string())?;
    decoded
        .as_slice()
        .try_into()
        .map_err(|_| format!("public key is {} bytes, expected 32", decoded.len()))
}

/// Parse raw public-key bytes into a verifying key (rejects non-canonical
/// curve points). Error string is the shared `MalformedPubkey` detail.
pub fn parse_verifying_key(pubkey: &[u8; 32]) -> Result<VerifyingKey, String> {
    VerifyingKey::from_bytes(pubkey).map_err(|err| err.to_string())
}

/// Decode a 128-hex ed25519 signature into its raw 64 bytes. Error string
/// is the shared `MalformedSignature` detail.
pub fn decode_signature(hex_str: &str) -> Result<[u8; 64], String> {
    let decoded = hex::decode(hex_str).map_err(|err| err.to_string())?;
    decoded
        .as_slice()
        .try_into()
        .map_err(|_| format!("signature is {} bytes, expected 64", decoded.len()))
}

/// Verify an ed25519 signature over the decoded 32-byte content hash —
/// the hash-then-sign pattern shared by CROWN wipe receipts, the Result
/// Envelope platform signature, and the `.cruxpack` passport signature.
/// `false` means the signature does not verify; the caller maps it to its
/// own `BadSignature` variant.
#[must_use]
pub fn verify_signature_over_hash(key: &VerifyingKey, hash: &[u8; 32], signature: &[u8; 64]) -> bool {
    key.verify(hash, &Signature::from_bytes(signature)).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn content_hash_is_deterministic_and_prefixed() {
        let doc = serde_json::json!({"a": [1, 2, 3], "b": {"c": "d"}});
        let h1 = content_hash_json(&doc);
        let h2 = content_hash_json(&doc);
        assert_eq!(h1, h2);
        assert!(h1.starts_with("blake3:"));
        assert_eq!(h1.len(), "blake3:".len() + 64);
        // Round-trips through the decoder.
        assert!(decode_content_hash(&h1).is_ok());
    }

    #[test]
    fn decode_errors_carry_the_shared_detail_strings() {
        assert!(!decode_content_hash("blake3:zz").unwrap_err().is_empty());
        assert_eq!(
            decode_content_hash("blake3:00ff").unwrap_err(),
            "content hash is 2 bytes, expected 32"
        );
        assert_eq!(
            decode_public_key("00ff").unwrap_err(),
            "public key is 2 bytes, expected 32"
        );
        assert_eq!(
            decode_signature("00ff").unwrap_err(),
            "signature is 2 bytes, expected 64"
        );
    }

    #[test]
    fn sign_verify_tamper_roundtrip() {
        let key = SigningKey::from_bytes(&[11_u8; 32]);
        let stated = content_hash_json(&serde_json::json!({"payload": "x"}));
        let hash = decode_content_hash(&stated).expect("hash");
        let sig: [u8; 64] = key.sign(&hash).to_bytes();

        let pub_bytes = decode_public_key(&hex::encode(key.verifying_key().to_bytes())).expect("pubkey");
        let vk = parse_verifying_key(&pub_bytes).expect("vk");
        assert!(verify_signature_over_hash(&vk, &hash, &sig));

        let mut wrong_hash = hash;
        wrong_hash[0] ^= 0xFF;
        assert!(!verify_signature_over_hash(&vk, &wrong_hash, &sig));
    }
}
