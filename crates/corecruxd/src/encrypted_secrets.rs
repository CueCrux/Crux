// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! XChaCha20-Poly1305 envelope for at-rest encryption of integration secrets
//! (GitHub PATs, future API keys). The 32-byte symmetric key is derived from
//! the daemon-root passport via `LocalPassportKey::derive_subkey`, so any
//! passport rotation invalidates existing envelopes — desirable behaviour
//! (forces operator to reconnect, never silently consumes a stale token).

#![allow(clippy::expect_used)] // cryptographic invariants: AEAD nonce/tag sizes are constants — .expect on these is a sound assertion, not a runtime panic

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};

pub const SCHEME_V1: &str = "xchacha20poly1305-v1";

#[derive(Debug, thiserror::Error)]
pub enum EncryptedSecretError {
    #[error("unknown scheme '{0}' — cannot decrypt")]
    UnknownScheme(String),
    #[error("nonce must be 24 hex bytes; got {0}")]
    InvalidNonce(usize),
    #[error("ciphertext is not valid hex")]
    InvalidHex,
    #[error("decryption failed (passport rotated, key mismatch, or tampered envelope)")]
    DecryptionFailed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedEnvelope {
    pub scheme: String,
    pub nonce_hex: String,
    pub ciphertext_hex: String,
}

pub fn seal(plaintext: &[u8], key: &[u8; 32]) -> EncryptedEnvelope {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce_bytes = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .expect("XChaCha20Poly1305::encrypt only fails on programmer error");
    EncryptedEnvelope {
        scheme: SCHEME_V1.to_string(),
        nonce_hex: hex::encode(nonce_bytes),
        ciphertext_hex: hex::encode(&ciphertext),
    }
}

pub fn open(envelope: &EncryptedEnvelope, key: &[u8; 32]) -> Result<Vec<u8>, EncryptedSecretError> {
    if envelope.scheme != SCHEME_V1 {
        return Err(EncryptedSecretError::UnknownScheme(envelope.scheme.clone()));
    }
    let nonce_bytes = hex::decode(&envelope.nonce_hex).map_err(|_| EncryptedSecretError::InvalidHex)?;
    if nonce_bytes.len() != 24 {
        return Err(EncryptedSecretError::InvalidNonce(nonce_bytes.len()));
    }
    let ciphertext = hex::decode(&envelope.ciphertext_hex).map_err(|_| EncryptedSecretError::InvalidHex)?;
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XNonce::from_slice(&nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| EncryptedSecretError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_seals_and_opens() {
        let key = [42u8; 32];
        let plaintext = b"github_pat_11ABCDEFG1234567890";
        let env = seal(plaintext, &key);
        assert_eq!(env.scheme, SCHEME_V1);
        assert_eq!(env.nonce_hex.len(), 48);
        assert!(!env.ciphertext_hex.is_empty());
        let recovered = open(&env, &key).expect("open");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn open_with_wrong_key_fails() {
        let key = [42u8; 32];
        let env = seal(b"secret", &key);
        let bad_key = [43u8; 32];
        assert!(matches!(
            open(&env, &bad_key),
            Err(EncryptedSecretError::DecryptionFailed)
        ));
    }

    #[test]
    fn unknown_scheme_rejected() {
        let env = EncryptedEnvelope {
            scheme: "future-scheme-v9".to_string(),
            nonce_hex: hex::encode([0u8; 24]),
            ciphertext_hex: hex::encode(b"junk"),
        };
        let result = open(&env, &[0u8; 32]);
        assert!(matches!(result, Err(EncryptedSecretError::UnknownScheme(_))));
    }

    #[test]
    fn nonce_is_unique_across_seals() {
        let key = [1u8; 32];
        let a = seal(b"x", &key);
        let b = seal(b"x", &key);
        assert_ne!(a.nonce_hex, b.nonce_hex);
        assert_ne!(a.ciphertext_hex, b.ciphertext_hex);
    }

    #[test]
    fn invalid_nonce_length_rejected() {
        let env = EncryptedEnvelope {
            scheme: SCHEME_V1.to_string(),
            nonce_hex: hex::encode([0u8; 12]),
            ciphertext_hex: hex::encode(b"junk"),
        };
        let result = open(&env, &[0u8; 32]);
        assert!(matches!(result, Err(EncryptedSecretError::InvalidNonce(12))));
    }
}
