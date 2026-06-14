// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Staged crypto-shred primitives.
//!
//! This module is deliberately non-destructive: it can seal subject-scoped
//! payload bytes under a caller-supplied 256-bit CEK and prove that retained
//! ciphertext cannot be opened without the CEK. Production CEK destruction is a
//! separate human-gated operation.

#![allow(deprecated)]

use base64::Engine as _;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const CRYPTO_SHRED_ENVELOPE_SCHEMA_V1: &str = "cuecrux.crypto_shred.envelope.v1";
pub const CRYPTO_SHRED_METHOD_V1: &str = "xchacha20poly1305-subject-cek-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CryptoShredEnvelopeV1 {
    pub schema: String,
    pub method: String,
    pub tenant_id: String,
    pub subject_type: String,
    pub subject_id: String,
    pub subject_cek_id: String,
    pub subject_cek_commitment: String,
    pub nonce_b64: String,
    pub aad_hash: String,
    pub plaintext_hash: String,
    pub ciphertext_hash: String,
    pub ciphertext_b64: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Copy)]
pub struct CryptoShredSealInputV1<'a> {
    pub tenant_id: &'a str,
    pub subject_type: &'a str,
    pub subject_id: &'a str,
    pub subject_cek_id: &'a str,
    pub created_at: &'a str,
}

#[derive(Debug, Error)]
pub enum CryptoShredError {
    #[error("invalid schema or method")]
    InvalidScheme,
    #[error("invalid base64 field {field}: {message}")]
    InvalidBase64 { field: &'static str, message: String },
    #[error("nonce must be 24 bytes")]
    InvalidNonce,
    #[error("CEK commitment mismatch")]
    CekCommitmentMismatch,
    #[error("decrypt failed")]
    DecryptFailed,
    #[error("encrypt failed")]
    EncryptFailed,
    #[error("aad encode failed: {0}")]
    AadEncode(String),
}

pub fn subject_cek_commitment_v1(cek: &[u8; 32], subject_cek_id: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"cuecrux.crypto_shred.subject_cek_commitment.v1");
    hasher.update(subject_cek_id.as_bytes());
    hasher.update(cek);
    format!("blake3:{}", hasher.finalize().to_hex())
}

pub fn seal_crypto_shred_payload_v1(
    input: &CryptoShredSealInputV1<'_>,
    plaintext: &[u8],
    cek: &[u8; 32],
    nonce: &[u8; 24],
) -> Result<CryptoShredEnvelopeV1, CryptoShredError> {
    let aad = aad_bytes(input)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(cek));
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoShredError::EncryptFailed)?;

    Ok(CryptoShredEnvelopeV1 {
        schema: CRYPTO_SHRED_ENVELOPE_SCHEMA_V1.to_string(),
        method: CRYPTO_SHRED_METHOD_V1.to_string(),
        tenant_id: input.tenant_id.to_string(),
        subject_type: input.subject_type.to_string(),
        subject_id: input.subject_id.to_string(),
        subject_cek_id: input.subject_cek_id.to_string(),
        subject_cek_commitment: subject_cek_commitment_v1(cek, input.subject_cek_id),
        nonce_b64: base64::engine::general_purpose::STANDARD.encode(nonce),
        aad_hash: format!("blake3:{}", blake3::hash(&aad).to_hex()),
        plaintext_hash: format!("blake3:{}", blake3::hash(plaintext).to_hex()),
        ciphertext_hash: format!("blake3:{}", blake3::hash(&ciphertext).to_hex()),
        ciphertext_b64: base64::engine::general_purpose::STANDARD.encode(ciphertext),
        created_at: input.created_at.to_string(),
    })
}

pub fn open_crypto_shred_payload_v1(
    envelope: &CryptoShredEnvelopeV1,
    cek: &[u8; 32],
) -> Result<Vec<u8>, CryptoShredError> {
    if envelope.schema != CRYPTO_SHRED_ENVELOPE_SCHEMA_V1 || envelope.method != CRYPTO_SHRED_METHOD_V1 {
        return Err(CryptoShredError::InvalidScheme);
    }
    let expected_commitment = subject_cek_commitment_v1(cek, &envelope.subject_cek_id);
    if envelope.subject_cek_commitment != expected_commitment {
        return Err(CryptoShredError::CekCommitmentMismatch);
    }
    let nonce = decode_fixed_24("nonce_b64", &envelope.nonce_b64)?;
    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(&envelope.ciphertext_b64)
        .map_err(|err| CryptoShredError::InvalidBase64 {
            field: "ciphertext_b64",
            message: err.to_string(),
        })?;
    let input = CryptoShredSealInputV1 {
        tenant_id: &envelope.tenant_id,
        subject_type: &envelope.subject_type,
        subject_id: &envelope.subject_id,
        subject_cek_id: &envelope.subject_cek_id,
        created_at: &envelope.created_at,
    };
    let aad = aad_bytes(&input)?;
    let aad_hash = format!("blake3:{}", blake3::hash(&aad).to_hex());
    if envelope.aad_hash != aad_hash {
        return Err(CryptoShredError::DecryptFailed);
    }
    let cipher = XChaCha20Poly1305::new(Key::from_slice(cek));
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoShredError::DecryptFailed)?;
    let plaintext_hash = format!("blake3:{}", blake3::hash(&plaintext).to_hex());
    if envelope.plaintext_hash != plaintext_hash {
        return Err(CryptoShredError::DecryptFailed);
    }
    Ok(plaintext)
}

fn decode_fixed_24(field: &'static str, value: &str) -> Result<[u8; 24], CryptoShredError> {
    let bytes =
        base64::engine::general_purpose::STANDARD
            .decode(value)
            .map_err(|err| CryptoShredError::InvalidBase64 {
                field,
                message: err.to_string(),
            })?;
    bytes.as_slice().try_into().map_err(|_| CryptoShredError::InvalidNonce)
}

#[derive(Serialize)]
struct CryptoShredAadV1<'a> {
    schema: &'static str,
    tenant_id: &'a str,
    subject_type: &'a str,
    subject_id: &'a str,
    subject_cek_id: &'a str,
    created_at: &'a str,
}

fn aad_bytes(input: &CryptoShredSealInputV1<'_>) -> Result<Vec<u8>, CryptoShredError> {
    serde_json::to_vec(&CryptoShredAadV1 {
        schema: "cuecrux.crypto_shred.aad.v1",
        tenant_id: input.tenant_id,
        subject_type: input.subject_type,
        subject_id: input.subject_id,
        subject_cek_id: input.subject_cek_id,
        created_at: input.created_at,
    })
    .map_err(|err| CryptoShredError::AadEncode(err.to_string()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn input() -> CryptoShredSealInputV1<'static> {
        CryptoShredSealInputV1 {
            tenant_id: "tenant-a",
            subject_type: "fact",
            subject_id: "f_123",
            subject_cek_id: "cek:tenant-a:fact:f_123:v1",
            created_at: "2026-06-14T12:00:00Z",
        }
    }

    #[test]
    fn crypto_shred_envelope_round_trips_with_cek() {
        let cek = [7u8; 32];
        let nonce = [9u8; 24];
        let plaintext = b"subject private payload";
        let envelope = seal_crypto_shred_payload_v1(&input(), plaintext, &cek, &nonce).unwrap();
        assert_eq!(envelope.schema, CRYPTO_SHRED_ENVELOPE_SCHEMA_V1);
        assert_eq!(envelope.method, CRYPTO_SHRED_METHOD_V1);
        assert_ne!(
            envelope.ciphertext_b64,
            base64::engine::general_purpose::STANDARD.encode(plaintext)
        );
        let opened = open_crypto_shred_payload_v1(&envelope, &cek).unwrap();
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn retained_ciphertext_is_unreadable_without_subject_cek() {
        let envelope = seal_crypto_shred_payload_v1(&input(), b"erase me", &[7u8; 32], &[9u8; 24]).unwrap();
        let wrong_key = [8u8; 32];
        let err = open_crypto_shred_payload_v1(&envelope, &wrong_key).unwrap_err();
        assert!(matches!(err, CryptoShredError::CekCommitmentMismatch));
    }

    #[test]
    fn aad_tampering_breaks_decrypt() {
        let cek = [7u8; 32];
        let mut envelope = seal_crypto_shred_payload_v1(&input(), b"erase me", &cek, &[9u8; 24]).unwrap();
        envelope.subject_id = "f_tampered".to_string();
        let err = open_crypto_shred_payload_v1(&envelope, &cek).unwrap_err();
        assert!(matches!(err, CryptoShredError::DecryptFailed));
    }
}
