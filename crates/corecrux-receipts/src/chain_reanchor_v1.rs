// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! G6 crypto-migration: signature-algorithm re-anchoring.
//!
//! The receipt format is algorithm-agile (`ReceiptSigV1.alg` + capability-token
//! `spec_version`), but it shipped without a path to retire one signature
//! algorithm and re-anchor existing chain heads under a new one. This module
//! adds that path additively — it changes no existing verification behaviour.
//!
//! A `chain_signature_reanchor` receipt binds a chain head that was originally
//! signed under algorithm A (e.g. `ed25519`) to a fresh attestation under
//! algorithm B (e.g. `p256-ecdsa-sha256`). An independent verifier confirms
//! BOTH legs: the original head signature still verifies under alg A, and the
//! re-anchor body verifies under alg B. A hybrid variant carries two signatures
//! (alg A + alg B) over the same body for longest-retention customers.
//!
//! This is deliberately a *separate* kind from `audit_gap_v1`'s `chain_reanchor`
//! (body-hash-algorithm migration metadata). That body records a hash-window
//! change; this one counter-signs a head under a new *signature* algorithm.
//!
//! See [`docs/spec/crypto-migration-v1.md`](../../../docs/spec/crypto-migration-v1.md).

use ciborium::value::Value as CborValue;
use ed25519_dalek::{Signer as _, SigningKey as Ed25519SigningKey, VerifyingKey as Ed25519VerifyingKey};
use p256::ecdsa::{
    signature::Verifier as _, Signature as P256Signature, SigningKey as P256SigningKey,
    VerifyingKey as P256VerifyingKey,
};

use crate::verify_v1::ReceiptSigV1;

pub const CHAIN_SIGNATURE_REANCHOR_BODY_SCHEMA_V1: &str = "cuecrux.receipt.body.v1";

/// Distinct from `audit_gap_v1::CHAIN_REANCHOR_KIND_V1` (`chain_reanchor`),
/// which is a body-hash-algorithm migration. This kind is a *signature*
/// algorithm re-anchor.
pub const CHAIN_SIGNATURE_REANCHOR_KIND_V1: &str = "chain_signature_reanchor";

/// Algorithm label for Ed25519 detached signatures (alg A in the common
/// migration). Matches `ReceiptSigV1.alg` produced elsewhere in this crate.
pub const ALG_ED25519_V1: &str = "ed25519";

/// Algorithm label for ECDSA over the NIST P-256 curve with SHA-256 (alg B in
/// the common migration). Distinct family from Ed25519, so a successful
/// verify-under-both proves genuine algorithm agility.
pub const ALG_P256_ECDSA_SHA256_V1: &str = "p256-ecdsa-sha256";

/// Inputs to [`build_chain_signature_reanchor_body_v1`].
///
/// `chain_head_hash` is the 32-byte BLAKE3 of the chain-head receipt body being
/// re-anchored — i.e. the value alg A originally signed
/// (`ReceiptSigV1.signed_payload_hash`). `original_signature` is the verbatim
/// detached signature alg A produced over that head, carried so an independent
/// verifier can re-check Leg A offline.
#[derive(Debug, Clone)]
pub struct ChainSignatureReanchorBodyInputV1<'a> {
    pub tenant_id: &'a str,
    pub receipt_id: &'a str,
    pub chain_head_hash: [u8; 32],
    pub original_alg: &'a str,
    pub original_signature: &'a [u8],
    pub original_key_id: &'a str,
    pub new_alg: &'a str,
    pub new_key_id: &'a str,
    pub reanchored_at_unix_ns: u64,
}

fn text_entry(key: &str, value: &str) -> (CborValue, CborValue) {
    (CborValue::Text(key.to_string()), CborValue::Text(value.to_string()))
}

fn bytes_entry(key: &str, value: &[u8]) -> (CborValue, CborValue) {
    (CborValue::Text(key.to_string()), CborValue::Bytes(value.to_vec()))
}

fn uint_entry(key: &str, value: u64) -> (CborValue, CborValue) {
    (CborValue::Text(key.to_string()), CborValue::Integer(value.into()))
}

fn encode(top: Vec<(CborValue, CborValue)>) -> (Vec<u8>, [u8; 32]) {
    let v = CborValue::Map(top);
    let mut bytes = Vec::new();
    if ciborium::ser::into_writer(&v, &mut bytes).is_err() {
        bytes.clear();
    }
    let digest = blake3::hash(&bytes);
    (bytes, *digest.as_bytes())
}

/// Build the canonical CBOR body bytes + BLAKE3 body hash for a
/// signature-algorithm re-anchor, mirroring the other `build_*_body_v1`
/// builders in this crate.
pub fn build_chain_signature_reanchor_body_v1(input: &ChainSignatureReanchorBodyInputV1<'_>) -> (Vec<u8>, [u8; 32]) {
    encode(vec![
        text_entry("schema", CHAIN_SIGNATURE_REANCHOR_BODY_SCHEMA_V1),
        text_entry("kind", CHAIN_SIGNATURE_REANCHOR_KIND_V1),
        text_entry("receipt_id", input.receipt_id),
        text_entry("tenant_id", input.tenant_id),
        bytes_entry("chain_head_hash", &input.chain_head_hash),
        text_entry("original_alg", input.original_alg),
        bytes_entry("original_signature", input.original_signature),
        text_entry("original_key_id", input.original_key_id),
        text_entry("new_alg", input.new_alg),
        text_entry("new_key_id", input.new_key_id),
        uint_entry("reanchored_at_unix_ns", input.reanchored_at_unix_ns),
    ])
}

/// Sign a re-anchor body under the NEW algorithm (alg B). The returned
/// `ReceiptSigV1` carries `alg = new_alg` while the body it covers carries the
/// original alg + signature.
///
/// `new_alg` must be a supported new-side algorithm
/// ([`ALG_ED25519_V1`] or [`ALG_P256_ECDSA_SHA256_V1`]); the matching signing
/// key must be supplied via [`ReanchorSigningKeyV1`].
pub fn sign_chain_signature_reanchor_v1(
    receipt_id: &str,
    body_bytes: &[u8],
    body_hash: [u8; 32],
    new_signing_key: &ReanchorSigningKeyV1<'_>,
    key_id: &str,
    signed_at: &str,
) -> ReceiptSigV1 {
    let (alg, signature) = new_signing_key.sign(body_bytes);
    ReceiptSigV1 {
        schema: "cuecrux.receipt.sig.v1".to_string(),
        receipt_id: receipt_id.to_string(),
        alg: alg.to_string(),
        key_id: key_id.to_string(),
        signed_at: signed_at.to_string(),
        signature,
        signed_payload_hash: body_hash.to_vec(),
    }
}

/// Hybrid signing: produce BOTH an alg-A and an alg-B `ReceiptSigV1` over the
/// same re-anchor body bytes. For longest-retention customers who want every
/// retained head covered by a currently-strong signature throughout a
/// transition window.
#[allow(clippy::too_many_arguments)]
pub fn sign_chain_signature_reanchor_hybrid_v1(
    receipt_id: &str,
    body_bytes: &[u8],
    body_hash: [u8; 32],
    alg_a_signing_key: &ReanchorSigningKeyV1<'_>,
    alg_a_key_id: &str,
    alg_b_signing_key: &ReanchorSigningKeyV1<'_>,
    alg_b_key_id: &str,
    signed_at: &str,
) -> (ReceiptSigV1, ReceiptSigV1) {
    let sig_a = sign_chain_signature_reanchor_v1(
        receipt_id,
        body_bytes,
        body_hash,
        alg_a_signing_key,
        alg_a_key_id,
        signed_at,
    );
    let sig_b = sign_chain_signature_reanchor_v1(
        receipt_id,
        body_bytes,
        body_hash,
        alg_b_signing_key,
        alg_b_key_id,
        signed_at,
    );
    (sig_a, sig_b)
}

/// A signing key tagged with its algorithm. The re-anchor signer is
/// algorithm-agile, so it carries the concrete key behind an enum rather than
/// hard-coding Ed25519.
pub enum ReanchorSigningKeyV1<'a> {
    Ed25519(&'a Ed25519SigningKey),
    P256(&'a P256SigningKey),
}

impl ReanchorSigningKeyV1<'_> {
    /// The algorithm label this signing key produces signatures under.
    pub fn alg(&self) -> &'static str {
        match self {
            ReanchorSigningKeyV1::Ed25519(_) => ALG_ED25519_V1,
            ReanchorSigningKeyV1::P256(_) => ALG_P256_ECDSA_SHA256_V1,
        }
    }

    /// Returns `(alg_label, signature_bytes)` over the full message bytes.
    fn sign(&self, msg: &[u8]) -> (&'static str, Vec<u8>) {
        match self {
            ReanchorSigningKeyV1::Ed25519(sk) => (ALG_ED25519_V1, sk.sign(msg).to_bytes().to_vec()),
            ReanchorSigningKeyV1::P256(sk) => {
                let sig: P256Signature = sk.sign(msg);
                (ALG_P256_ECDSA_SHA256_V1, sig.to_der().as_bytes().to_vec())
            }
        }
    }
}

/// A public key tagged with its algorithm, used by the verify path.
pub enum ReanchorVerifyingKeyV1<'a> {
    Ed25519(&'a Ed25519VerifyingKey),
    P256(&'a P256VerifyingKey),
}

impl ReanchorVerifyingKeyV1<'_> {
    fn alg(&self) -> &'static str {
        match self {
            ReanchorVerifyingKeyV1::Ed25519(_) => ALG_ED25519_V1,
            ReanchorVerifyingKeyV1::P256(_) => ALG_P256_ECDSA_SHA256_V1,
        }
    }

    /// Verify a detached signature over `msg`. Returns false on any malformed
    /// signature or verification failure.
    fn verify(&self, msg: &[u8], signature: &[u8]) -> bool {
        match self {
            ReanchorVerifyingKeyV1::Ed25519(vk) => {
                let Ok(sig_bytes) = <[u8; 64]>::try_from(signature) else {
                    return false;
                };
                vk.verify_strict(msg, &ed25519_dalek::Signature::from_bytes(&sig_bytes))
                    .is_ok()
            }
            ReanchorVerifyingKeyV1::P256(vk) => {
                let Ok(sig) = P256Signature::from_der(signature) else {
                    return false;
                };
                vk.verify(msg, &sig).is_ok()
            }
        }
    }
}

/// Outcome of [`verify_chain_signature_reanchor_v1`]. Both legs must be true
/// for `ok`; the per-leg fields let callers report which leg failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainSignatureReanchorVerifyReportV1 {
    /// Structural body checks: parses as CBOR, correct kind/schema, well-formed
    /// fields, distinct old/new algs.
    pub body_well_formed: bool,
    /// Leg A: the carried `original_signature` verifies under alg A over the
    /// supplied original chain-head body bytes, and `chain_head_hash` matches
    /// `BLAKE3(head_body_bytes)`.
    pub original_head_verifies: bool,
    /// Leg B: the re-anchor `ReceiptSigV1` verifies under alg B over the
    /// re-anchor body bytes.
    pub reanchor_verifies: bool,
    /// Both legs passed; the re-anchor attests "head X, alg A → alg B at T".
    pub ok: bool,
}

/// Confirm a signature-algorithm re-anchor: BOTH the original head signature
/// (alg A) AND the re-anchor signature (alg B) must verify.
///
/// - `reanchor_body_bytes` / `reanchor_sig_bytes`: the re-anchor receipt body
///   and its detached `ReceiptSigV1` (signed under alg B). Bytes are verified
///   exactly as stored (no reserialization).
/// - `original_head_body_bytes`: the chain-head receipt body the migration
///   re-anchors. `chain_head_hash` in the body MUST equal its BLAKE3.
/// - `alg_a_key` / `alg_b_key`: public keys for the two algorithms. Their alg
///   labels MUST match the body's `original_alg` / `new_alg` respectively.
pub fn verify_chain_signature_reanchor_v1(
    reanchor_body_bytes: &[u8],
    reanchor_sig_bytes: &[u8],
    original_head_body_bytes: &[u8],
    alg_a_key: &ReanchorVerifyingKeyV1<'_>,
    alg_b_key: &ReanchorVerifyingKeyV1<'_>,
) -> ChainSignatureReanchorVerifyReportV1 {
    let mut report = ChainSignatureReanchorVerifyReportV1 {
        body_well_formed: false,
        original_head_verifies: false,
        reanchor_verifies: false,
        ok: false,
    };

    let Some(fields) = ParsedReanchorBody::parse(reanchor_body_bytes) else {
        return report;
    };
    if !fields.is_well_formed() {
        return report;
    }
    // Supplied keys must match the algorithms named in the body.
    if alg_a_key.alg() != fields.original_alg || alg_b_key.alg() != fields.new_alg {
        return report;
    }
    report.body_well_formed = true;

    // Leg A — the original head still verifies under alg A, and the body's
    // chain_head_hash binds the exact head bytes the verifier supplies.
    let head_hash = *blake3::hash(original_head_body_bytes).as_bytes();
    report.original_head_verifies =
        head_hash == fields.chain_head_hash && alg_a_key.verify(original_head_body_bytes, &fields.original_signature);

    // Leg B — the re-anchor body verifies under alg B via its detached sig.
    report.reanchor_verifies =
        verify_reanchor_sig_under(reanchor_body_bytes, reanchor_sig_bytes, alg_b_key, &fields.new_alg);

    report.ok = report.original_head_verifies && report.reanchor_verifies;
    report
}

/// Confirm a hybrid re-anchor: the original head (alg A) verifies, the re-anchor
/// body verifies under alg B, AND a second alg-A signature over the same
/// re-anchor body verifies. All three legs must pass.
#[allow(clippy::too_many_arguments)]
pub fn verify_chain_signature_reanchor_hybrid_v1(
    reanchor_body_bytes: &[u8],
    reanchor_sig_a_bytes: &[u8],
    reanchor_sig_b_bytes: &[u8],
    original_head_body_bytes: &[u8],
    alg_a_key: &ReanchorVerifyingKeyV1<'_>,
    alg_b_key: &ReanchorVerifyingKeyV1<'_>,
) -> ChainSignatureReanchorVerifyReportV1 {
    // First confirm the standard two legs (original head + alg-B re-anchor).
    let mut report = verify_chain_signature_reanchor_v1(
        reanchor_body_bytes,
        reanchor_sig_b_bytes,
        original_head_body_bytes,
        alg_a_key,
        alg_b_key,
    );
    // Then require the additional alg-A signature over the re-anchor body.
    let alg_a_over_reanchor =
        verify_reanchor_sig_under(reanchor_body_bytes, reanchor_sig_a_bytes, alg_a_key, alg_a_key.alg());
    report.ok = report.ok && alg_a_over_reanchor;
    report
}

fn verify_reanchor_sig_under(
    body_bytes: &[u8],
    sig_bytes: &[u8],
    key: &ReanchorVerifyingKeyV1<'_>,
    expected_alg: &str,
) -> bool {
    let Ok(sig) = ciborium::de::from_reader::<ReceiptSigV1, _>(std::io::Cursor::new(sig_bytes)) else {
        return false;
    };
    if sig.alg != expected_alg || sig.alg != key.alg() {
        return false;
    }
    if sig.signed_payload_hash.as_slice() != blake3::hash(body_bytes).as_bytes() {
        return false;
    }
    key.verify(body_bytes, &sig.signature)
}

struct ParsedReanchorBody {
    chain_head_hash: [u8; 32],
    original_alg: String,
    original_signature: Vec<u8>,
    new_alg: String,
}

impl ParsedReanchorBody {
    fn parse(body_bytes: &[u8]) -> Option<Self> {
        let v: CborValue = ciborium::de::from_reader(std::io::Cursor::new(body_bytes)).ok()?;
        let CborValue::Map(map) = v else { return None };
        if text_field(&map, "kind").as_deref() != Some(CHAIN_SIGNATURE_REANCHOR_KIND_V1) {
            return None;
        }
        let chain_head_hash: [u8; 32] = bytes_field(&map, "chain_head_hash")?.as_slice().try_into().ok()?;
        Some(Self {
            chain_head_hash,
            original_alg: text_field(&map, "original_alg")?,
            original_signature: bytes_field(&map, "original_signature")?,
            new_alg: text_field(&map, "new_alg")?,
        })
    }

    fn is_well_formed(&self) -> bool {
        is_supported_alg(&self.original_alg)
            && is_supported_alg(&self.new_alg)
            && self.original_alg != self.new_alg
            && !self.original_signature.is_empty()
    }
}

fn is_supported_alg(alg: &str) -> bool {
    matches!(alg, ALG_ED25519_V1 | ALG_P256_ECDSA_SHA256_V1)
}

fn text_field(map: &[(CborValue, CborValue)], key: &str) -> Option<String> {
    for (k, v) in map {
        if let (CborValue::Text(k), CborValue::Text(s)) = (k, v) {
            if k == key {
                return Some(s.clone());
            }
        }
    }
    None
}

fn bytes_field(map: &[(CborValue, CborValue)], key: &str) -> Option<Vec<u8>> {
    for (k, v) in map {
        if let (CborValue::Text(k), CborValue::Bytes(b)) = (k, v) {
            if k == key {
                return Some(b.clone());
            }
        }
    }
    None
}

/// Cheap post-verification kind assertion, mirroring the other
/// `assert_*_kind_v1` helpers.
pub fn assert_chain_signature_reanchor_kind_v1(body_bytes: &[u8]) -> bool {
    let Ok(v) = ciborium::de::from_reader::<CborValue, _>(std::io::Cursor::new(body_bytes)) else {
        return false;
    };
    let CborValue::Map(map) = v else { return false };
    text_field(&map, "kind").as_deref() == Some(CHAIN_SIGNATURE_REANCHOR_KIND_V1)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey as P256SigningKey;
    use rand_core::OsRng;

    /// A stand-in chain head: a normal receipt body signed under alg A
    /// (ed25519). Returns (head_body_bytes, head_hash, original_signature).
    fn make_head_signed_under_ed25519(sk: &Ed25519SigningKey) -> (Vec<u8>, [u8; 32], Vec<u8>) {
        let body = CborValue::Map(vec![
            text_entry("schema", "cuecrux.receipt.body.v1"),
            text_entry("kind", "memory_use"),
            text_entry("receipt_id", "head_1"),
            text_entry("tenant_id", "tenant-a"),
        ]);
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&body, &mut bytes).unwrap();
        let hash = *blake3::hash(&bytes).as_bytes();
        let sig = sk.sign(&bytes).to_bytes().to_vec();
        (bytes, hash, sig)
    }

    fn reanchor_input(head_hash: [u8; 32], original_sig: &[u8]) -> ChainSignatureReanchorBodyInputV1<'_> {
        ChainSignatureReanchorBodyInputV1 {
            tenant_id: "tenant-a",
            receipt_id: "reanchor_1",
            chain_head_hash: head_hash,
            original_alg: ALG_ED25519_V1,
            original_signature: original_sig,
            original_key_id: "ed25519-key-1",
            new_alg: ALG_P256_ECDSA_SHA256_V1,
            new_key_id: "p256-key-1",
            reanchored_at_unix_ns: 1_750_000_000_000_000_000,
        }
    }

    fn encode_sig(sig: &ReceiptSigV1) -> Vec<u8> {
        let mut out = Vec::new();
        ciborium::ser::into_writer(sig, &mut out).unwrap();
        out
    }

    #[test]
    fn body_round_trips_and_is_byte_deterministic() {
        let head_sig = vec![0xAA; 64];
        let (a, ha) = build_chain_signature_reanchor_body_v1(&reanchor_input([7u8; 32], &head_sig));
        let (b, hb) = build_chain_signature_reanchor_body_v1(&reanchor_input([7u8; 32], &head_sig));
        assert_eq!(a, b);
        assert_eq!(ha, hb);
        assert_eq!(ha, *blake3::hash(&a).as_bytes());
        assert!(assert_chain_signature_reanchor_kind_v1(&a));
        assert!(!assert_chain_signature_reanchor_kind_v1(b"not cbor"));
    }

    #[test]
    fn verify_under_both_algorithms_succeeds() {
        // Alg A: original head signed under ed25519.
        let alg_a_sk = Ed25519SigningKey::from_bytes(&[3u8; 32]);
        let alg_a_vk = alg_a_sk.verifying_key();
        let (head_bytes, head_hash, head_sig) = make_head_signed_under_ed25519(&alg_a_sk);

        // Alg B: re-anchor signer is p256-ecdsa-sha256.
        let alg_b_sk = P256SigningKey::random(&mut OsRng);
        let alg_b_vk = P256VerifyingKey::from(&alg_b_sk);

        let (body, hash) = build_chain_signature_reanchor_body_v1(&reanchor_input(head_hash, &head_sig));
        let sig = sign_chain_signature_reanchor_v1(
            "reanchor_1",
            &body,
            hash,
            &ReanchorSigningKeyV1::P256(&alg_b_sk),
            "p256-key-1",
            "2026-06-14T12:00:00Z",
        );
        assert_eq!(sig.alg, ALG_P256_ECDSA_SHA256_V1);
        assert_eq!(sig.signed_payload_hash, hash.to_vec());

        let report = verify_chain_signature_reanchor_v1(
            &body,
            &encode_sig(&sig),
            &head_bytes,
            &ReanchorVerifyingKeyV1::Ed25519(&alg_a_vk),
            &ReanchorVerifyingKeyV1::P256(&alg_b_vk),
        );
        assert!(report.body_well_formed);
        assert!(report.original_head_verifies, "Leg A must verify: {report:?}");
        assert!(report.reanchor_verifies, "Leg B must verify: {report:?}");
        assert!(report.ok);
    }

    #[test]
    fn tampered_reanchor_body_is_rejected() {
        let alg_a_sk = Ed25519SigningKey::from_bytes(&[5u8; 32]);
        let alg_a_vk = alg_a_sk.verifying_key();
        let (head_bytes, head_hash, head_sig) = make_head_signed_under_ed25519(&alg_a_sk);
        let alg_b_sk = P256SigningKey::random(&mut OsRng);
        let alg_b_vk = P256VerifyingKey::from(&alg_b_sk);

        let (body, hash) = build_chain_signature_reanchor_body_v1(&reanchor_input(head_hash, &head_sig));
        let sig = sign_chain_signature_reanchor_v1(
            "reanchor_1",
            &body,
            hash,
            &ReanchorSigningKeyV1::P256(&alg_b_sk),
            "p256-key-1",
            "2026-06-14T12:00:00Z",
        );

        // Flip a byte in the body: Leg B (which signs the body) must fail.
        let mut tampered = body.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0xFF;
        let report = verify_chain_signature_reanchor_v1(
            &tampered,
            &encode_sig(&sig),
            &head_bytes,
            &ReanchorVerifyingKeyV1::Ed25519(&alg_a_vk),
            &ReanchorVerifyingKeyV1::P256(&alg_b_vk),
        );
        assert!(!report.ok);
        assert!(!report.reanchor_verifies);
    }

    #[test]
    fn tampered_original_head_is_rejected() {
        let alg_a_sk = Ed25519SigningKey::from_bytes(&[6u8; 32]);
        let alg_a_vk = alg_a_sk.verifying_key();
        let (head_bytes, head_hash, head_sig) = make_head_signed_under_ed25519(&alg_a_sk);
        let alg_b_sk = P256SigningKey::random(&mut OsRng);
        let alg_b_vk = P256VerifyingKey::from(&alg_b_sk);

        let (body, hash) = build_chain_signature_reanchor_body_v1(&reanchor_input(head_hash, &head_sig));
        let sig = sign_chain_signature_reanchor_v1(
            "reanchor_1",
            &body,
            hash,
            &ReanchorSigningKeyV1::P256(&alg_b_sk),
            "p256-key-1",
            "2026-06-14T12:00:00Z",
        );

        // Corrupt the head bytes: chain_head_hash mismatch + alg-A sig fails.
        let mut tampered_head = head_bytes.clone();
        tampered_head[0] ^= 0xFF;
        let report = verify_chain_signature_reanchor_v1(
            &body,
            &encode_sig(&sig),
            &tampered_head,
            &ReanchorVerifyingKeyV1::Ed25519(&alg_a_vk),
            &ReanchorVerifyingKeyV1::P256(&alg_b_vk),
        );
        assert!(!report.ok);
        assert!(!report.original_head_verifies);
        // Leg B still verifies — the re-anchor body itself is untouched.
        assert!(report.reanchor_verifies);
    }

    #[test]
    fn wrong_alg_b_key_is_rejected() {
        let alg_a_sk = Ed25519SigningKey::from_bytes(&[8u8; 32]);
        let alg_a_vk = alg_a_sk.verifying_key();
        let (head_bytes, head_hash, head_sig) = make_head_signed_under_ed25519(&alg_a_sk);
        let alg_b_sk = P256SigningKey::random(&mut OsRng);
        let other_b_sk = P256SigningKey::random(&mut OsRng);
        let other_b_vk = P256VerifyingKey::from(&other_b_sk);

        let (body, hash) = build_chain_signature_reanchor_body_v1(&reanchor_input(head_hash, &head_sig));
        let sig = sign_chain_signature_reanchor_v1(
            "reanchor_1",
            &body,
            hash,
            &ReanchorSigningKeyV1::P256(&alg_b_sk),
            "p256-key-1",
            "2026-06-14T12:00:00Z",
        );

        let report = verify_chain_signature_reanchor_v1(
            &body,
            &encode_sig(&sig),
            &head_bytes,
            &ReanchorVerifyingKeyV1::Ed25519(&alg_a_vk),
            &ReanchorVerifyingKeyV1::P256(&other_b_vk),
        );
        assert!(!report.reanchor_verifies);
        assert!(!report.ok);
    }

    #[test]
    fn hybrid_two_signatures_verify_over_same_body() {
        let alg_a_sk = Ed25519SigningKey::from_bytes(&[9u8; 32]);
        let alg_a_vk = alg_a_sk.verifying_key();
        let (head_bytes, head_hash, head_sig) = make_head_signed_under_ed25519(&alg_a_sk);
        let alg_b_sk = P256SigningKey::random(&mut OsRng);
        let alg_b_vk = P256VerifyingKey::from(&alg_b_sk);

        let (body, hash) = build_chain_signature_reanchor_body_v1(&reanchor_input(head_hash, &head_sig));
        let (sig_a, sig_b) = sign_chain_signature_reanchor_hybrid_v1(
            "reanchor_1",
            &body,
            hash,
            &ReanchorSigningKeyV1::Ed25519(&alg_a_sk),
            "ed25519-key-1",
            &ReanchorSigningKeyV1::P256(&alg_b_sk),
            "p256-key-1",
            "2026-06-14T12:00:00Z",
        );
        assert_eq!(sig_a.alg, ALG_ED25519_V1);
        assert_eq!(sig_b.alg, ALG_P256_ECDSA_SHA256_V1);

        let report = verify_chain_signature_reanchor_hybrid_v1(
            &body,
            &encode_sig(&sig_a),
            &encode_sig(&sig_b),
            &head_bytes,
            &ReanchorVerifyingKeyV1::Ed25519(&alg_a_vk),
            &ReanchorVerifyingKeyV1::P256(&alg_b_vk),
        );
        assert!(report.ok, "hybrid verify must pass all three legs: {report:?}");
        assert!(report.original_head_verifies);
        assert!(report.reanchor_verifies);
    }

    #[test]
    fn hybrid_rejects_missing_alg_a_signature() {
        let alg_a_sk = Ed25519SigningKey::from_bytes(&[10u8; 32]);
        let alg_a_vk = alg_a_sk.verifying_key();
        let (head_bytes, head_hash, head_sig) = make_head_signed_under_ed25519(&alg_a_sk);
        let alg_b_sk = P256SigningKey::random(&mut OsRng);
        let alg_b_vk = P256VerifyingKey::from(&alg_b_sk);

        let (body, hash) = build_chain_signature_reanchor_body_v1(&reanchor_input(head_hash, &head_sig));
        let sig_b = sign_chain_signature_reanchor_v1(
            "reanchor_1",
            &body,
            hash,
            &ReanchorSigningKeyV1::P256(&alg_b_sk),
            "p256-key-1",
            "2026-06-14T12:00:00Z",
        );
        // Provide a bogus alg-A signature; hybrid must reject.
        let mut bogus_a = sig_b.clone();
        bogus_a.alg = ALG_ED25519_V1.to_string();
        bogus_a.signature = vec![0u8; 64];

        let report = verify_chain_signature_reanchor_hybrid_v1(
            &body,
            &encode_sig(&bogus_a),
            &encode_sig(&sig_b),
            &head_bytes,
            &ReanchorVerifyingKeyV1::Ed25519(&alg_a_vk),
            &ReanchorVerifyingKeyV1::P256(&alg_b_vk),
        );
        assert!(!report.ok);
    }

    #[test]
    fn body_with_equal_algs_is_not_well_formed() {
        let head_sig = vec![0xAB; 64];
        let mut input = reanchor_input([1u8; 32], &head_sig);
        input.new_alg = ALG_ED25519_V1; // same as original_alg
        let (body, _) = build_chain_signature_reanchor_body_v1(&input);
        assert!(ParsedReanchorBody::parse(&body).is_some());
        assert!(!ParsedReanchorBody::parse(&body).unwrap().is_well_formed());
    }

    #[test]
    fn reanchor_signed_under_ed25519_new_side_also_verifies() {
        // Algorithm-agile: alg B can itself be ed25519 (e.g. key rotation under
        // the same family). Original under p256, re-anchor under ed25519.
        let alg_a_sk = P256SigningKey::random(&mut OsRng);
        let alg_a_vk = P256VerifyingKey::from(&alg_a_sk);
        // Head signed under p256 (alg A here).
        let head_body = CborValue::Map(vec![
            text_entry("schema", "cuecrux.receipt.body.v1"),
            text_entry("receipt_id", "head_2"),
        ]);
        let mut head_bytes = Vec::new();
        ciborium::ser::into_writer(&head_body, &mut head_bytes).unwrap();
        let head_hash = *blake3::hash(&head_bytes).as_bytes();
        let head_sig: P256Signature = alg_a_sk.sign(&head_bytes);
        let head_sig_der = head_sig.to_der().as_bytes().to_vec();

        let alg_b_sk = Ed25519SigningKey::from_bytes(&[11u8; 32]);
        let alg_b_vk = alg_b_sk.verifying_key();

        let input = ChainSignatureReanchorBodyInputV1 {
            tenant_id: "tenant-a",
            receipt_id: "reanchor_2",
            chain_head_hash: head_hash,
            original_alg: ALG_P256_ECDSA_SHA256_V1,
            original_signature: &head_sig_der,
            original_key_id: "p256-key-old",
            new_alg: ALG_ED25519_V1,
            new_key_id: "ed25519-key-new",
            reanchored_at_unix_ns: 1_750_000_000_000_000_001,
        };
        let (body, hash) = build_chain_signature_reanchor_body_v1(&input);
        let sig = sign_chain_signature_reanchor_v1(
            "reanchor_2",
            &body,
            hash,
            &ReanchorSigningKeyV1::Ed25519(&alg_b_sk),
            "ed25519-key-new",
            "2026-06-14T12:00:00Z",
        );

        let report = verify_chain_signature_reanchor_v1(
            &body,
            &encode_sig(&sig),
            &head_bytes,
            &ReanchorVerifyingKeyV1::P256(&alg_a_vk),
            &ReanchorVerifyingKeyV1::Ed25519(&alg_b_vk),
        );
        assert!(report.ok, "{report:?}");
    }
}
