// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! `.ccxatt` — companion provenance attestation.
//!
//! One detached attestation per segment, covering every companion built for it.
//! It answers a question the companion files themselves cannot: **who produced
//! these bytes, and are they still the bytes that were produced?**
//!
//! Under the processor model the platform computes companions and a customer's
//! daemon reads them locally. Publishing the formats makes them re-implementable,
//! so a self-built companion is indistinguishable from a platform one on inspection
//! alone. This is what makes it distinguishable.
//!
//! # What it is not
//!
//! **This is not DRM.** The CE is Apache-2.0; anyone may fork it and delete the
//! verification. What attestation buys is that bypass becomes a deliberate act —
//! removing a check from published source — rather than a convenient one. It also
//! catches the far more common honest failures: a corrupt download, a truncated
//! copy, or a customer who self-filled a lane and then reports bad recall.
//!
//! # Provenance states
//!
//! | State | Meaning | Load behaviour |
//! |---|---|---|
//! | [`Provenance::Platform`] | verifies against a configured CueCrux trust root | normal |
//! | [`Provenance::Local`] | verifies against this daemon's own device key | normal |
//! | [`Provenance::Invalid`] | present but signature or digest fails | **refuse, always** |
//! | [`Provenance::None`] | no `.ccxatt` at all | mode-dependent, always loud |
//!
//! A missing signature and a broken one are **different events**. `Invalid` means
//! tampering or corruption and there is no mode in which loading it is correct, so
//! it fails closed unconditionally. Only `None` is mode-dependent.
//!
//! The `Local` state is load-bearing for the alarm's usefulness: a daemon signs the
//! companions it builds itself, so `None` should essentially never occur in normal
//! operation. Without that, every free local user would trip the warning, learn to
//! ignore it, and the signal would be worth nothing.

use std::collections::BTreeMap;

use crate::IndexError;

/// Schema tag carried in every attestation body.
pub const CCXATT_SCHEMA_V1: &str = "crux.companion.attestation.v1";
/// Extension for the detached attestation file.
pub const CCXATT_EXT: &str = "ccxatt";

/// Who produced a segment's companions, as resolved at load time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provenance {
    /// Signature verified against a configured CueCrux trust root.
    Platform,
    /// Signature verified against this daemon's own device key.
    Local,
    /// An attestation is present but does not verify — signature, digest, or
    /// identity mismatch. Always fatal.
    Invalid,
    /// No attestation file. Loud in `warn`, fatal in `enforce`.
    None,
}

impl Provenance {
    /// Stable slug for logs, `/v1/version`, and query meta.
    pub fn slug(self) -> &'static str {
        match self {
            Provenance::Platform => "platform",
            Provenance::Local => "local",
            Provenance::Invalid => "invalid",
            Provenance::None => "none",
        }
    }

    /// True when this state must refuse to load regardless of mode.
    ///
    /// Only [`Provenance::Invalid`] qualifies. A *missing* attestation is a policy
    /// question; a *broken* one is evidence that the bytes are not what was signed.
    pub fn is_fatal(self) -> bool {
        matches!(self, Provenance::Invalid)
    }
}

/// Enforcement posture, mirroring the coordination plane's advisory/enforce split.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AttestationMode {
    /// Verification skipped. Reported as `degraded` so "we turned the alarm off"
    /// is visible rather than invisible.
    Off,
    /// `None` loads but is reported on every surface. The ship default.
    #[default]
    Warn,
    /// `None` refuses to load too.
    Enforce,
}

impl AttestationMode {
    /// Parse from config. Unrecognised values fall back to the safe default rather
    /// than silently disabling the check.
    pub fn from_str_or_default(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "off" => AttestationMode::Off,
            "enforce" => AttestationMode::Enforce,
            _ => AttestationMode::Warn,
        }
    }

    /// Whether a segment in this provenance state may be loaded.
    pub fn permits(self, provenance: Provenance) -> bool {
        if provenance.is_fatal() {
            return false; // C8: invalid is fatal in EVERY mode, including Off.
        }
        // Only `enforce` refuses a *missing* attestation; `warn` and `off` load it
        // loudly. `invalid` was already refused above, in every mode.
        !matches!((self, provenance), (AttestationMode::Enforce, Provenance::None))
    }
}

/// One companion covered by an attestation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompanionDigest {
    /// Extension without the dot, e.g. `ccxe`.
    pub ext: String,
    /// Model key for a keyed companion (`<stem>.ccxe@<key>`), else `None`.
    pub key: Option<String>,
    /// blake3 of the companion's bytes, lowercase hex.
    pub blake3: String,
    /// Size in bytes, for a cheap pre-check before hashing.
    pub bytes: u64,
}

/// The signed body of a `.ccxatt`.
///
/// Binding segment identity **and** per-companion digests is what stops a valid
/// attestation being replayed onto different bytes, or a bundle built for tenant A
/// being dropped into tenant B's shard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationBody {
    pub schema: String,
    pub shard_id: u32,
    pub segment_seq: u64,
    /// Hex segment id, matching the `.ccxseg` filename stem.
    pub segment_id: String,
    pub tenant_id: Option<String>,
    /// `platform` or `local` — which trust root the verifier must use.
    pub provenance: String,
    pub issued_at: u64,
    /// Ed25519 public key of the producer, lowercase hex.
    pub producer_pubkey: String,
    /// Producer fingerprint (passport fpr or issuer kid).
    pub producer_fpr: String,
    /// Builder source commit, so a format change is attributable.
    pub builder_commit: String,
    pub companions: Vec<CompanionDigest>,
}

impl AttestationBody {
    /// Canonical bytes signed and verified.
    ///
    /// Deterministic by construction: fields in a fixed order, companions sorted by
    /// `(ext, key)`, `\n`-separated. Two producers that agree on content produce
    /// byte-identical preimages, which is what makes the signature reproducible.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut sorted: Vec<&CompanionDigest> = self.companions.iter().collect();
        sorted.sort_by(|a, b| (&a.ext, &a.key).cmp(&(&b.ext, &b.key)));

        let mut out = String::new();
        out.push_str(&self.schema);
        out.push('\n');
        out.push_str(&self.shard_id.to_string());
        out.push('\n');
        out.push_str(&self.segment_seq.to_string());
        out.push('\n');
        out.push_str(&self.segment_id);
        out.push('\n');
        out.push_str(self.tenant_id.as_deref().unwrap_or(""));
        out.push('\n');
        out.push_str(&self.provenance);
        out.push('\n');
        out.push_str(&self.issued_at.to_string());
        out.push('\n');
        out.push_str(&self.producer_pubkey);
        out.push('\n');
        out.push_str(&self.producer_fpr);
        out.push('\n');
        out.push_str(&self.builder_commit);
        out.push('\n');
        for c in sorted {
            out.push_str(&c.ext);
            out.push('\t');
            out.push_str(c.key.as_deref().unwrap_or(""));
            out.push('\t');
            out.push_str(&c.blake3);
            out.push('\t');
            out.push_str(&c.bytes.to_string());
            out.push('\n');
        }
        out.into_bytes()
    }
}

/// Why an attestation failed to verify. Surfaced in logs and `/v1/version` so an
/// operator can tell a corrupt download from a forged one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestationFailure {
    /// The file could not be parsed as a v1 attestation.
    Malformed(String),
    /// Ed25519 verification failed against every configured trust root.
    BadSignature,
    /// Signed by a key that is not a configured root and not this device.
    UnknownProducer { producer_fpr: String },
    /// A covered companion is absent from disk.
    MissingCompanion { ext: String },
    /// A covered companion's bytes do not hash to the signed digest.
    DigestMismatch { ext: String },
    /// The attestation names a different segment than the one it sits beside.
    ///
    /// This is the replay guard: a validly-signed attestation moved next to other
    /// bytes must not authenticate them.
    SegmentMismatch { expected: String, found: String },
}

impl AttestationFailure {
    /// Stable reason code for `/v1/version` and structured logs.
    pub fn reason_code(&self) -> &'static str {
        match self {
            AttestationFailure::Malformed(_) => "companion_attestation_malformed",
            AttestationFailure::BadSignature => "companion_attestation_bad_signature",
            AttestationFailure::UnknownProducer { .. } => "companion_attestation_unknown_producer",
            AttestationFailure::MissingCompanion { .. } => "companion_attestation_missing_companion",
            AttestationFailure::DigestMismatch { .. } => "companion_attestation_digest_mismatch",
            AttestationFailure::SegmentMismatch { .. } => "companion_attestation_segment_mismatch",
        }
    }
}

/// Trust roots a verifier will accept, keyed by fingerprint.
///
/// `platform` roots are configured CueCrux issuer keys; `local` is this daemon's own
/// device key. Keeping them separate is what lets the verifier report *which* it
/// matched, rather than a bare pass/fail.
#[derive(Debug, Clone, Default)]
pub struct TrustRoots {
    platform: BTreeMap<String, [u8; 32]>,
    local: Option<([String; 1], [u8; 32])>,
}

impl TrustRoots {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a CueCrux platform issuer key. Multiple roots are supported so a key
    /// rotation does not require a flag day.
    pub fn with_platform_root(mut self, fpr: impl Into<String>, pubkey: [u8; 32]) -> Self {
        self.platform.insert(fpr.into(), pubkey);
        self
    }

    /// Set this daemon's own device key, used to verify companions it built itself.
    pub fn with_local_device(mut self, fpr: impl Into<String>, pubkey: [u8; 32]) -> Self {
        self.local = Some(([fpr.into()], pubkey));
        self
    }

    fn resolve(&self, fpr: &str) -> Option<(Provenance, [u8; 32])> {
        if let Some(pk) = self.platform.get(fpr) {
            return Some((Provenance::Platform, *pk));
        }
        if let Some(([local_fpr], pk)) = &self.local {
            if local_fpr == fpr {
                return Some((Provenance::Local, *pk));
            }
        }
        None
    }
}

/// Verify an attestation against the companion bytes it covers.
///
/// `companion_bytes` resolves `(ext, key)` to the bytes on disk; `None` means the
/// file is absent. `expected_segment_id` is the stem of the segment the attestation
/// was found beside — checked against the signed body so a valid attestation cannot
/// be moved onto other bytes.
///
/// Returns the resolved [`Provenance`], or the specific failure. Never panics on
/// malformed input.
pub fn verify_attestation<F>(
    body: &AttestationBody,
    signature: &[u8; 64],
    roots: &TrustRoots,
    expected_segment_id: &str,
    mut companion_bytes: F,
) -> std::result::Result<Provenance, AttestationFailure>
where
    F: FnMut(&str, Option<&str>) -> Option<Vec<u8>>,
{
    if body.schema != CCXATT_SCHEMA_V1 {
        return Err(AttestationFailure::Malformed(format!(
            "unsupported schema {:?}",
            body.schema
        )));
    }
    // Identity first: cheapest check, and it is the replay guard.
    if body.segment_id != expected_segment_id {
        return Err(AttestationFailure::SegmentMismatch {
            expected: expected_segment_id.to_string(),
            found: body.segment_id.clone(),
        });
    }

    let Some((provenance, pubkey)) = roots.resolve(&body.producer_fpr) else {
        return Err(AttestationFailure::UnknownProducer {
            producer_fpr: body.producer_fpr.clone(),
        });
    };

    let verifying = ed25519_dalek::VerifyingKey::from_bytes(&pubkey)
        .map_err(|e| AttestationFailure::Malformed(format!("bad producer key: {e}")))?;
    let sig = ed25519_dalek::Signature::from_bytes(signature);
    if ed25519_dalek::Verifier::verify(&verifying, &body.signing_bytes(), &sig).is_err() {
        return Err(AttestationFailure::BadSignature);
    }

    // Digests last: only worth hashing once the signature is known good.
    for c in &body.companions {
        let Some(bytes) = companion_bytes(&c.ext, c.key.as_deref()) else {
            return Err(AttestationFailure::MissingCompanion { ext: c.ext.clone() });
        };
        if bytes.len() as u64 != c.bytes {
            return Err(AttestationFailure::DigestMismatch { ext: c.ext.clone() });
        }
        if blake3::hash(&bytes).to_hex().as_str() != c.blake3 {
            return Err(AttestationFailure::DigestMismatch { ext: c.ext.clone() });
        }
    }

    Ok(provenance)
}

/// blake3 of a companion's bytes, lowercase hex — the digest form stored in a body.
pub fn companion_digest(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

// ── on-disk form ────────────────────────────────────────────────────────────
//
// A `.ccxatt` file **is** the signing preimage, with one `sig\t<hex>` line
// appended. Nothing is re-serialised on the way in or out.
//
// That is deliberate. The classic signature bug is a verifier that decodes a
// document, re-encodes it to rebuild the preimage, and disagrees with the signer
// by a space, a key order, or a number format — so a valid signature reads as
// invalid, or worse, two different documents share one preimage. Here the bytes
// that were signed are the bytes on disk, so that class of bug cannot occur.

/// Line prefix carrying the detached signature.
const SIG_PREFIX: &str = "sig\t";

/// Serialise a signed attestation: canonical body, then the signature line.
pub fn encode_attestation(body: &AttestationBody, signature: &[u8; 64]) -> Vec<u8> {
    let mut out = body.signing_bytes();
    out.extend_from_slice(SIG_PREFIX.as_bytes());
    for b in signature {
        out.extend_from_slice(format!("{b:02x}").as_bytes());
    }
    out.push(b'\n');
    out
}

/// Parse a `.ccxatt`, returning the body **and the exact preimage bytes read from
/// disk** alongside the signature.
///
/// The caller verifies against the returned preimage, not against a re-encoding of
/// the body — see the module note above.
pub fn decode_attestation(data: &[u8]) -> std::result::Result<ParsedAttestation, AttestationFailure> {
    let text = std::str::from_utf8(data).map_err(|e| AttestationFailure::Malformed(format!("not utf-8: {e}")))?;
    let sig_at = text
        .rfind(&format!("\n{SIG_PREFIX}"))
        .ok_or_else(|| AttestationFailure::Malformed("no signature line".into()))?;
    // +1 keeps the newline that terminates the last body line inside the preimage.
    let preimage = &text[..=sig_at];
    let sig_hex = text[sig_at + 1 + SIG_PREFIX.len()..].trim();
    if sig_hex.len() != 128 {
        return Err(AttestationFailure::Malformed(format!(
            "signature must be 128 hex chars, got {}",
            sig_hex.len()
        )));
    }
    let mut signature = [0u8; 64];
    for (i, slot) in signature.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&sig_hex[i * 2..i * 2 + 2], 16)
            .map_err(|e| AttestationFailure::Malformed(format!("bad signature hex: {e}")))?;
    }

    let mut lines = preimage.lines();
    let mut next = |field: &str| -> std::result::Result<String, AttestationFailure> {
        lines
            .next()
            .map(str::to_string)
            .ok_or_else(|| AttestationFailure::Malformed(format!("truncated: missing {field}")))
    };
    let schema = next("schema")?;
    let shard_id = next("shard_id")?
        .parse()
        .map_err(|_| AttestationFailure::Malformed("bad shard_id".into()))?;
    let segment_seq = next("segment_seq")?
        .parse()
        .map_err(|_| AttestationFailure::Malformed("bad segment_seq".into()))?;
    let segment_id = next("segment_id")?;
    let tenant_raw = next("tenant_id")?;
    let provenance = next("provenance")?;
    let issued_at = next("issued_at")?
        .parse()
        .map_err(|_| AttestationFailure::Malformed("bad issued_at".into()))?;
    let producer_pubkey = next("producer_pubkey")?;
    let producer_fpr = next("producer_fpr")?;
    let builder_commit = next("builder_commit")?;

    let mut companions = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() != 4 {
            return Err(AttestationFailure::Malformed(format!(
                "companion row needs 4 columns, got {}",
                cols.len()
            )));
        }
        companions.push(CompanionDigest {
            ext: cols[0].to_string(),
            key: (!cols[1].is_empty()).then(|| cols[1].to_string()),
            blake3: cols[2].to_string(),
            bytes: cols[3]
                .parse()
                .map_err(|_| AttestationFailure::Malformed("bad companion size".into()))?,
        });
    }

    Ok(ParsedAttestation {
        body: AttestationBody {
            schema,
            shard_id,
            segment_seq,
            segment_id,
            tenant_id: (!tenant_raw.is_empty()).then_some(tenant_raw),
            provenance,
            issued_at,
            producer_pubkey,
            producer_fpr,
            builder_commit,
            companions,
        },
        signature,
        preimage: preimage.as_bytes().to_vec(),
    })
}

/// A parsed `.ccxatt`: the decoded body, its signature, and the exact bytes that
/// were signed.
#[derive(Debug, Clone)]
pub struct ParsedAttestation {
    pub body: AttestationBody,
    pub signature: [u8; 64],
    /// Bytes as read from disk — what the signature must be checked against.
    pub preimage: Vec<u8>,
}

/// Verify a `.ccxatt` read from disk.
///
/// Two checks the in-memory [`verify_attestation`] cannot make on its own:
///
/// 1. **The signature is checked over the bytes actually on disk**, so a verifier
///    can never disagree with a signer over canonicalisation.
/// 2. **Those bytes must equal how we re-render the parsed body.** Without this a
///    crafted preimage could carry one meaning in its raw bytes and parse to
///    another — signed as A, interpreted as B. Cheap to check, and it closes the
///    gap that verifying-over-the-preimage would otherwise open.
pub fn verify_parsed<F>(
    parsed: &ParsedAttestation,
    roots: &TrustRoots,
    expected_segment_id: &str,
    companion_bytes: F,
) -> std::result::Result<Provenance, AttestationFailure>
where
    F: FnMut(&str, Option<&str>) -> Option<Vec<u8>>,
{
    if parsed.body.signing_bytes() != parsed.preimage {
        return Err(AttestationFailure::Malformed(
            "on-disk bytes do not match the parsed body's canonical form".into(),
        ));
    }
    verify_attestation(
        &parsed.body,
        &parsed.signature,
        roots,
        expected_segment_id,
        companion_bytes,
    )
}

impl From<AttestationFailure> for IndexError {
    fn from(f: AttestationFailure) -> Self {
        IndexError::IntegrityFailure {
            msg: format!("companion attestation: {}", f.reason_code()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn body(segment_id: &str, companions: Vec<CompanionDigest>, producer_fpr: &str, pk: [u8; 32]) -> AttestationBody {
        AttestationBody {
            schema: CCXATT_SCHEMA_V1.to_string(),
            shard_id: 0,
            segment_seq: 7,
            segment_id: segment_id.to_string(),
            tenant_id: Some("tenant-a".to_string()),
            provenance: "platform".to_string(),
            issued_at: 1_786_000_000,
            producer_pubkey: hex(&pk),
            producer_fpr: producer_fpr.to_string(),
            builder_commit: "abc1234".to_string(),
            companions,
        }
    }

    fn hex(b: &[u8]) -> String {
        b.iter().fold(String::new(), |mut acc, x| {
            use std::fmt::Write as _;
            let _ = write!(acc, "{x:02x}");
            acc
        })
    }

    fn digest_of(bytes: &[u8], ext: &str) -> CompanionDigest {
        CompanionDigest {
            ext: ext.to_string(),
            key: None,
            blake3: companion_digest(bytes),
            bytes: bytes.len() as u64,
        }
    }

    #[test]
    fn platform_signed_attestation_verifies() {
        let sk = key(1);
        let vk = sk.verifying_key().to_bytes();
        let payload = b"dense-companion-bytes".to_vec();
        let b = body("seg-abc", vec![digest_of(&payload, "ccxe")], "platform-kid-1", vk);
        let sig = sk.sign(&b.signing_bytes()).to_bytes();
        let roots = TrustRoots::new().with_platform_root("platform-kid-1", vk);

        let got = verify_attestation(&b, &sig, &roots, "seg-abc", |ext, _| {
            (ext == "ccxe").then(|| payload.clone())
        });
        assert_eq!(got, Ok(Provenance::Platform));
    }

    /// A daemon signing its own locally-embedded companion resolves to `Local`, not
    /// `None`. This is what keeps the missing-attestation alarm rare enough to mean
    /// something.
    #[test]
    fn locally_signed_attestation_resolves_to_local_not_none() {
        let sk = key(2);
        let vk = sk.verifying_key().to_bytes();
        let payload = b"locally-embedded".to_vec();
        let mut b = body("seg-local", vec![digest_of(&payload, "ccxe")], "this-device", vk);
        b.provenance = "local".to_string();
        let sig = sk.sign(&b.signing_bytes()).to_bytes();
        let roots = TrustRoots::new().with_local_device("this-device", vk);

        let got = verify_attestation(&b, &sig, &roots, "seg-local", |_, _| Some(payload.clone()));
        assert_eq!(got, Ok(Provenance::Local));
    }

    /// The replay guard: a validly-signed attestation moved next to a different
    /// segment must not authenticate it.
    #[test]
    fn attestation_replayed_onto_another_segment_is_rejected() {
        let sk = key(3);
        let vk = sk.verifying_key().to_bytes();
        let payload = b"bytes".to_vec();
        let b = body("seg-original", vec![digest_of(&payload, "ccxe")], "root", vk);
        let sig = sk.sign(&b.signing_bytes()).to_bytes();
        let roots = TrustRoots::new().with_platform_root("root", vk);

        let got = verify_attestation(&b, &sig, &roots, "seg-DIFFERENT", |_, _| Some(payload.clone()));
        assert!(matches!(got, Err(AttestationFailure::SegmentMismatch { .. })));
    }

    #[test]
    fn tampered_companion_bytes_are_rejected() {
        let sk = key(4);
        let vk = sk.verifying_key().to_bytes();
        let payload = b"original".to_vec();
        let b = body("seg-x", vec![digest_of(&payload, "ccxe")], "root", vk);
        let sig = sk.sign(&b.signing_bytes()).to_bytes();
        let roots = TrustRoots::new().with_platform_root("root", vk);

        let got = verify_attestation(&b, &sig, &roots, "seg-x", |_, _| Some(b"tampered!".to_vec()));
        assert!(matches!(got, Err(AttestationFailure::DigestMismatch { .. })));
    }

    /// Editing the body invalidates the signature even when every digest still
    /// matches — the body is signed, not just the file list.
    #[test]
    fn edited_body_fails_signature_even_with_valid_digests() {
        let sk = key(5);
        let vk = sk.verifying_key().to_bytes();
        let payload = b"bytes".to_vec();
        let b = body("seg-y", vec![digest_of(&payload, "ccxe")], "root", vk);
        let sig = sk.sign(&b.signing_bytes()).to_bytes();

        let mut forged = b.clone();
        forged.tenant_id = Some("tenant-B".to_string()); // cross-tenant re-label attempt
        let roots = TrustRoots::new().with_platform_root("root", vk);

        let got = verify_attestation(&forged, &sig, &roots, "seg-y", |_, _| Some(payload.clone()));
        assert_eq!(got, Err(AttestationFailure::BadSignature));
    }

    #[test]
    fn unknown_producer_is_rejected_not_silently_downgraded() {
        let sk = key(6);
        let vk = sk.verifying_key().to_bytes();
        let payload = b"bytes".to_vec();
        let b = body("seg-z", vec![digest_of(&payload, "ccxe")], "stranger", vk);
        let sig = sk.sign(&b.signing_bytes()).to_bytes();
        let roots = TrustRoots::new().with_platform_root("a-different-root", [9u8; 32]);

        let got = verify_attestation(&b, &sig, &roots, "seg-z", |_, _| Some(payload.clone()));
        assert!(matches!(got, Err(AttestationFailure::UnknownProducer { .. })));
    }

    #[test]
    fn missing_covered_companion_is_reported_distinctly_from_a_bad_digest() {
        let sk = key(7);
        let vk = sk.verifying_key().to_bytes();
        let payload = b"bytes".to_vec();
        let b = body("seg-m", vec![digest_of(&payload, "ccxe")], "root", vk);
        let sig = sk.sign(&b.signing_bytes()).to_bytes();
        let roots = TrustRoots::new().with_platform_root("root", vk);

        let got = verify_attestation(&b, &sig, &roots, "seg-m", |_, _| None);
        assert!(matches!(got, Err(AttestationFailure::MissingCompanion { .. })));
    }

    /// Signing bytes must not depend on the order companions were listed in, or two
    /// honest producers would disagree on the signature for identical content.
    #[test]
    fn signing_bytes_are_order_independent() {
        let a = digest_of(b"one", "ccxe");
        let b2 = digest_of(b"two", "ccxprof");
        let vk = key(8).verifying_key().to_bytes();
        let forward = body("s", vec![a.clone(), b2.clone()], "root", vk);
        let reverse = body("s", vec![b2, a], "root", vk);
        assert_eq!(forward.signing_bytes(), reverse.signing_bytes());
    }

    /// Keyed companions are distinct entries, so a model-B rebuild cannot be passed
    /// off as model-A's vectors.
    #[test]
    fn keyed_companions_are_distinct_in_the_preimage() {
        let vk = key(9).verifying_key().to_bytes();
        let mut a = digest_of(b"vecs", "ccxe");
        a.key = Some("baai-bge-m3".to_string());
        let mut b2 = digest_of(b"vecs", "ccxe");
        b2.key = Some("nomic-embed-text-v1.5".to_string());
        assert_ne!(
            body("s", vec![a], "root", vk).signing_bytes(),
            body("s", vec![b2], "root", vk).signing_bytes()
        );
    }

    // ── on-disk round-trip ────────────────────────────────────────────

    #[test]
    fn encode_decode_round_trips_and_verifies_from_disk_bytes() {
        let sk = key(11);
        let vk = sk.verifying_key().to_bytes();
        let payload = b"companion".to_vec();
        let b = body("seg-rt", vec![digest_of(&payload, "ccxe")], "root", vk);
        let sig = sk.sign(&b.signing_bytes()).to_bytes();

        let encoded = encode_attestation(&b, &sig);
        let parsed = decode_attestation(&encoded).expect("decode");
        assert_eq!(parsed.body, b, "body must survive the round trip");
        assert_eq!(parsed.signature, sig);

        let roots = TrustRoots::new().with_platform_root("root", vk);
        let got = verify_parsed(&parsed, &roots, "seg-rt", |_, _| Some(payload.clone()));
        assert_eq!(got, Ok(Provenance::Platform));
    }

    /// The file IS the preimage — no re-serialisation happens on either side.
    #[test]
    fn the_file_contains_the_signing_preimage_verbatim() {
        let sk = key(12);
        let b = body(
            "seg-p",
            vec![digest_of(b"x", "ccxe")],
            "root",
            sk.verifying_key().to_bytes(),
        );
        let encoded = encode_attestation(&b, &sk.sign(&b.signing_bytes()).to_bytes());
        let parsed = decode_attestation(&encoded).unwrap();
        assert_eq!(parsed.preimage, b.signing_bytes());
    }

    /// A preimage crafted to parse as one thing while having signed another is
    /// rejected, even though its signature is genuine over the bytes on disk.
    #[test]
    fn preimage_that_disagrees_with_its_parsed_body_is_rejected() {
        let sk = key(13);
        let vk = sk.verifying_key().to_bytes();
        let b = body("seg-c", vec![digest_of(b"x", "ccxe")], "root", vk);
        let mut raw = String::from_utf8(b.signing_bytes()).unwrap();
        // A trailing blank line parses away but changes the bytes.
        raw.push('\n');
        let sig = sk.sign(raw.as_bytes()).to_bytes();
        let mut encoded = raw.into_bytes();
        encoded.extend_from_slice(b"sig\t");
        for byte in sig {
            encoded.extend_from_slice(format!("{byte:02x}").as_bytes());
        }
        encoded.push(b'\n');

        let parsed = decode_attestation(&encoded).expect("decodes");
        let roots = TrustRoots::new().with_platform_root("root", vk);
        let got = verify_parsed(&parsed, &roots, "seg-c", |_, _| Some(b"x".to_vec()));
        assert!(
            matches!(got, Err(AttestationFailure::Malformed(_))),
            "signed-as-A parsed-as-B must be refused, got {got:?}"
        );
    }

    #[test]
    fn truncated_or_unsigned_files_are_malformed_not_panics() {
        assert!(decode_attestation(b"").is_err());
        assert!(decode_attestation(b"just some text\n").is_err());
        assert!(decode_attestation(b"schema\nsig\tnothex\n").is_err());
        assert!(decode_attestation(&[0xff, 0xfe, 0xfd]).is_err());
    }

    // ── mode semantics ────────────────────────────────────────────────

    /// Invalid is fatal in EVERY mode, including `Off`. A broken signature is not a
    /// policy question — it is evidence the bytes are not what was signed.
    #[test]
    fn invalid_is_fatal_in_every_mode_including_off() {
        for mode in [AttestationMode::Off, AttestationMode::Warn, AttestationMode::Enforce] {
            assert!(!mode.permits(Provenance::Invalid), "{mode:?} must refuse Invalid");
        }
    }

    #[test]
    fn none_loads_in_warn_and_refuses_in_enforce() {
        assert!(AttestationMode::Warn.permits(Provenance::None));
        assert!(AttestationMode::Off.permits(Provenance::None));
        assert!(!AttestationMode::Enforce.permits(Provenance::None));
    }

    #[test]
    fn verified_states_load_in_every_mode() {
        for mode in [AttestationMode::Off, AttestationMode::Warn, AttestationMode::Enforce] {
            assert!(mode.permits(Provenance::Platform));
            assert!(mode.permits(Provenance::Local));
        }
    }

    /// An unrecognised mode string must not silently disable the check.
    #[test]
    fn unknown_mode_falls_back_to_warn_not_off() {
        assert_eq!(AttestationMode::from_str_or_default("nonsense"), AttestationMode::Warn);
        assert_eq!(AttestationMode::from_str_or_default(""), AttestationMode::Warn);
        assert_eq!(
            AttestationMode::from_str_or_default("ENFORCE"),
            AttestationMode::Enforce
        );
        assert_eq!(AttestationMode::from_str_or_default(" off "), AttestationMode::Off);
        assert_eq!(AttestationMode::default(), AttestationMode::Warn);
    }
}
