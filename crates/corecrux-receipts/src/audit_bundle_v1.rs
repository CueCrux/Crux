// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! BYO Audit Trail bundle (agent-ux-11) — `bundle_format_version: 3`.
//!
//! Bundle layout (tar.zst):
//!
//! ```text
//! audit-bundle.tar.zst
//! ├── manifest.json    # signed Ed25519 over canonical JSON (sig field excluded)
//! ├── events.jsonl     # one fact-event per line, sorted by (stored_at, fact_id)
//! └── receipts.cbor    # CBOR array of {receipt_id, fact_id} cross-references
//! ```
//!
//! Design notes:
//! - **Offline verification is non-negotiable.** The verifier reads the
//!   archive, recomputes the content hashes, recomputes the canonical
//!   manifest digest, and verifies the Ed25519 signature against the
//!   pinned `signer_public_key_b64` embedded in the manifest. No network,
//!   no daemon, no key fetch.
//! - **Stable, pinnable issuer**: the manifest embeds both the Ed25519 public
//!   key and its signed provisioning class. Key resolution is shared by daemon
//!   and CLI through `resolve_audit_export_signing_key`.
//! - **Schema-versioned**: `bundle_format_version: 3` — v3 adds the signed
//!   audit-export signing-key class. The verifier still accepts legacy v1
//!   bundles (struct-order JSON, no domain tag) and v2 bundles (domain-separated,
//!   key-canonical JSON); it rejects any other version.

use std::io::{Read, Write};

use base64::Engine as _;
use ciborium::{de::from_reader as cbor_from_reader, ser::into_writer as cbor_into_writer};
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::witness_v1::{
    verify_rekor_checkpoint, verify_witness_binding_v1, verify_witness_proof_v1, WitnessLogPublicKeyV1, WitnessProofV1,
};

/// Legacy bundle format (v1): the signing input was struct-declaration-order
/// JSON with no domain-separation tag. Still accepted by the verifier so
/// bundles exported before the v2 canonicalisation continue to verify.
pub const BUNDLE_FORMAT_V1: u32 = 1;

/// Previous bundle format (v2): domain-separated, key-canonical manifest
/// signing, before the signed `key_class` marker was introduced.
pub const BUNDLE_FORMAT_V2: u32 = 2;

/// Current schema/signing version. v3 adds a signed marker describing whether
/// the embedded issuer public key came from an environment override, a
/// data-dir-persistent key, or an ephemeral fallback.
pub const BUNDLE_FORMAT_VERSION: u32 = 3;

/// Domain-separation tag prefixed to the legacy v2 signing input, mirroring the
/// `crypto_shred_v1` convention (`b"cuecrux.crypto_shred..."`). Binding the
/// signature to this per-type, per-version label prevents a signature over an
/// audit-bundle manifest from ever verifying as a different receipt type, and
/// vice-versa.
pub const AUDIT_BUNDLE_SIGNING_DOMAIN_V2: &[u8] = b"cuecrux.audit_bundle.v2\0";

/// Domain-separation tag for newly emitted v3 bundles.
pub const AUDIT_BUNDLE_SIGNING_DOMAIN: &[u8] = b"cuecrux.audit_bundle.v3\0";

/// Hard cap on the decompressed size the verifier will materialise from a
/// `tar.zst` bundle (256 MiB). A bundle that expands beyond this is rejected
/// before the oversized buffer is allocated, bounding the zstd
/// decompression-bomb / OOM surface if the offline verifier is ever fed
/// caller-supplied bytes (e.g. a future "upload a bundle to verify" endpoint).
pub const MAX_DECOMPRESSED_BUNDLE_BYTES: u64 = 256 * 1024 * 1024;

/// File-name constants — third-party tooling can `tar -tf` and look for these.
pub const MANIFEST_FILENAME: &str = "manifest.json";
pub const EVENTS_FILENAME: &str = "events.jsonl";
pub const RECEIPTS_FILENAME: &str = "receipts.cbor";
/// Optional member: one `WitnessProofV1` per line. Absent (and its manifest
/// fields skipped) when no seal-chain heads were witnessed in the export
/// window, so witness-free bundles stay byte-identical to pre-witness v1.
pub const WITNESS_FILENAME: &str = "witness_proofs.jsonl";

fn is_zero_u64(n: &u64) -> bool {
    *n == 0
}

#[derive(Debug, Error)]
pub enum AuditBundleError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("cbor error: {0}")]
    Cbor(String),
    #[error("ed25519 error: {0}")]
    Signature(#[from] ed25519_dalek::SignatureError),
    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error(
        "unsupported bundle_format_version: {0} (verifier supports {BUNDLE_FORMAT_V1}, {BUNDLE_FORMAT_V2}, and {BUNDLE_FORMAT_VERSION})"
    )]
    UnsupportedVersion(u32),
    #[error("decompressed bundle exceeds the {MAX_DECOMPRESSED_BUNDLE_BYTES}-byte cap")]
    DecompressedTooLarge,
    #[error("manifest missing required field: {0}")]
    MissingField(&'static str),
    #[error("content hash mismatch for {file}: expected {expected}, got {actual}")]
    ContentHashMismatch {
        file: String,
        expected: String,
        actual: String,
    },
    #[error("manifest signature invalid")]
    SignatureInvalid,
    #[error("bundle is missing required member: {0}")]
    MissingMember(&'static str),
    #[error("invalid public key length: expected 32 bytes, got {0}")]
    InvalidPubKeyLen(usize),
    #[error("invalid signature length: expected 64 bytes, got {0}")]
    InvalidSigLen(usize),
}

/// A single fact-event in the exported bundle. Mirrors the shape returned
/// by `FactStore.all_facts()` so a third party can replay or join against
/// the per-topic timeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEventV1 {
    pub fact_id: String,
    pub entity: String,
    pub key: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_receipt: Option<String>,
    pub confidence: f32,
    /// RFC3339 timestamp.
    pub stored_at: String,
    pub tokens: usize,
    pub deleted: bool,
    pub version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supersedes: Option<String>,
}

/// CBOR-encoded cross-reference between each fact-event and its source
/// receipt id. We do not include the receipt body inline here — the bundle
/// surfaces *what receipt is referenced* in the export window. Operator-tier
/// deployments with the v3 dataplane can join this list against their
/// `receipts/` directory to assemble the full proof tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReceiptRefV1 {
    pub fact_id: String,
    pub receipt_id: String,
}

/// Scope filter applied at export time. Recorded in the manifest so
/// verifiers (and auditors) can reproduce the slice.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuditBundleScopeV1 {
    /// If set, only entities matching this prefix were included.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity_prefix: Option<String>,
    /// True iff reserved-prefix entries (`__agent::*`, `__ops::*`,
    /// `__bootstrap__::*`) were included (operator-tier export).
    pub include_reserved: bool,
    /// Free-form caller label (passport id or operator note).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caller: Option<String>,
}

/// Provenance class for the key that signed an audit bundle.
///
/// This is assurance metadata, not a verification shortcut: offline
/// verification always uses the public key embedded in the signed manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditBundleKeyClassV1 {
    /// Key loaded from `CORECRUXD_AUDIT_EXPORT_SIGNING_KEY_B64`.
    Env,
    /// Stable key generated once and stored in the daemon data directory.
    Persistent,
    /// One-shot key used only when no data directory is available.
    Ephemeral,
}

/// The signed manifest. Canonical-JSON of this struct WITH `signature_b64`
/// cleared is the input to Ed25519 sign/verify.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditBundleManifestV1 {
    pub bundle_format_version: u32,
    pub bundle_id: String,
    /// RFC3339, inclusive.
    pub since: String,
    /// RFC3339, exclusive. Set even when the caller didn't pass an upper
    /// bound — we record the export wall-clock so the audit trail is
    /// reproducible.
    pub until: String,
    pub generated_at: String,
    pub scope: AuditBundleScopeV1,
    pub fact_count: u64,
    pub receipt_count: u64,
    pub events_jsonl_sha256: String,
    pub receipts_cbor_sha256: String,
    /// Number of witness inclusion-proofs carried in `witness_proofs.jsonl`.
    /// Skipped (member omitted) when zero, keeping witness-free bundles
    /// byte-identical to format-v1 bundles that predate witnessing.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub witness_proof_count: u64,
    /// SHA-256 of `witness_proofs.jsonl`, lowercase hex. `None` when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witness_proofs_sha256: Option<String>,
    /// Base64 (standard, padded) Ed25519 public key — 32 bytes.
    pub signer_public_key_b64: String,
    /// Free-form key identifier. Default empty; not load-bearing for
    /// verification (the public key is what matters).
    pub signer_key_id: String,
    /// How the signer key was provisioned. Absent only on legacy v1/v2
    /// bundles created before this signed provenance marker existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_class: Option<AuditBundleKeyClassV1>,
    /// Base64 (standard, padded) Ed25519 signature — 64 bytes. Empty
    /// during signing input construction.
    #[serde(default)]
    pub signature_b64: String,
}

impl AuditBundleManifestV1 {
    /// Bytes used as the Ed25519 sign/verify input, with `signature_b64`
    /// cleared. The encoding is selected by `bundle_format_version` so old and
    /// new bundles both verify:
    ///
    /// - **v3** (current): `AUDIT_BUNDLE_SIGNING_DOMAIN` followed by a
    ///   key-canonical JSON encoding of the manifest.
    /// - **v2**: `AUDIT_BUNDLE_SIGNING_DOMAIN_V2` followed by a
    ///   key-canonical JSON encoding of the manifest (`canonical_json_bytes`).
    ///   The domain tag gives per-type/per-version separation (no cross-type
    ///   replay); the recursive key sort makes the signed bytes independent of
    ///   struct field order — necessary because `serde_json` is built with
    ///   `preserve_order`, so a plain serialize is declaration-ordered, not
    ///   canonical.
    /// - **v1** (legacy): plain `serde_json::to_vec`, struct-declaration order,
    ///   no domain tag — reproduced verbatim so bundles signed before v2 still
    ///   verify.
    pub fn canonical_signing_bytes(&self) -> Result<Vec<u8>, AuditBundleError> {
        let mut clone = self.clone();
        clone.signature_b64.clear();
        if self.bundle_format_version >= BUNDLE_FORMAT_VERSION {
            let value = serde_json::to_value(&clone)?;
            let canonical = canonical_json_bytes(&value)?;
            let mut bytes = Vec::with_capacity(AUDIT_BUNDLE_SIGNING_DOMAIN.len() + canonical.len());
            bytes.extend_from_slice(AUDIT_BUNDLE_SIGNING_DOMAIN);
            bytes.extend_from_slice(&canonical);
            Ok(bytes)
        } else if self.bundle_format_version == BUNDLE_FORMAT_V2 {
            let value = serde_json::to_value(&clone)?;
            let canonical = canonical_json_bytes(&value)?;
            let mut bytes = Vec::with_capacity(AUDIT_BUNDLE_SIGNING_DOMAIN_V2.len() + canonical.len());
            bytes.extend_from_slice(AUDIT_BUNDLE_SIGNING_DOMAIN_V2);
            bytes.extend_from_slice(&canonical);
            Ok(bytes)
        } else {
            Ok(serde_json::to_vec(&clone)?)
        }
    }
}

/// Serialise a JSON value with object keys sorted recursively, so the bytes are
/// independent of field/insertion order. `serde_json` runs with `preserve_order`
/// workspace-wide (its `Map` is insertion-ordered), so this explicit sort is
/// what makes the v2 signing input canonical. Array order is preserved (it is
/// semantically significant). This is sufficient canonicalisation for a single
/// Rust signer + verifier; it is intentionally not a full RFC 8785 JCS (number
/// and string re-canonicalisation) as no cross-implementation verifier exists.
fn canonical_json_bytes(value: &serde_json::Value) -> Result<Vec<u8>, serde_json::Error> {
    fn canonicalise(value: &serde_json::Value) -> serde_json::Value {
        match value {
            serde_json::Value::Object(map) => {
                let mut entries: Vec<(&String, &serde_json::Value)> = map.iter().collect();
                entries.sort_by(|a, b| a.0.cmp(b.0));
                let mut sorted = serde_json::Map::new();
                for (key, child) in entries {
                    sorted.insert(key.clone(), canonicalise(child));
                }
                serde_json::Value::Object(sorted)
            }
            serde_json::Value::Array(items) => serde_json::Value::Array(items.iter().map(canonicalise).collect()),
            other => other.clone(),
        }
    }
    serde_json::to_vec(&canonicalise(value))
}

/// Inputs to `build_bundle_v1`. Caller provides the filtered + sorted
/// event list and the signing key; this function does the framing.
pub struct BuildBundleInputV1<'a> {
    pub bundle_id: String,
    pub since_rfc3339: String,
    pub until_rfc3339: String,
    pub generated_at_rfc3339: String,
    pub scope: AuditBundleScopeV1,
    pub events: Vec<AuditEventV1>,
    pub receipt_refs: Vec<AuditReceiptRefV1>,
    /// Witness inclusion-proofs for seal-chain heads anchored in the export
    /// window. Empty in the free/local tier (no member written).
    pub witness_proofs: Vec<WitnessProofV1>,
    pub signing_key: &'a SigningKey,
    pub signer_key_id: String,
    pub key_class: AuditBundleKeyClassV1,
}

/// Built bundle, ready to be written to disk.
pub struct BuiltBundleV1 {
    pub manifest: AuditBundleManifestV1,
    pub manifest_json: Vec<u8>,
    pub events_jsonl: Vec<u8>,
    pub receipts_cbor: Vec<u8>,
    pub witness_proofs_jsonl: Vec<u8>,
}

impl BuiltBundleV1 {
    /// Write the bundle as `tar.zst` to the given writer.
    pub fn write_tar_zst<W: Write>(&self, writer: W) -> Result<(), AuditBundleError> {
        let zstd_encoder = zstd::stream::write::Encoder::new(writer, 3)
            .map_err(AuditBundleError::Io)?
            .auto_finish();
        let mut tar_builder = tar::Builder::new(zstd_encoder);

        write_tar_entry(&mut tar_builder, MANIFEST_FILENAME, &self.manifest_json)?;
        write_tar_entry(&mut tar_builder, EVENTS_FILENAME, &self.events_jsonl)?;
        write_tar_entry(&mut tar_builder, RECEIPTS_FILENAME, &self.receipts_cbor)?;
        if !self.witness_proofs_jsonl.is_empty() {
            write_tar_entry(&mut tar_builder, WITNESS_FILENAME, &self.witness_proofs_jsonl)?;
        }

        tar_builder.finish()?;
        Ok(())
    }
}

fn write_tar_entry<W: Write>(builder: &mut tar::Builder<W>, path: &str, bytes: &[u8]) -> Result<(), AuditBundleError> {
    let mut header = tar::Header::new_gnu();
    header.set_path(path)?;
    header.set_size(bytes.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder.append(&header, bytes)?;
    Ok(())
}

/// Build (frame + sign) a bundle. Does NOT write to disk — the caller
/// chooses how to persist (file, in-memory buffer for HTTP streaming, etc).
pub fn build_bundle_v1(input: BuildBundleInputV1<'_>) -> Result<BuiltBundleV1, AuditBundleError> {
    let mut events_jsonl: Vec<u8> = Vec::new();
    for ev in &input.events {
        serde_json::to_writer(&mut events_jsonl, ev)?;
        events_jsonl.push(b'\n');
    }

    let mut receipts_cbor: Vec<u8> = Vec::new();
    cbor_into_writer(&input.receipt_refs, &mut receipts_cbor).map_err(|e| AuditBundleError::Cbor(e.to_string()))?;

    let mut witness_proofs_jsonl: Vec<u8> = Vec::new();
    for proof in &input.witness_proofs {
        serde_json::to_writer(&mut witness_proofs_jsonl, proof)?;
        witness_proofs_jsonl.push(b'\n');
    }

    let events_hash = hex_sha256(&events_jsonl);
    let receipts_hash = hex_sha256(&receipts_cbor);
    let (witness_proof_count, witness_proofs_sha256) = if input.witness_proofs.is_empty() {
        (0, None)
    } else {
        (
            input.witness_proofs.len() as u64,
            Some(hex_sha256(&witness_proofs_jsonl)),
        )
    };

    let verifying: VerifyingKey = input.signing_key.verifying_key();
    let signer_public_key_b64 = base64::engine::general_purpose::STANDARD.encode(verifying.to_bytes());

    let mut manifest = AuditBundleManifestV1 {
        bundle_format_version: BUNDLE_FORMAT_VERSION,
        bundle_id: input.bundle_id,
        since: input.since_rfc3339,
        until: input.until_rfc3339,
        generated_at: input.generated_at_rfc3339,
        scope: input.scope,
        fact_count: input.events.len() as u64,
        receipt_count: input.receipt_refs.len() as u64,
        events_jsonl_sha256: events_hash,
        receipts_cbor_sha256: receipts_hash,
        witness_proof_count,
        witness_proofs_sha256,
        signer_public_key_b64,
        signer_key_id: input.signer_key_id,
        key_class: Some(input.key_class),
        signature_b64: String::new(),
    };

    let signing_bytes = manifest.canonical_signing_bytes()?;
    let sig = input.signing_key.sign(&signing_bytes).to_bytes();
    manifest.signature_b64 = base64::engine::general_purpose::STANDARD.encode(sig);

    let manifest_json = serde_json::to_vec_pretty(&manifest)?;

    Ok(BuiltBundleV1 {
        manifest,
        manifest_json,
        events_jsonl,
        receipts_cbor,
        witness_proofs_jsonl,
    })
}

/// Result of a verifier run. `ok=true` only when every check passes.
#[derive(Debug, Clone, Serialize)]
pub struct VerifyReportV1 {
    pub ok: bool,
    pub bundle_format_version: u32,
    pub bundle_id: String,
    pub fact_count: u64,
    pub receipt_count: u64,
    pub events_jsonl_sha256_match: bool,
    pub receipts_cbor_sha256_match: bool,
    pub signature_valid: bool,
    /// Number of witness inclusion-proofs the manifest commits to.
    pub witness_proof_count: u64,
    /// Whether `witness_proofs.jsonl` matches the manifest SHA-256 (true when
    /// there are no witness proofs).
    pub witness_proofs_sha256_match: bool,
    /// Whether every embedded witness proof re-verified (RFC6962). True when
    /// there are no witness proofs.
    pub witness_proofs_valid: bool,
    /// Whether every witness root was endorsed by the pinned log key
    /// (checkpoint/SET verified). `None` when no trust root was supplied — in
    /// that mode inclusion is checked but root endorsement is not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness_root_endorsed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
}

/// Streaming zstd decode with a hard cap on the decompressed size. Reads
/// through a `zstd::Decoder` into a buffer that can grow to at most
/// `max_bytes + 1`, then rejects if the stream is over the cap — so a
/// decompression bomb can never allocate an unbounded buffer. Replaces the
/// unbounded `zstd::stream::decode_all`.
fn decode_all_bounded(compressed: &[u8], max_bytes: u64) -> Result<Vec<u8>, AuditBundleError> {
    use std::io::Read as _;
    // `take(max_bytes + 1)`: if that last byte is readable, the decompressed
    // stream is over the cap. `saturating_add` guards the (theoretical) overflow.
    let mut limited = zstd::stream::read::Decoder::new(compressed)?.take(max_bytes.saturating_add(1));
    let mut decoded = Vec::new();
    limited.read_to_end(&mut decoded)?;
    if decoded.len() as u64 > max_bytes {
        return Err(AuditBundleError::DecompressedTooLarge);
    }
    Ok(decoded)
}

/// Verify a `tar.zst` bundle from raw bytes. OFFLINE — does not touch the
/// network or any daemon. The verifier:
///
/// 1. Decompresses zstd, walks the tar archive, pulls the three members.
/// 2. Re-parses `manifest.json`, rejects unknown `bundle_format_version`.
/// 3. Recomputes BLAKE3-flavoured SHA-256 over `events.jsonl` and
///    `receipts.cbor`, compares to manifest digests.
/// 4. Reconstructs the canonical sign-input (manifest with empty
///    `signature_b64`), recomputes Ed25519 verification against the
///    manifest's pinned `signer_public_key_b64`.
///
/// Any failure short-circuits with `ok=false` and a populated
/// `failure_reason`.
pub fn verify_bundle_v1(tar_zst_bytes: &[u8]) -> Result<VerifyReportV1, AuditBundleError> {
    verify_bundle_with_trust_roots_v1(tar_zst_bytes, None)
}

/// Like [`verify_bundle_v1`], but when `log_key` is supplied it also verifies
/// each witness proof's Rekor checkpoint/SET against that pinned log key
/// (Ed25519 for self-hosted logs, ECDSA P-256 for public-good Rekor) — proving
/// the tree root is the one the log operator signed (the trust root), not merely
/// internally consistent. Without a key, root endorsement is `None` (not checked).
pub fn verify_bundle_with_trust_roots_v1(
    tar_zst_bytes: &[u8],
    log_key: Option<&WitnessLogPublicKeyV1>,
) -> Result<VerifyReportV1, AuditBundleError> {
    let decoded = decode_all_bounded(tar_zst_bytes, MAX_DECOMPRESSED_BUNDLE_BYTES)?;
    let mut archive = tar::Archive::new(decoded.as_slice());

    let mut manifest_bytes: Option<Vec<u8>> = None;
    let mut events_bytes: Option<Vec<u8>> = None;
    let mut receipts_bytes: Option<Vec<u8>> = None;
    let mut witness_bytes: Option<Vec<u8>> = None;

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.to_path_buf();
        let path_str = path.to_string_lossy().to_string();
        let mut buf = Vec::with_capacity(entry.size() as usize);
        entry.read_to_end(&mut buf)?;
        match path_str.as_str() {
            MANIFEST_FILENAME => manifest_bytes = Some(buf),
            EVENTS_FILENAME => events_bytes = Some(buf),
            RECEIPTS_FILENAME => receipts_bytes = Some(buf),
            WITNESS_FILENAME => witness_bytes = Some(buf),
            _ => { /* ignore unknown members — forward-compat */ }
        }
    }

    let manifest_raw = manifest_bytes.ok_or(AuditBundleError::MissingMember(MANIFEST_FILENAME))?;
    let events = events_bytes.ok_or(AuditBundleError::MissingMember(EVENTS_FILENAME))?;
    let receipts = receipts_bytes.ok_or(AuditBundleError::MissingMember(RECEIPTS_FILENAME))?;

    let manifest: AuditBundleManifestV1 = serde_json::from_slice(&manifest_raw)?;
    if !matches!(
        manifest.bundle_format_version,
        BUNDLE_FORMAT_V1 | BUNDLE_FORMAT_V2 | BUNDLE_FORMAT_VERSION
    ) {
        return Err(AuditBundleError::UnsupportedVersion(manifest.bundle_format_version));
    }
    if manifest.bundle_format_version == BUNDLE_FORMAT_VERSION && manifest.key_class.is_none() {
        return Err(AuditBundleError::MissingField("key_class"));
    }

    let events_hash = hex_sha256(&events);
    let receipts_hash = hex_sha256(&receipts);
    let events_match = events_hash == manifest.events_jsonl_sha256;
    let receipts_match = receipts_hash == manifest.receipts_cbor_sha256;

    if !events_match {
        return Ok(VerifyReportV1 {
            ok: false,
            bundle_format_version: manifest.bundle_format_version,
            bundle_id: manifest.bundle_id,
            fact_count: manifest.fact_count,
            receipt_count: manifest.receipt_count,
            events_jsonl_sha256_match: false,
            receipts_cbor_sha256_match: receipts_match,
            signature_valid: false,
            witness_proof_count: manifest.witness_proof_count,
            witness_proofs_sha256_match: false,
            witness_proofs_valid: false,
            witness_root_endorsed: None,
            failure_reason: Some(format!(
                "{EVENTS_FILENAME} sha256 mismatch: expected {}, got {}",
                manifest.events_jsonl_sha256, events_hash
            )),
        });
    }
    if !receipts_match {
        return Ok(VerifyReportV1 {
            ok: false,
            bundle_format_version: manifest.bundle_format_version,
            bundle_id: manifest.bundle_id,
            fact_count: manifest.fact_count,
            receipt_count: manifest.receipt_count,
            events_jsonl_sha256_match: true,
            receipts_cbor_sha256_match: false,
            signature_valid: false,
            witness_proof_count: manifest.witness_proof_count,
            witness_proofs_sha256_match: false,
            witness_proofs_valid: false,
            witness_root_endorsed: None,
            failure_reason: Some(format!(
                "{RECEIPTS_FILENAME} sha256 mismatch: expected {}, got {}",
                manifest.receipts_cbor_sha256, receipts_hash
            )),
        });
    }

    let pubkey_bytes = base64::engine::general_purpose::STANDARD.decode(&manifest.signer_public_key_b64)?;
    if pubkey_bytes.len() != 32 {
        return Err(AuditBundleError::InvalidPubKeyLen(pubkey_bytes.len()));
    }
    let mut pubkey_arr = [0u8; 32];
    pubkey_arr.copy_from_slice(&pubkey_bytes);
    let verifying = VerifyingKey::from_bytes(&pubkey_arr)?;

    let sig_bytes = base64::engine::general_purpose::STANDARD.decode(&manifest.signature_b64)?;
    if sig_bytes.len() != 64 {
        return Err(AuditBundleError::InvalidSigLen(sig_bytes.len()));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);

    let signing_bytes = manifest.canonical_signing_bytes()?;
    let sig_ok = verifying.verify_strict(&signing_bytes, &signature).is_ok();
    if !sig_ok {
        return Ok(VerifyReportV1 {
            ok: false,
            bundle_format_version: manifest.bundle_format_version,
            bundle_id: manifest.bundle_id,
            fact_count: manifest.fact_count,
            receipt_count: manifest.receipt_count,
            events_jsonl_sha256_match: true,
            receipts_cbor_sha256_match: true,
            signature_valid: false,
            witness_proof_count: manifest.witness_proof_count,
            witness_proofs_sha256_match: false,
            witness_proofs_valid: false,
            witness_root_endorsed: None,
            failure_reason: Some("manifest signature failed Ed25519 verification".to_string()),
        });
    }

    // Manifest is authentic — now re-check the witness inclusion-proofs it
    // commits to. A stripped, mutated, or non-verifying proof fails the bundle.
    let (witness_sha_match, witness_valid, witness_endorsed, witness_failure) =
        verify_witness_member(&manifest, witness_bytes.as_deref(), log_key);

    Ok(VerifyReportV1 {
        ok: witness_sha_match && witness_valid && witness_endorsed.unwrap_or(true),
        bundle_format_version: manifest.bundle_format_version,
        bundle_id: manifest.bundle_id,
        fact_count: manifest.fact_count,
        receipt_count: manifest.receipt_count,
        events_jsonl_sha256_match: true,
        receipts_cbor_sha256_match: true,
        signature_valid: true,
        witness_proof_count: manifest.witness_proof_count,
        witness_proofs_sha256_match: witness_sha_match,
        witness_proofs_valid: witness_valid,
        witness_root_endorsed: witness_endorsed,
        failure_reason: witness_failure,
    })
}

/// Re-check the optional `witness_proofs.jsonl` member against the (already
/// signature-verified) manifest. Returns `(sha_match, all_proofs_valid,
/// failure_reason)`. Because the manifest is signed and carries the proof count
/// and the member SHA-256, a stripped or mutated member is detectable here
/// without trusting the daemon.
fn verify_witness_member(
    manifest: &AuditBundleManifestV1,
    witness_bytes: Option<&[u8]>,
    log_key: Option<&WitnessLogPublicKeyV1>,
) -> (bool, bool, Option<bool>, Option<String>) {
    match (manifest.witness_proof_count, witness_bytes) {
        (0, None) => (true, true, None, None),
        (0, Some(bytes)) => {
            if bytes.is_empty() {
                (true, true, None, None)
            } else {
                (
                    false,
                    false,
                    None,
                    Some("witness_proofs.jsonl present but the signed manifest declares none".to_string()),
                )
            }
        }
        (count, None) => (
            false,
            false,
            None,
            Some(format!(
                "manifest declares {count} witness proof(s) but witness_proofs.jsonl is missing"
            )),
        ),
        (count, Some(bytes)) => {
            let sha = hex_sha256(bytes);
            if manifest.witness_proofs_sha256.as_deref() != Some(sha.as_str()) {
                return (false, false, None, Some(format!("{WITNESS_FILENAME} sha256 mismatch")));
            }
            let mut parsed: u64 = 0;
            for (i, line) in bytes.split(|b| *b == b'\n').enumerate() {
                if line.is_empty() {
                    continue;
                }
                let proof: WitnessProofV1 = match serde_json::from_slice(line) {
                    Ok(proof) => proof,
                    Err(err) => {
                        return (
                            true,
                            false,
                            None,
                            Some(format!("witness proof on line {i} is malformed: {err}")),
                        )
                    }
                };
                if !verify_witness_proof_v1(&proof) {
                    return (
                        true,
                        false,
                        None,
                        Some(format!(
                            "witness proof {i} (leaf {}) failed RFC6962 verification",
                            proof.leaf_hash
                        )),
                    );
                }
                if !verify_witness_binding_v1(&proof) {
                    return (
                        true,
                        false,
                        None,
                        Some(format!(
                            "witness proof {i} (head {}) is not bound to its log entry",
                            proof.head_hash
                        )),
                    );
                }
                if let Some(key) = log_key {
                    let endorsed = proof
                        .checkpoint
                        .as_deref()
                        .is_some_and(|cp| verify_rekor_checkpoint(cp, key, &proof.root_hash));
                    if !endorsed {
                        return (
                            true,
                            true,
                            Some(false),
                            Some(format!(
                                "witness proof {i} root not endorsed by the pinned log key (checkpoint/SET)"
                            )),
                        );
                    }
                }
                parsed += 1;
            }
            if parsed != count {
                return (
                    true,
                    false,
                    None,
                    Some(format!(
                        "witness proof count mismatch: manifest {count}, member {parsed}"
                    )),
                );
            }
            (true, true, log_key.map(|_| true), None)
        }
    }
}

/// SHA-256 over bytes, returned as lower-case hex.
fn hex_sha256(bytes: &[u8]) -> String {
    // We don't depend on the `sha2` crate in this crate, so reach for
    // BLAKE3-compat hex via a small helper that uses the standard-library
    // `crc`? No — use a tiny embedded SHA-256 via the existing `blake3`
    // *signature* of "stable content hash" pattern in this codebase. The
    // master plan asks for `events_jsonl_sha256` *by name* so we want
    // genuine SHA-256, not BLAKE3.
    //
    // `ed25519-dalek` pulls in `sha2` transitively; we just use it
    // directly (no extra Cargo entry needed).
    use sha2::{Digest as _, Sha256};
    let digest = Sha256::digest(bytes);
    let mut s = String::with_capacity(64);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for b in digest {
        s.push(char::from(HEX[usize::from(b >> 4)]));
        s.push(char::from(HEX[usize::from(b & 0x0f)]));
    }
    s
}

/// CBOR helper for unit-testing — decode a `receipts.cbor` blob back to
/// the typed Vec. Public so the verifier binary can pretty-print.
pub fn decode_receipts_cbor(bytes: &[u8]) -> Result<Vec<AuditReceiptRefV1>, AuditBundleError> {
    cbor_from_reader::<Vec<AuditReceiptRefV1>, _>(bytes).map_err(|e| AuditBundleError::Cbor(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn sample_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[0x42; 32])
    }

    fn sample_input() -> BuildBundleInputV1<'static> {
        // Leaks key as 'static — fine for tests.
        let sk: &'static SigningKey = Box::leak(Box::new(sample_signing_key()));
        BuildBundleInputV1 {
            bundle_id: "bundle-test-001".to_string(),
            since_rfc3339: "2026-05-27T00:00:00Z".to_string(),
            until_rfc3339: "2026-05-28T00:00:00Z".to_string(),
            generated_at_rfc3339: "2026-05-28T01:00:00Z".to_string(),
            scope: AuditBundleScopeV1 {
                entity_prefix: None,
                include_reserved: false,
                caller: Some("test-passport".to_string()),
            },
            events: vec![
                AuditEventV1 {
                    fact_id: "f_001".to_string(),
                    entity: "project-x".to_string(),
                    key: "status".to_string(),
                    value: "shipped".to_string(),
                    source_receipt: Some("r_abc".to_string()),
                    confidence: 1.0,
                    stored_at: "2026-05-27T12:00:00Z".to_string(),
                    tokens: 1,
                    deleted: false,
                    version: 1,
                    supersedes: None,
                },
                AuditEventV1 {
                    fact_id: "f_002".to_string(),
                    entity: "project-y".to_string(),
                    key: "owner".to_string(),
                    value: "alice".to_string(),
                    source_receipt: None,
                    confidence: 0.9,
                    stored_at: "2026-05-27T13:00:00Z".to_string(),
                    tokens: 1,
                    deleted: false,
                    version: 1,
                    supersedes: None,
                },
            ],
            receipt_refs: vec![AuditReceiptRefV1 {
                fact_id: "f_001".to_string(),
                receipt_id: "r_abc".to_string(),
            }],
            witness_proofs: vec![],
            signing_key: sk,
            signer_key_id: "test-key-1".to_string(),
            key_class: AuditBundleKeyClassV1::Persistent,
        }
    }

    #[test]
    fn build_and_verify_roundtrip() {
        let built = build_bundle_v1(sample_input()).expect("build");
        assert_eq!(built.manifest.bundle_format_version, BUNDLE_FORMAT_VERSION);
        assert_eq!(built.manifest.fact_count, 2);
        assert_eq!(built.manifest.receipt_count, 1);
        assert_eq!(built.manifest.key_class, Some(AuditBundleKeyClassV1::Persistent));

        let mut tar_bytes = Vec::new();
        built.write_tar_zst(&mut tar_bytes).unwrap();
        assert!(!tar_bytes.is_empty());

        let report = verify_bundle_v1(&tar_bytes).expect("verify");
        assert!(report.ok, "verifier rejected freshly-built bundle: {report:?}");
        assert_eq!(report.fact_count, 2);
        assert_eq!(report.receipt_count, 1);
        assert!(report.events_jsonl_sha256_match);
        assert!(report.receipts_cbor_sha256_match);
        assert!(report.signature_valid);
    }

    #[test]
    fn tamper_with_events_jsonl_breaks_content_hash() {
        let built = build_bundle_v1(sample_input()).expect("build");

        // Hand-roll a tampered tar.zst by mutating events.jsonl before
        // framing. This simulates a third party flipping a byte in the
        // archive — the verifier MUST detect it via the manifest's
        // stored sha256.
        let mut tampered_events = built.events_jsonl.clone();
        // Flip one byte (the very first character — guaranteed to change
        // the SHA-256 digest).
        tampered_events[0] = tampered_events[0].wrapping_add(1);

        let mut tar_bytes: Vec<u8> = Vec::new();
        {
            let zstd_enc = zstd::stream::write::Encoder::new(&mut tar_bytes, 3)
                .unwrap()
                .auto_finish();
            let mut builder = tar::Builder::new(zstd_enc);
            write_tar_entry(&mut builder, MANIFEST_FILENAME, &built.manifest_json).unwrap();
            write_tar_entry(&mut builder, EVENTS_FILENAME, &tampered_events).unwrap();
            write_tar_entry(&mut builder, RECEIPTS_FILENAME, &built.receipts_cbor).unwrap();
            builder.finish().unwrap();
        }

        let report = verify_bundle_v1(&tar_bytes).expect("verify");
        assert!(!report.ok, "tampered events.jsonl should fail verification");
        assert!(!report.events_jsonl_sha256_match);
        assert!(report.failure_reason.unwrap().contains("events.jsonl"));
    }

    #[test]
    fn tamper_with_signature_breaks_verification() {
        let built = build_bundle_v1(sample_input()).expect("build");

        // Flip a byte in the manifest's signature — re-encode the manifest
        // and re-frame the bundle.
        let mut manifest = built.manifest.clone();
        // Decode the sig, flip a byte, re-encode.
        let mut sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(&manifest.signature_b64)
            .unwrap();
        sig_bytes[0] = sig_bytes[0].wrapping_add(1);
        manifest.signature_b64 = base64::engine::general_purpose::STANDARD.encode(&sig_bytes);
        let tampered_manifest = serde_json::to_vec_pretty(&manifest).unwrap();

        let mut tar_bytes: Vec<u8> = Vec::new();
        {
            let zstd_enc = zstd::stream::write::Encoder::new(&mut tar_bytes, 3)
                .unwrap()
                .auto_finish();
            let mut builder = tar::Builder::new(zstd_enc);
            write_tar_entry(&mut builder, MANIFEST_FILENAME, &tampered_manifest).unwrap();
            write_tar_entry(&mut builder, EVENTS_FILENAME, &built.events_jsonl).unwrap();
            write_tar_entry(&mut builder, RECEIPTS_FILENAME, &built.receipts_cbor).unwrap();
            builder.finish().unwrap();
        }

        let report = verify_bundle_v1(&tar_bytes).expect("verify");
        assert!(!report.ok, "tampered signature should fail verification");
        assert!(!report.signature_valid);
        assert!(report.failure_reason.unwrap().contains("signature"));
    }

    #[test]
    fn tamper_with_key_class_breaks_manifest_signature() {
        let built = build_bundle_v1(sample_input()).expect("build");
        let mut manifest = built.manifest.clone();
        manifest.key_class = Some(AuditBundleKeyClassV1::Env);
        let tampered_manifest = serde_json::to_vec_pretty(&manifest).unwrap();

        let mut tar_bytes: Vec<u8> = Vec::new();
        {
            let zstd_enc = zstd::stream::write::Encoder::new(&mut tar_bytes, 3)
                .unwrap()
                .auto_finish();
            let mut builder = tar::Builder::new(zstd_enc);
            write_tar_entry(&mut builder, MANIFEST_FILENAME, &tampered_manifest).unwrap();
            write_tar_entry(&mut builder, EVENTS_FILENAME, &built.events_jsonl).unwrap();
            write_tar_entry(&mut builder, RECEIPTS_FILENAME, &built.receipts_cbor).unwrap();
            builder.finish().unwrap();
        }

        let report = verify_bundle_v1(&tar_bytes).expect("verify");
        assert!(!report.ok, "key provenance is signed and must not be mutable");
        assert!(!report.signature_valid);
    }

    #[test]
    fn unsupported_bundle_format_version_is_rejected() {
        let built = build_bundle_v1(sample_input()).expect("build");
        let mut manifest = built.manifest.clone();
        manifest.bundle_format_version = 999;
        // Need to re-sign for the version field to be coherent (otherwise
        // the verifier would fail earlier on sig-mismatch). We don't have
        // the signing key here — but the verifier checks version BEFORE
        // signature, so the test still demonstrates the gate.
        let tampered_manifest = serde_json::to_vec_pretty(&manifest).unwrap();

        let mut tar_bytes: Vec<u8> = Vec::new();
        {
            let zstd_enc = zstd::stream::write::Encoder::new(&mut tar_bytes, 3)
                .unwrap()
                .auto_finish();
            let mut builder = tar::Builder::new(zstd_enc);
            write_tar_entry(&mut builder, MANIFEST_FILENAME, &tampered_manifest).unwrap();
            write_tar_entry(&mut builder, EVENTS_FILENAME, &built.events_jsonl).unwrap();
            write_tar_entry(&mut builder, RECEIPTS_FILENAME, &built.receipts_cbor).unwrap();
            builder.finish().unwrap();
        }

        let err = verify_bundle_v1(&tar_bytes).unwrap_err();
        assert!(matches!(err, AuditBundleError::UnsupportedVersion(999)));
    }

    #[test]
    fn v3_manifest_without_key_class_is_rejected() {
        let built = build_bundle_v1(sample_input()).expect("build");
        let mut manifest = built.manifest.clone();
        manifest.key_class = None;
        let malformed_manifest = serde_json::to_vec_pretty(&manifest).unwrap();

        let mut tar_bytes: Vec<u8> = Vec::new();
        {
            let zstd_enc = zstd::stream::write::Encoder::new(&mut tar_bytes, 3)
                .unwrap()
                .auto_finish();
            let mut builder = tar::Builder::new(zstd_enc);
            write_tar_entry(&mut builder, MANIFEST_FILENAME, &malformed_manifest).unwrap();
            write_tar_entry(&mut builder, EVENTS_FILENAME, &built.events_jsonl).unwrap();
            write_tar_entry(&mut builder, RECEIPTS_FILENAME, &built.receipts_cbor).unwrap();
            builder.finish().unwrap();
        }

        let err = verify_bundle_v1(&tar_bytes).unwrap_err();
        assert!(matches!(err, AuditBundleError::MissingField("key_class")));
    }

    #[test]
    fn missing_member_is_rejected() {
        let built = build_bundle_v1(sample_input()).expect("build");

        let mut tar_bytes: Vec<u8> = Vec::new();
        {
            let zstd_enc = zstd::stream::write::Encoder::new(&mut tar_bytes, 3)
                .unwrap()
                .auto_finish();
            let mut builder = tar::Builder::new(zstd_enc);
            write_tar_entry(&mut builder, MANIFEST_FILENAME, &built.manifest_json).unwrap();
            // EVENTS_FILENAME deliberately omitted.
            write_tar_entry(&mut builder, RECEIPTS_FILENAME, &built.receipts_cbor).unwrap();
            builder.finish().unwrap();
        }

        let err = verify_bundle_v1(&tar_bytes).unwrap_err();
        assert!(matches!(err, AuditBundleError::MissingMember(_)));
    }

    #[test]
    fn decode_receipts_cbor_roundtrip() {
        let built = build_bundle_v1(sample_input()).expect("build");
        let refs = decode_receipts_cbor(&built.receipts_cbor).unwrap();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].fact_id, "f_001");
        assert_eq!(refs[0].receipt_id, "r_abc");
    }

    // Adversarial archive inputs (ExecPlan crux-storage-fault-hardening-2026-06-11, M1):
    // typed errors, never panics, never silent success.

    #[test]
    fn verify_bundle_rejects_garbage_and_empty_bytes() {
        assert!(verify_bundle_v1(b"definitely not a tar.zst archive").is_err());
        assert!(verify_bundle_v1(&[]).is_err());
    }

    #[test]
    fn verify_bundle_rejects_truncated_archive_at_every_depth() {
        let built = build_bundle_v1(sample_input()).expect("build");
        let mut full: Vec<u8> = Vec::new();
        built.write_tar_zst(&mut full).unwrap();
        for cut in [1usize, full.len() / 4, full.len() / 2, full.len() - 1] {
            match verify_bundle_v1(&full[..cut]) {
                Err(_) => {}
                Ok(report) => panic!("truncation to {cut} bytes verified: {report:?}"),
            }
        }
    }

    // ---- H1: canonicalisation + domain separation (audit 2026-07-11) ----

    #[test]
    fn current_signing_bytes_are_v3_domain_tagged() {
        let built = build_bundle_v1(sample_input()).expect("build");
        assert_eq!(built.manifest.bundle_format_version, BUNDLE_FORMAT_VERSION);
        let signed = built.manifest.canonical_signing_bytes().expect("signing bytes");
        assert!(
            signed.starts_with(AUDIT_BUNDLE_SIGNING_DOMAIN),
            "v3 signing input must start with the domain tag"
        );
    }

    #[test]
    fn v2_signing_bytes_keep_the_v2_domain_tag() {
        let mut manifest = build_bundle_v1(sample_input()).expect("build").manifest;
        manifest.bundle_format_version = BUNDLE_FORMAT_V2;
        manifest.key_class = None;
        let signed = manifest.canonical_signing_bytes().expect("signing bytes");
        assert!(signed.starts_with(AUDIT_BUNDLE_SIGNING_DOMAIN_V2));
        assert!(!signed.starts_with(AUDIT_BUNDLE_SIGNING_DOMAIN));
    }

    #[test]
    fn v1_signing_bytes_stay_legacy_struct_order() {
        // A v1 manifest must reproduce the exact pre-v2 bytes (plain to_vec, no
        // domain tag) so bundles signed before v2 still verify (the committed
        // golden vector is v1 — see `packaged_valid_minimal_vector_verifies`).
        let mut manifest = build_bundle_v1(sample_input()).expect("build").manifest;
        manifest.bundle_format_version = BUNDLE_FORMAT_V1;
        let mut expected = manifest.clone();
        expected.signature_b64.clear();
        let legacy = serde_json::to_vec(&expected).expect("legacy bytes");
        let actual = manifest.canonical_signing_bytes().expect("bytes");
        assert_eq!(actual, legacy);
        assert!(
            !actual.starts_with(AUDIT_BUNDLE_SIGNING_DOMAIN),
            "v1 signing input must NOT be domain-tagged"
        );
    }

    #[test]
    fn canonical_json_bytes_is_field_order_invariant() {
        // preserve_order is on workspace-wide, so these two values differ in key
        // insertion order; the canonical encoding must erase that difference.
        let a = serde_json::json!({"b": 2, "a": 1, "nested": {"y": true, "x": [3, 2, 1]}});
        let b = serde_json::json!({"nested": {"x": [3, 2, 1], "y": true}, "a": 1, "b": 2});
        assert_eq!(
            canonical_json_bytes(&a).expect("a"),
            canonical_json_bytes(&b).expect("b")
        );
        // Array order remains significant.
        let c = serde_json::json!({"x": [1, 2, 3]});
        let d = serde_json::json!({"x": [3, 2, 1]});
        assert_ne!(
            canonical_json_bytes(&c).expect("c"),
            canonical_json_bytes(&d).expect("d")
        );
    }

    #[test]
    fn v2_signature_is_domain_bound_rejecting_cross_type_replay() {
        use ed25519_dalek::Verifier as _;
        let built = build_bundle_v1(sample_input()).expect("build");
        let vk = sample_signing_key().verifying_key();

        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(&built.manifest.signature_b64)
            .expect("sig b64");
        let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().expect("64-byte sig");
        let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);

        // Sanity: verifies over the real domain-tagged signing bytes.
        let signed = built.manifest.canonical_signing_bytes().expect("signed");
        assert!(vk.verify(&signed, &sig).is_ok());

        // The same manifest canonical bytes WITHOUT the domain tag (what a naive
        // verifier or a different receipt type would present) must not verify.
        let mut unsigned = built.manifest.clone();
        unsigned.signature_b64.clear();
        let no_domain = canonical_json_bytes(&serde_json::to_value(&unsigned).expect("value")).expect("canon");
        assert!(
            vk.verify(&no_domain, &sig).is_err(),
            "must not verify without the domain tag"
        );

        // Presented under a foreign receipt-type domain, it must also fail.
        let mut foreign = b"cuecrux.some_other_receipt.v1\0".to_vec();
        foreign.extend_from_slice(&no_domain);
        assert!(
            vk.verify(&foreign, &sig).is_err(),
            "must not verify under a foreign domain"
        );
    }

    // ---- L1: bounded decompression (audit 2026-07-11) ----

    #[test]
    fn decode_all_bounded_rejects_oversized_stream() {
        // 1 MiB of zeros: tiny compressed, 1 MiB decompressed.
        let raw = vec![0u8; 1024 * 1024];
        let compressed = zstd::stream::encode_all(raw.as_slice(), 3).expect("compress");
        // Cap below the decompressed size → rejected without materialising it all.
        let err = decode_all_bounded(&compressed, 64 * 1024).unwrap_err();
        assert!(matches!(err, AuditBundleError::DecompressedTooLarge));
        // Cap above the size → decodes fully.
        let decoded = decode_all_bounded(&compressed, 4 * 1024 * 1024).expect("decode");
        assert_eq!(decoded.len(), raw.len());
    }

    proptest::proptest! {
        #[test]
        fn canonical_json_bytes_invariant_under_key_permutation(
            entries in proptest::collection::hash_map("[a-z]{1,8}", proptest::prelude::any::<i64>(), 1..12)
        ) {
            let mut keys: Vec<String> = entries.keys().cloned().collect();
            keys.sort();
            let mut forward = serde_json::Map::new();
            for k in &keys {
                forward.insert(k.clone(), serde_json::json!(entries[k]));
            }
            let mut reversed = serde_json::Map::new();
            for k in keys.iter().rev() {
                reversed.insert(k.clone(), serde_json::json!(entries[k]));
            }
            proptest::prop_assert_eq!(
                canonical_json_bytes(&serde_json::Value::Object(forward)).unwrap(),
                canonical_json_bytes(&serde_json::Value::Object(reversed)).unwrap()
            );
        }
    }

    #[test]
    fn packaged_valid_minimal_vector_verifies() {
        let bytes = include_bytes!("../vectors/audit-bundle-v1/valid-minimal/audit-bundle.tar.zst");
        let report = verify_bundle_v1(bytes).expect("verify packaged valid vector");
        assert!(report.ok, "valid archive vector failed: {report:?}");
        assert_eq!(report.bundle_id, "vector-valid-minimal");
        assert_eq!(report.fact_count, 1);
        assert_eq!(report.receipt_count, 0);
        assert!(report.signature_valid);
    }

    #[test]
    fn packaged_valid_minimal_v2_vector_verifies() {
        // A v2 bundle signed by the *independent* Python generator
        // (`tools/gen_audit_bundle_vectors.py`) must verify under the Rust
        // verifier — proving the v2 domain-tagged, key-canonical signing bytes
        // are byte-identical across the two implementations.
        let bytes = include_bytes!("../vectors/audit-bundle-v1/valid-minimal-v2/audit-bundle.tar.zst");
        let report = verify_bundle_v1(bytes).expect("verify packaged v2 vector");
        assert!(report.ok, "v2 archive vector failed: {report:?}");
        assert_eq!(report.bundle_format_version, BUNDLE_FORMAT_V2);
        assert_eq!(report.bundle_id, "vector-valid-minimal-v2");
        assert!(report.signature_valid);
    }

    #[test]
    fn packaged_valid_minimal_v3_vector_verifies() {
        let bytes = include_bytes!("../vectors/audit-bundle-v1/valid-minimal-v3/audit-bundle.tar.zst");
        let report = verify_bundle_v1(bytes).expect("verify packaged v3 vector");
        assert!(report.ok, "v3 archive vector failed: {report:?}");
        assert_eq!(report.bundle_format_version, BUNDLE_FORMAT_VERSION);
        assert_eq!(report.bundle_id, "vector-valid-minimal-v3");
        assert!(report.signature_valid);
    }

    #[test]
    fn packaged_invalid_events_hash_vector_fails() {
        let bytes = include_bytes!("../vectors/audit-bundle-v1/invalid-events-hash/audit-bundle.tar.zst");
        let report = verify_bundle_v1(bytes).expect("verify packaged invalid vector");
        assert!(!report.ok, "invalid archive vector should fail");
        assert!(!report.events_jsonl_sha256_match);
        assert!(report
            .failure_reason
            .as_deref()
            .unwrap_or_default()
            .contains("events.jsonl sha256 mismatch"));
    }

    // ---- Witness inclusion-proof tests (Audit II Tier 2, M3 / Track W) ----

    /// A `WitnessProofV1` whose tree_size==1 inclusion proof is valid: the leaf
    /// IS the root and the audit path is empty, so RFC6962 verification passes.
    fn sample_witness_proof(hex_byte: &str) -> WitnessProofV1 {
        let h = hex_byte.repeat(32); // 64 hex chars
        WitnessProofV1 {
            transparency_log: "rekor".to_string(),
            log_url: "https://rekor.example".to_string(),
            rekor_uuid: Some(format!("uuid-{hex_byte}")),
            leaf_hash: h.clone(),
            log_index: 0,
            tree_size: 1,
            root_hash: h,
            inclusion_proof: Vec::new(),
            checkpoint: None,
            integrated_time: "1700000000".to_string(),
            head_hash: String::new(),
            entry_body_b64: String::new(),
        }
    }

    fn frame_members(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut tar_bytes = Vec::new();
        let enc = zstd::stream::write::Encoder::new(&mut tar_bytes, 3)
            .unwrap()
            .auto_finish();
        let mut builder = tar::Builder::new(enc);
        for (name, bytes) in members {
            write_tar_entry(&mut builder, name, bytes).unwrap();
        }
        builder.finish().unwrap();
        drop(builder);
        tar_bytes
    }

    #[test]
    fn build_and_verify_with_witness_proofs_roundtrip() {
        let mut input = sample_input();
        input.witness_proofs = vec![sample_witness_proof("ab"), sample_witness_proof("cd")];
        let built = build_bundle_v1(input).expect("build");
        assert_eq!(built.manifest.witness_proof_count, 2);
        assert!(built.manifest.witness_proofs_sha256.is_some());
        assert!(!built.witness_proofs_jsonl.is_empty());

        let mut tar_bytes = Vec::new();
        built.write_tar_zst(&mut tar_bytes).unwrap();
        let report = verify_bundle_v1(&tar_bytes).expect("verify");
        assert!(report.ok, "valid witness proofs should verify: {report:?}");
        assert_eq!(report.witness_proof_count, 2);
        assert!(report.witness_proofs_sha256_match);
        assert!(report.witness_proofs_valid);
    }

    #[test]
    fn witness_free_bundle_omits_member_and_manifest_fields() {
        // Backward-compat: no witness proofs => no member, fields skipped, the
        // manifest JSON must not even mention witness_proof_count.
        let built = build_bundle_v1(sample_input()).expect("build");
        assert_eq!(built.manifest.witness_proof_count, 0);
        assert!(built.witness_proofs_jsonl.is_empty());
        let manifest_str = String::from_utf8(built.manifest_json.clone()).unwrap();
        assert!(!manifest_str.contains("witness_proof_count"));
        assert!(!manifest_str.contains("witness_proofs_sha256"));

        let mut tar_bytes = Vec::new();
        built.write_tar_zst(&mut tar_bytes).unwrap();
        let report = verify_bundle_v1(&tar_bytes).expect("verify");
        assert!(report.ok);
        assert_eq!(report.witness_proof_count, 0);
        assert!(report.witness_proofs_sha256_match);
        assert!(report.witness_proofs_valid);
    }

    #[test]
    fn tampered_witness_member_breaks_content_hash() {
        let mut input = sample_input();
        input.witness_proofs = vec![sample_witness_proof("ab")];
        let built = build_bundle_v1(input).expect("build");

        let mut tampered = built.witness_proofs_jsonl.clone();
        tampered[0] = tampered[0].wrapping_add(1);
        let tar_bytes = frame_members(&[
            (MANIFEST_FILENAME, &built.manifest_json),
            (EVENTS_FILENAME, &built.events_jsonl),
            (RECEIPTS_FILENAME, &built.receipts_cbor),
            (WITNESS_FILENAME, &tampered),
        ]);

        let report = verify_bundle_v1(&tar_bytes).expect("verify");
        assert!(!report.ok, "tampered witness member must fail");
        assert!(!report.witness_proofs_sha256_match);
    }

    #[test]
    fn stripped_witness_member_is_detected() {
        let mut input = sample_input();
        input.witness_proofs = vec![sample_witness_proof("ab")];
        let built = build_bundle_v1(input).expect("build");

        // Re-frame WITHOUT the witness member; the signed manifest still
        // declares one proof, so the verifier must reject the stripped bundle.
        let tar_bytes = frame_members(&[
            (MANIFEST_FILENAME, &built.manifest_json),
            (EVENTS_FILENAME, &built.events_jsonl),
            (RECEIPTS_FILENAME, &built.receipts_cbor),
        ]);

        let report = verify_bundle_v1(&tar_bytes).expect("verify");
        assert!(!report.ok, "stripped witness member must fail");
        assert_eq!(report.witness_proof_count, 1);
        assert!(report.failure_reason.unwrap().contains("missing"));
    }

    #[test]
    fn inconsistent_witness_proof_fails_rfc6962_even_with_matching_hash() {
        // The acceptance property: a proof whose Merkle math does not hold is
        // rejected OFFLINE — even though the bundle is otherwise intact and the
        // member SHA-256 matches the signed manifest. This is the
        // "rewrite + re-sign a head, proof no longer consistent -> detectable
        // without trusting the daemon" case.
        let mut bad = sample_witness_proof("ab");
        bad.root_hash = "cd".repeat(32); // root != leaf for tree_size==1
        let mut input = sample_input();
        input.witness_proofs = vec![bad];
        let built = build_bundle_v1(input).expect("build");

        let mut tar_bytes = Vec::new();
        built.write_tar_zst(&mut tar_bytes).unwrap();
        let report = verify_bundle_v1(&tar_bytes).expect("verify");
        assert!(!report.ok);
        assert!(report.witness_proofs_sha256_match, "member is unmodified, sha matches");
        assert!(!report.witness_proofs_valid, "but RFC6962 verification fails");
        assert!(report.failure_reason.unwrap().contains("RFC6962"));
    }

    #[test]
    fn read_witnessed_proofs_jsonl_filters_pending_and_skips_garbage() {
        use std::io::Write as _;
        // Self-cleaning temp dir (auto-removed on Drop, even on panic) — the
        // `tmp` guard is held for the test's lifetime so it no longer leaks a
        // `corecruxd-witness-read-*` dir into `/tmp` every run.
        let tmp = tempfile::Builder::new()
            .prefix("corecruxd-witness-read-")
            .tempdir()
            .unwrap();
        let dir = tmp.path().to_path_buf();
        let path = dir.join("witness_proofs.jsonl");
        let proof = sample_witness_proof("ab");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(
            f,
            "{{\"kind\":\"pending\",\"head_hash\":\"aa\",\"segment_seq\":1,\"enqueued_at_unix\":1}}"
        )
        .unwrap();
        writeln!(f, "not json").unwrap();
        writeln!(
            f,
            "{{\"kind\":\"witnessed\",\"head_hash\":\"aa\",\"witnessed_at_unix\":2,\"proof\":{}}}",
            serde_json::to_string(&proof).unwrap()
        )
        .unwrap();
        drop(f);

        let proofs = crate::witness_v1::read_witnessed_proofs_jsonl(&path);
        assert_eq!(proofs.len(), 1, "only the witnessed record yields a proof");
        assert_eq!(proofs[0].leaf_hash, proof.leaf_hash);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn trust_root_checkpoint_endorsement_gates_the_bundle() {
        use ed25519_dalek::{Signer as _, SigningKey};
        let rekor_sk = SigningKey::from_bytes(&[0x77; 32]);
        let rekor_pk = rekor_sk.verifying_key().to_bytes();

        // A witness proof whose root ("ab"*32) is endorsed by a checkpoint the
        // synthetic Rekor key signs.
        let mut proof = sample_witness_proof("ab");
        let root_b64 = base64::engine::general_purpose::STANDARD.encode([0xab_u8; 32]);
        let text = format!("rekor.example\n1\n{root_b64}\n");
        let mut keyhash_sig = vec![0u8; 4];
        keyhash_sig.extend_from_slice(&rekor_sk.sign(text.as_bytes()).to_bytes());
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(&keyhash_sig);
        proof.checkpoint = Some(format!("{text}\n\u{2014} rekor.example {sig_b64}\n"));

        let mut input = sample_input();
        input.witness_proofs = vec![proof];
        let built = build_bundle_v1(input).expect("build");
        let mut tar = Vec::new();
        built.write_tar_zst(&mut tar).unwrap();

        // No pinned key: inclusion verified, endorsement not checked.
        let r0 = verify_bundle_v1(&tar).expect("verify");
        assert!(r0.ok);
        assert_eq!(r0.witness_root_endorsed, None);

        // Correct pinned key: root endorsed -> bundle ok.
        let r1 =
            verify_bundle_with_trust_roots_v1(&tar, Some(&WitnessLogPublicKeyV1::Ed25519(rekor_pk))).expect("verify");
        assert!(r1.ok, "{r1:?}");
        assert_eq!(r1.witness_root_endorsed, Some(true));

        // Wrong pinned key: endorsement fails -> bundle rejected even though
        // inclusion is valid.
        let wrong = SigningKey::from_bytes(&[0x88; 32]).verifying_key().to_bytes();
        let r2 = verify_bundle_with_trust_roots_v1(&tar, Some(&WitnessLogPublicKeyV1::Ed25519(wrong))).expect("verify");
        assert!(!r2.ok);
        assert!(r2.witness_proofs_valid, "inclusion still valid");
        assert_eq!(r2.witness_root_endorsed, Some(false));
    }

    #[test]
    fn witness_proof_binding_is_enforced_in_the_bundle() {
        use sha2::{Digest as _, Sha256};
        let hx = |b: &[u8]| -> String { b.iter().map(|x| format!("{x:02x}")).collect() };
        // A bound proof: the entry body's artifact digest commits to the head,
        // and the proof's leaf is the RFC6962 leaf of that body.
        let head = [0x9a_u8; 32];
        let body = serde_json::to_vec(&serde_json::json!({
            "spec": { "data": { "hash": { "value": hx(&Sha256::digest(head)) } } }
        }))
        .unwrap();
        let mut hasher = Sha256::new();
        hasher.update([0x00]);
        hasher.update(&body);
        let leaf = hx(&hasher.finalize());

        let mut proof = sample_witness_proof("11");
        proof.leaf_hash = leaf.clone();
        proof.root_hash = leaf; // tree_size 1: leaf == root
        proof.head_hash = hx(&head[..]);
        proof.entry_body_b64 = base64::engine::general_purpose::STANDARD.encode(&body);

        let mut input = sample_input();
        input.witness_proofs = vec![proof.clone()];
        let built = build_bundle_v1(input).expect("build");
        let mut tar = Vec::new();
        built.write_tar_zst(&mut tar).unwrap();
        assert!(verify_bundle_v1(&tar).expect("verify").ok, "bound proof verifies");

        // Re-point the proof at a different head: the body no longer commits to
        // it, so binding fails and the bundle is rejected.
        let mut unbound = proof;
        unbound.head_hash = hx(&[0u8; 32]);
        let mut input2 = sample_input();
        input2.witness_proofs = vec![unbound];
        let built2 = build_bundle_v1(input2).expect("build");
        let mut tar2 = Vec::new();
        built2.write_tar_zst(&mut tar2).unwrap();
        let r2 = verify_bundle_v1(&tar2).expect("verify");
        assert!(!r2.ok);
        assert!(r2.failure_reason.unwrap().contains("not bound"));
    }
}
