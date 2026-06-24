// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! External witness and trusted timestamp receipt classes.
//!
//! G1/G2 require proofs that can be checked without trusting the local
//! daemon. This module records transparency-log inclusion proofs and
//! RFC3161 timestamp tokens as signed receipt bodies, then exposes local
//! verification helpers for the parts that are deterministic without
//! network access.

use base64::Engine as _;
use ciborium::value::Value as CborValue;
use cms::cert::x509::der::{Decode, Encode, Tag as CmsTag, Tagged};
use cms::{
    cert::{
        x509::{ext::pkix::SubjectKeyIdentifier, Certificate as CmsCertificate},
        CertificateChoices,
    },
    content_info::ContentInfo,
    signed_data::{SignedData, SignerIdentifier, SignerInfo},
};
use const_oid::{
    db::{rfc5911, rfc5912},
    ObjectIdentifier,
};
use ed25519_dalek::{Signer as _, SigningKey};
use p256::ecdsa::signature::Verifier as _;
use p256::pkcs8::DecodePublicKey as _;
use ring::signature;
use sha2::{Digest as _, Sha256, Sha384, Sha512};
use x509_cert::{der::Encode as X509Cert02Encode, Certificate as PemCertificate};
use x509_parser::der_parser::{
    ber::{BerObjectContent, Tag as DerTag},
    der::parse_der_sequence,
};
use x509_parser::{certificate::X509Certificate, prelude::FromDer};

use crate::verify_v1::ReceiptSigV1;

pub const WITNESS_BODY_SCHEMA_V1: &str = "cuecrux.receipt.body.v1";
pub const EXTERNAL_ANCHOR_KIND_V1: &str = "external_anchor";
pub const RFC3161_TIMESTAMP_KIND_V1: &str = "rfc3161_timestamp";
const ID_CT_TST_INFO: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");

/// An RFC6962 inclusion proof returned by a witness submission.
///
/// Carries everything an offline verifier needs to re-check that a seal-chain
/// head was anchored in a transparency log *without trusting the daemon*: the
/// leaf hash, its position, the signed tree head, and the audit path. Produced
/// by the daemon's witness adapter and embedded in `audit_bundle_v1`. The
/// fields map one-for-one onto [`ExternalAnchorBodyInputV1`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WitnessProofV1 {
    /// Transparency-log provider label, e.g. `rekor`.
    pub transparency_log: String,
    /// Base URL of the log the entry was written to.
    pub log_url: String,
    /// Provider entry identifier (Rekor entry UUID), when returned.
    pub rekor_uuid: Option<String>,
    /// RFC6962 leaf hash, lowercase hex (SHA-256 of `0x00 || entry_body`).
    pub leaf_hash: String,
    /// Zero-based index of the leaf within the tree of size `tree_size`.
    pub log_index: u64,
    /// Size of the tree the proof is anchored against.
    pub tree_size: u64,
    /// RFC6962 signed-tree-head root hash, lowercase hex.
    pub root_hash: String,
    /// Audit-path sibling hashes, leaf to root, lowercase hex.
    pub inclusion_proof: Vec<String>,
    /// Optional signed checkpoint / signed-tree-head note.
    pub checkpoint: Option<String>,
    /// Provider's integrated time, unix seconds rendered as a string.
    pub integrated_time: String,
    /// The seal-chain head this proof anchors, lowercase hex (32-byte
    /// `material_hash`). Empty on legacy/synthetic proofs. Binds the proof to a
    /// specific head so it cannot be silently re-pointed (see
    /// [`verify_witness_binding_v1`]).
    #[serde(default)]
    pub head_hash: String,
    /// Base64 of the transparency-log entry body (the `hashedrekord`). Lets an
    /// offline verifier re-derive the leaf and confirm the entry's artifact
    /// digest commits to `head_hash`. Empty on legacy/synthetic proofs.
    #[serde(default)]
    pub entry_body_b64: String,
}

/// Re-check that a [`WitnessProofV1`] is bound to its seal-chain head: the entry
/// body hashes to the proof's RFC6962 leaf, and the entry's `hashedrekord`
/// artifact digest (`spec.data.hash.value`) equals `SHA-256(head_hash)`. Proves
/// the proof anchors *this* head, not some other entry.
///
/// Returns `true` when there is no binding material (`head_hash`/`entry_body_b64`
/// empty — legacy/synthetic proofs); callers that require binding should also
/// check `head_hash` is non-empty. Returns `false` only when binding material is
/// present but inconsistent.
pub fn verify_witness_binding_v1(proof: &WitnessProofV1) -> bool {
    if proof.head_hash.is_empty() && proof.entry_body_b64.is_empty() {
        return true;
    }
    // Both must be present to bind.
    if proof.head_hash.is_empty() || proof.entry_body_b64.is_empty() {
        return false;
    }
    let Ok(body) = base64::engine::general_purpose::STANDARD.decode(&proof.entry_body_b64) else {
        return false;
    };
    // entry body -> RFC6962 leaf (SHA-256 over a 0x00 prefix).
    let mut hasher = Sha256::new();
    hasher.update([0x00]);
    hasher.update(&body);
    let leaf_hex = hex_lower(&hasher.finalize());
    let proof_leaf = proof.leaf_hash.strip_prefix("sha256:").unwrap_or(&proof.leaf_hash);
    if leaf_hex != proof_leaf {
        return false;
    }
    // head_hash -> the entry's artifact digest (spec.data.hash.value).
    let Some(head_bytes) = parse_sha256_hex(&proof.head_hash) else {
        return false;
    };
    let head_digest_hex = hex_lower(&Sha256::digest(head_bytes));
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&body) else {
        return false;
    };
    value
        .pointer("/spec/data/hash/value")
        .and_then(serde_json::Value::as_str)
        .map(|v| v.strip_prefix("sha256:").unwrap_or(v))
        == Some(head_digest_hex.as_str())
}

/// Re-check a [`WitnessProofV1`]'s RFC6962 inclusion proof: hash the leaf along
/// the audit path up to the signed root. Pure and offline — proves the head was
/// in the log of size `tree_size` without trusting the daemon. Does not by
/// itself prove the root is endorsed by the log operator (that needs the
/// checkpoint/SET signature against the pinned log public key).
pub fn verify_witness_proof_v1(proof: &WitnessProofV1) -> bool {
    verify_rfc6962_inclusion_proof_v1(
        &proof.leaf_hash,
        proof.log_index,
        proof.tree_size,
        &proof.root_hash,
        &proof.inclusion_proof,
    )
}

/// Read the witnessed [`WitnessProofV1`]s from a daemon `witness_proofs.jsonl`
/// journal. The journal interleaves `{"kind":"pending",…}` and
/// `{"kind":"witnessed","head_hash":…,"proof":{…}}` records; this returns the
/// `proof` of each witnessed record. Tolerant — unparseable lines are skipped,
/// and a missing file yields an empty vec — so the bundle assembler (in a
/// different crate than the daemon's store) can read proofs off disk without
/// depending on the store's record types.
pub fn read_witnessed_proofs_jsonl(path: &std::path::Path) -> Vec<WitnessProofV1> {
    let Ok(content) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if value.get("kind").and_then(serde_json::Value::as_str) != Some("witnessed") {
            continue;
        }
        let Some(proof_val) = value.get("proof") else {
            continue;
        };
        if let Ok(proof) = serde_json::from_value::<WitnessProofV1>(proof_val.clone()) {
            out.push(proof);
        }
    }
    out
}

/// Verify a Rekor checkpoint (signed-note / c2sp tlog-checkpoint format) against
/// the log's Ed25519 public key and confirm it commits to `expected_root_hex`.
///
/// This is the **trust root** for witness verification. RFC6962 inclusion only
/// proves a leaf hashes up to *some* root; this proves that root is the one the
/// log operator signed, so an internally-consistent but fabricated tree is
/// rejected. Returns false on any parse, signature, or root mismatch.
///
/// A signed note is `text` (newline-terminated lines: origin, tree_size,
/// base64(root_hash), …) then a blank line then one or more
/// `— <name> <base64(keyhash[4] || ed25519_sig[64])>` lines. The signature
/// covers `text` only.
///
/// Algorithm scope: this verifies an **Ed25519**-signed checkpoint — correct for
/// self-hosted / private (Trillian/cosign) logs keyed with Ed25519. The
/// public-good Sigstore Rekor signs with **ECDSA P-256**; a P-256 variant is a
/// follow-up needed for live public-Rekor verification (Track W / M4).
/// Split a signed-note checkpoint into `(signed_text, sig_block)` iff its root
/// line commits to `expected_root_hex`. `signed_text` ends with the last text
/// line's newline — the exact bytes the note signature covers.
fn checkpoint_text_if_root_matches<'a>(checkpoint: &'a str, expected_root_hex: &str) -> Option<(&'a str, &'a str)> {
    let sep = checkpoint.find("\n\n")?;
    let text = &checkpoint[..=sep];
    let sig_block = &checkpoint[sep + 2..];
    let mut lines = text.lines();
    let (_origin, _size, root_b64) = (lines.next()?, lines.next()?, lines.next()?);
    let root_bytes = base64::engine::general_purpose::STANDARD.decode(root_b64.trim()).ok()?;
    if root_bytes.as_slice() != parse_sha256_hex(expected_root_hex)?.as_slice() {
        return None;
    }
    Some((text, sig_block))
}

/// The signature payload (after the 4-byte key-hash prefix) of a signed-note
/// `— <name> <base64(keyhash[4] || sig)>` line.
fn note_signature_payload(sig_line: &str) -> Option<Vec<u8>> {
    let rest = sig_line.trim_start().strip_prefix("\u{2014} ")?;
    let (_name, sig_b64) = rest.rsplit_once(' ')?;
    let raw = base64::engine::general_purpose::STANDARD.decode(sig_b64.trim()).ok()?;
    (raw.len() > 4).then(|| raw[4..].to_vec())
}

/// Verify a Rekor checkpoint signed with **Ed25519** (self-hosted / private
/// Trillian/cosign logs) against `log_ed25519_pubkey`, confirming it commits to
/// `expected_root_hex`. See [`verify_rekor_checkpoint_p256_v1`] for public-good
/// Sigstore Rekor (ECDSA P-256), and [`verify_rekor_checkpoint`] to dispatch.
pub fn verify_rekor_checkpoint_v1(checkpoint: &str, log_ed25519_pubkey: &[u8; 32], expected_root_hex: &str) -> bool {
    let Some((text, sig_block)) = checkpoint_text_if_root_matches(checkpoint, expected_root_hex) else {
        return false;
    };
    let Ok(verifying) = ed25519_dalek::VerifyingKey::from_bytes(log_ed25519_pubkey) else {
        return false;
    };
    for sig_line in sig_block.lines() {
        let Some(payload) = note_signature_payload(sig_line) else {
            continue;
        };
        let Ok(sig_arr) = <[u8; 64]>::try_from(payload.as_slice()) else {
            continue;
        };
        let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);
        if verifying.verify_strict(text.as_bytes(), &signature).is_ok() {
            return true;
        }
    }
    false
}

/// Verify a Rekor checkpoint signed with **ECDSA P-256** (public-good Sigstore
/// Rekor) against `log_p256_key`, confirming it commits to `expected_root_hex`.
/// The note signature is `keyhash[4] || DER-ECDSA-sig`.
pub fn verify_rekor_checkpoint_p256_v1(
    checkpoint: &str,
    log_p256_key: &p256::ecdsa::VerifyingKey,
    expected_root_hex: &str,
) -> bool {
    let Some((text, sig_block)) = checkpoint_text_if_root_matches(checkpoint, expected_root_hex) else {
        return false;
    };
    for sig_line in sig_block.lines() {
        let Some(payload) = note_signature_payload(sig_line) else {
            continue;
        };
        let Ok(signature) = p256::ecdsa::Signature::from_der(&payload) else {
            continue;
        };
        if log_p256_key.verify(text.as_bytes(), &signature).is_ok() {
            return true;
        }
    }
    false
}

/// A transparency-log public key for checkpoint/SET verification.
#[derive(Debug, Clone)]
pub enum WitnessLogPublicKeyV1 {
    /// Ed25519 (self-hosted / private Trillian/cosign logs).
    Ed25519([u8; 32]),
    /// ECDSA P-256 (public-good Sigstore Rekor).
    P256(p256::ecdsa::VerifyingKey),
}

impl WitnessLogPublicKeyV1 {
    /// Parse a log key: a 32-byte input is Ed25519; otherwise the bytes are
    /// treated as a P-256 SPKI public key (PEM or DER).
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if let Ok(key) = <[u8; 32]>::try_from(bytes) {
            return Some(WitnessLogPublicKeyV1::Ed25519(key));
        }
        if let Ok(text) = std::str::from_utf8(bytes) {
            if let Ok(vk) = p256::ecdsa::VerifyingKey::from_public_key_pem(text.trim()) {
                return Some(WitnessLogPublicKeyV1::P256(vk));
            }
        }
        p256::ecdsa::VerifyingKey::from_public_key_der(bytes)
            .ok()
            .map(WitnessLogPublicKeyV1::P256)
    }
}

/// Verify a Rekor checkpoint against either log key type.
pub fn verify_rekor_checkpoint(checkpoint: &str, key: &WitnessLogPublicKeyV1, expected_root_hex: &str) -> bool {
    match key {
        WitnessLogPublicKeyV1::Ed25519(k) => verify_rekor_checkpoint_v1(checkpoint, k, expected_root_hex),
        WitnessLogPublicKeyV1::P256(vk) => verify_rekor_checkpoint_p256_v1(checkpoint, vk, expected_root_hex),
    }
}

#[derive(Debug, Clone)]
pub struct ExternalAnchorBodyInputV1<'a> {
    pub tenant_id: &'a str,
    pub receipt_id: &'a str,
    pub anchor_id: &'a str,
    pub actor_passport: &'a str,
    /// Provider label, e.g. `rekor`, `sigstore`, or a private witness.
    pub transparency_log: &'a str,
    pub log_url: &'a str,
    pub rekor_uuid: Option<&'a str>,
    /// RFC6962 leaf hash as lowercase hex, optionally prefixed with `sha256:`.
    pub leaf_hash: &'a str,
    pub log_index: u64,
    pub tree_size: u64,
    /// RFC6962 signed tree head root hash.
    pub root_hash: &'a str,
    /// RFC6962 audit path sibling hashes from leaf to root.
    pub inclusion_proof: &'a [&'a str],
    pub checkpoint: Option<&'a str>,
    pub integrated_time: &'a str,
    pub created_at: &'a str,
}

#[derive(Debug, Clone)]
pub struct Rfc3161TimestampBodyInputV1<'a> {
    pub tenant_id: &'a str,
    pub receipt_id: &'a str,
    pub timestamp_id: &'a str,
    pub actor_passport: &'a str,
    pub tsa_url: &'a str,
    pub tsa_policy_oid: Option<&'a str>,
    pub message_imprint_alg: &'a str,
    /// Hash the TSA token is expected to bind, lowercase hex with optional
    /// `sha256:` prefix for SHA-256 imprints.
    pub message_imprint_hash: &'a str,
    /// DER-encoded RFC3161 TimeStampToken returned by the TSA.
    pub timestamp_token_der: &'a [u8],
    pub serial_number: Option<&'a str>,
    pub gen_time: &'a str,
    pub created_at: &'a str,
}

fn text_entry(key: &str, value: &str) -> (CborValue, CborValue) {
    (CborValue::Text(key.to_string()), CborValue::Text(value.to_string()))
}

fn uint_entry(key: &str, value: u64) -> (CborValue, CborValue) {
    (CborValue::Text(key.to_string()), CborValue::Integer(value.into()))
}

fn text_array(values: &[&str]) -> CborValue {
    CborValue::Array(values.iter().map(|v| CborValue::Text((*v).to_string())).collect())
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

fn sign_receipt_body_v1(
    receipt_id: &str,
    body_bytes: &[u8],
    body_hash: [u8; 32],
    signing_key: &SigningKey,
    key_id: &str,
    signed_at: &str,
) -> ReceiptSigV1 {
    let sig = signing_key.sign(body_bytes).to_bytes().to_vec();
    ReceiptSigV1 {
        schema: "cuecrux.receipt.sig.v1".to_string(),
        receipt_id: receipt_id.to_string(),
        alg: "ed25519".to_string(),
        key_id: key_id.to_string(),
        signed_at: signed_at.to_string(),
        signature: sig,
        signed_payload_hash: body_hash.to_vec(),
    }
}

pub fn build_external_anchor_body_v1(input: &ExternalAnchorBodyInputV1<'_>) -> (Vec<u8>, [u8; 32]) {
    let mut top = vec![
        text_entry("schema", WITNESS_BODY_SCHEMA_V1),
        text_entry("kind", EXTERNAL_ANCHOR_KIND_V1),
        text_entry("receipt_id", input.receipt_id),
        text_entry("tenant_id", input.tenant_id),
        text_entry("anchor_id", input.anchor_id),
        text_entry("actor_passport", input.actor_passport),
        text_entry("transparency_log", input.transparency_log),
        text_entry("log_url", input.log_url),
        text_entry("leaf_hash", input.leaf_hash),
        uint_entry("log_index", input.log_index),
        uint_entry("tree_size", input.tree_size),
        text_entry("root_hash", input.root_hash),
        (
            CborValue::Text("inclusion_proof".to_string()),
            text_array(input.inclusion_proof),
        ),
        text_entry("integrated_time", input.integrated_time),
        text_entry("created_at", input.created_at),
    ];
    if let Some(v) = input.rekor_uuid {
        top.push(text_entry("rekor_uuid", v));
    }
    if let Some(v) = input.checkpoint {
        top.push(text_entry("checkpoint", v));
    }
    encode(top)
}

pub fn build_rfc3161_timestamp_body_v1(input: &Rfc3161TimestampBodyInputV1<'_>) -> (Vec<u8>, [u8; 32]) {
    let mut top = vec![
        text_entry("schema", WITNESS_BODY_SCHEMA_V1),
        text_entry("kind", RFC3161_TIMESTAMP_KIND_V1),
        text_entry("receipt_id", input.receipt_id),
        text_entry("tenant_id", input.tenant_id),
        text_entry("timestamp_id", input.timestamp_id),
        text_entry("actor_passport", input.actor_passport),
        text_entry("tsa_url", input.tsa_url),
        text_entry("message_imprint_alg", input.message_imprint_alg),
        text_entry("message_imprint_hash", input.message_imprint_hash),
        (
            CborValue::Text("timestamp_token_der".to_string()),
            CborValue::Bytes(input.timestamp_token_der.to_vec()),
        ),
        text_entry("timestamp_token_sha256", &sha256_hex(input.timestamp_token_der)),
        text_entry("gen_time", input.gen_time),
        text_entry("created_at", input.created_at),
    ];
    if let Some(v) = input.tsa_policy_oid {
        top.push(text_entry("tsa_policy_oid", v));
    }
    if let Some(v) = input.serial_number {
        top.push(text_entry("serial_number", v));
    }
    encode(top)
}

pub fn sign_external_anchor_v1(
    receipt_id: &str,
    body_bytes: &[u8],
    body_hash: [u8; 32],
    signing_key: &SigningKey,
    key_id: &str,
    signed_at: &str,
) -> ReceiptSigV1 {
    sign_receipt_body_v1(receipt_id, body_bytes, body_hash, signing_key, key_id, signed_at)
}

pub fn sign_rfc3161_timestamp_v1(
    receipt_id: &str,
    body_bytes: &[u8],
    body_hash: [u8; 32],
    signing_key: &SigningKey,
    key_id: &str,
    signed_at: &str,
) -> ReceiptSigV1 {
    sign_receipt_body_v1(receipt_id, body_bytes, body_hash, signing_key, key_id, signed_at)
}

pub fn verify_rfc6962_inclusion_proof_v1(
    leaf_hash: &str,
    log_index: u64,
    tree_size: u64,
    root_hash: &str,
    inclusion_proof: &[String],
) -> bool {
    if tree_size == 0 || log_index >= tree_size {
        return false;
    }
    let Some(mut computed) = parse_sha256_hex(leaf_hash) else {
        return false;
    };
    let Some(expected_root) = parse_sha256_hex(root_hash) else {
        return false;
    };
    if tree_size == 1 {
        return inclusion_proof.is_empty() && computed == expected_root;
    }

    let mut fn_index = log_index;
    let mut sn = tree_size - 1;
    for sibling in inclusion_proof {
        let Some(sibling_hash) = parse_sha256_hex(sibling) else {
            return false;
        };
        if sn == 0 {
            return false;
        }
        if fn_index % 2 == 1 || fn_index == sn {
            computed = rfc6962_node_hash(&sibling_hash, &computed);
            while fn_index != 0 && fn_index % 2 == 0 {
                fn_index >>= 1;
                sn >>= 1;
            }
        } else {
            computed = rfc6962_node_hash(&computed, &sibling_hash);
        }
        fn_index >>= 1;
        sn >>= 1;
    }

    sn == 0 && computed == expected_root
}

pub fn verify_external_anchor_body_v1(body_bytes: &[u8]) -> bool {
    let Some(fields) = parse_body_fields(body_bytes) else {
        return false;
    };
    if fields.text("kind").as_deref() != Some(EXTERNAL_ANCHOR_KIND_V1) {
        return false;
    }
    let (Some(leaf_hash), Some(root_hash), Some(log_index), Some(tree_size)) = (
        fields.text("leaf_hash"),
        fields.text("root_hash"),
        fields.uint("log_index"),
        fields.uint("tree_size"),
    ) else {
        return false;
    };
    let proof = fields.text_array("inclusion_proof").unwrap_or_default();
    verify_rfc6962_inclusion_proof_v1(&leaf_hash, log_index, tree_size, &root_hash, &proof)
}

pub fn verify_rfc3161_timestamp_token_binding_v1(
    body_bytes: &[u8],
    expected_message_imprint_hash: Option<&str>,
) -> bool {
    let Some(fields) = parse_body_fields(body_bytes) else {
        return false;
    };
    if fields.text("kind").as_deref() != Some(RFC3161_TIMESTAMP_KIND_V1) {
        return false;
    }
    let (Some(token), Some(token_hash), Some(imprint_hash)) = (
        fields.bytes("timestamp_token_der"),
        fields.text("timestamp_token_sha256"),
        fields.text("message_imprint_hash"),
    ) else {
        return false;
    };
    if !hex_eq(&sha256_hex(&token), &token_hash) {
        return false;
    }
    if let Some(expected) = expected_message_imprint_hash {
        if !hex_eq(expected, &imprint_hash) {
            return false;
        }
    }
    true
}

#[derive(Debug, Clone)]
pub struct Rfc3161StrictValidationOptionsV1<'a> {
    pub expected_message_imprint_hash: Option<&'a str>,
    pub expected_policy_oid: Option<&'a str>,
    /// Optional nonce bytes as the unsigned integer value, not DER encoded.
    pub expected_nonce: Option<&'a [u8]>,
    /// DER-encoded trusted TSA roots. At least one is required for strict mode.
    pub trusted_root_certs_der: &'a [&'a [u8]],
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Rfc3161StrictValidationReportV1 {
    pub ok: bool,
    pub token_hash_ok: bool,
    pub cms_structure_ok: bool,
    pub content_type_ok: bool,
    pub signed_attrs_ok: bool,
    pub message_imprint_ok: bool,
    pub policy_ok: bool,
    pub nonce_ok: bool,
    pub gen_time_ok: bool,
    pub cms_signature_ok: bool,
    pub tsa_eku_ok: bool,
    pub cert_chain_ok: bool,
    pub tsa_policy_oid: Option<String>,
    pub gen_time: Option<String>,
    pub signer_subject: Option<String>,
    pub failure_reason: Option<String>,
}

impl Rfc3161StrictValidationReportV1 {
    fn new() -> Self {
        Self {
            ok: false,
            token_hash_ok: false,
            cms_structure_ok: false,
            content_type_ok: false,
            signed_attrs_ok: false,
            message_imprint_ok: false,
            policy_ok: false,
            nonce_ok: false,
            gen_time_ok: false,
            cms_signature_ok: false,
            tsa_eku_ok: false,
            cert_chain_ok: false,
            tsa_policy_oid: None,
            gen_time: None,
            signer_subject: None,
            failure_reason: None,
        }
    }

    fn fail(mut self, reason: impl Into<String>) -> Self {
        self.failure_reason = Some(reason.into());
        self
    }

    fn pass(mut self) -> Self {
        self.ok = true;
        self.failure_reason = None;
        self
    }
}

#[derive(Debug, Clone)]
struct ParsedTstInfoV1 {
    version: u64,
    policy_oid: String,
    message_imprint_alg_oid: String,
    message_imprint_hash: Vec<u8>,
    gen_time: x509_parser::time::ASN1Time,
    gen_time_rfc3339: String,
    nonce: Option<Vec<u8>>,
}

pub fn verify_rfc3161_timestamp_token_strict_v1(
    body_bytes: &[u8],
    opts: &Rfc3161StrictValidationOptionsV1<'_>,
) -> Rfc3161StrictValidationReportV1 {
    let mut report = Rfc3161StrictValidationReportV1::new();
    if opts.trusted_root_certs_der.is_empty() {
        return report.fail("strict RFC3161 validation requires at least one trusted TSA root certificate");
    }

    let Some(fields) = parse_body_fields(body_bytes) else {
        return report.fail("receipt body is not valid CBOR");
    };
    if fields.text("kind").as_deref() != Some(RFC3161_TIMESTAMP_KIND_V1) {
        return report.fail("body is not an rfc3161_timestamp receipt body");
    }
    let (Some(token), Some(token_hash), Some(body_imprint_alg), Some(body_imprint_hash)) = (
        fields.bytes("timestamp_token_der"),
        fields.text("timestamp_token_sha256"),
        fields.text("message_imprint_alg"),
        fields.text("message_imprint_hash"),
    ) else {
        return report.fail("rfc3161_timestamp body is missing token, token hash, or message imprint fields");
    };
    report.token_hash_ok = hex_eq(&sha256_hex(&token), &token_hash);
    if !report.token_hash_ok {
        return report.fail("timestamp_token_sha256 does not match timestamp_token_der");
    }
    if let Some(expected) = opts.expected_message_imprint_hash {
        if !digest_hex_eq(expected, &body_imprint_hash, digest_len_for_alg(&body_imprint_alg)) {
            return report.fail("expected message imprint does not match receipt body message_imprint_hash");
        }
    }

    let token_ci = match ContentInfo::from_der(&token) {
        Ok(v) => v,
        Err(err) => return report.fail(format!("TimeStampToken ContentInfo parse failed: {err}")),
    };
    if token_ci.content_type != rfc5911::ID_SIGNED_DATA {
        return report.fail("TimeStampToken ContentInfo contentType is not id-signedData");
    }
    let signed_data = match token_ci.content.decode_as::<SignedData>() {
        Ok(v) => v,
        Err(err) => return report.fail(format!("SignedData parse failed: {err}")),
    };
    if signed_data.encap_content_info.econtent_type != ID_CT_TST_INFO {
        return report.fail("SignedData encapContentInfo eContentType is not id-ct-TSTInfo");
    }
    let Some(econtent) = signed_data.encap_content_info.econtent.as_ref() else {
        return report.fail("SignedData is missing encapsulated TSTInfo content");
    };
    let tst_info_der = econtent.value();
    let tst_info = match parse_tst_info_v1(tst_info_der) {
        Ok(v) => v,
        Err(err) => return report.fail(format!("TSTInfo parse failed: {err}")),
    };
    report.cms_structure_ok = true;
    report.content_type_ok = true;
    report.tsa_policy_oid = Some(tst_info.policy_oid.clone());
    report.gen_time = Some(tst_info.gen_time_rfc3339.clone());

    if tst_info.version != 1 {
        return report.fail(format!("unsupported TSTInfo version: {}", tst_info.version));
    }
    if alg_name_for_digest_oid_str(&tst_info.message_imprint_alg_oid) != Some(body_imprint_alg.as_str()) {
        return report.fail("TSTInfo messageImprint hashAlgorithm does not match receipt body message_imprint_alg");
    }
    let Some(expected_imprint) = parse_digest_hex(&body_imprint_hash, tst_info.message_imprint_hash.len()) else {
        return report.fail("receipt body message_imprint_hash is not valid hex for the TSTInfo hash algorithm");
    };
    report.message_imprint_ok = tst_info.message_imprint_hash.as_slice() == expected_imprint.as_slice();
    if !report.message_imprint_ok {
        return report.fail("TSTInfo messageImprint hashedMessage does not match receipt body");
    }

    report.policy_ok = fields
        .text("tsa_policy_oid")
        .is_none_or(|receipt_policy| receipt_policy == tst_info.policy_oid)
        && opts
            .expected_policy_oid
            .is_none_or(|expected_policy| expected_policy == tst_info.policy_oid);
    if !report.policy_ok {
        return report.fail("TSTInfo policy does not match expected or receipt body TSA policy");
    }

    report.nonce_ok = match opts.expected_nonce {
        Some(expected_nonce) => tst_info
            .nonce
            .as_ref()
            .is_some_and(|nonce| nonce.as_slice() == trim_unsigned_integer(expected_nonce)),
        None => true,
    };
    if !report.nonce_ok {
        return report.fail("TSTInfo nonce does not match expected nonce");
    }

    let signer_info = match single_signer_info(&signed_data) {
        Ok(v) => v,
        Err(reason) => return report.fail(reason),
    };
    let cert_ders = match certificate_der_set(&signed_data) {
        Ok(v) => v,
        Err(reason) => return report.fail(reason),
    };
    let (signer_cert_der, signer_cert) = match find_signer_cert_der(&cert_ders, signer_info) {
        Some(v) => v,
        None => return report.fail("no certificate in SignedData matches SignerInfo sid"),
    };
    report.signer_subject = Some(signer_cert.subject().to_string());

    let content_digest = match digest_for_oid(signer_info.digest_alg.oid, tst_info_der) {
        Some(v) => v,
        None => return report.fail("SignerInfo digestAlgorithm is unsupported"),
    };
    report.signed_attrs_ok = verify_signed_attrs_v1(
        signer_info,
        signed_data.encap_content_info.econtent_type,
        &content_digest,
    )
    .is_ok();
    if !report.signed_attrs_ok {
        return report.fail("SignerInfo signedAttrs contentType/messageDigest verification failed");
    }

    report.cms_signature_ok = verify_cms_signature_v1(signer_info, &signer_cert).is_ok();
    if !report.cms_signature_ok {
        return report.fail("SignerInfo signature verification failed");
    }

    let gen_time = tst_info.gen_time;
    report.gen_time_ok = signer_cert.validity().is_valid_at(gen_time);
    if !report.gen_time_ok {
        return report.fail("TSA signer certificate was not valid at TSTInfo genTime");
    }

    report.tsa_eku_ok = signer_has_timestamping_eku(&signer_cert);
    if !report.tsa_eku_ok {
        return report.fail("TSA signer certificate lacks id-kp-timeStamping EKU");
    }

    let root_ders = opts
        .trusted_root_certs_der
        .iter()
        .map(|cert| cert.to_vec())
        .collect::<Vec<_>>();
    report.cert_chain_ok = validate_tsa_chain_v1(signer_cert_der, &cert_ders, &root_ders, gen_time).is_ok();
    if !report.cert_chain_ok {
        return report.fail("TSA signer certificate does not chain to a trusted root");
    }

    report.pass()
}

pub fn parse_x509_certs_der_or_pem_v1(bytes: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    if bytes.starts_with(b"-----BEGIN") {
        PemCertificate::load_pem_chain(bytes)
            .map_err(|err| format!("PEM certificate parse failed: {err}"))?
            .into_iter()
            .map(|cert| {
                cert.to_der()
                    .map_err(|err| format!("certificate DER encoding failed: {err}"))
            })
            .collect()
    } else {
        X509Certificate::from_der(bytes).map_err(|err| format!("DER certificate parse failed: {err}"))?;
        Ok(vec![bytes.to_vec()])
    }
}

pub fn is_valid_object_identifier_text_v1(oid: &str) -> bool {
    let oid = oid.trim();
    oid.split('.').count() >= 3 && ObjectIdentifier::new(oid).is_ok()
}

fn parse_tst_info_v1(bytes: &[u8]) -> Result<ParsedTstInfoV1, String> {
    let (rem, seq) = parse_der_sequence(bytes).map_err(|err| format!("{err:?}"))?;
    if !rem.is_empty() {
        return Err("TSTInfo has trailing bytes".to_string());
    }
    let fields = seq.as_sequence().map_err(|err| format!("{err:?}"))?;
    if fields.len() < 5 {
        return Err("TSTInfo is missing required fields".to_string());
    }

    let version = fields[0]
        .as_u64()
        .map_err(|err| format!("version parse failed: {err:?}"))?;
    let policy_oid = fields[1]
        .as_oid()
        .map_err(|err| format!("policy OID parse failed: {err:?}"))?
        .to_id_string();
    let imprint_fields = fields[2]
        .as_sequence()
        .map_err(|err| format!("messageImprint parse failed: {err:?}"))?;
    if imprint_fields.len() < 2 {
        return Err("messageImprint is missing hashAlgorithm or hashedMessage".to_string());
    }
    let alg_fields = imprint_fields[0]
        .as_sequence()
        .map_err(|err| format!("messageImprint hashAlgorithm parse failed: {err:?}"))?;
    let Some(alg_oid_obj) = alg_fields.first() else {
        return Err("messageImprint hashAlgorithm is missing algorithm OID".to_string());
    };
    let message_imprint_alg_oid = alg_oid_obj
        .as_oid()
        .map_err(|err| format!("messageImprint algorithm OID parse failed: {err:?}"))?
        .to_id_string();
    let message_imprint_hash = imprint_fields[1]
        .as_slice()
        .map_err(|err| format!("messageImprint hashedMessage parse failed: {err:?}"))?
        .to_vec();

    fields[3]
        .as_biguint()
        .map_err(|err| format!("serialNumber parse failed: {err:?}"))?;
    let gen_time_raw = match &fields[4].content {
        BerObjectContent::GeneralizedTime(dt) => dt.to_string(),
        _ => return Err("genTime is not DER GeneralizedTime".to_string()),
    };
    let gen_time_content = gen_time_raw.as_bytes();
    let gen_time_der = wrap_generalized_time_der(gen_time_content)?;
    let (_, gen_time) = x509_parser::time::ASN1Time::from_der(&gen_time_der)
        .map_err(|err| format!("genTime validation failed: {err:?}"))?;
    let gen_time_rfc3339 = generalized_time_to_rfc3339(gen_time_content);

    let nonce = fields
        .iter()
        .skip(5)
        .find(|field| field.header.tag() == DerTag::Integer)
        .map(|field| {
            field
                .as_biguint()
                .map(|value| trim_unsigned_integer(&value.to_bytes_be()).to_vec())
                .map_err(|err| format!("nonce parse failed: {err:?}"))
        })
        .transpose()?;

    Ok(ParsedTstInfoV1 {
        version,
        policy_oid,
        message_imprint_alg_oid,
        message_imprint_hash,
        gen_time,
        gen_time_rfc3339,
        nonce,
    })
}

fn wrap_generalized_time_der(content: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = vec![0x18];
    if content.len() < 128 {
        out.push(content.len() as u8);
    } else if content.len() <= 255 {
        out.extend_from_slice(&[0x81, content.len() as u8]);
    } else {
        return Err("GeneralizedTime is too long".to_string());
    }
    out.extend_from_slice(content);
    Ok(out)
}

fn generalized_time_to_rfc3339(content: &[u8]) -> String {
    if content.len() == 15 && content[14] == b'Z' {
        let s = String::from_utf8_lossy(content);
        format!(
            "{}-{}-{}T{}:{}:{}Z",
            &s[0..4],
            &s[4..6],
            &s[6..8],
            &s[8..10],
            &s[10..12],
            &s[12..14]
        )
    } else {
        String::from_utf8_lossy(content).to_string()
    }
}

fn single_signer_info(signed_data: &SignedData) -> Result<&SignerInfo, String> {
    let mut iter = signed_data.signer_infos.0.iter();
    let Some(first) = iter.next() else {
        return Err("SignedData does not contain a SignerInfo".to_string());
    };
    if iter.next().is_some() {
        return Err("strict RFC3161 validation requires exactly one SignerInfo".to_string());
    }
    Ok(first)
}

fn certificate_der_set(signed_data: &SignedData) -> Result<Vec<Vec<u8>>, String> {
    let Some(certs) = signed_data.certificates.as_ref() else {
        return Err("SignedData does not include TSA certificates".to_string());
    };
    let mut out = Vec::new();
    for cert in certs.0.iter() {
        if let CertificateChoices::Certificate(cert) = cert {
            out.push(
                cert.to_der()
                    .map_err(|err| format!("certificate DER encoding failed: {err}"))?,
            );
        }
    }
    if out.is_empty() {
        return Err("SignedData certificate set has no X.509 certificates".to_string());
    }
    Ok(out)
}

fn find_signer_cert_der<'a>(
    cert_ders: &'a [Vec<u8>],
    signer_info: &SignerInfo,
) -> Option<(&'a [u8], X509Certificate<'a>)> {
    for cert_der in cert_ders {
        let owned = CmsCertificate::from_der(cert_der).ok()?;
        if !cert_matches_signer_v1(&owned, &signer_info.sid) {
            continue;
        }
        let (_, parsed) = X509Certificate::from_der(cert_der).ok()?;
        return Some((cert_der.as_slice(), parsed));
    }
    None
}

fn cert_matches_signer_v1(cert: &CmsCertificate, sid: &SignerIdentifier) -> bool {
    match sid {
        SignerIdentifier::IssuerAndSerialNumber(isn) => {
            cert.tbs_certificate().issuer() == &isn.issuer
                && cert.tbs_certificate().serial_number() == &isn.serial_number
        }
        SignerIdentifier::SubjectKeyIdentifier(ski) => cert
            .tbs_certificate()
            .get_extension::<SubjectKeyIdentifier>()
            .ok()
            .flatten()
            .is_some_and(|(_, cert_ski)| cert_ski.0.as_bytes() == ski.0.as_bytes()),
    }
}

fn verify_signed_attrs_v1(
    signer_info: &SignerInfo,
    expected_content_type: ObjectIdentifier,
    expected_content_digest: &[u8],
) -> Result<(), String> {
    let Some(attrs) = signer_info.signed_attrs.as_ref() else {
        return Err("SignerInfo has no signedAttrs".to_string());
    };
    let content_type = signed_attr_oid_value(attrs, rfc5911::ID_CONTENT_TYPE)?;
    if content_type != expected_content_type {
        return Err("signedAttrs contentType does not match TSTInfo eContentType".to_string());
    }
    let message_digest = signed_attr_octets_value(attrs, rfc5911::ID_MESSAGE_DIGEST)?;
    if message_digest != expected_content_digest {
        return Err("signedAttrs messageDigest does not match TSTInfo digest".to_string());
    }
    Ok(())
}

fn signed_attr_oid_value(
    attrs: &cms::cert::x509::attr::Attributes,
    oid: ObjectIdentifier,
) -> Result<ObjectIdentifier, String> {
    let attr = single_attr(attrs, oid)?;
    let value = attr
        .values
        .get(0)
        .ok_or_else(|| "signed attribute has no values".to_string())?;
    value
        .decode_as::<ObjectIdentifier>()
        .map_err(|err| format!("signed attribute OID decode failed: {err}"))
}

fn signed_attr_octets_value(
    attrs: &cms::cert::x509::attr::Attributes,
    oid: ObjectIdentifier,
) -> Result<Vec<u8>, String> {
    let attr = single_attr(attrs, oid)?;
    let value = attr
        .values
        .get(0)
        .ok_or_else(|| "signed attribute has no values".to_string())?;
    if value.tag() != CmsTag::OctetString {
        return Err("signed attribute value is not an OCTET STRING".to_string());
    }
    Ok(value.value().to_vec())
}

fn single_attr(
    attrs: &cms::cert::x509::attr::Attributes,
    oid: ObjectIdentifier,
) -> Result<&cms::cert::x509::attr::Attribute, String> {
    let mut matches = attrs.iter().filter(|attr| attr.oid == oid);
    let Some(first) = matches.next() else {
        return Err(format!("missing signed attribute {oid}"));
    };
    if first.values.len() != 1 {
        return Err(format!("signed attribute {oid} must have exactly one value"));
    }
    if matches.next().is_some() {
        return Err(format!("duplicate signed attribute {oid}"));
    }
    Ok(first)
}

fn verify_cms_signature_v1(signer_info: &SignerInfo, signer_cert: &X509Certificate<'_>) -> Result<(), String> {
    let Some(attrs) = signer_info.signed_attrs.as_ref() else {
        return Err("SignerInfo has no signedAttrs".to_string());
    };
    let signed_attrs_der = attrs
        .to_der()
        .map_err(|err| format!("signedAttrs DER encoding failed: {err}"))?;
    let verification_alg = ring_alg_for_signature_v1(signer_info.signature_algorithm.oid, signer_cert)?;
    let public_key = signer_cert.public_key();
    let key = signature::UnparsedPublicKey::new(verification_alg, &public_key.subject_public_key.data);
    key.verify(&signed_attrs_der, signer_info.signature.as_bytes())
        .map_err(|_| "CMS signature verification failed".to_string())
}

fn ring_alg_for_signature_v1(
    signature_oid: ObjectIdentifier,
    signer_cert: &X509Certificate<'_>,
) -> Result<&'static dyn signature::VerificationAlgorithm, String> {
    let key_len = signer_cert.public_key().subject_public_key.data.len();
    match signature_oid.to_string().as_str() {
        "1.2.840.10045.4.3.2" => {
            if key_len > 80 {
                Ok(&signature::ECDSA_P384_SHA256_ASN1)
            } else {
                Ok(&signature::ECDSA_P256_SHA256_ASN1)
            }
        }
        "1.2.840.10045.4.3.3" => {
            if key_len > 80 {
                Ok(&signature::ECDSA_P384_SHA384_ASN1)
            } else {
                Ok(&signature::ECDSA_P256_SHA384_ASN1)
            }
        }
        "1.2.840.113549.1.1.11" => Ok(&signature::RSA_PKCS1_2048_8192_SHA256),
        "1.2.840.113549.1.1.12" => Ok(&signature::RSA_PKCS1_2048_8192_SHA384),
        "1.2.840.113549.1.1.13" => Ok(&signature::RSA_PKCS1_2048_8192_SHA512),
        "1.3.101.112" => Ok(&signature::ED25519),
        other => Err(format!("unsupported CMS signature algorithm OID: {other}")),
    }
}

fn signer_has_timestamping_eku(cert: &X509Certificate<'_>) -> bool {
    cert.extended_key_usage()
        .ok()
        .flatten()
        .is_some_and(|eku| eku.value.time_stamping)
}

fn validate_tsa_chain_v1(
    signer_cert_der: &[u8],
    cert_ders: &[Vec<u8>],
    trusted_root_ders: &[Vec<u8>],
    gen_time: x509_parser::time::ASN1Time,
) -> Result<(), String> {
    let mut current_der = signer_cert_der.to_vec();
    let mut seen_hashes = Vec::<[u8; 32]>::new();
    let mut candidates = cert_ders.to_vec();
    candidates.extend_from_slice(trusted_root_ders);

    for _ in 0..=candidates.len() {
        let current_hash = Sha256::digest(&current_der).into();
        if seen_hashes.contains(&current_hash) {
            return Err("certificate chain loop detected".to_string());
        }
        seen_hashes.push(current_hash);

        let (_, current) = X509Certificate::from_der(&current_der)
            .map_err(|err| format!("certificate parse failed during chain validation: {err}"))?;
        if !current.validity().is_valid_at(gen_time) {
            return Err("certificate in TSA chain was not valid at genTime".to_string());
        }
        if trusted_root_ders
            .iter()
            .any(|root| root.as_slice() == current_der.as_slice())
        {
            current
                .verify_signature(None)
                .map_err(|_| "trusted TSA root self-signature verification failed".to_string())?;
            return Ok(());
        }

        let mut next_der = None;
        for candidate_der in &candidates {
            if candidate_der.as_slice() == current_der.as_slice() {
                continue;
            }
            let Ok((_, issuer)) = X509Certificate::from_der(candidate_der) else {
                continue;
            };
            if current.issuer() == issuer.subject() && current.verify_signature(Some(issuer.public_key())).is_ok() {
                next_der = Some(candidate_der.clone());
                break;
            }
        }
        let Some(found) = next_der else {
            return Err("no issuer found for certificate in TSA chain".to_string());
        };
        current_der = found;
    }
    Err("certificate chain exceeded candidate length".to_string())
}

fn digest_for_oid(oid: ObjectIdentifier, bytes: &[u8]) -> Option<Vec<u8>> {
    if oid == rfc5912::ID_SHA_256 {
        Some(Sha256::digest(bytes).to_vec())
    } else if oid == rfc5912::ID_SHA_384 {
        Some(Sha384::digest(bytes).to_vec())
    } else if oid == rfc5912::ID_SHA_512 {
        Some(Sha512::digest(bytes).to_vec())
    } else {
        None
    }
}

fn alg_name_for_digest_oid_str(oid: &str) -> Option<&'static str> {
    match oid {
        "2.16.840.1.101.3.4.2.1" => Some("sha256"),
        "2.16.840.1.101.3.4.2.2" => Some("sha384"),
        "2.16.840.1.101.3.4.2.3" => Some("sha512"),
        _ => None,
    }
}

fn digest_len_for_alg(alg: &str) -> Option<usize> {
    match alg.to_ascii_lowercase().as_str() {
        "sha256" => Some(32),
        "sha384" => Some(48),
        "sha512" => Some(64),
        _ => None,
    }
}

fn digest_hex_eq(a: &str, b: &str, expected_len: Option<usize>) -> bool {
    let Some(expected_len) = expected_len else {
        return false;
    };
    let Some(aa) = parse_digest_hex(a, expected_len) else {
        return false;
    };
    let Some(bb) = parse_digest_hex(b, expected_len) else {
        return false;
    };
    aa == bb
}

fn parse_digest_hex(s: &str, expected_len: usize) -> Option<Vec<u8>> {
    let raw = s.strip_prefix("sha256:").unwrap_or(s);
    let raw = raw.strip_prefix("sha384:").unwrap_or(raw);
    let raw = raw.strip_prefix("sha512:").unwrap_or(raw);
    if raw.len() != expected_len * 2 {
        return None;
    }
    let mut out = Vec::with_capacity(expected_len);
    for chunk in raw.as_bytes().chunks_exact(2) {
        let hi = hex_val(chunk[0])?;
        let lo = hex_val(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn trim_unsigned_integer(bytes: &[u8]) -> &[u8] {
    let mut out = bytes;
    while out.len() > 1 && out[0] == 0 {
        out = &out[1..];
    }
    out
}

pub fn assert_external_anchor_kind_v1(body_bytes: &[u8]) -> bool {
    parse_body_fields(body_bytes)
        .and_then(|fields| fields.text("kind"))
        .as_deref()
        == Some(EXTERNAL_ANCHOR_KIND_V1)
}

pub fn assert_rfc3161_timestamp_kind_v1(body_bytes: &[u8]) -> bool {
    parse_body_fields(body_bytes)
        .and_then(|fields| fields.text("kind"))
        .as_deref()
        == Some(RFC3161_TIMESTAMP_KIND_V1)
}

#[cfg(test)]
fn rfc6962_leaf_hash(leaf_input: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(leaf_input);
    h.finalize().into()
}

fn rfc6962_node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex_lower(&Sha256::digest(bytes))
}

fn hex_eq(a: &str, b: &str) -> bool {
    let Some(aa) = parse_sha256_hex(a) else { return false };
    let Some(bb) = parse_sha256_hex(b) else { return false };
    aa == bb
}

fn parse_sha256_hex(s: &str) -> Option<[u8; 32]> {
    let raw = s.strip_prefix("sha256:").unwrap_or(s);
    if raw.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in raw.as_bytes().chunks_exact(2).enumerate() {
        let hi = hex_val(chunk[0])?;
        let lo = hex_val(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

struct BodyFields {
    map: Vec<(CborValue, CborValue)>,
}

impl BodyFields {
    fn text(&self, key: &str) -> Option<String> {
        self.get(key).and_then(|v| match v {
            CborValue::Text(s) => Some(s.clone()),
            _ => None,
        })
    }

    fn bytes(&self, key: &str) -> Option<Vec<u8>> {
        self.get(key).and_then(|v| match v {
            CborValue::Bytes(bytes) => Some(bytes.clone()),
            _ => None,
        })
    }

    fn uint(&self, key: &str) -> Option<u64> {
        self.get(key).and_then(|v| match v {
            CborValue::Integer(i) => (*i).try_into().ok(),
            _ => None,
        })
    }

    fn text_array(&self, key: &str) -> Option<Vec<String>> {
        self.get(key).and_then(|v| match v {
            CborValue::Array(arr) => {
                let mut out = Vec::with_capacity(arr.len());
                for el in arr {
                    let CborValue::Text(s) = el else {
                        return None;
                    };
                    out.push(s.clone());
                }
                Some(out)
            }
            _ => None,
        })
    }

    fn get(&self, key: &str) -> Option<&CborValue> {
        for (k, v) in &self.map {
            if let CborValue::Text(s) = k {
                if s == key {
                    return Some(v);
                }
            }
        }
        None
    }
}

fn parse_body_fields(body_bytes: &[u8]) -> Option<BodyFields> {
    let v: CborValue = ciborium::de::from_reader(std::io::Cursor::new(body_bytes)).ok()?;
    let CborValue::Map(map) = v else { return None };
    Some(BodyFields { map })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use ed25519_dalek::VerifyingKey;

    const OPENSSL_TSA_ROOT_DER_HEX: &str = concat!(
        "308201a63082014ba00302010202146357e286ac744b2644b9a1944bc53332ce452aeb300a06082a8648ce3d0403023020311e301c06035504030c15437565437275782054534120526f6f742054455354301e170d3236303631343130323332",
        "385a170d3336303631313130323332385a3020311e301c06035504030c15437565437275782054534120526f6f7420544553543059301306072a8648ce3d020106082a8648ce3d03010703420004c8c194328268f50786a22f5418e0e799b96e",
        "9a3408e6664eaef4fe55187b9d9f85f8ed06493f9384f556afc8e63d7d720d7f3e4728c8215620db479155426327a3633061301d0603551d0e0416041420a6b0cc0760ce03e42a1abe8dc28dd7f3588d77301f0603551d2304183016801420a6",
        "b0cc0760ce03e42a1abe8dc28dd7f3588d77300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020106300a06082a8648ce3d04030203490030460221009d2f57cbfeb2f962585b84a4ec824df010a3b8e32c50a25b9a",
        "0ab3824a5c8752022100ac9ae04621d06d2a5687bbbb3aaa8d08648f875d49712b0d04ebf7d5582542ec",
    );

    const OPENSSL_TSA_TOKEN_DER_HEX: &str = concat!(
        "3082055206092a864886f70d010702a08205433082053f020103310f300d06096086480165030402010500306d060b2a864886f70d0109100104a05e045c305a02010106032a03043031300d06096086480165030402010500042080a7a77c0c",
        "d501aec2d7694dcc7fdf4cf50a4cab83579fb290924fc8520ba680020102180f32303236303631343130323332385a020900c23a5af413e2a2cfa0820368308201ba30820160a0030201020214437244843a279eb992604133c83183abb6a90e",
        "bc300a06082a8648ce3d0403023020311e301c06035504030c15437565437275782054534120526f6f742054455354301e170d3236303631343130323332385a170d3237303631343130323332385a3020311e301c06035504030c1543756543",
        "72757820545341204c65616620544553543059301306072a8648ce3d020106082a8648ce3d03010703420004d21bb325d01bd4c057c7021a73aff34d0c14bf6c5785206dc916e9416f742f0087918d532fdb601dfcdf0cbdd0ff0536f189565f",
        "72519eeebef4c0bede05a02fa3783076300c0603551d130101ff04023000300e0603551d0f0101ff04040302078030160603551d250101ff040c300a06082b06010505070308301d0603551d0e041604147425117c29124793460e9b439f6e0a",
        "12015af4a1301f0603551d2304183016801420a6b0cc0760ce03e42a1abe8dc28dd7f3588d77300a06082a8648ce3d0403020348003045022100ba128d57fb0ef7f2d27ce152ae15317f65f42f634403400e6c3c3b65af18d6b3022047c2767d",
        "28e4e7098d4fb30e7a0d43efdbe9a8984a2a18dbb2d5420cda0be816308201a63082014ba00302010202146357e286ac744b2644b9a1944bc53332ce452aeb300a06082a8648ce3d0403023020311e301c06035504030c154375654372757820",
        "54534120526f6f742054455354301e170d3236303631343130323332385a170d3336303631313130323332385a3020311e301c06035504030c15437565437275782054534120526f6f7420544553543059301306072a8648ce3d020106082a86",
        "48ce3d03010703420004c8c194328268f50786a22f5418e0e799b96e9a3408e6664eaef4fe55187b9d9f85f8ed06493f9384f556afc8e63d7d720d7f3e4728c8215620db479155426327a3633061301d0603551d0e0416041420a6b0cc0760ce",
        "03e42a1abe8dc28dd7f3588d77301f0603551d2304183016801420a6b0cc0760ce03e42a1abe8dc28dd7f3588d77300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020106300a06082a8648ce3d0403020349003046",
        "0221009d2f57cbfeb2f962585b84a4ec824df010a3b8e32c50a25b9a0ab3824a5c8752022100ac9ae04621d06d2a5687bbbb3aaa8d08648f875d49712b0d04ebf7d5582542ec3182014c3082014802010130383020311e301c06035504030c15",
        "437565437275782054534120526f6f7420544553540214437244843a279eb992604133c83183abb6a90ebc300d06096086480165030402010500a081a4301a06092a864886f70d010903310d060b2a864886f70d0109100104301c06092a8648",
        "86f70d010905310f170d3236303631343130323332385a302f06092a864886f70d01090431220420a154fa93da08b28749c6997f1141c4d99df70a3e2413752bc57fca13a96807933037060b2a864886f70d010910022f312830263024302204",
        "20a40d8b814db0a06bcdada9d081a75c5e9325878aee771f8219744111c9dca9fb300a06082a8648ce3d04030204473045022100f59034d403430bb434427cdf47dbc58365f92d60756980a26a5418624ecff2e402206489558c4bd929accf38",
        "91a22b4435a12ad9aa0723534bec33449b8acc2db3bf",
    );

    fn two_leaf_tree() -> ([u8; 32], [u8; 32], [u8; 32]) {
        let leaf0 = rfc6962_leaf_hash(b"leaf-0");
        let leaf1 = rfc6962_leaf_hash(b"leaf-1");
        let root = rfc6962_node_hash(&leaf0, &leaf1);
        (leaf0, leaf1, root)
    }

    fn external_input<'a>(proof: &'a [&'a str], leaf: &'a str, root: &'a str) -> ExternalAnchorBodyInputV1<'a> {
        ExternalAnchorBodyInputV1 {
            tenant_id: "tenant-a",
            receipt_id: "anchor_1",
            anchor_id: "anchor-1",
            actor_passport: "passport:operator",
            transparency_log: "rekor",
            log_url: "https://rekor.sigstore.dev",
            rekor_uuid: Some("rekor-uuid-1"),
            leaf_hash: leaf,
            log_index: 0,
            tree_size: 2,
            root_hash: root,
            inclusion_proof: proof,
            checkpoint: Some("rekor-checkpoint"),
            integrated_time: "2026-06-14T10:00:00Z",
            created_at: "2026-06-14T10:00:01Z",
        }
    }

    fn timestamp_input(token: &[u8]) -> Rfc3161TimestampBodyInputV1<'_> {
        Rfc3161TimestampBodyInputV1 {
            tenant_id: "tenant-a",
            receipt_id: "tsa_1",
            timestamp_id: "tsa-1",
            actor_passport: "passport:operator",
            tsa_url: "https://tsa.example",
            tsa_policy_oid: Some("1.2.3.4"),
            message_imprint_alg: "sha256",
            message_imprint_hash: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            timestamp_token_der: token,
            serial_number: Some("01"),
            gen_time: "2026-06-14T10:00:00Z",
            created_at: "2026-06-14T10:00:01Z",
        }
    }

    fn hex_bytes(raw: &str) -> Vec<u8> {
        raw.as_bytes()
            .chunks_exact(2)
            .map(|chunk| {
                let hi = hex_val(chunk[0]).unwrap();
                let lo = hex_val(chunk[1]).unwrap();
                (hi << 4) | lo
            })
            .collect()
    }

    #[test]
    fn rfc6962_inclusion_proof_verifies_two_leaf_tree() {
        let (leaf0, leaf1, root) = two_leaf_tree();
        assert!(verify_rfc6962_inclusion_proof_v1(
            &hex_lower(&leaf0),
            0,
            2,
            &hex_lower(&root),
            &[hex_lower(&leaf1)]
        ));
        assert!(!verify_rfc6962_inclusion_proof_v1(
            &hex_lower(&leaf0),
            0,
            2,
            &hex_lower(&leaf1),
            &[hex_lower(&leaf1)]
        ));
    }

    #[test]
    fn external_anchor_body_binds_inclusion_proof() {
        let (leaf0, leaf1, root) = two_leaf_tree();
        let proof = [hex_lower(&leaf1)];
        let (body, hash) = build_external_anchor_body_v1(&external_input(
            &proof.iter().map(String::as_str).collect::<Vec<_>>(),
            &hex_lower(&leaf0),
            &hex_lower(&root),
        ));
        assert_eq!(hash, *blake3::hash(&body).as_bytes());
        assert!(assert_external_anchor_kind_v1(&body));
        assert!(verify_external_anchor_body_v1(&body));
        assert!(!assert_rfc3161_timestamp_kind_v1(&body));
    }

    #[test]
    fn rfc3161_timestamp_body_binds_token_hash_and_imprint() {
        let token = b"fake-rfc3161-timestamp-token";
        let (body, hash) = build_rfc3161_timestamp_body_v1(&timestamp_input(token));
        assert_eq!(hash, *blake3::hash(&body).as_bytes());
        assert!(assert_rfc3161_timestamp_kind_v1(&body));
        assert!(verify_rfc3161_timestamp_token_binding_v1(
            &body,
            Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        ));
        assert!(!verify_rfc3161_timestamp_token_binding_v1(
            &body,
            Some("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
        ));
    }

    #[test]
    fn rfc3161_strict_validation_accepts_openssl_time_stamp_token() {
        let token = hex_bytes(OPENSSL_TSA_TOKEN_DER_HEX);
        let imprint_hash = "sha256:80a7a77c0cd501aec2d7694dcc7fdf4cf50a4cab83579fb290924fc8520ba680";
        let input = Rfc3161TimestampBodyInputV1 {
            tenant_id: "tenant-a",
            receipt_id: "tsa_fixture",
            timestamp_id: "timestamp-fixture",
            actor_passport: "passport:operator",
            tsa_url: "https://tsa.example",
            tsa_policy_oid: Some("1.2.3.4"),
            message_imprint_alg: "sha256",
            message_imprint_hash: imprint_hash,
            timestamp_token_der: &token,
            serial_number: Some("02"),
            gen_time: "2026-06-14T10:23:28Z",
            created_at: "2026-06-14T10:23:29Z",
        };
        let (body, _) = build_rfc3161_timestamp_body_v1(&input);
        let root = hex_bytes(OPENSSL_TSA_ROOT_DER_HEX);
        let root_refs = vec![root.as_slice()];
        let nonce = hex_bytes("C23A5AF413E2A2CF");

        let report = verify_rfc3161_timestamp_token_strict_v1(
            &body,
            &Rfc3161StrictValidationOptionsV1 {
                expected_message_imprint_hash: Some(imprint_hash),
                expected_policy_oid: Some("1.2.3.4"),
                expected_nonce: Some(&nonce),
                trusted_root_certs_der: &root_refs,
            },
        );

        assert!(report.ok, "{report:?}");
        assert!(report.token_hash_ok);
        assert!(report.cms_structure_ok);
        assert!(report.content_type_ok);
        assert!(report.signed_attrs_ok);
        assert!(report.message_imprint_ok);
        assert!(report.policy_ok);
        assert!(report.nonce_ok);
        assert!(report.gen_time_ok);
        assert!(report.cms_signature_ok);
        assert!(report.tsa_eku_ok);
        assert!(report.cert_chain_ok);
        assert_eq!(report.tsa_policy_oid.as_deref(), Some("1.2.3.4"));
        assert_eq!(report.gen_time.as_deref(), Some("2026-06-14T10:23:28Z"));
        assert_eq!(report.signer_subject.as_deref(), Some("CN=CueCrux TSA Leaf TEST"));
    }

    #[test]
    fn rfc3161_strict_validation_rejects_wrong_policy_and_nonce() {
        let token = hex_bytes(OPENSSL_TSA_TOKEN_DER_HEX);
        let imprint_hash = "sha256:80a7a77c0cd501aec2d7694dcc7fdf4cf50a4cab83579fb290924fc8520ba680";
        let input = Rfc3161TimestampBodyInputV1 {
            tenant_id: "tenant-a",
            receipt_id: "tsa_fixture",
            timestamp_id: "timestamp-fixture",
            actor_passport: "passport:operator",
            tsa_url: "https://tsa.example",
            tsa_policy_oid: Some("1.2.3.4"),
            message_imprint_alg: "sha256",
            message_imprint_hash: imprint_hash,
            timestamp_token_der: &token,
            serial_number: Some("02"),
            gen_time: "2026-06-14T10:23:28Z",
            created_at: "2026-06-14T10:23:29Z",
        };
        let (body, _) = build_rfc3161_timestamp_body_v1(&input);
        let root = hex_bytes(OPENSSL_TSA_ROOT_DER_HEX);
        let root_refs = vec![root.as_slice()];

        let wrong_policy = verify_rfc3161_timestamp_token_strict_v1(
            &body,
            &Rfc3161StrictValidationOptionsV1 {
                expected_message_imprint_hash: Some(imprint_hash),
                expected_policy_oid: Some("1.2.3.5"),
                expected_nonce: Some(&hex_bytes("C23A5AF413E2A2CF")),
                trusted_root_certs_der: &root_refs,
            },
        );
        assert!(!wrong_policy.ok);
        assert_eq!(
            wrong_policy.failure_reason.as_deref(),
            Some("TSTInfo policy does not match expected or receipt body TSA policy")
        );

        let wrong_nonce = verify_rfc3161_timestamp_token_strict_v1(
            &body,
            &Rfc3161StrictValidationOptionsV1 {
                expected_message_imprint_hash: Some(imprint_hash),
                expected_policy_oid: Some("1.2.3.4"),
                expected_nonce: Some(&hex_bytes("01")),
                trusted_root_certs_der: &root_refs,
            },
        );
        assert!(!wrong_nonce.ok);
        assert_eq!(
            wrong_nonce.failure_reason.as_deref(),
            Some("TSTInfo nonce does not match expected nonce")
        );
    }

    #[test]
    fn object_identifier_text_validation_rejects_malformed_policy_oid() {
        assert!(is_valid_object_identifier_text_v1("1.2.3.4"));
        assert!(is_valid_object_identifier_text_v1(" 1.2.840.113549.1.9.16.1.4 "));
        assert!(!is_valid_object_identifier_text_v1(""));
        assert!(!is_valid_object_identifier_text_v1("1.2"));
        assert!(!is_valid_object_identifier_text_v1("1.2.bad"));
        assert!(!is_valid_object_identifier_text_v1("3.1.1"));
    }

    #[test]
    fn external_anchor_signs_with_receipt_sig_envelope() {
        let (leaf0, leaf1, root) = two_leaf_tree();
        let proof = [hex_lower(&leaf1)];
        let proof_refs = proof.iter().map(String::as_str).collect::<Vec<_>>();
        let (body, hash) =
            build_external_anchor_body_v1(&external_input(&proof_refs, &hex_lower(&leaf0), &hex_lower(&root)));
        let signing_key = SigningKey::from_bytes(&[13u8; 32]);
        let sig = sign_external_anchor_v1("anchor_1", &body, hash, &signing_key, "kid", "2026-06-14T10:00:02Z");
        assert_eq!(sig.signed_payload_hash, hash.to_vec());
        let vk: VerifyingKey = signing_key.verifying_key();
        let sig_bytes: [u8; 64] = sig.signature.as_slice().try_into().unwrap();
        vk.verify_strict(&body, &ed25519_dalek::Signature::from_bytes(&sig_bytes))
            .expect("signature verifies over external anchor body");
    }

    #[test]
    fn timestamp_signs_with_receipt_sig_envelope() {
        let (body, hash) = build_rfc3161_timestamp_body_v1(&timestamp_input(b"token"));
        let signing_key = SigningKey::from_bytes(&[14u8; 32]);
        let sig = sign_rfc3161_timestamp_v1("tsa_1", &body, hash, &signing_key, "kid", "2026-06-14T10:00:02Z");
        assert_eq!(sig.schema, "cuecrux.receipt.sig.v1");
        assert_eq!(sig.alg, "ed25519");
        assert_eq!(sig.signature.len(), 64);
    }

    #[test]
    fn rekor_checkpoint_verifies_against_pinned_key() {
        use base64::Engine as _;
        use ed25519_dalek::Signer as _;
        let sk = SigningKey::from_bytes(&[0x11; 32]);
        let pk = sk.verifying_key().to_bytes();
        let root = [0xAB_u8; 32];
        let root_b64 = base64::engine::general_purpose::STANDARD.encode(root);
        let text = format!("rekor.example\n42\n{root_b64}\n");
        let sig = sk.sign(text.as_bytes()).to_bytes();
        let mut keyhash_sig = vec![0u8; 4];
        keyhash_sig.extend_from_slice(&sig);
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(&keyhash_sig);
        let checkpoint = format!("{text}\n\u{2014} rekor.example {sig_b64}\n");
        let root_hex: String = root.iter().map(|b| format!("{b:02x}")).collect();

        assert!(verify_rekor_checkpoint_v1(&checkpoint, &pk, &root_hex));

        // Wrong log key, wrong expected root, and tampered text each fail.
        let wrong_key = SigningKey::from_bytes(&[0x22; 32]).verifying_key().to_bytes();
        assert!(!verify_rekor_checkpoint_v1(&checkpoint, &wrong_key, &root_hex));
        assert!(!verify_rekor_checkpoint_v1(&checkpoint, &pk, &"cd".repeat(32)));
        let tampered = checkpoint.replace("\n42\n", "\n43\n");
        assert!(!verify_rekor_checkpoint_v1(&tampered, &pk, &root_hex));
    }

    #[test]
    fn rekor_checkpoint_p256_verifies_and_dispatches() {
        use p256::ecdsa::{signature::Signer as _, SigningKey};
        use p256::pkcs8::EncodePublicKey as _;
        let sk = SigningKey::from_slice(&[0x55; 32]).expect("scalar");
        let vk = *sk.verifying_key();
        let root = [0xAB_u8; 32];
        let root_b64 = base64::engine::general_purpose::STANDARD.encode(root);
        let text = format!("rekor.example\n7\n{root_b64}\n");
        let sig: p256::ecdsa::Signature = sk.sign(text.as_bytes());
        let mut keyhash_sig = vec![0u8; 4];
        keyhash_sig.extend_from_slice(sig.to_der().as_bytes());
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(&keyhash_sig);
        let checkpoint = format!("{text}\n\u{2014} rekor.example {sig_b64}\n");
        let root_hex: String = root.iter().map(|b| format!("{b:02x}")).collect();

        assert!(verify_rekor_checkpoint_p256_v1(&checkpoint, &vk, &root_hex));
        // Dispatcher via a key parsed from SPKI PEM (the form Rekor publishes).
        let pem = vk.to_public_key_pem(p256::pkcs8::LineEnding::LF).expect("pem");
        let key = WitnessLogPublicKeyV1::parse(pem.as_bytes()).expect("parse p256 pem");
        assert!(matches!(key, WitnessLogPublicKeyV1::P256(_)));
        assert!(verify_rekor_checkpoint(&checkpoint, &key, &root_hex));
        // Wrong root and tampered text are rejected.
        assert!(!verify_rekor_checkpoint_p256_v1(&checkpoint, &vk, &"cd".repeat(32)));
        assert!(!verify_rekor_checkpoint_p256_v1(
            &checkpoint.replace("\n7\n", "\n8\n"),
            &vk,
            &root_hex
        ));
    }
}
