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

use ciborium::value::Value as CborValue;
use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest as _, Sha256};

use crate::verify_v1::ReceiptSigV1;

pub const WITNESS_BODY_SCHEMA_V1: &str = "cuecrux.receipt.body.v1";
pub const EXTERNAL_ANCHOR_KIND_V1: &str = "external_anchor";
pub const RFC3161_TIMESTAMP_KIND_V1: &str = "rfc3161_timestamp";

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
}
