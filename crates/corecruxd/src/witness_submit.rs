// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Witness submission adapters (Track W / G1).
//!
//! Defines the [`Witness`] trait and its first implementation, [`RekorWitness`],
//! which anchors the current seal-chain head hash into a Sigstore Rekor
//! transparency log as a `hashedrekord` entry and returns the RFC6962 inclusion
//! proof the daemon needs to build an `external_anchor` receipt.
//!
//! Layering: pure receipt-body construction and proof verification live in
//! `corecrux_receipts::witness_v1` (no network). This module is the network
//! transport layer only, and is OFF by default — the daemon only constructs a
//! [`RekorWitness`] when `CORECRUXD_WITNESS_ENABLED=1` and a provider is
//! configured (see [`crate::witness`]). M1 deliberately ships the adapter and
//! its tests without wiring it into the daemon runtime; the background submit
//! task and proof store land in M2.

use std::time::Duration;

use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Provider label recorded on proofs produced by [`RekorWitness`].
pub const REKOR_PROVIDER_V1: &str = "rekor";

/// An RFC6962 inclusion proof returned by a witness submission.
///
/// The fields map one-for-one onto the inputs
/// `corecrux_receipts::ExternalAnchorBodyInputV1` needs to build a signed
/// `external_anchor` receipt body (M2), so callers never have to reshape the
/// transparency-log response by hand.
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
}

/// Failure modes of a witness submission. Network and decode failures are
/// recoverable (the head stays unwitnessed and is retried by the M2 task);
/// [`WitnessError::Inconsistent`] means the log returned a proof that does not
/// verify and must never be persisted as if it did.
#[derive(Debug, thiserror::Error)]
pub enum WitnessError {
    #[error("witness http error: {0}")]
    Http(String),
    #[error("witness response decode error: {0}")]
    Decode(String),
    #[error("witness response contained no log entry")]
    EmptyResponse,
    #[error("witness returned an inclusion proof that does not verify: {0}")]
    Inconsistent(String),
}

/// A transparency-log witness.
///
/// [`Witness::submit`] anchors a 32-byte seal-chain head hash and returns a
/// proof that can be re-checked without trusting the daemon. It is synchronous
/// (blocking): the M2 background task invokes it from a blocking context so the
/// async runtime is never stalled on network I/O.
pub trait Witness: Send + Sync {
    /// Submit `head_hash` (the latest `SegmentSealMaterialV1::material_hash()`)
    /// to the log and return its verified inclusion proof.
    fn submit(&self, head_hash: &[u8; 32]) -> Result<WitnessProofV1, WitnessError>;
}

/// Anchors seal-chain heads into a Sigstore Rekor transparency log.
///
/// Each submission signs the head hash with the daemon's Ed25519 key and writes
/// a `hashedrekord` entry, then maps Rekor's response into a [`WitnessProofV1`]
/// and self-verifies the returned Merkle proof before handing it back.
pub struct RekorWitness {
    agent: ureq::Agent,
    rekor_url: String,
    signing_key: SigningKey,
    public_key_pem_b64: String,
}

impl RekorWitness {
    /// Build a Rekor witness pointing at `rekor_url`, signing entries with
    /// `signing_key`, and bounding every network phase by `timeout`.
    pub fn new(rekor_url: impl Into<String>, signing_key: SigningKey, timeout: Duration) -> Self {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_connect(Some(timeout))
            .timeout_recv_response(Some(timeout))
            .timeout_recv_body(Some(timeout))
            .build()
            .into();
        let public_key_pem = ed25519_spki_pem(&signing_key.verifying_key());
        let public_key_pem_b64 = base64::engine::general_purpose::STANDARD.encode(public_key_pem.as_bytes());
        Self {
            agent,
            rekor_url: rekor_url.into().trim_end_matches('/').to_string(),
            signing_key,
            public_key_pem_b64,
        }
    }

    fn entries_url(&self) -> String {
        format!("{}/api/v1/log/entries", self.rekor_url)
    }

    /// Build the `hashedrekord` create payload for `head_hash`: the SHA-256 of
    /// the head as the artifact digest, an Ed25519 signature over the head, and
    /// the daemon's SPKI public key.
    fn build_request(&self, head_hash: &[u8; 32]) -> HashedRekordCreate {
        let digest_hex = hex::encode(Sha256::digest(head_hash));
        let signature = self.signing_key.sign(head_hash).to_bytes();
        let signature_b64 = base64::engine::general_purpose::STANDARD.encode(signature);
        HashedRekordCreate {
            api_version: "0.0.1",
            kind: "hashedrekord",
            spec: HashedRekordSpec {
                data: HashedRekordData {
                    hash: HashedRekordHash {
                        algorithm: "sha256",
                        value: digest_hex,
                    },
                },
                signature: HashedRekordSignature {
                    content: signature_b64,
                    public_key: HashedRekordPublicKey {
                        content: self.public_key_pem_b64.clone(),
                    },
                },
            },
        }
    }
}

impl Witness for RekorWitness {
    fn submit(&self, head_hash: &[u8; 32]) -> Result<WitnessProofV1, WitnessError> {
        let request = self.build_request(head_hash);
        let request_value = serde_json::to_value(&request).map_err(|e| WitnessError::Decode(e.to_string()))?;

        let mut response = self
            .agent
            .post(&self.entries_url())
            .header("Content-Type", "application/json")
            .send_json(request_value)
            .map_err(|e| WitnessError::Http(e.to_string()))?;

        let entries: std::collections::BTreeMap<String, RekorLogEntry> = response
            .body_mut()
            .read_json()
            .map_err(|e| WitnessError::Decode(e.to_string()))?;

        let (uuid, entry) = entries.into_iter().next().ok_or(WitnessError::EmptyResponse)?;

        let proof = entry.into_proof(uuid, self.rekor_url.clone())?;

        // Never hand back a proof we cannot re-derive ourselves: a lying or
        // garbled log must surface as Inconsistent, not be persisted as if the
        // head were witnessed.
        if !corecrux_receipts::verify_rfc6962_inclusion_proof_v1(
            &proof.leaf_hash,
            proof.log_index,
            proof.tree_size,
            &proof.root_hash,
            &proof.inclusion_proof,
        ) {
            return Err(WitnessError::Inconsistent(format!(
                "leaf {} at index {}/{} does not hash to root {}",
                proof.leaf_hash, proof.log_index, proof.tree_size, proof.root_hash
            )));
        }

        Ok(proof)
    }
}

/// SPKI (`SubjectPublicKeyInfo`) PEM for an Ed25519 verifying key.
///
/// The DER prefix for Ed25519 SPKI is fixed (`AlgorithmIdentifier` with OID
/// 1.3.101.112 and no parameters, then a 32-byte `BIT STRING`), so we emit it
/// directly rather than pulling in the `pkcs8` feature.
fn ed25519_spki_pem(vk: &VerifyingKey) -> String {
    const ED25519_SPKI_PREFIX: [u8; 12] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
    let mut der = Vec::with_capacity(ED25519_SPKI_PREFIX.len() + 32);
    der.extend_from_slice(&ED25519_SPKI_PREFIX);
    der.extend_from_slice(vk.as_bytes());
    let b64 = base64::engine::general_purpose::STANDARD.encode(&der);

    let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        // chunk is ASCII base64, always valid UTF-8.
        pem.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        pem.push('\n');
    }
    pem.push_str("-----END PUBLIC KEY-----\n");
    pem
}

// ---- Rekor wire types ------------------------------------------------------

#[derive(Debug, Serialize)]
struct HashedRekordCreate {
    #[serde(rename = "apiVersion")]
    api_version: &'static str,
    kind: &'static str,
    spec: HashedRekordSpec,
}

#[derive(Debug, Serialize)]
struct HashedRekordSpec {
    data: HashedRekordData,
    signature: HashedRekordSignature,
}

#[derive(Debug, Serialize)]
struct HashedRekordData {
    hash: HashedRekordHash,
}

#[derive(Debug, Serialize)]
struct HashedRekordHash {
    algorithm: &'static str,
    value: String,
}

#[derive(Debug, Serialize)]
struct HashedRekordSignature {
    content: String,
    #[serde(rename = "publicKey")]
    public_key: HashedRekordPublicKey,
}

#[derive(Debug, Serialize)]
struct HashedRekordPublicKey {
    content: String,
}

#[derive(Debug, Deserialize)]
struct RekorLogEntry {
    body: String,
    #[serde(rename = "integratedTime")]
    integrated_time: i64,
    verification: RekorVerification,
}

#[derive(Debug, Deserialize)]
struct RekorVerification {
    #[serde(rename = "inclusionProof")]
    inclusion_proof: RekorInclusionProof,
}

#[derive(Debug, Deserialize)]
struct RekorInclusionProof {
    #[serde(rename = "logIndex")]
    log_index: u64,
    #[serde(rename = "treeSize")]
    tree_size: u64,
    #[serde(rename = "rootHash")]
    root_hash: String,
    hashes: Vec<String>,
    checkpoint: Option<String>,
}

impl RekorLogEntry {
    fn into_proof(self, uuid: String, log_url: String) -> Result<WitnessProofV1, WitnessError> {
        let body_bytes = base64::engine::general_purpose::STANDARD
            .decode(self.body.as_bytes())
            .map_err(|e| WitnessError::Decode(format!("entry body is not base64: {e}")))?;
        // RFC6962 leaf hash: SHA-256 over a 0x00 domain-separation prefix.
        let mut hasher = Sha256::new();
        hasher.update([0x00]);
        hasher.update(&body_bytes);
        let leaf_hash = hex::encode(hasher.finalize());

        let proof = self.verification.inclusion_proof;
        Ok(WitnessProofV1 {
            transparency_log: REKOR_PROVIDER_V1.to_string(),
            log_url,
            rekor_uuid: Some(uuid),
            leaf_hash,
            log_index: proof.log_index,
            tree_size: proof.tree_size,
            root_hash: proof.root_hash,
            inclusion_proof: proof.hashes,
            checkpoint: proof.checkpoint,
            integrated_time: self.integrated_time.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;

    fn test_key() -> SigningKey {
        SigningKey::from_bytes(&[0xab; 32])
    }

    /// RFC6962 leaf hash for an entry body — mirrors `into_proof`.
    fn rfc6962_leaf(body: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update([0x00]);
        hasher.update(body);
        hasher.finalize().into()
    }

    /// RFC6962 interior node hash — `SHA-256(0x01 || left || right)`.
    fn rfc6962_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update([0x01]);
        hasher.update(left);
        hasher.update(right);
        hasher.finalize().into()
    }

    /// One-shot HTTP/1.1 mock that serves `response_body` to the first request
    /// and reports the raw request bytes back on the channel. Mirrors the
    /// `corecrux-memory` sync test harness.
    fn start_mock(
        status_line: &'static str,
        response_body: String,
    ) -> (String, mpsc::Receiver<Vec<u8>>, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (tx, rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("read timeout");
            let mut buf = [0u8; 4096];
            let mut request = Vec::new();
            // Read until we have headers + the full body (small in tests).
            loop {
                match stream.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        request.extend_from_slice(&buf[..n]);
                        if let Some(end) = find_body_end(&request) {
                            if request.len() >= end {
                                break;
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
            let payload = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status_line,
                response_body.len(),
                response_body
            );
            stream.write_all(payload.as_bytes()).expect("write");
            stream.flush().expect("flush");
            let _ = tx.send(request);
        });
        (format!("http://{addr}"), rx, handle)
    }

    /// Returns the offset just past `\r\n\r\n` plus any declared Content-Length.
    fn find_body_end(bytes: &[u8]) -> Option<usize> {
        let header_end = bytes.windows(4).position(|w| w == b"\r\n\r\n")? + 4;
        let headers = String::from_utf8_lossy(&bytes[..header_end]).to_lowercase();
        let content_length = headers
            .lines()
            .find_map(|l| l.strip_prefix("content-length:"))
            .and_then(|v| v.trim().parse::<usize>().ok())
            .unwrap_or(0);
        Some(header_end + content_length)
    }

    fn rekor_response(body_b64: &str, log_index: u64, tree_size: u64, root_hex: &str, hashes: Vec<String>) -> String {
        serde_json::json!({
            "abc123def456": {
                "body": body_b64,
                "integratedTime": 1_700_000_000_i64,
                "logID": "c0ffee",
                "logIndex": 42,
                "verification": {
                    "inclusionProof": {
                        "logIndex": log_index,
                        "treeSize": tree_size,
                        "rootHash": root_hex,
                        "hashes": hashes,
                        "checkpoint": "rekor.example - 1\n2\nrootb64\n"
                    },
                    "signedEntryTimestamp": "c2ln"
                }
            }
        })
        .to_string()
    }

    #[test]
    fn build_request_has_hashedrekord_shape() {
        let witness = RekorWitness::new("https://rekor.example", test_key(), Duration::from_secs(5));
        let head = [0x11u8; 32];
        let req = witness.build_request(&head);
        assert_eq!(req.kind, "hashedrekord");
        assert_eq!(req.api_version, "0.0.1");
        assert_eq!(req.spec.data.hash.algorithm, "sha256");
        assert_eq!(req.spec.data.hash.value, hex::encode(Sha256::digest(head)));
        // Signature verifies against the head with the daemon key.
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(req.spec.signature.content.as_bytes())
            .expect("sig b64");
        let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().expect("64-byte sig");
        let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
        test_key()
            .verifying_key()
            .verify_strict(&head, &sig)
            .expect("daemon signature verifies over the head");
        // Public key is a base64 of a PEM SPKI block.
        let pem = String::from_utf8(
            base64::engine::general_purpose::STANDARD
                .decode(req.spec.signature.public_key.content.as_bytes())
                .expect("pubkey b64"),
        )
        .expect("pem utf8");
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----"));
    }

    #[test]
    fn submit_maps_tree_size_one_proof_and_self_verifies() {
        // Smallest valid RFC6962 proof: tree_size == 1, leaf == root, no path.
        let body = b"canonical-rekor-entry-body";
        let body_b64 = base64::engine::general_purpose::STANDARD.encode(body);
        let leaf = rfc6962_leaf(body);
        let root_hex = hex::encode(leaf);
        let response = rekor_response(&body_b64, 0, 1, &root_hex, vec![]);

        let (url, rx, handle) = start_mock("201 Created", response);
        let witness = RekorWitness::new(url, test_key(), Duration::from_secs(5));
        let proof = witness.submit(&[0x22u8; 32]).expect("submit ok");
        handle.join().expect("join");

        let request = rx.recv().expect("recorded request");
        let request_str = String::from_utf8_lossy(&request);
        assert!(request_str.contains("POST /api/v1/log/entries"));
        assert!(request_str.contains("hashedrekord"));

        assert_eq!(proof.transparency_log, "rekor");
        assert_eq!(proof.tree_size, 1);
        assert_eq!(proof.log_index, 0);
        assert_eq!(proof.leaf_hash, root_hex);
        assert_eq!(proof.rekor_uuid.as_deref(), Some("abc123def456"));
        assert_eq!(proof.integrated_time, "1700000000");
        // The proof submit() returned independently verifies.
        assert!(corecrux_receipts::verify_rfc6962_inclusion_proof_v1(
            &proof.leaf_hash,
            proof.log_index,
            proof.tree_size,
            &proof.root_hash,
            &proof.inclusion_proof,
        ));
    }

    #[test]
    fn submit_maps_tree_size_two_proof_with_sibling() {
        // Two-leaf tree: our entry is leaf 0, sibling is leaf 1.
        let body = b"entry-zero";
        let body_b64 = base64::engine::general_purpose::STANDARD.encode(body);
        let leaf0 = rfc6962_leaf(body);
        let leaf1 = rfc6962_leaf(b"entry-one");
        let root = rfc6962_node(&leaf0, &leaf1);
        let response = rekor_response(&body_b64, 0, 2, &hex::encode(root), vec![hex::encode(leaf1)]);

        let (url, rx, handle) = start_mock("201 Created", response);
        let witness = RekorWitness::new(url, test_key(), Duration::from_secs(5));
        let proof = witness.submit(&[0x33u8; 32]).expect("submit ok");
        handle.join().expect("join");
        let _ = rx.recv();

        assert_eq!(proof.tree_size, 2);
        assert_eq!(proof.inclusion_proof, vec![hex::encode(leaf1)]);
        assert!(corecrux_receipts::verify_rfc6962_inclusion_proof_v1(
            &proof.leaf_hash,
            proof.log_index,
            proof.tree_size,
            &proof.root_hash,
            &proof.inclusion_proof,
        ));
    }

    #[test]
    fn submit_rejects_inconsistent_proof() {
        // Root hash does not match the leaf — submit must refuse it.
        let body = b"entry-bad";
        let body_b64 = base64::engine::general_purpose::STANDARD.encode(body);
        let bogus_root = hex::encode([0xeeu8; 32]);
        let response = rekor_response(&body_b64, 0, 1, &bogus_root, vec![]);

        let (url, _rx, handle) = start_mock("201 Created", response);
        let witness = RekorWitness::new(url, test_key(), Duration::from_secs(5));
        let err = witness.submit(&[0x44u8; 32]).expect_err("must reject");
        handle.join().expect("join");
        assert!(matches!(err, WitnessError::Inconsistent(_)), "got {err:?}");
    }

    #[test]
    fn submit_surfaces_http_errors() {
        let (url, _rx, handle) = start_mock("500 Internal Server Error", "boom".to_string());
        let witness = RekorWitness::new(url, test_key(), Duration::from_secs(5));
        let err = witness.submit(&[0x55u8; 32]).expect_err("must error");
        handle.join().expect("join");
        assert!(matches!(err, WitnessError::Http(_)), "got {err:?}");
    }

    #[test]
    fn ed25519_spki_pem_is_well_formed() {
        let pem = ed25519_spki_pem(&test_key().verifying_key());
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----\n"));
        assert!(pem.trim_end().ends_with("-----END PUBLIC KEY-----"));
    }
}
