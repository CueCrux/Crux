// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
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
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
use p256::pkcs8::EncodePublicKey as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Provider label recorded on proofs produced by [`RekorWitness`].
pub const REKOR_PROVIDER_V1: &str = "rekor";

// The witness inclusion-proof type lives in `corecrux-receipts` (it is a
// receipt artifact, embedded in `audit_bundle_v1` and re-checked by the offline
// bundle verifier). Re-exported here so the daemon's witness modules keep their
// `crate::witness_submit::WitnessProofV1` import path.
pub use corecrux_receipts::WitnessProofV1;

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
    #[error("witness signing error: {0}")]
    Sign(String),
    #[error("witness signer configuration error: {0}")]
    Config(String),
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

/// The witness signing seam (audit-v2 R2 / witness-key-custody). Abstracts *where*
/// the ECDSA P-256 private key lives: `EnvKeySigner` holds it in-process (today's
/// behaviour); a Vault Transit signer keeps it in Vault and never sees the bytes.
///
/// Both `hashedrekord` inputs come from here — the SPKI public-key PEM and a
/// DER-encoded ECDSA-P256/SHA-256 signature over the message.
pub trait WitnessSigner: Send + Sync {
    /// SPKI public-key PEM (LF line endings), resolved once at construction.
    fn public_key_pem(&self) -> String;
    /// ECDSA-P256/SHA-256 signature over `message`, ASN.1 DER-encoded.
    fn sign_der(&self, message: &[u8]) -> Result<Vec<u8>, WitnessError>;
}

/// In-process signer: the P-256 private key lives in the daemon (loaded from
/// `CORECRUXD_WITNESS_SIGNING_KEY`). This is the pre-R2 behaviour, preserved as
/// the default so single-node/dev installs are unaffected.
pub struct EnvKeySigner {
    signing_key: P256SigningKey,
    public_key_pem: String,
}

impl EnvKeySigner {
    pub fn new(signing_key: P256SigningKey) -> Self {
        let public_key_pem = signing_key
            .verifying_key()
            .to_public_key_pem(p256::pkcs8::LineEnding::LF)
            .unwrap_or_default();
        Self {
            signing_key,
            public_key_pem,
        }
    }
}

impl WitnessSigner for EnvKeySigner {
    fn public_key_pem(&self) -> String {
        self.public_key_pem.clone()
    }

    fn sign_der(&self, message: &[u8]) -> Result<Vec<u8>, WitnessError> {
        // ECDSA signing over a valid key is infallible; matches the prior
        // `self.signing_key.sign(head_hash).to_der()` path exactly.
        let signature: P256Signature = self.signing_key.sign(message);
        Ok(signature.to_der().as_bytes().to_vec())
    }
}

/// Env: Vault base address (e.g. `https://vault.internal:8200`).
pub const ENV_VAULT_ADDR: &str = "VAULT_ADDR";
/// Env: Vault token used to authenticate the sign/keys calls.
pub const ENV_VAULT_TOKEN: &str = "VAULT_TOKEN";
/// Env: Transit secrets-engine mount (default `transit`).
pub const ENV_WITNESS_VAULT_MOUNT: &str = "CORECRUXD_WITNESS_VAULT_MOUNT";
/// Env: Transit key name to sign with. Presence of this var selects the Vault signer.
pub const ENV_WITNESS_VAULT_KEY: &str = "CORECRUXD_WITNESS_VAULT_KEY";

/// Off-host signer: the ECDSA P-256 private key lives in Vault's Transit engine
/// and is never loaded into the daemon. Signing is a `POST /v1/{mount}/sign/{key}`
/// with a prehashed=false input (Vault SHA-256s and signs); the daemon only ever
/// sends the head bytes and receives a signature (audit-v2 R2).
pub struct VaultTransitSigner {
    agent: ureq::Agent,
    addr: String,
    token: String,
    mount: String,
    key_name: String,
    public_key_pem: String,
}

impl VaultTransitSigner {
    fn sign_url(&self) -> String {
        format!("{}/v1/{}/sign/{}", self.addr, self.mount, self.key_name)
    }

    fn keys_url(addr: &str, mount: &str, key_name: &str) -> String {
        format!("{addr}/v1/{mount}/keys/{key_name}")
    }

    fn build_agent(timeout: Duration) -> ureq::Agent {
        ureq::Agent::config_builder()
            .timeout_connect(Some(timeout))
            .timeout_recv_response(Some(timeout))
            .timeout_recv_body(Some(timeout))
            .build()
            .into()
    }

    /// Connect to Vault, fetch the Transit key's SPKI public-key PEM (the latest
    /// version), and build the signer. The private key stays in Vault.
    pub fn connect(
        addr: impl Into<String>,
        token: impl Into<String>,
        mount: impl Into<String>,
        key_name: impl Into<String>,
        timeout: Duration,
    ) -> Result<Self, WitnessError> {
        let addr = addr.into().trim_end_matches('/').to_string();
        let token = token.into();
        let mount = mount.into();
        let key_name = key_name.into();
        let agent = Self::build_agent(timeout);

        let mut resp = agent
            .get(&Self::keys_url(&addr, &mount, &key_name))
            .header("X-Vault-Token", &token)
            .call()
            .map_err(|e| WitnessError::Config(format!("vault keys read failed: {e}")))?;
        let body: serde_json::Value = resp
            .body_mut()
            .read_json()
            .map_err(|e| WitnessError::Config(format!("vault keys decode failed: {e}")))?;
        let public_key_pem = Self::extract_public_key_pem(&body)?;

        Ok(Self {
            agent,
            addr,
            token,
            mount,
            key_name,
            public_key_pem,
        })
    }

    /// Build from env (`VAULT_ADDR`, `VAULT_TOKEN`, `CORECRUXD_WITNESS_VAULT_MOUNT`
    /// default `transit`, `CORECRUXD_WITNESS_VAULT_KEY`). Absent addr/token/key →
    /// `Config` error so selection can fall back to the env key.
    pub fn from_env(timeout: Duration) -> Result<Self, WitnessError> {
        let addr = env_nonempty(ENV_VAULT_ADDR)?;
        let token = env_nonempty(ENV_VAULT_TOKEN)?;
        let key_name = env_nonempty(ENV_WITNESS_VAULT_KEY)?;
        let mount = std::env::var(ENV_WITNESS_VAULT_MOUNT)
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "transit".to_string());
        Self::connect(addr, token, mount, key_name, timeout)
    }

    /// Pull the latest version's SPKI public-key PEM out of a Transit key read.
    fn extract_public_key_pem(body: &serde_json::Value) -> Result<String, WitnessError> {
        let data = body
            .get("data")
            .ok_or_else(|| WitnessError::Config("vault keys: no data".into()))?;
        let keys = data
            .get("keys")
            .and_then(|k| k.as_object())
            .ok_or_else(|| WitnessError::Config("vault keys: no keys map".into()))?;
        // Prefer latest_version; else the highest numeric key.
        let version = data
            .get("latest_version")
            .and_then(|v| v.as_u64())
            .map(|v| v.to_string())
            .filter(|v| keys.contains_key(v))
            .or_else(|| {
                keys.keys()
                    .filter_map(|k| k.parse::<u64>().ok())
                    .max()
                    .map(|v| v.to_string())
            })
            .ok_or_else(|| WitnessError::Config("vault keys: no key version".into()))?;
        keys.get(&version)
            .and_then(|v| v.get("public_key"))
            .and_then(|v| v.as_str())
            .filter(|s| s.contains("PUBLIC KEY"))
            .map(str::to_string)
            .ok_or_else(|| WitnessError::Config("vault keys: no SPKI public_key (is the key ecdsa-p256?)".into()))
    }
}

impl WitnessSigner for VaultTransitSigner {
    fn public_key_pem(&self) -> String {
        self.public_key_pem.clone()
    }

    fn sign_der(&self, message: &[u8]) -> Result<Vec<u8>, WitnessError> {
        // prehashed=false: Vault SHA-256s `input` then signs, matching the
        // EnvKeySigner path (ECDSA over the raw message). asn1 marshaling → DER,
        // the exact wire shape Rekor's hashedrekord expects.
        let body = serde_json::json!({
            "input": base64::engine::general_purpose::STANDARD.encode(message),
            "hash_algorithm": "sha2-256",
            "prehashed": false,
            "marshaling_algorithm": "asn1",
        });
        let mut resp = self
            .agent
            .post(&self.sign_url())
            .header("X-Vault-Token", &self.token)
            .send_json(body)
            .map_err(|e| WitnessError::Sign(format!("vault sign request failed: {e}")))?;
        let value: serde_json::Value = resp
            .body_mut()
            .read_json()
            .map_err(|e| WitnessError::Sign(format!("vault sign decode failed: {e}")))?;
        let signature = value
            .get("data")
            .and_then(|d| d.get("signature"))
            .and_then(|s| s.as_str())
            .ok_or_else(|| WitnessError::Sign("vault sign response missing data.signature".into()))?;
        // Format: `vault:v<N>:<base64-der>`. The base64 alphabet has no ':'.
        let b64 = signature
            .rsplit(':')
            .next()
            .ok_or_else(|| WitnessError::Sign("malformed vault signature".into()))?;
        base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| WitnessError::Sign(format!("vault signature base64 decode failed: {e}")))
    }
}

/// Read a required non-empty env var, mapping absence/blank to a `Config` error.
fn env_nonempty(name: &str) -> Result<String, WitnessError> {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| WitnessError::Config(format!("{name} is unset")))
}

/// Anchors seal-chain heads into a Sigstore Rekor transparency log.
///
/// Each submission signs the head hash via its [`WitnessSigner`] and writes a
/// `hashedrekord` entry, then maps Rekor's response into a [`WitnessProofV1`] and
/// self-verifies the returned Merkle proof before handing it back.
pub struct RekorWitness {
    agent: ureq::Agent,
    rekor_url: String,
    signer: Box<dyn WitnessSigner>,
    public_key_pem_b64: String,
}

impl RekorWitness {
    /// Build a Rekor witness pointing at `rekor_url`, signing entries with the
    /// ECDSA P-256 `signing_key`, and bounding every network phase by `timeout`.
    ///
    /// P-256 (not the daemon's Ed25519 seal key) because Sigstore Rekor's
    /// `hashedrekord` verification rejects plain-Ed25519 signatures and accepts
    /// ECDSA-P256/SHA-256 (verified against live Rekor staging; see ExecPlan M4).
    ///
    /// Build a witness around any [`WitnessSigner`] (in-process key, Vault Transit, …).
    pub fn with_signer(rekor_url: impl Into<String>, signer: Box<dyn WitnessSigner>, timeout: Duration) -> Self {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_connect(Some(timeout))
            .timeout_recv_response(Some(timeout))
            .timeout_recv_body(Some(timeout))
            .build()
            .into();
        let public_key_pem_b64 = base64::engine::general_purpose::STANDARD.encode(signer.public_key_pem().as_bytes());
        Self {
            agent,
            rekor_url: rekor_url.into().trim_end_matches('/').to_string(),
            signer,
            public_key_pem_b64,
        }
    }

    fn entries_url(&self) -> String {
        format!("{}/api/v1/log/entries", self.rekor_url)
    }

    /// Build the `hashedrekord` create payload for `head_hash`: the SHA-256 of
    /// the head as the artifact digest, an ECDSA-P256/SHA-256 (DER) signature
    /// over the head, and the witness's SPKI public key.
    fn build_request(&self, head_hash: &[u8; 32]) -> Result<HashedRekordCreate, WitnessError> {
        let digest_hex = hex::encode(Sha256::digest(head_hash));
        let signature_der = self.signer.sign_der(head_hash)?;
        let signature_b64 = base64::engine::general_purpose::STANDARD.encode(&signature_der);
        Ok(HashedRekordCreate {
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
        })
    }
}

impl Witness for RekorWitness {
    fn submit(&self, head_hash: &[u8; 32]) -> Result<WitnessProofV1, WitnessError> {
        let request = self.build_request(head_hash)?;
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

        let proof = entry.into_proof(uuid, self.rekor_url.clone(), hex::encode(head_hash))?;

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

        // Bind the proof to the head we submitted: the log entry must commit to it.
        if !corecrux_receipts::verify_witness_binding_v1(&proof) {
            return Err(WitnessError::Inconsistent(format!(
                "witness proof is not bound to head {}",
                proof.head_hash
            )));
        }

        Ok(proof)
    }
}

/// Environment variable holding the witness's ECDSA P-256 signing key.
pub const WITNESS_SIGNING_KEY_ENV: &str = "CORECRUXD_WITNESS_SIGNING_KEY";

/// Load the witness's ECDSA P-256 signing key from
/// [`WITNESS_SIGNING_KEY_ENV`] (base64 of a 32-byte P-256 scalar). Separate from
/// the daemon's Ed25519 seal key because Rekor's `hashedrekord` verification
/// requires ECDSA P-256. Returns `None` when unset/empty/invalid (the witness
/// task then logs and idles — heads stay pending).
///
/// **Custody note (audit-v2 R2):** this path holds the raw private key **in the
/// daemon's process environment** — readable via a core dump, `docker inspect`,
/// or host access. For off-host custody, provision the key in Vault Transit and
/// set `CORECRUXD_WITNESS_VAULT_KEY` (+ `VAULT_ADDR`/`VAULT_TOKEN`) — see
/// [`VaultTransitSigner`] / [`select_witness_signer`]. Migration: import the key
/// into Transit **or** issue a fresh witness key there and re-anchor from the new
/// identity; the env-key path stays the default so nothing breaks unattended.
pub fn load_witness_signing_key() -> Option<P256SigningKey> {
    let encoded = std::env::var(WITNESS_SIGNING_KEY_ENV).ok()?;
    let encoded = encoded.trim();
    if encoded.is_empty() {
        return None;
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(encoded))
        .ok()?;
    P256SigningKey::from_slice(&decoded).ok()
}

/// Select the witness signer by config precedence (witness-custody M3):
///
/// 1. **Vault Transit** when `CORECRUXD_WITNESS_VAULT_KEY` is set (with
///    `VAULT_ADDR`/`VAULT_TOKEN`) — the private key never enters the process. A
///    misconfigured or unreachable Vault **logs and falls through** to the env
///    key rather than silently dropping the witness.
/// 2. else the **in-process env key** (`CORECRUXD_WITNESS_SIGNING_KEY`) — the
///    pre-R2 default, unchanged.
/// 3. else `None` — no key, heads stay pending (unchanged).
pub fn select_witness_signer(timeout: Duration) -> Option<Box<dyn WitnessSigner>> {
    if std::env::var(ENV_WITNESS_VAULT_KEY)
        .ok()
        .is_some_and(|v| !v.trim().is_empty())
    {
        match VaultTransitSigner::from_env(timeout) {
            Ok(signer) => {
                tracing::info!("witness: signing via Vault Transit (private key stays off-host)");
                return Some(Box::new(signer));
            }
            Err(e) => {
                tracing::warn!(error = %e, "witness: Vault Transit signer unavailable; falling back to env key");
            }
        }
    }
    if let Some(key) = load_witness_signing_key() {
        tracing::info!("witness: signing via in-process env key (CORECRUXD_WITNESS_SIGNING_KEY)");
        return Some(Box::new(EnvKeySigner::new(key)));
    }
    None
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
    fn into_proof(self, uuid: String, log_url: String, head_hash: String) -> Result<WitnessProofV1, WitnessError> {
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
            head_hash,
            entry_body_b64: self.body,
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

    fn test_key() -> P256SigningKey {
        P256SigningKey::from_slice(&[0x42; 32]).expect("valid p256 scalar")
    }

    fn rekor_with_key(url: impl Into<String>, key: P256SigningKey, timeout: Duration) -> RekorWitness {
        RekorWitness::with_signer(url, Box::new(EnvKeySigner::new(key)), timeout)
    }

    #[test]
    fn env_key_signer_matches_direct_key_path() {
        // M1 gate: the seam is a pure refactor — EnvKeySigner must produce exactly
        // what the old `signing_key.sign(head).to_der()` path produced, and a public
        // key PEM identical to the direct `to_public_key_pem` path.
        let key = test_key();
        let head = [0x7u8; 32];

        let expected_sig: P256Signature = key.sign(&head);
        let signer = EnvKeySigner::new(key.clone());
        assert_eq!(
            signer.sign_der(&head).expect("sign"),
            expected_sig.to_der().as_bytes().to_vec(),
            "EnvKeySigner DER signature must match the direct-key path"
        );
        assert_eq!(
            signer.public_key_pem(),
            key.verifying_key()
                .to_public_key_pem(p256::pkcs8::LineEnding::LF)
                .unwrap(),
            "EnvKeySigner public key PEM must match the direct-key path"
        );

        // And the produced signature verifies over the head under the key.
        use p256::ecdsa::signature::Verifier as _;
        let sig = P256Signature::from_der(&signer.sign_der(&head).unwrap()).expect("der");
        key.verifying_key().verify(&head, &sig).expect("must verify");
    }

    fn vault_signer_at(url: String, key: &P256SigningKey) -> VaultTransitSigner {
        VaultTransitSigner {
            agent: VaultTransitSigner::build_agent(Duration::from_secs(2)),
            addr: url,
            token: "test-token".into(),
            mount: "transit".into(),
            key_name: "witness".into(),
            public_key_pem: key
                .verifying_key()
                .to_public_key_pem(p256::pkcs8::LineEnding::LF)
                .unwrap(),
        }
    }

    #[test]
    fn vault_transit_signer_returns_verifiable_der_and_never_sends_the_key() {
        // M2 gate: the signer sends only the message input, gets back a signature
        // that verifies under the Transit public key, and NEVER transmits the key.
        use p256::ecdsa::signature::Verifier as _;
        let key = test_key();
        let message = [0x9u8; 32];
        let signature: P256Signature = key.sign(&message);
        let der = signature.to_der().as_bytes().to_vec();
        let vault_sig = format!("vault:v1:{}", base64::engine::general_purpose::STANDARD.encode(&der));
        let body = serde_json::json!({ "data": { "signature": vault_sig } }).to_string();
        let (url, rx, handle) = start_mock("200 OK", body);

        let signer = vault_signer_at(url, &key);
        let got = signer.sign_der(&message).expect("sign");
        assert_eq!(got, der, "returned DER must be the Vault signature");
        let sig = P256Signature::from_der(&got).expect("der");
        key.verifying_key()
            .verify(&message, &sig)
            .expect("must verify under the transit pubkey");

        let request = String::from_utf8_lossy(&rx.recv_timeout(Duration::from_secs(2)).expect("request")).to_string();
        handle.join().ok();
        assert!(
            request.contains(&base64::engine::general_purpose::STANDARD.encode(message)),
            "request must carry the base64 message input"
        );
        assert!(
            !request.contains(&hex::encode(key.to_bytes())),
            "the private key scalar must NEVER appear in the request"
        );
    }

    #[test]
    fn vault_transit_signer_error_degrades_not_panics() {
        let key = test_key();
        let (url, _rx, handle) = start_mock("500 Internal Server Error", "{\"errors\":[\"boom\"]}".into());
        let err = vault_signer_at(url, &key).sign_der(&[0x1u8; 32]).unwrap_err();
        assert!(
            matches!(err, WitnessError::Sign(_)),
            "vault failure must map to Sign, not panic"
        );
        handle.join().ok();
    }

    #[test]
    #[serial_test::serial]
    fn select_witness_signer_precedence() {
        // M3: no config -> None (heads pending, unchanged).
        std::env::remove_var(ENV_WITNESS_VAULT_KEY);
        std::env::remove_var(WITNESS_SIGNING_KEY_ENV);
        assert!(select_witness_signer(Duration::from_secs(1)).is_none());

        // env key present, no Vault -> Some (in-process EnvKeySigner).
        std::env::set_var(
            WITNESS_SIGNING_KEY_ENV,
            base64::engine::general_purpose::STANDARD.encode([0x42u8; 32]),
        );
        assert!(select_witness_signer(Duration::from_secs(1)).is_some());
        std::env::remove_var(WITNESS_SIGNING_KEY_ENV);
    }

    #[test]
    fn extract_public_key_pem_reads_latest_version() {
        let pem = "-----BEGIN PUBLIC KEY-----\nMFkw...\n-----END PUBLIC KEY-----\n";
        let body = serde_json::json!({
            "data": { "latest_version": 2, "keys": { "1": { "public_key": "stale" }, "2": { "public_key": pem } } }
        });
        assert_eq!(VaultTransitSigner::extract_public_key_pem(&body).unwrap(), pem);
        // A non-ecdsa key read (no SPKI) must be a Config error, not a silent empty.
        let bad = serde_json::json!({ "data": { "latest_version": 1, "keys": { "1": { "name": "aes256" } } } });
        assert!(matches!(
            VaultTransitSigner::extract_public_key_pem(&bad),
            Err(WitnessError::Config(_))
        ));
    }

    /// RFC6962 leaf hash for an entry body — mirrors `into_proof`.
    fn rfc6962_leaf(body: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update([0x00]);
        hasher.update(body);
        hasher.finalize().into()
    }

    /// A minimal `hashedrekord` entry body whose artifact digest commits to
    /// `head`, so the witness binding check holds (mirrors real Rekor).
    fn hashedrekord_body(head: &[u8; 32]) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "apiVersion": "0.0.1",
            "kind": "hashedrekord",
            "spec": { "data": { "hash": { "algorithm": "sha256", "value": hex::encode(Sha256::digest(head)) } } }
        }))
        .expect("body json")
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
        let witness = rekor_with_key("https://rekor.example", test_key(), Duration::from_secs(5));
        let head = [0x11u8; 32];
        let req = witness.build_request(&head).expect("build_request");
        assert_eq!(req.kind, "hashedrekord");
        assert_eq!(req.api_version, "0.0.1");
        assert_eq!(req.spec.data.hash.algorithm, "sha256");
        assert_eq!(req.spec.data.hash.value, hex::encode(Sha256::digest(head)));
        // Signature is a DER ECDSA-P256 sig that verifies over the head.
        use p256::ecdsa::signature::Verifier as _;
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(req.spec.signature.content.as_bytes())
            .expect("sig b64");
        let sig = P256Signature::from_der(&sig_bytes).expect("der sig");
        test_key()
            .verifying_key()
            .verify(&head, &sig)
            .expect("p256 signature verifies over the head");
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
        let head = [0x22u8; 32];
        let body = hashedrekord_body(&head);
        let body_b64 = base64::engine::general_purpose::STANDARD.encode(&body);
        let leaf = rfc6962_leaf(&body);
        let root_hex = hex::encode(leaf);
        let response = rekor_response(&body_b64, 0, 1, &root_hex, vec![]);

        let (url, rx, handle) = start_mock("201 Created", response);
        let witness = rekor_with_key(url, test_key(), Duration::from_secs(5));
        let proof = witness.submit(&head).expect("submit ok");
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
        let head = [0x33u8; 32];
        let body = hashedrekord_body(&head);
        let body_b64 = base64::engine::general_purpose::STANDARD.encode(&body);
        let leaf0 = rfc6962_leaf(&body);
        let leaf1 = rfc6962_leaf(b"entry-one");
        let root = rfc6962_node(&leaf0, &leaf1);
        let response = rekor_response(&body_b64, 0, 2, &hex::encode(root), vec![hex::encode(leaf1)]);

        let (url, rx, handle) = start_mock("201 Created", response);
        let witness = rekor_with_key(url, test_key(), Duration::from_secs(5));
        let proof = witness.submit(&head).expect("submit ok");
        handle.join().expect("join");
        let _ = rx.recv();

        assert_eq!(proof.tree_size, 2);
        assert_eq!(proof.head_hash, hex::encode(head));
        assert!(
            corecrux_receipts::verify_witness_binding_v1(&proof),
            "proof binds to head"
        );
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
        let witness = rekor_with_key(url, test_key(), Duration::from_secs(5));
        let err = witness.submit(&[0x44u8; 32]).expect_err("must reject");
        handle.join().expect("join");
        assert!(matches!(err, WitnessError::Inconsistent(_)), "got {err:?}");
    }

    #[test]
    fn submit_surfaces_http_errors() {
        let (url, _rx, handle) = start_mock("500 Internal Server Error", "boom".to_string());
        let witness = rekor_with_key(url, test_key(), Duration::from_secs(5));
        let err = witness.submit(&[0x55u8; 32]).expect_err("must error");
        handle.join().expect("join");
        assert!(matches!(err, WitnessError::Http(_)), "got {err:?}");
    }

    #[test]
    #[ignore = "hits live Rekor staging over the network; run with --ignored"]
    fn live_submit_to_rekor_staging_p256() {
        // Real end-to-end: the reworked P-256 adapter submits to Sigstore Rekor
        // staging and the returned inclusion proof self-verifies (RFC6962).
        let witness = rekor_with_key(
            "https://rekor.sigstage.dev",
            P256SigningKey::from_slice(&[0x3c; 32]).expect("scalar"),
            Duration::from_secs(30),
        );
        // Vary the head per run (env seed) to avoid Rekor duplicate-entry 409s.
        let seed = std::env::var("CRUX_LIVE_REKOR_SEED").unwrap_or_else(|_| "default-seed".to_string());
        let head: [u8; 32] = Sha256::digest(seed.as_bytes()).into();
        let proof = witness.submit(&head).expect("live submit + self-verify");
        assert_eq!(proof.transparency_log, "rekor");
        assert!(proof.tree_size >= 1);
        assert!(proof.checkpoint.is_some());
        assert!(proof.rekor_uuid.is_some());
        assert_eq!(proof.head_hash, hex::encode(head));
        assert!(
            corecrux_receipts::verify_witness_binding_v1(&proof),
            "real Rekor proof binds to the submitted head"
        );
    }
}
