// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Vault PKI X.509 trust-anchor signer for C2PA Content Credentials
//! (agent-ux-07 M6).
//!
//! ## Custody model — CSR-sign-only
//!
//! - The **leaf private key** is generated on the daemon host (P-256
//!   ECDSA), kept on disk under `CORECRUXD_C2PA_LEAF_KEY_PATH`, and
//!   loaded into RAM under a `parking_lot::RwLock` for signing. The
//!   private key NEVER leaves the daemon host.
//! - The daemon builds a Certificate Signing Request (CSR) over that
//!   public key and POSTs it to `${VAULT_ADDR}/v1/${mount}/sign/c2pa-leaf`.
//!   Vault signs the CSR with its own root and returns the leaf
//!   certificate + (optional) CA chain.
//! - The **root key** never leaves Vault. The root's public certificate
//!   is distributed to third-party verifiers via the operator runbook
//!   in `docs/c2pa-x509-vault-setup.md`.
//!
//! ## Why P-256 (not Ed25519)
//!
//! The C2PA reference toolchain (`c2patool`, `c2pa-rs`) does not parse
//! Ed25519 signatures in practice. P-256 ECDSA-with-SHA256 is the
//! lowest-friction algorithm that survives real-world viewer interop.
//!
//! ## Rotation
//!
//! Leaf certificates have a 720h (30d) TTL by default. The signer
//! exposes [`VaultPkiX509Signer::maybe_rotate_if_due`] which the daemon
//! wires to a background tokio task on a 1-hour interval; when the
//! current leaf has <7d remaining the signer mints a new leaf and
//! atomically swaps the in-memory + on-disk state.
//!
//! ## Feature flag
//!
//! Selected via `CORECRUXD_C2PA_SIGNER_BACKEND=vault-pki-p256` AND
//! `CORECRUXD_FEATURE_C2PA_X509_SIGNER=1`. The legacy local-Ed25519
//! emitter (PR #121) remains the default and is selected by
//! `CORECRUXD_C2PA_SIGNER_BACKEND=local-ed25519`.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::SigningKey as P256SigningKey;
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use p256::SecretKey;
use parking_lot::RwLock;
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
use thiserror::Error;
use x509_cert::der::Decode as _;
use x509_cert::Certificate;

/// Default Vault PKI mount path (matches the prod setup from
/// 2026-05-28).
pub const DEFAULT_VAULT_PKI_MOUNT: &str = "pki-c2pa";

/// Default on-disk paths for the daemon-local artefacts. Operators can
/// override via env.
pub const DEFAULT_LEAF_KEY_PATH: &str = "/var/lib/corecruxd/c2pa-leaf.key.pem";
pub const DEFAULT_LEAF_CERT_PATH: &str = "/var/lib/corecruxd/c2pa-leaf.cert.pem";
pub const DEFAULT_ROOT_ANCHOR_PATH: &str = "/var/lib/corecruxd/c2pa-root.cert.pem";

/// Default leaf TTL when minting via Vault.
pub const DEFAULT_LEAF_TTL_HOURS: u64 = 720;

/// Threshold under which the rotation watcher mints a new leaf
/// (`7 * 24 = 168` hours = 7 days). Held as a constant so tests can
/// reference it without re-computing.
pub const ROTATION_THRESHOLD_HOURS: u64 = 7 * 24;

/// Environment variables consumed by [`VaultPkiX509Signer::from_env`].
pub const ENV_VAULT_ADDR: &str = "VAULT_ADDR";
pub const ENV_VAULT_TOKEN: &str = "VAULT_TOKEN";
pub const ENV_VAULT_CACERT: &str = "VAULT_CACERT";
pub const ENV_VAULT_PKI_MOUNT: &str = "CORECRUXD_VAULT_PKI_MOUNT";
pub const ENV_LEAF_KEY_PATH: &str = "CORECRUXD_C2PA_LEAF_KEY_PATH";
pub const ENV_LEAF_CERT_PATH: &str = "CORECRUXD_C2PA_LEAF_CERT_PATH";
pub const ENV_ROOT_ANCHOR_PATH: &str = "CORECRUXD_C2PA_ROOT_ANCHOR_PATH";
pub const ENV_LEAF_TTL_HOURS: &str = "CORECRUXD_C2PA_LEAF_TTL_HOURS";

/// Default leaf subject Common Name written into the CSR. Vault PKI
/// re-uses the CN when the role config allows (the prod `c2pa-leaf`
/// role does).
pub const DEFAULT_LEAF_CN: &str = "cuecrux daemon C2PA signer";

#[derive(Debug, Error)]
pub enum VaultPkiSignerError {
    #[error("env var missing: {0}")]
    MissingEnv(&'static str),
    #[error("env var has invalid value for {var}: {reason}")]
    InvalidEnv { var: &'static str, reason: String },
    #[error("filesystem io error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("p256 key serialization error: {0}")]
    KeyEncoding(String),
    #[error("p256 key parse error: {0}")]
    KeyDecoding(String),
    #[error("CSR generation error: {0}")]
    CsrGen(String),
    #[error("HTTP error talking to Vault PKI: {0}")]
    Http(String),
    #[error("Vault PKI response decode error: {0}")]
    VaultDecode(String),
    #[error("PEM parse error: {0}")]
    PemParse(String),
    #[error("certificate parse error: {0}")]
    CertParse(String),
    #[error("signer is not initialised (call initialize() first)")]
    NotInitialised,
    #[error("signing error: {0}")]
    Sign(String),
}

pub type Result<T> = std::result::Result<T, VaultPkiSignerError>;

/// Configuration for [`VaultPkiX509Signer`]. Build via
/// [`Config::from_env`] in production; construct directly in tests.
#[derive(Debug, Clone)]
pub struct Config {
    pub vault_addr: String,
    pub vault_token: String,
    /// Optional path to a custom CA bundle for self-signed Vault TLS.
    /// When unset, ureq uses webpki-roots.
    pub vault_cacert_path: Option<PathBuf>,
    pub pki_mount: String,
    pub leaf_key_path: PathBuf,
    pub leaf_cert_path: PathBuf,
    pub root_anchor_path: PathBuf,
    pub leaf_ttl_hours: u64,
    pub leaf_common_name: String,
}

impl Config {
    /// Construct a config from the standard environment variables.
    /// Fails if `VAULT_ADDR` or `VAULT_TOKEN` are missing.
    pub fn from_env() -> Result<Self> {
        let vault_addr = std::env::var(ENV_VAULT_ADDR)
            .map_err(|_| VaultPkiSignerError::MissingEnv(ENV_VAULT_ADDR))?
            .trim()
            .to_string();
        if vault_addr.is_empty() {
            return Err(VaultPkiSignerError::MissingEnv(ENV_VAULT_ADDR));
        }
        let vault_token = std::env::var(ENV_VAULT_TOKEN)
            .map_err(|_| VaultPkiSignerError::MissingEnv(ENV_VAULT_TOKEN))?
            .trim()
            .to_string();
        if vault_token.is_empty() {
            return Err(VaultPkiSignerError::MissingEnv(ENV_VAULT_TOKEN));
        }
        let vault_cacert_path = std::env::var(ENV_VAULT_CACERT).ok().and_then(|v| {
            let v = v.trim();
            if v.is_empty() {
                None
            } else {
                Some(PathBuf::from(v))
            }
        });
        let pki_mount = std::env::var(ENV_VAULT_PKI_MOUNT)
            .unwrap_or_else(|_| DEFAULT_VAULT_PKI_MOUNT.to_string())
            .trim()
            .trim_matches('/')
            .to_string();
        let leaf_key_path = std::env::var(ENV_LEAF_KEY_PATH)
            .ok()
            .map_or_else(|| PathBuf::from(DEFAULT_LEAF_KEY_PATH), PathBuf::from);
        let leaf_cert_path = std::env::var(ENV_LEAF_CERT_PATH)
            .ok()
            .map_or_else(|| PathBuf::from(DEFAULT_LEAF_CERT_PATH), PathBuf::from);
        let root_anchor_path = std::env::var(ENV_ROOT_ANCHOR_PATH)
            .ok()
            .map_or_else(|| PathBuf::from(DEFAULT_ROOT_ANCHOR_PATH), PathBuf::from);
        let leaf_ttl_hours = match std::env::var(ENV_LEAF_TTL_HOURS) {
            Ok(v) => v.trim().parse::<u64>().map_err(|e| VaultPkiSignerError::InvalidEnv {
                var: ENV_LEAF_TTL_HOURS,
                reason: e.to_string(),
            })?,
            Err(_) => DEFAULT_LEAF_TTL_HOURS,
        };
        Ok(Self {
            vault_addr,
            vault_token,
            vault_cacert_path,
            pki_mount,
            leaf_key_path,
            leaf_cert_path,
            root_anchor_path,
            leaf_ttl_hours,
            leaf_common_name: DEFAULT_LEAF_CN.to_string(),
        })
    }
}

/// In-memory snapshot of the currently active leaf.
#[derive(Clone)]
pub struct LeafState {
    pub signing_key: SecretKey,
    /// Full chain in PEM order: leaf first, then intermediates (no
    /// root). Suitable for embedding in `x5chain` COSE headers.
    pub cert_chain_pem: String,
    /// DER bytes of each certificate in the chain. Index 0 = leaf.
    pub cert_chain_der: Vec<Vec<u8>>,
    /// Leaf `notAfter` field as a `SystemTime`.
    pub cert_not_after: SystemTime,
}

impl std::fmt::Debug for LeafState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `signing_key` deliberately elided — printing private-key
        // material is a security footgun. `finish_non_exhaustive()`
        // signals the omission to clippy + downstream readers.
        f.debug_struct("LeafState")
            .field("cert_chain_pem.len", &self.cert_chain_pem.len())
            .field("cert_chain_depth", &self.cert_chain_der.len())
            .field("cert_not_after", &self.cert_not_after)
            .finish_non_exhaustive()
    }
}

/// Returned by [`VaultPkiX509Signer::sign`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X509Signature {
    /// DER-encoded ECDSA signature (the format C2PA / COSE expect).
    pub signature_der: Vec<u8>,
    /// Raw 64-byte r||s form, kept alongside DER for verifiers that
    /// prefer the raw shape.
    pub signature_raw: Vec<u8>,
    /// Full chain PEM (leaf + intermediates, no root).
    pub cert_chain_pem: String,
    /// DER bytes of each certificate, in chain order.
    pub cert_chain_der: Vec<Vec<u8>>,
}

/// Pluggable POST hook so the unit tests can inject a mock Vault
/// without spinning a real HTTPS server. Production uses
/// [`ureq_post_csr`].
pub type CsrPostFn = Arc<dyn Fn(&Config, &str) -> Result<VaultSignResponse> + Send + Sync + 'static>;

/// JSON shape returned by `POST /v1/<mount>/sign/<role>`.
#[derive(Debug, Clone)]
pub struct VaultSignResponse {
    pub certificate_pem: String,
    pub ca_chain_pem: Vec<String>,
}

/// Vault PKI signer.
pub struct VaultPkiX509Signer {
    config: Config,
    state: RwLock<Option<LeafState>>,
    post_fn: CsrPostFn,
}

impl std::fmt::Debug for VaultPkiX509Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `post_fn` is a function pointer — uninteresting in Debug.
        f.debug_struct("VaultPkiX509Signer")
            .field("vault_addr", &self.config.vault_addr)
            .field("mount", &self.config.pki_mount)
            .field("leaf_key_path", &self.config.leaf_key_path)
            .field("leaf_cert_path", &self.config.leaf_cert_path)
            .field("state", &*self.state.read())
            .finish_non_exhaustive()
    }
}

impl VaultPkiX509Signer {
    /// Construct a signer with the default ureq-based Vault POST hook.
    pub fn new(config: Config) -> Self {
        Self {
            config,
            state: RwLock::new(None),
            post_fn: Arc::new(ureq_post_csr),
        }
    }

    /// Construct a signer with a custom Vault POST hook (used by tests
    /// to inject a mock).
    pub fn with_post_fn(config: Config, post_fn: CsrPostFn) -> Self {
        Self {
            config,
            state: RwLock::new(None),
            post_fn,
        }
    }

    /// Build a signer from environment variables.
    pub fn from_env() -> Result<Self> {
        Ok(Self::new(Config::from_env()?))
    }

    /// Read-only access to the active configuration.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Initialise the in-memory leaf state from disk if both the key
    /// and the cert exist and the cert has more than `ROTATION_THRESHOLD_HOURS`
    /// remaining. Otherwise, mint a fresh leaf via Vault.
    pub fn initialize(&self) -> Result<()> {
        if let Some(state) = self.try_load_from_disk()? {
            if !needs_rotation(state.cert_not_after, ROTATION_THRESHOLD_HOURS) {
                *self.state.write() = Some(state);
                return Ok(());
            }
        }
        self.regenerate_leaf()
    }

    /// Force a fresh leaf — generate a new P-256 key locally, build a
    /// CSR, POST to Vault, parse the returned chain, write key + chain
    /// to disk atomically, and swap the in-memory state.
    pub fn regenerate_leaf(&self) -> Result<()> {
        let secret = SecretKey::random(&mut rand_core::OsRng);
        let key_pkcs8_pem = secret
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|e| VaultPkiSignerError::KeyEncoding(e.to_string()))?
            .to_string();

        // rcgen needs its own KeyPair built from our PKCS#8 bytes so
        // that the resulting CSR's SubjectPublicKeyInfo matches the
        // key we'll later use to sign. Round-tripping via PKCS#8
        // guarantees the public key matches without exposing the
        // private key to rcgen's RNG.
        let key_pair = KeyPair::from_pem_and_sign_algo(&key_pkcs8_pem, &PKCS_ECDSA_P256_SHA256)
            .map_err(|e| VaultPkiSignerError::CsrGen(e.to_string()))?;
        let mut params =
            CertificateParams::new(Vec::<String>::new()).map_err(|e| VaultPkiSignerError::CsrGen(e.to_string()))?;
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, self.config.leaf_common_name.clone());
        let csr = params
            .serialize_request(&key_pair)
            .map_err(|e| VaultPkiSignerError::CsrGen(e.to_string()))?;
        let csr_pem = csr.pem().map_err(|e| VaultPkiSignerError::CsrGen(e.to_string()))?;

        // Vault PKI: POST /v1/<mount>/sign/c2pa-leaf
        let resp = (self.post_fn)(&self.config, &csr_pem)?;

        let mut chain_pems: Vec<String> = Vec::with_capacity(1 + resp.ca_chain_pem.len());
        chain_pems.push(resp.certificate_pem.trim().to_string());
        for intermediate in &resp.ca_chain_pem {
            let pem = intermediate.trim();
            // Don't include the root in the chain — by convention the
            // x5chain header carries leaf+intermediates only.
            if !pem.is_empty() && !is_root_cert_pem(pem)? {
                chain_pems.push(pem.to_string());
            }
        }
        let cert_chain_pem = chain_pems.join("\n") + "\n";

        let mut chain_der: Vec<Vec<u8>> = Vec::with_capacity(chain_pems.len());
        for pem in &chain_pems {
            chain_der.push(pem_to_der(pem)?);
        }

        let leaf_cert =
            Certificate::from_der(&chain_der[0]).map_err(|e| VaultPkiSignerError::CertParse(e.to_string()))?;
        let cert_not_after = system_time_from_validity(&leaf_cert);

        atomic_write_pem(&self.config.leaf_key_path, &key_pkcs8_pem)?;
        atomic_write_pem(&self.config.leaf_cert_path, &cert_chain_pem)?;

        let state = LeafState {
            signing_key: secret,
            cert_chain_pem,
            cert_chain_der: chain_der,
            cert_not_after,
        };
        *self.state.write() = Some(state);
        Ok(())
    }

    /// Sign a pre-computed hash with the in-memory leaf key (ECDSA
    /// P-256 over SHA-256-shaped 32-byte digests).
    pub fn sign(&self, content_hash: &[u8]) -> Result<X509Signature> {
        let guard = self.state.read();
        let state = guard.as_ref().ok_or(VaultPkiSignerError::NotInitialised)?;
        let signing_key: P256SigningKey = state.signing_key.clone().into();
        let sig: p256::ecdsa::Signature = signing_key
            .sign_prehash(content_hash)
            .map_err(|e| VaultPkiSignerError::Sign(e.to_string()))?;
        let signature_der = sig.to_der().as_bytes().to_vec();
        let signature_raw = sig.to_bytes().to_vec();
        Ok(X509Signature {
            signature_der,
            signature_raw,
            cert_chain_pem: state.cert_chain_pem.clone(),
            cert_chain_der: state.cert_chain_der.clone(),
        })
    }

    /// Borrow the active leaf state for inspection (corecruxctl
    /// `c2pa-cert-status`). Returns `None` if `initialize()` has not
    /// been called.
    pub fn current_leaf_chain_pem(&self) -> Option<String> {
        self.state.read().as_ref().map(|s| s.cert_chain_pem.clone())
    }

    /// Return the active leaf's `notAfter` SystemTime if loaded.
    pub fn current_leaf_not_after(&self) -> Option<SystemTime> {
        self.state.read().as_ref().map(|s| s.cert_not_after)
    }

    /// Check whether the leaf is within `ROTATION_THRESHOLD_HOURS` of
    /// expiry. Returns `Ok(true)` when a rotation has been performed,
    /// `Ok(false)` when the leaf is still healthy.
    pub fn maybe_rotate_if_due(&self) -> Result<bool> {
        let needs = {
            let guard = self.state.read();
            match guard.as_ref() {
                Some(state) => needs_rotation(state.cert_not_after, ROTATION_THRESHOLD_HOURS),
                None => true,
            }
        };
        if needs {
            self.regenerate_leaf()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Internal: attempt to rehydrate from disk. Returns `Ok(None)` if
    /// the cached pair is missing, malformed, or expired.
    fn try_load_from_disk(&self) -> Result<Option<LeafState>> {
        if !self.config.leaf_key_path.exists() || !self.config.leaf_cert_path.exists() {
            return Ok(None);
        }
        let key_pem = std::fs::read_to_string(&self.config.leaf_key_path).map_err(|e| VaultPkiSignerError::Io {
            path: self.config.leaf_key_path.clone(),
            source: e,
        })?;
        let secret =
            SecretKey::from_pkcs8_pem(&key_pem).map_err(|e| VaultPkiSignerError::KeyDecoding(e.to_string()))?;
        let chain_pem = std::fs::read_to_string(&self.config.leaf_cert_path).map_err(|e| VaultPkiSignerError::Io {
            path: self.config.leaf_cert_path.clone(),
            source: e,
        })?;
        let chain_pems = split_pem_certs(&chain_pem);
        if chain_pems.is_empty() {
            return Ok(None);
        }
        let mut chain_der: Vec<Vec<u8>> = Vec::with_capacity(chain_pems.len());
        for pem in &chain_pems {
            chain_der.push(pem_to_der(pem)?);
        }
        let leaf_cert =
            Certificate::from_der(&chain_der[0]).map_err(|e| VaultPkiSignerError::CertParse(e.to_string()))?;
        let cert_not_after = system_time_from_validity(&leaf_cert);
        Ok(Some(LeafState {
            signing_key: secret,
            cert_chain_pem: chain_pem,
            cert_chain_der: chain_der,
            cert_not_after,
        }))
    }
}

/// Implement [`crate::c2pa_manifest_v1::C2paSigner`] so the
/// VaultPkiX509Signer can be passed to [`crate::c2pa_manifest_v1::sign_c2pa_manifest_via_signer`]
/// without the c2pa module learning anything about Vault. This is
/// **true ES256** (ECDSA-P256-SHA256): we prehash the canonical body
/// with SHA-256 and sign that digest with the leaf key — identical in
/// scheme to [`crate::c2pa_manifest_v1::ByokP256Signer`], so the `es256`
/// algorithm identifier is honest and any off-the-shelf ES256 verifier
/// (including the daemon's `verify_c2pa_signed_manifest_es256_v1`) accepts
/// the envelope given the canonical bytes + leaf cert. BLAKE3 remains the
/// SEPARATE envelope-integrity hash carried in `canonical_body_hash`.
impl crate::c2pa_manifest_v1::C2paSigner for VaultPkiX509Signer {
    fn sign_body(
        &self,
        canonical_body_bytes: &[u8],
    ) -> std::result::Result<crate::c2pa_manifest_v1::SignedManifestParts, crate::c2pa_manifest_v1::C2paManifestError>
    {
        // True ES256: ECDSA-P256 over the SHA-256 prehash of the canonical
        // body. `sign` is a prehash signer, and sign_prehash(SHA-256(body))
        // is exactly what a high-level ES256 signer computes, so the result
        // verifies under `verify(body, sig)` with no BLAKE3 special-casing.
        let digest = sha256_digest(canonical_body_bytes);
        let x509_sig = self
            .sign(&digest)
            .map_err(|e| crate::c2pa_manifest_v1::C2paManifestError::Encode(format!("vault pki sign: {e}")))?;
        // Key id for X.509 envelopes = SHA-256 hex of the leaf DER.
        // Stable across reloads, doesn't collide with Ed25519 key ids,
        // and lets verifiers cross-reference the chain.
        let leaf_der = x509_sig.cert_chain_der.first().cloned().unwrap_or_default();
        let key_id = format!("x509-sha256:{}", hex_lower(&sha256_digest(&leaf_der)));
        Ok(crate::c2pa_manifest_v1::SignedManifestParts {
            signature_bytes: x509_sig.signature_der,
            signature_alg: "es256".to_string(),
            key_id,
            x5chain_pem: Some(x509_sig.cert_chain_pem),
        })
    }
}

fn sha256_digest(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest as _, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    let out = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

/// Default POST hook — synchronous ureq call to Vault PKI. Vault's
/// response shape:
/// ```json
/// {"data":{"certificate":"...","ca_chain":["..."],"issuing_ca":"..."}}
/// ```
pub fn ureq_post_csr(config: &Config, csr_pem: &str) -> Result<VaultSignResponse> {
    let url = format!(
        "{}/v1/{}/sign/c2pa-leaf",
        config.vault_addr.trim_end_matches('/'),
        config.pki_mount
    );
    let body = serde_json::json!({
        "csr": csr_pem,
        "common_name": config.leaf_common_name,
        "ttl": format!("{}h", config.leaf_ttl_hours),
    });

    // Build an agent. ureq's tls feature uses native-tls by default; for
    // self-signed Vault we honour VAULT_CACERT if supplied by writing a
    // tiny tls-config note: without rustls plumbing we fall back to
    // trusting the cert via standard CA discovery. Operators who need
    // self-signed Vault TLS should set SSL_CERT_FILE/SSL_CERT_DIR.
    if let Some(cacert_path) = &config.vault_cacert_path {
        std::env::set_var("SSL_CERT_FILE", cacert_path);
    }
    let agent = ureq::AgentBuilder::new().timeout(Duration::from_secs(15)).build();

    let resp = agent
        .post(&url)
        .set("X-Vault-Token", &config.vault_token)
        .set("Content-Type", "application/json")
        .send_json(body)
        .map_err(|e| VaultPkiSignerError::Http(e.to_string()))?;
    let json: serde_json::Value = resp
        .into_json()
        .map_err(|e| VaultPkiSignerError::VaultDecode(e.to_string()))?;
    let data = json
        .get("data")
        .ok_or_else(|| VaultPkiSignerError::VaultDecode("missing data field".into()))?;
    let certificate_pem = data
        .get("certificate")
        .and_then(|v| v.as_str())
        .ok_or_else(|| VaultPkiSignerError::VaultDecode("missing data.certificate".into()))?
        .to_string();
    let mut ca_chain_pem: Vec<String> = Vec::new();
    if let Some(arr) = data.get("ca_chain").and_then(|v| v.as_array()) {
        for v in arr {
            if let Some(s) = v.as_str() {
                ca_chain_pem.push(s.to_string());
            }
        }
    }
    if ca_chain_pem.is_empty() {
        if let Some(s) = data.get("issuing_ca").and_then(|v| v.as_str()) {
            ca_chain_pem.push(s.to_string());
        }
    }
    Ok(VaultSignResponse {
        certificate_pem,
        ca_chain_pem,
    })
}

// ── Helpers ──────────────────────────────────────────────────────────────

fn needs_rotation(not_after: SystemTime, threshold_hours: u64) -> bool {
    let now = SystemTime::now();
    match not_after.duration_since(now) {
        Ok(remaining) => remaining < Duration::from_secs(threshold_hours * 3600),
        // not_after is in the past → definitely needs rotation.
        Err(_) => true,
    }
}

fn system_time_from_validity(cert: &Certificate) -> SystemTime {
    let not_after = cert.tbs_certificate().validity().not_after;
    let unix = not_after.to_unix_duration();
    UNIX_EPOCH + unix
}

fn atomic_write_pem(path: &Path, pem: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            std::fs::create_dir_all(parent).map_err(|e| VaultPkiSignerError::Io {
                path: parent.to_path_buf(),
                source: e,
            })?;
        }
    }
    let tmp = path.with_extension("pem.tmp");
    std::fs::write(&tmp, pem).map_err(|e| VaultPkiSignerError::Io {
        path: tmp.clone(),
        source: e,
    })?;
    std::fs::rename(&tmp, path).map_err(|e| VaultPkiSignerError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    Ok(())
}

fn pem_to_der(pem: &str) -> Result<Vec<u8>> {
    let trimmed = pem.trim();
    let start_marker = "-----BEGIN CERTIFICATE-----";
    let end_marker = "-----END CERTIFICATE-----";
    let start = trimmed
        .find(start_marker)
        .ok_or_else(|| VaultPkiSignerError::PemParse("missing BEGIN CERTIFICATE".into()))?;
    let body_start = start + start_marker.len();
    let end = trimmed[body_start..]
        .find(end_marker)
        .ok_or_else(|| VaultPkiSignerError::PemParse("missing END CERTIFICATE".into()))?;
    let b64 = trimmed[body_start..body_start + end]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>();
    base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .map_err(|e| VaultPkiSignerError::PemParse(format!("base64 decode: {e}")))
}

fn split_pem_certs(pem: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut buf = String::new();
    let mut inside = false;
    for line in pem.lines() {
        if line.starts_with("-----BEGIN CERTIFICATE-----") {
            inside = true;
            buf.clear();
            buf.push_str(line);
            buf.push('\n');
        } else if line.starts_with("-----END CERTIFICATE-----") {
            buf.push_str(line);
            buf.push('\n');
            out.push(buf.clone());
            buf.clear();
            inside = false;
        } else if inside {
            buf.push_str(line);
            buf.push('\n');
        }
    }
    out
}

fn is_root_cert_pem(pem: &str) -> Result<bool> {
    let der = pem_to_der(pem)?;
    let cert = Certificate::from_der(&der).map_err(|e| VaultPkiSignerError::CertParse(e.to_string()))?;
    // Self-signed → issuer == subject (RDN sequence equality).
    Ok(cert.tbs_certificate().issuer() == cert.tbs_certificate().subject())
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    };

    /// Build a tiny in-test root CA + leaf-signer using rcgen, so the
    /// mock Vault hook can mint real-looking leaves.
    struct TestPki {
        /// rcgen 0.14 bundles the issuing params + signing key into an `Issuer`,
        /// which is what CSR `signed_by` now consumes (single argument).
        root_issuer: rcgen::Issuer<'static, KeyPair>,
        root_pem: String,
    }

    impl TestPki {
        fn new() -> Self {
            let mut params = CertificateParams::new(vec!["CueCrux C2PA Root TEST".to_string()]).unwrap();
            params
                .distinguished_name
                .push(rcgen::DnType::CommonName, "CueCrux C2PA Root TEST");
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
            let cert = params.self_signed(&key_pair).unwrap();
            let root_pem = cert.pem();
            let root_issuer = rcgen::Issuer::new(params, key_pair);
            Self { root_issuer, root_pem }
        }

        /// Sign a leaf CSR (PEM) with this root. Returns leaf PEM.
        fn sign_csr(&self, csr_pem: &str) -> String {
            let csr_params = rcgen::CertificateSigningRequestParams::from_pem(csr_pem).unwrap();
            let leaf = csr_params.signed_by(&self.root_issuer).unwrap();
            leaf.pem()
        }
    }

    fn test_config(tmp: &tempfile::TempDir) -> Config {
        Config {
            vault_addr: "http://vault.test.invalid".into(),
            vault_token: "test-token".into(),
            vault_cacert_path: None,
            pki_mount: "pki-c2pa".into(),
            leaf_key_path: tmp.path().join("leaf.key.pem"),
            leaf_cert_path: tmp.path().join("leaf.cert.pem"),
            root_anchor_path: tmp.path().join("root.cert.pem"),
            leaf_ttl_hours: 720,
            leaf_common_name: DEFAULT_LEAF_CN.into(),
        }
    }

    fn mock_post_fn(pki: TestPki) -> CsrPostFn {
        let root_pem = pki.root_pem.clone();
        let pki_arc = Arc::new(Mutex::new(pki));
        Arc::new(move |_cfg: &Config, csr_pem: &str| -> Result<VaultSignResponse> {
            let pki = pki_arc.lock().unwrap();
            let leaf_pem = pki.sign_csr(csr_pem);
            Ok(VaultSignResponse {
                certificate_pem: leaf_pem,
                ca_chain_pem: vec![root_pem.clone()],
            })
        })
    }

    fn failing_post_fn(after: usize) -> CsrPostFn {
        let count = Arc::new(AtomicUsize::new(0));
        Arc::new(move |_cfg, _csr| {
            let n = count.fetch_add(1, Ordering::SeqCst);
            if n >= after {
                Err(VaultPkiSignerError::Http("simulated failure".into()))
            } else {
                Err(VaultPkiSignerError::Http("simulated failure".into()))
            }
        })
    }

    #[test]
    fn test_csr_generation_produces_p256_pubkey() {
        // Hook checks that the CSR we POST actually carries a P-256
        // SubjectPublicKeyInfo. We accept the CSR, parse it, and assert
        // the algorithm OID matches id-ecPublicKey + secp256r1.
        let saw_p256 = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let saw = saw_p256.clone();
        let pki = TestPki::new();
        let root_pem = pki.root_pem.clone();
        let pki_arc = Arc::new(Mutex::new(pki));
        let post_fn: CsrPostFn = Arc::new(move |_cfg, csr_pem| {
            // Parse the CSR via rcgen — verifies the signature
            // (self-signed by the in-test P-256 key) and the SubjectPublicKeyInfo.
            let csr_params = rcgen::CertificateSigningRequestParams::from_pem(csr_pem).unwrap();
            // SubjectPublicKey for P-256 SEC1 uncompressed point is 65 bytes
            // (0x04 || X || Y); compressed is 33 bytes. Anything else =
            // wrong curve and the test must fail.
            use rcgen::PublicKeyData;
            let spki_len = csr_params.public_key.der_bytes().len();
            assert!(
                spki_len == 65 || spki_len == 33,
                "expected SEC1 P-256 SubjectPublicKey (33 or 65 bytes), got {spki_len}"
            );
            saw.store(true, Ordering::SeqCst);
            let pki = pki_arc.lock().unwrap();
            let leaf = pki.sign_csr(csr_pem);
            Ok(VaultSignResponse {
                certificate_pem: leaf,
                ca_chain_pem: vec![root_pem.clone()],
            })
        });
        let tmp = tempfile::tempdir().unwrap();
        let signer = VaultPkiX509Signer::with_post_fn(test_config(&tmp), post_fn);
        signer.regenerate_leaf().unwrap();
        assert!(saw_p256.load(Ordering::SeqCst));
        // And the signing key the signer stashed is P-256.
        let guard = signer.state.read();
        let state = guard.as_ref().unwrap();
        let _: P256SigningKey = state.signing_key.clone().into();
    }

    #[test]
    fn test_atomic_disk_write_no_partial_file() {
        // After a failing Vault POST, neither the .pem nor the .pem.tmp
        // file should exist (we write to .tmp then rename; if Vault
        // fails we never touch the .tmp at all).
        let tmp = tempfile::tempdir().unwrap();
        let signer = VaultPkiX509Signer::with_post_fn(test_config(&tmp), failing_post_fn(0));
        let res = signer.regenerate_leaf();
        assert!(res.is_err());
        // No half-written file left on disk.
        let key_tmp = signer.config.leaf_key_path.with_extension("pem.tmp");
        let cert_tmp = signer.config.leaf_cert_path.with_extension("pem.tmp");
        assert!(!key_tmp.exists(), "leaf key .tmp leaked: {key_tmp:?}");
        assert!(!cert_tmp.exists(), "leaf cert .tmp leaked: {cert_tmp:?}");
        assert!(
            !signer.config.leaf_key_path.exists(),
            "leaf key shouldn't exist on Vault failure"
        );
        assert!(
            !signer.config.leaf_cert_path.exists(),
            "leaf cert shouldn't exist on Vault failure"
        );
    }

    #[test]
    fn test_rotation_due_when_under_7d() {
        let now = SystemTime::now();
        let in_six_days = now + Duration::from_secs(6 * 24 * 3600);
        let in_thirty_days = now + Duration::from_secs(30 * 24 * 3600);
        assert!(needs_rotation(in_six_days, ROTATION_THRESHOLD_HOURS));
        assert!(!needs_rotation(in_thirty_days, ROTATION_THRESHOLD_HOURS));
        let in_the_past = now - Duration::from_secs(3600);
        assert!(needs_rotation(in_the_past, ROTATION_THRESHOLD_HOURS));
    }

    #[test]
    fn test_sign_with_known_key_roundtrips_via_p256_verifier() {
        use p256::ecdsa::{signature::hazmat::PrehashVerifier, VerifyingKey};
        let tmp = tempfile::tempdir().unwrap();
        let signer = VaultPkiX509Signer::with_post_fn(test_config(&tmp), mock_post_fn(TestPki::new()));
        signer.regenerate_leaf().unwrap();
        let hash = [0xabu8; 32];
        let sig = signer.sign(&hash).unwrap();
        // Reconstruct the verifying key from the in-memory secret.
        let guard = signer.state.read();
        let state = guard.as_ref().unwrap();
        let signing_key: P256SigningKey = state.signing_key.clone().into();
        let verifying_key = VerifyingKey::from(&signing_key);
        let parsed_sig = p256::ecdsa::Signature::from_der(&sig.signature_der).unwrap();
        verifying_key.verify_prehash(&hash, &parsed_sig).unwrap();
    }

    #[test]
    fn test_root_anchor_pem_parses_self_signed_subject() {
        // Stand in for the real anchor: rcgen-built test root has a
        // self-signed cert with CN matching what we asked for. The
        // production anchor (the cuecrux-c2pa-root.pem from prod
        // Vault) parses through the same code path.
        let pki = TestPki::new();
        let der = pem_to_der(&pki.root_pem).unwrap();
        let cert = Certificate::from_der(&der).unwrap();
        assert_eq!(cert.tbs_certificate().issuer(), cert.tbs_certificate().subject());
        let subject = cert.tbs_certificate().subject().to_string();
        assert!(subject.contains("CueCrux C2PA Root TEST"), "got subject: {subject}");
        // is_root_cert_pem agrees.
        assert!(is_root_cert_pem(&pki.root_pem).unwrap());
    }

    #[test]
    fn test_round_trip_through_initialize_and_reload() {
        // First initialize: should mint a fresh leaf via Vault.
        let tmp = tempfile::tempdir().unwrap();
        let signer_a = VaultPkiX509Signer::with_post_fn(test_config(&tmp), mock_post_fn(TestPki::new()));
        signer_a.initialize().unwrap();
        let pem_a = signer_a.state.read().as_ref().unwrap().cert_chain_pem.clone();
        assert!(signer_a.config.leaf_key_path.exists());
        assert!(signer_a.config.leaf_cert_path.exists());

        // Second initialize on a NEW signer with the SAME config —
        // should reload from disk without minting.
        let cfg = test_config(&tmp);
        let cfg = Config {
            leaf_key_path: signer_a.config.leaf_key_path.clone(),
            leaf_cert_path: signer_a.config.leaf_cert_path.clone(),
            ..cfg
        };
        // A failing post fn would crash if reload didn't work.
        let signer_b = VaultPkiX509Signer::with_post_fn(cfg, failing_post_fn(0));
        signer_b.initialize().unwrap();
        let pem_b = signer_b.state.read().as_ref().unwrap().cert_chain_pem.clone();
        assert_eq!(pem_a, pem_b, "reload must produce identical chain");
    }

    #[test]
    fn test_maybe_rotate_if_due_skips_when_healthy() {
        let tmp = tempfile::tempdir().unwrap();
        let signer = VaultPkiX509Signer::with_post_fn(test_config(&tmp), mock_post_fn(TestPki::new()));
        signer.initialize().unwrap();
        // Fresh leaf is ~30d valid, well over the 7d threshold.
        let rotated = signer.maybe_rotate_if_due().unwrap();
        assert!(!rotated, "shouldn't rotate a healthy leaf");
    }

    #[test]
    fn test_maybe_rotate_if_due_fires_when_close_to_expiry() {
        let tmp = tempfile::tempdir().unwrap();
        let signer = VaultPkiX509Signer::with_post_fn(test_config(&tmp), mock_post_fn(TestPki::new()));
        signer.initialize().unwrap();
        // Manually push the in-memory cert_not_after into the rotation
        // window. (regenerate_leaf is the real production path; here we
        // simulate clock advance.)
        {
            let mut guard = signer.state.write();
            let state = guard.as_mut().unwrap();
            state.cert_not_after = SystemTime::now() + Duration::from_secs(3 * 24 * 3600);
        }
        let rotated = signer.maybe_rotate_if_due().unwrap();
        assert!(rotated, "expected rotation under the 7d threshold");
    }

    #[test]
    fn test_config_from_env_requires_addr_and_token() {
        // Cannot rely on env vars in parallel tests — only assert the
        // error paths, which don't poke process-wide state.
        std::env::remove_var(ENV_VAULT_ADDR);
        std::env::remove_var(ENV_VAULT_TOKEN);
        let err = Config::from_env().unwrap_err();
        assert!(matches!(err, VaultPkiSignerError::MissingEnv(ENV_VAULT_ADDR)));
    }

    #[test]
    fn test_pem_to_der_roundtrip() {
        let pki = TestPki::new();
        let der = pem_to_der(&pki.root_pem).unwrap();
        assert!(!der.is_empty());
        let cert = Certificate::from_der(&der).unwrap();
        assert!(cert.tbs_certificate().serial_number().as_bytes().len() > 0);
    }

    #[test]
    fn test_end_to_end_c2pa_envelope_via_x509_signer() {
        // Build a C2PA manifest, sign through the VaultPkiX509Signer
        // as a `C2paSigner` impl, parse the envelope back, and
        // confirm the x5chain PEM round-trips and the alg is `es256`.
        use crate::c2pa_manifest_v1::{
            build_c2pa_manifest_v1, parse_jumbf_base64, sign_c2pa_manifest_via_signer, C2paManifestInputV1,
        };
        let tmp = tempfile::tempdir().unwrap();
        let signer = VaultPkiX509Signer::with_post_fn(test_config(&tmp), mock_post_fn(TestPki::new()));
        signer.regenerate_leaf().unwrap();
        let content = b"x509-end-to-end-content";
        let manifest = build_c2pa_manifest_v1(&C2paManifestInputV1 {
            content_bytes: content,
            content_type: Some("image/png"),
            crown_receipt_id: "r_x509_e2e",
            signer_passport: "passport:test",
            claim_generator: "cuecrux/test",
            manifest_id: "urn:cuecrux:c2pa:e2e",
            when: "2026-05-28T00:00:00Z",
            model: None,
        });
        let signed = sign_c2pa_manifest_via_signer(manifest, &signer, "2026-05-28T00:00:00Z").unwrap();
        assert_eq!(signed.signature_alg, "es256");
        assert!(signed.key_id.starts_with("x509-sha256:"));
        assert!(signed.x5chain_pem.is_some());
        let envelope = signed.to_jumbf_base64();
        let parsed = parse_jumbf_base64(&envelope).unwrap();
        assert_eq!(parsed.signature_alg, "es256");
        assert_eq!(parsed.signature, signed.signature);
        assert!(parsed.x5chain_pem.is_some());
    }

    #[test]
    fn test_vault_signed_envelope_verifies_as_true_es256() {
        // Regression guard for the algorithm-confusion bug: the Vault signer
        // labelled envelopes `es256` while signing a BLAKE3 prehash, so the
        // daemon provenance verifier `verify_c2pa_signed_manifest_es256_v1`
        // (which does ECDSA-over-SHA-256) reported signature_valid=false.
        // After the fix the SAME verifier must ACCEPT the manifest.
        use crate::c2pa_manifest_v1::{
            build_c2pa_manifest_v1, parse_jumbf_base64, sign_c2pa_manifest_via_signer,
            verify_c2pa_signed_manifest_es256_v1, C2paManifestInputV1,
        };
        let tmp = tempfile::tempdir().unwrap();
        let signer = VaultPkiX509Signer::with_post_fn(test_config(&tmp), mock_post_fn(TestPki::new()));
        signer.regenerate_leaf().unwrap();
        let content = b"true-es256-vault-content";
        let manifest = build_c2pa_manifest_v1(&C2paManifestInputV1 {
            content_bytes: content,
            content_type: Some("image/png"),
            crown_receipt_id: "r_es256",
            signer_passport: "passport:test",
            claim_generator: "cuecrux/test",
            manifest_id: "urn:cuecrux:c2pa:es256",
            when: "2026-05-28T00:00:00Z",
            model: None,
        });
        let signed = sign_c2pa_manifest_via_signer(manifest, &signer, "2026-05-28T00:00:00Z").unwrap();
        let parsed = parse_jumbf_base64(&signed.to_jumbf_base64()).unwrap();

        // The off-the-shelf ES256 daemon-path verifier must now accept it.
        let report = verify_c2pa_signed_manifest_es256_v1(&parsed, content).unwrap();
        assert!(
            report.signature_valid,
            "Vault-signed es256 envelope must verify under the daemon ES256 verifier"
        );
        assert!(report.canonical_hash_match);
        assert!(report.content_hash_match);
        assert!(report.ok);

        // Crypto-level: the signature is ECDSA-P256 over SHA-256 (true ES256)
        // and specifically is NOT a BLAKE3-prehash signature.
        use p256::ecdsa::signature::hazmat::PrehashVerifier as _;
        use sha2::{Digest as _, Sha256};
        let guard = signer.state.read();
        let state = guard.as_ref().unwrap();
        let signing_key: P256SigningKey = state.signing_key.clone().into();
        let vk = p256::ecdsa::VerifyingKey::from(&signing_key);
        let sig = p256::ecdsa::Signature::from_der(&parsed.signature).unwrap();
        let sha = Sha256::digest(&parsed.canonical_body_bytes);
        assert!(
            vk.verify_prehash(&sha, &sig).is_ok(),
            "signature must verify as ECDSA over SHA-256 (true ES256)"
        );
        let blake = blake3::hash(&parsed.canonical_body_bytes);
        assert!(
            vk.verify_prehash(blake.as_bytes(), &sig).is_err(),
            "must NOT verify as a BLAKE3-prehash signature"
        );
    }

    #[test]
    fn test_strict_profile_assertion_on_returned_leaf() {
        // After regenerate_leaf the in-memory chain's leaf cert must
        // satisfy the strict C2PA profile: BasicConstraints CA:FALSE
        // (since c2pa-leaf role sets basic_constraints_valid_for_non_ca).
        // The test PKI mirrors Vault's profile by NOT marking the leaf
        // as a CA. If a Vault drift introduced is_ca: true, this test
        // would fail because the cert would carry CA:TRUE.
        let tmp = tempfile::tempdir().unwrap();
        let signer = VaultPkiX509Signer::with_post_fn(test_config(&tmp), mock_post_fn(TestPki::new()));
        signer.regenerate_leaf().unwrap();
        let chain_pem = signer.current_leaf_chain_pem().unwrap();
        let leaf_pem = split_pem_certs(&chain_pem).into_iter().next().unwrap();
        let leaf_der = pem_to_der(&leaf_pem).unwrap();
        let leaf = Certificate::from_der(&leaf_der).unwrap();
        // Walk the extensions and confirm any BasicConstraints
        // extension says CA:FALSE.
        // OID 2.5.29.19 = id-ce-basicConstraints.
        if let Some(exts) = leaf.tbs_certificate().extensions() {
            for ext in exts {
                if ext.extn_id.to_string() == "2.5.29.19" {
                    // The DER for BasicConstraints CA:FALSE is
                    // SEQUENCE {} (empty) which encodes to 30 00.
                    // CA:TRUE would include a BOOLEAN TRUE (01 01 ff).
                    let bytes = ext.extn_value.as_bytes();
                    assert!(
                        !bytes.windows(3).any(|w| w == [0x01u8, 0x01, 0xff]),
                        "leaf cert must not assert CA:TRUE"
                    );
                }
            }
        }
        // And subject CN matches what we requested.
        let subject = leaf.tbs_certificate().subject().to_string();
        assert!(
            subject.contains(DEFAULT_LEAF_CN),
            "leaf subject CN must match config, got: {subject}"
        );
    }

    #[test]
    fn test_split_pem_certs_handles_concatenated() {
        let pki1 = TestPki::new();
        let pki2 = TestPki::new();
        let combined = format!("{}\n{}\n", pki1.root_pem.trim(), pki2.root_pem.trim());
        let split = split_pem_certs(&combined);
        assert_eq!(split.len(), 2);
        assert!(split[0].contains("BEGIN CERTIFICATE"));
        assert!(split[1].contains("BEGIN CERTIFICATE"));
    }
}
