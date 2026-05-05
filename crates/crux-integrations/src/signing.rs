// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Manifest signing + trusted keyring (M1 of community-extensions ExecPlan).
//!
//! The crate already shipped Ed25519 *verification* (the module-private
//! `verify_signature` helper + [`IntegrationManifest::validate`]) and a
//! `trusted_public_keys` map on [`super::ValidationPolicy`]. This module
//! adds the missing pieces a community-contribution flow needs:
//!
//! - [`sign_manifest`] — fill in a manifest's `signature` field given an
//!   Ed25519 signing key + the passport fingerprint authoring the pack.
//! - [`TrustedKeyring`] — typed on-disk representation of operator-managed
//!   keys, persisted at `<data_dir>/extensions/trusted-keys.json` by
//!   convention. Carries per-key [`TrustTier`] so the operator can mark a
//!   given key as `CommunityReviewed` vs `LocallySigned` without rewriting
//!   the manifest.
//! - [`TrustedKeyring::as_trusted_public_keys`] — convenience to project
//!   the typed keyring into the legacy `ValidationPolicy.trusted_public_keys`
//!   shape so every existing consumer keeps working.
//! - [`TrustedKeyring::resolve_signature`] — given a signed manifest, look
//!   up the trust tier the matching key was added with. The
//!   `extension_registry` (M2) uses this to decide what tier to record on
//!   the persisted install record.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::{IntegrationError, IntegrationManifest, SignatureEnvelope, TrustTier};

/// On-disk format for the operator-managed keyring at
/// `<data_dir>/extensions/trusted-keys.json`. Keys are addressed by their
/// signing passport fingerprint (hex-encoded; same shape as
/// `IntegrationManifest::publisher_passport_fpr`) so the verifier can find
/// them directly.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustedKeyring {
    pub schema: String,
    #[serde(default)]
    pub keys: BTreeMap<String, TrustedKeyEntry>,
}

/// One row in the keyring. Operator-supplied trust tier lets the daemon
/// distinguish a key the operator personally trusts (e.g. their own
/// developer key, [`TrustTier::LocallySigned`]) from a key endorsed by a
/// community-vetting process ([`TrustTier::CommunityReviewed`]).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustedKeyEntry {
    /// 32-byte Ed25519 public key, hex-encoded (no leading 0x).
    pub public_key_hex: String,
    pub trust_tier: TrustTier,
    pub added_at_unix_ms: u64,
    /// Free-form note: who added it, why, ticket reference.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub added_by: String,
}

impl TrustedKeyring {
    pub const SCHEMA_V1: &'static str = "crux.extensions.trusted-keys.v1";

    pub fn new() -> Self {
        Self {
            schema: Self::SCHEMA_V1.to_string(),
            keys: BTreeMap::new(),
        }
    }

    /// Load from disk. Returns an empty keyring (no error) when the file
    /// doesn't exist — that's the expected first-boot state. Returns an
    /// error only when the file is present but malformed.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, IntegrationError> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(Self::new());
        }
        let bytes = fs::read(path).map_err(IntegrationError::Io)?;
        let mut keyring: Self = serde_json::from_slice(&bytes)?;
        if keyring.schema.is_empty() {
            keyring.schema = Self::SCHEMA_V1.to_string();
        }
        if keyring.schema != Self::SCHEMA_V1 {
            return Err(IntegrationError::InvalidSignatureMaterial(format!(
                "trusted-keys schema mismatch: expected {}, got {}",
                Self::SCHEMA_V1,
                keyring.schema
            )));
        }
        // Validate every public key length once so misuse fails loudly at
        // load time rather than silently at first verification.
        for (fpr, entry) in &keyring.keys {
            super::decode_fixed_hex::<32>(&entry.public_key_hex, "public key").map_err(|e| match e {
                IntegrationError::InvalidSignatureMaterial(msg) => {
                    IntegrationError::InvalidSignatureMaterial(format!("{fpr}: {msg}"))
                }
                other => other,
            })?;
        }
        Ok(keyring)
    }

    /// Persist atomically (write tmp → rename) so a partial write never
    /// leaves the keyring corrupt. Caller is responsible for setting unix
    /// permissions on the parent dir; we don't chmod here.
    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), IntegrationError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(IntegrationError::Io)?;
        }
        let tmp = path.with_extension("json.tmp");
        let bytes = serde_json::to_vec_pretty(self)?;
        fs::write(&tmp, bytes).map_err(IntegrationError::Io)?;
        fs::rename(&tmp, path).map_err(IntegrationError::Io)?;
        Ok(())
    }

    pub fn add(&mut self, passport_fpr: impl Into<String>, entry: TrustedKeyEntry) {
        self.keys.insert(passport_fpr.into(), entry);
    }

    pub fn remove(&mut self, passport_fpr: &str) -> Option<TrustedKeyEntry> {
        self.keys.remove(passport_fpr)
    }

    pub fn get(&self, passport_fpr: &str) -> Option<&TrustedKeyEntry> {
        self.keys.get(passport_fpr)
    }

    /// Project into the existing [`super::ValidationPolicy::trusted_public_keys`]
    /// shape (`BTreeMap<passport_fpr, public_key_hex>`) so every existing
    /// consumer of `ValidationPolicy` keeps working unchanged.
    pub fn as_trusted_public_keys(&self) -> BTreeMap<String, String> {
        self.keys
            .iter()
            .map(|(fpr, entry)| (fpr.clone(), entry.public_key_hex.clone()))
            .collect()
    }

    /// Look up the trust tier the matching key was added with. Returns
    /// [`TrustTier::Unknown`] if the manifest's signature points at a key
    /// not in the keyring; the caller is expected to have already invoked
    /// `manifest.validate(&policy)` and observed an error in that case, but
    /// this helper exists for the post-verify "what tier did this turn out
    /// to be" question.
    pub fn resolve_signature(&self, manifest: &IntegrationManifest) -> TrustTier {
        manifest
            .signature
            .as_ref()
            .and_then(|sig| self.keys.get(&sig.passport_fpr))
            .map_or(TrustTier::Unknown, |entry| entry.trust_tier)
    }
}

/// Sign a manifest in-place: fills in (or overwrites) the `signature`
/// field with an Ed25519 signature over the canonical signing payload.
/// Also updates `hashes.manifest` so verifiers can short-circuit.
pub fn sign_manifest(
    manifest: &mut IntegrationManifest,
    signing_key: &SigningKey,
    passport_fpr: impl Into<String>,
) -> Result<(), IntegrationError> {
    let payload = manifest.signing_payload()?;
    let signature = signing_key.sign(&payload);
    let public_key_hex = hex::encode(signing_key.verifying_key().to_bytes());
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());
    manifest.signature = Some(SignatureEnvelope {
        alg: "ed25519".to_string(),
        passport_fpr: passport_fpr.into(),
        public_key_hex: Some(public_key_hex),
        sig: sig_b64,
    });
    manifest.hashes.manifest = Some(manifest.manifest_hash()?);
    Ok(())
}

/// Convenience: derive a stable passport fingerprint from a public key
/// (BLAKE3 of the 32 raw bytes, hex-encoded, prefixed with `p_`). Used by
/// the keyring CLI helper for keys created via `crux-integrations sign`
/// where the operator hasn't decided on a passport id yet.
pub fn fingerprint_from_public_key(verifying_key: &VerifyingKey) -> String {
    let h = blake3::hash(&verifying_key.to_bytes());
    let hex = hex::encode(&h.as_bytes()[..16]);
    format!("p_{hex}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DataAccess, EntryKind, IntegrationEntry, ManifestHashes, NetworkAccess, SafetyPolicy, ValidationPolicy,
        INTEGRATION_SCHEMA_V1,
    };
    use ed25519_dalek::SigningKey;

    fn fixed_signing_key() -> SigningKey {
        // Deterministic key for tests so we don't depend on RNG.
        let seed: [u8; 32] = [
            0x9f, 0x77, 0x14, 0x07, 0xb2, 0x5a, 0xc4, 0x88, 0xe9, 0xc4, 0x36, 0x40, 0x6e, 0xa3, 0xc0, 0xfb, 0xfa, 0x36,
            0x99, 0x88, 0x55, 0xa9, 0xc4, 0x46, 0xfd, 0xa6, 0x06, 0xee, 0x6e, 0x9b, 0x82, 0x6b,
        ];
        SigningKey::from_bytes(&seed)
    }

    fn unsigned_manifest() -> IntegrationManifest {
        IntegrationManifest {
            schema: INTEGRATION_SCHEMA_V1.to_string(),
            id: "ext.example.quote".to_string(),
            name: "Quote of the Day".to_string(),
            version: "0.1.0".to_string(),
            publisher_passport_fpr: "p_community_alice".to_string(),
            summary: "Returns a quote.".to_string(),
            entry: IntegrationEntry {
                kind: EntryKind::HttpRecipe,
                path: "tools/quote.json".to_string(),
            },
            capabilities: vec!["facts:read".to_string()],
            network: NetworkAccess::default(),
            data_access: DataAccess::default(),
            safety: SafetyPolicy::default(),
            hashes: ManifestHashes::default(),
            signature: None,
            external_tool_endpoint: None,
            tools: Vec::new(),
        }
    }

    #[test]
    fn sign_then_verify_round_trip() {
        let mut manifest = unsigned_manifest();
        let key = fixed_signing_key();
        sign_manifest(&mut manifest, &key, "p_community_alice").expect("sign");
        assert!(manifest.signature.is_some());
        assert!(manifest.hashes.manifest.is_some());

        // Build a policy whose keyring trusts our test key.
        let mut keyring = TrustedKeyring::new();
        keyring.add(
            "p_community_alice",
            TrustedKeyEntry {
                public_key_hex: hex::encode(key.verifying_key().to_bytes()),
                trust_tier: TrustTier::CommunityReviewed,
                added_at_unix_ms: 1,
                added_by: "operator-test".to_string(),
            },
        );
        let policy = ValidationPolicy {
            allow_unsigned_first_party: false,
            allow_executable_helpers: false,
            trusted_public_keys: keyring.as_trusted_public_keys(),
            ..ValidationPolicy::default()
        };
        manifest.validate(&policy).expect("verify");
        assert_eq!(keyring.resolve_signature(&manifest), TrustTier::CommunityReviewed);
    }

    #[test]
    fn tampered_payload_fails_verification() {
        let mut manifest = unsigned_manifest();
        let key = fixed_signing_key();
        sign_manifest(&mut manifest, &key, "p_community_alice").expect("sign");
        // Tamper after signing.
        manifest.summary = "Returns a quote (with extra surveillance!)".to_string();
        let mut keyring = TrustedKeyring::new();
        keyring.add(
            "p_community_alice",
            TrustedKeyEntry {
                public_key_hex: hex::encode(key.verifying_key().to_bytes()),
                trust_tier: TrustTier::CommunityReviewed,
                added_at_unix_ms: 1,
                added_by: String::new(),
            },
        );
        let policy = ValidationPolicy {
            allow_unsigned_first_party: false,
            trusted_public_keys: keyring.as_trusted_public_keys(),
            ..ValidationPolicy::default()
        };
        let err = manifest.validate(&policy).expect_err("tamper must fail");
        // Either the hash check fails first (if hashes.manifest was filled)
        // or the signature itself fails. Both are acceptable rejections.
        assert!(matches!(
            err,
            IntegrationError::SignatureInvalid | IntegrationError::ManifestHashMismatch { .. }
        ));
    }

    #[test]
    fn signature_with_unknown_key_fails() {
        let mut manifest = unsigned_manifest();
        let key_a = fixed_signing_key();
        sign_manifest(&mut manifest, &key_a, "p_community_alice").expect("sign");

        // Keyring trusts a DIFFERENT key under the same fingerprint.
        let key_b = SigningKey::from_bytes(&[0x42; 32]);
        let mut keyring = TrustedKeyring::new();
        keyring.add(
            "p_community_alice",
            TrustedKeyEntry {
                public_key_hex: hex::encode(key_b.verifying_key().to_bytes()),
                trust_tier: TrustTier::CommunityReviewed,
                added_at_unix_ms: 1,
                added_by: String::new(),
            },
        );
        let policy = ValidationPolicy {
            // Manifest's signature carries its own public_key_hex (from
            // sign_manifest), so the verifier uses that and we have to
            // reject *that* key for the unknown-key case to fire. Strip
            // the inline key and force the verifier to consult the keyring.
            ..ValidationPolicy::default()
        };
        // Drop the inline key so the verifier consults the keyring.
        if let Some(sig) = manifest.signature.as_mut() {
            sig.public_key_hex = None;
        }
        manifest.hashes.manifest = None; // skip the hash short-circuit so
                                         // we hit the signature path
        let policy = ValidationPolicy {
            trusted_public_keys: keyring.as_trusted_public_keys(),
            ..policy
        };
        let err = manifest.validate(&policy).expect_err("wrong key must fail");
        assert!(matches!(err, IntegrationError::SignatureInvalid));
    }

    #[test]
    fn keyring_round_trips_through_disk() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("trusted-keys.json");
        let mut k1 = TrustedKeyring::new();
        k1.add(
            "p_alice",
            TrustedKeyEntry {
                public_key_hex: "00".repeat(32),
                trust_tier: TrustTier::CommunityReviewed,
                added_at_unix_ms: 17_700_000_000_000,
                added_by: "operator".to_string(),
            },
        );
        k1.save(&path).expect("save");
        let k2 = TrustedKeyring::load(&path).expect("load");
        assert_eq!(k1, k2);
    }

    #[test]
    fn keyring_load_missing_file_returns_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("does-not-exist.json");
        let k = TrustedKeyring::load(&path).expect("load");
        assert!(k.keys.is_empty());
        assert_eq!(k.schema, TrustedKeyring::SCHEMA_V1);
    }

    #[test]
    fn keyring_load_rejects_bad_pubkey_length() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("trusted-keys.json");
        let mut k = TrustedKeyring::new();
        k.add(
            "p_alice",
            TrustedKeyEntry {
                public_key_hex: "00".repeat(16), // 16 bytes, not 32
                trust_tier: TrustTier::CommunityReviewed,
                added_at_unix_ms: 1,
                added_by: String::new(),
            },
        );
        k.save(&path).expect("save");
        let err = TrustedKeyring::load(&path).expect_err("must reject");
        assert!(matches!(err, IntegrationError::InvalidSignatureMaterial(_)));
    }

    #[test]
    fn fingerprint_from_public_key_is_stable() {
        let key = fixed_signing_key();
        let fpr1 = fingerprint_from_public_key(&key.verifying_key());
        let fpr2 = fingerprint_from_public_key(&key.verifying_key());
        assert_eq!(fpr1, fpr2);
        assert!(fpr1.starts_with("p_"));
        assert_eq!(fpr1.len(), 2 + 32); // "p_" + 16 bytes hex
    }
}
