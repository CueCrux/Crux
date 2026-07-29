// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Dedicated Ed25519 identity and signed envelopes for cloud-witness records.
//!
//! The key file contains only a lowercase-hex 32-byte Ed25519 seed. On Unix,
//! its parent directory is owner-only (`0700`) and the file is owner-only
//! (`0600`). Signed envelopes carry the public key, never the seed.

use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write as _};
use std::path::Path;
use std::time::Duration;

use anyhow::Context as _;
use base64::Engine as _;
use ed25519_dalek::pkcs8::EncodePublicKey as _;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use rand::Rng as _;
use serde_json::Value;
use sha2::{Digest as _, Sha256};

const KEY_SEED_BYTES: usize = 32;
const PUBLIC_KEY_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 64;
const KID_HEX_CHARS: usize = 16;
const CREATE_RACE_RETRIES: usize = 50;
const CREATE_RACE_RETRY_DELAY: Duration = Duration::from_millis(2);

/// Public identity bound to a persisted cloud-witness signing key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessIdentity {
    /// Stable key identifier: `wit_` plus the first 16 lowercase hexadecimal
    /// characters of SHA-256 over the Ed25519 RFC 8410 SPKI DER bytes.
    pub kid: String,
    /// Standard padded Base64 encoding of the raw 32-byte Ed25519 public key.
    pub public_key_b64: String,
}

/// Persisted Ed25519 signing identity used only for cloud-witness records.
pub struct WitnessKey {
    signing_key: SigningKey,
    identity: WitnessIdentity,
}

impl std::fmt::Debug for WitnessKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WitnessKey")
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

impl WitnessKey {
    /// Load an existing witness seed or create one at `path` on first use.
    ///
    /// Concurrent creators are safe: creation uses `create_new`, and a loser
    /// waits for the winner's complete seed to become readable. Existing key
    /// paths must be regular, non-symlink files that were never group/world
    /// accessible; unsafe custody degrades witness mode instead of silently
    /// trusting a potentially disclosed seed.
    pub fn load_or_create(path: &Path) -> anyhow::Result<Self> {
        ensure_private_parent(path)?;
        let seed = match fs::symlink_metadata(path) {
            Ok(metadata) => {
                validate_existing_key(path, &metadata)?;
                let content =
                    fs::read_to_string(path).with_context(|| format!("reading witness key {}", path.display()))?;
                set_key_owner_only(path)?;
                parse_seed(path, &content)?
            }
            Err(err) if err.kind() == ErrorKind::NotFound => create_seed(path)?,
            Err(err) => return Err(err).with_context(|| format!("inspecting witness key {}", path.display())),
        };
        Self::from_seed(seed)
    }

    /// Return the public identity corresponding to this witness key.
    #[must_use]
    pub fn identity(&self) -> WitnessIdentity {
        self.identity.clone()
    }

    /// Sign a witness record and return its self-contained JSON envelope.
    ///
    /// The signature input is the recursively key-sorted canonical JSON of
    /// `record`. Only the record is signed; private key material is never
    /// included in the returned value.
    pub fn sign_record(&self, record: &Value) -> anyhow::Result<Value> {
        let signing_bytes = canonical_json_bytes(record)?;
        let signature = self.signing_key.sign(&signing_bytes);
        Ok(serde_json::json!({
            "record": record,
            "witness": {
                "alg": "ed25519",
                "kid": self.identity.kid,
                "public_key_b64": self.identity.public_key_b64,
                "sig_b64": base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
            }
        }))
    }

    fn from_seed(seed: [u8; KEY_SEED_BYTES]) -> anyhow::Result<Self> {
        let signing_key = SigningKey::from_bytes(&seed);
        let identity = identity_from_verifying_key(&signing_key.verifying_key())?;
        Ok(Self { signing_key, identity })
    }
}

/// Verify a signed witness envelope against a previously trusted identity.
///
/// Verification pins both the key id and raw public key to `expected`,
/// re-derives the SPKI-based key id, and uses Ed25519 strict verification over
/// the canonical JSON record. Consequently, replacing the inline public key
/// and re-signing with an attacker's key is rejected.
pub fn verify_witness_envelope(envelope: &Value, expected: &WitnessIdentity) -> anyhow::Result<()> {
    let record = envelope.get("record").context("witness envelope is missing record")?;
    let witness = envelope
        .get("witness")
        .and_then(Value::as_object)
        .context("witness envelope is missing witness object")?;
    let alg = string_field(witness, "alg")?;
    anyhow::ensure!(alg == "ed25519", "unsupported witness signature algorithm");

    let envelope_kid = string_field(witness, "kid")?;
    let envelope_public_key_b64 = string_field(witness, "public_key_b64")?;
    anyhow::ensure!(
        envelope_kid == expected.kid,
        "witness key id does not match expected identity"
    );
    anyhow::ensure!(
        envelope_public_key_b64 == expected.public_key_b64,
        "witness public key does not match expected identity"
    );

    let expected_public_key = decode_public_key(&expected.public_key_b64)
        .context("expected witness identity contains an invalid public key")?;
    let verifying_key =
        VerifyingKey::from_bytes(&expected_public_key).context("invalid expected Ed25519 public key")?;
    let derived_identity = identity_from_verifying_key(&verifying_key)?;
    anyhow::ensure!(
        derived_identity == *expected,
        "expected witness identity is not self-consistent"
    );

    let inline_public_key =
        decode_public_key(envelope_public_key_b64).context("witness envelope contains an invalid public key")?;
    anyhow::ensure!(
        inline_public_key == expected_public_key,
        "witness inline public key does not match expected identity"
    );
    let inline_verifying_key =
        VerifyingKey::from_bytes(&inline_public_key).context("invalid inline Ed25519 public key")?;
    let inline_identity = identity_from_verifying_key(&inline_verifying_key)?;
    anyhow::ensure!(
        inline_identity.kid == envelope_kid,
        "witness key id does not match inline public key"
    );

    let signature_b64 = string_field(witness, "sig_b64")?;
    let signature_bytes = base64::engine::general_purpose::STANDARD
        .decode(signature_b64)
        .context("invalid witness signature base64")?;
    let signature_array: [u8; SIGNATURE_BYTES] = signature_bytes.try_into().map_err(|bytes: Vec<u8>| {
        anyhow::anyhow!("witness signature is {} bytes, expected {SIGNATURE_BYTES}", bytes.len())
    })?;
    let signature = Signature::from_bytes(&signature_array);
    let signing_bytes = canonical_json_bytes(record)?;
    verifying_key
        .verify_strict(&signing_bytes, &signature)
        .context("witness signature verification failed")
}

/// Serialize a JSON value with object keys sorted recursively.
///
/// Array order is preserved because it is semantically significant. Witness
/// records contain ordinary JSON strings, booleans, integers, and nulls; this
/// sorted-key encoding is the canonical signature input for the witness-v1
/// schema.
pub fn canonical_json_bytes(value: &Value) -> anyhow::Result<Vec<u8>> {
    fn canonicalize(value: &Value) -> Value {
        match value {
            Value::Object(map) => {
                let mut entries: Vec<(&String, &Value)> = map.iter().collect();
                entries.sort_by(|left, right| left.0.cmp(right.0));
                let mut sorted = serde_json::Map::new();
                for (key, child) in entries {
                    sorted.insert(key.clone(), canonicalize(child));
                }
                Value::Object(sorted)
            }
            Value::Array(items) => Value::Array(items.iter().map(canonicalize).collect()),
            other => other.clone(),
        }
    }

    serde_json::to_vec(&canonicalize(value)).context("serializing canonical witness record JSON")
}

fn identity_from_verifying_key(verifying_key: &VerifyingKey) -> anyhow::Result<WitnessIdentity> {
    let spki = verifying_key
        .to_public_key_der()
        .context("encoding Ed25519 public key as SPKI DER")?;
    let spki_digest = Sha256::digest(spki.as_bytes());
    let digest_hex = hex::encode(spki_digest);
    let kid_suffix = digest_hex
        .get(..KID_HEX_CHARS)
        .context("SHA-256 hex digest was unexpectedly short")?;
    Ok(WitnessIdentity {
        kid: format!("wit_{kid_suffix}"),
        public_key_b64: base64::engine::general_purpose::STANDARD.encode(verifying_key.to_bytes()),
    })
}

fn string_field<'a>(object: &'a serde_json::Map<String, Value>, name: &str) -> anyhow::Result<&'a str> {
    object
        .get(name)
        .and_then(Value::as_str)
        .with_context(|| format!("witness envelope is missing string field {name}"))
}

fn decode_public_key(encoded: &str) -> anyhow::Result<[u8; PUBLIC_KEY_BYTES]> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .context("invalid public key base64")?;
    decoded.try_into().map_err(|bytes: Vec<u8>| {
        anyhow::anyhow!(
            "witness public key is {} bytes, expected {PUBLIC_KEY_BYTES}",
            bytes.len()
        )
    })
}

fn validate_existing_key(path: &Path, metadata: &fs::Metadata) -> anyhow::Result<()> {
    anyhow::ensure!(
        metadata.file_type().is_file() && !metadata.file_type().is_symlink(),
        "witness key {} must be a non-symlink regular file",
        path.display()
    );
    validate_key_permissions(path, metadata)
}

#[cfg(unix)]
fn validate_key_permissions(path: &Path, metadata: &fs::Metadata) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let mode = metadata.permissions().mode() & 0o777;
    anyhow::ensure!(
        mode.trailing_zeros() >= 6,
        "witness key {} has unsafe permissions {mode:o}; refusing a potentially disclosed key",
        path.display()
    );
    Ok(())
}

// These off-unix stubs mirror the signatures of their genuinely fallible unix
// counterparts, so the Result is not redundant — suppress rather than diverge.
#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
fn validate_key_permissions(_path: &Path, _metadata: &fs::Metadata) -> anyhow::Result<()> {
    Ok(())
}

fn parse_seed(path: &Path, content: &str) -> anyhow::Result<[u8; KEY_SEED_BYTES]> {
    let encoded = content
        .strip_suffix('\n')
        .with_context(|| format!("witness key file {} is incomplete", path.display()))?;
    anyhow::ensure!(!encoded.is_empty(), "witness key file {} is empty", path.display());
    let decoded = hex::decode(encoded).with_context(|| format!("decoding witness key {}", path.display()))?;
    decoded.try_into().map_err(|bytes: Vec<u8>| {
        anyhow::anyhow!(
            "witness key file {} contains {} bytes, expected {KEY_SEED_BYTES}",
            path.display(),
            bytes.len()
        )
    })
}

fn create_seed(path: &Path) -> anyhow::Result<[u8; KEY_SEED_BYTES]> {
    let mut seed = [0_u8; KEY_SEED_BYTES];
    rand::rng().fill_bytes(&mut seed);

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }

    match options.open(path) {
        Ok(mut file) => {
            let mut encoded = hex::encode(seed);
            encoded.push('\n');
            if let Err(err) = file.write_all(encoded.as_bytes()) {
                drop(file);
                let _ = fs::remove_file(path);
                return Err(err).with_context(|| format!("writing witness key {}", path.display()));
            }
            if let Err(err) = file.sync_all() {
                drop(file);
                let _ = fs::remove_file(path);
                return Err(err).with_context(|| format!("syncing witness key {}", path.display()));
            }
            set_key_owner_only(path)?;
            Ok(seed)
        }
        Err(err) if err.kind() == ErrorKind::AlreadyExists => read_seed_after_create_race(path),
        Err(err) => Err(err).with_context(|| format!("creating witness key {}", path.display())),
    }
}

fn read_seed_after_create_race(path: &Path) -> anyhow::Result<[u8; KEY_SEED_BYTES]> {
    for _ in 0..CREATE_RACE_RETRIES {
        match fs::read_to_string(path) {
            Ok(content) if !content.trim().is_empty() => {
                if let Ok(seed) = parse_seed(path, &content) {
                    let metadata = fs::symlink_metadata(path)
                        .with_context(|| format!("inspecting witness key {}", path.display()))?;
                    validate_existing_key(path, &metadata)?;
                    set_key_owner_only(path)?;
                    return Ok(seed);
                }
                std::thread::sleep(CREATE_RACE_RETRY_DELAY);
            }
            Ok(_) => std::thread::sleep(CREATE_RACE_RETRY_DELAY),
            Err(err) if err.kind() == ErrorKind::NotFound => std::thread::sleep(CREATE_RACE_RETRY_DELAY),
            Err(err) => return Err(err).with_context(|| format!("reading witness key {}", path.display())),
        }
    }
    anyhow::bail!(
        "witness key {} did not become complete and readable after concurrent creation",
        path.display()
    )
}

fn ensure_private_parent(path: &Path) -> anyhow::Result<()> {
    let Some(parent) = path.parent().filter(|parent| !parent.as_os_str().is_empty()) else {
        return Ok(());
    };
    match fs::symlink_metadata(parent) {
        Ok(metadata) => {
            anyhow::ensure!(
                metadata.file_type().is_dir() && !metadata.file_type().is_symlink(),
                "witness key parent {} must be a non-symlink directory",
                parent.display()
            );
            validate_directory_permissions(parent, &metadata)
        }
        Err(err) if err.kind() == ErrorKind::NotFound => {
            fs::create_dir_all(parent)
                .with_context(|| format!("creating witness key directory {}", parent.display()))?;
            set_directory_owner_only(parent)
        }
        Err(err) => Err(err).with_context(|| format!("inspecting witness key directory {}", parent.display())),
    }
}

#[cfg(unix)]
fn validate_directory_permissions(path: &Path, metadata: &fs::Metadata) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let mode = metadata.permissions().mode() & 0o777;
    anyhow::ensure!(
        mode & 0o022 == 0,
        "witness key directory {} is group/world writable ({mode:o})",
        path.display()
    );
    Ok(())
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
fn validate_directory_permissions(_path: &Path, _metadata: &fs::Metadata) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_directory_owner_only(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let mut permissions = fs::metadata(path)
        .with_context(|| format!("reading witness key directory permissions {}", path.display()))?
        .permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(path, permissions)
        .with_context(|| format!("setting witness key directory permissions {}", path.display()))
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
fn set_directory_owner_only(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_key_owner_only(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let mut permissions = fs::metadata(path)
        .with_context(|| format!("reading witness key permissions {}", path.display()))?
        .permissions();
    permissions.set_mode(0o600);
    fs::set_permissions(path, permissions)
        .with_context(|| format!("setting witness key permissions {}", path.display()))
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
fn set_key_owner_only(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_json_is_recursively_key_sorted() {
        let left = serde_json::json!({
            "z": 3,
            "a": {"y": true, "x": [3, 2, 1]},
            "m": null,
        });
        let right = serde_json::json!({
            "m": null,
            "a": {"x": [3, 2, 1], "y": true},
            "z": 3,
        });
        let canonical = canonical_json_bytes(&left).expect("canonical left");
        assert_eq!(canonical, canonical_json_bytes(&right).expect("canonical right"));
        assert_eq!(canonical, br#"{"a":{"x":[3,2,1],"y":true},"m":null,"z":3}"#);

        let reordered_array = serde_json::json!({"a": {"x": [1, 2, 3], "y": true}, "m": null, "z": 3});
        assert_ne!(
            canonical,
            canonical_json_bytes(&reordered_array).expect("canonical reordered array")
        );
    }

    #[test]
    fn key_is_private_and_reused() {
        let temp = tempfile::tempdir().expect("tempdir");
        let key_dir = temp.path().join("state").join("llm-shim");
        let key_path = key_dir.join("witness.key");
        let first = WitnessKey::load_or_create(&key_path).expect("first start");
        let first_identity = first.identity();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            let key_mode = fs::metadata(&key_path).expect("key metadata").permissions().mode() & 0o777;
            let dir_mode = fs::metadata(&key_dir).expect("dir metadata").permissions().mode() & 0o777;
            assert_eq!(key_mode, 0o600);
            assert_eq!(dir_mode, 0o700);
        }

        let second = WitnessKey::load_or_create(&key_path).expect("second start");
        assert_eq!(first_identity, second.identity());
        assert!(first_identity.kid.starts_with("wit_"));
        assert_eq!(first_identity.kid.len(), "wit_".len() + KID_HEX_CHARS);
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_existing_key_and_parent_custody_are_rejected() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};

        let temp = tempfile::tempdir().expect("tempdir");
        let key_dir = temp.path().join("unsafe");
        fs::create_dir(&key_dir).expect("key dir");
        let key_path = key_dir.join("witness.key");
        fs::write(&key_path, format!("{}\n", hex::encode([7_u8; KEY_SEED_BYTES]))).expect("fixture key");

        let mut key_permissions = fs::metadata(&key_path).expect("key metadata").permissions();
        key_permissions.set_mode(0o644);
        fs::set_permissions(&key_path, key_permissions).expect("unsafe key mode");
        assert!(WitnessKey::load_or_create(&key_path).is_err());

        fs::remove_file(&key_path).expect("remove unsafe key");
        let target = temp.path().join("target.key");
        fs::write(&target, format!("{}\n", hex::encode([8_u8; KEY_SEED_BYTES]))).expect("symlink target");
        let mut target_permissions = fs::metadata(&target).expect("target metadata").permissions();
        target_permissions.set_mode(0o600);
        fs::set_permissions(&target, target_permissions).expect("target mode");
        symlink(&target, &key_path).expect("key symlink");
        assert!(WitnessKey::load_or_create(&key_path).is_err());

        fs::remove_file(&key_path).expect("remove symlink");
        let mut dir_permissions = fs::metadata(&key_dir).expect("dir metadata").permissions();
        dir_permissions.set_mode(0o777);
        fs::set_permissions(&key_dir, dir_permissions).expect("unsafe dir mode");
        assert!(WitnessKey::load_or_create(&key_path).is_err());
    }

    #[test]
    #[allow(clippy::print_stdout)]
    fn valid_envelope_verifies_and_forgery_paths_fail() {
        let temp = tempfile::tempdir().expect("tempdir");
        let trusted = WitnessKey::load_or_create(&temp.path().join("trusted/witness.key")).expect("trusted key");
        let trusted_identity = trusted.identity();
        let record = serde_json::json!({
            "schema": "cuecrux.mediation.witness.v1",
            "kind": "cloud_request_witnessed",
            "request_digest": "sha256:001122",
        });
        let valid = trusted.sign_record(&record).expect("sign valid record");
        println!("WITNESS_SIGNED_EXAMPLE={valid}");
        verify_witness_envelope(&valid, &trusted_identity).expect("valid envelope");

        let mut altered = valid.clone();
        altered["record"]["request_digest"] = Value::String("sha256:101122".to_string());
        assert!(verify_witness_envelope(&altered, &trusted_identity).is_err());

        let attacker = WitnessKey::from_seed([0x42_u8; KEY_SEED_BYTES]).expect("attacker key");
        let mut attacker_record = record.clone();
        attacker_record["request_digest"] = Value::String("sha256:101122".to_string());
        let attacker_envelope = attacker
            .sign_record(&attacker_record)
            .expect("attacker signs altered record");
        assert!(verify_witness_envelope(&attacker_envelope, &trusted_identity).is_err());

        let mut mismatched_kid = valid;
        mismatched_kid["witness"]["kid"] = Value::String(attacker.identity().kid);
        assert!(verify_witness_envelope(&mismatched_kid, &trusted_identity).is_err());
    }

    #[test]
    fn unusable_key_path_is_reported_without_panicking() {
        let temp = tempfile::tempdir().expect("tempdir");
        assert!(WitnessKey::load_or_create(temp.path()).is_err());
    }
}
