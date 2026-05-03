// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Local passport synthesis for Crux Daemon (master-plan §3.2).
//!
//! On Crux Daemon the passport is derived deterministically from:
//! - an install UUID (per-install, stored on disk)
//! - a local user identifier (hostname-hash or configured username)
//!
//! The install UUID is hashed with BLAKE3 to produce `origin_install`, and
//! the principal_id takes the form `ce:<first-8-hex-of-install-hash>:<user>`.
//!
//! Hosted does **not** use this module — the passport comes from VaultCrux's
//! auth plugin and is resolved from a bearer JWT / API key.

use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

use blake3::Hasher;
use ed25519_dalek::{Signer as DalekSigner, SigningKey};

use crate::error::SessionError;
use crate::plan::{Passport, HASH_LEN, SIGNATURE_LEN};

/// Filename inside a Crux Daemon data directory that holds the durable install
/// UUID. First read on startup — generated + persisted if missing.
pub const INSTALL_UUID_FILENAME: &str = ".install-uuid";

/// Filename inside a Crux Daemon data directory that holds the durable local Passport
/// signing seed used for RCX free-local Capability Tokens.
pub const PASSPORT_KEY_FILENAME: &str = "passport.key";

const PASSPORT_FPR_BYTES: usize = 16;

#[derive(Debug, Clone)]
pub struct LocalPassportConfig {
    pub install_uuid: String,
    pub user: String,
}

#[derive(Clone)]
pub struct LocalPassportKey {
    signing_key: SigningKey,
    passport_fpr: String,
    public_key_hex: String,
}

impl std::fmt::Debug for LocalPassportKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalPassportKey")
            .field("passport_fpr", &self.passport_fpr)
            .field("public_key_hex", &self.public_key_hex)
            .finish_non_exhaustive()
    }
}

impl LocalPassportConfig {
    /// Load (or initialise) the Crux Daemon install UUID from `data_dir/.install-uuid`.
    ///
    /// On first call the file does not exist; we generate a new UUIDv4
    /// via the `uuid` crate and write it atomically. Subsequent calls
    /// read the stored value. This makes `principal_id` stable across
    /// corecruxd restarts — essential for audit, migration (M8), and
    /// any downstream system that keys on principal.
    pub fn from_data_dir(data_dir: &Path, user: impl Into<String>) -> Result<Self, SessionError> {
        let path = install_uuid_path(data_dir);
        let install_uuid = read_or_init_install_uuid(&path)?;
        Ok(Self {
            install_uuid,
            user: user.into(),
        })
    }
}

pub fn install_uuid_path(data_dir: &Path) -> PathBuf {
    data_dir.join(INSTALL_UUID_FILENAME)
}

pub fn passport_key_path(data_dir: &Path) -> PathBuf {
    data_dir.join(PASSPORT_KEY_FILENAME)
}

fn read_or_init_install_uuid(path: &Path) -> Result<String, SessionError> {
    match fs::read_to_string(path) {
        Ok(content) => {
            let trimmed = content.trim().to_string();
            if trimmed.is_empty() {
                return Err(SessionError::Encode(format!(
                    "install-uuid file {} is empty",
                    path.display()
                )));
            }
            Ok(trimmed)
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(|e| SessionError::Encode(format!("create data_dir: {e}")))?;
            }
            // Use a simple UUIDv4-like 32-char hex. The installation ID is
            // hashed with BLAKE3 before it ever leaves this machine (see
            // `synthesise`), so the exact format doesn't matter as long as
            // it's globally unique.
            let mut bytes = [0u8; 16];
            rand::Rng::fill(&mut rand::thread_rng(), &mut bytes[..]);
            let uuid = hex::encode(bytes);
            fs::write(path, &uuid).map_err(|e| SessionError::Encode(format!("write install-uuid: {e}")))?;
            Ok(uuid)
        }
        Err(e) => Err(SessionError::Encode(format!("read install-uuid: {e}"))),
    }
}

impl LocalPassportKey {
    /// Load (or initialise) the local RCX Passport signing key from
    /// `data_dir/passport.key`.
    ///
    /// The file stores only the 32-byte ed25519 seed as lowercase hex. The
    /// public fingerprint is derived from the verifying key, so it stays
    /// stable across daemon restarts without exposing private material.
    pub fn from_data_dir(data_dir: &Path) -> Result<Self, SessionError> {
        Self::from_seed(read_or_init_passport_seed(&passport_key_path(data_dir))?)
    }

    /// Load (or initialise) the local RCX Passport signing key from an
    /// explicit path. This supports the daemon v2 config topology where the
    /// Passport key may live outside the segment data directory.
    pub fn from_path(path: &Path) -> Result<Self, SessionError> {
        Self::from_seed(read_or_init_passport_seed(path)?)
    }

    pub fn from_seed(seed: [u8; 32]) -> Result<Self, SessionError> {
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        let public_key = verifying_key.to_bytes();
        let passport_fpr = passport_fpr_from_public_key(&public_key);
        let public_key_hex = hex::encode(public_key);
        Ok(Self {
            signing_key,
            passport_fpr,
            public_key_hex,
        })
    }

    pub fn passport_fpr(&self) -> &str {
        &self.passport_fpr
    }

    pub fn public_key_hex(&self) -> &str {
        &self.public_key_hex
    }

    pub fn sign_hash(&self, hash: &[u8; HASH_LEN]) -> [u8; SIGNATURE_LEN] {
        let sig = self.signing_key.sign(hash);
        let mut out = [0_u8; SIGNATURE_LEN];
        out.copy_from_slice(&sig.to_bytes());
        out
    }

    /// Derive a 32-byte subkey from this passport's seed for a domain-separated
    /// purpose (e.g. encrypting integration secrets at rest). Uses
    /// `blake3::derive_key` which is HKDF-style. The seed never leaves the
    /// `LocalPassportKey` instance — callers receive a domain-specific output
    /// they can use as a symmetric key.
    pub fn derive_subkey(&self, context: &str) -> [u8; 32] {
        let seed = self.signing_key.to_bytes();
        blake3::derive_key(context, &seed)
    }
}

fn read_or_init_passport_seed(path: &Path) -> Result<[u8; 32], SessionError> {
    match fs::read_to_string(path) {
        Ok(content) => parse_passport_seed(path, &content),
        Err(e) if e.kind() == ErrorKind::NotFound => write_new_passport_seed(path),
        Err(e) => Err(SessionError::Encode(format!("read passport key: {e}"))),
    }
}

fn parse_passport_seed(path: &Path, content: &str) -> Result<[u8; 32], SessionError> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Err(SessionError::Encode(format!(
            "passport key file {} is empty",
            path.display()
        )));
    }
    let decoded = hex::decode(trimmed)?;
    if decoded.len() != 32 {
        return Err(SessionError::ByteArrayLength {
            field: "passport.key",
            expected: 32,
            actual: decoded.len(),
        });
    }
    let mut seed = [0_u8; 32];
    seed.copy_from_slice(&decoded);
    Ok(seed)
}

fn write_new_passport_seed(path: &Path) -> Result<[u8; 32], SessionError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| SessionError::Encode(format!("create data_dir: {e}")))?;
    }

    let mut seed = [0_u8; 32];
    rand::Rng::fill(&mut rand::thread_rng(), &mut seed[..]);

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    match options.open(path) {
        Ok(mut file) => {
            file.write_all(hex::encode(seed).as_bytes())
                .map_err(|e| SessionError::Encode(format!("write passport key: {e}")))?;
            file.write_all(b"\n")
                .map_err(|e| SessionError::Encode(format!("write passport key: {e}")))?;
            Ok(seed)
        }
        Err(e) if e.kind() == ErrorKind::AlreadyExists => read_or_init_passport_seed(path),
        Err(e) => Err(SessionError::Encode(format!("create passport key: {e}"))),
    }
}

fn passport_fpr_from_public_key(public_key: &[u8; 32]) -> String {
    let digest = blake3::hash(public_key);
    format!("p_{}", hex::encode(&digest.as_bytes()[..PASSPORT_FPR_BYTES]))
}

impl LocalPassportConfig {
    pub fn synthesise(&self) -> (Passport, [u8; HASH_LEN]) {
        let install_hash = hash_install(&self.install_uuid);
        let principal_id = format!("ce:{}:{}", &hex::encode(install_hash)[..8], self.user);
        let passport = Passport {
            principal_id,
            tier: "local".to_string(),
            affinities: vec!["*".to_string()],
            passport_receipt: None,
        };
        (passport, install_hash)
    }
}

fn hash_install(install_uuid: &str) -> [u8; HASH_LEN] {
    let mut hasher = Hasher::new();
    hasher.update(install_uuid.as_bytes());
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthesise_is_deterministic() {
        let cfg = LocalPassportConfig {
            install_uuid: "a1b2c3d4-e5f6-7890-1234-567890abcdef".into(),
            user: "myles".into(),
        };
        let (pp1, h1) = cfg.synthesise();
        let (pp2, h2) = cfg.synthesise();
        assert_eq!(pp1.principal_id, pp2.principal_id);
        assert_eq!(h1, h2);
        assert!(pp1.principal_id.starts_with("ce:"));
        assert!(pp1.principal_id.ends_with(":myles"));
        assert_eq!(pp1.tier, "local");
        assert_eq!(pp1.affinities, vec!["*".to_string()]);
    }

    #[test]
    fn different_installs_produce_different_principals() {
        let cfg1 = LocalPassportConfig {
            install_uuid: "install-one".into(),
            user: "u".into(),
        };
        let cfg2 = LocalPassportConfig {
            install_uuid: "install-two".into(),
            user: "u".into(),
        };
        let (pp1, _) = cfg1.synthesise();
        let (pp2, _) = cfg2.synthesise();
        assert_ne!(pp1.principal_id, pp2.principal_id);
    }

    #[test]
    fn from_data_dir_initialises_and_persists_install_uuid() {
        let tmp = std::env::temp_dir().join(format!("crux-session-test-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&tmp).unwrap();
        let cfg1 = LocalPassportConfig::from_data_dir(&tmp, "myles").unwrap();
        let cfg2 = LocalPassportConfig::from_data_dir(&tmp, "myles").unwrap();
        assert_eq!(
            cfg1.install_uuid, cfg2.install_uuid,
            "install UUID must persist across reads"
        );
        let (pp1, _) = cfg1.synthesise();
        let (pp2, _) = cfg2.synthesise();
        assert_eq!(pp1.principal_id, pp2.principal_id);
        // Cleanup
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn from_data_dir_errors_on_empty_file() {
        let tmp = std::env::temp_dir().join(format!("crux-session-test-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(install_uuid_path(&tmp), "").unwrap();
        let result = LocalPassportConfig::from_data_dir(&tmp, "myles");
        assert!(result.is_err());
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn from_data_dir_different_dirs_produce_different_installs() {
        let tmp1 = std::env::temp_dir().join(format!("crux-session-test-{}", rand::random::<u64>()));
        let tmp2 = std::env::temp_dir().join(format!("crux-session-test-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&tmp1).unwrap();
        std::fs::create_dir_all(&tmp2).unwrap();
        let cfg1 = LocalPassportConfig::from_data_dir(&tmp1, "u").unwrap();
        let cfg2 = LocalPassportConfig::from_data_dir(&tmp2, "u").unwrap();
        assert_ne!(cfg1.install_uuid, cfg2.install_uuid);
        std::fs::remove_dir_all(&tmp1).ok();
        std::fs::remove_dir_all(&tmp2).ok();
    }

    #[test]
    fn passport_key_initialises_and_persists_identity() {
        let tmp = std::env::temp_dir().join(format!("crux-session-passport-key-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&tmp).unwrap();
        let key1 = LocalPassportKey::from_data_dir(&tmp).unwrap();
        let key2 = LocalPassportKey::from_data_dir(&tmp).unwrap();

        assert_eq!(key1.passport_fpr(), key2.passport_fpr());
        assert_eq!(key1.public_key_hex(), key2.public_key_hex());
        assert!(key1.passport_fpr().starts_with("p_"));
        assert_eq!(key1.passport_fpr().len(), 34);

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn passport_key_initialises_from_explicit_path() {
        let tmp = std::env::temp_dir().join(format!("crux-session-passport-path-{}", rand::random::<u64>()));
        let key_path = tmp.join("keys").join("passport.key");
        let key1 = LocalPassportKey::from_path(&key_path).unwrap();
        let key2 = LocalPassportKey::from_path(&key_path).unwrap();

        assert_eq!(key1.passport_fpr(), key2.passport_fpr());
        assert_eq!(key1.public_key_hex(), key2.public_key_hex());
        assert!(key_path.exists());

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn passport_key_signs_hash_with_ed25519() {
        use ed25519_dalek::Verifier as _;

        let key = LocalPassportKey::from_seed([7_u8; 32]).unwrap();
        let hash = [9_u8; HASH_LEN];
        let signature = ed25519_dalek::Signature::from_bytes(&key.sign_hash(&hash));
        key.signing_key
            .verifying_key()
            .verify(&hash, &signature)
            .expect("signature should verify");
    }
}
