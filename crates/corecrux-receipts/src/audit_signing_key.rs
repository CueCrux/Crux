// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Shared audit-export signing-key resolution.
//!
//! Environment configuration takes precedence. Without an environment key, a
//! caller with a data directory gets a stable key generated once and stored as
//! an owner-only file. Callers without a data directory retain the historical
//! ephemeral fallback so library-only and in-memory use remains possible.

use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use base64::Engine as _;
use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore as _};
use thiserror::Error;

use crate::AuditBundleKeyClassV1;

/// Environment variable carrying an Ed25519 secret key in base64.
pub const AUDIT_EXPORT_SIGNING_KEY_ENV: &str = "CORECRUXD_AUDIT_EXPORT_SIGNING_KEY_B64";
/// Optional human-readable signer key id embedded in the bundle manifest.
pub const AUDIT_EXPORT_SIGNING_KEY_ID_ENV: &str = "CORECRUXD_AUDIT_EXPORT_KEY_ID";
/// Data-dir-relative file containing the raw 32-byte persistent signing key.
pub const AUDIT_EXPORT_SIGNING_KEY_FILENAME: &str = "audit-export-signing.key";

/// A signing key together with the signed provenance metadata a bundle must
/// carry for that key.
pub struct ResolvedAuditSigningKey {
    pub signing_key: SigningKey,
    pub signer_key_id: String,
    pub key_class: AuditBundleKeyClassV1,
}

#[derive(Debug, Error)]
pub enum AuditSigningKeyError {
    #[error("{AUDIT_EXPORT_SIGNING_KEY_ENV} is not valid base64 containing at least 32 bytes")]
    InvalidEnvironmentKey,
    #[error("persistent audit-export signing key at {path} must contain exactly 32 bytes, got {actual}")]
    InvalidPersistentKeyLength { path: PathBuf, actual: usize },
    #[error("failed to access audit-export signing key at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("audit-export signing-key resolver lock was poisoned")]
    ResolverLockPoisoned,
}

/// Return the stable key-file path used beneath a daemon data directory.
pub fn persistent_audit_export_signing_key_path(data_dir: &Path) -> PathBuf {
    data_dir.join(AUDIT_EXPORT_SIGNING_KEY_FILENAME)
}

/// Resolve an audit-export signer with strict precedence:
///
/// 1. `CORECRUXD_AUDIT_EXPORT_SIGNING_KEY_B64` (`key_class = env`);
/// 2. a generated-once 0600 key under `data_dir` (`persistent`);
/// 3. a one-shot key only when `data_dir` is unavailable (`ephemeral`).
///
/// A configured but malformed environment value is an error; it never causes
/// a silent fallback to a different issuer identity.
pub fn resolve_audit_export_signing_key(
    data_dir: Option<&Path>,
) -> Result<ResolvedAuditSigningKey, AuditSigningKeyError> {
    let signer_key_id = std::env::var(AUDIT_EXPORT_SIGNING_KEY_ID_ENV).unwrap_or_default();
    if let Some(signing_key) = signing_key_from_environment()? {
        return Ok(ResolvedAuditSigningKey {
            signing_key,
            signer_key_id,
            key_class: AuditBundleKeyClassV1::Env,
        });
    }

    if let Some(data_dir) = data_dir {
        let signing_key = load_or_create_persistent_key(data_dir)?;
        return Ok(ResolvedAuditSigningKey {
            signing_key,
            signer_key_id,
            key_class: AuditBundleKeyClassV1::Persistent,
        });
    }

    Ok(ResolvedAuditSigningKey {
        signing_key: generate_signing_key(),
        signer_key_id,
        key_class: AuditBundleKeyClassV1::Ephemeral,
    })
}

fn signing_key_from_environment() -> Result<Option<SigningKey>, AuditSigningKeyError> {
    let Ok(encoded) = std::env::var(AUDIT_EXPORT_SIGNING_KEY_ENV) else {
        return Ok(None);
    };
    let raw = encoded.trim();
    for engine in [
        base64::engine::general_purpose::STANDARD,
        base64::engine::general_purpose::STANDARD_NO_PAD,
        base64::engine::general_purpose::URL_SAFE,
        base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ] {
        if let Ok(decoded) = engine.decode(raw) {
            if decoded.len() >= 32 {
                let mut secret = [0u8; 32];
                secret.copy_from_slice(&decoded[..32]);
                return Ok(Some(SigningKey::from_bytes(&secret)));
            }
        }
    }
    Err(AuditSigningKeyError::InvalidEnvironmentKey)
}

fn load_or_create_persistent_key(data_dir: &Path) -> Result<SigningKey, AuditSigningKeyError> {
    static CREATE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let _guard = CREATE_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| AuditSigningKeyError::ResolverLockPoisoned)?;

    fs::create_dir_all(data_dir).map_err(|source| AuditSigningKeyError::Io {
        path: data_dir.to_path_buf(),
        source,
    })?;
    let path = persistent_audit_export_signing_key_path(data_dir);
    match fs::read(&path) {
        Ok(bytes) => {
            set_owner_only_permissions(&path)?;
            signing_key_from_persistent_bytes(&path, &bytes)
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => create_persistent_key(&path),
        Err(source) => Err(AuditSigningKeyError::Io { path, source }),
    }
}

fn create_persistent_key(path: &Path) -> Result<SigningKey, AuditSigningKeyError> {
    let key = generate_signing_key();
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }

    match options.open(path) {
        Ok(mut file) => {
            file.write_all(&key.to_bytes())
                .and_then(|()| file.sync_all())
                .map_err(|source| AuditSigningKeyError::Io {
                    path: path.to_path_buf(),
                    source,
                })?;
            set_owner_only_permissions(path)?;
            Ok(key)
        }
        // Defensive cross-process race handling. The process-local mutex covers
        // concurrent daemon requests; create_new also protects against a second
        // process winning between the initial read and create.
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            let bytes = fs::read(path).map_err(|source| AuditSigningKeyError::Io {
                path: path.to_path_buf(),
                source,
            })?;
            set_owner_only_permissions(path)?;
            signing_key_from_persistent_bytes(path, &bytes)
        }
        Err(source) => Err(AuditSigningKeyError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn signing_key_from_persistent_bytes(path: &Path, bytes: &[u8]) -> Result<SigningKey, AuditSigningKeyError> {
    let secret: [u8; 32] = bytes
        .try_into()
        .map_err(|_| AuditSigningKeyError::InvalidPersistentKeyLength {
            path: path.to_path_buf(),
            actual: bytes.len(),
        })?;
    Ok(SigningKey::from_bytes(&secret))
}

fn generate_signing_key() -> SigningKey {
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    SigningKey::from_bytes(&secret)
}

#[cfg(unix)]
fn set_owner_only_permissions(path: &Path) -> Result<(), AuditSigningKeyError> {
    use std::os::unix::fs::PermissionsExt as _;
    let permissions = fs::Permissions::from_mode(0o600);
    fs::set_permissions(path, permissions).map_err(|source| AuditSigningKeyError::Io {
        path: path.to_path_buf(),
        source,
    })
}

// Signature mirrors the unix implementation, which is genuinely fallible; the
// Result is not redundant there, so the lint is suppressed rather than obeyed.
#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
fn set_owner_only_permissions(_path: &Path) -> Result<(), AuditSigningKeyError> {
    Ok(())
}
