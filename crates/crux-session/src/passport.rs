// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Local passport synthesis for Crux CE (master-plan §3.2).
//!
//! On CE the passport is derived deterministically from:
//! - an install UUID (per-install, stored on disk)
//! - a local user identifier (hostname-hash or configured username)
//!
//! The install UUID is hashed with BLAKE3 to produce `origin_install`, and
//! the principal_id takes the form `ce:<first-8-hex-of-install-hash>:<user>`.
//!
//! Hosted does **not** use this module — the passport comes from VaultCrux's
//! auth plugin and is resolved from a bearer JWT / API key.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use blake3::Hasher;

use crate::error::SessionError;
use crate::plan::{Passport, HASH_LEN};

/// Filename inside a CE data directory that holds the durable install
/// UUID. First read on startup — generated + persisted if missing.
pub const INSTALL_UUID_FILENAME: &str = ".install-uuid";

#[derive(Debug, Clone)]
pub struct LocalPassportConfig {
    pub install_uuid: String,
    pub user: String,
}

impl LocalPassportConfig {
    /// Load (or initialise) the CE install UUID from `data_dir/.install-uuid`.
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

fn read_or_init_install_uuid(path: &Path) -> Result<String, SessionError> {
    match fs::read_to_string(path) {
        Ok(content) => {
            let trimmed = content.trim().to_string();
            if trimmed.is_empty() {
                return Err(SessionError::Encode(format!(
                    "install-uuid file {path:?} is empty"
                )));
            }
            Ok(trimmed)
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)
                    .map_err(|e| SessionError::Encode(format!("create data_dir: {e}")))?;
            }
            // Use a simple UUIDv4-like 32-char hex. The installation ID is
            // hashed with BLAKE3 before it ever leaves this machine (see
            // `synthesise`), so the exact format doesn't matter as long as
            // it's globally unique.
            let mut bytes = [0u8; 16];
            rand::Rng::fill(&mut rand::thread_rng(), &mut bytes[..]);
            let uuid = hex::encode(bytes);
            fs::write(path, &uuid)
                .map_err(|e| SessionError::Encode(format!("write install-uuid: {e}")))?;
            Ok(uuid)
        }
        Err(e) => Err(SessionError::Encode(format!("read install-uuid: {e}"))),
    }
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
}
