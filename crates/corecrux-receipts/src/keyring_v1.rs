// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

use std::collections::BTreeMap;

use base64::Engine as _;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum KeyRingError {
    #[error("keyring json parse error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid keyring: {msg}")]
    Invalid { msg: String },
    #[error("invalid base64 pubkey for key_id={key_id}: {msg}")]
    InvalidPubKey { key_id: String, msg: String },
}

/// Minimal Phase 8 keyring format (snapshot-friendly).
///
/// Note: this is intentionally not a full JWKS implementation yet; it is enough to
/// support deterministic ed25519 verification by `key_id`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Ed25519KeyRingV1 {
    pub v: u32,
    pub keys: Vec<Ed25519KeyEntryV1>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Ed25519KeyEntryV1 {
    #[serde(rename = "keyId")]
    pub key_id: String,
    /// Base64-encoded 32-byte ed25519 public key.
    #[serde(rename = "pubKeyBase64")]
    pub pub_key_base64: String,
}

impl Ed25519KeyRingV1 {
    pub fn parse_json(input: &str) -> Result<Self, KeyRingError> {
        let v: Ed25519KeyRingV1 = serde_json::from_str(input)?;
        if v.v != 1 {
            return Err(KeyRingError::Invalid {
                msg: format!("unsupported keyring version {}", v.v),
            });
        }
        if v.keys.is_empty() {
            return Err(KeyRingError::Invalid {
                msg: "keyring has no keys".to_string(),
            });
        }
        for k in &v.keys {
            if k.key_id.trim().is_empty() {
                return Err(KeyRingError::Invalid {
                    msg: "keyring contains empty keyId".to_string(),
                });
            }
        }
        Ok(v)
    }

    pub fn to_index_map(&self) -> Result<BTreeMap<String, [u8; 32]>, KeyRingError> {
        let mut out = BTreeMap::new();
        for k in &self.keys {
            let raw = base64::engine::general_purpose::STANDARD
                .decode(&k.pub_key_base64)
                .map_err(|e| KeyRingError::InvalidPubKey {
                    key_id: k.key_id.clone(),
                    msg: e.to_string(),
                })?;
            if raw.len() != 32 {
                return Err(KeyRingError::InvalidPubKey {
                    key_id: k.key_id.clone(),
                    msg: format!("expected 32 bytes, got {}", raw.len()),
                });
            }
            let mut pk = [0u8; 32];
            pk.copy_from_slice(&raw);
            out.insert(k.key_id.clone(), pk);
        }
        Ok(out)
    }
}
