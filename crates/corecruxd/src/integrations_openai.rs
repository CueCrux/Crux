// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! OpenAI integration — encrypted API key storage + verification + status.
//!
//! On-disk layout (under `data_dir/integrations/openai/`):
//! - `credentials.json` — `OpenAiCredentials { encrypted_api_key, organization_id?,
//!   default_model?, connected_at_unix_ms, last_verified_at_unix_ms? }`. The API key
//!   itself never appears in plaintext; the envelope is sealed with the daemon-root
//!   passport-derived key (see `crate::encrypted_secrets`).
//!
//! Verification uses `GET https://api.openai.com/v1/models` — succeeds iff the key
//! has at least `models.read` permission. We deliberately don't require any
//! higher-privilege probe, so a read-only project key is accepted.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::encrypted_secrets::{EncryptedEnvelope, EncryptedSecretError};

#[derive(Debug, thiserror::Error)]
pub enum OpenAiIntegrationError {
    #[error("not connected: no credentials on disk")]
    NotConnected,
    #[error("API key verification failed: {0}")]
    VerifyFailed(String),
    #[error("network: {0}")]
    Network(String),
    #[error(transparent)]
    Encryption(#[from] EncryptedSecretError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpenAiCredentials {
    pub encrypted_api_key: EncryptedEnvelope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_model: Option<String>,
    /// Cached subset of model ids returned by /v1/models on the most recent
    /// verification — surfaces in the connect response so the UI can offer a
    /// "default model" picker without hitting the API again.
    #[serde(default)]
    pub available_models: Vec<String>,
    pub connected_at_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_verified_at_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OpenAiStatus {
    pub connected: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_model: Option<String>,
    #[serde(default)]
    pub available_models: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connected_at_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_verified_at_unix_ms: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct VerifiedKey {
    pub available_models: Vec<String>,
}

pub fn read_status(data_dir: &Path) -> OpenAiStatus {
    match read_credentials(data_dir) {
        Ok(creds) => OpenAiStatus {
            connected: true,
            organization_id: creds.organization_id,
            default_model: creds.default_model,
            available_models: creds.available_models,
            connected_at_unix_ms: Some(creds.connected_at_unix_ms),
            last_verified_at_unix_ms: creds.last_verified_at_unix_ms,
        },
        Err(_) => OpenAiStatus {
            connected: false,
            organization_id: None,
            default_model: None,
            available_models: Vec::new(),
            connected_at_unix_ms: None,
            last_verified_at_unix_ms: None,
        },
    }
}

pub fn read_credentials(data_dir: &Path) -> Result<OpenAiCredentials, OpenAiIntegrationError> {
    let path = credentials_path(data_dir);
    if !path.exists() {
        return Err(OpenAiIntegrationError::NotConnected);
    }
    let bytes = fs::read(&path)?;
    let creds: OpenAiCredentials = serde_json::from_slice(&bytes)?;
    Ok(creds)
}

pub fn write_credentials(data_dir: &Path, creds: &OpenAiCredentials) -> Result<(), OpenAiIntegrationError> {
    let path = credentials_path(data_dir);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, serde_json::to_vec_pretty(creds)?)?;
    fs::rename(tmp, &path)?;
    set_owner_only_perms(&path)?;
    Ok(())
}

pub fn delete_credentials(data_dir: &Path) -> Result<(), OpenAiIntegrationError> {
    let path = credentials_path(data_dir);
    if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(())
}

#[allow(dead_code)] // Read by future LLM proxy / completion routes.
pub fn decrypt_api_key(creds: &OpenAiCredentials, key: &[u8; 32]) -> Result<String, OpenAiIntegrationError> {
    let bytes = crate::encrypted_secrets::open(&creds.encrypted_api_key, key)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Verify an OpenAI API key by hitting `GET https://api.openai.com/v1/models`.
/// Blocking — caller must dispatch via `tokio::task::spawn_blocking`.
pub fn verify_api_key(api_key: &str, organization_id: Option<&str>) -> Result<VerifiedKey, OpenAiIntegrationError> {
    let trimmed = api_key.trim();
    if trimmed.is_empty() {
        return Err(OpenAiIntegrationError::VerifyFailed("API key is empty".to_string()));
    }
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(10)))
        .build()
        .into();
    let mut req = agent
        .get("https://api.openai.com/v1/models")
        .header("Authorization", &format!("Bearer {trimmed}"))
        .header("User-Agent", "crux-daemon");
    if let Some(org) = organization_id {
        let org = org.trim();
        if !org.is_empty() {
            req = req.header("OpenAI-Organization", org);
        }
    }
    let mut response = req
        .call()
        .map_err(|e| OpenAiIntegrationError::Network(e.to_string()))?;
    let status = response.status().as_u16();
    let body = response
        .body_mut()
        .read_to_string()
        .map_err(|e| OpenAiIntegrationError::Network(e.to_string()))?;
    if status != 200 {
        return Err(OpenAiIntegrationError::VerifyFailed(format!(
            "openai returned {status}: {}",
            truncate(&body, 256)
        )));
    }
    let parsed: serde_json::Value = serde_json::from_str(&body)?;
    let mut models: Vec<String> = parsed
        .get("data")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|m| m.get("id").and_then(|s| s.as_str()).map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    // Sort for stable display; cap to 64 to keep credential file small.
    models.sort();
    models.truncate(64);
    Ok(VerifiedKey { available_models: models })
}

fn credentials_path(data_dir: &Path) -> PathBuf {
    data_dir.join("integrations").join("openai").join("credentials.json")
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max])
    }
}

#[cfg(unix)]
fn set_owner_only_perms(path: &Path) -> Result<(), OpenAiIntegrationError> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_owner_only_perms(_path: &Path) -> Result<(), OpenAiIntegrationError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encrypted_secrets::seal;

    fn sample_creds() -> (OpenAiCredentials, [u8; 32]) {
        let key = [7u8; 32];
        let envelope = seal(b"sk-test-12345", &key);
        (
            OpenAiCredentials {
                encrypted_api_key: envelope,
                organization_id: Some("org-abc".to_string()),
                default_model: Some("gpt-4o-mini".to_string()),
                available_models: vec!["gpt-4o".into(), "gpt-4o-mini".into()],
                connected_at_unix_ms: 1_700_000_000_000,
                last_verified_at_unix_ms: Some(1_700_000_000_000),
            },
            key,
        )
    }

    #[test]
    fn status_disconnected_when_no_credentials() {
        let dir = std::env::temp_dir().join(format!("crux-openai-test-{}", uuid_like()));
        let s = read_status(&dir);
        assert!(!s.connected);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_then_read_round_trips() {
        let dir = std::env::temp_dir().join(format!("crux-openai-rt-{}", uuid_like()));
        let (creds, _key) = sample_creds();
        write_credentials(&dir, &creds).expect("write");
        let loaded = read_credentials(&dir).expect("read");
        assert_eq!(loaded, creds);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn delete_removes_file_idempotent() {
        let dir = std::env::temp_dir().join(format!("crux-openai-del-{}", uuid_like()));
        let (creds, _key) = sample_creds();
        write_credentials(&dir, &creds).expect("write");
        delete_credentials(&dir).expect("delete");
        assert!(!read_status(&dir).connected);
        delete_credentials(&dir).expect("second delete is a no-op");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn decrypt_api_key_round_trips() {
        let (creds, key) = sample_creds();
        let plaintext = decrypt_api_key(&creds, &key).expect("decrypt");
        assert_eq!(plaintext, "sk-test-12345");
    }

    #[test]
    fn verify_rejects_empty_key() {
        let err = verify_api_key("", None).expect_err("empty rejected");
        assert!(matches!(err, OpenAiIntegrationError::VerifyFailed(_)));
    }

    fn uuid_like() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    }
}
