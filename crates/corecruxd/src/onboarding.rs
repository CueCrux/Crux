// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Persistent state for the embedded Crux Console first-run flow.
//!
//! State lives at `data_dir/console/settings.json` and is written atomically
//! via tmp-then-rename (mirrors `console_index.rs`). The schema is forward-
//! compatible: unknown fields are preserved across reads.

use std::fs;
use std::path::{Path, PathBuf};

const SETTINGS_SCHEMA_V1: &str = "crux.console.settings.v1";

#[derive(Debug, thiserror::Error)]
pub enum OnboardingError {
    #[error("invalid console settings schema '{0}'")]
    InvalidSchema(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq, Default)]
pub struct OnboardingState {
    /// Unix-ms when the user dismissed onboarding. `None` means show onboarding
    /// on next page load.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at_unix_ms: Option<u64>,
    /// Auth mode the user picked during onboarding (informational; the actual
    /// running mode is `AppState::auth`). Useful for surfacing "you chose X but
    /// container is running Y — restart to apply".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chosen_auth_mode: Option<String>,
    /// Operator-chosen embedding endpoint URL (overrides the env-set default
    /// at next daemon restart). `None` means "use whatever the env said".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chosen_embedding_url: Option<String>,
    /// Operator-chosen embedding model name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chosen_embedding_model: Option<String>,
    /// Whether the embedding feature is intended to be on. Persisted intent;
    /// actual liveness depends on whether `CORECRUXD_EMBEDDING_URL` was set
    /// when the daemon started.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embedding_enabled: Option<bool>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
struct StoredSettings {
    schema: String,
    #[serde(default)]
    onboarding: OnboardingState,
}

impl Default for StoredSettings {
    fn default() -> Self {
        Self {
            schema: SETTINGS_SCHEMA_V1.to_string(),
            onboarding: OnboardingState::default(),
        }
    }
}

pub fn read_state(data_dir: &Path) -> Result<OnboardingState, OnboardingError> {
    let path = settings_path(data_dir);
    if !path.exists() {
        return Ok(OnboardingState::default());
    }
    let bytes = fs::read(&path)?;
    let stored: StoredSettings = serde_json::from_slice(&bytes)?;
    if stored.schema != SETTINGS_SCHEMA_V1 {
        return Err(OnboardingError::InvalidSchema(stored.schema));
    }
    Ok(stored.onboarding)
}

pub fn write_state(data_dir: &Path, state: &OnboardingState) -> Result<(), OnboardingError> {
    let stored = StoredSettings {
        schema: SETTINGS_SCHEMA_V1.to_string(),
        onboarding: state.clone(),
    };
    let path = settings_path(data_dir);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, serde_json::to_vec_pretty(&stored)?)?;
    fs::rename(tmp, path)?;
    Ok(())
}

fn settings_path(data_dir: &Path) -> PathBuf {
    data_dir.join("console").join("settings.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let dir = std::env::temp_dir().join(format!("corecruxd-onboarding-{name}-{nanos}"));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn missing_settings_returns_default() {
        let dir = temp_dir("missing");
        let state = read_state(&dir).expect("read default");
        assert_eq!(state, OnboardingState::default());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn round_trip_preserves_state() {
        let dir = temp_dir("roundtrip");
        let state = OnboardingState {
            completed_at_unix_ms: Some(1_700_000_000_000),
            chosen_auth_mode: Some("dev_scopes".to_string()),
            chosen_embedding_url: Some("http://localhost:11434".to_string()),
            chosen_embedding_model: Some("nomic-embed-text".to_string()),
            embedding_enabled: Some(true),
        };
        write_state(&dir, &state).expect("write");
        let loaded = read_state(&dir).expect("read");
        assert_eq!(loaded, state);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn unknown_schema_rejected() {
        let dir = temp_dir("badschema");
        fs::create_dir_all(dir.join("console")).expect("mkdir");
        fs::write(
            dir.join("console").join("settings.json"),
            br#"{"schema":"crux.console.settings.v999","onboarding":{}}"#,
        )
        .expect("write bad schema");
        let err = read_state(&dir).expect_err("should reject");
        assert!(matches!(err, OnboardingError::InvalidSchema(_)));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_creates_console_subdir() {
        let dir = temp_dir("subdir");
        write_state(&dir, &OnboardingState::default()).expect("write");
        assert!(dir.join("console").join("settings.json").exists());
        let _ = fs::remove_dir_all(&dir);
    }
}
