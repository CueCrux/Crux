// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `.crux/agent-profile.toml` reader + writer.
//!
//! The config file is committed to the workspace. It records which profiles
//! are enabled (with version pins), the workspace fingerprint, and the
//! target filenames. Atomic-write on save via tempfile + rename.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("config file not found at {0}")]
    NotFound(PathBuf),
    #[error("config already exists at {0} (use `regenerate` instead of `init`)")]
    AlreadyExists(PathBuf),
    #[error("config io error: {0}")]
    Io(String),
    #[error("config TOML error: {0}")]
    Toml(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProfileEntry {
    pub version: u32,
    pub enabled_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TargetsConfig {
    #[serde(default = "default_claude_md")]
    pub claude_md: String,
    #[serde(default = "default_agents_md")]
    pub agents_md: String,
}

fn default_claude_md() -> String {
    "CLAUDE.md".into()
}
fn default_agents_md() -> String {
    "AGENTS.md".into()
}

impl Default for TargetsConfig {
    fn default() -> Self {
        Self {
            claude_md: default_claude_md(),
            agents_md: default_agents_md(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentProfileConfig {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    pub workspace_fingerprint: String,
    #[serde(default)]
    pub profiles: BTreeMap<String, ProfileEntry>,
    #[serde(default)]
    pub targets: TargetsConfig,
}

fn default_schema_version() -> u32 {
    1
}

impl AgentProfileConfig {
    pub fn new(workspace_fingerprint: String) -> Self {
        Self {
            schema_version: default_schema_version(),
            workspace_fingerprint,
            profiles: BTreeMap::new(),
            targets: TargetsConfig::default(),
        }
    }

    pub fn relative_path() -> &'static Path {
        Path::new(".crux/agent-profile.toml")
    }

    pub fn workspace_path(workspace_root: &Path) -> PathBuf {
        workspace_root.join(Self::relative_path())
    }

    /// Load from `<workspace_root>/.crux/agent-profile.toml`.
    pub fn load(workspace_root: &Path) -> Result<Self, ConfigError> {
        let path = Self::workspace_path(workspace_root);
        if !path.exists() {
            return Err(ConfigError::NotFound(path));
        }
        let raw = fs::read_to_string(&path).map_err(|e| ConfigError::Io(e.to_string()))?;
        let cfg: Self = toml::from_str(&raw).map_err(|e| ConfigError::Toml(e.to_string()))?;
        Ok(cfg)
    }

    /// Atomic save: write to a tempfile then rename, so a crash mid-write
    /// leaves the previous file intact (per Constraint "atomic writes").
    pub fn save(&self, workspace_root: &Path) -> Result<(), ConfigError> {
        let path = Self::workspace_path(workspace_root);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| ConfigError::Io(e.to_string()))?;
        }
        let tmp = path.with_extension("toml.tmp");
        let serialised = toml::to_string_pretty(self).map_err(|e| ConfigError::Toml(e.to_string()))?;
        {
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp)
                .map_err(|e| ConfigError::Io(e.to_string()))?;
            f.write_all(serialised.as_bytes())
                .map_err(|e| ConfigError::Io(e.to_string()))?;
            f.sync_all().map_err(|e| ConfigError::Io(e.to_string()))?;
        }
        fs::rename(&tmp, &path).map_err(|e| ConfigError::Io(e.to_string()))?;
        Ok(())
    }

    pub fn enable(&mut self, name: &str, version: u32) {
        self.profiles.insert(
            name.to_string(),
            ProfileEntry {
                version,
                enabled_at: Utc::now(),
            },
        );
    }

    pub fn disable(&mut self, name: &str) -> bool {
        self.profiles.remove(name).is_some()
    }
}

/// Workspace fingerprint = BLAKE3 hash of the absolute path. Stable across
/// runs, distinct per workspace. Used so the runtime fact namespace can
/// distinguish multiple workspaces sharing the same Crux daemon.
pub fn workspace_fingerprint(workspace_root: &Path) -> String {
    let canonical = workspace_root
        .canonicalize()
        .unwrap_or_else(|_| workspace_root.to_path_buf());
    let bytes = canonical.to_string_lossy().as_bytes().to_vec();
    let hash = blake3::hash(&bytes);
    format!("blake3:{}", hash.to_hex())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn save_and_load_round_trip() {
        let dir = TempDir::new().unwrap();
        let mut cfg = AgentProfileConfig::new("blake3:abc".into());
        cfg.enable("memory-practices", 1);
        cfg.enable("eu-ai-act", 1);
        cfg.save(dir.path()).unwrap();
        let loaded = AgentProfileConfig::load(dir.path()).unwrap();
        assert_eq!(loaded.workspace_fingerprint, "blake3:abc");
        assert_eq!(loaded.profiles.len(), 2);
        assert!(loaded.profiles.contains_key("memory-practices"));
    }

    #[test]
    fn load_missing_errors() {
        let dir = TempDir::new().unwrap();
        let err = AgentProfileConfig::load(dir.path()).unwrap_err();
        assert!(matches!(err, ConfigError::NotFound(_)));
    }

    #[test]
    fn disable_removes_entry() {
        let mut cfg = AgentProfileConfig::new("x".into());
        cfg.enable("a", 1);
        cfg.enable("b", 1);
        assert!(cfg.disable("a"));
        assert!(!cfg.disable("a"));
        assert_eq!(cfg.profiles.len(), 1);
    }

    #[test]
    fn fingerprint_is_stable() {
        let dir = TempDir::new().unwrap();
        let f1 = workspace_fingerprint(dir.path());
        let f2 = workspace_fingerprint(dir.path());
        assert_eq!(f1, f2);
        assert!(f1.starts_with("blake3:"));
    }

    #[test]
    fn fingerprint_differs_per_workspace() {
        let a = TempDir::new().unwrap();
        let b = TempDir::new().unwrap();
        assert_ne!(workspace_fingerprint(a.path()), workspace_fingerprint(b.path()));
    }

    #[test]
    fn workspace_path_uses_dot_crux_dir() {
        let p = AgentProfileConfig::workspace_path(std::path::Path::new("/tmp/ws"));
        assert!(p.ends_with(".crux/agent-profile.toml"));
    }

    #[test]
    fn relative_path_under_dot_crux() {
        assert_eq!(
            AgentProfileConfig::relative_path(),
            std::path::Path::new(".crux/agent-profile.toml")
        );
    }

    #[test]
    fn targets_config_defaults() {
        let t = TargetsConfig::default();
        assert_eq!(t.claude_md, "CLAUDE.md");
        assert_eq!(t.agents_md, "AGENTS.md");
    }
}
