// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Tooling environment detection (`corecruxctl tooling-env`) — reports daemon URL, data dir, auth posture.

use clap::ValueEnum;
use serde::Serialize;

type DynError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum ToolingEnvironment {
    Local,
    Staging,
    Production,
}

impl ToolingEnvironment {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Staging => "staging",
            Self::Production => "production",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "local" => Some(Self::Local),
            "staging" => Some(Self::Staging),
            "production" => Some(Self::Production),
            _ => None,
        }
    }

    pub fn resolve(explicit: Option<Self>) -> Result<Self, DynError> {
        if let Some(value) = explicit {
            return Ok(value);
        }

        match std::env::var("CORECRUXCTL_ENV") {
            Ok(raw) => Self::parse(&raw).ok_or_else(|| format!("invalid CORECRUXCTL_ENV value '{raw}'").into()),
            Err(std::env::VarError::NotPresent) => Ok(Self::Local),
            Err(err) => Err(format!("failed to read CORECRUXCTL_ENV: {err}").into()),
        }
    }

    pub fn requires_ops_evidence(self) -> bool {
        !matches!(self, Self::Local)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn as_str_roundtrip() {
        for env in [
            ToolingEnvironment::Local,
            ToolingEnvironment::Staging,
            ToolingEnvironment::Production,
        ] {
            let s = env.as_str();
            let parsed = ToolingEnvironment::parse(s).unwrap();
            assert_eq!(env, parsed);
        }
    }

    #[test]
    fn parse_case_insensitive() {
        assert_eq!(ToolingEnvironment::parse("LOCAL"), Some(ToolingEnvironment::Local));
        assert_eq!(ToolingEnvironment::parse("Staging"), Some(ToolingEnvironment::Staging));
        assert_eq!(
            ToolingEnvironment::parse("  PRODUCTION  "),
            Some(ToolingEnvironment::Production)
        );
    }

    #[test]
    fn parse_invalid_returns_none() {
        assert_eq!(ToolingEnvironment::parse(""), None);
        assert_eq!(ToolingEnvironment::parse("dev"), None);
        assert_eq!(ToolingEnvironment::parse("prod"), None);
    }

    #[test]
    fn resolve_uses_explicit_over_env() {
        // Explicit value should always win regardless of env var
        let result = ToolingEnvironment::resolve(Some(ToolingEnvironment::Production)).unwrap();
        assert_eq!(result, ToolingEnvironment::Production);
    }

    #[test]
    #[serial_test::serial]
    fn resolve_defaults_to_local_when_env_unset() {
        // Temporarily remove the env var if present
        let prev = std::env::var("CORECRUXCTL_ENV").ok();
        std::env::remove_var("CORECRUXCTL_ENV");
        let result = ToolingEnvironment::resolve(None).unwrap();
        assert_eq!(result, ToolingEnvironment::Local);
        // Restore
        if let Some(v) = prev {
            std::env::set_var("CORECRUXCTL_ENV", v);
        }
    }

    #[test]
    #[serial_test::serial]
    fn resolve_reads_env_var() {
        let prev = std::env::var("CORECRUXCTL_ENV").ok();
        std::env::set_var("CORECRUXCTL_ENV", "staging");
        let result = ToolingEnvironment::resolve(None).unwrap();
        assert_eq!(result, ToolingEnvironment::Staging);
        // Restore
        match prev {
            Some(v) => std::env::set_var("CORECRUXCTL_ENV", v),
            None => std::env::remove_var("CORECRUXCTL_ENV"),
        }
    }

    #[test]
    #[serial_test::serial]
    fn resolve_rejects_invalid_env_var() {
        let prev = std::env::var("CORECRUXCTL_ENV").ok();
        std::env::set_var("CORECRUXCTL_ENV", "bogus");
        let result = ToolingEnvironment::resolve(None);
        assert!(result.is_err());
        match prev {
            Some(v) => std::env::set_var("CORECRUXCTL_ENV", v),
            None => std::env::remove_var("CORECRUXCTL_ENV"),
        }
    }

    #[test]
    fn requires_ops_evidence_only_for_non_local() {
        assert!(!ToolingEnvironment::Local.requires_ops_evidence());
        assert!(ToolingEnvironment::Staging.requires_ops_evidence());
        assert!(ToolingEnvironment::Production.requires_ops_evidence());
    }
}
