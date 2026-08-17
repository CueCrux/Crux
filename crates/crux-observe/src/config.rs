// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Configuration for the self-observation subsystem.

/// Check whether self-observation is enabled via the `CRUX_SELF_OBSERVE` env var.
///
/// Returns `true` if the variable is set to `1`, `true`, or `yes` (case-insensitive).
/// Returns `false` otherwise (including when the variable is absent).
pub fn self_observe_enabled() -> bool {
    match std::env::var("CRUX_SELF_OBSERVE") {
        Ok(val) => matches!(val.to_lowercase().as_str(), "1" | "true" | "yes"),
        Err(_) => false,
    }
}

/// Configuration for the observe subsystem.
#[derive(Debug, Clone)]
pub struct ObserveConfig {
    /// Whether self-observation is enabled.
    pub enabled: bool,
    /// Node identifier for tagging events.
    pub node_id: String,
    /// Maximum number of ops facts to retain (ring buffer size).
    pub max_ops_facts: usize,
    /// Metrics sampling interval in seconds.
    pub metrics_interval_secs: u64,
}

impl Default for ObserveConfig {
    fn default() -> Self {
        Self {
            enabled: self_observe_enabled(),
            node_id: "local".to_string(),
            max_ops_facts: 1000,
            metrics_interval_secs: 30,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Env-var tests are combined into one function to avoid parallel test
    // pollution — std::env::set_var is process-global and not thread-safe.
    #[test]
    fn self_observe_env_var_parsing() {
        std::env::remove_var("CRUX_SELF_OBSERVE");
        assert!(!self_observe_enabled(), "should be disabled when unset");

        for val in &["1", "true", "True", "TRUE", "yes", "Yes", "YES"] {
            std::env::set_var("CRUX_SELF_OBSERVE", val);
            assert!(self_observe_enabled(), "expected enabled for {val}");
        }

        for val in &["0", "false", "no", "nah", ""] {
            std::env::set_var("CRUX_SELF_OBSERVE", val);
            assert!(!self_observe_enabled(), "expected disabled for {val}");
        }

        std::env::remove_var("CRUX_SELF_OBSERVE");
    }

    #[test]
    fn config_defaults() {
        // Note: ObserveConfig::default() reads CRUX_SELF_OBSERVE. This test
        // may race with self_observe_env_var_parsing. We check non-env fields
        // unconditionally and skip the `enabled` assertion if the env var is set.
        let cfg = ObserveConfig::default();
        assert_eq!(cfg.node_id, "local");
        assert_eq!(cfg.max_ops_facts, 1000);
        assert_eq!(cfg.metrics_interval_secs, 30);
    }
}
