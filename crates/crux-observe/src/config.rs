// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

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

    #[test]
    fn self_observe_disabled_by_default() {
        // Remove the env var if it happens to be set
        std::env::remove_var("CRUX_SELF_OBSERVE");
        assert!(!self_observe_enabled());
    }

    #[test]
    fn self_observe_enabled_when_set() {
        for val in &["1", "true", "True", "TRUE", "yes", "Yes", "YES"] {
            std::env::set_var("CRUX_SELF_OBSERVE", val);
            assert!(self_observe_enabled(), "expected enabled for {val}");
        }
        // Clean up
        std::env::remove_var("CRUX_SELF_OBSERVE");
    }

    #[test]
    fn self_observe_disabled_for_other_values() {
        for val in &["0", "false", "no", "nah", ""] {
            std::env::set_var("CRUX_SELF_OBSERVE", val);
            assert!(!self_observe_enabled(), "expected disabled for {val}");
        }
        std::env::remove_var("CRUX_SELF_OBSERVE");
    }

    #[test]
    fn config_defaults() {
        std::env::remove_var("CRUX_SELF_OBSERVE");
        let cfg = ObserveConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.node_id, "local");
        assert_eq!(cfg.max_ops_facts, 1000);
        assert_eq!(cfg.metrics_interval_secs, 30);
    }
}
