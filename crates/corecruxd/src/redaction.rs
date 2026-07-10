// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Daemon wiring for the log-redaction layer (ExecPlan
//! `crux-log-redaction-2026-06-11`).
//!
//! Owns the process-wide hooked [`Redactor`] instance and the
//! `corecrux_log_redactions_total{rule}` Prometheus counter. The redactor is
//! created lazily (init_tracing runs before [`crate::metrics::Metrics`]
//! exists), counting into a registry-independent `CounterVec` that is
//! attached to the shared `/metrics` registry once it is up.

use std::sync::{Arc, LazyLock, OnceLock};

use crux_observe::redact::{RedactionHook, Redactor};
use prometheus::{CounterVec, Opts};

static REDACTIONS_TOTAL: LazyLock<CounterVec> = LazyLock::new(|| {
    // SAFETY: static metric name + label set; failure is a programmer error
    // caught by the unit tests below.
    #[allow(clippy::expect_used)]
    CounterVec::new(
        Opts::new(
            "corecrux_log_redactions_total",
            "Log/ops-fact redaction rule hits (CORECRUXD_REDACT audit and on modes), by rule id",
        ),
        &["rule"],
    )
    .expect("corecrux_log_redactions_total must construct")
});

static REDACTOR: OnceLock<Arc<Redactor>> = OnceLock::new();

/// The daemon's shared redactor: built from `CORECRUXD_REDACT` /
/// `CORECRUXD_REDACT_EXTRA_PATTERNS` with the Prometheus counter hook
/// installed, and published as the crux-observe process-global so other
/// crates in this process (e.g. crux-mcp) scrub with the same instance.
pub fn redactor() -> Arc<Redactor> {
    Arc::clone(REDACTOR.get_or_init(|| {
        let hook: RedactionHook = Arc::new(|rule: &str| {
            REDACTIONS_TOTAL.with_label_values(&[rule]).inc();
        });
        let r = Arc::new(Redactor::from_env_with_hook(hook));
        let _ = crux_observe::redact::set_global(Arc::clone(&r));
        r
    }))
}

/// Attach `corecrux_log_redactions_total` to the shared `/metrics` registry.
/// Idempotent — double registration is logged at debug and ignored.
pub fn register_metrics(registry: &prometheus::Registry) {
    if let Err(err) = registry.register(Box::new(REDACTIONS_TOTAL.clone())) {
        tracing::debug!(error = %err, "redaction counter already registered");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_registers_and_renders() {
        let registry = prometheus::Registry::new();
        register_metrics(&registry);
        // Double registration must not panic.
        register_metrics(&registry);

        REDACTIONS_TOTAL.with_label_values(&["fld.test_rule"]).inc();

        let families = registry.gather();
        let fam = families
            .iter()
            .find(|f| f.get_name() == "corecrux_log_redactions_total")
            .expect("metric family present");
        assert!(
            fam.get_metric()
                .iter()
                .any(|m| m.get_label().iter().any(|l| l.get_value() == "fld.test_rule")),
            "rule label present"
        );
    }

    #[test]
    fn redactor_is_shared_and_hook_counts() {
        let r1 = redactor();
        let r2 = redactor();
        assert!(Arc::ptr_eq(&r1, &r2), "redactor must be a process singleton");

        let before = REDACTIONS_TOTAL.with_label_values(&["fld.password"]).get();
        // Default mode is audit (or whatever env says) — both audit and on count.
        let _ = r1.redact_field("password", "fixture-pw-SYNTHETIC");
        if r1.mode() == crux_observe::redact::RedactMode::Off {
            return; // operator env explicitly off — nothing to assert
        }
        let after = REDACTIONS_TOTAL.with_label_values(&["fld.password"]).get();
        assert!(after > before, "hook must increment the counter");
    }
}
