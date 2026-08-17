// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

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

    /// M4 soak-evidence discharge (ExecPlan crux-log-redaction-2026-06-11):
    /// prod `/metrics` shows NO `corecrux_log_redactions_total` family after a
    /// long audit-mode soak. This test pins why that is the healthy signal —
    /// the prometheus text encoder skips a `CounterVec` family with zero
    /// children, so "family absent" == "zero rule hits", not "not wired" —
    /// and that one secret-shaped line makes the family render.
    #[test]
    fn family_absent_from_text_encode_until_first_hit() {
        use prometheus::{Encoder, TextEncoder};

        fn render(registry: &prometheus::Registry) -> String {
            let mut buf = Vec::new();
            TextEncoder::new().encode(&registry.gather(), &mut buf).expect("encode");
            String::from_utf8(buf).expect("utf8")
        }

        // A fresh CounterVec with the prod family name (the shared static may
        // already carry hits from sibling tests in this process).
        #[allow(clippy::expect_used)]
        let counter = CounterVec::new(
            Opts::new("corecrux_log_redactions_total", "test twin of the prod family"),
            &["rule"],
        )
        .expect("construct");
        let registry = prometheus::Registry::new();
        registry.register(Box::new(counter.clone())).expect("register");

        assert!(
            !render(&registry).contains("corecrux_log_redactions_total"),
            "zero-child CounterVec family must be skipped by the text encoder"
        );

        // Seed one secret-shaped line through a redactor counting into it
        // (audit mode — same as the prod default — counts without mutating).
        let hook_counter = counter.clone();
        let hook: RedactionHook = Arc::new(move |rule: &str| {
            hook_counter.with_label_values(&[rule]).inc();
        });
        let mut redactor = Redactor::with_mode(crux_observe::redact::RedactMode::Audit);
        redactor.set_hook(hook);
        let line = r#"call failed api_key="sk-fixtureSYNTHETIC0000000000""#;
        let scrubbed = redactor.redact_line(line);
        assert_eq!(scrubbed, line, "audit mode never mutates output");

        let rendered = render(&registry);
        assert!(
            rendered.contains("corecrux_log_redactions_total"),
            "family renders after the first hit: {rendered}"
        );
        assert!(
            rendered.contains("rule=\"fld.api_key\"") || rendered.contains("rule=\"sk\""),
            "hit carries its rule label: {rendered}"
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
