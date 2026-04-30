// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Prometheus metrics for the session handshake surface (master-plan §11).
//!
//! Encapsulated in a dedicated sub-struct so the ~130-field `Metrics`
//! struct in `metrics.rs` doesn't keep growing. The sub-struct registers
//! its handles against the shared registry on construction; the outer
//! `Metrics` owns it as a plain field and exposes the same `inc_*` /
//! `observe_*` pattern everything else in the codebase uses.

use std::sync::Arc;

use prometheus::{CounterVec, Gauge, HistogramOpts, HistogramVec, Opts, Registry};

pub struct SessionMetrics {
    pub handshakes_total: CounterVec,                     // labels: origin, outcome
    pub handshake_latency_seconds: HistogramVec,          // labels: origin
    pub capability_graph_size: HistogramVec,              // labels: origin, tier
    pub active: Gauge,                                    // no labels on Crux Daemon (single install)
    pub expired_total: CounterVec,                        // labels: origin, reason
    pub plan_bytes: HistogramVec,                         // labels: encoding (cbor|json)
    pub invocation_receipts_total: CounterVec,            // labels: channel, capability, outcome
    pub invocation_receipt_latency_seconds: HistogramVec, // labels: channel, capability
    pub invocation_verify_total: CounterVec,              // labels: outcome (verified|flagged|not_found)
    pub plan_sealer_errors_total: Gauge,
    pub segment_seal_failures_total: Gauge,
}

impl SessionMetrics {
    pub fn new(registry: &Arc<Registry>) -> Self {
        let handshakes_total = CounterVec::new(
            Opts::new(
                "vaultcrux_session_handshakes_total",
                "Session handshake requests, labelled by origin and outcome",
            ),
            &["origin", "outcome"],
        )
        .expect("counter");
        registry
            .register(Box::new(handshakes_total.clone()))
            .expect("register handshakes_total");

        let handshake_latency_seconds = HistogramVec::new(
            HistogramOpts::new(
                "vaultcrux_session_handshake_latency_seconds",
                "End-to-end handshake latency",
            )
            .buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0]),
            &["origin"],
        )
        .expect("histogram");
        registry
            .register(Box::new(handshake_latency_seconds.clone()))
            .expect("register handshake_latency");

        let capability_graph_size = HistogramVec::new(
            HistogramOpts::new(
                "vaultcrux_session_capability_graph_size",
                "Number of capabilities in issued session plans",
            )
            .buckets(vec![0.0, 1.0, 2.0, 4.0, 8.0, 12.0, 20.0, 40.0, 80.0]),
            &["origin", "tier"],
        )
        .expect("histogram");
        registry
            .register(Box::new(capability_graph_size.clone()))
            .expect("register capability_graph_size");

        let active = Gauge::new(
            "vaultcrux_session_active",
            "Currently-active sessions in the local registry",
        )
        .expect("gauge");
        registry.register(Box::new(active.clone())).expect("register active");

        let expired_total = CounterVec::new(
            Opts::new(
                "vaultcrux_session_expired_total",
                "Sessions removed by reason (ttl_expired | client_closed | admin_closed)",
            ),
            &["origin", "reason"],
        )
        .expect("counter");
        registry
            .register(Box::new(expired_total.clone()))
            .expect("register expired_total");

        let plan_bytes = HistogramVec::new(
            HistogramOpts::new("vaultcrux_session_plan_bytes", "Size of issued session plans")
                .buckets(vec![256.0, 512.0, 1024.0, 2048.0, 4096.0, 8192.0, 16384.0, 32768.0]),
            &["encoding"],
        )
        .expect("histogram");
        registry
            .register(Box::new(plan_bytes.clone()))
            .expect("register plan_bytes");

        let invocation_receipts_total = CounterVec::new(
            Opts::new(
                "vaultcrux_invocation_receipts_total",
                "Per-capability invocation receipt counts",
            ),
            &["channel", "capability", "outcome"],
        )
        .expect("counter");
        registry
            .register(Box::new(invocation_receipts_total.clone()))
            .expect("register invocation_receipts_total");

        let invocation_receipt_latency_seconds = HistogramVec::new(
            HistogramOpts::new(
                "vaultcrux_invocation_receipt_latency_seconds",
                "Per-capability invocation latency",
            )
            .buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0]),
            &["channel", "capability"],
        )
        .expect("histogram");
        registry
            .register(Box::new(invocation_receipt_latency_seconds.clone()))
            .expect("register invocation_receipt_latency");

        let invocation_verify_total = CounterVec::new(
            Opts::new("vaultcrux_invocation_verify_total", "POST /invocation/verify outcomes"),
            &["outcome"],
        )
        .expect("counter");
        registry
            .register(Box::new(invocation_verify_total.clone()))
            .expect("register invocation_verify_total");

        let plan_sealer_errors_total = Gauge::new(
            "vaultcrux_session_plan_sealer_errors_total",
            "Cumulative segment-seal errors during session mint",
        )
        .expect("gauge");
        registry
            .register(Box::new(plan_sealer_errors_total.clone()))
            .expect("register plan_sealer_errors");

        let segment_seal_failures_total = Gauge::new(
            "vaultcrux_session_segment_seal_failures_total",
            "Cumulative always-store segment-seal failures that caused a handshake to fail closed",
        )
        .expect("gauge");
        registry
            .register(Box::new(segment_seal_failures_total.clone()))
            .expect("register segment_seal_failures");

        Self {
            handshakes_total,
            handshake_latency_seconds,
            capability_graph_size,
            active,
            expired_total,
            plan_bytes,
            invocation_receipts_total,
            invocation_receipt_latency_seconds,
            invocation_verify_total,
            plan_sealer_errors_total,
            segment_seal_failures_total,
        }
    }

    pub fn handshake_ok(
        &self,
        origin: &str,
        latency_secs: f64,
        graph_size: usize,
        tier: &str,
        plan_bytes: usize,
        encoding: &str,
    ) {
        self.handshakes_total.with_label_values(&[origin, "ok"]).inc();
        self.handshake_latency_seconds
            .with_label_values(&[origin])
            .observe(latency_secs);
        self.capability_graph_size
            .with_label_values(&[origin, tier])
            .observe(graph_size as f64);
        self.plan_bytes
            .with_label_values(&[encoding])
            .observe(plan_bytes as f64);
    }

    pub fn handshake_failed(&self, origin: &str, reason: &str) {
        self.handshakes_total.with_label_values(&[origin, reason]).inc();
    }

    pub fn handshake_seal_failure(&self, origin: &str) {
        self.handshakes_total
            .with_label_values(&[origin, "segment_seal_failed"])
            .inc();
        self.segment_seal_failures_total.inc();
    }

    pub fn invocation_verify(&self, outcome: &str) {
        self.invocation_verify_total.with_label_values(&[outcome]).inc();
    }

    pub fn active_set(&self, n: i64) {
        self.active.set(n as f64);
    }

    /// Histogram observe for a just-completed invocation. Use
    /// `outcome` ∈ {"ok","error","partial"} per master-plan §8.1.
    // Wired up by the proprietary invocation receipt path (master-plan §8);
    // kept in Crux Daemon so the metric surface matches hosted.
    #[allow(dead_code)]
    pub fn invocation_observe(&self, channel: &str, capability: &str, outcome: &str, latency_secs: f64) {
        self.invocation_receipts_total
            .with_label_values(&[channel, capability, outcome])
            .inc();
        self.invocation_receipt_latency_seconds
            .with_label_values(&[channel, capability])
            .observe(latency_secs);
    }
}

/// Allow `Clone` so call-sites can hold their own Arc-less handle — the
/// prometheus handles are already cheap to clone (internal `Arc`s).
impl Clone for SessionMetrics {
    fn clone(&self) -> Self {
        Self {
            handshakes_total: self.handshakes_total.clone(),
            handshake_latency_seconds: self.handshake_latency_seconds.clone(),
            capability_graph_size: self.capability_graph_size.clone(),
            active: self.active.clone(),
            expired_total: self.expired_total.clone(),
            plan_bytes: self.plan_bytes.clone(),
            invocation_receipts_total: self.invocation_receipts_total.clone(),
            invocation_receipt_latency_seconds: self.invocation_receipt_latency_seconds.clone(),
            invocation_verify_total: self.invocation_verify_total.clone(),
            plan_sealer_errors_total: self.plan_sealer_errors_total.clone(),
            segment_seal_failures_total: self.segment_seal_failures_total.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prometheus::Encoder;

    #[test]
    fn metrics_register_and_increment() {
        let registry = Arc::new(Registry::new());
        let metrics = SessionMetrics::new(&registry);
        metrics.handshake_ok("ce", 0.012, 4, "local", 987, "json");
        metrics.handshake_failed("ce", "bad_request");
        metrics.handshake_seal_failure("ce");
        metrics.invocation_observe("bulk", "retrieve", "ok", 0.007);
        metrics.invocation_verify("verified");
        metrics.active_set(42);

        let encoder = prometheus::TextEncoder::new();
        let gathered = registry.gather();
        let mut buf = Vec::new();
        encoder.encode(&gathered, &mut buf).unwrap();
        let rendered = String::from_utf8(buf).unwrap();
        for needle in [
            "vaultcrux_session_handshakes_total{origin=\"ce\",outcome=\"ok\"} 1",
            "vaultcrux_session_handshakes_total{origin=\"ce\",outcome=\"bad_request\"} 1",
            "vaultcrux_session_handshakes_total{origin=\"ce\",outcome=\"segment_seal_failed\"} 1",
            "vaultcrux_invocation_receipts_total{capability=\"retrieve\",channel=\"bulk\",outcome=\"ok\"} 1",
            "vaultcrux_invocation_verify_total{outcome=\"verified\"} 1",
            "vaultcrux_session_active 42",
        ] {
            assert!(
                rendered.contains(needle),
                "expected `{needle}` in metrics output:\n{rendered}"
            );
        }
    }
}
