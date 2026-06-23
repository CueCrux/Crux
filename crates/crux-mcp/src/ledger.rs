// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Durable agent action ledger (action-ledger M2).
//!
//! Every `tools/call` dispatch can append an `agent.tool_invocation.v1`
//! event to the daemon's **observations stream** via loopback HTTP
//! (`POST /v1/sessions/{ledger::<passport>}/observations`). That path —
//! the same one the mediation plane rides (Crux PR #161) — gives each
//! event a CROWN receipt, a tamper-evident JSONL chain, and a
//! best-effort dataplane stream write, and it works on CPU-only builds
//! (the `/v1/admin/append` dataplane path 501s there; the observations
//! path does not).
//!
//! Properties:
//! - **Default OFF** behind [`FEATURE_FLAG_ENV`]; zero behaviour change
//!   for legacy deploys.
//! - **Fire-and-forget**: the hot path only builds a small JSON payload
//!   and schedules a blocking task; the HTTP POST happens off-path. A
//!   ledger-write failure must never fail (or slow) the tool call —
//!   failures log a warning and bump a counter, nothing else.
//! - **Privacy**: arguments are stored as a BLAKE3 hash prefix
//!   ([`args_hash`]), never raw. Raw-args capture is a separate opt-in
//!   ([`RAW_ARGS_ENV`]) for local debugging; the ledger JSONL is
//!   daemon-local state that does not sync.
//! - **Passport attribution** (QC.3): unauthenticated callers land in
//!   the `ledger::__anon__` session — counted, but partitioned.
//!
//! Prometheus metrics (registered into the daemon registry by
//! `corecruxd::main` via [`register_metrics`]): per-tool latency
//! histogram, token-spend counter, response-truncation counter, and a
//! ledger-emit failure counter. Passport is deliberately NOT a metric
//! label (cardinality); per-passport detail lives in the ledger itself.

use std::sync::OnceLock;
use std::time::Duration;

use prometheus::{CounterVec, HistogramOpts, HistogramVec, IntGauge, Opts, Registry};
use serde_json::{json, Value};
use tracing::{debug, warn};

use crate::envelope::PredictedEffect;

/// Feature flag for ledger emission. Default off.
pub const FEATURE_FLAG_ENV: &str = "CORECRUXD_FEATURE_TOOL_LEDGER";

/// Opt-in flag to include raw tool arguments in ledger events (local
/// debugging only — default off; `args_hash` is always present).
pub const RAW_ARGS_ENV: &str = "CORECRUXD_TOOL_LEDGER_RAW_ARGS";

/// Observation `kind` discriminator for ledger events.
pub const EVENT_KIND: &str = "agent.tool_invocation.v1";

/// Observation `provider` for ledger events.
pub const PROVIDER: &str = "crux-mcp";

/// Hex chars of the BLAKE3 hash kept in `args_hash` (16 = 64 bits —
/// plenty for correlation, useless for reversal).
const ARGS_HASH_PREFIX_LEN: usize = 16;

fn env_truthy(var: &str) -> bool {
    match std::env::var(var) {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            !matches!(v.as_str(), "" | "0" | "false" | "off" | "no")
        }
        Err(_) => false,
    }
}

/// Return true if ledger emission is enabled via the feature flag.
pub fn ledger_enabled() -> bool {
    env_truthy(FEATURE_FLAG_ENV)
}

fn raw_args_enabled() -> bool {
    env_truthy(RAW_ARGS_ENV)
}

/// Ledger session id for a passport: `ledger::<passport>`. Mirrors the
/// mediation plane's `mediation::<group>` grouping so per-passport
/// usage queries are one JSONL file scan.
pub fn ledger_session_id(passport: &str) -> String {
    format!("ledger::{passport}")
}

/// `blake3:<16-hex-prefix>` of the compact-serialized arguments.
/// Deterministic for identical args; never reversible to content.
pub fn args_hash(args: &Value) -> String {
    let bytes = serde_json::to_vec(args).unwrap_or_default();
    let hash = blake3::hash(&bytes);
    format!("blake3:{}", &hash.to_hex().as_str()[..ARGS_HASH_PREFIX_LEN])
}

/// Inputs for one ledger event. Borrowed where possible — the payload
/// builder is on the hot path.
pub struct InvocationRecord<'a> {
    pub tool: &'a str,
    pub passport: &'a str,
    pub turn_id: Option<&'a str>,
    pub args: &'a Value,
    pub est_tokens_in: u64,
    pub est_tokens_out: u64,
    pub result_bytes: u64,
    pub token_budget_in: Option<u64>,
    pub latency_ms: u64,
    pub outcome_ok: bool,
    pub request_id: Option<&'a Value>,
    pub predicted_effects: &'a [PredictedEffect],
}

/// Build the observation body for one invocation. Pure (no IO, no env
/// reads except the raw-args opt-in) so the field mapping is
/// unit-testable.
pub fn build_event_body(rec: &InvocationRecord<'_>) -> Value {
    let mut payload = json!({
        "tool": rec.tool,
        "passport": rec.passport,
        "args_hash": args_hash(rec.args),
        "result_bytes": rec.result_bytes,
        "est_tokens_in": rec.est_tokens_in,
        "est_tokens_out": rec.est_tokens_out,
        "latency_ms": rec.latency_ms,
        "outcome": if rec.outcome_ok { "ok" } else { "error" },
        "predicted_effects": rec.predicted_effects,
    });
    if let Some(turn) = rec.turn_id {
        payload["turn_id"] = json!(turn);
    }
    if let Some(sid) = rec.args.get("session_id").and_then(Value::as_str) {
        payload["session_id"] = json!(sid);
    }
    if let Some(b) = rec.token_budget_in {
        payload["token_budget_in"] = json!(b);
    }
    if let Some(id) = rec.request_id {
        payload["request_id"] = id.clone();
    }
    if raw_args_enabled() {
        payload["args_raw"] = rec.args.clone();
    }
    json!({
        "kind": EVENT_KIND,
        "provider": PROVIDER,
        "payload": payload,
    })
}

/// Fire-and-forget: schedule the loopback POST off the hot path.
///
/// `daemon_base_url` comes from `McpContext`; when it is `None` (test
/// contexts, stdio-only deployments) the event is dropped with a debug
/// log + failure counter — never an error.
pub fn emit(daemon_base_url: Option<String>, passport: &str, body: Value) {
    let Some(base) = daemon_base_url else {
        debug!("tool ledger: no daemon_base_url; dropping event");
        metrics()
            .emit_failures_total
            .with_label_values(&["no_loopback_url"])
            .inc();
        return;
    };
    let url = format!(
        "{}/v1/sessions/{}/observations",
        base.trim_end_matches('/'),
        ledger_session_id(passport)
    );
    // spawn_blocking: ureq is a blocking client; the closure runs on the
    // blocking pool. The JoinHandle is dropped deliberately.
    drop(tokio::task::spawn_blocking(move || {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(10)))
            .http_status_as_error(false)
            .build()
            .into();
        let mut req = agent
            .post(&url)
            .header("X-Corecrux-Scopes", "sessions:write,admin:write")
            .header("content-type", "application/json");
        if let Some(token) = crate::tools::loopback_auth::loopback_bearer_token() {
            req = req.header("Authorization", &format!("Bearer {token}"));
        }
        match req.send_json(&body) {
            Ok(resp) if resp.status().as_u16() < 300 => {}
            Ok(resp) => {
                let status = resp.status().as_u16();
                warn!(status, "tool ledger: observation append rejected");
                metrics().emit_failures_total.with_label_values(&["http_status"]).inc();
            }
            Err(err) => {
                warn!(error = %err, "tool ledger: observation append transport failure");
                metrics().emit_failures_total.with_label_values(&["transport"]).inc();
            }
        }
    }));
}

// ── Prometheus metrics ────────────────────────────────────────────────────

/// Per-tool invocation metrics. Tool name is a bounded label (the
/// registered tool surface); dispatches that fail name resolution are
/// labelled `unknown` so attacker-supplied names can't explode
/// cardinality. Passport is intentionally NOT a label.
pub struct LedgerMetrics {
    pub tool_invocation_duration_seconds: HistogramVec,
    pub token_spend_total: CounterVec,
    pub tool_response_truncated_total: CounterVec,
    pub emit_failures_total: CounterVec,
    // ── G7 coverage-attestation gauges ───────────────────────────────
    //
    // First-class unsigned / un-anchored / gap counts from the most
    // recent `corecruxctl receipts coverage-window-attest` run. These are
    // *gauges* (current state), not counters: each attestation overwrites
    // them via [`set_coverage_gaps`]. Unlabelled to avoid tenant
    // cardinality — they describe the latest attested window; per-window
    // detail lives in the signed report itself.
    /// Events observed in the last attested window with no corresponding
    /// receipt (i.e. unsigned activity — a CROWN receipt was never minted).
    pub coverage_events_without_receipt: IntGauge,
    /// Receipt bodies in the last attested window with no external anchor.
    pub coverage_receipts_without_anchor: IntGauge,
    /// Total gaps in the last attested window
    /// (`events_without_receipt + receipts_without_anchor`).
    pub coverage_gaps_total: IntGauge,
    /// Total events the last attested window covered.
    pub coverage_events_total: IntGauge,
    /// Total receipts the last attested window covered.
    pub coverage_receipts_total: IntGauge,
    /// Total anchored receipts in the last attested window.
    pub coverage_anchored_total: IntGauge,
}

/// Global metrics handles — usable (and unit-testable) even before
/// [`register_metrics`] wires them into a scrape registry.
// The `.expect()`s below are on prometheus opts/label construction with static
// literal names and bucket lists — infallible by construction (same pattern as
// corecruxd's Metrics::new). expect_used is workspace-warn, denied in CI via
// -D warnings; allow it here deliberately rather than thread Results through an
// infallible static initialiser.
#[allow(clippy::expect_used)]
pub fn metrics() -> &'static LedgerMetrics {
    static METRICS: OnceLock<LedgerMetrics> = OnceLock::new();
    METRICS.get_or_init(|| LedgerMetrics {
        tool_invocation_duration_seconds: HistogramVec::new(
            HistogramOpts::new(
                "corecrux_tool_invocation_duration_seconds",
                "MCP tools/call dispatch latency per tool and outcome.",
            )
            .buckets(vec![
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
            ]),
            &["tool", "outcome"],
        )
        .expect("static histogram opts are valid"),
        token_spend_total: CounterVec::new(
            Opts::new(
                "corecrux_token_spend_total",
                "Estimated tokens (args + result, ~4 chars/token) spent per tool.",
            ),
            &["tool"],
        )
        .expect("static counter opts are valid"),
        tool_response_truncated_total: CounterVec::new(
            Opts::new(
                "corecrux_tool_response_truncated_total",
                "Responses truncated by a token_budget-honouring path, per tool and reason.",
            ),
            &["tool", "reason"],
        )
        .expect("static counter opts are valid"),
        emit_failures_total: CounterVec::new(
            Opts::new(
                "corecrux_tool_ledger_emit_failures_total",
                "Ledger observation appends that failed (tool calls are never failed by this).",
            ),
            &["reason"],
        )
        .expect("static counter opts are valid"),
        coverage_events_without_receipt: IntGauge::new(
            "corecrux_coverage_events_without_receipt",
            "Events in the last attested coverage window with no corresponding receipt (unsigned activity).",
        )
        .expect("static gauge opts are valid"),
        coverage_receipts_without_anchor: IntGauge::new(
            "corecrux_coverage_receipts_without_anchor",
            "Receipt bodies in the last attested coverage window with no external anchor (un-anchored).",
        )
        .expect("static gauge opts are valid"),
        coverage_gaps_total: IntGauge::new(
            "corecrux_coverage_gaps_total",
            "Total gaps in the last attested coverage window (unsigned events + un-anchored receipts).",
        )
        .expect("static gauge opts are valid"),
        coverage_events_total: IntGauge::new(
            "corecrux_coverage_events_total",
            "Events covered by the last attested coverage window.",
        )
        .expect("static gauge opts are valid"),
        coverage_receipts_total: IntGauge::new(
            "corecrux_coverage_receipts_total",
            "Receipts covered by the last attested coverage window.",
        )
        .expect("static gauge opts are valid"),
        coverage_anchored_total: IntGauge::new(
            "corecrux_coverage_anchored_total",
            "Anchored receipts in the last attested coverage window.",
        )
        .expect("static gauge opts are valid"),
    })
}

/// Counts mirrored from a `coverage-window-attest` run, for the gauges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoverageGapCounts {
    pub events: u64,
    pub receipts: u64,
    pub anchored: u64,
    pub events_without_receipt: u64,
    pub receipts_without_anchor: u64,
}

impl CoverageGapCounts {
    /// `events_without_receipt + receipts_without_anchor`.
    #[must_use]
    pub fn gaps(&self) -> u64 {
        self.events_without_receipt.saturating_add(self.receipts_without_anchor)
    }
}

/// Publish the latest coverage-window counts to the gauges. Called after a
/// `coverage-window-attest` run (CLI emits the report; an operator/daemon hook
/// pushes the counts here). Values are clamped into the i64 gauge domain.
pub fn set_coverage_gaps(counts: CoverageGapCounts) {
    let m = metrics();
    let clamp = |v: u64| i64::try_from(v).unwrap_or(i64::MAX);
    m.coverage_events_total.set(clamp(counts.events));
    m.coverage_receipts_total.set(clamp(counts.receipts));
    m.coverage_anchored_total.set(clamp(counts.anchored));
    m.coverage_events_without_receipt
        .set(clamp(counts.events_without_receipt));
    m.coverage_receipts_without_anchor
        .set(clamp(counts.receipts_without_anchor));
    m.coverage_gaps_total.set(clamp(counts.gaps()));
}

/// Prometheus alert rules (YAML, `groups:` form) for the coverage gauges.
/// Returned as a static string so it can be written to a rules file by
/// deploy tooling and asserted in tests. Thresholds are conservative
/// defaults: any unsigned activity or un-anchored receipt is a warning, a
/// growing gap total is a page.
#[must_use]
pub fn coverage_alert_rules_yaml() -> &'static str {
    r#"groups:
  - name: crux-coverage-attestation
    rules:
      - alert: CruxUnsignedActivity
        expr: corecrux_coverage_events_without_receipt > 0
        for: 15m
        labels:
          severity: warning
        annotations:
          summary: "Unsigned activity in the last attested coverage window"
          description: "{{ $value }} events had no CROWN receipt. Every state mutation must mint a receipt (Art.12 record-keeping)."
      - alert: CruxUnanchoredReceipts
        expr: corecrux_coverage_receipts_without_anchor > 0
        for: 30m
        labels:
          severity: warning
        annotations:
          summary: "Un-anchored receipts in the last attested coverage window"
          description: "{{ $value }} receipts lack an external anchor. Re-run the anchoring job or investigate the witness pipeline."
      - alert: CruxCoverageGapsHigh
        expr: corecrux_coverage_gaps_total > 10
        for: 1h
        labels:
          severity: critical
        annotations:
          summary: "Coverage gap total is high"
          description: "{{ $value }} total gaps (unsigned events + un-anchored receipts) in the last attested window."
      - alert: CruxCoverageAttestationStale
        expr: absent(corecrux_coverage_gaps_total)
        for: 25h
        labels:
          severity: warning
        annotations:
          summary: "No coverage attestation has run recently"
          description: "The coverage gauges are absent — the daily coverage-window-attest job may have stopped."
"#
}

/// Register the ledger collectors into a Prometheus registry (called
/// once from `corecruxd::main`). Safe to skip in tests — the handles
/// work unregistered.
pub fn register_metrics(registry: &Registry) {
    let m = metrics();
    for collector in [
        Box::new(m.tool_invocation_duration_seconds.clone()) as Box<dyn prometheus::core::Collector>,
        Box::new(m.token_spend_total.clone()),
        Box::new(m.tool_response_truncated_total.clone()),
        Box::new(m.emit_failures_total.clone()),
        Box::new(m.coverage_events_without_receipt.clone()),
        Box::new(m.coverage_receipts_without_anchor.clone()),
        Box::new(m.coverage_gaps_total.clone()),
        Box::new(m.coverage_events_total.clone()),
        Box::new(m.coverage_receipts_total.clone()),
        Box::new(m.coverage_anchored_total.clone()),
    ] {
        if let Err(err) = registry.register(collector) {
            // Double-registration (e.g. two MCP routers in one process)
            // is a wiring bug worth logging, not a panic.
            warn!(error = %err, "tool ledger: metric registration failed");
        }
    }
}

/// Record per-dispatch metrics. `tool` must already be
/// cardinality-guarded by the caller (use `"unknown"` for unresolved
/// names).
pub fn record_dispatch_metrics(tool: &str, outcome_ok: bool, latency: Duration, est_tokens_total: u64) {
    let m = metrics();
    let outcome = if outcome_ok { "ok" } else { "error" };
    m.tool_invocation_duration_seconds
        .with_label_values(&[tool, outcome])
        .observe(latency.as_secs_f64());
    m.token_spend_total
        .with_label_values(&[tool])
        .inc_by(est_tokens_total as f64);
}

/// Bump the truncation counter from a budget-honouring path.
pub fn record_truncation(tool: &str, reason: &str) {
    metrics()
        .tool_response_truncated_total
        .with_label_values(&[tool, reason])
        .inc();
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn record<'a>(args: &'a Value, request_id: Option<&'a Value>) -> InvocationRecord<'a> {
        InvocationRecord {
            tool: "store_fact",
            passport: "alice",
            turn_id: Some("turn-7"),
            args,
            est_tokens_in: 12,
            est_tokens_out: 80,
            result_bytes: 320,
            token_budget_in: Some(500),
            latency_ms: 3,
            outcome_ok: true,
            request_id,
            predicted_effects: &[],
        }
    }

    #[tokio::test]
    async fn flag_default_off() {
        let _g = crate::test_env_lock().lock().await;
        std::env::remove_var(FEATURE_FLAG_ENV);
        assert!(!ledger_enabled());
        std::env::set_var(FEATURE_FLAG_ENV, "1");
        assert!(ledger_enabled());
        std::env::remove_var(FEATURE_FLAG_ENV);
    }

    #[test]
    fn args_hash_is_deterministic_and_prefixed() {
        let a = serde_json::json!({"entity": "e", "key": "k"});
        let h1 = args_hash(&a);
        let h2 = args_hash(&a);
        assert_eq!(h1, h2);
        assert!(h1.starts_with("blake3:"));
        assert_eq!(h1.len(), "blake3:".len() + 16);
        let b = serde_json::json!({"entity": "e", "key": "DIFFERENT"});
        assert_ne!(h1, args_hash(&b));
    }

    #[tokio::test]
    async fn event_body_field_mapping() {
        let _g = crate::test_env_lock().lock().await;
        std::env::remove_var(RAW_ARGS_ENV);
        let args = serde_json::json!({"entity": "e", "session_id": "sess-9", "token_budget": 500});
        let rid = serde_json::json!(42);
        let body = build_event_body(&record(&args, Some(&rid)));
        assert_eq!(body["kind"], EVENT_KIND);
        assert_eq!(body["provider"], PROVIDER);
        let p = &body["payload"];
        assert_eq!(p["tool"], "store_fact");
        assert_eq!(p["passport"], "alice");
        assert_eq!(p["turn_id"], "turn-7");
        assert_eq!(p["session_id"], "sess-9");
        assert_eq!(p["token_budget_in"], 500);
        assert_eq!(p["latency_ms"], 3);
        assert_eq!(p["outcome"], "ok");
        assert_eq!(p["result_bytes"], 320);
        assert_eq!(p["est_tokens_out"], 80);
        assert_eq!(p["request_id"], 42);
        assert!(p["args_hash"].as_str().unwrap().starts_with("blake3:"));
        // Raw args must be absent by default.
        assert!(p.get("args_raw").is_none());
    }

    #[tokio::test]
    async fn raw_args_only_when_opted_in() {
        let _g = crate::test_env_lock().lock().await;
        std::env::set_var(RAW_ARGS_ENV, "1");
        let args = serde_json::json!({"entity": "e"});
        let body = build_event_body(&record(&args, None));
        std::env::remove_var(RAW_ARGS_ENV);
        assert_eq!(body["payload"]["args_raw"], args);
    }

    #[test]
    fn ledger_session_id_shape() {
        assert_eq!(ledger_session_id("__anon__"), "ledger::__anon__");
        assert_eq!(ledger_session_id("alice"), "ledger::alice");
    }

    #[test]
    fn coverage_gap_counts_reconcile() {
        let c = CoverageGapCounts {
            events: 10,
            receipts: 8,
            anchored: 5,
            events_without_receipt: 2,
            receipts_without_anchor: 3,
        };
        assert_eq!(c.gaps(), 5);
    }

    #[test]
    fn set_coverage_gaps_sets_first_class_gauges() {
        set_coverage_gaps(CoverageGapCounts {
            events: 42,
            receipts: 40,
            anchored: 37,
            events_without_receipt: 2,
            receipts_without_anchor: 3,
        });
        let m = metrics();
        assert_eq!(m.coverage_events_total.get(), 42);
        assert_eq!(m.coverage_receipts_total.get(), 40);
        assert_eq!(m.coverage_anchored_total.get(), 37);
        assert_eq!(m.coverage_events_without_receipt.get(), 2);
        assert_eq!(m.coverage_receipts_without_anchor.get(), 3);
        assert_eq!(m.coverage_gaps_total.get(), 5);

        // A subsequent attestation overwrites (gauge, not counter).
        set_coverage_gaps(CoverageGapCounts {
            events: 1,
            receipts: 1,
            anchored: 1,
            events_without_receipt: 0,
            receipts_without_anchor: 0,
        });
        assert_eq!(m.coverage_gaps_total.get(), 0);
        assert_eq!(m.coverage_events_without_receipt.get(), 0);
    }

    #[test]
    fn coverage_alert_rules_yaml_names_each_gauge() {
        let yaml = coverage_alert_rules_yaml();
        assert!(yaml.contains("corecrux_coverage_events_without_receipt"));
        assert!(yaml.contains("corecrux_coverage_receipts_without_anchor"));
        assert!(yaml.contains("corecrux_coverage_gaps_total"));
        assert!(yaml.contains("alert: CruxUnsignedActivity"));
        assert!(yaml.contains("alert: CruxUnanchoredReceipts"));
        assert!(yaml.contains("alert: CruxCoverageGapsHigh"));
        assert!(yaml.contains("severity: critical"));
    }

    #[test]
    fn coverage_gauges_register_into_a_registry() {
        let registry = Registry::new();
        register_metrics(&registry);
        let names: Vec<String> = registry
            .gather()
            .into_iter()
            .map(|mf| mf.get_name().to_string())
            .collect();
        assert!(names.iter().any(|n| n == "corecrux_coverage_gaps_total"));
        assert!(names.iter().any(|n| n == "corecrux_coverage_events_without_receipt"));
        assert!(names.iter().any(|n| n == "corecrux_coverage_receipts_without_anchor"));
    }

    #[test]
    fn record_truncation_increments_labelled_counter() {
        let before = metrics()
            .tool_response_truncated_total
            .with_label_values(&["ledger-test-tool", "token_budget"])
            .get();
        record_truncation("ledger-test-tool", "token_budget");
        let after = metrics()
            .tool_response_truncated_total
            .with_label_values(&["ledger-test-tool", "token_budget"])
            .get();
        assert!(after > before);
    }

    #[tokio::test]
    async fn emit_without_base_url_is_a_counted_noop() {
        let before = metrics()
            .emit_failures_total
            .with_label_values(&["no_loopback_url"])
            .get();
        emit(None, "alice", serde_json::json!({"kind": EVENT_KIND}));
        let after = metrics()
            .emit_failures_total
            .with_label_values(&["no_loopback_url"])
            .get();
        assert!(after > before);
    }

    /// M2 latency gate: the on-path cost of ledger emission (payload
    /// build + hash + task scheduling — everything dispatch waits on)
    /// must stay well under 1ms at p50.
    #[tokio::test]
    async fn on_path_emission_cost_p50_under_1ms() {
        let _g = crate::test_env_lock().lock().await;
        std::env::remove_var(RAW_ARGS_ENV);
        let args = serde_json::json!({
            "entity": "bench-entity", "key": "bench-key",
            "value": "x".repeat(2048), "token_budget": 500
        });
        let effects = vec![PredictedEffect::now("fact_write", "bench-entity", "bench-key")];
        let mut samples = Vec::with_capacity(200);
        for i in 0..200u64 {
            let start = std::time::Instant::now();
            let rec = InvocationRecord {
                tool: "store_fact",
                passport: "bench",
                turn_id: None,
                args: &args,
                est_tokens_in: 64,
                est_tokens_out: 512,
                result_bytes: 2048,
                token_budget_in: Some(500),
                latency_ms: i,
                outcome_ok: true,
                request_id: None,
                predicted_effects: &effects,
            };
            let body = build_event_body(&rec);
            // base URL pointing nowhere — connection failure happens on
            // the blocking pool, off-path; we only measure scheduling.
            emit(Some("http://127.0.0.1:9".to_string()), "bench", body);
            samples.push(start.elapsed());
        }
        samples.sort();
        let p50 = samples[samples.len() / 2];
        assert!(
            p50 < Duration::from_millis(1),
            "on-path ledger emission p50 {p50:?} must be < 1ms"
        );
    }
}
