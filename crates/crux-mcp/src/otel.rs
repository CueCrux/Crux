// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Lightweight OpenTelemetry GenAI span emission for MCP tool dispatch.
//!
//! Master ExecPlan `agent-ux-best-in-class-master-2026-05-27` §"Tier
//! mapping" row 6 / child plan `agent-ux-06-typed-action-traces-2026-05-27`.
//!
//! ## Why this exists
//!
//! The corecruxd binary (`crates/corecruxd/src/main.rs`) already wires an
//! `opentelemetry-otlp` exporter onto a `tracing-opentelemetry` layer
//! when `OTEL_EXPORTER_OTLP_ENDPOINT` is set. Every `tracing::info_span!`
//! the rest of the daemon emits then surfaces as an OTel span — no
//! separate exporter setup needed at the MCP layer.
//!
//! This module records one structured `tracing` event per MCP tool
//! dispatch with attributes matching the OTel GenAI semantic conventions
//! (<https://opentelemetry.io/docs/specs/semconv/gen-ai/>):
//!
//! - `gen_ai.system = "cuecrux"`
//! - `gen_ai.operation.name = "<tool_name>"`
//! - `gen_ai.agent.id = "<passport_name>"`
//!
//! ## Feature flag
//!
//! Gated by `CORECRUXD_FEATURE_OTEL_SPANS=1`; default OFF so deploys
//! that haven't opted in see exactly the legacy log volume. Also degrades
//! silently when `OTEL_EXPORTER_OTLP_ENDPOINT` is unset (no exporter
//! attached → `tracing` events still emit to stderr at the configured
//! level but no OTel export happens; this satisfies acceptance #7).

/// Environment variable that gates OTel span emission. Default off.
pub const FEATURE_FLAG_ENV: &str = "CORECRUXD_FEATURE_OTEL_SPANS";

/// Return true if span emission is enabled via the feature flag.
pub fn spans_enabled() -> bool {
    match std::env::var(FEATURE_FLAG_ENV) {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            !matches!(v.as_str(), "" | "0" | "false" | "off" | "no")
        }
        Err(_) => false,
    }
}

/// Record a tool-dispatch event with GenAI-semconv attributes.
///
/// We deliberately use `tracing::info!` (an *event*) rather than
/// `tracing::span!` so the call site stays sync and we don't need to
/// hold a span guard across the async tool dispatch. The downstream
/// `tracing-opentelemetry` layer wraps each event in a one-shot span
/// when an OTel tracer provider is registered, which is enough for the
/// observability story called for in the master plan's M5 acceptance
/// bar.
pub fn record_tool_span_start(tool: &str, passport: Option<&str>) {
    if !spans_enabled() {
        return;
    }
    tracing::info!(
        gen_ai.system = "cuecrux",
        gen_ai.operation.name = tool,
        gen_ai.agent.id = passport.unwrap_or("__anon__"),
        cuecrux.tool = tool,
        "mcp.tool_dispatch.start"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feature_flag_default_off() {
        // Hold the crate-wide test env lock so this sync test doesn't
        // race the tokio-test suite (`blocking_lock` is safe here: plain
        // `#[test]`, no tokio runtime in scope).
        let _g = crate::test_env_lock().blocking_lock();
        std::env::remove_var(FEATURE_FLAG_ENV);
        assert!(!spans_enabled());
    }

    #[test]
    fn record_when_disabled_is_noop() {
        // Just assert this doesn't panic / blow up when the flag is off.
        let _g = crate::test_env_lock().blocking_lock();
        std::env::remove_var(FEATURE_FLAG_ENV);
        record_tool_span_start("query_facts", Some("alice"));
        record_tool_span_start("query_facts", None);
    }

    #[test]
    fn record_when_enabled_does_not_panic_without_exporter() {
        // Acceptance #7: with OTEL_EXPORTER_OTLP_ENDPOINT unset the
        // call must still succeed (degrade silently — no exporter, but
        // the local tracing layer still consumes the event).
        let _g = crate::test_env_lock().blocking_lock();
        std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
        std::env::set_var(FEATURE_FLAG_ENV, "1");
        record_tool_span_start("query_facts", Some("alice"));
        std::env::remove_var(FEATURE_FLAG_ENV);
    }
}
