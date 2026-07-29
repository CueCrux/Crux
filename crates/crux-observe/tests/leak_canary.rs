// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Leak-canary integration test (ExecPlan crux-log-redaction-2026-06-11 M2).
//!
//! Seeds tracing calls with clearly-synthetic fixture secrets across the
//! text and JSON sinks (each behind `RedactMakeWriter` in `on` mode) and
//! asserts zero plaintext occurrences + correct `[REDACTED:*]` markers.
//! Runs in the required test job forever after.
//!
//! All "secrets" below are synthetic fixtures (`fixture-`/`SYNTHETIC`) —
//! they exist only to exercise the high-confidence shape rules.

use std::io;
use std::sync::{Arc, Mutex};

use crux_observe::redact::{RedactMode, Redactor};
use crux_observe::redact_writer::RedactMakeWriter;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt as _;

const FIX_JWT: &str = "eyJfixtureSYNTHETICheader00.eyJfixturePayload00.fixtureSigSYNTHETIC";
const FIX_SK: &str = "sk-fixtureSYNTHETIC0000000000";
const FIX_PW: &str = "fixture-hunter2-SYNTHETIC";
const FIX_GHP: &str = "ghp_fixtureSYNTHETIC0123456789";

#[derive(Clone, Default)]
struct Buf(Arc<Mutex<Vec<u8>>>);

impl Buf {
    fn contents(&self) -> String {
        // SAFETY: test-only; poisoning implies a prior panic.
        #[allow(clippy::unwrap_used)]
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

impl io::Write for Buf {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // SAFETY: test-only; poisoning implies a prior panic.
        #[allow(clippy::unwrap_used)]
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Buf {
    type Writer = Buf;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn emit_fixture_events() {
    tracing::warn!(api_key = FIX_SK, attempt = 3, "upstream call failed");
    tracing::error!(password = FIX_PW, user = "fixture-user", "login rejected");
    tracing::warn!("raw token spotted in message: {FIX_JWT}");
    tracing::info!(token_budget = 500, auth_mode = "jwt_hs256", "telemetry must survive");
    tracing::warn!(gh = FIX_GHP, "github helper failed");
}

fn assert_no_plaintext(sink: &str, out: &str) {
    for (name, secret) in [("jwt", FIX_JWT), ("sk", FIX_SK), ("password", FIX_PW), ("ghp", FIX_GHP)] {
        assert!(
            !out.contains(secret),
            "{sink} sink leaked fixture {name} secret:\n{out}"
        );
    }
    assert!(
        out.contains("[REDACTED:"),
        "{sink} sink has no redaction markers:\n{out}"
    );
}

#[test]
fn leak_canary_text_and_json_sinks_on_mode() {
    let redactor = Arc::new(Redactor::with_mode(RedactMode::On));
    let text_buf = Buf::default();
    let json_buf = Buf::default();

    let subscriber = tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(RedactMakeWriter::new(text_buf.clone(), Arc::clone(&redactor))),
        )
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_writer(RedactMakeWriter::new(json_buf.clone(), Arc::clone(&redactor))),
        );

    tracing::subscriber::with_default(subscriber, emit_fixture_events);

    let text = text_buf.contents();
    let json = json_buf.contents();

    assert_no_plaintext("text", &text);
    assert_no_plaintext("json", &json);

    // Field-name rules fired with correct rule ids.
    assert!(text.contains("[REDACTED:fld.api_key#"), "text: {text}");
    assert!(text.contains("[REDACTED:fld.password#"), "text: {text}");
    // Value-shape rule fired on the free-text message.
    assert!(text.contains("[REDACTED:jwt#"), "text: {text}");
    assert!(json.contains("[REDACTED:fld.api_key#"), "json: {json}");

    // JSON sink lines must remain parseable after redaction.
    for line in json.lines().filter(|l| !l.trim().is_empty()) {
        assert!(
            serde_json::from_str::<serde_json::Value>(line).is_ok(),
            "redacted JSON line no longer parses: {line}"
        );
    }

    // False-positive budget: token_budget-class telemetry survives every sink.
    assert!(text.contains("token_budget=500"), "text: {text}");
    assert!(text.contains(r#"auth_mode="jwt_hs256""#), "text: {text}");
    assert!(json.contains("\"token_budget\":500"), "json: {json}");
}

#[test]
fn leak_canary_audit_mode_counts_but_never_mutates() {
    let redactor = Arc::new(Redactor::with_mode(RedactMode::Audit));
    let text_buf = Buf::default();

    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_writer(RedactMakeWriter::new(text_buf.clone(), Arc::clone(&redactor))),
    );
    tracing::subscriber::with_default(subscriber, emit_fixture_events);

    let text = text_buf.contents();
    assert!(text.contains(FIX_SK), "audit mode must not alter output");
    assert!(!text.contains("[REDACTED:"), "audit mode must not insert markers");
    let counts = redactor.counts();
    let total: u64 = counts.iter().map(|(_, c)| *c).sum();
    assert!(total >= 3, "audit mode must count rule hits, got {counts:?}");
}

#[test]
fn leak_canary_non_matching_output_byte_identical() {
    // Snapshot guarantee: a fixture log line with no secrets is bit-for-bit
    // identical with and without the redacting writer.
    let plain_buf = Buf::default();
    let wrapped_buf = Buf::default();
    let redactor = Arc::new(Redactor::with_mode(RedactMode::On));

    let emit = || {
        tracing::info!(
            frames = 4096,
            duration_ms = 18,
            tenant = "lme-s",
            "segment seal complete"
        );
    };

    let plain = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .without_time()
            .with_writer(plain_buf.clone()),
    );
    tracing::subscriber::with_default(plain, emit);

    let wrapped = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .without_time()
            .with_writer(RedactMakeWriter::new(wrapped_buf.clone(), redactor)),
    );
    tracing::subscriber::with_default(wrapped, emit);

    assert_eq!(
        plain_buf.contents(),
        wrapped_buf.contents(),
        "non-matching log output must be unchanged by the redaction writer"
    );
}

// ── M3: ops-facts sink (OpsObserveLayer → FactStore) ───────────────

/// Drain the ops fact store until `want` facts exist (the layer writes via
/// spawned tasks) or a timeout elapses; returns all fact values concatenated.
async fn wait_for_ops_facts(
    store: &std::sync::Arc<tokio::sync::RwLock<corecrux_memory::FactStore>>,
    want: usize,
) -> Vec<String> {
    for _ in 0..200 {
        {
            let s = store.read().await;
            let values: Vec<String> = s
                .all_facts()
                .filter(|f| f.entity.starts_with("__ops__::"))
                .map(|f| f.value.clone())
                .collect();
            if values.len() >= want {
                return values;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("ops facts did not appear within timeout");
}

#[tokio::test(flavor = "multi_thread")]
async fn leak_canary_ops_facts_sink_on_mode() {
    use crux_observe::ops_layer::OpsObserveLayer;

    let store = Arc::new(tokio::sync::RwLock::new(corecrux_memory::FactStore::new()));
    let redactor = Arc::new(Redactor::with_mode(RedactMode::On));
    let layer = OpsObserveLayer::with_redactor(Arc::clone(&store), "canary-node".into(), 100, true, redactor);

    let subscriber = tracing_subscriber::registry().with(layer);
    tracing::subscriber::with_default(subscriber, || {
        tracing::warn!(api_key = FIX_SK, attempt = 3, "upstream call failed");
        tracing::error!(password = FIX_PW, token_budget = 500, "login rejected, saw {FIX_JWT}");
    });

    let values = wait_for_ops_facts(&store, 2).await;
    let all = values.join("\n");

    // Zero plaintext fixture secrets in any durable fact value.
    for (name, secret) in [("sk", FIX_SK), ("password", FIX_PW), ("jwt", FIX_JWT)] {
        assert!(
            !all.contains(secret),
            "ops-facts sink leaked fixture {name} secret:\n{all}"
        );
    }
    // Markers present with correct rule ids: field rules on named fields,
    // value-shape rule on the free-text message.
    assert!(all.contains("[REDACTED:fld.api_key#"), "got: {all}");
    assert!(all.contains("[REDACTED:fld.password#"), "got: {all}");
    assert!(all.contains("[REDACTED:jwt#"), "got: {all}");
    // Fact values stay parseable as their event JSON.
    for v in &values {
        assert!(
            serde_json::from_str::<serde_json::Value>(v).is_ok(),
            "redacted ops fact value no longer parses: {v}"
        );
    }
    // False-positive budget: token_budget telemetry survives in the fact body.
    assert!(all.contains("\"token_budget\":500"), "got: {all}");
}

#[tokio::test(flavor = "multi_thread")]
async fn leak_canary_ops_facts_sink_audit_mode_counts_only() {
    use crux_observe::ops_layer::OpsObserveLayer;

    let store = Arc::new(tokio::sync::RwLock::new(corecrux_memory::FactStore::new()));
    let redactor = Arc::new(Redactor::with_mode(RedactMode::Audit));
    let layer = OpsObserveLayer::with_redactor(
        Arc::clone(&store),
        "canary-node".into(),
        100,
        true,
        Arc::clone(&redactor),
    );

    let subscriber = tracing_subscriber::registry().with(layer);
    tracing::subscriber::with_default(subscriber, || {
        tracing::warn!(api_key = FIX_SK, "upstream call failed");
    });

    let values = wait_for_ops_facts(&store, 1).await;
    let all = values.join("\n");
    assert!(all.contains(FIX_SK), "audit mode must not alter stored fields");
    assert!(!all.contains("[REDACTED:"), "audit mode must not insert markers");
    assert!(
        redactor.counts().iter().any(|(k, _)| k == "fld.api_key"),
        "audit mode must still count rule hits"
    );
}
