// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

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
