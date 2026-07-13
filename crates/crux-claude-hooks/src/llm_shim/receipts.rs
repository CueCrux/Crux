// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Shim-side mediation receipt records (observational drafts).
//!
//! Two-sided trail per the G19 spec (`Streaming-Receipts-Spec.md`):
//!
//! - **Injected side** — one `context_injected` record per mediated request:
//!   what context entered, identified by `stable_hash` (when the bundle came
//!   from the daemon) and `bundle_digest` (always).
//! - **Emitted side** — one `stream_completed` / `stream_aborted` record per
//!   request end-state, carrying `output_digest` (algorithm-prefixed digest of
//!   the emitted bytes — never the content) and the injected-side linkage.
//!
//! Field names mirror `corecrux-receipts::stream_v1` body fields so the
//! daemon can lift a spooled draft into a canonical signed receipt without
//! remapping. Records are JSON (not CBOR) because the shim is not a signer.
//!
//! Sink policy (free-tier / local-only): best-effort POST to
//! `POST /v1/mediation/receipts` when `daemon_receipts` is on; on any failure
//! (or when off) the record is appended to a local JSONL spool. A record is
//! never silently dropped: spool-write failure logs to stderr, the request
//! itself is never blocked.

use std::io::Write as _;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use super::{BundleSource, ShimConfig, BUNDLE_VERSION, SHIM_RECEIPT_SCHEMA};

/// RFC3339 UTC timestamp (second precision — receipt ordering inside one
/// second is carried by the spool append order).
pub fn now_rfc3339() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    epoch_secs_to_rfc3339(secs)
}

/// Civil-from-days conversion (Howard Hinnant's algorithm) — keeps the crate
/// free of a chrono dependency for one timestamp format.
fn epoch_secs_to_rfc3339(secs: u64) -> String {
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let rem = secs % 86_400;
    let (hour, minute, second) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_part = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_part + 2) / 5 + 1;
    let month = if month_part < 10 {
        month_part + 3
    } else {
        month_part - 9
    };
    if month <= 2 {
        year += 1;
    }
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Build the injected-side record for one mediated request.
pub fn context_injected_record(config: &ShimConfig, bundle: &BundleSource, receipt_id: &str, path: &str) -> Value {
    json!({
        "schema": SHIM_RECEIPT_SCHEMA,
        "kind": "context_injected",
        "receipt_id": receipt_id,
        "session_id": config.session_id,
        "bundle_version": BUNDLE_VERSION,
        "stable_hash": bundle.stable_hash,
        "bundle_digest": bundle.bundle_digest,
        "bundle_origin": bundle.origin,
        "injection_point": "llm_shim",
        "upstream": config.upstream,
        "path": path,
        "created_at": now_rfc3339(),
    })
}

/// End-state of a mediated response, mapped to the G19 receipt kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndState {
    Completed,
    Aborted,
}

impl EndState {
    pub fn kind(self) -> &'static str {
        match self {
            EndState::Completed => "stream_completed",
            EndState::Aborted => "stream_aborted",
        }
    }
}

/// Inputs for the emitted-side record.
pub struct StreamEnd<'a> {
    pub end_state: EndState,
    /// `true` for SSE/streamed responses, `false` for buffered ones (the shim
    /// mints an end-state record either way — one trail, one shape).
    pub stream: bool,
    pub model: Option<&'a str>,
    pub first_byte_at: Option<String>,
    /// Algorithm-prefixed digest of the bytes emitted to the client
    /// (`sha256:<hex>`); `None` when nothing was emitted before abort.
    pub output_digest: Option<String>,
    pub abort_reason: Option<&'a str>,
    /// Linkage back to the injected side (absent in passthrough mode).
    pub injected_stable_hash: Option<&'a str>,
    pub injected_bundle_digest: Option<&'a str>,
}

/// Build the emitted-side record for one request end-state.
pub fn stream_end_record(config: &ShimConfig, end: &StreamEnd<'_>, receipt_id: &str, path: &str) -> Value {
    json!({
        "schema": SHIM_RECEIPT_SCHEMA,
        "kind": end.end_state.kind(),
        "receipt_id": receipt_id,
        "session_id": config.session_id,
        "provider": "llm_shim",
        "upstream": config.upstream,
        "path": path,
        "model": end.model,
        "stream": end.stream,
        "first_token_at": end.first_byte_at,
        "ended_at": now_rfc3339(),
        "abort_reason": end.abort_reason,
        "output_digest": end.output_digest,
        "injected_stable_hash": end.injected_stable_hash,
        "injected_bundle_digest": end.injected_bundle_digest,
        "created_at": now_rfc3339(),
    })
}

/// Deliver a record: best-effort daemon POST, JSONL spool fallback. Never
/// blocks or fails the mediated request.
pub fn emit(config: &ShimConfig, record: &Value) {
    if let Err(err) = deliver_record(config.daemon_receipts, &config.receipts_spool, record) {
        eprintln!(
            "crux-llm-shim: receipt spool write failed ({}): {err}",
            config.receipts_spool.display()
        );
    }
}

/// Deliver any mediation record through the shared daemon-first, JSONL-spool
/// fallback used by both local injection and cloud witness modes.
///
/// The returned error means both durable paths failed. Cloud witness mode runs
/// this function on its receipt worker so delivery stalls and failures never
/// block provider traffic.
pub fn deliver_record(daemon_receipts: bool, spool: &Path, record: &Value) -> anyhow::Result<()> {
    if daemon_receipts && crate::daemon_client::post_json("/v1/mediation/receipts", record).is_ok() {
        return Ok(());
    }
    append_jsonl(spool, record)
}

fn append_jsonl(path: &Path, record: &Value) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
    let mut line = serde_json::to_vec(record)?;
    line.push(b'\n');
    fs2::FileExt::lock_exclusive(&file)?;
    let write_result = file.write_all(&line);
    let unlock_result = fs2::FileExt::unlock(&file);
    write_result?;
    unlock_result?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_config(spool: PathBuf) -> ShimConfig {
        ShimConfig {
            upstream: "http://127.0.0.1:11434".into(),
            listen: "127.0.0.1:0".into(),
            bundle: None,
            session_id: "shim-test".into(),
            receipts_spool: spool,
            daemon_receipts: false,
        }
    }

    #[test]
    fn rfc3339_known_vectors() {
        assert_eq!(epoch_secs_to_rfc3339(0), "1970-01-01T00:00:00Z");
        // 2026-06-12T00:00:00Z (verified: date -u -d @1781222400)
        assert_eq!(epoch_secs_to_rfc3339(1_781_222_400), "2026-06-12T00:00:00Z");
        // Leap-year boundary: 2024-02-29T23:59:59Z
        assert_eq!(epoch_secs_to_rfc3339(1_709_251_199), "2024-02-29T23:59:59Z");
    }

    #[test]
    fn injected_record_carries_linkage_identity() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path().join("r.jsonl"));
        let bundle = BundleSource::from_markdown(
            "# bundle".into(),
            Some("blake3:abc".into()),
            "endpoint:http://127.0.0.1:14800/v1/context".into(),
        );
        let rec = context_injected_record(&config, &bundle, "r-1", "/v1/chat/completions");
        assert_eq!(rec["kind"], "context_injected");
        assert_eq!(rec["bundle_version"], "context_bundle/v1");
        assert_eq!(rec["stable_hash"], "blake3:abc");
        assert!(rec["bundle_digest"].as_str().unwrap().starts_with("sha256:"));
        assert_eq!(rec["injection_point"], "llm_shim");
    }

    #[test]
    fn end_record_kinds_and_linkage() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path().join("r.jsonl"));
        let end = StreamEnd {
            end_state: EndState::Aborted,
            stream: true,
            model: Some("llama3.2"),
            first_byte_at: Some("2026-06-12T00:00:00Z".into()),
            output_digest: Some("sha256:00".into()),
            abort_reason: Some("client_disconnect"),
            injected_stable_hash: None,
            injected_bundle_digest: Some("sha256:11"),
        };
        let rec = stream_end_record(&config, &end, "r-2", "/v1/chat/completions");
        assert_eq!(rec["kind"], "stream_aborted");
        assert_eq!(rec["abort_reason"], "client_disconnect");
        assert_eq!(rec["injected_bundle_digest"], "sha256:11");
        assert_eq!(EndState::Completed.kind(), "stream_completed");
    }

    #[test]
    fn emit_spools_jsonl_when_daemon_off() {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("nested/receipts.jsonl");
        let config = test_config(spool.clone());
        emit(&config, &serde_json::json!({"kind": "context_injected", "n": 1}));
        emit(&config, &serde_json::json!({"kind": "stream_completed", "n": 2}));
        let text = std::fs::read_to_string(&spool).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        let first: Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["kind"], "context_injected");
    }

    #[test]
    fn concurrent_appenders_preserve_jsonl_framing() {
        let dir = tempfile::tempdir().unwrap();
        let spool = std::sync::Arc::new(dir.path().join("receipts.jsonl"));
        let mut joins = Vec::new();
        for writer in 0..8 {
            let spool = std::sync::Arc::clone(&spool);
            joins.push(std::thread::spawn(move || {
                for sequence in 0..100 {
                    append_jsonl(&spool, &json!({"writer": writer, "sequence": sequence})).unwrap();
                }
            }));
        }
        for join in joins {
            join.join().unwrap();
        }
        let text = std::fs::read_to_string(spool.as_ref()).unwrap();
        let records: Vec<Value> = text.lines().map(|line| serde_json::from_str(line).unwrap()).collect();
        assert_eq!(records.len(), 800);
    }
}
