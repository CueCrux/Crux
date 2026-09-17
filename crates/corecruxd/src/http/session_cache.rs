// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! `GET /v1/sessions/{sessionId}/cache` — the **prompt-cache clock**.
//!
//! Claude Code caches the prompt prefix with a TTL measured from request start
//! (1 hour on a Claude subscription, 5 minutes on API-key/credit billing). When
//! it lapses, the next prompt re-writes the whole prefix at the 2x write rate.
//! Nobody could see that clock before this endpoint: on corpus
//! `drivew-host-claude-transcripts-2026-09` (the Claude Code sessions with >= 5
//! API turns under the operator's transcript directory, read 2026-09-17), idle
//! TTL expiry caused **77.4% of all rewritten cache tokens** — 76 events, 29.0M
//! tokens — and 7 of those 76 were 60-65 minute gaps, a self-paced wakeup that
//! missed by minutes.
//!
//! Everything here is read-only over state the daemon **already** records:
//!
//! - `last_request_at` is the tip of the session's observation log, the JSONL
//!   the installed `crux-observe` hooks already append to via
//!   `POST /v1/sessions/{id}/observations` on SessionStart / UserPromptSubmit /
//!   PostToolUse / Stop / SessionEnd. No new write path exists for this
//!   feature. The server-owned `ts` is used rather than the hook's `client_ts`,
//!   so a skewed client clock cannot push the countdown into the future.
//! - `est_rewrite_tokens` is `Headline::last_turn_context_tokens` from the cost
//!   report the `SessionEnd` cost hook posts — `cache_read + cache_creation +
//!   input` on the session's most recent API turn, i.e. the prefix that is warm
//!   right now. A session that has never been costed reports `null`; the
//!   endpoint never guesses a size.
//! - `ttl_policy` prefers the measured `ephemeral_5m` / `ephemeral_1h` split
//!   the cache ledger already computes over any setting, because that is
//!   evidence rather than configuration. `CRUX_PROMPT_CACHE_TTL` overrides it
//!   for a daemon that knows better. With neither, the policy is reported as
//!   `"unknown"` and the countdown assumes the 1-hour default — an assumption
//!   the response states in `note` rather than hiding.

use std::path::Path;

use axum::extract::{Path as AxumPath, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::auth::{http_scope_context, require_http_any_scope_for_tenant};
use crux_cost::report::Headline;

use super::facts::scoped_session_id_for_http;
use super::observations::observation_file_path;
use super::{problem_response, AppState};

/// Read scopes. Deliberately the pair `route_auth` already enforces for a GET
/// under `/v1/sessions/` ([`super::route_auth`]), so the middleware and the
/// handler cannot disagree about who may read the clock.
const READ_SCOPES: &[&str] = &["query:read", "admin:read"];

/// 1-hour TTL, the Claude-subscription default.
const TTL_1H_SECONDS: i64 = 3600;
/// 5-minute TTL, the API-key / credit-billing default.
const TTL_5M_SECONDS: i64 = 300;

/// Operator override for the TTL policy, read from the daemon's own
/// environment. Accepts `1h` / `3600` and `5m` / `300`.
const TTL_POLICY_ENV: &str = "CRUX_PROMPT_CACHE_TTL";

/// How `ttl_policy` was arrived at — always reported, so a caller can tell a
/// measurement from a default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum TtlBasis {
    /// `CRUX_PROMPT_CACHE_TTL` in the daemon environment.
    Env,
    /// The session's own `ephemeral_5m` / `ephemeral_1h` cache-write split.
    Measured,
    /// Nothing said; the 1-hour subscription default was assumed.
    Assumed,
}

/// Query string for [`get_session_cache`].
#[derive(Debug, Default, Deserialize)]
pub(super) struct SessionCacheQuery {
    /// Tenant owning the cost report. Defaults to `default`.
    #[serde(default)]
    tenant_id: Option<String>,
}

/// `GET /v1/sessions/{sessionId}/cache` response body.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(super) struct SessionCacheResponse {
    /// Echo of the requested session id (unscoped, as the caller wrote it).
    pub session_id: String,
    /// Is the cached prefix still inside its TTL?
    pub warm: bool,
    /// Seconds left before the prefix lapses. `0` once cold — never negative,
    /// because "how long has it been cold" is a different question and
    /// `last_request_at` already answers it.
    pub ttl_seconds_remaining: i64,
    /// RFC3339 tip of the session's observation log.
    pub last_request_at: String,
    /// Tokens the next prompt re-writes if the TTL lapses first, or `null` when
    /// the session has never been costed.
    pub est_rewrite_tokens: Option<u64>,
    /// `1h` | `5m` | `unknown`.
    pub ttl_policy: &'static str,
    /// Where `ttl_policy` came from.
    pub ttl_policy_basis: TtlBasis,
    /// The TTL the countdown actually used, in seconds.
    pub ttl_seconds: i64,
    /// Present only when something was assumed rather than observed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Resolved TTL policy: wire string, how it was decided, and its length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct TtlPolicy {
    pub label: &'static str,
    pub basis: TtlBasis,
    pub seconds: i64,
}

impl TtlPolicy {
    /// The 1-hour default, assumed because nothing said otherwise.
    fn assumed() -> Self {
        Self {
            label: "unknown",
            basis: TtlBasis::Assumed,
            seconds: TTL_1H_SECONDS,
        }
    }
}

/// Resolve the TTL policy: the daemon's environment first, then the session's
/// own measured cache-write tier split, then the assumed 1-hour default.
///
/// The measured split is preferred over any *setting* the daemon could read,
/// because `promptCacheTtl` lives in the operator's Claude Code config and a
/// daemon on another host has no honest way to see it — whereas which tier the
/// session actually wrote is recorded in its own usage numbers.
pub(super) fn resolve_ttl_policy(env_value: Option<&str>, headline: Option<&Headline>) -> TtlPolicy {
    if let Some(raw) = env_value {
        match raw.trim().to_ascii_lowercase().as_str() {
            "1h" | "3600" | "3600s" => {
                return TtlPolicy {
                    label: "1h",
                    basis: TtlBasis::Env,
                    seconds: TTL_1H_SECONDS,
                }
            }
            "5m" | "300" | "300s" => {
                return TtlPolicy {
                    label: "5m",
                    basis: TtlBasis::Env,
                    seconds: TTL_5M_SECONDS,
                }
            }
            // An unparsable override is ignored, not obeyed half-way.
            _ => {}
        }
    }
    match headline {
        Some(h) if h.cache_creation_1h > 0 || h.cache_creation_5m > 0 => {
            if h.cache_creation_1h >= h.cache_creation_5m {
                TtlPolicy {
                    label: "1h",
                    basis: TtlBasis::Measured,
                    seconds: TTL_1H_SECONDS,
                }
            } else {
                TtlPolicy {
                    label: "5m",
                    basis: TtlBasis::Measured,
                    seconds: TTL_5M_SECONDS,
                }
            }
        }
        _ => TtlPolicy::assumed(),
    }
}

/// Assemble the response from a resolved clock. Pure, so the countdown is
/// testable against an injected `now` rather than the wall clock.
pub(super) fn build_response(
    session_id: &str,
    last_request_at: DateTime<Utc>,
    now: DateTime<Utc>,
    policy: TtlPolicy,
    est_rewrite_tokens: Option<u64>,
) -> SessionCacheResponse {
    let idle = now.signed_duration_since(last_request_at).num_seconds();
    let remaining = policy.seconds.saturating_sub(idle).max(0);
    let mut notes: Vec<&str> = Vec::new();
    if policy.basis == TtlBasis::Assumed {
        notes.push(
            "ttl_policy unknown: no cache-tier split observed for this session and no \
             CRUX_PROMPT_CACHE_TTL set, so the countdown assumes the 1-hour Claude-subscription \
             default",
        );
    }
    if est_rewrite_tokens.is_none() {
        notes.push("est_rewrite_tokens is null: this session has no posted cost report to size the warm prefix from");
    }
    SessionCacheResponse {
        session_id: session_id.to_owned(),
        warm: remaining > 0,
        ttl_seconds_remaining: remaining,
        last_request_at: last_request_at.to_rfc3339(),
        est_rewrite_tokens,
        ttl_policy: policy.label,
        ttl_policy_basis: policy.basis,
        ttl_seconds: policy.seconds,
        note: (!notes.is_empty()).then(|| notes.join("; ")),
    }
}

/// Just the timestamp off an observation line. Deserialising the whole
/// `ObservationRecordV1` would pull every capped payload into memory for a
/// number the tip of the file already carries.
#[derive(Deserialize)]
struct ObservationTs {
    ts: DateTime<Utc>,
}

/// Tail window mirroring [`super::observations`]'s own chain-tip reader, so the
/// clock costs the same O(1)-ish read however long the session ran.
const TAIL_WINDOW: u64 = 64 * 1024;

/// `ts` of the last record in the session's observation JSONL, or `None` when
/// the file is absent, empty, or holds no parseable line.
///
/// The last *line* is the newest record: appends are serialised under the
/// observation append lock and carry a monotonic `seq`, so file order is append
/// order. Reads a 64 KiB tail and walks it backwards — the same shape as
/// `read_chain_tip`, including the full-read fallback for the case where one
/// record is larger than the window.
fn last_observation_at(file_path: &Path) -> std::io::Result<Option<DateTime<Utc>>> {
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom};

    let mut file = match File::open(file_path) {
        Ok(f) => f,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    };
    let size = file.metadata()?.len();
    if size == 0 {
        return Ok(None);
    }
    let start = size.saturating_sub(TAIL_WINDOW);
    file.seek(SeekFrom::Start(start))?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    let text = String::from_utf8_lossy(&buf);
    for line in text.lines().rev() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(record) = serde_json::from_str::<ObservationTs>(line) {
            return Ok(Some(record.ts));
        }
    }
    // The window held no parseable record (one line longer than it, or a
    // partially-written tail). Fall back to the whole file rather than
    // reporting a session cold that is not.
    full_scan_last_ts(file_path)
}

/// Full-file fallback for [`last_observation_at`]: the newest `ts` anywhere in
/// the log. Constant memory, one pass.
fn full_scan_last_ts(file_path: &Path) -> std::io::Result<Option<DateTime<Utc>>> {
    use std::fs::File;
    use std::io::{BufRead, BufReader};
    let file = File::open(file_path)?;
    let mut newest: Option<DateTime<Utc>> = None;
    for line in BufReader::new(file).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(record) = serde_json::from_str::<ObservationTs>(&line) {
            newest = Some(match newest {
                Some(current) if current >= record.ts => current,
                _ => record.ts,
            });
        }
    }
    Ok(newest)
}

/// `GET /v1/sessions/{sessionId}/cache` — how long this session's prompt cache
/// stays warm, and what a lapse would cost.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_session_cache(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(session_id): AxumPath<String>,
    Query(params): Query<SessionCacheQuery>,
) -> Response {
    let tenant_id = params
        .tenant_id
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .unwrap_or("default")
        .to_owned();
    if let Err(problem) = require_http_any_scope_for_tenant(&state.auth, &headers, READ_SCOPES, &tenant_id) {
        return problem.into_response();
    }
    let ctx = match http_scope_context(&state.auth, &headers) {
        Ok(ctx) => ctx,
        Err(problem) => return problem.into_response(),
    };

    let scoped = scoped_session_id_for_http(&ctx, &session_id);
    let file_path = observation_file_path(&state.data_dir, &scoped);
    let last_request_at = match last_observation_at(&file_path) {
        Ok(Some(at)) => at,
        Ok(None) => {
            return problem_response(
                StatusCode::NOT_FOUND,
                "no observations recorded for this session — the prompt-cache clock starts at the \
                 first observe-hook event"
                    .to_string(),
            )
        }
        Err(err) => {
            return problem_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("read session observations: {err}"),
            )
        }
    };

    // The cost report is an enrichment, not a precondition: without it the
    // clock is still correct, only the rewrite size is unknown. It is keyed by
    // the raw (unscoped) session id, the way `corecruxctl session cost --post`
    // writes it.
    let headline: Option<Headline> = if crate::cost::cost_lens_enabled() {
        let store = crate::cost::global().lock().await;
        store.get(&tenant_id, &session_id).map(|r| r.report.headline)
    } else {
        None
    };
    let policy = resolve_ttl_policy(std::env::var(TTL_POLICY_ENV).ok().as_deref(), headline.as_ref());
    let est = headline.as_ref().and_then(|h| h.last_turn_context_tokens);

    let body = build_response(&session_id, last_request_at, Utc::now(), policy, est);
    (StatusCode::OK, Json(body)).into_response()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn at(rfc3339: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(rfc3339).expect("fixture timestamp").into()
    }

    fn one_hour() -> TtlPolicy {
        TtlPolicy {
            label: "1h",
            basis: TtlBasis::Measured,
            seconds: TTL_1H_SECONDS,
        }
    }

    // ── The countdown ────────────────────────────────────────────────────

    #[test]
    fn warm_session_counts_down_from_the_last_observation() {
        let r = build_response(
            "s1",
            at("2026-09-17T14:02:00Z"),
            at("2026-09-17T14:28:00Z"),
            one_hour(),
            Some(181_447),
        );
        assert!(r.warm);
        assert_eq!(r.ttl_seconds_remaining, 2040); // 3600 - 26 min
        assert_eq!(r.last_request_at, "2026-09-17T14:02:00+00:00");
        assert_eq!(r.est_rewrite_tokens, Some(181_447));
        assert_eq!(r.ttl_policy, "1h");
        assert_eq!(r.note, None, "nothing was assumed, so nothing to caveat");
    }

    #[test]
    fn lapsed_session_is_cold_and_never_reports_a_negative_countdown() {
        let r = build_response(
            "s1",
            at("2026-09-17T14:02:00Z"),
            at("2026-09-17T16:40:00Z"),
            one_hour(),
            Some(181_447),
        );
        assert!(!r.warm);
        assert_eq!(r.ttl_seconds_remaining, 0);
        // The cold-since time is still exact, which is what the banner prints.
        assert_eq!(r.last_request_at, "2026-09-17T14:02:00+00:00");
    }

    #[test]
    fn the_boundary_second_is_cold_not_warm() {
        let exactly_ttl = build_response(
            "s1",
            at("2026-09-17T14:00:00Z"),
            at("2026-09-17T15:00:00Z"),
            one_hour(),
            None,
        );
        assert!(
            !exactly_ttl.warm,
            "TTL is measured from request start; 3600s in, it is gone"
        );
        let one_second_left = build_response(
            "s1",
            at("2026-09-17T14:00:00Z"),
            at("2026-09-17T14:59:59Z"),
            one_hour(),
            None,
        );
        assert!(one_second_left.warm);
        assert_eq!(one_second_left.ttl_seconds_remaining, 1);
    }

    #[test]
    fn a_five_minute_policy_shortens_the_countdown() {
        let policy = TtlPolicy {
            label: "5m",
            basis: TtlBasis::Measured,
            seconds: TTL_5M_SECONDS,
        };
        let r = build_response(
            "s1",
            at("2026-09-17T14:00:00Z"),
            at("2026-09-17T14:04:00Z"),
            policy,
            None,
        );
        assert!(r.warm);
        assert_eq!(r.ttl_seconds_remaining, 60);
        assert_eq!(r.ttl_seconds, 300);
    }

    // ── Honesty about what is unknown ────────────────────────────────────

    #[test]
    fn an_uncosted_session_reports_null_tokens_and_says_why() {
        let r = build_response(
            "s1",
            at("2026-09-17T14:00:00Z"),
            at("2026-09-17T14:10:00Z"),
            one_hour(),
            None,
        );
        assert_eq!(r.est_rewrite_tokens, None);
        let note = r.note.expect("a null must be explained");
        assert!(note.contains("est_rewrite_tokens is null"), "{note}");
    }

    #[test]
    fn an_assumed_policy_states_the_assumption_in_the_response() {
        let r = build_response(
            "s1",
            at("2026-09-17T14:00:00Z"),
            at("2026-09-17T14:10:00Z"),
            TtlPolicy::assumed(),
            Some(1000),
        );
        assert_eq!(r.ttl_policy, "unknown");
        assert_eq!(r.ttl_policy_basis, TtlBasis::Assumed);
        assert_eq!(r.ttl_seconds, TTL_1H_SECONDS, "the countdown assumes 1h");
        let note = r.note.expect("an assumption must be stated");
        assert!(note.contains("assumes the 1-hour"), "{note}");
    }

    // ── Policy resolution ────────────────────────────────────────────────

    fn headline_with(cache_creation_5m: u64, cache_creation_1h: u64) -> Headline {
        Headline {
            cache_creation_5m,
            cache_creation_1h,
            ..Headline::default()
        }
    }

    #[test]
    fn policy_prefers_the_env_override() {
        assert_eq!(resolve_ttl_policy(Some("5m"), None).label, "5m");
        assert_eq!(resolve_ttl_policy(Some("5m"), None).basis, TtlBasis::Env);
        assert_eq!(resolve_ttl_policy(Some("300"), None).seconds, TTL_5M_SECONDS);
        assert_eq!(resolve_ttl_policy(Some(" 1H "), None).label, "1h");
        // The override wins over the measurement.
        assert_eq!(
            resolve_ttl_policy(Some("5m"), Some(&headline_with(0, 900_000))).label,
            "5m"
        );
    }

    #[test]
    fn an_unparsable_override_falls_through_rather_than_half_applying() {
        let p = resolve_ttl_policy(Some("half an hour"), Some(&headline_with(0, 900_000)));
        assert_eq!(p.label, "1h");
        assert_eq!(p.basis, TtlBasis::Measured);
    }

    #[test]
    fn policy_is_measured_from_the_cache_tier_split() {
        // Claude Code on a subscription writes the 1h tier almost exclusively.
        let subscription = resolve_ttl_policy(None, Some(&headline_with(0, 900_000)));
        assert_eq!((subscription.label, subscription.basis), ("1h", TtlBasis::Measured));
        let credits = resolve_ttl_policy(None, Some(&headline_with(900_000, 0)));
        assert_eq!((credits.label, credits.basis), ("5m", TtlBasis::Measured));
        // Mixed: the tier carrying more tokens decides.
        assert_eq!(resolve_ttl_policy(None, Some(&headline_with(10, 900_000))).label, "1h");
    }

    #[test]
    fn policy_is_unknown_when_nothing_was_observed() {
        assert_eq!(resolve_ttl_policy(None, None).basis, TtlBasis::Assumed);
        // A costed session that wrote no cache at all is still unknown.
        assert_eq!(
            resolve_ttl_policy(None, Some(&headline_with(0, 0))).basis,
            TtlBasis::Assumed
        );
    }

    // ── Reading the observation tip ──────────────────────────────────────

    fn write_lines(dir: &Path, name: &str, lines: &[&str]) -> std::path::PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, lines.join("\n")).expect("write fixture");
        p
    }

    #[test]
    fn observation_tip_is_the_last_record() {
        let tmp = tempfile::tempdir().unwrap();
        let p = write_lines(
            tmp.path(),
            "s.jsonl",
            &[
                r#"{"ts":"2026-09-17T14:00:00Z","kind":"session_start"}"#,
                r#"{"ts":"2026-09-17T14:20:00Z","kind":"tool_use"}"#,
                r#"{"ts":"2026-09-17T14:40:00Z","kind":"stop"}"#,
            ],
        );
        assert_eq!(last_observation_at(&p).unwrap(), Some(at("2026-09-17T14:40:00Z")));
    }

    #[test]
    fn malformed_and_blank_lines_are_skipped_not_fatal() {
        let tmp = tempfile::tempdir().unwrap();
        // A half-written final line (the hook appends while we read) must fall
        // back to the previous record rather than reporting the session cold.
        let p = write_lines(
            tmp.path(),
            "s.jsonl",
            &[
                "",
                "{ not json",
                r#"{"kind":"no timestamp here"}"#,
                r#"{"ts":"2026-09-17T14:40:00Z","kind":"tool_use"}"#,
                r#"{"ts":"2026-09-17T14:4"#,
            ],
        );
        assert_eq!(last_observation_at(&p).unwrap(), Some(at("2026-09-17T14:40:00Z")));
    }

    #[test]
    fn a_record_larger_than_the_tail_window_falls_back_to_a_full_scan() {
        let tmp = tempfile::tempdir().unwrap();
        // One record bigger than TAIL_WINDOW: the tail holds no line start, so
        // the reverse walk finds nothing and the full scan has to answer.
        let big = "x".repeat((TAIL_WINDOW as usize) + 4096);
        let p = write_lines(
            tmp.path(),
            "s.jsonl",
            &[
                r#"{"ts":"2026-09-17T14:00:00Z","kind":"session_start"}"#,
                &format!(r#"{{"ts":"2026-09-17T14:40:00Z","kind":"tool_use","payload":"{big}"}}"#),
            ],
        );
        assert_eq!(last_observation_at(&p).unwrap(), Some(at("2026-09-17T14:40:00Z")));
    }

    #[test]
    fn a_missing_or_empty_log_yields_no_tip() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(last_observation_at(&tmp.path().join("absent.jsonl")).unwrap(), None);
        let p = write_lines(tmp.path(), "empty.jsonl", &["", "  "]);
        assert_eq!(last_observation_at(&p).unwrap(), None);
    }

    // ── Handler ──────────────────────────────────────────────────────────

    async fn body_json(resp: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    }

    #[tokio::test]
    async fn handler_returns_the_clock_for_a_session_with_observations() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = super::super::tests::test_app_state(16);
        state.data_dir = tmp.path().to_path_buf();
        std::fs::create_dir_all(tmp.path().join("observations")).unwrap();
        let recent = Utc::now() - chrono::Duration::minutes(20);
        std::fs::write(
            observation_file_path(tmp.path(), "sess-warm"),
            format!(r#"{{"ts":"{}","kind":"tool_use"}}"#, recent.to_rfc3339()),
        )
        .unwrap();

        let resp = get_session_cache(
            State(state),
            HeaderMap::new(),
            AxumPath("sess-warm".to_string()),
            Query(SessionCacheQuery::default()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["session_id"], "sess-warm");
        assert_eq!(body["warm"], true);
        let remaining = body["ttl_seconds_remaining"].as_i64().unwrap();
        assert!(
            (2380..=2400).contains(&remaining),
            "about 40 minutes left, got {remaining}"
        );
        // Never costed in this test, so the size is null and the response says so.
        assert!(body["est_rewrite_tokens"].is_null());
        assert!(body["note"].as_str().unwrap().contains("est_rewrite_tokens is null"));
    }

    #[tokio::test]
    async fn handler_reports_cold_after_the_ttl_lapses() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = super::super::tests::test_app_state(16);
        state.data_dir = tmp.path().to_path_buf();
        std::fs::create_dir_all(tmp.path().join("observations")).unwrap();
        let stale = Utc::now() - chrono::Duration::minutes(90);
        std::fs::write(
            observation_file_path(tmp.path(), "sess-cold"),
            format!(r#"{{"ts":"{}","kind":"stop"}}"#, stale.to_rfc3339()),
        )
        .unwrap();

        let resp = get_session_cache(
            State(state),
            HeaderMap::new(),
            AxumPath("sess-cold".to_string()),
            Query(SessionCacheQuery::default()),
        )
        .await;
        let body = body_json(resp).await;
        assert_eq!(body["warm"], false);
        assert_eq!(body["ttl_seconds_remaining"], 0);
    }

    #[tokio::test]
    async fn an_unobserved_session_is_a_404_not_a_fabricated_clock() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = super::super::tests::test_app_state(16);
        state.data_dir = tmp.path().to_path_buf();
        let resp = get_session_cache(
            State(state),
            HeaderMap::new(),
            AxumPath("never-seen".to_string()),
            Query(SessionCacheQuery::default()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
