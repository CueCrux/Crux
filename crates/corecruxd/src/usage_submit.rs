// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Phase T (M1) — the consent-gated, opt-in submitter for the local
//! `usage_ping` receipt.
//!
//! ## The whole risk is this file
//!
//! Crux's trust story is "no phone-home": with default config the daemon
//! makes **zero** non-loopback network calls, and the release gate
//! `scripts/assert-no-phone-home.sh` boots with default env and fails on any
//! egress attempt. This module adds the *only* sanctioned outbound path — a
//! signed, metadata-only adoption ping — and it must never fire unless the
//! operator has explicitly opted in **and** recorded consent.
//!
//! ## Three-way consent/egress gate
//!
//! [`submit_usage_ping`] performs **zero** network I/O unless ALL THREE hold:
//!
//! 1. `CORECRUXD_USAGE_RECEIPTS_SUBMIT` is true (master enable), AND
//! 2. `CORECRUXD_USAGE_RECEIPTS_ENDPOINT` is a set `https://` URL (there is
//!    **no** hardcoded default — a fresh install dials nothing), AND
//! 3. `CORECRUXD_USAGE_RECEIPTS_CONSENT_AT` records an explicit consent act.
//!
//! Any missing leg is a no-op that returns [`UsageSubmitOutcome::Skipped`]
//! *before* the transport is ever touched. A plaintext (`http://`) endpoint is
//! rejected via the same [`OutboundError::PlainHttpBlocked`] rule the
//! community-extension outbound path uses (`allow_plain_http:false`).
//!
//! ## Metadata-only payload
//!
//! [`UsagePingSubmission`] carries ONLY receipt id, the receipt's own metadata
//! body (canonical CBOR, hex-encoded), body hash, passport fingerprint, the
//! daemon's Ed25519 public key, event class, timestamp, and the signature
//! envelope — enough for a collector to reconstruct the signed message, verify
//! the signature, and count distinct passports. The receipt body is
//! metadata-only *by construction* (`build_usage_ping_body_v1` takes a
//! strongly-typed input that cannot express content), so sending its bytes
//! still leaks nothing: there is no field through which fact content, query
//! text, or corpus identity could be expressed, and `passport_fpr ==
//! blake3(public_key)[..16]` binds the key to the fingerprint the collector
//! tallies by.
//!
//! ## Never on a timer, never on boot
//!
//! The submitter is triggered **only** by an explicit `usage_ping` mint on the
//! `/v1/mediation/receipts` surface, *after* the local signed receipt has been
//! persisted (see `http::stream_receipts::mint_usage_receipt`). It is never
//! wired into the boot path or a background interval — that is what keeps the
//! no-phone-home assertion green under default config.

use serde::Serialize;

use crate::extension_outbound::{OutboundConfig, OutboundError, OutboundTransport, RateTable, UreqTransport};

/// Rate-limiter bucket key for the usage-ping submitter (reuses the
/// community-extension [`RateTable`], keyed by (this id, passport_fpr)).
const USAGE_SUBMIT_RATE_KEY: &str = "usage_ping_submit";

/// Operator-set consent + endpoint knobs for the opt-in submitter. Every
/// field is default-absent: [`UsageSubmitConfig::default`] dials nothing, and
/// [`active_endpoint`](Self::active_endpoint) only returns `Some` when the
/// full three-way gate is satisfied.
#[derive(Debug, Clone, Default)]
pub struct UsageSubmitConfig {
    /// `CORECRUXD_USAGE_RECEIPTS_SUBMIT` — master enable, default false.
    pub enabled: bool,
    /// `CORECRUXD_USAGE_RECEIPTS_ENDPOINT` — the `https://` collector URL.
    /// Default `None`; there is **no hardcoded endpoint**.
    pub endpoint: Option<String>,
    /// `CORECRUXD_USAGE_RECEIPTS_CONSENT_AT` — the recorded consent act (an
    /// RFC3339 timestamp). Default `None`; the submitter refuses to fire
    /// without it.
    pub consent_at: Option<String>,
}

impl UsageSubmitConfig {
    /// The collector endpoint, but only when the full opt-in gate is
    /// satisfied: submit enabled AND a non-empty endpoint AND a recorded
    /// consent act. Returns `None` otherwise — callers use this to decide
    /// whether to spawn a submit at all, so an unconfigured daemon never even
    /// constructs a network task.
    pub fn active_endpoint(&self) -> Option<&str> {
        if !self.enabled {
            return None;
        }
        let endpoint = self.endpoint.as_deref().map(str::trim).filter(|e| !e.is_empty())?;
        // Consent must be recorded — a set endpoint without it does not fire.
        self.consent_at.as_deref().map(str::trim).filter(|c| !c.is_empty())?;
        Some(endpoint)
    }
}

/// Interpret the raw `CORECRUXD_USAGE_RECEIPTS_CONSENT_AT` value.
///
/// - unset / empty → `None` (no consent recorded → submitter inert)
/// - the literal `"yes"` → stamp the current time (RFC3339) as the consent act
/// - anything else → the operator-provided value, trimmed (expected RFC3339)
pub fn parse_consent_at(raw: Option<String>) -> Option<String> {
    let value = raw?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.eq_ignore_ascii_case("yes") {
        return Some(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
    }
    Some(trimmed.to_string())
}

/// The Ed25519 signature envelope carried in a submission — enough material
/// for the collector to verify the ping without ever seeing the body content.
#[derive(Debug, Clone, Serialize)]
pub struct UsagePingSubmissionSig {
    pub alg: String,
    pub key_id: String,
    pub signed_at: String,
    pub signature_hex: String,
}

/// The exact wire payload POSTed to the collector. **Metadata only** — there
/// is no field for fact content, query text, or corpus identity. The serde
/// field order below is the on-wire key order.
#[derive(Debug, Clone, Serialize)]
pub struct UsagePingSubmission {
    /// The signed receipt's id.
    pub receipt_id: String,
    /// Hex of the canonical CBOR receipt body — the exact bytes the daemon
    /// signed. This is the **signed message** the collector reconstructs to
    /// verify the signature. Safe to send: the usage_ping body is metadata-only
    /// by construction (receipt_id, kind, tenant_id, passport_fpr, event_class,
    /// count, created_at — **never** fact / query / corpus content).
    pub body_cbor_hex: String,
    /// `blake3:<hex>` digest of the canonical receipt body (a hash, not the
    /// body).
    pub body_hash: String,
    /// The daemon's passport fingerprint — the adoption unit the collector
    /// tallies distinct instances by.
    pub passport_fpr: String,
    /// The daemon's Ed25519 public key, hex-encoded. Not secret; the collector
    /// needs it to verify the signature, and `passport_fpr ==
    /// blake3(public_key)[..16]` binds it to the fingerprint above.
    pub public_key_hex: String,
    /// One of the closed `usage_ping` event classes (`session` / `query` /
    /// `daemon_start`).
    pub event_class: String,
    /// The receipt's creation timestamp.
    pub created_at: String,
    /// The Ed25519 signature envelope.
    pub sig: UsagePingSubmissionSig,
}

/// Result of a submit attempt. `Skipped` means the three-way gate was not
/// satisfied and **no network call was attempted**.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UsageSubmitOutcome {
    /// The submitter was inert; the reason is a static string for logging.
    Skipped(&'static str),
    /// The collector accepted the ping with a 2xx status. `latest_version` is
    /// the current-latest Crux release string the collector reported in its
    /// response body (M2 version-notify), or `None` when the response omitted
    /// it (older collector) or was unparseable — a no-op in either case.
    Submitted {
        status: u16,
        latest_version: Option<String>,
    },
}

/// Attempt a consent-gated submit of one usage ping.
///
/// This is the single choke point for the daemon's only outbound signal. It
/// enforces the three-way gate, the HTTPS-only rule, and a per-passport rate
/// limit *before* the transport is ever invoked, so a non-fully-configured
/// daemon performs zero network I/O here.
pub fn submit_usage_ping(
    transport: &dyn OutboundTransport,
    rate_table: &RateTable,
    outbound: &OutboundConfig,
    cfg: &UsageSubmitConfig,
    submission: &UsagePingSubmission,
) -> Result<UsageSubmitOutcome, OutboundError> {
    // ── The three-way consent/egress gate (the whole point of M1) ────────
    if !cfg.enabled {
        return Ok(UsageSubmitOutcome::Skipped(
            "submit disabled (CORECRUXD_USAGE_RECEIPTS_SUBMIT unset)",
        ));
    }
    let Some(endpoint) = cfg.endpoint.as_deref().map(str::trim).filter(|e| !e.is_empty()) else {
        return Ok(UsageSubmitOutcome::Skipped(
            "no collector endpoint (CORECRUXD_USAGE_RECEIPTS_ENDPOINT unset)",
        ));
    };
    if cfg
        .consent_at
        .as_deref()
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .is_none()
    {
        return Ok(UsageSubmitOutcome::Skipped(
            "no recorded consent (CORECRUXD_USAGE_RECEIPTS_CONSENT_AT unset)",
        ));
    }

    // ── HTTPS-only (reuse the extension_outbound plain-http rule) ─────────
    // `allow_plain_http` is false by default, so any non-https endpoint is
    // rejected before a single byte leaves the process.
    if !endpoint.starts_with("https://") && (!endpoint.starts_with("http://") || !outbound.allow_plain_http) {
        return Err(OutboundError::PlainHttpBlocked);
    }

    // ── Rate-limit per passport (reuse the extension RateTable) ───────────
    rate_table.check_and_record(
        USAGE_SUBMIT_RATE_KEY,
        &submission.passport_fpr,
        outbound.default_rate_per_min,
    )?;

    let body_json = serde_json::to_string(submission)?;
    if body_json.len() > outbound.max_request_bytes {
        return Err(OutboundError::RequestTooLarge(
            body_json.len(),
            outbound.max_request_bytes,
        ));
    }

    let resp = transport.invoke(endpoint, None, body_json, outbound.timeout)?;
    if !(200..=299).contains(&resp.status) {
        return Err(OutboundError::UpstreamError {
            status: resp.status,
            body: resp.body.chars().take(256).collect(),
        });
    }
    // M2 version-notify: the collector's 2xx body may carry a `latest_version`
    // string (the current-latest Crux release). Parse it best-effort — a body
    // without it (older collector) or an unparseable body yields `None`, which
    // the caller treats as a no-op.
    let latest_version = parse_latest_version(&resp.body);
    Ok(UsageSubmitOutcome::Submitted {
        status: resp.status,
        latest_version,
    })
}

/// Parse the optional `latest_version` string from a collector response body.
///
/// A body without the field (older collector), an empty value, or an
/// unparseable body all yield `None` — version-notify is then a no-op. Never
/// errors: this must not destabilize the submit path.
fn parse_latest_version(body: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    let s = v.get("latest_version")?.as_str()?.trim();
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

/// Parse a `MAJOR.MINOR.PATCH` version string into a comparable tuple. Strips a
/// leading `v` and any `-pre` / `+build` metadata; missing minor/patch default
/// to `0`. Returns `None` if the major component is not a number.
fn parse_semver(v: &str) -> Option<(u64, u64, u64)> {
    let core = v.trim().trim_start_matches('v');
    // Drop any pre-release / build metadata suffix before splitting on '.'.
    let core = core.split(['-', '+']).next().unwrap_or(core);
    let mut it = core.split('.');
    let major = it.next()?.trim().parse::<u64>().ok()?;
    let minor = it.next().unwrap_or("0").trim().parse::<u64>().ok()?;
    let patch = it.next().unwrap_or("0").trim().parse::<u64>().ok()?;
    Some((major, minor, patch))
}

/// Is `own` strictly older (by semver) than `latest`? Returns `false` when
/// either string is unparseable — an unknown comparison never warns (safe
/// default), and a current/ahead daemon is not "behind".
pub fn is_behind(own: &str, latest: &str) -> bool {
    match (parse_semver(own), parse_semver(latest)) {
        (Some(o), Some(l)) => o < l,
        _ => false,
    }
}

/// Record the collector-reported latest release into the shared `/v1/version`
/// slot and, if this daemon's own build is behind it, log an upgrade WARN.
///
/// The value is always stored (so `/v1/version` reflects the last-seen latest,
/// current or not); the WARN fires only when strictly behind. Own version is
/// `env!("CARGO_PKG_VERSION")` — the same string surfaced as `build.version`.
pub fn note_latest_release(slot: &std::sync::RwLock<Option<String>>, latest: &str) {
    let own = env!("CARGO_PKG_VERSION");
    if is_behind(own, latest) {
        tracing::warn!(
            target: "usage_submit",
            own_version = own,
            latest_release = latest,
            "crux daemon {own} is behind latest release {latest}; upgrade recommended"
        );
    }
    if let Ok(mut guard) = slot.write() {
        *guard = Some(latest.to_string());
    }
}

/// Best-effort, fire-and-forget submit invoked from the `usage_ping` mint path
/// **after** the local receipt is persisted. A no-op (never even spawns a
/// task) unless the full three-way gate is active. Uses the production
/// [`UreqTransport`] on a blocking task so it never stalls the async handler,
/// and a failure is logged, never surfaced — an adoption ping must not
/// destabilize the receipt write.
pub fn maybe_spawn_submit(state: &crate::http::AppState, submission: UsagePingSubmission) {
    // Gate check up front: an unconfigured daemon constructs no network task.
    if state.usage_submit.active_endpoint().is_none() {
        return;
    }
    let rate_table = state.extension_rate_table.clone();
    let cfg = state.usage_submit.clone();
    // M2 version-notify: the submit task writes the collector-reported latest
    // release here; `/v1/version` reads it.
    let latest_release = state.latest_release.clone();
    tokio::task::spawn_blocking(move || {
        let transport = UreqTransport;
        let outbound = OutboundConfig::from_env();
        match submit_usage_ping(&transport, &rate_table, &outbound, &cfg, &submission) {
            Ok(UsageSubmitOutcome::Submitted { status, latest_version }) => {
                tracing::info!(target: "usage_submit", status, receipt_id = %submission.receipt_id, "usage ping submitted");
                // M2: surface an upgrade notice (WARN + `/v1/version`) when the
                // collector reports a newer release than this build. A response
                // without `latest_version` is a no-op.
                if let Some(latest) = latest_version {
                    note_latest_release(&latest_release, &latest);
                }
            }
            Ok(UsageSubmitOutcome::Skipped(reason)) => {
                tracing::debug!(target: "usage_submit", reason, "usage ping submit skipped");
            }
            Err(err) => {
                tracing::warn!(target: "usage_submit", error = %err, receipt_id = %submission.receipt_id, "usage ping submit failed");
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extension_outbound::{OutboundTransport, TransportResponse};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    /// Records every invoke so tests can assert *zero* network was attempted
    /// when the gate is not satisfied.
    #[derive(Default)]
    struct SpyTransport {
        seen: Arc<Mutex<Vec<(String, String)>>>,
        status: u16,
        resp_body: String,
    }

    impl SpyTransport {
        fn ok() -> Self {
            Self {
                seen: Arc::new(Mutex::new(Vec::new())),
                status: 200,
                resp_body: "{}".to_string(),
            }
        }
        /// A 2xx transport whose response body is `resp_body` — used to feed the
        /// M2 `latest_version` parse path a realistic collector response.
        fn with_body(resp_body: &str) -> Self {
            Self {
                seen: Arc::new(Mutex::new(Vec::new())),
                status: 200,
                resp_body: resp_body.to_string(),
            }
        }
        fn calls(&self) -> Vec<(String, String)> {
            self.seen.lock().unwrap().clone()
        }
    }

    impl OutboundTransport for SpyTransport {
        fn invoke(
            &self,
            url: &str,
            _bearer: Option<&str>,
            body_json: String,
            _timeout: Duration,
        ) -> Result<TransportResponse, OutboundError> {
            self.seen.lock().unwrap().push((url.to_string(), body_json.clone()));
            Ok(TransportResponse {
                status: self.status,
                body: self.resp_body.clone(),
            })
        }
    }

    fn submission() -> UsagePingSubmission {
        // Build the *real* canonical body via the metadata-only constructor so
        // the metadata-only test can hex-decode `body_cbor_hex` and re-parse it:
        // `build_usage_ping_body_v1` takes a strongly-typed input that cannot
        // express content, so the resulting body is provably metadata-only.
        let (body_bytes, _) = corecrux_receipts::build_usage_ping_body_v1(&corecrux_receipts::UsagePingBodyInputV1 {
            tenant_id: "local",
            receipt_id: "r-1",
            passport_fpr: "fpr_test",
            event_class: corecrux_receipts::UsageEventClassV1::Session,
            count: 1,
            created_at: "2026-07-03T00:00:00Z",
        });
        UsagePingSubmission {
            receipt_id: "r-1".to_string(),
            body_cbor_hex: hex::encode(&body_bytes),
            body_hash: "blake3:deadbeef".to_string(),
            passport_fpr: "fpr_test".to_string(),
            public_key_hex: hex::encode([0xbbu8; 32]),
            event_class: "session".to_string(),
            created_at: "2026-07-03T00:00:00Z".to_string(),
            sig: UsagePingSubmissionSig {
                alg: "ed25519".to_string(),
                key_id: "fpr_test".to_string(),
                signed_at: "2026-07-03T00:00:00Z".to_string(),
                signature_hex: "aa".repeat(64),
            },
        }
    }

    fn fully_configured() -> UsageSubmitConfig {
        UsageSubmitConfig {
            enabled: true,
            endpoint: Some("https://collector.example.com/usage".to_string()),
            consent_at: Some("2026-07-03T00:00:00Z".to_string()),
        }
    }

    // ── Gate leg 1: master enable off ────────────────────────────────────
    #[test]
    fn default_config_is_fully_inert() {
        let cfg = UsageSubmitConfig::default();
        assert!(cfg.active_endpoint().is_none(), "a default install dials nothing");
        let spy = SpyTransport::ok();
        let out = submit_usage_ping(&spy, &RateTable::new(), &OutboundConfig::default(), &cfg, &submission()).unwrap();
        assert!(matches!(out, UsageSubmitOutcome::Skipped(_)));
        assert!(
            spy.calls().is_empty(),
            "no network call may be attempted under default config"
        );
    }

    // ── Gate leg 2: feature/submit ON but NO endpoint → inert, zero egress ─
    // This is the M1 no-phone-home regression: SUBMIT=1 with no endpoint set
    // must attempt no network call.
    #[test]
    fn submit_enabled_without_endpoint_is_inert() {
        let cfg = UsageSubmitConfig {
            enabled: true,
            endpoint: None,
            consent_at: Some("2026-07-03T00:00:00Z".to_string()),
        };
        assert!(cfg.active_endpoint().is_none());
        let spy = SpyTransport::ok();
        let out = submit_usage_ping(&spy, &RateTable::new(), &OutboundConfig::default(), &cfg, &submission()).unwrap();
        assert_eq!(
            out,
            UsageSubmitOutcome::Skipped("no collector endpoint (CORECRUXD_USAGE_RECEIPTS_ENDPOINT unset)")
        );
        assert!(spy.calls().is_empty(), "no endpoint must mean zero network attempts");
    }

    // ── Gate leg 3: endpoint set but NO consent → does not fire ───────────
    #[test]
    fn submit_without_consent_does_not_fire() {
        let cfg = UsageSubmitConfig {
            enabled: true,
            endpoint: Some("https://collector.example.com/usage".to_string()),
            consent_at: None,
        };
        assert!(cfg.active_endpoint().is_none(), "no consent → gate closed");
        let spy = SpyTransport::ok();
        let out = submit_usage_ping(&spy, &RateTable::new(), &OutboundConfig::default(), &cfg, &submission()).unwrap();
        assert_eq!(
            out,
            UsageSubmitOutcome::Skipped("no recorded consent (CORECRUXD_USAGE_RECEIPTS_CONSENT_AT unset)")
        );
        assert!(spy.calls().is_empty());
    }

    // ── HTTPS-only: a plaintext endpoint is rejected (PlainHttpBlocked) ───
    #[test]
    fn plaintext_endpoint_is_rejected() {
        let cfg = UsageSubmitConfig {
            enabled: true,
            endpoint: Some("http://collector.example.com/usage".to_string()),
            consent_at: Some("2026-07-03T00:00:00Z".to_string()),
        };
        // The gate itself passes (all three set), but the HTTPS rule blocks it.
        assert!(cfg.active_endpoint().is_some());
        let spy = SpyTransport::ok();
        let err = submit_usage_ping(&spy, &RateTable::new(), &OutboundConfig::default(), &cfg, &submission())
            .expect_err("plaintext endpoint must be blocked");
        assert!(matches!(err, OutboundError::PlainHttpBlocked));
        assert!(
            spy.calls().is_empty(),
            "a rejected plaintext endpoint must attempt zero network"
        );
    }

    // ── Fully configured → fires, and the payload is metadata-only ────────
    #[test]
    fn fully_configured_submits_metadata_only_payload() {
        let cfg = fully_configured();
        let spy = SpyTransport::ok();
        let out = submit_usage_ping(&spy, &RateTable::new(), &OutboundConfig::default(), &cfg, &submission()).unwrap();
        // The spy's `{}` body carries no `latest_version` → None (no-op notify).
        assert_eq!(
            out,
            UsageSubmitOutcome::Submitted {
                status: 200,
                latest_version: None
            }
        );

        let calls = spy.calls();
        assert_eq!(calls.len(), 1, "exactly one network call when fully configured");
        let (url, body_json) = &calls[0];
        assert_eq!(url, "https://collector.example.com/usage");

        // The wire payload carries ONLY the metadata fields. `body_cbor_hex`
        // (the receipt's own metadata body) and `public_key_hex` (the passport
        // public key, needed to verify the sig) are legitimate metadata: the
        // body is metadata-only by construction, proven below.
        let sent: serde_json::Value = serde_json::from_str(body_json).expect("payload is json");
        let obj = sent.as_object().expect("payload is an object");
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "body_cbor_hex",
                "body_hash",
                "created_at",
                "event_class",
                "passport_fpr",
                "public_key_hex",
                "receipt_id",
                "sig"
            ],
            "payload must be exactly the metadata field set"
        );

        // Positive: the metadata is present and correct.
        assert_eq!(obj["receipt_id"], "r-1");
        assert_eq!(obj["body_hash"], "blake3:deadbeef");
        assert_eq!(obj["passport_fpr"], "fpr_test");
        assert_eq!(obj["event_class"], "session");
        assert_eq!(obj["sig"]["alg"], "ed25519");
        // The public key is present and 32 bytes (64 hex chars).
        let public_key_hex = obj["public_key_hex"].as_str().expect("public_key_hex is a string");
        assert_eq!(public_key_hex.len(), 64, "public key is 32 bytes hex-encoded");

        // Stronger guarantee: decode `body_cbor_hex` back to bytes, parse the
        // CBOR body, and prove the *decoded body itself* is metadata-only — no
        // content-bearing key can ride even inside the signed message.
        let body_cbor_hex = obj["body_cbor_hex"].as_str().expect("body_cbor_hex is a string");
        let decoded = hex::decode(body_cbor_hex).expect("body_cbor_hex is valid hex");
        assert!(
            corecrux_receipts::assert_usage_ping_kind_v1(&decoded),
            "the decoded body must parse as a metadata-only usage_ping (any content key would fail this)"
        );
        let decoded_text = String::from_utf8_lossy(&decoded);
        for content_key in ["fact", "query", "entity", "entries", "corpus", "value", "prompt"] {
            assert!(
                !decoded_text.contains(content_key),
                "the decoded receipt body must not carry content key {content_key}"
            );
        }

        // Negative: not one content-bearing key rides the wire. (`body_hash` is
        // a hash and `body_cbor_hex` a metadata-only body; the banned list
        // avoids substrings of the legitimate keys and of hex digits.)
        for banned in [
            "body_bytes",
            "count",
            "tenant_id",
            "fact_id",
            "entries",
            "prompt_hash",
            "corpus",
        ] {
            assert!(
                !body_json.contains(banned),
                "usage submission must not carry content key {banned}"
            );
        }
    }

    #[test]
    fn parse_consent_at_variants() {
        assert!(parse_consent_at(None).is_none());
        assert!(parse_consent_at(Some("   ".to_string())).is_none());
        // "yes" stamps an RFC3339 now.
        let stamped = parse_consent_at(Some("yes".to_string())).expect("yes stamps now");
        assert!(
            stamped.contains('T') && stamped.ends_with('Z'),
            "stamp is RFC3339: {stamped}"
        );
        // An explicit timestamp is passed through (trimmed).
        assert_eq!(
            parse_consent_at(Some("  2026-07-03T12:00:00Z ".to_string())).as_deref(),
            Some("2026-07-03T12:00:00Z")
        );
    }

    // ── M2 version-notify ────────────────────────────────────────────────

    #[test]
    fn parse_latest_version_variants() {
        assert_eq!(
            parse_latest_version(r#"{"latest_version":"0.5.36"}"#).as_deref(),
            Some("0.5.36")
        );
        // Trimmed.
        assert_eq!(
            parse_latest_version(r#"{"latest_version":"  0.5.36  "}"#).as_deref(),
            Some("0.5.36")
        );
        // Extra fields alongside are ignored.
        assert_eq!(
            parse_latest_version(r#"{"ok":true,"latest_version":"1.2.3"}"#).as_deref(),
            Some("1.2.3")
        );
        // Older collector: no field → None (no-op).
        assert!(parse_latest_version(r#"{"ok":true}"#).is_none());
        // Empty value → None.
        assert!(parse_latest_version(r#"{"latest_version":""}"#).is_none());
        // Non-string / malformed → None (never errors).
        assert!(parse_latest_version(r#"{"latest_version":123}"#).is_none());
        assert!(parse_latest_version("not json at all").is_none());
        assert!(parse_latest_version("").is_none());
    }

    #[test]
    fn is_behind_semver_compare() {
        // Strictly older on each component → behind.
        assert!(is_behind("0.5.35", "0.5.36"));
        assert!(is_behind("0.5.35", "0.6.0"));
        assert!(is_behind("0.5.35", "1.0.0"));
        // Equal → not behind.
        assert!(!is_behind("0.5.36", "0.5.36"));
        // Ahead → not behind.
        assert!(!is_behind("0.5.37", "0.5.36"));
        assert!(!is_behind("1.0.0", "0.9.9"));
        // Leading `v` and pre-release/build metadata are tolerated.
        assert!(is_behind("v0.5.35", "v0.5.36"));
        assert!(is_behind("0.5.35-rc1", "0.5.36"));
        assert!(!is_behind("0.5.36+build.7", "0.5.36"));
        // Missing minor/patch default to 0.
        assert!(is_behind("0.5", "0.5.1"));
        // Unparsable either side → never "behind" (safe default: no warn).
        assert!(!is_behind("garbage", "0.5.36"));
        assert!(!is_behind("0.5.36", "garbage"));
    }

    #[test]
    fn note_latest_release_writes_slot() {
        // The slot is always populated so `/v1/version` reflects the last-seen
        // latest, whether or not this build is behind it.
        let slot = std::sync::RwLock::new(None);
        note_latest_release(&slot, "9999.0.0");
        assert_eq!(slot.read().unwrap().as_deref(), Some("9999.0.0"));
        // A subsequent notice overwrites.
        note_latest_release(&slot, "0.0.1");
        assert_eq!(slot.read().unwrap().as_deref(), Some("0.0.1"));
    }

    #[test]
    fn submit_parses_latest_version_from_collector_body() {
        let cfg = fully_configured();
        // A collector that reports the current-latest release in its 2xx body.
        let spy = SpyTransport::with_body(r#"{"accepted":true,"latest_version":"9999.0.0"}"#);
        let out = submit_usage_ping(&spy, &RateTable::new(), &OutboundConfig::default(), &cfg, &submission()).unwrap();
        assert_eq!(
            out,
            UsageSubmitOutcome::Submitted {
                status: 200,
                latest_version: Some("9999.0.0".to_string())
            }
        );

        // A collector that omits the field (older build) → None, still Submitted.
        let spy_old = SpyTransport::with_body(r#"{"accepted":true}"#);
        let out_old = submit_usage_ping(
            &spy_old,
            &RateTable::new(),
            &OutboundConfig::default(),
            &cfg,
            &submission(),
        )
        .unwrap();
        assert_eq!(
            out_old,
            UsageSubmitOutcome::Submitted {
                status: 200,
                latest_version: None
            }
        );
    }
}
