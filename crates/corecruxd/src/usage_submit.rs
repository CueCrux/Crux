// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

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
//! [`UsagePingSubmission`] carries ONLY receipt id, body hash, passport
//! fingerprint, event class, timestamp, and the Ed25519 signature envelope —
//! enough for a collector to verify the signature and count distinct
//! passports. It has no field through which fact content, query text, or
//! corpus identity could be expressed.
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
    /// `blake3:<hex>` digest of the canonical receipt body (a hash, not the
    /// body).
    pub body_hash: String,
    /// The daemon's passport fingerprint — the adoption unit the collector
    /// tallies distinct instances by.
    pub passport_fpr: String,
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
    /// The collector accepted the ping with a 2xx status.
    Submitted { status: u16 },
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
    Ok(UsageSubmitOutcome::Submitted { status: resp.status })
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
    tokio::task::spawn_blocking(move || {
        let transport = UreqTransport;
        let outbound = OutboundConfig::from_env();
        match submit_usage_ping(&transport, &rate_table, &outbound, &cfg, &submission) {
            Ok(UsageSubmitOutcome::Submitted { status }) => {
                tracing::info!(target: "usage_submit", status, receipt_id = %submission.receipt_id, "usage ping submitted");
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
    }

    impl SpyTransport {
        fn ok() -> Self {
            Self {
                seen: Arc::new(Mutex::new(Vec::new())),
                status: 200,
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
                body: "{}".to_string(),
            })
        }
    }

    fn submission() -> UsagePingSubmission {
        UsagePingSubmission {
            receipt_id: "r-1".to_string(),
            body_hash: "blake3:deadbeef".to_string(),
            passport_fpr: "fpr_test".to_string(),
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
        assert_eq!(out, UsageSubmitOutcome::Submitted { status: 200 });

        let calls = spy.calls();
        assert_eq!(calls.len(), 1, "exactly one network call when fully configured");
        let (url, body_json) = &calls[0];
        assert_eq!(url, "https://collector.example.com/usage");

        // The wire payload carries ONLY the metadata fields.
        let sent: serde_json::Value = serde_json::from_str(body_json).expect("payload is json");
        let obj = sent.as_object().expect("payload is an object");
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "body_hash",
                "created_at",
                "event_class",
                "passport_fpr",
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

        // Negative: not one content-bearing key rides the wire. (`body_hash`
        // is a hash, not the body; the banned list avoids substrings of the
        // six legitimate keys.)
        for banned in [
            "body_cbor_hex",
            "body_bytes",
            "count",
            "tenant_id",
            "fact_id",
            "entity",
            "entries",
            "query",
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
}
