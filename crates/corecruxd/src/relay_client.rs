// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Outbound relay client — the daemon's half of the relay handshake (ExecPlan
//! `crux-hosted-relay-gateway-2026-07-30`, M4b; contract v1 §§3, 4, 6, 11).
//!
//! This is the **first WebSocket anywhere in this tree**. It dials *out* only:
//! the whole point of the relay is that a customer runs a daemon with no
//! inbound port, no DNS record and no certificate.
//!
//! # What is here, and what is deliberately not
//!
//! The protocol decisions are pure functions with the async transport kept to a
//! thin shell around them, because the parts that can be wrong in a dangerous
//! way — what gets signed, and whether a refusal is retryable — are exactly the
//! parts a socket makes hard to test. [`build_attach`] and [`retry_class`] are
//! total, synchronous, and carry the contract's tables as code.
//!
//! # Challenge-first is not a nicety
//!
//! The relay issues the nonce ([`ChallengeFrame`]), so the daemon **cannot**
//! precompute a proof. [`build_attach`] therefore takes a [`ChallengeFrame`] as
//! a required argument — there is no way to obtain an [`AttachFrame`] without
//! one in hand, so "offer the token before the challenge" is not an ordering
//! mistake the caller can make. A client that could do it would be relying on
//! the relay to reject it.
//!
//! # The retry column is the anti-storm mechanism
//!
//! Contract §11 maps every refusal to a retry class, and most of them are
//! [`RetryClass::Never`]. That is the mechanism behind M4's "no reconnect storm
//! under sustained outage" gate: a token the relay will never accept — wrong
//! trust root, revoked device, unentitled tier — must stop the client, not
//! slow it down. Treating a terminal refusal as slow-retryable turns one
//! misconfigured daemon into sustained load on the relay and a log the operator
//! cannot read. An unknown close code is [`RetryClass::Never`] for the same
//! reason: a relay that grew a refusal this build does not understand is the
//! last thing that should be hammered.
//!
//! # Never log the token or the proof
//!
//! Contract §11 states it and it is enforced structurally here: [`AttachFrame`]
//! has a hand-written [`std::fmt::Debug`] that redacts `token_b64` and
//! `proof_sig`, so the obvious `tracing::debug!(?frame)` cannot leak a bearer
//! credential.
//!
//! # Known gap, named in the contract rather than discovered here
//!
//! The frozen feature set has **no `CONNECT`-proxy or SOCKS support**. A
//! corporate egress proxy defeats the no-inbound-port story. The mitigation
//! needs no crate change — dial `CONNECT` manually and hand the stream to
//! `client_async_tls_with_config` — but it is not implemented here, and
//! [`RelayDialError::ProxyUnsupported`] exists so the failure names itself
//! instead of surfacing as a generic connect error.

// The dial loop that consumes this module is M5's, because there is nothing to
// dial until the relay service exists (`relay.cuecrux.com` resolves; nothing
// serves it). Shipping the protocol half now is deliberate: the handshake is
// what has to be *right*, and it is provable today against the real verifier
// — `the_relay_accepts_a_daemon_built_attach` runs the relay's own F3 over a
// daemon-built frame. Deferring it until a socket existed would mean writing
// the security-critical part under schedule pressure, with the transport
// already sunk.
#![allow(dead_code)]

use std::time::Duration;

use rcx_capability_token::{
    presentation_proof_message, AttenuationContext, DataEgressClass, DelegationAudience, RcxCapabilityToken,
    RCX_RELAY_BACKEND_ID, RCX_RELAY_SESSION_CAPABILITY,
};
use serde::{Deserialize, Serialize};

use crate::relay_device::DeviceIdentity;

/// WebSocket subprotocol offered at upgrade (§4 F0).
pub const RELAY_SUBPROTOCOL: &str = "crux.relay.1";

/// The only `relay_protocol` this build speaks (§2).
pub const RELAY_PROTOCOL_VERSION: u32 = 1;

/// Attestation the relay asserts after the PoP check (§6).
pub const RELAY_PASSPORT_ATTESTATION: &str = "passport_bound";

/// Cap on the base64 token in `attach`, matching the sync boundary's
/// `MAX_PEER_TOKEN_HEADER_BYTES` (§4 F2). Enforced client-side so an oversize
/// token fails locally rather than as a `4400 malformed_attach` round trip.
pub const MAX_ATTACH_TOKEN_BYTES: usize = 16 * 1024;

/// Nonce length the relay issues (§4 F1). A challenge carrying anything else is
/// refused before any signing happens.
pub const RELAY_NONCE_BYTES: usize = 32;

// ── frames (§4) ─────────────────────────────────────────────────────────────

/// F1 `challenge` — relay → daemon, first frame, unconditional.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ChallengeFrame {
    pub relay_protocol: u32,
    /// 32 bytes, hex.
    pub nonce: String,
    pub nonce_ttl_seconds: u64,
    pub relay_instance_id: String,
    pub server_time_unix: u64,
}

/// F2 `attach` — daemon → relay.
///
/// `Debug` is hand-written: `token_b64` is a bearer credential and `proof_sig`
/// is the possession proof for it. See the module note.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct AttachFrame {
    #[serde(rename = "type")]
    pub frame_type: &'static str,
    pub relay_protocol: u32,
    pub token_b64: String,
    /// 32 bytes, hex — must equal `envelope.delegate_public_key` or the relay
    /// answers `DelegateMismatch`.
    pub device_public_key: String,
    /// Echo of the challenge nonce, verbatim.
    pub nonce: String,
    /// 64 bytes, hex.
    pub proof_sig: String,
    pub daemon_instance_id: Option<String>,
    pub daemon_version: String,
    pub capabilities_schema_version: u32,
}

impl std::fmt::Debug for AttachFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Every field is listed: the two credentials are replaced rather than
        // dropped, so a reader can see they exist and see that they are not
        // being printed. A silently omitted field looks like an oversight.
        f.debug_struct("AttachFrame")
            .field("frame_type", &self.frame_type)
            .field("relay_protocol", &self.relay_protocol)
            .field("token_b64", &"<redacted>")
            .field("device_public_key", &self.device_public_key)
            .field("nonce", &self.nonce)
            .field("proof_sig", &"<redacted>")
            .field("daemon_instance_id", &self.daemon_instance_id)
            .field("daemon_version", &self.daemon_version)
            .field("capabilities_schema_version", &self.capabilities_schema_version)
            .finish()
    }
}

/// F4 `attached` — relay → daemon. The three identity fields come from the
/// relay's `VerifiedAttenuation`, never from anything the daemon asserted.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct AttachedFrame {
    pub session_id: String,
    pub tenant_id: String,
    pub actor_fpr: String,
    pub delegated_by: String,
    pub delegation_id: String,
    pub heartbeat_interval_seconds: u64,
    pub max_frame_bytes: usize,
}

// ── the frozen session context (§6) ─────────────────────────────────────────

/// The session-grant tuple both sides compute independently.
///
/// It is **not a wire field** (§5): the daemon signs over it and the relay
/// rebuilds it, so a disagreement shows up as a failed proof rather than as
/// something either side can assert. That is why this is one function and not
/// two call sites — the byte-identical requirement is the whole point.
///
/// `data_egress_classes` is `["text"]`, deliberately **not** sync's `&[]`
/// (contract §6, naming `sync.rs`): for a relayed console, egress *is* the
/// point, so declaring none would sign a claim that is false.
fn relay_context<'a>(tenant_id: &'a str, attestations: &'a [&'a str]) -> AttenuationContext<'a> {
    const RELAY_EGRESS: &[DataEgressClass] = &[DataEgressClass::Text];
    AttenuationContext {
        audience: DelegationAudience::CruxRelay,
        tenant_id,
        backend_id: RCX_RELAY_BACKEND_ID,
        capability: RCX_RELAY_SESSION_CAPABILITY,
        data_egress_classes: RELAY_EGRESS,
        present_attestations: attestations,
    }
}

// ── attach construction ─────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AttachError {
    #[error("relay speaks protocol {theirs}; this build speaks {ours}")]
    ProtocolMismatch { ours: u32, theirs: u32 },
    #[error("challenge nonce is not {RELAY_NONCE_BYTES} bytes of hex")]
    BadNonce,
    #[error("token is {size} bytes encoded, over the {MAX_ATTACH_TOKEN_BYTES} byte cap")]
    TokenTooLarge { size: usize },
    #[error("this token carries no delegation envelope; mint one with relay_device::attenuate_for_relay first")]
    NotAttenuated,
    #[error("the envelope delegates to a different key than this daemon's device identity")]
    DeviceMismatch,
}

/// Build the `attach` frame for a received challenge.
///
/// Pure: no clock, no socket, no randomness. Everything that varies comes from
/// `challenge`, so the frame this produces for a given (token, device,
/// challenge) is reproducible — which is what makes the proof testable against
/// the verifier rather than merely against itself.
///
/// # Errors
/// See [`AttachError`]. Every variant is a refusal to sign, never a degraded
/// frame: a proof over the wrong context or an unattenuated token would be
/// refused by the relay anyway, and failing here says why.
pub fn build_attach(
    token: &RcxCapabilityToken,
    device: &DeviceIdentity,
    challenge: &ChallengeFrame,
    daemon_version: &str,
    capabilities_schema_version: u32,
) -> Result<AttachFrame, AttachError> {
    if challenge.relay_protocol != RELAY_PROTOCOL_VERSION {
        return Err(AttachError::ProtocolMismatch {
            ours: RELAY_PROTOCOL_VERSION,
            theirs: challenge.relay_protocol,
        });
    }
    let nonce = decode_hex_vec(&challenge.nonce).ok_or(AttachError::BadNonce)?;
    if nonce.len() != RELAY_NONCE_BYTES {
        return Err(AttachError::BadNonce);
    }

    // An unattenuated token would be signed over happily and refused by the
    // relay as `DelegationNotPermitted`, which reads as a relay problem. Catch
    // it here, where the fix (mint the envelope) is obvious.
    let envelope = token.delegation_envelope.as_ref().ok_or(AttachError::NotAttenuated)?;
    // The proof key must equal `envelope.delegate_public_key` (§5) — presenting
    // a proof from a key the envelope does not name is `DelegateMismatch`.
    // Checking locally turns a remote 4401 into a local, nameable error.
    if envelope.delegate_public_key != device.public_key() {
        return Err(AttachError::DeviceMismatch);
    }

    let token_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        token.to_canonical_json().as_bytes(),
    );
    if token_b64.len() > MAX_ATTACH_TOKEN_BYTES {
        return Err(AttachError::TokenTooLarge { size: token_b64.len() });
    }

    let attestations = [RELAY_PASSPORT_ATTESTATION];
    let message = presentation_proof_message(
        token,
        relay_context(&token.tenant_scope.tenant_id, &attestations),
        &nonce,
    );
    let proof_sig = device.sign(&message);

    Ok(AttachFrame {
        frame_type: "attach",
        relay_protocol: RELAY_PROTOCOL_VERSION,
        token_b64,
        device_public_key: hex_encode(&device.public_key()),
        // Echo verbatim rather than re-encoding the decoded bytes: the relay
        // matches on what it issued.
        nonce: challenge.nonce.clone(),
        proof_sig: hex_encode(&proof_sig),
        daemon_instance_id: token.subject.daemon_instance_id.clone(),
        daemon_version: daemon_version.to_string(),
        capabilities_schema_version,
    })
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn decode_hex_vec(value: &str) -> Option<Vec<u8>> {
    if value.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

// ── close codes and the retry column (§11) ──────────────────────────────────

/// What the daemon may do after a close. See the module note on why `Never`
/// dominates and why unknown codes land there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryClass {
    /// Terminal until an operator action or a re-mint changes something.
    Never,
    /// One immediate re-dial, then backoff. Only for a nonce that raced its TTL.
    ImmediateOnceThenBackoff,
    /// Exponential backoff.
    Backoff,
    /// Exponential backoff plus jitter — the relay is telling many daemons the
    /// same thing at once, so unjittered backoff would resynchronise them into
    /// the thundering herd the backoff exists to prevent.
    BackoffJitter,
}

impl RetryClass {
    /// Whether the client should dial again at all.
    #[must_use]
    pub fn is_retryable(self) -> bool {
        !matches!(self, Self::Never)
    }
}

/// Map a close code to its retry class, per the frozen §11 table.
///
/// Keyed on the numeric code, not the reason string: the reason is for
/// correlating logs with the sync boundary's `delegation_rejection_class`
/// vocabulary, and keying behaviour on a human-readable string would make a
/// typo a security change.
#[must_use]
pub fn retry_class(close_code: u16) -> RetryClass {
    match close_code {
        // 4408 attach_timeout, 4503 revocation_unavailable.
        4408 | 4503 => RetryClass::Backoff,
        // 4429 tenant_quota_exceeded, 1001 relay_draining, 1011 relay_error —
        // all fleet-wide conditions, so all jittered.
        4429 | 1001 | 1011 => RetryClass::BackoffJitter,
        // 4401 covers both a raced nonce (retryable once) and hard token /
        // proof refusals (terminal). The code alone cannot separate them, and
        // the safe collapse is the *pessimistic* one everywhere except the
        // nonce case, which is disambiguated by `retry_class_for` below.
        4401 => RetryClass::Never,
        // 4426 protocol, 4400 malformed, 4409 duplicate attach, 4403 policy
        // denials, 4402 tier — every one needs a change on this side.
        _ => RetryClass::Never,
    }
}

/// Retry class refined by the reason string, where the code alone is ambiguous.
///
/// Only `4401` is ambiguous: `peer_nonce_rejected` means this daemon raced the
/// nonce TTL and one immediate re-dial is correct, while every other 4401 is a
/// token or proof the relay will refuse identically forever. Defaulting to the
/// terminal reading and *promoting* the one known-retryable reason keeps an
/// unrecognised 4401 from becoming a retry loop.
#[must_use]
pub fn retry_class_for(close_code: u16, reason: &str) -> RetryClass {
    if close_code == 4401 && reason == "peer_nonce_rejected" {
        return RetryClass::ImmediateOnceThenBackoff;
    }
    retry_class(close_code)
}

// ── backoff ─────────────────────────────────────────────────────────────────

/// Bounded exponential backoff.
///
/// Deterministic given an attempt number and a jitter fraction, so the schedule
/// is asserted in tests rather than observed in production.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackoffPolicy {
    pub base: Duration,
    pub max: Duration,
}

impl Default for BackoffPolicy {
    fn default() -> Self {
        Self {
            base: Duration::from_secs(1),
            max: Duration::from_secs(300),
        }
    }
}

impl BackoffPolicy {
    /// Unjittered delay before `attempt` (0-based), capped at
    /// [`BackoffPolicy::max`]. Used for [`RetryClass::Backoff`].
    #[must_use]
    pub fn delay(self, attempt: u32) -> Duration {
        // Saturating shift: `attempt` is unbounded over a long outage, and
        // `1 << 64` is undefined-behaviour-adjacent nonsense rather than "a
        // very long wait". Clamped well below the shift width, then again to
        // `max`, so the schedule is monotonic and finite for every input.
        let factor = 1u32.checked_shl(attempt.min(31)).unwrap_or(u32::MAX);
        self.base.saturating_mul(factor).min(self.max)
    }

    /// Delay for [`RetryClass::BackoffJitter`], spread over `[d/2, d]`.
    ///
    /// `random` is a caller-supplied uniform in `[0, 1)`; drawing it here would
    /// make the schedule untestable, which is how jitter bugs survive. The
    /// spread is *downward* from the unjittered delay so jitter can never
    /// lengthen a wait beyond the policy's cap.
    ///
    /// Jitter matters only for the fleet-wide close codes (quota, drain, relay
    /// error): those tell many daemons the same thing at the same instant, and
    /// unjittered backoff would resynchronise them into precisely the herd the
    /// backoff exists to break up.
    #[must_use]
    pub fn delay_jittered(self, attempt: u32, random: f64) -> Duration {
        let base = self.delay(attempt);
        let r = if random.is_finite() {
            random.clamp(0.0, 1.0)
        } else {
            0.0
        };
        base.mul_f64(0.5 + 0.5 * r)
    }
}

// ── dial ────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum RelayDialError {
    #[error("relay endpoint must be wss:// (a plaintext relay carries a bearer token in clear)")]
    NotSecure,
    #[error("an HTTP proxy is configured ({var}), and this build has no CONNECT support — see contract v1 §3")]
    ProxyUnsupported { var: &'static str },
    #[error("websocket transport failure: {0}")]
    Transport(String),
    #[error("relay closed before challenge: {code} {reason}")]
    ClosedBeforeChallenge { code: u16, reason: String },
    #[error("first frame was not a challenge")]
    ChallengeExpected,
    #[error(transparent)]
    Attach(#[from] AttachError),
}

/// Environment variables that indicate an egress proxy this build cannot use.
const PROXY_ENV_VARS: &[&str] = &["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"];

/// Refuse to dial when a proxy is configured, naming the variable.
///
/// Without this the connection simply fails to reach the relay and the operator
/// sees a timeout — the single most expensive way to learn that the frozen
/// feature set has no `CONNECT` support. This converts a support ticket into a
/// log line.
///
/// # Errors
/// Returns [`RelayDialError::ProxyUnsupported`] naming the first proxy variable
/// found set and non-empty.
pub fn refuse_if_proxied() -> Result<(), RelayDialError> {
    for var in PROXY_ENV_VARS {
        if std::env::var(var).is_ok_and(|value| !value.trim().is_empty()) {
            return Err(RelayDialError::ProxyUnsupported { var });
        }
    }
    Ok(())
}

/// Reject a relay endpoint that is not `wss://`.
///
/// The `attach` frame carries a bearer token and its possession proof, so a
/// plaintext dial hands both to anyone on the path. Mirrors the same rule in
/// `rcx_revocation::HttpCrlTransport` for the CRL fetch.
///
/// # Errors
/// Returns [`RelayDialError::NotSecure`] for any non-`wss://` endpoint.
pub fn require_secure_endpoint(endpoint_url: &str) -> Result<(), RelayDialError> {
    if endpoint_url.starts_with("wss://") {
        Ok(())
    } else {
        Err(RelayDialError::NotSecure)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::relay_device::attenuate_for_relay;
    use crate::relay_device::test_support::{hosted, issuer, passport, NOW};
    use crux_session::passport::LocalPassportKey;
    use rcx_capability_token::{verify_token_attenuated, AttenuatedOutcome, PresentationProof};

    // ── retry column parity with contract §11 ────────────────────────────────

    #[test]
    fn every_terminal_close_code_stops_the_client() {
        // The anti-storm gate. A token the relay will refuse identically
        // forever must stop the client, not slow it down: retrying turns one
        // misconfigured daemon into sustained relay load.
        for code in [4426u16, 4400, 4409, 4403, 4402] {
            assert_eq!(retry_class(code), RetryClass::Never, "close {code} must be terminal");
            assert!(!retry_class(code).is_retryable(), "close {code}");
        }
    }

    #[test]
    fn transient_conditions_back_off_and_fleet_wide_ones_also_jitter() {
        // attach_timeout and revocation_unavailable are about this connection.
        assert_eq!(retry_class(4408), RetryClass::Backoff);
        assert_eq!(retry_class(4503), RetryClass::Backoff);
        // Quota, drain and relay error hit many daemons at once, so unjittered
        // backoff would resynchronise them into the herd it exists to prevent.
        for code in [4429u16, 1001, 1011] {
            assert_eq!(retry_class(code), RetryClass::BackoffJitter, "close {code}");
        }
    }

    #[test]
    fn a_raced_nonce_retries_once_but_every_other_4401_is_terminal() {
        // 4401 is the one ambiguous code: a nonce that lost to its TTL is worth
        // exactly one immediate re-dial; a rejected token or proof is not.
        assert_eq!(
            retry_class_for(4401, "peer_nonce_rejected"),
            RetryClass::ImmediateOnceThenBackoff
        );
        for reason in [
            "peer_token_rejected",
            "peer_delegate_mismatch",
            "peer_possession_rejected",
            "peer_delegation_signature_rejected",
        ] {
            assert_eq!(retry_class_for(4401, reason), RetryClass::Never, "{reason}");
        }
    }

    #[test]
    fn an_unrecognised_close_code_is_terminal_rather_than_retried() {
        // A relay that grew a refusal this build does not understand is the
        // last thing that should be hammered.
        for code in [4999u16, 1006, 3000, 0] {
            assert_eq!(retry_class(code), RetryClass::Never, "close {code}");
        }
        assert_eq!(retry_class_for(4999, "peer_nonce_rejected"), RetryClass::Never);
    }

    // ── backoff ──────────────────────────────────────────────────────────────

    #[test]
    fn backoff_grows_then_caps_and_never_overflows() {
        let policy = BackoffPolicy::default();
        assert_eq!(policy.delay(0), Duration::from_secs(1));
        assert_eq!(policy.delay(3), Duration::from_secs(8));
        assert_eq!(policy.delay(10), policy.max, "capped");
        // A sustained outage drives `attempt` arbitrarily high; a naive
        // `1 << attempt` is nonsense rather than "a very long wait".
        assert_eq!(policy.delay(u32::MAX), policy.max);
        assert_eq!(policy.delay(31), policy.max);
    }

    #[test]
    fn jitter_spreads_downward_and_never_exceeds_the_cap() {
        // Downward-only: jitter must not lengthen a wait past the policy cap,
        // or the cap stops being one.
        let policy = BackoffPolicy::default();
        let plain = policy.delay(2);
        assert_eq!(policy.delay_jittered(2, 1.0), plain, "r=1 is the unjittered delay");
        assert_eq!(policy.delay_jittered(2, 0.0), plain / 2, "r=0 is half");
        for r in [0.0, 0.25, 0.5, 0.75, 1.0] {
            let d = policy.delay_jittered(2, r);
            assert!(d <= plain && d >= plain / 2, "r={r} gave {d:?}");
        }
        // A non-finite random must not produce a NaN duration (which panics in
        // `mul_f64`), so it degrades to the shortest delay in the band.
        assert_eq!(policy.delay_jittered(2, f64::NAN), plain / 2);
        assert_eq!(policy.delay_jittered(2, -5.0), plain / 2);
    }

    // ── endpoint and proxy guards ────────────────────────────────────────────

    #[test]
    fn a_plaintext_relay_endpoint_is_refused() {
        // `attach` carries a bearer token and its possession proof.
        assert!(require_secure_endpoint("wss://relay.cuecrux.com").is_ok());
        for bad in [
            "ws://relay.cuecrux.com",
            "https://relay.cuecrux.com",
            "relay.cuecrux.com",
        ] {
            assert!(
                matches!(require_secure_endpoint(bad), Err(RelayDialError::NotSecure)),
                "{bad} must be refused"
            );
        }
    }

    // ── attach construction ──────────────────────────────────────────────────

    fn challenge(nonce_hex: &str, protocol: u32) -> ChallengeFrame {
        ChallengeFrame {
            relay_protocol: protocol,
            nonce: nonce_hex.to_string(),
            nonce_ttl_seconds: 120,
            relay_instance_id: "relay-1".to_string(),
            server_time_unix: 1_800_000_000,
        }
    }

    const NONCE_HEX: &str = "aa";

    fn good_nonce() -> String {
        NONCE_HEX.repeat(RELAY_NONCE_BYTES)
    }

    #[test]
    fn a_protocol_mismatch_refuses_before_anything_is_signed() {
        let (device, token) = relay_token();
        let err = build_attach(&token, &device, &challenge(&good_nonce(), 2), "0.5.55", 1)
            .expect_err("protocol 2 must be refused");
        assert_eq!(
            err,
            AttachError::ProtocolMismatch {
                ours: RELAY_PROTOCOL_VERSION,
                theirs: 2
            }
        );
    }

    #[test]
    fn a_malformed_or_wrong_length_nonce_is_refused() {
        let (device, token) = relay_token();
        for bad in ["", "zz", &"ab".repeat(31), &"ab".repeat(33), "abc"] {
            let err = build_attach(&token, &device, &challenge(bad, 1), "0.5.55", 1)
                .expect_err("nonce {bad} must be refused");
            assert_eq!(err, AttachError::BadNonce, "nonce {bad:?}");
        }
    }

    #[test]
    fn the_attach_frame_redacts_the_token_and_the_proof_in_debug() {
        // Contract §11 says never log the token or the proof; this makes the
        // obvious `tracing::debug!(?frame)` structurally safe.
        let (device, token) = relay_token();
        let frame = build_attach(&token, &device, &challenge(&good_nonce(), 1), "0.5.55", 1).expect("attach");

        let rendered = format!("{frame:?}");

        assert!(!rendered.contains(&frame.token_b64), "the token must not be printable");
        assert!(!rendered.contains(&frame.proof_sig), "the proof must not be printable");
        assert!(rendered.contains("<redacted>"));
        // The device key is public and is what an operator registers, so it stays.
        assert!(rendered.contains(&frame.device_public_key));
    }

    // ── the gate: what the daemon signs, the relay accepts ───────────────────

    /// Run the relay's side of F3 over a daemon-built `attach`.
    ///
    /// This is the test that matters. Every other assertion here checks that
    /// the client refuses things; only this one shows it *produces* something a
    /// verifier accepts. Without it, a wrong `AttenuationContext` — the wrong
    /// egress class, the wrong audience, sync's `&[]` copied by habit — would
    /// pass every unit test in this file and fail on first contact with a real
    /// relay, which is the single most expensive place to discover it.
    fn relay_verifies(frame: &AttachFrame, token: &RcxCapabilityToken, nonce_hex: &str) -> AttenuatedOutcome {
        let nonce = decode_hex_vec(nonce_hex).expect("nonce");
        let proof = PresentationProof {
            public_key: decode_hex_array32(&frame.device_public_key),
            nonce: &nonce,
            signature: decode_hex_array64(&frame.proof_sig),
        };
        let attestations = [RELAY_PASSPORT_ATTESTATION];
        verify_token_attenuated(
            token,
            &issuer().verifying_key().to_bytes(),
            NOW,
            &proof,
            &nonce,
            relay_context(&token.tenant_scope.tenant_id, &attestations),
            |_| false,
        )
    }

    fn decode_hex_array32(value: &str) -> [u8; 32] {
        decode_hex_vec(value).expect("hex").try_into().expect("32 bytes")
    }

    fn decode_hex_array64(value: &str) -> [u8; 64] {
        let v = decode_hex_vec(value).expect("hex");
        let mut out = [0u8; 64];
        out.copy_from_slice(&v);
        out
    }

    #[test]
    fn the_relay_accepts_a_daemon_built_attach() {
        let (device, token) = relay_token();
        let nonce = good_nonce();

        let frame = build_attach(&token, &device, &challenge(&nonce, 1), "0.5.55", 1).expect("attach");

        match relay_verifies(&frame, &token, &nonce) {
            AttenuatedOutcome::Verified(v) => {
                // These are the three identity fields the relay echoes in F4
                // `attached`, and they come from the verifier — never from
                // anything the daemon asserted in the frame. The session is
                // attributed to the DEVICE, delegated by the passport.
                assert_eq!(v.actor_fpr, device.fpr(), "the session is the device's");
                assert_eq!(
                    v.delegated_by.as_deref(),
                    Some(token.subject.passport_fpr.as_str()),
                    "delegated by the account passport"
                );
                assert_eq!(v.delegation_id.as_deref(), Some("d-1"));
            }
            other => panic!("relay must accept a well-formed attach, got {other:?}"),
        }
    }

    #[test]
    fn a_proof_captured_for_one_nonce_does_not_satisfy_another() {
        // The replay property the challenge-first ordering exists to provide.
        let (device, token) = relay_token();
        let frame = build_attach(&token, &device, &challenge(&good_nonce(), 1), "0.5.55", 1).expect("attach");

        let other_nonce = "bb".repeat(RELAY_NONCE_BYTES);
        let outcome = relay_verifies(&frame, &token, &other_nonce);

        assert!(
            matches!(outcome, AttenuatedOutcome::BadPossessionProof),
            "a replayed proof must be refused, got {outcome:?}"
        );
    }

    #[test]
    fn a_proof_from_a_key_the_envelope_does_not_name_is_refused() {
        // Belt and braces against `build_attach`'s own DeviceMismatch check:
        // that one is a local convenience, this is what the relay enforces.
        let (device, token) = relay_token();
        let nonce = good_nonce();
        let mut frame = build_attach(&token, &device, &challenge(&nonce, 1), "0.5.55", 1).expect("attach");
        let impostor = DeviceIdentity::derive(&LocalPassportKey::from_seed([42u8; 32]).expect("seed"));
        frame.device_public_key = hex_encode(&impostor.public_key());

        let outcome = relay_verifies(&frame, &token, &nonce);

        // BadPossessionProof, NOT DelegateMismatch — the verifier checks the
        // signature against the presented key before comparing that key to the
        // envelope. That ordering is the safer one and worth pinning: it means
        // an attacker cannot swap in candidate public keys to learn which one
        // the envelope names, because every attempt fails at the signature
        // first and the two refusals are indistinguishable from outside.
        assert!(
            matches!(outcome, AttenuatedOutcome::BadPossessionProof),
            "got {outcome:?}"
        );
    }

    #[test]
    fn a_revoked_device_is_refused_even_with_a_perfect_proof() {
        // Where M2's CRL feeds in: the proof is valid and the envelope correct,
        // and the session must still be refused.
        let (device, token) = relay_token();
        let nonce = good_nonce();
        let frame = build_attach(&token, &device, &challenge(&nonce, 1), "0.5.55", 1).expect("attach");
        let nonce_bytes = decode_hex_vec(&nonce).expect("nonce");
        let attestations = [RELAY_PASSPORT_ATTESTATION];

        let outcome = verify_token_attenuated(
            &token,
            &issuer().verifying_key().to_bytes(),
            NOW,
            &PresentationProof {
                public_key: decode_hex_array32(&frame.device_public_key),
                nonce: &nonce_bytes,
                signature: decode_hex_array64(&frame.proof_sig),
            },
            &nonce_bytes,
            relay_context(&token.tenant_scope.tenant_id, &attestations),
            |fpr| fpr == device.fpr(),
        );

        assert!(
            matches!(outcome, AttenuatedOutcome::PrincipalRevoked),
            "got {outcome:?}"
        );
    }

    #[test]
    fn an_unattenuated_token_is_refused_before_it_reaches_the_relay() {
        let passport = passport();
        let device = DeviceIdentity::derive(&passport);
        let grant = hosted(&passport, vec![device.fpr().to_string()], true, 1_900_000_000);

        let err = build_attach(&grant.token, &device, &challenge(&good_nonce(), 1), "0.5.55", 1)
            .expect_err("a base token carries no envelope");

        assert_eq!(err, AttachError::NotAttenuated);
    }

    #[test]
    fn an_envelope_for_a_different_device_is_refused_locally() {
        let passport = passport();
        let device = DeviceIdentity::derive(&passport);
        let other = DeviceIdentity::derive(&LocalPassportKey::from_seed([77u8; 32]).expect("seed"));
        // `allowed_delegate_fprs` must be STRICTLY ASCENDING or the token is
        // structurally invalid (`invalid_delegation_policy`) — canonical order
        // is part of the signed shape, not a presentation detail.
        let mut delegates = vec![device.fpr().to_string(), other.fpr().to_string()];
        delegates.sort();
        let grant = hosted(&passport, delegates, true, 1_900_000_000);
        let token = attenuate_for_relay(&grant, &passport, &other, "d-2", NOW, 900).expect("attenuate");

        let err = build_attach(&token, &device, &challenge(&good_nonce(), 1), "0.5.55", 1)
            .expect_err("this daemon is not the delegate");

        assert_eq!(err, AttachError::DeviceMismatch);
    }

    /// This daemon's device identity plus a relay-attenuated token delegating
    /// to it — the exact pair a real `attach` is built from.
    fn relay_token() -> (DeviceIdentity, RcxCapabilityToken) {
        let passport = passport();
        let device = DeviceIdentity::derive(&passport);
        let grant = hosted(&passport, vec![device.fpr().to_string()], true, 1_900_000_000);
        let token = attenuate_for_relay(&grant, &passport, &device, "d-1", NOW, 900).expect("attenuate");
        (device, token)
    }
}
