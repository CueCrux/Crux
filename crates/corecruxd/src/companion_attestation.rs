// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Companion provenance attestation — the daemon-side wiring of `.ccxatt`.
//!
//! The format, the four provenance states and the three modes live in
//! `corecrux-index`'s `ccxatt` module. This module is what makes them happen: the daemon
//! signs the companions it builds itself, and verifies the ones it is handed.
//!
//! ## Why the CE signs its own work
//!
//! The point of attestation is that a *missing* provenance stamp is loud. That
//! only means something if `none` is genuinely anomalous — if every free local
//! ingest tripped the alarm, operators would learn to ignore it and the signal
//! would be worth nothing. So a locally-built companion is signed with this
//! daemon's own device key and resolves to provenance `local`, not `none`.
//! The warning then fires only when someone has handed us companions from
//! nowhere.
//!
//! ## Signing must never be able to fail an ingest
//!
//! Writing companions is the daemon's job; attesting them is a control layered
//! on top. A missing or unreadable passport key means "no attestation written",
//! logged, and the ingest proceeds — never an error. The reverse would let a
//! provenance control take the write path down.

use std::path::Path;

use corecrux_index::{AttestationMode, TrustRoots};

/// Enforcement posture. `off | warn | enforce`, defaulting to `warn`.
pub const MODE_ENV: &str = "CORECRUXD_COMPANION_ATTESTATION";

/// 64-hex Ed25519 public key of a CueCrux platform issuer, mirroring the
/// kid-matched `CORECRUXD_RCX_TRUST_ROOT_PUBKEY` pattern. Paired with
/// [`PLATFORM_TRUST_ROOT_FPR_ENV`], which names the key so a rotation is a
/// config change rather than a flag day.
pub const PLATFORM_TRUST_ROOT_ENV: &str = "CORECRUXD_COMPANION_TRUST_ROOT_PUBKEY";

/// Fingerprint (issuer kid) the platform pubkey is registered under.
pub const PLATFORM_TRUST_ROOT_FPR_ENV: &str = "CORECRUXD_COMPANION_TRUST_ROOT_FPR";

/// Build the policy from config and install it on the index manager.
///
/// Returns the mode in force, for the surfaces that must report it — including
/// `off`, which is reported as `degraded` precisely so that turning the alarm
/// off is visible rather than invisible.
///
/// The daemon's own passport key is registered as the local device root, which
/// is what lets a companion this daemon built resolve to `local` instead of
/// `none`. A platform root is registered when both env vars are set; without it
/// a platform-signed bundle resolves to `Invalid` (unknown producer) rather than
/// silently downgrading to `none` — an unknown signer is not the same as no
/// signer, and must not be treated as one.
pub fn install_policy(index: &mut corecrux_retrieval::IndexManager, data_dir: &Path) -> AttestationMode {
    let mode = std::env::var(MODE_ENV)
        .map(|raw| AttestationMode::from_str_or_default(&raw))
        .unwrap_or_default();

    let mut roots = TrustRoots::new();

    let key_path = crux_session::passport::passport_key_path(data_dir);
    match crux_session::passport::LocalPassportKey::from_existing_path(&key_path) {
        Ok(key) => {
            roots = roots.with_local_device(key.passport_fpr(), key.verifying_key_bytes());
        }
        Err(err) => {
            // Without the local root, this daemon cannot recognise its own work,
            // and every locally-sealed segment reads as `none`. Loud, because in
            // `enforce` it would refuse the operator's own corpus.
            tracing::warn!(
                path = %key_path.display(),
                error = %err,
                "companion-attestation-no-local-root: this daemon cannot verify companions it built itself"
            );
        }
    }

    match (
        std::env::var(PLATFORM_TRUST_ROOT_FPR_ENV),
        std::env::var(PLATFORM_TRUST_ROOT_ENV),
    ) {
        (Ok(fpr), Ok(hex_key)) => match parse_pubkey_hex(&hex_key) {
            Some(pubkey) => {
                roots = roots.with_platform_root(fpr.trim(), pubkey);
            }
            None => tracing::warn!(
                env = PLATFORM_TRUST_ROOT_ENV,
                "companion-attestation-bad-platform-root: expected 64 hex characters; root not registered"
            ),
        },
        (Err(_), Err(_)) => {}
        _ => tracing::warn!(
            "companion-attestation-partial-platform-root: {PLATFORM_TRUST_ROOT_FPR_ENV} and \
             {PLATFORM_TRUST_ROOT_ENV} must be set together; root not registered"
        ),
    }

    index.set_attestation_policy(corecrux_retrieval::AttestationPolicy::new(mode, roots));
    tracing::info!(mode = ?mode, "companion-attestation-policy-installed");
    mode
}

fn parse_pubkey_hex(raw: &str) -> Option<[u8; 32]> {
    let raw = raw.trim();
    if raw.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(raw.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// Surface 1 of 4 — the startup summary.
///
/// A `WARN` per segment scrolls past on a long boot, so the count is restated
/// once at `ERROR` level. `off` reports itself, because an operator who inherits
/// a daemon should be able to see that the check was disabled.
pub fn log_startup_summary(index: &corecrux_retrieval::IndexManager, mode: AttestationMode) {
    let counts = index.provenance_counts();
    let unattested = counts.get("none").copied().unwrap_or(0);
    let invalid = counts.get("invalid").copied().unwrap_or(0);
    let refused = index.refused_segments().len();

    tracing::info!(
        mode = ?mode,
        platform = counts.get("platform").copied().unwrap_or(0),
        local = counts.get("local").copied().unwrap_or(0),
        none = unattested,
        invalid,
        refused,
        "companion-provenance-summary"
    );

    if invalid > 0 {
        tracing::error!(
            invalid,
            "companion-provenance-INVALID: segments whose companions do not match their signed \
             digests were refused their lanes in every mode; they remain discoverable and erasable"
        );
    }
    if unattested > 0 {
        tracing::error!(
            unattested,
            mode = ?mode,
            "companion-provenance-UNATTESTED: segments carry no .ccxatt; in `warn` they are served \
             anyway, in `enforce` they are not"
        );
    }
    if matches!(mode, AttestationMode::Off) {
        tracing::error!(
            "companion-provenance-OFF: companion attestation is disabled; missing provenance will \
             not be reported. This daemon is running degraded by configuration."
        );
    }
}

/// Identity of the segment being attested — the fields the signed body binds.
pub struct SealedSegmentRef<'a> {
    pub shard_id: u32,
    pub segment_seq: u64,
    /// Hex segment id, matching the `.ccxseg` filename stem.
    pub segment_id_hex: &'a str,
    pub tenant_id: &'a str,
    /// Unix seconds. Passed in rather than read here so the signing path has no
    /// clock of its own.
    pub issued_at: u64,
}

/// Self-sign the companions of a segment this daemon just sealed.
///
/// The signing, enumeration and atomic write live in
/// [`corecrux_index::write_local_attestation`], shared with
/// `corecruxctl attest-companions`. What is daemon-specific is here: reading the
/// passport key, and refusing to let any of it fail an ingest.
///
/// The passport key is read, never minted. `LocalPassportKey::from_data_dir`
/// would create one on a miss, and quietly generating a signing identity as a
/// side effect of an ingest is not a thing this path should be able to do.
pub fn write_local_attestation(
    data_dir: &Path,
    segments_dir: &Path,
    stem: &str,
    segment: SealedSegmentRef<'_>,
) -> Option<usize> {
    let key_path = crux_session::passport::passport_key_path(data_dir);
    let key = match crux_session::passport::LocalPassportKey::from_existing_path(&key_path) {
        Ok(key) => key,
        Err(err) => {
            tracing::warn!(
                segment_seq = segment.segment_seq,
                path = %key_path.display(),
                error = %err,
                "companion-attestation-skipped: no readable passport key, segment sealed without a \
                 provenance stamp (it will load as `none`)"
            );
            return None;
        }
    };

    let request = corecrux_index::LocalAttestationRequest {
        shard_id: segment.shard_id,
        segment_seq: segment.segment_seq,
        segment_id_hex: segment.segment_id_hex,
        tenant_id: Some(segment.tenant_id),
        issued_at: segment.issued_at,
        producer_fpr: key.passport_fpr(),
        builder_commit: option_env!("CORECRUX_GIT_SHA").unwrap_or("unknown"),
    };

    match corecrux_index::write_local_attestation(segments_dir, stem, &request, key.delegation_signing_key()) {
        Ok(Some(covered)) => {
            tracing::info!(
                segment_seq = segment.segment_seq,
                covered,
                producer_fpr = %key.passport_fpr(),
                "companion-attestation-written"
            );
            Some(covered)
        }
        Ok(None) => {
            // A fact-only segment legitimately has no companions to cover.
            tracing::debug!(
                segment_seq = segment.segment_seq,
                "companion-attestation-skipped: no companions to cover"
            );
            None
        }
        Err(err) => {
            tracing::warn!(segment_seq = segment.segment_seq, error = %err, "companion-attestation-write-failed");
            None
        }
    }
}
