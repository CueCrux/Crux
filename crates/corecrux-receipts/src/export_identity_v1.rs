// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Signed-export identity pinning (play03 defect **D2**).
//!
//! Every signed-export verifier in this workspace checks the signature
//! against the public key that travels *inside* the artifact it is verifying.
//! That proves the artifact is internally consistent — it does not prove who
//! made it. An attacker who edits a bundle and re-signs it with a key they
//! generated a second ago produces an artifact that passes every check and
//! reports a green `ok`. The verifier is a self-attestation, not a proof of
//! custody.
//!
//! The remedy here is deliberately not a PKI (see the plan's Non-goals): it is
//! a **caller-supplied expected key**. The caller who has some out-of-band
//! reason to know which issuer should have signed (an operator who recorded the
//! daemon's export key, a customer handed a bundle plus a fingerprint) supplies
//! it, and the verifier refuses a green verdict when the embedded signer is not
//! that key. This mirrors the pattern already proven on the C2PA verifier
//! (`corecruxctl output-verify`, `CRUX_C2PA_VERIFY_PUBLIC_KEY_HEX`).
//!
//! Because most callers have no pin today, the interim behaviour is a
//! **relabel, not a refusal**: an unpinned pass keeps `ok = true` but is
//! labelled [`EXPORT_TRUST_UNPINNED_LABEL`] so nobody reads it as proof of
//! origin. [`export_identity_posture_v1`] exposes that same distinction as a
//! process-level signal for callers who report a custody *posture* rather than
//! verify one artifact.

use serde::Serialize;
use thiserror::Error;

/// Environment variable carrying the expected **audit-export signer** public
/// key as 64 hex characters — the key `resolve_audit_export_signing_key`
/// resolves. Consulted as the fallback pin by audit-bundle verifiers that take
/// no explicit pin argument, mirroring `CRUX_C2PA_VERIFY_PUBLIC_KEY_HEX` on the
/// C2PA verifier. Unset means "no pin available", which is a real answer
/// (`Unpinned`), not an error.
pub const EXPORT_VERIFY_PUBLIC_KEY_ENV: &str = "CRUX_EXPORT_VERIFY_PUBLIC_KEY_HEX";

/// Environment variable carrying the expected **daemon passport** public key
/// for `corecruxctl context verify`.
///
/// Deliberately a second variable: a context-export bundle carries two
/// independent signers — the passport signs the custody manifest and the
/// cruxpack, while the audit bundle nested inside is signed by the audit-export
/// key of [`EXPORT_VERIFY_PUBLIC_KEY_ENV`]. One variable pinning both would be
/// wrong for whichever identity it was not set from.
pub const CONTEXT_VERIFY_PASSPORT_KEY_ENV: &str = "CRUX_CONTEXT_VERIFY_PASSPORT_HEX";

/// Verdict label when the embedded signer matched a supplied pin.
pub const EXPORT_TRUST_PINNED_LABEL: &str = "signer pinned — the embedded key matches the expected identity";

/// Verdict label for a pass with no pin available. The artifact is internally
/// consistent; nothing about its *origin* has been proven.
pub const EXPORT_TRUST_UNPINNED_LABEL: &str = "internally consistent, UNPINNED — trust unproven";

/// Verdict label when a pin was supplied and the embedded signer is a
/// different key. Always accompanies `ok = false`.
pub const EXPORT_TRUST_MISMATCH_LABEL: &str = "REJECTED — the embedded signer is not the pinned identity";

/// Failure to interpret a caller- or environment-supplied expected signer.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ExpectedSignerError {
    #[error("expected signer key must be 64 hex characters (32-byte Ed25519 public key), got {0}")]
    BadLength(usize),
    #[error("expected signer key is not valid hex")]
    BadHex,
}

/// A pinned issuer identity: the raw 32-byte Ed25519 public key the caller
/// expects to have signed the artifact.
///
/// Deliberately holds the key bytes and not a fingerprint — every signed-export
/// artifact in this workspace embeds the full public key, so comparing the key
/// itself avoids introducing a second, weaker identifier to get wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpectedSignerV1([u8; 32]);

impl ExpectedSignerV1 {
    /// Parse 64 hex characters (case-insensitive, surrounding whitespace
    /// trimmed) into a pin.
    pub fn from_hex(hex_str: &str) -> Result<Self, ExpectedSignerError> {
        let trimmed = hex_str.trim();
        if trimmed.len() != 64 {
            return Err(ExpectedSignerError::BadLength(trimmed.len()));
        }
        let decoded = hex::decode(trimmed).map_err(|_| ExpectedSignerError::BadHex)?;
        let key: [u8; 32] = decoded.try_into().map_err(|_| ExpectedSignerError::BadHex)?;
        Ok(Self(key))
    }

    /// Read the pin from [`EXPORT_VERIFY_PUBLIC_KEY_ENV`] — the audit-export
    /// signer. See [`Self::from_env_var`] for the semantics.
    pub fn from_env() -> Result<Option<Self>, ExpectedSignerError> {
        Self::from_env_var(EXPORT_VERIFY_PUBLIC_KEY_ENV)
    }

    /// Read the pin from a named environment variable. `Ok(None)` when the
    /// variable is unset or empty; a *set but malformed* value is an error
    /// rather than a silent downgrade to unpinned — an operator who configured
    /// a pin must never be told "verified" on the strength of a typo.
    pub fn from_env_var(name: &str) -> Result<Option<Self>, ExpectedSignerError> {
        match std::env::var(name) {
            Ok(raw) if raw.trim().is_empty() => Ok(None),
            Ok(raw) => Self::from_hex(&raw).map(Some),
            Err(_) => Ok(None),
        }
    }

    /// Raw key bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lower-case hex rendering, the form accepted by [`Self::from_hex`].
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// True when `candidate` is exactly this key. `candidate` is whatever the
    /// artifact embedded, already decoded to raw bytes; a wrong-length input is
    /// never a match.
    pub fn matches_bytes(&self, candidate: &[u8]) -> bool {
        candidate == self.0
    }

    /// True when `candidate_hex` decodes to exactly this key.
    pub fn matches_hex(&self, candidate_hex: &str) -> bool {
        match hex::decode(candidate_hex.trim()) {
            Ok(bytes) => self.matches_bytes(&bytes),
            Err(_) => false,
        }
    }
}

/// Outcome of comparing an artifact's embedded signer against a pin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerPinOutcomeV1 {
    /// A pin was supplied and the embedded signer is that key.
    Pinned,
    /// No pin was available. The artifact may still be internally consistent;
    /// its origin is unproven.
    Unpinned,
    /// A pin was supplied and the embedded signer is a *different* key. This
    /// must force `ok = false` at every verifier that reports it.
    Mismatch,
}

impl SignerPinOutcomeV1 {
    /// Human-readable label a verifier report carries alongside `ok`.
    pub fn label(self) -> &'static str {
        match self {
            Self::Pinned => EXPORT_TRUST_PINNED_LABEL,
            Self::Unpinned => EXPORT_TRUST_UNPINNED_LABEL,
            Self::Mismatch => EXPORT_TRUST_MISMATCH_LABEL,
        }
    }

    /// True only for [`Self::Pinned`] — identity actually proven.
    pub fn is_pinned(self) -> bool {
        matches!(self, Self::Pinned)
    }

    /// True when the pin was supplied and failed. A verifier reporting this
    /// must not report `ok = true`.
    pub fn is_mismatch(self) -> bool {
        matches!(self, Self::Mismatch)
    }
}

/// Compare an artifact's embedded signer key against an optional pin.
pub fn evaluate_signer_pin_v1(expected: Option<&ExpectedSignerV1>, embedded_key: &[u8]) -> SignerPinOutcomeV1 {
    match expected {
        None => SignerPinOutcomeV1::Unpinned,
        Some(pin) if pin.matches_bytes(embedded_key) => SignerPinOutcomeV1::Pinned,
        Some(_) => SignerPinOutcomeV1::Mismatch,
    }
}

/// Whether this process can prove the *origin* of a signed export at all.
///
/// **This is the D2 → D1 contract.** `context_custody_audit` (play03 M3, defect
/// D1) consumes it to decide whether the PROVE pillar may be reported as
/// `strong`: while no export pin is configured, every export this node produces
/// verifies green on its own signature alone, so PROVE must be downgraded and
/// labelled with [`EXPORT_TRUST_UNPINNED_LABEL`] rather than claimed.
///
/// Reads [`EXPORT_VERIFY_PUBLIC_KEY_ENV`], the audit-export signer, because
/// that is the identity behind every bundle the node hands out
/// (`/v1/audit/bundle/verify`, `corecruxctl audit-verify`, `audit_export_bundle`).
/// [`CONTEXT_VERIFY_PASSPORT_KEY_ENV`] pins a different identity on one CLI
/// surface and is deliberately not folded in here.
///
/// A configured-but-malformed pin reads as [`ExportIdentityPostureV1::Unpinned`]
/// — it cannot prove anything, and the honest posture is the weaker one. The
/// per-artifact verifiers surface the parse error instead of swallowing it.
pub fn export_identity_posture_v1() -> ExportIdentityPostureV1 {
    match ExpectedSignerV1::from_env() {
        Ok(Some(_)) => ExportIdentityPostureV1::Pinned,
        Ok(None) | Err(_) => ExportIdentityPostureV1::Unpinned,
    }
}

/// Process-level answer to "can an export from this node be traced to a known
/// issuer?". See [`export_identity_posture_v1`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportIdentityPostureV1 {
    /// An expected signer is configured, so verifiers can refuse an unexpected
    /// issuer.
    Pinned,
    /// No expected signer is configured; export verification is
    /// self-attesting only.
    Unpinned,
}

impl ExportIdentityPostureV1 {
    /// Stable wire token (`"pinned"` / `"unpinned"`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pinned => "pinned",
            Self::Unpinned => "unpinned",
        }
    }

    /// True only when an expected signer is configured.
    pub fn is_pinned(self) -> bool {
        matches!(self, Self::Pinned)
    }

    /// Label describing what a green verdict from this node currently means.
    pub fn label(self) -> &'static str {
        match self {
            Self::Pinned => EXPORT_TRUST_PINNED_LABEL,
            Self::Unpinned => EXPORT_TRUST_UNPINNED_LABEL,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_A: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const KEY_B: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    #[test]
    fn hex_round_trips() {
        let pin = ExpectedSignerV1::from_hex(KEY_A).expect("parse");
        assert_eq!(pin.to_hex(), KEY_A);
        assert_eq!(pin.as_bytes(), &[0x11u8; 32]);
    }

    #[test]
    fn hex_is_case_insensitive_and_whitespace_tolerant() {
        let upper = ExpectedSignerV1::from_hex("  AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111AAAA1111  ")
            .expect("parse");
        let lower = ExpectedSignerV1::from_hex("aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111")
            .expect("parse");
        assert_eq!(upper, lower);
    }

    #[test]
    fn short_or_non_hex_pins_are_rejected() {
        assert_eq!(
            ExpectedSignerV1::from_hex("abcd"),
            Err(ExpectedSignerError::BadLength(4))
        );
        let non_hex = "z".repeat(64);
        assert_eq!(ExpectedSignerV1::from_hex(&non_hex), Err(ExpectedSignerError::BadHex));
    }

    #[test]
    fn pin_evaluation_covers_all_three_outcomes() {
        let pin = ExpectedSignerV1::from_hex(KEY_A).expect("parse");
        let other = ExpectedSignerV1::from_hex(KEY_B).expect("parse");

        assert_eq!(
            evaluate_signer_pin_v1(None, pin.as_bytes()),
            SignerPinOutcomeV1::Unpinned
        );
        assert_eq!(
            evaluate_signer_pin_v1(Some(&pin), pin.as_bytes()),
            SignerPinOutcomeV1::Pinned
        );
        assert_eq!(
            evaluate_signer_pin_v1(Some(&pin), other.as_bytes()),
            SignerPinOutcomeV1::Mismatch
        );
    }

    #[test]
    fn wrong_length_embedded_key_never_matches() {
        let pin = ExpectedSignerV1::from_hex(KEY_A).expect("parse");
        assert!(!pin.matches_bytes(&[0x11u8; 31]));
        assert!(!pin.matches_hex("1111"));
        assert!(pin.matches_hex(KEY_A));
    }

    #[test]
    fn unpinned_label_is_the_interim_relabel() {
        assert!(SignerPinOutcomeV1::Unpinned.label().contains("UNPINNED"));
        assert!(!SignerPinOutcomeV1::Unpinned.is_pinned());
        assert!(SignerPinOutcomeV1::Mismatch.is_mismatch());
        assert!(SignerPinOutcomeV1::Pinned.is_pinned());
    }

    /// `from_env` is a one-line delegation, and that made it invisible to the
    /// suite: every other test exercised `from_env_var` with a custom variable
    /// name, so a mutant replacing `from_env`'s body with `Ok(None)` survived
    /// (`cargo-mutants --in-diff`, PR #736 lineage).
    ///
    /// What survived is not cosmetic. `Ok(None)` is the *unpinned* answer, so a
    /// `from_env` that quietly stopped reading its variable would disable
    /// export-signer pinning entirely while every existing test stayed green —
    /// the precise silent downgrade this module exists to refuse. This pins the
    /// wiring: `from_env` must read `EXPORT_VERIFY_PUBLIC_KEY_ENV` specifically.
    ///
    /// Sole test in this crate touching that variable, and it restores the
    /// previous value, so it cannot race a sibling.
    #[test]
    fn from_env_reads_the_documented_variable() {
        let previous = std::env::var(EXPORT_VERIFY_PUBLIC_KEY_ENV).ok();

        std::env::set_var(EXPORT_VERIFY_PUBLIC_KEY_ENV, KEY_A);
        let pinned = ExpectedSignerV1::from_env().expect("a well-formed pin parses");
        assert_eq!(
            pinned.map(|p| p.to_hex()),
            Some(KEY_A.to_string()),
            "from_env must read EXPORT_VERIFY_PUBLIC_KEY_ENV, not silently return None"
        );

        // Unset is genuinely unpinned — the honest answer, and the one the
        // surviving mutant impersonated.
        std::env::remove_var(EXPORT_VERIFY_PUBLIC_KEY_ENV);
        assert_eq!(ExpectedSignerV1::from_env(), Ok(None));

        // A set-but-malformed value is an error, never a silent downgrade.
        std::env::set_var(EXPORT_VERIFY_PUBLIC_KEY_ENV, "not-a-key");
        assert!(
            ExpectedSignerV1::from_env().is_err(),
            "a typo'd pin must fail loudly rather than report unpinned"
        );

        match previous {
            Some(v) => std::env::set_var(EXPORT_VERIFY_PUBLIC_KEY_ENV, v),
            None => std::env::remove_var(EXPORT_VERIFY_PUBLIC_KEY_ENV),
        }
    }

    #[test]
    fn posture_tokens_are_stable() {
        assert_eq!(ExportIdentityPostureV1::Pinned.as_str(), "pinned");
        assert_eq!(ExportIdentityPostureV1::Unpinned.as_str(), "unpinned");
        assert!(ExportIdentityPostureV1::Pinned.is_pinned());
        assert!(!ExportIdentityPostureV1::Unpinned.is_pinned());
        assert_eq!(ExportIdentityPostureV1::Unpinned.label(), EXPORT_TRUST_UNPINNED_LABEL);
    }
}
