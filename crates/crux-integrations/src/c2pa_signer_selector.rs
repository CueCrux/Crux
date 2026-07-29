// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Runtime selector for the C2PA manifest signer backend.
//!
//! Crux PR #123 landed the Vault PKI X.509 + P-256 signer backend
//! ([`corecrux_receipts::vault_pki_x509_signer::VaultPkiX509Signer`]).
//! The legacy Ed25519 path (PR #121) remains the default, available
//! via [`corecrux_receipts::ed25519_signer`].
//!
//! This module exposes a single runtime flag — `CORECRUX_C2PA_SIGNER`
//! — that selects between the two backends and constructs an
//! `Arc<dyn C2paSigner + Send + Sync>` suitable for sharing across
//! request-handling tasks.
//!
//! ## Why a single flag (not the dual-flag wiring in `crux-mcp`)
//!
//! `crux_mcp::tools::output_attest` currently uses a dual-flag pair
//! (`CORECRUXD_FEATURE_C2PA_X509_SIGNER=1` AND
//! `CORECRUXD_C2PA_SIGNER_BACKEND=vault-pki-p256`) so that a
//! single-knob misconfiguration cannot accidentally promote the
//! Vault path. That posture works for the legacy ed25519/X.509 split
//! shipped in PR #123 commit `407bbab`. The single-flag posture in
//! this module is the public, daemon-wide runtime surface specified
//! by the ExecPlan `corecruxd-c2pa-vault-pki-runtime-enablement-2026-05-29`
//! — it intentionally treats `vault` as a first-class backend rather
//! than a guarded escape hatch. Both surfaces co-exist; the dual-flag
//! posture in `output_attest` is retained as a backward-compatible
//! fallback (see [`C2paSignerKind::from_canonical_env`] returning `None`).
//!
//! ## Default OFF (caller-applied)
//!
//! [`C2paSignerKind::from_canonical_env`] returns `Option<Self>`:
//! - `Some(InProcess)` for `CORECRUX_C2PA_SIGNER=in_process` or any
//!   unknown value (with a warning).
//! - `Some(Vault)` for `CORECRUX_C2PA_SIGNER=vault`.
//! - `None` when the env var is unset or empty, so the caller can
//!   apply its own policy (e.g. honouring the PR #123 dual-flag pair
//!   as a legacy fallback before defaulting to `InProcess`).
//!
//! Unknown values log a warning and fall back to `InProcess` rather
//! than failing startup — the ExecPlan's M6 flip is an explicit
//! operator-attended action, so a typo in an env file should not
//! silently switch the trust anchor.
//!
//! ## Security
//!
//! The Vault token is resolved by the underlying
//! [`VaultPkiX509Signer::from_env`] flow (which reads `VAULT_TOKEN`
//! at signer construction time and never persists it). This module
//! does not touch tokens directly and never logs them; per
//! `CueCrux/CLAUDE.md` §10 a Vault token never appears in any file
//! this crate writes.

use std::sync::Arc;

use corecrux_receipts::vault_pki_x509_signer::VaultPkiX509Signer;
use corecrux_receipts::C2paSigner;
use ed25519_dalek::SigningKey;

/// Environment variable consumed by [`C2paSignerKind::from_canonical_env`].
///
/// Recognised values:
/// - unset / empty → `None` (caller applies its own fallback)
/// - `in_process` → `Some(C2paSignerKind::InProcess)`
/// - `vault` → `Some(C2paSignerKind::Vault)`
/// - anything else → `Some(C2paSignerKind::InProcess)` with a tracing warning
pub const SIGNER_FLAG_ENV: &str = "CORECRUX_C2PA_SIGNER";

/// String value selecting the legacy in-process Ed25519 signer.
pub const SIGNER_VALUE_IN_PROCESS: &str = "in_process";

/// String value selecting the Vault-backed P-256 X.509 signer
/// (Crux PR #123).
pub const SIGNER_VALUE_VAULT: &str = "vault";

/// Selector for the C2PA manifest signer backend.
///
/// Resolved from `CORECRUX_C2PA_SIGNER` via
/// [`Self::from_canonical_env`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum C2paSignerKind {
    /// Legacy in-process Ed25519 CROWN signer
    /// ([`corecrux_receipts::ed25519_signer`]). Default backend; emits
    /// `signature.alg = "ed25519"` envelopes byte-identical to PR
    /// #121.
    InProcess,
    /// Vault PKI X.509 + P-256 signer
    /// ([`VaultPkiX509Signer`]). Emits envelopes with
    /// `signature.alg = "es256"` and an `x5chain` header carrying
    /// the leaf + intermediates (RFC 9360).
    Vault,
}

impl C2paSignerKind {
    /// Read the canonical single env (`CORECRUX_C2PA_SIGNER`) and
    /// resolve the selector. Returns `None` when the env var is unset
    /// or empty, so the caller can apply its own legacy fallback (e.g.
    /// the PR #123 dual-flag pair). Unrecognised values fall back to
    /// `Some(C2paSignerKind::InProcess)` with a warning — see module
    /// docs for the rationale.
    pub fn from_canonical_env() -> Option<Self> {
        let raw = std::env::var(SIGNER_FLAG_ENV).ok()?;
        let normalised = raw.trim().to_ascii_lowercase();
        match normalised.as_str() {
            "" => None,
            SIGNER_VALUE_IN_PROCESS => Some(Self::InProcess),
            SIGNER_VALUE_VAULT => Some(Self::Vault),
            other => {
                tracing::warn!(
                    env = SIGNER_FLAG_ENV,
                    value = other,
                    "unknown CORECRUX_C2PA_SIGNER value; defaulting to in_process"
                );
                Some(Self::InProcess)
            }
        }
    }

    /// String form for logs + structured-log breadcrumbs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InProcess => SIGNER_VALUE_IN_PROCESS,
            Self::Vault => SIGNER_VALUE_VAULT,
        }
    }
}

/// Error returned by [`build_manifest_signer`].
#[derive(Debug, thiserror::Error)]
pub enum BuildSignerError {
    /// The in-process Ed25519 signer requires a private-key seed; the
    /// expected fixture env var was missing / unparseable. The
    /// concrete env var name + key id are documented at the call
    /// site.
    #[error("in-process Ed25519 signer init failed: {0}")]
    InProcessInit(String),
    /// The Vault PKI signer failed to construct from environment
    /// (typically `VAULT_ADDR` / `VAULT_TOKEN` missing or the configured
    /// PKI mount/role unreachable).
    #[error("Vault PKI signer init failed: {0}")]
    VaultInit(String),
}

/// Owned in-process Ed25519 [`C2paSigner`] adapter.
///
/// The legacy [`corecrux_receipts::ed25519_signer`] helper returns
/// `impl C2paSigner + 'a` bound by a borrow of the signing key. The
/// daemon-wide runtime path needs an owned `Arc<dyn C2paSigner +
/// Send + Sync>` it can hand to async request handlers, so this
/// type owns the key + key id and implements the trait by delegating
/// to the same Ed25519 primitives.
///
/// Behaviour is byte-identical to the borrowed adapter: same
/// signature algorithm string (`"ed25519"`), same signature bytes,
/// no `x5chain_pem` (None).
#[derive(Debug)]
pub struct OwnedEd25519Signer {
    signing_key: SigningKey,
    key_id: String,
}

impl OwnedEd25519Signer {
    /// Build from a raw signing key + key id. The key id is what the
    /// emitted manifest carries; downstream verifiers use it to look
    /// the public key up in the daemon's trust list.
    pub fn new(signing_key: SigningKey, key_id: impl Into<String>) -> Self {
        Self {
            signing_key,
            key_id: key_id.into(),
        }
    }
}

impl C2paSigner for OwnedEd25519Signer {
    fn sign_body(
        &self,
        canonical_body_bytes: &[u8],
    ) -> Result<corecrux_receipts::SignedManifestParts, corecrux_receipts::C2paManifestError> {
        use ed25519_dalek::Signer as _;
        let sig = self.signing_key.sign(canonical_body_bytes).to_bytes();
        Ok(corecrux_receipts::SignedManifestParts {
            signature_bytes: sig.to_vec(),
            signature_alg: "ed25519".to_string(),
            key_id: self.key_id.clone(),
            x5chain_pem: None,
        })
    }
}

/// Concrete signer trait object handed back from
/// [`build_manifest_signer`]. The auto-trait bounds make it safe to
/// share across async tasks (axum handlers, gRPC services).
pub type ManifestSignerArc = Arc<dyn C2paSigner + Send + Sync>;

/// Construct a manifest signer for the given backend selector.
///
/// `InProcess` builds an [`OwnedEd25519Signer`] from `signing_key` +
/// `key_id`. The caller resolves these from the daemon's existing
/// CROWN-key env vars (or test fixtures).
///
/// `Vault` builds a [`VaultPkiX509Signer`] via
/// [`VaultPkiX509Signer::from_env`] and immediately calls
/// `initialize()` so cert state is loaded / refreshed before the
/// first sign call. The signer is `Send + Sync` (uses parking_lot
/// `RwLock` internally), so it is safe to share across tasks.
///
/// The lazy contract: when `kind == InProcess`, this function does
/// not touch the Vault env vars or hit the network. When `kind ==
/// Vault`, the in-process key material is not loaded.
pub fn build_manifest_signer(
    kind: C2paSignerKind,
    signing_key: SigningKey,
    key_id: impl Into<String>,
) -> Result<ManifestSignerArc, BuildSignerError> {
    match kind {
        C2paSignerKind::InProcess => Ok(Arc::new(OwnedEd25519Signer::new(signing_key, key_id))),
        C2paSignerKind::Vault => {
            let signer = VaultPkiX509Signer::from_env().map_err(|e| BuildSignerError::VaultInit(e.to_string()))?;
            signer
                .initialize()
                .map_err(|e| BuildSignerError::VaultInit(format!("initialize: {e}")))?;
            Ok(Arc::new(signer))
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use corecrux_receipts::{build_c2pa_manifest_v1, sign_c2pa_manifest_via_signer, C2paManifestInputV1};
    use serial_test::serial;

    fn fixture_signing_key() -> SigningKey {
        // Deterministic seed so the unit test snapshot is stable.
        SigningKey::from_bytes(&[0x42u8; 32])
    }

    /// 1. Default (env unset) resolves to `None` so the caller applies
    ///    its own fallback policy.
    #[test]
    #[serial(c2pa_signer_env)]
    fn c2pa_signer_kind_from_canonical_env_default_none() {
        std::env::remove_var(SIGNER_FLAG_ENV);
        assert_eq!(C2paSignerKind::from_canonical_env(), None);
    }

    /// 2. `vault` resolves to `Some(Vault)`.
    #[test]
    #[serial(c2pa_signer_env)]
    fn c2pa_signer_kind_from_canonical_env_explicit_vault() {
        std::env::set_var(SIGNER_FLAG_ENV, "vault");
        assert_eq!(C2paSignerKind::from_canonical_env(), Some(C2paSignerKind::Vault));
        std::env::remove_var(SIGNER_FLAG_ENV);
    }

    /// 3. `in_process` (and `IN_PROCESS` upper-case variant via the
    ///    trim+to_ascii_lowercase pass) resolves to `Some(InProcess)`.
    ///    Empty string falls through to `None` (caller fallback).
    #[test]
    #[serial(c2pa_signer_env)]
    fn c2pa_signer_kind_from_canonical_env_in_process_explicit() {
        std::env::set_var(SIGNER_FLAG_ENV, "in_process");
        assert_eq!(C2paSignerKind::from_canonical_env(), Some(C2paSignerKind::InProcess));
        std::env::set_var(SIGNER_FLAG_ENV, "  IN_PROCESS  ");
        assert_eq!(C2paSignerKind::from_canonical_env(), Some(C2paSignerKind::InProcess));
        std::env::set_var(SIGNER_FLAG_ENV, "");
        assert_eq!(C2paSignerKind::from_canonical_env(), None);
        std::env::remove_var(SIGNER_FLAG_ENV);
    }

    /// 4. Unknown values warn + fall back to `Some(InProcess)` (do NOT
    ///    crash the daemon, do NOT fall through to caller fallback —
    ///    the operator explicitly set the env var to something, so
    ///    honour their intent to use the single-flag surface).
    #[test]
    #[serial(c2pa_signer_env)]
    fn c2pa_signer_kind_from_canonical_env_unknown_falls_back() {
        std::env::set_var(SIGNER_FLAG_ENV, "weird");
        assert_eq!(C2paSignerKind::from_canonical_env(), Some(C2paSignerKind::InProcess));
        std::env::set_var(SIGNER_FLAG_ENV, "vault-pki-p256"); // wrong, not the accepted shape
        assert_eq!(C2paSignerKind::from_canonical_env(), Some(C2paSignerKind::InProcess));
        std::env::remove_var(SIGNER_FLAG_ENV);
    }

    /// 5. `build_manifest_signer(InProcess, ..)` returns a trait
    ///    object that can sign + the signature parses back via the
    ///    backend-agnostic pipeline.
    ///
    ///    The Vault branch is NOT exercised here because it requires
    ///    real `VAULT_ADDR` + `VAULT_TOKEN` env vars and a reachable
    ///    Vault PKI mount — that's M4 (integration) per the parent
    ///    ExecPlan, explicitly out of scope for unit tests.
    #[test]
    fn build_manifest_signer_returns_arc_trait_object() {
        let signer = build_manifest_signer(
            C2paSignerKind::InProcess,
            fixture_signing_key(),
            "test-key-runtime-c2pa",
        )
        .expect("InProcess build never reaches Vault");

        let manifest = build_c2pa_manifest_v1(&C2paManifestInputV1 {
            content_bytes: b"image-bytes",
            content_type: Some("image/png"),
            crown_receipt_id: "r_runtime_01",
            signer_passport: "p_test",
            claim_generator: "cuecrux/test",
            manifest_id: "urn:cuecrux:c2pa:test",
            when: "2026-05-29T12:00:00Z",
            model: None,
        });
        let signed =
            sign_c2pa_manifest_via_signer(manifest, &*signer, "2026-05-29T12:00:00Z").expect("sign via Arc<dyn>");
        assert_eq!(signed.signature_alg, "ed25519");
        assert_eq!(signed.key_id, "test-key-runtime-c2pa");
        assert_eq!(signed.signature.len(), 64, "Ed25519 sig is 64 bytes");
        assert!(signed.x5chain_pem.is_none(), "in-process path has no x5chain");
    }

    /// 6. Round-trip: the manifest produced via the Arc<dyn> path
    ///    verifies under the same key — proves the trait dispatch
    ///    doesn't mutate signer-relevant state.
    #[test]
    fn build_manifest_signer_round_trip_verifies() {
        let key = fixture_signing_key();
        let verifying = key.verifying_key();
        let signer = build_manifest_signer(C2paSignerKind::InProcess, key, "k-roundtrip").expect("InProcess build");

        let content = b"round-trip";
        let manifest = build_c2pa_manifest_v1(&C2paManifestInputV1 {
            content_bytes: content,
            content_type: None,
            crown_receipt_id: "r_roundtrip",
            signer_passport: "p_test",
            claim_generator: "cuecrux/test",
            manifest_id: "urn:cuecrux:c2pa:roundtrip",
            when: "2026-05-29T12:00:00Z",
            model: None,
        });
        let signed = sign_c2pa_manifest_via_signer(manifest, &*signer, "2026-05-29T12:00:00Z").unwrap();
        let envelope = signed.to_jumbf_base64();
        let parsed = corecrux_receipts::parse_jumbf_base64(&envelope).unwrap();
        let report = corecrux_receipts::verify_c2pa_manifest_v1(&parsed, content, &verifying).unwrap();
        assert!(report.ok, "verify report: {report:?}");
    }

    /// 7. as_str() exposes the env-value string for breadcrumb logs.
    #[test]
    fn c2pa_signer_kind_as_str_matches_env_value() {
        assert_eq!(C2paSignerKind::InProcess.as_str(), SIGNER_VALUE_IN_PROCESS);
        assert_eq!(C2paSignerKind::Vault.as_str(), SIGNER_VALUE_VAULT);
    }
}
