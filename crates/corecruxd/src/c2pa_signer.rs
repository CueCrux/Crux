// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

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
//! by the ExecPlan
//! `corecruxd-c2pa-vault-pki-runtime-enablement-2026-05-29` — it
//! intentionally treats `vault` as a first-class backend rather than
//! a guarded escape hatch. Both surfaces co-exist; the dual-flag
//! posture in `output_attest` is the lower-level guard that stays
//! authoritative when both are set.
//!
//! ## Default OFF
//!
//! When `CORECRUX_C2PA_SIGNER` is unset, empty, or `in_process`, this
//! module returns the in-process Ed25519 signer and never constructs
//! a Vault client. The Vault path is reached only by explicit
//! `CORECRUX_C2PA_SIGNER=vault`.
//!
//! Unknown values log a warning and fall back to `in_process` rather
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

/// Environment variable consumed by [`C2paSignerKind::from_env`].
///
/// Recognised values:
/// - unset / empty / `in_process` → [`C2paSignerKind::InProcess`]
/// - `vault` → [`C2paSignerKind::Vault`]
/// - anything else → [`C2paSignerKind::InProcess`] with a tracing warning
pub const SIGNER_FLAG_ENV: &str = "CORECRUX_C2PA_SIGNER";

/// String value selecting the legacy in-process Ed25519 signer.
pub const SIGNER_VALUE_IN_PROCESS: &str = "in_process";

/// String value selecting the Vault-backed P-256 X.509 signer
/// (Crux PR #123).
pub const SIGNER_VALUE_VAULT: &str = "vault";

/// Selector for the C2PA manifest signer backend.
///
/// Resolved from `CORECRUX_C2PA_SIGNER` via [`Self::from_env`].
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
    /// Read `CORECRUX_C2PA_SIGNER` from the environment and resolve
    /// the selector. Unrecognised values fall back to
    /// [`C2paSignerKind::InProcess`] with a warning — see module
    /// docs for the rationale.
    pub fn from_env() -> Self {
        match std::env::var(SIGNER_FLAG_ENV) {
            Err(_) => Self::InProcess,
            Ok(raw) => {
                let normalised = raw.trim().to_ascii_lowercase();
                match normalised.as_str() {
                    "" | SIGNER_VALUE_IN_PROCESS => Self::InProcess,
                    SIGNER_VALUE_VAULT => Self::Vault,
                    other => {
                        tracing::warn!(
                            env = SIGNER_FLAG_ENV,
                            value = other,
                            "unknown CORECRUX_C2PA_SIGNER value; defaulting to in_process"
                        );
                        Self::InProcess
                    }
                }
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

// Tests live in the M3 commit — see PR / git log for the
// CORECRUX_C2PA_SIGNER unit-test suite (5+2 assertions covering kind
// resolution + InProcess trait-dispatch round trip).
