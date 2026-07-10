// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Pluggable signer trait for plan receipts.
//!
//! - Crux Daemon uses [`NullSigner`]: BLAKE3-only, no signature.
//! - Hosted uses a Vault-Transit-backed signer (separate crate / TS
//!   implementation). The trait here exists so the handshake service has a
//!   single code path; the hosted signer wraps whatever Vault exposes.

use ed25519_dalek::{Signer as DalekSigner, SigningKey};

use crate::error::SessionError;
use crate::plan::{ReceiptMode, HASH_LEN, SIGNATURE_LEN};

#[derive(Debug, Clone)]
pub struct Signed {
    pub signature: [u8; SIGNATURE_LEN],
    pub signer_kid: String,
}

pub trait PlanSigner: Send + Sync {
    /// The receipt mode this signer produces. The handshake service reads
    /// this **before** computing the plan hash, because `receipt.mode` is
    /// part of the hashed content (only `hash`/`signature`/`signer_kid` are
    /// zeroed — master-plan §3.3).
    fn mode(&self) -> ReceiptMode;

    /// If this signer returns `None`, the handshake runs in local/BLAKE3-only
    /// mode and `receipt.signature`/`receipt.signer_kid` stay `null`.
    fn sign(&self, hash: &[u8; HASH_LEN]) -> Result<Option<Signed>, SessionError>;
}

/// The local signer: does nothing.
#[derive(Debug, Default, Clone)]
pub struct NullSigner;

impl PlanSigner for NullSigner {
    fn mode(&self) -> ReceiptMode {
        ReceiptMode::Local
    }

    fn sign(&self, _hash: &[u8; HASH_LEN]) -> Result<Option<Signed>, SessionError> {
        Ok(None)
    }
}

/// An in-process ed25519 signer. Used in tests and as the fallback for hosted
/// when Vault Transit is unavailable (dev environments only — production
/// must use the Vault-backed signer).
#[derive(Clone)]
pub struct InProcessEd25519Signer {
    signing_key: SigningKey,
    kid: String,
}

impl InProcessEd25519Signer {
    pub fn new(signing_key: SigningKey, kid: impl Into<String>) -> Self {
        Self {
            signing_key,
            kid: kid.into(),
        }
    }

    pub fn from_seed(seed: [u8; 32], kid: impl Into<String>) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&seed),
            kid: kid.into(),
        }
    }

    pub fn verifying_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }
}

impl PlanSigner for InProcessEd25519Signer {
    fn mode(&self) -> ReceiptMode {
        ReceiptMode::Verified
    }

    fn sign(&self, hash: &[u8; HASH_LEN]) -> Result<Option<Signed>, SessionError> {
        let sig = self.signing_key.sign(hash);
        let mut sig_arr = [0u8; SIGNATURE_LEN];
        sig_arr.copy_from_slice(&sig.to_bytes());
        Ok(Some(Signed {
            signature: sig_arr,
            signer_kid: self.kid.clone(),
        }))
    }
}
