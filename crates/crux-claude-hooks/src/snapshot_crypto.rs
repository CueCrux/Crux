// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Client-side AEAD envelope for hosted compaction-snapshot sync
//! (ExecPlan `hosted-compaction-sync-encrypted-2026-07-17`).
//!
//! The product promise is "unreadable to us": the snapshot is sealed on the
//! client BEFORE it becomes a non-private fact that the hosted mirror stores.
//! Only the sealed [`Envelope`] (base64, opaque) ever occupies a synced field.
//!
//! - **AEAD:** XChaCha20-Poly1305 (`chacha20poly1305` crate). The 24-byte
//!   extended nonce means a random per-seal nonce is collision-safe — no counter
//!   or persisted state. Same construction as the in-tree at-rest secret
//!   envelope `corecruxd::encrypted_secrets`.
//! - **Key:** derived on demand from the ed25519 passport *seed* via
//!   `crux_session::LocalPassportKey::derive_subkey` (BLAKE3 KDF, domain label
//!   [`SNAPSHOT_KEY_CONTEXT`]). The seed never leaves the device, so the hosted
//!   mirror/operator cannot derive the key — that is what makes the snapshot
//!   "unreadable to us". The derived key is never persisted or logged.
//!
//! Same passport seed on both devices (the "same passport provisioned on both
//! machines" prerequisite) ⇒ same derived key ⇒ cross-device decrypt. A
//! different seed ⇒ AEAD authentication fails ⇒ the caller skips quietly.

use std::path::{Path, PathBuf};

use base64::Engine as _;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::Rng as _;
use serde::{Deserialize, Serialize};

/// Domain-separation label for the snapshot content key (BLAKE3 KDF context).
/// The version suffix moves only alongside an [`ENVELOPE_V`] bump.
pub const SNAPSHOT_KEY_CONTEXT: &str = "crux/compaction-snapshot/v1";

/// Current envelope version. [`open`] rejects anything else.
pub const ENVELOPE_V: u8 = 1;

/// AEAD algorithm tag carried in the envelope. [`open`] rejects anything else.
pub const ENVELOPE_ALG: &str = "xchacha20poly1305";

/// XChaCha20-Poly1305 nonce width, in bytes.
const NONCE_BYTES: usize = 24;

const B64: base64::engine::general_purpose::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// Failure modes for [`open`] / [`Envelope::from_fact_value`]. Distinct variants
/// let callers (and tests) tell an unknown-scheme envelope from an
/// authentication failure without string-matching. No variant carries plaintext.
#[derive(Debug, PartialEq, Eq)]
pub enum SnapshotCryptoError {
    /// The envelope declares a version/algorithm this build does not implement.
    UnknownVersion { v: u8, alg: String },
    /// The envelope is not well-formed (bad base64, wrong nonce length, bad JSON).
    MalformedEnvelope,
    /// AEAD authentication failed — wrong key (different passport), or the
    /// ciphertext/nonce was tampered with.
    DecryptFailed,
}

impl std::fmt::Display for SnapshotCryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownVersion { v, alg } => {
                write!(f, "unknown snapshot envelope (v={v}, alg={alg}) — cannot open")
            }
            Self::MalformedEnvelope => write!(f, "malformed snapshot envelope"),
            Self::DecryptFailed => write!(f, "snapshot decryption failed (wrong passport or tampered envelope)"),
        }
    }
}

impl std::error::Error for SnapshotCryptoError {}

/// Versioned sealed envelope. `nonce` and `ct` are base64-std. Serialized to
/// JSON then base64-wrapped by [`Envelope::to_fact_value`] into the single
/// opaque string stored as the `session_snapshot` fact value.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Envelope {
    pub v: u8,
    pub alg: String,
    pub nonce: String,
    pub ct: String,
}

impl Envelope {
    /// Serialize to the opaque base64 string stored as the fact value.
    ///
    /// # Errors
    /// Propagates a JSON serialization failure (not expected for this struct).
    pub fn to_fact_value(&self) -> anyhow::Result<String> {
        let json = serde_json::to_vec(self)?;
        Ok(B64.encode(json))
    }

    /// Parse an envelope back from the opaque base64 fact value.
    ///
    /// # Errors
    /// [`SnapshotCryptoError::MalformedEnvelope`] on bad base64 or JSON.
    pub fn from_fact_value(value: &str) -> Result<Self, SnapshotCryptoError> {
        let json = B64
            .decode(value.trim().as_bytes())
            .map_err(|_| SnapshotCryptoError::MalformedEnvelope)?;
        serde_json::from_slice(&json).map_err(|_| SnapshotCryptoError::MalformedEnvelope)
    }
}

/// Seal `plaintext` under `key` with a fresh random nonce.
///
/// # Errors
/// Returns an error only if the AEAD encrypt fails (allocation/programmer
/// error); the hook treats this as best-effort and skips the hosted store.
pub fn seal(key: &[u8; 32], plaintext: &[u8]) -> anyhow::Result<Envelope> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce_bytes = [0u8; NONCE_BYTES];
    rand::rng().fill_bytes(&mut nonce_bytes);
    // `nonce_bytes` is a fixed 24-byte array, so `try_from` never errors here;
    // handled as a Result anyway to stay panic/expect-free (crate lints deny both).
    let nonce = XNonce::try_from(&nonce_bytes[..]).map_err(|_| anyhow::anyhow!("snapshot seal: nonce length"))?;
    let ct = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| anyhow::anyhow!("snapshot seal: AEAD encrypt failed"))?;
    Ok(Envelope {
        v: ENVELOPE_V,
        alg: ENVELOPE_ALG.to_string(),
        nonce: B64.encode(nonce_bytes),
        ct: B64.encode(ct),
    })
}

/// Open `envelope` under `key`, returning the recovered plaintext.
///
/// # Errors
/// - [`SnapshotCryptoError::UnknownVersion`] if `v`/`alg` are not understood.
/// - [`SnapshotCryptoError::MalformedEnvelope`] on bad base64 / nonce length.
/// - [`SnapshotCryptoError::DecryptFailed`] on wrong key or tamper (AEAD auth).
pub fn open(key: &[u8; 32], envelope: &Envelope) -> Result<Vec<u8>, SnapshotCryptoError> {
    if envelope.v != ENVELOPE_V || envelope.alg != ENVELOPE_ALG {
        return Err(SnapshotCryptoError::UnknownVersion {
            v: envelope.v,
            alg: envelope.alg.clone(),
        });
    }
    let nonce_bytes = B64
        .decode(envelope.nonce.as_bytes())
        .map_err(|_| SnapshotCryptoError::MalformedEnvelope)?;
    let nonce = XNonce::try_from(nonce_bytes.as_slice()).map_err(|_| SnapshotCryptoError::MalformedEnvelope)?;
    let ct = B64
        .decode(envelope.ct.as_bytes())
        .map_err(|_| SnapshotCryptoError::MalformedEnvelope)?;
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(&nonce, ct.as_ref())
        .map_err(|_| SnapshotCryptoError::DecryptFailed)
}

/// Resolve the passport-key path the hook should read. Priority:
/// `CRUX_PASSPORT_KEY_PATH` (hook override) → `CORECRUXD_PASSPORT_KEY_PATH`
/// (matches the daemon's own resolution) → `CORECRUXD_DATA_DIR/passport.key`.
/// Returns `None` when none is configured.
#[must_use]
pub fn passport_key_path_from_env() -> Option<PathBuf> {
    for var in ["CRUX_PASSPORT_KEY_PATH", "CORECRUXD_PASSPORT_KEY_PATH"] {
        if let Ok(raw) = std::env::var(var) {
            let trimmed = raw.trim();
            if !trimmed.is_empty() {
                return Some(PathBuf::from(trimmed));
            }
        }
    }
    if let Ok(dir) = std::env::var("CORECRUXD_DATA_DIR") {
        let trimmed = dir.trim();
        if !trimmed.is_empty() {
            return Some(Path::new(trimmed).join("passport.key"));
        }
    }
    None
}

/// Derive the 32-byte snapshot content key from the passport seed, if a
/// passport-key file is configured AND already exists on disk.
///
/// Returns `None` — never an error, never a side effect — when no seed is
/// available, so the caller silently skips hosted sync (free/local path). The
/// seed file is only ever *read*: this never creates a fresh seed, because a
/// freshly-minted seed on device B would differ from device A and silently
/// break cross-device decrypt.
///
// ponytail: derived key is a stack `[u8; 32]`, not zeroize-on-drop — matches
// the in-tree `encrypted_secrets` precedent (same passport seed lives unzeroized
// in `LocalPassportKey`). Upgrade path if the threat model tightens: wrap the
// return + the intermediate in `zeroize::Zeroizing`.
#[must_use]
pub fn derive_snapshot_key() -> Option<[u8; 32]> {
    let path = passport_key_path_from_env()?;
    // Read-only: a missing file means "no hosted key here" → skip, don't mint one.
    if !path.is_file() {
        return None;
    }
    let key = crux_session::LocalPassportKey::from_path(&path).ok()?;
    Some(key.derive_subkey(SNAPSHOT_KEY_CONTEXT))
}

#[cfg(test)]
mod tests {
    use super::*;

    const K1: [u8; 32] = [42u8; 32];
    const K2: [u8; 32] = [7u8; 32];

    #[test]
    fn round_trip_recovers_plaintext() {
        let pt = b"open todos + git anchor: sha=abc123 branch=main milestone=M2";
        let env = seal(&K1, pt).expect("seal");
        assert_eq!(env.v, ENVELOPE_V);
        assert_eq!(env.alg, ENVELOPE_ALG);
        let recovered = open(&K1, &env).expect("open");
        assert_eq!(recovered, pt);
    }

    #[test]
    fn wrong_key_fails_authentication() {
        let env = seal(&K1, b"secret snapshot").expect("seal");
        assert_eq!(open(&K2, &env), Err(SnapshotCryptoError::DecryptFailed));
    }

    #[test]
    fn tampered_ciphertext_fails_authentication() {
        let mut env = seal(&K1, b"secret snapshot").expect("seal");
        // Flip one byte of the ciphertext (decode, mutate, re-encode).
        let mut ct = B64.decode(env.ct.as_bytes()).expect("decode ct");
        ct[0] ^= 0x01;
        env.ct = B64.encode(&ct);
        assert_eq!(open(&K1, &env), Err(SnapshotCryptoError::DecryptFailed));
    }

    #[test]
    fn tampered_nonce_fails_authentication() {
        let mut env = seal(&K1, b"secret snapshot").expect("seal");
        let mut nonce = B64.decode(env.nonce.as_bytes()).expect("decode nonce");
        nonce[0] ^= 0x01;
        env.nonce = B64.encode(&nonce);
        assert_eq!(open(&K1, &env), Err(SnapshotCryptoError::DecryptFailed));
    }

    #[test]
    fn two_seals_of_same_plaintext_use_distinct_nonces() {
        let a = seal(&K1, b"identical").expect("seal a");
        let b = seal(&K1, b"identical").expect("seal b");
        assert_ne!(a.nonce, b.nonce, "random nonce must differ across seals");
        assert_ne!(a.ct, b.ct, "ciphertext must differ when the nonce differs");
    }

    #[test]
    fn unknown_version_is_rejected() {
        let mut env = seal(&K1, b"x").expect("seal");
        env.v = 2;
        assert_eq!(
            open(&K1, &env),
            Err(SnapshotCryptoError::UnknownVersion {
                v: 2,
                alg: ENVELOPE_ALG.to_string()
            })
        );
    }

    #[test]
    fn unknown_alg_is_rejected() {
        let mut env = seal(&K1, b"x").expect("seal");
        env.alg = "aes-256-gcm".to_string();
        assert!(matches!(
            open(&K1, &env),
            Err(SnapshotCryptoError::UnknownVersion { .. })
        ));
    }

    #[test]
    fn malformed_envelope_is_rejected_not_panicked() {
        let env = Envelope {
            v: ENVELOPE_V,
            alg: ENVELOPE_ALG.to_string(),
            nonce: "not-base64!!".to_string(),
            ct: "also!!bad".to_string(),
        };
        assert_eq!(open(&K1, &env), Err(SnapshotCryptoError::MalformedEnvelope));

        // Wrong nonce length (valid base64, but not 24 bytes).
        let short = Envelope {
            v: ENVELOPE_V,
            alg: ENVELOPE_ALG.to_string(),
            nonce: B64.encode([0u8; 12]),
            ct: B64.encode(b"junk"),
        };
        assert_eq!(open(&K1, &short), Err(SnapshotCryptoError::MalformedEnvelope));
    }

    #[test]
    fn fact_value_round_trips_and_hides_plaintext() {
        let pt = b"UNIQUE_PLAINTEXT_MARKER_9137";
        let env = seal(&K1, pt).expect("seal");
        let value = env.to_fact_value().expect("to_fact_value");
        // The opaque fact value must not contain the plaintext (ciphertext-only).
        assert!(!value.contains("UNIQUE_PLAINTEXT_MARKER_9137"));
        let parsed = Envelope::from_fact_value(&value).expect("from_fact_value");
        assert_eq!(parsed, env);
        assert_eq!(open(&K1, &parsed).expect("open"), pt);
    }

    #[test]
    fn from_fact_value_rejects_garbage() {
        assert_eq!(
            Envelope::from_fact_value("@@not base64@@"),
            Err(SnapshotCryptoError::MalformedEnvelope)
        );
        // Valid base64, but not our JSON.
        let junk = B64.encode(b"{\"unrelated\":true}");
        assert_eq!(
            Envelope::from_fact_value(&junk),
            Err(SnapshotCryptoError::MalformedEnvelope)
        );
    }

    // ---- KDF determinism (same passport → same key; different → different) ----

    #[test]
    fn kdf_same_seed_same_key_different_seed_different_key() {
        use crux_session::LocalPassportKey;
        let dev_a = LocalPassportKey::from_seed([9u8; 32]).expect("key a");
        let dev_b = LocalPassportKey::from_seed([9u8; 32]).expect("key b (same seed)");
        let other = LocalPassportKey::from_seed([10u8; 32]).expect("other seed");

        let k_a = dev_a.derive_subkey(SNAPSHOT_KEY_CONTEXT);
        let k_b = dev_b.derive_subkey(SNAPSHOT_KEY_CONTEXT);
        let k_other = other.derive_subkey(SNAPSHOT_KEY_CONTEXT);

        assert_eq!(k_a, k_b, "same passport seed must derive the same content key");
        assert_ne!(k_a, k_other, "a different passport seed must derive a different key");

        // End-to-end: device B (same seed) opens device A's envelope; the
        // stranger cannot.
        let env = seal(&k_a, b"cross-device snapshot").expect("seal");
        assert_eq!(open(&k_b, &env).expect("open"), b"cross-device snapshot");
        assert_eq!(open(&k_other, &env), Err(SnapshotCryptoError::DecryptFailed));
    }

    #[test]
    fn kdf_is_domain_separated_by_context_label() {
        use crux_session::LocalPassportKey;
        let key = LocalPassportKey::from_seed([5u8; 32]).expect("key");
        let snapshot = key.derive_subkey(SNAPSHOT_KEY_CONTEXT);
        let other_domain = key.derive_subkey("crux/some-other-purpose/v1");
        assert_ne!(
            snapshot, other_domain,
            "different domain labels must derive independent keys from the same seed"
        );
    }
}
