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
//!
//! - **AAD binding (envelope v2):** every seal/open binds canonical
//!   additional-authenticated-data `{v, alg, entity, session_id}`. This ties a
//!   ciphertext to the exact fact carrier and the session it was sealed under,
//!   so a value moved under a different fact key, a different entity, or a
//!   different scheme fails authentication (replay / cross-session substitution
//!   defence — crypto-review Finding 2). The AAD is reconstructed identically on
//!   `open` from the validated `v`/`alg`, the constant entity, and the caller's
//!   `session_id`; a mismatch is indistinguishable from a wrong key (auth fail).

use std::path::{Path, PathBuf};

use base64::Engine as _;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::Rng as _;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Fact entity under which the client-side-encrypted compaction snapshot is
/// stored (non-private, so it rides the hosted mirror; value is ciphertext only).
/// Shared by the PreCompact writer and the SessionStart reader.
pub const SNAPSHOT_ENTITY: &str = "session_snapshot";

/// Domain-separation label for the snapshot content key (BLAKE3 KDF context).
/// The `v1` suffix tracks the *key-derivation* scheme, which is unchanged: it
/// moves only if the seed→key derivation changes, NOT when [`ENVELOPE_V`] bumps
/// (the v1→v2 envelope bump added AAD binding but did not touch the KDF, so the
/// derived key — and any device pairing — stays stable).
pub const SNAPSHOT_KEY_CONTEXT: &str = "crux/compaction-snapshot/v1";

/// Current envelope version. [`open`] rejects anything else.
///
/// v2 (crypto-review Finding 2) binds canonical AAD `{v, alg, entity,
/// session_id}` into the AEAD. v1 (no AAD) is intentionally unreadable by this
/// build — there are no persisted v1 blobs in prod (the feature was never
/// enabled), so no migration path is needed.
pub const ENVELOPE_V: u8 = 2;

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

/// Canonical additional-authenticated-data for a snapshot envelope, binding the
/// ciphertext to the scheme (`v`, `alg`), the fact carrier (`entity`), and the
/// session it was sealed under (`session_id`). Serialized deterministically
/// (fixed struct-field order, no maps) so `seal` and `open` produce identical
/// bytes for the same inputs.
#[derive(Serialize)]
struct SnapshotAad<'a> {
    v: u8,
    alg: &'a str,
    entity: &'a str,
    session_id: &'a str,
}

/// Build the canonical AAD bytes for `session_id` under the current scheme.
fn snapshot_aad(session_id: &str) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(&SnapshotAad {
        v: ENVELOPE_V,
        alg: ENVELOPE_ALG,
        entity: SNAPSHOT_ENTITY,
        session_id,
    })
}

/// Seal `plaintext` under `key` with a fresh random nonce, binding canonical AAD
/// `{v, alg, entity, session_id}` (envelope v2). `session_id` is the identifier
/// the envelope is scoped to (the fact key it will be stored under); `open` must
/// be given the same `session_id` or authentication fails.
///
/// # Errors
/// Returns an error only if AAD serialization or the AEAD encrypt fails
/// (allocation/programmer error); the hook treats this as best-effort and skips.
pub fn seal(key: &[u8; 32], session_id: &str, plaintext: &[u8]) -> anyhow::Result<Envelope> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce_bytes = [0u8; NONCE_BYTES];
    rand::rng().fill_bytes(&mut nonce_bytes);
    // `nonce_bytes` is a fixed 24-byte array, so `try_from` never errors here;
    // handled as a Result anyway to stay panic/expect-free (crate lints deny both).
    let nonce = XNonce::try_from(&nonce_bytes[..]).map_err(|_| anyhow::anyhow!("snapshot seal: nonce length"))?;
    let aad = snapshot_aad(session_id).map_err(|e| anyhow::anyhow!("snapshot seal: aad: {e}"))?;
    let ct = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("snapshot seal: AEAD encrypt failed"))?;
    Ok(Envelope {
        v: ENVELOPE_V,
        alg: ENVELOPE_ALG.to_string(),
        nonce: B64.encode(nonce_bytes),
        ct: B64.encode(ct),
    })
}

/// Open `envelope` under `key` for `session_id`, returning the recovered
/// plaintext. The AAD `{v, alg, entity, session_id}` is reconstructed and must
/// match the seal exactly: a value sealed under a different `session_id` (or a
/// different scheme/entity) fails authentication just like a wrong key.
///
/// # Errors
/// - [`SnapshotCryptoError::UnknownVersion`] if `v`/`alg` are not understood.
/// - [`SnapshotCryptoError::MalformedEnvelope`] on bad base64 / nonce length.
/// - [`SnapshotCryptoError::DecryptFailed`] on wrong key, wrong `session_id`, or
///   tamper (AEAD authentication).
pub fn open(key: &[u8; 32], session_id: &str, envelope: &Envelope) -> Result<Vec<u8>, SnapshotCryptoError> {
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
    let aad = snapshot_aad(session_id).map_err(|_| SnapshotCryptoError::MalformedEnvelope)?;
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ct.as_ref(),
                aad: &aad,
            },
        )
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
/// The key is returned in a [`Zeroizing`] wrapper so it is wiped from memory on
/// drop. `Zeroizing<[u8; 32]>` derefs to `[u8; 32]`, so callers pass `&key`
/// unchanged to [`seal`] / [`open`] via deref coercion.
///
// ponytail: this zeroizes the *derived* key. The passport *seed* itself still
// lives unzeroized inside `crux_session::LocalPassportKey` (shared crate, every
// `derive_subkey` caller) — a broader hardening tracked separately, out of scope
// for this hook-local key path.
#[must_use]
pub fn derive_snapshot_key() -> Option<Zeroizing<[u8; 32]>> {
    let path = passport_key_path_from_env()?;
    // Read-only: a missing file means "no hosted key here" → skip, don't mint one.
    if !path.is_file() {
        return None;
    }
    let key = crux_session::LocalPassportKey::from_path(&path).ok()?;
    Some(Zeroizing::new(key.derive_subkey(SNAPSHOT_KEY_CONTEXT)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const K1: [u8; 32] = [42u8; 32];
    const K2: [u8; 32] = [7u8; 32];
    const SID: &str = "session-test-1";

    #[test]
    fn round_trip_recovers_plaintext() {
        let pt = b"open todos + git anchor: sha=abc123 branch=main milestone=M2";
        let env = seal(&K1, SID, pt).expect("seal");
        assert_eq!(env.v, ENVELOPE_V);
        assert_eq!(env.alg, ENVELOPE_ALG);
        let recovered = open(&K1, SID, &env).expect("open");
        assert_eq!(recovered, pt);
    }

    #[test]
    fn wrong_key_fails_authentication() {
        let env = seal(&K1, SID, b"secret snapshot").expect("seal");
        assert_eq!(open(&K2, SID, &env), Err(SnapshotCryptoError::DecryptFailed));
    }

    #[test]
    fn wrong_session_id_fails_authentication() {
        // Finding 2: the AAD binds session_id. Opening under a different
        // session_id (an old / other-session / substituted-key envelope) fails
        // authentication even under the correct key.
        let env = seal(&K1, "session-A", b"A's working state").expect("seal");
        assert_eq!(
            open(&K1, "session-B", &env),
            Err(SnapshotCryptoError::DecryptFailed),
            "an envelope sealed for session-A must not open as session-B"
        );
        // Same key + same session_id still round-trips.
        assert_eq!(open(&K1, "session-A", &env).expect("open"), b"A's working state");
    }

    #[test]
    fn tampered_ciphertext_fails_authentication() {
        let mut env = seal(&K1, SID, b"secret snapshot").expect("seal");
        // Flip one byte of the ciphertext (decode, mutate, re-encode).
        let mut ct = B64.decode(env.ct.as_bytes()).expect("decode ct");
        ct[0] ^= 0x01;
        env.ct = B64.encode(&ct);
        assert_eq!(open(&K1, SID, &env), Err(SnapshotCryptoError::DecryptFailed));
    }

    #[test]
    fn tampered_nonce_fails_authentication() {
        let mut env = seal(&K1, SID, b"secret snapshot").expect("seal");
        let mut nonce = B64.decode(env.nonce.as_bytes()).expect("decode nonce");
        nonce[0] ^= 0x01;
        env.nonce = B64.encode(&nonce);
        assert_eq!(open(&K1, SID, &env), Err(SnapshotCryptoError::DecryptFailed));
    }

    #[test]
    fn two_seals_of_same_plaintext_use_distinct_nonces() {
        let a = seal(&K1, SID, b"identical").expect("seal a");
        let b = seal(&K1, SID, b"identical").expect("seal b");
        assert_ne!(a.nonce, b.nonce, "random nonce must differ across seals");
        assert_ne!(a.ct, b.ct, "ciphertext must differ when the nonce differs");
    }

    #[test]
    fn unknown_version_is_rejected() {
        let mut env = seal(&K1, SID, b"x").expect("seal");
        env.v = 99;
        assert_eq!(
            open(&K1, SID, &env),
            Err(SnapshotCryptoError::UnknownVersion {
                v: 99,
                alg: ENVELOPE_ALG.to_string()
            })
        );
    }

    #[test]
    fn unknown_alg_is_rejected() {
        let mut env = seal(&K1, SID, b"x").expect("seal");
        env.alg = "aes-256-gcm".to_string();
        assert!(matches!(
            open(&K1, SID, &env),
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
        assert_eq!(open(&K1, SID, &env), Err(SnapshotCryptoError::MalformedEnvelope));

        // Wrong nonce length (valid base64, but not 24 bytes).
        let short = Envelope {
            v: ENVELOPE_V,
            alg: ENVELOPE_ALG.to_string(),
            nonce: B64.encode([0u8; 12]),
            ct: B64.encode(b"junk"),
        };
        assert_eq!(open(&K1, SID, &short), Err(SnapshotCryptoError::MalformedEnvelope));
    }

    #[test]
    fn fact_value_round_trips_and_hides_plaintext() {
        let pt = b"UNIQUE_PLAINTEXT_MARKER_9137";
        let env = seal(&K1, SID, pt).expect("seal");
        let value = env.to_fact_value().expect("to_fact_value");
        // The opaque fact value must not contain the plaintext (ciphertext-only).
        assert!(!value.contains("UNIQUE_PLAINTEXT_MARKER_9137"));
        let parsed = Envelope::from_fact_value(&value).expect("from_fact_value");
        assert_eq!(parsed, env);
        assert_eq!(open(&K1, SID, &parsed).expect("open"), pt);
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
        let env = seal(&k_a, SID, b"cross-device snapshot").expect("seal");
        assert_eq!(open(&k_b, SID, &env).expect("open"), b"cross-device snapshot");
        assert_eq!(open(&k_other, SID, &env), Err(SnapshotCryptoError::DecryptFailed));
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
