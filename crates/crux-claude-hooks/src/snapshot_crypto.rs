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
//! - **AAD binding (envelope v3):** every seal/open binds canonical
//!   additional-authenticated-data `{v, alg, entity, passport_scope, session_id,
//!   counter}` (fixed struct-field order → byte-identical reconstruction). This
//!   ties a ciphertext to the scheme, the fact carrier, the passport it belongs
//!   to, the writing session, and its monotonic counter — so tampering with any
//!   of those fields fails authentication (crypto-review Finding 2 redesign). On
//!   `open` the AAD is reconstructed from the envelope's *own* authenticated
//!   fields (after `v`/`alg` are validated); the caller then applies policy over
//!   the now-authentic `passport_scope`/`counter` (this-passport filter +
//!   high-water rollback check). A mismatch is indistinguishable from a wrong key.
//!
//! - **Cross-device restore (v3, F2 redesign — support both flows):** the reader
//!   supports (i) *same-session resume* — a snapshot whose bound `session_id`
//!   equals the current session — and (ii) *fresh-session pickup* — the newest
//!   snapshot for this passport (highest `counter`) that authenticates and is
//!   strictly newer than the persisted [`HighWater`] mark. The counter + a local
//!   high-water mark are what make "latest for this passport" trustworthy: an
//!   attacker who replays an old ciphertext cannot advance the counter (it is in
//!   the AAD), and the reader rejects anything at/below what it has already
//!   accepted. `passport_scope` is the passport public-key fingerprint — 1:1 with
//!   the seed, computable locally by the reader, used both to bind and to select
//!   "this passport's" snapshots.

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

/// Whether hosted encrypted snapshot sync is explicitly enabled (Finding 6).
///
/// Strict default-OFF opt-in shared by the store (PreCompact) and restore
/// (SessionStart) paths: only `CRUX_COMPACTION_SYNC=1|on` turns it on; `0`,
/// `off`, and unset are all off. Deliberately NOT derived from `sync_status` —
/// the previous auto-enable let an unset flag silently probe the daemon and turn
/// hosted egress on. Checked BEFORE any key derivation or network op, so the
/// free/local path (flag unset) does zero extra work. The Pro mirror
/// configuration remains the product-posture gate on the daemon side.
#[must_use]
pub fn hosted_sync_enabled() -> bool {
    matches!(std::env::var("CRUX_COMPACTION_SYNC").as_deref(), Ok("1" | "on"))
}

/// Domain-separation label for the snapshot content key (BLAKE3 KDF context).
/// The `v1` suffix tracks the *key-derivation* scheme, which is unchanged: it
/// moves only if the seed→key derivation changes, NOT when [`ENVELOPE_V`] bumps
/// (the v1→v2→v3 envelope bumps changed AAD binding only, never the KDF, so the
/// derived key — and any device pairing — stays stable).
pub const SNAPSHOT_KEY_CONTEXT: &str = "crux/compaction-snapshot/v1";

/// Current envelope version. [`open`] rejects anything else.
///
/// v3 (crypto-review Finding 2 redesign) binds canonical AAD `{v, alg, entity,
/// passport_scope, session_id, counter}` and carries `passport_scope`/
/// `session_id`/`counter` in the envelope so the reader can select "this
/// passport's latest" and reject rollbacks. v1 (no AAD) and v2 (`{v, alg,
/// entity, session_id}`) are intentionally unreadable by this build — the
/// feature was never enabled, so there are no persisted v1/v2 blobs and no
/// migration path is needed. The KDF label is unchanged, so derived keys are
/// stable across the version bump.
pub const ENVELOPE_V: u8 = 3;

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
///
/// `passport_scope`, `session_id`, and `counter` are carried in the clear
/// (they are metadata, not secrets) so the reader can select candidates and
/// reconstruct the AAD — but they are all bound into the AEAD's AAD, so any
/// tampering with them fails authentication just like a wrong key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Envelope {
    pub v: u8,
    pub alg: String,
    /// Passport public-key fingerprint the snapshot belongs to (1:1 with seed).
    pub passport_scope: String,
    /// Session id the snapshot was sealed under (the writing session).
    pub session_id: String,
    /// Per-passport monotonic-ish counter (rollback / "latest" ordering).
    pub counter: u64,
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
/// ciphertext to the scheme (`v`, `alg`), the fact carrier (`entity`), the
/// passport it belongs to (`passport_scope`), the session it was sealed under
/// (`session_id`), and its monotonic `counter`. Serialized deterministically
/// (fixed struct-field order, no maps) so `seal` and `open` produce identical
/// bytes for the same inputs — a byte-for-byte AAD reconstruction is required or
/// authentication fails.
#[derive(Serialize)]
struct SnapshotAad<'a> {
    v: u8,
    alg: &'a str,
    entity: &'a str,
    passport_scope: &'a str,
    session_id: &'a str,
    counter: u64,
}

/// Build the canonical AAD bytes under the current scheme. `v`/`alg`/`entity`
/// are the fixed scheme constants; `passport_scope`/`session_id`/`counter` are
/// the per-snapshot bindings.
fn snapshot_aad(passport_scope: &str, session_id: &str, counter: u64) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(&SnapshotAad {
        v: ENVELOPE_V,
        alg: ENVELOPE_ALG,
        entity: SNAPSHOT_ENTITY,
        passport_scope,
        session_id,
        counter,
    })
}

/// Seal `plaintext` under `key` with a fresh random nonce, binding canonical AAD
/// `{v, alg, entity, passport_scope, session_id, counter}` (envelope v3). The
/// three bindings are also stored in the returned [`Envelope`] so the reader can
/// select candidates and reconstruct the AAD; `open` re-derives the AAD from
/// those authenticated fields, so tampering with any of them fails auth.
///
/// # Errors
/// Returns an error only if AAD serialization or the AEAD encrypt fails
/// (allocation/programmer error); the hook treats this as best-effort and skips.
pub fn seal(
    key: &[u8; 32],
    passport_scope: &str,
    session_id: &str,
    counter: u64,
    plaintext: &[u8],
) -> anyhow::Result<Envelope> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce_bytes = [0u8; NONCE_BYTES];
    rand::rng().fill_bytes(&mut nonce_bytes);
    // `nonce_bytes` is a fixed 24-byte array, so `try_from` never errors here;
    // handled as a Result anyway to stay panic/expect-free (crate lints deny both).
    let nonce = XNonce::try_from(&nonce_bytes[..]).map_err(|_| anyhow::anyhow!("snapshot seal: nonce length"))?;
    let aad =
        snapshot_aad(passport_scope, session_id, counter).map_err(|e| anyhow::anyhow!("snapshot seal: aad: {e}"))?;
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
        passport_scope: passport_scope.to_string(),
        session_id: session_id.to_string(),
        counter,
        nonce: B64.encode(nonce_bytes),
        ct: B64.encode(ct),
    })
}

/// Open `envelope` under `key`, returning the recovered plaintext. The AAD `{v,
/// alg, entity, passport_scope, session_id, counter}` is reconstructed from the
/// envelope's *own* declared bindings (after `v`/`alg` are validated) and must
/// match what was sealed: tampering with any bound field — `passport_scope`,
/// `session_id`, or `counter` — fails authentication just like a wrong key.
///
/// This authenticates the envelope's internal consistency; the caller is
/// responsible for policy over the now-authentic fields (is `passport_scope`
/// mine? is `counter` newer than my high-water mark? is `session_id` the current
/// session?). See the restore selection in `cmds::session_start`.
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
    let aad = snapshot_aad(&envelope.passport_scope, &envelope.session_id, envelope.counter)
        .map_err(|_| SnapshotCryptoError::MalformedEnvelope)?;
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

/// True when `CRUX_AGENT_TOKEN` (the server-visible bearer credential) equals
/// the passport seed in any canonical representation — lowercase/uppercase hex,
/// or standard base64 of the decoded seed (Finding 5).
///
/// Reusing the seed as the bearer would hand the server the exact material the
/// snapshot key is derived from, voiding "unreadable to us". Callers refuse to
/// enable hosted sync when this returns true. Neither value is logged; both are
/// held in [`Zeroizing`] while compared.
#[must_use]
pub fn bearer_reuses_passport_seed() -> bool {
    let Some(token) = std::env::var("CRUX_AGENT_TOKEN").ok().filter(|s| !s.is_empty()) else {
        return false;
    };
    let token = Zeroizing::new(token);
    let Some(path) = passport_key_path_from_env() else {
        return false;
    };
    let Ok(raw) = std::fs::read_to_string(&path) else {
        return false;
    };
    let raw = Zeroizing::new(raw);
    let seed_hex = raw.trim();
    if seed_hex.is_empty() {
        return false;
    }
    // Hex form: the file is lowercase, but a reused token might be uppercased.
    if token.trim().eq_ignore_ascii_case(seed_hex) {
        return true;
    }
    // Standard base64 of the decoded seed bytes.
    if let Ok(bytes) = hex::decode(seed_hex) {
        let bytes = Zeroizing::new(bytes);
        let b64 = Zeroizing::new(B64.encode(bytes.as_slice()));
        if token.trim() == b64.as_str() {
            return true;
        }
    }
    false
}

/// A derived snapshot content key plus the passport scope it belongs to.
///
/// `scope` is the passport public-key fingerprint (public, non-secret): it is
/// bound into every envelope's AAD, used to select "this passport's" snapshots
/// on restore, and used as the per-passport high-water key. `key` is the actual
/// 32-byte content key in a [`Zeroizing`] wrapper (wiped on drop);
/// `Zeroizing<[u8; 32]>` derefs to `[u8; 32]`, so callers pass `&dk.key`
/// unchanged to [`seal`] / [`open`] via deref coercion.
///
// ponytail: this zeroizes the *derived* key. The passport *seed* itself still
// lives unzeroized inside `crux_session::LocalPassportKey` (shared crate, every
// `derive_subkey` caller) — a broader hardening tracked separately, out of scope
// for this hook-local key path.
pub struct DerivedSnapshotKey {
    pub scope: String,
    pub key: Zeroizing<[u8; 32]>,
}

/// Derive the snapshot content key + passport scope from the passport seed, if a
/// passport-key file is configured AND already exists on disk.
///
/// Returns `None` — never an error, never a side effect — when no seed is
/// available, so the caller silently skips hosted sync (free/local path). The
/// seed file is only ever *read*: this never creates a fresh seed, because a
/// freshly-minted seed on device B would differ from device A and silently break
/// cross-device decrypt. `from_existing_path` does one direct open (Finding 4) —
/// no `is_file()`+`from_path` TOCTOU that could mint a fresh, non-matching seed.
#[must_use]
pub fn derive_snapshot_key() -> Option<DerivedSnapshotKey> {
    let path = passport_key_path_from_env()?;
    let passport = crux_session::LocalPassportKey::from_existing_path(&path).ok()?;
    Some(DerivedSnapshotKey {
        scope: passport.passport_fpr().to_string(),
        key: Zeroizing::new(passport.derive_subkey(SNAPSHOT_KEY_CONTEXT)),
    })
}

/// Next per-passport counter for a snapshot: a wall-clock timestamp in
/// nanoseconds since the epoch.
///
/// Chosen as the simplest correct monotonic-ish source (time IS available in the
/// real hook binary): it advances on every write without any persisted counter
/// state, and orders snapshots across devices by real write time — which is
/// exactly the notion of "latest" the restore path wants. `u128` nanos truncate
/// to `u64` safely for centuries.
///
/// Residual (documented follow-up, not a correctness hole for the threat model):
/// a backward wall-clock step, or two writes within the same nanosecond, could
/// produce a non-increasing counter on one device; across devices the ordering
/// assumes NTP-synced clocks. The reader breaks exact ties deterministically by
/// `session_id`, and the AAD binding means an attacker still cannot forge or
/// advance a counter. A hard per-device logical counter is the upgrade path.
#[must_use]
pub fn next_counter() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// Persisted per-passport high-water state for rollback / replay defence.
///
/// `FirstRun` (no state yet) and `Mark(n)` are usable; `Corrupt` (the file
/// exists but is unreadable/unparseable) means the reader must fail toward
/// *no restore* this boot rather than trust a value it cannot read.
#[derive(Debug, PartialEq, Eq)]
pub enum HighWater {
    /// No high-water file yet — legitimate first run; treat as 0 (restore allowed).
    FirstRun,
    /// Highest counter this device has accepted for the passport.
    Mark(u64),
    /// File present but unreadable/unparseable — fail toward no restore.
    Corrupt,
}

#[derive(Serialize, Deserialize)]
struct HighWaterFile {
    high_water: u64,
}

/// Durable per-passport high-water file path, next to the passport key (NOT in
/// `TMPDIR`, which resets on reboot and would re-open the rollback window).
/// `None` when no passport-key path is configured (then there is no seed either,
/// so restore has already skipped). Scope is sanitised for use as a filename.
fn high_water_path(scope: &str) -> Option<PathBuf> {
    let dir = passport_key_path_from_env()?.parent()?.to_path_buf();
    let safe: String = scope
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(64)
        .collect();
    let name = if safe.is_empty() { "default" } else { safe.as_str() };
    Some(dir.join(format!("compaction-snapshot-hw-{name}.json")))
}

/// Load the persisted high-water mark for `scope`. Missing file ⇒ `FirstRun`;
/// a readable, parseable file ⇒ `Mark(n)`; anything else ⇒ `Corrupt`. Never
/// panics.
#[must_use]
pub fn load_high_water(scope: &str) -> HighWater {
    let Some(path) = high_water_path(scope) else {
        return HighWater::FirstRun;
    };
    match std::fs::read_to_string(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => HighWater::FirstRun,
        Err(_) => HighWater::Corrupt,
        Ok(s) => match serde_json::from_str::<HighWaterFile>(&s) {
            Ok(f) => HighWater::Mark(f.high_water),
            Err(_) => HighWater::Corrupt,
        },
    }
}

/// Persist `counter` as the high-water mark for `scope` iff it advances the
/// mark (monotonic; never lowers it). Best-effort: a write failure is logged and
/// ignored — it degrades rollback strictness for one boot but never crashes the
/// hook. A `Corrupt`/missing prior state is treated as 0, so this also self-heals
/// a corrupt file back to a usable value.
pub fn advance_high_water(scope: &str, counter: u64) {
    let Some(path) = high_water_path(scope) else {
        return;
    };
    let current = match load_high_water(scope) {
        HighWater::Mark(n) => n,
        HighWater::FirstRun | HighWater::Corrupt => 0,
    };
    let next = current.max(counter);
    let body = serde_json::json!({ "high_water": next }).to_string();
    if let Err(err) = std::fs::write(&path, body) {
        eprintln!("crux-hook: persist snapshot high-water failed (rollback strictness degraded this boot): {err}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const K1: [u8; 32] = [42u8; 32];
    const K2: [u8; 32] = [7u8; 32];
    const SCOPE: &str = "passport-fpr-aaaa";
    const SID: &str = "session-test-1";
    const CTR: u64 = 1_700_000_000_000_000_001;

    fn seal_t(key: &[u8; 32], pt: &[u8]) -> Envelope {
        seal(key, SCOPE, SID, CTR, pt).expect("seal")
    }

    #[test]
    fn round_trip_recovers_plaintext() {
        let pt = b"open todos + git anchor: sha=abc123 branch=main milestone=M2";
        let env = seal_t(&K1, pt);
        assert_eq!(env.v, ENVELOPE_V);
        assert_eq!(env.alg, ENVELOPE_ALG);
        assert_eq!(env.passport_scope, SCOPE);
        assert_eq!(env.session_id, SID);
        assert_eq!(env.counter, CTR);
        let recovered = open(&K1, &env).expect("open");
        assert_eq!(recovered, pt);
    }

    #[test]
    fn wrong_key_fails_authentication() {
        let env = seal_t(&K1, b"secret snapshot");
        assert_eq!(open(&K2, &env), Err(SnapshotCryptoError::DecryptFailed));
    }

    #[test]
    fn tampered_session_id_fails_authentication() {
        // v3 AAD binds session_id: relabelling the envelope's session_id (e.g. an
        // attacker trying to pass an old snapshot off as the current session)
        // fails authentication even under the correct key.
        let mut env = seal_t(&K1, b"A's working state");
        assert_eq!(open(&K1, &env).expect("open"), b"A's working state");
        env.session_id = "session-B".to_string();
        assert_eq!(
            open(&K1, &env),
            Err(SnapshotCryptoError::DecryptFailed),
            "relabelling session_id must fail auth (bound in AAD)"
        );
    }

    #[test]
    fn tampered_passport_scope_fails_authentication() {
        // v3 AAD binds passport_scope: an attacker cannot relabel a foreign
        // snapshot with a different scope to slip past the reader's passport filter.
        let mut env = seal_t(&K1, b"state");
        env.passport_scope = "someone-elses-fpr".to_string();
        assert_eq!(open(&K1, &env), Err(SnapshotCryptoError::DecryptFailed));
    }

    #[test]
    fn tampered_counter_fails_authentication() {
        // v3 AAD binds counter: an attacker replaying an old blob cannot bump its
        // counter to defeat the high-water rollback check without breaking auth.
        let mut env = seal_t(&K1, b"state");
        env.counter = env.counter.wrapping_add(10_000);
        assert_eq!(open(&K1, &env), Err(SnapshotCryptoError::DecryptFailed));
    }

    #[test]
    fn tampered_ciphertext_fails_authentication() {
        let mut env = seal_t(&K1, b"secret snapshot");
        // Flip one byte of the ciphertext (decode, mutate, re-encode).
        let mut ct = B64.decode(env.ct.as_bytes()).expect("decode ct");
        ct[0] ^= 0x01;
        env.ct = B64.encode(&ct);
        assert_eq!(open(&K1, &env), Err(SnapshotCryptoError::DecryptFailed));
    }

    #[test]
    fn tampered_nonce_fails_authentication() {
        let mut env = seal_t(&K1, b"secret snapshot");
        let mut nonce = B64.decode(env.nonce.as_bytes()).expect("decode nonce");
        nonce[0] ^= 0x01;
        env.nonce = B64.encode(&nonce);
        assert_eq!(open(&K1, &env), Err(SnapshotCryptoError::DecryptFailed));
    }

    #[test]
    fn two_seals_of_same_plaintext_use_distinct_nonces() {
        let a = seal_t(&K1, b"identical");
        let b = seal_t(&K1, b"identical");
        assert_ne!(a.nonce, b.nonce, "random nonce must differ across seals");
        assert_ne!(a.ct, b.ct, "ciphertext must differ when the nonce differs");
    }

    #[test]
    fn unknown_version_is_rejected() {
        let mut env = seal_t(&K1, b"x");
        env.v = 99;
        assert_eq!(
            open(&K1, &env),
            Err(SnapshotCryptoError::UnknownVersion {
                v: 99,
                alg: ENVELOPE_ALG.to_string()
            })
        );
    }

    #[test]
    fn unknown_alg_is_rejected() {
        let mut env = seal_t(&K1, b"x");
        env.alg = "aes-256-gcm".to_string();
        assert!(matches!(
            open(&K1, &env),
            Err(SnapshotCryptoError::UnknownVersion { .. })
        ));
    }

    fn envelope_with(nonce: String, ct: String) -> Envelope {
        Envelope {
            v: ENVELOPE_V,
            alg: ENVELOPE_ALG.to_string(),
            passport_scope: SCOPE.to_string(),
            session_id: SID.to_string(),
            counter: CTR,
            nonce,
            ct,
        }
    }

    #[test]
    fn malformed_envelope_is_rejected_not_panicked() {
        let env = envelope_with("not-base64!!".to_string(), "also!!bad".to_string());
        assert_eq!(open(&K1, &env), Err(SnapshotCryptoError::MalformedEnvelope));

        // Wrong nonce length (valid base64, but not 24 bytes).
        let short = envelope_with(B64.encode([0u8; 12]), B64.encode(b"junk"));
        assert_eq!(open(&K1, &short), Err(SnapshotCryptoError::MalformedEnvelope));
    }

    #[test]
    fn fact_value_round_trips_and_hides_plaintext() {
        let pt = b"UNIQUE_PLAINTEXT_MARKER_9137";
        let env = seal_t(&K1, pt);
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

    #[test]
    fn aad_is_deterministic_and_canonically_ordered() {
        // AAD reconstruction must be byte-identical or authentication fails. The
        // `SnapshotAad` struct serializes fields in declaration order (no map
        // sorting, no nondeterminism), so identical inputs → identical bytes.
        let a = snapshot_aad("fpr-x", "sess-y", 77).expect("aad");
        let b = snapshot_aad("fpr-x", "sess-y", 77).expect("aad");
        assert_eq!(a, b, "AAD must be byte-identical for identical inputs");

        let s = String::from_utf8(a).expect("utf8");
        let order = [
            "\"v\"",
            "\"alg\"",
            "\"entity\"",
            "\"passport_scope\"",
            "\"session_id\"",
            "\"counter\"",
        ];
        let mut last = 0usize;
        for field in order {
            let pos = s
                .find(field)
                .unwrap_or_else(|| panic!("AAD missing field {field}: {s}"));
            assert!(pos >= last, "AAD field {field} out of canonical order: {s}");
            last = pos;
        }

        // Every bound field participates: changing any one changes the AAD bytes.
        assert_ne!(
            snapshot_aad("fpr-x", "sess-y", 78).unwrap(),
            snapshot_aad("fpr-x", "sess-y", 77).unwrap()
        );
        assert_ne!(
            snapshot_aad("fpr-z", "sess-y", 77).unwrap(),
            snapshot_aad("fpr-x", "sess-y", 77).unwrap()
        );
        assert_ne!(
            snapshot_aad("fpr-x", "sess-z", 77).unwrap(),
            snapshot_aad("fpr-x", "sess-y", 77).unwrap()
        );
    }

    #[test]
    fn next_counter_is_nonzero_and_nondecreasing() {
        let a = next_counter();
        let b = next_counter();
        assert!(a > 0, "wall-clock counter must be non-zero");
        assert!(b >= a, "counter must be non-decreasing within a run");
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
        let env = seal(&k_a, SCOPE, SID, CTR, b"cross-device snapshot").expect("seal");
        assert_eq!(open(&k_b, &env).expect("open"), b"cross-device snapshot");
        assert_eq!(open(&k_other, &env), Err(SnapshotCryptoError::DecryptFailed));
    }

    #[test]
    fn high_water_round_trips_and_only_advances() {
        let _env = crate::test_support::env_guard();
        let prev = std::env::var("CRUX_PASSPORT_KEY_PATH").ok();
        let tmp = tempfile::tempdir().unwrap();
        let key_file = tmp.path().join("passport.key");
        std::fs::write(&key_file, "aa".repeat(32)).unwrap();
        std::env::set_var("CRUX_PASSPORT_KEY_PATH", &key_file);
        let scope = "scope-hw-test";

        // Missing file ⇒ FirstRun.
        assert_eq!(load_high_water(scope), HighWater::FirstRun);
        advance_high_water(scope, 100);
        assert_eq!(load_high_water(scope), HighWater::Mark(100));
        // Lower value must not lower the mark.
        advance_high_water(scope, 50);
        assert_eq!(load_high_water(scope), HighWater::Mark(100));
        // Higher value advances it.
        advance_high_water(scope, 250);
        assert_eq!(load_high_water(scope), HighWater::Mark(250));

        // Corrupt file ⇒ Corrupt (fail toward no restore).
        let path = high_water_path(scope).unwrap();
        std::fs::write(&path, "{ not json").unwrap();
        assert_eq!(load_high_water(scope), HighWater::Corrupt);
        // advance() self-heals a corrupt file back to a usable value.
        advance_high_water(scope, 300);
        assert_eq!(load_high_water(scope), HighWater::Mark(300));

        match prev {
            Some(v) => std::env::set_var("CRUX_PASSPORT_KEY_PATH", v),
            None => std::env::remove_var("CRUX_PASSPORT_KEY_PATH"),
        }
    }

    #[test]
    fn bearer_reuses_passport_seed_detects_hex_and_base64() {
        // Finding 5: reject CRUX_AGENT_TOKEN == passport seed in any canonical form.
        let _env = crate::test_support::env_guard();
        let prev_tok = std::env::var("CRUX_AGENT_TOKEN").ok();
        let prev_path = std::env::var("CRUX_PASSPORT_KEY_PATH").ok();

        let seed = [0x5au8; 32];
        let seed_hex = hex::encode(seed);
        let key_file = std::env::temp_dir().join(format!("f5-seed-{}.key", rand::random::<u64>()));
        std::fs::write(&key_file, &seed_hex).unwrap();
        std::env::set_var("CRUX_PASSPORT_KEY_PATH", &key_file);

        // Hex reuse (lowercase and uppercase) is caught.
        std::env::set_var("CRUX_AGENT_TOKEN", &seed_hex);
        assert!(bearer_reuses_passport_seed(), "lowercase hex seed reuse must be caught");
        std::env::set_var("CRUX_AGENT_TOKEN", seed_hex.to_uppercase());
        assert!(bearer_reuses_passport_seed(), "uppercase hex seed reuse must be caught");

        // Base64-of-seed reuse is caught.
        std::env::set_var("CRUX_AGENT_TOKEN", B64.encode(seed));
        assert!(bearer_reuses_passport_seed(), "base64 seed reuse must be caught");

        // A distinct bearer is fine.
        std::env::set_var("CRUX_AGENT_TOKEN", "totally-unrelated-bearer-token-000000");
        assert!(
            !bearer_reuses_passport_seed(),
            "an unrelated bearer must not trip the guard"
        );

        // No token ⇒ not a conflict.
        std::env::remove_var("CRUX_AGENT_TOKEN");
        assert!(!bearer_reuses_passport_seed());

        std::fs::remove_file(&key_file).ok();
        match prev_tok {
            Some(v) => std::env::set_var("CRUX_AGENT_TOKEN", v),
            None => std::env::remove_var("CRUX_AGENT_TOKEN"),
        }
        match prev_path {
            Some(v) => std::env::set_var("CRUX_PASSPORT_KEY_PATH", v),
            None => std::env::remove_var("CRUX_PASSPORT_KEY_PATH"),
        }
    }

    #[test]
    fn hosted_sync_enabled_is_strict_opt_in() {
        // Finding 6: only 1|on enable; 0, off, and unset are all off. No daemon
        // probe happens either way (this runs with no daemon).
        let _env = crate::test_support::env_guard();
        let prev = std::env::var("CRUX_COMPACTION_SYNC").ok();
        for (val, want) in [("1", true), ("on", true), ("0", false), ("off", false)] {
            std::env::set_var("CRUX_COMPACTION_SYNC", val);
            assert_eq!(hosted_sync_enabled(), want, "CRUX_COMPACTION_SYNC={val}");
        }
        std::env::remove_var("CRUX_COMPACTION_SYNC");
        assert!(!hosted_sync_enabled(), "unset must be off (no auto-enable)");
        match prev {
            Some(v) => std::env::set_var("CRUX_COMPACTION_SYNC", v),
            None => std::env::remove_var("CRUX_COMPACTION_SYNC"),
        }
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
