// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Vault key recovery and escrow.
//!
//! Three layers, each usable without the next:
//!
//! * **Layer 0 — recovery code.** A 256-bit CSPRNG code derives a wrapping key that wraps
//!   the vault's data encryption key (DEK). The server stores only the wrapped blob and
//!   holds no input to the key derivation, so a full dump of the store is unusable.
//! * **Layer 1 — Shamir 2-of-3 escrow.** The wrapping key is split into three shares: A on
//!   the user's device, B on their printed copy, C held by us. Any two reconstruct; **one
//!   reconstructs nothing**, so our holdings alone are insufficient by construction.
//! * **Layer 2 — release is an operation.** Handing share C back is delayed, notified,
//!   cancellable and receipted. See [`release`].
//!
//! Adversary model and the constraint-to-defence mapping: `docs/THREAT_MODEL.md`,
//! section "Key Escrow and Recovery".
//!
//! Losing both user shares is **unrecoverable by design**. The only way to make it
//! recoverable is for our holdings alone to be sufficient, which is the property this
//! crate exists to prevent.

// This crate holds key material. A panic in a wrap/unwrap path is an availability bug on
// the customer's only route back to their data, and a panic message can carry operands.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

pub mod release;
pub mod verify;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use data_encoding::{Encoding, Specification};
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Crockford base-32: no `I`, `L`, `O` or `U`, so a transcribed code cannot be ambiguous.
const CROCKFORD: &str = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// Symbols in the code body (256 bits / 5 bits per symbol, rounded up).
const BODY_SYMBOLS: usize = 52;
/// Symbols of checksum appended to the body.
const CHECK_SYMBOLS: usize = 2;
/// Symbols per displayed group.
const GROUP: usize = 6;

/// Domain separation for the recovery code -> wrapping key derivation.
///
/// Published deliberately: [`verify`] derives candidate keys under it to show that
/// nothing the server holds opens a vault, and a customer can only reproduce that
/// check if the context string is public.
pub(crate) const KDF_CONTEXT: &str = "cuecrux crux-escrow 2026-08-01 recovery-code wrapping key v1";
/// Domain separation for the transcription checksum.
const CHECKSUM_CONTEXT: &str = "cuecrux crux-escrow 2026-08-01 recovery-code checksum v1";
/// Domain separation for per-share integrity tags.
const SHARE_TAG_CONTEXT: &str = "cuecrux crux-escrow 2026-08-01 escrow share tag v1";

/// Bytes of BLAKE3 output kept as a share's integrity tag.
const SHARE_TAG_LEN: usize = 4;

/// Everything that can go wrong. Deliberately coarse: a caller must not be able to tell a
/// wrong key from a corrupt blob by the error variant alone.
#[derive(Debug, thiserror::Error)]
pub enum EscrowError {
    /// The transcribed code was the wrong length, used a symbol outside the alphabet, or
    /// failed its checksum. One variant on purpose — it is a typo either way.
    #[error("recovery code is not valid (length, alphabet, or checksum)")]
    MalformedCode,
    /// The wrapped blob did not authenticate under this key. Wrong code, wrong shares,
    /// wrong vault, or tampered ciphertext — indistinguishable, by design.
    #[error("could not unwrap: wrong key or altered ciphertext")]
    Unwrap,
    /// A share failed its integrity tag. Caught here rather than silently reconstructing a
    /// wrong key downstream.
    #[error("escrow share {index} is corrupt")]
    CorruptShare {
        /// Position of the offending share in the caller's slice.
        index: usize,
    },
    /// Fewer than the threshold of distinct shares were supplied.
    #[error("need 2 distinct shares to reconstruct, got {got}")]
    NotEnoughShares {
        /// How many usable shares the caller supplied.
        got: usize,
    },
    /// Secret sharing or the AEAD refused the inputs.
    #[error("escrow primitive failed: {0}")]
    Primitive(String),
}

fn crockford() -> Result<&'static Encoding, EscrowError> {
    static ENCODING: OnceLock<Result<Encoding, String>> = OnceLock::new();
    ENCODING
        .get_or_init(|| {
            let mut spec = Specification::new();
            spec.symbols.push_str(CROCKFORD);
            // Crockford's decode leniency: the excluded glyphs map to what they look like.
            spec.translate.from.push_str("ILO");
            spec.translate.to.push_str("110");
            spec.encoding().map_err(|e| e.to_string())
        })
        .as_ref()
        .map_err(|e| EscrowError::Primitive(e.clone()))
}

/// Draw from the thread CSPRNG (OS-seeded ChaCha, periodically reseeded). Key material
/// and nonces come from here and nowhere else.
fn random_bytes<const N: usize>() -> [u8; N] {
    rand::random()
}

/// A 256-bit recovery code. Never serialised, never logged, zeroed on drop.
///
/// [`Self::render`] is the only way to get it out, and it is intended to be shown to the
/// customer exactly once.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RecoveryCode([u8; 32]);

impl std::fmt::Debug for RecoveryCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render key material through Debug — it reaches logs and panic messages.
        f.write_str("RecoveryCode(<redacted>)")
    }
}

impl RecoveryCode {
    /// Draw a fresh code from the OS CSPRNG.
    ///
    /// # Errors
    /// Infallible today; returns `Result` so the AEAD-bearing constructors above it share
    /// one signature.
    pub fn generate() -> Result<Self, EscrowError> {
        Ok(Self(random_bytes()))
    }

    /// Render for transcription: nine groups of six, checksummed.
    ///
    /// # Errors
    /// [`EscrowError::Primitive`] only if the static alphabet is invalid, which is a
    /// build-time impossibility retained rather than panicking.
    pub fn render(&self) -> Result<String, EscrowError> {
        let enc = crockford()?;
        let mut symbols = enc.encode(&self.0);
        symbols.push_str(&self.checksum()?);
        Ok(symbols
            .as_bytes()
            .chunks(GROUP)
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .collect::<Vec<_>>()
            .join("-"))
    }

    /// Parse a transcribed code. Separators and case are ignored; `I`/`L`/`O` are folded to
    /// `1`/`1`/`0` per Crockford.
    ///
    /// # Errors
    /// [`EscrowError::MalformedCode`] for any wrong length, stray symbol, or checksum
    /// mismatch — a single variant so a typo cannot be localised by probing.
    pub fn parse(input: &str) -> Result<Self, EscrowError> {
        let enc = crockford()?;
        // Fold confusables here rather than leaning on the decoder's translate table: the
        // checksum symbols are compared as text and never reach the decoder, so folding
        // only inside `decode` would reject a code whose *check* symbols were transcribed
        // as I/L/O. Normalising the whole string keeps both halves on one rule.
        let cleaned: String = input
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .map(|c| match c.to_ascii_uppercase() {
                'I' | 'L' => '1',
                'O' => '0',
                upper => upper,
            })
            .collect();
        if cleaned.len() != BODY_SYMBOLS + CHECK_SYMBOLS {
            return Err(EscrowError::MalformedCode);
        }
        let (body, check) = cleaned.split_at(BODY_SYMBOLS);
        let decoded = enc.decode(body.as_bytes()).map_err(|_| EscrowError::MalformedCode)?;
        let bytes: [u8; 32] = decoded.try_into().map_err(|_| EscrowError::MalformedCode)?;
        let code = Self(bytes);
        // The checksum is not a secret and a mismatch is not an oracle for anything; a
        // plain compare is correct here.
        if code.checksum()? != check {
            return Err(EscrowError::MalformedCode);
        }
        Ok(code)
    }

    /// Two symbols over the code bytes: a 10-bit check, so it catches a transcription slip
    /// with probability ~1023/1024.
    ///
    /// The residual is deliberate rather than papered over. A wider check would need a
    /// longer code, and the checksum is not the safety property: a typo that slips past it
    /// derives a wrapping key that fails the AEAD tag, so the customer gets "recovery
    /// failed" and never wrong plaintext. The checksum's job is to say so *before* they
    /// go looking for their printed copy. Pinned by `a_typo_never_opens_the_vault`.
    fn checksum(&self) -> Result<String, EscrowError> {
        let enc = crockford()?;
        let digest = blake3::derive_key(CHECKSUM_CONTEXT, &self.0);
        let alphabet = enc.specification().symbols;
        let pick = |b: u8| -> Result<char, EscrowError> {
            alphabet
                .chars()
                .nth((b & 0x1f) as usize)
                .ok_or_else(|| EscrowError::Primitive("alphabet shorter than 32".into()))
        };
        Ok([pick(digest[0])?, pick(digest[1])?].iter().collect())
    }

    /// The wrapping key this code derives. Split by [`split_escrow`], used by [`wrap_dek`].
    fn wrapping_key(&self) -> WrappingKey {
        WrappingKey(blake3::derive_key(KDF_CONTEXT, &self.0))
    }
}

/// The key that wraps a vault's DEK. Derived from a recovery code, or reconstructed from
/// two escrow shares. Never leaves the client in plaintext.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct WrappingKey([u8; 32]);

impl std::fmt::Debug for WrappingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WrappingKey(<redacted>)")
    }
}

/// The only thing the server stores: AEAD ciphertext plus its nonce.
///
/// It carries no key, no salt and no derivation input. A dump of every one of these is
/// unusable without a customer-held code or two escrow shares — asserted by
/// `server_dump_yields_nothing`, not merely claimed.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WrappedDek {
    /// Vault this blob belongs to. Bound as AEAD associated data, so a blob moved to
    /// another vault fails to authenticate.
    pub vault_id: String,
    /// XChaCha20-Poly1305 nonce, 24 bytes, fresh per wrap.
    pub nonce: [u8; 24],
    /// Wrapped DEK with its Poly1305 tag appended.
    pub ciphertext: Vec<u8>,
}

fn aead(key: &WrappingKey) -> Result<XChaCha20Poly1305, EscrowError> {
    XChaCha20Poly1305::new_from_slice(&key.0).map_err(|e| EscrowError::Primitive(e.to_string()))
}

/// Wrap a DEK under a recovery code.
///
/// # Errors
/// [`EscrowError::Primitive`] if the AEAD refuses the inputs.
pub fn wrap_dek(dek: &[u8; 32], vault_id: &str, code: &RecoveryCode) -> Result<WrappedDek, EscrowError> {
    wrap_dek_with_key(dek, vault_id, &code.wrapping_key())
}

/// Wrap a DEK under an already-derived wrapping key.
///
/// # Errors
/// As [`wrap_dek`].
pub fn wrap_dek_with_key(dek: &[u8; 32], vault_id: &str, key: &WrappingKey) -> Result<WrappedDek, EscrowError> {
    let nonce: [u8; 24] = random_bytes();
    let ciphertext = aead(key)?
        .encrypt(
            &nonce.into(),
            Payload {
                msg: dek,
                aad: vault_id.as_bytes(),
            },
        )
        .map_err(|e| EscrowError::Primitive(e.to_string()))?;
    Ok(WrappedDek {
        vault_id: vault_id.to_string(),
        nonce,
        ciphertext,
    })
}

/// Recover a DEK from its wrapped blob using the customer's recovery code.
///
/// # Errors
/// [`EscrowError::Unwrap`] for a wrong code, a blob from another vault, or tampering —
/// the three are not distinguished.
pub fn unwrap_dek(blob: &WrappedDek, code: &RecoveryCode) -> Result<[u8; 32], EscrowError> {
    unwrap_dek_with_key(blob, &code.wrapping_key())
}

/// Recover a DEK from its wrapped blob using a reconstructed wrapping key.
///
/// # Errors
/// As [`unwrap_dek`].
pub fn unwrap_dek_with_key(blob: &WrappedDek, key: &WrappingKey) -> Result<[u8; 32], EscrowError> {
    let mut plain = aead(key)?
        .decrypt(
            &blob.nonce.into(),
            Payload {
                msg: &blob.ciphertext,
                aad: blob.vault_id.as_bytes(),
            },
        )
        .map_err(|_| EscrowError::Unwrap)?;
    let dek: [u8; 32] = plain.as_slice().try_into().map_err(|_| EscrowError::Unwrap)?;
    plain.zeroize();
    Ok(dek)
}

/// A vault whose key has been wrapped but whose recovery code has not yet been shown.
///
/// The wrapped blob is reachable only through [`Self::acknowledge`], so setup cannot be
/// persisted without the customer having been shown their code — the M1 acknowledgement
/// gate, enforced by the type rather than by a code review.
#[derive(Debug)]
pub struct VaultSetup {
    code: RecoveryCode,
    wrapped: WrappedDek,
}

impl VaultSetup {
    /// Wrap `dek` under a freshly generated recovery code.
    ///
    /// # Errors
    /// As [`wrap_dek`].
    pub fn new(dek: &[u8; 32], vault_id: &str) -> Result<Self, EscrowError> {
        let code = RecoveryCode::generate()?;
        let wrapped = wrap_dek(dek, vault_id, &code)?;
        Ok(Self { code, wrapped })
    }

    /// The code to display, once.
    ///
    /// # Errors
    /// As [`RecoveryCode::render`].
    pub fn recovery_code(&self) -> Result<String, EscrowError> {
        self.code.render()
    }

    /// Borrow the code to derive escrow shares before acknowledgement.
    #[must_use]
    pub fn code(&self) -> &RecoveryCode {
        &self.code
    }

    /// Confirm the customer acknowledged the code, yielding the blob to store. Consumes
    /// the setup, dropping (and zeroing) the code with it.
    #[must_use]
    pub fn acknowledge(self) -> WrappedDek {
        self.wrapped
    }
}

/// One share of a 2-of-3 split. Opaque bytes plus an integrity tag.
///
/// Serialised for the printed copy and for share C's custody store. Holding **one** of
/// these reveals nothing about the wrapping key.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EscrowShare {
    /// Which holder this share is for. Carried for operations, not for security — the
    /// threshold does not depend on it.
    pub holder: ShareHolder,
    /// Shamir share bytes with a trailing BLAKE3 integrity tag.
    pub bytes: Vec<u8>,
}

/// Who holds a share. Exactly one of the three is ours.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ShareHolder {
    /// Share A — the user's device keychain or daemon data dir.
    Device,
    /// Share B — the user's printed offline copy.
    Printed,
    /// Share C — us, in Vault/HSM custody. Non-exportable; released only via [`release`].
    Custodian,
}

/// Split a recovery code's wrapping key into three shares, any two of which reconstruct it.
///
/// # Errors
/// [`EscrowError::Primitive`] if the split fails. Never returns a partial set.
pub fn split_escrow(code: &RecoveryCode) -> Result<[EscrowShare; 3], EscrowError> {
    split_wrapping_key(&code.wrapping_key())
}

/// Split an already-derived wrapping key into three shares.
///
/// # Errors
/// As [`split_escrow`].
pub fn split_wrapping_key(key: &WrappingKey) -> Result<[EscrowShare; 3], EscrowError> {
    let raw =
        vsss_rs::Gf256::split_bytes(2, 3, key.0, rand::rng()).map_err(|e| EscrowError::Primitive(format!("{e:?}")))?;

    let holders = [ShareHolder::Device, ShareHolder::Printed, ShareHolder::Custodian];
    let mut out = Vec::with_capacity(3);
    for (holder, share) in holders.into_iter().zip(raw) {
        let mut bytes = share;
        bytes.extend_from_slice(&share_tag(&bytes));
        out.push(EscrowShare { holder, bytes });
    }
    out.try_into()
        .map_err(|_| EscrowError::Primitive("split did not produce 3 shares".into()))
}

/// Reconstruct the wrapping key from any two shares.
///
/// # Errors
/// [`EscrowError::CorruptShare`] if a share fails its integrity tag — checked before
/// reconstruction, so a corrupt share can never silently yield a wrong key.
/// [`EscrowError::NotEnoughShares`] if fewer than two distinct shares are supplied.
pub fn combine_shares(shares: &[EscrowShare]) -> Result<WrappingKey, EscrowError> {
    let mut verified: Vec<Vec<u8>> = Vec::with_capacity(shares.len());
    for (index, share) in shares.iter().enumerate() {
        let Some(split) = share.bytes.len().checked_sub(SHARE_TAG_LEN) else {
            return Err(EscrowError::CorruptShare { index });
        };
        let (body, tag) = share.bytes.split_at(split);
        if share_tag(body) != tag {
            return Err(EscrowError::CorruptShare { index });
        }
        // Two copies of the same share are one share; Shamir would otherwise reconstruct
        // garbage from a duplicated point.
        if !verified.iter().any(|v| v == body) {
            verified.push(body.to_vec());
        }
    }
    if verified.len() < 2 {
        return Err(EscrowError::NotEnoughShares { got: verified.len() });
    }
    let combined = vsss_rs::Gf256::combine_bytes(&verified).map_err(|e| EscrowError::Primitive(format!("{e:?}")))?;
    let key: [u8; 32] = combined
        .as_slice()
        .try_into()
        .map_err(|_| EscrowError::Primitive("reconstructed key was not 32 bytes".into()))?;
    Ok(WrappingKey(key))
}

fn share_tag(body: &[u8]) -> [u8; SHARE_TAG_LEN] {
    let digest = blake3::derive_key(SHARE_TAG_CONTEXT, body);
    let mut tag = [0u8; SHARE_TAG_LEN];
    tag.copy_from_slice(&digest[..SHARE_TAG_LEN]);
    tag
}

#[cfg(test)]
mod tests;
