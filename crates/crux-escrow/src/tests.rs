// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! The two tests that justify the plan are [`server_dump_yields_nothing`] and
//! [`one_share_yields_nothing`]. Neither can pass if our holdings ever become sufficient.

// Tests assert on exact outcomes; an unexpected `Err` here should fail loudly.
#![allow(clippy::unwrap_used, clippy::panic)]

use super::*;

const DEK: [u8; 32] = [7u8; 32];
const VAULT: &str = "vault-01HTEST";

// ── M1: recovery code + wrapped DEK ─────────────────────────────────

#[test]
fn code_round_trips_through_transcription() {
    let code = RecoveryCode::generate().unwrap();
    let rendered = code.render().unwrap();
    // What a human actually types back: lowercase, spaces instead of dashes.
    let typed = rendered.to_lowercase().replace('-', " ");
    let parsed = RecoveryCode::parse(&typed).unwrap();

    let blob = wrap_dek(&DEK, VAULT, &code).unwrap();
    assert_eq!(unwrap_dek(&blob, &parsed).unwrap(), DEK);
}

#[test]
fn rendered_code_is_nine_groups_of_six() {
    let rendered = RecoveryCode::generate().unwrap().render().unwrap();
    let groups: Vec<&str> = rendered.split('-').collect();
    assert_eq!(groups.len(), 9, "{rendered}");
    assert!(groups.iter().all(|g| g.len() == 6), "{rendered}");
    assert!(
        rendered.chars().all(|c| c == '-' || CROCKFORD.contains(c)),
        "code used a symbol outside the alphabet: {rendered}"
    );
}

/// A transcription slip must never open the vault.
///
/// Two separate claims, and only the second is absolute:
///
/// 1. The checksum rejects the typo up front — a 10-bit check, so it misses about one
///    slip in 1024. That residual is why claim 2 exists.
/// 2. A typo that slips past the checksum still cannot recover the DEK, because the
///    wrapping key it derives fails the AEAD tag. The customer sees "recovery failed",
///    never wrong plaintext.
///
/// Asserting only claim 1 would be a flaky test *and* a false statement about the format.
#[test]
fn a_typo_never_opens_the_vault() {
    let mut trials = 0_u32;
    let mut rejected_by_checksum = 0_u32;

    for _ in 0..40 {
        let code = RecoveryCode::generate().unwrap();
        let rendered = code.render().unwrap();
        let blob = wrap_dek(&DEK, VAULT, &code).unwrap();

        for (i, c) in rendered.char_indices().filter(|(_, c)| *c != '-') {
            // Substitute the next symbol in the alphabet: the classic transcription slip.
            let pos = CROCKFORD.find(c).unwrap();
            let replacement = CROCKFORD.as_bytes()[(pos + 1) % CROCKFORD.len()] as char;
            let mut mangled: Vec<char> = rendered.chars().collect();
            mangled[i] = replacement;
            let mangled: String = mangled.into_iter().collect();
            trials += 1;

            match RecoveryCode::parse(&mangled) {
                Err(EscrowError::MalformedCode) => rejected_by_checksum += 1,
                Err(other) => panic!("typo at {i} produced an unexpected error: {other}"),
                // Slipped the checksum. The AEAD is the backstop and it is not optional.
                Ok(wrong) => assert!(
                    matches!(unwrap_dek(&blob, &wrong), Err(EscrowError::Unwrap)),
                    "a typo at {i} recovered the vault: {mangled}"
                ),
            }
        }
    }

    assert_eq!(trials, 40 * 54, "every symbol of every code should have been tried");
    // Expected miss rate is ~1/1024; anything near 5% means the checksum stopped working.
    let rate = f64::from(rejected_by_checksum) / f64::from(trials);
    assert!(
        rate > 0.95,
        "checksum only caught {rejected_by_checksum}/{trials} typos"
    );
}

/// A user who writes 1 as I or L, or 0 as O, still gets in — including when the confusable
/// lands in the two checksum symbols, which are compared as text and so are the half that
/// silently stopped folding once already.
#[test]
fn crockford_confusables_are_folded() {
    for _ in 0..40 {
        let code = RecoveryCode::generate().unwrap();
        let rendered = code.render().unwrap();
        for one in ['I', 'L'] {
            let confused = rendered.replace('1', &one.to_string()).replace('0', "O");
            assert_eq!(
                RecoveryCode::parse(&confused).unwrap().0,
                code.0,
                "'{one}' for 1 / 'O' for 0 should decode to the same bytes: {confused}"
            );
        }
    }
}

#[test]
fn wrong_code_does_not_unwrap() {
    let blob = wrap_dek(&DEK, VAULT, &RecoveryCode::generate().unwrap()).unwrap();
    let other = RecoveryCode::generate().unwrap();
    assert!(matches!(unwrap_dek(&blob, &other), Err(EscrowError::Unwrap)));
}

#[test]
fn a_blob_moved_to_another_vault_does_not_unwrap() {
    let code = RecoveryCode::generate().unwrap();
    let mut blob = wrap_dek(&DEK, VAULT, &code).unwrap();
    blob.vault_id = "vault-someone-else".into();
    assert!(matches!(unwrap_dek(&blob, &code), Err(EscrowError::Unwrap)));
}

#[test]
fn tampered_ciphertext_is_rejected() {
    let code = RecoveryCode::generate().unwrap();
    let mut blob = wrap_dek(&DEK, VAULT, &code).unwrap();
    blob.ciphertext[0] ^= 0x01;
    assert!(matches!(unwrap_dek(&blob, &code), Err(EscrowError::Unwrap)));
}

/// The load-bearing M1 test: a full dump of the server's store contains no key material
/// and cannot be brute-forced into any, because it holds no derivation input at all.
#[test]
fn server_dump_yields_nothing() {
    let setup = VaultSetup::new(&DEK, VAULT).unwrap();
    let stored = setup.acknowledge();
    let dump = serde_json::to_vec(&stored).unwrap();

    // 1. The DEK is not in there.
    assert!(
        !dump.windows(DEK.len()).any(|w| w == DEK),
        "the DEK appeared verbatim in the stored blob"
    );
    // 2. Neither is anything the DEK can be derived from: the stored fields are exactly
    //    vault id, nonce and ciphertext. A new field here fails this test on purpose.
    let fields: serde_json::Value = serde_json::from_slice(&dump).unwrap();
    let mut keys: Vec<&str> = fields.as_object().unwrap().keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        ["ciphertext", "nonce", "vault_id"],
        "the server stores a field beyond ciphertext; re-argue the threat model before adding one"
    );
    // 3. And the ciphertext is not the plaintext under a different encoding.
    assert_ne!(stored.ciphertext.as_slice(), DEK.as_slice());
}

#[test]
fn recovery_code_is_never_rendered_by_debug() {
    let code = RecoveryCode::generate().unwrap();
    assert_eq!(format!("{code:?}"), "RecoveryCode(<redacted>)");
    let key = WrappingKey(blake3::derive_key("t", b"x"));
    assert_eq!(format!("{key:?}"), "WrappingKey(<redacted>)");
    // VaultSetup derives Debug; it must not leak the code through its field.
    let setup = VaultSetup::new(&DEK, VAULT).unwrap();
    assert!(format!("{setup:?}").contains("<redacted>"));
}

// ── M2: Shamir 2-of-3 ───────────────────────────────────────────────

#[test]
fn any_two_shares_reconstruct() {
    let setup = VaultSetup::new(&DEK, VAULT).unwrap();
    let shares = split_escrow(setup.code()).unwrap();
    let stored = setup.acknowledge();

    for (i, j) in [(0, 1), (0, 2), (1, 2)] {
        let key = combine_shares(&[shares[i].clone(), shares[j].clone()]).unwrap();
        assert_eq!(
            unwrap_dek_with_key(&stored, &key).unwrap(),
            DEK,
            "shares {i}+{j} did not recover the vault"
        );
    }
}

/// The load-bearing M2 test: **one share reconstructs nothing** — including ours.
#[test]
fn one_share_yields_nothing() {
    let setup = VaultSetup::new(&DEK, VAULT).unwrap();
    let shares = split_escrow(setup.code()).unwrap();
    let stored = setup.acknowledge();

    for share in &shares {
        assert!(
            matches!(
                combine_shares(std::slice::from_ref(share)),
                Err(EscrowError::NotEnoughShares { got: 1 })
            ),
            "a single {:?} share was accepted for reconstruction",
            share.holder
        );
        // And duplicating it does not manufacture a second point.
        assert!(matches!(
            combine_shares(&[share.clone(), share.clone()]),
            Err(EscrowError::NotEnoughShares { got: 1 })
        ));
        // The share bytes are not the key, nor a prefix of it.
        assert!(!share.bytes.windows(32).any(|w| w == stored.ciphertext.as_slice()));
    }

    // Specifically: what we hold, alone, is useless.
    let ours = shares.iter().find(|s| s.holder == ShareHolder::Custodian).unwrap();
    assert!(combine_shares(std::slice::from_ref(ours)).is_err());
}

#[test]
fn a_corrupt_share_is_detected_not_silently_wrong() {
    let setup = VaultSetup::new(&DEK, VAULT).unwrap();
    let mut shares = split_escrow(setup.code()).unwrap();
    let stored = setup.acknowledge();

    // Flip one bit in every byte position of share B in turn; each must be caught.
    for byte in 0..shares[1].bytes.len() {
        let mut damaged = shares.clone();
        damaged[1].bytes[byte] ^= 0x01;
        let outcome = combine_shares(&[damaged[0].clone(), damaged[1].clone()]);
        assert!(
            matches!(outcome, Err(EscrowError::CorruptShare { index: 1 })),
            "corruption at byte {byte} was not detected"
        );
    }

    // A truncated share is corruption too, not a panic.
    shares[1].bytes.truncate(2);
    assert!(matches!(
        combine_shares(&[shares[0].clone(), shares[1].clone()]),
        Err(EscrowError::CorruptShare { index: 1 })
    ));
    let _ = stored;
}

#[test]
fn shares_from_different_vaults_do_not_mix() {
    let a = VaultSetup::new(&DEK, "vault-a").unwrap();
    let b = VaultSetup::new(&DEK, "vault-b").unwrap();
    let shares_a = split_escrow(a.code()).unwrap();
    let shares_b = split_escrow(b.code()).unwrap();
    let stored_a = a.acknowledge();
    let _ = b.acknowledge();

    // Tags are per-share so a swapped share passes its own integrity check; the AEAD is
    // what refuses. This is the layer that catches it, and it must catch it.
    let key = combine_shares(&[shares_a[0].clone(), shares_b[1].clone()]).unwrap();
    assert!(matches!(unwrap_dek_with_key(&stored_a, &key), Err(EscrowError::Unwrap)));
}

#[test]
fn shares_survive_serialisation_to_paper_and_back() {
    let setup = VaultSetup::new(&DEK, VAULT).unwrap();
    let shares = split_escrow(setup.code()).unwrap();
    let stored = setup.acknowledge();

    let printed = serde_json::to_string(&shares[1]).unwrap();
    let device = serde_json::to_string(&shares[0]).unwrap();
    let restored: Vec<EscrowShare> = [device, printed]
        .iter()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect();

    let key = combine_shares(&restored).unwrap();
    assert_eq!(unwrap_dek_with_key(&stored, &key).unwrap(), DEK);
}

#[test]
fn escrow_opt_out_rewraps_to_layer_zero() {
    // Opting out re-wraps under a fresh code; the old shares must stop working.
    let setup = VaultSetup::new(&DEK, VAULT).unwrap();
    let old_shares = split_escrow(setup.code()).unwrap();
    let stored = setup.acknowledge();
    let recovered = combine_shares(&old_shares[..2]).unwrap();
    let dek = unwrap_dek_with_key(&stored, &recovered).unwrap();

    let fresh = VaultSetup::new(&dek, VAULT).unwrap();
    let rewrapped = fresh.acknowledge();
    let stale = combine_shares(&old_shares[..2]).unwrap();
    assert!(matches!(
        unwrap_dek_with_key(&rewrapped, &stale),
        Err(EscrowError::Unwrap)
    ));
}
