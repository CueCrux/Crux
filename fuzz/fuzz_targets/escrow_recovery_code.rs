#![no_main]

use crux_escrow::{
    combine_shares, unwrap_dek_with_key, EscrowError, EscrowShare, RecoveryCode, ShareHolder, WrappedDek,
};
use libfuzzer_sys::fuzz_target;

/// Mirrors the private share-tag context in `crux_escrow`. Recomputing the tag here is the
/// whole point: an untagged fuzz body stops at the integrity check, so the reconstruction
/// primitive (`vsss-rs` GF(2^8) `combine_bytes`) would never see an untrusted byte. The
/// drift assertion below fires if this string stops matching the crate's.
const SHARE_TAG_CONTEXT: &str = "cuecrux crux-escrow 2026-08-01 escrow share tag v1";
/// Bytes of the trailing BLAKE3 tag on a share, as `crux_escrow::SHARE_TAG_LEN`.
const SHARE_TAG_LEN: usize = 4;
/// Cap on shares per input. The threshold is 2 of 3; beyond a handful the only thing more
/// shares buy is quadratic time in the dedup loop, which starves the fuzzer.
const MAX_SHARES: usize = 8;
/// Byte the input is split on to carve share bodies — a structural handle the mutator can
/// insert and remove, so share count and lengths are fuzzed, not fixed.
const SEPARATOR: u8 = 0xff;

fn share(holder: ShareHolder, body: &[u8], tagged: bool) -> EscrowShare {
    let mut bytes = body.to_vec();
    if tagged {
        bytes.extend_from_slice(&blake3::derive_key(SHARE_TAG_CONTEXT, body)[..SHARE_TAG_LEN]);
    }
    EscrowShare { holder, bytes }
}

fuzz_target!(|data: &[u8]| {
    // ── Layer 0: the transcribed recovery code. Every byte of it is typed by a human, so
    //    length, alphabet, case, separators and Crockford confusables are all untrusted.
    let typed = String::from_utf8_lossy(data);
    if let Ok(code) = RecoveryCode::parse(&typed) {
        // A code that parsed must render, and our own rendering must parse back to the
        // same code. An asymmetry here locks a customer out of their vault holding a
        // correctly transcribed code, which is the failure this crate exists to prevent.
        let rendered = code.render().expect("a code that parsed must render");
        let reparsed = RecoveryCode::parse(&rendered).expect("our own rendering must parse");
        assert_eq!(
            rendered,
            reparsed.render().expect("a code that parsed must render"),
            "render/parse is not a round trip"
        );
    }

    // ── Layer 1: escrow shares. These arrive from a printed copy and from custody
    //    storage, so their bytes are equally untrusted.
    let holders = [ShareHolder::Device, ShareHolder::Printed, ShareHolder::Custodian];
    let bodies: Vec<&[u8]> = data.split(|b| *b == SEPARATOR).take(MAX_SHARES).collect();

    // Raw bodies: mostly rejected by the integrity tag, which is the point — this is the
    // length arithmetic (`checked_sub`, `split_at`) on a share shorter than its own tag.
    let raw: Vec<EscrowShare> = bodies
        .iter()
        .zip(holders.iter().cycle())
        .map(|(body, holder)| share(*holder, body, false))
        .collect();
    let _ = combine_shares(&raw);

    // Correctly tagged bodies: past the integrity gate and into reconstruction, where
    // `vsss-rs` sees arbitrary lengths, duplicate x-coordinates and empty bodies.
    let sound: Vec<EscrowShare> = bodies
        .iter()
        .zip(holders.iter().cycle())
        .map(|(body, holder)| share(*holder, body, true))
        .collect();
    match combine_shares(&sound) {
        Err(EscrowError::CorruptShare { index }) => panic!(
            "share {index} carried a tag derived under SHARE_TAG_CONTEXT and was still rejected: \
             this target's copy of the context string has drifted from crux-escrow's, and every \
             reconstruction path below the integrity gate is now unfuzzed"
        ),
        // A reconstructed key is only ever used against a stored blob, and the blob is
        // whatever the server hands back. Untrusted ciphertext must fail the AEAD tag.
        Ok(key) => {
            let mut nonce = [0u8; 24];
            for (slot, byte) in nonce.iter_mut().zip(data) {
                *slot = *byte;
            }
            let blob = WrappedDek {
                vault_id: typed.into_owned(),
                nonce,
                ciphertext: data.to_vec(),
            };
            let _ = unwrap_dek_with_key(&blob, &key);
        }
        Err(_) => {}
    }
});
