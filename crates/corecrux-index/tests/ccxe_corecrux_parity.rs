// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! **The M2 gate.** A Crux CE daemon must open a `.ccxe` dense companion that the
//! **CoreCrux platform builder** produced.
//!
//! This is the whole point of porting the format rather than renaming the CE's own
//! one: under the processor model the platform computes companions and the customer's
//! daemon reads them locally. Name parity proves nothing — a shared extension over two
//! byte layouts is worse than two names, because it fails silently. Only a fixture
//! built by the *other* implementation proves the port.
//!
//! Fixtures in `tests/fixtures/` were emitted by `CcxeBuilder` in
//! `CoreCrux/crates/corecrux-index` at commit `88a8439`, dim 64, 64 vectors, model id
//! `BAAI/bge-m3`, across the three quantisations the platform actually writes. If the
//! upstream format changes, these fail — which is exactly the drift signal
//! VENDORED_FROM.md relies on.

use corecrux_index::{CcxeReader, Quantization};

fn fixture(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read fixture {}: {e}", path.display()))
}

#[test]
fn ce_reads_corecrux_built_f32_companion() {
    let reader =
        CcxeReader::from_bytes(&fixture("corecrux-f32.ccxe")).expect("CE must open a CoreCrux-built f32 .ccxe");

    assert_eq!(reader.header.quantization, Quantization::Float32);
    assert_eq!(reader.header.dim, 64);
    assert_eq!(reader.num_vectors(), 64);
    // The authoritative model id comes from the header, never the filename.
    assert_eq!(reader.header.model_id, "BAAI/bge-m3");
    assert_eq!(reader.doc_ids, (0..64u32).collect::<Vec<_>>());

    // f32 vectors are readable and normalised enough to score.
    let q = reader.vectors[7].clone();
    let hits = reader.cosine_search(&q, 3);
    assert_eq!(hits[0].0, 7, "a vector must be its own nearest neighbour");
}

#[test]
fn ce_reads_corecrux_built_int8_companion() {
    let reader =
        CcxeReader::from_bytes(&fixture("corecrux-int8.ccxe")).expect("CE must open a CoreCrux-built int8 .ccxe");

    assert_eq!(reader.header.quantization, Quantization::Int8);
    assert_eq!(reader.num_vectors(), 64);
    assert_eq!(reader.header.model_id, "BAAI/bge-m3");

    let q = reader.vectors[3].clone();
    assert_eq!(reader.cosine_search(&q, 1)[0].0, 3);
}

/// The one that would break first on a codec change: TurboQuant is packed sub-byte,
/// so reading it exercises the ported `turboquant` decoder end-to-end, not just the
/// header parser.
#[test]
fn ce_reads_corecrux_built_turboquant_companion() {
    let reader =
        CcxeReader::from_bytes(&fixture("corecrux-tq4.ccxe")).expect("CE must open a CoreCrux-built tq4 .ccxe");

    assert_eq!(reader.header.quantization, Quantization::TurboQuant4);
    assert_eq!(reader.num_vectors(), 64);
    assert!(reader.packed.is_some(), "tq4 must land in the packed representation");
    assert!(reader.vectors.is_empty(), "packed modes must not eagerly expand to f32");

    // Decode a vector through the ported codec and confirm it self-retrieves.
    let decoded = reader.packed.as_ref().expect("packed").decode_orig(3);
    assert_eq!(decoded.len(), 64);
    assert_eq!(reader.cosine_search(&decoded, 1)[0].0, 3);
}

/// TurboQuant is lossy, so a 4-bit fixture must be materially smaller than the f32
/// one built from the identical corpus. If this ever inverts, the packed path is
/// silently falling back to per-element storage.
#[test]
fn turboquant_fixture_is_denser_than_f32() {
    let f32_len = fixture("corecrux-f32.ccxe").len();
    let tq4_len = fixture("corecrux-tq4.ccxe").len();
    assert!(
        tq4_len * 4 < f32_len,
        "tq4 ({tq4_len} B) must be >4x smaller than f32 ({f32_len} B)"
    );
}
