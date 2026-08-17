// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Load-time companion provenance: the three modes, the four states, and the one
//! interaction that only exists because discovery moved to `.ccxseg` (M4).
//!
//! The load-bearing test here is `a_locally_signed_segment_loads_as_local`. If a
//! legitimate local build ever resolves to `none`, every free operator trips the
//! alarm on every ingest, learns to ignore it, and the control is worth nothing.

use std::path::{Path, PathBuf};

use corecrux_index::{
    encode_attestation, AttestationBody, AttestationMode, CcxiBuilder, CompanionDigest, Provenance, TrustRoots,
    CCXATT_SCHEMA_V1,
};
use corecrux_retrieval::index_manager::IndexManager;
use corecrux_retrieval::segment_attestation::AttestationPolicy;
use corecrux_segment::{build_segment_v1, FrameInput, SegmentId};
use ed25519_dalek::{Signer, SigningKey};

const SEG_ID: [u8; 16] = [7u8; 16];

fn hex16(bytes: &[u8; 16]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn stem_for(seq: u64) -> String {
    format!("seg-{seq:020}-{}", hex16(&SEG_ID))
}

fn tenant_hash(tenant_id: &str) -> u64 {
    xxhash_rust::xxh64::xxh64(tenant_id.as_bytes(), 0)
}

/// A segment plus a real `.ccxi`, so "served" is observable through `readers()`.
fn write_segment_with_ccxi(dir: &Path, seq: u64, tenant: &str) -> String {
    let header = corecrux_frame::canonical_header_bytes_v1(&corecrux_frame::CanonicalHeaderV1 {
        tenant_id: tenant.to_string(),
        stream_id: "s".into(),
        stream_type: "note".into(),
        seq: 1,
        event_id: "e".into(),
        occurred_at: "2026-08-09T00:00:00Z".into(),
        ingested_at: "2026-08-09T00:00:01Z".into(),
        event_type: "note.created".into(),
        content_type: "text/plain".into(),
        payload_len: 7,
        payload_hash: [0u8; 32],
    });
    let bytes = build_segment_v1(
        0,
        1,
        seq,
        SegmentId(SEG_ID),
        1,
        2,
        &[FrameInput {
            stream_hash: 1,
            seq: 1,
            event_id: "evt",
            header_hash: [1u8; 32],
            payload_hash: [2u8; 32],
            header_bytes: &header,
            payload_bytes: b"payload",
        }],
    )
    .expect("build segment")
    .bytes;

    let stem = stem_for(seq);
    std::fs::write(dir.join(format!("{stem}.ccxseg")), bytes).unwrap();

    let mut builder = CcxiBuilder::new(0, seq, 100);
    builder.add_document(0, "terraform drift detection", 0, tenant_hash(tenant));
    std::fs::write(dir.join(format!("{stem}.ccxi")), builder.build()).unwrap();
    stem
}

/// Sign an attestation over every companion beside `stem`, as the seal path does.
fn sign_attestation(dir: &Path, stem: &str, key: &SigningKey, tenant: &str) -> PathBuf {
    let mut companions = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap().flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let Some(rest) = name.strip_prefix(&format!("{stem}.")) else {
            continue;
        };
        if rest == "ccxseg" || rest.starts_with("ccxatt") {
            continue;
        }
        let bytes = std::fs::read(entry.path()).unwrap();
        companions.push(CompanionDigest {
            ext: rest.to_string(),
            key: None,
            blake3: corecrux_index::companion_digest(&bytes),
            bytes: bytes.len() as u64,
        });
    }
    companions.sort_by(|a, b| (&a.ext, &a.key).cmp(&(&b.ext, &b.key)));

    let body = AttestationBody {
        schema: CCXATT_SCHEMA_V1.to_string(),
        shard_id: 0,
        segment_seq: 1,
        segment_id: hex16(&SEG_ID),
        tenant_id: Some(tenant.to_string()),
        provenance: "local".to_string(),
        issued_at: 1_754_700_000,
        producer_pubkey: key
            .verifying_key()
            .to_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
        producer_fpr: "test-device-fpr".to_string(),
        builder_commit: "test".to_string(),
        companions,
    };
    let sig = key.sign(&body.signing_bytes()).to_bytes();
    let path = dir.join(format!("{stem}.ccxatt"));
    std::fs::write(&path, encode_attestation(&body, &sig)).unwrap();
    path
}

fn test_key() -> SigningKey {
    SigningKey::from_bytes(&[42u8; 32])
}

fn policy(mode: AttestationMode, key: &SigningKey) -> AttestationPolicy {
    AttestationPolicy::new(
        mode,
        TrustRoots::new().with_local_device("test-device-fpr", key.verifying_key().to_bytes()),
    )
}

/// The false-positive guard. A legitimate local build must load clean.
#[test]
fn a_locally_signed_segment_loads_as_local_and_serves() {
    let tmp = tempfile::tempdir().unwrap();
    let key = test_key();
    let stem = write_segment_with_ccxi(tmp.path(), 1, "acme");
    sign_attestation(tmp.path(), &stem, &key, "acme");

    let mut mgr = IndexManager::new();
    mgr.set_attestation_policy(policy(AttestationMode::Warn, &key));
    mgr.scan_and_load(tmp.path()).unwrap();

    assert_eq!(mgr.segment_provenance(1), Some(Provenance::Local));
    assert_eq!(mgr.readers().len(), 1, "a local build serves normally");
    assert!(mgr.refused_segments().is_empty(), "and must not be refused");
    assert_eq!(mgr.provenance_counts().get("local").copied(), Some(1));
}

/// A broken stamp is evidence the bytes are not what was signed. There is no
/// mode in which loading them is correct — including `off`.
#[test]
fn a_tampered_companion_is_refused_in_every_mode() {
    for mode in [AttestationMode::Off, AttestationMode::Warn, AttestationMode::Enforce] {
        let tmp = tempfile::tempdir().unwrap();
        let key = test_key();
        let stem = write_segment_with_ccxi(tmp.path(), 1, "acme");
        sign_attestation(tmp.path(), &stem, &key, "acme");

        // Tamper AFTER signing: the digest in the body no longer matches.
        let ccxi = tmp.path().join(format!("{stem}.ccxi"));
        let mut bytes = std::fs::read(&ccxi).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        std::fs::write(&ccxi, bytes).unwrap();

        let mut mgr = IndexManager::new();
        mgr.set_attestation_policy(policy(mode, &key));
        mgr.scan_and_load(tmp.path()).unwrap();

        assert_eq!(mgr.segment_provenance(1), Some(Provenance::Invalid), "{mode:?}");
        assert_eq!(mgr.refused_segments(), vec![1], "{mode:?}");
        assert!(
            mgr.readers().is_empty(),
            "tampered bytes must never be served in {mode:?}"
        );
    }
}

/// `warn` loads a missing stamp; `enforce` does not.
#[test]
fn a_missing_attestation_loads_in_warn_and_refuses_in_enforce() {
    let key = test_key();

    let warn_dir = tempfile::tempdir().unwrap();
    write_segment_with_ccxi(warn_dir.path(), 1, "acme");
    let mut warn_mgr = IndexManager::new();
    warn_mgr.set_attestation_policy(policy(AttestationMode::Warn, &key));
    warn_mgr.scan_and_load(warn_dir.path()).unwrap();
    assert_eq!(warn_mgr.segment_provenance(1), Some(Provenance::None));
    assert_eq!(warn_mgr.readers().len(), 1, "warn loads it, loudly");
    assert!(warn_mgr.refused_segments().is_empty());

    let enf_dir = tempfile::tempdir().unwrap();
    write_segment_with_ccxi(enf_dir.path(), 1, "acme");
    let mut enf_mgr = IndexManager::new();
    enf_mgr.set_attestation_policy(policy(AttestationMode::Enforce, &key));
    enf_mgr.scan_and_load(enf_dir.path()).unwrap();
    assert_eq!(enf_mgr.segment_provenance(1), Some(Provenance::None));
    assert_eq!(enf_mgr.refused_segments(), vec![1], "enforce refuses it");
    assert!(enf_mgr.readers().is_empty());
}

/// Surface 3 reports what the **answer** rested on, not what the corpus holds.
///
/// This is the whole reason it is not a corpus-wide count: with two segments
/// present and only one contributing hits, a corpus tally would report an
/// unattested segment on an answer that never touched it — and, worse, report
/// clean on an answer that did.
#[test]
fn the_query_provenance_tally_counts_only_contributing_segments() {
    let tmp = tempfile::tempdir().unwrap();
    let key = test_key();

    // Segment 1 is signed; segment 2 is not.
    let signed = write_segment_with_ccxi(tmp.path(), 1, "acme");
    sign_attestation(tmp.path(), &signed, &key, "acme");
    write_segment_with_ccxi(tmp.path(), 2, "acme");

    let mut mgr = IndexManager::new();
    mgr.set_attestation_policy(policy(AttestationMode::Warn, &key));
    mgr.scan_and_load(tmp.path()).unwrap();
    assert_eq!(mgr.readers().len(), 2, "both serve in warn");

    // An answer drawn only from reader position 0 (the signed segment).
    let only_signed = mgr.provenance_tally_for_reader_indices([0usize]);
    assert_eq!(only_signed.contributing_segments, 1);
    assert_eq!(only_signed.local, 1);
    assert_eq!(only_signed.none, 0, "the unattested segment did not answer this");
    assert!(only_signed.is_clean());

    // An answer that touched the unattested one says so.
    let touched_unattested = mgr.provenance_tally_for_reader_indices([1usize]);
    assert_eq!(touched_unattested.none, 1);
    assert!(!touched_unattested.is_clean());

    // Ten hits from one segment are one contributing segment, not ten.
    let repeated = mgr.provenance_tally_for_reader_indices([0usize, 0, 0, 1, 1]);
    assert_eq!(repeated.contributing_segments, 2);
    assert_eq!(repeated.local, 1);
    assert_eq!(repeated.none, 1);
}

/// The interaction that only exists because M4 made discovery the erasure
/// enumeration: a refused segment loses its **lanes**, never its **visibility**.
///
/// Dropping it from the scan would make it un-erasable — reopening the exact
/// GDPR hole that keying discovery off `.ccxseg` was written to close. Refusing
/// to serve data is a retrieval decision; refusing to see it is a deletion bug.
#[test]
fn a_refused_segment_is_still_attributable_and_erasable() {
    let tmp = tempfile::tempdir().unwrap();
    let key = test_key();
    let stem = write_segment_with_ccxi(tmp.path(), 1, "acme");
    let ccxseg = tmp.path().join(format!("{stem}.ccxseg"));

    let mut mgr = IndexManager::new();
    mgr.set_attestation_policy(policy(AttestationMode::Enforce, &key));
    mgr.scan_and_load(tmp.path()).unwrap();

    assert_eq!(mgr.refused_segments(), vec![1]);
    assert!(mgr.readers().is_empty(), "unserved");
    assert_eq!(mgr.segment_count(), 1, "but still discovered");

    // Attribution still works — it reads the segment's own frame headers.
    let footprint = mgr.tenant_footprint(tenant_hash("acme"));
    assert_eq!(footprint.segments.len(), 1, "a refused segment is still attributable");
    assert_eq!(footprint.docs, 1);
    assert_eq!(footprint.unattributable_segments, 0);

    // And erasure still removes it.
    assert!(mgr.reclaim_segment(1).expect("reclaim") > 0);
    assert!(!ccxseg.exists(), "a refused segment must remain erasable");
}
