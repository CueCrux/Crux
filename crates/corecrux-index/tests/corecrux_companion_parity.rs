// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! **The M5 gate.** A Crux CE daemon must open every companion container the
//! **CoreCrux platform builders** produce, not merely a container that shares a name.
//!
//! Under the processor model the platform computes companions and the customer's
//! daemon reads them locally. Name parity proves nothing — one extension over two byte
//! layouts fails silently, which is worse than two names. Only a fixture built by the
//! *other* implementation proves the port, and only the other implementation's builder
//! can produce one: constraint C7 keeps every `Ccx*Builder` except `CcxeBuilder` out of
//! the CE, so there is no CE-side way to fake these bytes.
//!
//! Fixtures in `tests/fixtures/corecrux.*` were emitted by the builders in
//! `CoreCrux/crates/corecrux-index` at commit `88a8439`. If the upstream format
//! changes, these fail — which is the drift signal `VENDORED_FROM.md` relies on.

use corecrux_index::{
    subject_hash, CcxalReader, CcxdiReader, CcxevModality, CcxevReader, CcxfReader, CcxnReader, CcxpReader, CcxsReader,
    CcxseReader, EntityType, ProjectionPredicate, SubjectKind, CCXEV_NO_TIME,
};

fn fixture(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read fixture {}: {e}", path.display()))
}

// ── .ccxs — subject profile ──────────────────────────────────────────────────

#[test]
fn ce_reads_a_corecrux_built_ccxs() {
    let bytes = fixture("corecrux.ccxs");
    let reader = CcxsReader::new(&bytes).expect("CE must open a CoreCrux-built .ccxs");

    assert_eq!(reader.subject_count(), 2);
    assert_eq!(reader.traits_total(), 3);
    assert_eq!(reader.header().shard_id, 7);
    assert_eq!(reader.header().segment_seq, 42);
    assert_eq!(reader.header().epoch, 1_700_000_000);

    let acme = reader
        .lookup(SubjectKind::Tenant, "acme")
        .expect("the tenant subject must be found by (kind, id)");
    assert_eq!(acme.subject_id(), "acme");
    assert_eq!(acme.n_traits(), 2);
    assert!(!acme.evidence_unverified);
    let mut traits: Vec<(String, String)> = acme.iter().map(|(p, o)| (p.to_string(), o.to_string())).collect();
    traits.sort();
    assert_eq!(
        traits,
        vec![
            ("has_hobby".to_string(), "bouldering".to_string()),
            ("prefers".to_string(), "dark roast coffee".to_string()),
        ]
    );
}

/// The evidence flag is a single bit in the entry, easy to read off the wrong byte.
/// An unverified claim silently reading as verified is the failure that matters.
#[test]
fn ccxs_carries_the_unverified_evidence_flag_across_the_port() {
    let bytes = fixture("corecrux.ccxs");
    let reader = CcxsReader::new(&bytes).expect("open .ccxs");
    let passport = reader
        .lookup(SubjectKind::Passport, "1f0c9b2a-0000-4000-8000-000000000001")
        .expect("passport subject");
    assert!(passport.evidence_unverified);
    assert_eq!(passport.collect_traits().len(), 1);
    assert_eq!(passport.collect_traits()[0].predicate, "lives_in");
    assert_eq!(passport.collect_traits()[0].object, "Bristol");
}

/// Kind is part of the key. If the CE hashed only the id it would serve one
/// subject's traits for another's — the reason the kind byte is in the preimage.
#[test]
fn ccxs_lookup_does_not_cross_subject_kinds() {
    let bytes = fixture("corecrux.ccxs");
    let reader = CcxsReader::new(&bytes).expect("open .ccxs");
    assert!(reader.lookup(SubjectKind::Passport, "acme").is_none());
    assert!(reader.lookup(SubjectKind::Tenant, "unknown-tenant").is_none());
}

/// Flipping one body byte must fail the CRC32C footer rather than yield garbage.
#[test]
fn a_tampered_ccxs_fails_its_footer_crc() {
    let mut bytes = fixture("corecrux.ccxs");
    let last = bytes.len() - 8;
    bytes[last] ^= 0xFF;
    assert!(CcxsReader::new(&bytes).is_err());
}

// ── .ccxse — subject-trait embeddings ────────────────────────────────────────

#[test]
fn ce_reads_a_corecrux_built_ccxse() {
    let bytes = fixture("corecrux.ccxse");
    let reader = CcxseReader::new(&bytes).expect("CE must open a CoreCrux-built .ccxse");

    assert_eq!(reader.subject_count(), 2);
    assert_eq!(reader.embedding_dim(), 8);
    assert_eq!(reader.embeddings_total(), 3);
    assert_eq!(reader.source_ccxs_crc(), 0xABCD_1234);

    // Keyed by exactly the hash `.ccxs` uses — one hash serves both files.
    let h = subject_hash(SubjectKind::Tenant, "acme");
    let slice = reader.lookup_by_hash(h).expect("tenant subject embeddings");
    assert_eq!(slice.embedding_dim(), 8);
    let v = slice.vector_at(0).expect("first vector");
    assert_eq!(v.len(), 8);

    // The generator wrote vectors as (d + k) / 10.0; fp16 keeps ~3 decimal digits.
    let total: usize = reader.iter().map(|s| s.n_embeddings() as usize).sum();
    assert_eq!(total, 3);
}

#[test]
fn ccxse_decodes_fp16_payloads_to_the_values_the_builder_wrote() {
    let bytes = fixture("corecrux.ccxse");
    let reader = CcxseReader::new(&bytes).expect("open .ccxse");
    let h = subject_hash(SubjectKind::Tenant, "acme");
    let slice = reader.lookup_by_hash(h).expect("tenant embeddings");
    let v = slice.vector_at(0).expect("vector 0");
    // Whichever ordinal this subject landed on, element d is (d + k)/10 for some
    // small k, so the step between consecutive elements is 0.1 regardless.
    for w in v.windows(2) {
        assert!((w[1] - w[0] - 0.1).abs() < 1e-2, "fp16 step should be ~0.1, got {v:?}");
    }
}

#[test]
fn ccxse_lookup_of_an_absent_hash_is_none_not_a_neighbour() {
    let bytes = fixture("corecrux.ccxse");
    let reader = CcxseReader::new(&bytes).expect("open .ccxse");
    assert!(reader.lookup_by_hash(0xDEAD_BEEF_DEAD_BEEF).is_none());
}

#[test]
fn a_tampered_ccxse_fails_its_footer_crc() {
    let mut bytes = fixture("corecrux.ccxse");
    let last = bytes.len() - 8;
    bytes[last] ^= 0xFF;
    assert!(CcxseReader::new(&bytes).is_err());
}

// ── .ccxdi — document index ──────────────────────────────────────────────────

#[test]
fn ce_reads_a_corecrux_built_ccxdi() {
    let bytes = fixture("corecrux.ccxdi");
    let reader = CcxdiReader::from_bytes(&bytes).expect("CE must open a CoreCrux-built .ccxdi");

    assert_eq!(reader.header().doc_count, 2);
    assert_eq!(reader.header().region_count, 3);
    assert_eq!(reader.header().pointer_count, 3);

    let docs: Vec<_> = reader.iter_docs().collect();
    assert_eq!(docs.len(), 2);
    assert_eq!(docs[0].doc_id, 1001);
    assert_eq!(docs[0].region_count, 2);
    assert_eq!(docs[0].pointer_count, 2);

    let regions = reader.regions_for_doc(1001).expect("regions for doc 1001");
    assert_eq!(regions.len(), 2);
    assert_eq!(regions[0].header.as_deref(), Some("Deployment"));
    assert_eq!(regions[0].byte_start, 0);
    assert_eq!(regions[0].byte_end, 120);
    assert_eq!(regions[1].header, None);

    let pointers = reader.pointers_for_doc(1001).expect("pointers for doc 1001");
    assert_eq!(pointers.len(), 2);
    assert!(pointers.iter().any(|p| p.surface == "corecruxd"));
    assert!(pointers.iter().any(|p| p.surface == "rollback"));
}

/// Schema v2 stamps a per-doc tenant hash. Reading it as `None` would make the
/// indexing lane treat the doc as "wildcard, scan-all" — a cross-tenant read.
#[test]
fn ccxdi_v2_tenant_hashes_survive_the_port() {
    let bytes = fixture("corecrux.ccxdi");
    let reader = CcxdiReader::from_bytes(&bytes).expect("open .ccxdi");
    assert_eq!(reader.header().schema_version, 2);
    assert_eq!(
        reader.find_doc(1001).expect("doc 1001").tenant_hash,
        Some(0x1122_3344_5566_7788)
    );
    assert_eq!(
        reader.find_doc(1002).expect("doc 1002").tenant_hash,
        Some(0x99AA_BBCC_DDEE_FF00)
    );
}

/// Salience is Q8.8 on disk. A wrong scale factor still produces plausible
/// numbers, so pin the exact values the builder was handed.
#[test]
fn ccxdi_q8_8_salience_round_trips() {
    let bytes = fixture("corecrux.ccxdi");
    let reader = CcxdiReader::from_bytes(&bytes).expect("open .ccxdi");
    let pointers = reader.pointers_for_doc(1002).expect("pointers");
    assert_eq!(pointers.len(), 1);
    assert!((pointers[0].score - 1.25).abs() < 1e-3, "got {}", pointers[0].score);
}

#[test]
fn a_tampered_ccxdi_fails_its_footer_crc() {
    let mut bytes = fixture("corecrux.ccxdi");
    let last = bytes.len() - 8;
    bytes[last] ^= 0xFF;
    assert!(CcxdiReader::from_bytes(&bytes).is_err());
}

// ── .ccxal — vernacular atoms ────────────────────────────────────────────────

#[test]
fn ce_reads_a_corecrux_built_ccxal() {
    let bytes = fixture("corecrux.ccxal");
    let reader = CcxalReader::from_bytes(&bytes).expect("CE must open a CoreCrux-built .ccxal");

    assert_eq!(reader.doc_count(), 2);
    assert_eq!(reader.d0_atom_count(), 2);
    assert_eq!(reader.d1_atom_count(), 1);
    assert_eq!(reader.header().vocab_version, 3);
    assert_eq!(reader.header().sealed_at, 1_700_000_123);
    assert_eq!(reader.header().ingest_agent_id, [0xA1; 16]);

    let doc = reader.doc(0).expect("doc 0");
    assert_eq!(doc.doc_id, 555);
    assert_eq!(doc.d0_count, 1);
    assert_eq!(doc.d1_count, 1);
}

/// The `#[repr(C)]` atom structs are the port's sharpest edge: a field-offset slip
/// decodes every atom into plausible-looking nonsense rather than failing.
#[test]
fn ccxal_atom_fields_land_at_the_offsets_the_builder_wrote() {
    let bytes = fixture("corecrux.ccxal");
    let reader = CcxalReader::from_bytes(&bytes).expect("open .ccxal");

    let d0 = reader.d0_atom(0).expect("d0 atom 0");
    assert_eq!(d0.doc_id, 555);
    assert_eq!(d0.region_id, 2);
    assert_eq!(d0.byte_start, 10);
    assert_eq!(d0.byte_end, 48);
    assert_eq!(d0.content_hash, [0x5A; 16]);
    assert_eq!(d0.provenance_triad, [0x0C; 12]);

    let d1 = reader.d1_atom(0).expect("d1 atom 0");
    assert_eq!(d1.actor_class, 1);
    assert_eq!(d1.object_class, 2);
    assert_eq!(d1.temporal_anchor_type, 3);
    assert_eq!(d1.actor_code, 4242);
    assert_eq!(d1.object_code, 8484);
    assert_eq!(d1.predicate_code, 77);
    assert_eq!(d1.conf_q8_8, 0x0140);
    assert_eq!(d1.temporal_value, -900);
}

#[test]
fn ccxal_strings_pool_carries_the_oov_surface() {
    let bytes = fixture("corecrux.ccxal");
    let reader = CcxalReader::from_bytes(&bytes).expect("open .ccxal");
    let pool = reader.strings_pool();
    assert!(
        pool.windows(11).any(|w| w == b"gigafactory"),
        "OOV surface must survive into the strings pool"
    );
}

#[test]
fn a_tampered_ccxal_fails_its_footer_crc() {
    let mut bytes = fixture("corecrux.ccxal");
    let last = bytes.len() - 8;
    bytes[last] ^= 0xFF;
    assert!(CcxalReader::from_bytes(&bytes).is_err());
}

// ── .ccxn — entity matrix ────────────────────────────────────────────────────

#[test]
fn ce_reads_a_corecrux_built_ccxn() {
    let bytes = fixture("corecrux.ccxn");
    let reader = CcxnReader::new(&bytes).expect("CE must open a CoreCrux-built .ccxn");

    assert_eq!(reader.entity_count(), 3);
    assert_eq!(reader.occurrences_total(), 4);

    let hits = reader.lookup_by_canonical("hollow knight").expect("product entity");
    assert_eq!(hits.entity_type, EntityType::Product);
    assert_eq!(hits.n_occurrences(), 2);
    let occs: Vec<_> = hits.iter().collect();
    assert_eq!(occs[0].session_id, 900);
    assert_eq!(occs[0].doc_id, 1);
    assert_eq!(occs[0].frame_offset, 4096);
}

/// The type tag drives lane weighting downstream, so a shifted enum would
/// mis-weight every hit rather than fail.
#[test]
fn ccxn_entity_type_tags_survive_the_port() {
    let bytes = fixture("corecrux.ccxn");
    let reader = CcxnReader::new(&bytes).expect("open .ccxn");
    assert_eq!(
        reader.lookup_by_canonical("bristol").expect("location").entity_type,
        EntityType::Location
    );
    assert_eq!(
        reader.lookup_by_canonical("cuecrux ltd").expect("org").entity_type,
        EntityType::Organization
    );
}

#[test]
fn ccxn_lookup_of_an_absent_entity_is_none() {
    let bytes = fixture("corecrux.ccxn");
    let reader = CcxnReader::new(&bytes).expect("open .ccxn");
    assert!(reader.lookup_by_canonical("nonexistent entity").is_none());
}

#[test]
fn a_tampered_ccxn_fails_its_footer_crc() {
    let mut bytes = fixture("corecrux.ccxn");
    let last = bytes.len() - 8;
    bytes[last] ^= 0xFF;
    assert!(CcxnReader::new(&bytes).is_err());
}

// ── .ccxf — reverse frames ───────────────────────────────────────────────────

#[test]
fn ce_reads_a_corecrux_built_ccxf() {
    let bytes = fixture("corecrux.ccxf");
    let reader = CcxfReader::new(&bytes).expect("CE must open a CoreCrux-built .ccxf");

    assert_eq!(reader.frame_count(), 2);
    let f0 = reader.get(0).expect("frame 0");
    assert_eq!(f0.session_id, 900);
    assert_eq!(f0.doc_id, 1);
    assert_eq!(f0.generated_at_unix_secs, 1_700_000_500);
    assert_eq!(f0.source_chunk_offset, 64);
    assert_eq!(f0.frame_text, "which game did the user finish last weekend?");
    assert_eq!(f0.args, vec!["item=Hollow Knight", "time=last_weekend"]);

    // The allocation-free text iterator must agree with the full decode.
    let texts: Vec<_> = reader.iter_text().collect();
    assert_eq!(texts.len(), 2);
    assert_eq!(texts[0], (900u64, 1u32, f0.frame_text.as_str()));
}

/// A frame with no args must read as an empty list, not as a borrow into the
/// next frame's args — the classic off-by-one in a shared args table.
#[test]
fn ccxf_an_argless_frame_reads_as_empty_not_as_its_neighbours_args() {
    let bytes = fixture("corecrux.ccxf");
    let reader = CcxfReader::new(&bytes).expect("open .ccxf");
    let f1 = reader.get(1).expect("frame 1");
    assert_eq!(f1.frame_text, "where does the user live?");
    assert!(f1.args.is_empty());
    assert_eq!(f1.generated_at_unix_secs, 0);
}

#[test]
fn a_tampered_ccxf_fails_its_footer_crc() {
    let mut bytes = fixture("corecrux.ccxf");
    let last = bytes.len() - 8;
    bytes[last] ^= 0xFF;
    assert!(CcxfReader::new(&bytes).is_err());
}

// ── .ccxev — extracted events ────────────────────────────────────────────────

#[test]
fn ce_reads_a_corecrux_built_ccxev() {
    let bytes = fixture("corecrux.ccxev");
    let reader = CcxevReader::from_bytes(&bytes).expect("CE must open a CoreCrux-built .ccxev");

    assert_eq!(reader.event_count(), 2);
    assert_eq!(reader.header().version, 2, "the platform writes v2 with record_off");
    let events = reader.events().expect("materialise events");
    let e0 = &events[0];
    assert_eq!(e0.session_id, 900);
    assert_eq!(e0.doc_id, 1);
    assert_eq!(e0.record_off, 4096);
    assert_eq!(e0.verb_class, "purchase");
    assert_eq!(e0.object, "Fender Stratocaster");
    assert_eq!(e0.object_categories, vec!["instrument", "guitar"]);
    assert_eq!(e0.time_unix_secs, 1_699_000_000);
    assert!(e0.agent_is_user);
    assert!(!e0.negation);
    assert_eq!(e0.modality, CcxevModality::Factual);
    assert!((e0.confidence - 0.875).abs() < 1e-3);
}

/// `negation` and `agent_is_user` are packed bit flags, and a negated event that
/// reads as affirmative is scored as evidence for the opposite of what was said.
#[test]
fn ccxev_packed_flags_and_the_no_time_sentinel_survive_the_port() {
    let bytes = fixture("corecrux.ccxev");
    let reader = CcxevReader::from_bytes(&bytes).expect("open .ccxev");
    let events = reader.events().expect("materialise events");
    let e1 = &events[1];
    assert!(!e1.agent_is_user);
    assert!(e1.negation);
    assert_eq!(e1.modality, CcxevModality::Hypothetical);
    assert_eq!(e1.time_unix_secs, CCXEV_NO_TIME, "the no-time sentinel must round-trip");
    assert_eq!(e1.verb_class, "travel");
}

#[test]
fn a_tampered_ccxev_fails_its_footer_crc() {
    let mut bytes = fixture("corecrux.ccxev");
    let last = bytes.len() - 8;
    bytes[last] ^= 0xFF;
    assert!(CcxevReader::from_bytes(&bytes).is_err());
}

// ── .ccxp — structured-fact projections ──────────────────────────────────────

#[test]
fn ce_reads_a_corecrux_built_ccxp() {
    let bytes = fixture("corecrux.ccxp");
    let reader = CcxpReader::new(&bytes).expect("CE must open a CoreCrux-built .ccxp");

    assert_eq!(reader.fact_count(), 3);
    let f0 = reader.get(0).expect("fact 0");
    assert_eq!(f0.predicate, ProjectionPredicate::UserAction);
    assert_eq!(f0.session_id, 900);
    assert_eq!(f0.doc_id, 1);
    assert_eq!(f0.frame_offset, 4096);
    assert!((f0.confidence - 0.9).abs() < 1e-3);
    assert_eq!(f0.args, vec!["bought", "espresso machine", "today"]);
    assert_eq!(f0.source_pattern.as_deref(), Some("regex:bought-today/v1"));
}

#[test]
fn ccxp_predicate_tags_and_absent_source_patterns_survive_the_port() {
    let bytes = fixture("corecrux.ccxp");
    let reader = CcxpReader::new(&bytes).expect("open .ccxp");

    let f1 = reader.get(1).expect("fact 1");
    assert_eq!(f1.predicate, ProjectionPredicate::CountState);
    assert_eq!(f1.args, vec!["books", "47"]);
    assert_eq!(
        f1.source_pattern, None,
        "an absent pattern must not borrow a neighbour's"
    );

    let f2 = reader.get(2).expect("fact 2");
    assert_eq!(f2.predicate, ProjectionPredicate::TemporalEvent);
    assert_eq!(f2.args, vec!["Sarah's wedding", "2026-05-14"]);
    assert_eq!(reader.iter().count(), 3);
}

#[test]
fn a_tampered_ccxp_fails_its_footer_crc() {
    let mut bytes = fixture("corecrux.ccxp");
    let last = bytes.len() - 8;
    bytes[last] ^= 0xFF;
    assert!(CcxpReader::new(&bytes).is_err());
}
