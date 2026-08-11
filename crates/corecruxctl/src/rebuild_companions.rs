// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! `corecruxctl rebuild-companions` — regenerate a segment's dense companion
//! under a different embedder, without destroying the one it already has.
//!
//! ExecPlan `crux-companion-vocabulary-unification-2026-08-08` M7.
//!
//! The walk, the doc-id numbering and the atomic write live in
//! [`corecrux_storage::rebuild`], because they are the seal-time derivation run
//! offline and belong beside the segment reader. This module is the operator
//! surface around it: which embedder, which key, and — the part that cannot be
//! skipped — re-signing the attestation so the file the rebuild just wrote is
//! actually covered.
//!
//! ## Why the re-sign is not optional
//!
//! A segment's `.ccxatt` binds a digest **list**. Verification resolves the
//! entries it lists and says nothing about a file that is not in it, so a
//! companion added after signing is not "invalid" — it is invisible, and the
//! segment keeps verifying while a whole model's vectors ride along unattested.
//! With `CORECRUXD_COMPANION_ATTESTATION=enforce` that companion would then be
//! refused; in `warn` it loads while the alarm points at the wrong thing. Both
//! outcomes are worse than the rebuild refusing to start, which is what this
//! does when no passport key is readable.

use std::path::{Path, PathBuf};

use corecrux_storage::rebuild::{
    rebuild_ccxe_companions, DenseRebuildEmbedder, RebuildOptions, RebuildReport, RebuildStatus, SegmentReport,
};
use crux_session::passport::{passport_key_path, LocalPassportKey};

use crate::ingest::EmbeddingClient;

/// Companion types this command can rebuild.
///
/// Only `ccxe`. Every other companion is a platform artifact the CE reads and
/// does not write (C7 of the plan); `.ccxe` is the single exception, because the
/// CE legitimately embeds its own vectors.
pub const SUPPORTED_TYPES: [&str; 1] = ["ccxe"];

pub struct Args {
    pub data_dir: PathBuf,
    /// Companion type. Only `ccxe` is supported.
    pub companion_type: String,
    /// Model id to embed with. Defaults to `CORECRUXD_EMBEDDING_MODEL`.
    pub model: Option<String>,
    /// Embedding endpoint. Defaults to `CORECRUXD_EMBEDDING_URL`.
    pub embedding_url: Option<String>,
    pub shard: Option<u32>,
    pub segment: Option<u64>,
    /// Re-embed and rewrite the companion for this model key when it exists.
    /// Never touches another model's key.
    pub force: bool,
    /// Report what would be rebuilt; embed nothing, write nothing, spend nothing.
    pub dry_run: bool,
}

/// What the run did, including what it cost.
#[derive(Debug)]
pub struct Report {
    pub rebuild: RebuildReport,
    /// Segments whose `.ccxatt` was refreshed to cover the new companion.
    pub attestations_refreshed: usize,
    /// Segments that were rebuilt but could not be re-signed, with the reason.
    /// Named rather than counted: an unattested companion is a specific file an
    /// operator has to go and deal with.
    pub attestation_failures: Vec<(String, String)>,
}

/// Bridges the HTTP embedding client to the rebuild engine's trait, counting
/// nothing itself — the engine counts calls, because the engine is what decides
/// how many to make.
struct HttpRebuildEmbedder {
    client: EmbeddingClient,
}

impl DenseRebuildEmbedder for HttpRebuildEmbedder {
    fn model_id(&self) -> &str {
        self.client.model()
    }

    fn embed(&self, text: &str) -> Result<Vec<f32>, String> {
        self.client.embed(text)
    }

    fn profile_json(&self, dimensions: usize) -> Option<Vec<u8>> {
        // The same profile shape `SemanticProfile::from_embedding_config` builds
        // for any external OpenAI-compatible embedder: model + observed
        // dimension, with the tokenizer/prompt/normalisation fields at their
        // "the provider did not tell us" defaults. `dimensions` is what the
        // vectors actually came back as, never a configured guess — a sidecar
        // that disagreed with its own companion would fail the strict check it
        // exists to satisfy.
        let profile = corecrux_memory::embeddings::SemanticProfile::from_parts(
            self.client.model(),
            dimensions,
            "model_default",
            "none",
            "none",
        );
        serde_json::to_vec_pretty(&profile).ok()
    }
}

pub fn run(args: &Args, mut progress: impl FnMut(&SegmentReport)) -> Result<Report, String> {
    if !SUPPORTED_TYPES.contains(&args.companion_type.as_str()) {
        return Err(format!(
            "unsupported companion type {:?}; supported: {}",
            args.companion_type,
            SUPPORTED_TYPES.join(", ")
        ));
    }

    let embedder = HttpRebuildEmbedder {
        client: EmbeddingClient::from_env(
            args.embedding_url.as_deref(),
            args.model.as_deref(),
            "rebuild-companions",
        )
        .map_err(|err| err.to_string())?,
    };

    // Read the key up front, never mint one. A rebuild that discovered at the
    // end that it could not sign would have already spent the credits.
    let key = if args.dry_run {
        None
    } else {
        let key_path = passport_key_path(&args.data_dir);
        Some(LocalPassportKey::from_existing_path(&key_path).map_err(|err| {
            format!(
                "no readable passport key at {} ({err}); a rebuilt companion must be attested, \
                 so run this on the daemon's own data dir",
                key_path.display()
            )
        })?)
    };

    let issued_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    let mut attestations_refreshed = 0usize;
    let mut attestation_failures: Vec<(String, String)> = Vec::new();

    let report = rebuild_ccxe_companions(
        &args.data_dir,
        &embedder,
        &RebuildOptions {
            shard: args.shard,
            segment: args.segment,
            force: args.force,
            dry_run: args.dry_run,
        },
        |segment| {
            progress(segment);
            if !matches!(segment.status, RebuildStatus::Rebuilt { .. }) {
                return;
            }
            let Some(key) = key.as_ref() else { return };
            // Re-sign here rather than in a second pass, so an interrupted run
            // leaves attested work behind rather than a tail of companions the
            // loader will refuse under `enforce`.
            match refresh_attestation(&segment.segments_dir, segment, key, issued_at) {
                Ok(true) => attestations_refreshed += 1,
                Ok(false) => {}
                Err(err) => attestation_failures.push((segment.stem.clone(), err)),
            }
        },
    )
    .map_err(|err| format!("rebuild failed: {err}"))?;

    Ok(Report {
        rebuild: report,
        attestations_refreshed,
        attestation_failures,
    })
}

/// Re-sign a segment's companions so the freshly-written one is covered.
///
/// Shares [`corecrux_index::write_local_attestation`] with the seal path and
/// with `attest-companions`; a second implementation here would be a second
/// chance for the three to disagree about what a signature covers, and a
/// backfill writing stamps the loader rejects turns `none` (which serves in
/// `warn`) into `invalid` (which refuses in every mode).
fn refresh_attestation(
    segments_dir: &Path,
    segment: &SegmentReport,
    key: &LocalPassportKey,
    issued_at: u64,
) -> Result<bool, String> {
    let Some(id_hex) = segment.stem.strip_prefix("seg-").and_then(|rest| rest.split_once('-')) else {
        return Err(format!("cannot parse segment id out of {}", segment.stem));
    };
    let request = corecrux_index::LocalAttestationRequest {
        shard_id: segment.shard_id,
        segment_seq: segment.segment_seq,
        segment_id_hex: id_hex.1,
        // As with the backfill: membership belongs to the segment's own frames,
        // which may hold several tenants. Asserting one here would be a guess
        // baked into a signature.
        tenant_id: None,
        issued_at,
        producer_fpr: key.passport_fpr(),
        builder_commit: option_env!("CORECRUX_GIT_SHA").unwrap_or("unknown"),
    };
    corecrux_index::write_local_attestation(segments_dir, &segment.stem, &request, key.delegation_signing_key())
        .map(|covered| covered.is_some())
        .map_err(|err| err.to_string())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn seal_prose(data_dir: &Path, texts: &[&str]) -> String {
        use corecrux_storage::{AppendEventInput, ShardStorage, ShardStorageOptions};

        let mut storage = ShardStorage::open(
            &data_dir.join("shards"),
            0,
            1,
            ShardStorageOptions {
                build_ccxi: true,
                ..Default::default()
            },
        )
        .unwrap();
        let events: Vec<AppendEventInput<'_>> = texts
            .iter()
            .enumerate()
            .map(|(i, text)| AppendEventInput {
                event_id: Box::leak(format!("evt-{i}").into_boxed_str()),
                occurred_at: "2026-08-11T00:00:00Z",
                event_type: "corecrux.prose.chunk.v1",
                content_type: "text/plain; charset=utf-8",
                payload_bytes: text.as_bytes(),
            })
            .collect();
        let stream_hash = corecrux_frame::stream_hash_xxhash64("tenant-a", "corpus", "doc-1").unwrap();
        storage
            .append_batch(
                stream_hash,
                0,
                "tenant-a",
                "corpus",
                "doc-1",
                "2026-08-11T00:00:00Z",
                &events,
            )
            .unwrap();
        storage.force_seal_head().unwrap();
        drop(storage);

        std::fs::read_dir(data_dir.join("shards").join("shard-0000").join("segments"))
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .find(|n| n.ends_with(".ccxseg"))
            .expect("a sealed segment")
            .trim_end_matches(".ccxseg")
            .to_string()
    }

    struct FixedEmbedder;
    impl DenseRebuildEmbedder for FixedEmbedder {
        fn model_id(&self) -> &str {
            "BAAI/bge-m3"
        }
        fn embed(&self, _text: &str) -> Result<Vec<f32>, String> {
            Ok(vec![0.5, 0.5])
        }
    }

    /// Hazard (b): a companion added after the segment was signed is not covered
    /// by the existing `.ccxatt` — verification resolves only the entries it
    /// lists, so the rebuilt file rides along unattested and the segment still
    /// verifies. The rebuild must refresh the stamp, and the refreshed stamp
    /// must both name the new companion and verify.
    #[test]
    fn a_rebuilt_companion_is_covered_by_the_refreshed_attestation() {
        let tmp = tempfile::tempdir().unwrap();
        let key = LocalPassportKey::from_data_dir(tmp.path()).unwrap();
        let stem = seal_prose(tmp.path(), &["alpha document", "beta document"]);
        let segments = tmp.path().join("shards").join("shard-0000").join("segments");

        // Stamp the segment as it stands — the pre-rebuild state, with no
        // knowledge of the companion that is about to appear.
        let request = corecrux_index::LocalAttestationRequest {
            shard_id: 0,
            segment_seq: 1,
            segment_id_hex: stem.split_once('-').unwrap().1.split_once('-').unwrap().1,
            tenant_id: None,
            issued_at: 1,
            producer_fpr: key.passport_fpr(),
            builder_commit: "test",
        };
        corecrux_index::write_local_attestation(&segments, &stem, &request, key.delegation_signing_key())
            .unwrap()
            .expect("the sealed segment has a .ccxi to attest");
        let before = std::fs::read(segments.join(format!("{stem}.ccxatt"))).unwrap();
        let parsed_before = corecrux_index::decode_attestation(&before).unwrap();
        assert!(
            !parsed_before.body.companions.iter().any(|c| c.ext == "ccxe"),
            "precondition: nothing dense is covered yet"
        );

        let mut refreshed = 0usize;
        let report = rebuild_ccxe_companions(tmp.path(), &FixedEmbedder, &RebuildOptions::default(), |segment| {
            if matches!(segment.status, RebuildStatus::Rebuilt { .. }) {
                assert!(refresh_attestation(&segment.segments_dir, segment, &key, 2).unwrap());
                refreshed += 1;
            }
        })
        .unwrap();
        assert_eq!(report.rebuilt, 1);
        assert_eq!(refreshed, 1);

        let after = std::fs::read(segments.join(format!("{stem}.ccxatt"))).unwrap();
        let parsed = corecrux_index::decode_attestation(&after).unwrap();
        let covered = parsed
            .body
            .companions
            .iter()
            .find(|c| c.ext == "ccxe")
            .expect("the rebuilt companion must be covered");
        assert_eq!(covered.key.as_deref(), Some("baai-bge-m3"));
        assert_eq!(
            covered.blake3,
            corecrux_index::companion_digest(
                &std::fs::read(segments.join(format!("{stem}.ccxe@baai-bge-m3"))).unwrap()
            ),
            "and covered by the digest of the bytes actually on disk"
        );

        // The refreshed stamp must verify, not merely exist: a backfill writing
        // stamps the loader rejects turns `none` into `invalid`, which refuses
        // in every mode while `none` still serves in `warn`.
        let roots = corecrux_index::TrustRoots::new().with_local_device(key.passport_fpr(), key.verifying_key_bytes());
        let segment_id_hex = stem.split_once('-').unwrap().1.split_once('-').unwrap().1;
        let provenance = corecrux_index::verify_parsed(&parsed, &roots, segment_id_hex, |ext, key| {
            let name = match key {
                Some(key) => format!("{stem}.{ext}@{key}"),
                None => format!("{stem}.{ext}"),
            };
            std::fs::read(segments.join(name)).ok()
        })
        .expect("the refreshed attestation must verify");
        assert_eq!(provenance, corecrux_index::Provenance::Local);
    }

    /// The only supported companion type is `ccxe`. Every other companion is a
    /// platform artifact the CE reads and never writes (C7), and a command that
    /// quietly accepted `--type ccxn` would be a builder by another name.
    #[test]
    fn an_unsupported_companion_type_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let err = run(
            &Args {
                data_dir: tmp.path().to_path_buf(),
                companion_type: "ccxn".to_string(),
                model: None,
                embedding_url: Some("http://127.0.0.1:1".to_string()),
                shard: None,
                segment: None,
                force: false,
                dry_run: true,
            },
            |_| {},
        )
        .expect_err("must refuse");
        assert!(err.contains("unsupported companion type"), "{err}");
    }

    /// Without an endpoint there is nothing to embed with, and the failure must
    /// name the flag rather than surfacing as a connection error mid-corpus.
    #[test]
    fn a_missing_embedding_url_is_named_before_any_work() {
        let tmp = tempfile::tempdir().unwrap();
        let previous = std::env::var("CORECRUXD_EMBEDDING_URL").ok();
        std::env::remove_var("CORECRUXD_EMBEDDING_URL");
        let err = run(
            &Args {
                data_dir: tmp.path().to_path_buf(),
                companion_type: "ccxe".to_string(),
                model: None,
                embedding_url: None,
                shard: None,
                segment: None,
                force: false,
                dry_run: true,
            },
            |_| {},
        )
        .expect_err("must refuse");
        if let Some(previous) = previous {
            std::env::set_var("CORECRUXD_EMBEDDING_URL", previous);
        }
        assert!(err.contains("rebuild-companions requires"), "{err}");
    }

    /// Refusing without a passport key is the deliberate choice: an unattested
    /// companion is refused by a daemon in `enforce` mode, so producing one is
    /// worse than not starting.
    #[test]
    fn a_rebuild_refuses_when_it_could_not_attest_what_it_writes() {
        let tmp = tempfile::tempdir().unwrap();
        seal_prose(tmp.path(), &["alpha document"]);
        let err = run(
            &Args {
                data_dir: tmp.path().to_path_buf(),
                companion_type: "ccxe".to_string(),
                model: Some("BAAI/bge-m3".to_string()),
                embedding_url: Some("http://127.0.0.1:1".to_string()),
                shard: None,
                segment: None,
                force: false,
                dry_run: false,
            },
            |_| {},
        )
        .expect_err("must refuse");
        assert!(err.contains("no readable passport key"), "{err}");
        assert!(
            !tmp.path()
                .join("shards/shard-0000/segments")
                .read_dir()
                .unwrap()
                .flatten()
                .any(|e| e.file_name().to_string_lossy().contains(".ccxe")),
            "and it must refuse before writing anything"
        );
    }
}
