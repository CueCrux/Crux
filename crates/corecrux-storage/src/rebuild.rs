// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Offline companion rebuild — regenerate a `.ccxe` dense companion from the
//! sealed segment that is its own source.
//!
//! ExecPlan `crux-companion-vocabulary-unification-2026-08-08` M7.
//!
//! ## Why this exists
//!
//! Before this, the answer to "a better embedder shipped, how do I move?" was
//! re-ingest everything — which assumes the customer still holds the sources.
//! For a corpus fed from transient input that is not an upgrade path, it is data
//! loss. But the sources are not needed: `.ccxseg` holds the chunk text, and a
//! dense companion is derived from it. `companions::build_ccxi_companion`
//! already runs that derivation at seal time, walking frames and feeding a
//! builder; this is the same walk with embedding substituted for tokenising, run
//! offline against a segment that was sealed long ago.
//!
//! ## Additive by construction
//!
//! A rebuild writes `<stem>.ccxe@<key>` where `key` is
//! [`corecrux_index::model_id_file_key`] of the new model, **alongside** the
//! existing companion rather than over it:
//!
//! ```text
//! seg-…-….ccxe                       ← existing, still serving
//! seg-…-….ccxe@baai-bge-m3           ← new, built by the rebuild
//! ```
//!
//! Cutover is pointing the query embedder at the new model; rollback is pointing
//! it back; reclaim is deleting the old key once confident. At no point is there
//! a window with no dense lane. Nothing here ever deletes: [`RebuildOptions::force`]
//! rewrites **only the key being built**, and dropping another model's key is a
//! separate, explicit act.
//!
//! The `@<key>` suffix disambiguates files on disk and nothing more. The
//! authoritative `model_id` is in the `.ccxe` header, and the query-side fusion
//! guard reads it there.

use std::path::{Path, PathBuf};

use super::{fsync_dir, io_err, Result, StorageError};

/// The embedder a rebuild runs against.
///
/// Deliberately one text per call rather than a batch: the delegated door
/// (`/v1/compute/embed`) is metered at one credit per call, so the unit the
/// report counts has to be the unit the customer is billed for. A batching
/// implementation is free to buffer internally as long as it counts honestly.
pub trait DenseRebuildEmbedder {
    /// Model identity written into the `.ccxe` header — the authoritative one.
    fn model_id(&self) -> &str;

    /// Embed one chunk of text.
    fn embed(&self, text: &str) -> std::result::Result<Vec<f32>, String>;

    /// Serialised embedder profile to persist as `<stem>.ccxprof@<key>`, if the
    /// embedder can describe itself beyond its model id.
    ///
    /// `dimensions` is the dimension actually observed in this segment's
    /// vectors, not a configured guess.
    fn profile_json(&self, _dimensions: usize) -> Option<Vec<u8>> {
        None
    }
}

/// What a rebuild did to one segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RebuildStatus {
    /// A companion was written for this model key.
    Rebuilt { vectors: usize, dimensions: usize },
    /// The key already existed and `force` was not set. Nothing was embedded —
    /// re-running a rebuild must not re-bill it.
    AlreadyPresent,
    /// Nothing to embed. **Not a failure**: a segment holding fact records
    /// rather than prose yields no text payload, and CoreCrux's rebuilder
    /// reports `no_text_payloads` there by design (LME-S `seg-0021` is the
    /// worked example). Failing it would make every such corpus unrebuildable.
    Skipped { reason: &'static str },
    /// This segment could not be rebuilt. Other segments still are.
    Failed { error: String },
}

/// Reason string for a segment that carries no embeddable text.
pub const SKIP_NO_TEXT_PAYLOADS: &str = "no_text_payloads";

/// Per-segment line of the rebuild report.
#[derive(Debug, Clone)]
pub struct SegmentReport {
    /// The `segments/` directory holding this segment, so a caller can re-sign
    /// the bundle without re-deriving the path.
    pub segments_dir: PathBuf,
    /// `seg-<seq>-<idhex>`.
    pub stem: String,
    pub shard_id: u32,
    pub segment_seq: u64,
    pub status: RebuildStatus,
}

/// Aggregate outcome of a rebuild run.
#[derive(Debug, Clone)]
pub struct RebuildReport {
    pub model_id: String,
    /// `model_id_file_key(model_id)` — the `@<key>` suffix written on disk.
    pub model_key: String,
    pub segments_scanned: usize,
    pub rebuilt: usize,
    pub already_present: usize,
    pub skipped: usize,
    pub failed: usize,
    /// Embedder calls made. On the delegated door this is credits spent, one per
    /// call, which is why it is reported rather than merely logged.
    pub embedding_calls: usize,
    pub vectors_written: usize,
    pub segments: Vec<SegmentReport>,
}

impl RebuildReport {
    /// Stems this run actually wrote a companion for.
    pub fn rebuilt_segments(&self) -> impl Iterator<Item = &SegmentReport> {
        self.segments
            .iter()
            .filter(|s| matches!(s.status, RebuildStatus::Rebuilt { .. }))
    }
}

/// Which segments a run touches.
#[derive(Debug, Clone, Default)]
pub struct RebuildOptions {
    /// Restrict to one shard id.
    pub shard: Option<u32>,
    /// Restrict to one segment sequence.
    pub segment: Option<u64>,
    /// Re-embed and rewrite the companion for **this model key** when it already
    /// exists. Never touches another model's key.
    pub force: bool,
    /// Report what would be rebuilt without embedding or writing anything.
    pub dry_run: bool,
}

/// Rebuild the `.ccxe` dense companion of every sealed segment under `data_dir`,
/// keyed by the embedder's model.
///
/// Idempotent: a segment whose key already exists is reported `AlreadyPresent`
/// and **not re-embedded**, so re-running a long, metered rebuild after an
/// interruption costs only the segments still missing.
///
/// `on_segment` fires once per segment as it completes, because on a real corpus
/// this runs for hours and a report only at the end is not progress. It is also
/// where a caller re-signs the segment's attestation while the rebuild is still
/// running, so an interrupted run leaves attested work behind rather than a tail
/// of uncovered companions.
pub fn rebuild_ccxe_companions(
    data_dir: &Path,
    embedder: &dyn DenseRebuildEmbedder,
    options: &RebuildOptions,
    mut on_segment: impl FnMut(&SegmentReport),
) -> Result<RebuildReport> {
    let model_id = embedder.model_id().to_string();
    let model_key = corecrux_index::model_id_file_key(&model_id);

    let mut report = RebuildReport {
        model_id,
        model_key: model_key.clone(),
        segments_scanned: 0,
        rebuilt: 0,
        already_present: 0,
        skipped: 0,
        failed: 0,
        embedding_calls: 0,
        vectors_written: 0,
        segments: Vec::new(),
    };

    let shards_dir = data_dir.join("shards");
    let shard_entries = std::fs::read_dir(&shards_dir).map_err(io_err)?;
    let mut shard_dirs: Vec<(u32, PathBuf)> = Vec::new();
    for shard in shard_entries.flatten() {
        let name = shard.file_name().to_string_lossy().to_string();
        let Some(shard_id) = name.strip_prefix("shard-").and_then(|n| n.parse::<u32>().ok()) else {
            continue;
        };
        if options.shard.is_some_and(|want| want != shard_id) {
            continue;
        }
        shard_dirs.push((shard_id, shard.path()));
    }
    shard_dirs.sort();

    for (shard_id, shard_dir) in shard_dirs {
        let segments_dir = shard_dir.join("segments");
        let Ok(entries) = std::fs::read_dir(&segments_dir) else {
            continue;
        };
        let mut stems: Vec<(String, PathBuf)> = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("ccxseg") {
                continue;
            }
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            stems.push((stem.to_string(), path));
        }
        stems.sort();

        for (stem, segment_path) in stems {
            let Some(segment_seq) = parse_segment_seq(&stem) else {
                continue;
            };
            if options.segment.is_some_and(|want| want != segment_seq) {
                continue;
            }
            report.segments_scanned += 1;

            let mut calls = 0usize;
            let status = rebuild_one(
                &shard_dir,
                &segments_dir,
                &stem,
                &segment_path,
                &model_key,
                embedder,
                options,
                &mut calls,
            );
            report.embedding_calls += calls;

            match &status {
                RebuildStatus::Rebuilt { vectors, .. } => {
                    report.rebuilt += 1;
                    report.vectors_written += vectors;
                }
                RebuildStatus::AlreadyPresent => report.already_present += 1,
                RebuildStatus::Skipped { .. } => report.skipped += 1,
                RebuildStatus::Failed { .. } => report.failed += 1,
            }

            let line = SegmentReport {
                segments_dir: segments_dir.clone(),
                stem,
                shard_id,
                segment_seq,
                status,
            };
            on_segment(&line);
            report.segments.push(line);
        }
    }

    Ok(report)
}

/// `seg-<seq>-<idhex>` → `seq`.
fn parse_segment_seq(stem: &str) -> Option<u64> {
    let rest = stem.strip_prefix("seg-")?;
    let (seq, _id_hex) = rest.split_once('-')?;
    seq.parse().ok()
}

#[allow(clippy::too_many_arguments)] // one cohesive call; splitting it would only move the arguments
fn rebuild_one(
    shard_dir: &Path,
    segments_dir: &Path,
    stem: &str,
    segment_path: &Path,
    model_key: &str,
    embedder: &dyn DenseRebuildEmbedder,
    options: &RebuildOptions,
    calls: &mut usize,
) -> RebuildStatus {
    let target = segments_dir.join(format!("{stem}.ccxe@{model_key}"));
    if target.exists() && !options.force {
        return RebuildStatus::AlreadyPresent;
    }

    let bytes = match std::fs::read(segment_path) {
        Ok(bytes) => bytes,
        Err(err) => return RebuildStatus::Failed { error: err.to_string() },
    };
    let header = match corecrux_segment::decode_segment_v1(&bytes) {
        Ok((header, _toc, _entries, _footer)) => header,
        Err(err) => {
            return RebuildStatus::Failed {
                error: format!("segment does not decode: {err}"),
            }
        }
    };
    let frames = match corecrux_segment::decode_segment_frames_v1(&bytes) {
        Ok(frames) => frames,
        Err(err) => {
            return RebuildStatus::Failed {
                error: format!("frames do not decode: {err}"),
            }
        }
    };

    // `doc_id` is the append index over ALL frames, including the ones with no
    // indexable text. `build_ccxi_companion` takes it from the same enumeration
    // and skips without consuming an id, so a companion built here lines up with
    // the `.ccxi` beside it and with the `(doc_id, segment_index)` key the dense
    // lane uses at query time. Renumbering around the skips would silently shift
    // every vector after the first fact record.
    let mut entries: Vec<(u32, Vec<f32>)> = Vec::new();
    let mut dimensions: Option<usize> = None;
    for (doc_id, frame) in frames.iter().enumerate() {
        let text = match std::str::from_utf8(&frame.payload_bytes) {
            Ok(text) if !text.is_empty() => text,
            _ => continue,
        };
        if options.dry_run {
            // Enough to tell `no_text_payloads` from "would rebuild" without
            // spending a credit to find out.
            entries.push((doc_id as u32, Vec::new()));
            continue;
        }
        *calls += 1;
        let vector = match embedder.embed(text) {
            Ok(vector) => vector,
            Err(err) => {
                return RebuildStatus::Failed {
                    error: format!("embedding frame {doc_id} failed: {err}"),
                }
            }
        };
        if vector.is_empty() || vector.iter().any(|v| !v.is_finite()) {
            return RebuildStatus::Failed {
                error: format!("embedder returned an empty or non-finite vector for frame {doc_id}"),
            };
        }
        match dimensions {
            None => dimensions = Some(vector.len()),
            Some(expected) if expected != vector.len() => {
                return RebuildStatus::Failed {
                    error: format!(
                        "embedding dimension changed within a segment: expected {expected}, got {}",
                        vector.len()
                    ),
                }
            }
            _ => {}
        }
        entries.push((doc_id as u32, vector));
    }

    if entries.is_empty() {
        return RebuildStatus::Skipped {
            reason: SKIP_NO_TEXT_PAYLOADS,
        };
    }
    if options.dry_run {
        return RebuildStatus::Rebuilt {
            vectors: entries.len(),
            dimensions: 0,
        };
    }
    let Some(dimensions) = dimensions else {
        return RebuildStatus::Skipped {
            reason: SKIP_NO_TEXT_PAYLOADS,
        };
    };
    let Ok(dim) = u16::try_from(dimensions) else {
        return RebuildStatus::Failed {
            error: format!("embedding dimension {dimensions} exceeds the .ccxe header field"),
        };
    };

    // Identity comes off the sealed header, never the filename: a segment that
    // was hand-copied under the wrong name must not have that name written into
    // its companion. `epoch` likewise — the ingest writer stamps 0 because a CE
    // node tracks no dataplane compaction generation, but here the real one is
    // right there in the segment.
    let mut builder = corecrux_index::CcxeBuilder::new(
        header.shard_id,
        header.segment_seq,
        header.epoch,
        dim,
        embedder.model_id(),
    );
    for (doc_id, vector) in &entries {
        builder.add_vector(*doc_id, vector.clone());
    }

    if let Err(err) = write_atomic(shard_dir, &target, &builder.build()) {
        return RebuildStatus::Failed { error: err.to_string() };
    }
    if let Some(profile) = embedder.profile_json(dimensions) {
        let profile_path = segments_dir.join(format!("{stem}.ccxprof@{model_key}"));
        if let Err(err) = write_atomic(shard_dir, &profile_path, &profile) {
            return RebuildStatus::Failed { error: err.to_string() };
        }
    }

    RebuildStatus::Rebuilt {
        vectors: entries.len(),
        dimensions,
    }
}

/// Write through the shard's `tmp/` dir and rename into place.
///
/// The staging file lives in `tmp/`, not beside the target: a `.partial` in
/// `segments/` is not on the companion allowlist, so an interrupted rebuild
/// would leave debris the next shard open sweeps into quarantine. `tmp/` is
/// exactly where the open path expects to find and clear an interrupted write.
fn write_atomic(shard_dir: &Path, target: &Path, bytes: &[u8]) -> Result<()> {
    let tmp_dir = shard_dir.join("tmp");
    std::fs::create_dir_all(&tmp_dir).map_err(io_err)?;
    let Some(name) = target.file_name().and_then(|n| n.to_str()) else {
        return Err(StorageError::Internal {
            msg: format!("companion path has no file name: {}", target.display()),
        });
    };
    let tmp = tmp_dir.join(format!("{name}.partial"));
    std::fs::write(&tmp, bytes).map_err(io_err)?;
    std::fs::rename(&tmp, target).map_err(io_err)?;
    if let Some(parent) = target.parent() {
        fsync_dir(parent)?;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// Deterministic stand-in for a real embedder: a hash of the text, so a
    /// vector is reproducible across runs (which is what idempotence asserts)
    /// and differs per model (which is what the fusion guard asserts).
    struct FakeEmbedder {
        model: String,
        dim: usize,
        calls: std::cell::Cell<usize>,
    }

    impl FakeEmbedder {
        fn new(model: &str, dim: usize) -> Self {
            Self {
                model: model.to_string(),
                dim,
                calls: std::cell::Cell::new(0),
            }
        }
    }

    impl DenseRebuildEmbedder for FakeEmbedder {
        fn model_id(&self) -> &str {
            &self.model
        }

        fn embed(&self, text: &str) -> std::result::Result<Vec<f32>, String> {
            self.calls.set(self.calls.get() + 1);
            let seed = blake3::hash(format!("{}\n{text}", self.model).as_bytes());
            Ok((0..self.dim)
                .map(|i| f32::from(seed.as_bytes()[i % 32]) / 255.0)
                .collect())
        }

        fn profile_json(&self, dimensions: usize) -> Option<Vec<u8>> {
            Some(format!("{{\"model\":\"{}\",\"dimensions\":{dimensions}}}", self.model).into_bytes())
        }
    }

    fn seal_prose(dir: &Path, texts: &[&str]) -> String {
        use crate::{AppendEventInput, ShardStorage, ShardStorageOptions};

        let mut storage = ShardStorage::open(
            &dir.join("shards"),
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
        sealed_stem(dir)
    }

    fn segments_dir(dir: &Path) -> PathBuf {
        dir.join("shards").join("shard-0000").join("segments")
    }

    /// The stem of the one sealed segment in a freshly-seeded test data dir.
    fn sealed_stem(dir: &Path) -> String {
        std::fs::read_dir(segments_dir(dir))
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .find(|n| n.ends_with(".ccxseg"))
            .expect("a sealed segment")
            .trim_end_matches(".ccxseg")
            .to_string()
    }

    /// Test 17 (M7): a rebuild under a second model writes its own keyed
    /// companion and leaves the first one exactly as it was.
    #[test]
    fn rebuild_under_a_second_model_is_additive() {
        let tmp = tempfile::tempdir().unwrap();
        let stem = seal_prose(tmp.path(), &["alpha text", "beta text", "gamma text"]);
        let segments = segments_dir(tmp.path());

        // Stand in for the companion an earlier ingest wrote under model A.
        let model_a = FakeEmbedder::new("model-a", 8);
        let mut builder = corecrux_index::CcxeBuilder::new(0, 1, 1, 8, model_a.model_id());
        for doc_id in 0..3u32 {
            builder.add_vector(doc_id, model_a.embed("seed").unwrap());
        }
        let existing = segments.join(format!("{stem}.ccxe"));
        std::fs::write(&existing, builder.build()).unwrap();
        let before = std::fs::read(&existing).unwrap();

        let model_b = FakeEmbedder::new("BAAI/bge-m3", 8);
        let report = rebuild_ccxe_companions(tmp.path(), &model_b, &RebuildOptions::default(), |_| {}).unwrap();

        assert_eq!(report.model_key, "baai-bge-m3");
        assert_eq!(report.rebuilt, 1);
        assert_eq!(report.vectors_written, 3);
        assert_eq!(report.embedding_calls, 3, "one metered call per chunk");

        let keyed = segments.join(format!("{stem}.ccxe@baai-bge-m3"));
        assert!(keyed.exists(), "the new companion must exist");
        assert!(existing.exists(), "and the old one must still exist");
        assert_eq!(
            std::fs::read(&existing).unwrap(),
            before,
            "the rebuild must not have touched model A's bytes"
        );

        // Header model id is the authority, and it is the new model's.
        let reader = corecrux_index::CcxeReader::from_path(&keyed).unwrap();
        assert_eq!(reader.header.model_id, "BAAI/bge-m3");
        assert_eq!(reader.doc_ids, vec![0, 1, 2]);
    }

    /// Test 20 (M7): a fact-only segment has no text to embed. That is a
    /// reported outcome, not a failure — CoreCrux's rebuilder behaves the same
    /// way on LME-S `seg-0021`, and failing it would make such a corpus
    /// permanently unrebuildable.
    #[test]
    fn a_segment_with_no_text_payloads_is_skipped_not_failed() {
        use crate::{AppendEventInput, ShardStorage, ShardStorageOptions};

        let tmp = tempfile::tempdir().unwrap();
        let mut storage = ShardStorage::open(&tmp.path().join("shards"), 0, 1, ShardStorageOptions::default()).unwrap();
        let stream_hash = corecrux_frame::stream_hash_xxhash64("tenant-a", "facts", "doc-1").unwrap();
        storage
            .append_batch(
                stream_hash,
                0,
                "tenant-a",
                "facts",
                "doc-1",
                "2026-08-11T00:00:00Z",
                &[AppendEventInput {
                    event_id: "fact-1",
                    occurred_at: "2026-08-11T00:00:00Z",
                    event_type: "corecrux.entity.fact.v1",
                    content_type: "application/cbor",
                    // Invalid UTF-8: a binary fact record, not prose.
                    payload_bytes: &[0xff, 0xfe, 0xfd, 0xfc],
                }],
            )
            .unwrap();
        storage.force_seal_head().unwrap();
        drop(storage);

        let embedder = FakeEmbedder::new("model-b", 8);
        let report = rebuild_ccxe_companions(tmp.path(), &embedder, &RebuildOptions::default(), |_| {}).unwrap();

        assert_eq!(report.failed, 0, "a fact-only segment is not a failure");
        assert_eq!(report.skipped, 1);
        assert_eq!(report.embedding_calls, 0, "nothing to embed, nothing to bill");
        assert!(matches!(
            report.segments[0].status,
            RebuildStatus::Skipped {
                reason: SKIP_NO_TEXT_PAYLOADS
            }
        ));
        assert_eq!(
            std::fs::read_dir(segments_dir(tmp.path()))
                .unwrap()
                .flatten()
                .filter(|e| e.file_name().to_string_lossy().contains(".ccxe"))
                .count(),
            0,
            "and no empty companion is left behind"
        );
    }

    /// Test 21 (M7): re-running writes the same bytes and does not duplicate a
    /// key. The second run must also not re-embed — on the delegated door that
    /// is a second bill for work already paid for.
    #[test]
    fn rebuild_is_idempotent_and_does_not_rebill() {
        let tmp = tempfile::tempdir().unwrap();
        let stem = seal_prose(tmp.path(), &["alpha text", "beta text"]);
        let segments = segments_dir(tmp.path());
        let embedder = FakeEmbedder::new("model-b", 8);

        let first = rebuild_ccxe_companions(tmp.path(), &embedder, &RebuildOptions::default(), |_| {}).unwrap();
        assert_eq!(first.rebuilt, 1);
        assert_eq!(first.embedding_calls, 2);
        let keyed = segments.join(format!("{stem}.ccxe@model-b"));
        let after_first = std::fs::read(&keyed).unwrap();

        let second = rebuild_ccxe_companions(tmp.path(), &embedder, &RebuildOptions::default(), |_| {}).unwrap();
        assert_eq!(second.already_present, 1);
        assert_eq!(second.rebuilt, 0);
        assert_eq!(second.embedding_calls, 0, "an existing key must not be re-embedded");
        assert_eq!(std::fs::read(&keyed).unwrap(), after_first, "bytes unchanged");

        // And a forced re-embed of the same key is byte-identical too, so the
        // builder itself is deterministic rather than the skip merely hiding it.
        let forced = rebuild_ccxe_companions(
            tmp.path(),
            &embedder,
            &RebuildOptions {
                force: true,
                ..Default::default()
            },
            |_| {},
        )
        .unwrap();
        assert_eq!(forced.rebuilt, 1);
        assert_eq!(
            std::fs::read(&keyed).unwrap(),
            after_first,
            "same bytes on a forced rebuild"
        );

        let keys: Vec<String> = std::fs::read_dir(&segments)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.contains(".ccxe@"))
            .collect();
        assert_eq!(keys.len(), 1, "exactly one file per key, never a duplicate: {keys:?}");
    }

    /// `doc_id` must be the append index over every frame, including the ones
    /// with no text. Renumbering around a skipped fact record would shift every
    /// vector after it against the `.ccxi` that shares the segment — both files
    /// still valid, every dense score attributed to the wrong chunk.
    #[test]
    fn doc_ids_skip_non_text_frames_rather_than_renumbering() {
        use crate::{AppendEventInput, ShardStorage, ShardStorageOptions};

        let tmp = tempfile::tempdir().unwrap();
        let mut storage = ShardStorage::open(&tmp.path().join("shards"), 0, 1, ShardStorageOptions::default()).unwrap();
        let stream_hash = corecrux_frame::stream_hash_xxhash64("tenant-a", "corpus", "doc-1").unwrap();
        storage
            .append_batch(
                stream_hash,
                0,
                "tenant-a",
                "corpus",
                "doc-1",
                "2026-08-11T00:00:00Z",
                &[
                    AppendEventInput {
                        event_id: "a",
                        occurred_at: "2026-08-11T00:00:00Z",
                        event_type: "corecrux.prose.chunk.v1",
                        content_type: "text/plain; charset=utf-8",
                        payload_bytes: b"first chunk",
                    },
                    AppendEventInput {
                        event_id: "b",
                        occurred_at: "2026-08-11T00:00:00Z",
                        event_type: "corecrux.entity.fact.v1",
                        content_type: "application/cbor",
                        payload_bytes: &[0xff, 0xfe],
                    },
                    AppendEventInput {
                        event_id: "c",
                        occurred_at: "2026-08-11T00:00:00Z",
                        event_type: "corecrux.prose.chunk.v1",
                        content_type: "text/plain; charset=utf-8",
                        payload_bytes: b"third chunk",
                    },
                ],
            )
            .unwrap();
        storage.force_seal_head().unwrap();
        drop(storage);
        let stem = sealed_stem(tmp.path());

        let embedder = FakeEmbedder::new("model-b", 8);
        rebuild_ccxe_companions(tmp.path(), &embedder, &RebuildOptions::default(), |_| {}).unwrap();

        let reader =
            corecrux_index::CcxeReader::from_path(segments_dir(tmp.path()).join(format!("{stem}.ccxe@model-b")))
                .unwrap();
        assert_eq!(reader.doc_ids, vec![0, 2], "the fact frame consumes doc_id 1");
    }

    /// `--dry-run` reports the outcomes a real run would, without embedding
    /// (which on the delegated door means without spending) or writing.
    #[test]
    fn dry_run_costs_nothing_and_writes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let stem = seal_prose(tmp.path(), &["alpha text", "beta text"]);
        let embedder = FakeEmbedder::new("model-b", 8);

        let report = rebuild_ccxe_companions(
            tmp.path(),
            &embedder,
            &RebuildOptions {
                dry_run: true,
                ..Default::default()
            },
            |_| {},
        )
        .unwrap();

        assert_eq!(report.rebuilt, 1);
        assert_eq!(report.embedding_calls, 0);
        assert!(!segments_dir(tmp.path()).join(format!("{stem}.ccxe@model-b")).exists());
    }

    /// A per-segment filter must actually restrict the run — on a metered
    /// rebuild, a filter that silently matched everything is a bill.
    #[test]
    fn segment_and_shard_filters_restrict_the_run() {
        let tmp = tempfile::tempdir().unwrap();
        seal_prose(tmp.path(), &["alpha text"]);
        let embedder = FakeEmbedder::new("model-b", 8);

        let other_segment = rebuild_ccxe_companions(
            tmp.path(),
            &embedder,
            &RebuildOptions {
                segment: Some(9999),
                ..Default::default()
            },
            |_| {},
        )
        .unwrap();
        assert_eq!(other_segment.segments_scanned, 0);
        assert_eq!(other_segment.embedding_calls, 0);

        let other_shard = rebuild_ccxe_companions(
            tmp.path(),
            &embedder,
            &RebuildOptions {
                shard: Some(7),
                ..Default::default()
            },
            |_| {},
        )
        .unwrap();
        assert_eq!(other_shard.segments_scanned, 0);
    }

    /// An embedder failure fails its own segment and no other. A rebuild over a
    /// large corpus that aborted on the first transient error would have to
    /// start over, re-billing everything it had already done.
    #[test]
    fn an_embedder_failure_is_confined_to_its_segment() {
        struct Failing;
        impl DenseRebuildEmbedder for Failing {
            fn model_id(&self) -> &str {
                "model-b"
            }
            fn embed(&self, _text: &str) -> std::result::Result<Vec<f32>, String> {
                Err("provider said no".to_string())
            }
        }

        let tmp = tempfile::tempdir().unwrap();
        seal_prose(tmp.path(), &["alpha text"]);
        let report = rebuild_ccxe_companions(tmp.path(), &Failing, &RebuildOptions::default(), |_| {}).unwrap();

        assert_eq!(report.failed, 1);
        assert_eq!(report.rebuilt, 0);
        assert!(matches!(report.segments[0].status, RebuildStatus::Failed { .. }));
    }
}
