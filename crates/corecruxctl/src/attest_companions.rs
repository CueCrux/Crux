// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! `corecruxctl attest-companions` — stamp provenance on segments sealed before
//! attestation existed.
//!
//! Every companion built from now on is signed at seal time. A corpus that
//! predates that carries none, so on the first run of an attestation-aware
//! daemon every one of its segments resolves to `none` and the alarm fires on
//! data that is not actually suspect — the exact false-positive that makes an
//! alarm worth ignoring.
//!
//! This walks the shards and signs what is already there, with the same key, the
//! same body and the same writer the seal path uses
//! ([`corecrux_index::write_local_attestation`]). Two implementations would be
//! two chances for the backfill and the live writer to disagree about what a
//! signature covers.
//!
//! ## What this does and does not claim
//!
//! A backfilled stamp says **this daemon vouches for these bytes as they are
//! now** — it is `local` provenance, identical in meaning to a segment this
//! daemon sealed itself. It does **not** retroactively prove where the bytes
//! came from. If a corpus may already hold companions from somewhere else, that
//! is a question to settle before running this, not after: signing them makes
//! them indistinguishable from your own work.

use std::path::{Path, PathBuf};

use crux_session::passport::{passport_key_path, LocalPassportKey};

#[derive(Debug, Default)]
pub struct Report {
    pub attested: usize,
    pub companions_covered: usize,
    pub already_attested: usize,
    pub no_companions: usize,
    pub would_attest: usize,
    pub failed: Vec<(String, String)>,
}

pub struct Args {
    pub data_dir: PathBuf,
    /// Restrict to one shard id.
    pub shard: Option<u32>,
    /// Report without writing.
    pub dry_run: bool,
    /// Re-sign segments that already carry a `.ccxatt`.
    pub force: bool,
}

/// Segment stem → its `.ccxseg` path, for one segments directory.
fn segment_stems(segments_dir: &Path) -> std::io::Result<Vec<(String, PathBuf)>> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(segments_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("ccxseg") {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        out.push((stem.to_string(), path));
    }
    out.sort();
    Ok(out)
}

/// `seg-<seq>-<idhex>` → `(seq, idhex)`.
fn parse_stem(stem: &str) -> Option<(u64, &str)> {
    let rest = stem.strip_prefix("seg-")?;
    let (seq, id_hex) = rest.split_once('-')?;
    Some((seq.parse().ok()?, id_hex))
}

pub fn run(args: &Args) -> Result<Report, String> {
    let key_path = passport_key_path(&args.data_dir);
    // Read, never mint. Minting here would stamp a corpus with an identity that
    // exists only because this command ran, which no verifier would recognise
    // as the daemon's.
    let key = LocalPassportKey::from_existing_path(&key_path).map_err(|err| {
        format!(
            "no readable passport key at {} ({err}); run this on the daemon's own data dir",
            key_path.display()
        )
    })?;

    let issued_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    let shards_dir = args.data_dir.join("shards");
    let mut report = Report::default();

    let shard_entries =
        std::fs::read_dir(&shards_dir).map_err(|err| format!("cannot read {}: {err}", shards_dir.display()))?;

    for shard in shard_entries.flatten() {
        let shard_name = shard.file_name().to_string_lossy().to_string();
        let Some(shard_id) = shard_name.strip_prefix("shard-").and_then(|n| n.parse::<u32>().ok()) else {
            continue;
        };
        if args.shard.is_some_and(|want| want != shard_id) {
            continue;
        }
        let segments_dir = shard.path().join("segments");
        let Ok(stems) = segment_stems(&segments_dir) else {
            continue;
        };

        for (stem, _path) in stems {
            let Some((segment_seq, id_hex)) = parse_stem(&stem) else {
                continue;
            };
            if !args.force && segments_dir.join(format!("{stem}.ccxatt")).exists() {
                report.already_attested += 1;
                continue;
            }

            // Ask before writing so `--dry-run` reports the same three outcomes
            // the real run would, rather than promising to stamp a segment that
            // has nothing to stamp.
            match corecrux_index::collect_companion_digests(&segments_dir, &stem) {
                Ok(c) if c.is_empty() => {
                    report.no_companions += 1;
                    continue;
                }
                Ok(_) => {}
                Err(err) => {
                    report.failed.push((stem.clone(), err.to_string()));
                    continue;
                }
            }
            if args.dry_run {
                report.would_attest += 1;
                continue;
            }

            let request = corecrux_index::LocalAttestationRequest {
                shard_id,
                segment_seq,
                segment_id_hex: id_hex,
                // The backfill does not claim a tenant. Membership belongs to the
                // segment's own frames, which may hold several; asserting one here
                // would be a guess baked into a signature.
                tenant_id: None,
                issued_at,
                producer_fpr: key.passport_fpr(),
                builder_commit: option_env!("CORECRUX_GIT_SHA").unwrap_or("unknown"),
            };
            match corecrux_index::write_local_attestation(&segments_dir, &stem, &request, key.delegation_signing_key())
            {
                Ok(Some(covered)) => {
                    report.attested += 1;
                    report.companions_covered += covered;
                }
                Ok(None) => report.no_companions += 1,
                Err(err) => report.failed.push((stem.clone(), err.to_string())),
            }
        }
    }

    Ok(report)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn seed(dir: &Path, stem: &str, with_companion: bool) {
        let segments = dir.join("shards").join("shard-0000").join("segments");
        std::fs::create_dir_all(&segments).unwrap();
        std::fs::write(segments.join(format!("{stem}.ccxseg")), vec![0u8; 64]).unwrap();
        if with_companion {
            std::fs::write(segments.join(format!("{stem}.ccxi")), vec![1u8; 32]).unwrap();
        }
    }

    fn args(dir: &Path) -> Args {
        Args {
            data_dir: dir.to_path_buf(),
            shard: None,
            dry_run: false,
            force: false,
        }
    }

    #[test]
    fn backfills_segments_that_have_companions() {
        let tmp = tempfile::tempdir().unwrap();
        LocalPassportKey::from_data_dir(tmp.path()).unwrap();
        seed(tmp.path(), "seg-00000000000000000001-aa", true);

        let report = run(&args(tmp.path())).unwrap();
        assert_eq!(report.attested, 1);
        assert_eq!(report.companions_covered, 1);
        assert!(tmp
            .path()
            .join("shards/shard-0000/segments/seg-00000000000000000001-aa.ccxatt")
            .exists());
    }

    /// A fact-only segment has nothing to attest. That is a reportable outcome,
    /// not a failure, and not a stamp over an empty set.
    #[test]
    fn a_segment_with_no_companions_is_reported_not_stamped() {
        let tmp = tempfile::tempdir().unwrap();
        LocalPassportKey::from_data_dir(tmp.path()).unwrap();
        seed(tmp.path(), "seg-00000000000000000002-bb", false);

        let report = run(&args(tmp.path())).unwrap();
        assert_eq!(report.no_companions, 1);
        assert_eq!(report.attested, 0);
        assert!(!tmp
            .path()
            .join("shards/shard-0000/segments/seg-00000000000000000002-bb.ccxatt")
            .exists());
    }

    #[test]
    fn an_existing_stamp_is_left_alone_unless_forced() {
        let tmp = tempfile::tempdir().unwrap();
        LocalPassportKey::from_data_dir(tmp.path()).unwrap();
        seed(tmp.path(), "seg-00000000000000000003-cc", true);
        assert_eq!(run(&args(tmp.path())).unwrap().attested, 1);

        let second = run(&args(tmp.path())).unwrap();
        assert_eq!(second.already_attested, 1);
        assert_eq!(second.attested, 0);

        let forced = run(&Args {
            force: true,
            ..args(tmp.path())
        })
        .unwrap();
        assert_eq!(forced.attested, 1);
    }

    /// `--dry-run` must report the outcome the real run would, including that a
    /// companion-less segment would not be stamped.
    #[test]
    fn dry_run_writes_nothing_and_distinguishes_the_outcomes() {
        let tmp = tempfile::tempdir().unwrap();
        LocalPassportKey::from_data_dir(tmp.path()).unwrap();
        seed(tmp.path(), "seg-00000000000000000004-dd", true);
        seed(tmp.path(), "seg-00000000000000000005-ee", false);

        let report = run(&Args {
            dry_run: true,
            ..args(tmp.path())
        })
        .unwrap();
        assert_eq!(report.would_attest, 1);
        assert_eq!(report.no_companions, 1);
        assert_eq!(report.attested, 0);
        assert!(!tmp
            .path()
            .join("shards/shard-0000/segments/seg-00000000000000000004-dd.ccxatt")
            .exists());
    }

    /// Minting a key would stamp the corpus with an identity that exists only
    /// because this command ran — one no verifier would accept as the daemon's.
    #[test]
    fn refuses_when_there_is_no_passport_key() {
        let tmp = tempfile::tempdir().unwrap();
        seed(tmp.path(), "seg-00000000000000000006-ff", true);

        let err = run(&args(tmp.path())).expect_err("must refuse");
        assert!(err.contains("no readable passport key"), "{err}");
        assert!(!tmp.path().join("passport.key").exists());
    }
}
