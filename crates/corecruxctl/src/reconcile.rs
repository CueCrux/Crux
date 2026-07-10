// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Reconcile driver — compares on-disk state with manifest expectations, surfaces drift + missing segments.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use chrono::{Duration as ChronoDuration, Utc};
use corecrux_frame::decode_canonical_header_bytes_v1;
use corecrux_segment::{decode_frame_v1, decode_segment_v1};
use corecrux_storage::{load_manifest_segment_catalog, SegmentMeta};
use postgres::{Client, NoTls};
use serde::Serialize;

type DynError = Box<dyn std::error::Error + Send + Sync>;

const RECONCILE_SCHEMA_V2: &str = "corecruxctl.reconcile.postgres.v2";
const DAY_NS: u64 = 86_400_000_000_000;

#[derive(Debug, Clone)]
pub struct ReconcilePostgresOptions {
    pub data_dir: PathBuf,
    pub connection_string: String,
    pub tenant_id: String,
    pub stream_type: Option<String>,
    pub stream_id: Option<String>,
    pub shard: Option<u32>,
    pub window_days: Option<u32>,
    pub max_segments: Option<usize>,
    pub batch_size: usize,
    pub sample_limit: usize,
    pub evidence_out: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReconcileHashMismatchSample {
    #[serde(rename = "eventId")]
    pub event_id: String,
    #[serde(rename = "coreCruxPayloadHash")]
    pub corecrux_payload_hash: String,
    #[serde(rename = "postgresPayloadHash")]
    pub postgres_payload_hash: String,
    #[serde(rename = "streamType")]
    pub stream_type: String,
    #[serde(rename = "streamId")]
    pub stream_id: String,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct ReconcileSamples {
    #[serde(rename = "missingInPostgres", default, skip_serializing_if = "Vec::is_empty")]
    pub missing_in_postgres: Vec<String>,
    #[serde(rename = "missingInCoreCrux", default, skip_serializing_if = "Vec::is_empty")]
    pub missing_in_corecrux: Vec<String>,
    #[serde(rename = "hashMismatch", default, skip_serializing_if = "Vec::is_empty")]
    pub hash_mismatch: Vec<ReconcileHashMismatchSample>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReconcilePostgresReport {
    pub schema: String,
    #[serde(rename = "generatedAt")]
    pub generated_at: String,
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    #[serde(rename = "dataDir")]
    pub data_dir: String,
    #[serde(rename = "connectionStringRedacted")]
    pub connection_string_redacted: String,
    #[serde(rename = "streamType", skip_serializing_if = "Option::is_none")]
    pub stream_type: Option<String>,
    #[serde(rename = "streamId", skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<String>,
    #[serde(rename = "shard", skip_serializing_if = "Option::is_none")]
    pub shard: Option<u32>,
    #[serde(rename = "windowDays", skip_serializing_if = "Option::is_none")]
    pub window_days: Option<u32>,
    #[serde(rename = "maxSegments", skip_serializing_if = "Option::is_none")]
    pub max_segments: Option<usize>,
    #[serde(rename = "batchSize")]
    pub batch_size: usize,
    #[serde(rename = "segmentsScanned")]
    pub segments_scanned: u64,
    pub partial: bool,
    #[serde(rename = "elapsedMs")]
    pub elapsed_ms: u64,
    pub checked: u64,
    pub matched: u64,
    #[serde(rename = "missingInPostgres")]
    pub missing_in_postgres: u64,
    #[serde(rename = "missingInCoreCrux")]
    pub missing_in_corecrux: u64,
    #[serde(rename = "hashMismatch")]
    pub hash_mismatch: u64,
    #[serde(rename = "coreCruxEvents")]
    pub corecrux_events: u64,
    #[serde(rename = "postgresRows")]
    pub postgres_rows: u64,
    pub samples: ReconcileSamples,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReconcileRecord {
    payload_hash: String,
    stream_type: String,
    stream_id: String,
}

#[derive(Debug, Clone)]
struct SelectedSegment {
    shard_dir: PathBuf,
    segment: SegmentMeta,
}

#[derive(Debug)]
struct CoreCruxCollectResult {
    records: HashMap<String, ReconcileRecord>,
    segments_scanned: u64,
    partial: bool,
}

#[derive(Debug)]
struct PostgresCollectResult {
    records: HashMap<String, ReconcileRecord>,
    rows: u64,
}

pub fn reconcile_postgres(opts: &ReconcilePostgresOptions) -> Result<ReconcilePostgresReport, DynError> {
    let started = Instant::now();
    let corecrux = collect_corecrux_records(opts)?;
    let postgres = collect_postgres_records(opts)?;
    let (matched, missing_in_postgres, missing_in_corecrux, hash_mismatch, samples) =
        reconcile_maps(&corecrux.records, &postgres.records, opts.sample_limit);

    let report = ReconcilePostgresReport {
        schema: RECONCILE_SCHEMA_V2.to_string(),
        generated_at: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        tenant_id: opts.tenant_id.clone(),
        data_dir: opts.data_dir.display().to_string(),
        connection_string_redacted: redact_connection_string(&opts.connection_string),
        stream_type: opts.stream_type.clone(),
        stream_id: opts.stream_id.clone(),
        shard: opts.shard,
        window_days: opts.window_days,
        max_segments: opts.max_segments,
        batch_size: opts.batch_size.max(1),
        segments_scanned: corecrux.segments_scanned,
        partial: corecrux.partial || has_partial_scope(opts),
        elapsed_ms: started.elapsed().as_millis() as u64,
        checked: corecrux.records.len() as u64,
        matched,
        missing_in_postgres,
        missing_in_corecrux,
        hash_mismatch,
        corecrux_events: corecrux.records.len() as u64,
        postgres_rows: postgres.rows,
        samples,
    };

    if let Some(path) = &opts.evidence_out {
        write_report(path, &report)?;
    }

    Ok(report)
}

fn list_shards(shards_root: &Path) -> Result<Vec<u32>, DynError> {
    let mut shard_ids = Vec::new();
    for entry in std::fs::read_dir(shards_root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(ToOwned::to_owned) else {
            continue;
        };
        let Some(rest) = name.strip_prefix("shard-") else {
            continue;
        };
        let Ok(shard_id) = rest.parse::<u32>() else {
            continue;
        };
        shard_ids.push(shard_id);
    }
    shard_ids.sort_unstable();
    shard_ids.dedup();
    Ok(shard_ids)
}

fn collect_corecrux_records(opts: &ReconcilePostgresOptions) -> Result<CoreCruxCollectResult, DynError> {
    let shards_root = opts.data_dir.join("shards");
    let cutoff_unix_ns = opts
        .window_days
        .map(|days| now_unix_ns().saturating_sub((days as u64) * DAY_NS));
    let mut segments = Vec::new();

    for shard_id in list_shards(&shards_root)? {
        if opts.shard.is_some_and(|expected| expected != shard_id) {
            continue;
        }
        let shard_dir = shards_root.join(format!("shard-{shard_id:04}"));
        let catalog = load_manifest_segment_catalog(&shard_dir)?;
        for segment in catalog.segments {
            if cutoff_unix_ns.is_some_and(|cutoff| segment.sealed_at_unix_ns < cutoff) {
                continue;
            }
            segments.push(SelectedSegment {
                shard_dir: shard_dir.clone(),
                segment,
            });
        }
    }

    let mut partial = false;
    if let Some(limit) = opts.max_segments {
        partial = true;
        segments.sort_by(|left, right| {
            right
                .segment
                .sealed_at_unix_ns
                .cmp(&left.segment.sealed_at_unix_ns)
                .then(right.segment.segment_seq.cmp(&left.segment.segment_seq))
        });
        if segments.len() > limit {
            segments.truncate(limit);
        }
    }

    let segments_scanned = segments.len() as u64;
    let mut records = HashMap::new();
    for selected in segments {
        let segment_path = selected.shard_dir.join(&selected.segment.relative_path);
        let bytes = std::fs::read(&segment_path)?;
        let (_header, _toc_header, entries, _footer) = decode_segment_v1(&bytes)?;
        for entry in entries {
            let start = entry.file_offset as usize;
            let end = start.saturating_add(entry.frame_len as usize);
            if end > bytes.len() {
                return Err(format!("frame range out of bounds for {}:{}", segment_path.display(), entry.seq).into());
            }
            let frame = decode_frame_v1(&bytes[start..end])?;
            if frame.header_bytes.len() < 32 {
                return Err(format!("stored header too short for {}:{}", segment_path.display(), entry.seq).into());
            }
            let canonical_len = frame.header_bytes.len() - 32;
            let header = decode_canonical_header_bytes_v1(&frame.header_bytes[..canonical_len]).map_err(|err| {
                format!(
                    "failed to decode canonical header for {}:{}: {err}",
                    segment_path.display(),
                    entry.seq
                )
            })?;

            if header.tenant_id != opts.tenant_id {
                continue;
            }
            if opts
                .stream_type
                .as_deref()
                .is_some_and(|value| value != header.stream_type)
            {
                continue;
            }
            if opts.stream_id.as_deref().is_some_and(|value| value != header.stream_id) {
                continue;
            }

            let next = ReconcileRecord {
                payload_hash: hex_bytes(&header.payload_hash),
                stream_type: header.stream_type,
                stream_id: header.stream_id,
            };
            match records.get(&header.event_id) {
                Some(existing) if existing != &next => {
                    return Err(format!(
                        "event_id {} maps to conflicting payload hashes across CoreCrux segments",
                        header.event_id
                    )
                    .into());
                }
                Some(_) => {}
                None => {
                    records.insert(header.event_id, next);
                }
            }
        }
    }

    Ok(CoreCruxCollectResult {
        records,
        segments_scanned,
        partial,
    })
}

fn collect_postgres_records(opts: &ReconcilePostgresOptions) -> Result<PostgresCollectResult, DynError> {
    let mut client = Client::connect(&opts.connection_string, NoTls)?;
    let mut records = HashMap::new();
    let mut rows_seen = 0u64;
    let mut last_id = 0i64;
    let batch_size = opts.batch_size.max(1) as i64;
    let cutoff = opts
        .window_days
        .map(|days| (Utc::now() - ChronoDuration::days(days as i64)).to_rfc3339());

    loop {
        let rows = client.query(
            "SELECT id, event_id, payload_hash, stream_type, stream_id
             FROM engine.corecrux_shadow_write_journal
             WHERE tenant_id = $1
               AND ($2::text IS NULL OR stream_type = $2)
               AND ($3::text IS NULL OR stream_id = $3)
               AND id > $4
               AND ($5::timestamptz IS NULL OR written_at >= $5::timestamptz)
             ORDER BY id ASC
             LIMIT $6",
            &[
                &opts.tenant_id,
                &opts.stream_type,
                &opts.stream_id,
                &last_id,
                &cutoff,
                &batch_size,
            ],
        )?;
        if rows.is_empty() {
            break;
        }

        let fetched = rows.len();
        rows_seen = rows_seen.saturating_add(fetched as u64);
        for row in rows {
            last_id = row.get::<_, i64>("id");
            let record = ReconcileRecord {
                payload_hash: row.get::<_, String>("payload_hash"),
                stream_type: row.get::<_, String>("stream_type"),
                stream_id: row.get::<_, String>("stream_id"),
            };
            let event_id = row.get::<_, String>("event_id");
            match records.get(&event_id) {
                Some(existing) if existing != &record => {
                    return Err(format!(
                        "event_id {} maps to conflicting payload hashes in Postgres shadow journal",
                        event_id
                    )
                    .into());
                }
                Some(_) => {}
                None => {
                    records.insert(event_id, record);
                }
            }
        }

        if fetched < batch_size as usize {
            break;
        }
    }

    Ok(PostgresCollectResult {
        records,
        rows: rows_seen,
    })
}

fn reconcile_maps(
    corecrux: &HashMap<String, ReconcileRecord>,
    postgres: &HashMap<String, ReconcileRecord>,
    sample_limit: usize,
) -> (u64, u64, u64, u64, ReconcileSamples) {
    let mut matched = 0u64;
    let mut missing_in_postgres = 0u64;
    let mut missing_in_corecrux = 0u64;
    let mut hash_mismatch = 0u64;
    let mut samples = ReconcileSamples::default();

    for (event_id, core_event) in corecrux {
        match postgres.get(event_id) {
            None => {
                missing_in_postgres = missing_in_postgres.saturating_add(1);
                if samples.missing_in_postgres.len() < sample_limit {
                    samples.missing_in_postgres.push(event_id.clone());
                }
            }
            Some(pg_event) if pg_event.payload_hash != core_event.payload_hash => {
                hash_mismatch = hash_mismatch.saturating_add(1);
                if samples.hash_mismatch.len() < sample_limit {
                    samples.hash_mismatch.push(ReconcileHashMismatchSample {
                        event_id: event_id.clone(),
                        corecrux_payload_hash: core_event.payload_hash.clone(),
                        postgres_payload_hash: pg_event.payload_hash.clone(),
                        stream_type: core_event.stream_type.clone(),
                        stream_id: core_event.stream_id.clone(),
                    });
                }
            }
            Some(_) => {
                matched = matched.saturating_add(1);
            }
        }
    }

    for event_id in postgres.keys() {
        if !corecrux.contains_key(event_id) {
            missing_in_corecrux = missing_in_corecrux.saturating_add(1);
            if samples.missing_in_corecrux.len() < sample_limit {
                samples.missing_in_corecrux.push(event_id.clone());
            }
        }
    }

    (
        matched,
        missing_in_postgres,
        missing_in_corecrux,
        hash_mismatch,
        samples,
    )
}

fn write_report(path: &Path, report: &ReconcilePostgresReport) -> Result<(), DynError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_vec_pretty(report)?)?;
    Ok(())
}

fn has_partial_scope(opts: &ReconcilePostgresOptions) -> bool {
    opts.shard.is_some() || opts.window_days.is_some() || opts.max_segments.is_some()
}

fn redact_connection_string(connection_string: &str) -> String {
    let trimmed = connection_string.trim();
    if trimmed.is_empty() {
        return "empty".to_string();
    }
    let without_query = trimmed.split('?').next().unwrap_or(trimmed);
    if let Some((prefix, suffix)) = without_query.split_once('@') {
        if let Some((scheme, _rest)) = prefix.split_once("://") {
            return format!("{scheme}://***@{suffix}");
        }
    }
    "redacted".to_string()
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn now_unix_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{has_partial_scope, reconcile_maps, ReconcilePostgresOptions, ReconcileRecord};
    use std::collections::HashMap;
    use std::path::PathBuf;

    fn base_options() -> ReconcilePostgresOptions {
        ReconcilePostgresOptions {
            data_dir: PathBuf::from("/tmp/corecrux"),
            connection_string: "postgres://user:secret@example/db".to_string(),
            tenant_id: "tenant-a".to_string(),
            stream_type: None,
            stream_id: None,
            shard: None,
            window_days: None,
            max_segments: None,
            batch_size: 5000,
            sample_limit: 10,
            evidence_out: None,
        }
    }

    #[test]
    fn reconcile_maps_reports_each_divergence_class() {
        let mut corecrux = HashMap::new();
        corecrux.insert(
            "evt-match".to_string(),
            ReconcileRecord {
                payload_hash: "aa".to_string(),
                stream_type: "knowledge".to_string(),
                stream_id: "s1".to_string(),
            },
        );
        corecrux.insert(
            "evt-missing-postgres".to_string(),
            ReconcileRecord {
                payload_hash: "bb".to_string(),
                stream_type: "knowledge".to_string(),
                stream_id: "s1".to_string(),
            },
        );
        corecrux.insert(
            "evt-hash-mismatch".to_string(),
            ReconcileRecord {
                payload_hash: "cc".to_string(),
                stream_type: "knowledge".to_string(),
                stream_id: "s2".to_string(),
            },
        );

        let mut postgres = HashMap::new();
        postgres.insert(
            "evt-match".to_string(),
            ReconcileRecord {
                payload_hash: "aa".to_string(),
                stream_type: "knowledge".to_string(),
                stream_id: "s1".to_string(),
            },
        );
        postgres.insert(
            "evt-hash-mismatch".to_string(),
            ReconcileRecord {
                payload_hash: "dd".to_string(),
                stream_type: "knowledge".to_string(),
                stream_id: "s2".to_string(),
            },
        );
        postgres.insert(
            "evt-missing-corecrux".to_string(),
            ReconcileRecord {
                payload_hash: "ee".to_string(),
                stream_type: "knowledge".to_string(),
                stream_id: "s3".to_string(),
            },
        );

        let (matched, missing_in_postgres, missing_in_corecrux, hash_mismatch, samples) =
            reconcile_maps(&corecrux, &postgres, 8);

        assert_eq!(matched, 1);
        assert_eq!(missing_in_postgres, 1);
        assert_eq!(missing_in_corecrux, 1);
        assert_eq!(hash_mismatch, 1);
        assert_eq!(samples.missing_in_postgres, vec!["evt-missing-postgres"]);
        assert_eq!(samples.missing_in_corecrux, vec!["evt-missing-corecrux"]);
        assert_eq!(samples.hash_mismatch.len(), 1);
        assert_eq!(samples.hash_mismatch[0].event_id, "evt-hash-mismatch");
    }

    #[test]
    fn reconcile_maps_all_matched() {
        let mut corecrux = HashMap::new();
        corecrux.insert(
            "evt-1".to_string(),
            ReconcileRecord {
                payload_hash: "aa".to_string(),
                stream_type: "knowledge".to_string(),
                stream_id: "s1".to_string(),
            },
        );
        corecrux.insert(
            "evt-2".to_string(),
            ReconcileRecord {
                payload_hash: "bb".to_string(),
                stream_type: "knowledge".to_string(),
                stream_id: "s2".to_string(),
            },
        );
        let postgres = corecrux.clone();
        let (matched, missing_pg, missing_cc, hash_mm, samples) = reconcile_maps(&corecrux, &postgres, 10);
        assert_eq!(matched, 2);
        assert_eq!(missing_pg, 0);
        assert_eq!(missing_cc, 0);
        assert_eq!(hash_mm, 0);
        assert!(samples.missing_in_postgres.is_empty());
        assert!(samples.missing_in_corecrux.is_empty());
        assert!(samples.hash_mismatch.is_empty());
    }

    #[test]
    fn reconcile_maps_both_empty() {
        let corecrux = HashMap::new();
        let postgres = HashMap::new();
        let (matched, missing_pg, missing_cc, hash_mm, _samples) = reconcile_maps(&corecrux, &postgres, 10);
        assert_eq!(matched, 0);
        assert_eq!(missing_pg, 0);
        assert_eq!(missing_cc, 0);
        assert_eq!(hash_mm, 0);
    }

    #[test]
    fn reconcile_maps_sample_limit_caps_output() {
        let mut corecrux = HashMap::new();
        for i in 0..20 {
            corecrux.insert(
                format!("evt-{i}"),
                ReconcileRecord {
                    payload_hash: format!("hash-{i}"),
                    stream_type: "t".to_string(),
                    stream_id: "s".to_string(),
                },
            );
        }
        // postgres is empty, so all 20 are missing_in_postgres.
        let postgres = HashMap::new();
        let (_matched, missing_pg, _missing_cc, _hash_mm, samples) = reconcile_maps(&corecrux, &postgres, 5);
        assert_eq!(missing_pg, 20);
        assert_eq!(samples.missing_in_postgres.len(), 5);
    }

    #[test]
    fn redact_connection_string_hides_credentials() {
        assert_eq!(
            super::redact_connection_string("postgres://user:secret@example.com/db"),
            "postgres://***@example.com/db"
        );
        assert_eq!(
            super::redact_connection_string("postgres://user:secret@example.com/db?sslmode=require"),
            "postgres://***@example.com/db"
        );
        assert_eq!(super::redact_connection_string(""), "empty");
        assert_eq!(super::redact_connection_string("no-at-sign"), "redacted");
    }

    #[test]
    fn hex_bytes_produces_lowercase_hex() {
        assert_eq!(super::hex_bytes(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
        assert_eq!(super::hex_bytes(&[]), "");
        assert_eq!(super::hex_bytes(&[0x00, 0xff]), "00ff");
    }

    #[test]
    fn reconcile_report_serializes_to_json() {
        use super::ReconcilePostgresReport;
        let report = ReconcilePostgresReport {
            schema: "test".to_string(),
            generated_at: "2026-01-01T00:00:00Z".to_string(),
            tenant_id: "t".to_string(),
            data_dir: "/tmp".to_string(),
            connection_string_redacted: "redacted".to_string(),
            stream_type: None,
            stream_id: None,
            shard: None,
            window_days: None,
            max_segments: None,
            batch_size: 100,
            segments_scanned: 5,
            partial: false,
            elapsed_ms: 42,
            checked: 10,
            matched: 10,
            missing_in_postgres: 0,
            missing_in_corecrux: 0,
            hash_mismatch: 0,
            corecrux_events: 10,
            postgres_rows: 10,
            samples: super::ReconcileSamples::default(),
        };
        let json = serde_json::to_string(&report).expect("serialize");
        assert!(json.contains("\"schema\":\"test\""));
        assert!(json.contains("\"matched\":10"));
        // Optional fields should be absent when None.
        assert!(!json.contains("\"streamType\""));
    }

    #[test]
    fn partial_scope_detects_window_shard_and_segment_caps() {
        let mut opts = base_options();
        assert!(!has_partial_scope(&opts));
        opts.window_days = Some(7);
        assert!(has_partial_scope(&opts));
        opts.window_days = None;
        opts.shard = Some(4);
        assert!(has_partial_scope(&opts));
        opts.shard = None;
        opts.max_segments = Some(10);
        assert!(has_partial_scope(&opts));
    }

    // ── redact_connection_string edge cases ────────────────────────────

    #[test]
    fn redact_connection_string_whitespace_only() {
        assert_eq!(super::redact_connection_string("   "), "empty");
    }

    #[test]
    fn redact_connection_string_no_scheme() {
        // Has @ but no :// prefix
        assert_eq!(super::redact_connection_string("user@host"), "redacted");
    }

    #[test]
    fn redact_connection_string_multiple_at_signs() {
        assert_eq!(
            super::redact_connection_string("postgres://user:p@ss@host/db"),
            "postgres://***@ss@host/db"
        );
    }

    // ── hex_bytes edge cases ───────────────────────────────────────────

    #[test]
    fn hex_bytes_single_byte() {
        assert_eq!(super::hex_bytes(&[0x0A]), "0a");
    }

    #[test]
    fn hex_bytes_all_zeros() {
        assert_eq!(super::hex_bytes(&[0, 0, 0]), "000000");
    }

    // ── reconcile_maps: hash mismatch sample limit ────────────────────

    #[test]
    fn reconcile_maps_hash_mismatch_sample_limit() {
        let mut corecrux = HashMap::new();
        let mut postgres = HashMap::new();
        for i in 0..20 {
            corecrux.insert(
                format!("evt-{i}"),
                ReconcileRecord {
                    payload_hash: format!("core-{i}"),
                    stream_type: "t".to_string(),
                    stream_id: "s".to_string(),
                },
            );
            postgres.insert(
                format!("evt-{i}"),
                ReconcileRecord {
                    payload_hash: format!("pg-{i}"),
                    stream_type: "t".to_string(),
                    stream_id: "s".to_string(),
                },
            );
        }
        let (_matched, _missing_pg, _missing_cc, hash_mm, samples) = reconcile_maps(&corecrux, &postgres, 3);
        assert_eq!(hash_mm, 20);
        assert_eq!(samples.hash_mismatch.len(), 3);
    }

    // ── reconcile_maps: missing_in_corecrux sample limit ──────────────

    #[test]
    fn reconcile_maps_missing_in_corecrux_sample_limit() {
        let corecrux = HashMap::new();
        let mut postgres = HashMap::new();
        for i in 0..15 {
            postgres.insert(
                format!("evt-{i}"),
                ReconcileRecord {
                    payload_hash: format!("hash-{i}"),
                    stream_type: "t".to_string(),
                    stream_id: "s".to_string(),
                },
            );
        }
        let (_matched, _missing_pg, missing_cc, _hash_mm, samples) = reconcile_maps(&corecrux, &postgres, 4);
        assert_eq!(missing_cc, 15);
        assert_eq!(samples.missing_in_corecrux.len(), 4);
    }

    // ── write_report creates parent directories ───────────────────────

    #[test]
    fn write_report_creates_dirs_and_writes_json() {
        use super::{write_report, ReconcilePostgresReport, ReconcileSamples};
        let tmp = tempfile::TempDir::new().unwrap();
        let nested = tmp.path().join("a/b/c/report.json");
        let report = ReconcilePostgresReport {
            schema: "test".to_string(),
            generated_at: "2026-01-01T00:00:00Z".to_string(),
            tenant_id: "t".to_string(),
            data_dir: "/tmp".to_string(),
            connection_string_redacted: "r".to_string(),
            stream_type: None,
            stream_id: None,
            shard: None,
            window_days: None,
            max_segments: None,
            batch_size: 1,
            segments_scanned: 0,
            partial: false,
            elapsed_ms: 0,
            checked: 0,
            matched: 0,
            missing_in_postgres: 0,
            missing_in_corecrux: 0,
            hash_mismatch: 0,
            corecrux_events: 0,
            postgres_rows: 0,
            samples: ReconcileSamples::default(),
        };
        write_report(&nested, &report).unwrap();
        assert!(nested.exists());
        let contents = std::fs::read_to_string(&nested).unwrap();
        assert!(contents.contains("\"schema\""));
    }

    // ── ReconcileRecord equality ──────────────────────────────────────

    #[test]
    fn reconcile_record_equality() {
        let a = ReconcileRecord {
            payload_hash: "aa".to_string(),
            stream_type: "t".to_string(),
            stream_id: "s".to_string(),
        };
        let b = a.clone();
        assert_eq!(a, b);

        let c = ReconcileRecord {
            payload_hash: "bb".to_string(),
            stream_type: "t".to_string(),
            stream_id: "s".to_string(),
        };
        assert_ne!(a, c);
    }

    // ── ReconcileSamples serialization ────────────────────────────────

    #[test]
    fn reconcile_samples_empty_skips_fields() {
        let samples = super::ReconcileSamples::default();
        let json = serde_json::to_string(&samples).unwrap();
        // All Vec fields are empty so skip_serializing_if should omit them
        assert!(!json.contains("missingInPostgres"));
        assert!(!json.contains("missingInCoreCrux"));
        assert!(!json.contains("hashMismatch"));
    }

    // ── has_partial_scope: all combinations ──────────────────────────

    #[test]
    fn has_partial_scope_all_set() {
        let mut opts = base_options();
        opts.shard = Some(1);
        opts.window_days = Some(7);
        opts.max_segments = Some(10);
        assert!(has_partial_scope(&opts));
    }

    // ── ReconcileHashMismatchSample serialization ────────────────────

    // ── now_unix_ns plausible ──────────────────────────────────────────

    #[test]
    fn now_unix_ns_plausible() {
        let ns = super::now_unix_ns();
        assert!(ns > 1_577_836_800_000_000_000); // 2020-01-01
    }

    // ── list_shards edge cases ─────────────────────────────────────────

    #[test]
    fn list_shards_from_tempdir() {
        let dir = tempfile::TempDir::new().unwrap();
        let shards = super::list_shards(dir.path()).unwrap();
        assert!(shards.is_empty());
    }

    #[test]
    fn list_shards_finds_sorted_and_deduped() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir(dir.path().join("shard-0005")).unwrap();
        std::fs::create_dir(dir.path().join("shard-0001")).unwrap();
        std::fs::create_dir(dir.path().join("shard-0010")).unwrap();
        std::fs::create_dir(dir.path().join("other-dir")).unwrap();
        std::fs::write(dir.path().join("shard-0099"), b"file").unwrap();
        let shards = super::list_shards(dir.path()).unwrap();
        assert_eq!(shards, vec![1, 5, 10]);
    }

    // ── ReconcileRecord ────────────────────────────────────────────────

    #[test]
    fn reconcile_record_clone_and_debug() {
        let r = ReconcileRecord {
            payload_hash: "aabb".to_string(),
            stream_type: "t".to_string(),
            stream_id: "s".to_string(),
        };
        let c = r.clone();
        assert_eq!(r, c);
        let dbg = format!("{:?}", r);
        assert!(dbg.contains("aabb"));
    }

    // ── ReconcileSamples non-empty serialization ───────────────────────

    #[test]
    fn reconcile_samples_non_empty_includes_fields() {
        let samples = super::ReconcileSamples {
            missing_in_postgres: vec!["evt-1".to_string()],
            missing_in_corecrux: vec!["evt-2".to_string()],
            hash_mismatch: vec![super::ReconcileHashMismatchSample {
                event_id: "e".to_string(),
                corecrux_payload_hash: "a".to_string(),
                postgres_payload_hash: "b".to_string(),
                stream_type: "t".to_string(),
                stream_id: "s".to_string(),
            }],
        };
        let json = serde_json::to_string(&samples).unwrap();
        assert!(json.contains("missingInPostgres"));
        assert!(json.contains("missingInCoreCrux"));
        assert!(json.contains("hashMismatch"));
    }

    // ── ReconcilePostgresReport with all optional fields ───────────────

    #[test]
    fn reconcile_report_with_all_optional_fields() {
        let report = super::ReconcilePostgresReport {
            schema: "test".to_string(),
            generated_at: "2026-01-01T00:00:00Z".to_string(),
            tenant_id: "t".to_string(),
            data_dir: "/tmp".to_string(),
            connection_string_redacted: "r".to_string(),
            stream_type: Some("knowledge".to_string()),
            stream_id: Some("s1".to_string()),
            shard: Some(1),
            window_days: Some(7),
            max_segments: Some(100),
            batch_size: 5000,
            segments_scanned: 50,
            partial: true,
            elapsed_ms: 123,
            checked: 200,
            matched: 180,
            missing_in_postgres: 10,
            missing_in_corecrux: 5,
            hash_mismatch: 5,
            corecrux_events: 200,
            postgres_rows: 190,
            samples: super::ReconcileSamples::default(),
        };
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["streamType"], "knowledge");
        assert_eq!(json["streamId"], "s1");
        assert_eq!(json["shard"], 1);
        assert_eq!(json["windowDays"], 7);
        assert_eq!(json["maxSegments"], 100);
        assert_eq!(json["partial"], true);
    }

    #[test]
    fn hash_mismatch_sample_serializes_all_fields() {
        let sample = super::ReconcileHashMismatchSample {
            event_id: "e1".to_string(),
            corecrux_payload_hash: "aaa".to_string(),
            postgres_payload_hash: "bbb".to_string(),
            stream_type: "knowledge".to_string(),
            stream_id: "s1".to_string(),
        };
        let json = serde_json::to_value(&sample).unwrap();
        assert_eq!(json["eventId"], "e1");
        assert_eq!(json["coreCruxPayloadHash"], "aaa");
        assert_eq!(json["postgresPayloadHash"], "bbb");
        assert_eq!(json["streamType"], "knowledge");
        assert_eq!(json["streamId"], "s1");
    }

    // ── reconcile_maps: sample_limit=0 caps all samples ──────────

    #[test]
    fn reconcile_maps_sample_limit_zero() {
        let mut corecrux = HashMap::new();
        corecrux.insert(
            "evt-1".to_string(),
            ReconcileRecord {
                payload_hash: "aa".to_string(),
                stream_type: "t".to_string(),
                stream_id: "s".to_string(),
            },
        );
        let postgres = HashMap::new();
        let (_matched, missing_pg, _missing_cc, _hash_mm, samples) = reconcile_maps(&corecrux, &postgres, 0);
        assert_eq!(missing_pg, 1);
        // sample_limit=0 means no samples collected
        assert!(samples.missing_in_postgres.is_empty());
    }

    // ── reconcile_maps: only missing_in_corecrux ─────────────────

    #[test]
    fn reconcile_maps_only_missing_in_corecrux() {
        let corecrux = HashMap::new();
        let mut postgres = HashMap::new();
        postgres.insert(
            "evt-1".to_string(),
            ReconcileRecord {
                payload_hash: "aa".to_string(),
                stream_type: "t".to_string(),
                stream_id: "s".to_string(),
            },
        );
        postgres.insert(
            "evt-2".to_string(),
            ReconcileRecord {
                payload_hash: "bb".to_string(),
                stream_type: "t".to_string(),
                stream_id: "s".to_string(),
            },
        );
        let (matched, missing_pg, missing_cc, hash_mm, samples) = reconcile_maps(&corecrux, &postgres, 10);
        assert_eq!(matched, 0);
        assert_eq!(missing_pg, 0);
        assert_eq!(missing_cc, 2);
        assert_eq!(hash_mm, 0);
        assert_eq!(samples.missing_in_corecrux.len(), 2);
    }

    // ── reconcile_maps: mixed divergences with saturating ────────

    #[test]
    fn reconcile_maps_large_counts_saturating() {
        let mut corecrux = HashMap::new();
        let mut postgres = HashMap::new();
        // Many matched + some mismatches
        for i in 0..100 {
            let hash_core = format!("hash-{i}");
            let hash_pg = if i % 10 == 0 {
                format!("different-{i}")
            } else {
                format!("hash-{i}")
            };
            corecrux.insert(
                format!("evt-{i}"),
                ReconcileRecord {
                    payload_hash: hash_core,
                    stream_type: "t".to_string(),
                    stream_id: "s".to_string(),
                },
            );
            postgres.insert(
                format!("evt-{i}"),
                ReconcileRecord {
                    payload_hash: hash_pg,
                    stream_type: "t".to_string(),
                    stream_id: "s".to_string(),
                },
            );
        }
        let (matched, missing_pg, missing_cc, hash_mm, _samples) = reconcile_maps(&corecrux, &postgres, 5);
        assert_eq!(matched + hash_mm, 100);
        assert_eq!(missing_pg, 0);
        assert_eq!(missing_cc, 0);
        assert_eq!(hash_mm, 10); // every 10th is mismatched
    }

    // ── redact_connection_string: no at sign with scheme ─────────

    #[test]
    fn redact_connection_string_scheme_no_at() {
        assert_eq!(super::redact_connection_string("postgres://localhost/db"), "redacted");
    }

    // ── redact_connection_string: with port ──────────────────────

    #[test]
    fn redact_connection_string_with_port() {
        assert_eq!(
            super::redact_connection_string("postgres://user:pwd@host:5432/db"),
            "postgres://***@host:5432/db"
        );
    }

    // ── redact_connection_string: tab/newline in input ────────────

    #[test]
    fn redact_connection_string_whitespace_trimmed() {
        assert_eq!(
            super::redact_connection_string("  postgres://user:pwd@host/db  "),
            "postgres://***@host/db"
        );
    }

    // ── has_partial_scope: none set ──────────────────────────────

    #[test]
    fn has_partial_scope_none_set() {
        let opts = base_options();
        assert!(!has_partial_scope(&opts));
    }

    // ── write_report: overwrite existing ─────────────────────────

    #[test]
    fn write_report_overwrites_existing() {
        use super::{write_report, ReconcilePostgresReport, ReconcileSamples};
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("report.json");
        let report1 = ReconcilePostgresReport {
            schema: "first".to_string(),
            generated_at: "2026-01-01T00:00:00Z".to_string(),
            tenant_id: "t".to_string(),
            data_dir: "/tmp".to_string(),
            connection_string_redacted: "r".to_string(),
            stream_type: None,
            stream_id: None,
            shard: None,
            window_days: None,
            max_segments: None,
            batch_size: 1,
            segments_scanned: 0,
            partial: false,
            elapsed_ms: 0,
            checked: 0,
            matched: 0,
            missing_in_postgres: 0,
            missing_in_corecrux: 0,
            hash_mismatch: 0,
            corecrux_events: 0,
            postgres_rows: 0,
            samples: ReconcileSamples::default(),
        };
        write_report(&path, &report1).unwrap();
        let report2 = ReconcilePostgresReport {
            schema: "second".to_string(),
            ..report1
        };
        write_report(&path, &report2).unwrap();
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("\"second\""));
        assert!(!contents.contains("\"first\""));
    }

    // ── ReconcileHashMismatchSample equality ─────────────────────

    #[test]
    fn reconcile_hash_mismatch_sample_equality() {
        let a = super::ReconcileHashMismatchSample {
            event_id: "e1".to_string(),
            corecrux_payload_hash: "a".to_string(),
            postgres_payload_hash: "b".to_string(),
            stream_type: "t".to_string(),
            stream_id: "s".to_string(),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    // ── ReconcileSamples equality ────────────────────────────────

    #[test]
    fn reconcile_samples_equality() {
        let a = super::ReconcileSamples {
            missing_in_postgres: vec!["e1".to_string()],
            missing_in_corecrux: vec![],
            hash_mismatch: vec![],
        };
        let b = a.clone();
        assert_eq!(a, b);
        let c = super::ReconcileSamples::default();
        assert_ne!(a, c);
    }

    // ── list_shards: nested dirs ignored ─────────────────────────

    #[test]
    fn list_shards_ignores_non_shard_dirs() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir(dir.path().join("shard-0001")).unwrap();
        std::fs::create_dir(dir.path().join("not-a-shard")).unwrap();
        std::fs::create_dir(dir.path().join("shard-abc")).unwrap(); // non-numeric
        std::fs::create_dir(dir.path().join("SHARD-0002")).unwrap(); // wrong case
        let shards = super::list_shards(dir.path()).unwrap();
        assert_eq!(shards, vec![1]);
    }

    // ── ReconcilePostgresReport: partial field ───────────────────

    #[test]
    fn reconcile_report_partial_field() {
        let report = super::ReconcilePostgresReport {
            schema: "test".to_string(),
            generated_at: "2026-01-01T00:00:00Z".to_string(),
            tenant_id: "t".to_string(),
            data_dir: "/tmp".to_string(),
            connection_string_redacted: "r".to_string(),
            stream_type: None,
            stream_id: None,
            shard: None,
            window_days: None,
            max_segments: None,
            batch_size: 1,
            segments_scanned: 0,
            partial: true,
            elapsed_ms: 0,
            checked: 0,
            matched: 0,
            missing_in_postgres: 0,
            missing_in_corecrux: 0,
            hash_mismatch: 0,
            corecrux_events: 0,
            postgres_rows: 0,
            samples: super::ReconcileSamples::default(),
        };
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["partial"], true);
        assert_eq!(json["segmentsScanned"], 0);
    }

    // ── DAY_NS constant ─────────────────────────────────────────

    #[test]
    fn day_ns_constant_is_correct() {
        assert_eq!(super::DAY_NS, 86_400_000_000_000);
        assert_eq!(super::DAY_NS, 86400 * 1_000_000_000);
    }

    // ── RECONCILE_SCHEMA_V2 ─────────────────────────────────────

    #[test]
    fn reconcile_schema_v2_value() {
        assert_eq!(super::RECONCILE_SCHEMA_V2, "corecruxctl.reconcile.postgres.v2");
    }

    // ── ReconcilePostgresOptions: clone + debug ──────────────────────

    #[test]
    fn reconcile_postgres_options_clone_debug() {
        let opts = base_options();
        let cloned = opts.clone();
        assert_eq!(cloned.tenant_id, "tenant-a");
        assert_eq!(cloned.batch_size, 5000);
        let dbg = format!("{:?}", opts);
        assert!(dbg.contains("tenant-a"));
    }

    // ── ReconcilePostgresOptions: all fields set ─────────────────────

    #[test]
    fn reconcile_postgres_options_all_fields() {
        let opts = ReconcilePostgresOptions {
            data_dir: std::path::PathBuf::from("/data"),
            connection_string: "postgres://user:pass@host/db".to_string(),
            tenant_id: "t".to_string(),
            stream_type: Some("knowledge".to_string()),
            stream_id: Some("s1".to_string()),
            shard: Some(2),
            window_days: Some(7),
            max_segments: Some(100),
            batch_size: 1000,
            sample_limit: 5,
            evidence_out: Some(std::path::PathBuf::from("/out/report.json")),
        };
        assert_eq!(opts.stream_type.as_deref(), Some("knowledge"));
        assert_eq!(opts.shard, Some(2));
        assert_eq!(
            opts.evidence_out.as_ref().unwrap().display().to_string(),
            "/out/report.json"
        );
    }

    // ── ReconcileHashMismatchSample: debug + clone ───────────────────

    #[test]
    fn reconcile_hash_mismatch_sample_debug() {
        let sample = super::ReconcileHashMismatchSample {
            event_id: "e1".to_string(),
            corecrux_payload_hash: "a".to_string(),
            postgres_payload_hash: "b".to_string(),
            stream_type: "t".to_string(),
            stream_id: "s".to_string(),
        };
        let dbg = format!("{:?}", sample);
        assert!(dbg.contains("e1"));
        assert!(dbg.contains("corecrux_payload_hash"));
    }

    // ── ReconcilePostgresReport: equality ────────────────────────────

    #[test]
    fn reconcile_report_equality() {
        let report1 = super::ReconcilePostgresReport {
            schema: "test".to_string(),
            generated_at: "now".to_string(),
            tenant_id: "t".to_string(),
            data_dir: "/tmp".to_string(),
            connection_string_redacted: "r".to_string(),
            stream_type: None,
            stream_id: None,
            shard: None,
            window_days: None,
            max_segments: None,
            batch_size: 1,
            segments_scanned: 0,
            partial: false,
            elapsed_ms: 0,
            checked: 0,
            matched: 0,
            missing_in_postgres: 0,
            missing_in_corecrux: 0,
            hash_mismatch: 0,
            corecrux_events: 0,
            postgres_rows: 0,
            samples: super::ReconcileSamples::default(),
        };
        let report2 = report1.clone();
        assert_eq!(report1, report2);
    }

    // ── reconcile_maps: one-sided with hash mismatch ─────────────────

    #[test]
    fn reconcile_maps_single_hash_mismatch() {
        let mut corecrux = HashMap::new();
        corecrux.insert(
            "evt-1".to_string(),
            ReconcileRecord {
                payload_hash: "aa".to_string(),
                stream_type: "t".to_string(),
                stream_id: "s".to_string(),
            },
        );
        let mut postgres = HashMap::new();
        postgres.insert(
            "evt-1".to_string(),
            ReconcileRecord {
                payload_hash: "bb".to_string(),
                stream_type: "t".to_string(),
                stream_id: "s".to_string(),
            },
        );
        let (matched, missing_pg, missing_cc, hash_mm, samples) = reconcile_maps(&corecrux, &postgres, 10);
        assert_eq!(matched, 0);
        assert_eq!(missing_pg, 0);
        assert_eq!(missing_cc, 0);
        assert_eq!(hash_mm, 1);
        assert_eq!(samples.hash_mismatch.len(), 1);
        assert_eq!(samples.hash_mismatch[0].corecrux_payload_hash, "aa");
        assert_eq!(samples.hash_mismatch[0].postgres_payload_hash, "bb");
    }

    // ── redact_connection_string: no password ────────────────────────

    #[test]
    fn redact_connection_string_no_password() {
        assert_eq!(
            super::redact_connection_string("postgres://user@host/db"),
            "postgres://***@host/db"
        );
    }

    // ── hex_bytes: large input ───────────────────────────────────────

    #[test]
    fn hex_bytes_large_input() {
        let data: Vec<u8> = (0..=255).collect();
        let hex = super::hex_bytes(&data);
        assert_eq!(hex.len(), 512);
        assert!(hex.starts_with("000102"));
        assert!(hex.ends_with("feff"));
    }

    // ── ReconcileSamples: default is truly empty ─────────────────────

    #[test]
    fn reconcile_samples_default_all_empty() {
        let s = super::ReconcileSamples::default();
        assert!(s.missing_in_postgres.is_empty());
        assert!(s.missing_in_corecrux.is_empty());
        assert!(s.hash_mismatch.is_empty());
    }
}
