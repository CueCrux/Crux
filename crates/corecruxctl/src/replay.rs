// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use base64::Engine;
use corecrux_frame::{
    canonical_header_bytes_v1, compute_header_hash, compute_payload_hash, CanonicalHeaderV1,
};
use corecrux_types::{DriftClass, DRIFT_SOURCE_CHANGE};

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct FrameLocationJson {
    #[serde(rename = "shardId")]
    pub shard_id: u64,
    #[serde(rename = "segmentId")]
    pub segment_id: u64,
    pub offset: u64,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct V3JsonlRecord {
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    #[serde(rename = "streamType")]
    pub stream_type: String,
    #[serde(rename = "streamId")]
    pub stream_id: String,
    pub seq: u64,
    #[serde(rename = "eventId")]
    pub event_id: String,
    #[serde(rename = "occurredAt")]
    pub occurred_at: String,
    #[serde(rename = "ingestedAt")]
    pub ingested_at: String,
    #[serde(rename = "eventType")]
    pub event_type: String,
    #[serde(rename = "contentType")]
    pub content_type: String,
    #[serde(rename = "payloadB64")]
    pub payload_b64: String,
    pub location: FrameLocationJson,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ReplayDigest {
    pub total_events: u64,
    pub per_stream_last_seq: BTreeMap<String, u64>,
    pub digest_blake3: String,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ReplayFirstDivergence {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub segment_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub toc_offset: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ReplayPackReport {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub drift_class: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_digest: Option<String>,
    pub actual_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_divergence: Option<ReplayFirstDivergence>,
    pub strict: bool,
    pub total_events: u64,
    pub input: String,
}

fn resolve_pack_input_jsonl(
    pack: &Path,
) -> Result<PathBuf, Box<dyn std::error::Error + Send + Sync>> {
    let candidates = [
        pack.join("input.jsonl"),
        pack.join("events.jsonl"),
        pack.join("segments.jsonl"),
        pack.join("replay.jsonl"),
    ];
    for c in candidates {
        if c.exists() {
            return Ok(c);
        }
    }
    Err(format!(
        "replay pack input not found under {} (expected one of: input.jsonl, events.jsonl, segments.jsonl, replay.jsonl)",
        pack.display()
    )
    .into())
}

fn extract_digest_field(v: &serde_json::Value) -> Option<String> {
    let candidates = [
        "/digest_blake3",
        "/digest",
        "/expected_digest",
        "/expectedDigest",
        "/replayDigest",
        "/digestBlake3",
    ];
    for key in candidates {
        if let Some(s) = v.pointer(key).and_then(|x| x.as_str()) {
            if !s.is_empty() {
                return Some(s.to_string());
            }
        }
    }
    None
}

fn load_expected_digest_from_pack(
    pack: &Path,
) -> Result<Option<String>, Box<dyn std::error::Error + Send + Sync>> {
    let candidates = [
        pack.join("expected/digest.json"),
        pack.join("expected/replay.digest.json"),
        pack.join("expected.json"),
        pack.join("manifest.json"),
    ];
    for c in candidates {
        if !c.exists() {
            continue;
        }
        let bytes = std::fs::read(&c)?;
        let v: serde_json::Value = serde_json::from_slice(&bytes)?;
        if let Some(d) = extract_digest_field(&v) {
            return Ok(Some(d));
        }
    }
    Ok(None)
}

pub fn replay_digest_from_pack(
    pack: &Path,
    strict: bool,
) -> Result<ReplayPackReport, Box<dyn std::error::Error + Send + Sync>> {
    if !pack.is_dir() {
        return Err(format!("pack path must be a directory: {}", pack.display()).into());
    }
    let input = resolve_pack_input_jsonl(pack)?;
    let digest = replay_digest_from_jsonl(&input)?;
    let expected = load_expected_digest_from_pack(pack)?;
    let ok = expected
        .as_ref()
        .is_none_or(|exp| exp.eq_ignore_ascii_case(&digest.digest_blake3));
    let drift_class = if ok {
        None
    } else {
        Some(DriftClass::SourceChange.as_str().to_string())
    };
    let report = ReplayPackReport {
        ok,
        drift_class,
        expected_digest: expected,
        actual_digest: digest.digest_blake3,
        first_divergence: if ok {
            None
        } else {
            Some(ReplayFirstDivergence {
                segment_id: None,
                toc_offset: None,
                seq: None,
            })
        },
        strict,
        total_events: digest.total_events,
        input: input.display().to_string(),
    };
    if strict && !report.ok {
        return Err(
            format!("strict replay pack mismatch (drift_class={DRIFT_SOURCE_CHANGE})").into(),
        );
    }
    Ok(report)
}

pub fn replay_digest_from_jsonl(
    path: &Path,
) -> Result<ReplayDigest, Box<dyn std::error::Error + Send + Sync>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let mut total_events: u64 = 0;
    let mut per_stream_last_seq: BTreeMap<String, u64> = BTreeMap::new();
    let mut hasher = blake3::Hasher::new();

    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let rec: V3JsonlRecord = serde_json::from_str(&line)?;
        let payload =
            base64::engine::general_purpose::STANDARD.decode(rec.payload_b64.as_bytes())?;
        let payload_hash = compute_payload_hash(&payload);

        let canonical = CanonicalHeaderV1 {
            tenant_id: rec.tenant_id.clone(),
            stream_id: rec.stream_id.clone(),
            stream_type: rec.stream_type.clone(),
            seq: rec.seq,
            event_id: rec.event_id.clone(),
            occurred_at: rec.occurred_at.clone(),
            ingested_at: rec.ingested_at.clone(),
            event_type: rec.event_type.clone(),
            content_type: rec.content_type.clone(),
            payload_len: payload.len() as u32,
            payload_hash,
        };
        let header_bytes = canonical_header_bytes_v1(&canonical);
        let header_hash = compute_header_hash(&header_bytes);

        // Digest update is deterministic: (headerHash || payloadHash || location_bytes).
        hasher.update(&header_hash);
        hasher.update(&payload_hash);
        hasher.update(&rec.location.shard_id.to_le_bytes());
        hasher.update(&rec.location.segment_id.to_le_bytes());
        hasher.update(&rec.location.offset.to_le_bytes());

        total_events += 1;
        let stream_key = format!(
            "{}\u{0}{}\u{0}{}",
            rec.tenant_id, rec.stream_type, rec.stream_id
        );
        per_stream_last_seq.insert(stream_key, rec.seq);
    }

    let digest_blake3 = hasher.finalize().to_hex().to_string();
    Ok(ReplayDigest {
        total_events,
        per_stream_last_seq,
        digest_blake3,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        load_expected_digest_from_pack, replay_digest_from_pack, resolve_pack_input_jsonl,
    };

    fn temp_pack_dir(name: &str) -> std::path::PathBuf {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("corecruxctl-replay-{name}-{ts}"));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    fn write_file(path: &std::path::Path, content: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create parent");
        }
        std::fs::write(path, content).expect("write file");
    }

    #[test]
    fn resolves_pack_input_candidates() {
        let dir = temp_pack_dir("input-candidates");
        let events = dir.join("events.jsonl");
        write_file(&events, "\n");
        let resolved = resolve_pack_input_jsonl(&dir).expect("resolve input");
        assert_eq!(resolved, events);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn loads_expected_digest_from_expected_digest_file() {
        let dir = temp_pack_dir("expected-digest");
        write_file(
            &dir.join("expected/digest.json"),
            r#"{"digest_blake3":"abc123"}"#,
        );
        write_file(
            &dir.join("manifest.json"),
            r#"{"digest_blake3":"should_not_win"}"#,
        );
        let got = load_expected_digest_from_pack(&dir)
            .expect("load expected digest")
            .expect("digest present");
        assert_eq!(got, "abc123");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn replay_pack_reports_drift_and_strict_fails() {
        let dir = temp_pack_dir("strict-drift");
        write_file(
            &dir.join("input.jsonl"),
            r#"{"tenantId":"t","streamType":"s","streamId":"id","seq":1,"eventId":"e1","occurredAt":"2026-01-01T00:00:00Z","ingestedAt":"2026-01-01T00:00:00Z","eventType":"evt","contentType":"application/json","payloadB64":"e30=","location":{"shardId":1,"segmentId":1,"offset":0}}"#,
        );
        write_file(
            &dir.join("expected/digest.json"),
            r#"{"digest_blake3":"deadbeef"}"#,
        );

        let non_strict = replay_digest_from_pack(&dir, false).expect("non-strict replay");
        assert!(!non_strict.ok);
        assert_eq!(
            non_strict.drift_class.as_deref(),
            Some("DRIFT_SOURCE_CHANGE")
        );

        let strict = replay_digest_from_pack(&dir, true);
        assert!(strict.is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
