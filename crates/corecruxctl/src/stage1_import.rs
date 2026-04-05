// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

use std::fs::{create_dir_all, File};
use std::io::{BufReader, Read, Write};
use std::path::Path;

use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::replay::{replay_digest_from_jsonl, FrameLocationJson, V3JsonlRecord};

#[derive(Debug, Deserialize)]
struct Stage1EventEnvelope {
    #[serde(rename = "eventId")]
    event_id: String,
    #[serde(rename = "tenantId")]
    tenant_id: String,
    #[serde(rename = "streamId")]
    stream_id: String,
    #[serde(rename = "streamType")]
    stream_type: String,
    seq: Option<u64>,
    #[serde(rename = "occurredAt")]
    occurred_at: String,
    #[serde(rename = "eventType")]
    event_type: String,
}

#[derive(Debug, Serialize)]
pub struct ImportResult {
    pub input_events_log: String,
    pub out_dir: String,
    pub records: u64,
    pub output_jsonl: String,
    pub mapping_jsonl: String,
    pub expected_digest_json: String,
}

#[derive(Debug, Serialize)]
struct MappingLine {
    #[serde(rename = "v1Offset")]
    v1_offset: u64,
    #[serde(rename = "v3Location")]
    v3_location: FrameLocationJson,
}

pub fn import_stage1_events_log(
    events_log: &Path,
    out_dir: &Path,
) -> Result<ImportResult, Box<dyn std::error::Error + Send + Sync>> {
    create_dir_all(out_dir)?;

    let output_jsonl_path = out_dir.join("events.v3.jsonl");
    let mapping_jsonl_path = out_dir.join("mapping.jsonl");
    let expected_digest_path = out_dir.join("expected_digest.json");

    let mut input = BufReader::new(File::open(events_log)?);
    let mut out_jsonl = File::create(&output_jsonl_path)?;
    let mut out_mapping = File::create(&mapping_jsonl_path)?;

    let mut offset: u64 = 0;
    let mut records: u64 = 0;

    loop {
        let mut len_buf = [0u8; 4];
        match input.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(err) => return Err(err.into()),
        }

        let len = u32::from_be_bytes(len_buf) as usize;
        offset += 4;

        if len == 0 || len > 4 * 1024 * 1024 {
            return Err(format!("invalid record length {len} at offset {}", offset - 4).into());
        }

        let mut payload = vec![0u8; len];
        input.read_exact(&mut payload)?;
        offset += len as u64;

        let mut crc_buf = [0u8; 4];
        input.read_exact(&mut crc_buf)?;
        offset += 4;

        let expected_crc = u32::from_be_bytes(crc_buf);
        let actual_crc = crc32c::crc32c(&payload);
        if expected_crc != actual_crc {
            return Err(format!(
        "crc32c mismatch at record start offset {}: expected {expected_crc}, actual {actual_crc}",
        offset - (len as u64) - 8
      )
            .into());
        }

        let env: Stage1EventEnvelope = serde_json::from_slice(&payload)?;
        let seq = env.seq.unwrap_or(0);

        let rec = V3JsonlRecord {
            tenant_id: env.tenant_id,
            stream_type: env.stream_type,
            stream_id: env.stream_id,
            seq,
            event_id: env.event_id,
            occurred_at: env.occurred_at.clone(),
            ingested_at: env.occurred_at,
            event_type: env.event_type,
            content_type: "application/json".to_string(),
            payload_b64: base64::engine::general_purpose::STANDARD.encode(&payload),
            location: FrameLocationJson {
                shard_id: 0,
                segment_id: 0,
                offset: offset - (len as u64) - 8, // points at the u32 length prefix
            },
        };

        writeln!(out_jsonl, "{}", serde_json::to_string(&rec)?)?;
        writeln!(
            out_mapping,
            "{}",
            serde_json::to_string(&MappingLine {
                v1_offset: rec.location.offset,
                v3_location: rec.location.clone(),
            })?
        )?;

        records += 1;
    }

    out_jsonl.flush()?;
    out_mapping.flush()?;

    let digest = replay_digest_from_jsonl(&output_jsonl_path)?;
    let mut f = File::create(&expected_digest_path)?;
    f.write_all(serde_json::to_string_pretty(&digest)?.as_bytes())?;
    f.write_all(b"\n")?;
    f.flush()?;

    Ok(ImportResult {
        input_events_log: events_log.display().to_string(),
        out_dir: out_dir.display().to_string(),
        records,
        output_jsonl: output_jsonl_path.display().to_string(),
        mapping_jsonl: mapping_jsonl_path.display().to_string(),
        expected_digest_json: expected_digest_path.display().to_string(),
    })
}
