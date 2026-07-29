// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Small persisted metadata index used by the embedded console.
//!
//! This deliberately stores chunk metadata and redacted previews only. Raw
//! payloads remain in the dataplane stream log and are not copied into the
//! console index.

use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};

use corecrux_proto::dataplane_v1::AppendEvent;
use fs2::FileExt;

const CONSOLE_CHUNK_INDEX_SCHEMA_V1: &str = "crux.console.chunk-index.v1";
const MAX_INDEXED_CHUNKS: usize = 10_000;
const REDACTED_PREVIEW_MAX_CHARS: usize = 512;

#[derive(Debug, thiserror::Error)]
pub enum ConsoleIndexError {
    #[error("invalid console chunk index schema '{0}'")]
    InvalidSchema(String),
    #[error("invalid cursor '{0}'")]
    InvalidCursor(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ConsoleFrameLocation {
    pub shard_id: u64,
    pub epoch: u64,
    pub segment_seq: u64,
    pub offset: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ConsoleChunkMetadata {
    pub chunk_digest: String,
    pub payload_digest: String,
    pub tenant_id: String,
    pub stream_type: String,
    pub stream_id: String,
    pub seq: u64,
    pub event_id: String,
    pub event_type: String,
    pub content_type: String,
    pub payload_bytes: usize,
    pub occurred_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingested_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<ConsoleFrameLocation>,
    pub preview_available: bool,
    pub preview_redacted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redacted_preview: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ConsoleChunkPage {
    pub chunks: Vec<ConsoleChunkMetadata>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
struct ConsoleChunkIndex {
    schema: String,
    updated_at_unix_ms: u64,
    #[serde(default)]
    chunks: Vec<ConsoleChunkMetadata>,
}

pub fn record_appended_events(
    data_dir: &Path,
    tenant_id: &str,
    stream_type: &str,
    stream_id: &str,
    expected_next_seq: u64,
    events: &[AppendEvent],
    now_unix_ms: u64,
) -> Result<(), ConsoleIndexError> {
    with_index_lock(data_dir, || {
        let mut index = read_index(data_dir)?;
        for (offset, event) in events.iter().enumerate() {
            let seq = expected_next_seq.saturating_add(offset as u64);
            let chunk = metadata_from_append(tenant_id, stream_type, stream_id, seq, event);
            index
                .chunks
                .retain(|existing| existing.chunk_digest != chunk.chunk_digest);
            index.chunks.push(chunk);
        }
        if index.chunks.len() > MAX_INDEXED_CHUNKS {
            let drop_count = index.chunks.len() - MAX_INDEXED_CHUNKS;
            index.chunks.drain(0..drop_count);
        }
        index.updated_at_unix_ms = now_unix_ms;
        write_index(data_dir, &index)
    })
}

pub fn list_tenants(data_dir: &Path) -> Result<Vec<String>, ConsoleIndexError> {
    let index = read_index(data_dir)?;
    let mut tenants: Vec<String> = index.chunks.into_iter().map(|chunk| chunk.tenant_id).collect();
    tenants.sort();
    tenants.dedup();
    Ok(tenants)
}

pub fn list_chunks(
    data_dir: &Path,
    tenant_id: &str,
    limit: usize,
    cursor: Option<&str>,
) -> Result<ConsoleChunkPage, ConsoleIndexError> {
    let start = parse_cursor(cursor)?;
    let index = read_index(data_dir)?;
    let chunks: Vec<ConsoleChunkMetadata> = index
        .chunks
        .into_iter()
        .filter(|chunk| chunk.tenant_id == tenant_id)
        .collect();
    let page_chunks: Vec<ConsoleChunkMetadata> = chunks.iter().skip(start).take(limit).cloned().collect();
    let next_offset = start.saturating_add(page_chunks.len());
    let next_cursor = if next_offset < chunks.len() {
        Some(next_offset.to_string())
    } else {
        None
    };
    Ok(ConsoleChunkPage {
        chunks: page_chunks,
        next_cursor,
    })
}

pub fn find_chunk(data_dir: &Path, chunk_digest: &str) -> Result<Option<ConsoleChunkMetadata>, ConsoleIndexError> {
    let index = read_index(data_dir)?;
    Ok(index
        .chunks
        .into_iter()
        .find(|chunk| chunk.chunk_digest == chunk_digest))
}

fn metadata_from_append(
    tenant_id: &str,
    stream_type: &str,
    stream_id: &str,
    seq: u64,
    event: &AppendEvent,
) -> ConsoleChunkMetadata {
    let payload_digest = format!("blake3:{}", blake3::hash(&event.payload).to_hex());
    let chunk_digest = chunk_digest(tenant_id, stream_type, stream_id, seq, event);
    let redacted_preview = redacted_preview(&event.content_type, &event.payload);
    ConsoleChunkMetadata {
        chunk_digest,
        payload_digest,
        tenant_id: tenant_id.to_string(),
        stream_type: stream_type.to_string(),
        stream_id: stream_id.to_string(),
        seq,
        event_id: event.event_id.clone(),
        event_type: event.event_type.clone(),
        content_type: event.content_type.clone(),
        payload_bytes: event.payload.len(),
        occurred_at: event.occurred_at.clone(),
        ingested_at: None,
        location: None,
        preview_available: redacted_preview.is_some(),
        preview_redacted: true,
        redacted_preview,
    }
}

fn chunk_digest(tenant_id: &str, stream_type: &str, stream_id: &str, seq: u64, event: &AppendEvent) -> String {
    let mut hasher = blake3::Hasher::new();
    for part in [
        tenant_id.as_bytes(),
        stream_type.as_bytes(),
        stream_id.as_bytes(),
        &seq.to_le_bytes(),
        event.event_id.as_bytes(),
        &event.payload,
    ] {
        hasher.update(part);
        hasher.update(&[0]);
    }
    format!("blake3:{}", hasher.finalize().to_hex())
}

fn redacted_preview(content_type: &str, payload: &[u8]) -> Option<String> {
    if !is_textual(content_type) {
        return None;
    }
    let text = std::str::from_utf8(payload).ok()?;
    Some(redact_secret_like(text))
}

fn redact_secret_like(text: &str) -> String {
    let lower = text.to_ascii_lowercase();
    let secret_markers = [
        "api_key",
        "apikey",
        "authorization",
        "bearer ",
        "password",
        "private_key",
        "secret",
        "token",
    ];
    if secret_markers.iter().any(|marker| lower.contains(marker)) {
        return "[redacted secret-like content]".to_string();
    }
    let mut out: String = text.chars().take(REDACTED_PREVIEW_MAX_CHARS).collect();
    if text.chars().count() > REDACTED_PREVIEW_MAX_CHARS {
        out.push_str("...");
    }
    out
}

fn is_textual(content_type: &str) -> bool {
    let content_type = content_type.to_ascii_lowercase();
    content_type.starts_with("text/")
        || content_type.starts_with("application/json")
        || content_type.starts_with("application/x-ndjson")
        || content_type.ends_with("+json")
}

fn parse_cursor(cursor: Option<&str>) -> Result<usize, ConsoleIndexError> {
    match cursor {
        Some(raw) => raw
            .parse::<usize>()
            .map_err(|_| ConsoleIndexError::InvalidCursor(raw.to_string())),
        None => Ok(0),
    }
}

fn read_index(data_dir: &Path) -> Result<ConsoleChunkIndex, ConsoleIndexError> {
    let path = index_path(data_dir);
    if !path.exists() {
        return Ok(ConsoleChunkIndex {
            schema: CONSOLE_CHUNK_INDEX_SCHEMA_V1.to_string(),
            updated_at_unix_ms: 0,
            chunks: Vec::new(),
        });
    }
    let bytes = fs::read(path)?;
    let index: ConsoleChunkIndex = serde_json::from_slice(&bytes)?;
    if index.schema != CONSOLE_CHUNK_INDEX_SCHEMA_V1 {
        return Err(ConsoleIndexError::InvalidSchema(index.schema));
    }
    Ok(index)
}

fn write_index(data_dir: &Path, index: &ConsoleChunkIndex) -> Result<(), ConsoleIndexError> {
    let path = index_path(data_dir);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, serde_json::to_vec_pretty(index)?)?;
    fs::rename(tmp, path)?;
    Ok(())
}

fn index_path(data_dir: &Path) -> PathBuf {
    data_dir.join("console").join("chunks-index.json")
}

fn with_index_lock<T>(
    data_dir: &Path,
    f: impl FnOnce() -> Result<T, ConsoleIndexError>,
) -> Result<T, ConsoleIndexError> {
    let lock_path = data_dir.join("console").join("chunks-index.lock");
    if let Some(parent) = lock_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let lock = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(lock_path)?;
    lock.lock_exclusive()?;
    let result = f();
    FileExt::unlock(&lock)?;
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Self-cleaning temp dir: the returned [`tempfile::TempDir`] removes itself
    /// on Drop (even when a test returns early via `?` or panics), so tests bind
    /// it to a guard instead of leaking a `corecruxd-console-index-*` dir into
    /// `/tmp` every run. Prefix retained for debuggability.
    fn temp_data_dir(name: &str) -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix(&format!("corecruxd-console-index-{name}-"))
            .tempdir()
            .expect("create temp dir")
    }

    #[test]
    fn record_and_page_chunks_without_raw_secret_preview() -> Result<(), ConsoleIndexError> {
        let tmp = temp_data_dir("record");
        let root = tmp.path().to_path_buf();
        let events = vec![AppendEvent {
            event_id: "evt-1".to_string(),
            occurred_at: "2026-05-01T12:00:00Z".to_string(),
            event_type: "test.event".to_string(),
            content_type: "application/json".to_string(),
            payload: br#"{"token":"secret","value":1}"#.to_vec(),
        }];
        record_appended_events(&root, "tenant-a", "artifact", "stream-a", 10, &events, 1_000)?;

        let page = list_chunks(&root, "tenant-a", 10, None)?;
        assert_eq!(page.chunks.len(), 1);
        assert_eq!(page.chunks[0].seq, 10);
        assert_eq!(
            page.chunks[0].redacted_preview.as_deref(),
            Some("[redacted secret-like content]")
        );
        let page_text = serde_json::to_string(&page).expect("page json");
        assert!(!page_text.contains(r#""token":"secret""#));
        Ok(())
    }

    #[test]
    fn console_index_concurrent_appends_preserve_all_chunks() -> Result<(), ConsoleIndexError> {
        let tmp = temp_data_dir("concurrent");
        let root = tmp.path().to_path_buf();
        let handles: Vec<_> = (0..16)
            .map(|idx| {
                let root = root.clone();
                std::thread::spawn(move || {
                    let events = vec![AppendEvent {
                        event_id: format!("evt-{idx}"),
                        occurred_at: "2026-05-01T12:00:00Z".to_string(),
                        event_type: "test.event".to_string(),
                        content_type: "application/json".to_string(),
                        payload: format!(r#"{{"value":{idx}}}"#).into_bytes(),
                    }];
                    record_appended_events(&root, "tenant-a", "artifact", "stream-a", idx, &events, 1_000 + idx)
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("thread join")?;
        }
        let page = list_chunks(&root, "tenant-a", 32, None)?;
        assert_eq!(page.chunks.len(), 16);
        let mut ids: Vec<_> = page.chunks.into_iter().map(|chunk| chunk.event_id).collect();
        ids.sort();
        assert_eq!(ids.first().map(String::as_str), Some("evt-0"));
        assert_eq!(ids.last().map(String::as_str), Some("evt-9"));
        assert!(ids.contains(&"evt-15".to_string()));
        Ok(())
    }
}
