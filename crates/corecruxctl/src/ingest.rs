// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! File and directory ingest for the daemon's local CPU prose-ingest route.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};

type DynErr = Box<dyn std::error::Error + Send + Sync>;

const TARGET_CHARS: usize = 1_800;
const MIN_BOUNDARY_CHARS: usize = 1_200;
const OVERLAP_CHARS: usize = 180;
const MAX_DOCUMENTS_PER_REQUEST: usize = 4_096;
const MAX_CHUNKS_PER_REQUEST: usize = 65_536;
// The storage append beneath the HTTP handler accepts at most 1,024 events.
const MAX_CHUNKS_PER_DOCUMENT_APPEND: usize = 1_024;
// The route inherits the daemon's default 16 MiB envelope. Leave room for
// headers and for deployments configured with a slightly smaller proxy cap.
const MAX_REQUEST_JSON_BYTES: usize = 12 * 1024 * 1024;

/// Options for [`execute`] and [`run`].
#[derive(Debug, Clone)]
pub struct IngestOptions {
    pub path: PathBuf,
    pub tenant: String,
    pub corpus: String,
    pub daemon_url: String,
    pub dry_run: bool,
    pub embed: bool,
}

/// Provenance attached to every chunk in the ingest request.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ChunkProvenance {
    pub source_path: String,
    pub file_hash: String,
    pub mtime: String,
    pub chunk_index: usize,
    pub chunk_count: usize,
}

/// One chunk in the `/v1/local/ingest` wire contract.
#[derive(Debug, Clone, Serialize)]
pub struct IngestChunk {
    pub chunk_id: String,
    pub text: String,
    pub chunk_index: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dense_vector: Option<Vec<f32>>,
    pub metadata: ChunkProvenance,
}

/// One source document in the `/v1/local/ingest` wire contract.
#[derive(Debug, Clone, Serialize)]
pub struct IngestDocument {
    pub doc_id: String,
    pub title: String,
    pub url: String,
    pub source_timestamp: String,
    pub chunks: Vec<IngestChunk>,
}

/// One request body sent to the local ingest route.
#[derive(Debug, Clone, Serialize)]
pub struct IngestRequest {
    pub tenant_id: String,
    pub corpus_id: String,
    pub documents: Vec<IngestDocument>,
}

#[derive(Debug, Clone, Deserialize)]
struct IngestResponse {
    ingested: usize,
    documents: usize,
    frame_count: u64,
    sealed: bool,
    segment_seq: u64,
    receipt_id: Option<String>,
    dense_vectors: usize,
    dense_dim: Option<usize>,
    /// B1 (`corecrux-ingest-dense-silent-failure-2026-08-07`): `ok` | `partial` |
    /// `skipped` | `not_configured` | `not_applicable`. Defaulted so this CLI
    /// still talks to a daemon that predates the field.
    #[serde(default)]
    dense_status: Option<String>,
    #[serde(default)]
    dense_expected: Option<usize>,
}

/// Receipt and sealed-segment identifiers returned for one HTTP batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchSeal {
    pub batch: usize,
    pub segment_seq: u64,
    pub receipt_id: Option<String>,
    pub chunks: usize,
    pub documents: usize,
    pub frame_count: u64,
    pub sealed: bool,
    pub dense_vectors: usize,
    pub dense_dim: Option<usize>,
    /// `None` when the daemon predates `dense_status` (B1).
    pub dense_status: Option<String>,
    pub dense_expected: Option<usize>,
}

/// Aggregate result for a completed or dry-run ingest.
#[derive(Debug, Clone, Default)]
pub struct IngestReport {
    pub files_walked: usize,
    pub files_ingested: usize,
    pub skipped_files: usize,
    pub skipped_directories: usize,
    pub chunks: usize,
    pub documents_prepared: usize,
    pub documents_sealed: usize,
    pub batches: usize,
    pub dry_run: bool,
    pub embedded: bool,
    pub seals: Vec<BatchSeal>,
}

#[derive(Debug, Clone, Default)]
struct WalkStats {
    files_walked: usize,
    skipped_files: usize,
    skipped_directories: usize,
}

/// Walk, parse, chunk, and optionally post one file or directory.
pub fn execute(options: &IngestOptions) -> Result<IngestReport, DynErr> {
    if options.tenant.trim().is_empty() {
        return Err("--tenant must not be empty".into());
    }
    if options.corpus.trim().is_empty() {
        return Err("--corpus must not be empty".into());
    }

    let (paths, mut walk) = collect_supported_files(&options.path)?;
    let relative_root = if options.path.is_dir() {
        options.path.as_path()
    } else {
        options.path.parent().unwrap_or_else(|| Path::new("."))
    };
    let mut documents = Vec::new();
    for path in paths {
        match document_from_file(&path, relative_root)? {
            Some(document) => documents.push(document),
            None => walk.skipped_files += 1,
        }
    }

    let files_ingested = documents.len();
    let chunks = documents.iter().map(|document| document.chunks.len()).sum();
    if options.embed && !options.dry_run {
        embed_documents(&mut documents)?;
    }
    let requests = build_requests(&options.tenant, &options.corpus, documents)?;

    let mut report = IngestReport {
        files_walked: walk.files_walked,
        files_ingested,
        skipped_files: walk.skipped_files,
        skipped_directories: walk.skipped_directories,
        chunks,
        documents_prepared: files_ingested,
        batches: requests.len(),
        dry_run: options.dry_run,
        embedded: options.embed && !options.dry_run,
        ..IngestReport::default()
    };

    if options.dry_run {
        return Ok(report);
    }
    if requests.is_empty() {
        return Err("no supported, non-empty text was found to ingest".into());
    }

    let token = std::env::var("CRUX_AGENT_TOKEN")
        .ok()
        .filter(|value| !value.trim().is_empty());
    for (index, request) in requests.iter().enumerate() {
        let sent_documents = request.documents.len();
        let sent_chunks: usize = request.documents.iter().map(|document| document.chunks.len()).sum();
        let response = post_request(&options.daemon_url, token.as_deref(), request)?;
        // Reconcile sent against acknowledged. A 202 carrying `ingested: 0`
        // for a two-document batch used to be copied straight into the report,
        // which then claimed `files_ingested: 2, documents_sealed: 0` and
        // returned `Ok`. `openclaw::import_run` in this crate already compares
        // the two sides; this is the same shape.
        if response.documents != sent_documents || response.ingested != sent_chunks {
            return Err(format!(
                "ingest batch {}/{} was accepted but the daemon acknowledged {} documents / {} chunks against {sent_documents} documents / {sent_chunks} chunks sent; \
                 {} documents sealed in earlier batches",
                index + 1,
                requests.len(),
                response.documents,
                response.ingested,
                report.documents_sealed,
            )
            .into());
        }
        report.documents_sealed += response.documents;
        report.seals.push(BatchSeal {
            batch: index + 1,
            segment_seq: response.segment_seq,
            receipt_id: response.receipt_id,
            chunks: response.ingested,
            documents: response.documents,
            frame_count: response.frame_count,
            sealed: response.sealed,
            dense_vectors: response.dense_vectors,
            dense_dim: response.dense_dim,
            dense_status: response.dense_status,
            dense_expected: response.dense_expected,
        });
    }
    Ok(report)
}

/// Execute ingest and print the human-facing summary and follow-up query.
pub fn run(options: &IngestOptions) -> Result<(), DynErr> {
    let report = execute(options)?;
    println!("files walked: {}", report.files_walked);
    println!("files ingested: {}", report.files_ingested);
    println!(
        "skipped: {} files, {} directories",
        report.skipped_files, report.skipped_directories
    );
    println!("chunks: {}", report.chunks);
    if report.dry_run {
        println!(
            "dry run: {} documents prepared in {} batches; nothing sealed",
            report.documents_prepared, report.batches
        );
    } else {
        println!("documents sealed: {}", report.documents_sealed);
        for seal in &report.seals {
            println!(
                "batch {}: segment_seq={} receipt_id={} chunks={} sealed={}",
                seal.batch,
                seal.segment_seq,
                seal.receipt_id.as_deref().unwrap_or("none"),
                seal.chunks,
                seal.sealed
            );
            // B1: a dense gap is not visible in chunks/sealed — those look
            // healthy while retrieval has degraded to lexical-only. Say it.
            if let Some(status) = seal.dense_status.as_deref() {
                if matches!(status, "skipped" | "partial") {
                    eprintln!(
                        "  warning: batch {} sealed with dense_status={status} \
                         ({} of {} chunks embedded) — this corpus is lexical-only \
                         and semantic recall will be degraded",
                        seal.batch,
                        seal.dense_vectors,
                        seal.dense_expected.unwrap_or(seal.chunks),
                    );
                }
            }
        }
    }
    println!("query next:");
    println!("{}", follow_up_query_command(&options.daemon_url, &options.tenant));
    Ok(())
}

/// Exact copy/paste query command printed after ingest.
pub fn follow_up_query_command(daemon_url: &str, tenant: &str) -> String {
    let url = format!("{}/v1/query/text-search", daemon_url.trim_end_matches('/'));
    let body = serde_json::json!({
        "tenant_id": tenant,
        "query": "YOUR QUERY",
        "limit": 10
    });
    let auth = if std::env::var("CRUX_AGENT_TOKEN")
        .ok()
        .is_some_and(|token| !token.trim().is_empty())
    {
        " -H \"Authorization: Bearer $CRUX_AGENT_TOKEN\""
    } else {
        ""
    };
    format!(
        "curl -sS -X POST {} -H 'Content-Type: application/json'{auth} --data {}",
        shell_single_quote(&url),
        shell_single_quote(&body.to_string())
    )
}

fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn collect_supported_files(input: &Path) -> Result<(Vec<PathBuf>, WalkStats), DynErr> {
    let metadata =
        std::fs::symlink_metadata(input).map_err(|error| format!("cannot inspect {}: {error}", input.display()))?;
    let mut files = Vec::new();
    let mut stats = WalkStats::default();
    if metadata.file_type().is_symlink() {
        stats.skipped_files = 1;
    } else if metadata.is_file() {
        stats.files_walked = 1;
        if supported_extension(input) {
            files.push(input.to_path_buf());
        } else {
            stats.skipped_files = 1;
        }
    } else if metadata.is_dir() {
        walk_directory(input, &mut files, &mut stats)?;
    } else {
        stats.skipped_files = 1;
    }
    files.sort();
    Ok((files, stats))
}

fn walk_directory(directory: &Path, files: &mut Vec<PathBuf>, stats: &mut WalkStats) -> Result<(), DynErr> {
    let mut entries = std::fs::read_dir(directory)
        .map_err(|error| format!("cannot read directory {}: {error}", directory.display()))?
        .collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            stats.skipped_files += 1;
        } else if file_type.is_dir() {
            if skipped_directory_name(&entry.file_name()) {
                stats.skipped_directories += 1;
            } else {
                walk_directory(&path, files, stats)?;
            }
        } else if file_type.is_file() {
            stats.files_walked += 1;
            if supported_extension(&path) {
                files.push(path);
            } else {
                stats.skipped_files += 1;
            }
        } else {
            stats.skipped_files += 1;
        }
    }
    Ok(())
}

fn skipped_directory_name(name: &OsStr) -> bool {
    let name = name.to_string_lossy();
    name.starts_with('.') || matches!(name.as_ref(), "node_modules" | "target")
}

fn supported_extension(path: &Path) -> bool {
    path.extension().and_then(OsStr::to_str).is_some_and(|extension| {
        matches!(
            extension.to_ascii_lowercase().as_str(),
            "md" | "markdown" | "txt" | "json"
        )
    })
}

fn document_from_file(path: &Path, relative_root: &Path) -> Result<Option<IngestDocument>, DynErr> {
    let bytes = std::fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    if bytes.contains(&0) {
        return Ok(None);
    }
    let Ok(raw) = std::str::from_utf8(&bytes) else {
        return Ok(None);
    };
    let raw = raw.strip_prefix('\u{feff}').unwrap_or(raw);
    let extension = path
        .extension()
        .and_then(OsStr::to_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    let text = if extension == "json" {
        flatten_json_strings(raw).map_err(|error| format!("invalid JSON in {}: {error}", path.display()))?
    } else {
        raw.to_string()
    };
    if text.trim().is_empty() {
        return Ok(None);
    }

    let chunk_texts = if matches!(extension.as_str(), "md" | "markdown") {
        chunk_markdown(&text)
    } else {
        chunk_plain_text(&text)
    };
    if chunk_texts.is_empty() {
        return Ok(None);
    }

    let relative = path.strip_prefix(relative_root).unwrap_or(path);
    let source_path = relative.to_string_lossy().replace('\\', "/");
    let file_hash = blake3::hash(&bytes).to_hex().to_string();
    let path_hash = blake3::hash(source_path.as_bytes()).to_hex().to_string();
    let doc_id = format!("doc-{}-blake3-{file_hash}", &path_hash[..12]);
    let metadata = std::fs::metadata(path)?;
    let mtime = rfc3339_mtime(metadata.modified()?);
    let chunk_count = chunk_texts.len();
    let chunks = chunk_texts
        .into_iter()
        .enumerate()
        .map(|(index, text)| IngestChunk {
            chunk_id: format!("{doc_id}::{index:06}"),
            text,
            chunk_index: index as u32,
            dense_vector: None,
            metadata: ChunkProvenance {
                source_path: source_path.clone(),
                file_hash: file_hash.clone(),
                mtime: mtime.clone(),
                chunk_index: index,
                chunk_count,
            },
        })
        .collect();

    Ok(Some(IngestDocument {
        doc_id,
        title: source_path.clone(),
        url: source_path,
        source_timestamp: mtime,
        chunks,
    }))
}

fn rfc3339_mtime(time: SystemTime) -> String {
    DateTime::<Utc>::from(time).to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// Recursively collect JSON string values into newline-delimited text.
pub fn flatten_json_strings(input: &str) -> Result<String, serde_json::Error> {
    fn collect(value: &serde_json::Value, strings: &mut Vec<String>) {
        match value {
            serde_json::Value::String(value) if !value.trim().is_empty() => strings.push(value.trim().to_string()),
            serde_json::Value::Array(values) => {
                for value in values {
                    collect(value, strings);
                }
            }
            serde_json::Value::Object(values) => {
                for value in values.values() {
                    collect(value, strings);
                }
            }
            _ => {}
        }
    }

    let value: serde_json::Value = serde_json::from_str(input)?;
    let mut strings = Vec::new();
    collect(&value, &mut strings);
    Ok(strings.join("\n\n"))
}

/// Chunk Markdown at ATX headings, then window unusually long sections.
pub fn chunk_markdown(input: &str) -> Vec<String> {
    let mut sections = Vec::new();
    let mut current = String::new();
    for line in input.split_inclusive('\n') {
        if markdown_heading(line) && !current.trim().is_empty() {
            sections.push(std::mem::take(&mut current));
        }
        current.push_str(line);
    }
    if !current.trim().is_empty() {
        sections.push(current);
    }
    sections
        .into_iter()
        .flat_map(|section| chunk_plain_text(&section))
        .collect()
}

fn markdown_heading(line: &str) -> bool {
    let trimmed = line.trim_start();
    let hashes = trimmed.bytes().take_while(|byte| *byte == b'#').count();
    (1..=6).contains(&hashes) && trimmed.as_bytes().get(hashes).is_some_and(u8::is_ascii_whitespace)
}

/// Paragraph-aware sliding windows of approximately 1,800 characters.
pub fn chunk_plain_text(input: &str) -> Vec<String> {
    let text = input.trim();
    if text.is_empty() {
        return Vec::new();
    }
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= TARGET_CHARS {
        return vec![text.to_string()];
    }

    let mut chunks = Vec::new();
    let mut start = 0usize;
    while start < chars.len() {
        let ideal_end = (start + TARGET_CHARS).min(chars.len());
        let mut end = ideal_end;
        if ideal_end < chars.len() {
            let minimum = (start + MIN_BOUNDARY_CHARS).min(ideal_end);
            for candidate in (minimum..=ideal_end).rev() {
                if candidate >= 2 && chars[candidate - 2] == '\n' && chars[candidate - 1] == '\n' {
                    end = candidate;
                    break;
                }
            }
            if end == ideal_end {
                for candidate in (minimum..=ideal_end).rev() {
                    if chars[candidate - 1].is_whitespace() {
                        end = candidate;
                        break;
                    }
                }
            }
        }
        let chunk: String = chars[start..end].iter().collect::<String>().trim().to_string();
        if !chunk.is_empty() {
            chunks.push(chunk);
        }
        if end == chars.len() {
            break;
        }
        let next = end.saturating_sub(OVERLAP_CHARS);
        start = if next > start { next } else { end };
    }
    chunks
}

fn build_requests(tenant: &str, corpus: &str, documents: Vec<IngestDocument>) -> Result<Vec<IngestRequest>, DynErr> {
    let documents = fragment_documents(documents)?;
    let mut requests = Vec::new();
    let mut current = IngestRequest {
        tenant_id: tenant.to_string(),
        corpus_id: corpus.to_string(),
        documents: Vec::new(),
    };
    let empty_request_bytes = serde_json::to_vec(&current)?.len();
    let mut current_bytes = empty_request_bytes;
    let mut current_chunks = 0usize;
    for document in documents {
        let document_chunks = document.chunks.len();
        let document_bytes = serde_json::to_vec(&document)?.len();
        let separator_bytes = usize::from(!current.documents.is_empty());
        let would_hit_count_limit = current.documents.len() == MAX_DOCUMENTS_PER_REQUEST
            || current_chunks + document_chunks > MAX_CHUNKS_PER_REQUEST;
        let would_hit_size_limit =
            !current.documents.is_empty() && current_bytes + separator_bytes + document_bytes > MAX_REQUEST_JSON_BYTES;
        if would_hit_count_limit || would_hit_size_limit {
            requests.push(current);
            current = IngestRequest {
                tenant_id: tenant.to_string(),
                corpus_id: corpus.to_string(),
                documents: Vec::new(),
            };
            current_bytes = empty_request_bytes;
            current_chunks = 0;
        }
        let separator_bytes = usize::from(!current.documents.is_empty());
        if current_bytes + separator_bytes + document_bytes > MAX_REQUEST_JSON_BYTES {
            return Err("one local-ingest document fragment exceeds the conservative 12 MiB request limit".into());
        }
        current_chunks += document_chunks;
        current_bytes += separator_bytes + document_bytes;
        current.documents.push(document);
    }
    if !current.documents.is_empty() {
        requests.push(current);
    }
    Ok(requests)
}

fn fragment_documents(documents: Vec<IngestDocument>) -> Result<Vec<IngestDocument>, DynErr> {
    let mut fragments = Vec::new();
    for document in documents {
        let mut remaining = document.chunks.as_slice();
        while !remaining.is_empty() {
            let take = remaining.len().min(MAX_CHUNKS_PER_DOCUMENT_APPEND);
            let mut fragment = IngestDocument {
                doc_id: document.doc_id.clone(),
                title: document.title.clone(),
                url: document.url.clone(),
                source_timestamp: document.source_timestamp.clone(),
                chunks: remaining[..take].to_vec(),
            };
            while fragment.chunks.len() > 1 && serde_json::to_vec(&fragment)?.len() > MAX_REQUEST_JSON_BYTES {
                fragment.chunks.truncate(fragment.chunks.len() / 2);
            }
            let consumed = fragment.chunks.len();
            fragments.push(fragment);
            remaining = &remaining[consumed..];
        }
    }
    Ok(fragments)
}

fn post_request(daemon_url: &str, token: Option<&str>, request: &IngestRequest) -> Result<IngestResponse, DynErr> {
    let endpoint = format!("{}/v1/local/ingest", daemon_url.trim_end_matches('/'));
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(120)))
        .build()
        .into();
    let mut builder = agent.post(&endpoint);
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let mut response = match builder.send_json(request) {
        Ok(response) => response,
        Err(ureq::Error::StatusCode(code)) => {
            return Err(format!("local ingest failed (HTTP {code}) at {endpoint}").into());
        }
        Err(error) => return Err(format!("local ingest request to {endpoint} failed: {error}").into()),
    };
    if response.status().as_u16() != 202 {
        return Err(format!("local ingest returned unexpected HTTP {}", response.status()).into());
    }
    Ok(response.body_mut().read_json()?)
}

#[derive(Serialize)]
struct EmbeddingRequest<'a> {
    model: &'a str,
    input: &'a str,
}

#[derive(Deserialize)]
struct EmbeddingResponse {
    data: Vec<EmbeddingData>,
}

#[derive(Deserialize)]
struct EmbeddingData {
    embedding: Vec<f32>,
}

fn embed_documents(documents: &mut [IngestDocument]) -> Result<(), DynErr> {
    let base = std::env::var("CORECRUXD_EMBEDDING_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or("--embed requires CORECRUXD_EMBEDDING_URL")?;
    let model = std::env::var("CORECRUXD_EMBEDDING_MODEL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "nomic-embed-text".to_string());
    let endpoint = embedding_endpoint(&base);
    let api_key = std::env::var("OPENAI_API_KEY")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(120)))
        .build()
        .into();
    let mut dimensions = None;
    for document in documents {
        for chunk in &mut document.chunks {
            let mut builder = agent.post(&endpoint);
            if let Some(api_key) = &api_key {
                builder = builder.header("authorization", format!("Bearer {api_key}"));
            }
            let mut response = match builder.send_json(EmbeddingRequest {
                model: &model,
                input: &chunk.text,
            }) {
                Ok(response) => response,
                Err(ureq::Error::StatusCode(code)) => {
                    return Err(format!("embedding request failed (HTTP {code}) at {endpoint}").into());
                }
                Err(error) => return Err(format!("embedding request to {endpoint} failed: {error}").into()),
            };
            let parsed: EmbeddingResponse = response.body_mut().read_json()?;
            let vector = parsed
                .data
                .into_iter()
                .next()
                .map(|item| item.embedding)
                .ok_or("embedding endpoint returned no vectors")?;
            if vector.is_empty() || vector.iter().any(|value| !value.is_finite()) {
                return Err("embedding endpoint returned an empty or non-finite vector".into());
            }
            match dimensions {
                None => dimensions = Some(vector.len()),
                Some(expected) if expected != vector.len() => {
                    return Err(format!(
                        "embedding dimension changed within ingest: expected {expected}, got {}",
                        vector.len()
                    )
                    .into());
                }
                _ => {}
            }
            chunk.dense_vector = Some(vector);
        }
    }
    Ok(())
}

fn embedding_endpoint(base: &str) -> String {
    let base = base.trim_end_matches('/');
    if base.ends_with("/v1/embeddings") {
        base.to_string()
    } else if base.ends_with("/v1") {
        format!("{base}/embeddings")
    } else {
        format!("{base}/v1/embeddings")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn test_document(id: usize, chunks: usize) -> IngestDocument {
        let doc_id = format!("doc-{id}");
        IngestDocument {
            doc_id: doc_id.clone(),
            title: format!("{id}.txt"),
            url: format!("{id}.txt"),
            source_timestamp: "2026-07-13T00:00:00Z".to_string(),
            chunks: (0..chunks)
                .map(|chunk_index| IngestChunk {
                    chunk_id: format!("{doc_id}::{chunk_index}"),
                    text: format!("text {chunk_index}"),
                    chunk_index: chunk_index as u32,
                    dense_vector: None,
                    metadata: ChunkProvenance {
                        source_path: format!("{id}.txt"),
                        file_hash: "00".repeat(32),
                        mtime: "2026-07-13T00:00:00Z".to_string(),
                        chunk_index,
                        chunk_count: chunks,
                    },
                })
                .collect(),
        }
    }

    #[test]
    fn markdown_chunks_start_at_headings() {
        let input = format!("# First\n\n{}\n\n## Second\n\nshort ending", "alpha ".repeat(400));
        let chunks = chunk_markdown(&input);
        assert!(chunks.first().unwrap().starts_with("# First"));
        assert!(chunks.iter().any(|chunk| chunk.starts_with("## Second")));
        assert!(chunks
            .iter()
            .all(|chunk| !(chunk.contains("# First") && chunk.contains("## Second"))));
    }

    #[test]
    fn text_windows_have_bounded_size_and_overlap() {
        let input = (0..900).map(|index| format!("word{index:04} ")).collect::<String>();
        let chunks = chunk_plain_text(&input);
        assert!(chunks.len() > 2);
        assert!(chunks.iter().all(|chunk| chunk.chars().count() <= TARGET_CHARS));
        for pair in chunks.windows(2) {
            let left: Vec<char> = pair[0].chars().collect();
            let right: Vec<char> = pair[1].chars().collect();
            let mut overlap = 0;
            let max = OVERLAP_CHARS.min(left.len()).min(right.len());
            for length in 1..=max {
                if left[left.len() - length..] == right[..length] {
                    overlap = length;
                }
            }
            assert!(overlap > 0);
            assert!(overlap <= OVERLAP_CHARS);
        }
    }

    #[test]
    fn json_flatten_collects_only_string_values() {
        let text =
            flatten_json_strings(r#"{"title":"Hello","count":3,"nested":{"body":"World"},"items":[true,"Again"]}"#)
                .unwrap();
        assert_eq!(text, "Hello\n\nWorld\n\nAgain");
        assert!(!text.contains('3'));
        assert!(!text.contains("true"));
    }

    #[test]
    fn walker_skips_hidden_and_build_directories() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp.path().join(".git")).unwrap();
        std::fs::create_dir_all(temp.path().join(".hidden")).unwrap();
        std::fs::create_dir_all(temp.path().join("node_modules")).unwrap();
        std::fs::create_dir_all(temp.path().join("target")).unwrap();
        std::fs::create_dir_all(temp.path().join("docs")).unwrap();
        std::fs::write(temp.path().join(".git/config.txt"), "skip").unwrap();
        std::fs::write(temp.path().join(".hidden/secret.md"), "skip").unwrap();
        std::fs::write(temp.path().join("node_modules/package.txt"), "skip").unwrap();
        std::fs::write(temp.path().join("target/output.txt"), "skip").unwrap();
        std::fs::write(temp.path().join("docs/keep.md"), "# Keep").unwrap();
        std::fs::write(temp.path().join("docs/image.png"), [0, 1, 2]).unwrap();

        let (files, stats) = collect_supported_files(temp.path()).unwrap();
        assert_eq!(files, vec![temp.path().join("docs/keep.md")]);
        assert_eq!(stats.skipped_directories, 4);
        assert_eq!(stats.skipped_files, 1);
    }

    #[test]
    fn supported_extension_with_binary_bytes_is_skipped() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("binary.txt");
        std::fs::write(&path, [0xff, 0xfe, 0xfd]).unwrap();
        assert!(document_from_file(&path, temp.path()).unwrap().is_none());
    }

    #[test]
    fn request_shape_carries_provenance() {
        let requests = build_requests("local", "docs", vec![test_document(1, 2)]).unwrap();
        let value = serde_json::to_value(&requests[0]).unwrap();
        assert_eq!(value["tenant_id"], "local");
        assert_eq!(value["corpus_id"], "docs");
        assert_eq!(value["documents"][0]["source_timestamp"], "2026-07-13T00:00:00Z");
        assert_eq!(value["documents"][0]["chunks"][1]["chunk_index"], 1);
        assert_eq!(value["documents"][0]["chunks"][1]["metadata"]["chunk_count"], 2);
        assert!(value["documents"][0]["chunks"][0].get("dense_vector").is_none());
    }

    #[test]
    fn batching_respects_document_and_chunk_limits() {
        let docs = (0..(MAX_DOCUMENTS_PER_REQUEST + 1))
            .map(|index| test_document(index, 1))
            .collect();
        let requests = build_requests("local", "docs", docs).unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].documents.len(), MAX_DOCUMENTS_PER_REQUEST);
        assert_eq!(requests[1].documents.len(), 1);

        let requests = build_requests("local", "docs", vec![test_document(0, MAX_CHUNKS_PER_REQUEST + 1)]).unwrap();
        assert!(requests.len() >= 2);
        assert_eq!(
            requests
                .iter()
                .flat_map(|request| &request.documents)
                .map(|document| document.chunks.len())
                .sum::<usize>(),
            MAX_CHUNKS_PER_REQUEST + 1
        );
        assert!(requests.iter().all(|request| {
            request
                .documents
                .iter()
                .map(|document| document.chunks.len())
                .sum::<usize>()
                <= MAX_CHUNKS_PER_REQUEST
        }));
        assert!(requests
            .iter()
            .flat_map(|request| &request.documents)
            .all(|document| document.chunks.len() <= MAX_CHUNKS_PER_DOCUMENT_APPEND));
    }

    #[test]
    fn embedding_endpoint_accepts_base_or_full_url() {
        assert_eq!(
            embedding_endpoint("http://localhost:8000"),
            "http://localhost:8000/v1/embeddings"
        );
        assert_eq!(
            embedding_endpoint("http://localhost:8000/v1"),
            "http://localhost:8000/v1/embeddings"
        );
        assert_eq!(
            embedding_endpoint("http://localhost:8000/v1/embeddings"),
            "http://localhost:8000/v1/embeddings"
        );
    }

    #[test]
    fn embedding_request_uses_openai_compatible_shape() {
        let value = serde_json::to_value(EmbeddingRequest {
            model: "fixture-embed",
            input: "one chunk",
        })
        .unwrap();
        assert_eq!(
            value,
            serde_json::json!({"model": "fixture-embed", "input": "one chunk"})
        );
    }

    #[test]
    fn shell_quote_handles_apostrophes_in_query_fields() {
        assert_eq!(shell_single_quote("tenant's docs"), "'tenant'\"'\"'s docs'");
    }

    // ── shared scaffolding for the transport / filesystem tests ──────────────

    /// Set (or clear) process env vars for the duration of a test, restoring the
    /// previous values on drop. Every user must be `#[serial_test::serial]`.
    struct EnvGuard(Vec<(&'static str, Option<std::ffi::OsString>)>);

    impl EnvGuard {
        fn apply(vars: &[(&'static str, Option<&str>)]) -> Self {
            let mut prev = Vec::new();
            for (key, value) in vars {
                prev.push((*key, std::env::var_os(key)));
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
            EnvGuard(prev)
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (key, value) in self.0.drain(..) {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
    }

    /// B1: a daemon that reports a dense gap has that gap carried into the
    /// `BatchSeal`, so the caller-facing warning has something to fire on.
    #[test]
    fn dense_gap_reply_is_carried_into_the_seal() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("a.md"), "# Alpha\n\nbody text").unwrap();
        let reply = serde_json::json!({
            "ingested": 1,
            "documents": 1,
            "frame_count": 7u64,
            "sealed": true,
            "segment_seq": 42u64,
            "receipt_id": "rcpt-1",
            "dense_vectors": 0,
            "dense_dim": serde_json::Value::Null,
            "dense_status": "skipped",
            "dense_expected": 1,
        })
        .to_string();
        let (port, _handle) = crate::test_support::serve_responses(vec![(202, reply)]);

        let report = execute(&options(temp.path(), &format!("http://127.0.0.1:{port}"))).unwrap();
        assert_eq!(report.seals[0].dense_status.as_deref(), Some("skipped"));
        assert_eq!(report.seals[0].dense_expected, Some(1));
    }

    /// A well-formed `/v1/local/ingest` reply body.
    fn ingest_reply(ingested: usize, documents: usize) -> String {
        serde_json::json!({
            "ingested": ingested,
            "documents": documents,
            "frame_count": 7u64,
            "sealed": true,
            "segment_seq": 42u64,
            "receipt_id": "rcpt-1",
            "dense_vectors": 0,
            "dense_dim": serde_json::Value::Null,
        })
        .to_string()
    }

    fn options(path: &Path, url: &str) -> IngestOptions {
        IngestOptions {
            path: path.to_path_buf(),
            tenant: "local".to_string(),
            corpus: "docs".to_string(),
            daemon_url: url.to_string(),
            dry_run: false,
            embed: false,
        }
    }

    // ── D-9: sent-vs-acknowledged reconciliation ──────────────────────────

    fn two_document_corpus() -> tempfile::TempDir {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("a.txt"), "alpha body text\n").expect("a.txt");
        std::fs::write(tmp.path().join("b.txt"), "beta body text\n").expect("b.txt");
        tmp
    }

    fn options_for(dir: &Path, port: u16) -> IngestOptions {
        IngestOptions {
            path: dir.to_path_buf(),
            tenant: "local".to_string(),
            corpus: "docs".to_string(),
            daemon_url: format!("http://127.0.0.1:{port}"),
            dry_run: false,
            embed: false,
        }
    }

    /// Parse the JSON body out of a captured raw request (`ureq` pretty-prints
    /// `send_json` bodies, so match on structure rather than raw substrings).
    fn body_json(raw: &str) -> serde_json::Value {
        let (_, body) = raw.split_once("\r\n\r\n").expect("request body");
        serde_json::from_str(body).expect("json body")
    }

    // ── rejections ──────────────────────────────────────────────────────────

    #[test]
    fn execute_rejects_blank_tenant_and_corpus() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("a.md"), "# hi").unwrap();
        let mut opts = options(temp.path(), "http://127.0.0.1:1");
        opts.dry_run = true;
        opts.tenant = "   ".to_string();
        assert!(execute(&opts).unwrap_err().to_string().contains("--tenant"));
        opts.tenant = "local".to_string();
        opts.corpus = String::new();
        assert!(execute(&opts).unwrap_err().to_string().contains("--corpus"));
    }

    /// A directory with nothing ingestable must fail loudly rather than report a
    /// clean run of zero documents — the empty batch is the error, not a pass.
    #[test]
    #[serial_test::serial]
    fn execute_errors_when_nothing_ingestable_was_found() {
        let _env = EnvGuard::apply(&[("CRUX_AGENT_TOKEN", None)]);
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("image.png"), [0u8, 1, 2]).unwrap();
        let err = execute(&options(temp.path(), "http://127.0.0.1:1"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("no supported, non-empty text was found"), "{err}");
    }

    #[test]
    fn collect_supported_files_reports_an_unreadable_input_path() {
        let err = collect_supported_files(Path::new("/no/such/ingest/path"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("cannot inspect"), "{err}");
    }

    #[test]
    fn document_from_file_rejects_malformed_json() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("broken.json");
        std::fs::write(&path, "{\"a\": ").unwrap();
        let err = document_from_file(&path, temp.path()).unwrap_err().to_string();
        assert!(err.contains("invalid JSON in"), "{err}");
    }

    /// One malformed `.json` file aborts the whole walk — fail-closed, so a
    /// corrupt record can never be quietly dropped from an otherwise-clean batch.
    #[test]
    fn execute_aborts_the_whole_run_on_one_malformed_json_file() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("good.md"), "# fine\n\nbody text").unwrap();
        std::fs::write(temp.path().join("bad.json"), "{not json}").unwrap();
        let mut opts = options(temp.path(), "http://127.0.0.1:1");
        opts.dry_run = true;
        assert!(execute(&opts).unwrap_err().to_string().contains("invalid JSON in"));
    }

    #[test]
    fn document_from_file_skips_empty_json_and_whitespace_only_text() {
        let temp = tempfile::tempdir().unwrap();
        // Valid JSON carrying no string values flattens to nothing.
        let numbers = temp.path().join("numbers.json");
        std::fs::write(&numbers, r#"{"a":1,"b":[2,3],"c":null}"#).unwrap();
        assert!(document_from_file(&numbers, temp.path()).unwrap().is_none());
        // Whitespace-only text file.
        let blank = temp.path().join("blank.txt");
        std::fs::write(&blank, "   \n\t\n").unwrap();
        assert!(document_from_file(&blank, temp.path()).unwrap().is_none());
    }

    /// A UTF-8 BOM must be stripped from the chunk text, but the file hash is
    /// still taken over the raw bytes (so re-ingest stays content-addressed).
    #[test]
    fn document_from_file_strips_the_utf8_bom() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("bom.txt");
        let bytes = "\u{feff}hello bom".as_bytes().to_vec();
        std::fs::write(&path, &bytes).unwrap();
        let doc = document_from_file(&path, temp.path()).unwrap().unwrap();
        assert_eq!(doc.chunks[0].text, "hello bom");
        assert_eq!(
            doc.chunks[0].metadata.file_hash,
            blake3::hash(&bytes).to_hex().to_string()
        );
        assert_eq!(doc.chunks[0].metadata.chunk_count, 1);
        assert_eq!(doc.title, "bom.txt");
    }

    #[test]
    fn document_from_file_flattens_json_string_values() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("record.json");
        std::fs::write(&path, r#"{"title":"Alpha","n":1,"body":{"text":"Beta"}}"#).unwrap();
        let doc = document_from_file(&path, temp.path()).unwrap().unwrap();
        assert_eq!(doc.chunks[0].text, "Alpha\n\nBeta");
        assert!(doc.doc_id.starts_with("doc-"));
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_input_is_skipped_never_followed() {
        let temp = tempfile::tempdir().unwrap();
        let real = temp.path().join("real.md");
        std::fs::write(&real, "# real").unwrap();
        let link = temp.path().join("link.md");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        // Symlink passed directly as the input path.
        let (files, stats) = collect_supported_files(&link).unwrap();
        assert!(files.is_empty());
        assert_eq!((stats.files_walked, stats.skipped_files), (0, 1));

        // Symlink encountered during a directory walk.
        let (files, stats) = collect_supported_files(temp.path()).unwrap();
        assert_eq!(files, vec![real]);
        assert_eq!(stats.skipped_files, 1, "the link is skipped, not double-ingested");
    }

    #[test]
    fn execute_records_binary_files_as_skipped_not_ingested() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("good.md"), "# keep\n\nbody").unwrap();
        // NUL bytes under a supported extension: walked, then skipped at parse.
        std::fs::write(temp.path().join("binary.txt"), [0x68, 0x00, 0x69]).unwrap();
        let mut opts = options(temp.path(), "http://127.0.0.1:1");
        opts.dry_run = true;
        let report = execute(&opts).unwrap();
        assert_eq!(report.files_walked, 2);
        assert_eq!(report.files_ingested, 1);
        assert_eq!(report.skipped_files, 1, "the binary file is counted, not silently lost");
        assert!(report.dry_run && !report.embedded);
        assert_eq!(report.batches, 1);
        assert_eq!(report.documents_sealed, 0, "a dry run seals nothing");
    }

    #[test]
    fn build_requests_rejects_a_single_oversize_fragment() {
        let mut doc = test_document(0, 1);
        doc.chunks[0].text = "x".repeat(MAX_REQUEST_JSON_BYTES + 1_024);
        let err = build_requests("local", "docs", vec![doc]).unwrap_err().to_string();
        assert!(err.contains("exceeds the conservative 12 MiB request limit"), "{err}");
    }

    /// A document whose 1,024-chunk append slice still serializes over the 12 MiB
    /// cap is halved until it fits — no chunk may be dropped in the process.
    #[test]
    fn fragment_documents_halves_oversize_appends_without_losing_chunks() {
        let mut doc = test_document(0, MAX_CHUNKS_PER_DOCUMENT_APPEND + 1);
        for chunk in &mut doc.chunks {
            chunk.text = "y".repeat(16 * 1024);
        }
        let fragments = fragment_documents(vec![doc]).unwrap();
        let total: usize = fragments.iter().map(|f| f.chunks.len()).sum();
        assert_eq!(total, MAX_CHUNKS_PER_DOCUMENT_APPEND + 1, "no chunk may be dropped");
        assert!(
            fragments
                .iter()
                .any(|f| f.chunks.len() < MAX_CHUNKS_PER_DOCUMENT_APPEND),
            "the oversize slice must have been halved"
        );
        assert!(fragments
            .iter()
            .all(|f| serde_json::to_vec(f).unwrap().len() <= MAX_REQUEST_JSON_BYTES));
        assert!(fragments.iter().all(|f| f.doc_id == "doc-0"));
    }

    // ── transport ───────────────────────────────────────────────────────────

    /// The route contract is 202 Accepted. A 2xx that is *not* 202 (a proxy's
    /// bare 200, say) must be refused — otherwise a request that never reached
    /// the ingest handler would be read as a successful seal.
    #[test]
    fn post_request_rejects_a_non_202_success() {
        let (port, handle) = crate::test_support::serve_responses(vec![(200, ingest_reply(1, 1))]);
        let request = IngestRequest {
            tenant_id: "local".to_string(),
            corpus_id: "docs".to_string(),
            documents: vec![test_document(1, 1)],
        };
        let err = post_request(&format!("http://127.0.0.1:{port}"), None, &request)
            .unwrap_err()
            .to_string();
        handle.join().ok();
        assert!(err.contains("unexpected HTTP 200"), "{err}");
    }

    #[test]
    fn post_request_maps_an_http_status_failure() {
        let (port, handle) = crate::test_support::serve_responses(vec![(503, "unavailable".to_string())]);
        let request = IngestRequest {
            tenant_id: "local".to_string(),
            corpus_id: "docs".to_string(),
            documents: vec![test_document(1, 1)],
        };
        let err = post_request(&format!("http://127.0.0.1:{port}"), None, &request)
            .unwrap_err()
            .to_string();
        handle.join().ok();
        assert!(err.contains("local ingest failed (HTTP 503)"), "{err}");
        assert!(err.contains("/v1/local/ingest"), "{err}");
    }

    #[test]
    fn post_request_reports_a_transport_failure_with_the_endpoint() {
        // Nothing is listening on port 1 — the non-status error arm.
        let request = IngestRequest {
            tenant_id: "local".to_string(),
            corpus_id: "docs".to_string(),
            documents: Vec::new(),
        };
        let err = post_request("http://127.0.0.1:1/", None, &request)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("local ingest request to http://127.0.0.1:1/v1/local/ingest failed"),
            "{err}"
        );
    }

    #[test]
    #[serial_test::serial]
    fn execute_posts_the_batch_and_records_the_seal() {
        let _env = EnvGuard::apply(&[("CRUX_AGENT_TOKEN", Some("tok-123"))]);
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("a.md"), "# Alpha\n\nbody text").unwrap();
        let (port, handle) = crate::test_support::serve_responses(vec![(202, ingest_reply(1, 1))]);

        let report = execute(&options(temp.path(), &format!("http://127.0.0.1:{port}"))).unwrap();
        assert_eq!(report.documents_sealed, 1);
        assert_eq!(report.batches, 1);
        assert_eq!(
            report.seals,
            vec![BatchSeal {
                batch: 1,
                segment_seq: 42,
                receipt_id: Some("rcpt-1".to_string()),
                chunks: 1,
                documents: 1,
                frame_count: 7,
                sealed: true,
                dense_vectors: 0,
                dense_dim: None,
                // The fixture reply predates `dense_status`, as a daemon older
                // than B1 would — the field must decode as absent, not fail.
                dense_status: None,
                dense_expected: None,
            }]
        );

        let reqs = handle.join().unwrap();
        assert_eq!(reqs.len(), 1);
        assert!(reqs[0].starts_with("POST /v1/local/ingest "));
        assert!(reqs[0].to_lowercase().contains("authorization: bearer tok-123"));
        let body = body_json(&reqs[0]);
        assert_eq!(body["tenant_id"], "local");
        assert_eq!(body["corpus_id"], "docs");
        assert_eq!(body["documents"][0]["chunks"][0]["metadata"]["source_path"], "a.md");
    }

    /// A blank `CRUX_AGENT_TOKEN` must not become an `Authorization: Bearer `
    /// header — an empty bearer reads as "authenticated" to some proxies.
    #[test]
    #[serial_test::serial]
    fn execute_omits_the_bearer_for_a_blank_token() {
        let _env = EnvGuard::apply(&[("CRUX_AGENT_TOKEN", Some("   "))]);
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("a.md"), "# Alpha\n\nbody").unwrap();
        let (port, handle) = crate::test_support::serve_responses(vec![(202, ingest_reply(1, 1))]);
        execute(&options(temp.path(), &format!("http://127.0.0.1:{port}"))).unwrap();
        let reqs = handle.join().unwrap();
        assert!(!reqs[0].to_lowercase().contains("authorization:"), "{}", reqs[0]);
    }

    /// D-9 (inverted pin): `execute` copied the daemon's own
    /// `documents`/`ingested` counters into the report without comparing them
    /// to what it sent, so a daemon that accepted the request but sealed
    /// nothing (`ingested: 0`) yielded `Ok` with `files_ingested: 2` and
    /// `documents_sealed: 0` — a no-op ingest read as success. Fixed in M4 of
    /// `crux-pinned-defect-remediation-2026-07-31`.
    #[test]
    #[serial_test::serial]
    fn execute_reconciles_sent_against_acknowledged_counts() {
        let _env = EnvGuard::apply(&[("CRUX_AGENT_TOKEN", None)]);
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("a.md"), "# Alpha\n\nbody").unwrap();
        std::fs::write(temp.path().join("b.md"), "# Beta\n\nbody").unwrap();
        let (port, handle) = crate::test_support::serve_responses(vec![(202, ingest_reply(0, 0))]);

        let err = execute(&options(temp.path(), &format!("http://127.0.0.1:{port}")))
            .expect_err("a zero acknowledgement must not read as success");
        handle.join().ok();
        let msg = err.to_string();
        assert!(
            msg.contains("acknowledged 0 documents") && msg.contains("2 documents"),
            "the error names both sides of the reconciliation: {msg}"
        );
    }

    #[test]
    #[serial_test::serial]
    fn run_prints_a_summary_for_both_dry_and_live_runs() {
        let _env = EnvGuard::apply(&[("CRUX_AGENT_TOKEN", None)]);
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("a.md"), "# Alpha\n\nbody").unwrap();
        let mut opts = options(temp.path(), "http://127.0.0.1:1");
        opts.dry_run = true;
        run(&opts).unwrap();

        let (port, handle) = crate::test_support::serve_responses(vec![(202, ingest_reply(1, 1))]);
        let live = options(temp.path(), &format!("http://127.0.0.1:{port}"));
        run(&live).unwrap();
        handle.join().ok();
    }

    #[test]
    #[serial_test::serial]
    fn follow_up_query_command_carries_auth_only_when_a_token_is_set() {
        let temp = "http://host:14800/";
        {
            let _env = EnvGuard::apply(&[("CRUX_AGENT_TOKEN", Some("t"))]);
            let cmd = follow_up_query_command(temp, "local");
            assert!(cmd.contains("Authorization: Bearer $CRUX_AGENT_TOKEN"));
            assert!(cmd.contains("'http://host:14800/v1/query/text-search'"));
        }
        let _env = EnvGuard::apply(&[("CRUX_AGENT_TOKEN", None)]);
        assert!(!follow_up_query_command(temp, "local").contains("Authorization"));
    }

    // ── embedding lane ──────────────────────────────────────────────────────

    fn embedding_reply(vector: &[f32]) -> String {
        serde_json::json!({ "data": [{ "embedding": vector }] }).to_string()
    }

    #[test]
    #[serial_test::serial]
    fn embed_documents_requires_the_endpoint_env() {
        let _env = EnvGuard::apply(&[("CORECRUXD_EMBEDDING_URL", Some("   ")), ("OPENAI_API_KEY", None)]);
        let mut docs = vec![test_document(0, 1)];
        let err = embed_documents(&mut docs).unwrap_err().to_string();
        assert!(err.contains("--embed requires CORECRUXD_EMBEDDING_URL"), "{err}");
    }

    #[test]
    #[serial_test::serial]
    fn embed_documents_attaches_one_vector_per_chunk() {
        let (port, handle) = crate::test_support::serve_responses(vec![
            (200, embedding_reply(&[0.1, 0.2, 0.3])),
            (200, embedding_reply(&[0.4, 0.5, 0.6])),
        ]);
        let _env = EnvGuard::apply(&[
            ("CORECRUXD_EMBEDDING_URL", Some(&format!("http://127.0.0.1:{port}"))),
            ("CORECRUXD_EMBEDDING_MODEL", Some("fixture-embed")),
            ("OPENAI_API_KEY", Some("sk-test")),
        ]);
        let mut docs = vec![test_document(0, 2)];
        embed_documents(&mut docs).unwrap();
        assert_eq!(
            docs[0].chunks[0].dense_vector.as_deref(),
            Some([0.1, 0.2, 0.3].as_slice())
        );
        assert_eq!(
            docs[0].chunks[1].dense_vector.as_deref(),
            Some([0.4, 0.5, 0.6].as_slice())
        );

        let reqs = handle.join().unwrap();
        assert!(reqs[0].starts_with("POST /v1/embeddings "));
        assert!(reqs[0].to_lowercase().contains("authorization: bearer sk-test"));
        assert_eq!(body_json(&reqs[0])["model"], "fixture-embed");
        assert_eq!(body_json(&reqs[1])["input"], "text 1");
    }

    /// A mid-ingest dimension change would silently corrupt the dense lane, so
    /// the second, differently-sized vector must abort the run.
    #[test]
    #[serial_test::serial]
    fn embed_documents_rejects_a_dimension_change_mid_ingest() {
        let (port, handle) = crate::test_support::serve_responses(vec![
            (200, embedding_reply(&[0.1, 0.2, 0.3])),
            (200, embedding_reply(&[0.4, 0.5])),
        ]);
        let _env = EnvGuard::apply(&[
            ("CORECRUXD_EMBEDDING_URL", Some(&format!("http://127.0.0.1:{port}/v1"))),
            ("CORECRUXD_EMBEDDING_MODEL", None),
            ("OPENAI_API_KEY", None),
        ]);
        let mut docs = vec![test_document(0, 2)];
        let err = embed_documents(&mut docs).unwrap_err().to_string();
        let reqs = handle.join().unwrap();
        assert!(err.contains("expected 3, got 2"), "{err}");
        // The default model is used when the env var is unset.
        assert_eq!(body_json(&reqs[0])["model"], "nomic-embed-text");
        assert!(!reqs[0].to_lowercase().contains("authorization:"));
    }

    #[test]
    #[serial_test::serial]
    fn embed_documents_rejects_empty_and_non_finite_vectors() {
        for (reply, expected) in [
            (embedding_reply(&[]), "empty or non-finite vector"),
            // JSON cannot spell NaN, and serde_json rejects literals that
            // overflow f64 — but a valid f64 past the f32 range widens to +inf.
            (
                r#"{"data":[{"embedding":[1e39]}]}"#.to_string(),
                "empty or non-finite vector",
            ),
            (r#"{"data":[]}"#.to_string(), "returned no vectors"),
        ] {
            let (port, handle) = crate::test_support::serve_responses(vec![(200, reply)]);
            let _env = EnvGuard::apply(&[
                (
                    "CORECRUXD_EMBEDDING_URL",
                    Some(&format!("http://127.0.0.1:{port}/v1/embeddings")),
                ),
                ("OPENAI_API_KEY", None),
            ]);
            let mut docs = vec![test_document(0, 1)];
            let err = embed_documents(&mut docs).unwrap_err().to_string();
            handle.join().ok();
            assert!(err.contains(expected), "{err}");
        }
    }

    #[test]
    #[serial_test::serial]
    fn embed_documents_maps_endpoint_status_and_transport_failures() {
        let (port, handle) = crate::test_support::serve_responses(vec![(429, "slow down".to_string())]);
        {
            let _env = EnvGuard::apply(&[
                ("CORECRUXD_EMBEDDING_URL", Some(&format!("http://127.0.0.1:{port}"))),
                ("OPENAI_API_KEY", None),
            ]);
            let mut docs = vec![test_document(0, 1)];
            let err = embed_documents(&mut docs).unwrap_err().to_string();
            assert!(err.contains("embedding request failed (HTTP 429)"), "{err}");
        }
        handle.join().ok();

        let _env = EnvGuard::apply(&[
            ("CORECRUXD_EMBEDDING_URL", Some("http://127.0.0.1:1")),
            ("OPENAI_API_KEY", None),
        ]);
        let mut docs = vec![test_document(0, 1)];
        let err = embed_documents(&mut docs).unwrap_err().to_string();
        assert!(
            err.contains("embedding request to http://127.0.0.1:1/v1/embeddings failed"),
            "{err}"
        );
    }

    /// `--embed` is honoured on a live run and ignored on a dry run (the dry run
    /// must never dial the embedding endpoint).
    #[test]
    #[serial_test::serial]
    fn dry_run_never_calls_the_embedding_endpoint() {
        let _env = EnvGuard::apply(&[("CORECRUXD_EMBEDDING_URL", Some("http://127.0.0.1:1"))]);
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("a.md"), "# Alpha\n\nbody").unwrap();
        let mut opts = options(temp.path(), "http://127.0.0.1:1");
        opts.dry_run = true;
        opts.embed = true;
        let report = execute(&opts).unwrap();
        assert!(!report.embedded, "embedding is suppressed on a dry run");
    }

    /// D-9: `execute` copied the daemon's counts into its report without
    /// comparing them to what it sent. A 202 carrying `ingested: 0` for a
    /// two-document batch returned `Ok` with `files_ingested: 2,
    /// documents_sealed: 0` — the operator was told the ingest succeeded and
    /// nothing recorded that the documents never landed.
    #[test]
    fn an_acknowledged_zero_count_is_an_error_not_a_successful_report() {
        let tmp = two_document_corpus();
        let body = serde_json::json!({
            "ingested": 0,
            "documents": 0,
            "frame_count": 0,
            "sealed": true,
            "segment_seq": 1,
            "receipt_id": null,
            "dense_vectors": 0,
            "dense_dim": null,
        })
        .to_string();
        let (port, handle) = crate::test_support::serve_responses(vec![(202, body)]);

        let err = execute(&options_for(tmp.path(), port)).expect_err("a zero acknowledgement must not read as success");
        let msg = err.to_string();
        assert!(
            msg.contains("acknowledged 0 documents") && msg.contains("2 documents"),
            "the error names both sides of the reconciliation: {msg}"
        );
        let _ = handle.join();
    }

    /// A partial acknowledgement is caught the same way — one of two documents
    /// landing is not a success.
    #[test]
    fn a_partial_acknowledgement_is_an_error() {
        let tmp = two_document_corpus();
        let body = serde_json::json!({
            "ingested": 1,
            "documents": 1,
            "frame_count": 1,
            "sealed": true,
            "segment_seq": 1,
            "receipt_id": null,
            "dense_vectors": 0,
            "dense_dim": null,
        })
        .to_string();
        let (port, handle) = crate::test_support::serve_responses(vec![(202, body)]);

        let err =
            execute(&options_for(tmp.path(), port)).expect_err("a partial acknowledgement must not read as success");
        assert!(err.to_string().contains("acknowledged 1 documents"), "{err}");
        let _ = handle.join();
    }

    /// Control: a matching acknowledgement still reports success.
    #[test]
    fn a_matching_acknowledgement_reports_success() {
        let tmp = two_document_corpus();
        let body = serde_json::json!({
            "ingested": 2,
            "documents": 2,
            "frame_count": 2,
            "sealed": true,
            "segment_seq": 1,
            "receipt_id": "abc",
            "dense_vectors": 0,
            "dense_dim": null,
        })
        .to_string();
        let (port, handle) = crate::test_support::serve_responses(vec![(202, body)]);

        let report = execute(&options_for(tmp.path(), port)).expect("matching counts succeed");
        assert_eq!(report.files_ingested, 2);
        assert_eq!(report.documents_sealed, 2);
        assert_eq!(report.seals.len(), 1);
        let _ = handle.join();
    }
}
