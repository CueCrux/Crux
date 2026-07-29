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
        let response = post_request(&options.daemon_url, token.as_deref(), request)?;
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
}
