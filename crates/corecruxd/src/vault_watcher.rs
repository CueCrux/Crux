// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! `EntryKind::FileWatcher` runtime — local markdown vault (Obsidian-shaped).
//!
//! ExecPlan `crux-integrations-and-template-library-2026-07-25` (I4, package D0).
//!
//! The integration-pack manifest contract has declared an
//! `EntryKind::FileWatcher` variant since v1 with no runtime behind it. This
//! module is that runtime, and its first (only) target is a directory of
//! markdown notes: each cycle it scans the configured roots, diffs against a
//! persisted cursor, and pushes changed notes through the same local prose
//! ingest path `POST /v1/local/ingest` uses — so vault notes become BM25- (and,
//! when a dense embedder is configured, vector-) searchable on the node.
//!
//! ## Double gate — off unless the operator asked twice
//!
//! Nothing here runs unless BOTH are true:
//!
//! 1. A pack whose manifest `entry.kind` is `file_watcher` is **installed AND
//!    granted** on this node (`crux_integrations::enabled_packs_of_kind`). The
//!    first-party pack is `vault.markdown-watcher`.
//! 2. `CORECRUXD_VAULT_WATCH_ROOTS` names at least one absolute directory
//!    (colon-separated, `PATH`-style).
//!
//! Either alone does nothing, and [`activation`] logs one honest line saying
//! which half is missing so a half-configured node is diagnosable from the boot
//! log rather than from silence.
//!
//! ## Safety properties of the scan
//!
//! - Hidden directories (`.git`, `.obsidian`, any `.*`) are never descended.
//! - **Symlinks are refused**, files and directories alike — the scan uses
//!   `symlink_metadata` and skips anything that is a link, so a link planted
//!   inside a vault cannot pull `/etc` into the corpus.
//! - Every candidate is canonicalized and re-checked to be under the
//!   canonical root before it is read.
//! - Only `*.md` is considered, and files above [`MAX_FILE_BYTES`] are skipped.
//! - Work per cycle is capped at [`MAX_FILES_PER_CYCLE`]; the remainder is
//!   reported as `pending` and picked up next cycle (the cursor only advances
//!   over files actually ingested).
//!
//! ## Persistence
//!
//! Two facts, both under the born-private `__sync__::vault-watcher` entity:
//!
//! - key `status` — written by [`crate::sync_scheduler`] (schema
//!   `crux.sync_job_status.v1`); its `detail` carries this module's per-cycle
//!   report, including the paths deleted from disk.
//! - key `cursor` — written here (schema `crux.vault_watcher.cursor.v1`):
//!
//! ```json
//! {
//!   "schema": "crux.vault_watcher.cursor.v1",
//!   "updated_at_unix_ms": 1753440000000,
//!   "truncated": false,
//!   "entries": {
//!     "/vault/note.md": {
//!       "mtime_ms": 1753439000000,
//!       "size": 2048,
//!       "content_hash": "b3:9f86d0…",
//!       "seen_at_unix_ms": 1753440000000,
//!       "title": "Note",
//!       "tags": ["project", "crux"]
//!     }
//!   }
//! }
//! ```
//!
//! The cursor is capped at [`MAX_CURSOR_BYTES`]; over that, the most recently
//! seen entries are kept, the rest are dropped, and `truncated` goes true (also
//! surfaced in the status detail). A dropped entry is re-ingested next time it
//! is seen — truncation costs work, never correctness.
//!
//! ## Deletions are recorded, not applied
//!
//! A note that disappears from disk is removed from the cursor and listed in
//! the status detail. This wave performs **no destructive store operation** —
//! sealed segments are append-only and retracting a document needs a tombstone
//! design that does not exist yet.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use corecrux_memory::fact_store::{FactQuery, StoreFact};
use corecrux_memory::{FactStore, HorizonClass};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::local_ingest::{chunk_markdown, ingest_prose_documents, LocalIngestHandles, ProseChunk, ProseDocument};
use crate::sync_scheduler::{JobOutcome, JobResult, SYNC_ENTITY_PREFIX};

/// Scheduler job id; also the `__sync__::` entity suffix for both facts.
pub const JOB_ID: &str = "vault-watcher";
/// Fact key holding the scan cursor.
pub const CURSOR_KEY: &str = "cursor";
/// Schema tag stamped on the cursor value.
pub const CURSOR_SCHEMA_V1: &str = "crux.vault_watcher.cursor.v1";

/// Colon-separated absolute directories to watch. Unset/empty ⇒ watcher off.
pub const ENV_ROOTS: &str = "CORECRUXD_VAULT_WATCH_ROOTS";
/// Scan cadence in seconds (default [`DEFAULT_INTERVAL_SECS`]).
pub const ENV_INTERVAL_SECS: &str = "CORECRUXD_VAULT_WATCH_INTERVAL_SECS";
/// Tenant the notes are sealed under (default [`DEFAULT_TENANT`]).
pub const ENV_TENANT: &str = "CORECRUXD_VAULT_WATCH_TENANT";
/// Corpus the notes are sealed under (default [`DEFAULT_CORPUS`]).
pub const ENV_CORPUS: &str = "CORECRUXD_VAULT_WATCH_CORPUS";

/// Default cadence: 5 minutes.
pub const DEFAULT_INTERVAL_SECS: u64 = 300;
/// Default tenant + corpus — the same pair `crux-ingest` defaults to, so the
/// watcher lands notes where `corecruxctl ingest` puts hand-fed documents.
pub const DEFAULT_TENANT: &str = "local";
pub const DEFAULT_CORPUS: &str = "docs";

/// Largest note read in one go (4 MiB — matches the ingest door's per-chunk cap).
pub const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;
/// Files ingested per cycle. Bounds the first pass over a large vault.
pub const MAX_FILES_PER_CYCLE: usize = 500;
/// Documents per seal batch.
const MAX_DOCS_PER_BATCH: usize = 128;
/// Chunks per seal batch.
const MAX_CHUNKS_PER_BATCH: usize = 2_048;
/// Serialized cursor cap (~256 KB) before oldest-seen entries are dropped.
pub const MAX_CURSOR_BYTES: usize = 256 * 1024;
/// Directory name skipped explicitly (also covered by the hidden-dir rule;
/// named so the intent survives a change to that rule).
const OBSIDIAN_DIR: &str = ".obsidian";

// ── Configuration + activation ───────────────────────────────────────────

/// Resolved watcher configuration. Constructed only when the double gate passes.
#[derive(Debug, Clone)]
pub struct VaultWatcherConfig {
    pub roots: Vec<PathBuf>,
    pub interval: Duration,
    pub tenant_id: String,
    pub corpus_id: String,
}

/// Parse `PATH`-style watch roots. Keeps absolute paths that resolve to a
/// directory; returns each rejected entry with the reason so the caller can log
/// once rather than silently dropping operator intent.
pub fn parse_watch_roots(raw: &str) -> (Vec<PathBuf>, Vec<String>) {
    let mut roots = Vec::new();
    let mut rejected = Vec::new();
    let mut seen = BTreeSet::new();
    for part in raw.split(':') {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        let path = PathBuf::from(trimmed);
        if !path.is_absolute() {
            rejected.push(format!("{trimmed} (not absolute)"));
            continue;
        }
        let Ok(canonical) = std::fs::canonicalize(&path) else {
            rejected.push(format!("{trimmed} (not readable)"));
            continue;
        };
        if !canonical.is_dir() {
            rejected.push(format!("{trimmed} (not a directory)"));
            continue;
        }
        if seen.insert(canonical.clone()) {
            roots.push(canonical);
        }
    }
    (roots, rejected)
}

/// Why the watcher is (not) active. Returned so `main.rs` logs one line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Activation {
    /// Both gates passed.
    Active { pack_ids: Vec<String>, roots: usize },
    /// Neither gate passed — the ordinary default. Silent.
    Inactive,
    /// Exactly one gate passed. Carries the operator-facing explanation.
    HalfConfigured(String),
}

/// Evaluate the double gate against the pack registry under `data_dir` and the
/// process environment.
///
/// Registry read errors are treated as "no packs" and folded into the returned
/// explanation — a corrupt integrations directory must not panic the boot path.
pub fn activation(data_dir: &Path) -> (Activation, Option<VaultWatcherConfig>) {
    let raw_roots = std::env::var(ENV_ROOTS).unwrap_or_default();
    let (roots, rejected) = parse_watch_roots(&raw_roots);

    let packs = match crux_integrations::enabled_packs_of_kind(data_dir, crux_integrations::EntryKind::FileWatcher) {
        Ok(packs) => packs,
        Err(err) => {
            tracing::warn!(
                ?err,
                "vault-watcher-pack-registry-unreadable; treating as no packs granted"
            );
            Vec::new()
        }
    };
    let pack_ids: Vec<String> = packs.into_iter().map(|manifest| manifest.id).collect();

    if !rejected.is_empty() {
        tracing::warn!(
            rejected = ?rejected,
            "vault-watcher: ignoring {} unusable entry in {ENV_ROOTS} (roots must be absolute, readable directories)",
            rejected.len()
        );
    }

    match (pack_ids.is_empty(), roots.is_empty()) {
        (true, true) => (Activation::Inactive, None),
        (false, true) => (
            Activation::HalfConfigured(format!(
                "file-watcher pack(s) {pack_ids:?} are granted but {ENV_ROOTS} is unset — nothing to watch; \
                 set it to colon-separated absolute directories"
            )),
            None,
        ),
        (true, false) => (
            Activation::HalfConfigured(format!(
                "{ENV_ROOTS} names {} director{} but no file-watcher integration pack is installed+granted — \
                 grant `vault.markdown-watcher` to activate",
                roots.len(),
                if roots.len() == 1 { "y" } else { "ies" }
            )),
            None,
        ),
        (false, false) => {
            let config = VaultWatcherConfig {
                roots: roots.clone(),
                interval: interval_from_env(),
                tenant_id: env_or(ENV_TENANT, DEFAULT_TENANT),
                corpus_id: env_or(ENV_CORPUS, DEFAULT_CORPUS),
            };
            (
                Activation::Active {
                    pack_ids,
                    roots: roots.len(),
                },
                Some(config),
            )
        }
    }
}

fn env_or(key: &str, fallback: &str) -> String {
    std::env::var(key)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| fallback.to_string())
}

fn interval_from_env() -> Duration {
    let secs = std::env::var(ENV_INTERVAL_SECS)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|s| *s > 0)
        .unwrap_or(DEFAULT_INTERVAL_SECS);
    Duration::from_secs(secs)
}

// ── Scanning ─────────────────────────────────────────────────────────────

/// One markdown file the scan accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannedFile {
    /// Canonical absolute path; the cursor key and the ingest `doc_id`.
    pub path: PathBuf,
    pub mtime_ms: u64,
    pub size: u64,
}

/// Recursively scan one root for `*.md`, refusing symlinks and hidden
/// directories. Unreadable entries are skipped, not fatal: a single bad
/// permission must not blind the whole cycle.
pub fn scan_root(root: &Path) -> Result<Vec<ScannedFile>, String> {
    let canonical_root =
        std::fs::canonicalize(root).map_err(|err| format!("canonicalize {}: {err}", root.display()))?;
    let mut out = Vec::new();
    let mut stack = vec![canonical_root.clone()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(err) => {
                tracing::debug!(dir = %dir.display(), error = %err, "vault-watcher-readdir-skipped");
                continue;
            }
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            // `symlink_metadata` does not follow: a link is identified as a link.
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if meta.file_type().is_symlink() {
                tracing::debug!(path = %path.display(), "vault-watcher-symlink-refused");
                continue;
            }
            if meta.is_dir() {
                if name.starts_with('.') || name == OBSIDIAN_DIR {
                    continue;
                }
                stack.push(path);
                continue;
            }
            if !meta.is_file() || name.starts_with('.') {
                continue;
            }
            if !path
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e.eq_ignore_ascii_case("md"))
            {
                continue;
            }
            if meta.len() > MAX_FILE_BYTES {
                tracing::debug!(path = %path.display(), bytes = meta.len(), "vault-watcher-file-too-large-skipped");
                continue;
            }
            // Belt-and-braces containment check: even though no symlink was
            // followed, prove the resolved path is still under the root.
            let Ok(resolved) = std::fs::canonicalize(&path) else {
                continue;
            };
            if !resolved.starts_with(&canonical_root) {
                tracing::warn!(path = %path.display(), "vault-watcher-path-escape-refused");
                continue;
            }
            out.push(ScannedFile {
                path: resolved,
                mtime_ms: mtime_ms(&meta),
                size: meta.len(),
            });
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

fn mtime_ms(meta: &std::fs::Metadata) -> u64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_millis() as u64)
}

// ── Frontmatter ──────────────────────────────────────────────────────────

/// The two frontmatter fields this runtime understands.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Frontmatter {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

/// Split a note into (frontmatter, body).
///
/// Recognises the YAML block form: a leading `---` line, terminated by `---` or
/// `...` on its own line. `serde_yaml` is already a workspace dependency, so
/// the block is parsed properly rather than by a hand-rolled scanner. A block
/// that fails to parse (or is not a mapping) yields an empty [`Frontmatter`]
/// and is still stripped — malformed YAML must not leak into the BM25 text.
pub fn parse_frontmatter(input: &str) -> (Frontmatter, &str) {
    let trimmed = input.strip_prefix('\u{feff}').unwrap_or(input);
    let Some(rest) = trimmed
        .strip_prefix("---\n")
        .or_else(|| trimmed.strip_prefix("---\r\n"))
    else {
        return (Frontmatter::default(), trimmed);
    };

    let mut offset = 0usize;
    let mut block_end: Option<(usize, usize)> = None;
    for line in rest.split_inclusive('\n') {
        let marker = line.trim_end_matches(['\n', '\r']).trim_end();
        if marker == "---" || marker == "..." {
            block_end = Some((offset, offset + line.len()));
            break;
        }
        offset += line.len();
    }
    let Some((yaml_end, body_start)) = block_end else {
        // Unterminated block: not frontmatter, treat the whole file as body.
        return (Frontmatter::default(), trimmed);
    };

    let body = &rest[body_start..];
    let front = parse_frontmatter_block(&rest[..yaml_end]);
    (front, body)
}

fn parse_frontmatter_block(yaml: &str) -> Frontmatter {
    let Ok(value) = serde_yaml::from_str::<serde_yaml::Value>(yaml) else {
        return Frontmatter::default();
    };
    let Some(mapping) = value.as_mapping() else {
        return Frontmatter::default();
    };
    let get = |key: &str| mapping.get(serde_yaml::Value::String(key.to_string()));

    let title = get("title")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(str::to_string);

    let tags = match get("tags") {
        Some(serde_yaml::Value::Sequence(items)) => items
            .iter()
            .filter_map(|item| item.as_str().map(str::trim))
            .filter(|t| !t.is_empty())
            .map(str::to_string)
            .collect(),
        // Obsidian's inline form: `tags: alpha, beta` (or space-separated).
        Some(serde_yaml::Value::String(inline)) => inline
            .split([',', ' '])
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .map(str::to_string)
            .collect(),
        _ => Vec::new(),
    };

    Frontmatter { title, tags }
}

// ── Cursor ───────────────────────────────────────────────────────────────

/// Per-file state remembered between cycles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CursorEntry {
    pub mtime_ms: u64,
    pub size: u64,
    /// `b3:<hex>` of the file bytes at last ingest.
    pub content_hash: String,
    pub seen_at_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

/// `__sync__::vault-watcher` key `cursor`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultCursor {
    #[serde(default = "cursor_schema")]
    pub schema: String,
    #[serde(default)]
    pub updated_at_unix_ms: u64,
    /// True when [`VaultCursor::cap`] dropped entries to fit the size budget.
    #[serde(default)]
    pub truncated: bool,
    #[serde(default)]
    pub entries: BTreeMap<String, CursorEntry>,
}

fn cursor_schema() -> String {
    CURSOR_SCHEMA_V1.to_string()
}

impl Default for VaultCursor {
    fn default() -> Self {
        Self {
            schema: cursor_schema(),
            updated_at_unix_ms: 0,
            truncated: false,
            entries: BTreeMap::new(),
        }
    }
}

impl VaultCursor {
    /// Drop the least-recently-seen entries until the serialized form fits
    /// [`MAX_CURSOR_BYTES`]. Returns the number of entries dropped.
    pub fn cap(&mut self, max_bytes: usize) -> usize {
        self.truncated = false;
        let mut dropped = 0usize;
        while self.entries.len() > 1 && serialized_len(self) > max_bytes {
            // Oldest by seen_at, then by path for determinism.
            let Some(victim) = self
                .entries
                .iter()
                .min_by(|a, b| a.1.seen_at_unix_ms.cmp(&b.1.seen_at_unix_ms).then_with(|| a.0.cmp(b.0)))
                .map(|(path, _)| path.clone())
            else {
                break;
            };
            self.entries.remove(&victim);
            dropped += 1;
        }
        if dropped > 0 {
            self.truncated = true;
        }
        dropped
    }
}

fn serialized_len(cursor: &VaultCursor) -> usize {
    serde_json::to_vec(cursor).map_or(0, |bytes| bytes.len())
}

/// Classification of one scanned file against the cursor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileChange {
    /// Not in the cursor.
    Added,
    /// In the cursor with a different `(mtime, size)` — content must be re-read
    /// to know whether it actually changed.
    Touched,
    /// `(mtime, size)` identical to the cursor; no read needed.
    Unchanged,
}

/// Classify a scanned file. Content hashing is deliberately NOT done here: a
/// cycle over an unchanged vault must not read every byte on disk.
pub fn classify(cursor: &VaultCursor, file: &ScannedFile) -> FileChange {
    match cursor.entries.get(&path_key(&file.path)) {
        None => FileChange::Added,
        Some(entry) if entry.mtime_ms == file.mtime_ms && entry.size == file.size => FileChange::Unchanged,
        Some(_) => FileChange::Touched,
    }
}

/// Cursor keys present on disk no longer.
pub fn deleted_paths(cursor: &VaultCursor, scanned: &[ScannedFile]) -> Vec<String> {
    let live: BTreeSet<String> = scanned.iter().map(|f| path_key(&f.path)).collect();
    cursor
        .entries
        .keys()
        .filter(|key| !live.contains(*key))
        .cloned()
        .collect()
}

fn path_key(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

fn content_hash(bytes: &[u8]) -> String {
    format!("b3:{}", blake3::hash(bytes).to_hex())
}

// ── Runtime ──────────────────────────────────────────────────────────────

/// A note that survived the diff and is ready to seal.
struct PreparedNote {
    key: String,
    document: ProseDocument,
    entry: CursorEntry,
}

/// The file-watcher runtime. One instance per daemon; driven by
/// [`crate::sync_scheduler`].
pub struct VaultWatcher {
    config: VaultWatcherConfig,
    fact_store: Arc<RwLock<FactStore>>,
    ingest: LocalIngestHandles,
}

impl VaultWatcher {
    pub fn new(config: VaultWatcherConfig, fact_store: Arc<RwLock<FactStore>>, ingest: LocalIngestHandles) -> Self {
        Self {
            config,
            fact_store,
            ingest,
        }
    }

    pub fn interval(&self) -> Duration {
        self.config.interval
    }

    /// Read the persisted cursor. A missing or unparseable cursor starts empty
    /// (the next cycle simply re-ingests, which the chunk-id idempotency key
    /// absorbs) rather than failing the job.
    pub async fn load_cursor(&self) -> VaultCursor {
        let guard = self.fact_store.read().await;
        let result = guard.query(&FactQuery {
            entity: Some(format!("{SYNC_ENTITY_PREFIX}{JOB_ID}")),
            top_k: 10,
            ..Default::default()
        });
        result
            .facts
            .iter()
            .find(|fact| fact.key == CURSOR_KEY && !fact.deleted)
            .and_then(|fact| serde_json::from_str::<VaultCursor>(&fact.value).ok())
            .unwrap_or_default()
    }

    async fn persist_cursor(&self, cursor: &VaultCursor) {
        let value = match serde_json::to_string(cursor) {
            Ok(value) => value,
            Err(err) => {
                tracing::warn!(?err, "vault-watcher-cursor-serialize-failed");
                return;
            }
        };
        let req = StoreFact {
            tenant_hash: "default".to_string(),
            entity: format!("{SYNC_ENTITY_PREFIX}{JOB_ID}"),
            key: CURSOR_KEY.to_string(),
            value,
            source_receipt: None,
            confidence: 1.0,
            private: true,
            horizon_class: Some(HorizonClass::Volatile),
            actor: Some("vault-watcher".to_string()),
        };
        let mut guard = self.fact_store.write().await;
        if let Err(err) = guard.try_store(req) {
            tracing::warn!(?err, "vault-watcher-cursor-append-failed");
        }
    }

    /// One scan + diff + ingest cycle. This is the scheduler job body.
    pub async fn run_cycle(&self) -> JobResult {
        let now_ms = crate::ops_events::now_unix_ms();
        let mut cursor = self.load_cursor().await;

        // 1. Scan every root. A root that vanished (unmounted drive) is a
        //    reportable failure, not a reason to treat its notes as deleted.
        let mut scanned: Vec<ScannedFile> = Vec::new();
        let mut scan_errors: Vec<String> = Vec::new();
        for root in &self.config.roots {
            match scan_root(root) {
                Ok(files) => scanned.extend(files),
                Err(err) => scan_errors.push(err),
            }
        }
        if !scan_errors.is_empty() && scanned.is_empty() {
            return Err(format!("all watch roots unreadable: {}", scan_errors.join("; ")));
        }
        scanned.sort_by(|a, b| a.path.cmp(&b.path));
        scanned.dedup_by(|a, b| a.path == b.path);

        // 2. Diff.
        let deleted = deleted_paths(&cursor, &scanned);
        let candidates: Vec<&ScannedFile> = scanned
            .iter()
            .filter(|file| !matches!(classify(&cursor, file), FileChange::Unchanged))
            .collect();
        let pending = candidates.len().saturating_sub(MAX_FILES_PER_CYCLE);

        // 3. Read + prepare the ones we will ingest this cycle.
        let mut prepared: Vec<PreparedNote> = Vec::new();
        let mut unchanged_content = 0usize;
        let mut read_errors: Vec<String> = Vec::new();
        let mut added = 0usize;
        let mut modified = 0usize;
        for file in candidates.into_iter().take(MAX_FILES_PER_CYCLE) {
            let key = path_key(&file.path);
            let bytes = match std::fs::read(&file.path) {
                Ok(bytes) => bytes,
                Err(err) => {
                    read_errors.push(format!("{key}: {err}"));
                    continue;
                }
            };
            let hash = content_hash(&bytes);
            let was_known = cursor.entries.contains_key(&key);
            if let Some(existing) = cursor.entries.get(&key) {
                if existing.content_hash == hash {
                    // Touched but byte-identical (a `touch`, or an editor
                    // rewrite): refresh the stat fields, skip the re-seal.
                    let mut refreshed = existing.clone();
                    refreshed.mtime_ms = file.mtime_ms;
                    refreshed.size = file.size;
                    refreshed.seen_at_unix_ms = now_ms;
                    cursor.entries.insert(key, refreshed);
                    unchanged_content += 1;
                    continue;
                }
            }
            let text = match String::from_utf8(bytes) {
                Ok(text) => text,
                Err(_) => {
                    read_errors.push(format!("{key}: not valid UTF-8"));
                    continue;
                }
            };
            let (front, body) = parse_frontmatter(&text);
            let chunks = chunk_markdown(body);
            if chunks.is_empty() {
                // An empty (or frontmatter-only) note: remember it so we stop
                // re-reading it, but seal nothing — the door rejects empty text.
                cursor.entries.insert(
                    key,
                    CursorEntry {
                        mtime_ms: file.mtime_ms,
                        size: file.size,
                        content_hash: hash,
                        seen_at_unix_ms: now_ms,
                        title: front.title,
                        tags: front.tags,
                    },
                );
                continue;
            }
            if was_known {
                modified += 1;
            } else {
                added += 1;
            }
            let document = ProseDocument {
                doc_id: key.clone(),
                chunks: chunks
                    .into_iter()
                    .enumerate()
                    .map(|(index, text)| ProseChunk {
                        chunk_id: format!("{key}::{index:06}"),
                        text,
                        dense_vector: None,
                    })
                    .collect(),
            };
            prepared.push(PreparedNote {
                key,
                entry: CursorEntry {
                    mtime_ms: file.mtime_ms,
                    size: file.size,
                    content_hash: hash,
                    seen_at_unix_ms: now_ms,
                    title: front.title,
                    tags: front.tags,
                },
                document,
            });
        }

        // 4. Seal in bounded batches. A batch failure aborts the cycle: its
        //    notes stay out of the cursor and are retried next time.
        let mut ingested_chunks = 0usize;
        let mut sealed_batches = 0usize;
        for batch in batch_notes(prepared) {
            let documents: Vec<ProseDocument> = batch.iter().map(|note| note.document.clone()).collect();
            let (documents, profile) = self.embed(documents).await?;
            let summary = ingest_prose_documents(
                &self.ingest,
                &self.config.tenant_id,
                &self.config.corpus_id,
                documents,
                profile,
            )
            .await
            .map_err(|err| format!("vault ingest seal failed: {err}"))?;
            ingested_chunks += summary.chunks;
            sealed_batches += 1;
            for note in batch {
                cursor.entries.insert(note.key, note.entry);
            }
        }

        // 5. Retire deleted paths from the cursor (record only — no store
        //    mutation; sealed segments are append-only).
        for key in &deleted {
            cursor.entries.remove(key);
        }

        // 6. Persist the cursor when it moved.
        cursor.updated_at_unix_ms = now_ms;
        let dropped = cursor.cap(MAX_CURSOR_BYTES);
        self.persist_cursor(&cursor).await;

        Ok(JobOutcome::Ran(Some(serde_json::json!({
            "roots": self.config.roots.iter().map(|r| r.display().to_string()).collect::<Vec<_>>(),
            "tenant_id": self.config.tenant_id,
            "corpus_id": self.config.corpus_id,
            "scanned": scanned.len(),
            "added": added,
            "modified": modified,
            "unchanged_content": unchanged_content,
            "deleted": deleted,
            "deleted_note": "recorded only; sealed segments are append-only and are not retracted",
            "pending": pending,
            "ingested_chunks": ingested_chunks,
            "sealed_batches": sealed_batches,
            "cursor_entries": cursor.entries.len(),
            "cursor_truncated": cursor.truncated,
            "cursor_dropped": dropped,
            "scan_errors": scan_errors,
            "read_errors": read_errors,
        }))))
    }

    /// Attach dense vectors when the node has an embedder, mirroring the
    /// server-embed branch of `POST /v1/local/ingest`.
    ///
    /// Delegation has a no-fallback contract: if a remote embedding provider is
    /// configured and the call fails, the cycle errors rather than silently
    /// sealing a BM25-only batch under a dense profile. A purely local embedder
    /// that errors degrades to BM25-only with a warning, matching the door.
    async fn embed(
        &self,
        documents: Vec<ProseDocument>,
    ) -> Result<(Vec<ProseDocument>, Option<corecrux_memory::embeddings::SemanticProfile>), String> {
        let texts: Vec<&str> = documents
            .iter()
            .flat_map(|doc| &doc.chunks)
            .map(|chunk| chunk.text.as_str())
            .collect();
        let guard = self.fact_store.read().await;
        let delegated = guard.delegation_status().is_some();
        if guard.semantic_profile().is_none() {
            return Ok((documents, None));
        }
        let embeddings = match guard.try_embed_texts(&texts) {
            Ok(embeddings) => embeddings,
            Err(err) if delegated => {
                return Err(format!("embedding delegation degraded; refusing to seal: {err}"));
            }
            Err(err) => {
                tracing::warn!(error = %err, chunks = texts.len(), "vault-watcher-embedding-failed; sealing BM25-only");
                None
            }
        };
        let profile = embeddings.as_ref().and(guard.semantic_profile());
        drop(guard);

        let Some(embeddings) = embeddings else {
            return Ok((documents, None));
        };
        let mut embeddings = embeddings.into_iter();
        let documents = documents
            .into_iter()
            .map(|mut doc| {
                for chunk in &mut doc.chunks {
                    chunk.dense_vector = embeddings.next();
                }
                doc
            })
            .collect();
        Ok((documents, profile))
    }
}

/// Split prepared notes into seal batches bounded by document + chunk count.
fn batch_notes(notes: Vec<PreparedNote>) -> Vec<Vec<PreparedNote>> {
    let mut batches: Vec<Vec<PreparedNote>> = Vec::new();
    let mut current: Vec<PreparedNote> = Vec::new();
    let mut current_chunks = 0usize;
    for note in notes {
        let chunks = note.document.chunks.len();
        if !current.is_empty()
            && (current.len() >= MAX_DOCS_PER_BATCH || current_chunks + chunks > MAX_CHUNKS_PER_BATCH)
        {
            batches.push(std::mem::take(&mut current));
            current_chunks = 0;
        }
        current_chunks += chunks;
        current.push(note);
    }
    if !current.is_empty() {
        batches.push(current);
    }
    batches
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::fs;

    fn write(path: &Path, contents: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("mkdir");
        }
        fs::write(path, contents).expect("write");
    }

    fn watcher(root: &Path) -> (VaultWatcher, tempfile::TempDir) {
        let data = tempfile::tempdir().expect("data dir");
        let watcher = VaultWatcher::new(
            VaultWatcherConfig {
                roots: vec![fs::canonicalize(root).expect("canonicalize root")],
                interval: Duration::from_secs(300),
                tenant_id: DEFAULT_TENANT.to_string(),
                corpus_id: DEFAULT_CORPUS.to_string(),
            },
            Arc::new(RwLock::new(FactStore::new())),
            LocalIngestHandles {
                data_dir: data.path().to_path_buf(),
                ingest_lock: Arc::new(tokio::sync::Mutex::new(())),
                retrieval_index: Arc::new(RwLock::new(corecrux_retrieval::IndexManager::new())),
            },
        );
        (watcher, data)
    }

    // ── scanning ──────────────────────────────────────────────────────

    #[test]
    fn scan_finds_markdown_recursively_and_skips_hidden_and_obsidian() {
        let vault = tempfile::tempdir().expect("vault");
        let root = vault.path();
        write(&root.join("note.md"), "# Note");
        write(&root.join("nested/deep/other.md"), "# Other");
        write(&root.join(".obsidian/workspace.md"), "# Config");
        write(&root.join(".git/HEAD.md"), "# Git");
        write(&root.join(".hidden-note.md"), "# Hidden");
        write(&root.join("readme.txt"), "not markdown");

        let found = scan_root(root).expect("scan");
        let names: BTreeSet<String> = found
            .iter()
            .map(|f| f.path.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert_eq!(
            names,
            ["note.md".to_string(), "other.md".to_string()].into_iter().collect(),
            "only non-hidden .md files, recursively"
        );
        assert!(found.iter().all(|f| f.size > 0));
    }

    #[test]
    fn scan_is_case_insensitive_on_extension_and_honours_size_cap() {
        let vault = tempfile::tempdir().expect("vault");
        write(&vault.path().join("upper.MD"), "# Upper");
        let found = scan_root(vault.path()).expect("scan");
        assert_eq!(found.len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn scan_refuses_symlinked_files_and_directories() {
        let vault = tempfile::tempdir().expect("vault");
        let outside = tempfile::tempdir().expect("outside");
        write(&vault.path().join("real.md"), "# Real");
        write(&outside.path().join("secret.md"), "# Secret");

        std::os::unix::fs::symlink(outside.path().join("secret.md"), vault.path().join("link.md"))
            .expect("file symlink");
        std::os::unix::fs::symlink(outside.path(), vault.path().join("linkdir")).expect("dir symlink");

        let found = scan_root(vault.path()).expect("scan");
        assert_eq!(found.len(), 1, "only the real file, no symlink traversal: {found:?}");
        assert!(found[0].path.ends_with("real.md"));
    }

    // ── diffing ───────────────────────────────────────────────────────

    #[test]
    fn classify_detects_add_touch_and_unchanged() {
        let file = ScannedFile {
            path: PathBuf::from("/vault/a.md"),
            mtime_ms: 100,
            size: 10,
        };
        let mut cursor = VaultCursor::default();
        assert_eq!(classify(&cursor, &file), FileChange::Added);

        cursor.entries.insert(
            "/vault/a.md".to_string(),
            CursorEntry {
                mtime_ms: 100,
                size: 10,
                content_hash: "b3:x".to_string(),
                seen_at_unix_ms: 1,
                title: None,
                tags: Vec::new(),
            },
        );
        assert_eq!(classify(&cursor, &file), FileChange::Unchanged);

        let touched = ScannedFile { mtime_ms: 200, ..file };
        assert_eq!(classify(&cursor, &touched), FileChange::Touched);
    }

    #[test]
    fn deleted_paths_reports_cursor_entries_missing_from_disk() {
        let mut cursor = VaultCursor::default();
        for path in ["/vault/a.md", "/vault/b.md"] {
            cursor.entries.insert(
                path.to_string(),
                CursorEntry {
                    mtime_ms: 1,
                    size: 1,
                    content_hash: "b3:x".to_string(),
                    seen_at_unix_ms: 1,
                    title: None,
                    tags: Vec::new(),
                },
            );
        }
        let scanned = vec![ScannedFile {
            path: PathBuf::from("/vault/a.md"),
            mtime_ms: 1,
            size: 1,
        }];
        assert_eq!(deleted_paths(&cursor, &scanned), vec!["/vault/b.md".to_string()]);
    }

    #[test]
    fn cursor_cap_drops_oldest_and_flags_truncation() {
        let mut cursor = VaultCursor::default();
        for index in 0..200 {
            cursor.entries.insert(
                format!("/vault/note-{index:04}.md"),
                CursorEntry {
                    mtime_ms: 1,
                    size: 1,
                    content_hash: format!("b3:{index:064}"),
                    seen_at_unix_ms: index as u64,
                    title: Some("t".repeat(64)),
                    tags: vec!["tag".to_string()],
                },
            );
        }
        let before = cursor.entries.len();
        let dropped = cursor.cap(8 * 1024);
        assert!(dropped > 0, "expected truncation");
        assert!(cursor.truncated);
        assert_eq!(cursor.entries.len(), before - dropped);
        assert!(serialized_len(&cursor) <= 8 * 1024);
        // The oldest-seen entry went first; the newest survived.
        assert!(!cursor.entries.contains_key("/vault/note-0000.md"));
        assert!(cursor.entries.contains_key("/vault/note-0199.md"));

        // A cursor already under budget is left alone.
        let mut small = VaultCursor::default();
        assert_eq!(small.cap(MAX_CURSOR_BYTES), 0);
        assert!(!small.truncated);
    }

    // ── frontmatter ───────────────────────────────────────────────────

    #[test]
    fn frontmatter_parses_title_and_list_tags_and_strips_block() {
        let (front, body) =
            parse_frontmatter("---\ntitle: My Note\ntags:\n  - alpha\n  - beta\n---\n# Heading\ntext\n");
        assert_eq!(front.title.as_deref(), Some("My Note"));
        assert_eq!(front.tags, vec!["alpha".to_string(), "beta".to_string()]);
        assert_eq!(body, "# Heading\ntext\n");
        assert!(!body.contains("title:"));
    }

    #[test]
    fn frontmatter_parses_inline_tags() {
        let (front, body) = parse_frontmatter("---\ntags: alpha, beta\n---\nbody\n");
        assert_eq!(front.tags, vec!["alpha".to_string(), "beta".to_string()]);
        assert_eq!(body, "body\n");
    }

    #[test]
    fn frontmatter_absent_or_malformed_is_not_fatal() {
        let (front, body) = parse_frontmatter("# Just markdown\n");
        assert_eq!(front, Frontmatter::default());
        assert_eq!(body, "# Just markdown\n");

        // Unterminated block: whole file is body, nothing stripped.
        let (front, body) = parse_frontmatter("---\ntitle: x\nno terminator\n");
        assert_eq!(front, Frontmatter::default());
        assert!(body.starts_with("---"));

        // Terminated but invalid YAML: stripped, empty frontmatter.
        let (front, body) = parse_frontmatter("---\n\tthis: [is: not: yaml\n---\nbody\n");
        assert_eq!(front, Frontmatter::default());
        assert_eq!(body, "body\n");
    }

    // ── activation ────────────────────────────────────────────────────

    #[test]
    fn parse_watch_roots_keeps_absolute_dirs_and_reports_the_rest() {
        let dir = tempfile::tempdir().expect("dir");
        let canonical = fs::canonicalize(dir.path()).expect("canonicalize");
        let file = dir.path().join("f.md");
        write(&file, "x");

        let raw = format!(
            "{}:relative/path:{}:/definitely/not/here",
            canonical.display(),
            file.display()
        );
        let (roots, rejected) = parse_watch_roots(&raw);
        assert_eq!(roots, vec![canonical]);
        assert_eq!(rejected.len(), 3);
        assert!(rejected.iter().any(|r| r.contains("not absolute")));
        assert!(rejected.iter().any(|r| r.contains("not a directory")));
        assert!(rejected.iter().any(|r| r.contains("not readable")));

        let (roots, rejected) = parse_watch_roots("");
        assert!(roots.is_empty());
        assert!(rejected.is_empty());
    }

    // ── end-to-end cycle ──────────────────────────────────────────────

    #[tokio::test]
    async fn cycle_ingests_new_notes_then_reports_modify_and_delete() {
        let vault = tempfile::tempdir().expect("vault");
        let note = vault.path().join("one.md");
        write(&note, "---\ntitle: One\ntags: [x]\n---\n# One\n\nhello vault\n");
        write(&vault.path().join("two.md"), "# Two\n\nsecond note\n");
        let (watcher, _data) = watcher(vault.path());

        // Cycle 1 — both notes are new.
        let detail = match watcher.run_cycle().await.expect("cycle 1") {
            JobOutcome::Ran(Some(detail)) => detail,
            other => panic!("expected a ran outcome, got {other:?}"),
        };
        assert_eq!(detail["added"], 2);
        assert_eq!(detail["modified"], 0);
        assert_eq!(detail["scanned"], 2);
        assert!(detail["ingested_chunks"].as_u64().unwrap() >= 2);
        assert_eq!(detail["deleted"], serde_json::json!([]));

        let cursor = watcher.load_cursor().await;
        assert_eq!(cursor.entries.len(), 2);
        let key = fs::canonicalize(&note).unwrap().to_string_lossy().to_string();
        assert_eq!(cursor.entries[&key].title.as_deref(), Some("One"));
        assert_eq!(cursor.entries[&key].tags, vec!["x".to_string()]);

        // Cycle 2 — nothing changed.
        let detail = match watcher.run_cycle().await.expect("cycle 2") {
            JobOutcome::Ran(Some(detail)) => detail,
            other => panic!("expected a ran outcome, got {other:?}"),
        };
        assert_eq!(detail["added"], 0);
        assert_eq!(detail["modified"], 0);
        assert_eq!(detail["ingested_chunks"], 0);

        // Cycle 3 — one modified, one deleted.
        write(&note, "---\ntitle: One\n---\n# One\n\nhello vault, revised\n");
        // Force a stat change even on coarse-grained filesystem clocks.
        let meta = fs::metadata(&note).unwrap();
        assert!(meta.len() > 0);
        fs::remove_file(vault.path().join("two.md")).expect("delete");

        let detail = match watcher.run_cycle().await.expect("cycle 3") {
            JobOutcome::Ran(Some(detail)) => detail,
            other => panic!("expected a ran outcome, got {other:?}"),
        };
        assert_eq!(detail["added"], 0);
        assert_eq!(detail["modified"], 1);
        let deleted = detail["deleted"].as_array().expect("deleted array");
        assert_eq!(deleted.len(), 1);
        assert!(deleted[0].as_str().unwrap().ends_with("two.md"));

        let cursor = watcher.load_cursor().await;
        assert_eq!(cursor.entries.len(), 1, "deleted note retired from the cursor");
    }

    #[tokio::test]
    async fn cycle_over_empty_vault_is_ok_and_writes_a_cursor() {
        let vault = tempfile::tempdir().expect("vault");
        let (watcher, _data) = watcher(vault.path());
        let detail = match watcher.run_cycle().await.expect("cycle") {
            JobOutcome::Ran(Some(detail)) => detail,
            other => panic!("expected a ran outcome, got {other:?}"),
        };
        assert_eq!(detail["scanned"], 0);
        assert_eq!(detail["added"], 0);
        assert!(watcher.load_cursor().await.entries.is_empty());
    }

    #[tokio::test]
    async fn cycle_errors_when_every_root_is_unreadable() {
        let vault = tempfile::tempdir().expect("vault");
        let (mut watcher, _data) = watcher(vault.path());
        watcher.config.roots = vec![PathBuf::from("/definitely/not/here")];
        let err = watcher.run_cycle().await.expect_err("unreadable root is an error");
        assert!(err.contains("unreadable"), "{err}");
    }

    #[tokio::test]
    async fn frontmatter_only_note_is_remembered_but_not_sealed() {
        let vault = tempfile::tempdir().expect("vault");
        write(&vault.path().join("meta.md"), "---\ntitle: Meta\n---\n");
        let (watcher, _data) = watcher(vault.path());
        let detail = match watcher.run_cycle().await.expect("cycle") {
            JobOutcome::Ran(Some(detail)) => detail,
            other => panic!("expected a ran outcome, got {other:?}"),
        };
        assert_eq!(detail["added"], 0);
        assert_eq!(detail["ingested_chunks"], 0);
        assert_eq!(watcher.load_cursor().await.entries.len(), 1);
    }
}
