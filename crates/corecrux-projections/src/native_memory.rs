// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Read-only projection over the harness-native memory store
//! (`~/.claude/projects/<project>/memory/*.md`).
//!
//! ExecPlan `crux-memory-parity-and-codex-bridge-2026-09-17` **M4**
//! ("native memory ingested (read-only)").
//!
//! ## What this is
//!
//! Claude Code keeps a curated memory set on disk: one markdown file per
//! memory, each with a small frontmatter block (`name`, `description`,
//! `metadata.type`, `metadata.modified`), a body that cross-references other
//! memories with `[[wikilinks]]`, and a sibling `MEMORY.md` index that groups
//! them under `##` headings. That set is what actually steers the harness, and
//! the daemon has been blind to it. This module parses it into fact-shaped
//! records so a session with no native store of its own — Codex, today — can
//! reach the same memory through the daemon.
//!
//! ## Read-only, by construction
//!
//! This module **never writes, moves, truncates or creates** anything under a
//! memory root. Every filesystem call here is [`std::fs::read_dir`],
//! [`std::fs::metadata`] or a [`std::fs::OpenOptions`] handle opened with
//! `.read(true)` and nothing else; there is no `write`/`create`/`truncate`/
//! `remove`/`rename` call in the file, and `cargo test -p corecrux-projections
//! native_memory` pins `(path, mtime, sha256)` for every file across a full
//! ingest. The directory is the operator's live memory store, loaded into the
//! first user message of every concurrent session: corrupting it is
//! unrecoverable, so the discipline is structural rather than conventional.
//!
//! ## What is stored, and what is not
//!
//! The workspace convention (`AGENTS.md` / `CLAUDE.md`, memory-practices) is
//! explicit: *do not migrate `MEMORY.md` wholesale into facts; link via
//! `value={memory_md_ref: "<slug>.md"}`*. So [`NativeMemoryEntryV1::fact_value`]
//! carries the `memory_md_ref` pointer, the one-line `description`, the index
//! grouping and the link graph — never the body. Bodies stay on disk and are
//! served on demand by [`read_memory_body`].
//!
//! ## Failure posture
//!
//! A malformed file degrades, it does not abort the projection: missing or
//! unparseable frontmatter, a missing `description`, CRLF line endings, non-UTF8
//! bytes and oversized files each produce a [`MemoryWarningV1`] and the rest of
//! the set still ingests. A `[[wikilink]]` with no matching file is a
//! [`DanglingEdgeV1`], recorded and reported, never fatal.
//!
//! ## Determinism
//!
//! Same discipline as the rest of the crate: entries live in a `BTreeMap`,
//! edges and warnings are sorted before they are returned, and
//! [`NativeMemoryIngestV1::set_hash`] is a blake3 over the sorted
//! `(slug, content_hash)` pairs — so two ingests of an unchanged directory are
//! byte-identical, which is what the digest work in M3 needs.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Projection identity, reported in every ingest envelope.
pub const NATIVE_MEMORY_PROJECTION_ID: &str = "native_memory/v1";

/// Environment variable naming the memory root(s). Unset = feature off.
///
/// Accepts a `:`-separated list. A leading `~/` expands to `$HOME`, and a
/// single `*` path segment expands over the directory's children — so the
/// documented default shape `~/.claude/projects/*/memory` covers every project
/// dir on the machine.
pub const NATIVE_MEMORY_ROOT_ENV: &str = "CORECRUXD_NATIVE_MEMORY_ROOT";

/// The index file inside a memory root. Parsed for its `##` groupings; never
/// ingested as a memory in its own right.
pub const NATIVE_MEMORY_INDEX_FILE: &str = "MEMORY.md";

/// Fact key under which a memory's pointer record is addressed.
pub const NATIVE_MEMORY_FACT_KEY: &str = "native_memory";

/// Entity prefix for a projected memory (`memory:<slug>`).
pub const NATIVE_MEMORY_ENTITY_PREFIX: &str = "memory:";

/// Provenance stamp on every projected fact value.
pub const NATIVE_MEMORY_SOURCE: &str = "claude-code-native-memory";

/// Placeholder substituted for a secret-shaped token.
pub const REDACTION_PLACEHOLDER: &str = "[redacted]";

/// Default per-file ceiling. A native memory is a page of prose; anything an
/// order of magnitude past the largest observed file (19 KiB) is not one, and
/// is skipped rather than slurped.
pub const DEFAULT_MAX_FILE_BYTES: u64 = 1_048_576;

/// Default ceiling on files considered per root.
pub const DEFAULT_MAX_FILES: usize = 4_096;

/// Knobs for one ingest pass. Defaults are the operator-store shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeMemoryIngestOptions {
    /// Skip (with a warning) any file larger than this.
    pub max_file_bytes: u64,
    /// Stop scanning a root after this many `*.md` files.
    pub max_files: usize,
    /// Replace secret-shaped tokens in descriptions, hooks and bodies.
    pub redact: bool,
}

impl Default for NativeMemoryIngestOptions {
    fn default() -> Self {
        Self {
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            max_files: DEFAULT_MAX_FILES,
            redact: true,
        }
    }
}

/// Why a file or link did not project cleanly. Never carries body text — a
/// memory body may quote a credential, so warnings carry positions and counts
/// only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryWarningKind {
    /// No `---` frontmatter block at the top of the file.
    MissingFrontmatter,
    /// A frontmatter block that opened but never closed, or an unparseable line.
    MalformedFrontmatter,
    /// Frontmatter parsed, but carried no `description:`.
    MissingDescription,
    /// `name:` in the frontmatter disagrees with the file stem.
    NameSlugMismatch,
    /// The file was not valid UTF-8; it was decoded lossily.
    NonUtf8Bytes,
    /// The file exceeded `max_file_bytes` and was skipped.
    Oversize,
    /// The file could not be opened or read.
    Unreadable,
    /// The slug collides with a reserved fact-entity prefix; skipped.
    ReservedSlug,
    /// The same slug appeared in two roots; the first root won.
    DuplicateSlug,
    /// A secret-shaped token was replaced before the text left this module.
    Redacted,
    /// A root path did not exist or was not a directory.
    RootUnreadable,
}

/// One degraded-but-not-fatal observation from an ingest.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct MemoryWarningV1 {
    /// What went wrong.
    pub kind: MemoryWarningKind,
    /// The file (or root) it happened in, as a root-relative name.
    pub file: String,
    /// Short, body-free explanation.
    pub detail: String,
}

/// Where a link was written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeOrigin {
    /// A `[[wikilink]]` in a memory body.
    Body,
    /// A `[title](slug.md)` link in `MEMORY.md`.
    Index,
}

/// A resolved memory-to-memory edge.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct MemoryEdgeV1 {
    /// Source slug (or `MEMORY.md` for index edges).
    pub from: String,
    /// Target slug, which exists in this ingest.
    pub to: String,
    /// Where the link was written.
    pub origin: EdgeOrigin,
}

/// A link whose target has no file in the ingested set. Reported, never fatal.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DanglingEdgeV1 {
    /// Source slug (or `MEMORY.md`).
    pub from: String,
    /// The slug that was linked to but not found.
    pub to: String,
    /// Where the link was written.
    pub origin: EdgeOrigin,
}

/// One `- [Title](file.md) — hook` row of `MEMORY.md`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryIndexEntryV1 {
    /// Link text.
    pub title: String,
    /// Link target, verbatim.
    pub target: String,
    /// Target reduced to a slug when it names a sibling `*.md`.
    pub slug: Option<String>,
    /// Trailing prose after the link (the recall hook).
    pub hook: String,
    /// Whether `slug` matched an ingested memory.
    pub resolved: bool,
}

/// One `##` section of `MEMORY.md`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryIndexSectionV1 {
    /// Heading text, verbatim.
    pub heading: String,
    /// Rows under the heading, in file order.
    pub entries: Vec<MemoryIndexEntryV1>,
}

/// A parsed `MEMORY.md`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryIndexV1 {
    /// Root the index belongs to.
    pub root: String,
    /// Index file name.
    pub file: String,
    /// Size on disk.
    pub bytes: u64,
    /// Sections in file order.
    pub sections: Vec<MemoryIndexSectionV1>,
}

/// One projected memory: everything except the body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeMemoryEntryV1 {
    /// File stem — the slug memories link to with `[[...]]`.
    pub slug: String,
    /// File name inside the root (`<slug>.md`).
    pub file_name: String,
    /// Absolute root directory this memory was read from.
    pub root: String,
    /// `name:` from the frontmatter, when present.
    pub name: Option<String>,
    /// `description:` from the frontmatter; empty when absent (warned).
    pub description: String,
    /// `metadata.type`, e.g. `project`.
    pub memory_type: Option<String>,
    /// `metadata.node_type`, e.g. `memory`.
    pub node_type: Option<String>,
    /// `metadata.modified`, verbatim (an RFC3339 string in practice).
    pub modified: Option<String>,
    /// `MEMORY.md` heading this memory is listed under, when it is listed.
    pub group: Option<String>,
    /// Link text used for it in `MEMORY.md`.
    pub index_title: Option<String>,
    /// Recall hook written beside it in `MEMORY.md`.
    pub index_hook: Option<String>,
    /// Outbound `[[wikilinks]]` that resolved to an ingested memory.
    pub links: Vec<String>,
    /// Outbound `[[wikilinks]]` with no matching file.
    pub dangling_links: Vec<String>,
    /// Memories that link to this one.
    pub backlinks: Vec<String>,
    /// File size on disk.
    pub bytes: u64,
    /// Body size after frontmatter and CRLF normalisation.
    pub body_bytes: u64,
    /// blake3 of the raw file bytes — the identity a later read is checked against.
    pub content_hash: String,
    /// Whether the projected text had a secret-shaped token replaced.
    pub redacted: bool,
    /// Whether the file needed lossy UTF-8 decoding.
    pub lossy: bool,
}

impl NativeMemoryEntryV1 {
    /// Fact entity for this memory (`memory:<slug>`).
    pub fn entity(&self) -> String {
        format!("{NATIVE_MEMORY_ENTITY_PREFIX}{}", self.slug)
    }

    /// The fact **value** for this memory.
    ///
    /// Per the workspace memory-practices rule, this is a pointer plus the
    /// recall metadata — `memory_md_ref`, the one-line description, the index
    /// grouping and the link graph. The body is deliberately absent; callers
    /// that want it call [`read_memory_body`].
    pub fn fact_value(&self) -> serde_json::Value {
        serde_json::json!({
            "memory_md_ref": self.file_name,
            "description": self.description,
            "name": self.name,
            "group": self.group,
            "type": self.memory_type,
            "node_type": self.node_type,
            "modified": self.modified,
            "index_title": self.index_title,
            "index_hook": self.index_hook,
            "links": self.links,
            "dangling_links": self.dangling_links,
            "backlinks": self.backlinks,
            "root": self.root,
            "bytes": self.bytes,
            "content_hash": self.content_hash,
            "redacted": self.redacted,
            "source": NATIVE_MEMORY_SOURCE,
            "projection": NATIVE_MEMORY_PROJECTION_ID,
            "read_only": true,
        })
    }
}

/// The result of one read-only pass over the configured roots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeMemoryIngestV1 {
    /// Projection identity.
    pub projection: String,
    /// Roots actually scanned, in the order given.
    pub roots: Vec<String>,
    /// `*.md` files seen, including each root's `MEMORY.md`.
    pub files_scanned: usize,
    /// Memories projected (`files_scanned` minus indexes and skips).
    pub memories: usize,
    /// Projected memories, keyed by slug.
    pub entries: BTreeMap<String, NativeMemoryEntryV1>,
    /// One parsed `MEMORY.md` per root that had one.
    pub indexes: Vec<MemoryIndexV1>,
    /// Slugs per `MEMORY.md` heading.
    pub groups: BTreeMap<String, Vec<String>>,
    /// Resolved edges, sorted.
    pub edges: Vec<MemoryEdgeV1>,
    /// Unresolved links, sorted. Non-fatal by contract.
    pub dangling: Vec<DanglingEdgeV1>,
    /// Degraded-file observations, sorted.
    pub warnings: Vec<MemoryWarningV1>,
    /// blake3 over the sorted `(slug, content_hash)` pairs.
    pub set_hash: String,
}

impl NativeMemoryIngestV1 {
    /// Look up one projected memory.
    pub fn get(&self, slug: &str) -> Option<&NativeMemoryEntryV1> {
        self.entries.get(slug)
    }

    /// Every memory as an `(entity, key, value)` fact triple, slug-ordered.
    pub fn fact_rows(&self) -> Vec<(String, &'static str, serde_json::Value)> {
        self.entries
            .values()
            .map(|entry| (entry.entity(), NATIVE_MEMORY_FACT_KEY, entry.fact_value()))
            .collect()
    }
}

/// A body read back from disk on demand.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryBodyV1 {
    /// The memory's slug.
    pub slug: String,
    /// Body markdown, frontmatter stripped and CRLF normalised.
    pub body: String,
    /// Body length in bytes.
    pub body_bytes: u64,
    /// blake3 of the raw file bytes at read time.
    pub content_hash: String,
    /// True when `content_hash` differs from the hash recorded at ingest —
    /// the file changed underneath the projection.
    pub changed_since_ingest: bool,
    /// Whether a secret-shaped token was replaced.
    pub redacted: bool,
    /// Whether the file needed lossy UTF-8 decoding.
    pub lossy: bool,
}

/// One description-text search hit.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemorySearchHitV1 {
    /// The matched memory's slug.
    pub slug: String,
    /// Its description.
    pub description: String,
    /// Its `MEMORY.md` grouping.
    pub group: Option<String>,
    /// Fraction of query terms found, 0.0–1.0.
    pub score: f32,
    /// Which query terms were found, sorted.
    pub matched_terms: Vec<String>,
}

/// Errors from the on-demand body read. The ingest pass itself is infallible:
/// it degrades to warnings.
#[derive(Debug, thiserror::Error)]
pub enum NativeMemoryError {
    /// No memory with that slug in the ingested set.
    #[error("unknown memory slug: {slug}")]
    UnknownSlug {
        /// The slug asked for.
        slug: String,
    },
    /// The slug was not a bare file stem, or escaped the root.
    #[error("invalid memory slug")]
    InvalidSlug,
    /// The file could not be read.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

// ── Root resolution ──────────────────────────────────────────────────────────

/// Expand a `CORECRUXD_NATIVE_MEMORY_ROOT` spec into concrete directories.
///
/// `:`-separated entries; `~/` expands against `home`; one `*` segment expands
/// over that directory's children (sorted, directories only). Entries that do
/// not resolve are dropped — the caller reports them as `RootUnreadable`.
pub fn resolve_roots(spec: &str, home: Option<&Path>) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let mut seen: BTreeSet<PathBuf> = BTreeSet::new();
    for raw in spec.split(':') {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        let expanded = expand_home(trimmed, home);
        for candidate in expand_glob(&expanded) {
            if candidate.is_dir() && seen.insert(candidate.clone()) {
                out.push(candidate);
            }
        }
    }
    out
}

fn expand_home(raw: &str, home: Option<&Path>) -> PathBuf {
    match (raw.strip_prefix("~/"), home) {
        (Some(rest), Some(home)) => home.join(rest),
        _ => PathBuf::from(raw),
    }
}

/// Expand at most one `*` path segment. Anything else is returned as-is.
fn expand_glob(path: &Path) -> Vec<PathBuf> {
    let components: Vec<_> = path.components().collect();
    let Some(star_at) = components.iter().position(|c| c.as_os_str().to_string_lossy() == "*") else {
        return vec![path.to_path_buf()];
    };
    let mut prefix = PathBuf::new();
    for component in &components[..star_at] {
        prefix.push(component.as_os_str());
    }
    let mut suffix = PathBuf::new();
    for component in &components[star_at + 1..] {
        suffix.push(component.as_os_str());
    }
    let Ok(dir) = std::fs::read_dir(&prefix) else {
        return Vec::new();
    };
    let mut children: Vec<PathBuf> = dir
        .filter_map(std::result::Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    children.sort();
    children
        .into_iter()
        .map(|child| {
            if suffix.as_os_str().is_empty() {
                child
            } else {
                child.join(&suffix)
            }
        })
        .collect()
}

// ── Ingest ───────────────────────────────────────────────────────────────────

/// Walk `roots` and project every `*.md` into a [`NativeMemoryIngestV1`].
///
/// Read-only: the only filesystem calls reached from here are `read_dir`,
/// `metadata` and read-mode `OpenOptions`. Infallible by design — an unreadable
/// root, an oversized file or a broken frontmatter block each become a
/// [`MemoryWarningV1`] and the pass continues.
pub fn ingest_native_memory(roots: &[PathBuf], options: NativeMemoryIngestOptions) -> NativeMemoryIngestV1 {
    let mut entries: BTreeMap<String, NativeMemoryEntryV1> = BTreeMap::new();
    let mut warnings: Vec<MemoryWarningV1> = Vec::new();
    let mut indexes: Vec<MemoryIndexV1> = Vec::new();
    let mut files_scanned = 0usize;
    // Slug -> raw wikilink targets, kept until every root is read so a
    // cross-root link still resolves.
    let mut raw_links: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for root in roots {
        let files = match list_markdown_files(root, options.max_files) {
            Ok(files) => files,
            Err(err) => {
                warnings.push(MemoryWarningV1 {
                    kind: MemoryWarningKind::RootUnreadable,
                    file: root.display().to_string(),
                    detail: err.kind().to_string(),
                });
                continue;
            }
        };
        let root_display = root.display().to_string();
        for path in files {
            files_scanned += 1;
            let file_name = file_name_of(&path);
            let raw = match read_file_bytes(&path, options.max_file_bytes) {
                Ok(raw) => raw,
                Err(ReadSkip::Oversize { bytes }) => {
                    warnings.push(MemoryWarningV1 {
                        kind: MemoryWarningKind::Oversize,
                        file: file_name,
                        detail: format!("{bytes} bytes exceeds max_file_bytes={}", options.max_file_bytes),
                    });
                    continue;
                }
                Err(ReadSkip::Io(kind)) => {
                    warnings.push(MemoryWarningV1 {
                        kind: MemoryWarningKind::Unreadable,
                        file: file_name,
                        detail: kind.to_string(),
                    });
                    continue;
                }
            };

            let content_hash = blake3::hash(&raw.bytes).to_hex().to_string();
            let (text, lossy) = decode_lossy(&raw.bytes);
            if lossy {
                warnings.push(MemoryWarningV1 {
                    kind: MemoryWarningKind::NonUtf8Bytes,
                    file: file_name.clone(),
                    detail: "decoded with U+FFFD replacements".to_string(),
                });
            }
            let text = normalise_newlines(&text);

            if file_name == NATIVE_MEMORY_INDEX_FILE {
                indexes.push(parse_memory_index(
                    &root_display,
                    &file_name,
                    raw.bytes.len() as u64,
                    &text,
                ));
                continue;
            }

            let Some(slug) = slug_of(&path) else {
                warnings.push(MemoryWarningV1 {
                    kind: MemoryWarningKind::ReservedSlug,
                    file: file_name,
                    detail: "file stem is empty or not addressable".to_string(),
                });
                continue;
            };
            if is_reserved_slug(&slug) {
                warnings.push(MemoryWarningV1 {
                    kind: MemoryWarningKind::ReservedSlug,
                    file: file_name,
                    detail: "slug collides with a reserved fact-entity prefix".to_string(),
                });
                continue;
            }
            if let Some(existing) = entries.get(&slug) {
                warnings.push(MemoryWarningV1 {
                    kind: MemoryWarningKind::DuplicateSlug,
                    file: file_name,
                    detail: format!("already projected from {}", existing.root),
                });
                continue;
            }

            let parsed = parse_frontmatter(&text);
            for kind in &parsed.warnings {
                warnings.push(MemoryWarningV1 {
                    kind: *kind,
                    file: file_name.clone(),
                    detail: frontmatter_detail(*kind),
                });
            }
            if let Some(name) = parsed.name.as_deref() {
                if name != slug {
                    warnings.push(MemoryWarningV1 {
                        kind: MemoryWarningKind::NameSlugMismatch,
                        file: file_name.clone(),
                        detail: format!("frontmatter name {name:?} != file stem {slug:?}"),
                    });
                }
            }

            let (description, desc_redacted) = maybe_redact(&parsed.description, options.redact);
            if desc_redacted {
                warnings.push(MemoryWarningV1 {
                    kind: MemoryWarningKind::Redacted,
                    file: file_name.clone(),
                    detail: "secret-shaped token replaced in description".to_string(),
                });
            }

            raw_links.insert(slug.clone(), extract_wikilinks(&parsed.body));

            entries.insert(
                slug.clone(),
                NativeMemoryEntryV1 {
                    slug,
                    file_name,
                    root: root_display.clone(),
                    name: parsed.name,
                    description,
                    memory_type: parsed.memory_type,
                    node_type: parsed.node_type,
                    modified: parsed.modified,
                    group: None,
                    index_title: None,
                    index_hook: None,
                    links: Vec::new(),
                    dangling_links: Vec::new(),
                    backlinks: Vec::new(),
                    bytes: raw.bytes.len() as u64,
                    body_bytes: parsed.body.len() as u64,
                    content_hash,
                    redacted: desc_redacted,
                    lossy,
                },
            );
        }
    }

    // ── Link graph. A link whose target has no file is dangling, not fatal. ──
    let known: BTreeSet<String> = entries.keys().cloned().collect();
    let mut edges: Vec<MemoryEdgeV1> = Vec::new();
    let mut dangling: Vec<DanglingEdgeV1> = Vec::new();
    let mut backlinks: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (from, targets) in &raw_links {
        let mut resolved: BTreeSet<String> = BTreeSet::new();
        let mut broken: BTreeSet<String> = BTreeSet::new();
        for target in targets {
            if target == from {
                continue;
            }
            if known.contains(target) {
                resolved.insert(target.clone());
                backlinks.entry(target.clone()).or_default().insert(from.clone());
            } else {
                broken.insert(target.clone());
            }
        }
        for to in &resolved {
            edges.push(MemoryEdgeV1 {
                from: from.clone(),
                to: to.clone(),
                origin: EdgeOrigin::Body,
            });
        }
        for to in &broken {
            dangling.push(DanglingEdgeV1 {
                from: from.clone(),
                to: to.clone(),
                origin: EdgeOrigin::Body,
            });
        }
        if let Some(entry) = entries.get_mut(from) {
            entry.links = resolved.into_iter().collect();
            entry.dangling_links = broken.into_iter().collect();
        }
    }
    for (slug, from_set) in backlinks {
        if let Some(entry) = entries.get_mut(&slug) {
            entry.backlinks = from_set.into_iter().collect();
        }
    }

    // ── Index groupings + index edges. ──
    let mut groups: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for index in &mut indexes {
        for section in &mut index.sections {
            for row in &mut section.entries {
                let Some(slug) = row.slug.clone() else { continue };
                row.resolved = known.contains(&slug);
                if row.resolved {
                    edges.push(MemoryEdgeV1 {
                        from: NATIVE_MEMORY_INDEX_FILE.to_string(),
                        to: slug.clone(),
                        origin: EdgeOrigin::Index,
                    });
                    groups.entry(section.heading.clone()).or_default().push(slug.clone());
                    if let Some(entry) = entries.get_mut(&slug) {
                        entry.group = Some(section.heading.clone());
                        entry.index_title = Some(row.title.clone());
                        let (hook, hook_redacted) = maybe_redact(&row.hook, options.redact);
                        entry.index_hook = Some(hook.clone());
                        row.hook = hook;
                        entry.redacted |= hook_redacted;
                    }
                } else {
                    dangling.push(DanglingEdgeV1 {
                        from: NATIVE_MEMORY_INDEX_FILE.to_string(),
                        to: slug,
                        origin: EdgeOrigin::Index,
                    });
                }
            }
        }
    }
    for slugs in groups.values_mut() {
        slugs.sort();
        slugs.dedup();
    }

    edges.sort();
    edges.dedup();
    dangling.sort();
    dangling.dedup();
    warnings.sort();
    warnings.dedup();

    let set_hash = compute_set_hash(&entries);
    let memories = entries.len();
    NativeMemoryIngestV1 {
        projection: NATIVE_MEMORY_PROJECTION_ID.to_string(),
        roots: roots.iter().map(|r| r.display().to_string()).collect(),
        files_scanned,
        memories,
        entries,
        indexes,
        groups,
        edges,
        dangling,
        warnings,
        set_hash,
    }
}

/// Read one memory's body from disk, on demand.
///
/// Opened read-only, like everything else here. The returned
/// `changed_since_ingest` flag compares the file's current blake3 with the hash
/// recorded at ingest, so a caller can tell a stale projection from a fresh one
/// without the projection ever writing anything down.
pub fn read_memory_body(
    ingest: &NativeMemoryIngestV1,
    slug: &str,
    options: NativeMemoryIngestOptions,
) -> std::result::Result<MemoryBodyV1, NativeMemoryError> {
    if !is_safe_slug(slug) {
        return Err(NativeMemoryError::InvalidSlug);
    }
    let entry = ingest
        .get(slug)
        .ok_or_else(|| NativeMemoryError::UnknownSlug { slug: slug.to_string() })?;
    let path = Path::new(&entry.root).join(&entry.file_name);
    let raw = match read_file_bytes(&path, options.max_file_bytes) {
        Ok(raw) => raw,
        Err(ReadSkip::Oversize { bytes }) => {
            return Err(NativeMemoryError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("memory body is {bytes} bytes, over the configured ceiling"),
            )))
        }
        Err(ReadSkip::Io(kind)) => return Err(NativeMemoryError::Io(std::io::Error::from(kind))),
    };
    let content_hash = blake3::hash(&raw.bytes).to_hex().to_string();
    let (text, lossy) = decode_lossy(&raw.bytes);
    let text = normalise_newlines(&text);
    let parsed = parse_frontmatter(&text);
    let (body, redacted) = maybe_redact(&parsed.body, options.redact);
    Ok(MemoryBodyV1 {
        slug: slug.to_string(),
        body_bytes: body.len() as u64,
        changed_since_ingest: content_hash != entry.content_hash,
        content_hash,
        body,
        redacted,
        lossy,
    })
}

/// Search projected memories by description text.
///
/// Scores as the fraction of query terms appearing in the memory's recall
/// surface (slug, name, description, index title, index hook, group). A memory
/// scoring below `floor` is not returned and there is **no recency fallback** —
/// an empty result means no match, which is the honesty rule M1 sets for the
/// retrieval path generally.
pub fn search_memories(ingest: &NativeMemoryIngestV1, query: &str, floor: f32, limit: usize) -> Vec<MemorySearchHitV1> {
    let terms = query_terms(query);
    if terms.is_empty() || limit == 0 {
        return Vec::new();
    }
    let mut hits: Vec<MemorySearchHitV1> = Vec::new();
    for entry in ingest.entries.values() {
        let mut haystack = String::with_capacity(256);
        haystack.push_str(&entry.slug);
        haystack.push(' ');
        haystack.push_str(&entry.description);
        for extra in [
            entry.name.as_deref(),
            entry.index_title.as_deref(),
            entry.index_hook.as_deref(),
            entry.group.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            haystack.push(' ');
            haystack.push_str(extra);
        }
        let haystack = haystack.to_lowercase();
        let matched: Vec<String> = terms
            .iter()
            .filter(|t| haystack.contains(t.as_str()))
            .cloned()
            .collect();
        if matched.is_empty() {
            continue;
        }
        let score = matched.len() as f32 / terms.len() as f32;
        if score < floor {
            continue;
        }
        hits.push(MemorySearchHitV1 {
            slug: entry.slug.clone(),
            description: entry.description.clone(),
            group: entry.group.clone(),
            score,
            matched_terms: matched,
        });
    }
    hits.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.slug.cmp(&b.slug))
    });
    hits.truncate(limit);
    hits
}

// ── Parsing helpers ──────────────────────────────────────────────────────────

#[derive(Debug, Default)]
struct ParsedMemory {
    name: Option<String>,
    description: String,
    memory_type: Option<String>,
    node_type: Option<String>,
    modified: Option<String>,
    body: String,
    warnings: Vec<MemoryWarningKind>,
}

fn frontmatter_detail(kind: MemoryWarningKind) -> String {
    match kind {
        MemoryWarningKind::MissingFrontmatter => "no leading `---` block".to_string(),
        MemoryWarningKind::MalformedFrontmatter => "frontmatter block never closed".to_string(),
        MemoryWarningKind::MissingDescription => "no `description:` key".to_string(),
        other => format!("{other:?}"),
    }
}

/// Parse the YAML-ish frontmatter block. Deliberately not a YAML parser: the
/// harness writes a flat `key: value` block with one nested `metadata:` map, and
/// a full YAML dependency would accept shapes the harness never emits while
/// still failing on the ones it does.
fn parse_frontmatter(text: &str) -> ParsedMemory {
    let mut parsed = ParsedMemory::default();
    let Some(rest) = text.strip_prefix("---\n") else {
        parsed.warnings.push(MemoryWarningKind::MissingFrontmatter);
        parsed.warnings.push(MemoryWarningKind::MissingDescription);
        parsed.body = text.trim_start().to_string();
        return parsed;
    };
    let Some(end) = find_frontmatter_end(rest) else {
        parsed.warnings.push(MemoryWarningKind::MalformedFrontmatter);
        parsed.warnings.push(MemoryWarningKind::MissingDescription);
        parsed.body = rest.trim_start().to_string();
        return parsed;
    };
    let (block, after) = rest.split_at(end);
    parsed.body = after
        .trim_start_matches("---\n")
        .trim_start_matches("---")
        .trim_start_matches('\n')
        .to_string();

    let mut in_metadata = false;
    for line in block.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let indented = line.starts_with(' ') || line.starts_with('\t');
        let Some((key, value)) = split_key_value(line) else {
            parsed.warnings.push(MemoryWarningKind::MalformedFrontmatter);
            continue;
        };
        if !indented {
            in_metadata = key == "metadata";
            match key.as_str() {
                "name" => parsed.name = non_empty(&value),
                "description" => parsed.description = value,
                _ => {}
            }
            continue;
        }
        if !in_metadata {
            continue;
        }
        match key.as_str() {
            "type" => parsed.memory_type = non_empty(&value),
            "node_type" => parsed.node_type = non_empty(&value),
            "modified" => parsed.modified = non_empty(&value),
            _ => {}
        }
    }
    if parsed.description.trim().is_empty() {
        parsed.warnings.push(MemoryWarningKind::MissingDescription);
    }
    parsed.description = parsed.description.trim().to_string();
    parsed
}

/// Byte offset of the closing `---` line inside a frontmatter block.
fn find_frontmatter_end(rest: &str) -> Option<usize> {
    let mut offset = 0usize;
    for line in rest.split_inclusive('\n') {
        if line.trim_end() == "---" {
            return Some(offset);
        }
        offset += line.len();
    }
    None
}

fn split_key_value(line: &str) -> Option<(String, String)> {
    let trimmed = line.trim();
    if trimmed.starts_with('#') {
        return None;
    }
    let (key, value) = trimmed.split_once(':')?;
    let key = key.trim();
    if key.is_empty() || key.contains(' ') {
        return None;
    }
    Some((key.to_string(), unquote(value.trim()).to_string()))
}

fn unquote(value: &str) -> &str {
    let bytes = value.as_bytes();
    if bytes.len() >= 2 && (bytes[0] == b'"' || bytes[0] == b'\'') && bytes[bytes.len() - 1] == bytes[0] {
        &value[1..value.len() - 1]
    } else {
        value
    }
}

fn non_empty(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Collect `[[target]]` link targets, in first-seen order, deduped.
/// `[[target|alias]]` and `[[target.md]]` both reduce to `target`.
fn extract_wikilinks(body: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let bytes = body.as_bytes();
    let mut i = 0usize;
    while i + 3 < bytes.len() {
        if bytes[i] != b'[' || bytes[i + 1] != b'[' {
            i += 1;
            continue;
        }
        let Some(close) = body[i + 2..].find("]]") else { break };
        let inner = &body[i + 2..i + 2 + close];
        i += 2 + close + 2;
        if inner.contains('\n') || inner.contains('[') {
            continue;
        }
        let target = inner.split('|').next().unwrap_or(inner).trim();
        let target = target.strip_suffix(".md").unwrap_or(target).trim();
        if target.is_empty() || !is_safe_slug(target) {
            continue;
        }
        if seen.insert(target.to_string()) {
            out.push(target.to_string());
        }
    }
    out
}

/// Parse `MEMORY.md` into `##` sections of `- [Title](target) — hook` rows.
fn parse_memory_index(root: &str, file: &str, bytes: u64, text: &str) -> MemoryIndexV1 {
    let mut sections: Vec<MemoryIndexSectionV1> = Vec::new();
    let mut current: Option<MemoryIndexSectionV1> = None;
    for line in text.lines() {
        if let Some(heading) = line.strip_prefix("## ") {
            if let Some(section) = current.take() {
                sections.push(section);
            }
            current = Some(MemoryIndexSectionV1 {
                heading: heading.trim().to_string(),
                entries: Vec::new(),
            });
            continue;
        }
        let trimmed = line.trim_start();
        let Some(row) = trimmed.strip_prefix("- ") else {
            continue;
        };
        let Some(entry) = parse_index_row(row) else { continue };
        let section = current.get_or_insert_with(|| MemoryIndexSectionV1 {
            heading: String::new(),
            entries: Vec::new(),
        });
        section.entries.push(entry);
    }
    if let Some(section) = current.take() {
        sections.push(section);
    }
    MemoryIndexV1 {
        root: root.to_string(),
        file: file.to_string(),
        bytes,
        sections,
    }
}

fn parse_index_row(row: &str) -> Option<MemoryIndexEntryV1> {
    let open = row.find('[')?;
    let close = row[open..].find("](")? + open;
    let end = row[close..].find(')')? + close;
    let title = row[open + 1..close].to_string();
    let target = row[close + 2..end].to_string();
    let hook = row[end + 1..]
        .trim_start_matches([' ', '—', '-', ':', '\u{2014}'])
        .trim()
        .to_string();
    // Only a sibling `<slug>.md` is a memory reference; an absolute path or an
    // external link is kept verbatim with `slug: None`.
    let slug = target
        .strip_suffix(".md")
        .filter(|s| is_safe_slug(s))
        .map(std::string::ToString::to_string);
    Some(MemoryIndexEntryV1 {
        title,
        target,
        slug,
        hook,
        resolved: false,
    })
}

fn query_terms(query: &str) -> Vec<String> {
    let mut terms: Vec<String> = query
        .to_lowercase()
        .split(|c: char| !c.is_alphanumeric() && c != '-' && c != '_')
        .map(str::trim)
        .filter(|t| t.len() >= 2)
        .map(std::string::ToString::to_string)
        .collect();
    terms.sort();
    terms.dedup();
    terms
}

// ── Redaction ────────────────────────────────────────────────────────────────

/// Prefixes that identify a credential by shape alone.
const SECRET_PREFIXES: &[&str] = &[
    "sk-ant-",
    "sk-",
    "ghp_",
    "gho_",
    "ghs_",
    "ghu_",
    "ghr_",
    "github_pat_",
    "xoxb-",
    "xoxp-",
    "xoxa-",
    "hvs.",
    "hvb.",
    "AKIA",
    "ASIA",
    "AIza",
    "base64:",
    "glpat-",
    "npm_",
    "dop_v1_",
    "SG.",
];

/// Keys whose right-hand side is a credential value.
const SECRET_ASSIGN_KEYS: &[&str] = &[
    "token",
    "secret",
    "password",
    "passwd",
    "apikey",
    "api_key",
    "authkey",
    "auth_token",
    "access_token",
    "client_secret",
    "private_key",
];

/// Replace secret-shaped tokens with [`REDACTION_PLACEHOLDER`].
///
/// Conservative on purpose: known credential prefixes, JWT-shaped triples and
/// `key=value` assignments whose key names a credential. It deliberately does
/// **not** redact bare 40-char hex, because the workspace's memories are full of
/// commit SHAs and redacting those would gut the content this projection exists
/// to serve.
pub fn redact_secret_shaped(text: &str) -> (String, bool) {
    if text.is_empty() {
        return (String::new(), false);
    }
    let mut out = String::with_capacity(text.len());
    let mut redacted = false;
    let mut rest = text;
    while !rest.is_empty() {
        let split = rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len());
        let (token, tail) = rest.split_at(split);
        if token.is_empty() {
            let ws = tail.find(|c: char| !c.is_whitespace()).unwrap_or(tail.len());
            out.push_str(&tail[..ws]);
            rest = &tail[ws..];
            continue;
        }
        match redact_token(token) {
            Some(replacement) => {
                out.push_str(&replacement);
                redacted = true;
            }
            None => out.push_str(token),
        }
        rest = tail;
    }
    (out, redacted)
}

fn redact_token(token: &str) -> Option<String> {
    let core = token.trim_matches(|c: char| !c.is_alphanumeric() && c != '_' && c != '-' && c != '.' && c != ':');
    if core.len() < 8 {
        return None;
    }
    if let Some((key, value)) = core.split_once('=') {
        let key_norm = key.trim().to_lowercase().replace('-', "_");
        if SECRET_ASSIGN_KEYS.contains(&key_norm.as_str()) && value.trim().len() >= 6 {
            return Some(format!("{key}={REDACTION_PLACEHOLDER}"));
        }
    }
    // A credential is a solid run of credential characters. Prose that merely
    // *names* a prefix — "the secret is `base64:`-prefixed" — is not one, and
    // redacting it would eat the sentence that makes the memory useful.
    if !core
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':' | '+' | '/' | '='))
    {
        return None;
    }
    // The prefix identifies the issuer; the credential body has to actually be
    // there, so require at least 12 characters after it.
    if SECRET_PREFIXES
        .iter()
        .any(|p| core.starts_with(p) && core.len() >= p.len() + 12)
    {
        return Some(REDACTION_PLACEHOLDER.to_string());
    }
    if is_jwt_shaped(core) {
        return Some(REDACTION_PLACEHOLDER.to_string());
    }
    None
}

fn is_jwt_shaped(token: &str) -> bool {
    let parts: Vec<&str> = token.split('.').collect();
    parts.len() == 3
        && token.len() >= 40
        && parts
            .iter()
            .all(|p| p.len() >= 8 && p.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'))
        && parts[0].starts_with("ey")
}

fn maybe_redact(text: &str, redact: bool) -> (String, bool) {
    if redact {
        redact_secret_shaped(text)
    } else {
        (text.to_string(), false)
    }
}

// ── Filesystem helpers (read-only) ───────────────────────────────────────────

struct RawFile {
    bytes: Vec<u8>,
}

enum ReadSkip {
    Oversize { bytes: u64 },
    Io(std::io::ErrorKind),
}

/// Open read-only and slurp. `OpenOptions` is spelled out rather than using
/// `fs::read` so the read-only intent of this module is visible at the call
/// site: `.read(true)` and nothing else, ever.
fn read_file_bytes(path: &Path, max_bytes: u64) -> std::result::Result<RawFile, ReadSkip> {
    let metadata = std::fs::metadata(path).map_err(|e| ReadSkip::Io(e.kind()))?;
    if metadata.len() > max_bytes {
        return Err(ReadSkip::Oversize { bytes: metadata.len() });
    }
    let mut file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|e| ReadSkip::Io(e.kind()))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes).map_err(|e| ReadSkip::Io(e.kind()))?;
    Ok(RawFile { bytes })
}

/// Sorted `*.md` files directly under `root`. Not recursive: the native store
/// is flat, and recursing would pull in whatever else lives beside it.
fn list_markdown_files(root: &Path, max_files: usize) -> std::io::Result<Vec<PathBuf>> {
    let mut files: Vec<PathBuf> = Vec::new();
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("md") {
            continue;
        }
        files.push(path);
        if files.len() >= max_files {
            break;
        }
    }
    files.sort();
    Ok(files)
}

fn file_name_of(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn slug_of(path: &Path) -> Option<String> {
    let stem = path.file_stem()?.to_string_lossy().into_owned();
    if stem.is_empty() || !is_safe_slug(&stem) {
        return None;
    }
    Some(stem)
}

/// A slug must be a bare file stem: no separators, no traversal, no leading dot.
fn is_safe_slug(slug: &str) -> bool {
    !slug.is_empty()
        && slug.len() <= 200
        && !slug.starts_with('.')
        && slug
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        && !slug.contains("..")
}

/// Reserved fact-entity namespaces (`__engram__::`, `__ops__::`, …) are
/// double-underscore prefixed. A memory file must never be able to address one.
fn is_reserved_slug(slug: &str) -> bool {
    slug.starts_with("__")
}

fn decode_lossy(bytes: &[u8]) -> (String, bool) {
    match std::str::from_utf8(bytes) {
        Ok(text) => (text.to_string(), false),
        Err(_) => (String::from_utf8_lossy(bytes).into_owned(), true),
    }
}

fn normalise_newlines(text: &str) -> String {
    if text.contains('\r') {
        text.replace("\r\n", "\n").replace('\r', "\n")
    } else {
        text.to_string()
    }
}

fn compute_set_hash(entries: &BTreeMap<String, NativeMemoryEntryV1>) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(NATIVE_MEMORY_PROJECTION_ID.as_bytes());
    for (slug, entry) in entries {
        hasher.update(b"\x00");
        hasher.update(slug.as_bytes());
        hasher.update(b"\x01");
        hasher.update(entry.content_hash.as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "---\nname: alpha\ndescription: Alpha does a thing\nmetadata: \n  node_type: memory\n  type: project\n  modified: 2026-08-11T13:46:55.903Z\n---\n\nBody with [[beta]] and [[ghost]].\n";

    #[test]
    fn parses_frontmatter_and_body() {
        let parsed = parse_frontmatter(SAMPLE);
        assert_eq!(parsed.name.as_deref(), Some("alpha"));
        assert_eq!(parsed.description, "Alpha does a thing");
        assert_eq!(parsed.memory_type.as_deref(), Some("project"));
        assert_eq!(parsed.node_type.as_deref(), Some("memory"));
        assert_eq!(parsed.modified.as_deref(), Some("2026-08-11T13:46:55.903Z"));
        assert!(parsed.body.starts_with("Body with"));
        assert!(parsed.warnings.is_empty());
    }

    #[test]
    fn missing_frontmatter_warns_but_keeps_body() {
        let parsed = parse_frontmatter("just prose\n");
        assert!(parsed.warnings.contains(&MemoryWarningKind::MissingFrontmatter));
        assert!(parsed.warnings.contains(&MemoryWarningKind::MissingDescription));
        assert_eq!(parsed.body.trim(), "just prose");
    }

    #[test]
    fn unclosed_frontmatter_is_malformed_not_fatal() {
        let parsed = parse_frontmatter("---\nname: x\nbody text\n");
        assert!(parsed.warnings.contains(&MemoryWarningKind::MalformedFrontmatter));
    }

    #[test]
    fn crlf_is_normalised_before_parsing() {
        let crlf = SAMPLE.replace('\n', "\r\n");
        let parsed = parse_frontmatter(&normalise_newlines(&crlf));
        assert_eq!(parsed.description, "Alpha does a thing");
    }

    #[test]
    fn wikilinks_dedupe_and_drop_aliases() {
        let links = extract_wikilinks("see [[beta]] and [[beta|Beta]] and [[gamma.md]]");
        assert_eq!(links, vec!["beta".to_string(), "gamma".to_string()]);
    }

    #[test]
    fn index_rows_split_title_target_and_hook() {
        let Some(row) = parse_index_row("[Title here](slug-one.md) — the recall hook") else {
            unreachable!("index row parses")
        };
        assert_eq!(row.title, "Title here");
        assert_eq!(row.target, "slug-one.md");
        assert_eq!(row.slug.as_deref(), Some("slug-one"));
        assert_eq!(row.hook, "the recall hook");
    }

    #[test]
    fn redaction_hits_credentials_and_spares_shas() {
        let (out, hit) = redact_secret_shaped("token is sk-ant-api03-AAAABBBBCCCCDDDD now");
        assert!(hit);
        assert!(out.contains(REDACTION_PLACEHOLDER));
        let (out, hit) = redact_secret_shaped("fixed in a413ce6f and 20ae0539abcdef0123456789abcdef0123456789");
        assert!(!hit);
        assert!(out.contains("a413ce6f"));
    }

    /// Prose that *names* a credential prefix is not a credential. Observed on
    /// the operator's real store: "the secret is `base64:`-prefixed when
    /// re-minting" was being swallowed whole by a prefix-only rule.
    #[test]
    fn redaction_spares_prose_that_only_names_a_prefix() {
        let (out, hit) = redact_secret_shaped("the secret is `base64:`-prefixed when re-minting");
        assert!(!hit, "prose mentioning a prefix must survive: {out}");
        assert!(out.contains("base64:"));
        let (out, hit) = redact_secret_shaped("set CRUX_ADMIN_JWT to the base64:QUJDREVGR0hJSktMTU5PUA value");
        assert!(hit);
        assert!(out.contains(REDACTION_PLACEHOLDER));
    }

    #[test]
    fn reserved_and_unsafe_slugs_are_rejected() {
        assert!(is_reserved_slug("__engram__"));
        assert!(!is_safe_slug("../escape"));
        assert!(!is_safe_slug("a/b"));
        assert!(is_safe_slug("crux-two-planes"));
    }

    #[test]
    fn glob_expansion_returns_the_literal_path_when_no_star() {
        let expanded = expand_glob(Path::new("/tmp/memory"));
        assert_eq!(expanded, vec![PathBuf::from("/tmp/memory")]);
    }
}
