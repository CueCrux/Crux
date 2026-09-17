// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Gate tests for the read-only native-memory projection.
//!
//! ExecPlan `crux-memory-parity-and-codex-bridge-2026-09-17` M4.
//!
//! The load-bearing one is [`ingest_writes_nothing_to_the_memory_root`]: it
//! snapshots `(path, mtime, sha256)` for every file under the fixture roots,
//! runs a full ingest plus a body read plus a search, and asserts the snapshot
//! is identical afterwards. The real directory this projection is pointed at is
//! the operator's live memory store; a write there is unrecoverable, so the
//! no-write property is pinned rather than assumed.
//!
//! Fixtures are invented representative files under `tests/fixtures/native-memory/`.
//! The operator's real memory directory is never read by a test.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use corecrux_projections::native_memory::{
    ingest_native_memory, read_memory_body, redact_secret_shaped, resolve_roots, search_memories, EdgeOrigin,
    MemoryWarningKind, NativeMemoryIngestOptions, NativeMemoryIngestV1, NATIVE_MEMORY_ENTITY_PREFIX,
    NATIVE_MEMORY_FACT_KEY, NATIVE_MEMORY_PROJECTION_ID, REDACTION_PLACEHOLDER,
};
use sha2::{Digest, Sha256};

fn fixture_root(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/native-memory")
        .join(name)
}

fn alpha_only() -> Vec<PathBuf> {
    vec![fixture_root("project-alpha")]
}

fn both_roots() -> Vec<PathBuf> {
    vec![fixture_root("project-alpha"), fixture_root("project-beta")]
}

fn ingest_alpha() -> NativeMemoryIngestV1 {
    ingest_native_memory(&alpha_only(), NativeMemoryIngestOptions::default())
}

/// `(relative path, mtime, sha256)` for every file under `roots`, sorted.
fn snapshot(roots: &[PathBuf]) -> BTreeMap<String, (SystemTime, String)> {
    let mut out = BTreeMap::new();
    for root in roots {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(root)
            .expect("fixture root readable")
            .map(|e| e.expect("dir entry").path())
            .collect();
        entries.sort();
        for path in entries {
            if !path.is_file() {
                continue;
            }
            let meta = std::fs::metadata(&path).expect("metadata");
            let bytes = std::fs::read(&path).expect("read");
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            let sha = hasher.finalize().iter().fold(String::new(), |mut acc, b| {
                use std::fmt::Write as _;
                let _ = write!(acc, "{b:02x}");
                acc
            });
            let key = format!("{}/{}", root.display(), file_name(&path));
            out.insert(key, (meta.modified().expect("mtime"), sha));
        }
    }
    out
}

fn file_name(path: &Path) -> String {
    path.file_name().unwrap().to_string_lossy().into_owned()
}

// ── Gate: zero writes ────────────────────────────────────────────────────────

#[test]
fn ingest_writes_nothing_to_the_memory_root() {
    let roots = both_roots();
    let before = snapshot(&roots);
    assert!(before.len() >= 12, "fixture snapshot looks empty: {}", before.len());

    let ingest = ingest_native_memory(&roots, NativeMemoryIngestOptions::default());
    // Exercise every read path, not just the walk: body read, search, fact rows.
    let _ =
        read_memory_body(&ingest, "toolchain-outside-path", NativeMemoryIngestOptions::default()).expect("body reads");
    let _ = search_memories(&ingest, "toolchain path", 0.0, 10);
    let _ = ingest.fact_rows();

    let after = snapshot(&roots);
    assert_eq!(
        before.keys().collect::<Vec<_>>(),
        after.keys().collect::<Vec<_>>(),
        "ingest added or removed a file"
    );
    for (path, (mtime_before, sha_before)) in &before {
        let (mtime_after, sha_after) = after.get(path).expect("file still present");
        assert_eq!(mtime_before, mtime_after, "mtime changed for {path}");
        assert_eq!(sha_before, sha_after, "content hash changed for {path}");
    }
}

/// A grep-level guard on the module itself: the read-only property is a
/// property of the source, so pin it there too. A future edit that reaches for
/// `File::create` or `fs::write` fails here before it ever reaches a real store.
#[test]
fn projection_source_contains_no_write_calls() {
    let source = std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/native_memory.rs"))
        .expect("module readable");
    // Strip the doc comments: they name the forbidden calls in prose.
    let code: String = source
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    for forbidden in [
        "fs::write",
        "File::create",
        "fs::remove",
        "fs::rename",
        "fs::copy",
        "fs::create_dir",
        "set_permissions",
        ".write(true)",
        ".create(true)",
        ".append(true)",
        ".truncate(true)",
    ] {
        assert!(
            !code.contains(forbidden),
            "native_memory.rs must stay read-only, found `{forbidden}`"
        );
    }
}

// ── Gate: every file ingested, links resolved, dangling reported ─────────────

#[test]
fn every_fixture_file_is_accounted_for() {
    let ingest = ingest_alpha();
    let on_disk = std::fs::read_dir(fixture_root("project-alpha"))
        .expect("root")
        .filter(|e| {
            e.as_ref()
                .map(|e| e.path().extension().and_then(|x| x.to_str()) == Some("md"))
                .unwrap_or(false)
        })
        .count();
    assert_eq!(ingest.files_scanned, on_disk, "every *.md file is scanned");
    // Everything except MEMORY.md projects as a memory; nothing is silently dropped.
    assert_eq!(ingest.memories, on_disk - 1);
    assert_eq!(ingest.projection, NATIVE_MEMORY_PROJECTION_ID);
    assert_eq!(ingest.indexes.len(), 1);
}

#[test]
fn wikilinks_resolve_and_dangling_links_are_reported_not_fatal() {
    let ingest = ingest_alpha();
    let entry = ingest.get("toolchain-outside-path").expect("entry");
    assert_eq!(
        entry.links,
        vec![
            "host-deploy-runbook".to_string(),
            "shared-tree-checkout-collision".to_string()
        ]
    );
    assert!(entry.dangling_links.is_empty());

    let runbook = ingest.get("host-deploy-runbook").expect("entry");
    assert_eq!(runbook.dangling_links, vec!["a-memory-that-does-not-exist".to_string()]);

    // Dangling edges are recorded from both bodies and the index, and the
    // projection still produced a full entry set.
    assert!(ingest
        .dangling
        .iter()
        .any(|d| d.to == "a-memory-that-does-not-exist" && d.origin == EdgeOrigin::Body));
    assert!(ingest
        .dangling
        .iter()
        .any(|d| d.to == "removed-long-ago" && d.origin == EdgeOrigin::Index));
    assert!(!ingest.entries.is_empty());

    // Backlinks are the inverse of the resolved edges.
    let collision = ingest.get("shared-tree-checkout-collision").expect("entry");
    assert_eq!(collision.backlinks, vec!["toolchain-outside-path".to_string()]);
    assert_eq!(collision.dangling_links, vec!["never-written-down".to_string()]);
}

#[test]
fn index_headings_become_group_metadata() {
    let ingest = ingest_alpha();
    assert_eq!(
        ingest.get("toolchain-outside-path").expect("entry").group.as_deref(),
        Some("Environment traps")
    );
    assert_eq!(
        ingest.get("host-deploy-runbook").expect("entry").group.as_deref(),
        Some("Deploy runbooks")
    );
    assert!(ingest.groups.contains_key("Odd shapes"));
    let entry = ingest.get("toolchain-outside-path").expect("entry");
    assert_eq!(entry.index_title.as_deref(), Some("Toolchain lives outside PATH"));
    assert!(entry.index_hook.as_deref().unwrap_or_default().contains("not on PATH"));
}

// ── Gate: malformed input degrades, never aborts ─────────────────────────────

#[test]
fn malformed_files_warn_and_still_project() {
    let ingest = ingest_alpha();
    let kinds: Vec<MemoryWarningKind> = ingest.warnings.iter().map(|w| w.kind).collect();
    for expected in [
        MemoryWarningKind::MissingFrontmatter,
        MemoryWarningKind::MalformedFrontmatter,
        MemoryWarningKind::MissingDescription,
        MemoryWarningKind::NonUtf8Bytes,
        MemoryWarningKind::Redacted,
    ] {
        assert!(kinds.contains(&expected), "expected a {expected:?} warning");
    }
    // Each degraded file is still an entry — the projection did not abort.
    for slug in [
        "no-frontmatter",
        "missing-description",
        "unclosed-frontmatter",
        "non-utf8",
        "crlf-endings",
    ] {
        assert!(ingest.get(slug).is_some(), "{slug} should still project");
    }
    assert_eq!(ingest.get("missing-description").expect("entry").description, "");
    assert!(ingest.get("non-utf8").expect("entry").lossy);
    // CRLF frontmatter parses exactly like LF frontmatter.
    assert_eq!(
        ingest.get("crlf-endings").expect("entry").description,
        "Written by an editor that emits CRLF line endings"
    );
}

#[test]
fn warning_details_never_carry_body_text() {
    let ingest = ingest_alpha();
    for warning in &ingest.warnings {
        assert!(
            !warning.detail.contains(REDACTION_PLACEHOLDER) || warning.kind == MemoryWarningKind::Redacted,
            "warning detail leaked redacted content"
        );
        assert!(
            warning.detail.len() < 200,
            "warning detail is too chatty to be body-free"
        );
    }
}

// ── Gate: fact shape follows the workspace memory_md_ref convention ──────────

#[test]
fn fact_value_links_out_and_never_carries_the_body() {
    let ingest = ingest_alpha();
    let rows = ingest.fact_rows();
    assert_eq!(rows.len(), ingest.memories);
    let (entity, key, value) = rows
        .iter()
        .find(|(e, _, _)| e == "memory:toolchain-outside-path")
        .expect("row present");
    assert!(entity.starts_with(NATIVE_MEMORY_ENTITY_PREFIX));
    assert_eq!(*key, NATIVE_MEMORY_FACT_KEY);
    assert_eq!(value["memory_md_ref"], "toolchain-outside-path.md");
    assert_eq!(value["read_only"], true);
    assert!(value["description"].as_str().unwrap().contains("not on PATH"));
    // The standing workspace rule: link out, do not migrate the body in.
    let serialised = serde_json::to_string(value).expect("serialise");
    assert!(!serialised.contains("The toolchain is installed but"));
    assert!(!serialised.contains("\"body\""));
}

// ── Gate: HTTP-shaped round trip (slug -> description + body) ────────────────

#[test]
fn body_round_trips_by_slug() {
    let ingest = ingest_alpha();
    let entry = ingest.get("shared-tree-checkout-collision").expect("entry");
    assert_eq!(
        entry.description,
        "Sibling sessions reset the SAME nested repo tree and uncommitted edits vanish; use a worktree per lane"
    );
    let body = read_memory_body(&ingest, &entry.slug, NativeMemoryIngestOptions::default()).expect("body");
    assert!(body.body.starts_with("Two sessions sharing one checkout"));
    assert!(!body.body.starts_with("---"), "frontmatter is stripped from the body");
    assert!(!body.changed_since_ingest);
    assert_eq!(body.content_hash, entry.content_hash);
}

#[test]
fn body_read_rejects_traversal_and_unknown_slugs() {
    let ingest = ingest_alpha();
    assert!(read_memory_body(&ingest, "../../etc/passwd", NativeMemoryIngestOptions::default()).is_err());
    assert!(read_memory_body(&ingest, "nope", NativeMemoryIngestOptions::default()).is_err());
}

// ── Search honesty, redaction, determinism, multi-root ───────────────────────

#[test]
fn search_scores_by_term_coverage_and_can_return_nothing() {
    let ingest = ingest_alpha();
    let hits = search_memories(&ingest, "toolchain PATH", 0.5, 10);
    assert_eq!(hits.first().map(|h| h.slug.as_str()), Some("toolchain-outside-path"));
    assert!(hits[0].score >= 0.5);
    assert!(!hits[0].matched_terms.is_empty());
    // No recency fallback: a query that matches nothing returns nothing.
    assert!(search_memories(&ingest, "kubernetes helm istio", 0.5, 10).is_empty());
    assert!(search_memories(&ingest, "", 0.0, 10).is_empty());
}

#[test]
fn secret_shaped_text_is_redacted_in_descriptions_and_bodies() {
    let ingest = ingest_alpha();
    let entry = ingest.get("secret-shaped").expect("entry");
    assert!(entry.redacted);
    assert!(entry.description.contains(REDACTION_PLACEHOLDER));
    assert!(!entry.description.contains("sk-ant-api03-EXAMPLE"));
    let body = read_memory_body(&ingest, "secret-shaped", NativeMemoryIngestOptions::default()).expect("body");
    assert!(body.redacted);
    assert!(!body.body.contains("ghp_EXAMPLE"));
    // A commit sha is not a secret and must survive.
    assert!(body.body.contains("a413ce6f"));

    let (raw, hit) = redact_secret_shaped("nothing to see here");
    assert!(!hit);
    assert_eq!(raw, "nothing to see here");
}

#[test]
fn two_ingests_of_an_unchanged_root_are_identical() {
    let first = ingest_alpha();
    let second = ingest_alpha();
    assert_eq!(first.set_hash, second.set_hash);
    assert_eq!(
        serde_json::to_string(&first).expect("serialise"),
        serde_json::to_string(&second).expect("serialise")
    );
}

#[test]
fn multiple_roots_merge_and_the_first_root_wins_a_duplicate_slug() {
    let ingest = ingest_native_memory(&both_roots(), NativeMemoryIngestOptions::default());
    assert!(ingest.get("second-root-memory").is_some());
    let shared = ingest.get("toolchain-outside-path").expect("entry");
    assert!(
        shared.root.ends_with("project-alpha"),
        "first root should win, got {}",
        shared.root
    );
    assert!(ingest
        .warnings
        .iter()
        .any(|w| w.kind == MemoryWarningKind::DuplicateSlug));
    // A cross-root wikilink still resolves.
    assert_eq!(
        ingest.get("second-root-memory").expect("entry").links,
        vec!["toolchain-outside-path".to_string()]
    );
}

#[test]
fn missing_root_warns_instead_of_failing() {
    let ingest = ingest_native_memory(
        &[PathBuf::from("/nonexistent/memory/root")],
        NativeMemoryIngestOptions::default(),
    );
    assert_eq!(ingest.memories, 0);
    assert!(ingest
        .warnings
        .iter()
        .any(|w| w.kind == MemoryWarningKind::RootUnreadable));
}

#[test]
fn root_spec_expands_home_and_a_single_star_segment() {
    let home = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let roots = resolve_roots("~/native-memory/*", Some(&home));
    let names: Vec<String> = roots.iter().map(|p| file_name(p)).collect();
    assert_eq!(names, vec!["project-alpha".to_string(), "project-beta".to_string()]);

    let literal = resolve_roots(&fixture_root("project-alpha").display().to_string(), Some(&home));
    assert_eq!(literal.len(), 1);
    assert!(resolve_roots("", Some(&home)).is_empty());
}
