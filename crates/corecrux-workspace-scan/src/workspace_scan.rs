// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Workspace scanner — Phase 2 of the context graph.
//!
//! Walks a Rust workspace (Cargo.toml + crates/) and emits structured facts
//! about modules, files, public symbols, dependencies, stubs, and dead code.
//! All extraction is regex-based for speed and zero new heavy deps; we trade
//! ~10–15% accuracy on macro-heavy / generic-heavy code for sub-second scans.
//!
//! ## Outputs
//!
//! Returns a `WorkspaceScan` struct with:
//! - `crates`: name + path + cargo dependencies
//! - `files`: per-file path + LOC + module + symbol counts
//! - `symbols`: pub fn/struct/enum/trait declarations with file + line
//! - `deps`: from-file → to-module edges (extracted from `use` statements)
//! - `stubs`: file + line + kind (`todo!`, `unimplemented!`, `panic!("...")`)
//! - `dead_code`: pub symbols with zero internal references (heuristic; may
//!   miss macro-defined / dynamic-dispatch usages)
//!
//! Persisted as facts under `__workspace_scan__::<scan_id>::` so each scan is
//! versioned and queryable. The context_graph endpoint folds the latest scan
//! into the project graph.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, HashSet};
#[cfg(unix)]
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::workspace_scan_manifests::ExternalDep;

pub const SCAN_METADATA_MAX_BYTES: usize = 256;
pub const RUST_SYNTAX_MAX_DEPTH: usize = 128;
const RUST_SOURCE_MAX_LINE_BYTES: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("workspace path not configured (CORECRUXD_WORKSPACE_PATH unset or empty)")]
    NotConfigured,
    #[error("scan policy: {0}")]
    Policy(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WorkspaceScan {
    pub scan_id: String,
    pub root_path: String,
    pub started_at_unix_ms: u64,
    pub finished_at_unix_ms: u64,
    pub duration_ms: u64,
    pub crates: Vec<CrateInfo>,
    pub files: Vec<FileInfo>,
    pub symbols: Vec<SymbolInfo>,
    pub deps: Vec<DepEdge>,
    pub stubs: Vec<StubHit>,
    pub dead_code: Vec<DeadSymbol>,
    /// Public symbols referenced somewhere in the workspace, but **never from
    /// outside a `#[cfg(test)]` scope or a test file**.
    ///
    /// The third category. Every reference-counting tier sees these as alive
    /// (they are referenced) and every execution tier sees them as unobserved
    /// (production never calls them), so neither can name what they actually
    /// are: code kept alive only by its own tests. Deleting one is a judgement
    /// call about the test, not an automatic win — which is a different answer
    /// from both "dead" and "live", and worth being able to give.
    #[serde(default)]
    pub test_only_symbols: Vec<String>,
    /// Parsed HTTP routes (axum `.route("/path", METHOD(handler))` calls).
    /// Each entry resolves the handler to its definition file/line so the
    /// storyline composer can root a tree at the right place.
    #[serde(default)]
    pub routes: Vec<RouteHit>,
    /// Diagnostic surface — populated alongside the main scan. Surfaces
    /// resolution gaps that would otherwise be silent (route handlers that
    /// the symbol index couldn't bind, files where many call sites failed
    /// to resolve, etc.).
    #[serde(default, skip_serializing_if = "ScanDiagnostics::is_empty")]
    pub diagnostics: ScanDiagnostics,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub external_deps: Vec<ExternalDep>,
    pub stats: ScanStats,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanDiagnostics {
    /// Routes whose handler_fn couldn't be resolved to a definition file.
    /// Likely macro-generated handlers, or symbols re-exported through a
    /// module path the symbol index doesn't track. Each entry carries a
    /// `reason` so the human / agent surface can explain the gap.
    #[serde(default)]
    pub unresolved_routes: Vec<UnresolvedRoute>,
    /// Source files deliberately omitted before parsing by a safety cap or
    /// non-regular-file check. The field name is retained for schema
    /// compatibility, but baseline TypeScript and V2 JavaScript guards also
    /// report here. Empty/off remains absent from serialized scans.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub v3_skipped_files: Vec<V3SkippedFile>,
    /// Source files that were read but could **not be parsed**.
    ///
    /// Distinct from `v3_skipped_files`, which records only files rejected
    /// *before* parsing. Without this, an unparsable file produced an entry
    /// with no symbols — byte-identical to a file that genuinely declares
    /// none — so `blast_radius` and dead-code answers for its contents read
    /// as "nothing here". A parse that could not run is not a parse that ran
    /// and found nothing.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parse_failures: Vec<ParseFailure>,
}

impl ScanDiagnostics {
    pub fn is_empty(&self) -> bool {
        self.unresolved_routes.is_empty() && self.v3_skipped_files.is_empty() && self.parse_failures.is_empty()
    }
}

/// A file the scanner read but could not parse. See
/// [`ScanDiagnostics::parse_failures`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParseFailure {
    pub rel_path: String,
    /// The parser that was applied: `rust`, `manifest:<ecosystem>`, or the
    /// polyglot language id.
    pub language: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct V3SkippedFile {
    pub rel_path: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnresolvedRoute {
    pub method: String,
    pub path: String,
    pub handler_fn: String,
    pub source_file: String,
    pub source_line: usize,
    /// Best guess at why resolution failed. One of:
    /// - `"ambiguous"` — multiple candidate fns with this name; resolver
    ///   couldn't pick (e.g. neither same-crate nor singleton-global narrows it).
    /// - `"not_found"` — no fn with this name exists in the workspace symbol
    ///   index. Typical cause: the handler is re-exported from an external
    ///   crate, or generated by a macro.
    pub reason: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanStats {
    pub crate_count: usize,
    pub file_count: usize,
    pub total_loc: usize,
    pub symbol_count: usize,
    pub dep_count: usize,
    pub stub_count: usize,
    pub dead_code_count: usize,
    #[serde(default)]
    pub route_count: usize,
    #[serde(default)]
    pub file_reference_count: usize,
    #[serde(default, skip_serializing_if = "usize_is_zero")]
    pub external_dep_count: usize,
    /// Number of files with a `//!` header that produced a `doc_summary`.
    /// Denominator is `file_count`; the ratio is the workspace doc-coverage
    /// percentage. Surfaced in the console Story panel header.
    #[serde(default)]
    pub doc_coverage_files: usize,
    /// M8: routes grouped by their handler's crate. Lets the console show
    /// "where the API surface lives" without re-bucketing on every render.
    /// Routes with `handler_file: None` are NOT counted (use `diagnostics
    /// .unresolved_routes` to surface those).
    #[serde(default)]
    pub routes_by_crate: std::collections::BTreeMap<String, usize>,
}

fn usize_is_zero(n: &usize) -> bool {
    *n == 0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrateInfo {
    /// `corecruxd`, `crux-mcp`, etc. Read from the crate's Cargo.toml.
    pub name: String,
    /// Path relative to the workspace root, e.g. `crates/corecruxd`.
    pub rel_path: String,
    /// Internal dependencies (workspace crates this one depends on).
    pub internal_deps: Vec<String>,
    pub file_count: usize,
    pub total_loc: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    /// Path relative to the workspace root.
    pub rel_path: String,
    pub crate_name: String,
    /// Module path inferred from file location (e.g. `corecruxd::http::admin`).
    pub module_path: String,
    pub loc: usize,
    pub symbol_count: usize,
    pub stub_count: usize,
    /// First sentence (≤80 chars) of the file-level `//!` header. None if no
    /// header. Used by the agent surface and the human Files list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doc_summary: Option<String>,
    /// Full file-level `//!` header text (multi-line, leading `//! ` stripped).
    /// None if no header. Shown in the human file drawer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doc_full: Option<String>,
    /// Symbol names defined in this file (denormalised from `scan.symbols`).
    #[serde(default)]
    pub defines: Vec<String>,
    /// Outgoing edges: file → file references resolved by the call-site pass.
    /// `same_file=true` entries are intra-file calls (kept because the user
    /// asked for both intra- and cross-crate edges).
    #[serde(default)]
    pub references: Vec<FileReference>,
    /// Inverse index of `references` — the rel_paths of files that call into
    /// at least one symbol defined here.
    #[serde(default)]
    pub referenced_by: Vec<String>,
    /// True for files that look like test code (path heuristic + optional
    /// `#![cfg(test)]` inner attribute on the first line). Off by default
    /// in storyline output via the `include_tests=false` query param.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub is_test_file: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileReference {
    pub to_file: String,
    pub to_symbol: String,
    pub call_count: usize,
    pub same_file: bool,
    /// The fn this call site lives inside, if the symbol cursor could
    /// determine it. None = top-level / module-init code (rare; usually a
    /// `static` initializer or const expression). M5 hardening: when this
    /// is Some, the storyline composer can show only the calls that this
    /// specific fn makes, instead of the file's whole aggregate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_symbol: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteHit {
    pub method: String,     // GET / POST / PATCH / DELETE / PUT
    pub path: String,       // "/v1/projects/{id}"
    pub handler_fn: String, // post_project
    /// Framework that supplied this route when detection is framework-specific.
    /// Omitted for legacy/Rust hits so dark feature gates preserve serialized bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub framework: Option<String>,
    /// Where the handler function is defined. None if the symbol couldn't be
    /// resolved (e.g. handler comes from a re-exported module behind a macro).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handler_file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handler_line: Option<usize>,
    /// Where the `.route("/...", METHOD(handler))` declaration lives.
    pub source_file: String,
    pub source_line: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolInfo {
    pub crate_name: String,
    pub module_path: String,
    pub file_rel_path: String,
    pub line: usize,
    pub kind: String, // fn / struct / enum / trait / type / const / static / mod
    pub name: String,
    pub is_pub: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepEdge {
    pub from_crate: String,
    pub from_file: String,
    pub to_module: String, // resolved best-effort from `use` path
    pub raw: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StubHit {
    pub crate_name: String,
    pub file_rel_path: String,
    pub line: usize,
    pub kind: String, // todo / unimplemented / panic_not_implemented
    pub snippet: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadSymbol {
    pub crate_name: String,
    pub module_path: String,
    pub file_rel_path: String,
    pub line: usize,
    pub kind: String,
    pub name: String,
    pub confidence: f32,
    pub note: String,
}

pub fn run_scan_with_policy(
    policy: &crate::repo_scan_policy::RepoScanPolicy,
) -> Result<WorkspaceScan, ScanError> {
    policy.execute_workspace(|canonical| {
        let mut scan = run_scan_at_in_context(canonical)?;
        crate::workspace_scan_manifests::attach_external_deps_if_enabled(canonical, &mut scan)?;
        redact_self_workspace_paths(&mut scan);
        Ok(scan)
    })
}

pub fn redact_self_workspace_paths(scan: &mut WorkspaceScan) {
    let previous_root = PathBuf::from(&scan.root_path);
    for crate_info in &mut scan.crates {
        let path = Path::new(&crate_info.rel_path);
        if !path.is_absolute() {
            continue;
        }
        crate_info.rel_path = if previous_root.is_absolute() {
            path.strip_prefix(&previous_root)
                .ok()
                .filter(|relative| !relative.as_os_str().is_empty())
                .map_or_else(|| ".".to_string(), |relative| relative.display().to_string())
        } else {
            ".".to_string()
        };
    }
    // The self-workspace graph is intentionally shared code intelligence, but
    // the host's absolute checkout path is deployment metadata.
    scan.root_path = ".".to_string();
}

#[cfg(test)]
pub fn run_scan_at(root: &Path) -> Result<WorkspaceScan, ScanError> {
    let policy = crate::repo_scan_policy::RepoScanPolicy::for_exact_root(root)?;
    run_scan_at_with_policy(root, &policy)
}

#[cfg(test)]
fn run_scan_at_with_policy(
    root: &Path,
    policy: &crate::repo_scan_policy::RepoScanPolicy,
) -> Result<WorkspaceScan, ScanError> {
    policy.execute(root, |canonical| {
        let mut scan = run_scan_at_in_context(canonical)?;
        crate::workspace_scan_manifests::attach_external_deps_if_enabled(canonical, &mut scan)?;
        Ok(scan)
    })
}

pub fn run_scan_at_in_context(root: &Path) -> Result<WorkspaceScan, ScanError> {
    if ast_scan_enabled_from_env() {
        return crate::workspace_scan_ast::run_scan_ast_at(root);
    }
    run_scan_regex_at(root)
}

pub fn ast_scan_enabled_from_env() -> bool {
    std::env::var("CORECRUXD_AST_SCAN").ok().is_some_and(|v| {
        let v = v.trim().to_ascii_lowercase();
        !(v.is_empty() || v == "0" || v == "false" || v == "off" || v == "no")
    })
}

/// Reject source shapes that can drive `syn` or its recursive visitors beyond
/// a bounded stack before parsing. This is a lexical admission guard, not a
/// syntax validator; `syn` remains authoritative after it passes.
pub fn validate_rust_syntax_complexity(src: &str) -> Result<(), ScanError> {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum LexState {
        Code,
        LineComment,
        BlockComment,
        Quoted(u8),
    }
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum AngleContext {
        None,
        TypeAlias,
        Aggregate,
        Signature,
        Annotation,
        Impl,
        Cast,
    }
    #[derive(Clone, Copy)]
    struct AngleSuspension {
        depth: usize,
        context: AngleContext,
        context_base_depth: usize,
        generic_depth: usize,
        annotation_expected: bool,
        cast_scope_base_depth: Option<usize>,
    }

    let bytes = src.as_bytes();
    let mut state = LexState::Code;
    let mut escaped = false;
    let mut block_depth = 0usize;
    let mut syntax_depth = 0usize;
    let mut generic_depth = 0usize;
    let mut prefix_run = 0usize;
    let mut path_segments = 0usize;
    let mut assignment_depth = 0usize;
    let mut angle_context = AngleContext::None;
    let mut angle_context_base_depth = 0usize;
    let mut aggregate_brace_depth = None;
    let mut aggregate_discriminant_depth = None;
    let mut suspended_angles: Vec<AngleSuspension> = Vec::new();
    let mut attribute_angle = None;
    let mut annotation_expected = false;
    let mut cast_scope_base_depth = None;
    let mut closure_parameter_depth = None;
    let mut line_bytes = 0usize;
    let mut index = 0usize;
    while index < bytes.len() {
        if index % 4096 == 0 {
            crate::repo_scan_policy::check_deadline()?;
        }
        let byte = bytes[index];
        let next = bytes.get(index + 1).copied();
        if byte == b'\n' {
            line_bytes = 0;
        } else {
            line_bytes = line_bytes.saturating_add(1);
            if line_bytes > RUST_SOURCE_MAX_LINE_BYTES {
                return Err(ScanError::Policy(format!(
                    "Rust source line exceeds {RUST_SOURCE_MAX_LINE_BYTES} bytes"
                )));
            }
        }
        match state {
            LexState::Code => {
                if byte == b'/' && next == Some(b'/') {
                    state = LexState::LineComment;
                    index += 1;
                } else if byte == b'/' && next == Some(b'*') {
                    state = LexState::BlockComment;
                    block_depth = 1;
                    index += 1;
                } else if let Some(end) = rust_raw_string_end(bytes, index)? {
                    index = end;
                    prefix_run = 0;
                } else if byte == b'"' {
                    state = LexState::Quoted(b'"');
                    escaped = false;
                    prefix_run = 0;
                } else if byte == b'\'' && rust_char_literal_end(bytes, index).is_some() {
                    state = LexState::Quoted(b'\'');
                    escaped = false;
                    prefix_run = 0;
                } else {
                    let angle_isolated = attribute_angle.is_some();
                    let previous = index.checked_sub(1).and_then(|offset| bytes.get(offset)).copied();
                    let assignment_operator = byte == b'='
                        && next != Some(b'=')
                        && next != Some(b'>')
                        && !matches!(previous, Some(b'=' | b'!' | b'<' | b'>'));
                    if assignment_operator && !angle_isolated {
                        assignment_depth = assignment_depth.saturating_add(1);
                    }
                    let starts_identifier = (byte.is_ascii_alphabetic() || byte == b'_')
                        && !bytes
                            .get(index.wrapping_sub(1))
                            .is_some_and(|previous| previous.is_ascii_alphanumeric() || *previous == b'_')
                        && !bytes[..index].ends_with(b"r#");
                    if starts_identifier && !angle_isolated {
                        let end = bytes[index..]
                            .iter()
                            .position(|candidate| !(candidate.is_ascii_alphanumeric() || *candidate == b'_'))
                            .map_or(bytes.len(), |offset| index + offset);
                        match &bytes[index..end] {
                            b"type" => {
                                angle_context = AngleContext::TypeAlias;
                                angle_context_base_depth = syntax_depth;
                            }
                            b"struct" | b"enum" | b"union" | b"trait" => {
                                angle_context = AngleContext::Aggregate;
                                angle_context_base_depth = syntax_depth;
                            }
                            b"fn" => {
                                angle_context = AngleContext::Signature;
                                angle_context_base_depth = syntax_depth;
                            }
                            b"impl" | b"where" => {
                                angle_context = AngleContext::Impl;
                                angle_context_base_depth = syntax_depth;
                            }
                            b"let" | b"const" | b"static" => {
                                annotation_expected = true;
                            }
                            b"as" if generic_depth == 0 => {
                                angle_context = AngleContext::Cast;
                                angle_context_base_depth = syntax_depth;
                                cast_scope_base_depth = Some(syntax_depth);
                            }
                            _ => {}
                        }
                    }
                    if !angle_isolated
                        && matches!(byte, b'&' | b'*')
                        && rust_type_prefix_run(bytes, index) > RUST_SYNTAX_MAX_DEPTH
                    {
                        return Err(ScanError::Policy(format!(
                            "Rust type-prefix nesting exceeds {RUST_SYNTAX_MAX_DEPTH}"
                        )));
                    }
                    let cast_angle_open = byte == b'<'
                        && angle_context == AngleContext::Cast
                        && rust_angle_has_matching_close(bytes, index)?;
                    match byte {
                        b'(' | b'[' | b'{' => {
                            syntax_depth = syntax_depth.saturating_add(1);
                            if byte == b'[' && attribute_angle.is_none() && rust_attribute_open(bytes, index) {
                                attribute_angle = Some(AngleSuspension {
                                    depth: syntax_depth,
                                    context: angle_context,
                                    context_base_depth: angle_context_base_depth,
                                    generic_depth,
                                    annotation_expected,
                                    cast_scope_base_depth,
                                });
                                cast_scope_base_depth = None;
                            } else if byte == b'{' && attribute_angle.is_none() {
                                if generic_depth > 0 {
                                    crate::repo_scan_policy::charge_parser_work(
                                        1,
                                        std::mem::size_of::<AngleSuspension>(),
                                        "Rust angle-context stack",
                                    )?;
                                    suspended_angles.push(AngleSuspension {
                                        depth: syntax_depth,
                                        context: angle_context,
                                        context_base_depth: angle_context_base_depth,
                                        generic_depth,
                                        annotation_expected,
                                        cast_scope_base_depth,
                                    });
                                    angle_context = AngleContext::None;
                                    angle_context_base_depth = syntax_depth;
                                    generic_depth = 0;
                                    annotation_expected = false;
                                    cast_scope_base_depth = None;
                                } else {
                                    match angle_context {
                                        AngleContext::Aggregate => {
                                            aggregate_brace_depth.get_or_insert(syntax_depth);
                                        }
                                        AngleContext::Signature | AngleContext::Impl => {
                                            angle_context = AngleContext::None;
                                        }
                                        AngleContext::Annotation => {
                                            angle_context = AngleContext::None;
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            prefix_run = 0;
                        }
                        b')' | b']' | b'}' => {
                            if let Some(saved) = attribute_angle.filter(|saved| saved.depth == syntax_depth) {
                                attribute_angle = None;
                                angle_context = saved.context;
                                angle_context_base_depth = saved.context_base_depth;
                                generic_depth = saved.generic_depth;
                                annotation_expected = saved.annotation_expected;
                                cast_scope_base_depth = saved.cast_scope_base_depth;
                            } else if let Some(saved) = suspended_angles
                                .last()
                                .copied()
                                .filter(|saved| saved.depth == syntax_depth)
                            {
                                suspended_angles.pop();
                                angle_context = saved.context;
                                angle_context_base_depth = saved.context_base_depth;
                                generic_depth = saved.generic_depth;
                                annotation_expected = saved.annotation_expected;
                                cast_scope_base_depth = saved.cast_scope_base_depth;
                            }
                            if byte == b'}' && aggregate_brace_depth == Some(syntax_depth) {
                                aggregate_brace_depth = None;
                                aggregate_discriminant_depth = None;
                                angle_context = AngleContext::None;
                            }
                            if generic_depth == 0 && cast_scope_base_depth == Some(syntax_depth) {
                                // A cast target cannot extend past the
                                // expression delimiter that contains it. This
                                // also covers parenthesized casts followed by
                                // ordinary comparisons.
                                angle_context = AngleContext::None;
                                cast_scope_base_depth = None;
                            }
                            syntax_depth = syntax_depth.saturating_sub(1);
                            prefix_run = 0;
                        }
                        _ if attribute_angle.is_some() => {
                            prefix_run = 0;
                        }
                        b'<' if attribute_angle.is_none()
                            && (generic_depth > 0
                                || (angle_context != AngleContext::None && angle_context != AngleContext::Cast)
                                || cast_angle_open
                                || bytes[..index].ends_with(b"::")
                                || rust_qself_open(bytes, index)) =>
                        {
                            generic_depth = generic_depth.saturating_add(1);
                            prefix_run = 0;
                        }
                        b'>' if generic_depth > 0 => {
                            generic_depth = generic_depth.saturating_sub(1);
                            if generic_depth == 0 && angle_context == AngleContext::Cast {
                                angle_context = AngleContext::None;
                            }
                            prefix_run = 0;
                        }
                        b'<' if angle_context == AngleContext::Cast => {
                            angle_context = AngleContext::None;
                            prefix_run = 0;
                        }
                        b':' if next == Some(b':') => {
                            path_segments = path_segments.saturating_add(1);
                            prefix_run = 0;
                            index += 1;
                        }
                        b':' => {
                            if angle_context == AngleContext::None
                                && (annotation_expected || closure_parameter_depth.is_some())
                            {
                                angle_context = AngleContext::Annotation;
                                angle_context_base_depth = syntax_depth;
                            }
                            annotation_expected = false;
                            path_segments = 0;
                            prefix_run = 0;
                        }
                        b'-' if next == Some(b'>') => {
                            angle_context = AngleContext::Annotation;
                            angle_context_base_depth = syntax_depth;
                            prefix_run = 0;
                            // Do not let the arrow's `>` consume one open
                            // generic layer on the next loop iteration.
                            index += 1;
                        }
                        b'=' if angle_context != AngleContext::TypeAlias && generic_depth == 0 => {
                            if angle_context == AngleContext::Aggregate && aggregate_brace_depth == Some(syntax_depth) {
                                // Enum discriminants are expressions. Resume
                                // aggregate/type context at the next
                                // top-level variant comma.
                                aggregate_discriminant_depth = Some(syntax_depth);
                                angle_context = AngleContext::None;
                            } else {
                                angle_context = AngleContext::None;
                            }
                            if cast_scope_base_depth == Some(syntax_depth) {
                                cast_scope_base_depth = None;
                            }
                            annotation_expected = false;
                            path_segments = 0;
                            prefix_run = 0;
                        }
                        b',' => {
                            if aggregate_discriminant_depth == Some(syntax_depth) {
                                aggregate_discriminant_depth = None;
                                angle_context = AngleContext::Aggregate;
                            } else if generic_depth == 0 && cast_scope_base_depth == Some(syntax_depth) {
                                // This is an expression/argument boundary.
                                // Commas inside an actual generic target have
                                // generic_depth > 0 and remain type context.
                                angle_context = AngleContext::None;
                                cast_scope_base_depth = None;
                            } else if generic_depth == 0 && angle_context == AngleContext::Annotation {
                                angle_context = AngleContext::None;
                            }
                            path_segments = 0;
                            assignment_depth = 0;
                            prefix_run = 0;
                        }
                        b';' => {
                            if angle_context != AngleContext::None && syntax_depth > angle_context_base_depth {
                                // The expression half of an array type
                                // (`[T; EXPR]`) is not a type grammar. Ignore
                                // comparison operators until its delimiter
                                // closes while retaining any enclosing generic
                                // depth.
                                crate::repo_scan_policy::charge_parser_work(
                                    1,
                                    std::mem::size_of::<AngleSuspension>(),
                                    "Rust angle-context stack",
                                )?;
                                suspended_angles.push(AngleSuspension {
                                    depth: syntax_depth,
                                    context: angle_context,
                                    context_base_depth: angle_context_base_depth,
                                    generic_depth,
                                    annotation_expected,
                                    cast_scope_base_depth,
                                });
                                angle_context = AngleContext::None;
                                angle_context_base_depth = syntax_depth;
                                generic_depth = 0;
                                annotation_expected = false;
                                cast_scope_base_depth = None;
                            } else {
                                angle_context = AngleContext::None;
                                cast_scope_base_depth = None;
                                annotation_expected = false;
                                closure_parameter_depth = None;
                                generic_depth = 0;
                                path_segments = 0;
                                assignment_depth = 0;
                                prefix_run = 0;
                            }
                        }
                        b'+' | b'/' | b'%' | b'^' | b'?' | b'.'
                            if generic_depth == 0 && cast_scope_base_depth == Some(syntax_depth) =>
                        {
                            angle_context = AngleContext::None;
                            cast_scope_base_depth = None;
                            prefix_run = 0;
                        }
                        b'-' if next != Some(b'>')
                            && generic_depth == 0
                            && cast_scope_base_depth == Some(syntax_depth) =>
                        {
                            angle_context = AngleContext::None;
                            cast_scope_base_depth = None;
                            prefix_run = 0;
                        }
                        b'>' if generic_depth == 0 && cast_scope_base_depth == Some(syntax_depth) => {
                            angle_context = AngleContext::None;
                            cast_scope_base_depth = None;
                            prefix_run = 0;
                        }
                        b'&' if next == Some(b'&')
                            && generic_depth == 0
                            && cast_scope_base_depth == Some(syntax_depth) =>
                        {
                            angle_context = AngleContext::None;
                            cast_scope_base_depth = None;
                            prefix_run = 0;
                            index += 1;
                        }
                        b'|' if next == Some(b'|')
                            && generic_depth == 0
                            && cast_scope_base_depth == Some(syntax_depth) =>
                        {
                            angle_context = AngleContext::None;
                            cast_scope_base_depth = None;
                            prefix_run = 0;
                            index += 1;
                        }
                        b'|' => {
                            if closure_parameter_depth == Some(syntax_depth) {
                                closure_parameter_depth = None;
                                if angle_context == AngleContext::Annotation {
                                    angle_context = AngleContext::None;
                                    generic_depth = 0;
                                }
                            } else if rust_closure_bar_open(bytes, index) {
                                closure_parameter_depth.get_or_insert(syntax_depth);
                            }
                            prefix_run = 0;
                        }
                        b'!' | b'&' | b'*' | b'-' => {
                            prefix_run = prefix_run.saturating_add(1);
                        }
                        byte if byte.is_ascii_whitespace() => {}
                        byte if byte.is_ascii_alphanumeric() || byte == b'_' => {
                            prefix_run = 0;
                        }
                        b'<' | b'>' | b'\'' => {
                            prefix_run = 0;
                        }
                        _ => {
                            prefix_run = 0;
                            path_segments = 0;
                        }
                    }
                    if syntax_depth > RUST_SYNTAX_MAX_DEPTH
                        || generic_depth > RUST_SYNTAX_MAX_DEPTH
                        || prefix_run > RUST_SYNTAX_MAX_DEPTH
                        || path_segments > RUST_SYNTAX_MAX_DEPTH
                        || assignment_depth > RUST_SYNTAX_MAX_DEPTH
                    {
                        return Err(ScanError::Policy(format!(
                            "Rust syntax nesting exceeds {RUST_SYNTAX_MAX_DEPTH}"
                        )));
                    }
                }
            }
            LexState::LineComment => {
                if byte == b'\n' {
                    state = LexState::Code;
                }
            }
            LexState::BlockComment => {
                if byte == b'/' && next == Some(b'*') {
                    block_depth = block_depth.saturating_add(1);
                    if block_depth > RUST_SYNTAX_MAX_DEPTH {
                        return Err(ScanError::Policy(format!(
                            "Rust comment nesting exceeds {RUST_SYNTAX_MAX_DEPTH}"
                        )));
                    }
                    index += 1;
                } else if byte == b'*' && next == Some(b'/') {
                    block_depth = block_depth.saturating_sub(1);
                    index += 1;
                    if block_depth == 0 {
                        state = LexState::Code;
                    }
                }
            }
            LexState::Quoted(quote) => {
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == quote {
                    state = LexState::Code;
                }
            }
        }
        index += 1;
    }
    validate_rust_tree_depth(src)?;
    crate::repo_scan_policy::check_deadline()
}

fn validate_rust_tree_depth(src: &str) -> Result<(), ScanError> {
    crate::repo_scan_policy::check_deadline()?;
    crate::repo_scan_policy::charge_source_parse_work(src, "Rust tree-sitter preflight")?;

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .map_err(|error| ScanError::Policy(format!("Rust syntax preflight unavailable: {error}")))?;
    let bytes = src.as_bytes();
    let mut progress = |_state: &tree_sitter::ParseState| match crate::repo_scan_policy::check_deadline() {
        Ok(()) => std::ops::ControlFlow::Continue(()),
        Err(_) => std::ops::ControlFlow::Break(()),
    };
    let options = tree_sitter::ParseOptions::new().progress_callback(&mut progress);
    let tree = parser.parse_with_options(
        &mut |offset, _point| bytes.get(offset..).unwrap_or_default(),
        None,
        Some(options),
    );
    crate::repo_scan_policy::check_deadline()?;
    let Some(tree) = tree else {
        return Err(ScanError::Policy(
            "Rust syntax preflight did not complete within the scan budget".to_string(),
        ));
    };
    if tree.root_node().has_error() {
        return Err(ScanError::Policy(
            "Rust syntax preflight rejected an unparseable source tree".to_string(),
        ));
    }

    // Tree-sitter owns its parse stack on the heap. Walk its concrete tree
    // iteratively so no attacker-controlled source shape reaches `syn` (or
    // recursive AST destruction) above the daemon's fixed depth ceiling.
    let mut cursor = tree.root_node().walk();
    let mut depth = 0usize;
    let mut visited = 1usize;
    'walk: loop {
        if visited % 1024 == 0 {
            crate::repo_scan_policy::check_deadline()?;
        }
        if cursor.goto_first_child() {
            depth = depth.saturating_add(1);
            visited = visited.saturating_add(1);
            if depth > RUST_SYNTAX_MAX_DEPTH {
                return Err(ScanError::Policy(format!(
                    "Rust syntax tree depth exceeds {RUST_SYNTAX_MAX_DEPTH}"
                )));
            }
            continue;
        }
        loop {
            if cursor.goto_next_sibling() {
                visited = visited.saturating_add(1);
                break;
            }
            if !cursor.goto_parent() {
                break 'walk;
            }
            depth = depth.saturating_sub(1);
        }
    }
    Ok(())
}

fn rust_qself_open(bytes: &[u8], index: usize) -> bool {
    let mut cursor = index;
    while cursor > 0 {
        cursor -= 1;
        let previous = bytes[cursor];
        if previous.is_ascii_whitespace() {
            continue;
        }
        if matches!(
            previous,
            b'(' | b'['
                | b'{'
                | b'='
                | b','
                | b';'
                | b':'
                | b'!'
                | b'|'
                | b'&'
                | b'?'
                | b'+'
                | b'-'
                | b'*'
                | b'/'
                | b'%'
                | b'^'
                | b'.'
        ) {
            return true;
        }
        if previous == b'>' {
            return true;
        }
        if previous.is_ascii_alphanumeric() || previous == b'_' {
            let end = cursor + 1;
            while cursor > 0 && (bytes[cursor - 1].is_ascii_alphanumeric() || bytes[cursor - 1] == b'_') {
                cursor -= 1;
            }
            return matches!(
                &bytes[cursor..end],
                b"return" | b"break" | b"yield" | b"if" | b"while" | b"match" | b"in" | b"as"
            );
        }
        return false;
    }
    true
}

fn rust_attribute_open(bytes: &[u8], index: usize) -> bool {
    let mut cursor = index;
    while cursor > 0 {
        cursor -= 1;
        match bytes[cursor] {
            byte if byte.is_ascii_whitespace() => {}
            b'#' => return true,
            b'!' => {
                while cursor > 0 {
                    cursor -= 1;
                    if !bytes[cursor].is_ascii_whitespace() {
                        return bytes[cursor] == b'#';
                    }
                }
                return false;
            }
            _ => return false,
        }
    }
    false
}

fn rust_angle_has_matching_close(bytes: &[u8], index: usize) -> Result<bool, ScanError> {
    #[derive(Clone, Copy)]
    enum State {
        Code,
        LineComment,
        BlockComment(usize),
        Quoted(u8),
    }

    let mut angle_depth = 0usize;
    let mut brace_depth = 0usize;
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut state = State::Code;
    let mut escaped = false;
    let mut cursor = index;
    while cursor < bytes.len() {
        if cursor % 4096 == 0 {
            crate::repo_scan_policy::check_deadline()?;
        }
        let byte = bytes[cursor];
        let next = bytes.get(cursor + 1).copied();
        match state {
            State::Code => {
                if let Some(end) = rust_raw_string_end(bytes, cursor)? {
                    cursor = end;
                } else {
                    match byte {
                        b'/' if next == Some(b'/') => {
                            state = State::LineComment;
                            cursor += 1;
                        }
                        b'/' if next == Some(b'*') => {
                            state = State::BlockComment(1);
                            cursor += 1;
                        }
                        b'"' => {
                            state = State::Quoted(byte);
                            escaped = false;
                        }
                        b'\'' if rust_char_literal_end(bytes, cursor).is_some() => {
                            cursor = rust_char_literal_end(bytes, cursor).unwrap_or(cursor);
                        }
                        b'{' => brace_depth = brace_depth.saturating_add(1),
                        b'}' if brace_depth > 0 => brace_depth -= 1,
                        b'(' => paren_depth = paren_depth.saturating_add(1),
                        b')' if paren_depth > 0 => paren_depth -= 1,
                        b'[' => bracket_depth = bracket_depth.saturating_add(1),
                        b']' if bracket_depth > 0 => bracket_depth -= 1,
                        b')' | b']' | b'}' if brace_depth == 0 && paren_depth == 0 && bracket_depth == 0 => {
                            return Ok(false);
                        }
                        b'<' if brace_depth == 0 => angle_depth = angle_depth.saturating_add(1),
                        b'>' if brace_depth == 0 && angle_depth > 0 => {
                            angle_depth -= 1;
                            if angle_depth == 0 {
                                return Ok(true);
                            }
                        }
                        b';' if angle_depth > 0 && brace_depth == 0 && paren_depth == 0 && bracket_depth == 0 => {
                            return Ok(false);
                        }
                        b'&' | b'|' | b'=' | b'!'
                            if angle_depth == 1
                                && brace_depth == 0
                                && paren_depth == 0
                                && bracket_depth == 0
                                && next == Some(byte) =>
                        {
                            return Ok(false);
                        }
                        _ => {}
                    }
                }
            }
            State::LineComment => {
                if byte == b'\n' {
                    state = State::Code;
                }
            }
            State::BlockComment(depth) => {
                if byte == b'/' && next == Some(b'*') {
                    state = State::BlockComment(depth.saturating_add(1));
                    cursor += 1;
                } else if byte == b'*' && next == Some(b'/') {
                    state = if depth == 1 {
                        State::Code
                    } else {
                        State::BlockComment(depth - 1)
                    };
                    cursor += 1;
                }
            }
            State::Quoted(quote) => {
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == quote {
                    state = State::Code;
                }
            }
        }
        cursor += 1;
    }
    Ok(false)
}

fn rust_closure_bar_open(bytes: &[u8], index: usize) -> bool {
    let mut cursor = index;
    while cursor > 0 {
        cursor -= 1;
        let previous = bytes[cursor];
        if previous.is_ascii_whitespace() {
            continue;
        }
        if matches!(previous, b'(' | b'[' | b'{' | b'=' | b',' | b';') {
            return true;
        }
        if previous == b'>' {
            while cursor > 0 {
                cursor -= 1;
                if bytes[cursor].is_ascii_whitespace() {
                    continue;
                }
                return bytes[cursor] == b'=';
            }
            return false;
        }
        if previous.is_ascii_alphanumeric() || previous == b'_' {
            let end = cursor + 1;
            while cursor > 0 && (bytes[cursor - 1].is_ascii_alphanumeric() || bytes[cursor - 1] == b'_') {
                cursor -= 1;
            }
            return matches!(&bytes[cursor..end], b"move" | b"async" | b"return");
        }
        return false;
    }
    true
}

fn rust_type_prefix_run(bytes: &[u8], start: usize) -> usize {
    fn skip_space(bytes: &[u8], cursor: &mut usize) {
        while bytes.get(*cursor).is_some_and(u8::is_ascii_whitespace) {
            *cursor += 1;
        }
    }
    fn consume_word(bytes: &[u8], cursor: &mut usize, word: &[u8]) -> bool {
        if bytes.get(*cursor..).is_some_and(|tail| tail.starts_with(word))
            && !bytes
                .get(*cursor + word.len())
                .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        {
            *cursor += word.len();
            true
        } else {
            false
        }
    }

    let mut cursor = start;
    let mut depth = 0usize;
    loop {
        skip_space(bytes, &mut cursor);
        match bytes.get(cursor).copied() {
            Some(b'&') => {
                depth = depth.saturating_add(1);
                cursor += 1;
                skip_space(bytes, &mut cursor);
                if bytes.get(cursor) == Some(&b'\'') {
                    cursor += 1;
                    while bytes
                        .get(cursor)
                        .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
                    {
                        cursor += 1;
                    }
                    skip_space(bytes, &mut cursor);
                }
                let _ = consume_word(bytes, &mut cursor, b"mut");
            }
            Some(b'*') => {
                cursor += 1;
                skip_space(bytes, &mut cursor);
                if !consume_word(bytes, &mut cursor, b"const") && !consume_word(bytes, &mut cursor, b"mut") {
                    break;
                }
                depth = depth.saturating_add(1);
            }
            _ => break,
        }
    }
    depth
}

fn rust_raw_string_end(bytes: &[u8], start: usize) -> Result<Option<usize>, ScanError> {
    let r_index = if bytes.get(start) == Some(&b'r') {
        start
    } else if bytes.get(start) == Some(&b'b') && bytes.get(start + 1) == Some(&b'r') {
        start + 1
    } else {
        return Ok(None);
    };
    let mut quote = r_index + 1;
    while bytes.get(quote) == Some(&b'#') {
        quote += 1;
    }
    if bytes.get(quote) != Some(&b'"') {
        return Ok(None);
    }
    let hashes = quote.saturating_sub(r_index + 1);
    let mut cursor = quote + 1;
    while cursor < bytes.len() {
        if cursor % 4096 == 0 {
            crate::repo_scan_policy::check_deadline()?;
        }
        if bytes[cursor] == b'"' && (0..hashes).all(|offset| bytes.get(cursor + 1 + offset) == Some(&b'#')) {
            return Ok(Some(cursor + hashes));
        }
        cursor += 1;
    }
    Ok(Some(bytes.len().saturating_sub(1)))
}

fn rust_char_literal_end(bytes: &[u8], start: usize) -> Option<usize> {
    let value_start = start.checked_add(1)?;
    let first = *bytes.get(value_start)?;
    let closing = if first == b'\\' {
        match *bytes.get(value_start + 1)? {
            b'x' => {
                if bytes
                    .get(value_start + 2..value_start + 4)?
                    .iter()
                    .all(u8::is_ascii_hexdigit)
                {
                    value_start + 4
                } else {
                    return None;
                }
            }
            b'u' if bytes.get(value_start + 2) == Some(&b'{') => {
                let mut cursor = value_start + 3;
                let mut digits = 0usize;
                while bytes.get(cursor).is_some_and(u8::is_ascii_hexdigit) && digits < 6 {
                    cursor += 1;
                    digits += 1;
                }
                if digits == 0 || bytes.get(cursor) != Some(&b'}') {
                    return None;
                }
                cursor + 1
            }
            b'\\' | b'\'' | b'"' | b'n' | b'r' | b't' | b'0' => value_start + 2,
            _ => return None,
        }
    } else {
        let scalar = std::str::from_utf8(bytes.get(value_start..)?).ok()?.chars().next()?;
        if scalar == '\n' || scalar == '\r' || scalar == '\'' {
            return None;
        }
        value_start + scalar.len_utf8()
    };
    (bytes.get(closing) == Some(&b'\'')).then_some(closing)
}

pub fn run_scan_regex_at(root: &Path) -> Result<WorkspaceScan, ScanError> {
    crate::repo_scan_policy::check_deadline()?;
    let started_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64);
    let started_inst = std::time::Instant::now();
    let scan_id = format!("ws_{started_ms}_{}", uuid::Uuid::new_v4().simple());

    let mut scan = WorkspaceScan {
        scan_id,
        root_path: root.display().to_string(),
        started_at_unix_ms: started_ms,
        ..Default::default()
    };

    // ── 1. Find crates by walking for Cargo.toml files. ───────────────
    let mut cargo_files: Vec<PathBuf> = Vec::new();
    let mut discovery_error = None;
    walk_dir(root, root, &mut |rel_path, abs_path| {
        if discovery_error.is_some() {
            return;
        }
        if abs_path.file_name().and_then(|n| n.to_str()) == Some("Cargo.toml") && rel_path != Path::new("Cargo.toml")
        // skip workspace root manifest
        {
            match crate::repo_scan_policy::charge_generated_work(
                1,
                abs_path.as_os_str().len(),
                "Cargo manifest discovery index",
            ) {
                Ok(()) => cargo_files.push(abs_path.to_path_buf()),
                Err(error) => discovery_error = Some(error),
            }
        }
    })?;
    if let Some(error) = discovery_error {
        return Err(error);
    }
    crate::repo_scan_policy::check_deadline()?;

    // For each crate, parse minimum metadata + collect rs files.
    let mut crate_dirs: HashMap<String, PathBuf> = HashMap::new(); // name → crate dir
    let mut crate_internal_deps: HashMap<String, Vec<String>> = HashMap::new();
    for cargo in &cargo_files {
        crate::repo_scan_policy::check_deadline()?;
        let crate_dir = cargo.parent().unwrap_or(root).to_path_buf();
        let toml = read_scan_to_string(cargo)?;
        let name = parse_crate_name(&toml).unwrap_or_else(|| {
            crate_dir
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("?")
                .to_string()
        });
        let internal = parse_internal_path_deps(&toml)?;
        crate::repo_scan_policy::charge_generated_work(
            2,
            name.len().saturating_mul(2).saturating_add(crate_dir.as_os_str().len()),
            "crate manifest indexes",
        )?;
        crate_dirs.insert(name.clone(), crate_dir);
        crate_internal_deps.insert(name, internal);
    }

    // Walk every .rs file under each crate's src/.
    let mut files_by_crate: HashMap<String, Vec<PathBuf>> = HashMap::new();
    for (name, dir) in &crate_dirs {
        crate::repo_scan_policy::check_deadline()?;
        let src = dir.join("src");
        if !crate::repo_scan_policy::scan_path_is_directory(&src)? {
            continue;
        }
        let mut acc: Vec<PathBuf> = Vec::new();
        let mut discovery_error = None;
        walk_dir(&src, &src, &mut |_rel, abs| {
            if discovery_error.is_some() {
                return;
            }
            if abs.extension().and_then(|e| e.to_str()) == Some("rs") {
                match crate::repo_scan_policy::charge_generated_work(
                    1,
                    abs.as_os_str().len(),
                    "Rust source discovery index",
                ) {
                    Ok(()) => acc.push(abs.to_path_buf()),
                    Err(error) => discovery_error = Some(error),
                }
            }
        })?;
        if let Some(error) = discovery_error {
            return Err(error);
        }
        crate::repo_scan_policy::charge_generated_work(1, name.len(), "crate source index")?;
        files_by_crate.insert(name.clone(), acc);
    }

    // Pre-build a lookup for resolving `use crate_name::...` in the dep step.
    crate::repo_scan_policy::charge_generated_work(
        crate_dirs.len(),
        crate_dirs.keys().map(String::len).sum(),
        "known crate index",
    )?;
    let known_crate_names: BTreeSet<String> = crate_dirs.keys().cloned().collect();

    // ── 2. Per-crate: parse files, extract symbols + deps + stubs ─────
    for (cname, files) in &files_by_crate {
        crate::repo_scan_policy::check_deadline()?;
        // crate_dirs was populated from the same files_by_crate keys above —
        // the missing-key branch is structurally unreachable but we handle it
        // gracefully rather than panic.
        let Some(crate_root) = crate_dirs.get(cname).cloned() else {
            continue;
        };
        let mut crate_loc = 0usize;
        let mut crate_file_count = 0usize;

        for abs in files {
            crate::repo_scan_policy::check_deadline()?;
            let rel = abs.strip_prefix(root).map_or_else(|_| abs.clone(), |p| p.to_path_buf());
            let rel_str = rel.display().to_string();
            let module_path = infer_module_path(cname, &crate_root, abs);

            let src = read_scan_to_string(abs)?;
            crate::repo_scan_policy::charge_source_parse_work(&src, "Rust regex scanner parser work")?;
            let loc = src.lines().count();
            crate_loc += loc;
            crate_file_count += 1;

            let mut file_symbol_count = 0usize;
            let mut file_stub_count = 0usize;
            // The stub detector lives in this file. Its own source contains
            // the literal `todo!(`, `unimplemented!(`, `panic!(...)` strings
            // as detector tokens (and again as test inputs), which trip the
            // detector against itself. Skip stub-scanning when we encounter
            // this file so the report stays trustworthy.
            //
            // NOTE: this path is this file's own location, so it must be
            // updated whenever the file moves — a stale value silently turns
            // the guard off and the scanner starts reporting itself as stubbed.
            // `full_scan_emits_routes_and_references` is what catches it.
            let is_self_source = rel_str.ends_with("corecrux-workspace-scan/src/workspace_scan.rs");

            for (line_no, line) in src.lines().enumerate() {
                if line_no % 256 == 0 {
                    crate::repo_scan_policy::check_deadline()?;
                }
                let line_num = line_no + 1;
                // Symbols.
                if let Some((kind, name, is_pub)) = parse_symbol_line(line) {
                    crate::repo_scan_policy::charge_generated_work(
                        1,
                        cname
                            .len()
                            .saturating_add(module_path.len())
                            .saturating_add(rel_str.len())
                            .saturating_add(kind.len())
                            .saturating_add(name.len()),
                        "scan output",
                    )?;
                    scan.symbols.push(SymbolInfo {
                        crate_name: cname.clone(),
                        module_path: module_path.clone(),
                        file_rel_path: rel_str.clone(),
                        line: line_num,
                        kind: kind.to_string(),
                        name: name.clone(),
                        is_pub,
                    });
                    file_symbol_count += 1;
                }
                // Stubs (skip the detector's own source — see comment above).
                if !is_self_source {
                    if let Some((kind, snippet)) = parse_stub_line(line) {
                        crate::repo_scan_policy::charge_generated_work(
                            1,
                            cname
                                .len()
                                .saturating_add(rel_str.len())
                                .saturating_add(kind.len())
                                .saturating_add(snippet.len()),
                            "scan output",
                        )?;
                        scan.stubs.push(StubHit {
                            crate_name: cname.clone(),
                            file_rel_path: rel_str.clone(),
                            line: line_num,
                            kind: kind.to_string(),
                            snippet,
                        });
                        file_stub_count += 1;
                    }
                }
                // `use` statements → dep edges.
                if let Some(target_module) = parse_use_target(line, cname, &known_crate_names) {
                    crate::repo_scan_policy::charge_generated_work(
                        1,
                        cname
                            .len()
                            .saturating_add(rel_str.len())
                            .saturating_add(target_module.len())
                            .saturating_add(line.len()),
                        "scan output",
                    )?;
                    scan.deps.push(DepEdge {
                        from_crate: cname.clone(),
                        from_file: rel_str.clone(),
                        to_module: target_module,
                        raw: line.trim().to_string(),
                    });
                }
            }

            // Extract the file-level `//!` header (consecutive `//!` lines
            // from the top of the file, allowing leading blank lines / `//`
            // copyright comments). Cheap; one line-by-line pass.
            let (doc_full, doc_summary) = parse_file_doc_header(&src);
            let is_test_file = looks_like_test_file(&rel_str, &src);

            crate::repo_scan_policy::charge_generated_work(
                1,
                rel_str
                    .len()
                    .saturating_add(cname.len())
                    .saturating_add(module_path.len())
                    .saturating_add(doc_full.as_deref().map_or(0, str::len)),
                "scan output",
            )?;
            scan.files.push(FileInfo {
                rel_path: rel_str,
                crate_name: cname.clone(),
                module_path,
                loc,
                symbol_count: file_symbol_count,
                stub_count: file_stub_count,
                doc_summary,
                doc_full,
                defines: Vec::new(),
                references: Vec::new(),
                referenced_by: Vec::new(),
                is_test_file,
            });
        }

        let rel_path = crate_root
            .strip_prefix(root)
            .map_or_else(|_| crate_root.display().to_string(), |p| p.display().to_string());
        let internal_deps = crate_internal_deps.remove(cname).unwrap_or_default();
        crate::repo_scan_policy::charge_generated_work(
            1,
            cname
                .len()
                .saturating_add(rel_path.len())
                .saturating_add(internal_deps.iter().map(String::len).sum::<usize>()),
            "scan output",
        )?;
        scan.crates.push(CrateInfo {
            name: cname.clone(),
            rel_path,
            internal_deps,
            file_count: crate_file_count,
            total_loc: crate_loc,
        });
    }

    // ── 2.5. File-level call edges + route detection. ─────────────────
    // Builds three indexes off the symbol table from pass 2, then walks each
    // file once more looking for call sites + axum `.route(...)` declarations.
    // Cost is roughly equivalent to one extra pass over the source corpus;
    // measured ~1× the existing scan time on the Crux workspace.
    {
        // Reverse index: symbol name → indexes into scan.symbols. Built from
        // both pub and private symbols so intra-file calls resolve too.
        let mut symbol_by_name: HashMap<String, Vec<usize>> = HashMap::new();
        // Quick lookup: file rel_path → index into scan.files.
        let mut file_idx_by_path: HashMap<String, usize> = HashMap::new();
        for (i, f) in scan.files.iter().enumerate() {
            if i % 256 == 0 {
                crate::repo_scan_policy::check_deadline()?;
            }
            crate::repo_scan_policy::charge_generated_work(1, f.rel_path.len(), "file path index")?;
            file_idx_by_path.insert(f.rel_path.clone(), i);
        }
        for (i, s) in scan.symbols.iter().enumerate() {
            if i % 256 == 0 {
                crate::repo_scan_policy::check_deadline()?;
            }
            // Only index callable symbols. Structs/enums/types appear in call
            // expressions too (constructors), but the resulting edges add a lot
            // of noise; restrict to fn for the storyline view.
            if s.kind == "fn" {
                crate::repo_scan_policy::charge_generated_work(1, s.name.len(), "symbol name index")?;
                symbol_by_name.entry(s.name.clone()).or_default().push(i);
            }
        }
        // Denormalise `defines` into FileInfo for cheap downstream queries.
        let mut define_names_by_file: HashMap<usize, HashSet<String>> = HashMap::new();
        for (idx, s) in scan.symbols.iter().enumerate() {
            if idx % 256 == 0 {
                crate::repo_scan_policy::check_deadline()?;
            }
            if let Some(file_idx) = file_idx_by_path.get(&s.file_rel_path).copied() {
                if define_names_by_file.entry(file_idx).or_default().insert(s.name.clone()) {
                    crate::repo_scan_policy::charge_generated_work(
                        2,
                        s.name.len().saturating_mul(2),
                        "file definition index and output",
                    )?;
                    scan.files[file_idx].defines.push(s.name.clone());
                }
            }
        }

        // Per-file accumulator. Edge key carries the containing fn (M5):
        // (to_file, to_symbol, from_symbol_or_empty). When from_symbol is
        // unknown (top-level / module-init code), we use "" so the BTreeMap
        // can still be deterministic.
        type EdgeKey = (String, String, String);
        let mut per_file_edges: HashMap<usize, std::collections::BTreeMap<EdgeKey, usize>> = HashMap::new();

        // Build a per-file (line → enclosing fn name) cursor for M5. Each
        // file gets a sorted Vec<(line, name)> of fn definitions; resolving
        // the enclosing fn for a call site is then a binary search.
        let mut fn_cursor_by_file: HashMap<String, Vec<(usize, String)>> = HashMap::new();
        for (idx, s) in scan.symbols.iter().enumerate() {
            if idx % 256 == 0 {
                crate::repo_scan_policy::check_deadline()?;
            }
            if s.kind == "fn" {
                crate::repo_scan_policy::charge_generated_work(
                    1,
                    s.file_rel_path.len().saturating_add(s.name.len()),
                    "function cursor index",
                )?;
                fn_cursor_by_file
                    .entry(s.file_rel_path.clone())
                    .or_default()
                    .push((s.line, s.name.clone()));
            }
        }
        for v in fn_cursor_by_file.values_mut() {
            crate::repo_scan_policy::check_deadline()?;
            v.sort_by_key(|(l, _)| *l);
        }

        for (cname, files) in &files_by_crate {
            crate::repo_scan_policy::check_deadline()?;
            for abs in files {
                crate::repo_scan_policy::check_deadline()?;
                let rel = abs.strip_prefix(root).map_or_else(|_| abs.clone(), |p| p.to_path_buf());
                let rel_str = rel.display().to_string();
                let from_idx = match file_idx_by_path.get(&rel_str) {
                    Some(i) => *i,
                    None => continue,
                };
                let src = read_scan_to_string(abs)?;

                // ── route detection ── handled at the file level so that
                // multi-line `.route(...)` declarations resolve correctly.
                if src.contains(".route(") {
                    for route in parse_routes_in_source(&src, &rel_str)? {
                        // Resolve handler_fn via symbol_by_name (prefer same
                        // crate, then any single match). Failure modes split
                        // into two diagnostic reasons:
                        //   - "not_found": no fn with this name anywhere
                        //   - "ambiguous": multiple candidates, no clear winner
                        let mut resolved_file: Option<String> = None;
                        let mut resolved_line: Option<usize> = None;
                        let mut diag_reason: Option<&'static str> = None;
                        match symbol_by_name.get(&route.handler_fn) {
                            None => {
                                diag_reason = Some("not_found");
                            }
                            Some(candidates) => {
                                let same_crate = unique_matching_index(candidates, |index| {
                                    scan.symbols[index].crate_name == *cname
                                })?;
                                let pick = if same_crate.is_some() {
                                    same_crate
                                } else if candidates.len() == 1 {
                                    Some(candidates[0])
                                } else {
                                    None
                                };
                                if let Some(idx) = pick {
                                    resolved_file = Some(scan.symbols[idx].file_rel_path.clone());
                                    resolved_line = Some(scan.symbols[idx].line);
                                } else {
                                    diag_reason = Some("ambiguous");
                                }
                            }
                        }
                        if let Some(reason) = diag_reason {
                            crate::repo_scan_policy::charge_generated_work(
                                1,
                                route
                                    .method
                                    .len()
                                    .saturating_add(route.path.len())
                                    .saturating_add(route.handler_fn.len())
                                    .saturating_add(route.source_file.len())
                                    .saturating_add(reason.len()),
                                "unresolved route output",
                            )?;
                            scan.diagnostics.unresolved_routes.push(UnresolvedRoute {
                                method: route.method.clone(),
                                path: route.path.clone(),
                                handler_fn: route.handler_fn.clone(),
                                source_file: route.source_file.clone(),
                                source_line: route.source_line,
                                reason: reason.to_string(),
                            });
                        }
                        crate::repo_scan_policy::charge_generated_work(
                            1,
                            route
                                .method
                                .len()
                                .saturating_add(route.path.len())
                                .saturating_add(route.handler_fn.len())
                                .saturating_add(route.source_file.len())
                                .saturating_add(resolved_file.as_deref().map_or(0, str::len)),
                            "route output",
                        )?;
                        scan.routes.push(RouteHit {
                            method: route.method,
                            path: route.path,
                            handler_fn: route.handler_fn,
                            framework: None,
                            handler_file: resolved_file,
                            handler_line: resolved_line,
                            source_file: route.source_file,
                            source_line: route.source_line,
                        });
                    }
                }

                for (line_no, line) in src.lines().enumerate() {
                    if line_no % 256 == 0 {
                        crate::repo_scan_policy::check_deadline()?;
                    }
                    let trimmed = line.trim_start();
                    if trimmed.starts_with("//") {
                        continue;
                    }

                    // ── call-site detection ───
                    // Walk the line looking for `<ident_path>(`. We don't try
                    // to parse Rust properly — a regex-style scan over ASCII
                    // identifier characters and `::` is enough to surface most
                    // cross-file calls. Macro invocations end with `!` which
                    // we explicitly reject.
                    for call_name in scan_call_sites(line)? {
                        // Resolve.
                        let candidates = match symbol_by_name.get(&call_name) {
                            Some(c) => c,
                            None => continue,
                        };
                        // Prefer same-file matches first (handles intra-file
                        // private fn calls). If none, fall back to same-crate
                        // singleton, then global singleton.
                        let same_file =
                            first_matching_index(candidates, |index| scan.symbols[index].file_rel_path == rel_str)?;
                        let target_idx = if same_file.is_some() {
                            // Resolve to first same-file match. Single hit is
                            // the common case; multiple-in-one-file is rare
                            // and usually a test mod reusing the fn name.
                            same_file
                        } else {
                            let same_crate =
                                unique_matching_index(candidates, |index| scan.symbols[index].crate_name == *cname)?;
                            if same_crate.is_some() {
                                same_crate
                            } else if candidates.len() == 1 {
                                Some(candidates[0])
                            } else {
                                None // ambiguous, skip
                            }
                        };
                        if let Some(idx) = target_idx {
                            let target = &scan.symbols[idx];
                            // Don't emit a self-loop edge from a fn declaration
                            // to itself (the declaration looks like a call site
                            // when scanned naively: `pub fn foo(` matches).
                            // Skip if the line begins with `fn ` or `pub fn ` etc.
                            if line.trim_start().starts_with("fn ")
                                || line.trim_start().starts_with("pub fn ")
                                || line.trim_start().starts_with("pub(crate) fn ")
                                || line.trim_start().starts_with("pub(super) fn ")
                                || line.trim_start().starts_with("async fn ")
                                || line.trim_start().starts_with("pub async fn ")
                            {
                                continue;
                            }
                            // Resolve the enclosing fn (M5). Binary-search the
                            // sorted (line, name) list for this file to find
                            // the latest fn whose declaration line ≤ current.
                            let from_symbol = fn_cursor_by_file
                                .get(&rel_str)
                                .and_then(|cursor| {
                                    let line_num = line_no + 1;
                                    let pos = cursor.partition_point(|(l, _)| *l <= line_num);
                                    if pos == 0 {
                                        None
                                    } else {
                                        Some(cursor[pos - 1].1.clone())
                                    }
                                })
                                .unwrap_or_default();
                            let key = (target.file_rel_path.clone(), target.name.clone(), from_symbol);
                            let edges = per_file_edges.entry(from_idx).or_default();
                            match edges.entry(key) {
                                std::collections::btree_map::Entry::Occupied(mut entry) => {
                                    *entry.get_mut() = entry.get().saturating_add(1);
                                }
                                std::collections::btree_map::Entry::Vacant(entry) => {
                                    let key = entry.key();
                                    crate::repo_scan_policy::charge_generated_work(
                                        1,
                                        key.0.len().saturating_add(key.1.len()).saturating_add(key.2.len()),
                                        "reference edge index",
                                    )?;
                                    entry.insert(1);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Emit accumulated edges into FileInfo.references.
        let mut total_edges = 0usize;
        for (edge_idx, (from_idx, edges)) in per_file_edges.into_iter().enumerate() {
            if edge_idx % 256 == 0 {
                crate::repo_scan_policy::check_deadline()?;
            }
            let from_path = scan.files[from_idx].rel_path.clone();
            for ((to_file, to_symbol, from_symbol), call_count) in edges {
                let same_file = to_file == from_path;
                let from_symbol = if from_symbol.is_empty() {
                    None
                } else {
                    Some(from_symbol)
                };
                crate::repo_scan_policy::charge_generated_work(
                    1,
                    to_file
                        .len()
                        .saturating_add(to_symbol.len())
                        .saturating_add(from_symbol.as_deref().map_or(0, str::len)),
                    "reference edge output",
                )?;
                scan.files[from_idx].references.push(FileReference {
                    to_file,
                    to_symbol,
                    call_count,
                    same_file,
                    from_symbol,
                });
                total_edges += 1;
            }
        }
        scan.stats.file_reference_count = total_edges;
        scan.stats.route_count = scan.routes.len();

        // Build the inverse `referenced_by` index. Cross-file only — same-file
        // edges would just self-list every file, which adds noise.
        let mut inverse: HashMap<String, BTreeSet<String>> = HashMap::new();
        for (file_idx, f) in scan.files.iter().enumerate() {
            if file_idx % 256 == 0 {
                crate::repo_scan_policy::check_deadline()?;
            }
            for r in &f.references {
                if !r.same_file {
                    let sources = inverse.entry(r.to_file.clone()).or_default();
                    if !sources.contains(&f.rel_path) {
                        crate::repo_scan_policy::charge_generated_work(
                            1,
                            r.to_file.len().saturating_add(f.rel_path.len()),
                            "inverse reference index",
                        )?;
                        sources.insert(f.rel_path.clone());
                    }
                }
            }
        }
        for (file_idx, f) in scan.files.iter_mut().enumerate() {
            if file_idx % 256 == 0 {
                crate::repo_scan_policy::check_deadline()?;
            }
            if let Some(set) = inverse.remove(&f.rel_path) {
                crate::repo_scan_policy::charge_generated_work(
                    set.len(),
                    set.iter().map(String::len).sum(),
                    "inverse reference output",
                )?;
                f.referenced_by = set.into_iter().collect();
            }
        }
    }

    // ── 3. Dead-code detection (heuristic). ───────────────────────────
    // For each pub symbol, scan all .rs files for an occurrence pattern.
    // Skip names that are too short / common (`new`, `len`, `is_empty`, ...) —
    // they would hit everywhere and produce no signal.
    let common_names: BTreeSet<&str> = [
        "new", "default", "len", "is_empty", "from", "into", "as_str", "as_ref", "clone", "drop", "fmt", "next",
        "iter", "build", "ok", "err", "some", "none", "main", "init",
    ]
    .iter()
    .copied()
    .collect();

    // Build one workspace corpus. Keeping a per-crate copy and then cloning it
    // into this buffer doubled the largest scan allocation.
    let mut workspace_corpus = String::new();
    for files in files_by_crate.values() {
        crate::repo_scan_policy::check_deadline()?;
        for abs in files {
            crate::repo_scan_policy::check_deadline()?;
            let src = read_scan_to_string(abs)?;
            crate::repo_scan_policy::charge_generated_work(0, src.len().saturating_add(1), "dead-code search corpus")?;
            if !workspace_corpus.is_empty() {
                workspace_corpus.push('\n');
            }
            workspace_corpus.push_str(&src);
        }
    }
    crate::repo_scan_policy::check_deadline()?;

    for (idx, sym) in scan.symbols.iter().enumerate() {
        if idx % 64 == 0 {
            crate::repo_scan_policy::check_deadline()?;
        }
        if !sym.is_pub {
            continue;
        }
        if sym.name.starts_with('_') {
            continue;
        }
        if sym.name.len() < 4 {
            continue;
        }
        if common_names.contains(sym.name.as_str()) {
            continue;
        }
        // Skip the declaration site itself by counting occurrences and
        // requiring more than one (the declaration is one occurrence).
        let needle = sym.name.as_str();
        let total_hits = count_substring(&workspace_corpus, needle)?;
        // Heuristic: a symbol referenced ≤1 time is likely dead. Confidence is
        // lower for short names and names that appear in commit messages
        // (we'd need a more careful AST pass to be sure).
        if total_hits <= 1 {
            crate::repo_scan_policy::charge_generated_work(
                1,
                sym.crate_name
                    .len()
                    .saturating_add(sym.module_path.len())
                    .saturating_add(sym.file_rel_path.len())
                    .saturating_add(sym.kind.len())
                    .saturating_add(sym.name.len())
                    .saturating_add(96),
                "dead-code output",
            )?;
            scan.dead_code.push(DeadSymbol {
                crate_name: sym.crate_name.clone(),
                module_path: sym.module_path.clone(),
                file_rel_path: sym.file_rel_path.clone(),
                line: sym.line,
                kind: sym.kind.clone(),
                name: sym.name.clone(),
                confidence: 0.6,
                note: "no other references found in workspace (regex-based; may miss macro / dynamic dispatch)"
                    .to_string(),
            });
        }
    }

    // ── 4. Stats roll-up. ──────────────────────────────────────────────
    let route_count = scan.routes.len();
    let file_reference_count = scan.files.iter().map(|f| f.references.len()).sum();
    let doc_coverage_files = scan.files.iter().filter(|f| f.doc_summary.is_some()).count();
    let mut routes_by_crate: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    let crate_by_file: HashMap<&str, &str> = scan
        .files
        .iter()
        .map(|file| (file.rel_path.as_str(), file.crate_name.as_str()))
        .collect();
    for (route_idx, r) in scan.routes.iter().enumerate() {
        if route_idx % 256 == 0 {
            crate::repo_scan_policy::check_deadline()?;
        }
        if let Some(crate_name) = r
            .handler_file
            .as_deref()
            .and_then(|handler_file| crate_by_file.get(handler_file))
        {
            *routes_by_crate.entry((*crate_name).to_string()).or_insert(0) += 1;
        }
    }
    scan.stats = ScanStats {
        crate_count: scan.crates.len(),
        file_count: scan.files.len(),
        total_loc: scan.files.iter().map(|f| f.loc).sum(),
        symbol_count: scan.symbols.len(),
        dep_count: scan.deps.len(),
        stub_count: scan.stubs.len(),
        dead_code_count: scan.dead_code.len(),
        route_count,
        file_reference_count,
        external_dep_count: scan.external_deps.len(),
        doc_coverage_files,
        routes_by_crate,
    };

    let elapsed_ms = started_inst.elapsed().as_millis() as u64;
    scan.finished_at_unix_ms = scan.started_at_unix_ms + elapsed_ms;
    scan.duration_ms = elapsed_ms;
    Ok(scan)
}

/// Entity the newest scan is written to. One row, overwritten each scan.
///
/// Shared by the writer (`http::workspace::post_scan`) and both readers, so a
/// rename cannot desynchronise them — which is exactly how the previous
/// text-search lookup failed silently.
pub const LATEST_SCAN_ENTITY: &str = "__workspace_scan__::latest";
/// Fact key holding the serialised scan.
pub const SCAN_KEY: &str = "content";

/// Read the most recent persisted scan from the fact store, if any.
pub async fn load_latest(
    fact_store: &std::sync::Arc<tokio::sync::RwLock<corecrux_memory::FactStore>>,
) -> Option<WorkspaceScan> {
    let store = fact_store.read().await;
    // Exact-entity lookup, NOT a `query:` text search.
    //
    // `query:` is not a prefix scan and not BM25 — an earlier version of this
    // comment said length normalisation buried the fact, which was wrong about
    // the mechanism though right that the lookup failed. What `query:` actually
    // does (`corecrux_memory::fact_store::query_inner`) is one of two things:
    // a lowercase SUBSTRING match over value/key/entity, or — when a dense
    // provider is configured — nothing at all, because keyword filtering is
    // skipped and every fact is ranked by cosine similarity instead. Either way
    // the result is then truncated to `top_k`, so a specific entity can be
    // ranked out by unrelated facts and the caller sees an empty result rather
    // than an error.
    //
    // There is exactly one entity to fetch and its id is a constant. Asking for
    // it by name cannot be ranked out.
    let result = store.query(&corecrux_memory::fact_store::FactQuery {
        min_effective_confidence: None,
        tenant_hash: None,
        query: None,
        entity: Some(LATEST_SCAN_ENTITY.to_string()),
        entity_prefix: None,
        top_k: 8,
        token_budget: None,
    });
    let latest = corecrux_memory::fact_store::dedup_latest(result.facts);
    let fact = latest
        .into_iter()
        .find(|f| f.entity == LATEST_SCAN_ENTITY && f.key == SCAN_KEY)?;
    let mut scan = serde_json::from_str::<WorkspaceScan>(&fact.value).ok()?;
    redact_self_workspace_paths(&mut scan);
    Some(scan)
}

// ─────────────────────────── Storyline composer ───────────────────────
// Builds a file-level call tree starting from a chosen root file. Used by
// both the agent surface (text/JSON over HTTP + MCP) and the human Story
// panel. Edge model: aggregate FileInfo.references by `to_file`, summing
// call counts and collecting the symbols that this edge represents.

const STORYLINE_DEFAULT_DEPTH: usize = 5;
const STORYLINE_MAX_NODES: usize = 200;

#[derive(Debug, Clone, Serialize)]
pub struct StorylineNode {
    pub file: String,
    /// Module path of the file (e.g. `corecruxd::http::workspace`).
    pub module_path: String,
    /// Crate the file belongs to.
    pub crate_name: String,
    /// First sentence of the file's `//!` header, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doc_summary: Option<String>,
    pub depth: usize,
    /// At depth 0, the entry symbol (handler fn name). At depth>0, the
    /// symbols this file is called for from the parent (joined with ", ").
    pub edge_symbols: Vec<String>,
    /// Sum of call counts for all `edge_symbols` (depth>0). 0 at depth 0.
    pub edge_call_count: usize,
    /// True if the parent edge was intra-file.
    pub same_file: bool,
    pub children: Vec<StorylineNode>,
    /// When true, this file's outgoing edges were truncated by the limits.
    /// The agent / human view should render a "+N more" affordance.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
    /// True when this node was already visited earlier in the BFS — the
    /// edge into it was kept (so the cycle is visible) but its children
    /// were not re-expanded. Tree-art renders a `↻` badge for these.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub cycle: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Storyline {
    /// What rooted this storyline. One of: a route entry (set if a route
    /// matched the request) or just a file path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route: Option<RouteHit>,
    pub root_file: String,
    pub root: StorylineNode,
    pub stats: StorylineStats,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct StorylineStats {
    pub total_nodes: usize,
    pub max_depth_reached: usize,
    pub truncated_branches: usize,
    /// How many BFS edges hit a file already in the visited set. Non-zero
    /// = the call graph contains cycles between the involved files.
    pub cycle_back_edges: usize,
}

/// Build a storyline tree rooted at `root_file`. If `entry_symbol` is given,
/// it's surfaced as the root node's edge_symbols (for routes, this is the
/// handler fn name). BFS, capped at `STORYLINE_DEFAULT_DEPTH` and
/// `STORYLINE_MAX_NODES` total nodes. When `include_tests` is false, edges
/// pointing at files marked `is_test_file` are skipped — this keeps the
/// default storyline focused on production call paths.
pub fn compose_storyline_for_file(
    scan: &WorkspaceScan,
    root_file: &str,
    entry_symbol: Option<&str>,
    include_tests: bool,
) -> Option<Storyline> {
    let by_path: HashMap<&str, &FileInfo> = scan.files.iter().map(|f| (f.rel_path.as_str(), f)).collect();
    let root_info = by_path.get(root_file).copied()?;
    let mut total = 1usize;
    let mut truncated_branches = 0usize;
    let mut max_depth = 0usize;
    let mut cycle_back_edges = 0usize;
    let mut visited: BTreeSet<String> = BTreeSet::new();
    visited.insert(root_file.to_string());
    let root_node = expand_node(
        root_info,
        entry_symbol.map(|s| vec![s.to_string()]).unwrap_or_default(),
        0,
        false,
        0,
        &by_path,
        include_tests,
        &mut visited,
        &mut total,
        &mut truncated_branches,
        &mut max_depth,
        &mut cycle_back_edges,
    );
    Some(Storyline {
        route: None,
        root_file: root_file.to_string(),
        root: root_node,
        stats: StorylineStats {
            total_nodes: total,
            max_depth_reached: max_depth,
            truncated_branches,
            cycle_back_edges,
        },
    })
}

/// Convenience wrapper: compose a storyline rooted at a route's handler.
pub fn compose_storyline_for_route(scan: &WorkspaceScan, route: &RouteHit, include_tests: bool) -> Option<Storyline> {
    let handler_file = route.handler_file.as_deref()?;
    let mut s = compose_storyline_for_file(scan, handler_file, Some(&route.handler_fn), include_tests)?;
    s.route = Some(route.clone());
    Some(s)
}

#[allow(clippy::too_many_arguments)]
fn expand_node(
    info: &FileInfo,
    edge_symbols: Vec<String>,
    edge_call_count: usize,
    same_file: bool,
    depth: usize,
    by_path: &HashMap<&str, &FileInfo>,
    include_tests: bool,
    visited: &mut BTreeSet<String>,
    total: &mut usize,
    truncated_branches: &mut usize,
    max_depth: &mut usize,
    cycle_back_edges: &mut usize,
) -> StorylineNode {
    if depth > *max_depth {
        *max_depth = depth;
    }
    let mut children: Vec<StorylineNode> = Vec::new();
    if depth < STORYLINE_DEFAULT_DEPTH && *total < STORYLINE_MAX_NODES {
        // M5: when we know a single entry symbol for this node (e.g. the
        // route handler `post_scan`), filter the file's references to those
        // whose `from_symbol` matches. This makes the storyline tree show
        // only the calls *post_scan itself* makes, not the whole file's
        // outgoing edges. Falls back to the whole-file aggregate when we
        // have no entry symbol or no edges match the filter.
        let entry_filter: Option<&str> = if edge_symbols.len() == 1 {
            Some(edge_symbols[0].as_str())
        } else {
            None
        };
        let mut by_target: std::collections::BTreeMap<String, (Vec<String>, usize, bool)> =
            std::collections::BTreeMap::new();
        let mut matched_any = false;
        for r in &info.references {
            if !include_tests {
                if let Some(target) = by_path.get(r.to_file.as_str()) {
                    if target.is_test_file {
                        continue;
                    }
                }
            }
            if let Some(want) = entry_filter {
                if r.from_symbol.as_deref() != Some(want) {
                    continue;
                }
                matched_any = true;
            }
            let entry = by_target
                .entry(r.to_file.clone())
                .or_insert((Vec::new(), 0, r.same_file));
            if !entry.0.contains(&r.to_symbol) {
                entry.0.push(r.to_symbol.clone());
            }
            entry.1 += r.call_count;
        }
        // Fallback: if filtering yielded nothing (e.g. parent symbol wasn't
        // in the cursor — module-init code, or pre-M5 persisted scan), fall
        // back to the whole-file aggregate so the tree isn't empty.
        if entry_filter.is_some() && !matched_any {
            for r in &info.references {
                if !include_tests {
                    if let Some(target) = by_path.get(r.to_file.as_str()) {
                        if target.is_test_file {
                            continue;
                        }
                    }
                }
                let entry = by_target
                    .entry(r.to_file.clone())
                    .or_insert((Vec::new(), 0, r.same_file));
                if !entry.0.contains(&r.to_symbol) {
                    entry.0.push(r.to_symbol.clone());
                }
                entry.1 += r.call_count;
            }
        }
        // Sort by aggregate weight desc so the biggest dependencies bubble up.
        // Each entry: target_file -> (distinct symbols called, sum of call counts, same_file flag).
        type AggregatedEdge = (String, (Vec<String>, usize, bool));
        let mut ordered: Vec<AggregatedEdge> = by_target.into_iter().collect();
        ordered.sort_by(|a, b| b.1 .1.cmp(&a.1 .1));
        for (target_file, (symbols, count, same)) in ordered {
            if *total >= STORYLINE_MAX_NODES {
                *truncated_branches += 1;
                break;
            }
            // Cycle protection: don't re-expand a file we've already visited
            // in this storyline. We still emit a leaf node so the reader sees
            // the edge, but no children.
            let already_seen = visited.contains(&target_file);
            let target_info = match by_path.get(target_file.as_str()) {
                Some(i) => *i,
                None => continue,
            };
            *total += 1;
            visited.insert(target_file.clone());
            if already_seen {
                *cycle_back_edges += 1;
            }
            if already_seen || depth + 1 >= STORYLINE_DEFAULT_DEPTH {
                children.push(StorylineNode {
                    file: target_info.rel_path.clone(),
                    module_path: target_info.module_path.clone(),
                    crate_name: target_info.crate_name.clone(),
                    doc_summary: target_info.doc_summary.clone(),
                    depth: depth + 1,
                    edge_symbols: symbols,
                    edge_call_count: count,
                    same_file: same,
                    children: Vec::new(),
                    truncated: !target_info.references.is_empty() && !already_seen,
                    cycle: already_seen,
                });
            } else {
                children.push(expand_node(
                    target_info,
                    symbols,
                    count,
                    same,
                    depth + 1,
                    by_path,
                    include_tests,
                    visited,
                    total,
                    truncated_branches,
                    max_depth,
                    cycle_back_edges,
                ));
            }
        }
    } else if !info.references.is_empty() {
        *truncated_branches += 1;
    }
    StorylineNode {
        file: info.rel_path.clone(),
        module_path: info.module_path.clone(),
        crate_name: info.crate_name.clone(),
        doc_summary: info.doc_summary.clone(),
        depth,
        edge_symbols,
        edge_call_count,
        same_file,
        children,
        truncated: depth >= STORYLINE_DEFAULT_DEPTH && !info.references.is_empty(),
        cycle: false,
    }
}

/// Render a storyline as ascii tree-art for LLM consumption. Each line is
/// `<prefix><branch> file::symbol[s] (count)  — doc_summary`. Designed to be
/// round-tripped through a text-only context window.
pub fn format_storyline_tree(s: &Storyline) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    if let Some(route) = &s.route {
        let _ = writeln!(out, "{} {}", route.method, route.path);
    } else {
        let _ = writeln!(out, "ROOT {}", s.root_file);
    }
    render_node(&s.root, "", true, &mut out, true);
    let _ = write!(
        out,
        "\n[{} files, max depth {}, {} truncated branch(es)]\n",
        s.stats.total_nodes, s.stats.max_depth_reached, s.stats.truncated_branches
    );
    out
}

fn render_node(node: &StorylineNode, prefix: &str, is_root: bool, out: &mut String, is_last: bool) {
    use std::fmt::Write;
    if is_root {
        let branch = "└─";
        let display_symbols = if node.edge_symbols.is_empty() {
            "<root>".to_string()
        } else {
            node.edge_symbols.join(", ")
        };
        let _ = write!(
            out,
            "{}{} {}::{}",
            prefix,
            branch,
            short_file(&node.file),
            display_symbols
        );
        if let Some(doc) = &node.doc_summary {
            let _ = write!(out, "  — {doc}");
        }
        out.push('\n');
        let new_prefix = format!("{prefix}   ");
        let n = node.children.len();
        for (i, c) in node.children.iter().enumerate() {
            render_node(c, &new_prefix, false, out, i + 1 == n);
        }
    } else {
        let branch = if is_last { "└─" } else { "├─" };
        let same = if node.same_file { " (intra)" } else { "" };
        let weight = format_call_weight(node.edge_call_count);
        let _ = write!(
            out,
            "{}{} {}::{}{}{}",
            prefix,
            branch,
            short_file(&node.file),
            node.edge_symbols.join(", "),
            weight,
            same,
        );
        if let Some(doc) = &node.doc_summary {
            let _ = write!(out, "  — {doc}");
        }
        if node.cycle {
            out.push_str("  [cycle]");
        }
        if node.truncated {
            out.push_str("  [+more]");
        }
        out.push('\n');
        let cont = if is_last { "   " } else { "│  " };
        let new_prefix = format!("{}{}", prefix, cont);
        let n = node.children.len();
        for (i, c) in node.children.iter().enumerate() {
            render_node(c, &new_prefix, false, out, i + 1 == n);
        }
    }
}

fn short_file(path: &str) -> &str {
    // Drop the leading "crates/" so the tree is more readable.
    path.strip_prefix("crates/").unwrap_or(path)
}

/// M7: bucket the call-count display so single-digit and triple-digit
/// counts don't compete visually. Exact counts are still in the JSON
/// output for agents that traverse the graph; the tree renderer is human-
/// facing only.
fn format_call_weight(count: usize) -> String {
    match count {
        0 => String::new(),
        1 => String::new(),
        2..=9 => format!(" ({}x)", count),
        10..=49 => format!(" (many: {})", count),
        _ => format!(" (hot: {})", count),
    }
}

/// Compact integer-keyed JSON for agents that want to traverse the graph
/// themselves. Files are interned to small integer ids; edges become a
/// (from_id, to_id, count) list. Routes carry the entry chain (sequence of
/// file ids reachable in BFS from the handler).
pub fn storyline_compact_json(scan: &WorkspaceScan, include_tests: bool) -> serde_json::Value {
    let mut id_by_path: HashMap<String, usize> = HashMap::new();
    let mut files_block = Vec::with_capacity(scan.files.len());
    for (i, f) in scan.files.iter().enumerate() {
        id_by_path.insert(f.rel_path.clone(), i);
        files_block.push(serde_json::json!({
            "p": f.rel_path,
            "c": f.crate_name,
            "m": f.module_path,
            "d": f.doc_summary,
            "f": f.defines,
            "t": f.is_test_file,
        }));
    }
    let mut edges = Vec::new();
    for (i, f) in scan.files.iter().enumerate() {
        for r in &f.references {
            // Skip edges into test files when the caller didn't ask for them.
            if !include_tests {
                if let Some(target) = scan.files.iter().find(|x| x.rel_path == r.to_file) {
                    if target.is_test_file {
                        continue;
                    }
                }
            }
            if let Some(to_id) = id_by_path.get(&r.to_file) {
                edges.push(serde_json::json!([i, *to_id, r.call_count, r.to_symbol]));
            }
        }
    }
    let mut routes_block = Vec::new();
    for route in &scan.routes {
        let chain: Vec<usize> = match route.handler_file.as_ref() {
            Some(hf) => {
                if let Some(s) = compose_storyline_for_route(scan, route, include_tests) {
                    let mut ids = Vec::new();
                    collect_chain_ids(&s.root, &id_by_path, &mut ids);
                    ids
                } else {
                    id_by_path.get(hf).copied().into_iter().collect()
                }
            }
            None => Vec::new(),
        };
        let mut route_block = serde_json::json!({
            "m": route.method,
            "p": route.path,
            "h": route.handler_fn,
            "f": route.handler_file.as_ref().and_then(|p| id_by_path.get(p)),
            "chain": chain,
        });
        if let Some(framework) = &route.framework {
            route_block["fw"] = serde_json::Value::String(framework.clone());
        }
        routes_block.push(route_block);
    }
    serde_json::json!({
        "files": files_block,
        "edges": edges,
        "routes": routes_block,
    })
}

fn collect_chain_ids(node: &StorylineNode, id_by_path: &HashMap<String, usize>, out: &mut Vec<usize>) {
    if let Some(id) = id_by_path.get(&node.file) {
        if !out.contains(id) {
            out.push(*id);
        }
    }
    for c in &node.children {
        collect_chain_ids(c, id_by_path, out);
    }
}

// ────────────────────────── Internal helpers ──────────────────────────

/// Contained directory walker. Skips `target/`, `node_modules/`, and dot-dirs;
/// never follows symlinks; rejects repeated canonical directories; and charges
/// the active scan's shared depth/entry/byte/deadline budget.
pub fn walk_dir<F: FnMut(&Path, &Path)>(root: &Path, base: &Path, visit: &mut F) -> Result<(), ScanError> {
    walk_dir_filtered(root, base, None, |_| false, visit)
}

pub fn walk_dir_filtered<F, S>(
    root: &Path,
    base: &Path,
    max_depth: Option<usize>,
    skip_dir: S,
    visit: &mut F,
) -> Result<(), ScanError>
where
    F: FnMut(&Path, &Path),
    S: Fn(&str) -> bool,
{
    #[cfg(target_os = "linux")]
    if let Some(directory) = crate::repo_scan_policy::open_active_scan_directory(base)? {
        return walk_dir_filtered_anchored(root, base, directory, max_depth, &skip_dir, visit);
    }
    let canonical_root = crate::repo_scan_policy::active_root().unwrap_or(std::fs::canonicalize(root)?);
    let canonical_base = std::fs::canonicalize(base)?;
    if !canonical_base.starts_with(&canonical_root) {
        return Err(ScanError::Policy("scan base escaped its canonical root".to_string()));
    }
    let base_depth = canonical_base
        .strip_prefix(&canonical_root)
        .map_or(0, |path| path.components().count());
    let mut stack = vec![(base.to_path_buf(), base_depth)];
    let mut visited = HashSet::new();
    while let Some((dir, depth)) = stack.pop() {
        crate::repo_scan_policy::check_depth(depth)?;
        let metadata = std::fs::symlink_metadata(&dir)?;
        let canonical_dir = crate::repo_scan_policy::authorize_directory(&dir, &metadata)?;
        if !visited.insert(canonical_dir) {
            return Err(ScanError::Policy(format!(
                "repository scan encountered a repeated directory: {}",
                dir.display()
            )));
        }
        let mut entries = Vec::new();
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            crate::repo_scan_policy::discover_entry(&entry.path())?;
            entries.push(entry);
        }
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name.starts_with('.') || name == "target" || name == "node_modules" || skip_dir(name) {
                continue;
            }
            let metadata = std::fs::symlink_metadata(&path)?;
            let rel = path.strip_prefix(root).unwrap_or(&path);
            if metadata.is_dir() {
                let child_depth = depth.saturating_add(1);
                crate::repo_scan_policy::check_depth(child_depth)?;
                if max_depth.is_none_or(|limit| child_depth <= limit) {
                    stack.push((path, child_depth));
                }
            } else {
                crate::repo_scan_policy::discover_file(&path, &metadata)?;
                visit(rel, &path);
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn walk_dir_filtered_anchored<F, S>(
    root: &Path,
    base: &Path,
    directory: std::fs::File,
    max_depth: Option<usize>,
    skip_dir: &S,
    visit: &mut F,
) -> Result<(), ScanError>
where
    F: FnMut(&Path, &Path),
    S: Fn(&str) -> bool,
{
    let active_root = crate::repo_scan_policy::active_root()
        .ok_or_else(|| ScanError::Policy("descriptor-relative walk requires an active scan root".to_string()))?;
    if !root.starts_with(&active_root) || !base.starts_with(&active_root) {
        return Err(ScanError::Policy(
            "descriptor-relative scan base escaped its execution root".to_string(),
        ));
    }
    let base_depth = base
        .strip_prefix(&active_root)
        .map_or(0, |path| path.components().count());
    let mut visited = HashSet::new();
    walk_opened_directory(
        root,
        base,
        directory,
        base_depth,
        max_depth,
        skip_dir,
        visit,
        &mut visited,
    )
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn walk_opened_directory<F, S>(
    root: &Path,
    dir_path: &Path,
    directory: std::fs::File,
    depth: usize,
    max_depth: Option<usize>,
    skip_dir: &S,
    visit: &mut F,
    visited: &mut HashSet<(u64, u64)>,
) -> Result<(), ScanError>
where
    F: FnMut(&Path, &Path),
    S: Fn(&str) -> bool,
{
    use std::os::unix::fs::MetadataExt as _;

    crate::repo_scan_policy::check_depth(depth)?;
    let metadata = directory
        .metadata()
        .map_err(|error| crate::repo_scan_policy::reject_read_io(dir_path, "opened directory metadata", &error))?;
    if !metadata.is_dir() {
        return Err(ScanError::Policy(format!(
            "repository scan expected an opened directory: {}",
            dir_path.display()
        )));
    }
    if !visited.insert((metadata.dev(), metadata.ino())) {
        return Err(ScanError::Policy(format!(
            "repository scan encountered a repeated directory: {}",
            dir_path.display()
        )));
    }
    let entries = crate::repo_scan_policy::read_opened_scan_directory_names(&directory, dir_path)?;
    for name in entries {
        let name_text = name.to_str().unwrap_or("");
        if name_text.starts_with('.') || name_text == "target" || name_text == "node_modules" || skip_dir(name_text) {
            continue;
        }
        let path = dir_path.join(&name);
        let entry = crate::repo_scan_policy::open_scan_entry(&directory, dir_path, &name)?;
        let rel = path.strip_prefix(root).unwrap_or(&path);
        if let Some(child_directory) = entry.directory {
            let child_depth = depth.saturating_add(1);
            crate::repo_scan_policy::check_depth(child_depth)?;
            if max_depth.is_none_or(|limit| child_depth <= limit) {
                walk_opened_directory(
                    root,
                    &path,
                    child_directory,
                    child_depth,
                    max_depth,
                    skip_dir,
                    visit,
                    visited,
                )?;
            }
        } else {
            // Enumeration admits the inode and corpus bytes, but does not
            // authorize a content read. Format-specific scanners decide
            // whether the file is relevant and apply their narrower ceiling
            // before `read_scan_bytes` enforces the global per-file limit.
            crate::repo_scan_policy::discover_file(&path, &entry.metadata)?;
            visit(rel, &path);
        }
    }
    Ok(())
}

/// Bounded, no-follow-aware scanner read. The opened file is identity-checked,
/// and the read never consumes more than the remaining cumulative byte budget.
pub fn read_scan_bytes(path: &Path) -> Result<Vec<u8>, ScanError> {
    #[cfg(unix)]
    {
        if let Some(file) = crate::repo_scan_policy::open_active_scan_file(path)? {
            let metadata = file
                .metadata()
                .map_err(|error| crate::repo_scan_policy::reject_read_io(path, "root-anchored metadata", &error))?;
            verify_opened_file(path, &metadata, &metadata)?;
            crate::repo_scan_policy::charge_opened_read(path, &metadata)?;
            let max_bytes = crate::repo_scan_policy::max_file_bytes();
            let remaining_bytes = crate::repo_scan_policy::remaining_read_bytes()?;
            return read_scan_bytes_from_file(path, file, &metadata, max_bytes, remaining_bytes);
        }
    }
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| crate::repo_scan_policy::reject_read_io(path, "metadata", &error))?;
    crate::repo_scan_policy::charge_read(path, &metadata)?;
    let max_bytes = crate::repo_scan_policy::max_file_bytes();
    let remaining_bytes = crate::repo_scan_policy::remaining_read_bytes()?;
    read_scan_bytes_opened(path, &metadata, max_bytes, remaining_bytes)
}

#[cfg(unix)]
fn read_scan_bytes_opened(
    path: &Path,
    metadata: &std::fs::Metadata,
    max_bytes: u64,
    remaining_bytes: u64,
) -> Result<Vec<u8>, ScanError> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| crate::repo_scan_policy::reject_read_io(path, "open", &error))?;
    let opened_metadata = file
        .metadata()
        .map_err(|error| crate::repo_scan_policy::reject_read_io(path, "opened metadata", &error))?;
    verify_opened_file(path, metadata, &opened_metadata)?;
    read_scan_bytes_from_file(path, file, &opened_metadata, max_bytes, remaining_bytes)
}

#[cfg(unix)]
fn read_scan_bytes_from_file(
    path: &Path,
    mut file: std::fs::File,
    opened_metadata: &std::fs::Metadata,
    max_bytes: u64,
    remaining_bytes: u64,
) -> Result<Vec<u8>, ScanError> {
    if opened_metadata.len() > max_bytes {
        return Err(crate::repo_scan_policy::reject_file_growth(path));
    }
    if opened_metadata.len() > remaining_bytes {
        return Err(crate::repo_scan_policy::reject_read_budget(path));
    }
    let read_limit = max_bytes.min(remaining_bytes);
    let mut bytes = Vec::with_capacity(usize::try_from(opened_metadata.len().min(read_limit)).unwrap_or(0));
    (&mut file)
        .take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|error| crate::repo_scan_policy::reject_read_io(path, "read", &error))?;
    let final_metadata = file
        .metadata()
        .map_err(|error| crate::repo_scan_policy::reject_read_io(path, "final metadata", &error))?;
    verify_opened_file(path, opened_metadata, &final_metadata)?;
    if final_metadata.len() > max_bytes {
        return Err(crate::repo_scan_policy::reject_file_growth(path));
    }
    if final_metadata.len() > remaining_bytes {
        return Err(crate::repo_scan_policy::reject_read_budget(path));
    }
    crate::repo_scan_policy::charge_read_bytes(bytes.len())?;
    Ok(bytes)
}

#[cfg(not(unix))]
fn read_scan_bytes_opened(
    path: &Path,
    _metadata: &std::fs::Metadata,
    _max_bytes: u64,
    _remaining_bytes: u64,
) -> Result<Vec<u8>, ScanError> {
    Err(crate::repo_scan_policy::reject_unsupported_secure_open(path))
}

#[cfg(unix)]
fn verify_opened_file(path: &Path, expected: &std::fs::Metadata, opened: &std::fs::Metadata) -> Result<(), ScanError> {
    use std::os::unix::fs::MetadataExt as _;

    if opened.is_file()
        && expected.dev() == opened.dev()
        && expected.ino() == opened.ino()
        && expected.len() == opened.len()
        && expected.mtime() == opened.mtime()
        && expected.mtime_nsec() == opened.mtime_nsec()
        && expected.ctime() == opened.ctime()
        && expected.ctime_nsec() == opened.ctime_nsec()
        && expected.nlink() == 1
        && opened.nlink() == 1
    {
        Ok(())
    } else {
        Err(crate::repo_scan_policy::reject_file_change(path))
    }
}

#[cfg(not(unix))]
fn verify_opened_file(
    path: &Path,
    _expected: &std::fs::Metadata,
    _opened: &std::fs::Metadata,
) -> Result<(), ScanError> {
    Err(crate::repo_scan_policy::reject_unsupported_secure_open(path))
}

pub fn read_scan_to_string(path: &Path) -> Result<String, ScanError> {
    String::from_utf8(read_scan_bytes(path)?)
        .map_err(|error| ScanError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, error)))
}

pub fn read_optional_scan_to_string(path: &Path) -> Result<Option<String>, ScanError> {
    if crate::repo_scan_policy::scan_file_metadata(path)?.is_some() {
        read_scan_to_string(path).map(Some)
    } else {
        Ok(None)
    }
}

pub fn parse_crate_name(toml: &str) -> Option<String> {
    // Find the `[package]` section then `name = "..."`.
    let mut in_package = false;
    for raw in toml.lines() {
        let line = raw.trim();
        if line.starts_with('[') {
            in_package = line == "[package]";
            continue;
        }
        if in_package {
            // Match `name = "..."` (or single quotes). Be strict on the field
            // boundary so "namespace = ..." doesn't false-match.
            if let Some(rest) = line.strip_prefix("name") {
                let after = rest.trim_start();
                if let Some(value_part) = after.strip_prefix('=') {
                    let v = value_part.trim().trim_matches('"').trim_matches('\'');
                    if !v.is_empty() && v.len() <= SCAN_METADATA_MAX_BYTES {
                        return Some(v.to_string());
                    }
                }
            }
        }
    }
    None
}

pub fn parse_internal_path_deps(toml: &str) -> Result<Vec<String>, ScanError> {
    // Find lines like `crux-mcp = { path = "../crux-mcp" }` or
    // `crux-mcp = { workspace = true }` — both indicate workspace deps.
    let mut out = Vec::new();
    for raw in toml.lines() {
        let line = raw.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if let Some(eq_pos) = line.find('=') {
            let name = line[..eq_pos].trim();
            let rest = line[eq_pos + 1..].trim();
            if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
                continue;
            }
            if rest.contains("path =") || rest.contains("path=") || rest.contains("workspace = true") {
                crate::repo_scan_policy::charge_generated_work(1, name.len(), "internal dependency index")?;
                out.push(name.to_string());
            }
        }
    }
    Ok(out)
}

/// Infer a module path like `corecruxd::http::admin` from a file path.
pub fn infer_module_path(crate_name: &str, crate_root: &Path, file: &Path) -> String {
    let src = crate_root.join("src");
    let rel = match file.strip_prefix(&src) {
        Ok(r) => r,
        Err(_) => return crate_name.to_string(),
    };
    let mut parts: Vec<String> = vec![crate_name.replace('-', "_")];
    let mut comps: Vec<&str> = rel.iter().map(|s| s.to_str().unwrap_or("")).collect();
    if let Some(last) = comps.last_mut() {
        if *last == "lib.rs" || *last == "main.rs" {
            comps.pop();
        } else if let Some(stem) = last.strip_suffix(".rs") {
            *last = stem;
            // `mod.rs` semantics: keep the directory name only.
        }
    }
    if comps.last().copied() == Some("mod") {
        comps.pop();
    }
    for c in comps {
        if c.is_empty() {
            continue;
        }
        parts.push(c.to_string());
    }
    parts.join("::")
}

/// Parse a single line for a symbol declaration. Returns (kind, name, is_pub).
fn parse_symbol_line(line: &str) -> Option<(&'static str, String, bool)> {
    let trimmed = line.trim_start();
    if trimmed.starts_with("//") {
        return None;
    }
    let (rest, is_pub) = if let Some(r) = trimmed.strip_prefix("pub ") {
        (r, true)
    } else if let Some(r) = trimmed.strip_prefix("pub(crate) ") {
        (r, true)
    } else if let Some(r) = trimmed.strip_prefix("pub(super) ") {
        (r, true)
    } else {
        (trimmed, false)
    };
    let kinds: &[(&str, &str)] = &[
        ("async fn ", "fn"),
        ("unsafe fn ", "fn"),
        ("fn ", "fn"),
        ("struct ", "struct"),
        ("enum ", "enum"),
        ("trait ", "trait"),
        ("type ", "type"),
        ("const ", "const"),
        ("static ", "static"),
        ("mod ", "mod"),
    ];
    for (prefix, kind) in kinds {
        if let Some(after) = rest.strip_prefix(prefix) {
            let name: String = after
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty() {
                return Some((*kind, name, is_pub));
            }
        }
    }
    None
}

/// Test-file heuristic — true if any of:
/// - path contains a `/tests/` segment (integration test directory),
/// - path is under a conventional `src/test`, `src/androidTest`, or
///   `src/integrationTest` source set,
/// - filename ends with `_tests.rs` or is exactly `tests.rs`,
/// - first non-blank, non-comment line is `#![cfg(test)]` (rare, but legal).
pub fn looks_like_test_file(rel_path: &str, src: &str) -> bool {
    let normalized = rel_path.replace('\\', "/");
    let path_match = normalized.contains("/tests/")
        || normalized.ends_with("/tests.rs")
        || normalized.ends_with("_tests.rs")
        || ["src/test/", "src/androidTest/", "src/integrationTest/"]
            .iter()
            .any(|source_set| normalized.starts_with(source_set) || normalized.contains(&format!("/{source_set}")));
    if path_match {
        return true;
    }
    // Cheap: peek the first ~20 non-blank lines for `#![cfg(test)]`.
    let mut seen = 0usize;
    for line in src.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with("//") {
            continue;
        }
        if t.starts_with("#![cfg(test)]") {
            return true;
        }
        seen += 1;
        if seen >= 20 {
            break;
        }
    }
    false
}

/// Extract the leading `//!` block from a Rust source file. Returns
/// `(full, summary)` where `summary` is the first sentence (≤80 chars).
/// Skips a leading copyright `//` block and blank lines so the doc starts
/// where the developer actually wrote `//!`.
pub fn parse_file_doc_header(src: &str) -> (Option<String>, Option<String>) {
    let mut full = String::new();
    let mut started = false;
    for line in src.lines() {
        let t = line.trim_start();
        if !started {
            // Skip leading blank lines, copyright `//` (but not `//!`), and
            // inner attributes like `#![recursion_limit = ...]` or
            // `#![allow(...)]` that often live between the copyright header
            // and the module doc block.
            if t.is_empty() || (t.starts_with("//") && !t.starts_with("//!")) || t.starts_with("#![") {
                continue;
            }
        }
        if let Some(rest) = t.strip_prefix("//!") {
            started = true;
            // Strip the single space convention: `//! ` → `` (just the body).
            let body = rest.strip_prefix(' ').unwrap_or(rest);
            if !full.is_empty() {
                full.push('\n');
            }
            full.push_str(body);
        } else {
            // Non-`//!` line after the block started → header is over.
            if started {
                break;
            }
            // Or a code line before any `//!` was found → no header.
            return (None, None);
        }
    }
    if full.is_empty() {
        return (None, None);
    }
    // Build the summary: first sentence, capped at 80 chars.
    let collapsed: String = full.replace('\n', " ").split_whitespace().collect::<Vec<_>>().join(" ");
    let first_sentence = collapsed
        .split_once(". ")
        .map(|(s, _)| s.to_string())
        .unwrap_or(collapsed);
    let summary = if first_sentence.len() > 80 {
        let mut cut = 80;
        // Don't slice mid-character: walk back to a char boundary.
        while cut > 0 && !first_sentence.is_char_boundary(cut) {
            cut -= 1;
        }
        format!("{}…", &first_sentence[..cut])
    } else {
        first_sentence
    };
    (Some(full), Some(summary))
}

/// Parsed representation of a `.route("/path", METHOD(handler))` line. The
/// caller resolves `handler_fn` to a definition file via the symbol index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedRoute {
    pub method: String,
    pub path: String,
    pub handler_fn: String,
    pub source_file: String,
    pub source_line: usize,
}

/// Parse one route declaration (which may span multiple lines after `.route(`).
/// `chunk` is everything from immediately after the opening `.route(` up to
/// the matching `)`. Source line is the line where `.route(` was found.
fn parse_route_chunk(chunk: &str, source_file: &str, source_line: usize) -> Option<ParsedRoute> {
    // First arg: "PATH"
    let after = chunk.trim_start().strip_prefix('"')?;
    let (path_str, rest) = after.split_once('"')?;
    // Second arg: METHOD(handler) — METHOD may be a path like
    // `axum::routing::post`. Skip whitespace + comma.
    let rest = rest.trim_start().strip_prefix(',')?.trim_start();
    // Method ident path: chars until `(`.
    let method_path: String = rest
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == ':')
        .collect();
    if method_path.is_empty() {
        return None;
    }
    let method_last = method_path.rsplit("::").next().unwrap_or(&method_path);
    let method_upper = method_last.to_ascii_uppercase();
    if !matches!(method_upper.as_str(), "GET" | "POST" | "PATCH" | "DELETE" | "PUT") {
        return None;
    }
    let after_method = &rest[method_path.len()..];
    let after_method = after_method.trim_start().strip_prefix('(')?.trim_start();
    let handler_path: String = after_method
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == ':')
        .collect();
    if handler_path.is_empty() {
        return None;
    }
    let handler_fn = handler_path.rsplit("::").next().unwrap_or(&handler_path).to_string();
    Some(ParsedRoute {
        method: method_upper,
        path: path_str.to_string(),
        handler_fn,
        source_file: source_file.to_string(),
        source_line,
    })
}

/// Walk a whole source file looking for `.route(...)` declarations, including
/// multi-line ones. Returns every route found in source order.
pub fn parse_routes_in_source(src: &str, source_file: &str) -> Result<Vec<ParsedRoute>, ScanError> {
    let mut out = Vec::new();
    let bytes = src.as_bytes();
    let mut i = 0usize;
    // Pre-compute line numbers for each byte offset.
    // Cheap: walk bytes once, push line starts.
    crate::repo_scan_policy::charge_generated_work(1, std::mem::size_of::<usize>(), "route line-start index")?;
    let mut line_starts: Vec<usize> = vec![0];
    for (idx, b) in bytes.iter().enumerate() {
        if idx % 4096 == 0 {
            crate::repo_scan_policy::check_deadline()?;
        }
        if *b == b'\n' {
            crate::repo_scan_policy::charge_generated_work(1, std::mem::size_of::<usize>(), "route line-start index")?;
            line_starts.push(idx + 1);
        }
    }
    let needle = b".route(";
    while i + needle.len() <= bytes.len() {
        if i % 4096 == 0 {
            crate::repo_scan_policy::check_deadline()?;
        }
        if &bytes[i..i + needle.len()] == needle {
            // Skip if this looks like a comment line — find the start of the
            // current line and check.
            let line_idx = match line_starts.binary_search(&i) {
                Ok(idx) => idx,
                Err(idx) => idx.saturating_sub(1),
            };
            let line_start = line_starts[line_idx];
            let line_prefix = std::str::from_utf8(&bytes[line_start..i]).unwrap_or("");
            if line_prefix.trim_start().starts_with("//") {
                i += needle.len();
                continue;
            }
            // Find the matching `)`. Walk depth-counted from the position
            // right after the opening `(`. Bail at 4 KB to keep pathological
            // input bounded.
            let chunk_start = i + needle.len();
            let mut depth = 1i32;
            let mut j = chunk_start;
            let limit = (chunk_start + 4096).min(bytes.len());
            let mut in_str = false;
            let mut prev = 0u8;
            while j < limit && depth > 0 {
                if j % 1024 == 0 {
                    crate::repo_scan_policy::check_deadline()?;
                }
                let c = bytes[j];
                if in_str {
                    if c == b'"' && prev != b'\\' {
                        in_str = false;
                    }
                } else {
                    match c {
                        b'"' => in_str = true,
                        b'(' => depth += 1,
                        b')' => depth -= 1,
                        _ => {}
                    }
                }
                prev = c;
                if depth == 0 {
                    break;
                }
                j += 1;
            }
            if depth == 0 {
                let chunk = std::str::from_utf8(&bytes[chunk_start..j]).unwrap_or("");
                if let Some(route) = parse_route_chunk(chunk, source_file, line_idx + 1) {
                    crate::repo_scan_policy::charge_generated_work(
                        1,
                        route
                            .method
                            .len()
                            .saturating_add(route.path.len())
                            .saturating_add(route.handler_fn.len())
                            .saturating_add(route.source_file.len()),
                        "parsed route",
                    )?;
                    out.push(route);
                }
                i = j + 1;
                continue;
            }
        }
        i += 1;
    }
    Ok(out)
}

/// Scan a single source line for function call sites. Returns the set of
/// callee names found on this line (last `::` segment of any `ident_path(`
/// occurrence, excluding macros which end with `!`). The caller resolves
/// each name against the symbol index. Whitespace inside arg lists doesn't
/// matter — we only care about the identifier immediately preceding `(`.
fn scan_call_sites(line: &str) -> Result<Vec<String>, ScanError> {
    let bytes = line.as_bytes();
    let mut out: Vec<String> = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        if i % 4096 == 0 {
            crate::repo_scan_policy::check_deadline()?;
        }
        if bytes[i] != b'(' {
            i += 1;
            continue;
        }
        // Found an `(`. Walk backward over whitespace, then over the identifier
        // (alphanumeric / `_` / `:`).
        let mut end = i;
        while end > 0 {
            let c = bytes[end - 1];
            if c == b' ' || c == b'\t' {
                end -= 1;
            } else {
                break;
            }
        }
        let mut start = end;
        while start > 0 {
            let c = bytes[start - 1];
            if c.is_ascii_alphanumeric() || c == b'_' || c == b':' {
                start -= 1;
            } else {
                break;
            }
        }
        if start < end {
            // Reject method calls: `foo.bar(...)` looks like a call to a fn
            // named `bar` from the byte-walker's perspective, but `bar` is a
            // method on whatever `foo` is — not a free fn the symbol index
            // can resolve. Pre-fix this matched real fn names like `clone`,
            // `get`, `keys`, `into`, `from`, `iter`, `next`, `fmt` etc.
            // anywhere a Clone/Iterator/etc. impl appeared, polluting every
            // downstream metric.
            if start > 0 && bytes[start - 1] == b'.' {
                i += 1;
                continue;
            }
            // Reject macro invocations: they have `!` between the ident and `(`.
            // (We've already walked past whitespace, so check the char at end.)
            // Also reject if the byte just before start is `!` — then this is
            // `ident!(...)`, not a call.
            // (No, scan_call_sites scans for `(` so the `!` would be at end-1.
            // But we walked past whitespace, then identifier. So if there was a
            // `!`, it would have stopped the identifier walk. Need a separate
            // check: was the char just before this `(` (after whitespace, before
            // walking ident) a `!`? Easier: re-check here.)
            // Actually simpler: if `end < i` (whitespace was skipped) and the
            // char between end and i isn't a `!`, we're fine. But the typical
            // call has no whitespace. The case to catch is `foo!(`. After
            // walking back from `(`, end == i, then start walks back over
            // `foo`. So `bytes[end]` is `!` — but `!` is not alphanumeric so it
            // stops the start walk. The identifier we extract excludes `!`.
            // We need to check if the char at end (the byte just after the
            // identifier we extracted) is `!`. If so, this is a macro.
            if end < bytes.len() && bytes[end] == b'!' {
                i += 1;
                continue;
            }
            // Also: check the char right before `(` itself. If start..end ends
            // with `!`, it's a macro. But `!` is excluded from the ident scan,
            // so we need to look at bytes[end-1] for the case where there's
            // no whitespace between `!` and `(`.
            // Actually `start..end` is the identifier (alnum/_/:), so we need
            // to check `bytes[end..i]` for `!`.
            let between = &bytes[end..i];
            if between.contains(&b'!') {
                i += 1;
                continue;
            }
            let ident = std::str::from_utf8(&bytes[start..end]).unwrap_or("");
            // Take last `::` segment.
            let last = ident.rsplit("::").next().unwrap_or(ident);
            // Reject keywords / control flow that look like calls: `if`, `while`,
            // `match`, `for`, `return`, `let`, `move`, `Self`, plus type names
            // we don't want to match. We're after fn names only; type names are
            // typically PascalCase, but we can't filter on case alone (some
            // crates use snake_case for closures). Just block obvious keywords.
            const BLOCKED: &[&str] = &[
                "if", "while", "match", "for", "return", "let", "move", "loop", "break", "continue", "else", "as",
                "ref", "mut",
            ];
            if !last.is_empty() && !BLOCKED.contains(&last) {
                crate::repo_scan_policy::charge_generated_work(1, last.len(), "call-site candidate")?;
                out.push(last.to_string());
            }
        }
        i += 1;
    }
    Ok(out)
}

fn first_matching_index(candidates: &[usize], predicate: impl Fn(usize) -> bool) -> Result<Option<usize>, ScanError> {
    for (candidate_index, candidate) in candidates.iter().copied().enumerate() {
        if candidate_index % 256 == 0 {
            crate::repo_scan_policy::check_deadline()?;
        }
        if predicate(candidate) {
            return Ok(Some(candidate));
        }
    }
    Ok(None)
}

fn unique_matching_index(candidates: &[usize], predicate: impl Fn(usize) -> bool) -> Result<Option<usize>, ScanError> {
    let mut found = None;
    for (candidate_index, candidate) in candidates.iter().copied().enumerate() {
        if candidate_index % 256 == 0 {
            crate::repo_scan_policy::check_deadline()?;
        }
        if !predicate(candidate) {
            continue;
        }
        if found.is_some() {
            return Ok(None);
        }
        found = Some(candidate);
    }
    Ok(found)
}

pub fn parse_stub_line(line: &str) -> Option<(&'static str, String)> {
    let trimmed = line.trim();
    if trimmed.starts_with("//") {
        return None;
    }
    let snippet = trimmed.chars().take(120).collect::<String>();
    if line.contains("todo!(") {
        return Some(("todo", snippet));
    }
    if line.contains("unimplemented!(") {
        return Some(("unimplemented", snippet));
    }
    if line.contains("panic!(") {
        let lower = line.to_lowercase();
        if lower.contains("not implemented") || lower.contains("not yet implemented") || lower.contains("todo") {
            return Some(("panic_not_implemented", snippet));
        }
    }
    None
}

pub fn parse_use_target(line: &str, from_crate: &str, known_crates: &BTreeSet<String>) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.starts_with("//") {
        return None;
    }
    let body = trimmed
        .strip_prefix("pub use ")
        .or_else(|| trimmed.strip_prefix("use "))?;
    // Split on `::` and collect a flat-enough target. We don't try to handle
    // `use a::{b, c}` group imports — those produce one edge per group.
    let head: String = body
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == ':')
        .collect();
    if head.is_empty() {
        return None;
    }
    // Resolve the first segment.
    let first = head.split("::").next().unwrap_or("");
    if first == "crate" || first == "self" || first == "super" {
        // Internal self-reference within the same crate.
        return Some(format!("{}::{}", from_crate.replace('-', "_"), head));
    }
    // Cross-crate: only emit if it resolves to a known workspace crate.
    let first_norm = first.replace('_', "-");
    if known_crates.contains(&first.to_string()) || known_crates.contains(&first_norm) {
        return Some(head);
    }
    None
}

fn count_substring(haystack: &str, needle: &str) -> Result<usize, ScanError> {
    if needle.is_empty() {
        return Ok(0);
    }
    let mut count = 0usize;
    let mut start = 0usize;
    while let Some(pos) = haystack[start..].find(needle) {
        crate::repo_scan_policy::check_deadline()?;
        // Require word boundary on both sides to avoid matching substrings
        // inside other identifiers (e.g. `foo_bar` matching `foo`).
        let abs = start + pos;
        let before = if abs == 0 {
            ' '
        } else {
            haystack.as_bytes()[abs - 1] as char
        };
        let after_idx = abs + needle.len();
        let after = if after_idx >= haystack.len() {
            ' '
        } else {
            haystack.as_bytes()[after_idx] as char
        };
        if !before.is_ascii_alphanumeric() && before != '_' && !after.is_ascii_alphanumeric() && after != '_' {
            count += 1;
        }
        start = abs + needle.len();
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// D-5: `walk_dir` pushed any `path.is_dir()`, which *follows* symlinks,
    /// so `a/b/loop -> <root>` recursed without bound. It is the walker behind
    /// both the AST and the polyglot scanners on the live repo-watch path;
    /// `discover_manifests` already guarded the same shape.
    ///
    /// The walk is run on a worker thread with a hard join deadline: before
    /// the fix this test does not fail, it *hangs*, and an unbounded repro
    /// would wedge CI.
    #[cfg(unix)]
    #[test]
    fn walk_dir_does_not_follow_symlinks_into_a_loop() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path().to_path_buf();
        let nested = root.join("a/b");
        std::fs::create_dir_all(&nested).expect("nested dirs");
        std::fs::write(root.join("top.rs"), "fn main() {}").expect("top file");
        std::fs::write(nested.join("deep.rs"), "fn deep() {}").expect("deep file");
        // Points back at the root: following it recurses for ever.
        std::os::unix::fs::symlink(&root, nested.join("loop")).expect("dir symlink");
        // A symlink to a *file* is still visited — callers record why they
        // skip it, and dropping it here would hide it entirely.
        std::os::unix::fs::symlink(root.join("top.rs"), root.join("alias.rs")).expect("file symlink");

        let (tx, rx) = std::sync::mpsc::channel();
        let walker = std::thread::spawn(move || {
            let mut seen: Vec<String> = Vec::new();
            let mut visits = 0usize;
            let outcome = walk_dir(&root, &root, &mut |rel, _abs| {
                visits += 1;
                // Belt and braces: cap the work even if the walk is unbounded,
                // so a regression fails the deadline rather than filling disk
                // or spinning for ever.
                if visits <= 10_000 {
                    seen.push(rel.to_string_lossy().replace('\\', "/"));
                }
            });
            let _ = tx.send((outcome.is_ok(), visits, seen));
        });

        let (ok, visits, mut seen) = rx
            .recv_timeout(std::time::Duration::from_secs(20))
            .expect("walk_dir must terminate on a symlink loop");
        walker.join().expect("walker thread");

        assert!(ok, "the walk completes cleanly");
        seen.sort();
        assert_eq!(
            seen,
            vec!["a/b/deep.rs".to_string(), "alias.rs".to_string(), "top.rs".to_string()],
            "the directory loop is not descended; the file alias is still surfaced"
        );
        assert_eq!(visits, 3, "no path is visited twice via the loop");
    }

    #[test]
    fn rust_complexity_guard_bounds_generics_and_ignores_literals_and_comments() {
        let nested = format!(
            "type Deep = {}u8{};\n",
            "Vec<".repeat(RUST_SYNTAX_MAX_DEPTH + 1),
            ">".repeat(RUST_SYNTAX_MAX_DEPTH + 1)
        );
        let error = validate_rust_syntax_complexity(&nested).expect_err("deep generics must fail");
        assert!(error.to_string().contains("Rust syntax nesting"));

        let harmless = format!(
            "const TEXT: &str = r#\"{}\"#;\n/* {} */\n",
            "<{(".repeat(RUST_SYNTAX_MAX_DEPTH + 10),
            ">})".repeat(RUST_SYNTAX_MAX_DEPTH + 10)
        );
        validate_rust_syntax_complexity(&harmless).expect("literal and comment delimiters are inert");

        let comparisons = "let _ = left < right;\n".repeat(RUST_SYNTAX_MAX_DEPTH + 1);
        validate_rust_syntax_complexity(&comparisons).expect("flat comparisons are not generic nesting");

        let assignment_chain = format!(
            "fn fixture() {{ {}tail; }}",
            "value = ".repeat(RUST_SYNTAX_MAX_DEPTH + 1)
        );
        let error =
            validate_rust_syntax_complexity(&assignment_chain).expect_err("deep assignment recursion must fail");
        assert!(error.to_string().contains("Rust syntax nesting"));
        let independent_assignments =
            "fn fixture() {\n".to_string() + &"value = 1;\n".repeat(RUST_SYNTAX_MAX_DEPTH + 1) + "}";
        validate_rust_syntax_complexity(&independent_assignments)
            .expect("statement boundaries reset assignment recursion depth");

        let recursive_shapes = [
            format!(
                "fn fixture() {{ let _ = {}; }}",
                std::iter::repeat_n("value", RUST_SYNTAX_MAX_DEPTH + 2)
                    .collect::<Vec<_>>()
                    .join(" + ")
            ),
            format!(
                "fn fixture() {{ let _ = value{}; }}",
                ".method()".repeat(RUST_SYNTAX_MAX_DEPTH + 2)
            ),
            format!(
                "fn fixture() {{ let _ = value{}; }}",
                "()".repeat(RUST_SYNTAX_MAX_DEPTH + 2)
            ),
            format!(
                "fn fixture() {{ let _ = value{}; }}",
                "[0]".repeat(RUST_SYNTAX_MAX_DEPTH + 2)
            ),
            format!(
                "fn fixture() {{ {}if condition {{}} }}",
                "if condition {} else ".repeat(RUST_SYNTAX_MAX_DEPTH + 2)
            ),
            format!(
                "fn fixture() {{ let _ = {}0; }}",
                "|| ".repeat(RUST_SYNTAX_MAX_DEPTH + 2)
            ),
            format!("fn fixture() {{ {}0; }}", "return ".repeat(RUST_SYNTAX_MAX_DEPTH + 2)),
            format!(
                "fn fixture() -> Result<(), ()> {{ let _ = value{}; Ok(()) }}",
                "?".repeat(RUST_SYNTAX_MAX_DEPTH + 2)
            ),
            format!("type DeepFn = {}u8;", "fn() -> ".repeat(RUST_SYNTAX_MAX_DEPTH + 2)),
        ];
        for source in recursive_shapes {
            let error = validate_rust_syntax_complexity(&source)
                .expect_err("deep recursive Rust syntax tree must fail before syn");
            assert!(
                error.to_string().contains("Rust syntax"),
                "unexpected preflight error: {error}"
            );
        }

        let labels = format!(
            "{}let _ = 1;{}",
            "'scope: {".repeat(RUST_SYNTAX_MAX_DEPTH + 1),
            "}".repeat(RUST_SYNTAX_MAX_DEPTH + 1)
        );
        let error = validate_rust_syntax_complexity(&labels).expect_err("deep labeled blocks must fail");
        assert!(error.to_string().contains("Rust syntax nesting"));

        let lowercase_generics = format!(
            "struct x<T>(T); type Deep = {}u8{};",
            "x<".repeat(RUST_SYNTAX_MAX_DEPTH + 1),
            ">".repeat(RUST_SYNTAX_MAX_DEPTH + 1)
        );
        assert!(validate_rust_syntax_complexity(&lowercase_generics).is_err());

        let use_path = format!("use {}leaf;", "segment::".repeat(RUST_SYNTAX_MAX_DEPTH + 1));
        assert!(validate_rust_syntax_complexity(&use_path).is_err());

        let raw_pointers = format!("type Deep = {}u8;", "*const ".repeat(RUST_SYNTAX_MAX_DEPTH + 1));
        assert!(validate_rust_syntax_complexity(&raw_pointers).is_err());
        let references = format!("type Deep<'a> = {}u8;", "&'a ".repeat(RUST_SYNTAX_MAX_DEPTH + 1));
        assert!(validate_rust_syntax_complexity(&references).is_err());

        let grouped_comparisons = format!(
            "let _ = ({}) && ({});",
            std::iter::repeat_n("A<B", RUST_SYNTAX_MAX_DEPTH + 1)
                .collect::<Vec<_>>()
                .join(" && "),
            std::iter::repeat_n("C>D", RUST_SYNTAX_MAX_DEPTH + 1)
                .collect::<Vec<_>>()
                .join(" && ")
        );
        let error = validate_rust_syntax_complexity(&grouped_comparisons)
            .expect_err("recursive boolean-expression trees must be bounded");
        assert!(error.to_string().contains("tree depth"));

        let const_generic = format!(
            "struct x<T, const B: bool>(T); type Deep = {}u8, {{true && true}}>{};",
            "x<".repeat(RUST_SYNTAX_MAX_DEPTH + 1),
            ", true>".repeat(RUST_SYNTAX_MAX_DEPTH)
        );
        assert!(validate_rust_syntax_complexity(&const_generic).is_err());

        let tuple_comparisons = format!(
            "let _ = ({}, {});",
            std::iter::repeat_n("A<B", RUST_SYNTAX_MAX_DEPTH + 1)
                .collect::<Vec<_>>()
                .join(", "),
            std::iter::repeat_n("C>D", RUST_SYNTAX_MAX_DEPTH + 1)
                .collect::<Vec<_>>()
                .join(", ")
        );
        validate_rust_syntax_complexity(&tuple_comparisons).expect("tuple comparison elements are not generic nesting");

        let array_const_comparison = format!(
            "type X = [u8; (1 < 2) as usize];\n{}",
            "let _ = left < right;\n".repeat(RUST_SYNTAX_MAX_DEPTH + 1)
        );
        validate_rust_syntax_complexity(&array_const_comparison)
            .expect("array const expressions and following comparisons are not generics");

        let struct_field_comparisons = format!(
            "struct S {{ field: bool }}\nfn fixture() {{ let _ = S {{ field: {} }}; }}",
            std::iter::repeat_n("left < right", RUST_SYNTAX_MAX_DEPTH + 1)
                .collect::<Vec<_>>()
                .join(" && ")
        );
        let error = validate_rust_syntax_complexity(&struct_field_comparisons)
            .expect_err("recursive struct-field expressions must be bounded");
        assert!(error.to_string().contains("tree depth"));

        let qself = format!(
            "fn fixture() {{ let _ = <{} as Default>::default(); }}",
            format!(
                "{}u8{}",
                "Vec<".repeat(RUST_SYNTAX_MAX_DEPTH + 1),
                ">".repeat(RUST_SYNTAX_MAX_DEPTH + 1)
            )
        );
        let error = validate_rust_syntax_complexity(&qself).expect_err("deep QSelf type must fail before syn");
        assert!(error.to_string().contains("Rust syntax nesting"));

        let nested_type = format!(
            "{}u8{}",
            "Vec<".repeat(RUST_SYNTAX_MAX_DEPTH + 1),
            ">".repeat(RUST_SYNTAX_MAX_DEPTH + 1)
        );
        let const_block_then_type = format!("type D = Wrapper<{{ let _x = 0; 0 }}, {nested_type}>;");
        assert!(
            validate_rust_syntax_complexity(&const_block_then_type).is_err(),
            "a const-block statement must not clear the enclosing generic context"
        );

        let union_field = format!("union U {{ field: std::mem::ManuallyDrop<{nested_type}> }}");
        assert!(
            validate_rust_syntax_complexity(&union_field).is_err(),
            "union field types must receive the aggregate guard"
        );

        let enum_after_discriminant = format!("enum E {{ A = 0, B({nested_type}) }}");
        assert!(
            validate_rust_syntax_complexity(&enum_after_discriminant).is_err(),
            "an enum discriminant must not disable later variant type guarding"
        );

        let keyword_qself = format!("fn fixture() {{ return <{nested_type} as Default>::default(); }}");
        assert!(
            validate_rust_syntax_complexity(&keyword_qself).is_err(),
            "QSelf after a control-flow keyword must be guarded"
        );
        let arm_qself = format!("fn fixture() {{ match 0 {{ _ => <{nested_type} as Default>::default() }}; }}");
        assert!(
            validate_rust_syntax_complexity(&arm_qself).is_err(),
            "QSelf after a fat arrow must be guarded"
        );

        let comparison_chain = std::iter::repeat_n("left < right", RUST_SYNTAX_MAX_DEPTH + 1)
            .collect::<Vec<_>>()
            .join(" && ");
        let closure_comparisons = format!("fn fixture() {{ let f = |x: i32| {{ x > 0 && {comparison_chain} }}; }}");
        let error = validate_rust_syntax_complexity(&closure_comparisons)
            .expect_err("recursive closure-body expressions must be bounded");
        assert!(error.to_string().contains("tree depth"));

        let raw_identifier = format!("fn fixture() {{ let r#type = 0; let _ = {comparison_chain}; }}");
        let error = validate_rust_syntax_complexity(&raw_identifier)
            .expect_err("recursive raw-identifier expressions must be bounded");
        assert!(error.to_string().contains("tree depth"));

        let attributed_field = format!("struct S {{ #[cfg(feature = \"fixture\")] field: {nested_type} }}");
        assert!(
            validate_rust_syntax_complexity(&attributed_field).is_err(),
            "attribute expressions must not erase aggregate type context"
        );
        let attributed_param = format!("fn fixture(#[cfg(feature = \"fixture\")] value: {nested_type}) {{}}");
        assert!(
            validate_rust_syntax_complexity(&attributed_param).is_err(),
            "attribute expressions must not erase signature type context"
        );

        let binary_qself =
            format!("fn fixture(flag: bool) {{ let _ = flag > <{nested_type} as Default>::default(); }}");
        assert!(
            validate_rust_syntax_complexity(&binary_qself).is_err(),
            "QSelf after a binary greater-than boundary must be guarded"
        );

        let closure_or_pattern =
            format!("enum E<T> {{ A, B(T) }} fn fixture() {{ let _ = |(E::A | E::B(_)): E<{nested_type}>| {{}}; }}");
        assert!(
            validate_rust_syntax_complexity(&closure_or_pattern).is_err(),
            "an inner or-pattern bar must not close the surrounding closure parameters"
        );

        let cast_target = format!("fn fixture() {{ let _ = 0 as {nested_type}; }}");
        assert!(
            validate_rust_syntax_complexity(&cast_target).is_err(),
            "deep cast target types must be guarded"
        );
        let lifetime_cast = format!("fn fixture() {{ let _ = 0 as Wrapper<'static, {nested_type}>; }}");
        assert!(
            validate_rust_syntax_complexity(&lifetime_cast).is_err(),
            "lifetimes in cast target types must not hide later nested generics"
        );
        let raw_const = r##"r#""{"#"##;
        let raw_const_cast = format!("fn fixture() {{ let _ = 0 as Wrapper<{{ {raw_const} }}, {nested_type}>; }}");
        assert!(
            validate_rust_syntax_complexity(&raw_const_cast).is_err(),
            "raw strings in cast const arguments must not desynchronise lookahead"
        );
        let flat_cast_comparisons =
            "fn fixture() {\n".to_string() + &"let _ = (0 as u8) < 3;\n".repeat(RUST_SYNTAX_MAX_DEPTH + 1) + "}";
        validate_rust_syntax_complexity(&flat_cast_comparisons)
            .expect("flat comparisons after simple cast targets are not nested generics");
        let comma_cast_comparisons = format!(
            "fn fixture() {{ consume(0 as u8, {}, z > q); }}",
            std::iter::repeat_n("a < b", RUST_SYNTAX_MAX_DEPTH + 1)
                .collect::<Vec<_>>()
                .join(", ")
        );
        validate_rust_syntax_complexity(&comma_cast_comparisons)
            .expect("an argument boundary ends a simple cast target");
        let multi_argument_cast = format!("fn fixture() {{ let _ = 0 as Wrapper<u8, {nested_type}>; }}");
        assert!(
            validate_rust_syntax_complexity(&multi_argument_cast).is_err(),
            "generic commas inside a cast target must preserve later nesting"
        );
        let function_pointer_alias = format!("type DeepFn = Wrapper<fn() -> u8, {nested_type}>;");
        assert!(
            validate_rust_syntax_complexity(&function_pointer_alias).is_err(),
            "a function-pointer arrow must not close an enclosing generic"
        );
        let function_pointer_cast = format!("fn fixture() {{ let _ = fptr as Wrapper<fn() -> u8, {nested_type}>; }}");
        assert!(
            validate_rust_syntax_complexity(&function_pointer_cast).is_err(),
            "a function-pointer arrow in a cast must preserve later generic arguments"
        );
        let function_pointer_comparisons = format!(
            "fn fixture() {{ let _ = (fptr as fn() -> u8) < rhs && {}; }}",
            std::iter::repeat_n("(a < b)", RUST_SYNTAX_MAX_DEPTH + 1)
                .collect::<Vec<_>>()
                .join(" && ")
        );
        let error = validate_rust_syntax_complexity(&function_pointer_comparisons)
            .expect_err("recursive function-pointer comparison expressions must be bounded");
        assert!(error.to_string().contains("tree depth"));

        let const_turbofish = format!("type X = Wrapper<{{ std::mem::size_of::<{nested_type}>() }}>;");
        assert!(
            validate_rust_syntax_complexity(&const_turbofish).is_err(),
            "deep turbofish types inside const generic blocks must be guarded"
        );
        let array_const_turbofish = format!("type X = [u8; std::mem::size_of::<{nested_type}>()];");
        assert!(
            validate_rust_syntax_complexity(&array_const_turbofish).is_err(),
            "deep turbofish types inside array const expressions must be guarded"
        );

        let commented_cast = format!(
            "fn fixture() {{ let _ = 0 as Vec</*{}*/{nested_type}>; }}",
            "x".repeat(5000)
        );
        assert!(
            validate_rust_syntax_complexity(&commented_cast).is_err(),
            "long comments in cast target types must not create a lookahead blind spot"
        );
        let chained_cast_comparisons = format!(
            "fn fixture() {{ let _ = (0 as u8 < 3) && {}; }}",
            std::iter::repeat_n("(left < right)", RUST_SYNTAX_MAX_DEPTH + 1)
                .collect::<Vec<_>>()
                .join(" && ")
        );
        let error = validate_rust_syntax_complexity(&chained_cast_comparisons)
            .expect_err("recursive cast-comparison expressions must be bounded");
        assert!(error.to_string().contains("tree depth"));
    }

    #[test]
    fn self_workspace_redaction_removes_legacy_absolute_roots() {
        let private_root_dir = tempfile::tempdir().expect("private root");
        let private_root = private_root_dir.path().canonicalize().expect("canonical private root");
        let mut scan = WorkspaceScan {
            root_path: private_root.display().to_string(),
            crates: vec![
                CrateInfo {
                    name: "root".to_string(),
                    rel_path: private_root.display().to_string(),
                    internal_deps: Vec::new(),
                    file_count: 0,
                    total_loc: 0,
                },
                CrateInfo {
                    name: "nested".to_string(),
                    rel_path: private_root.join("crates/nested").display().to_string(),
                    internal_deps: Vec::new(),
                    file_count: 0,
                    total_loc: 0,
                },
            ],
            ..Default::default()
        };

        redact_self_workspace_paths(&mut scan);

        assert_eq!(scan.root_path, ".");
        assert_eq!(scan.crates[0].rel_path, ".");
        assert_eq!(scan.crates[1].rel_path, "crates/nested");
        let json = serde_json::to_string(&scan).expect("scan json");
        assert!(!json.contains(private_root.to_str().expect("utf8 fixture")));
    }

    #[test]
    fn parses_pub_fn_and_struct_lines() {
        assert_eq!(
            parse_symbol_line("pub fn hello(x: u32) {").unwrap(),
            ("fn", "hello".into(), true)
        );
        assert_eq!(
            parse_symbol_line("pub struct Foo {").unwrap(),
            ("struct", "Foo".into(), true)
        );
        assert_eq!(
            parse_symbol_line("    pub(super) async fn run() {").unwrap(),
            ("fn", "run".into(), true)
        );
        assert_eq!(
            parse_symbol_line("fn private() {}").unwrap(),
            ("fn", "private".into(), false)
        );
        assert!(parse_symbol_line("// pub fn comment").is_none());
        assert!(parse_symbol_line("let x = 1;").is_none());
    }

    #[test]
    fn detects_stub_calls() {
        assert_eq!(parse_stub_line("    todo!()").unwrap().0, "todo");
        assert_eq!(
            parse_stub_line("    unimplemented!(\"later\")").unwrap().0,
            "unimplemented"
        );
        assert_eq!(
            parse_stub_line("panic!(\"not yet implemented\")").unwrap().0,
            "panic_not_implemented"
        );
        assert!(parse_stub_line("// todo!() in a comment").is_none());
        assert!(parse_stub_line("let x = 1;").is_none());
    }

    #[test]
    fn use_target_resolves_workspace_crates_only() {
        let mut known: BTreeSet<String> = BTreeSet::new();
        known.insert("crux-mcp".to_string());
        known.insert("corecruxd".to_string());
        assert_eq!(
            parse_use_target("use crux_mcp::tools::sync;", "corecruxd", &known).unwrap(),
            "crux_mcp::tools::sync"
        );
        // `crate::` resolves to the from_crate's own module path.
        assert!(parse_use_target("use crate::http::admin;", "corecruxd", &known)
            .unwrap()
            .starts_with("corecruxd::"));
        // External crates are not emitted.
        assert!(parse_use_target("use serde::Deserialize;", "corecruxd", &known).is_none());
        // Comment line.
        assert!(parse_use_target("// use foo::bar;", "corecruxd", &known).is_none());
    }

    #[test]
    fn count_substring_word_boundary() {
        let s = "foo foo_bar barfoo foo, foo!";
        // `foo` should match only at word boundaries: 3 hits ("foo ", "foo,", "foo!").
        assert_eq!(count_substring(s, "foo").expect("count"), 3);
    }

    #[test]
    fn module_path_inference() {
        let p = Path::new("/x");
        assert_eq!(
            infer_module_path("corecruxd", Path::new("/x"), Path::new("/x/src/main.rs")),
            "corecruxd"
        );
        assert_eq!(
            infer_module_path("corecruxd", p, Path::new("/x/src/http/admin.rs")),
            "corecruxd::http::admin"
        );
        assert_eq!(
            infer_module_path("corecruxd", p, Path::new("/x/src/http/mod.rs")),
            "corecruxd::http"
        );
        assert_eq!(infer_module_path("crux-mcp", p, Path::new("/x/src/lib.rs")), "crux_mcp");
    }

    #[test]
    fn parse_crate_name_finds_package_name() {
        let toml = r#"
[package]
name = "corecruxd"
version = "0.1.0"
"#;
        assert_eq!(parse_crate_name(toml).as_deref(), Some("corecruxd"));
    }

    #[test]
    fn run_scan_at_finds_self() {
        // Run against the Crux workspace in CI / local dev. We don't assert
        // exact counts (they grow over time) — just that the scan runs.
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .unwrap()
            .to_path_buf();
        if !root.join("Cargo.toml").exists() {
            return;
        }
        let scan = run_scan_at(&root).expect("scan");
        assert!(scan.crates.len() > 5, "expected >5 crates, got {}", scan.crates.len());
        assert!(scan.files.len() > 50, "expected >50 .rs files");
        assert!(scan.symbols.len() > 100, "expected >100 symbols");
    }

    #[test]
    fn formats_call_weight_buckets() {
        assert_eq!(format_call_weight(0), "");
        assert_eq!(format_call_weight(1), "");
        assert_eq!(format_call_weight(2), " (2x)");
        assert_eq!(format_call_weight(9), " (9x)");
        assert_eq!(format_call_weight(10), " (many: 10)");
        assert_eq!(format_call_weight(49), " (many: 49)");
        assert_eq!(format_call_weight(50), " (hot: 50)");
        assert_eq!(format_call_weight(455), " (hot: 455)");
    }

    #[test]
    fn detects_test_files_via_path_or_attr() {
        assert!(looks_like_test_file("crates/foo/tests/integration.rs", ""));
        assert!(looks_like_test_file("crates/foo/src/foo_tests.rs", ""));
        assert!(looks_like_test_file("crates/foo/src/tests.rs", ""));
        assert!(looks_like_test_file("src/test/java/com/acme/AppTest.java", ""));
        assert!(looks_like_test_file(
            "app/src/androidTest/java/com/acme/AppTest.java",
            ""
        ));
        assert!(looks_like_test_file(
            "service/src/integrationTest/java/com/acme/AppTest.java",
            ""
        ));
        assert!(!looks_like_test_file("crates/foo/src/foo.rs", "fn x() {}"));
        // First non-comment line is `#![cfg(test)]` → counts as test file.
        let attr_src = "// Copyright\n\n#![cfg(test)]\nfn x() {}\n";
        assert!(looks_like_test_file("crates/foo/src/lib.rs", attr_src));
        // Otherwise normal source.
        let normal = "//! Module docs.\nuse foo::bar;\nfn x() {}\n";
        assert!(!looks_like_test_file("crates/foo/src/lib.rs", normal));
    }

    #[test]
    fn route_hit_without_framework_preserves_frozen_wire_shape() {
        let route = RouteHit {
            method: "GET".to_string(),
            path: "/frozen".to_string(),
            handler_fn: "frozen_handler".to_string(),
            framework: None,
            handler_file: Some("src/handler.rs".to_string()),
            handler_line: Some(7),
            source_file: "src/routes.rs".to_string(),
            source_line: 3,
        };
        assert_eq!(
            serde_json::to_string(&route).expect("route json"),
            r#"{"method":"GET","path":"/frozen","handler_fn":"frozen_handler","handler_file":"src/handler.rs","handler_line":7,"source_file":"src/routes.rs","source_line":3}"#
        );

        let mut scan = WorkspaceScan::default();
        scan.routes.push(RouteHit {
            handler_file: None,
            handler_line: None,
            ..route
        });
        let compact = storyline_compact_json(&scan, false);
        assert_eq!(
            serde_json::to_string(&compact["routes"][0]).expect("compact route json"),
            r#"{"m":"GET","p":"/frozen","h":"frozen_handler","f":null,"chain":[]}"#
        );
    }

    #[test]
    fn parses_file_doc_header() {
        let src = "// Copyright (c) 2026\n// Licensed under...\n\n//! HTTP routes for the workspace scanner. Walks /src under docker-compose.\n//!\n//! More detail here.\n\nuse foo::bar;\n";
        let (full, summary) = parse_file_doc_header(src);
        assert_eq!(summary.as_deref(), Some("HTTP routes for the workspace scanner"));
        assert!(full.unwrap().contains("More detail"));

        let no_header = "use foo::bar;\nfn x() {}\n";
        assert_eq!(parse_file_doc_header(no_header), (None, None));

        // Regression: inner attributes (`#![...]`) between the copyright
        // header and the doc block must not break detection.
        let with_attr =
            "// Copyright\n\n#![recursion_limit = \"256\"]\n\n//! Module docs after attribute.\n\nuse foo;\n";
        let (full2, summary2) = parse_file_doc_header(with_attr);
        assert_eq!(summary2.as_deref(), Some("Module docs after attribute."));
        assert!(full2.is_some());

        let with_allow = "// Copyright\n#![allow(clippy::print_stdout)]\n//! Allowed-attr docs.\n";
        let (_, summary3) = parse_file_doc_header(with_allow);
        assert_eq!(summary3.as_deref(), Some("Allowed-attr docs."));
    }

    #[test]
    fn parses_route_chunk_and_full_source() {
        // Single-line, simple namespace.
        let r = parse_route_chunk(r#""/v1/projects", get(self::projects::get_projects))"#, "x", 1).expect("matches");
        assert_eq!(r.method, "GET");
        assert_eq!(r.path, "/v1/projects");
        assert_eq!(r.handler_fn, "get_projects");

        // Namespaced method (axum::routing::post) with PATCH method.
        let r2 =
            parse_route_chunk(r#""/v1/work/{id}", axum::routing::patch(work::patch_work))"#, "x", 1).expect("matches");
        assert_eq!(r2.method, "PATCH");
        assert_eq!(r2.handler_fn, "patch_work");

        // Wrong method should be rejected.
        assert!(parse_route_chunk(r#""/x", banana(handler))"#, "x", 1).is_none());

        // Multi-line route declaration via the file-level scanner.
        let src = r#"
fn build() {
    Router::new()
        .route(
            "/v1/workspace/scan",
            axum::routing::post(self::workspace::post_scan),
        )
        .route(
            "/v1/workspace/scan",
            get(self::workspace::get_scan),
        );
}
"#;
        let routes = parse_routes_in_source(src, "x.rs").expect("routes");
        assert_eq!(routes.len(), 2);
        assert!(routes
            .iter()
            .any(|r| r.path == "/v1/workspace/scan" && r.method == "POST"));
        assert!(routes
            .iter()
            .any(|r| r.path == "/v1/workspace/scan" && r.method == "GET"));
    }

    #[test]
    fn scans_call_sites_skipping_macros_and_keywords() {
        let line = "    let x = compute_total(a, b) + helper::format(s);";
        let calls = scan_call_sites(line).expect("calls");
        assert!(calls.contains(&"compute_total".to_string()));
        assert!(calls.contains(&"format".to_string()));

        // Macro should be skipped.
        let macro_line = "    println!(\"hi {}\", name);";
        let calls2 = scan_call_sites(macro_line).expect("macro calls");
        assert!(!calls2.contains(&"println".to_string()));

        // Keyword `if (` shouldn't show up as a call.
        let kw_line = "    if (x > 0) { foo() }";
        let calls3 = scan_call_sites(kw_line).expect("keyword calls");
        assert!(!calls3.contains(&"if".to_string()));
        assert!(calls3.contains(&"foo".to_string()));
    }

    #[test]
    fn scans_call_sites_skips_method_calls() {
        // M1 fix: `foo.clone()` is a method call, not a call to a free fn
        // named `clone`. Pre-fix, this matched and resolved to any local
        // `clone` fn, producing bogus edges.
        let m1 = "    let x = obj.clone();";
        assert!(!scan_call_sites(m1)
            .expect("method calls")
            .contains(&"clone".to_string()));

        let m2 = "    map.get(&key)";
        assert!(!scan_call_sites(m2).expect("method calls").contains(&"get".to_string()));

        let m3 = "    let h = headers.get_all(\"X\");";
        assert!(!scan_call_sites(m3)
            .expect("method calls")
            .contains(&"get_all".to_string()));

        // Chained methods — every `.method(` should drop, including the
        // intermediate `.iter()` and `.collect()`.
        let chain = "    items.iter().map(|x| x + 1).collect()";
        let chain_calls = scan_call_sites(chain).expect("chain calls");
        assert!(!chain_calls.contains(&"iter".to_string()));
        assert!(!chain_calls.contains(&"map".to_string()));
        assert!(!chain_calls.contains(&"collect".to_string()));

        // Legit free-fn call still emits.
        let free = "    clone(arg);";
        assert!(scan_call_sites(free)
            .expect("free calls")
            .contains(&"clone".to_string()));

        // Free fn after a path separator (`mod::clone`) still emits — there's
        // no `.` immediately before the identifier.
        let path = "    mymod::clone(arg)";
        assert!(scan_call_sites(path)
            .expect("path calls")
            .contains(&"clone".to_string()));
    }

    #[test]
    fn references_carry_from_symbol_via_cursor() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .unwrap()
            .to_path_buf();
        if !root.join("Cargo.toml").exists() {
            return;
        }
        let scan = run_scan_at(&root).expect("scan");
        // The workspace.rs handler file has `post_scan` which calls
        // `run_scan` (in workspace_scan.rs). Verify the cursor attributes
        // that edge to `post_scan` rather than leaving from_symbol = None.
        let workspace_http = scan
            .files
            .iter()
            .find(|f| f.rel_path.ends_with("corecruxd/src/http/workspace.rs"))
            .expect("http/workspace.rs");
        let edges_with_from: Vec<&FileReference> = workspace_http
            .references
            .iter()
            .filter(|r| r.from_symbol.is_some())
            .collect();
        assert!(
            !edges_with_from.is_empty(),
            "expected at least one edge in http/workspace.rs to carry from_symbol"
        );
        // Pre-M5 every edge had from_symbol = None; the test below would have
        // failed. Post-M5 we expect ≥50% of edges to have a from_symbol set
        // (the rest are top-of-file `use`-site noise).
        let pct = 100 * edges_with_from.len() / workspace_http.references.len();
        assert!(pct >= 50, "from_symbol coverage suspiciously low ({pct}%)");
    }

    #[test]
    fn storyline_composes_for_a_known_route() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .unwrap()
            .to_path_buf();
        if !root.join("Cargo.toml").exists() {
            return;
        }
        let scan = run_scan_at(&root).expect("scan");
        let route = scan
            .routes
            .iter()
            .find(|r| r.path == "/v1/workspace/scan" && r.method == "POST")
            .expect("POST /v1/workspace/scan");
        let story = compose_storyline_for_route(&scan, route, false).expect("storyline");
        assert!(story.stats.total_nodes >= 1);
        // The handler's edge_symbols should be the handler fn name.
        assert_eq!(story.root.edge_symbols, vec!["post_scan".to_string()]);
        // Tree-art renderer should produce something with the handler name.
        let tree = format_storyline_tree(&story);
        assert!(tree.contains("post_scan"), "tree output: {tree}");
        assert!(tree.contains("POST /v1/workspace/scan"), "tree output: {tree}");
    }

    #[test]
    fn full_scan_emits_unresolved_routes_diagnostic() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .unwrap()
            .to_path_buf();
        if !root.join("Cargo.toml").exists() {
            return;
        }
        let scan = run_scan_at(&root).expect("scan");
        let unresolved_total = scan.routes.iter().filter(|r| r.handler_file.is_none()).count();
        assert_eq!(
            scan.diagnostics.unresolved_routes.len(),
            unresolved_total,
            "diagnostic count must match the routes-without-handler count"
        );
        for u in &scan.diagnostics.unresolved_routes {
            assert!(
                matches!(u.reason.as_str(), "not_found" | "ambiguous"),
                "diagnostic reason must be one of {{not_found, ambiguous}}, got {}",
                u.reason
            );
            assert!(!u.handler_fn.is_empty());
        }
    }

    #[test]
    fn full_scan_emits_routes_by_crate() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .unwrap()
            .to_path_buf();
        if !root.join("Cargo.toml").exists() {
            return;
        }
        let scan = run_scan_at(&root).expect("scan");
        let total_routes_in_map: usize = scan.stats.routes_by_crate.values().sum();
        let resolved_routes = scan.routes.iter().filter(|r| r.handler_file.is_some()).count();
        assert_eq!(
            total_routes_in_map, resolved_routes,
            "routes_by_crate should sum to the count of routes with a resolved handler_file"
        );
        // corecruxd has the lion's share (~150/170 in current state).
        assert!(
            scan.stats.routes_by_crate.get("corecruxd").copied().unwrap_or(0) >= 100,
            "expected ≥100 routes in corecruxd"
        );
    }

    #[test]
    fn full_scan_emits_doc_coverage_stat() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .unwrap()
            .to_path_buf();
        if !root.join("Cargo.toml").exists() {
            return;
        }
        let scan = run_scan_at(&root).expect("scan");
        let pct = if scan.stats.file_count == 0 {
            0
        } else {
            100 * scan.stats.doc_coverage_files / scan.stats.file_count
        };
        assert!(
            scan.stats.doc_coverage_files > 0,
            "expected some files with //! headers"
        );
        assert!(pct >= 40, "doc coverage suspiciously low ({pct}%)");
        // Cross-check: the count must match a fresh re-filter.
        let re_count = scan.files.iter().filter(|f| f.doc_summary.is_some()).count();
        assert_eq!(scan.stats.doc_coverage_files, re_count);
    }

    #[test]
    fn full_scan_emits_routes_and_references() {
        // Run against the Crux workspace; assert the new artefacts exist.
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .unwrap()
            .to_path_buf();
        if !root.join("Cargo.toml").exists() {
            return;
        }
        let scan = run_scan_at(&root).expect("scan");
        assert!(
            scan.routes.len() > 20,
            "expected >20 routes (corecruxd has ~80), got {}",
            scan.routes.len()
        );
        // Spot-check a known route.
        assert!(
            scan.routes
                .iter()
                .any(|r| r.path == "/v1/workspace/scan" && r.method == "POST"),
            "POST /v1/workspace/scan should be detected"
        );
        // file_reference_count > 0 — we have ~thousands of internal calls.
        assert!(
            scan.stats.file_reference_count > 100,
            "expected >100 file references, got {}",
            scan.stats.file_reference_count
        );
        // doc_summary present on workspace_scan.rs (its own header).
        let me = scan
            .files
            .iter()
            .find(|f| f.rel_path.ends_with("corecrux-workspace-scan/src/workspace_scan.rs"));
        assert!(me.is_some(), "scan should include workspace_scan.rs");
        assert!(me.unwrap().doc_summary.is_some(), "workspace_scan.rs has a //! header");
    }

    #[test]
    fn stub_detector_skips_its_own_source() {
        // Regression: workspace_scan.rs contains the literal `todo!(`,
        // `unimplemented!(`, `panic!(...)` strings inside `parse_stub_line`
        // and its tests. Pre-fix, the detector matched them against itself
        // and reported 6 false-positive stubs in workspace_scan.rs alone.
        // Post-fix, the file is skipped entirely from stub scanning.
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .unwrap()
            .to_path_buf();
        if !root.join("Cargo.toml").exists() {
            return;
        }
        let scan = run_scan_at(&root).expect("scan");
        let self_stubs: Vec<&StubHit> = scan
            .stubs
            .iter()
            .filter(|s| {
                s.file_rel_path
                    .ends_with("corecrux-workspace-scan/src/workspace_scan.rs")
            })
            .collect();
        assert!(
            self_stubs.is_empty(),
            "stub detector matched against its own source: {} false-positive(s) at {:?}",
            self_stubs.len(),
            self_stubs.iter().map(|s| s.line).collect::<Vec<_>>()
        );
    }

    #[test]
    #[serial_test::serial]
    fn flag_off_invokes_regex_path() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let crate_dir = tmp.path().join("crates/demo");
        std::fs::create_dir_all(crate_dir.join("src")).expect("fixture dirs");
        std::fs::write(
            tmp.path().join("Cargo.toml"),
            "[workspace]\nmembers = [\"crates/demo\"]\n",
        )
        .expect("workspace toml");
        std::fs::write(
            crate_dir.join("Cargo.toml"),
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .expect("crate toml");
        std::fs::write(
            crate_dir.join("src/lib.rs"),
            "//! Demo.\n\npub fn entry() { helper(); }\nfn helper() {}\n",
        )
        .expect("lib");

        std::env::remove_var("CORECRUXD_AST_SCAN");
        assert!(!ast_scan_enabled_from_env());
        let via_flag = run_scan_at(tmp.path()).expect("flag-off scan");
        let direct_regex = run_scan_regex_at(tmp.path()).expect("direct regex scan");

        let mut via_flag = serde_json::to_value(via_flag).expect("flag json");
        let mut direct_regex = serde_json::to_value(direct_regex).expect("regex json");
        for value in [&mut via_flag, &mut direct_regex] {
            let obj = value.as_object_mut().expect("scan object");
            obj.insert(
                "scan_id".to_string(),
                serde_json::Value::String("normalized".to_string()),
            );
            obj.insert("started_at_unix_ms".to_string(), serde_json::Value::from(0));
            obj.insert("finished_at_unix_ms".to_string(), serde_json::Value::from(0));
            obj.insert("duration_ms".to_string(), serde_json::Value::from(0));
        }
        assert_eq!(via_flag, direct_regex);

        std::env::set_var("CORECRUXD_AST_SCAN", "0");
        assert!(!ast_scan_enabled_from_env());
        std::env::set_var("CORECRUXD_AST_SCAN", "1");
        assert!(ast_scan_enabled_from_env());
        std::env::remove_var("CORECRUXD_AST_SCAN");
    }
}
