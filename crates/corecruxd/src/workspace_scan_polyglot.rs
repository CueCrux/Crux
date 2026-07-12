// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Polyglot code-structure scanner backed by tree-sitter for non-Rust files.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

use tree_sitter::{Node, Parser};

use crate::workspace_scan::{
    parse_file_doc_header, parse_internal_path_deps, walk_dir, CrateInfo, DepEdge, FileInfo, FileReference, RouteHit,
    ScanDiagnostics, ScanError, ScanStats, SymbolInfo, UnresolvedRoute, V3SkippedFile, WorkspaceScan,
};

const POLYGLOT_V2_ENV: &str = "CORECRUXD_POLYGLOT_V2";
const POLYGLOT_V3_ENV: &str = "CORECRUXD_POLYGLOT_V3";
pub(crate) const POLYGLOT_AST_MAX_DEPTH: usize = 512;
pub(crate) const POLYGLOT_JS_MAX_BYTES: usize = 1024 * 1024;
pub(crate) const POLYGLOT_JS_MAX_LINE_BYTES: usize = 10_000;
pub(crate) const POLYGLOT_JAVA_MAX_BYTES: usize = 1024 * 1024;
pub(crate) const POLYGLOT_JAVA_MAX_LINE_BYTES: usize = 10_000;
pub(crate) const POLYGLOT_C_MAX_BYTES: usize = 1024 * 1024;
pub(crate) const POLYGLOT_C_MAX_LINE_BYTES: usize = 10_000;
pub(crate) const POLYGLOT_CPP_MAX_BYTES: usize = 1024 * 1024;
pub(crate) const POLYGLOT_CPP_MAX_LINE_BYTES: usize = 10_000;

#[derive(Debug, Clone, Copy)]
struct PolyglotScanOptions {
    v2_enabled: bool,
    v3_enabled: bool,
}

impl PolyglotScanOptions {
    fn from_env() -> Self {
        Self {
            v2_enabled: polyglot_v2_enabled_from_env(),
            v3_enabled: polyglot_v3_enabled(),
        }
    }
}

pub(crate) fn polyglot_v2_enabled_from_env() -> bool {
    crate::workspace_scan_manifests::env_flag_enabled(POLYGLOT_V2_ENV)
}

pub(crate) fn polyglot_v3_enabled() -> bool {
    crate::workspace_scan_manifests::env_flag_enabled(POLYGLOT_V3_ENV)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LanguageKind {
    Rust,
    TypeScript,
    Tsx,
    Python,
    Vue,
    Go,
    Java,
    C,
    Cpp,
}

#[derive(Debug, Clone)]
struct SourceBlock {
    text: String,
    start_line_offset: usize,
}

#[derive(Debug, Clone)]
struct ExtractedFile {
    rel_path: String,
    package_name: String,
    module_path: String,
    loc: usize,
    doc_summary: Option<String>,
    doc_full: Option<String>,
    is_test_file: bool,
    symbols: Vec<SymbolInfo>,
    symbol_keys: HashSet<(String, String)>,
    local_bindings: HashMap<String, LocalBinding>,
    deps: Vec<DepEdge>,
    calls: Vec<CallSite>,
    routes: Vec<RouteCandidate>,
    ast_depth_limit_hits: usize,
}

#[derive(Debug, Clone)]
struct LocalBinding {
    line: usize,
}

#[derive(Debug, Clone)]
struct CallSite {
    name: String,
    from_symbol: Option<String>,
}

#[derive(Debug, Clone)]
struct RouteCandidate {
    method: String,
    path: String,
    handler: RouteHandler,
    source_file: String,
    source_line: usize,
}

#[derive(Debug, Clone)]
enum RouteHandler {
    Named(String),
    Inline,
}

#[derive(Debug, Default)]
struct AstWalkGuard {
    depth_limit_hits: usize,
}

impl AstWalkGuard {
    fn allow_depth(&mut self, depth: usize) -> bool {
        if depth <= POLYGLOT_AST_MAX_DEPTH {
            return true;
        }
        self.depth_limit_hits += 1;
        false
    }
}

pub(crate) fn run_repo_scan_at(root: &Path) -> Result<WorkspaceScan, ScanError> {
    let options = PolyglotScanOptions::from_env();
    let mut scan = if should_use_rust_workspace_scan_with_options(root, options) {
        crate::workspace_scan::run_scan_at(root)?
    } else if has_rust_workspace(root) {
        // Cargo workspace + polyglot files: scan the cargo tree natively so
        // crate structure and route extraction survive, then merge the
        // tree-sitter extraction of the non-Rust files on top. Without this a
        // single stray .ts/.py file used to flatten a 28-crate workspace into
        // one package with zero routes.
        let mut scan = crate::workspace_scan::run_scan_at(root)?;
        let poly = run_polyglot_scan_inner(root, false, options)?;
        merge_polyglot_scan(&mut scan, poly, options);
        scan
    } else {
        run_polyglot_scan_inner(root, true, options)?
    };
    crate::workspace_scan_manifests::attach_external_deps_if_enabled(root, &mut scan);
    Ok(scan)
}

pub(crate) fn has_rust_workspace(root: &Path) -> bool {
    root.join("Cargo.toml").exists() && has_supported_file(root, &[Some("rs")])
}

pub(crate) fn should_use_rust_workspace_scan(root: &Path) -> bool {
    should_use_rust_workspace_scan_with_options(root, PolyglotScanOptions::from_env())
}

fn should_use_rust_workspace_scan_with_options(root: &Path, options: PolyglotScanOptions) -> bool {
    has_rust_workspace(root) && !has_polyglot_non_rust_files(root, options)
}

/// Fold a rust-excluded polyglot scan into a native Rust workspace scan.
/// Crates, routes, stubs and dead-code stay authoritative from the Rust side;
/// files/symbols/deps are unioned and the stats re-rolled from the merged
/// contents.
fn merge_polyglot_scan(scan: &mut WorkspaceScan, poly: WorkspaceScan, options: PolyglotScanOptions) {
    let existing: std::collections::BTreeSet<String> = scan.crates.iter().map(|c| c.name.clone()).collect();
    scan.crates
        .extend(poly.crates.into_iter().filter(|c| !existing.contains(&c.name)));
    scan.files.extend(poly.files);
    scan.symbols.extend(poly.symbols);
    scan.deps.extend(poly.deps);
    if options.v2_enabled {
        scan.routes.extend(poly.routes);
        scan.diagnostics
            .unresolved_routes
            .extend(poly.diagnostics.unresolved_routes);
    }
    if options.v3_enabled {
        scan.diagnostics
            .v3_skipped_files
            .extend(poly.diagnostics.v3_skipped_files);
    }
    scan.duration_ms += poly.duration_ms;
    scan.finished_at_unix_ms = scan.finished_at_unix_ms.max(poly.finished_at_unix_ms);
    roll_up_stats(scan);
}

#[cfg(test)]
pub(crate) fn run_polyglot_scan_at(root: &Path) -> Result<WorkspaceScan, ScanError> {
    run_polyglot_scan_inner(root, true, PolyglotScanOptions::from_env())
}

fn run_polyglot_scan_inner(
    root: &Path,
    include_rust: bool,
    options: PolyglotScanOptions,
) -> Result<WorkspaceScan, ScanError> {
    let started_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64);
    let started_inst = std::time::Instant::now();
    let package_name = discover_package_name(root);
    let files = supported_files(root, include_rust, options)?;
    let mut extracted = Vec::new();
    let mut v3_skipped_files = Vec::new();
    for (abs, lang) in files {
        if let Some(file) =
            extract_file_recording_skips(root, &abs, lang, &package_name, options, &mut v3_skipped_files)?
        {
            extracted.push(file);
        }
    }

    let mut scan = WorkspaceScan {
        scan_id: format!("ws_{started_ms}"),
        root_path: root.display().to_string(),
        started_at_unix_ms: started_ms,
        diagnostics: ScanDiagnostics {
            v3_skipped_files,
            ..ScanDiagnostics::default()
        },
        ..Default::default()
    };
    let mut file_idx_by_path = HashMap::new();
    let mut symbol_by_name: HashMap<String, Vec<SymbolInfo>> = HashMap::new();

    for file in &extracted {
        file_idx_by_path.insert(file.rel_path.clone(), scan.files.len());
        scan.files.push(FileInfo {
            rel_path: file.rel_path.clone(),
            crate_name: file.package_name.clone(),
            module_path: file.module_path.clone(),
            loc: file.loc,
            symbol_count: file.symbols.len(),
            stub_count: 0,
            doc_summary: file.doc_summary.clone(),
            doc_full: file.doc_full.clone(),
            defines: file.symbols.iter().map(|s| s.name.clone()).collect(),
            references: Vec::new(),
            referenced_by: Vec::new(),
            is_test_file: file.is_test_file,
        });
        scan.deps.extend(file.deps.iter().cloned());
        for symbol in &file.symbols {
            symbol_by_name
                .entry(symbol.name.clone())
                .or_default()
                .push(symbol.clone());
            scan.symbols.push(symbol.clone());
        }
    }

    resolve_polyglot_references(&mut scan, &extracted, &file_idx_by_path, &symbol_by_name);
    build_referenced_by(&mut scan);
    scan.crates = package_infos(root, &scan, &package_name);
    if options.v2_enabled {
        resolve_polyglot_routes(&mut scan, &extracted, &symbol_by_name);
    }
    roll_up_stats(&mut scan);
    let elapsed_ms = started_inst.elapsed().as_millis() as u64;
    scan.finished_at_unix_ms = scan.started_at_unix_ms + elapsed_ms;
    scan.duration_ms = elapsed_ms;
    Ok(scan)
}

fn supported_files(
    root: &Path,
    include_rust: bool,
    options: PolyglotScanOptions,
) -> Result<Vec<(PathBuf, LanguageKind)>, ScanError> {
    let mut files = Vec::new();
    walk_dir(root, root, &mut |rel, abs| {
        if should_skip_generated_polyglot_file(rel, options) {
            return;
        }
        if let Some(lang) = language_for_path(abs, options) {
            if include_rust || lang != LanguageKind::Rust {
                files.push((abs.to_path_buf(), lang));
            }
        }
    })?;
    files.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(files)
}

fn language_for_path(path: &Path, options: PolyglotScanOptions) -> Option<LanguageKind> {
    match path.extension().and_then(|e| e.to_str()).unwrap_or_default() {
        "rs" => Some(LanguageKind::Rust),
        "ts" => Some(LanguageKind::TypeScript),
        "tsx" => Some(LanguageKind::Tsx),
        "py" => Some(LanguageKind::Python),
        "vue" => Some(LanguageKind::Vue),
        "js" | "mjs" | "cjs" if options.v2_enabled => Some(LanguageKind::TypeScript),
        "jsx" if options.v2_enabled => Some(LanguageKind::Tsx),
        "go" if options.v2_enabled => Some(LanguageKind::Go),
        "java" if options.v3_enabled => Some(LanguageKind::Java),
        "c" if options.v3_enabled => Some(LanguageKind::C),
        // Ambiguous .h headers enter as C, then a deterministic source sniff
        // upgrades obvious namespace/template/extern-C++ headers after reading.
        // Explicit C++ header suffixes map directly to C++.
        "h" if options.v3_enabled => Some(LanguageKind::C),
        "cpp" | "cc" | "cxx" | "hpp" | "hh" | "hxx" if options.v3_enabled => Some(LanguageKind::Cpp),
        _ => None,
    }
}

fn language_for_source(lang: LanguageKind, path: &Path, src: &str) -> LanguageKind {
    let is_h_header = path.extension().and_then(|extension| extension.to_str()) == Some("h");
    if lang == LanguageKind::C && is_h_header && header_looks_cpp(src) {
        LanguageKind::Cpp
    } else {
        lang
    }
}

fn header_looks_cpp(src: &str) -> bool {
    // Deliberately a plain, deterministic substring sniff. Comments/strings
    // can false-positive, but results never depend on filesystem/toolchain state.
    src.contains("namespace ")
        || src.contains("template<")
        || src.contains("template <")
        || src.contains("extern \"C++\"")
}

fn should_skip_generated_polyglot_file(rel: &Path, options: PolyglotScanOptions) -> bool {
    let extension = rel.extension().and_then(|e| e.to_str()).unwrap_or_default();
    let is_v2_js = options.v2_enabled && matches!(extension, "js" | "jsx" | "mjs" | "cjs");
    let is_v3_source = options.v3_enabled
        && matches!(
            extension,
            "java" | "c" | "h" | "cpp" | "cc" | "cxx" | "hpp" | "hh" | "hxx"
        );
    rel.components().any(|component| {
        let segment = component.as_os_str().to_string_lossy();
        let existing_generated_dir = matches!(
            segment.as_ref(),
            "dist" | "build" | "out" | ".next" | ".nuxt" | ".output" | "coverage"
        );
        (is_v2_js && existing_generated_dir)
            || (is_v3_source
                && (existing_generated_dir
                    || matches!(segment.as_ref(), "target" | "vendor" | "vendored" | "third_party")))
    })
}

#[cfg(test)]
fn extract_file(
    root: &Path,
    abs: &Path,
    lang: LanguageKind,
    package_name: &str,
    options: PolyglotScanOptions,
) -> Result<Option<ExtractedFile>, ScanError> {
    extract_file_recording_skips(root, abs, lang, package_name, options, &mut Vec::new())
}

fn extract_file_recording_skips(
    root: &Path,
    abs: &Path,
    lang: LanguageKind,
    package_name: &str,
    options: PolyglotScanOptions,
    v3_skipped_files: &mut Vec<V3SkippedFile>,
) -> Result<Option<ExtractedFile>, ScanError> {
    let rel_path = rel_string(root, abs);
    if let Some(reason) = pathological_v3_size_skip_reason(&rel_path, abs, lang, options) {
        v3_skipped_files.push(V3SkippedFile {
            rel_path,
            reason: reason.to_string(),
        });
        return Ok(None);
    }
    let src = std::fs::read_to_string(abs).unwrap_or_default();
    if should_skip_pathological_v2_js(&rel_path, &src, options) {
        return Ok(None);
    }
    let lang = language_for_source(lang, abs, &src);
    if let Some(reason) = pathological_v3_source_skip_reason(&rel_path, &src, lang, options) {
        v3_skipped_files.push(V3SkippedFile {
            rel_path,
            reason: reason.to_string(),
        });
        return Ok(None);
    }
    let loc = src.lines().count();
    let (doc_full, doc_summary) = parse_file_doc_header(&src);
    let is_test_file = crate::workspace_scan::looks_like_test_file(&rel_path, &src)
        || rel_path.ends_with(".test.ts")
        || rel_path.ends_with(".spec.ts")
        || rel_path.ends_with(".test.js")
        || rel_path.ends_with(".spec.js")
        || rel_path.ends_with("_test.go")
        || rel_path.contains("/test_")
        || rel_path.contains("/tests/");
    let module_path = module_path(package_name, &rel_path);
    let mut file = ExtractedFile {
        rel_path: rel_path.clone(),
        package_name: package_name.to_string(),
        module_path,
        loc,
        doc_summary,
        doc_full,
        is_test_file,
        symbols: Vec::new(),
        symbol_keys: HashSet::new(),
        local_bindings: HashMap::new(),
        deps: Vec::new(),
        calls: Vec::new(),
        routes: Vec::new(),
        ast_depth_limit_hits: 0,
    };
    let mut guard = AstWalkGuard::default();

    match lang {
        LanguageKind::Rust => extract_rust_file(&src, &mut file, &mut guard),
        LanguageKind::TypeScript => extract_ts_block(&src, 0, false, &mut file, options, &mut guard)?,
        LanguageKind::Tsx => extract_ts_block(&src, 0, true, &mut file, options, &mut guard)?,
        LanguageKind::Python => extract_python_file(&src, &mut file, options, &mut guard)?,
        LanguageKind::Vue => {
            for block in vue_script_blocks(&src) {
                extract_ts_block(
                    &block.text,
                    block.start_line_offset,
                    false,
                    &mut file,
                    options,
                    &mut guard,
                )?;
            }
        }
        LanguageKind::Go => extract_go_file(&src, &mut file, options, &mut guard)?,
        LanguageKind::Java => extract_java_file(&src, &mut file, &mut guard)?,
        LanguageKind::C => extract_c_family_file(&src, &mut file, false, &mut guard)?,
        LanguageKind::Cpp => extract_c_family_file(&src, &mut file, true, &mut guard)?,
    }
    file.ast_depth_limit_hits = guard.depth_limit_hits;
    if file.ast_depth_limit_hits > 0 {
        tracing::warn!(
            file = %file.rel_path,
            max_depth = POLYGLOT_AST_MAX_DEPTH,
            depth_limit_hits = file.ast_depth_limit_hits,
            "polyglot ast walk depth limit reached; stopped descending"
        );
    }
    Ok(Some(file))
}

fn should_skip_pathological_v2_js(rel_path: &str, src: &str, options: PolyglotScanOptions) -> bool {
    if !options.v2_enabled || !is_v2_js_path(rel_path) {
        return false;
    }
    let byte_len = src.len();
    let longest_line = src.lines().map(str::len).max().unwrap_or(0);
    if byte_len <= POLYGLOT_JS_MAX_BYTES && longest_line <= POLYGLOT_JS_MAX_LINE_BYTES {
        return false;
    }
    tracing::warn!(
        file = %rel_path,
        bytes = byte_len,
        max_bytes = POLYGLOT_JS_MAX_BYTES,
        longest_line_bytes = longest_line,
        max_line_bytes = POLYGLOT_JS_MAX_LINE_BYTES,
        "polyglot v2 js file skipped before parsing"
    );
    true
}

fn is_v2_js_path(path: &str) -> bool {
    matches!(
        Path::new(path)
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or_default(),
        "js" | "jsx" | "mjs" | "cjs"
    )
}

fn v3_source_limits(lang: LanguageKind) -> Option<(usize, usize)> {
    match lang {
        LanguageKind::Java => Some((POLYGLOT_JAVA_MAX_BYTES, POLYGLOT_JAVA_MAX_LINE_BYTES)),
        LanguageKind::C => Some((POLYGLOT_C_MAX_BYTES, POLYGLOT_C_MAX_LINE_BYTES)),
        LanguageKind::Cpp => Some((POLYGLOT_CPP_MAX_BYTES, POLYGLOT_CPP_MAX_LINE_BYTES)),
        _ => None,
    }
}

fn pathological_v3_size_skip_reason(
    rel_path: &str,
    abs: &Path,
    lang: LanguageKind,
    options: PolyglotScanOptions,
) -> Option<&'static str> {
    if !options.v3_enabled {
        return None;
    }
    let (max_bytes, _) = v3_source_limits(lang)?;
    let metadata = match std::fs::symlink_metadata(abs) {
        Ok(metadata) => metadata,
        Err(err) => {
            tracing::warn!(file = %rel_path, ?err, "polyglot v3 file skipped before reading; metadata unavailable");
            return Some("metadata_unavailable");
        }
    };
    if !metadata.file_type().is_file() {
        tracing::warn!(file = %rel_path, "polyglot v3 non-regular file skipped before reading");
        return Some("non_regular_file");
    }
    let byte_len = metadata.len();
    if byte_len <= max_bytes as u64 {
        return None;
    }
    tracing::warn!(
        file = %rel_path,
        bytes = byte_len,
        max_bytes,
        "polyglot v3 file skipped before reading or parsing"
    );
    Some("max_bytes")
}

fn pathological_v3_source_skip_reason(
    rel_path: &str,
    src: &str,
    lang: LanguageKind,
    options: PolyglotScanOptions,
) -> Option<&'static str> {
    if !options.v3_enabled {
        return None;
    }
    let (max_bytes, max_line_bytes) = v3_source_limits(lang)?;
    let byte_len = src.len();
    let longest_line = src.lines().map(str::len).max().unwrap_or(0);
    let delimiter_depth = max_source_delimiter_depth(src, POLYGLOT_AST_MAX_DEPTH, lang);
    if byte_len <= max_bytes && longest_line <= max_line_bytes && delimiter_depth <= POLYGLOT_AST_MAX_DEPTH {
        return None;
    }
    tracing::warn!(
        file = %rel_path,
        bytes = byte_len,
        max_bytes,
        longest_line_bytes = longest_line,
        max_line_bytes,
        delimiter_depth,
        max_depth = POLYGLOT_AST_MAX_DEPTH,
        "polyglot v3 file skipped before parsing"
    );
    if byte_len > max_bytes {
        Some("max_bytes")
    } else if longest_line > max_line_bytes {
        Some("max_line_bytes")
    } else {
        Some("max_delimiter_depth")
    }
}

/// Cheap, non-recursive admission guard for delimiter and template/generic
/// nesting before native parsing. Deep non-bracket LR chains are intentionally
/// left to tree-sitter's heap parse stack; the AST walk is separately capped.
fn max_source_delimiter_depth(src: &str, stop_after: usize, lang: LanguageKind) -> usize {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum LexState {
        Code,
        LineComment,
        BlockComment,
        SingleQuoted,
        DoubleQuoted,
        JavaTextBlock,
    }

    let bytes = src.as_bytes();
    let include_angle_brackets = matches!(lang, LanguageKind::Java | LanguageKind::Cpp);
    let mut state = LexState::Code;
    let mut escaped = false;
    let mut depth = 0_usize;
    let mut angle_depth = 0_usize;
    let mut max_depth = 0_usize;
    let mut index = 0_usize;
    while index < bytes.len() {
        let byte = bytes[index];
        let next = bytes.get(index + 1).copied();
        match state {
            LexState::Code => match (byte, next) {
                (b'/', Some(b'/')) => {
                    state = LexState::LineComment;
                    index += 1;
                }
                (b'/', Some(b'*')) => {
                    state = LexState::BlockComment;
                    index += 1;
                }
                (b'"', _)
                    if lang == LanguageKind::Java
                        && bytes.get(index..).is_some_and(|tail| tail.starts_with(b"\"\"\"")) =>
                {
                    state = LexState::JavaTextBlock;
                    escaped = false;
                    index += 2;
                }
                _ if lang == LanguageKind::Cpp => {
                    if let Some(end_index) = cpp_raw_string_end(bytes, index) {
                        index = end_index;
                    } else if byte == b'\'' && !is_c_family_digit_separator(bytes, index) {
                        state = LexState::SingleQuoted;
                        escaped = false;
                    } else if byte == b'"' {
                        state = LexState::DoubleQuoted;
                        escaped = false;
                    } else {
                        update_source_delimiter_depth(
                            byte,
                            include_angle_brackets,
                            &mut depth,
                            &mut angle_depth,
                            &mut max_depth,
                        );
                        if max_depth > stop_after {
                            return max_depth;
                        }
                    }
                }
                (b'\'', _) if lang == LanguageKind::C && is_c_family_digit_separator(bytes, index) => {}
                (b'\'', _) => {
                    state = LexState::SingleQuoted;
                    escaped = false;
                }
                (b'"', _) => {
                    state = LexState::DoubleQuoted;
                    escaped = false;
                }
                _ => {
                    update_source_delimiter_depth(
                        byte,
                        include_angle_brackets,
                        &mut depth,
                        &mut angle_depth,
                        &mut max_depth,
                    );
                    if max_depth > stop_after {
                        return max_depth;
                    }
                }
            },
            LexState::LineComment => {
                if byte == b'\n' {
                    state = LexState::Code;
                }
            }
            LexState::BlockComment => {
                if byte == b'*' && next == Some(b'/') {
                    state = LexState::Code;
                    index += 1;
                }
            }
            LexState::SingleQuoted | LexState::DoubleQuoted => {
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if (state == LexState::SingleQuoted && byte == b'\'')
                    || (state == LexState::DoubleQuoted && byte == b'"')
                {
                    state = LexState::Code;
                }
            }
            LexState::JavaTextBlock => {
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if bytes.get(index..).is_some_and(|tail| tail.starts_with(b"\"\"\"")) {
                    state = LexState::Code;
                    index += 2;
                }
            }
        }
        index += 1;
    }
    max_depth
}

fn update_source_delimiter_depth(
    byte: u8,
    include_angle_brackets: bool,
    depth: &mut usize,
    angle_depth: &mut usize,
    max_depth: &mut usize,
) {
    match byte {
        b'(' | b'[' | b'{' => {
            if include_angle_brackets && byte == b'{' {
                *angle_depth = 0;
            }
            *depth += 1;
            *max_depth = (*max_depth).max(*depth);
        }
        b')' | b']' | b'}' => {
            if include_angle_brackets && byte == b'}' {
                *angle_depth = 0;
            }
            *depth = depth.saturating_sub(1);
        }
        b'<' if include_angle_brackets => {
            *angle_depth += 1;
            *max_depth = (*max_depth).max(*angle_depth);
        }
        b'>' if include_angle_brackets => *angle_depth = angle_depth.saturating_sub(1),
        b';' if include_angle_brackets => *angle_depth = 0,
        _ => {}
    }
}

fn is_c_family_digit_separator(bytes: &[u8], index: usize) -> bool {
    bytes.get(index.wrapping_sub(1)).is_some_and(u8::is_ascii_alphanumeric)
        && bytes.get(index + 1).is_some_and(u8::is_ascii_alphanumeric)
}

fn cpp_raw_string_end(bytes: &[u8], start: usize) -> Option<usize> {
    if start > 0 && (bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_') {
        return None;
    }
    let prefix = [b"u8R\"".as_slice(), b"uR\"", b"UR\"", b"LR\"", b"R\""]
        .into_iter()
        .find(|prefix| bytes.get(start..).is_some_and(|tail| tail.starts_with(prefix)))?;
    let delimiter_start = start + prefix.len();
    let open_paren = (delimiter_start..bytes.len().min(delimiter_start + 17)).find(|index| bytes[*index] == b'(')?;
    let delimiter = &bytes[delimiter_start..open_paren];
    if delimiter
        .iter()
        .any(|byte| byte.is_ascii_whitespace() || matches!(*byte, b'(' | b')' | b'\\'))
    {
        return None;
    }
    for close_paren in open_paren + 1..bytes.len() {
        if bytes[close_paren] != b')' {
            continue;
        }
        let delimiter_end = close_paren + 1 + delimiter.len();
        if bytes.get(close_paren + 1..delimiter_end) == Some(delimiter) && bytes.get(delimiter_end) == Some(&b'"') {
            return Some(delimiter_end);
        }
    }
    Some(bytes.len().saturating_sub(1))
}

fn extract_rust_file(src: &str, file: &mut ExtractedFile, guard: &mut AstWalkGuard) {
    let Ok(parsed) = syn::parse_file(src) else {
        return;
    };
    for item in &parsed.items {
        match item {
            syn::Item::Fn(f) => push_symbol(
                file,
                "fn",
                &f.sig.ident.to_string(),
                line_of(src, &f.sig.ident.to_string()),
                is_pub(&f.vis),
            ),
            syn::Item::Struct(s) => push_symbol(
                file,
                "class",
                &s.ident.to_string(),
                line_of(src, &s.ident.to_string()),
                is_pub(&s.vis),
            ),
            syn::Item::Enum(e) => push_symbol(
                file,
                "class",
                &e.ident.to_string(),
                line_of(src, &e.ident.to_string()),
                is_pub(&e.vis),
            ),
            syn::Item::Trait(t) => push_symbol(
                file,
                "interface",
                &t.ident.to_string(),
                line_of(src, &t.ident.to_string()),
                is_pub(&t.vis),
            ),
            syn::Item::Type(t) => push_symbol(
                file,
                "type",
                &t.ident.to_string(),
                line_of(src, &t.ident.to_string()),
                is_pub(&t.vis),
            ),
            syn::Item::Const(c) => push_symbol(
                file,
                "const",
                &c.ident.to_string(),
                line_of(src, &c.ident.to_string()),
                is_pub(&c.vis),
            ),
            syn::Item::Use(u) => {
                for raw in rust_use_paths(&u.tree, guard) {
                    file.deps.push(DepEdge {
                        from_crate: file.package_name.clone(),
                        from_file: file.rel_path.clone(),
                        to_module: raw.clone(),
                        raw: format!("use {raw};"),
                    });
                }
            }
            _ => {}
        }
    }
}

#[derive(Debug)]
struct TsWalkContext<'src, 'guard> {
    src: &'src [u8],
    line_offset: usize,
    options: PolyglotScanOptions,
    guard: &'guard mut AstWalkGuard,
}

#[derive(Debug, Clone)]
struct TsWalkState {
    current_fn: Option<String>,
    exported: bool,
    controller_prefix: Option<String>,
    top_level: bool,
    depth: usize,
}

fn extract_ts_block(
    src: &str,
    line_offset: usize,
    tsx: bool,
    file: &mut ExtractedFile,
    options: PolyglotScanOptions,
    guard: &mut AstWalkGuard,
) -> Result<(), ScanError> {
    let mut parser = Parser::new();
    let language = if tsx {
        tree_sitter_typescript::LANGUAGE_TSX
    } else {
        tree_sitter_typescript::LANGUAGE_TYPESCRIPT
    };
    parser
        .set_language(&language.into())
        .map_err(|err| ScanError::Io(std::io::Error::other(err.to_string())))?;
    let Some(tree) = parser.parse(src, None) else {
        return Ok(());
    };
    let bytes = src.as_bytes();
    let mut ctx = TsWalkContext {
        src: bytes,
        line_offset,
        options,
        guard,
    };
    walk_ts_node(
        tree.root_node(),
        &mut ctx,
        file,
        TsWalkState {
            current_fn: None,
            exported: false,
            controller_prefix: None,
            top_level: true,
            depth: 0,
        },
    );
    Ok(())
}

fn walk_ts_node(node: Node<'_>, ctx: &mut TsWalkContext<'_, '_>, file: &mut ExtractedFile, state: TsWalkState) {
    if !ctx.guard.allow_depth(state.depth) {
        return;
    }
    let src = ctx.src;
    let line_offset = ctx.line_offset;
    let options = ctx.options;
    let kind = node.kind();
    let is_export = state.exported || kind == "export_statement";
    match kind {
        "function_declaration" | "function_signature" => {
            if let Some(name) = field_ident(node, src, "name") {
                if state.top_level {
                    push_local_binding(file, &name, line_offset + node.start_position().row + 1);
                }
                push_symbol(
                    file,
                    "fn",
                    &name,
                    line_offset + node.start_position().row + 1,
                    is_export || !name.starts_with('_'),
                );
                walk_children(
                    node,
                    ctx,
                    file,
                    TsWalkState {
                        current_fn: Some(name),
                        exported: is_export,
                        controller_prefix: state.controller_prefix,
                        top_level: false,
                        depth: state.depth + 1,
                    },
                );
                return;
            }
        }
        "method_definition" | "method_signature" => {
            if let Some(name) = field_ident(node, src, "name") {
                push_symbol(
                    file,
                    "method",
                    &name,
                    line_offset + node.start_position().row + 1,
                    is_export || !name.starts_with('_'),
                );
                if options.v2_enabled && !file.is_test_file {
                    collect_nest_routes(node, src, line_offset, file, state.controller_prefix.as_deref(), &name);
                }
                walk_children(
                    node,
                    ctx,
                    file,
                    TsWalkState {
                        current_fn: Some(name),
                        exported: is_export,
                        controller_prefix: state.controller_prefix,
                        top_level: false,
                        depth: state.depth + 1,
                    },
                );
                return;
            }
        }
        "class_declaration" => {
            if let Some(name) = field_ident(node, src, "name") {
                push_symbol(
                    file,
                    "class",
                    &name,
                    line_offset + node.start_position().row + 1,
                    is_export || !name.starts_with('_'),
                );
            }
            let nested_controller_prefix = if options.v2_enabled {
                nest_controller_prefix(node, src).or(state.controller_prefix)
            } else {
                state.controller_prefix
            };
            walk_children(
                node,
                ctx,
                file,
                TsWalkState {
                    current_fn: state.current_fn,
                    exported: is_export,
                    controller_prefix: nested_controller_prefix,
                    top_level: false,
                    depth: state.depth + 1,
                },
            );
            return;
        }
        "interface_declaration" => {
            if let Some(name) = field_ident(node, src, "name") {
                push_symbol(
                    file,
                    "interface",
                    &name,
                    line_offset + node.start_position().row + 1,
                    is_export || !name.starts_with('_'),
                );
            }
        }
        "type_alias_declaration" => {
            if let Some(name) = field_ident(node, src, "name") {
                push_symbol(
                    file,
                    "type",
                    &name,
                    line_offset + node.start_position().row + 1,
                    is_export || !name.starts_with('_'),
                );
            }
        }
        "lexical_declaration" | "variable_declaration" => {
            let declared_names = ts_declared_names(node, src, ctx.guard, state.depth + 1);
            if state.top_level {
                for name in &declared_names {
                    push_local_binding(file, name, line_offset + node.start_position().row + 1);
                }
            }
            if is_export {
                for name in declared_names {
                    push_symbol(file, "const", &name, line_offset + node.start_position().row + 1, true);
                }
            }
            walk_children(
                node,
                ctx,
                file,
                TsWalkState {
                    current_fn: state.current_fn,
                    exported: is_export,
                    controller_prefix: state.controller_prefix,
                    top_level: false,
                    depth: state.depth + 1,
                },
            );
            return;
        }
        "import_statement" => {
            if let Some(module) = quoted_child_text(node, src, ctx.guard, state.depth + 1) {
                file.deps.push(DepEdge {
                    from_crate: file.package_name.clone(),
                    from_file: file.rel_path.clone(),
                    to_module: module,
                    raw: node_text(node, src),
                });
            }
        }
        "call_expression" => {
            if let Some(function) = node.child_by_field_name("function") {
                let name = last_ident_text(function, src);
                if !name.is_empty() {
                    file.calls.push(CallSite {
                        name: name.clone(),
                        from_symbol: state.current_fn.clone(),
                    });
                }
                if options.v2_enabled && name == "require" {
                    if let Some(module) = first_arg_string(node, src) {
                        file.deps.push(DepEdge {
                            from_crate: file.package_name.clone(),
                            from_file: file.rel_path.clone(),
                            to_module: module,
                            raw: node_text(node, src),
                        });
                    }
                }
            }
            if options.v2_enabled && !file.is_test_file {
                collect_ts_express_route(node, src, line_offset, file, ctx.guard, state.depth + 1);
            }
        }
        _ => {}
    }
    let child_top_level = state.top_level && matches!(kind, "program" | "export_statement");
    walk_children(
        node,
        ctx,
        file,
        TsWalkState {
            current_fn: state.current_fn,
            exported: is_export,
            controller_prefix: state.controller_prefix,
            top_level: child_top_level,
            depth: state.depth + 1,
        },
    );
}

fn walk_children(node: Node<'_>, ctx: &mut TsWalkContext<'_, '_>, file: &mut ExtractedFile, state: TsWalkState) {
    if !ctx.guard.allow_depth(state.depth) {
        return;
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk_ts_node(child, ctx, file, state.clone());
    }
}

fn extract_python_file(
    src: &str,
    file: &mut ExtractedFile,
    options: PolyglotScanOptions,
    guard: &mut AstWalkGuard,
) -> Result<(), ScanError> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_python::LANGUAGE.into())
        .map_err(|err| ScanError::Io(std::io::Error::other(err.to_string())))?;
    let Some(tree) = parser.parse(src, None) else {
        return Ok(());
    };
    let bytes = src.as_bytes();
    walk_py_node(tree.root_node(), bytes, file, None, options, guard, 0);
    Ok(())
}

fn walk_py_node(
    node: Node<'_>,
    src: &[u8],
    file: &mut ExtractedFile,
    current_fn: Option<String>,
    options: PolyglotScanOptions,
    guard: &mut AstWalkGuard,
    depth: usize,
) {
    if !guard.allow_depth(depth) {
        return;
    }
    match node.kind() {
        "decorated_definition" => {
            if options.v2_enabled && !file.is_test_file {
                collect_python_routes(node, src, file, guard, depth + 1);
            }
        }
        "function_definition" => {
            if let Some(name) = field_ident(node, src, "name") {
                push_symbol(file, "fn", &name, node.start_position().row + 1, !name.starts_with('_'));
                walk_py_children(node, src, file, Some(name), options, guard, depth + 1);
                return;
            }
        }
        "class_definition" => {
            if let Some(name) = field_ident(node, src, "name") {
                push_symbol(
                    file,
                    "class",
                    &name,
                    node.start_position().row + 1,
                    !name.starts_with('_'),
                );
            }
        }
        "import_statement" | "import_from_statement" => {
            let raw = node_text(node, src);
            if let Some(module) = python_import_module(&raw) {
                file.deps.push(DepEdge {
                    from_crate: file.package_name.clone(),
                    from_file: file.rel_path.clone(),
                    to_module: module,
                    raw,
                });
            }
        }
        "call" => {
            if let Some(function) = node.child_by_field_name("function") {
                let name = last_ident_text(function, src);
                if !name.is_empty() {
                    file.calls.push(CallSite {
                        name,
                        from_symbol: current_fn.clone(),
                    });
                }
            }
            if options.v2_enabled && !file.is_test_file {
                collect_python_add_url_rule(node, src, file);
            }
        }
        _ => {}
    }
    walk_py_children(node, src, file, current_fn, options, guard, depth + 1);
}

fn walk_py_children(
    node: Node<'_>,
    src: &[u8],
    file: &mut ExtractedFile,
    current_fn: Option<String>,
    options: PolyglotScanOptions,
    guard: &mut AstWalkGuard,
    depth: usize,
) {
    if !guard.allow_depth(depth) {
        return;
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk_py_node(child, src, file, current_fn.clone(), options, guard, depth);
    }
}

fn extract_go_file(
    src: &str,
    file: &mut ExtractedFile,
    options: PolyglotScanOptions,
    guard: &mut AstWalkGuard,
) -> Result<(), ScanError> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_go::LANGUAGE.into())
        .map_err(|err| ScanError::Io(std::io::Error::other(err.to_string())))?;
    let Some(tree) = parser.parse(src, None) else {
        return Ok(());
    };
    let bytes = src.as_bytes();
    if let Some(package_name) = go_package_name(tree.root_node(), bytes, guard) {
        file.package_name = package_name;
        file.module_path = module_path(&file.package_name, &file.rel_path);
    }
    let group_prefixes = collect_go_group_prefixes(tree.root_node(), bytes, guard);
    let mut ctx = GoWalkContext {
        src: bytes,
        options,
        group_prefixes: &group_prefixes,
        guard,
    };
    walk_go_node(
        tree.root_node(),
        &mut ctx,
        file,
        GoWalkState {
            current_fn: None,
            depth: 0,
        },
    );
    Ok(())
}

#[derive(Debug)]
struct GoWalkContext<'src, 'groups, 'guard> {
    src: &'src [u8],
    options: PolyglotScanOptions,
    group_prefixes: &'groups HashMap<String, String>,
    guard: &'guard mut AstWalkGuard,
}

#[derive(Debug, Clone)]
struct GoWalkState {
    current_fn: Option<String>,
    depth: usize,
}

fn walk_go_node(node: Node<'_>, ctx: &mut GoWalkContext<'_, '_, '_>, file: &mut ExtractedFile, state: GoWalkState) {
    if !ctx.guard.allow_depth(state.depth) {
        return;
    }
    let src = ctx.src;
    let options = ctx.options;
    match node.kind() {
        "function_declaration" => {
            if let Some(name) = field_ident(node, src, "name") {
                push_symbol(file, "fn", &name, node.start_position().row + 1, go_is_pub(&name));
                walk_go_children(
                    node,
                    ctx,
                    file,
                    GoWalkState {
                        current_fn: Some(name),
                        depth: state.depth + 1,
                    },
                );
                return;
            }
        }
        "method_declaration" => {
            if let Some(name) = field_ident(node, src, "name") {
                let symbol_name = go_method_symbol_name(node, src, &name);
                push_symbol(
                    file,
                    "method",
                    &symbol_name,
                    node.start_position().row + 1,
                    go_is_pub(&name),
                );
                walk_go_children(
                    node,
                    ctx,
                    file,
                    GoWalkState {
                        current_fn: Some(symbol_name),
                        depth: state.depth + 1,
                    },
                );
                return;
            }
        }
        "type_declaration" => {
            collect_go_types(node, src, file, ctx.guard, state.depth + 1);
        }
        "import_declaration" => {
            collect_go_imports(node, src, file, ctx.guard, state.depth + 1);
        }
        "call_expression" => {
            if let Some(function) = node.child_by_field_name("function") {
                let name = last_ident_text(function, src);
                if !name.is_empty() {
                    file.calls.push(CallSite {
                        name,
                        from_symbol: state.current_fn.clone(),
                    });
                }
            }
            if options.v2_enabled && !file.is_test_file {
                collect_go_route(node, src, file, ctx.group_prefixes, ctx.guard, state.depth + 1);
            }
        }
        _ => {}
    }
    walk_go_children(
        node,
        ctx,
        file,
        GoWalkState {
            current_fn: state.current_fn,
            depth: state.depth + 1,
        },
    );
}

fn walk_go_children(node: Node<'_>, ctx: &mut GoWalkContext<'_, '_, '_>, file: &mut ExtractedFile, state: GoWalkState) {
    if !ctx.guard.allow_depth(state.depth) {
        return;
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk_go_node(child, ctx, file, state.clone());
    }
}

fn extract_java_file(src: &str, file: &mut ExtractedFile, guard: &mut AstWalkGuard) -> Result<(), ScanError> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_java::LANGUAGE.into())
        .map_err(|err| ScanError::Io(std::io::Error::other(err.to_string())))?;
    let Some(tree) = parser.parse(src, None) else {
        return Ok(());
    };
    walk_java_node(tree.root_node(), src.as_bytes(), file, guard, 0);
    Ok(())
}

fn walk_java_node(node: Node<'_>, src: &[u8], file: &mut ExtractedFile, guard: &mut AstWalkGuard, depth: usize) {
    if !guard.allow_depth(depth) {
        return;
    }
    match node.kind() {
        "class_declaration" => {
            if let Some(name) = field_ident(node, src, "name") {
                push_symbol(
                    file,
                    "class",
                    &name,
                    node.start_position().row + 1,
                    java_is_public(node, src),
                );
            }
        }
        "interface_declaration" => {
            if let Some(name) = field_ident(node, src, "name") {
                push_symbol(
                    file,
                    "interface",
                    &name,
                    node.start_position().row + 1,
                    java_is_public(node, src),
                );
            }
        }
        "method_declaration" => {
            if let Some(name) = field_ident(node, src, "name") {
                push_symbol(
                    file,
                    "method",
                    &name,
                    node.start_position().row + 1,
                    java_is_public(node, src),
                );
            }
        }
        "field_declaration" if java_is_static_final(node, src) => {
            let mut cursor = node.walk();
            for declarator in node.children_by_field_name("declarator", &mut cursor) {
                if let Some(name) = field_ident(declarator, src, "name") {
                    push_symbol(
                        file,
                        "const",
                        &name,
                        node.start_position().row + 1,
                        java_is_public(node, src),
                    );
                }
            }
        }
        "constant_declaration" => {
            let mut cursor = node.walk();
            for declarator in node.children_by_field_name("declarator", &mut cursor) {
                if let Some(name) = field_ident(declarator, src, "name") {
                    push_symbol(file, "const", &name, node.start_position().row + 1, true);
                }
            }
        }
        _ => {}
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk_java_node(child, src, file, guard, depth + 1);
    }
}

fn java_modifiers(node: Node<'_>, src: &[u8]) -> String {
    let mut cursor = node.walk();
    let modifiers = node
        .named_children(&mut cursor)
        .find(|child| child.kind() == "modifiers")
        .map_or_else(String::new, |child| node_text(child, src));
    modifiers
}

fn java_is_public(node: Node<'_>, src: &[u8]) -> bool {
    !java_modifiers(node, src)
        .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .any(|modifier| modifier == "private")
}

fn java_is_static_final(node: Node<'_>, src: &[u8]) -> bool {
    let modifiers = java_modifiers(node, src);
    let words: Vec<&str> = modifiers
        .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .collect();
    words.contains(&"static") && words.contains(&"final")
}

#[derive(Debug, Clone)]
struct CFamilyWalkState {
    namespaces: Vec<String>,
    classes: Vec<String>,
    in_function: bool,
    member_is_pub: bool,
    depth: usize,
}

impl Default for CFamilyWalkState {
    fn default() -> Self {
        Self {
            namespaces: Vec::new(),
            classes: Vec::new(),
            in_function: false,
            member_is_pub: true,
            depth: 0,
        }
    }
}

fn extract_c_family_file(
    src: &str,
    file: &mut ExtractedFile,
    cpp: bool,
    guard: &mut AstWalkGuard,
) -> Result<(), ScanError> {
    let mut parser = Parser::new();
    let language = if cpp {
        tree_sitter_cpp::LANGUAGE
    } else {
        tree_sitter_c::LANGUAGE
    };
    parser
        .set_language(&language.into())
        .map_err(|err| ScanError::Io(std::io::Error::other(err.to_string())))?;
    let Some(tree) = parser.parse(src, None) else {
        return Ok(());
    };
    walk_c_family_node(
        tree.root_node(),
        src.as_bytes(),
        file,
        cpp,
        guard,
        CFamilyWalkState::default(),
    );
    Ok(())
}

fn walk_c_family_node(
    node: Node<'_>,
    src: &[u8],
    file: &mut ExtractedFile,
    cpp: bool,
    guard: &mut AstWalkGuard,
    state: CFamilyWalkState,
) {
    if !guard.allow_depth(state.depth) {
        return;
    }

    if cpp && node.kind() == "field_declaration_list" {
        let mut member_state = state;
        member_state.depth += 1;
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if child.kind() == "access_specifier" {
                member_state.member_is_pub = node_text(child, src).trim() == "public";
            } else {
                walk_c_family_node(child, src, file, cpp, guard, member_state.clone());
            }
        }
        return;
    }

    let mut child_state = state.clone();
    child_state.depth += 1;
    match node.kind() {
        "namespace_definition" if cpp => {
            if let Some(name) = field_ident(node, src, "name") {
                child_state.namespaces.extend(
                    name.split("::")
                        .filter(|part| !part.is_empty())
                        .map(ToString::to_string),
                );
            }
        }
        "class_specifier" | "struct_specifier" => {
            if node.child_by_field_name("body").is_some() {
                if cpp {
                    child_state.member_is_pub = node.kind() == "struct_specifier";
                }
                if let Some(name) = field_ident(node, src, "name") {
                    let symbol_name = normalize_c_family_name(&name);
                    push_symbol(
                        file,
                        "class",
                        &symbol_name,
                        node.start_position().row + 1,
                        c_family_is_public(node, src, cpp, &state),
                    );
                    if cpp {
                        child_state.classes.push(symbol_name);
                    }
                }
            }
        }
        "enum_specifier" => {
            if node.child_by_field_name("body").is_some() {
                if let Some(name) = field_ident(node, src, "name") {
                    push_symbol(
                        file,
                        "class",
                        &normalize_c_family_name(&name),
                        node.start_position().row + 1,
                        c_family_is_public(node, src, cpp, &state),
                    );
                }
            }
        }
        "type_definition" => {
            let mut cursor = node.walk();
            for declarator in node.children_by_field_name("declarator", &mut cursor) {
                if let Some(name) = c_declarator_name(declarator, src, guard, state.depth + 1) {
                    push_symbol(
                        file,
                        "type",
                        &name,
                        node.start_position().row + 1,
                        c_family_is_public(node, src, cpp, &state),
                    );
                }
            }
        }
        "function_definition" => {
            if let Some(name) = c_function_name(node, src, guard, state.depth + 1) {
                let is_method = cpp && (!state.classes.is_empty() || name.contains("::"));
                let qualified = if cpp { qualify_cpp_callable(&name, &state) } else { name };
                push_symbol(
                    file,
                    if is_method { "method" } else { "fn" },
                    &qualified,
                    node.start_position().row + 1,
                    c_family_is_public(node, src, cpp, &state),
                );
            }
            child_state.in_function = true;
        }
        "declaration" if !state.in_function && state.classes.is_empty() => {
            if let Some(name) = c_function_name(node, src, guard, state.depth + 1) {
                let is_method = cpp && name.contains("::");
                let qualified = if cpp { qualify_cpp_callable(&name, &state) } else { name };
                push_symbol(
                    file,
                    if is_method { "method" } else { "fn" },
                    &qualified,
                    node.start_position().row + 1,
                    c_family_is_public(node, src, cpp, &state),
                );
            }
        }
        "field_declaration" if cpp && !state.classes.is_empty() => {
            if let Some(name) = c_function_name(node, src, guard, state.depth + 1) {
                push_symbol(
                    file,
                    "method",
                    &qualify_cpp_callable(&name, &state),
                    node.start_position().row + 1,
                    state.member_is_pub,
                );
            }
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk_c_family_node(child, src, file, cpp, guard, child_state.clone());
    }
}

fn c_function_name(node: Node<'_>, src: &[u8], guard: &mut AstWalkGuard, depth: usize) -> Option<String> {
    let declarator = node.child_by_field_name("declarator")?;
    let function = first_node_by_kind(declarator, "function_declarator", guard, depth)?;
    let name_node = function.child_by_field_name("declarator")?;
    let raw_name = normalize_c_family_name(&node_text(name_node, src));
    let is_operator = name_node.kind() == "operator_name"
        || raw_name
            .rsplit("::")
            .next()
            .is_some_and(|segment| segment.starts_with("operator"));
    if raw_name.contains('*') && !is_operator {
        return None;
    }
    c_declarator_name(name_node, src, guard, depth + 1)
}

fn c_family_is_public(node: Node<'_>, src: &[u8], cpp: bool, state: &CFamilyWalkState) -> bool {
    if cpp && !state.classes.is_empty() {
        return state.member_is_pub;
    }
    let mut cursor = node.walk();
    let has_static_storage = node
        .named_children(&mut cursor)
        .any(|child| child.kind() == "storage_class_specifier" && node_text(child, src).trim() == "static");
    !has_static_storage
}

fn c_declarator_name(node: Node<'_>, src: &[u8], guard: &mut AstWalkGuard, depth: usize) -> Option<String> {
    if !guard.allow_depth(depth) {
        return None;
    }
    if matches!(
        node.kind(),
        "identifier"
            | "field_identifier"
            | "type_identifier"
            | "qualified_identifier"
            | "destructor_name"
            | "operator_name"
    ) {
        return Some(normalize_c_family_name(&node_text(node, src)));
    }
    if let Some(inner) = node.child_by_field_name("declarator") {
        return c_declarator_name(inner, src, guard, depth + 1);
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if let Some(name) = c_declarator_name(child, src, guard, depth + 1) {
            return Some(name);
        }
    }
    None
}

fn normalize_c_family_name(name: &str) -> String {
    name.chars().filter(|character| !character.is_whitespace()).collect()
}

fn qualify_cpp_callable(name: &str, state: &CFamilyWalkState) -> String {
    let name = name.trim_start_matches("::");
    let namespace = state.namespaces.join("::");
    if name.contains("::") {
        if namespace.is_empty() || name == namespace || name.starts_with(&format!("{namespace}::")) {
            return name.to_string();
        }
        return format!("{namespace}::{name}");
    }
    let mut qualification = state.namespaces.clone();
    qualification.extend(state.classes.iter().cloned());
    qualification.push(name.to_string());
    qualification.join("::")
}

fn collect_python_routes(node: Node<'_>, src: &[u8], file: &mut ExtractedFile, guard: &mut AstWalkGuard, depth: usize) {
    let mut decorators = Vec::new();
    let mut function_node = None;
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "decorator" => decorators.push(child),
            "function_definition" => function_node = Some(child),
            _ => {}
        }
    }
    let Some(function_node) = function_node else {
        return;
    };
    let Some(handler_name) = field_ident(function_node, src, "name") else {
        return;
    };
    for decorator in decorators {
        for (method, path) in parse_python_route_decorator(decorator, src, guard, depth + 1) {
            push_route_candidate(
                file,
                method,
                path,
                RouteHandler::Named(handler_name.clone()),
                decorator.start_position().row + 1,
            );
        }
    }
}

fn parse_python_route_decorator(
    decorator: Node<'_>,
    src: &[u8],
    guard: &mut AstWalkGuard,
    depth: usize,
) -> Vec<(String, String)> {
    let Some(call) = first_node_by_kind(decorator, "call", guard, depth + 1) else {
        return Vec::new();
    };
    let Some(function) = call.child_by_field_name("function") else {
        return Vec::new();
    };
    let method_name = last_ident_text(function, src);
    let method_lower = method_name.to_ascii_lowercase();
    let args = argument_nodes(call);
    let Some(path) = python_route_path_from_args(&args, src) else {
        return Vec::new();
    };
    if !path.starts_with('/') {
        return Vec::new();
    }
    match method_lower.as_str() {
        "get" | "post" | "put" | "delete" | "patch" | "head" | "options" => {
            vec![(method_lower.to_ascii_uppercase(), path)]
        }
        "websocket" => vec![("WS".to_string(), path)],
        "route" => python_route_methods(&args, src, &["GET"])
            .into_iter()
            .map(|method| (method, path.clone()))
            .collect(),
        _ => Vec::new(),
    }
}

fn collect_python_add_url_rule(node: Node<'_>, src: &[u8], file: &mut ExtractedFile) {
    let Some(function) = node.child_by_field_name("function") else {
        return;
    };
    if last_ident_text(function, src) != "add_url_rule" {
        return;
    }
    let function_text = node_text(function, src);
    let Some(receiver) = function_text.rsplit_once('.').map(|(receiver, _)| receiver.trim()) else {
        return;
    };
    if !matches!(receiver, "app" | "bp" | "blueprint") {
        return;
    }
    let args = argument_nodes(node);
    let Some(path) = python_route_path_from_args(&args, src) else {
        return;
    };
    if !path.starts_with('/') {
        return;
    }
    let Some(handler) = python_add_url_rule_handler(&args, src) else {
        return;
    };
    for method in python_route_methods(&args, src, &["ANY"]) {
        push_route_candidate(
            file,
            method,
            path.clone(),
            handler.clone(),
            node.start_position().row + 1,
        );
    }
}

fn python_route_path_from_args(args: &[Node<'_>], src: &[u8]) -> Option<String> {
    for arg in args.iter().copied().filter(|arg| arg.kind() != "keyword_argument") {
        if let Some(path) = string_literal_value(arg, src, false) {
            return Some(path);
        }
    }
    for arg in args.iter().copied().filter(|arg| arg.kind() == "keyword_argument") {
        let Some(name) = keyword_argument_name(arg, src) else {
            continue;
        };
        if !matches!(name.as_str(), "path" | "rule") {
            continue;
        }
        let Some(value) = keyword_argument_value(arg) else {
            continue;
        };
        if let Some(path) = string_literal_value(value, src, false) {
            return Some(path);
        }
    }
    None
}

fn python_route_methods(args: &[Node<'_>], src: &[u8], default_methods: &[&str]) -> Vec<String> {
    for arg in args.iter().copied().filter(|arg| arg.kind() == "keyword_argument") {
        let Some(name) = keyword_argument_name(arg, src) else {
            continue;
        };
        if name != "methods" {
            continue;
        }
        let Some(value) = keyword_argument_value(arg) else {
            return vec!["ANY".to_string()];
        };
        return python_methods_list(value, src).unwrap_or_else(|| vec!["ANY".to_string()]);
    }
    default_methods.iter().map(|method| (*method).to_string()).collect()
}

fn python_methods_list(value: Node<'_>, src: &[u8]) -> Option<Vec<String>> {
    if value.kind() != "list" {
        return None;
    }
    let mut methods = Vec::new();
    let mut cursor = value.walk();
    for child in value.named_children(&mut cursor) {
        let method = string_literal_value(child, src, false)?;
        methods.push(method.to_ascii_uppercase());
    }
    (!methods.is_empty()).then_some(methods)
}

fn python_add_url_rule_handler(args: &[Node<'_>], src: &[u8]) -> Option<RouteHandler> {
    for arg in args.iter().copied().filter(|arg| arg.kind() == "keyword_argument") {
        let Some(name) = keyword_argument_name(arg, src) else {
            continue;
        };
        if name != "view_func" {
            continue;
        }
        let value = keyword_argument_value(arg)?;
        return route_handler_from_arg(value, src);
    }
    let positional: Vec<Node<'_>> = args
        .iter()
        .copied()
        .filter(|arg| arg.kind() != "keyword_argument")
        .collect();
    positional
        .get(2)
        .copied()
        .and_then(|handler| route_handler_from_arg(handler, src))
}

fn collect_ts_express_route(
    node: Node<'_>,
    src: &[u8],
    line_offset: usize,
    file: &mut ExtractedFile,
    guard: &mut AstWalkGuard,
    depth: usize,
) {
    let Some(function) = node.child_by_field_name("function") else {
        return;
    };
    if function.kind() != "member_expression" {
        return;
    }
    let Some(method_name) = member_property(function, src) else {
        return;
    };
    let Some(method) = express_method(&method_name) else {
        return;
    };
    let Some(object) = function.child_by_field_name("object") else {
        return;
    };
    if object.kind() == "identifier" {
        if !ts_express_receiver_allowed(&node_text(object, src)) {
            return;
        }
        let args = argument_nodes(node);
        if args.len() < 2 {
            return;
        }
        let Some(path) = string_literal_value(args[0], src, false) else {
            return;
        };
        if !path.starts_with('/') {
            return;
        }
        if let Some(handler) = route_handler_from_arg(args[1], src) {
            push_route_candidate(file, method, path, handler, line_offset + node.start_position().row + 1);
        }
        return;
    }

    if let Some(path) = express_route_chain_path(object, src, guard, depth + 1) {
        let args = argument_nodes(node);
        let Some(handler_node) = args.first().copied() else {
            return;
        };
        if let Some(handler) = route_handler_from_arg(handler_node, src) {
            push_route_candidate(file, method, path, handler, line_offset + node.start_position().row + 1);
        }
    }
}

fn express_route_chain_path(node: Node<'_>, src: &[u8], guard: &mut AstWalkGuard, depth: usize) -> Option<String> {
    if !guard.allow_depth(depth) {
        return None;
    }
    if node.kind() != "call_expression" {
        return None;
    }
    let function = node.child_by_field_name("function")?;
    if function.kind() != "member_expression" {
        return None;
    }
    let method = member_property(function, src)?;
    let object = function.child_by_field_name("object")?;
    if method == "route" {
        if object.kind() != "identifier" || !ts_express_receiver_allowed(&node_text(object, src)) {
            return None;
        }
        let args = argument_nodes(node);
        let path_node = args.first().copied()?;
        let path = string_literal_value(path_node, src, false)?;
        return path.starts_with('/').then_some(path);
    }
    if express_method(&method).is_some() {
        return express_route_chain_path(object, src, guard, depth + 1);
    }
    None
}

fn collect_nest_routes(
    node: Node<'_>,
    src: &[u8],
    line_offset: usize,
    file: &mut ExtractedFile,
    controller_prefix: Option<&str>,
    handler_name: &str,
) {
    for decorator in decorator_nodes(node) {
        if let Some((method, path)) = parse_nest_method_decorator(&node_text(decorator, src)) {
            let joined_path = join_route_paths(controller_prefix.unwrap_or_default(), &path);
            push_route_candidate(
                file,
                method,
                joined_path,
                RouteHandler::Named(handler_name.to_string()),
                line_offset + decorator.start_position().row + 1,
            );
        }
    }
}

fn nest_controller_prefix(node: Node<'_>, src: &[u8]) -> Option<String> {
    for decorator in decorator_texts(node, src) {
        let trimmed = decorator.trim().trim_start_matches('@').trim();
        let Some(open_idx) = trimmed.find('(') else {
            if trimmed == "Controller" {
                return Some(String::new());
            }
            continue;
        };
        if trimmed[..open_idx].trim() != "Controller" {
            continue;
        }
        let args = &trimmed[open_idx + 1..];
        return Some(first_literal_from_arg_text(args, false).unwrap_or_default());
    }
    None
}

fn parse_nest_method_decorator(raw: &str) -> Option<(String, String)> {
    let trimmed = raw.trim().trim_start_matches('@').trim();
    let (name, args) = if let Some(open_idx) = trimmed.find('(') {
        (trimmed[..open_idx].trim(), Some(&trimmed[open_idx + 1..]))
    } else {
        (trimmed, None)
    };
    let method = match name {
        "Get" => "GET",
        "Post" => "POST",
        "Put" => "PUT",
        "Delete" => "DELETE",
        "Patch" => "PATCH",
        "Head" => "HEAD",
        "Options" => "OPTIONS",
        "All" => "ANY",
        _ => return None,
    };
    let path = args
        .and_then(|arg_text| first_literal_from_arg_text(arg_text, false))
        .unwrap_or_default();
    Some((method.to_string(), path))
}

fn collect_go_route(
    node: Node<'_>,
    src: &[u8],
    file: &mut ExtractedFile,
    group_prefixes: &HashMap<String, String>,
    guard: &mut AstWalkGuard,
    depth: usize,
) {
    let Some(function) = node.child_by_field_name("function") else {
        return;
    };
    if function.kind() != "selector_expression" {
        return;
    }
    let Some(field) = function.child_by_field_name("field").map(|n| node_text(n, src)) else {
        return;
    };
    let Some(operand) = function.child_by_field_name("operand") else {
        return;
    };
    let operand_text = node_text(operand, src);
    let method = match field.as_str() {
        "GET" | "Get" => Some("GET"),
        "POST" | "Post" => Some("POST"),
        "PUT" | "Put" => Some("PUT"),
        "DELETE" | "Delete" => Some("DELETE"),
        "PATCH" | "Patch" => Some("PATCH"),
        "HEAD" | "Head" => Some("HEAD"),
        "OPTIONS" | "Options" => Some("OPTIONS"),
        "HandleFunc" if operand_text == "http" || operand.kind() == "identifier" => Some("ANY"),
        _ => None,
    };
    let Some(method) = method else {
        return;
    };
    let mut route_prefix = String::new();
    if field != "HandleFunc" {
        match operand.kind() {
            "identifier" => {
                if let Some(prefix) = group_prefixes.get(&operand_text) {
                    route_prefix.clone_from(prefix);
                } else if !go_route_receiver_allowed(&operand_text) {
                    return;
                }
            }
            "call_expression" => {
                let Some(prefix) = go_group_call_prefix(operand, src, group_prefixes, guard, depth + 1) else {
                    return;
                };
                route_prefix = prefix;
            }
            _ => return,
        }
    }
    let args = argument_nodes(node);
    if args.len() < 2 {
        return;
    }
    let Some(path) = string_literal_value(args[0], src, true) else {
        return;
    };
    if !path.starts_with('/') {
        return;
    }
    if let Some(handler) = route_handler_from_arg(args[1], src) {
        let path = join_route_paths(&route_prefix, &path);
        push_route_candidate(file, method.to_string(), path, handler, node.start_position().row + 1);
    }
}

fn collect_go_group_prefixes(root: Node<'_>, src: &[u8], guard: &mut AstWalkGuard) -> HashMap<String, String> {
    let mut assignments = Vec::new();
    collect_go_group_assignment_nodes(root, src, &mut assignments, guard, 0);
    let mut prefixes = HashMap::new();
    let mut changed = true;
    while changed {
        changed = false;
        for (name, call) in &assignments {
            if prefixes.contains_key(name) {
                continue;
            }
            if let Some(prefix) = go_group_call_prefix(*call, src, &prefixes, guard, 0) {
                prefixes.insert(name.clone(), prefix);
                changed = true;
            }
        }
    }
    prefixes
}

fn collect_go_group_assignment_nodes<'a>(
    node: Node<'a>,
    src: &[u8],
    out: &mut Vec<(String, Node<'a>)>,
    guard: &mut AstWalkGuard,
    depth: usize,
) {
    if !guard.allow_depth(depth) {
        return;
    }
    if matches!(
        node.kind(),
        "short_var_declaration" | "assignment_statement" | "var_spec"
    ) {
        if let Some((name, call)) = go_group_assignment_node(node, src, guard, depth + 1) {
            out.push((name, call));
        }
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_go_group_assignment_nodes(child, src, out, guard, depth + 1);
    }
}

fn go_group_assignment_node<'a>(
    node: Node<'a>,
    src: &[u8],
    guard: &mut AstWalkGuard,
    depth: usize,
) -> Option<(String, Node<'a>)> {
    let mut cursor = node.walk();
    let children: Vec<Node<'a>> = node.named_children(&mut cursor).collect();
    let lhs = children.first().copied()?;
    let name = single_identifier_under(lhs, src, guard, depth + 1)?;
    let call = children
        .iter()
        .skip(1)
        .copied()
        .find_map(|child| go_direct_group_call_node(child, guard, depth + 1))?;
    Some((name, call))
}

fn go_direct_group_call_node<'a>(node: Node<'a>, guard: &mut AstWalkGuard, depth: usize) -> Option<Node<'a>> {
    if !guard.allow_depth(depth) {
        return None;
    }
    if is_go_group_call_node(node) {
        return Some(node);
    }
    if matches!(node.kind(), "expression_list" | "var_spec") {
        let mut cursor = node.walk();
        let children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
        if children.len() == 1 {
            return go_direct_group_call_node(children[0], guard, depth + 1);
        }
    }
    None
}

fn is_go_group_call_node(node: Node<'_>) -> bool {
    if node.kind() != "call_expression" {
        return false;
    }
    let Some(function) = node.child_by_field_name("function") else {
        return false;
    };
    if function.kind() != "selector_expression" {
        return false;
    }
    function
        .child_by_field_name("field")
        .is_some_and(|field| field.kind() == "field_identifier")
}

fn go_group_call_prefix(
    call: Node<'_>,
    src: &[u8],
    group_prefixes: &HashMap<String, String>,
    guard: &mut AstWalkGuard,
    depth: usize,
) -> Option<String> {
    if !guard.allow_depth(depth) {
        return None;
    }
    if call.kind() != "call_expression" {
        return None;
    }
    let function = call.child_by_field_name("function")?;
    if function.kind() != "selector_expression" || go_selector_field(function, src)? != "Group" {
        return None;
    }
    let object = function.child_by_field_name("operand")?;
    let base_prefix = match object.kind() {
        "identifier" => {
            let receiver = node_text(object, src);
            if let Some(prefix) = group_prefixes.get(&receiver) {
                prefix.clone()
            } else if go_route_receiver_allowed(&receiver) {
                String::new()
            } else {
                return None;
            }
        }
        "call_expression" => go_group_call_prefix(object, src, group_prefixes, guard, depth + 1)?,
        _ => return None,
    };
    let args = argument_nodes(call);
    let path = args
        .first()
        .copied()
        .and_then(|arg| string_literal_value(arg, src, true))?;
    path.starts_with('/').then(|| join_route_paths(&base_prefix, &path))
}

fn collect_go_types(node: Node<'_>, src: &[u8], file: &mut ExtractedFile, guard: &mut AstWalkGuard, depth: usize) {
    let mut specs = Vec::new();
    collect_nodes_by_kind(node, "type_spec", &mut specs, guard, depth);
    for spec in specs {
        let Some(name) = field_ident(spec, src, "name") else {
            continue;
        };
        let kind = spec
            .child_by_field_name("type")
            .map_or("type", |type_node| match type_node.kind() {
                "struct_type" => "class",
                "interface_type" => "interface",
                _ => "type",
            });
        push_symbol(file, kind, &name, spec.start_position().row + 1, go_is_pub(&name));
    }
}

fn collect_go_imports(node: Node<'_>, src: &[u8], file: &mut ExtractedFile, guard: &mut AstWalkGuard, depth: usize) {
    let mut specs = Vec::new();
    collect_nodes_by_kind(node, "import_spec", &mut specs, guard, depth);
    for spec in specs {
        let Some(path_node) = spec.child_by_field_name("path") else {
            continue;
        };
        let Some(module) = string_literal_value(path_node, src, true) else {
            continue;
        };
        file.deps.push(DepEdge {
            from_crate: file.package_name.clone(),
            from_file: file.rel_path.clone(),
            to_module: module,
            raw: node_text(spec, src),
        });
    }
}

fn go_package_name(node: Node<'_>, src: &[u8], guard: &mut AstWalkGuard) -> Option<String> {
    let mut packages = Vec::new();
    collect_nodes_by_kind(node, "package_clause", &mut packages, guard, 0);
    let package = packages.first().copied()?;
    let mut cursor = package.walk();
    for child in package.named_children(&mut cursor) {
        if child.kind() == "package_identifier" {
            return Some(node_text(child, src));
        }
    }
    None
}

fn go_method_symbol_name(node: Node<'_>, src: &[u8], method_name: &str) -> String {
    let receiver = node
        .child_by_field_name("receiver")
        .map(|receiver| go_receiver_type_name(&node_text(receiver, src)));
    receiver
        .filter(|name| !name.is_empty())
        .map_or_else(|| method_name.to_string(), |name| format!("{name}.{method_name}"))
}

fn go_receiver_type_name(raw: &str) -> String {
    let trimmed = raw.trim().trim_start_matches('(').trim_end_matches(')').trim();
    let token = trimmed.split_whitespace().last().unwrap_or(trimmed);
    token
        .trim_start_matches('*')
        .trim_start_matches('(')
        .trim_end_matches(')')
        .to_string()
}

fn go_is_pub(name: &str) -> bool {
    name.chars().next().is_some_and(char::is_uppercase)
}

fn push_route_candidate(
    file: &mut ExtractedFile,
    method: String,
    path: String,
    handler: RouteHandler,
    source_line: usize,
) {
    file.routes.push(RouteCandidate {
        method,
        path,
        handler,
        source_file: file.rel_path.clone(),
        source_line,
    });
}

fn push_local_binding(file: &mut ExtractedFile, name: &str, line: usize) {
    if name.is_empty() {
        return;
    }
    file.local_bindings
        .entry(name.to_string())
        .or_insert(LocalBinding { line });
}

fn argument_nodes(call: Node<'_>) -> Vec<Node<'_>> {
    let Some(arguments) = call.child_by_field_name("arguments") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut cursor = arguments.walk();
    for child in arguments.named_children(&mut cursor) {
        out.push(child);
    }
    out
}

fn first_arg_string(call: Node<'_>, src: &[u8]) -> Option<String> {
    let arg = argument_nodes(call).first().copied()?;
    string_literal_value(arg, src, false)
}

fn route_handler_from_arg(node: Node<'_>, src: &[u8]) -> Option<RouteHandler> {
    match node.kind() {
        "arrow_function" | "function" | "function_expression" | "func_literal" | "lambda" => Some(RouteHandler::Inline),
        "identifier" | "property_identifier" | "field_identifier" => Some(RouteHandler::Named(node_text(node, src))),
        "member_expression" | "selector_expression" => {
            let name = last_ident_text(node, src);
            if name.is_empty() {
                None
            } else {
                Some(RouteHandler::Named(name))
            }
        }
        _ => None,
    }
}

fn express_method(name: &str) -> Option<String> {
    match name {
        "get" => Some("GET".to_string()),
        "post" => Some("POST".to_string()),
        "put" => Some("PUT".to_string()),
        "delete" => Some("DELETE".to_string()),
        "patch" => Some("PATCH".to_string()),
        "head" => Some("HEAD".to_string()),
        "options" => Some("OPTIONS".to_string()),
        "all" => Some("ANY".to_string()),
        _ => None,
    }
}

fn ts_express_receiver_allowed(name: &str) -> bool {
    matches!(name, "app" | "router" | "server" | "srv" | "fastify" | "express" | "r")
        || name.ends_with("Router")
        || name.ends_with("router")
}

fn go_route_receiver_allowed(name: &str) -> bool {
    matches!(
        name,
        "r" | "router" | "mux" | "engine" | "g" | "e" | "app" | "srv" | "group"
    ) || name.ends_with("Router")
        || name.ends_with("Mux")
        || name.ends_with("Group")
        || name.ends_with("Engine")
}

fn member_property(node: Node<'_>, src: &[u8]) -> Option<String> {
    node.child_by_field_name("property").map(|n| node_text(n, src))
}

fn go_selector_field(node: Node<'_>, src: &[u8]) -> Option<String> {
    node.child_by_field_name("field").map(|n| node_text(n, src))
}

fn keyword_argument_name(node: Node<'_>, src: &[u8]) -> Option<String> {
    node.child_by_field_name("name")
        .or_else(|| node.child_by_field_name("keyword"))
        .map(|name| node_text(name, src))
        .or_else(|| {
            node_text(node, src)
                .split_once('=')
                .map(|(name, _)| name.trim().to_string())
        })
}

fn keyword_argument_value(node: Node<'_>) -> Option<Node<'_>> {
    if let Some(value) = node.child_by_field_name("value") {
        return Some(value);
    }
    let mut cursor = node.walk();
    node.named_children(&mut cursor).last()
}

fn first_node_by_kind<'a>(node: Node<'a>, kind: &str, guard: &mut AstWalkGuard, depth: usize) -> Option<Node<'a>> {
    if !guard.allow_depth(depth) {
        return None;
    }
    if node.kind() == kind {
        return Some(node);
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if let Some(found) = first_node_by_kind(child, kind, guard, depth + 1) {
            return Some(found);
        }
    }
    None
}

fn decorator_texts(node: Node<'_>, src: &[u8]) -> Vec<String> {
    decorator_nodes(node)
        .into_iter()
        .map(|decorator| node_text(decorator, src))
        .collect()
}

fn decorator_nodes(node: Node<'_>) -> Vec<Node<'_>> {
    let mut out = Vec::new();
    let mut previous = Vec::new();
    let mut sibling = node.prev_named_sibling();
    while let Some(candidate) = sibling {
        if candidate.kind() != "decorator" {
            break;
        }
        previous.push(candidate);
        sibling = candidate.prev_named_sibling();
    }
    previous.reverse();
    out.extend(previous);
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "decorator" {
            out.push(child);
        }
    }
    out
}

fn collect_nodes_by_kind<'a>(
    node: Node<'a>,
    kind: &str,
    out: &mut Vec<Node<'a>>,
    guard: &mut AstWalkGuard,
    depth: usize,
) {
    if !guard.allow_depth(depth) {
        return;
    }
    if node.kind() == kind {
        out.push(node);
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_nodes_by_kind(child, kind, out, guard, depth + 1);
    }
}

fn string_literal_value(node: Node<'_>, src: &[u8], allow_backtick: bool) -> Option<String> {
    literal_text_value(&node_text(node, src), allow_backtick)
}

fn first_literal_from_arg_text(text: &str, allow_backtick: bool) -> Option<String> {
    literal_text_value(text.trim_start(), allow_backtick)
}

fn literal_text_value(text: &str, allow_backtick: bool) -> Option<String> {
    let trimmed = text.trim_start();
    let quote_idx = trimmed.find(['"', '\'', '`'])?;
    let prefix = &trimmed[..quote_idx];
    if prefix.chars().any(|c| c == 'f' || c == 'F') {
        return None;
    }
    if !prefix.chars().all(|c| matches!(c, 'r' | 'R' | 'u' | 'U' | 'b' | 'B')) {
        return None;
    }
    let quote = trimmed.as_bytes().get(quote_idx).copied()?;
    if quote == b'`' && !allow_backtick {
        return None;
    }
    let body_start = quote_idx + 1;
    let body = &trimmed[body_start..];
    let end_idx = find_closing_quote(body, quote)?;
    Some(body[..end_idx].to_string())
}

fn find_closing_quote(text: &str, quote: u8) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut idx = 0usize;
    let mut escaped = false;
    while idx < bytes.len() {
        let b = bytes[idx];
        if quote != b'`' && b == b'\\' && !escaped {
            escaped = true;
            idx += 1;
            continue;
        }
        if b == quote && !escaped {
            return Some(idx);
        }
        escaped = false;
        idx += 1;
    }
    None
}

fn join_route_paths(prefix: &str, path: &str) -> String {
    let prefix = prefix.trim_matches('/');
    let path = path.trim_matches('/');
    match (prefix.is_empty(), path.is_empty()) {
        (true, true) => String::new(),
        (true, false) => format!("/{path}"),
        (false, true) => format!("/{prefix}"),
        (false, false) => format!("/{prefix}/{path}"),
    }
}

fn vue_script_blocks(src: &str) -> Vec<SourceBlock> {
    let mut blocks = Vec::new();
    let mut offset = 0usize;
    while let Some(start_rel) = src[offset..].find("<script") {
        let tag_start = offset + start_rel;
        let Some(tag_end_rel) = src[tag_start..].find('>') else {
            break;
        };
        let body_start = tag_start + tag_end_rel + 1;
        let Some(end_rel) = src[body_start..].find("</script>") else {
            break;
        };
        let body_end = body_start + end_rel;
        let start_line_offset = src[..body_start].bytes().filter(|b| *b == b'\n').count();
        blocks.push(SourceBlock {
            text: src[body_start..body_end].to_string(),
            start_line_offset,
        });
        offset = body_end + "</script>".len();
    }
    blocks
}

fn push_symbol(file: &mut ExtractedFile, kind: &str, name: &str, line: usize, is_pub: bool) {
    if name.is_empty() {
        return;
    }
    let key = (kind.to_string(), name.to_string());
    if !file.symbol_keys.insert(key.clone()) {
        return;
    }
    file.symbols.push(SymbolInfo {
        crate_name: file.package_name.clone(),
        module_path: file.module_path.clone(),
        file_rel_path: file.rel_path.clone(),
        line,
        kind: key.0,
        name: key.1,
        is_pub,
    });
}

fn resolve_polyglot_references(
    scan: &mut WorkspaceScan,
    extracted: &[ExtractedFile],
    file_idx_by_path: &HashMap<String, usize>,
    symbol_by_name: &HashMap<String, Vec<SymbolInfo>>,
) {
    for file in extracted {
        let Some(from_idx) = file_idx_by_path.get(&file.rel_path).copied() else {
            continue;
        };
        let mut edges: BTreeMap<(String, String, Option<String>), usize> = BTreeMap::new();
        for call in &file.calls {
            let Some(candidates) = symbol_by_name.get(&call.name) else {
                continue;
            };
            if candidates.len() != 1 {
                continue;
            }
            let target = &candidates[0];
            *edges
                .entry((
                    target.file_rel_path.clone(),
                    target.name.clone(),
                    call.from_symbol.clone(),
                ))
                .or_insert(0) += 1;
        }
        for ((to_file, to_symbol, from_symbol), call_count) in edges {
            scan.files[from_idx].references.push(FileReference {
                same_file: to_file == file.rel_path,
                to_file,
                to_symbol,
                call_count,
                from_symbol,
            });
        }
    }
}

fn resolve_polyglot_routes(
    scan: &mut WorkspaceScan,
    extracted: &[ExtractedFile],
    symbol_by_name: &HashMap<String, Vec<SymbolInfo>>,
) {
    for file in extracted {
        for route in &file.routes {
            match &route.handler {
                RouteHandler::Inline => {
                    scan.routes.push(RouteHit {
                        method: route.method.clone(),
                        path: route.path.clone(),
                        handler_fn: "<inline>".to_string(),
                        handler_file: Some(route.source_file.clone()),
                        handler_line: Some(route.source_line),
                        source_file: route.source_file.clone(),
                        source_line: route.source_line,
                    });
                }
                RouteHandler::Named(handler_fn) => {
                    let (handler_file, handler_line, reason) = resolve_route_handler(handler_fn, file, symbol_by_name);
                    if let Some(reason) = reason {
                        scan.diagnostics.unresolved_routes.push(UnresolvedRoute {
                            method: route.method.clone(),
                            path: route.path.clone(),
                            handler_fn: handler_fn.clone(),
                            source_file: route.source_file.clone(),
                            source_line: route.source_line,
                            reason: reason.to_string(),
                        });
                    }
                    scan.routes.push(RouteHit {
                        method: route.method.clone(),
                        path: route.path.clone(),
                        handler_fn: handler_fn.clone(),
                        handler_file,
                        handler_line,
                        source_file: route.source_file.clone(),
                        source_line: route.source_line,
                    });
                }
            }
        }
    }
}

fn resolve_route_handler(
    handler_fn: &str,
    source_file: &ExtractedFile,
    symbol_by_name: &HashMap<String, Vec<SymbolInfo>>,
) -> (Option<String>, Option<usize>, Option<&'static str>) {
    if let Some(binding) = source_file.local_bindings.get(handler_fn) {
        return (Some(source_file.rel_path.clone()), Some(binding.line), None);
    }
    let Some(candidates) = symbol_by_name.get(handler_fn) else {
        return (None, None, Some("not_found"));
    };
    let same_file: Vec<&SymbolInfo> = candidates
        .iter()
        .filter(|symbol| symbol.file_rel_path == source_file.rel_path)
        .collect();
    let pick = match same_file.len().cmp(&1) {
        std::cmp::Ordering::Equal => Some(same_file[0]),
        std::cmp::Ordering::Greater => None,
        std::cmp::Ordering::Less => {
            let same_package: Vec<&SymbolInfo> = candidates
                .iter()
                .filter(|symbol| same_route_resolution_package(source_file, symbol))
                .collect();
            if same_package.len() == 1 {
                Some(same_package[0])
            } else if !is_go_path(&source_file.rel_path) && candidates.len() == 1 {
                Some(&candidates[0])
            } else {
                None
            }
        }
    };
    if let Some(symbol) = pick {
        (Some(symbol.file_rel_path.clone()), Some(symbol.line), None)
    } else {
        (None, None, Some("ambiguous"))
    }
}

fn same_route_resolution_package(source_file: &ExtractedFile, symbol: &SymbolInfo) -> bool {
    if is_go_path(&source_file.rel_path) {
        path_dir(&source_file.rel_path) == path_dir(&symbol.file_rel_path)
    } else {
        symbol.crate_name == source_file.package_name
    }
}

fn is_go_path(path: &str) -> bool {
    Path::new(path)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("go"))
}

fn path_dir(path: &str) -> &str {
    path.rsplit_once(['/', '\\']).map_or("", |(dir, _)| dir)
}

fn build_referenced_by(scan: &mut WorkspaceScan) {
    let mut inverse: HashMap<String, Vec<String>> = HashMap::new();
    for file in &scan.files {
        for reference in &file.references {
            if !reference.same_file {
                inverse
                    .entry(reference.to_file.clone())
                    .or_default()
                    .push(file.rel_path.clone());
            }
        }
    }
    for file in &mut scan.files {
        if let Some(mut refs) = inverse.remove(&file.rel_path) {
            refs.sort();
            refs.dedup();
            file.referenced_by = refs;
        }
    }
}

fn roll_up_stats(scan: &mut WorkspaceScan) {
    let mut routes_by_crate = BTreeMap::new();
    for route in &scan.routes {
        if let Some(file) = route.handler_file.as_deref() {
            if let Some(info) = scan.files.iter().find(|f| f.rel_path == file) {
                *routes_by_crate.entry(info.crate_name.clone()).or_insert(0) += 1;
            }
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
        route_count: scan.routes.len(),
        file_reference_count: scan.files.iter().map(|f| f.references.len()).sum(),
        external_dep_count: scan.external_deps.len(),
        doc_coverage_files: scan.files.iter().filter(|f| f.doc_summary.is_some()).count(),
        routes_by_crate,
    };
}

fn package_infos(root: &Path, scan: &WorkspaceScan, default_name: &str) -> Vec<CrateInfo> {
    let mut packages: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for file in &scan.files {
        let entry = packages.entry(file.crate_name.clone()).or_insert((0, 0));
        entry.0 += 1;
        entry.1 += file.loc;
    }
    if packages.is_empty() {
        packages.insert(default_name.to_string(), (0, 0));
    }
    packages
        .into_iter()
        .map(|(name, (file_count, total_loc))| CrateInfo {
            rel_path: root.display().to_string(),
            internal_deps: parse_internal_path_deps(""),
            name,
            file_count,
            total_loc,
        })
        .collect()
}

fn discover_package_name(root: &Path) -> String {
    if let Some(name) = package_json_name(&root.join("package.json")) {
        return name;
    }
    if let Some(name) = pyproject_name(&root.join("pyproject.toml")) {
        return name;
    }
    if let Some(name) = setup_cfg_name(&root.join("setup.cfg")) {
        return name;
    }
    root.file_name()
        .and_then(|n| n.to_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("repo")
        .to_string()
}

fn package_json_name(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let json: serde_json::Value = serde_json::from_str(&text).ok()?;
    json.get("name").and_then(|v| v.as_str()).map(ToString::to_string)
}

fn pyproject_name(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let mut in_project = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_project = trimmed == "[project]";
        } else if in_project && trimmed.starts_with("name") {
            return quoted_value(trimmed);
        }
    }
    None
}

fn setup_cfg_name(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let mut in_metadata = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_metadata = trimmed == "[metadata]";
        } else if in_metadata && trimmed.starts_with("name") {
            return trimmed.split_once('=').map(|(_, v)| v.trim().to_string());
        }
    }
    None
}

fn quoted_value(line: &str) -> Option<String> {
    let (_, value) = line.split_once('=')?;
    Some(value.trim().trim_matches('"').trim_matches('\'').to_string())
}

fn has_supported_file(root: &Path, exts: &[Option<&str>]) -> bool {
    let mut found = false;
    let _ = walk_dir(root, root, &mut |_rel, abs| {
        if found {
            return;
        }
        let ext = abs.extension().and_then(|e| e.to_str());
        found = exts.contains(&ext);
    });
    found
}

fn has_polyglot_non_rust_files(root: &Path, options: PolyglotScanOptions) -> bool {
    let mut extensions = vec![Some("ts"), Some("tsx"), Some("py"), Some("vue")];
    if options.v2_enabled {
        extensions.extend([Some("js"), Some("jsx"), Some("mjs"), Some("cjs"), Some("go")]);
    }
    if options.v3_enabled {
        extensions.extend([
            Some("java"),
            Some("c"),
            Some("h"),
            Some("cpp"),
            Some("cc"),
            Some("cxx"),
            Some("hpp"),
            Some("hh"),
            Some("hxx"),
        ]);
    }
    has_supported_file(root, &extensions)
}

fn rel_string(root: &Path, abs: &Path) -> String {
    abs.strip_prefix(root)
        .map_or_else(|_| abs.to_path_buf(), Path::to_path_buf)
        .display()
        .to_string()
}

fn module_path(package_name: &str, rel_path: &str) -> String {
    // Strip V3 suffixes before the legacy chain so a V3-dark existing file
    // such as `web.c.ts` keeps its historical `web.c` module component.
    let v3_clean = [".java", ".cpp", ".cxx", ".hpp", ".hxx", ".cc", ".hh", ".c", ".h"]
        .iter()
        .find_map(|suffix| rel_path.strip_suffix(suffix))
        .unwrap_or(rel_path);
    let clean = v3_clean
        .trim_end_matches(".ts")
        .trim_end_matches(".tsx")
        .trim_end_matches(".jsx")
        .trim_end_matches(".mjs")
        .trim_end_matches(".cjs")
        .trim_end_matches(".js")
        .trim_end_matches(".py")
        .trim_end_matches(".vue")
        .trim_end_matches(".go")
        .trim_end_matches(".rs")
        .replace(['/', '\\', '-'], "::");
    format!("{}::{}", package_name.replace('-', "_"), clean)
}

fn node_text(node: Node<'_>, src: &[u8]) -> String {
    node.utf8_text(src).unwrap_or_default().to_string()
}

fn field_ident(node: Node<'_>, src: &[u8], field: &str) -> Option<String> {
    node.child_by_field_name(field).map(|n| node_text(n, src))
}

fn quoted_child_text(node: Node<'_>, src: &[u8], guard: &mut AstWalkGuard, depth: usize) -> Option<String> {
    if !guard.allow_depth(depth) {
        return None;
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        let text = node_text(child, src);
        if (text.starts_with('"') && text.ends_with('"')) || (text.starts_with('\'') && text.ends_with('\'')) {
            return Some(text.trim_matches('"').trim_matches('\'').to_string());
        }
        if let Some(inner) = quoted_child_text(child, src, guard, depth + 1) {
            return Some(inner);
        }
    }
    None
}

fn identifiers_under(node: Node<'_>, src: &[u8], guard: &mut AstWalkGuard, depth: usize) -> Vec<String> {
    if !guard.allow_depth(depth) {
        return Vec::new();
    }
    let mut out = Vec::new();
    if node.kind() == "identifier" {
        out.push(node_text(node, src));
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        out.extend(identifiers_under(child, src, guard, depth + 1));
    }
    out
}

fn ts_declared_names(node: Node<'_>, src: &[u8], guard: &mut AstWalkGuard, depth: usize) -> Vec<String> {
    let mut declarators = Vec::new();
    collect_nodes_by_kind(node, "variable_declarator", &mut declarators, guard, depth);
    if declarators.is_empty() && matches!(node.kind(), "lexical_declaration" | "variable_declaration") {
        return identifiers_under(node, src, guard, depth);
    }
    let mut out = Vec::new();
    for declarator in declarators {
        if let Some(name_node) = declarator.child_by_field_name("name") {
            out.extend(identifiers_under(name_node, src, guard, depth + 1));
        }
    }
    out.sort();
    out.dedup();
    out
}

fn single_identifier_under(node: Node<'_>, src: &[u8], guard: &mut AstWalkGuard, depth: usize) -> Option<String> {
    let mut names = identifiers_under(node, src, guard, depth);
    names.sort();
    names.dedup();
    if names.len() == 1 {
        names.pop()
    } else {
        None
    }
}

fn last_ident_text(node: Node<'_>, src: &[u8]) -> String {
    let text = node_text(node, src);
    text.rsplit(['.', ':']).next().unwrap_or(&text).trim().to_string()
}

fn python_import_module(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if let Some(rest) = trimmed.strip_prefix("from ") {
        return rest.split_whitespace().next().map(ToString::to_string);
    }
    trimmed
        .strip_prefix("import ")
        .and_then(|rest| rest.split([',', ' ']).next())
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
}

fn rust_use_paths(tree: &syn::UseTree, guard: &mut AstWalkGuard) -> Vec<String> {
    fn walk(
        prefix: &mut Vec<String>,
        tree: &syn::UseTree,
        out: &mut Vec<String>,
        guard: &mut AstWalkGuard,
        depth: usize,
    ) {
        if !guard.allow_depth(depth) {
            return;
        }
        match tree {
            syn::UseTree::Path(p) => {
                prefix.push(p.ident.to_string());
                walk(prefix, &p.tree, out, guard, depth + 1);
                prefix.pop();
            }
            syn::UseTree::Name(n) => {
                let mut parts = prefix.clone();
                parts.push(n.ident.to_string());
                out.push(parts.join("::"));
            }
            syn::UseTree::Rename(r) => {
                let mut parts = prefix.clone();
                parts.push(r.ident.to_string());
                out.push(parts.join("::"));
            }
            syn::UseTree::Glob(_) => {
                let mut parts = prefix.clone();
                parts.push("*".to_string());
                out.push(parts.join("::"));
            }
            syn::UseTree::Group(g) => {
                for item in &g.items {
                    walk(prefix, item, out, guard, depth + 1);
                }
            }
        }
    }
    let mut out = Vec::new();
    walk(&mut Vec::new(), tree, &mut out, guard, 0);
    out
}

fn is_pub(vis: &syn::Visibility) -> bool {
    matches!(vis, syn::Visibility::Public(_) | syn::Visibility::Restricted(_))
}

fn line_of(src: &str, needle: &str) -> usize {
    src.lines()
        .position(|line| line.contains(needle))
        .map_or(0, |idx| idx + 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::EnvVarGuard;
    use std::collections::BTreeSet;

    fn route_set(scan: &WorkspaceScan) -> BTreeSet<(String, String, String)> {
        scan.routes
            .iter()
            .map(|route| (route.method.clone(), route.path.clone(), route.handler_fn.clone()))
            .collect()
    }

    fn route_tuple(method: &str, path: &str, handler: &str) -> (String, String, String) {
        (method.to_string(), path.to_string(), handler.to_string())
    }

    fn deep_call_source(nesting: usize) -> String {
        let mut src = String::from("export function shallow() { return 1; }\n");
        for _ in 0..nesting {
            src.push_str("f(\n");
        }
        src.push_str("1\n");
        for _ in 0..nesting {
            src.push_str(")\n");
        }
        src
    }

    fn stable_scan_json(mut scan: WorkspaceScan) -> String {
        scan.scan_id = "ws_test".to_string();
        scan.started_at_unix_ms = 1;
        scan.finished_at_unix_ms = 2;
        scan.duration_ms = 1;
        serde_json::to_string(&scan).expect("scan json")
    }

    fn symbol_set(scan: &WorkspaceScan, rel_path: &str) -> BTreeSet<(String, String)> {
        scan.symbols
            .iter()
            .filter(|symbol| symbol.file_rel_path == rel_path)
            .map(|symbol| (symbol.kind.clone(), symbol.name.clone()))
            .collect()
    }

    fn symbol_is_pub(scan: &WorkspaceScan, rel_path: &str, kind: &str, name: &str) -> bool {
        scan.symbols
            .iter()
            .find(|symbol| symbol.file_rel_path == rel_path && symbol.kind == kind && symbol.name == name)
            .unwrap_or_else(|| panic!("missing {kind} {name} in {rel_path}"))
            .is_pub
    }

    fn write_all_v3_dark_files(root: &Path) {
        for (name, source) in [
            ("Dark.java", "class Dark {}\n"),
            ("dark.c", "int dark_c(void) { return 0; }\n"),
            ("dark.h", "int dark_h(void);\n"),
            ("dark.cpp", "int dark_cpp() { return 0; }\n"),
            ("dark.cc", "int dark_cc() { return 0; }\n"),
            ("dark.cxx", "int dark_cxx() { return 0; }\n"),
            ("dark.hpp", "int dark_hpp();\n"),
            ("dark.hh", "int dark_hh();\n"),
            ("dark.hxx", "int dark_hxx();\n"),
        ] {
            std::fs::write(root.join(name), source).expect("dark V3 source");
        }
    }

    #[test]
    #[serial_test::serial]
    fn polyglot_v3_java_fixture_extracts_normalized_symbols() {
        let _env = EnvVarGuard::set(POLYGLOT_V3_ENV, "1");
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            tmp.path().join("Service.java"),
            r#"package demo;

public interface Repository<T> {
    T find(String id);
}

interface Config {
    int TIMEOUT = 30;
}

public class Service<T extends Comparable<T>> implements Repository<T> {
    public static final int MAX_ITEMS = 100, MIN_ITEMS = 1;
    private static final String SECRET = "dark";

    public T find(String id) { return null; }
    private void helper() {}

    public static class Nested<U> {
        public U map(U value) { return value; }
    }
}
"#,
        )
        .expect("java");

        let scan = run_repo_scan_at(tmp.path()).expect("scan");
        assert_eq!(
            symbol_set(&scan, "Service.java"),
            BTreeSet::from([
                ("class".to_string(), "Nested".to_string()),
                ("class".to_string(), "Service".to_string()),
                ("const".to_string(), "MAX_ITEMS".to_string()),
                ("const".to_string(), "MIN_ITEMS".to_string()),
                ("const".to_string(), "SECRET".to_string()),
                ("const".to_string(), "TIMEOUT".to_string()),
                ("interface".to_string(), "Config".to_string()),
                ("interface".to_string(), "Repository".to_string()),
                ("method".to_string(), "find".to_string()),
                ("method".to_string(), "helper".to_string()),
                ("method".to_string(), "map".to_string()),
            ])
        );
        assert!(!symbol_is_pub(&scan, "Service.java", "method", "helper"));
        assert!(symbol_is_pub(&scan, "Service.java", "const", "TIMEOUT"));
    }

    #[test]
    #[serial_test::serial]
    fn polyglot_v3_c_fixture_extracts_normalized_symbols() {
        let _env = EnvVarGuard::set(POLYGLOT_V3_ENV, "1");
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            tmp.path().join("model.c"),
            r"typedef unsigned long item_id;

struct Point { int x; int y; };
enum Status { STATUS_OK, STATUS_ERROR };
typedef struct { item_id id; } Payload;

static int helper(int value) { return value + 1; }
int compute(struct Point point) { return helper(point.x); }
",
        )
        .expect("c");
        std::fs::write(tmp.path().join("model.h"), "int header_fn(item_id id);\n").expect("header");

        let scan = run_repo_scan_at(tmp.path()).expect("scan");
        assert_eq!(
            symbol_set(&scan, "model.c"),
            BTreeSet::from([
                ("class".to_string(), "Point".to_string()),
                ("class".to_string(), "Status".to_string()),
                ("fn".to_string(), "compute".to_string()),
                ("fn".to_string(), "helper".to_string()),
                ("type".to_string(), "Payload".to_string()),
                ("type".to_string(), "item_id".to_string()),
            ])
        );
        assert_eq!(
            symbol_set(&scan, "model.h"),
            BTreeSet::from([("fn".to_string(), "header_fn".to_string())])
        );
        assert!(!symbol_is_pub(&scan, "model.c", "fn", "helper"));
        assert!(symbol_is_pub(&scan, "model.c", "fn", "compute"));
    }

    #[test]
    #[serial_test::serial]
    fn polyglot_v3_cpp_fixture_extracts_qualified_methods_and_templates() {
        let _env = EnvVarGuard::set(POLYGLOT_V3_ENV, "1");
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            tmp.path().join("engine.cpp"),
            r"namespace Acme::Core {
enum Mode { Fast, Safe };
typedef struct Legacy { int value; } LegacyHandle;

template <typename T>
class Box {
public:
    T value() const { return value_; }
private:
    T value_;
};

class Engine {
    friend class Phantom;
public:
    void start();
    Engine operator*(const Engine& rhs) const;
    Engine& operator*=(const Engine& rhs);
protected:
    void pause();
private:
    void stop();
};

class Defaults { void hidden(); };
struct Open { void visible(); };

void Engine::start() {}
static int hidden_utility() { return 0; }
int utility() { return 1; }
}
",
        )
        .expect("cpp");

        let scan = run_repo_scan_at(tmp.path()).expect("scan");
        assert_eq!(
            symbol_set(&scan, "engine.cpp"),
            BTreeSet::from([
                ("class".to_string(), "Box".to_string()),
                ("class".to_string(), "Defaults".to_string()),
                ("class".to_string(), "Engine".to_string()),
                ("class".to_string(), "Legacy".to_string()),
                ("class".to_string(), "Mode".to_string()),
                ("class".to_string(), "Open".to_string()),
                ("fn".to_string(), "Acme::Core::hidden_utility".to_string()),
                ("fn".to_string(), "Acme::Core::utility".to_string()),
                ("method".to_string(), "Acme::Core::Box::value".to_string()),
                ("method".to_string(), "Acme::Core::Defaults::hidden".to_string()),
                ("method".to_string(), "Acme::Core::Engine::operator*".to_string()),
                ("method".to_string(), "Acme::Core::Engine::operator*=".to_string()),
                ("method".to_string(), "Acme::Core::Engine::pause".to_string()),
                ("method".to_string(), "Acme::Core::Engine::start".to_string()),
                ("method".to_string(), "Acme::Core::Engine::stop".to_string()),
                ("method".to_string(), "Acme::Core::Open::visible".to_string()),
                ("type".to_string(), "LegacyHandle".to_string()),
            ])
        );
        assert!(!symbol_is_pub(&scan, "engine.cpp", "fn", "Acme::Core::hidden_utility"));
        for name in [
            "Acme::Core::Defaults::hidden",
            "Acme::Core::Engine::pause",
            "Acme::Core::Engine::stop",
        ] {
            assert!(!symbol_is_pub(&scan, "engine.cpp", "method", name));
        }
        for name in [
            "Acme::Core::Engine::operator*",
            "Acme::Core::Engine::operator*=",
            "Acme::Core::Engine::start",
            "Acme::Core::Open::visible",
        ] {
            assert!(symbol_is_pub(&scan, "engine.cpp", "method", name));
        }
    }

    #[test]
    #[serial_test::serial]
    fn polyglot_v3_bodyless_c_family_references_do_not_emit_phantom_classes() {
        let _env = EnvVarGuard::set(POLYGLOT_V3_ENV, "1");
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            tmp.path().join("refs.c"),
            "struct Forward;\nenum Mode;\nvoid uses(const struct Forward *value, enum Mode mode);\n",
        )
        .expect("c refs");
        std::fs::write(
            tmp.path().join("refs.cpp"),
            "class Forward;\nstruct Other;\nenum class Mode;\nvoid uses(Forward *a, Other *b, Mode mode);\n",
        )
        .expect("cpp refs");

        let scan = run_repo_scan_at(tmp.path()).expect("scan");
        assert_eq!(
            symbol_set(&scan, "refs.c"),
            BTreeSet::from([("fn".to_string(), "uses".to_string())])
        );
        assert_eq!(
            symbol_set(&scan, "refs.cpp"),
            BTreeSet::from([("fn".to_string(), "uses".to_string())])
        );
    }

    #[test]
    #[serial_test::serial]
    fn polyglot_v3_h_headers_sniff_obvious_cpp_and_keep_plain_c() {
        let _env = EnvVarGuard::set(POLYGLOT_V3_ENV, "1");
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            tmp.path().join("plain.h"),
            "struct CBody { int value; };\nint c_header_fn(struct CBody value);\n",
        )
        .expect("c header");
        std::fs::write(
            tmp.path().join("obvious_cpp.h"),
            "namespace HeaderNs { class Header { public: void run(); }; }\n",
        )
        .expect("cpp header");

        let scan = run_repo_scan_at(tmp.path()).expect("scan");
        assert_eq!(
            symbol_set(&scan, "plain.h"),
            BTreeSet::from([
                ("class".to_string(), "CBody".to_string()),
                ("fn".to_string(), "c_header_fn".to_string()),
            ])
        );
        assert_eq!(
            symbol_set(&scan, "obvious_cpp.h"),
            BTreeSet::from([
                ("class".to_string(), "Header".to_string()),
                ("method".to_string(), "HeaderNs::Header::run".to_string()),
            ])
        );
    }

    #[test]
    #[serial_test::serial]
    fn polyglot_v3_duplicate_heavy_symbols_preserve_first_only_semantics() {
        let _env = EnvVarGuard::set(POLYGLOT_V3_ENV, "1");
        let tmp = tempfile::tempdir().expect("tempdir");
        let source = "int duplicate(void);\n".repeat(2_000);
        std::fs::write(tmp.path().join("duplicates.c"), source).expect("duplicates");

        let scan = run_repo_scan_at(tmp.path()).expect("scan");
        assert_eq!(
            symbol_set(&scan, "duplicates.c"),
            BTreeSet::from([("fn".to_string(), "duplicate".to_string())])
        );
        let symbol = scan
            .symbols
            .iter()
            .find(|symbol| symbol.file_rel_path == "duplicates.c")
            .expect("deduplicated symbol");
        assert_eq!(symbol.line, 1);
        assert_eq!(
            scan.files
                .iter()
                .find(|file| file.rel_path == "duplicates.c")
                .map(|file| file.symbol_count),
            Some(1)
        );
    }

    #[test]
    fn polyglot_v3_extension_gate_defaults_h_to_c() {
        let enabled = PolyglotScanOptions {
            v2_enabled: false,
            v3_enabled: true,
        };
        let disabled = PolyglotScanOptions {
            v2_enabled: false,
            v3_enabled: false,
        };
        assert_eq!(language_for_path(Path::new("api.h"), enabled), Some(LanguageKind::C));
        assert_eq!(
            language_for_path(Path::new("api.hpp"), enabled),
            Some(LanguageKind::Cpp)
        );
        assert_eq!(language_for_path(Path::new("Main.java"), disabled), None);
        assert_eq!(language_for_path(Path::new("main.c"), disabled), None);
        assert_eq!(language_for_path(Path::new("main.cpp"), disabled), None);
        for (path, expected) in [
            ("a.java", "demo::a"),
            ("a.c", "demo::a"),
            ("a.h", "demo::a"),
            ("a.cpp", "demo::a"),
            ("a.cc", "demo::a"),
            ("a.cxx", "demo::a"),
            ("a.hpp", "demo::a"),
            ("a.hh", "demo::a"),
            ("a.hxx", "demo::a"),
            ("a.tsx", "demo::a"),
            ("b.jsx", "demo::b"),
            ("c.cxx.ts", "demo::c.cxx"),
            ("foo.h.ts", "demo::foo.h"),
        ] {
            assert_eq!(module_path("demo", path), expected, "{path}");
        }

        let v2_only = PolyglotScanOptions {
            v2_enabled: true,
            v3_enabled: false,
        };
        assert!(!should_skip_generated_polyglot_file(
            Path::new("vendor/app.js"),
            v2_only
        ));
        assert!(should_skip_generated_polyglot_file(Path::new("dist/app.js"), v2_only));
    }

    #[test]
    fn polyglot_v3_preparse_depth_guard_ignores_comments_strings_and_comparisons() {
        let source = r#"
            // {{{{{{{{{{{{{{{{{{{{
            /* (((((((((((((((((((( */
            const char *text = "[[[[[[[[[[[[[[[[[[[[";
            char brace = '{';
        "#;
        assert_eq!(
            max_source_delimiter_depth(source, POLYGLOT_AST_MAX_DEPTH, LanguageKind::Cpp),
            0
        );

        let comparisons = "if (left < right) {}\n".repeat(POLYGLOT_AST_MAX_DEPTH + 100);
        assert!(
            max_source_delimiter_depth(&comparisons, POLYGLOT_AST_MAX_DEPTH, LanguageKind::Cpp)
                < POLYGLOT_AST_MAX_DEPTH
        );

        let digit_separator_then_depth = format!("1'000;\n{}", "{\n".repeat(POLYGLOT_AST_MAX_DEPTH + 1));
        assert!(
            max_source_delimiter_depth(&digit_separator_then_depth, POLYGLOT_AST_MAX_DEPTH, LanguageKind::Cpp,)
                > POLYGLOT_AST_MAX_DEPTH
        );
        assert!(
            max_source_delimiter_depth(&digit_separator_then_depth, POLYGLOT_AST_MAX_DEPTH, LanguageKind::C,)
                > POLYGLOT_AST_MAX_DEPTH
        );
    }

    #[test]
    #[serial_test::serial]
    fn polyglot_v3_raw_strings_text_blocks_and_digit_separators_do_not_false_skip() {
        let _env = EnvVarGuard::set(POLYGLOT_V3_ENV, "1");
        let tmp = tempfile::tempdir().expect("tempdir");
        let braces = "{".repeat(POLYGLOT_AST_MAX_DEPTH + 100);
        std::fs::write(
            tmp.path().join("literals.cpp"),
            format!(
                "int cpp_literal() {{ auto a = u8R\"tag({braces})tag\"; auto b = LR\"x({braces})x\"; return 1'000; }}\n"
            ),
        )
        .expect("cpp literals");
        std::fs::write(
            tmp.path().join("TextBlock.java"),
            format!("class TextBlock {{ String text = \"\"\"\n{braces}\n\"\"\"; void ok() {{}} }}\n"),
        )
        .expect("java text block");
        std::fs::write(tmp.path().join("digits.c"), "int c_digits(void) { return 1'000; }\n").expect("c digits");

        let scan = run_repo_scan_at(tmp.path()).expect("scan");
        assert_eq!(
            symbol_set(&scan, "literals.cpp"),
            BTreeSet::from([("fn".to_string(), "cpp_literal".to_string())])
        );
        assert_eq!(
            symbol_set(&scan, "TextBlock.java"),
            BTreeSet::from([
                ("class".to_string(), "TextBlock".to_string()),
                ("method".to_string(), "ok".to_string()),
            ])
        );
        assert_eq!(
            symbol_set(&scan, "digits.c"),
            BTreeSet::from([("fn".to_string(), "c_digits".to_string())])
        );
        assert!(scan.diagnostics.v3_skipped_files.is_empty());
    }

    #[test]
    #[serial_test::serial]
    fn polyglot_v3_generated_and_vendored_sources_are_skipped() {
        let _env = EnvVarGuard::set(POLYGLOT_V3_ENV, "1");
        let tmp = tempfile::tempdir().expect("tempdir");
        for directory in ["src", "build", "vendor", "third_party"] {
            std::fs::create_dir_all(tmp.path().join(directory)).expect("directory");
        }
        std::fs::write(tmp.path().join("src/app.c"), "int source_fn(void) { return 1; }\n").expect("src");
        std::fs::write(
            tmp.path().join("build/generated.java"),
            "class Generated { void generated() {} }\n",
        )
        .expect("build");
        std::fs::write(tmp.path().join("vendor/library.cpp"), "int vendored() { return 1; }\n").expect("vendor");
        std::fs::write(tmp.path().join("third_party/library.h"), "int third_party(void);\n").expect("third party");

        let scan = run_repo_scan_at(tmp.path()).expect("scan");
        assert_eq!(scan.files.len(), 1);
        assert_eq!(scan.files[0].rel_path, "src/app.c");
        assert!(scan.symbols.iter().any(|symbol| symbol.name == "source_fn"));
    }

    #[test]
    #[serial_test::serial]
    fn polyglot_v3_pathological_java_c_and_cpp_are_skipped_before_parse() {
        let _env = EnvVarGuard::set(POLYGLOT_V3_ENV, "1");
        let tmp = tempfile::tempdir().expect("tempdir");
        for (name, prefix) in [
            ("Deep.java", "class Deep { void run() {\n"),
            ("deep.c", "int run(void) {\n"),
            ("deep.cpp", "template <typename T> int run() {\n"),
        ] {
            let mut source = prefix.to_string();
            for _ in 0..=POLYGLOT_AST_MAX_DEPTH {
                source.push_str("{\n");
            }
            for _ in 0..=POLYGLOT_AST_MAX_DEPTH {
                source.push_str("}\n");
            }
            source.push_str("}\n");
            assert!(source.len() < POLYGLOT_CPP_MAX_BYTES);
            assert!(source.lines().map(str::len).max().unwrap_or(0) < POLYGLOT_CPP_MAX_LINE_BYTES);
            std::fs::write(tmp.path().join(name), source).expect("deep source");
        }
        for (name, max_bytes) in [
            ("Huge.java", POLYGLOT_JAVA_MAX_BYTES),
            ("huge.c", POLYGLOT_C_MAX_BYTES),
            ("huge.cpp", POLYGLOT_CPP_MAX_BYTES),
        ] {
            std::fs::write(tmp.path().join(name), vec![b' '; max_bytes + 1]).expect("huge source");
        }
        for (name, max_line_bytes) in [
            ("LongLine.java", POLYGLOT_JAVA_MAX_LINE_BYTES),
            ("long_line.c", POLYGLOT_C_MAX_LINE_BYTES),
            ("long_line.cpp", POLYGLOT_CPP_MAX_LINE_BYTES),
        ] {
            let source = format!("//{}\n", "x".repeat(max_line_bytes + 1));
            assert!(source.len() < POLYGLOT_CPP_MAX_BYTES);
            std::fs::write(tmp.path().join(name), source).expect("long line source");
        }
        let mut template_storm = String::from("template <typename T> struct A {};\nusing Storm = ");
        for _ in 0..=POLYGLOT_AST_MAX_DEPTH {
            template_storm.push_str("A<\n");
        }
        template_storm.push_str("int\n");
        for _ in 0..=POLYGLOT_AST_MAX_DEPTH {
            template_storm.push_str(">\n");
        }
        template_storm.push_str(";\n");
        assert!(template_storm.len() < POLYGLOT_CPP_MAX_BYTES);
        std::fs::write(tmp.path().join("template_storm.cpp"), template_storm).expect("template storm");

        let scan = run_repo_scan_at(tmp.path()).expect("scan");
        assert!(scan.files.is_empty());
        assert!(scan.symbols.is_empty());
        assert_eq!(scan.stats.file_count, 0);
        assert_eq!(
            scan.diagnostics
                .v3_skipped_files
                .iter()
                .map(|skipped| (skipped.rel_path.clone(), skipped.reason.clone()))
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                ("Deep.java".to_string(), "max_delimiter_depth".to_string()),
                ("Huge.java".to_string(), "max_bytes".to_string()),
                ("LongLine.java".to_string(), "max_line_bytes".to_string()),
                ("deep.c".to_string(), "max_delimiter_depth".to_string()),
                ("deep.cpp".to_string(), "max_delimiter_depth".to_string()),
                ("huge.c".to_string(), "max_bytes".to_string()),
                ("huge.cpp".to_string(), "max_bytes".to_string()),
                ("long_line.c".to_string(), "max_line_bytes".to_string()),
                ("long_line.cpp".to_string(), "max_line_bytes".to_string()),
                ("template_storm.cpp".to_string(), "max_delimiter_depth".to_string()),
            ])
        );
    }

    #[cfg(unix)]
    #[test]
    #[serial_test::serial]
    fn polyglot_v3_symlink_to_device_is_skipped_without_reading() {
        let _env = EnvVarGuard::set(POLYGLOT_V3_ENV, "1");
        let tmp = tempfile::tempdir().expect("tempdir");
        std::os::unix::fs::symlink("/dev/zero", tmp.path().join("zero.c")).expect("device symlink");

        let scan = run_repo_scan_at(tmp.path()).expect("scan");
        assert!(scan.files.is_empty());
        assert_eq!(
            scan.diagnostics.v3_skipped_files,
            vec![V3SkippedFile {
                rel_path: "zero.c".to_string(),
                reason: "non_regular_file".to_string(),
            }]
        );
    }

    #[test]
    #[serial_test::serial]
    fn polyglot_v3_skip_diagnostics_survive_rust_hybrid_merge() {
        let _env = EnvVarGuard::set(POLYGLOT_V3_ENV, "1");
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("Cargo.toml"), "[workspace]\nmembers = [\"mini\"]\n").expect("workspace");
        let member = tmp.path().join("mini");
        std::fs::create_dir_all(member.join("src")).expect("src");
        std::fs::write(
            member.join("Cargo.toml"),
            "[package]\nname = \"mini\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .expect("manifest");
        std::fs::write(member.join("src/lib.rs"), "pub fn rust_fn() {}\n").expect("rust");
        std::fs::write(tmp.path().join("huge.c"), vec![b' '; POLYGLOT_C_MAX_BYTES + 1]).expect("huge c");

        let scan = run_repo_scan_at(tmp.path()).expect("hybrid scan");
        assert!(scan.files.iter().any(|file| file.rel_path == "mini/src/lib.rs"));
        assert_eq!(
            scan.diagnostics.v3_skipped_files,
            vec![V3SkippedFile {
                rel_path: "huge.c".to_string(),
                reason: "max_bytes".to_string(),
            }]
        );
        let json = serde_json::to_string(&scan).expect("scan json");
        assert!(json.contains("v3_skipped_files"));
        assert!(json.contains("max_bytes"));
    }

    #[test]
    #[serial_test::serial]
    fn polyglot_v3_dark_files_are_byte_identical_through_hybrid_merge() {
        let _v2 = EnvVarGuard::unset(POLYGLOT_V2_ENV);
        let _v3 = EnvVarGuard::unset(POLYGLOT_V3_ENV);
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("Cargo.toml"), "[workspace]\nmembers = [\"mini\"]\n").expect("ws");
        let member = tmp.path().join("mini");
        std::fs::create_dir_all(member.join("src")).expect("src");
        std::fs::write(
            member.join("Cargo.toml"),
            "[package]\nname = \"mini\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .expect("manifest");
        std::fs::write(member.join("src/lib.rs"), "pub fn rust_fn() {}\n").expect("rust");
        std::fs::write(tmp.path().join("foo.h.ts"), "export function webFn() {}\n").expect("ts");

        let before = stable_scan_json(run_repo_scan_at(tmp.path()).expect("baseline scan"));
        write_all_v3_dark_files(tmp.path());

        let unset = stable_scan_json(run_repo_scan_at(tmp.path()).expect("unset scan"));
        let zero = {
            let _zero = EnvVarGuard::set(POLYGLOT_V3_ENV, "0");
            stable_scan_json(run_repo_scan_at(tmp.path()).expect("zero scan"))
        };
        assert_eq!(before.as_bytes(), unset.as_bytes());
        assert_eq!(before.as_bytes(), zero.as_bytes());
        for name in [
            "Dark.java",
            "dark.c",
            "dark.h",
            "dark.cpp",
            "dark.cc",
            "dark.cxx",
            "dark.hpp",
            "dark.hh",
            "dark.hxx",
        ] {
            assert!(!unset.contains(name), "dark payload leaked {name}");
        }
        assert!(unset.contains("foo.h.ts"));
        assert!(!unset.contains(POLYGLOT_V3_ENV));
        assert!(!unset.contains("v3_skipped_files"));
    }

    #[test]
    #[serial_test::serial]
    fn polyglot_v3_dark_is_byte_identical_with_v2_enabled() {
        let _v2 = EnvVarGuard::set(POLYGLOT_V2_ENV, "1");
        let _v3 = EnvVarGuard::unset(POLYGLOT_V3_ENV);
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("package.json"), r#"{"name":"dark-v2"}"#).expect("package");
        std::fs::write(tmp.path().join("app.js"), "function jsHandler() {}\n").expect("js");
        std::fs::write(tmp.path().join("main.go"), "package main\nfunc goHandler() {}\n").expect("go");
        std::fs::write(tmp.path().join("foo.h.ts"), "export function tsHandler() {}\n").expect("ts");

        let before = stable_scan_json(run_repo_scan_at(tmp.path()).expect("V2 baseline"));
        write_all_v3_dark_files(tmp.path());
        let after = stable_scan_json(run_repo_scan_at(tmp.path()).expect("V2 plus dark V3"));

        assert_eq!(before.as_bytes(), after.as_bytes());
        assert!(after.contains("app.js"));
        assert!(after.contains("main.go"));
        assert!(after.contains("foo.h.ts"));
        assert!(!after.contains("v3_skipped_files"));
    }

    #[test]
    fn ts_fixture_extracts_symbols_and_deps() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("package.json"), r#"{"name":"demo-ts"}"#).expect("package");
        std::fs::write(
            tmp.path().join("main.ts"),
            r#"import { helper } from "./helper";

export interface Thing { id: string }
export function run(input: Thing) { return helper(input.id); }
"#,
        )
        .expect("ts");
        let scan = run_polyglot_scan_at(tmp.path()).expect("scan");
        assert!(scan.symbols.iter().any(|s| s.name == "run" && s.kind == "fn"));
        assert!(scan.symbols.iter().any(|s| s.name == "Thing" && s.kind == "interface"));
        assert!(scan.deps.iter().any(|d| d.to_module == "./helper"));
    }

    #[test]
    fn ts_deep_walk_is_bounded_and_ts_is_not_pathology_skipped() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("package.json"), r#"{"name":"deep-ts"}"#).expect("package");
        let deep_src = deep_call_source(POLYGLOT_AST_MAX_DEPTH + 256);
        std::fs::write(tmp.path().join("deep.ts"), &deep_src).expect("deep ts");
        let long_ts = format!(
            "export const longValue = \"{}\";\n",
            "x".repeat(POLYGLOT_JS_MAX_LINE_BYTES + 1)
        );
        assert!(long_ts.lines().next().map_or(0, str::len) > POLYGLOT_JS_MAX_LINE_BYTES);
        std::fs::write(tmp.path().join("long.ts"), long_ts).expect("long ts");

        let scan = run_polyglot_scan_at(tmp.path()).expect("scan");
        assert!(scan.files.iter().any(|file| file.rel_path == "deep.ts"));
        assert!(scan.files.iter().any(|file| file.rel_path == "long.ts"));
        assert!(scan
            .symbols
            .iter()
            .any(|symbol| symbol.name == "shallow" && symbol.file_rel_path == "deep.ts"));
        assert!(scan
            .symbols
            .iter()
            .any(|symbol| symbol.name == "longValue" && symbol.file_rel_path == "long.ts"));

        let extracted = extract_file(
            tmp.path(),
            &tmp.path().join("deep.ts"),
            LanguageKind::TypeScript,
            "deep-ts",
            PolyglotScanOptions {
                v2_enabled: false,
                v3_enabled: false,
            },
        )
        .expect("extract")
        .expect("not skipped");
        assert!(
            extracted.ast_depth_limit_hits > 0,
            "deep TypeScript should hit the walker depth cap"
        );
    }

    #[test]
    #[serial_test::serial]
    fn polyglot_v2_fastapi_and_flask_routes_are_precise() {
        let _env = EnvVarGuard::set(POLYGLOT_V2_ENV, "1");
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("pyproject.toml"), "[project]\nname = \"api-py\"\n").expect("pyproject");
        std::fs::write(
            tmp.path().join("app.py"),
            r#"from fastapi import FastAPI, APIRouter
from flask import Flask, Blueprint

app = FastAPI()
router = APIRouter()
flask_app = Flask(__name__)
bp = Blueprint("bp", __name__)

@app.get("/items")
def list_items():
    pass

@router.post("/items")
def create_item():
    pass

@router.get(path="/kw-items", response_model=object)
def kw_items():
    pass

@flask_app.route("/submit", methods=["GET", "POST"])
def submit():
    pass

@flask_app.route("/payment-methods")
def payment_methods():
    pass

dynamic_methods = ["PATCH"]

@flask_app.route("/dynamic", methods=dynamic_methods)
def dynamic_route():
    pass

@bp.route("/default")
def default_route():
    pass

@app.websocket("/ws")
def websocket():
    pass

@mock.patch("os.path.exists")
def patched():
    pass

@app.get(f"/items/{item_id}")
def skipped():
    pass

def submit_rule():
    pass

def rule_any():
    pass

app.add_url_rule("/submit-rule", "submit_rule", submit_rule, methods=["POST"])
bp.add_url_rule(rule="/rule-any", endpoint="rule_any", view_func=rule_any)
"#,
        )
        .expect("python");

        let scan = run_repo_scan_at(tmp.path()).expect("scan");
        let expected = BTreeSet::from([
            route_tuple("GET", "/items", "list_items"),
            route_tuple("POST", "/items", "create_item"),
            route_tuple("GET", "/kw-items", "kw_items"),
            route_tuple("GET", "/submit", "submit"),
            route_tuple("POST", "/submit", "submit"),
            route_tuple("GET", "/payment-methods", "payment_methods"),
            route_tuple("ANY", "/dynamic", "dynamic_route"),
            route_tuple("GET", "/default", "default_route"),
            route_tuple("WS", "/ws", "websocket"),
            route_tuple("POST", "/submit-rule", "submit_rule"),
            route_tuple("ANY", "/rule-any", "rule_any"),
        ]);
        assert_eq!(route_set(&scan), expected);
        assert_eq!(scan.stats.route_count, 11);
    }

    #[test]
    #[serial_test::serial]
    fn polyglot_v2_express_js_routes_are_precise() {
        let _env = EnvVarGuard::set(POLYGLOT_V2_ENV, "1");
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("package.json"), r#"{"name":"api-js"}"#).expect("package");
        std::fs::write(
            tmp.path().join("app.js"),
            r#"const express = require("express");
const axios = require("axios");
const { get, post } = require("http-client");
const app = express();
const router = express.Router();
const userRouter = express.Router();
const api = { put() {} };
const client = { get() {} };
const http = { get() {} };
const map = new Map();

const namedHandler = (req, res) => {
  res.end("ok");
};

app.get("/health", namedHandler);
app.post("/inline", (req, res) => res.end("ok"));
app.all("/any", namedHandler);
router.route("/users").get(namedHandler).post(namedHandler).delete(namedHandler);
userRouter.head("/head", namedHandler);
app.options("/options", namedHandler);
axios.post("/phantom-axios", {});
api.put("/phantom-api", {});
client.get("/phantom-client", {});
http.get("/phantom-http", {});
map.get("key", namedHandler);
app.get(routePath, namedHandler);
"#,
        )
        .expect("js");

        let scan = run_repo_scan_at(tmp.path()).expect("scan");
        let expected = BTreeSet::from([
            route_tuple("GET", "/health", "namedHandler"),
            route_tuple("POST", "/inline", "<inline>"),
            route_tuple("ANY", "/any", "namedHandler"),
            route_tuple("GET", "/users", "namedHandler"),
            route_tuple("POST", "/users", "namedHandler"),
            route_tuple("DELETE", "/users", "namedHandler"),
            route_tuple("HEAD", "/head", "namedHandler"),
            route_tuple("OPTIONS", "/options", "namedHandler"),
        ]);
        assert_eq!(route_set(&scan), expected);
        assert_eq!(scan.stats.route_count, 8);
        assert!(scan.deps.iter().any(|dep| dep.to_module == "express"));
        assert!(scan.deps.iter().any(|dep| dep.to_module == "http-client"));
        assert!(!scan
            .symbols
            .iter()
            .any(|symbol| symbol.kind == "const" && matches!(symbol.name.as_str(), "get" | "post" | "namedHandler")));
        let health = scan
            .routes
            .iter()
            .find(|route| route.method == "GET" && route.path == "/health")
            .expect("health route");
        assert_eq!(health.handler_file.as_deref(), Some("app.js"));
    }

    #[test]
    #[serial_test::serial]
    fn polyglot_v2_generated_js_output_files_are_skipped() {
        let _env = EnvVarGuard::set(POLYGLOT_V2_ENV, "1");
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("package.json"), r#"{"name":"api-js"}"#).expect("package");
        std::fs::create_dir_all(tmp.path().join("src")).expect("src");
        std::fs::create_dir_all(tmp.path().join("dist")).expect("dist");
        std::fs::write(
            tmp.path().join("src").join("app.js"),
            r#"function handler() {}
app.get("/src", handler);
"#,
        )
        .expect("src app");
        std::fs::write(
            tmp.path().join("dist").join("app.js"),
            r#"function handler() {}
app.get("/dist", handler);
"#,
        )
        .expect("dist app");

        let scan = run_repo_scan_at(tmp.path()).expect("scan");
        assert_eq!(
            route_set(&scan),
            BTreeSet::from([route_tuple("GET", "/src", "handler")])
        );
        assert!(scan.files.iter().any(|file| file.rel_path == "src/app.js"));
        assert!(!scan.files.iter().any(|file| file.rel_path == "dist/app.js"));
    }

    #[test]
    #[serial_test::serial]
    fn polyglot_v2_deep_js_walk_is_depth_bounded_without_minified_skip() {
        let _env = EnvVarGuard::set(POLYGLOT_V2_ENV, "1");
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("package.json"), r#"{"name":"deep-js"}"#).expect("package");
        let src = deep_call_source(POLYGLOT_AST_MAX_DEPTH + 256);
        assert!(src.len() < POLYGLOT_JS_MAX_BYTES);
        assert!(src.lines().map(str::len).max().unwrap_or(0) < POLYGLOT_JS_MAX_LINE_BYTES);
        std::fs::write(tmp.path().join("app.js"), &src).expect("js");

        let scan = run_repo_scan_at(tmp.path()).expect("scan");
        assert!(scan.files.iter().any(|file| file.rel_path == "app.js"));
        assert!(scan
            .symbols
            .iter()
            .any(|symbol| symbol.name == "shallow" && symbol.file_rel_path == "app.js"));
        assert!(scan.symbols.len() <= 2);

        let extracted = extract_file(
            tmp.path(),
            &tmp.path().join("app.js"),
            LanguageKind::TypeScript,
            "deep-js",
            PolyglotScanOptions {
                v2_enabled: true,
                v3_enabled: false,
            },
        )
        .expect("extract")
        .expect("not skipped");
        assert!(
            extracted.ast_depth_limit_hits > 0,
            "deep multiline JS should hit the walker depth cap"
        );
    }

    #[test]
    #[serial_test::serial]
    fn polyglot_v2_pathological_single_line_js_is_skipped() {
        let _env = EnvVarGuard::set(POLYGLOT_V2_ENV, "1");
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("package.json"), r#"{"name":"minified-js"}"#).expect("package");
        let src = format!(
            "function handler() {{}} app.get(\"/too-long\", handler); //{}\n",
            "x".repeat(POLYGLOT_JS_MAX_LINE_BYTES + 1)
        );
        assert!(src.lines().next().map_or(0, str::len) > POLYGLOT_JS_MAX_LINE_BYTES);
        std::fs::write(tmp.path().join("app.js"), src).expect("js");

        let scan = run_repo_scan_at(tmp.path()).expect("scan");
        assert!(scan.files.is_empty());
        assert!(scan.symbols.is_empty());
        assert!(scan.routes.is_empty());
        assert_eq!(scan.stats.file_count, 0);
    }

    #[test]
    #[serial_test::serial]
    fn polyglot_v2_test_file_routes_are_suppressed_but_symbols_remain() {
        let _env = EnvVarGuard::set(POLYGLOT_V2_ENV, "1");
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("package.json"), r#"{"name":"api-js"}"#).expect("package");
        std::fs::write(
            tmp.path().join("app.test.js"),
            r#"export function testHandler() {}
app.get("/test-only", testHandler);
"#,
        )
        .expect("test app");

        let scan = run_repo_scan_at(tmp.path()).expect("scan");
        assert!(scan.routes.is_empty());
        assert_eq!(scan.stats.route_count, 0);
        assert!(scan
            .files
            .iter()
            .any(|file| file.rel_path == "app.test.js" && file.is_test_file));
        assert!(scan
            .symbols
            .iter()
            .any(|symbol| symbol.name == "testHandler" && symbol.file_rel_path == "app.test.js"));
    }

    #[test]
    #[serial_test::serial]
    fn polyglot_v2_nestjs_routes_join_controller_prefix() {
        let _env = EnvVarGuard::set(POLYGLOT_V2_ENV, "1");
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("package.json"), r#"{"name":"api-nest"}"#).expect("package");
        std::fs::write(
            tmp.path().join("controller.ts"),
            r#"import { Controller, Delete, Get, Post } from "@nestjs/common";

@Controller("/api")
export class ThingsController {
  @Get()
  list() {
    return [];
  }

  @Post("items")
  create() {
    return {};
  }

  @Delete("/items/:id")
  remove() {
    return {};
  }
}
"#,
        )
        .expect("ts");

        let scan = run_repo_scan_at(tmp.path()).expect("scan");
        let expected = BTreeSet::from([
            route_tuple("GET", "/api", "list"),
            route_tuple("POST", "/api/items", "create"),
            route_tuple("DELETE", "/api/items/:id", "remove"),
        ]);
        assert_eq!(route_set(&scan), expected);
        assert_eq!(scan.stats.route_count, 3);
    }

    #[test]
    #[serial_test::serial]
    fn polyglot_v2_go_routes_are_precise() {
        let _env = EnvVarGuard::set(POLYGLOT_V2_ENV, "1");
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            tmp.path().join("main.go"),
            r#"package main

import (
    "net/http"
    "strings"

    "github.com/gin-gonic/gin"
    "github.com/go-chi/chi/v5"
)

func ginHandler(c *gin.Context) {}
func chiHandler(w http.ResponseWriter, r *http.Request) {}
func httpHandler(w http.ResponseWriter, r *http.Request) {}

func setup() {
    r := gin.Default()
    r.GET("/gin", ginHandler)
    router := chi.NewRouter()
    router.Post("/chi", chiHandler)
    http.HandleFunc("/http", httpHandler)
    r.PUT("/inline", func(c *gin.Context) {})
    r.Group("/v1").GET("/direct", ginHandler)
    group := r.Group("/api/")
    group.GET("/assigned", ginHandler)
    client.Get("/sdk", &resp)
    api.PUT("/phantom-api", ginHandler)
    v1.GET("/phantom-v1", ginHandler)
    strings.Replace("x", "x", "y", -1)
}
"#,
        )
        .expect("go");

        let scan = run_repo_scan_at(tmp.path()).expect("scan");
        let expected = BTreeSet::from([
            route_tuple("GET", "/gin", "ginHandler"),
            route_tuple("POST", "/chi", "chiHandler"),
            route_tuple("ANY", "/http", "httpHandler"),
            route_tuple("PUT", "/inline", "<inline>"),
            route_tuple("GET", "/v1/direct", "ginHandler"),
            route_tuple("GET", "/api/assigned", "ginHandler"),
        ]);
        assert_eq!(route_set(&scan), expected);
        assert_eq!(scan.stats.route_count, 6);
    }

    #[test]
    #[serial_test::serial]
    fn polyglot_v2_go_package_main_resolution_is_directory_scoped() {
        let _env = EnvVarGuard::set(POLYGLOT_V2_ENV, "1");
        let tmp = tempfile::tempdir().expect("tempdir");
        let cmd_a = tmp.path().join("cmd").join("a");
        let cmd_b = tmp.path().join("cmd").join("b");
        std::fs::create_dir_all(&cmd_a).expect("cmd a");
        std::fs::create_dir_all(&cmd_b).expect("cmd b");
        std::fs::write(
            cmd_a.join("main.go"),
            r#"package main

func setup() {
    r.GET("/local", localHandler)
    r.GET("/leak", sharedHandler)
}
"#,
        )
        .expect("cmd a main");
        std::fs::write(
            cmd_a.join("handlers.go"),
            r#"package main

func localHandler() {}
"#,
        )
        .expect("cmd a handlers");
        std::fs::write(
            cmd_b.join("main.go"),
            r#"package main

func sharedHandler() {}
"#,
        )
        .expect("cmd b main");

        let scan = run_repo_scan_at(tmp.path()).expect("scan");
        assert_eq!(
            route_set(&scan),
            BTreeSet::from([
                route_tuple("GET", "/local", "localHandler"),
                route_tuple("GET", "/leak", "sharedHandler"),
            ])
        );
        let local = scan
            .routes
            .iter()
            .find(|route| route.path == "/local")
            .expect("local route");
        assert_eq!(local.handler_file.as_deref(), Some("cmd/a/handlers.go"));
        let leak = scan
            .routes
            .iter()
            .find(|route| route.path == "/leak")
            .expect("leak route");
        assert!(leak.handler_file.is_none());
        assert!(scan
            .diagnostics
            .unresolved_routes
            .iter()
            .any(|route| route.path == "/leak" && route.handler_fn == "sharedHandler" && route.reason == "ambiguous"));
    }

    #[test]
    #[serial_test::serial]
    fn polyglot_v2_extracts_js_go_and_jsx_language_data() {
        let _env = EnvVarGuard::set(POLYGLOT_V2_ENV, "1");
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("package.json"), r#"{"name":"demo-js"}"#).expect("package");
        std::fs::write(
            tmp.path().join("app.js"),
            r#"const path = require("path");
class Service {}
function helper() {}
function run() {
  helper();
  return path.basename("x");
}
"#,
        )
        .expect("js");
        std::fs::write(
            tmp.path().join("view.jsx"),
            r#"export function Widget() {
  return <div />;
}
"#,
        )
        .expect("jsx");
        std::fs::write(
            tmp.path().join("main.go"),
            r#"package main

import "fmt"

type Server struct{}
type Store interface { Get() string }

func helperGo() {}
func RunGo() {
    helperGo()
    fmt.Println("ok")
}
"#,
        )
        .expect("go");

        let scan = run_repo_scan_at(tmp.path()).expect("scan");
        assert!(scan.files.iter().any(|file| file.rel_path == "app.js"));
        assert!(scan.files.iter().any(|file| file.rel_path == "view.jsx"));
        assert!(scan.files.iter().any(|file| file.rel_path == "main.go"));
        assert!(scan.symbols.iter().any(|s| s.name == "Service" && s.kind == "class"));
        assert!(scan.symbols.iter().any(|s| s.name == "run" && s.kind == "fn"));
        assert!(scan.symbols.iter().any(|s| s.name == "Widget" && s.kind == "fn"));
        assert!(scan.symbols.iter().any(|s| s.name == "Server" && s.kind == "class"));
        assert!(scan.symbols.iter().any(|s| s.name == "Store" && s.kind == "interface"));
        assert!(scan.deps.iter().any(|dep| dep.to_module == "path"));
        assert!(scan.deps.iter().any(|dep| dep.to_module == "fmt"));
        assert!(scan
            .files
            .iter()
            .any(|file| file.rel_path == "app.js"
                && file.references.iter().any(|reference| reference.to_symbol == "helper")));
        assert!(scan.files.iter().any(|file| file.rel_path == "main.go"
            && file
                .references
                .iter()
                .any(|reference| reference.to_symbol == "helperGo")));
    }

    #[test]
    #[serial_test::serial]
    fn polyglot_v2_mixed_rust_go_repo_merges_crates_symbols_and_routes() {
        let _env = EnvVarGuard::set(POLYGLOT_V2_ENV, "1");
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("Cargo.toml"), "[workspace]\nmembers = [\"mini\"]\n").expect("ws");
        let member = tmp.path().join("mini");
        std::fs::create_dir_all(member.join("src")).expect("src");
        std::fs::write(
            member.join("Cargo.toml"),
            "[package]\nname = \"mini\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .expect("manifest");
        std::fs::write(
            member.join("src").join("lib.rs"),
            r#"pub fn rust_handler() {}

pub fn router() {
    Router::new().route("/rust", axum::routing::get(rust_handler));
}
"#,
        )
        .expect("lib");
        std::fs::write(
            tmp.path().join("main.go"),
            r#"package main

import "net/http"

func goHandler(w http.ResponseWriter, r *http.Request) {}

func setup() {
    http.HandleFunc("/go", goHandler)
}
"#,
        )
        .expect("go");

        assert!(!should_use_rust_workspace_scan(tmp.path()));
        let scan = run_repo_scan_at(tmp.path()).expect("scan");
        assert!(scan.crates.iter().any(|krate| krate.name == "mini"));
        assert!(scan.crates.iter().any(|krate| krate.name == "main"));
        assert!(scan.symbols.iter().any(|symbol| symbol.name == "rust_handler"));
        assert!(scan.symbols.iter().any(|symbol| symbol.name == "goHandler"));
        assert_eq!(
            route_set(&scan),
            BTreeSet::from([
                route_tuple("GET", "/rust", "rust_handler"),
                route_tuple("ANY", "/go", "goHandler"),
            ])
        );
        assert_eq!(scan.routes.first().map(|route| route.path.as_str()), Some("/rust"));
        assert_eq!(scan.stats.route_count, 2);
    }

    #[test]
    #[serial_test::serial]
    fn polyglot_v2_dark_js_and_go_are_invisible() {
        let _env = EnvVarGuard::unset(POLYGLOT_V2_ENV);
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("app.js"), "function handler() {}\n").expect("js");
        std::fs::write(tmp.path().join("main.go"), "package main\nfunc handler() {}\n").expect("go");

        let scan = run_repo_scan_at(tmp.path()).expect("scan");
        assert_eq!(scan.stats.file_count, 0);
        assert!(scan.files.is_empty());
        assert!(scan.symbols.is_empty());
        assert!(scan.routes.is_empty());
    }

    #[test]
    #[serial_test::serial]
    fn polyglot_v2_dark_js_go_unset_and_zero_outputs_match() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("app.js"), "app.get('/dark', handler);\n").expect("js");
        std::fs::write(tmp.path().join("main.go"), "package main\nfunc handler() {}\n").expect("go");

        let unset_json = {
            let _env = EnvVarGuard::unset(POLYGLOT_V2_ENV);
            stable_scan_json(run_repo_scan_at(tmp.path()).expect("scan"))
        };
        let zero_json = {
            let _env = EnvVarGuard::set(POLYGLOT_V2_ENV, "0");
            stable_scan_json(run_repo_scan_at(tmp.path()).expect("scan"))
        };
        assert_eq!(unset_json, zero_json);
    }

    #[test]
    #[serial_test::serial]
    fn polyglot_v2_dark_fastapi_has_no_routes_or_internal_keys() {
        let _env = EnvVarGuard::unset(POLYGLOT_V2_ENV);
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("pyproject.toml"), "[project]\nname = \"api-py\"\n").expect("pyproject");
        std::fs::write(
            tmp.path().join("app.py"),
            r#"from fastapi import FastAPI
app = FastAPI()

@app.get("/items")
def list_items():
    pass
"#,
        )
        .expect("py");

        let scan = run_repo_scan_at(tmp.path()).expect("scan");
        assert_eq!(scan.stats.route_count, 0);
        assert!(scan.routes.is_empty());
        let json = serde_json::to_string(&scan).expect("scan json");
        assert!(!json.contains("RouteCandidate"));
        assert!(!json.contains("routes_candidate"));
        assert!(!json.contains("CORECRUXD_POLYGLOT_V2"));
        assert!(!json.contains("unresolved_routes"));
    }

    #[test]
    #[serial_test::serial]
    fn polyglot_v2_dark_unset_and_false_outputs_match() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("package.json"), r#"{"name":"demo-dark"}"#).expect("package");
        std::fs::write(tmp.path().join("main.ts"), "export function tsFn() {}\n").expect("ts");
        std::fs::write(tmp.path().join("app.py"), "def py_fn():\n    pass\n").expect("py");

        let unset_json = {
            let _env = EnvVarGuard::unset(POLYGLOT_V2_ENV);
            stable_scan_json(run_repo_scan_at(tmp.path()).expect("scan"))
        };
        let false_json = {
            let _env = EnvVarGuard::set(POLYGLOT_V2_ENV, "false");
            stable_scan_json(run_repo_scan_at(tmp.path()).expect("scan"))
        };
        assert_eq!(unset_json, false_json);
    }

    #[test]
    #[serial_test::serial]
    fn polyglot_v2_dark_rust_ts_merge_unset_and_zero_outputs_match() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("Cargo.toml"), "[workspace]\nmembers = [\"mini\"]\n").expect("ws");
        let member = tmp.path().join("mini");
        std::fs::create_dir_all(member.join("src")).expect("src");
        std::fs::write(
            member.join("Cargo.toml"),
            "[package]\nname = \"mini\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .expect("manifest");
        std::fs::write(member.join("src").join("lib.rs"), "pub fn rust_fn() {}\n").expect("lib");
        let web = tmp.path().join("web");
        std::fs::create_dir_all(&web).expect("web");
        std::fs::write(web.join("app.ts"), "export function tsFn() {}\n").expect("ts");

        let unset_json = {
            let _env = EnvVarGuard::unset(POLYGLOT_V2_ENV);
            stable_scan_json(run_repo_scan_at(tmp.path()).expect("scan"))
        };
        let zero_json = {
            let _env = EnvVarGuard::set(POLYGLOT_V2_ENV, "0");
            stable_scan_json(run_repo_scan_at(tmp.path()).expect("scan"))
        };
        assert_eq!(unset_json, zero_json);
    }

    #[test]
    #[serial_test::serial]
    fn polyglot_v2_unresolved_express_handler_emits_diagnostic_and_route() {
        let _env = EnvVarGuard::set(POLYGLOT_V2_ENV, "1");
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("package.json"), r#"{"name":"api-js"}"#).expect("package");
        std::fs::write(tmp.path().join("app.js"), r#"app.get("/missing", missingHandler);"#).expect("js");

        let scan = run_repo_scan_at(tmp.path()).expect("scan");
        assert_eq!(
            route_set(&scan),
            BTreeSet::from([route_tuple("GET", "/missing", "missingHandler")])
        );
        assert_eq!(scan.diagnostics.unresolved_routes.len(), 1);
        let unresolved = &scan.diagnostics.unresolved_routes[0];
        assert_eq!(unresolved.reason, "not_found");
        assert_eq!(unresolved.handler_fn, "missingHandler");
        assert!(scan.routes[0].handler_file.is_none());
    }

    #[test]
    fn python_fixture_extracts_symbols_and_deps() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("pyproject.toml"), "[project]\nname = \"demo-py\"\n").expect("pyproject");
        std::fs::write(
            tmp.path().join("app.py"),
            "from os import path\n\nclass Service:\n    pass\n\ndef handle():\n    return path.basename('x')\n",
        )
        .expect("py");
        let scan = run_polyglot_scan_at(tmp.path()).expect("scan");
        assert!(scan.symbols.iter().any(|s| s.name == "handle" && s.kind == "fn"));
        assert!(scan.symbols.iter().any(|s| s.name == "Service" && s.kind == "class"));
        assert!(scan.deps.iter().any(|d| d.to_module == "os"));
    }

    #[test]
    fn vue_script_setup_lines_are_file_relative() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            tmp.path().join("Widget.vue"),
            r#"<template><div /></template>
<script setup lang="ts">
function useWidget() {
  return 1;
}
</script>
"#,
        )
        .expect("vue");
        let scan = run_polyglot_scan_at(tmp.path()).expect("scan");
        let sym = scan.symbols.iter().find(|s| s.name == "useWidget").expect("function");
        assert_eq!(sym.line, 3);
    }

    #[test]
    fn mixed_repo_scans_all_supported_languages() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("lib.rs"), "pub fn rust_fn() {}\n").expect("rs");
        std::fs::write(tmp.path().join("main.ts"), "export function tsFn() {}\n").expect("ts");
        std::fs::write(tmp.path().join("app.py"), "def py_fn():\n    pass\n").expect("py");
        let scan = run_polyglot_scan_at(tmp.path()).expect("scan");
        assert_eq!(scan.stats.file_count, 3);
        assert!(scan.symbols.iter().any(|s| s.name == "rust_fn"));
        assert!(scan.symbols.iter().any(|s| s.name == "tsFn"));
        assert!(scan.symbols.iter().any(|s| s.name == "py_fn"));
    }

    #[test]
    fn cargo_workspace_with_polyglot_files_keeps_crates_and_merges() {
        // A cargo workspace with one member crate plus a stray TS file must
        // NOT flatten into a single polyglot package: the merged scan keeps
        // the cargo crate structure and adds the non-Rust extraction.
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("Cargo.toml"), "[workspace]\nmembers = [\"mini\"]\n").expect("ws");
        let member = tmp.path().join("mini");
        std::fs::create_dir_all(member.join("src")).expect("src");
        std::fs::write(
            member.join("Cargo.toml"),
            "[package]\nname = \"mini\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .expect("manifest");
        std::fs::write(member.join("src").join("lib.rs"), "pub fn rust_fn() {}\n").expect("lib");
        let web = tmp.path().join("web");
        std::fs::create_dir_all(&web).expect("web");
        std::fs::write(web.join("app.ts"), "export function tsFn() {}\n").expect("ts");

        assert!(!should_use_rust_workspace_scan(tmp.path()));
        assert!(has_rust_workspace(tmp.path()));

        let scan = run_repo_scan_at(tmp.path()).expect("scan");
        assert!(
            scan.crates.iter().any(|c| c.name == "mini"),
            "cargo crate survives the merge; got {:?}",
            scan.crates.iter().map(|c| c.name.clone()).collect::<Vec<_>>()
        );
        assert!(scan.symbols.iter().any(|s| s.name == "rust_fn"));
        assert!(scan.symbols.iter().any(|s| s.name == "tsFn"));
        assert!(scan.files.iter().any(|f| f.rel_path == "web/app.ts"));
        // The rust file is extracted exactly once (native scan), never again
        // by the polyglot pass.
        assert_eq!(scan.symbols.iter().filter(|s| s.name == "rust_fn").count(), 1);
        assert_eq!(scan.stats.crate_count, scan.crates.len());
        assert_eq!(scan.stats.symbol_count, scan.symbols.len());
    }
}
